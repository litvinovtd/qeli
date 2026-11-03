//! Lightweight host + tunnel metrics for the web-panel dashboard (Tier-1
//! observability).
//!
//! A background sampler — spawned once by the supervisor — reads cheap `/proc`
//! counters and the data-plane worker's aggregate byte totals (over the control
//! socket) once a second, derives the quantities that need deltas (throughput,
//! CPU%), and keeps a short in-memory ring buffer. The panel polls
//! `GET /api/system` (latest host snapshot) and `GET /api/metrics` (the ring
//! buffer for the chart). No external deps, no disk, no per-request /proc parsing.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// 1 Hz sampling; keep 5 minutes of history (= the chart window).
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const HISTORY_LEN: usize = 300;

/// One point in the throughput / CPU / mem history (kept compact — the chart
/// transfers many of these on every poll).
#[derive(Clone, Serialize)]
pub struct Point {
    pub t: u64,
    pub up_mbps: f64,   // client -> server aggregate (tunnel upload)
    pub down_mbps: f64, // server -> client aggregate (tunnel download)
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub clients: usize,
}

/// Previous-sample counters needed to turn monotonic totals into rates.
#[derive(Default)]
struct Prev {
    cpu: Option<(u64, u64)>,      // (busy, total) jiffies
    proc_cpu: Option<ProcSample>, // worker identity + CPU/RSS counters
    net: Option<(u64, u64)>,      // host (rx, tx) bytes
    bytes: Option<(u64, u64)>,    // tunnel aggregate (sent, recv) bytes
    at: Option<Instant>,
}

/// Shared metrics state. Lives in `ServerState`; only the supervisor's sampler
/// writes it, the panel handlers read it.
pub struct MetricsState {
    history: Mutex<VecDeque<Point>>,
    latest: Mutex<Value>,
    prev: Mutex<Prev>,
    /// Data-plane worker pid (set by the supervise loop on each (re)spawn).
    pub worker_pid: AtomicI32,
}

impl MetricsState {
    pub fn new() -> Self {
        MetricsState {
            history: Mutex::new(VecDeque::with_capacity(HISTORY_LEN)),
            latest: Mutex::new(json!({"ok": true, "warming_up": true})),
            prev: Mutex::new(Prev::default()),
            worker_pid: AtomicI32::new(0),
        }
    }

    /// Latest host + tunnel snapshot (for `GET /api/system`).
    pub async fn latest_json(&self) -> Value {
        self.latest.lock().await.clone()
    }

    /// Throughput / CPU / mem ring buffer (for the dashboard chart).
    pub async fn history_json(&self) -> Value {
        let h = self.history.lock().await;
        json!({ "ok": true, "points": h.iter().cloned().collect::<Vec<_>>() })
    }
}

impl Default for MetricsState {
    fn default() -> Self {
        Self::new()
    }
}

/// Owned by the supervisor: sample once a second until shutdown.
///
/// `tun_names` lists the tunnel interfaces configured on this server, so the WAN counters
/// can exclude them by NAME. See `net_bytes`.
pub async fn run_sampler(
    metrics: Arc<MetricsState>,
    tun_names: Vec<String>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(SAMPLE_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while crate::profile_tasks::worker_tick(&mut tick, &mut shutdown).await {
        sample_once(&metrics, &tun_names).await;
    }
}

async fn sample_once(m: &MetricsState, tun_names: &[String]) {
    sample_with_socket(m, tun_names, &crate::server::control::control_socket_path()).await;
}

async fn sample_with_socket(m: &MetricsState, tun_names: &[String], socket_path: &str) {
    let now = Instant::now();
    let cpu_now = cpu_times();
    let mem = mem_info();
    let load = loadavg();
    let net_now = net_bytes(tun_names);
    let pid = m.worker_pid.load(Ordering::Relaxed);
    let proc_now = proc_stat(pid);
    let aggregate = tunnel_aggregate(socket_path).await;
    let clients = aggregate.map(|(_, _, clients)| clients).unwrap_or(0);
    let (tcp, udp) = count_conns(pid);
    let cores = cpu_cores();

    let mut prev = m.prev.lock().await;
    let dt = prev
        .at
        .map(|p| now.duration_since(p).as_secs_f64())
        .filter(|&d| d > 0.05)
        .unwrap_or(1.0);

    let cpu_pct = cpu_percent(prev.cpu, cpu_now);
    let proc_pct = process_percent(prev.proc_cpu, proc_now, prev.cpu, cpu_now, cores);
    let (rx_mbps, tx_mbps) = match (prev.net, net_now) {
        (Some((prx, ptx)), Some((rx, tx))) => (
            rx.saturating_sub(prx) as f64 * 8.0 / 1e6 / dt,
            tx.saturating_sub(ptx) as f64 * 8.0 / 1e6 / dt,
        ),
        _ => (0.0, 0.0),
    };
    let bytes_now = aggregate.map(|(sent, recv, _)| (sent, recv));
    let (up_mbps, down_mbps) = tunnel_rates(prev.bytes, bytes_now, dt);

    prev.cpu = cpu_now;
    prev.proc_cpu = proc_now;
    prev.net = net_now;
    // Missing RPC data invalidates the baseline; recovery must warm up again.
    prev.bytes = bytes_now;
    prev.at = Some(now);
    drop(prev);

    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (mem_used, mem_total) = mem.unwrap_or((0, 0));
    let mem_pct = if mem_total > 0 {
        mem_used as f64 / mem_total as f64 * 100.0
    } else {
        0.0
    };

    let point = Point {
        t,
        up_mbps: round1(up_mbps),
        down_mbps: round1(down_mbps),
        cpu_pct: round1(cpu_pct),
        mem_pct: round1(mem_pct),
        clients,
    };
    {
        let mut h = m.history.lock().await;
        if h.len() >= HISTORY_LEN {
            h.pop_front();
        }
        h.push_back(point);
    }

    let (l1, l5, l15) = load.unwrap_or((0.0, 0.0, 0.0));
    let proc_rss = proc_now.map(|sample| sample.rss_bytes).unwrap_or(0);
    let snap = json!({
        "ok": true,
        "t": t,
        "uptime_secs": uptime_secs().unwrap_or(0),
        "cpu_pct": round1(cpu_pct),
        "cores": cores,
        "mem_used": mem_used,
        "mem_total": mem_total,
        "mem_pct": round1(mem_pct),
        "load": [round2(l1), round2(l5), round2(l15)],
        "disk_pct": disk_pct("/").map(round1),
        "proc": { "pid": pid, "cpu_pct": round1(proc_pct), "rss_bytes": proc_rss },
        "net": { "rx_mbps": round1(rx_mbps), "tx_mbps": round1(tx_mbps) },
        "conns": { "tcp": tcp, "udp": udp },
        "up_mbps": round1(up_mbps),
        "down_mbps": round1(down_mbps),
        "clients": clients,
    });
    *m.latest.lock().await = snap;
}

//  /proc + syscall readers (all best-effort; None on any parse failure)

fn read_first_line(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()?
        .lines()
        .next()
        .map(|s| s.to_string())
}

/// (busy, total) jiffies from the aggregate `cpu` line of /proc/stat.
fn cpu_times() -> Option<(u64, u64)> {
    let line = read_first_line("/proc/stat")?;
    parse_cpu_times(&line)
}

fn parse_cpu_times(line: &str) -> Option<(u64, u64)> {
    let mut it = line.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let vals: Vec<u64> = it.map(str::parse).collect::<Result<_, _>>().ok()?;
    if vals.len() < 4 {
        return None;
    }
    // guest/guest_nice are already included in user/nice by the kernel.
    let total = vals
        .iter()
        .take(8)
        .try_fold(0u64, |sum, v| sum.checked_add(*v))?;
    let idle = vals[3].checked_add(vals.get(4).copied().unwrap_or(0))?;
    Some((total.checked_sub(idle)?, total))
}

fn cpu_percent(previous: Option<(u64, u64)>, current: Option<(u64, u64)>) -> f64 {
    match (previous, current) {
        (Some((pb, pt)), Some((b, t))) if t > pt && b >= pb => {
            // iowait can decrease. Keep one inconsistent sample from reporting >100%.
            ((b - pb) as f64 / (t - pt) as f64 * 100.0).min(100.0)
        }
        _ => 0.0,
    }
}

#[derive(Clone, Copy)]
struct ProcSample {
    pid: i32,
    start_ticks: u64,
    cpu_ticks: u64,
    rss_bytes: u64,
}

fn process_percent(
    previous: Option<ProcSample>,
    current: Option<ProcSample>,
    previous_cpu: Option<(u64, u64)>,
    current_cpu: Option<(u64, u64)>,
    cores: usize,
) -> f64 {
    match (previous, current, previous_cpu, current_cpu) {
        (Some(p), Some(c), Some((_, pt)), Some((_, t)))
            if p.pid == c.pid
                && p.start_ticks == c.start_ticks
                && t > pt
                && c.cpu_ticks >= p.cpu_ticks =>
        {
            // top(1) process scale: one saturated core is 100%.
            (c.cpu_ticks - p.cpu_ticks) as f64 / (t - pt) as f64 * cores as f64 * 100.0
        }
        _ => 0.0,
    }
}

fn tunnel_rates(previous: Option<(u64, u64)>, current: Option<(u64, u64)>, dt: f64) -> (f64, f64) {
    match (previous, current) {
        (Some((ps, pr)), Some((sent, recv))) => (
            recv.saturating_sub(pr) as f64 * 8.0 / 1e6 / dt,
            sent.saturating_sub(ps) as f64 * 8.0 / 1e6 / dt,
        ),
        _ => (0.0, 0.0),
    }
}

/// Number of logical CPUs (count of `cpuN` lines in /proc/stat).
fn cpu_cores() -> usize {
    std::fs::read_to_string("/proc/stat")
        .map(|s| {
            s.lines()
                .filter(|l| {
                    l.starts_with("cpu")
                        && l.as_bytes().get(3).map(u8::is_ascii_digit).unwrap_or(false)
                })
                .count()
        })
        .ok()
        .filter(|&n| n > 0)
        .unwrap_or(1)
}

/// (used_bytes, total_bytes) from /proc/meminfo (used = total − available).
fn mem_info() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = 0u64;
    let mut avail = 0u64;
    for l in s.lines() {
        if let Some(v) = l.strip_prefix("MemTotal:") {
            total = v.split_whitespace().next()?.parse().ok()?;
        } else if let Some(v) = l.strip_prefix("MemAvailable:") {
            avail = v.split_whitespace().next()?.parse().ok()?;
        }
    }
    if total == 0 {
        return None;
    }
    let total_b = total * 1024;
    Some((total_b.saturating_sub(avail * 1024), total_b))
}

fn loadavg() -> Option<(f64, f64, f64)> {
    let l = read_first_line("/proc/loadavg")?;
    let mut it = l.split_whitespace();
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

fn uptime_secs() -> Option<u64> {
    let l = read_first_line("/proc/uptime")?;
    let f: f64 = l.split_whitespace().next()?.parse().ok()?;
    Some(f as u64)
}

/// Used-space percentage of the filesystem holding `path`, via statvfs(3).
fn disk_pct(path: &str) -> Option<f64> {
    use std::ffi::CString;
    let c = CString::new(path).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let frsize = s.f_frsize as f64;
    let total = s.f_blocks as f64 * frsize;
    let avail = s.f_bavail as f64 * frsize;
    if total <= 0.0 {
        return None;
    }
    Some(((total - avail) / total * 100.0).clamp(0.0, 100.0))
}

/// Sum (rx, tx) bytes of physical-ish interfaces from /proc/net/dev — skips
/// loopback and the VPN's own tun interfaces (we want the WAN load, not the
/// tunnel doubled).
///
/// Exclusion is by CONFIGURED name (`tun_names`, from each profile's `tun.name`), with
/// the historical `vpn*`/`tun*`/`qtest*` prefixes kept as a fallback for interfaces this
/// process did not create. `tun.name` is a config key, so a profile named `qeli0` matched
/// none of those prefixes and its entire tunnel volume was counted as WAN — the dashboard
/// then showed roughly double the real load, on every graph an operator uses to judge
/// capacity. (Audit 2026-07-27, S4.)
fn net_bytes(tun_names: &[String]) -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/net/dev").ok()?;
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in s.lines() {
        if let Some((name, rest)) = line.split_once(':') {
            let name = name.trim();
            if name == "lo"
                || tun_names.iter().any(|t| t == name)
                || name.starts_with("vpn")
                || name.starts_with("tun")
                || name.starts_with("qtest")
            {
                continue;
            }
            let f: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|x| x.parse().ok())
                .collect();
            if f.len() >= 9 {
                rx += f[0];
                tx += f[8];
            }
        }
    }
    Some((rx, tx))
}

/// Identity and CPU/RSS counters for `pid`, or None.
fn proc_stat(pid: i32) -> Option<ProcSample> {
    if pid <= 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field (2nd) may contain spaces/parens — split after the LAST ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After comm: state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5) flags(6)
    // minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12) ...
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    let start_ticks: u64 = f.get(19)?.parse().ok()?;
    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    Some(ProcSample {
        pid,
        start_ticks,
        cpu_ticks: utime.checked_add(stime)?,
        rss_bytes: rss_pages.checked_mul(page)?,
    })
}

/// Socket inode numbers owned by one process. `/proc/<pid>/net/*` is network-namespace
/// wide, not process-local; joining it with the fd symlinks is what keeps unrelated host
/// services out of the qeli dashboard.
fn process_socket_inodes(pid: i32) -> std::collections::HashSet<u64> {
    if pid <= 0 {
        return std::collections::HashSet::new();
    }
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return std::collections::HashSet::new();
    };
    entries
        .flatten()
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter_map(|target| {
            let text = target.to_string_lossy();
            text.strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse().ok())
        })
        .collect()
}

fn count_socket_lines(
    text: &str,
    inodes: &std::collections::HashSet<u64>,
    established_only: bool,
) -> u64 {
    text.lines()
        .skip(1)
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if established_only && fields.get(3) != Some(&"01") {
                return false;
            }
            fields
                .get(9)
                .and_then(|inode| inode.parse::<u64>().ok())
                .is_some_and(|inode| inodes.contains(&inode))
        })
        .count() as u64
}

/// (established TCP, total UDP) sockets owned by the data-plane worker.
fn count_conns(pid: i32) -> (u64, u64) {
    let inodes = process_socket_inodes(pid);
    let count = |path: &str, established_only: bool| -> u64 {
        std::fs::read_to_string(path)
            .map(|text| count_socket_lines(&text, &inodes, established_only))
            .unwrap_or(0)
    };
    (
        count("/proc/net/tcp", true) + count("/proc/net/tcp6", true),
        count("/proc/net/udp", false) + count("/proc/net/udp6", false),
    )
}

/// Aggregate (bytes_sent, bytes_recv, client_count) across all live sessions,
/// read from the data-plane worker over the control socket.
async fn tunnel_aggregate(socket_path: &str) -> Option<(u64, u64, usize)> {
    let reply = crate::server::control::send_command(
        socket_path,
        &json!({ "cmd": "list-clients" }).to_string(),
    )
    .await
    .ok()?;
    let v: Value = serde_json::from_str(&reply).ok()?;
    let clients = v.get("clients")?.as_array()?;
    let mut sent = 0u64;
    let mut recv = 0u64;
    for c in clients {
        sent = sent.checked_add(c.get("bytes_sent").and_then(Value::as_u64).unwrap_or(0))?;
        recv = recv.checked_add(c.get("bytes_recv").and_then(Value::as_u64).unwrap_or(0))?;
    }
    Some((sent, recv, clients.len()))
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_count_is_process_scoped_and_tcp_state_aware() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                     0: 00000000:01BB 00000000:0000 01 0:0 00:0 0 1000 0 111\n\
                     1: 00000000:01BC 00000000:0000 0A 0:0 00:0 0 1000 0 222\n\
                     2: 00000000:01BD 00000000:0000 01 0:0 00:0 0 1000 0 333\n";
        let owned = [111_u64, 222].into_iter().collect();
        assert_eq!(count_socket_lines(table, &owned, true), 1);
        assert_eq!(count_socket_lines(table, &owned, false), 2);
    }

    #[test]
    fn missing_tunnel_sample_requires_fresh_baseline() {
        let old = Some((1_000_000_000, 2_000_000_000));
        assert_eq!(tunnel_rates(old, None, 1.0), (0.0, 0.0));
        let recovered = Some((1_000_125_000, 2_000_250_000));
        assert_eq!(tunnel_rates(None, recovered, 1.0), (0.0, 0.0));
        assert_eq!(
            tunnel_rates(recovered, Some((1_000_250_000, 2_000_500_000)), 1.0),
            (2.0, 1.0)
        );
        // An actual empty client list is a valid zero, unlike a missing reply.
        assert_eq!(
            tunnel_rates(Some((0, 0)), Some((125_000, 250_000)), 1.0),
            (2.0, 1.0)
        );
    }

    #[test]
    fn guest_time_is_not_counted_twice() {
        assert_eq!(
            parse_cpu_times("cpu 100 20 30 800 10 5 5 30 60 10"),
            Some((190, 1000))
        );
        assert_eq!(parse_cpu_times("cpu 100 20 30 850"), Some((150, 1000)));
    }

    #[test]
    fn invalid_cpu_samples_are_rejected_without_shifting_fields() {
        assert_eq!(parse_cpu_times("cpu 100 broken 30 800 10"), None);
        assert_eq!(parse_cpu_times("cpu 18446744073709551615 1 0 0"), None);
        assert_eq!(parse_cpu_times("cpu0 1 2 3 4"), None);
        assert_eq!(parse_cpu_times("cpu 1 2 3"), None);
    }

    #[test]
    fn cpu_counter_reset_and_iowait_reversal_are_bounded() {
        assert_eq!(cpu_percent(Some((500, 1000)), Some((400, 1100))), 0.0);
        assert_eq!(cpu_percent(Some((500, 1000)), Some((650, 1100))), 100.0);
        assert_eq!(cpu_percent(Some((500, 1000)), Some((525, 1100))), 25.0);
        assert_eq!(cpu_percent(Some((500, 1000)), Some((600, 900))), 0.0);
    }

    #[test]
    fn process_cpu_requires_same_pid_and_start_time() {
        let p = ProcSample {
            pid: 42,
            start_ticks: 100,
            cpu_ticks: 10,
            rss_bytes: 4096,
        };
        let mut c = ProcSample { cpu_ticks: 60, ..p };
        let rate =
            |current| process_percent(Some(p), Some(current), Some((0, 1000)), Some((0, 1200)), 4);
        assert_eq!(rate(c), 100.0);
        c.pid = 43;
        assert_eq!(rate(c), 0.0);
        c.pid = 42;
        c.start_ticks = 200; // PID reused after restart.
        assert_eq!(rate(c), 0.0);
        c.start_ticks = 100;
        c.cpu_ticks = 1;
        assert_eq!(rate(c), 0.0);
    }

    #[test]
    fn proc_stat_reads_current_process_identity() {
        let pid = std::process::id() as i32;
        let sample = proc_stat(pid).expect("Linux procfs for the current process");
        assert_eq!(sample.pid, pid);
        assert!(sample.start_ticks > 0);
        assert!(sample.rss_bytes > 0);
        assert!(proc_stat(0).is_none());
    }

    #[tokio::test]
    async fn sampler_recovers_from_real_control_disconnect_without_traffic_spike() {
        use std::os::unix::fs::DirBuilderExt;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let dir = std::env::temp_dir().join(format!(
            "qeli-metrics-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let fixture = Fixture(dir);
        let path = fixture.0.join("control.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let replies = [
            Some((1_000_000_000_u64, 2_000_000_000_u64)),
            None,
            Some((1_000_125_000, 2_000_250_000)),
            Some((1_000_250_000, 2_000_500_000)),
        ];
        let responder = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = String::new();
                BufReader::new(&mut stream)
                    .read_line(&mut request)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&request).unwrap()["cmd"],
                    "list-clients"
                );
                if let Some((sent, recv)) = reply {
                    let body = json!({"ok":true,"clients":[{"bytes_sent":sent,"bytes_recv":recv}]})
                        .to_string();
                    stream
                        .write_all(format!("{body}\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });
        let m = MetricsState::new();
        for expected in [(0.0, 0.0), (0.0, 0.0), (0.0, 0.0), (2.0, 1.0)] {
            m.prev.lock().await.at = Some(Instant::now() - Duration::from_secs(1));
            sample_with_socket(&m, &[], path.to_str().unwrap()).await;
            let snapshot = m.latest_json().await;
            assert_eq!(snapshot["up_mbps"], expected.0);
            assert_eq!(snapshot["down_mbps"], expected.1);
        }
        responder.await.unwrap();
        assert_eq!(
            m.history_json().await["points"].as_array().unwrap().len(),
            4
        );
    }
}
