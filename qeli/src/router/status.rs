use super::*;
pub(super) fn generation(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    if matches!(*fields.first()?, "Z" | "X") {
        return None;
    }
    Some(fields.get(19)?.to_string())
}
fn validated(file: &Path, pid_file: Option<&Path>, device: &str) -> Result<Value> {
    interface(device)?;
    private_dir(file.parent().context("status parent")?, false)?;
    let v: Value = serde_json::from_slice(&read_private(file, 8192)?)?;
    let r = &v["runtime"];
    let record = if let Some(path) = pid_file {
        read_private(path, 128)?
    } else {
        r["pid"]
            .as_u64()
            .context("missing report PID")?
            .to_string()
            .into_bytes()
    };
    let fields = std::str::from_utf8(&record)?
        .split_whitespace()
        .collect::<Vec<_>>();
    ensure!(
        !fields.is_empty() && fields.len() <= 2,
        "invalid service PID record"
    );
    let pid: u32 = fields[0].parse()?;
    ensure!(pid > 1, "invalid service PID");
    let start = generation(pid).context("process not live")?;
    let process_ns = fs::metadata(format!("/proc/{pid}/ns/net"))?;
    let this_ns = fs::metadata("/proc/thread-self/ns/net")?;
    ensure!(
        process_ns.dev() == this_ns.dev() && process_ns.ino() == this_ns.ino(),
        "status belongs to another network namespace"
    );
    if fields.len() == 2 {
        ensure!(fields[1] == start, "PID generation mismatch");
    }
    // OpenWrt's non-forking procd instance does not write a PID file. In this
    // mode require the report owner to be the exact installed qeli-client ELF.
    if pid_file.is_none() {
        let expected = fs::metadata(std::env::current_exe()?)?;
        let actual = fs::metadata(format!("/proc/{pid}/exe"))?;
        ensure!(
            expected.dev() == actual.dev() && expected.ino() == actual.ino(),
            "foreign process executable"
        );
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot = boot.trim();
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } == 0,
        "boottime unavailable"
    );
    let now = clock.tv_sec as u64 * 1000 + clock.tv_nsec as u64 / 1_000_000;
    let updated = r["updated_boottime_ms"]
        .as_u64()
        .context("status clock missing")?;
    ensure!(
        v["schema"] == 1
            && r["pid"] == pid
            && r["start_ticks"] == start
            && r["boot_id"] == boot
            && r["run_id"] == format!("{boot}:{pid}:{start}")
            && updated <= now + 100
            && now.saturating_sub(updated) <= 10000,
        "stale or foreign status"
    );
    let t = &v["tunnel"];
    ensure!(t["device"] == device, "status device mismatch");
    let state = t["state"].as_str().context("status state missing")?;
    ensure!(
        matches!(
            state,
            "connecting" | "connected" | "reconnecting" | "stopped" | "error"
        ),
        "unknown state"
    );
    if state == "connected" {
        let index = u32::try_from(t["ifindex"].as_u64().context("missing TUN index")?)?;
        let expected = t["addresses"]
            .as_array()
            .context("missing assigned addresses")?
            .iter()
            .map(|a| {
                a.as_str()
                    .context("invalid assigned address")?
                    .parse::<IpAddr>()
                    .map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            crate::router_status::ready(device, index, &expected),
            "TUN not current/ready or its assigned addresses are missing"
        );
    }
    ensure!(
        generation(pid).as_deref() == Some(&start),
        "process changed during read"
    );
    // Whitelist, never return raw diagnostics/error/credentials to a UI.
    let error = t["last_error_code"].as_str().filter(|s| {
        matches!(
            *s,
            "connection_failed" | "client_failed" | "network_not_ready"
        ) || s
            .strip_prefix("core_-")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    });
    Ok(
        json!({"available":true,"state":state,"device":device,"run_id":r["run_id"],"last_error_code":error,"retry_in_secs":t["retry_in_secs"].as_u64()}),
    )
}
pub(super) fn read(file: &Path, pid_file: Option<&Path>, device: &str) -> Value {
    validated(file, pid_file, device).unwrap_or_else(|_| json!({"available":false}))
}
