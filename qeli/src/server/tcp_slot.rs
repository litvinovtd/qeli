//! Linux TCP_INFO for the accepted socket, independent of its protocol wrapper.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;

use crate::protocol::tcp_slot_probe::{Request, REQUEST_TTL};

const TARGET: &str = "qeli::tcp_slot";
const WINDOW: Duration = Duration::from_millis(1250);
const MAX_AGE: Duration = Duration::from_millis(2500);
const COOLDOWN: Duration = Duration::from_secs(60);

fn enabled_override(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_none_or(|value| value == "1")
}

pub(super) fn enabled() -> bool {
    // Keep the old override for existing deployments. Absence now enables
    // qualified TCP profiles, while an explicit 0 still disables replacement.
    static ENABLED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        enabled_override(std::env::var_os("QELI_EXPERIMENTAL_TCP_SLOT_PROBE").as_deref())
    });
    *ENABLED
}

tokio::task_local! {
    pub(super) static SOCKET: RefCell<Option<OwnedFd>>;
}

pub(super) fn capture(stream: &tokio::net::TcpStream) -> Option<OwnedFd> {
    if !enabled() && !log::log_enabled!(target: TARGET, log::Level::Debug) {
        return None;
    }
    match stream.as_fd().try_clone_to_owned() {
        Ok(socket) => Some(socket),
        Err(error) => {
            log::debug!(target: TARGET, "TCP_INFO socket unavailable: {error}");
            None
        }
    }
}

#[derive(Debug)]
struct TcpInfo {
    bytes_acked: u64,
    total_retrans: u32,
    rtt_us: u32,
    notsent_bytes: u32,
    min_rtt_us: u32,
    busy_us: Option<u64>,
    rwnd_limited_us: Option<u64>,
    bytes_retrans: Option<u64>,
    snd_wnd_bytes: Option<u32>,
}

fn parse_tcp_info(bytes: &[u8]) -> Option<TcpInfo> {
    // Linux UAPI struct tcp_info is append-only. Older kernels return shorter
    // records. Use the actual length and leave absent fields unknown.
    let u32_at = |offset| {
        Some(u32::from_ne_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let u64_at = |offset| {
        Some(u64::from_ne_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
    };
    Some(TcpInfo {
        bytes_acked: u64_at(120)?,
        total_retrans: u32_at(100)?,
        rtt_us: u32_at(68)?,
        notsent_bytes: u32_at(144)?,
        min_rtt_us: u32_at(148)?,
        busy_us: u64_at(168),
        rwnd_limited_us: u64_at(176),
        bytes_retrans: u64_at(208),
        snd_wnd_bytes: u32_at(228),
    })
}

fn sample(socket: &OwnedFd) -> Option<TcpInfo> {
    let mut bytes = [0u8; 232];
    let mut len = bytes.len() as libc::socklen_t;
    // SAFETY: the owned TCP fd remains open during the call. The kernel may
    // write up to len bytes to the initialized buffer and updates len in place.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            bytes.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result != 0 {
        return None;
    }
    parse_tcp_info(bytes.get(..len as usize)?)
}

fn current() -> Option<TcpInfo> {
    SOCKET
        .try_with(|socket| sample(socket.borrow().as_ref()?))
        .ok()
        .flatten()
}

pub(super) fn acknowledged_bytes() -> Option<u64> {
    current().map(|info| info.bytes_acked)
}

pub(super) fn active() -> bool {
    SOCKET
        .try_with(|socket| socket.borrow().is_some())
        .unwrap_or(false)
}

pub(super) fn release() {
    let _ = SOCKET.try_with(|socket| socket.borrow_mut().take());
}

pub(super) struct DeliveryWindow {
    pub(super) carrier: u64,
    at: Instant,
    bps: u64,
    rtt_us: u32,
    notsent_bytes: u32,
    busy: bool,
    delivered_under_load: bool,
    bad_windows: u8,
}

#[derive(Clone, Copy)]
pub(super) struct Candidate {
    pub(super) request: Request,
    pub(super) old_carrier: u64,
    baseline_bps: u64,
    at: Instant,
}

impl Candidate {
    pub(super) fn improves(self, delivered: u64, elapsed: Duration, current_bps: u64) -> bool {
        rate(delivered, elapsed) > self.baseline_bps.max(current_bps).saturating_mul(3) / 2
    }
}

#[derive(Default)]
pub(super) struct Health {
    samples: BTreeMap<u32, DeliveryWindow>,
    pending: Option<Candidate>,
    last_request: Option<Instant>,
}

impl Health {
    pub(super) fn record(&mut self, slot: u32, mut window: DeliveryWindow) -> Option<Request> {
        self.samples
            .retain(|_, other| window.at.duration_since(other.at) <= MAX_AGE);
        let mut siblings = self
            .samples
            .iter()
            .filter(|(id, other)| **id != slot && other.delivered_under_load)
            .map(|(_, other)| (other.bps, other.rtt_us))
            .collect::<Vec<_>>();
        siblings.sort_unstable();
        let (slower, severe) =
            siblings
                .get(siblings.len() / 2)
                .map_or((false, false), |&(bps, rtt_us)| {
                    let elevated_rtt = rtt_us > 0
                        && window.rtt_us >= rtt_us.saturating_mul(2)
                        && window.rtt_us.saturating_sub(rtt_us) >= 10_000;
                    (
                        bps >= 125_000
                            && (window.bps < bps / 2 || elevated_rtt && window.bps < bps / 4 * 3),
                        bps >= 125_000
                            && window.notsent_bytes >= 128 * 1024
                            && window.bps.saturating_mul(3) < bps,
                    )
                });
        if window.busy && slower {
            window.bad_windows = self
                .samples
                .get(&slot)
                .filter(|other| other.carrier == window.carrier)
                .map_or(1, |other| other.bad_windows.saturating_add(1));
        }
        // Two loaded windows plus a severe rate/queue outlier justify preparing
        // a candidate before inner TCP exits STARTUP on the reduced bandwidth.
        // Kernel RTT excludes time waiting in TCP's unsent queue. Require a
        // large notsent backlog, even if RTT is high, to avoid promoting a
        // demand/ramp fluctuation to an early replacement.
        // Moderate degradation still needs three windows. Preparation alone
        // never retires the old carrier: the delivery probe must still improve
        // on both the old baseline and its current rate before COMMIT.
        let early_probe = severe && window.bad_windows >= 2;
        let offer = (window.bad_windows >= 3 || early_probe)
            && self
                .last_request
                .is_none_or(|at| window.at.duration_since(at) >= COOLDOWN);
        let next = offer.then(|| Candidate {
            request: Request {
                slot,
                nonce: rand::random(),
            },
            old_carrier: window.carrier,
            baseline_bps: window.bps,
            at: window.at,
        });
        if offer && early_probe && window.bad_windows < 3 {
            log::info!(target: TARGET,
                "TCP_SLOT_EARLY_PROBE slot={} carrier={} bad_windows={} rate_Bps={} rtt_us={} notsent_bytes={}",
                slot, window.carrier, window.bad_windows, window.bps, window.rtt_us, window.notsent_bytes);
        }
        self.samples.insert(slot, window);
        if let Some(candidate) = next {
            self.pending = Some(candidate);
            self.last_request = Some(candidate.at);
        }
        next.map(|candidate| candidate.request)
    }

    pub(super) fn claim(&mut self, request: Request) -> Option<Candidate> {
        let candidate = self.pending?;
        if candidate.request != request || candidate.at.elapsed() > REQUEST_TTL {
            return None;
        }
        self.pending.take()
    }

    pub(super) fn current_rate(&self, candidate: Candidate) -> u64 {
        self.samples
            .get(&candidate.request.slot)
            .filter(|sample| {
                sample.carrier == candidate.old_carrier
                    && sample.busy
                    && sample.at.elapsed() <= MAX_AGE
            })
            .map_or(0, |sample| sample.bps)
    }
}

fn rate(bytes: u64, elapsed: Duration) -> u64 {
    (u128::from(bytes) * 1_000_000 / elapsed.as_micros().max(1)).min(u128::from(u64::MAX)) as u64
}

pub(super) async fn observe(
    profile: &str,
    session: u64,
    slot: u32,
    carrier: u64,
    peer: std::net::SocketAddr,
    dequeued: &AtomicU64,
    mut on_window: impl FnMut(DeliveryWindow),
) {
    let Some(mut previous) = current() else {
        std::future::pending::<()>().await;
        return;
    };
    let mut previous_dequeued = dequeued.load(Ordering::Relaxed);
    let mut previous_at = tokio::time::Instant::now();
    let mut tick = tokio::time::interval_at(previous_at + WINDOW, WINDOW);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let Some(next) = current() else {
            std::future::pending::<()>().await;
            return;
        };
        let now = tokio::time::Instant::now();
        let payload = dequeued.load(Ordering::Relaxed);
        let delta = |old: Option<u64>, new: Option<u64>| new?.checked_sub(old?);
        let elapsed = now.duration_since(previous_at);
        let acked = next.bytes_acked.saturating_sub(previous.bytes_acked);
        let busy_us = delta(previous.busy_us, next.busy_us);
        let demand = payload.saturating_sub(previous_dequeued);
        log::debug!(target: TARGET,
            "TCP_SLOT profile={profile:?} session={session} slot={slot} carrier={carrier} peer={peer} interval_ms={} qeli_dequeued_bytes={} tcp_acked_bytes={} tcp_retrans_segments={} tcp_retrans_bytes={:?} notsent_bytes={} rtt_us={} min_rtt_us={} busy_us={:?} rwnd_limited_us={:?} snd_wnd_bytes={:?}",
            elapsed.as_millis(), demand, acked,
            next.total_retrans.wrapping_sub(previous.total_retrans),
            delta(previous.bytes_retrans, next.bytes_retrans), next.notsent_bytes, next.rtt_us,
            next.min_rtt_us, busy_us,
            delta(previous.rwnd_limited_us, next.rwnd_limited_us), next.snd_wnd_bytes,
        );
        on_window(DeliveryWindow {
            carrier,
            at: now,
            bps: rate(acked, elapsed),
            rtt_us: next.rtt_us,
            notsent_bytes: next.notsent_bytes,
            delivered_under_load: demand >= 128 * 1024 && acked >= 128 * 1024,
            busy: busy_us.is_some_and(|busy| u128::from(busy) * 3 >= elapsed.as_micros() * 2)
                && (demand >= 16 * 1024 || next.notsent_bytes >= 16 * 1024),
            bad_windows: 0,
        });
        previous = next;
        previous_dequeued = payload;
        previous_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_defaults_on_and_keeps_the_existing_explicit_override() {
        use std::ffi::OsStr;
        assert!(enabled_override(None));
        assert!(enabled_override(Some(OsStr::new("1"))));
        assert!(!enabled_override(Some(OsStr::new("0"))));
        assert!(!enabled_override(Some(OsStr::new(""))));
        assert!(!enabled_override(Some(OsStr::new("invalid"))));
    }

    #[test]
    fn tcp_info_respects_old_kernel_length_and_preserves_units() {
        let mut bytes = [0u8; 232];
        bytes[68..72].copy_from_slice(&35_000u32.to_ne_bytes());
        bytes[120..128].copy_from_slice(&123_456u64.to_ne_bytes());
        bytes[228..232].copy_from_slice(&4096u32.to_ne_bytes());
        assert!(parse_tcp_info(&bytes[..104]).is_none());
        let old = parse_tcp_info(&bytes[..192]).unwrap();
        assert_eq!(old.rtt_us, 35_000);
        assert_eq!(old.bytes_acked, 123_456);
        assert_eq!(old.snd_wnd_bytes, None);
        assert_eq!(old.bytes_retrans, None);
        assert_eq!(parse_tcp_info(&bytes).unwrap().snd_wnd_bytes, Some(4096));
    }

    #[test]
    fn only_persistent_loaded_outlier_requests_a_candidate_and_rejects_a_slow_probe() {
        let mut health = Health::default();
        let base = Instant::now();
        let window = |number: u32, carrier, bps, busy| DeliveryWindow {
            at: base + WINDOW * number,
            carrier,
            bps,
            rtt_us: if carrier == 10 { 18_000 } else { 36_000 },
            notsent_bytes: 0,
            busy,
            delivered_under_load: busy,
            bad_windows: 0,
        };
        for number in 0..3 {
            assert!(health
                .record(0, window(number, 10, 200_000, true))
                .is_none());
            assert!(health
                .record(1, window(number, 20, 200_000, true))
                .is_none());
        }
        for number in 3..6 {
            assert!(health
                .record(0, window(number, 10, 1_000_000, true))
                .is_none());
            assert!(health.record(1, window(number, 20, 10, false)).is_none());
        }
        for number in 6..8 {
            assert!(health
                .record(0, window(number, 10, 1_000_000, true))
                .is_none());
            assert!(health
                .record(1, window(number, 20, 650_000, true))
                .is_none());
        }
        assert!(health.record(0, window(8, 10, 1_000_000, true)).is_none());
        let request = health.record(1, window(8, 20, 650_000, true)).unwrap();
        assert!(health
            .claim(Request {
                nonce: request.nonce ^ 1,
                ..request
            })
            .is_none());
        let candidate = health.claim(request).unwrap();
        assert!(health.claim(request).is_none());
        assert_eq!(candidate.old_carrier, 20);
        assert!(!candidate.improves(256 * 1024, Duration::from_secs(1), 0));
        assert!(candidate.improves(256 * 1024, Duration::from_millis(100), 300_000));
        assert!(!candidate.improves(256 * 1024, Duration::from_millis(100), 2_000_000));
    }

    fn health_window(at: Instant, carrier: u64, bps: u64, rtt_us: u32) -> DeliveryWindow {
        DeliveryWindow {
            carrier,
            at,
            bps,
            rtt_us,
            notsent_bytes: 0,
            busy: true,
            delivered_under_load: u128::from(bps) * WINDOW.as_micros() / 1_000_000 >= 128 * 1024,
            bad_windows: 0,
        }
    }

    fn queued_health_window(at: Instant, carrier: u64, bps: u64, rtt_us: u32) -> DeliveryWindow {
        DeliveryWindow {
            notsent_bytes: 256 * 1024,
            ..health_window(at, carrier, bps, rtt_us)
        }
    }

    #[test]
    fn severe_loaded_outlier_prepares_after_two_windows_but_keeps_quality_gate_and_cooldown() {
        let mut health = Health::default();
        let base = Instant::now();
        let mut offered = None;
        for n in 0..2 {
            let at = base + WINDOW * n;
            assert!(health
                .record(0, health_window(at, 10, 1_000_000, 20_000))
                .is_none());
            offered = health.record(1, queued_health_window(at, 20, 200_000, 100_000));
            assert_eq!(offered.is_some(), n == 1);
        }
        let candidate = health.claim(offered.unwrap()).unwrap();
        assert!(!candidate.improves(256 * 1024, Duration::from_secs(2), 200_000));
        assert!(!candidate.improves(256 * 1024, Duration::from_millis(100), 2_000_000));
        assert!(candidate.improves(256 * 1024, Duration::from_millis(100), 200_000));
        for n in 2..20 {
            let at = base + WINDOW * n;
            assert!(health
                .record(0, health_window(at, 10, 1_000_000, 20_000))
                .is_none());
            assert!(health
                .record(1, health_window(at, 20, 200_000, 100_000))
                .is_none());
        }
    }

    #[test]
    fn normal_network_rtt_with_a_large_kernel_send_queue_still_prepares_early() {
        let mut health = Health::default();
        let base = Instant::now();
        for n in 0..2 {
            let at = base + WINDOW * n;
            assert!(health
                .record(0, health_window(at, 10, 1_000_000, 20_000))
                .is_none());
            let mut queued = health_window(at, 20, 200_000, 25_000);
            queued.notsent_bytes = 256 * 1024;
            let request = health.record(1, queued);
            assert_eq!(request.is_some(), n == 1);
        }
    }

    #[test]
    fn low_rate_without_unsent_backlog_or_moderate_loss_of_rate_keeps_three_window_hysteresis() {
        for (bps, rtt) in [(200_000, 25_000), (200_000, 100_000), (650_000, 100_000)] {
            let mut health = Health::default();
            let base = Instant::now();
            for n in 0..3 {
                let at = base + WINDOW * n;
                assert!(health
                    .record(0, health_window(at, 10, 1_000_000, 20_000))
                    .is_none());
                let request = health.record(1, health_window(at, 20, bps, rtt));
                assert_eq!(request.is_some(), n == 2);
            }
        }
    }

    #[test]
    fn a_transient_severe_window_does_not_reserve_a_candidate_or_accumulate_through_recovery() {
        let mut health = Health::default();
        let base = Instant::now();
        for (n, bps, rtt) in [
            (0, 200_000, 100_000),
            (1, 1_000_000, 20_000),
            (2, 200_000, 100_000),
        ] {
            let at = base + WINDOW * n;
            assert!(health
                .record(0, health_window(at, 10, 1_000_000, 20_000))
                .is_none());
            assert!(health
                .record(1, queued_health_window(at, 20, bps, rtt))
                .is_none());
            assert!(health.pending.is_none());
            assert!(health.last_request.is_none());
        }
        let at = base + WINDOW * 3;
        assert!(health
            .record(0, health_window(at, 10, 1_000_000, 20_000))
            .is_none());
        assert!(health
            .record(1, queued_health_window(at, 20, 200_000, 100_000))
            .is_some());
    }

    #[test]
    fn early_probe_does_not_carry_bad_windows_into_another_carrier_generation() {
        let mut health = Health::default();
        let base = Instant::now();
        for (n, carrier) in [(0, 20), (1, 21), (2, 21)] {
            let at = base + WINDOW * n;
            assert!(health
                .record(0, health_window(at, 10, 1_000_000, 20_000))
                .is_none());
            let request = health.record(1, queued_health_window(at, carrier, 200_000, 100_000));
            assert_eq!(request.is_some(), n == 2);
        }
    }

    #[test]
    fn early_probe_requires_the_unsent_threshold_even_when_rtt_is_high() {
        for backlog in [128 * 1024 - 1, 128 * 1024] {
            let mut health = Health::default();
            let base = Instant::now();
            for n in 0..2 {
                let at = base + WINDOW * n;
                assert!(health
                    .record(0, health_window(at, 10, 1_000_000, 20_000))
                    .is_none());
                let mut queued = health_window(at, 20, 200_000, 100_000);
                queued.notsent_bytes = backlog;
                assert_eq!(
                    health.record(1, queued).is_some(),
                    n == 1 && backlog >= 128 * 1024
                );
            }
        }
    }

    #[tokio::test]
    async fn tcp_info_reports_actual_ack_progress_on_a_linux_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut sender = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut receiver, _) = listener.accept().await.unwrap();
        let observed = sender.as_fd().try_clone_to_owned().unwrap();
        let baseline = sample(&observed).unwrap().bytes_acked;
        let data = [3u8; 8192];
        sender.write_all(&data).await.unwrap();
        let mut received = [0u8; 8192];
        receiver.read_exact(&mut received).await.unwrap();
        assert_eq!(data, received);
        tokio::time::timeout(Duration::from_secs(2), async {
            while sample(&observed).unwrap().bytes_acked < baseline + data.len() as u64 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
