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
pub(super) const CONFIRMATION_BUDGET: Duration = Duration::from_millis(1500);
const MAX_AGE: Duration = Duration::from_millis(2500);
const COOLDOWN: Duration = Duration::from_secs(60);
const RETRY_BACKOFF: Duration = Duration::from_secs(5);

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
    bad_since: Option<Instant>,
    severe: bool,
}

#[derive(Clone, Copy)]
pub(super) struct Candidate {
    pub(super) request: Request,
    pub(super) old_carrier: u64,
    baseline_bps: u64,
    required_bad_windows: u8,
    outlier_since: Instant,
    at: Instant,
}

/// Preserve the legacy fixed-size probe. Kernel ACK samples separate its warm
/// transfer from startup and the client's encrypted receipt/decoder turnaround.
pub(super) struct ProbeDelivery {
    bytes: u64,
    elapsed: Duration,
    warm_bps: Option<u64>,
}

impl ProbeDelivery {
    pub(super) fn whole_bps(&self) -> u64 {
        rate(self.bytes, self.elapsed)
    }
    pub(super) fn warm_bps(&self) -> Option<u64> {
        self.warm_bps
    }
}

pub(super) struct ProbeProgress {
    wire_bytes: u64,
    warm_start: Option<(u64, Duration)>,
    warm_bps: Option<u64>,
    complete: bool,
}

impl ProbeProgress {
    pub(super) fn new(wire_bytes: u64) -> Self {
        Self {
            wire_bytes,
            warm_start: None,
            warm_bps: None,
            complete: false,
        }
    }

    pub(super) fn record(&mut self, acked: u64, at: Duration) {
        if self.complete {
            return;
        }
        let acked = acked.min(self.wire_bytes);
        if acked >= self.wire_bytes {
            self.complete = true;
            if let Some((before, start)) = self.warm_start {
                let bytes = acked.saturating_sub(before);
                let elapsed = at.saturating_sub(start);
                // Do not infer capacity from one tiny, coalesced ACK burst.
                if bytes >= 128 * 1024 && elapsed >= Duration::from_millis(100) {
                    self.warm_bps = Some(rate(bytes, elapsed));
                }
            }
        } else if self.warm_start.is_none()
            && acked >= 64 * 1024
            && self.wire_bytes - acked >= 128 * 1024
        {
            self.warm_start = Some((acked, at));
        }
    }

    pub(super) fn delivery(self, bytes: u64, elapsed: Duration) -> ProbeDelivery {
        ProbeDelivery {
            bytes,
            elapsed,
            warm_bps: self.warm_bps,
        }
    }
}

impl Candidate {
    pub(super) fn improves(self, probe: &ProbeDelivery, current_bps: u64, severe: bool) -> bool {
        let reference = self.baseline_bps.max(current_bps);
        let whole = u128::from(probe.whole_bps());
        let reference = u128::from(reference);
        whole * 2 > reference * 3
            // A cold but accelerating carrier may have a modest whole-probe
            // advantage. Only a still severely queued outlier may use this path:
            // demand >10% overall gain AND >50% gain over a measured warm tail.
            || severe && whole * 10 > reference * 11
                && probe.warm_bps.is_some_and(|bps| u128::from(bps) * 2 > reference * 3)
    }
}

/// Own the request through COMMIT. Cancellation, timeout, and every early return
/// rearm a bounded retry without retiring the old carrier or stranding a lease.
pub(super) struct Attempt<'a> {
    health: &'a std::sync::Mutex<Health>,
    pub(super) candidate: Candidate,
    finished: bool,
}

impl<'a> Attempt<'a> {
    pub(super) fn claim(health: &'a std::sync::Mutex<Health>, request: Request) -> Option<Self> {
        let candidate = crate::util::lock_or_recover(health, "tcp_slot::claim").claim(request)?;
        Some(Self {
            health,
            candidate,
            finished: false,
        })
    }
    pub(super) fn committed(mut self) {
        crate::util::lock_or_recover(self.health, "tcp_slot::committed").complete(
            self.candidate,
            true,
            Instant::now(),
        );
        self.finished = true;
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.finished {
            crate::util::lock_or_recover(self.health, "tcp_slot::aborted").complete(
                self.candidate,
                false,
                Instant::now(),
            );
        }
    }
}

/// Preparing a fresh carrier does not authorize replacing the current one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Confirmation {
    Waiting,
    Rejected,
    Confirmed(u64),
}

#[derive(Default)]
pub(super) struct Health {
    samples: BTreeMap<u32, DeliveryWindow>,
    pending: Option<Candidate>,
    last_request: Option<Instant>,
    request_delay: Duration,
    active: Option<Candidate>,
    failure_epoch: Option<(u32, u64, Instant)>,
    failures: u8,
}

impl Health {
    pub(super) fn record(&mut self, slot: u32, mut window: DeliveryWindow) -> Option<Request> {
        if let Some(expired) = self
            .pending
            .filter(|c| window.at.duration_since(c.at) > REQUEST_TTL)
        {
            self.complete(expired, false, window.at);
        }
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
        window.severe = window.busy && severe;
        if window.busy && slower {
            let previous = self
                .samples
                .get(&slot)
                .filter(|other| other.carrier == window.carrier && other.bad_windows > 0);
            window.bad_windows = previous.map_or(1, |other| other.bad_windows.saturating_add(1));
            window.bad_since = Some(
                previous
                    .and_then(|other| other.bad_since)
                    .unwrap_or(window.at),
            );
        }
        // A loaded, severely queued outlier can begin preparation after its first
        // bad window. Overlap the handshake with the next observation window;
        // confirmation() still requires two consecutive bad windows before COMMIT.
        // Moderate degradation retains three windows. The delivery probe, the
        // old-carrier drain barrier and bounded retry/success cooldown remain mandatory.
        let was_healthy = self.samples.get(&slot).is_some_and(|previous| {
            previous.carrier == window.carrier
                && previous.delivered_under_load
                && previous.bad_windows == 0
                && siblings
                    .get(siblings.len() / 2)
                    .is_some_and(|&(bps, _)| previous.bps >= bps.saturating_mul(3) / 4)
        });
        let early_prepare =
            severe && (window.bad_windows >= 2 || window.bad_windows == 1 && was_healthy);
        let offer = (window.bad_windows >= 3 || early_prepare)
            && self.pending.is_none()
            && self.active.is_none()
            && self
                .last_request
                .is_none_or(|at| window.at.duration_since(at) >= self.request_delay);
        let next = offer.then(|| Candidate {
            request: Request {
                slot,
                nonce: rand::random(),
            },
            old_carrier: window.carrier,
            baseline_bps: window.bps,
            required_bad_windows: if severe { 2 } else { 3 },
            outlier_since: window.bad_since.unwrap_or(window.at),
            at: window.at,
        });
        if offer && early_prepare && window.bad_windows < 3 {
            log::info!(target: TARGET,
                "TCP_SLOT_EARLY_PREPARE slot={} carrier={} bad_windows={} rate_Bps={} rtt_us={} notsent_bytes={}",
                slot, window.carrier, window.bad_windows, window.bps, window.rtt_us, window.notsent_bytes);
        }
        self.samples.insert(slot, window);
        if let Some(candidate) = next {
            self.pending = Some(candidate);
            self.last_request = Some(candidate.at);
            self.request_delay = REQUEST_TTL;
        }
        next.map(|candidate| candidate.request)
    }

    pub(super) fn claim(&mut self, request: Request) -> Option<Candidate> {
        let candidate = self.pending?;
        if candidate.request != request || candidate.at.elapsed() > REQUEST_TTL {
            return None;
        }
        self.active = self.pending.take();
        self.active
    }

    fn complete(&mut self, candidate: Candidate, committed: bool, now: Instant) {
        let matches =
            |other: Candidate| other.request == candidate.request && other.at == candidate.at;
        if !self.active.is_some_and(matches) && !self.pending.is_some_and(matches) {
            return;
        }
        self.active = None;
        self.pending = None;
        self.last_request = Some(now);
        if committed {
            self.failures = 0;
            self.failure_epoch = None;
            self.request_delay = COOLDOWN;
        } else {
            let epoch = (
                candidate.request.slot,
                candidate.old_carrier,
                candidate.outlier_since,
            );
            self.failures = if self.failure_epoch == Some(epoch) {
                self.failures.saturating_add(1)
            } else {
                1
            };
            self.failure_epoch = Some(epoch);
            self.request_delay =
                (RETRY_BACKOFF * (1u32 << self.failures.saturating_sub(1).min(4))).min(COOLDOWN);
            log::info!(target: TARGET,
                "TCP_SLOT_RETRY_BACKOFF slot={} failures={} backoff_ms={}",
                candidate.request.slot, self.failures, self.request_delay.as_millis());
        }
    }

    pub(super) fn severely_degraded(&self, candidate: Candidate) -> bool {
        self.samples
            .get(&candidate.request.slot)
            .is_some_and(|sample| {
                sample.carrier == candidate.old_carrier
                    && sample.severe
                    && sample.bad_since == Some(candidate.outlier_since)
                    && sample.at.elapsed() <= MAX_AGE
            })
    }

    pub(super) fn confirmation(&self, candidate: Candidate) -> Confirmation {
        let Some(sample) = self.samples.get(&candidate.request.slot) else {
            return Confirmation::Rejected;
        };
        if sample.carrier != candidate.old_carrier
            || sample.at.elapsed() > MAX_AGE
            || sample.at < candidate.at
            || !sample.busy
            || sample.bad_windows == 0
            || sample.bad_since != Some(candidate.outlier_since)
        {
            return Confirmation::Rejected;
        }
        let required = if sample.severe {
            candidate.required_bad_windows
        } else {
            3
        };
        if sample.bad_windows < required {
            return Confirmation::Waiting;
        }
        Confirmation::Confirmed(sample.bps)
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
            bad_since: None,
            severe: false,
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
            bad_since: None,
            severe: false,
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
        assert!(!candidate.improves(
            &ProbeDelivery {
                bytes: 256 * 1024,
                elapsed: Duration::from_secs(1),
                warm_bps: None
            },
            0,
            false
        ));
        assert!(candidate.improves(
            &ProbeDelivery {
                bytes: 256 * 1024,
                elapsed: Duration::from_millis(100),
                warm_bps: None
            },
            300_000,
            false
        ));
        assert!(!candidate.improves(
            &ProbeDelivery {
                bytes: 256 * 1024,
                elapsed: Duration::from_millis(100),
                warm_bps: None
            },
            2_000_000,
            false
        ));
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
            bad_since: None,
            severe: false,
        }
    }

    fn queued_health_window(at: Instant, carrier: u64, bps: u64, rtt_us: u32) -> DeliveryWindow {
        DeliveryWindow {
            notsent_bytes: 256 * 1024,
            ..health_window(at, carrier, bps, rtt_us)
        }
    }

    fn prime_healthy_slot(health: &mut Health, at: Instant) {
        assert!(health
            .record(0, health_window(at - WINDOW, 10, 1_000_000, 20_000))
            .is_none());
        assert!(health
            .record(1, health_window(at - WINDOW, 20, 1_000_000, 25_000))
            .is_none());
    }

    #[test]
    fn an_unmeasured_carrier_keeps_two_window_severe_confirmation_before_preparation() {
        let mut health = Health::default();
        let base = Instant::now();
        health.record(0, health_window(base, 10, 1_000_000, 20_000));
        assert!(health
            .record(1, queued_health_window(base, 20, 200_000, 100_000))
            .is_none());
        health.record(0, health_window(base + WINDOW, 10, 1_000_000, 20_000));
        let request = health
            .record(1, queued_health_window(base + WINDOW, 20, 200_000, 100_000))
            .unwrap();
        let candidate = health.claim(request).unwrap();
        assert_eq!(
            health.confirmation(candidate),
            Confirmation::Confirmed(200_000)
        );
    }

    #[test]
    fn severe_outlier_prepares_early_but_still_requires_two_windows_and_a_faster_probe() {
        let mut health = Health::default();
        let base = Instant::now();
        prime_healthy_slot(&mut health, base);
        health.record(0, health_window(base, 10, 1_000_000, 20_000));
        let request = health
            .record(1, queued_health_window(base, 20, 200_000, 100_000))
            .unwrap();
        let candidate = health.claim(request).unwrap();
        assert_eq!(health.confirmation(candidate), Confirmation::Waiting);
        assert!(
            health.claim(request).is_none(),
            "the request nonce remains single-use"
        );
        health.record(0, health_window(base + WINDOW, 10, 1_000_000, 20_000));
        assert!(health
            .record(1, queued_health_window(base + WINDOW, 20, 200_000, 100_000))
            .is_none());
        assert_eq!(
            health.confirmation(candidate),
            Confirmation::Confirmed(200_000)
        );
        assert!(!candidate.improves(
            &ProbeDelivery {
                bytes: 256 * 1024,
                elapsed: Duration::from_secs(2),
                warm_bps: None
            },
            200_000,
            false
        ));
        assert!(!candidate.improves(
            &ProbeDelivery {
                bytes: 256 * 1024,
                elapsed: Duration::from_millis(100),
                warm_bps: None
            },
            2_000_000,
            false
        ));
        assert!(candidate.improves(
            &ProbeDelivery {
                bytes: 256 * 1024,
                elapsed: Duration::from_millis(100),
                warm_bps: None
            },
            200_000,
            false
        ));
        for n in 2..20 {
            let at = base + WINDOW * n;
            assert!(health
                .record(0, health_window(at, 10, 1_000_000, 20_000))
                .is_none());
            assert!(health
                .record(1, queued_health_window(at, 20, 200_000, 100_000))
                .is_none());
        }
    }

    #[test]
    fn normal_network_rtt_with_a_large_kernel_send_queue_can_prepare_before_confirmation() {
        let mut health = Health::default();
        let base = Instant::now();
        prime_healthy_slot(&mut health, base);
        health.record(0, health_window(base, 10, 1_000_000, 20_000));
        let request = health
            .record(1, queued_health_window(base, 20, 200_000, 25_000))
            .unwrap();
        let candidate = health.claim(request).unwrap();
        assert_eq!(health.confirmation(candidate), Confirmation::Waiting);
        health.record(0, health_window(base + WINDOW, 10, 1_000_000, 20_000));
        health.record(1, queued_health_window(base + WINDOW, 20, 200_000, 25_000));
        assert_eq!(
            health.confirmation(candidate),
            Confirmation::Confirmed(200_000)
        );
    }

    #[test]
    fn low_rate_without_unsent_backlog_or_moderate_loss_of_rate_keeps_three_window_hysteresis() {
        for (bps, rtt) in [(200_000, 25_000), (200_000, 100_000), (650_000, 100_000)] {
            let mut health = Health::default();
            let base = Instant::now();
            prime_healthy_slot(&mut health, base);
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
    fn transient_recovery_rejects_prepared_carrier_and_does_not_accumulate_bad_windows() {
        let mut health = Health::default();
        let base = Instant::now();
        prime_healthy_slot(&mut health, base);
        health.record(0, health_window(base, 10, 1_000_000, 20_000));
        let request = health
            .record(1, queued_health_window(base, 20, 200_000, 100_000))
            .unwrap();
        let candidate = health.claim(request).unwrap();
        health.record(0, health_window(base + WINDOW, 10, 1_000_000, 20_000));
        health.record(1, health_window(base + WINDOW, 20, 1_000_000, 20_000));
        assert_eq!(health.confirmation(candidate), Confirmation::Rejected);
        health.record(0, health_window(base + WINDOW * 2, 10, 1_000_000, 20_000));
        assert!(health
            .record(
                1,
                queued_health_window(base + WINDOW * 2, 20, 200_000, 100_000)
            )
            .is_none());
        assert_eq!(health.confirmation(candidate), Confirmation::Rejected);
    }

    #[test]
    fn recovered_attempts_retry_after_backoff_but_only_commit_consumes_full_cooldown() {
        let mut health = Health::default();
        let base = Instant::now();
        prime_healthy_slot(&mut health, base);
        health.record(0, health_window(base, 10, 1_000_000, 20_000));
        let request = health
            .record(1, queued_health_window(base, 20, 200_000, 100_000))
            .unwrap();
        let candidate = health.claim(request).unwrap();
        health.record(0, health_window(base + WINDOW, 10, 1_000_000, 20_000));
        health.record(1, health_window(base + WINDOW, 20, 1_000_000, 20_000));
        assert_eq!(health.confirmation(candidate), Confirmation::Rejected);
        health.complete(candidate, false, base + WINDOW);
        for n in 2..=5 {
            let at = base + WINDOW * n;
            health.record(0, health_window(at, 10, 1_000_000, 20_000));
            let retry = health.record(1, queued_health_window(at, 20, 200_000, 100_000));
            assert_eq!(retry.is_some(), n == 5, "retry time n={n}");
        }

        let mut health = Health::default();
        prime_healthy_slot(&mut health, base);
        health.record(0, health_window(base, 10, 1_000_000, 20_000));
        let request = health
            .record(1, queued_health_window(base, 20, 200_000, 100_000))
            .unwrap();
        let candidate = health.claim(request).unwrap();
        health.record(0, health_window(base + WINDOW, 10, 1_000_000, 20_000));
        health.record(1, queued_health_window(base + WINDOW, 20, 200_000, 100_000));
        assert_eq!(
            health.confirmation(candidate),
            Confirmation::Confirmed(200_000)
        );
        health.complete(candidate, true, base + WINDOW);
        health.record(0, health_window(base + WINDOW * 2, 10, 1_000_000, 20_000));
        health.record(1, health_window(base + WINDOW * 2, 20, 1_000_000, 20_000));
        assert_eq!(health.confirmation(candidate), Confirmation::Rejected);
        assert_eq!(health.last_request, Some(base + WINDOW));
        for n in 3..9 {
            let at = base + WINDOW * n;
            health.record(0, health_window(at, 10, 1_000_000, 20_000));
            assert!(health
                .record(1, queued_health_window(at, 20, 200_000, 100_000))
                .is_none());
        }
    }

    #[test]
    fn a_moderate_second_window_keeps_three_window_confirmation() {
        let mut health = Health::default();
        let base = Instant::now();
        prime_healthy_slot(&mut health, base);
        health.record(0, health_window(base, 10, 1_000_000, 20_000));
        let request = health
            .record(1, queued_health_window(base, 20, 200_000, 100_000))
            .unwrap();
        let candidate = health.claim(request).unwrap();
        for n in 1..3 {
            let at = base + WINDOW * n;
            health.record(0, health_window(at, 10, 1_000_000, 20_000));
            health.record(1, queued_health_window(at, 20, 650_000, 100_000));
            assert_eq!(
                health.confirmation(candidate),
                if n == 1 {
                    Confirmation::Waiting
                } else {
                    Confirmation::Confirmed(650_000)
                }
            );
        }
    }

    #[test]
    fn confirmation_rejects_another_carrier_generation_stale_sample_or_idle_slot() {
        for reason in 0..3 {
            let mut health = Health::default();
            let base = Instant::now();
            prime_healthy_slot(&mut health, base);
            health.record(0, health_window(base, 10, 1_000_000, 20_000));
            let request = health
                .record(1, queued_health_window(base, 20, 200_000, 100_000))
                .unwrap();
            let candidate = health.claim(request).unwrap();
            let sample = health.samples.get_mut(&1).unwrap();
            sample.bad_windows = 2;
            match reason {
                0 => sample.carrier += 1,
                1 => sample.at = base - MAX_AGE - Duration::from_millis(1),
                _ => sample.busy = false,
            }
            assert_eq!(health.confirmation(candidate), Confirmation::Rejected);
        }
    }

    #[test]
    fn early_probe_requires_the_unsent_threshold_even_when_rtt_is_high() {
        for backlog in [128 * 1024 - 1, 128 * 1024] {
            let mut health = Health::default();
            let base = Instant::now();
            prime_healthy_slot(&mut health, base);
            for n in 0..2 {
                let at = base + WINDOW * n;
                assert!(health
                    .record(0, health_window(at, 10, 1_000_000, 20_000))
                    .is_none());
                let mut queued = health_window(at, 20, 200_000, 100_000);
                queued.notsent_bytes = backlog;
                assert_eq!(
                    health.record(1, queued).is_some(),
                    n == 0 && backlog >= 128 * 1024
                );
            }
        }
    }

    #[test]
    fn warm_probe_requires_measured_ack_progress_and_a_material_whole_probe_gain() {
        let base = Instant::now();
        let candidate = Candidate {
            request: Request { slot: 1, nonce: 7 },
            old_carrier: 20,
            baseline_bps: 500_000,
            required_bad_windows: 2,
            outlier_since: base,
            at: base,
        };
        let mut progress = ProbeProgress::new(320 * 1024);
        progress.record(32 * 1024, Duration::from_millis(100));
        progress.record(80 * 1024, Duration::from_millis(300));
        progress.record(200 * 1024, Duration::from_millis(400));
        progress.record(320 * 1024, Duration::from_millis(500));
        let probe = progress.delivery(320 * 1024, Duration::from_millis(550));
        assert!(probe.whole_bps() < 750_000);
        assert_eq!(probe.warm_bps(), Some(1_228_800));
        assert!(candidate.improves(&probe, 500_000, true));
        assert!(
            !candidate.improves(&probe, 500_000, false),
            "moderate faults keep full-probe threshold"
        );
        assert!(
            !candidate.improves(&probe, 1_000_000, true),
            "old recovery raises the comparison floor"
        );
        let poor_whole = ProbeDelivery {
            bytes: 320 * 1024,
            elapsed: Duration::from_secs(1),
            warm_bps: probe.warm_bps(),
        };
        assert!(!candidate.improves(&poor_whole, 500_000, true));
    }

    #[test]
    fn coalesced_ack_or_insufficient_tail_cannot_bypass_full_probe_threshold() {
        for events in [
            vec![(320 * 1024, 100)],
            vec![(250 * 1024, 100), (320 * 1024, 300)],
            vec![(80 * 1024, 100), (320 * 1024, 150)],
            vec![(80 * 1024, 100), (200 * 1024, 300)],
        ] {
            let mut progress = ProbeProgress::new(320 * 1024);
            for (bytes, ms) in events {
                progress.record(bytes, Duration::from_millis(ms));
            }
            assert_eq!(
                progress
                    .delivery(320 * 1024, Duration::from_secs(1))
                    .warm_bps(),
                None
            );
        }
    }

    fn offer_at(health: &mut Health, at: Instant) -> Option<Request> {
        health.record(0, health_window(at, 10, 1_000_000, 20_000));
        health.record(1, queued_health_window(at, 20, 200_000, 100_000))
    }

    #[test]
    fn rejected_candidates_back_off_exponentially_and_stale_completions_do_not_rearm() {
        let mut health = Health::default();
        let mut at = Instant::now();
        prime_healthy_slot(&mut health, at);
        let first = offer_at(&mut health, at).unwrap();
        let mut candidate = health.claim(first).unwrap();
        let old = candidate;
        assert!(health.claim(first).is_none());
        for backoff in [5, 10, 20, 40, 60, 60] {
            health.complete(candidate, false, at);
            assert_eq!(health.request_delay, Duration::from_secs(backoff));
            let mut next = None;
            for step in 1..=backoff {
                next = offer_at(&mut health, at + Duration::from_secs(step));
                assert_eq!(next.is_some(), step == backoff);
            }
            at += Duration::from_secs(backoff);
            candidate = health.claim(next.unwrap()).unwrap();
            if candidate.request != old.request {
                health.complete(old, false, at);
                assert_eq!(health.active.unwrap().request, candidate.request);
            }
        }
        health.complete(candidate, true, at);
        assert_eq!(health.failures, 0);
        assert_eq!(health.request_delay, COOLDOWN);
        for step in 1..60 {
            assert!(offer_at(&mut health, at + Duration::from_secs(step)).is_none());
        }
        assert!(offer_at(&mut health, at + COOLDOWN).is_some());
    }

    #[test]
    fn lost_requests_expire_and_cancellation_releases_only_its_own_attempt() {
        let at = Instant::now();
        let mut health = Health::default();
        prime_healthy_slot(&mut health, at);
        let request = offer_at(&mut health, at).unwrap();
        for step in 1..=21 {
            assert!(offer_at(&mut health, at + Duration::from_secs(step)).is_none());
        }
        assert!(health.claim(request).is_none());
        for step in 22..26 {
            assert!(offer_at(&mut health, at + Duration::from_secs(step)).is_none());
        }
        assert!(offer_at(&mut health, at + Duration::from_secs(26)).is_some());

        let mut health = Health::default();
        prime_healthy_slot(&mut health, at);
        let request = offer_at(&mut health, at).unwrap();
        let mutex = std::sync::Mutex::new(health);
        let attempt = Attempt::claim(&mutex, request).unwrap();
        assert!(Attempt::claim(&mutex, request).is_none());
        drop(attempt); // also runs when an async probe is cancelled or times out
        let mut health = mutex.lock().unwrap();
        assert!(health.active.is_none());
        assert_eq!(health.request_delay, RETRY_BACKOFF);
        assert!(offer_at(&mut health, at + Duration::from_secs(4)).is_none());
        assert!(offer_at(&mut health, at + Duration::from_secs(6)).is_some());
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
