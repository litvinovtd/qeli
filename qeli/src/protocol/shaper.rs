//! Traffic-flow shaping (DPI-AUDIT 6.1 / 6.2): make an idle or bursty tunnel
//! look less like a constant full-MTU bulk transfer and more like interactive
//! browsing.
//!
//! Phase 1 (this module): an idle **cover-traffic scheduler**. When real data is
//! not flowing, cover packets are emitted at gaps sampled from an exponential
//! (Poisson-process) distribution rather than a fixed heartbeat interval, with a
//! browsing-like size distribution, capped by a byte budget. Cover packets are
//! empty-payload encrypted records — the peer drops them exactly like a
//! heartbeat — so this is NOT a wire-format change.
//!
//! Properties this buys, vs the old fixed-interval heartbeat:
//!   * no fixed period → kills the regular keepalive beacon tell (6.2);
//!   * the link is never "dead air" while idle, and the gap distribution is the
//!     heavy-ish tail of a Poisson process rather than a metronome (6.1, partial).
//!
//! Phase 1 deliberately does NOT delay real packets (zero added latency); only
//! idle gaps are filled, and only up to `budget_bytes_per_sec`. Aggressive
//! real-packet pacing / full distribution-matching is Phase 2 (opt-in, validated
//! against a capture — a bad model can ADD a tell, so it stays separate).

use rand::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Resolved (already merged with defaults) shaping parameters for one direction.
#[derive(Debug, Clone)]
pub struct ShapingConfig {
    pub enabled: bool,
    /// Mean of the exponential inter-cover gap while idle.
    pub idle_gap_mean_ms: u64,
    /// Floor on a sampled gap (avoid a pathological burst of tiny cover packets).
    pub idle_gap_min_ms: u64,
    /// Cap on a sampled gap (avoid an effectively-dead link on a long tail draw).
    pub idle_gap_max_ms: u64,
    /// Cover-traffic budget; 0 disables cover emission even when `enabled`.
    pub budget_bytes_per_sec: u32,
    /// Cover packet payload-size sampling range (the encrypted record is a bit
    /// larger; the caller pads to roughly this).
    pub min_size: u16,
    pub max_size: u16,
    /// Stealth mode: rate-cap the data plane + run cover UNDER LOAD (not just
    /// idle), so the small cover packets mix into the rate-capped full-MTU stream
    /// and break the "download" size+timing tell. Trades throughput for DPI cover.
    pub stealth: bool,
    /// Data-plane rate cap (Mbps) applied in stealth mode.
    pub stealth_rate_mbps: u32,
}

impl Default for ShapingConfig {
    fn default() -> Self {
        // Browsing-ish idle think-time, ~16 KiB/s cover ceiling, small-ish cover
        // packets. Off unless explicitly enabled.
        ShapingConfig {
            enabled: false,
            idle_gap_mean_ms: 700,
            idle_gap_min_ms: 40,
            idle_gap_max_ms: 6_000,
            budget_bytes_per_sec: 16 * 1024,
            min_size: 64,
            max_size: 1024,
            stealth: false,
            stealth_rate_mbps: 2,
        }
    }
}

/// Pick the next absolute heartbeat gap in one shot. Sampling around the configured
/// interval avoids the old interval-tick + post-tick sleep interaction that quantized
/// a 15-second heartbeat into an almost perfect 30-second beacon.
pub fn randomized_heartbeat_delay(interval: Duration, jitter: Duration) -> Duration {
    let base_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
    let jitter_ms = u64::try_from(jitter.as_millis())
        .unwrap_or(u64::MAX)
        .min(base_ms);
    if jitter_ms == 0 {
        return interval;
    }
    let low = base_ms.saturating_sub(jitter_ms);
    let high = base_ms.saturating_add(jitter_ms);
    Duration::from_millis(rand::rng().random_range(low..=high))
}
/// Maximum authenticated receive silence tolerated while the peer promises liveness
/// records. Shaping replaces heartbeat, so its configured maximum gap plus one complete
/// token-bucket refill is the cadence that matters. The multiplier tolerates two lost
/// records; the floor avoids flapping on short schedules and lossy mobile links.
pub fn liveness_deadline(
    heartbeat_enabled: bool,
    heartbeat_interval: Duration,
    heartbeat_jitter: Duration,
    shaping_enabled: bool,
    shaping_gap_max: Duration,
) -> Option<Duration> {
    let promised_gap = if shaping_enabled {
        shaping_gap_max.saturating_add(Duration::from_secs(1))
    } else if heartbeat_enabled {
        heartbeat_interval.saturating_add(heartbeat_jitter)
    } else {
        return None;
    };
    Some(promised_gap.saturating_mul(3).max(Duration::from_secs(30)))
}

/// One direction's aggregate cover-traffic token bucket. Bonded TCP streams share this object,
/// so `budget_bytes_per_sec` remains a session budget instead of multiplying by stream count.
pub struct CoverBudget {
    rate: f64,
    tokens: f64,
    last_refill: Instant,
}

impl CoverBudget {
    fn new(bytes_per_sec: u32, now: Instant) -> Self {
        let rate = f64::from(bytes_per_sec);
        Self {
            rate,
            tokens: rate,
            last_refill: now,
        }
    }

    fn try_spend(&mut self, bytes: usize, now: Instant) -> bool {
        if self.rate <= 0.0 {
            return false;
        }
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        if self.tokens < bytes as f64 {
            return false;
        }
        self.tokens -= bytes as f64;
        true
    }
}

pub type SharedCoverBudget = Arc<Mutex<CoverBudget>>;

/// Idle cover-traffic scheduler. Stateful (carries a token-bucket budget); one
/// per direction/stream. Cheap to clone the config into.
pub struct Shaper {
    cfg: ShapingConfig,
    local_cover_budget: CoverBudget,
    shared_cover_budget: Option<SharedCoverBudget>,
    // Separate token bucket (bits) for the stealth data-plane rate cap.
    rate_tokens: f64,
    rate_last: Instant,
}

impl Shaper {
    pub fn new(cfg: ShapingConfig, now: Instant) -> Self {
        let local_cover_budget = CoverBudget::new(cfg.budget_bytes_per_sec, now);
        Shaper {
            cfg,
            local_cover_budget,
            shared_cover_budget: None,
            rate_tokens: 0.0,
            rate_last: now,
        }
    }

    pub fn shared_budget(cfg: &ShapingConfig, now: Instant) -> SharedCoverBudget {
        Arc::new(Mutex::new(CoverBudget::new(cfg.budget_bytes_per_sec, now)))
    }

    pub fn with_shared_budget(mut self, budget: SharedCoverBudget) -> Self {
        self.shared_cover_budget = Some(budget);
        self
    }

    /// Stealth data-plane pacing: account `bytes` against the `stealth_rate_mbps`
    /// cap and return how long to sleep before sending (Duration::ZERO if under
    /// budget or stealth is off). Used by the client to throttle its uplink; the
    /// server uses its own aggregate RateBucket. Carries a deficit so bursts still
    /// average to the cap.
    pub fn stealth_pace(&mut self, bytes: usize, now: Instant) -> Duration {
        if !self.stealth() {
            return Duration::ZERO;
        }
        let rate_bps = self.stealth_rate_mbps() as f64 * 1_000_000.0;
        let elapsed = now.duration_since(self.rate_last).as_secs_f64();
        self.rate_last = now;
        self.rate_tokens = (self.rate_tokens + elapsed * rate_bps).min(rate_bps);
        // Floor the deficit at one second of debt (symmetric with the positive cap and
        // the 1.0s sleep clamp below). Without it, one anomalously large `bytes` drives
        // rate_tokens arbitrarily negative and stalls the pacer for many seconds while
        // the sleep is still clamped to 1s — the debt and the pause drift apart. Normal
        // MTU-sized writes never approach -rate_bps, so steady-state pacing is unchanged.
        self.rate_tokens = (self.rate_tokens - (bytes as f64) * 8.0).max(-rate_bps);
        if self.rate_tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((-self.rate_tokens / rate_bps).min(1.0))
        }
    }

    #[inline]
    pub fn enabled(&self) -> bool {
        self.cfg.enabled && self.cfg.budget_bytes_per_sec > 0
    }

    /// Stealth mode active: rate-cap + cover-under-load. Implies `enabled`.
    #[inline]
    pub fn stealth(&self) -> bool {
        self.enabled() && self.cfg.stealth
    }

    /// Data-plane rate cap (Mbps) for stealth mode (≥1).
    #[inline]
    pub fn stealth_rate_mbps(&self) -> u32 {
        self.cfg.stealth_rate_mbps.max(1)
    }

    /// Sample the delay until the next cover opportunity (exponential, clamped to
    /// `[idle_gap_min_ms, idle_gap_max_ms]`). The exponential tail is what makes
    /// the schedule non-periodic — no fixed beacon.
    pub fn next_gap(&mut self, rng: &mut impl Rng) -> Duration {
        let mean = self.cfg.idle_gap_mean_ms.max(1) as f64;
        // Inverse-CDF of Exp(1/mean): -mean * ln(1-u), u in [0,1).
        let u: f64 = rng.random::<f64>();
        let sampled = -mean * (1.0 - u).max(f64::MIN_POSITIVE).ln();
        let lo = self.cfg.idle_gap_min_ms as f64;
        let hi = self.cfg.idle_gap_max_ms.max(self.cfg.idle_gap_min_ms) as f64;
        Duration::from_millis(sampled.clamp(lo, hi) as u64)
    }

    /// Sample a cover packet payload size in `[min_size, max_size]`.
    pub fn next_size(&mut self, rng: &mut impl Rng) -> usize {
        let lo = self.cfg.min_size;
        let hi = self.cfg.max_size.max(self.cfg.min_size);
        if hi == lo {
            return lo as usize;
        }
        rng.random_range(lo..=hi) as usize
    }

    /// Token-bucket check+spend for `bytes` of cover traffic at `now`. Returns
    /// `true` if the budget allowed it (and deducts), `false` if over budget (the
    /// caller should skip this cover packet — real traffic, which is not metered
    /// here, will keep the link alive anyway).
    pub fn try_spend(&mut self, bytes: usize, now: Instant) -> bool {
        if let Some(shared) = &self.shared_cover_budget {
            return shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .try_spend(bytes, now);
        }
        self.local_cover_budget.try_spend(bytes, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ShapingConfig {
        ShapingConfig {
            enabled: true,
            idle_gap_mean_ms: 500,
            idle_gap_min_ms: 50,
            idle_gap_max_ms: 4000,
            budget_bytes_per_sec: 8192,
            min_size: 64,
            max_size: 512,
            stealth: false,
            stealth_rate_mbps: 2,
        }
    }

    #[test]
    fn gaps_stay_in_bounds_and_vary() {
        let mut s = Shaper::new(cfg(), Instant::now());
        let mut rng = rand::rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let g = s.next_gap(&mut rng).as_millis() as u64;
            assert!((50..=4000).contains(&g), "gap {g} out of bounds");
            seen.insert(g);
        }
        // Non-periodic: a fixed-interval beacon would yield one value.
        assert!(
            seen.len() > 50,
            "gaps must vary (non-periodic), got {} distinct",
            seen.len()
        );
    }

    #[test]
    fn sizes_stay_in_bounds() {
        let mut s = Shaper::new(cfg(), Instant::now());
        let mut rng = rand::rng();
        for _ in 0..200 {
            let sz = s.next_size(&mut rng);
            assert!((64..=512).contains(&sz));
        }
    }

    #[test]
    fn budget_caps_cover_traffic() {
        let now = Instant::now();
        let mut s = Shaper::new(cfg(), now);
        // Bucket starts at ~1s (8192 B). Spend it down; further spends in the same
        // instant must be refused (no time elapsed → no refill).
        let mut allowed = 0;
        for _ in 0..100 {
            if s.try_spend(512, now) {
                allowed += 1;
            }
        }
        assert!(
            allowed <= 16,
            "1s budget of 8192B / 512B = 16 packets max, got {allowed}"
        );
        assert!(
            allowed >= 15,
            "should allow ~the full first-second budget, got {allowed}"
        );
    }

    #[test]
    fn shared_budget_is_aggregate_across_stream_shapers() {
        let now = Instant::now();
        let config = cfg();
        let budget = Shaper::shared_budget(&config, now);
        let mut first = Shaper::new(config.clone(), now).with_shared_budget(budget.clone());
        let mut second = Shaper::new(config, now).with_shared_budget(budget);
        let mut allowed = 0;
        for index in 0..100 {
            let accepted = if index % 2 == 0 {
                first.try_spend(512, now)
            } else {
                second.try_spend(512, now)
            };
            allowed += usize::from(accepted);
        }
        assert_eq!(
            allowed, 16,
            "two streams must share one 8192-byte initial budget"
        );
    }

    #[test]
    fn disabled_when_zero_budget() {
        let mut c = cfg();
        c.budget_bytes_per_sec = 0;
        let s = Shaper::new(c, Instant::now());
        assert!(!s.enabled());
    }

    #[test]
    fn liveness_uses_the_actual_promised_cadence() {
        assert_eq!(
            liveness_deadline(
                true,
                Duration::from_secs(15),
                Duration::from_secs(2),
                false,
                Duration::ZERO,
            ),
            Some(Duration::from_secs(51)),
        );
        assert_eq!(
            liveness_deadline(
                false,
                Duration::from_secs(15),
                Duration::ZERO,
                true,
                Duration::from_secs(120),
            ),
            Some(Duration::from_secs(363)),
        );
        assert_eq!(
            liveness_deadline(
                false,
                Duration::from_secs(15),
                Duration::ZERO,
                false,
                Duration::from_secs(120),
            ),
            None,
        );
    }

    #[test]
    fn heartbeat_delay_is_symmetric_and_bounded() {
        let interval = Duration::from_secs(15);
        let jitter = Duration::from_secs(2);
        let mut saw_below = false;
        let mut saw_above = false;
        for _ in 0..256 {
            let delay = randomized_heartbeat_delay(interval, jitter);
            assert!((Duration::from_secs(13)..=Duration::from_secs(17)).contains(&delay));
            saw_below |= delay < interval;
            saw_above |= delay > interval;
        }
        assert!(saw_below && saw_above);
        assert_eq!(
            randomized_heartbeat_delay(interval, Duration::ZERO),
            interval
        );
    }
}
