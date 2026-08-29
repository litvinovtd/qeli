//! Worker-lifetime server-side roaming observability.
//!
//! Client native cores expose their own attempt/fallback counters through FFI. These counters are
//! deliberately separate: they describe what the server actually authenticated and committed for
//! one profile, and remain available to the control socket without coupling the data plane to web.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct TcpRoamingSnapshot {
    pub attempts_total: u64,
    pub commits_total: u64,
    pub failures_total: u64,
    pub grace_expired_total: u64,
}

#[derive(Default)]
pub(crate) struct TcpRoamingMetrics {
    attempts_total: AtomicU64,
    commits_total: AtomicU64,
    failures_total: AtomicU64,
    grace_expired_total: AtomicU64,
}

impl TcpRoamingMetrics {
    #[cfg(feature = "experimental-roaming")]
    pub(crate) fn note_attempt(&self) {
        self.attempts_total.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "experimental-roaming")]
    pub(crate) fn note_commit(&self) {
        self.commits_total.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "experimental-roaming")]
    pub(crate) fn note_failure(&self) {
        self.failures_total.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "experimental-roaming")]
    pub(crate) fn note_grace_expired(&self) {
        self.grace_expired_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> TcpRoamingSnapshot {
        TcpRoamingSnapshot {
            attempts_total: self.attempts_total.load(Ordering::Relaxed),
            commits_total: self.commits_total.load(Ordering::Relaxed),
            failures_total: self.failures_total.load(Ordering::Relaxed),
            grace_expired_total: self.grace_expired_total.load(Ordering::Relaxed),
        }
    }
}

#[cfg(all(test, feature = "experimental-roaming"))]
mod tests {
    use super::{TcpRoamingMetrics, TcpRoamingSnapshot};

    #[test]
    fn snapshot_is_monotonic_and_keeps_outcomes_separate() {
        let metrics = TcpRoamingMetrics::default();
        assert_eq!(metrics.snapshot(), TcpRoamingSnapshot::default());

        metrics.note_attempt();
        metrics.note_attempt();
        metrics.note_commit();
        metrics.note_failure();
        metrics.note_grace_expired();

        assert_eq!(
            metrics.snapshot(),
            TcpRoamingSnapshot {
                attempts_total: 2,
                commits_total: 1,
                failures_total: 1,
                grace_expired_total: 1,
            }
        );
    }
}
