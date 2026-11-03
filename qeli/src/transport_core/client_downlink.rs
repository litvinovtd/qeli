//! TCP receive-to-TUN handoff losses, separate from later device write errors.
use portable_atomic::{AtomicU64, Ordering};
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
use serde::Serialize;

#[derive(Clone, Copy)]
pub(crate) enum DownlinkDrop {
    PoolExhausted,
    QueueFull,
    Disconnected,
}

#[derive(Default)]
pub(crate) struct DownlinkCounters {
    pool_exhausted: AtomicU64,
    queue_full: AtomicU64,
    disconnected: AtomicU64,
}

// The Linux client's status writer consumes snapshots; native adapters only note losses.
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct DownlinkSnapshot {
    pub total: u64,
    pub pool_exhausted: u64,
    pub queue_full: u64,
    pub disconnected: u64,
}

impl DownlinkCounters {
    pub(crate) fn note(&self, reason: DownlinkDrop) {
        match reason {
            DownlinkDrop::PoolExhausted => &self.pool_exhausted,
            DownlinkDrop::QueueFull => &self.queue_full,
            DownlinkDrop::Disconnected => &self.disconnected,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(test, all(target_os = "linux", feature = "client")))]
    pub(crate) fn snapshot(&self) -> DownlinkSnapshot {
        let pool_exhausted = self.pool_exhausted.load(Ordering::Relaxed);
        let queue_full = self.queue_full.load(Ordering::Relaxed);
        let disconnected = self.disconnected.load(Ordering::Relaxed);
        DownlinkSnapshot {
            total: pool_exhausted
                .saturating_add(queue_full)
                .saturating_add(disconnected),
            pool_exhausted,
            queue_full,
            disconnected,
        }
    }
}

#[cfg(test)]
mod tcp_downlink_counter_tests {
    use super::*;

    #[test]
    fn reasons_have_one_sampled_total_and_fresh_counters_start_empty() {
        let counters = DownlinkCounters::default();
        for reason in [
            DownlinkDrop::PoolExhausted,
            DownlinkDrop::QueueFull,
            DownlinkDrop::QueueFull,
            DownlinkDrop::Disconnected,
        ] {
            counters.note(reason);
        }
        assert_eq!(
            counters.snapshot(),
            DownlinkSnapshot {
                total: 4,
                pool_exhausted: 1,
                queue_full: 2,
                disconnected: 1,
            }
        );
        assert_eq!(
            DownlinkCounters::default().snapshot(),
            DownlinkSnapshot::default()
        );
    }
}
