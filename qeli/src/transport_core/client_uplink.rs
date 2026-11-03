//! Reason counters for bounded TCP client hand-offs, separate from UDP socket loss.

use portable_atomic::{AtomicU64, Ordering};
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
use serde::Serialize;

#[derive(Clone, Copy)]
pub(crate) enum UplinkDrop {
    PoolExhausted,
    QueueFull,
    Oversize,
    NoCarrier,
}

#[derive(Default)]
pub(crate) struct UplinkCounters {
    pool_exhausted: AtomicU64,
    queue_full: AtomicU64,
    oversize: AtomicU64,
    no_carrier: AtomicU64,
}

// The Linux client's status writer consumes snapshots; native adapters only note losses.
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct UplinkSnapshot {
    pub total: u64,
    pub pool_exhausted: u64,
    pub queue_full: u64,
    pub oversize: u64,
    pub no_carrier: u64,
}

impl UplinkCounters {
    pub(crate) fn note(&self, reason: UplinkDrop) {
        match reason {
            UplinkDrop::PoolExhausted => &self.pool_exhausted,
            UplinkDrop::QueueFull => &self.queue_full,
            UplinkDrop::Oversize => &self.oversize,
            UplinkDrop::NoCarrier => &self.no_carrier,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(test, all(target_os = "linux", feature = "client")))]
    pub(crate) fn snapshot(&self) -> UplinkSnapshot {
        let pool_exhausted = self.pool_exhausted.load(Ordering::Relaxed);
        let queue_full = self.queue_full.load(Ordering::Relaxed);
        let oversize = self.oversize.load(Ordering::Relaxed);
        let no_carrier = self.no_carrier.load(Ordering::Relaxed);
        // Derive the total from this snapshot; a separately incremented total could
        // disagree with the reason sum when the status sampler races a packet.
        let total = pool_exhausted
            .saturating_add(queue_full)
            .saturating_add(oversize)
            .saturating_add(no_carrier);
        UplinkSnapshot {
            total,
            pool_exhausted,
            queue_full,
            oversize,
            no_carrier,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_separate_and_total_matches_the_sampled_values() {
        let counters = UplinkCounters::default();
        for reason in [
            UplinkDrop::PoolExhausted,
            UplinkDrop::QueueFull,
            UplinkDrop::QueueFull,
            UplinkDrop::Oversize,
            UplinkDrop::NoCarrier,
        ] {
            counters.note(reason);
        }
        assert_eq!(
            counters.snapshot(),
            UplinkSnapshot {
                total: 5,
                pool_exhausted: 1,
                queue_full: 2,
                oversize: 1,
                no_carrier: 1,
            }
        );
        assert_eq!(
            UplinkCounters::default().snapshot(),
            UplinkSnapshot::default()
        );
    }
}
