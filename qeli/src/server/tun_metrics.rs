//! Bounded, allocation-free diagnostics for the server TUN -> carrier pipeline.
//! Kernel-read time includes deliberate idle waits. Between-read time excludes that
//! syscall and measures userspace dispatch, pool wait and scheduling stalls instead.
use portable_atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const BOUNDS_US: [u64; 12] = [
    1,
    5,
    10,
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    u64::MAX,
];

#[derive(Default)]
pub(super) struct Timing {
    samples: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
    histogram: [AtomicU64; BOUNDS_US.len()],
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct TimingSnapshot {
    pub samples: u64,
    pub total_us: u64,
    pub max_us: u64,
    pub histogram: [u64; BOUNDS_US.len()],
}

impl Timing {
    pub(super) fn record(&self, elapsed: Duration) {
        let us = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        self.total_us.fetch_add(us, Ordering::Relaxed);
        self.max_us.fetch_max(us, Ordering::Relaxed);
        self.histogram[BOUNDS_US.iter().position(|limit| us <= *limit).unwrap()]
            .fetch_add(1, Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Relaxed);
    }
    fn snapshot(&self) -> TimingSnapshot {
        TimingSnapshot {
            samples: self.samples.load(Ordering::Relaxed),
            total_us: self.total_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
            histogram: self.histogram.each_ref().map(|n| n.load(Ordering::Relaxed)),
        }
    }
}

#[derive(Default)]
pub(super) struct TunMetrics {
    pub pool_wait: Timing,
    pub dispatch_wait: Timing,
    pub between_reads: Timing,
    pub kernel_read: Timing,
    pub udp_send: Timing,
    packets: AtomicU64,
    bytes: AtomicU64,
    pool_slots: AtomicU64,
    pool_budget_bytes: AtomicU64,
    reader_queue_peak: AtomicU64,
    writer_queue_peak: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct TunSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub pool_slots: u64,
    pub pool_budget_bytes: u64,
    pub reader_queue_peak: u64,
    pub writer_queue_peak: u64,
    pub pool_wait: TimingSnapshot,
    pub dispatch_wait: TimingSnapshot,
    pub between_reads: TimingSnapshot,
    pub kernel_read: TimingSnapshot,
    pub udp_send: TimingSnapshot,
    pub bucket_upper_us: [u64; BOUNDS_US.len()],
}

impl TunMetrics {
    pub(super) fn configure(&self, slots: usize, slot_bytes: usize) {
        self.pool_slots.store(slots as u64, Ordering::Relaxed);
        self.pool_budget_bytes
            .store(slots.saturating_mul(slot_bytes) as u64, Ordering::Relaxed);
    }
    pub(super) fn read_packet(&self, bytes: usize) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub(super) fn reader_depth(&self, depth: usize) {
        self.reader_queue_peak
            .fetch_max(depth as u64, Ordering::Relaxed);
    }
    pub(super) fn writer_depth(&self, depth: usize) {
        self.writer_queue_peak
            .fetch_max(depth as u64, Ordering::Relaxed);
    }
    pub(super) fn snapshot(&self) -> TunSnapshot {
        let get = |n: &AtomicU64| n.load(Ordering::Relaxed);
        TunSnapshot {
            packets: get(&self.packets),
            bytes: get(&self.bytes),
            pool_slots: get(&self.pool_slots),
            pool_budget_bytes: get(&self.pool_budget_bytes),
            reader_queue_peak: get(&self.reader_queue_peak),
            writer_queue_peak: get(&self.writer_queue_peak),
            pool_wait: self.pool_wait.snapshot(),
            dispatch_wait: self.dispatch_wait.snapshot(),
            between_reads: self.between_reads.snapshot(),
            kernel_read: self.kernel_read.snapshot(),
            udp_send: self.udp_send.snapshot(),
            bucket_upper_us: BOUNDS_US,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stages_count_only_explicit_samples_and_do_not_allocate_per_packet() {
        let m = TunMetrics::default();
        m.configure(512, 65535);
        m.read_packet(1200);
        m.read_packet(1280);
        m.pool_wait.record(Duration::from_micros(220));
        m.pool_wait.record(Duration::from_millis(6));
        m.kernel_read.record(Duration::from_secs(10));
        m.reader_depth(32);
        m.reader_depth(7);
        m.writer_depth(64);
        let s = m.snapshot();
        assert_eq!(
            (s.packets, s.bytes, s.pool_slots, s.pool_budget_bytes),
            (2, 2480, 512, 512 * 65535)
        );
        assert_eq!((s.reader_queue_peak, s.writer_queue_peak), (32, 64));
        assert_eq!(
            (
                s.pool_wait.samples,
                s.pool_wait.total_us,
                s.pool_wait.max_us
            ),
            (2, 6220, 6000)
        );
        assert_eq!(s.pool_wait.histogram.iter().sum::<u64>(), 2);
        assert_eq!(s.between_reads.samples, 0);
        assert_eq!(s.kernel_read.samples, 1);
    }
}
