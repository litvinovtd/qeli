//! Fixed-budget UDP batch handoff, shared by clients and server workers.
//! The admission limit is always 128 datagrams. The existing bounded recycler remains
//! the allocation ceiling. Wait metrics cover recv completion through batch dequeue,
//! including admission wait, not pending-batch drain, decryption, TUN delivery or WAN RTT.

use portable_atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CAPACITY: usize = super::udp_receive::UDP_RECEIVE_QUEUE_PACKETS;
const MAX_BATCH: usize = super::udp_batch::MAX_BATCH;
const WAIT_BUCKETS_US: [u64; 11] = [
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    25_000,
    100_000,
    u64::MAX,
];

#[derive(Debug, Default)]
pub(crate) struct QueueCounters {
    queued_packets: AtomicU64,
    queued_bytes: AtomicU64,
    peak_packets: AtomicU64,
    peak_bytes: AtomicU64,
    limit_packets: AtomicU64,
    delivered_packets: AtomicU64,
    cancelled_packets: AtomicU64,
    wait_total_us: AtomicU64,
    wait_max_us: AtomicU64,
    wait_histogram: [AtomicU64; WAIT_BUCKETS_US.len()],
}

/// Counts and byte depths are aggregated across the profile's receive pumps. Percentiles
/// are packet-weighted upper histogram bounds, cumulative over this counter's lifetime.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct QueueSnapshot {
    pub queued_packets: u64,
    pub queued_bytes: u64,
    pub peak_packets: u64,
    pub peak_bytes: u64,
    pub limit_packets: u64,
    pub delivered_packets: u64,
    pub cancelled_packets: u64,
    pub wait_mean_us: u64,
    pub wait_total_us: u64,
    pub wait_histogram_packets: [u64; WAIT_BUCKETS_US.len()],
    pub wait_bucket_upper_us: [u64; WAIT_BUCKETS_US.len()],
    pub wait_p50_upper_us: u64,
    pub wait_p95_upper_us: u64,
    pub wait_p99_upper_us: u64,
    pub wait_max_us: u64,
    pub grow_events: u64,
    pub shrink_events: u64,
}

impl QueueCounters {
    pub(crate) fn snapshot(&self) -> QueueSnapshot {
        let get = |value: &AtomicU64| value.load(Ordering::Relaxed);
        let delivered = get(&self.delivered_packets);
        let maximum = get(&self.wait_max_us);
        let histogram = self.wait_histogram.each_ref().map(get);
        let observed = histogram.iter().copied().sum::<u64>();
        let percentile = |percent: u64| {
            if observed == 0 {
                return 0;
            }
            let target = observed.saturating_mul(percent).div_ceil(100);
            let mut sum = 0u64;
            for (count, upper) in histogram.iter().zip(WAIT_BUCKETS_US) {
                sum = sum.saturating_add(*count);
                if sum >= target {
                    return upper.min(maximum);
                }
            }
            maximum
        };
        QueueSnapshot {
            queued_packets: get(&self.queued_packets),
            queued_bytes: get(&self.queued_bytes),
            peak_packets: get(&self.peak_packets),
            peak_bytes: get(&self.peak_bytes),
            limit_packets: get(&self.limit_packets),
            delivered_packets: delivered,
            cancelled_packets: get(&self.cancelled_packets),
            wait_mean_us: get(&self.wait_total_us).checked_div(delivered).unwrap_or(0),
            wait_total_us: get(&self.wait_total_us),
            wait_histogram_packets: histogram,
            wait_bucket_upper_us: WAIT_BUCKETS_US,
            wait_p50_upper_us: percentile(50),
            wait_p95_upper_us: percentile(95),
            wait_p99_upper_us: percentile(99),
            wait_max_us: maximum,
            grow_events: 0,
            shrink_events: 0,
        }
    }
}

pub(crate) struct ReceiveQueue {
    semaphore: Arc<Semaphore>,
    counters: Arc<QueueCounters>,
}

impl ReceiveQueue {
    pub(crate) fn new(counters: Arc<QueueCounters>, label: &'static str) -> Arc<Self> {
        counters
            .limit_packets
            .fetch_add(CAPACITY as u64, Ordering::Relaxed);
        log::info!("{label}: UDP receive queue fixed at {CAPACITY} datagrams; existing recycler memory cap retained");
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(CAPACITY)),
            counters,
        })
    }

    /// Timestamp at recv completion, before admission, so a full queue cannot hide wait time.
    pub(crate) async fn batch<T>(
        self: &Arc<Self>,
        packets: Vec<T>,
        bytes: usize,
        received_at: Instant,
    ) -> QueuedBatch<T> {
        let count = packets.len();
        assert!(
            count > 0 && count <= MAX_BATCH,
            "receive batch must fit the fixed queue"
        );
        debug_assert!(bytes <= count * super::udp_receive::MAX_UDP_PACKET_SIZE);
        let permit = self
            .semaphore
            .clone()
            .acquire_many_owned(count as u32)
            .await
            .expect("receive queue semaphore is private and is never closed");
        let depth = self
            .counters
            .queued_packets
            .fetch_add(count as u64, Ordering::Relaxed)
            + count as u64;
        let byte_depth = self
            .counters
            .queued_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed)
            + bytes as u64;
        self.counters
            .peak_packets
            .fetch_max(depth, Ordering::Relaxed);
        self.counters
            .peak_bytes
            .fetch_max(byte_depth, Ordering::Relaxed);
        QueuedBatch {
            packets,
            bytes,
            received_at,
            queue: self.clone(),
            permit: Some(permit),
        }
    }
}

impl Drop for ReceiveQueue {
    fn drop(&mut self) {
        self.counters
            .limit_packets
            .fetch_sub(CAPACITY as u64, Ordering::Relaxed);
    }
}

pub(crate) struct QueuedBatch<T> {
    packets: Vec<T>,
    bytes: usize,
    received_at: Instant,
    queue: Arc<ReceiveQueue>,
    permit: Option<OwnedSemaphorePermit>,
}

impl<T> QueuedBatch<T> {
    pub(crate) fn into_inner(mut self) -> Vec<T> {
        self.finish(true);
        std::mem::take(&mut self.packets)
    }

    fn finish(&mut self, delivered: bool) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let count = self.packets.len() as u64;
        let c = &self.queue.counters;
        c.queued_packets.fetch_sub(count, Ordering::Relaxed);
        c.queued_bytes
            .fetch_sub(self.bytes as u64, Ordering::Relaxed);
        if delivered {
            let waited = self
                .received_at
                .elapsed()
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
            c.wait_total_us
                .fetch_add(waited.saturating_mul(count), Ordering::Relaxed);
            c.wait_max_us.fetch_max(waited, Ordering::Relaxed);
            let bucket = WAIT_BUCKETS_US
                .iter()
                .position(|upper| waited <= *upper)
                .unwrap();
            c.wait_histogram[bucket].fetch_add(count, Ordering::Relaxed);
            c.delivered_packets.fetch_add(count, Ordering::Relaxed);
        } else {
            c.cancelled_packets.fetch_add(count, Ordering::Relaxed);
        }
        drop(permit);
    }
}

impl<T> Drop for QueuedBatch<T> {
    fn drop(&mut self) {
        self.finish(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn queue() -> (Arc<ReceiveQueue>, Arc<QueueCounters>) {
        let counters = Arc::new(QueueCounters::default());
        (ReceiveQueue::new(counters.clone(), "test"), counters)
    }

    #[test]
    fn old_memory_and_batch_limits_are_retained() {
        assert_eq!(CAPACITY, 128);
        assert_eq!(MAX_BATCH, 32);
    }

    #[tokio::test]
    async fn fixed_queue_preserves_order_and_waits_at_128() {
        let (q, c) = queue();
        let mut held = Vec::new();
        for i in 0..4 {
            held.push(
                q.batch((i * 32..(i + 1) * 32).collect(), 320, Instant::now())
                    .await,
            );
        }
        assert!(tokio::time::timeout(
            Duration::from_millis(5),
            q.batch(vec![128], 10, Instant::now())
        )
        .await
        .is_err());
        assert_eq!(c.snapshot().peak_packets, 128);
        let result: Vec<_> = held.into_iter().flat_map(QueuedBatch::into_inner).collect();
        assert_eq!(result, (0..128).collect::<Vec<_>>());
        assert_eq!(q.semaphore.available_permits(), 128);
        let s = c.snapshot();
        assert_eq!(
            (s.queued_packets, s.delivered_packets, s.cancelled_packets),
            (0, 128, 0)
        );
        assert_eq!(
            (s.limit_packets, s.grow_events, s.shrink_events),
            (128, 0, 0)
        );
    }

    #[tokio::test]
    async fn cancelled_admission_and_batches_release_the_entire_budget() {
        let (q, c) = queue();
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(q.batch(vec![0; 32], 320, Instant::now()).await);
        }
        assert!(tokio::time::timeout(
            Duration::from_millis(5),
            q.batch(vec![1], 10, Instant::now())
        )
        .await
        .is_err());
        drop(held);
        assert_eq!(q.semaphore.available_permits(), 128);
        let s = c.snapshot();
        assert_eq!(
            (s.queued_packets, s.delivered_packets, s.cancelled_packets),
            (0, 0, 128)
        );
    }

    #[tokio::test]
    async fn closed_channel_releases_depth_without_reporting_delivery() {
        let (q, c) = queue();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        drop(tx.send(q.batch(vec![1, 2], 20, Instant::now()).await).await);
        let s = c.snapshot();
        assert_eq!(
            (s.queued_packets, s.delivered_packets, s.cancelled_packets),
            (0, 0, 2)
        );
        assert_eq!(q.semaphore.available_permits(), 128);
    }

    #[tokio::test]
    async fn histogram_is_packet_weighted_and_excludes_cancellation() {
        let (q, c) = queue();
        let now = Instant::now();
        q.batch(vec![1; 20], 20, now - Duration::from_millis(2))
            .await
            .into_inner();
        drop(
            q.batch(vec![2; 20], 20, now - Duration::from_secs(20))
                .await,
        );
        let s = c.snapshot();
        assert_eq!((s.delivered_packets, s.cancelled_packets), (20, 20));
        assert!(s.wait_mean_us >= 2000 && s.wait_max_us < 1_000_000);
        assert_eq!(s.wait_histogram_packets.iter().sum::<u64>(), 20);
        assert!(s.wait_p50_upper_us >= s.wait_mean_us);
    }

    #[tokio::test]
    async fn shared_counter_retirement_does_not_change_other_pumps() {
        let c = Arc::new(QueueCounters::default());
        let a = ReceiveQueue::new(c.clone(), "a");
        let b = ReceiveQueue::new(c.clone(), "b");
        assert_eq!(c.snapshot().limit_packets, 256);
        let batch = b.batch(vec![1], 100, Instant::now()).await;
        drop(b);
        assert_eq!(c.snapshot().limit_packets, 256);
        batch.into_inner();
        assert_eq!(c.snapshot().limit_packets, 128);
        drop(a);
        assert_eq!(c.snapshot().limit_packets, 0);
    }
}
