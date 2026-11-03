//! Bounded observations of local TCP uplink work. No routing/liveness policy.
//!
//! Hot paths use atomics and a writer-owned, preallocated FIFO of small tickets.
//! Registry locking and JSON allocation occur only on carrier creation/sampling.
//! Snapshots are eventually consistent, not an atomic transaction across counters.

use crate::protocol::stream_io::WriteProgress;
use portable_atomic::{AtomicBool, AtomicU64, Ordering};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const RETAINED_CARRIERS: usize = 32;
const MAX_JSON_BYTES: usize = 64 * 1024;
const DEGRADED_AGE_MS: u64 = 10_000;
const RECENT_MS: u64 = 20_000;
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Registry {
    run_id: u64,
    started: Instant,
    next_carrier: AtomicU64,
    omitted: AtomicU64,
    rows: Mutex<VecDeque<Arc<CarrierMetrics>>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            run_id: NEXT_RUN.fetch_add(1, Ordering::Relaxed),
            started: Instant::now(),
            next_carrier: AtomicU64::new(1),
            omitted: AtomicU64::new(0),
            rows: Mutex::new(VecDeque::with_capacity(RETAINED_CARRIERS)),
        }
    }
}

impl Registry {
    pub(crate) fn register(&self, slot: u32, progress: WriteProgress) -> Arc<CarrierMetrics> {
        let row = Arc::new(CarrierMetrics::new(
            self.next_carrier.fetch_add(1, Ordering::Relaxed),
            slot,
            self.started,
            progress,
        ));
        let mut rows = self
            .rows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if rows.len() == RETAINED_CARRIERS {
            let closed = rows
                .iter()
                .position(|row| row.closed.load(Ordering::Relaxed));
            rows.remove(closed.unwrap_or(0));
            self.omitted.fetch_add(1, Ordering::Relaxed);
        }
        rows.push_back(row.clone());
        row
    }

    pub(crate) fn diagnostics_json(&self) -> Vec<u8> {
        self.json(false)
    }

    #[cfg(any(
        test,
        all(
            feature = "transport-core-ffi",
            any(
                target_os = "android",
                target_os = "windows",
                target_os = "macos",
                target_os = "ios"
            )
        )
    ))]
    pub(crate) fn finished_json(&self) -> Vec<u8> {
        self.json(true)
    }

    fn json(&self, finished: bool) -> Vec<u8> {
        let now = self
            .started
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX - 1)) as u64;
        let rows = self
            .rows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut report = Report {
            schema: 1,
            supported: true,
            runtime_available: !finished,
            finished,
            scope: "tcp_uplink",
            completion: "local_write_flush_not_peer_ack",
            age_semantics: "queue_wait_sample_and_pending_episode",
            progress_timestamps: "sampled",
            payloads: "queued_tunnel_payloads_including_control",
            run_id: self.run_id,
            elapsed_ms: now,
            omitted_carriers: self.omitted.load(Ordering::Relaxed),
            carriers: rows.iter().map(|row| row.snapshot(now)).collect(),
        };
        drop(rows);
        // Every row is fixed-shape and numeric, nevertheless enforce the byte cap.
        loop {
            let bytes = serde_json::to_vec(&report).unwrap_or_default();
            if bytes.len() <= MAX_JSON_BYTES {
                return bytes;
            }
            if report.carriers.pop().is_none() {
                return unavailable_json(true);
            }
            report.omitted_carriers = report.omitted_carriers.saturating_add(1);
        }
    }
}

pub(crate) fn unavailable_json(supported: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "schema": 1, "supported": supported,
        "runtime_available": false, "finished": false, "scope": "tcp_uplink",
        "completion": "local_write_flush_not_peer_ack", "run_id": 0, "elapsed_ms": 0,
        "age_semantics": "queue_wait_sample_and_pending_episode", "progress_timestamps": "sampled",
        "payloads": "queued_tunnel_payloads_including_control",
        "omitted_carriers": 0, "carriers": [] }))
    .unwrap_or_default()
}

#[derive(Serialize)]
struct Report {
    schema: u32,
    supported: bool,
    runtime_available: bool,
    finished: bool,
    scope: &'static str,
    completion: &'static str,
    age_semantics: &'static str,
    progress_timestamps: &'static str,
    payloads: &'static str,
    run_id: u64,
    elapsed_ms: u64,
    omitted_carriers: u64,
    carriers: Vec<Snapshot>,
}

pub(crate) struct CarrierMetrics {
    carrier_id: u64,
    logical_slot: u32,
    started: Instant,
    progress: WriteProgress,
    closed: AtomicBool,
    accounting_supported: AtomicBool,
    accepted_packets: AtomicU64,
    accepted_bytes: AtomicU64,
    local_finished_packets: AtomicU64,
    local_finished_bytes: AtomicU64,
    cancelled_packets: AtomicU64,
    cancelled_bytes: AtomicU64,
    rejected_packets: AtomicU64,
    rejected_bytes: AtomicU64,
    queue_full_drops_packets: AtomicU64,
    queue_full_drops_bytes: AtomicU64,
    queued_packets: AtomicU64,
    queued_bytes: AtomicU64,
    in_flight_packets: AtomicU64,
    in_flight_bytes: AtomicU64,
    pending_packets: AtomicU64,
    pending_bytes: AtomicU64,
    backlog_started: AtomicU64,
    oldest_in_flight: AtomicU64,
    last_queue_wait: AtomicU64,
    max_queue_wait: AtomicU64,
    last_dequeued: AtomicU64,
    last_local_finish: AtomicU64,
    last_queue_full: AtomicU64,
    sampled_progress: AtomicU64,
    last_progress_sample: AtomicU64,
}

impl CarrierMetrics {
    fn new(carrier_id: u64, logical_slot: u32, started: Instant, progress: WriteProgress) -> Self {
        Self {
            carrier_id,
            logical_slot,
            started,
            sampled_progress: AtomicU64::new(progress.snapshot()),
            progress,
            closed: AtomicBool::new(false),
            accounting_supported: AtomicBool::new(true),
            accepted_packets: AtomicU64::new(0),
            accepted_bytes: AtomicU64::new(0),
            local_finished_packets: AtomicU64::new(0),
            local_finished_bytes: AtomicU64::new(0),
            cancelled_packets: AtomicU64::new(0),
            cancelled_bytes: AtomicU64::new(0),
            rejected_packets: AtomicU64::new(0),
            rejected_bytes: AtomicU64::new(0),
            queue_full_drops_packets: AtomicU64::new(0),
            queue_full_drops_bytes: AtomicU64::new(0),
            queued_packets: AtomicU64::new(0),
            queued_bytes: AtomicU64::new(0),
            in_flight_packets: AtomicU64::new(0),
            in_flight_bytes: AtomicU64::new(0),
            pending_packets: AtomicU64::new(0),
            pending_bytes: AtomicU64::new(0),
            backlog_started: AtomicU64::new(0),
            oldest_in_flight: AtomicU64::new(0),
            last_queue_wait: AtomicU64::new(0),
            max_queue_wait: AtomicU64::new(0),
            last_dequeued: AtomicU64::new(0),
            last_local_finish: AtomicU64::new(0),
            last_queue_full: AtomicU64::new(0),
            last_progress_sample: AtomicU64::new(0),
        }
    }

    fn now(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX - 1)) as u64
    }

    /// Call after reserving an mpsc slot, before publishing the envelope.
    pub(crate) fn admit(self: &Arc<Self>, bytes: usize) -> Ticket {
        let now = self.now();
        let bytes = bytes as u64;
        self.accepted_packets.fetch_add(1, Ordering::Relaxed);
        self.accepted_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.queued_packets.fetch_add(1, Ordering::Relaxed);
        self.queued_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.pending_bytes.fetch_add(bytes, Ordering::Relaxed);
        if self.pending_packets.fetch_add(1, Ordering::Relaxed) == 0 {
            self.backlog_started.store(now + 1, Ordering::Relaxed);
        }
        Ticket {
            metrics: self.clone(),
            bytes,
            remaining: bytes,
            enqueued: now,
            started: now,
            state: TicketState::Queued,
            failed: false,
        }
    }

    pub(crate) fn queue_full(&self, bytes: usize) {
        self.queue_full_drops_packets
            .fetch_add(1, Ordering::Relaxed);
        self.queue_full_drops_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.last_queue_full
            .store(self.now() + 1, Ordering::Relaxed);
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    fn snapshot(&self, now: u64) -> Snapshot {
        let progress = self.progress.snapshot();
        if self.sampled_progress.swap(progress, Ordering::Relaxed) != progress {
            self.last_progress_sample.store(now + 1, Ordering::Relaxed);
        }
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        let age = |stamp: u64| (stamp > 0).then(|| now.saturating_sub(stamp - 1));
        let pending = load(&self.pending_packets);
        let in_flight = load(&self.in_flight_packets);
        let accounting_supported = self.accounting_supported.load(Ordering::Relaxed);
        let oldest = (in_flight > 0 && accounting_supported)
            .then(|| age(load(&self.oldest_in_flight)))
            .flatten();
        let backlog = (pending > 0)
            .then(|| age(load(&self.backlog_started)))
            .flatten();
        let last_wait = (load(&self.last_dequeued) > 0).then(|| load(&self.last_queue_wait));
        let recently_queued = age(load(&self.last_dequeued)).is_some_and(|age| age <= RECENT_MS);
        let recent_drop = age(load(&self.last_queue_full)).is_some_and(|age| age <= RECENT_MS);
        // A continuously nonempty queue is not by itself degradation. Require a
        // long gap in completed local payloads, clipped to this backlog episode.
        let completion_gap = (pending > 0)
            .then(|| age(load(&self.backlog_started).max(load(&self.last_local_finish))))
            .flatten();
        let closed = self.closed.load(Ordering::Relaxed);
        let activity = if closed {
            "closed"
        } else if pending == 0 {
            "idle"
        } else if accounting_supported
            && (oldest.is_some_and(|age| age >= DEGRADED_AGE_MS)
                || completion_gap.is_some_and(|age| age >= DEGRADED_AGE_MS)
                || (recently_queued && last_wait.is_some_and(|age| age >= DEGRADED_AGE_MS))
                || recent_drop)
        {
            "degraded"
        } else {
            "active"
        };
        Snapshot {
            carrier_id: self.carrier_id,
            logical_slot: self.logical_slot,
            closed,
            activity,
            accounting_supported,
            accepted_packets: load(&self.accepted_packets),
            accepted_bytes: load(&self.accepted_bytes),
            local_finished_packets: load(&self.local_finished_packets),
            local_finished_bytes: load(&self.local_finished_bytes),
            cancelled_packets: load(&self.cancelled_packets),
            cancelled_bytes: load(&self.cancelled_bytes),
            rejected_packets: load(&self.rejected_packets),
            rejected_bytes: load(&self.rejected_bytes),
            queue_full_drops_packets: load(&self.queue_full_drops_packets),
            queue_full_drops_bytes: load(&self.queue_full_drops_bytes),
            queued_packets: load(&self.queued_packets),
            queued_bytes: load(&self.queued_bytes),
            in_flight_packets: in_flight,
            in_flight_bytes: load(&self.in_flight_bytes),
            pending_packets: pending,
            pending_bytes: load(&self.pending_bytes),
            backlog_episode_ms: backlog,
            oldest_in_flight_ms: oldest,
            last_queue_wait_ms: last_wait,
            max_queue_wait_ms: load(&self.max_queue_wait),
            last_local_finish_ago_ms: age(load(&self.last_local_finish)),
            last_write_progress_ago_ms: age(load(&self.last_progress_sample)),
            pending_no_write_progress_ms: if pending > 0 {
                age(load(&self.backlog_started).max(load(&self.last_progress_sample)))
            } else {
                None
            },
            write_progress_bytes: progress,
            progress_boundary: "carrier_io_acceptance",
        }
    }
}

#[derive(Debug, Serialize)]
struct Snapshot {
    carrier_id: u64,
    logical_slot: u32,
    closed: bool,
    activity: &'static str,
    accounting_supported: bool,
    accepted_packets: u64,
    accepted_bytes: u64,
    local_finished_packets: u64,
    local_finished_bytes: u64,
    cancelled_packets: u64,
    cancelled_bytes: u64,
    rejected_packets: u64,
    rejected_bytes: u64,
    queue_full_drops_packets: u64,
    queue_full_drops_bytes: u64,
    queued_packets: u64,
    queued_bytes: u64,
    in_flight_packets: u64,
    in_flight_bytes: u64,
    pending_packets: u64,
    pending_bytes: u64,
    backlog_episode_ms: Option<u64>,
    oldest_in_flight_ms: Option<u64>,
    last_queue_wait_ms: Option<u64>,
    max_queue_wait_ms: u64,
    last_local_finish_ago_ms: Option<u64>,
    last_write_progress_ago_ms: Option<u64>,
    pending_no_write_progress_ms: Option<u64>,
    write_progress_bytes: u64,
    progress_boundary: &'static str,
}

#[derive(PartialEq)]
enum TicketState {
    Queued,
    InFlight,
    Done,
}

/// No allocation per packet. Drop records cancellation, including unconsumed
/// channel entries, partial records and generation cancellation.
pub(crate) struct Ticket {
    metrics: Arc<CarrierMetrics>,
    bytes: u64,
    remaining: u64,
    enqueued: u64,
    started: u64,
    state: TicketState,
    failed: bool,
}

impl Ticket {
    fn start(&mut self) {
        let row = &self.metrics;
        let now = row.now();
        let wait = now.saturating_sub(self.enqueued);
        self.started = now;
        row.last_queue_wait.store(wait, Ordering::Relaxed);
        row.max_queue_wait.fetch_max(wait, Ordering::Relaxed);
        row.last_dequeued.store(now + 1, Ordering::Relaxed);
        row.queued_packets.fetch_sub(1, Ordering::Relaxed);
        row.queued_bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        row.in_flight_packets.fetch_add(1, Ordering::Relaxed);
        row.in_flight_bytes.fetch_add(self.bytes, Ordering::Relaxed);
        self.state = TicketState::InFlight;
    }

    fn release(&mut self) {
        let row = &self.metrics;
        match self.state {
            TicketState::Queued => {
                row.queued_packets.fetch_sub(1, Ordering::Relaxed);
                row.queued_bytes.fetch_sub(self.bytes, Ordering::Relaxed);
            }
            TicketState::InFlight => {
                row.in_flight_packets.fetch_sub(1, Ordering::Relaxed);
                row.in_flight_bytes.fetch_sub(self.bytes, Ordering::Relaxed);
            }
            TicketState::Done => return,
        }
        row.pending_packets.fetch_sub(1, Ordering::Relaxed);
        row.pending_bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        self.state = TicketState::Done;
    }

    fn finish(mut self) {
        if self.failed {
            self.reject();
            return;
        }
        self.metrics
            .local_finished_packets
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .local_finished_bytes
            .fetch_add(self.bytes, Ordering::Relaxed);
        self.metrics
            .last_local_finish
            .store(self.metrics.now() + 1, Ordering::Relaxed);
        self.release();
    }

    pub(crate) fn reject(mut self) {
        self.metrics
            .rejected_packets
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .rejected_bytes
            .fetch_add(self.bytes, Ordering::Relaxed);
        self.release();
    }

    // Lost diagnostic correlation is neither a transport cancellation nor proof
    // of failure. Leave a gap in outcomes and advertise accounting_supported=false.
    fn forget(mut self) {
        self.release();
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.state == TicketState::Done {
            return;
        }
        self.metrics
            .cancelled_packets
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .cancelled_bytes
            .fetch_add(self.bytes, Ordering::Relaxed);
        self.release();
    }
}

/// Mirrors only the ordered, already bounded recordizer inputs, never flow IDs
/// or packet contents. A record may finish several packets or only a fragment.
pub(crate) struct InFlight {
    row: Arc<CarrierMetrics>,
    packets: VecDeque<Ticket>,
    capacity: usize,
}

impl InFlight {
    pub(crate) fn new(row: Arc<CarrierMetrics>, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            row,
            packets: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub(crate) fn push(&mut self, mut ticket: Ticket) {
        ticket.start();
        if !self.row.accounting_supported.load(Ordering::Relaxed) {
            ticket.forget();
            return;
        }
        if self.packets.len() == self.capacity {
            // Unexpected metadata bounds: invalidate accounting, never alter data
            // transport or grow a diagnostic structure without limit.
            self.invalidate();
            ticket.forget();
            return;
        }
        self.packets.push_back(ticket);
        self.update_oldest();
    }

    fn update_oldest(&self) {
        self.row.oldest_in_flight.store(
            self.packets.front().map_or(0, |packet| packet.started + 1),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn invalidate(&mut self) {
        self.row
            .accounting_supported
            .store(false, Ordering::Relaxed);
        for ticket in self.packets.drain(..) {
            ticket.forget();
        }
        self.update_oldest();
    }

    pub(crate) fn finish_bytes(&mut self, mut bytes: usize, success: bool) {
        if !self.row.accounting_supported.load(Ordering::Relaxed) {
            for ticket in self.packets.drain(..) {
                ticket.forget();
            }
            self.update_oldest();
            return;
        }
        while bytes > 0
            || self
                .packets
                .front()
                .is_some_and(|front| front.remaining == 0)
        {
            let Some(front) = self.packets.front_mut() else {
                self.invalidate();
                return;
            };
            let count = bytes.min(front.remaining as usize);
            front.remaining -= count as u64;
            front.failed |= !success;
            bytes -= count;
            if front.remaining == 0 {
                self.packets.pop_front().unwrap().finish();
            }
        }
        self.update_oldest();
    }
}

/// Captured outside the pump future, so it observes destruction of its queue and
/// in-flight tickets before marking the carrier closed, even on cancellation.
pub(crate) struct CloseGuard(pub(crate) Arc<CarrierMetrics>);
impl Drop for CloseGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> Arc<CarrierMetrics> {
        Registry::default().register(2, WriteProgress::default())
    }

    #[test]
    fn queued_and_partial_inflight_cancellation_release_pending_without_success() {
        let row = row();
        let queued = row.admit(9);
        let mut flight = InFlight::new(row.clone(), 2);
        flight.push(row.admit(12));
        flight.finish_bytes(5, true);
        assert_eq!(row.snapshot(0).local_finished_packets, 0);
        assert_eq!(row.snapshot(0).pending_packets, 2);
        drop(queued);
        drop(flight);
        let snapshot = row.snapshot(0);
        assert_eq!(
            (snapshot.cancelled_packets, snapshot.cancelled_bytes),
            (2, 21)
        );
        assert_eq!(
            (
                snapshot.pending_packets,
                snapshot.in_flight_packets,
                snapshot.queued_packets
            ),
            (0, 0, 0)
        );
        assert_eq!(snapshot.activity, "idle");
        assert_eq!(snapshot.backlog_episode_ms, None);
        assert_eq!(snapshot.oldest_in_flight_ms, None);
    }

    #[test]
    fn batched_fragmented_completion_counts_original_packets_only_once() {
        let row = row();
        let mut flight = InFlight::new(row.clone(), 2);
        flight.push(row.admit(5));
        flight.push(row.admit(7));
        flight.finish_bytes(3, true);
        assert_eq!(row.snapshot(0).local_finished_packets, 0);
        flight.finish_bytes(4, true);
        let middle = row.snapshot(0);
        assert_eq!(
            (middle.local_finished_packets, middle.local_finished_bytes),
            (1, 5)
        );
        assert_eq!((middle.in_flight_packets, middle.in_flight_bytes), (1, 7));
        // One failed fragment means the second original packet is not finished.
        flight.finish_bytes(5, false);
        let end = row.snapshot(0);
        assert_eq!((end.rejected_packets, end.rejected_bytes), (1, 7));
        assert_eq!(end.cancelled_packets, 0);
        assert_eq!(end.pending_packets, 0);
    }

    #[test]
    fn queue_full_is_not_admitted_and_idle_is_never_degraded() {
        let row = row();
        row.queue_full(1200);
        let snapshot = row.snapshot(1);
        assert_eq!((snapshot.accepted_packets, snapshot.accepted_bytes), (0, 0));
        assert_eq!(
            (
                snapshot.queue_full_drops_packets,
                snapshot.queue_full_drops_bytes
            ),
            (1, 1200)
        );
        assert_eq!(snapshot.activity, "idle");
    }

    #[test]
    fn inflight_age_starts_at_dequeue_and_metadata_loss_is_not_cancellation() {
        let row = row();
        let mut flight = InFlight::new(row.clone(), 1);
        let mut ticket = row.admit(10);
        ticket.enqueued = 0;
        flight.push(ticket);
        flight.packets.front_mut().unwrap().started = 40;
        flight.update_oldest();
        assert_eq!(row.snapshot(100).oldest_in_flight_ms, Some(60));
        // An impossible local-byte correlation must not invent successful sends.
        flight.invalidate();
        let snapshot = row.snapshot(100);
        assert!(!snapshot.accounting_supported);
        assert_eq!(snapshot.local_finished_packets, 0);
        assert_eq!(snapshot.cancelled_packets, 0);
        assert_eq!(snapshot.rejected_packets, 0);
    }

    #[test]
    fn registry_is_bounded_and_slot_reuse_has_distinct_identity() {
        let registry = Registry::default();
        let first = registry.register(0, WriteProgress::default());
        let second = registry.register(0, WriteProgress::default());
        assert_ne!(first.carrier_id, second.carrier_id);
        first.close();
        second.close();
        for _ in 0..40 {
            registry.register(0, WriteProgress::default()).close();
        }
        let bytes = registry.finished_json();
        assert!(bytes.len() <= MAX_JSON_BYTES);
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            report["carriers"].as_array().unwrap().len(),
            RETAINED_CARRIERS
        );
        assert_eq!(report["omitted_carriers"], 10);
        assert_eq!(report["finished"], true);
        assert_eq!(report["runtime_available"], false);
        assert_ne!(registry.run_id, Registry::default().run_id);
    }

    #[test]
    fn unavailable_snapshot_preserves_the_android_schema() {
        let report: serde_json::Value = serde_json::from_slice(&unavailable_json(true)).unwrap();
        for field in [
            "schema",
            "supported",
            "runtime_available",
            "finished",
            "scope",
            "completion",
            "run_id",
            "elapsed_ms",
            "omitted_carriers",
            "carriers",
            "age_semantics",
            "progress_timestamps",
            "payloads",
        ] {
            assert!(!report[field].is_null(), "missing {field}");
        }
        assert_eq!(report["runtime_available"], false);
        assert_eq!(report["finished"], false);
        assert!(report["carriers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn real_recordizer_batches_and_fragments_keep_exact_bounded_packet_accounting() {
        use crate::protocol::recordizer::{
            encoded_payload_len, pending_packet_capacity, Recordizer, RuntimeConfig,
        };
        let mut config = crate::config::RecordizerConfig::default();
        config.batch.max_packets = 3;
        config.record.full_probability = 1.0;
        config.fragment.enabled = true;
        config.fragment.max_fragments_per_packet = 64;
        let runtime = RuntimeConfig::from_config(&config, 96, 1024).unwrap();
        let row = row();
        let mut flight = InFlight::new(row.clone(), pending_packet_capacity(&runtime));
        let mut mux = Recordizer::new(runtime);
        let sizes = [1, 40, 200, 2, 300, 7];
        for size in sizes {
            flight.push(row.admit(size));
            for record in mux.push(&vec![0x41; size], Instant::now()).unwrap() {
                flight.finish_bytes(encoded_payload_len(&record).unwrap(), true);
            }
            assert!(row.snapshot(0).accounting_supported);
        }
        if let Some(record) = mux.flush() {
            flight.finish_bytes(encoded_payload_len(&record).unwrap(), true);
        }
        let snapshot = row.snapshot(0);
        assert_eq!(snapshot.local_finished_packets, sizes.len() as u64);
        assert_eq!(
            snapshot.local_finished_bytes,
            sizes.into_iter().sum::<usize>() as u64
        );
        assert_eq!(snapshot.pending_packets, 0);
        assert_eq!(snapshot.cancelled_packets, 0);
        assert!(snapshot.accounting_supported);
    }
}
