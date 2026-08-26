//! Negotiated packet-to-record multiplexing shared by every data carrier.
//!
//! The legacy data plane maps one inner packet to one AEAD record. `Recordizer`
//! breaks that invariant before `PacketCodec` encryption: several packets may
//! share one record and one packet may span several records. The mux marker and
//! headers are therefore encrypted and add no visible wire signature.

use rand::RngExt;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MAGIC: &[u8; 4] = b"QRM1";
const FRAME_HEADER_LEN: usize = 10;
const MIN_RECORD_PAYLOAD: usize = MAGIC.len() + FRAME_HEADER_LEN + 1;

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub delay_min: Duration,
    pub delay_max: Duration,
    pub max_packets: usize,
    pub max_queue_bytes: usize,
    /// Maximum plaintext passed to PacketCodec, including mux headers.
    pub max_payload_bytes: usize,
    pub small_min_ratio: f64,
    pub small_max_ratio: f64,
    pub full_probability: f64,
    pub fragment_enabled: bool,
    pub reassembly_timeout: Duration,
    pub max_inflight_packets: usize,
    pub max_reassembly_bytes: usize,
    pub max_fragments_per_packet: usize,
    pub max_packet_bytes: usize,
}

impl RuntimeConfig {
    pub fn from_config(
        config: &crate::config::RecordizerConfig,
        carrier_payload_budget: usize,
        max_packet_bytes: usize,
    ) -> Result<Self, RecordizerError> {
        let configured_max = usize::from(config.record.max_payload_bytes);
        let max_payload_bytes = if configured_max == 0 {
            carrier_payload_budget
        } else {
            configured_max.min(carrier_payload_budget)
        }
        .min(config.batch.max_queue_bytes as usize);
        if max_payload_bytes < MIN_RECORD_PAYLOAD {
            return Err(RecordizerError::InvalidConfig(
                "record payload budget is too small",
            ));
        }
        Ok(Self {
            delay_min: Duration::from_millis(config.batch.delay_min_ms),
            delay_max: Duration::from_millis(config.batch.delay_max_ms),
            max_packets: usize::from(config.batch.max_packets),
            max_queue_bytes: config.batch.max_queue_bytes as usize,
            max_payload_bytes,
            small_min_ratio: config.record.small_min_ratio,
            small_max_ratio: config.record.small_max_ratio,
            full_probability: config.record.full_probability,
            fragment_enabled: config.fragment.enabled,
            reassembly_timeout: Duration::from_millis(config.fragment.reassembly_timeout_ms),
            max_inflight_packets: usize::from(config.fragment.max_inflight_packets),
            max_reassembly_bytes: config.fragment.max_reassembly_bytes as usize,
            max_fragments_per_packet: usize::from(config.fragment.max_fragments_per_packet),
            max_packet_bytes,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordizerError {
    #[error("invalid recordizer configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("inner packet is empty or exceeds the configured limit")]
    PacketSize,
    #[error("recordizer envelope is truncated")]
    Truncated,
    #[error("recordizer envelope has an unsupported marker")]
    Unsupported,
    #[error("recordizer fragment metadata is invalid")]
    InvalidMetadata,
    #[error("recordizer fragment conflicts with buffered state")]
    Conflict,
    #[error("recordizer reassembly resource limit reached")]
    ResourceLimit,
}

/// Stateful sender. Input is copied immediately into the pending mux envelope,
/// so a caller can return its pooled TUN storage before the batching delay.
pub struct Recordizer {
    config: RuntimeConfig,
    current: Vec<u8>,
    current_target: usize,
    current_packets: usize,
    deadline: Option<Instant>,
    next_packet_id: u32,
}

impl Recordizer {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            current: Vec::with_capacity(config.max_payload_bytes),
            current_target: 0,
            current_packets: 0,
            deadline: None,
            next_packet_id: rand::random(),
            config,
        }
    }

    /// Raise the carrier payload ceiling after authenticated path-MTU discovery.
    ///
    /// A pending record keeps its original random target so changing the path
    /// budget cannot split, discard, or suddenly enlarge queued traffic. The
    /// next record is sampled from the new ceiling. PMTU fallback stays in the
    /// outer data-fragment layer; callers must not lower this value at runtime.
    pub fn raise_runtime(&mut self, config: RuntimeConfig) -> Result<(), RecordizerError> {
        if config.max_payload_bytes < self.config.max_payload_bytes {
            return Err(RecordizerError::InvalidConfig(
                "recordizer runtime payload budget cannot shrink",
            ));
        }
        self.current
            .reserve(config.max_payload_bytes.saturating_sub(self.current.len()));
        self.config = config;
        Ok(())
    }

    pub fn is_pending(&self) -> bool {
        !self.current.is_empty()
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn push(&mut self, packet: &[u8], now: Instant) -> Result<Vec<Vec<u8>>, RecordizerError> {
        if packet.is_empty()
            || packet.len() > self.config.max_packet_bytes
            || packet.len() > u16::MAX as usize
        {
            return Err(RecordizerError::PacketSize);
        }
        let packet_id = self.next_packet_id;
        let full_fragment_capacity = self
            .config
            .max_payload_bytes
            .saturating_sub(MAGIC.len() + FRAME_HEADER_LEN);
        let minimum_fragments = packet.len().div_ceil(full_fragment_capacity.max(1));
        if self.config.fragment_enabled && minimum_fragments > self.config.max_fragments_per_packet
        {
            return Err(RecordizerError::PacketSize);
        }
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        let total_len = packet.len() as u16;
        let mut offset = 0usize;
        let mut fragment_count = 0usize;
        let mut ready = Vec::new();

        while offset < packet.len() {
            if !self.config.fragment_enabled {
                let required = MAGIC.len() + FRAME_HEADER_LEN + packet.len();
                if required > self.config.max_payload_bytes {
                    return Err(RecordizerError::PacketSize);
                }
                self.ensure_record(now);
                let does_not_fit =
                    self.current.len() + FRAME_HEADER_LEN + packet.len() > self.current_target;
                if self.current_packets == 0 && does_not_fit {
                    // The random small target is optional morphology. Never emit a
                    // marker-only record merely because a whole packet needs the full cap.
                    self.current_target = self.config.max_payload_bytes;
                } else if does_not_fit || self.current_packets >= self.config.max_packets {
                    if let Some(record) = self.flush() {
                        ready.push(record);
                    }
                    self.ensure_record(now);
                    self.current_target = self.config.max_payload_bytes;
                }
                self.current.extend_from_slice(&packet_id.to_be_bytes());
                self.current.extend_from_slice(&total_len.to_be_bytes());
                self.current.extend_from_slice(&0u16.to_be_bytes());
                self.current.extend_from_slice(&total_len.to_be_bytes());
                self.current.extend_from_slice(packet);
                self.current_packets += 1;
                break;
            }
            let fragments_left = self
                .config
                .max_fragments_per_packet
                .saturating_sub(fragment_count);
            let remaining = packet.len() - offset;
            let minimum_remaining_fragments = remaining.div_ceil(full_fragment_capacity.max(1));
            if fragments_left == 0 || minimum_remaining_fragments > fragments_left {
                return Err(RecordizerError::PacketSize);
            }
            if minimum_remaining_fragments == fragments_left && !self.current.is_empty() {
                // Random small targets are morphology, not permission to violate the
                // authenticated receiver's fragment cap. Once no slack remains, flush
                // unrelated queued frames and use full safe records for this packet.
                if let Some(record) = self.flush() {
                    ready.push(record);
                }
            }
            self.ensure_record(now);
            if minimum_remaining_fragments == fragments_left {
                self.current_target = self.config.max_payload_bytes;
            }
            if self.current_packets >= self.config.max_packets
                || self.current_target.saturating_sub(self.current.len()) <= FRAME_HEADER_LEN
            {
                if let Some(record) = self.flush() {
                    ready.push(record);
                }
                continue;
            }
            let available = self.current_target - self.current.len() - FRAME_HEADER_LEN;
            let take = available.min(packet.len() - offset).min(u16::MAX as usize);
            if take == 0 {
                if let Some(record) = self.flush() {
                    ready.push(record);
                }
                continue;
            }
            self.current.extend_from_slice(&packet_id.to_be_bytes());
            self.current.extend_from_slice(&total_len.to_be_bytes());
            self.current
                .extend_from_slice(&(offset as u16).to_be_bytes());
            self.current.extend_from_slice(&(take as u16).to_be_bytes());
            self.current
                .extend_from_slice(&packet[offset..offset + take]);
            self.current_packets += 1;
            fragment_count += 1;
            offset += take;
            if self.current.len() >= self.current_target
                || self.current_packets >= self.config.max_packets
            {
                if let Some(record) = self.flush() {
                    ready.push(record);
                }
            }
        }
        if self.config.delay_max.is_zero() {
            if let Some(record) = self.flush() {
                ready.push(record);
            }
        }
        Ok(ready)
    }

    pub fn flush_due(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.deadline.filter(|deadline| now >= *deadline)?;
        self.flush()
    }

    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.current.is_empty() {
            return None;
        }
        self.deadline = None;
        self.current_target = 0;
        self.current_packets = 0;
        let mut next = Vec::with_capacity(self.config.max_payload_bytes);
        std::mem::swap(&mut self.current, &mut next);
        Some(next)
    }

    fn ensure_record(&mut self, now: Instant) {
        if !self.current.is_empty() {
            return;
        }
        self.current.extend_from_slice(MAGIC);
        self.current_target = choose_target(&self.config);
        self.deadline = Some(now + random_duration(self.config.delay_min, self.config.delay_max));
    }
}

fn choose_target(config: &RuntimeConfig) -> usize {
    let mut rng = rand::rng();
    if rng.random_bool(config.full_probability) {
        return config.max_payload_bytes;
    }
    let raw_min = ((config.max_payload_bytes as f64) * config.small_min_ratio).round() as usize;
    let raw_max = ((config.max_payload_bytes as f64) * config.small_max_ratio).round() as usize;
    let min = raw_min
        .max(MIN_RECORD_PAYLOAD)
        .min(config.max_payload_bytes);
    let max = raw_max.max(min).min(config.max_payload_bytes);
    rng.random_range(min..=max)
}

fn random_duration(min: Duration, max: Duration) -> Duration {
    if max <= min {
        return min;
    }
    let lo = u64::try_from(min.as_millis()).unwrap_or(u64::MAX);
    let hi = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(rand::rng().random_range(lo..=hi))
}

#[derive(Debug)]
struct Chunk {
    offset: usize,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct PendingPacket {
    created_at: Instant,
    total_len: usize,
    chunks: Vec<Chunk>,
    received_bytes: usize,
}

/// Receiver state. One instance belongs to one ordered TCP stream or one UDP
/// session. All limits are authenticated-peer resource bounds.
pub struct Reassembler {
    config: RuntimeConfig,
    pending: HashMap<u32, PendingPacket>,
    buffered_bytes: usize,
}

impl Reassembler {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            pending: HashMap::new(),
            buffered_bytes: 0,
        }
    }

    pub fn decode(&mut self, record: &[u8]) -> Result<Vec<Vec<u8>>, RecordizerError> {
        self.decode_at(record, Instant::now())
    }

    fn decode_at(&mut self, record: &[u8], now: Instant) -> Result<Vec<Vec<u8>>, RecordizerError> {
        self.expire(now);
        if record.len() < MAGIC.len() {
            return Err(RecordizerError::Truncated);
        }
        if &record[..MAGIC.len()] != MAGIC {
            return Err(RecordizerError::Unsupported);
        }
        let mut cursor = MAGIC.len();
        let mut completed = Vec::new();
        while cursor < record.len() {
            if record.len() - cursor < FRAME_HEADER_LEN {
                return Err(RecordizerError::Truncated);
            }
            let packet_id = u32::from_be_bytes(record[cursor..cursor + 4].try_into().unwrap());
            let total_len = usize::from(u16::from_be_bytes(
                record[cursor + 4..cursor + 6].try_into().unwrap(),
            ));
            let offset = usize::from(u16::from_be_bytes(
                record[cursor + 6..cursor + 8].try_into().unwrap(),
            ));
            let payload_len = usize::from(u16::from_be_bytes(
                record[cursor + 8..cursor + 10].try_into().unwrap(),
            ));
            cursor += FRAME_HEADER_LEN;
            let end = cursor
                .checked_add(payload_len)
                .ok_or(RecordizerError::InvalidMetadata)?;
            if total_len == 0
                || total_len > self.config.max_packet_bytes
                || payload_len == 0
                || end > record.len()
                || offset
                    .checked_add(payload_len)
                    .is_none_or(|value| value > total_len)
            {
                return Err(RecordizerError::InvalidMetadata);
            }
            let payload = &record[cursor..end];
            cursor = end;

            if offset == 0 && payload_len == total_len {
                if self.pending.contains_key(&packet_id) {
                    self.remove(packet_id);
                    return Err(RecordizerError::Conflict);
                }
                completed.push(payload.to_vec());
                continue;
            }
            if let Some(packet) = self.pending.get(&packet_id) {
                if packet.total_len != total_len {
                    self.remove(packet_id);
                    return Err(RecordizerError::Conflict);
                }
                if let Some(chunk) = packet
                    .chunks
                    .iter()
                    .find(|chunk| chunk.offset == offset && chunk.bytes.len() == payload_len)
                {
                    if chunk.bytes == payload {
                        continue;
                    }
                    self.remove(packet_id);
                    return Err(RecordizerError::Conflict);
                }
                let new_end = offset + payload_len;
                if packet.chunks.iter().any(|chunk| {
                    let old_end = chunk.offset + chunk.bytes.len();
                    offset < old_end && chunk.offset < new_end
                }) {
                    self.remove(packet_id);
                    return Err(RecordizerError::Conflict);
                }
            } else {
                if self.pending.len() >= self.config.max_inflight_packets {
                    return Err(RecordizerError::ResourceLimit);
                }
                self.pending.insert(
                    packet_id,
                    PendingPacket {
                        created_at: now,
                        total_len,
                        chunks: Vec::new(),
                        received_bytes: 0,
                    },
                );
            }
            if self.buffered_bytes.saturating_add(payload_len) > self.config.max_reassembly_bytes {
                self.remove(packet_id);
                return Err(RecordizerError::ResourceLimit);
            }
            if self
                .pending
                .get(&packet_id)
                .is_some_and(|packet| packet.chunks.len() >= self.config.max_fragments_per_packet)
            {
                self.remove(packet_id);
                return Err(RecordizerError::ResourceLimit);
            }
            let packet = self.pending.get_mut(&packet_id).expect("packet exists");
            packet.chunks.push(Chunk {
                offset,
                bytes: payload.to_vec(),
            });
            packet.received_bytes += payload_len;
            self.buffered_bytes += payload_len;

            if packet.received_bytes == packet.total_len {
                let mut packet = self
                    .pending
                    .remove(&packet_id)
                    .expect("complete packet exists");
                self.buffered_bytes = self.buffered_bytes.saturating_sub(packet.received_bytes);
                packet.chunks.sort_by_key(|chunk| chunk.offset);
                let mut bytes = Vec::with_capacity(packet.total_len);
                for chunk in packet.chunks {
                    if chunk.offset != bytes.len() {
                        return Err(RecordizerError::Conflict);
                    }
                    bytes.extend_from_slice(&chunk.bytes);
                }
                if bytes.len() != packet.total_len {
                    return Err(RecordizerError::Conflict);
                }
                completed.push(bytes);
            }
        }
        if cursor == MAGIC.len() {
            return Err(RecordizerError::InvalidMetadata);
        }
        Ok(completed)
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, packet)| {
                now.saturating_duration_since(packet.created_at) > self.config.reassembly_timeout
            })
            .map(|(packet_id, _)| *packet_id)
            .collect();
        for packet_id in expired {
            self.remove(packet_id);
        }
    }

    fn remove(&mut self, packet_id: u32) {
        if let Some(packet) = self.pending.remove(&packet_id) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(packet.received_bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(max_payload_bytes: usize) -> RuntimeConfig {
        RuntimeConfig {
            delay_min: Duration::ZERO,
            delay_max: Duration::ZERO,
            max_packets: 32,
            max_queue_bytes: max_payload_bytes,
            max_payload_bytes,
            small_min_ratio: 1.0,
            small_max_ratio: 1.0,
            full_probability: 1.0,
            fragment_enabled: true,
            reassembly_timeout: Duration::from_secs(3),
            max_inflight_packets: 8,
            max_reassembly_bytes: 64 * 1024,
            max_fragments_per_packet: 64,
            max_packet_bytes: 16 * 1024,
        }
    }

    #[test]
    fn coalesces_and_restores_packet_boundaries() {
        let mut cfg = config(256);
        cfg.delay_min = Duration::from_millis(5);
        cfg.delay_max = Duration::from_millis(5);
        let mut tx = Recordizer::new(cfg.clone());
        let now = Instant::now();
        assert!(tx.push(b"one", now).unwrap().is_empty());
        assert!(tx.push(b"two", now).unwrap().is_empty());
        let record = tx.flush().unwrap();
        let mut rx = Reassembler::new(cfg);
        assert_eq!(
            rx.decode(&record).unwrap(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
    }

    #[test]
    fn splits_and_reassembles_large_packet() {
        let cfg = config(80);
        let packet: Vec<u8> = (0..500).map(|value| value as u8).collect();
        let mut tx = Recordizer::new(cfg.clone());
        let records = tx.push(&packet, Instant::now()).unwrap();
        assert!(records.len() > 1);
        let mut rx = Reassembler::new(cfg);
        let packets: Vec<Vec<u8>> = records
            .iter()
            .flat_map(|record| rx.decode(record).unwrap())
            .collect();
        assert_eq!(packets, vec![packet]);
    }

    #[test]
    fn batching_waits_until_deadline() {
        let mut cfg = config(256);
        cfg.delay_min = Duration::from_millis(5);
        cfg.delay_max = Duration::from_millis(5);
        let now = Instant::now();
        let mut tx = Recordizer::new(cfg);
        assert!(tx.push(b"packet", now).unwrap().is_empty());
        assert!(tx.flush_due(now + Duration::from_millis(4)).is_none());
        assert!(tx.flush_due(now + Duration::from_millis(5)).is_some());
    }

    #[test]
    fn rejects_overlapping_fragments() {
        let cfg = config(80);
        let mut rx = Reassembler::new(cfg);
        let mut first = Vec::from(MAGIC.as_slice());
        first.extend_from_slice(&1u32.to_be_bytes());
        first.extend_from_slice(&10u16.to_be_bytes());
        first.extend_from_slice(&0u16.to_be_bytes());
        first.extend_from_slice(&6u16.to_be_bytes());
        first.extend_from_slice(b"123456");
        assert!(rx.decode(&first).unwrap().is_empty());
        let mut overlap = Vec::from(MAGIC.as_slice());
        overlap.extend_from_slice(&1u32.to_be_bytes());
        overlap.extend_from_slice(&10u16.to_be_bytes());
        overlap.extend_from_slice(&5u16.to_be_bytes());
        overlap.extend_from_slice(&5u16.to_be_bytes());
        overlap.extend_from_slice(b"67890");
        assert_eq!(rx.decode(&overlap), Err(RecordizerError::Conflict));
    }

    #[test]
    fn sender_rejects_a_packet_that_cannot_fit_the_negotiated_fragment_cap() {
        let mut cfg = config(80);
        cfg.max_fragments_per_packet = 3;
        let mut tx = Recordizer::new(cfg);
        assert_eq!(
            tx.push(&[0x42; 200], Instant::now()),
            Err(RecordizerError::PacketSize)
        );
        assert!(!tx.is_pending());
    }

    #[test]
    fn sender_switches_from_small_targets_before_exceeding_the_fragment_cap() {
        let mut cfg = config(80);
        cfg.small_min_ratio = 0.2;
        cfg.small_max_ratio = 0.2;
        cfg.full_probability = 0.0;
        cfg.max_fragments_per_packet = 4;
        let packet = vec![0x24; 100];
        let mut tx = Recordizer::new(cfg.clone());
        let records = tx.push(&packet, Instant::now()).unwrap();
        assert!(records.len() <= cfg.max_fragments_per_packet);

        let mut rx = Reassembler::new(cfg);
        let restored: Vec<Vec<u8>> = records
            .iter()
            .flat_map(|record| rx.decode(record).unwrap())
            .collect();
        assert_eq!(restored, vec![packet]);
    }

    #[test]
    fn raising_runtime_preserves_pending_data_and_uses_the_new_ceiling() {
        let mut initial = config(80);
        initial.delay_min = Duration::from_millis(5);
        initial.delay_max = Duration::from_millis(5);
        let mut tx = Recordizer::new(initial.clone());
        let now = Instant::now();
        assert!(tx.push(b"queued", now).unwrap().is_empty());

        let mut widened = initial.clone();
        widened.max_payload_bytes = 256;
        widened.max_queue_bytes = 256;
        tx.raise_runtime(widened.clone()).unwrap();

        let queued = tx.flush().unwrap();
        let packet = vec![0x5a; 180];
        assert!(tx.push(&packet, now).unwrap().is_empty());
        let widened_record = tx.flush().unwrap();
        assert!(widened_record.len() > initial.max_payload_bytes);
        assert!(widened_record.len() <= widened.max_payload_bytes);

        let mut rx = Reassembler::new(widened);
        assert_eq!(rx.decode(&queued).unwrap(), vec![b"queued".to_vec()]);
        assert_eq!(rx.decode(&widened_record).unwrap(), vec![packet]);
    }
}
