//! Versioned, bidirectional in-tunnel control framing.
//!
//! CONTROL_V2 is carried only as the plaintext of an authenticated `PacketCodec` record and
//! only after both peers advertise the corresponding capability. This module freezes the wire
//! format and implements bounded fragmentation/reassembly; it does not advertise the capability
//! or attach handlers to a live session during roaming stage 0.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const MAGIC: [u8; 2] = [0xC1, 0x9C];
pub const VERSION: u8 = 2;
/// magic(2), version(1), type(1), flags(1), message id(4), part index(2),
/// part count(2), payload length(2).
pub const HEADER_LEN: usize = 15;

pub const FLAG_ACK_REQUIRED: u8 = 1 << 0;
pub const FLAG_ACK: u8 = 1 << 1;
pub const FLAG_ERROR: u8 = 1 << 2;
pub const KNOWN_FLAGS: u8 = FLAG_ACK_REQUIRED | FLAG_ACK | FLAG_ERROR;

pub const TYPE_ACK: u8 = 0x01;
pub const TYPE_ERROR: u8 = 0x02;
pub const TYPE_PUSH_CONFIG: u8 = 0x10;
pub const TYPE_NOTICE: u8 = 0x11;
pub const TYPE_PATH_INIT: u8 = 0x20;
pub const TYPE_PATH_CHALLENGE: u8 = 0x21;
pub const TYPE_PATH_RESPONSE: u8 = 0x22;
pub const TYPE_PATH_COMMIT: u8 = 0x23;
pub const TYPE_PATH_ABORT: u8 = 0x24;
pub const TYPE_CLOSE_SESSION: u8 = 0x25;
pub const TYPE_SESSION_REVOKED: u8 = 0x26;
pub const TYPE_KICK: u8 = 0x27;

/// A part is deliberately much smaller than the maximum PacketCodec plaintext. That leaves a
/// stable budget for recordizer/transport envelopes and avoids a control message monopolising a
/// writer queue with a record at the protocol ceiling.
pub const MAX_PART_PAYLOAD: usize = 4 * 1024;
pub const MAX_PARTS: u16 = 16;
pub const MAX_MESSAGE_SIZE: usize = MAX_PART_PAYLOAD * MAX_PARTS as usize;
pub const MAX_INFLIGHT_MESSAGES: usize = 8;
pub const COMPLETED_ID_CACHE: usize = 64;
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ControlV2Error {
    #[error("not a CONTROL_V2 frame")]
    NotControlV2,
    #[error("truncated CONTROL_V2 header or payload")]
    Truncated,
    #[error("unsupported CONTROL_V2 version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown CONTROL_V2 flag bits 0x{0:02x}")]
    InvalidFlags(u8),
    #[error("invalid ACK/error flag and message-type combination")]
    InvalidStatusFrame,
    #[error("invalid CONTROL_V2 payload length")]
    InvalidLength,
    #[error("invalid CONTROL_V2 fragment metadata")]
    InvalidFragment,
    #[error("CONTROL_V2 part exceeds the per-part limit")]
    PartTooLarge,
    #[error("CONTROL_V2 message exceeds the reassembly limit")]
    MessageTooLarge,
    #[error("CONTROL_V2 message requires too many parts")]
    TooManyParts,
    #[error("CONTROL_V2 reassembly resource limit reached")]
    ResourceLimit,
    #[error("CONTROL_V2 fragment arrived out of order")]
    OutOfOrder,
    #[error("CONTROL_V2 fragment conflicts with prior state")]
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub message_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub part_index: u16,
    pub part_count: u16,
    pub payload: &'a [u8],
}

fn validate_metadata(frame: &Frame<'_>) -> Result<(), ControlV2Error> {
    if frame.flags & !KNOWN_FLAGS != 0 {
        return Err(ControlV2Error::InvalidFlags(frame.flags & !KNOWN_FLAGS));
    }
    if frame.payload.len() > MAX_PART_PAYLOAD || frame.payload.len() > u16::MAX as usize {
        return Err(ControlV2Error::PartTooLarge);
    }
    if frame.part_count == 0 || frame.part_index >= frame.part_count {
        return Err(ControlV2Error::InvalidFragment);
    }
    if frame.part_count > MAX_PARTS {
        return Err(ControlV2Error::TooManyParts);
    }

    let ack = frame.flags & FLAG_ACK != 0;
    let error = frame.flags & FLAG_ERROR != 0;
    if ack && error
        || ack != (frame.message_type == TYPE_ACK)
        || error != (frame.message_type == TYPE_ERROR)
        || (ack || error) && frame.flags & FLAG_ACK_REQUIRED != 0
        || (ack || error) && frame.part_count != 1
        || ack && !frame.payload.is_empty()
    {
        return Err(ControlV2Error::InvalidStatusFrame);
    }
    Ok(())
}

impl Frame<'_> {
    pub fn encode(&self) -> Result<Vec<u8>, ControlV2Error> {
        validate_metadata(self)?;
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.message_type);
        out.push(self.flags);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.part_index.to_be_bytes());
        out.extend_from_slice(&self.part_count.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(self.payload);
        Ok(out)
    }
}

#[inline]
pub fn is_control_v2(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && bytes[..MAGIC.len()] == MAGIC
}

pub fn decode(bytes: &[u8]) -> Result<Frame<'_>, ControlV2Error> {
    if !is_control_v2(bytes) {
        return Err(ControlV2Error::NotControlV2);
    }
    if bytes.len() < HEADER_LEN {
        return Err(ControlV2Error::Truncated);
    }
    if bytes[2] != VERSION {
        return Err(ControlV2Error::UnsupportedVersion(bytes[2]));
    }
    let payload_len = u16::from_be_bytes([bytes[13], bytes[14]]) as usize;
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ControlV2Error::InvalidLength)?;
    if total != bytes.len() {
        return Err(if total > bytes.len() {
            ControlV2Error::Truncated
        } else {
            ControlV2Error::InvalidLength
        });
    }
    let frame = Frame {
        message_type: bytes[3],
        flags: bytes[4],
        message_id: u32::from_be_bytes(bytes[5..9].try_into().expect("fixed header slice")),
        part_index: u16::from_be_bytes(bytes[9..11].try_into().expect("fixed header slice")),
        part_count: u16::from_be_bytes(bytes[11..13].try_into().expect("fixed header slice")),
        payload: &bytes[HEADER_LEN..],
    };
    validate_metadata(&frame)?;
    Ok(frame)
}

/// Split one logical message into independently authenticated PacketCodec plaintexts.
pub fn fragment_message(
    message_type: u8,
    flags: u8,
    message_id: u32,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, ControlV2Error> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(ControlV2Error::MessageTooLarge);
    }
    let part_count = payload.len().max(1).div_ceil(MAX_PART_PAYLOAD);
    if part_count > MAX_PARTS as usize {
        return Err(ControlV2Error::TooManyParts);
    }
    let mut frames = Vec::with_capacity(part_count);
    if payload.is_empty() {
        frames.push(
            Frame {
                message_type,
                flags,
                message_id,
                part_index: 0,
                part_count: 1,
                payload,
            }
            .encode()?,
        );
        return Ok(frames);
    }
    for (index, part) in payload.chunks(MAX_PART_PAYLOAD).enumerate() {
        frames.push(
            Frame {
                message_type,
                flags,
                message_id,
                part_index: index as u16,
                part_count: part_count as u16,
                payload: part,
            }
            .encode()?,
        );
    }
    Ok(frames)
}

pub fn ack(message_id: u32) -> Vec<u8> {
    Frame {
        message_type: TYPE_ACK,
        flags: FLAG_ACK,
        message_id,
        part_index: 0,
        part_count: 1,
        payload: &[],
    }
    .encode()
    .expect("the fixed ACK frame is valid")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub message_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyOutcome {
    Pending,
    Duplicate,
    Complete(Message),
}

#[derive(Debug)]
struct Assembly {
    message_type: u8,
    flags: u8,
    part_count: u16,
    parts: Vec<Vec<u8>>,
    total_len: usize,
    started_at: Instant,
}

/// Per-direction bounded assembler. A session owns one instance for each receive direction;
/// sharing IDs across directions would let an ACK suppress an unrelated peer message.
#[derive(Debug, Default)]
pub struct Reassembler {
    inflight: HashMap<u32, Assembly>,
    completed: VecDeque<u32>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.inflight.len();
        self.inflight.retain(|_, assembly| {
            now.saturating_duration_since(assembly.started_at) < REASSEMBLY_TIMEOUT
        });
        before - self.inflight.len()
    }

    fn remember_completed(&mut self, message_id: u32) {
        if self.completed.len() == COMPLETED_ID_CACHE {
            self.completed.pop_front();
        }
        self.completed.push_back(message_id);
    }

    pub fn push(
        &mut self,
        now: Instant,
        frame: Frame<'_>,
    ) -> Result<ReassemblyOutcome, ControlV2Error> {
        validate_metadata(&frame)?;
        self.expire(now);
        if self.completed.contains(&frame.message_id) {
            return Ok(ReassemblyOutcome::Duplicate);
        }

        if frame.part_count == 1 {
            self.remember_completed(frame.message_id);
            return Ok(ReassemblyOutcome::Complete(Message {
                message_type: frame.message_type,
                flags: frame.flags,
                message_id: frame.message_id,
                payload: frame.payload.to_vec(),
            }));
        }

        if !self.inflight.contains_key(&frame.message_id) {
            if frame.part_index != 0 {
                return Err(ControlV2Error::OutOfOrder);
            }
            if self.inflight.len() >= MAX_INFLIGHT_MESSAGES {
                return Err(ControlV2Error::ResourceLimit);
            }
            self.inflight.insert(
                frame.message_id,
                Assembly {
                    message_type: frame.message_type,
                    flags: frame.flags,
                    part_count: frame.part_count,
                    parts: Vec::with_capacity(frame.part_count as usize),
                    total_len: 0,
                    started_at: now,
                },
            );
        }

        let assembly = self
            .inflight
            .get_mut(&frame.message_id)
            .expect("assembly inserted or already present");
        if assembly.message_type != frame.message_type
            || assembly.flags != frame.flags
            || assembly.part_count != frame.part_count
        {
            return Err(ControlV2Error::Conflict);
        }

        let index = frame.part_index as usize;
        if index < assembly.parts.len() {
            return if assembly.parts[index].as_slice() == frame.payload {
                Ok(ReassemblyOutcome::Duplicate)
            } else {
                Err(ControlV2Error::Conflict)
            };
        }
        if index != assembly.parts.len() {
            return Err(ControlV2Error::OutOfOrder);
        }
        let next_total = assembly
            .total_len
            .checked_add(frame.payload.len())
            .ok_or(ControlV2Error::MessageTooLarge)?;
        if next_total > MAX_MESSAGE_SIZE {
            return Err(ControlV2Error::MessageTooLarge);
        }
        assembly.total_len = next_total;
        assembly.parts.push(frame.payload.to_vec());

        if assembly.parts.len() != assembly.part_count as usize {
            return Ok(ReassemblyOutcome::Pending);
        }

        let assembly = self
            .inflight
            .remove(&frame.message_id)
            .expect("complete assembly remains registered");
        let mut payload = Vec::with_capacity(assembly.total_len);
        for part in assembly.parts {
            payload.extend_from_slice(&part);
        }
        self.remember_completed(frame.message_id);
        Ok(ReassemblyOutcome::Complete(Message {
            message_type: assembly.message_type,
            flags: assembly.flags,
            message_id: frame.message_id,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_single_part_wire_vector_roundtrips() {
        let wire = Frame {
            message_type: TYPE_NOTICE,
            flags: FLAG_ACK_REQUIRED,
            message_id: 0x0102_0304,
            part_index: 0,
            part_count: 1,
            payload: b"ok",
        }
        .encode()
        .unwrap();
        assert_eq!(
            wire,
            vec![
                0xC1, 0x9C, 0x02, 0x11, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x02, b'o', b'k',
            ]
        );
        assert_eq!(decode(&wire).unwrap().payload, b"ok");
    }

    #[test]
    fn v1_and_ip_packets_cannot_be_misclassified_as_v2() {
        assert!(!is_control_v2(&[0xC1, 0x9B, 1, 0]));
        assert!(!is_control_v2(&[0x45, 0, 0, 20]));
        assert!(!is_control_v2(&[0x60, 0, 0, 0]));
        assert_ne!(MAGIC[0] >> 4, 4);
        assert_ne!(MAGIC[0] >> 4, 6);
    }

    #[test]
    fn malformed_or_ambiguous_frames_are_rejected() {
        let good = fragment_message(TYPE_NOTICE, 0, 7, b"hello")
            .unwrap()
            .remove(0);
        assert_eq!(
            decode(&good[..HEADER_LEN - 1]),
            Err(ControlV2Error::Truncated)
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(ControlV2Error::InvalidLength));
        let mut reserved = good.clone();
        reserved[4] = 0x80;
        assert_eq!(decode(&reserved), Err(ControlV2Error::InvalidFlags(0x80)));
        let mut wrong_version = good;
        wrong_version[2] = 3;
        assert_eq!(
            decode(&wrong_version),
            Err(ControlV2Error::UnsupportedVersion(3))
        );
    }

    #[test]
    fn ack_semantics_are_unambiguous() {
        let wire = ack(42);
        let frame = decode(&wire).unwrap();
        assert_eq!(frame.message_type, TYPE_ACK);
        assert_eq!(frame.flags, FLAG_ACK);
        assert_eq!(frame.message_id, 42);
        assert!(frame.payload.is_empty());
        assert_eq!(
            fragment_message(TYPE_ACK, 0, 42, b""),
            Err(ControlV2Error::InvalidStatusFrame)
        );
    }

    #[test]
    fn bounded_fragmentation_reassembles_in_order_and_deduplicates() {
        let payload = vec![0xA5; MAX_PART_PAYLOAD * 2 + 17];
        let frames = fragment_message(TYPE_PUSH_CONFIG, FLAG_ACK_REQUIRED, 99, &payload).unwrap();
        assert_eq!(frames.len(), 3);
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        assert_eq!(
            reassembler.push(now, decode(&frames[0]).unwrap()).unwrap(),
            ReassemblyOutcome::Pending
        );
        assert_eq!(
            reassembler.push(now, decode(&frames[0]).unwrap()).unwrap(),
            ReassemblyOutcome::Duplicate
        );
        assert_eq!(
            reassembler.push(now, decode(&frames[1]).unwrap()).unwrap(),
            ReassemblyOutcome::Pending
        );
        let complete = reassembler.push(now, decode(&frames[2]).unwrap()).unwrap();
        assert_eq!(
            complete,
            ReassemblyOutcome::Complete(Message {
                message_type: TYPE_PUSH_CONFIG,
                flags: FLAG_ACK_REQUIRED,
                message_id: 99,
                payload,
            })
        );
        assert_eq!(
            reassembler.push(now, decode(&frames[2]).unwrap()).unwrap(),
            ReassemblyOutcome::Duplicate
        );
    }

    #[test]
    fn out_of_order_conflict_timeout_and_resource_caps_fail_closed() {
        let payload = vec![1; MAX_PART_PAYLOAD + 1];
        let frames = fragment_message(TYPE_NOTICE, 0, 1, &payload).unwrap();
        let now = Instant::now();
        let mut reassembler = Reassembler::new();
        assert_eq!(
            reassembler.push(now, decode(&frames[1]).unwrap()),
            Err(ControlV2Error::OutOfOrder)
        );
        reassembler.push(now, decode(&frames[0]).unwrap()).unwrap();
        let mut conflict = frames[0].clone();
        conflict[HEADER_LEN] ^= 1;
        assert_eq!(
            reassembler.push(now, decode(&conflict).unwrap()),
            Err(ControlV2Error::Conflict)
        );
        assert_eq!(
            reassembler.expire(now + REASSEMBLY_TIMEOUT),
            1,
            "deadline is exclusive"
        );

        for id in 0..MAX_INFLIGHT_MESSAGES as u32 {
            let frames = fragment_message(TYPE_NOTICE, 0, 100 + id, &payload).unwrap();
            assert_eq!(
                reassembler.push(now, decode(&frames[0]).unwrap()).unwrap(),
                ReassemblyOutcome::Pending
            );
        }
        let extra = fragment_message(TYPE_NOTICE, 0, 999, &payload).unwrap();
        assert_eq!(
            reassembler.push(now, decode(&extra[0]).unwrap()),
            Err(ControlV2Error::ResourceLimit)
        );
        assert_eq!(
            fragment_message(TYPE_NOTICE, 0, 1, &vec![0; MAX_MESSAGE_SIZE + 1]),
            Err(ControlV2Error::MessageTooLarge)
        );
    }
}
