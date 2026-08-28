//! Authenticated fragmentation of encrypted UDP data records.
//!
//! The complete inner packet is encrypted by [`crate::protocol::PacketCodec`] first. The
//! resulting opaque record is then split into independently authenticated envelopes. This
//! keeps IP datagrams intact, avoids outer IP fragmentation, and leaves PacketCodec's AEAD
//! replay protection as the final check after exact reassembly.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub const MAGIC: [u8; 4] = [0xf1, b'Q', b'D', b'F'];
const VERSION: u8 = 1;
const FLAGS: u8 = 0;
const TAG_LEN: usize = 16;
const HEADER_WITHOUT_TAG: usize = 28;
pub const HEADER_LEN: usize = HEADER_WITHOUT_TAG + TAG_LEN;
pub const MAX_FRAGMENTS: u16 = 64;
pub const MAX_REASSEMBLY_RECORDS: usize = 32;
pub const MAX_REASSEMBLY_BYTES: usize = 512 * 1024;
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_REASSEMBLED_RECORD: usize =
    crate::protocol::packet::TLS_RECORD_HEADER + crate::protocol::packet::MAX_RECORD_SIZE;
/// UDP payload guaranteed by an IPv6 path at the mandatory 1280-byte link MTU.
pub const IPV6_MIN_UDP_PAYLOAD: usize = 1280 - 40 - 8;
/// Supported conservative IPv4 floor: 576-byte path minus IPv4 and UDP headers.
pub const IPV4_MIN_UDP_PAYLOAD: usize = 576 - 20 - 8;

/// Linux PMTU discovery mode used while sending active QELI MTU probes.
///
/// `IP_PMTUDISC_PROBE` deliberately ignores the route/cached PMTU and therefore
/// can report a payload size that the normal data path (`IP_PMTUDISC_DO`) cannot
/// send. Active probes still need DF, but must obey the kernel path-MTU view so
/// that the discovered budget is valid for subsequent DATA/DATA_FRAG packets.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const ACTIVE_PMTUDISC_MODE: libc::c_int = libc::IP_PMTUDISC_DO;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DataFragError {
    #[error("fragment payload budget is too small")]
    BudgetTooSmall,
    #[error("record does not require fragmentation")]
    NotFragmented,
    #[error("record exceeds the reassembly size limit")]
    RecordTooLarge,
    #[error("record requires too many fragments")]
    TooManyFragments,
    #[error("truncated data fragment")]
    Truncated,
    #[error("unsupported data fragment version or flags")]
    Unsupported,
    #[error("invalid data fragment metadata")]
    InvalidMetadata,
    #[error("data fragment authentication failed")]
    Authentication,
    #[error("data fragment conflicts with an earlier fragment")]
    Conflict,
    #[error("data reassembly resource limit reached")]
    ResourceLimit,
}

#[derive(Debug)]
struct ParsedFragment<'a> {
    record_id: u64,
    offset: u32,
    total_len: u32,
    index: u16,
    count: u16,
    payload: &'a [u8],
}

#[derive(Debug)]
struct Chunk {
    offset: u32,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct PendingRecord {
    created_at: Instant,
    total_len: u32,
    count: u16,
    chunks: Vec<Option<Chunk>>,
    received_count: u16,
    received_bytes: usize,
}

/// True only for the explicit envelope magic. A matching magic with malformed contents is
/// treated as a bad fragment, never retried as an AEAD record.
pub fn is_data_fragment(datagram: &[u8]) -> bool {
    datagram.get(..MAGIC.len()) == Some(MAGIC.as_slice())
}

pub const fn conservative_udp_payload_budget(outer_ipv6: bool) -> usize {
    if outer_ipv6 {
        IPV6_MIN_UDP_PAYLOAD
    } else {
        IPV4_MIN_UDP_PAYLOAD
    }
}

/// Largest PacketCodec record that fits one socket send after wrappers outside the record.
pub fn unfragmented_record_budget(
    udp_payload_budget: usize,
    obfs_overhead: usize,
    quic_enabled: bool,
) -> Result<usize, DataFragError> {
    unfragmented_record_budget_with_wrapper(
        udp_payload_budget,
        obfs_overhead,
        if quic_enabled {
            crate::protocol::quic::QUIC_SHORT_HEADER_MIN
        } else {
            0
        },
    )
}

/// Variant used by roaming-aware actors, where the QUIC-shaped wrapper can carry either a
/// legacy four-byte connection id or an eight-byte directional CID.
pub fn unfragmented_record_budget_with_wrapper(
    udp_payload_budget: usize,
    obfs_overhead: usize,
    wrapper_len: usize,
) -> Result<usize, DataFragError> {
    udp_payload_budget
        .checked_sub(obfs_overhead)
        .and_then(|value| value.checked_sub(wrapper_len))
        .filter(|value| *value > HEADER_LEN)
        .ok_or(DataFragError::BudgetTooSmall)
}

/// Split one already-encrypted PacketCodec record into authenticated envelopes.
/// `max_payload` is the maximum chunk bytes after subtracting the data-fragment header and
/// every wrapper outside it from the local outer-UDP datagram budget.
pub fn fragment_record(
    record: &[u8],
    key: &[u8; 32],
    record_id: u64,
    max_payload: usize,
) -> Result<Vec<Vec<u8>>, DataFragError> {
    if max_payload == 0 {
        return Err(DataFragError::BudgetTooSmall);
    }
    if record.len() <= max_payload {
        return Err(DataFragError::NotFragmented);
    }
    if record.len() > MAX_REASSEMBLED_RECORD || record.len() > u32::MAX as usize {
        return Err(DataFragError::RecordTooLarge);
    }
    let count = record.len().div_ceil(max_payload);
    if count > usize::from(MAX_FRAGMENTS) || count > u16::MAX as usize {
        return Err(DataFragError::TooManyFragments);
    }
    let count = count as u16;
    let total_len = record.len() as u32;
    let mut fragments = Vec::with_capacity(usize::from(count));
    for (index, payload) in record.chunks(max_payload).enumerate() {
        let offset = index
            .checked_mul(max_payload)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(DataFragError::RecordTooLarge)?;
        let mut datagram = Vec::with_capacity(HEADER_LEN + payload.len());
        datagram.extend_from_slice(&MAGIC);
        datagram.push(VERSION);
        datagram.push(FLAGS);
        datagram.extend_from_slice(&record_id.to_le_bytes());
        datagram.extend_from_slice(&offset.to_le_bytes());
        datagram.extend_from_slice(&total_len.to_le_bytes());
        datagram.extend_from_slice(&(index as u16).to_le_bytes());
        datagram.extend_from_slice(&count.to_le_bytes());
        datagram.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        let tag = fragment_tag(key, &datagram, payload);
        datagram.extend_from_slice(&tag);
        datagram.extend_from_slice(payload);
        fragments.push(datagram);
    }
    Ok(fragments)
}

fn fragment_tag(key: &[u8; 32], header: &[u8], payload: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(header);
    mac.update(payload);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

fn parse_and_authenticate<'a>(
    datagram: &'a [u8],
    key: &[u8; 32],
) -> Result<ParsedFragment<'a>, DataFragError> {
    if datagram.len() < HEADER_LEN {
        return Err(DataFragError::Truncated);
    }
    if !is_data_fragment(datagram) {
        return Err(DataFragError::InvalidMetadata);
    }
    if datagram[4] != VERSION || datagram[5] != FLAGS {
        return Err(DataFragError::Unsupported);
    }
    let record_id = u64::from_le_bytes(datagram[6..14].try_into().unwrap());
    let offset = u32::from_le_bytes(datagram[14..18].try_into().unwrap());
    let total_len = u32::from_le_bytes(datagram[18..22].try_into().unwrap());
    let index = u16::from_le_bytes(datagram[22..24].try_into().unwrap());
    let count = u16::from_le_bytes(datagram[24..26].try_into().unwrap());
    let payload_len = usize::from(u16::from_le_bytes(datagram[26..28].try_into().unwrap()));
    if !(2..=MAX_FRAGMENTS).contains(&count)
        || index >= count
        || payload_len == 0
        || total_len == 0
        || total_len as usize > MAX_REASSEMBLED_RECORD
        || datagram.len() != HEADER_LEN + payload_len
        || (offset as usize)
            .checked_add(payload_len)
            .is_none_or(|end| end > total_len as usize)
    {
        return Err(DataFragError::InvalidMetadata);
    }
    let expected = fragment_tag(
        key,
        &datagram[..HEADER_WITHOUT_TAG],
        &datagram[HEADER_LEN..],
    );
    if expected
        .ct_eq(&datagram[HEADER_WITHOUT_TAG..HEADER_LEN])
        .unwrap_u8()
        != 1
    {
        return Err(DataFragError::Authentication);
    }
    Ok(ParsedFragment {
        record_id,
        offset,
        total_len,
        index,
        count,
        payload: &datagram[HEADER_LEN..],
    })
}

#[derive(Debug, Default)]
pub struct DataReassembler {
    entries: HashMap<u64, PendingRecord>,
    buffered_bytes: usize,
}

impl DataReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(
        &mut self,
        datagram: &[u8],
        key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, DataFragError> {
        self.push_at(datagram, key, Instant::now())
    }

    fn push_at(
        &mut self,
        datagram: &[u8],
        key: &[u8; 32],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, DataFragError> {
        let fragment = parse_and_authenticate(datagram, key)?;
        self.expire(now);

        if let Some(existing) = self.entries.get(&fragment.record_id) {
            if existing.total_len != fragment.total_len || existing.count != fragment.count {
                self.remove(fragment.record_id);
                return Err(DataFragError::Conflict);
            }
            if let Some(chunk) = &existing.chunks[usize::from(fragment.index)] {
                return if chunk.offset == fragment.offset && chunk.bytes == fragment.payload {
                    Ok(None)
                } else {
                    self.remove(fragment.record_id);
                    Err(DataFragError::Conflict)
                };
            }
            let new_start = fragment.offset as usize;
            let new_end = new_start + fragment.payload.len();
            if existing.chunks.iter().flatten().any(|chunk| {
                let start = chunk.offset as usize;
                let end = start + chunk.bytes.len();
                new_start < end && start < new_end
            }) {
                self.remove(fragment.record_id);
                return Err(DataFragError::Conflict);
            }
        } else {
            if self.entries.len() >= MAX_REASSEMBLY_RECORDS {
                return Err(DataFragError::ResourceLimit);
            }
            self.entries.insert(
                fragment.record_id,
                PendingRecord {
                    created_at: now,
                    total_len: fragment.total_len,
                    count: fragment.count,
                    chunks: (0..fragment.count).map(|_| None).collect(),
                    received_count: 0,
                    received_bytes: 0,
                },
            );
        }

        if self.buffered_bytes.saturating_add(fragment.payload.len()) > MAX_REASSEMBLY_BYTES {
            self.remove(fragment.record_id);
            return Err(DataFragError::ResourceLimit);
        }
        let entry = self
            .entries
            .get_mut(&fragment.record_id)
            .expect("entry was inserted or already present");
        entry.chunks[usize::from(fragment.index)] = Some(Chunk {
            offset: fragment.offset,
            bytes: fragment.payload.to_vec(),
        });
        entry.received_count += 1;
        entry.received_bytes += fragment.payload.len();
        self.buffered_bytes += fragment.payload.len();

        if entry.received_count != entry.count {
            return Ok(None);
        }
        let mut entry = self
            .entries
            .remove(&fragment.record_id)
            .expect("complete entry exists");
        self.buffered_bytes = self.buffered_bytes.saturating_sub(entry.received_bytes);
        let mut chunks: Vec<Chunk> = entry.chunks.drain(..).flatten().collect();
        chunks.sort_by_key(|chunk| chunk.offset);
        let mut record = Vec::with_capacity(entry.total_len as usize);
        for chunk in chunks {
            if chunk.offset as usize != record.len() {
                return Err(DataFragError::Conflict);
            }
            record.extend_from_slice(&chunk.bytes);
        }
        if record.len() != entry.total_len as usize {
            return Err(DataFragError::Conflict);
        }
        Ok(Some(record))
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                now.saturating_duration_since(entry.created_at) > REASSEMBLY_TIMEOUT
            })
            .map(|(record_id, _)| *record_id)
            .collect();
        for record_id in expired {
            self.remove(record_id);
        }
    }

    fn remove(&mut self, record_id: u64) {
        if let Some(entry) = self.entries.remove(&record_id) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(entry.received_bytes);
        }
    }

    #[cfg(test)]
    fn pending(&self) -> (usize, usize) {
        (self.entries.len(), self.buffered_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn active_pmtu_probes_use_the_normal_df_mode() {
        assert_eq!(ACTIVE_PMTUDISC_MODE, libc::IP_PMTUDISC_DO);
        assert_ne!(ACTIVE_PMTUDISC_MODE, libc::IP_PMTUDISC_PROBE);
    }

    #[test]
    fn reorder_reassembles_exact_encrypted_record() {
        let record: Vec<u8> = (0..1500).map(|value| value as u8).collect();
        let mut fragments = fragment_record(&record, &KEY, 7, 400).unwrap();
        fragments.reverse();
        let mut reassembler = DataReassembler::new();
        let mut completed = None;
        for fragment in fragments {
            if let Some(value) = reassembler.push(&fragment, &KEY).unwrap() {
                completed = Some(value);
            }
        }
        assert_eq!(completed, Some(record));
        assert_eq!(reassembler.pending(), (0, 0));
    }

    #[test]
    fn tampered_mac_is_rejected_before_state_allocation() {
        let mut fragment = fragment_record(&vec![1u8; 1000], &KEY, 9, 500)
            .unwrap()
            .remove(0);
        *fragment.last_mut().unwrap() ^= 1;
        let mut reassembler = DataReassembler::new();
        assert_eq!(
            reassembler.push(&fragment, &KEY),
            Err(DataFragError::Authentication)
        );
        assert_eq!(reassembler.pending(), (0, 0));
    }

    #[test]
    fn exact_duplicate_is_idempotent_but_conflict_drops_record() {
        let a = fragment_record(&vec![1u8; 1000], &KEY, 11, 500).unwrap();
        let b = fragment_record(&vec![2u8; 1000], &KEY, 11, 500).unwrap();
        let mut reassembler = DataReassembler::new();
        assert_eq!(reassembler.push(&a[0], &KEY).unwrap(), None);
        assert_eq!(reassembler.push(&a[0], &KEY).unwrap(), None);
        assert_eq!(reassembler.push(&b[0], &KEY), Err(DataFragError::Conflict));
        assert_eq!(reassembler.pending(), (0, 0));
    }

    #[test]
    fn incomplete_record_expires_and_releases_budget() {
        let incomplete = fragment_record(&vec![3u8; 1000], &KEY, 12, 500).unwrap();
        let replacement_record = vec![4u8; 1000];
        let replacement = fragment_record(&replacement_record, &KEY, 13, 500).unwrap();
        let start = Instant::now();
        let after_timeout = start + REASSEMBLY_TIMEOUT + Duration::from_millis(1);
        let mut reassembler = DataReassembler::new();
        assert_eq!(
            reassembler.push_at(&incomplete[0], &KEY, start).unwrap(),
            None
        );
        assert_ne!(reassembler.pending(), (0, 0));
        assert_eq!(
            reassembler
                .push_at(&replacement[0], &KEY, after_timeout)
                .unwrap(),
            None
        );
        assert_eq!(
            reassembler
                .push_at(&replacement[1], &KEY, after_timeout)
                .unwrap(),
            Some(replacement_record)
        );
        assert_eq!(reassembler.pending(), (0, 0));
    }

    #[test]
    fn small_records_are_not_needlessly_enveloped() {
        assert_eq!(
            fragment_record(&[1, 2, 3], &KEY, 1, 100),
            Err(DataFragError::NotFragmented)
        );
    }

    #[test]
    fn every_fragment_fits_the_complete_ipv4_and_ipv6_outer_budget() {
        for outer_ipv6 in [false, true] {
            for obfs_overhead in [0usize, 24, 96] {
                for quic_enabled in [false, true] {
                    let udp_budget = conservative_udp_payload_budget(outer_ipv6);
                    let record_budget =
                        unfragmented_record_budget(udp_budget, obfs_overhead, quic_enabled)
                            .unwrap();
                    let record = vec![0x5a; record_budget + 1];
                    let fragments =
                        fragment_record(&record, &KEY, 99, record_budget - HEADER_LEN).unwrap();
                    assert!(fragments.len() >= 2);
                    let quic_overhead = if quic_enabled {
                        crate::protocol::quic::QUIC_SHORT_HEADER_MIN
                    } else {
                        0
                    };
                    assert!(fragments.iter().all(|fragment| {
                        fragment.len() + obfs_overhead + quic_overhead <= udp_budget
                    }));
                }
            }
        }
    }
}
