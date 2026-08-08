// QUIC-masking: the wrap/unwrap path is used; the header/packet parse structs
// (QuicHeader/QuicPacket/QuicError) are API surface for the planned UDP-side use.
#![allow(dead_code)]
use rand::prelude::*;

const QUIC_VERSION_V1: u32 = 0x00000001;
const QUIC_LONG_HEADER_FLAG: u8 = 0xC0;
const QUIC_SHORT_HEADER_FLAG: u8 = 0x40;

/// Smallest long header this parser will even look at: flags(1) + version(4) +
/// dcid_len(1) + scid_len(1) + token_len varint(1) + length varint(1) + pn(1).
///
/// This is deliberately the RFC-minimum and NOT the size we emit — a peer may legally
/// use empty connection IDs and 1-byte varints. Every field past this point is
/// bounds-checked individually by `unwrap_quic`, so the gate only has to exclude
/// packets too short to hold any header at all.
pub const QUIC_LONG_HEADER_MIN: usize = 1 + 4 + 1 + 1 + 1 + 1 + 1;
pub const QUIC_SHORT_HEADER_MIN: usize = 1 + 4 + 4;

/// Exact size of the long header `wrap_quic_long` produces: flags(1) + version(4) +
/// dcid_len(1) + dcid(4) + scid_len(1) + token_len(1) + length varint(2) + pn(4).
///
/// Kept separate from `QUIC_LONG_HEADER_MIN`, which used to be reused for the
/// `with_capacity` hint while being computed from an older layout without the Token
/// Length and Length fields — so every masked datagram under-reserved by 6 bytes and
/// reallocated on the hot path. (Audit 2026-07-27, X3.)
/// Bytes `wrap_quic_long` actually emits ahead of the payload: flags(1) + version(4) +
/// DCID len(1) + DCID(4) + SCID len(1) + Token Length(1) + Length varint(2) + packet
/// number(4). Public because the handshake fragmenter has to budget for it — see
/// [`crate::protocol::udp_frag::MAX_CHUNK`].
pub const QUIC_LONG_HEADER_EMITTED: usize = 1 + 4 + 1 + 4 + 1 + 1 + 2 + 4;

/// Append `v` as a QUIC variable-length integer (RFC 9000 §16), choosing the shortest
/// encoding that fits. Returns false when the value exceeds the 4-byte (30-bit) form —
/// the caller decides what to do rather than emitting a corrupted field.
///
/// Replaces a hard-coded 2-byte varint built as `((pn_len + data.len()) as u16) & 0x3FFF`
/// in `wrap_quic_long`: a silent truncation whose only guard was a `debug_assert!`, which
/// release builds strip. No caller sends 16 KiB in a single datagram today, but
/// "unreachable now, corrupt later" is precisely the class already fixed once in
/// `packet.rs::encrypt_packet`. The parse side (`read_varint`) has always accepted every
/// varint form, so emitting the longer encoding costs nothing. (Audit 2026-07-27, F5.)
fn push_varint(out: &mut Vec<u8>, v: u64) -> bool {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        out.push(0x40 | (v >> 8) as u8);
        out.push((v & 0xFF) as u8);
    } else if v < 0x4000_0000 {
        out.push(0x80 | (v >> 24) as u8);
        out.push(((v >> 16) & 0xFF) as u8);
        out.push(((v >> 8) & 0xFF) as u8);
        out.push((v & 0xFF) as u8);
    } else {
        return false;
    }
    true
}

pub struct QuicHeader {
    pub connection_id: [u8; 4],
    pub packet_number: u32,
    pub is_long: bool,
}

pub fn wrap_quic_long(
    data: &[u8],
    connection_id: &[u8; 4],
    packet_number: u32,
    packet_type: u8,
) -> Vec<u8> {
    let mut packet = Vec::new();
    wrap_quic_long_into(data, connection_id, packet_number, packet_type, &mut packet);
    packet
}

/// Caller-provided variant of [`wrap_quic_long`]. The output allocation is retained
/// across calls, which is useful for sequential UDP data-plane sends.
pub fn wrap_quic_long_into(
    data: &[u8],
    connection_id: &[u8; 4],
    packet_number: u32,
    packet_type: u8,
    packet: &mut Vec<u8>,
) {
    // RFC 9000 §17.2 long header + RFC 9001 §17.2.2 Initial fields. The long
    // packet type lives in bits 4-5; the low 2 bits are the packet-number
    // length minus one. We always emit a 4-byte packet number (0b11), a zero
    // Token Length, and a Length varint so the datagram parses as a well-formed
    // (though unencrypted) QUIC v1 Initial rather than a truncated long header.
    let flags = QUIC_LONG_HEADER_FLAG | ((packet_type & 0x03) << 4) | 0x03;
    let pn_len = 4usize;
    packet.clear();
    packet.reserve(QUIC_LONG_HEADER_EMITTED + data.len());
    packet.push(flags);
    packet.extend_from_slice(&QUIC_VERSION_V1.to_be_bytes());
    packet.push(4);
    packet.extend_from_slice(connection_id);
    packet.push(0); // SCID length = 0
    packet.push(0); // Token Length varint = 0

    // Length = packet number + payload, shortest correct varint (see push_varint).
    if !push_varint(packet, (pn_len + data.len()) as u64) {
        // >= 2^30 bytes in one datagram is not reachable from any transport we speak;
        // emit the payload unmasked rather than a packet whose Length field lies.
        packet.clear();
        packet.extend_from_slice(data);
        return;
    }
    packet.extend_from_slice(&packet_number.to_be_bytes());
    packet.extend_from_slice(data);
}

pub fn wrap_quic_short(data: &[u8], connection_id: &[u8; 4], packet_number: u32) -> Vec<u8> {
    let mut packet = Vec::new();
    wrap_quic_short_into(data, connection_id, packet_number, &mut packet);
    packet
}

/// Caller-provided variant of [`wrap_quic_short`].
pub fn wrap_quic_short_into(
    data: &[u8],
    connection_id: &[u8; 4],
    packet_number: u32,
    packet: &mut Vec<u8>,
) {
    let flags = QUIC_SHORT_HEADER_FLAG | 0x03;
    packet.clear();
    packet.reserve(QUIC_SHORT_HEADER_MIN + data.len());
    packet.push(flags);
    packet.extend_from_slice(connection_id);
    packet.extend_from_slice(&packet_number.to_be_bytes());
    packet.extend_from_slice(data);
}

/// Decode a QUIC variable-length integer (RFC 9000 §16), advancing `offset`.
/// Returns None when the buffer is too short, so callers can surface TooShort
/// instead of indexing past the end (which would abort under panic="abort").
fn read_varint(buf: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *buf.get(*offset)?;
    let len = 1usize << (first >> 6);
    if *offset + len > buf.len() {
        return None;
    }
    let mut value = (first & 0x3F) as u64;
    for i in 1..len {
        value = (value << 8) | buf[*offset + i] as u64;
    }
    *offset += len;
    Some(value)
}

pub fn unwrap_quic(packet: &[u8]) -> Result<QuicPacket, QuicError> {
    if packet.is_empty() {
        return Err(QuicError::TooShort);
    }

    let is_long = (packet[0] & 0x80) != 0;

    if is_long {
        if packet.len() < QUIC_LONG_HEADER_MIN {
            return Err(QuicError::TooShort);
        }

        let flags = packet[0];
        // RFC 9000 §17.2: long packet type is bits 4-5; the low 2 bits are the
        // packet-number length minus one (so pn_len is always 1..=4).
        let packet_type = (flags >> 4) & 0x03;
        let pn_len = ((flags & 0x03) + 1) as usize;
        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

        let mut offset = 5;

        let dcid_len = packet[offset] as usize;
        offset += 1;
        if offset + dcid_len > packet.len() {
            return Err(QuicError::TooShort);
        }
        let mut dcid = [0u8; 4];
        let dcid_bytes = &packet[offset..offset + dcid_len.min(4)];
        dcid[..dcid_bytes.len()].copy_from_slice(dcid_bytes);
        offset += dcid_len;

        // After consuming a variable-length DCID, `offset` may sit exactly at
        // packet.len(); indexing packet[offset] for the SCID length byte would
        // panic (→ process abort under panic="abort") on a packet truncated
        // right after the DCID.
        if offset >= packet.len() {
            return Err(QuicError::TooShort);
        }
        let scid_len = packet[offset] as usize;
        offset += 1;
        if offset + scid_len > packet.len() {
            return Err(QuicError::TooShort);
        }
        offset += scid_len;

        // RFC 9001 §17.2.2: an Initial long header carries a Token Length varint,
        // the token, then a Length varint (packet number + payload). Skip the
        // token and the Length field; every read is bounds-checked via
        // read_varint so malformed input returns TooShort instead of panicking.
        let token_len = match read_varint(packet, &mut offset) {
            Some(v) => v as usize,
            None => return Err(QuicError::TooShort),
        };
        if offset + token_len > packet.len() {
            return Err(QuicError::TooShort);
        }
        offset += token_len;

        if read_varint(packet, &mut offset).is_none() {
            return Err(QuicError::TooShort);
        }

        if offset + pn_len > packet.len() {
            return Err(QuicError::TooShort);
        }
        let mut pn_bytes = [0u8; 4];
        let pn_data = &packet[offset..offset + pn_len.min(4)];
        pn_bytes[4 - pn_data.len()..].copy_from_slice(pn_data);
        let packet_number = u32::from_be_bytes(pn_bytes);
        offset += pn_len;

        let payload = packet[offset..].to_vec();

        Ok(QuicPacket {
            is_long: true,
            packet_type,
            version,
            connection_id: dcid,
            packet_number,
            payload,
        })
    } else {
        if packet.len() < QUIC_SHORT_HEADER_MIN {
            return Err(QuicError::TooShort);
        }

        let flags = packet[0];
        let pn_len = ((flags & 0x03) + 1) as usize;

        let mut offset = 1;
        let mut connection_id = [0u8; 4];
        if offset + 4 <= packet.len() {
            connection_id.copy_from_slice(&packet[offset..offset + 4]);
        }
        offset += 4;

        let pn_end = offset + pn_len.min(4);
        if pn_end > packet.len() {
            return Err(QuicError::TooShort);
        }

        let mut pn_bytes = [0u8; 4];
        let pn_data = &packet[offset..pn_end];
        pn_bytes[4 - pn_data.len()..].copy_from_slice(pn_data);
        let packet_number = u32::from_be_bytes(pn_bytes);
        offset = pn_end;

        let payload = packet[offset..].to_vec();

        Ok(QuicPacket {
            is_long: false,
            packet_type: 0,
            version: QUIC_VERSION_V1,
            connection_id,
            packet_number,
            payload,
        })
    }
}

/// Cheap first-packet classifier: does this datagram look like a QUIC v1 long-header
/// Initial, as emitted by [`wrap_quic_long`]? The UDP server uses it to detect a
/// udp-quic client by signature and mirror that choice for the whole connection,
/// even when the server profile's own `quic.enabled` is off. Unambiguous against a
/// raw TLS ClientHello (first byte `0x16` → long-header form bit clear) and a
/// udp_frag datagram (magic `F0 9B 71…` → the version field is not `0x00000001`).
/// Only valid on the FIRST packet of a source — a QUIC *data* packet is a short
/// header over ciphertext and is indistinguishable by signature, so established
/// sessions must consult the per-session flag recorded here instead.
pub fn looks_like_quic_initial(packet: &[u8]) -> bool {
    packet.len() >= 5
        && (packet[0] & 0x80) != 0
        && u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) == QUIC_VERSION_V1
}

pub fn generate_connection_id() -> [u8; 4] {
    let mut rng = rand::rng();
    let mut id = [0u8; 4];
    rng.fill_bytes(&mut id);
    id
}

pub struct QuicPacket {
    pub is_long: bool,
    pub packet_type: u8,
    pub version: u32,
    pub connection_id: [u8; 4],
    pub packet_number: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("packet too short")]
    TooShort,
    #[error("invalid header")]
    InvalidHeader,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust half of the SHARED QUIC KAT (`conformance/quic.json`).
    ///
    /// The wrap half pins the envelope byte-for-byte; the parse half feeds crafted packets
    /// that anyone can send a client — the class that once crashed the C# and Kotlin parsers
    /// into a reconnect loop while Rust was already safe.
    #[test]
    fn quic_matches_shared_conformance_vectors() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex in fixture"))
                .collect()
        }
        fn hexs(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        let fx: serde_json::Value =
            serde_json::from_str(include_str!("../../../conformance/quic.json"))
                .expect("conformance/quic.json is not valid JSON");
        assert!(
            fx["platforms"]
                .as_array()
                .expect("fixture has no `platforms`")
                .iter()
                .any(|p| p.as_str() == Some("rust")),
            "rust is not listed in `platforms` of quic.json"
        );

        let wraps = fx["wrap"].as_array().expect("fixture has no `wrap`");
        assert!(!wraps.is_empty(), "fixture has no wrap cases");
        for w in wraps {
            let name = w["name"].as_str().unwrap_or("<unnamed>");
            let payload = unhex(w["payload"].as_str().unwrap());
            let cid: [u8; 4] = unhex(w["connection_id"].as_str().unwrap())
                .try_into()
                .expect("connection_id is not 4 bytes");
            let pn = w["packet_number"].as_u64().unwrap() as u32;

            let packet = wrap_quic_short(&payload, &cid, pn);
            assert_eq!(
                hexs(&packet),
                w["expect"]["packet"].as_str().unwrap(),
                "case {name}: wrapped packet disagrees"
            );

            // Round-trip: what we wrapped must unwrap back to the same inputs.
            let parsed = unwrap_quic(&packet)
                .unwrap_or_else(|e| panic!("case {name}: own output failed to parse: {e:?}"));
            assert_eq!(parsed.connection_id, cid, "case {name}: cid round-trip");
            assert_eq!(
                parsed.packet_number, pn,
                "case {name}: packet number round-trip"
            );
            assert_eq!(
                hexs(&parsed.payload),
                hexs(&payload),
                "case {name}: payload round-trip"
            );
        }

        let parses = fx["parse"].as_array().expect("fixture has no `parse`");
        assert!(!parses.is_empty(), "fixture has no parse cases");
        for p in parses {
            let name = p["name"].as_str().unwrap_or("<unnamed>");
            let packet = unhex(p["packet"].as_str().unwrap());
            let got = unwrap_quic(&packet);
            if p["expect"]["reject"].as_bool() == Some(true) {
                assert!(got.is_err(), "case {name}: a crafted packet was ACCEPTED");
            } else {
                let q =
                    got.unwrap_or_else(|e| panic!("case {name}: rejected a valid packet: {e:?}"));
                assert_eq!(
                    hexs(&q.payload),
                    p["expect"]["payload"].as_str().unwrap(),
                    "case {name}: payload disagrees"
                );
            }
        }
    }

    #[test]
    fn test_long_header_roundtrip() {
        let cid = [0xAA, 0xBB, 0xCC, 0xDD];
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x10, 0x01, 0x02, 0x03];
        let wrapped = wrap_quic_long(&data, &cid, 42, 0x00);

        let parsed = unwrap_quic(&wrapped).unwrap();
        assert!(parsed.is_long);
        assert_eq!(parsed.connection_id, cid);
        assert_eq!(parsed.packet_number, 42);
        assert_eq!(parsed.payload, data);
    }

    #[test]
    fn long_header_truncated_after_dcid_does_not_panic() {
        // flags(1) + version(4) + dcid_len=4(1) + dcid(4) = 10 bytes, then the
        // packet ends right where the SCID length byte should be. Must return
        // an error, not index-panic.
        let mut pkt = vec![0xC0, 0, 0, 0, 1, 4, 0xAA, 0xBB, 0xCC, 0xDD];
        assert!(matches!(unwrap_quic(&pkt), Err(QuicError::TooShort)));
        // Also fuzz a range of truncation points past the minimum length.
        let full = wrap_quic_long(&[1, 2, 3, 4, 5], &[1, 2, 3, 4], 7, 0);
        for cut in 0..full.len() {
            pkt = full[..cut].to_vec();
            let _ = unwrap_quic(&pkt); // must never panic
        }
    }

    #[test]
    fn test_short_header_roundtrip() {
        let cid = [0x11, 0x22, 0x33, 0x44];
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x10];
        let wrapped = wrap_quic_short(&data, &cid, 100);

        let parsed = unwrap_quic(&wrapped).unwrap();
        assert!(!parsed.is_long);
        assert_eq!(parsed.connection_id, cid);
        assert_eq!(parsed.packet_number, 100);
        assert_eq!(parsed.payload, data);
    }

    #[test]
    fn caller_owned_wrappers_match_and_reuse_storage() {
        let cid = [0x31, 0x32, 0x33, 0x34];
        let data = vec![0xAB; 1400];
        let expected_short = wrap_quic_short(&data, &cid, 7);
        let expected_long = wrap_quic_long(&data, &cid, 8, 0);
        let mut packet = Vec::with_capacity(QUIC_LONG_HEADER_EMITTED + data.len());

        wrap_quic_short_into(&data, &cid, 7, &mut packet);
        assert_eq!(packet, expected_short);
        let allocation = packet.as_ptr();

        wrap_quic_long_into(&data, &cid, 8, 0, &mut packet);
        assert_eq!(packet, expected_long);
        assert_eq!(
            packet.as_ptr(),
            allocation,
            "QUIC allocation must be reused"
        );
    }

    #[test]
    fn test_different_packet_types() {
        let cid = generate_connection_id();
        for pt in 0u8..4 {
            let data = vec![0x01, 0x02, 0x03];
            let wrapped = wrap_quic_long(&data, &cid, 1, pt);
            let parsed = unwrap_quic(&wrapped).unwrap();
            assert_eq!(parsed.packet_type, pt);
        }
    }

    #[test]
    fn test_empty_payload() {
        let cid = [0x00; 4];
        let data = vec![];
        let wrapped = wrap_quic_short(&data, &cid, 0);
        let parsed = unwrap_quic(&wrapped).unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_large_payload() {
        let cid = [0xFF; 4];
        let data = vec![0xABu8; 1400];
        let wrapped = wrap_quic_long(&data, &cid, 9999, 0x02);
        let parsed = unwrap_quic(&wrapped).unwrap();
        assert_eq!(parsed.payload.len(), 1400);
        assert_eq!(parsed.packet_number, 9999);
    }

    #[test]
    fn test_quic_header_looks_like_quic() {
        let cid = generate_connection_id();
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x10];
        let wrapped = wrap_quic_long(&data, &cid, 1, 0x00);

        assert_eq!(wrapped[0] & 0x80, 0x80);
        assert_eq!(&wrapped[1..5], &[0x00, 0x00, 0x00, 0x01]);

        let short = wrap_quic_short(&data, &cid, 1);
        assert_eq!(short[0] & 0x80, 0x00);
        assert_eq!(short[0] & 0x40, 0x40);
    }

    #[test]
    fn test_short_header_packet_number_lengths() {
        let cid = [0xAA; 4];
        let data = vec![0x01, 0x02];
        let pn = 0x12345678u32;
        let wrapped = wrap_quic_short(&data, &cid, pn);

        let parsed = unwrap_quic(&wrapped).unwrap();
        assert_eq!(parsed.packet_number, pn);
    }

    #[test]
    fn looks_like_quic_initial_classifies_by_signature() {
        let cid = generate_connection_id();
        // A real long-header Initial is detected regardless of packet type.
        for pt in 0u8..4 {
            let wrapped = wrap_quic_long(&[0x17, 0x03, 0x03, 0x00, 0x10], &cid, 1, pt);
            assert!(looks_like_quic_initial(&wrapped), "long header type {pt}");
        }
        // A QUIC short-header (data) packet must NOT be mistaken for an Initial.
        assert!(!looks_like_quic_initial(&wrap_quic_short(
            &[0x01, 0x02],
            &cid,
            7
        )));
        // A raw TLS ClientHello record (fake-tls, no QUIC) — form bit clear.
        assert!(!looks_like_quic_initial(&[
            0x16, 0x03, 0x01, 0x02, 0x00, 0xAB
        ]));
        // A udp_frag datagram: magic F0 9B 71 sets the form bit but the version
        // field is not QUIC v1, so it is correctly rejected (no false positive that
        // would send a non-quic fragment down the unwrap path).
        assert!(!looks_like_quic_initial(&[
            0xF0, 0x9B, 0x71, 0x00, 0x01, 0x02, 0x03
        ]));
        // Too short to carry a version field.
        assert!(!looks_like_quic_initial(&[0xC3, 0x00, 0x00]));
    }
}
