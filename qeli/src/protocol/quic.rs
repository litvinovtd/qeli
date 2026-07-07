// QUIC-masking: the wrap/unwrap path is used; the header/packet parse structs
// (QuicHeader/QuicPacket/QuicError) are API surface for the planned UDP-side use.
#![allow(dead_code)]
use rand::Rng;

const QUIC_VERSION_V1: u32 = 0x00000001;
const QUIC_LONG_HEADER_FLAG: u8 = 0xC0;
const QUIC_SHORT_HEADER_FLAG: u8 = 0x40;

pub const QUIC_LONG_HEADER_MIN: usize = 1 + 4 + 1 + 1 + 4 + 1;
pub const QUIC_SHORT_HEADER_MIN: usize = 1 + 4 + 4;

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
    // RFC 9000 §17.2 long header + RFC 9001 §17.2.2 Initial fields. The long
    // packet type lives in bits 4-5; the low 2 bits are the packet-number
    // length minus one. We always emit a 4-byte packet number (0b11), a zero
    // Token Length, and a Length varint so the datagram parses as a well-formed
    // (though unencrypted) QUIC v1 Initial rather than a truncated long header.
    let flags = QUIC_LONG_HEADER_FLAG | ((packet_type & 0x03) << 4) | 0x03;
    let pn_len = 4usize;
    // Length covers the packet number plus the payload; encoded as a 2-byte QUIC
    // varint (0b01 prefix, 14-bit value) which spans any single UDP datagram.
    let length = ((pn_len + data.len()) as u16) & 0x3FFF;
    let mut header = Vec::with_capacity(QUIC_LONG_HEADER_MIN + data.len());
    header.push(flags);
    header.extend_from_slice(&QUIC_VERSION_V1.to_be_bytes());
    header.push(4);
    header.extend_from_slice(connection_id);
    header.push(0); // SCID length = 0
    header.push(0); // Token Length varint = 0
    header.push(0x40 | (length >> 8) as u8); // Length varint, high byte
    header.push((length & 0xFF) as u8); // Length varint, low byte
    header.extend_from_slice(&packet_number.to_be_bytes());
    header.extend_from_slice(data);
    header
}

pub fn wrap_quic_short(data: &[u8], connection_id: &[u8; 4], packet_number: u32) -> Vec<u8> {
    let flags = QUIC_SHORT_HEADER_FLAG | 0x03;
    let mut header = Vec::with_capacity(QUIC_SHORT_HEADER_MIN + data.len());
    header.push(flags);
    header.extend_from_slice(connection_id);
    header.extend_from_slice(&packet_number.to_be_bytes());
    header.extend_from_slice(data);
    header
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
    let mut rng = rand::thread_rng();
    let mut id = [0u8; 4];
    rng.fill(&mut id);
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
