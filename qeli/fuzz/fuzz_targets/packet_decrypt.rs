#![no_main]
use libfuzzer_sys::fuzz_target;
use qeli_core::crypto::cipher::Cipher;
use qeli_core::protocol::packet::{conformance_replay_sequence, PacketCodec, PacketError};
use std::collections::HashSet;

fn codec(raw: bool) -> PacketCodec {
    if raw {
        PacketCodec::new_raw([0x42; 32])
    } else {
        PacketCodec::new([0x42; 32])
    }
}

fn seal(raw: bool, seq: u64, payload: &[u8], padding: u16, variant: u8) -> Vec<u8> {
    let mut nonce = [0; 12];
    nonce[..8].copy_from_slice(&seq.to_be_bytes());
    nonce[8] = variant;
    let mut plain = seq.to_be_bytes().to_vec();
    plain.extend_from_slice(payload);
    plain.extend_from_slice(&padding.to_be_bytes());
    let ct = Cipher::new(&[0x42; 32]).encrypt(&nonce, &plain).unwrap();
    let len = (12 + ct.len()) as u16;
    let mut wire = if raw {
        len.to_be_bytes().to_vec()
    } else {
        vec![0x17, 3, 3, (len >> 8) as u8, len as u8]
    };
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct);
    wire
}

fuzz_target!(|data: &[u8]| {
    // Arbitrary wire bytes exercise framing, allocation parity and rejection clearing.
    for raw in [false, true] {
        let allocating = codec(raw).decrypt_packet(data);
        let mut buffer = data.to_vec();
        let capacity = buffer.capacity();
        let in_place = codec(raw).decrypt_packet_in_place(&mut buffer);
        assert_eq!(allocating.is_ok(), in_place.is_ok());
        if let Ok(plain) = allocating {
            assert_eq!(plain, buffer);
        } else {
            assert!(buffer.is_empty());
        }
        assert_eq!(capacity, buffer.capacity());
    }
    // Authenticated records reach padding and replay state instead of stopping at AEAD.
    let sequences: Vec<u64> = data
        .chunks_exact(8)
        .take(64)
        .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
        .collect();
    let mut highest: Option<u64> = None;
    let mut seen = HashSet::new();
    let expected: Vec<bool> = sequences
        .iter()
        .map(|&seq| {
            let accept =
                highest.is_none_or(|top| seq > top || top - seq < 2048) && !seen.contains(&seq);
            if accept {
                let top = highest.map_or(seq, |top| top.max(seq));
                highest = Some(top);
                seen.insert(seq);
                seen.retain(|seq| top - seq < 2048);
            }
            accept
        })
        .collect();
    assert_eq!(conformance_replay_sequence(&sequences), expected);
    let payload = &data[..data.len().min(128)];
    for raw in [false, true] {
        let mut allocating = codec(raw);
        let mut in_place = codec(raw);
        for (&seq, &accept) in sequences.iter().zip(&expected) {
            let bad = seal(raw, seq, payload, u16::MAX, 1);
            assert!(matches!(
                allocating.decrypt_packet(&bad),
                Err(PacketError::InvalidPadding)
            ));
            let mut buffer = bad;
            assert!(matches!(
                in_place.decrypt_packet_in_place(&mut buffer),
                Err(PacketError::InvalidPadding)
            ));
            assert!(buffer.is_empty());
            let good = seal(raw, seq, payload, 0, 2);
            let result = allocating.decrypt_packet(&good);
            let mut buffer = good;
            assert_eq!(
                in_place.decrypt_packet_in_place(&mut buffer).is_ok(),
                accept
            );
            assert_eq!(result.is_ok(), accept);
            if accept {
                assert_eq!(result.unwrap(), payload);
                assert_eq!(buffer, payload);
            } else {
                assert!(buffer.is_empty());
            }
        }
    }
});
