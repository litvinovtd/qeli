#![no_main]
//! Raw rejection plus bounded, valid handshake fragments and exact assembly oracles.
use libfuzzer_sys::fuzz_target;
use qeli_core::protocol::udp_frag::{
    fragment, is_fragment, Reassembler, FRAG_HDR_LEN, FRAG_MAGIC, MAX_CHUNK, MAX_CHUNK_ACCEPT,
    MAX_FRAGS, MSG_CLIENT_HELLO,
};

fuzz_target!(|data: &[u8]| {
    let _ = is_fragment(data);
    let mut raw = Reassembler::new();
    let _ = raw.push(data);
    let _ = raw.push(data);
    if data.is_empty() {
        return;
    }
    let selector = usize::from(data[0]);
    let len = (selector % (usize::from(MAX_FRAGS) + 1) * MAX_CHUNK
        + usize::from(*data.get(1).unwrap_or(&0)))
    .min(usize::from(MAX_FRAGS) * MAX_CHUNK);
    let message: Vec<u8> = (0..len).map(|i| data[i % data.len()]).collect();
    let fragments = fragment(MSG_CLIENT_HELLO, &message).unwrap();
    let mut r = Reassembler::new();
    for position in 0..fragments.len() {
        let index = if selector & 1 == 0 {
            fragments.len() - 1 - position
        } else {
            position
        };
        let result = r.push(&fragments[index]).unwrap();
        if position + 1 == fragments.len() {
            assert_eq!(result.as_deref(), Some(message.as_slice()));
            // This reassembler retains a completed handshake until its caller drops it.
            assert_eq!(r.push(&fragments[index]).unwrap(), result);
        } else {
            assert_eq!(result, None);
            assert_eq!(r.push(&fragments[index]).unwrap(), None);
        }
    }
    let mut inconsistent = fragments[0].clone();
    inconsistent[3] ^= 0x80;
    assert!(r.push(&inconsistent).is_err());
    if fragments[0].len() > FRAG_HDR_LEN {
        let mut conflict = fragments[0].clone();
        conflict[FRAG_HDR_LEN] ^= 1;
        assert!(r.push(&conflict).is_err());
    }
    // Old peers send the historical 1200-byte chunks; receive bounds must accept them.
    let chunk = vec![data[0]; MAX_CHUNK_ACCEPT];
    let count = 1 + selector % usize::from(MAX_FRAGS);
    let mut legacy = Reassembler::new();
    for index in 0..count {
        let mut wire = FRAG_MAGIC.to_vec();
        wire.extend_from_slice(&[MSG_CLIENT_HELLO, index as u8, count as u8]);
        wire.extend_from_slice(&chunk);
        let result = legacy.push(&wire).unwrap();
        if index + 1 == count {
            assert_eq!(result.unwrap(), chunk.repeat(count));
        } else {
            assert_eq!(result, None);
        }
    }
    let mut oversized = FRAG_MAGIC.to_vec();
    oversized.extend_from_slice(&[MSG_CLIENT_HELLO, 0, 1]);
    oversized.resize(FRAG_HDR_LEN + MAX_CHUNK_ACCEPT + 1, 0);
    let mut fresh = Reassembler::new();
    assert!(fresh.push(&oversized).is_err());
    // Rejecting an oversized first fragment must leave a fresh assembler usable.
    for (index, wire) in fragments.iter().enumerate() {
        let result = fresh.push(wire).unwrap();
        if index + 1 == fragments.len() {
            assert_eq!(result.as_deref(), Some(message.as_slice()));
        } else {
            assert_eq!(result, None);
        }
    }
});
