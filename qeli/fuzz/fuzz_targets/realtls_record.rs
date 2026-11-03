//! Exercise authenticated inner parsing and rejection atomicity, not just bad tags.
#![no_main]
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use libfuzzer_sys::fuzz_target;
use qeli_core::protocol::realtls::record::{RecordCrypto, MAX_PLAINTEXT};

fuzz_target!(|data: &[u8]| {
    let mut arbitrary = RecordCrypto::new(&[0x11; 16], &[0x22; 12]);
    let _ = arbitrary.decrypt(data);
    let selector = data.first().copied().unwrap_or(0);
    let key = vec![0x11; if selector & 1 == 0 { 16 } else { 32 }];
    let iv = [0x22; 12];
    let mut inner = data
        .get(1..)
        .unwrap_or_default()
        .iter()
        .copied()
        .take(MAX_PLAINTEXT + 2)
        .collect::<Vec<_>>();
    match (selector >> 1) & 7 {
        0 => {
            inner.truncate(MAX_PLAINTEXT);
            inner.push(0x17);
        }
        1 => inner = vec![0; inner.len().max(1)],
        2 => inner = vec![0x17; MAX_PLAINTEXT + 2],
        3 => inner = vec![0x19],
        4 => inner = vec![0x16],
        5 => {
            inner.truncate(MAX_PLAINTEXT.saturating_sub(4));
            inner.extend([0x17, 0, 0, 0]);
        }
        _ => {}
    }
    let total = inner.len() + 16;
    let header = [
        0x17,
        3,
        if selector & 0x80 == 0 { 3 } else { 1 },
        (total >> 8) as u8,
        total as u8,
    ];
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&iv);
    let payload = Payload {
        msg: &inner,
        aad: &header,
    };
    let encrypted = if key.len() == 16 {
        Aes128Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(nonce, payload)
    } else {
        Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(nonce, payload)
    }
    .unwrap();
    let mut wire = header.to_vec();
    wire.extend(encrypted);
    let end = inner
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    let expected = if header[2] == 3
        && inner.len() <= MAX_PLAINTEXT + 1
        && end > 0
        && matches!(inner[end - 1], 0x15..=0x17)
        && (inner[end - 1] == 0x17 || end > 1)
    {
        Some((inner[end - 1], inner[..end - 1].to_vec()))
    } else {
        None
    };
    let mut dec = RecordCrypto::new(&key, &iv);
    assert_eq!(dec.decrypt(&wire), expected);
    if expected.is_none() {
        let mut enc = RecordCrypto::new(&key, &iv);
        assert_eq!(
            dec.decrypt(&enc.encrypt(0x17, b"corrected").unwrap())
                .unwrap()
                .1,
            b"corrected"
        );
    }
    let mut enc = RecordCrypto::new(&key, &iv);
    let mut dec = RecordCrypto::new(&key, &iv);
    let wire = enc.encrypt(0x17, data).unwrap();
    let mut got = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        let total = 5 + usize::from(u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]));
        got.extend(dec.decrypt(&wire[offset..offset + total]).unwrap().1);
        offset += total;
    }
    assert_eq!(got, data);
});
