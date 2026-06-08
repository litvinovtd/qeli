//! M2.2 — TLS 1.3 record protection (RFC 8446 §5.2) for TLS_AES_128_GCM_SHA256
//! and TLS_AES_256_GCM_SHA384. The AEAD is chosen by the key length passed to
//! [`RecordCrypto::new`] (16 → AES-128-GCM, 32 → AES-256-GCM); both use a 12-byte
//! nonce `write_iv XOR seq`, the 5-byte record header `17 03 03 len` as additional
//! data, and `content || content_type` as the inner plaintext (no extra padding).
//! Verified against the RFC 8448 §3 client `Finished` record (AES-128).

// M2.2 scaffolding: consumed by the client/server handshakes.
#![allow(dead_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

/// The negotiated AEAD (both GCM variants share a 12-byte nonce).
enum Gcm {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

/// One AEAD direction (a key/IV pair and its monotonic record sequence number).
pub struct RecordCrypto {
    gcm: Gcm,
    iv: [u8; 12],
    seq: u64,
}

impl RecordCrypto {
    /// `key` is 16 bytes (AES-128) or 32 bytes (AES-256); `iv` is 12 bytes.
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        let gcm = match key.len() {
            16 => Gcm::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).expect("16-byte key"),
            )),
            32 => Gcm::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).expect("32-byte key"),
            )),
            n => panic!("unsupported AEAD key length: {n}"),
        };
        let mut ivv = [0u8; 12];
        ivv.copy_from_slice(iv);
        RecordCrypto {
            gcm,
            iv: ivv,
            seq: 0,
        }
    }

    /// Per-record nonce: the 64-bit sequence number, right-aligned into the write
    /// IV by XOR (RFC 8446 §5.3).
    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    fn seal(&self, nonce: &[u8; 12], inner: &[u8], aad: &[u8]) -> Vec<u8> {
        let n = Nonce::from_slice(nonce);
        let p = Payload { msg: inner, aad };
        match &self.gcm {
            Gcm::Aes128(c) => c.encrypt(n, p),
            Gcm::Aes256(c) => c.encrypt(n, p),
        }
        .expect("AES-GCM encrypt")
    }

    fn open(&self, nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let n = Nonce::from_slice(nonce);
        let p = Payload { msg: ct, aad };
        match &self.gcm {
            Gcm::Aes128(c) => c.decrypt(n, p),
            Gcm::Aes256(c) => c.decrypt(n, p),
        }
        .ok()
    }

    /// Encrypt one record. `content_type` is the real TLS content type (e.g. 0x16
    /// handshake, 0x17 application_data). Returns the full record incl. 5-byte
    /// header. Advances the sequence number.
    pub fn encrypt(&mut self, content_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(content_type);

        let total = inner.len() + 16; // + AEAD tag
        let aad = [0x17, 0x03, 0x03, (total >> 8) as u8, total as u8];
        let nonce = self.nonce();
        let ct = self.seal(&nonce, &inner, &aad);
        self.seq += 1;

        let mut record = Vec::with_capacity(5 + ct.len());
        record.extend_from_slice(&aad);
        record.extend_from_slice(&ct);
        record
    }

    /// Decrypt one record (header + ciphertext). Returns `(inner_content_type,
    /// plaintext)` with trailing zero padding stripped. Advances the sequence
    /// number only on success.
    pub fn decrypt(&mut self, record: &[u8]) -> Option<(u8, Vec<u8>)> {
        if record.len() < 5 + 16 || record[0] != 0x17 {
            return None;
        }
        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        if record.len() != 5 + len {
            return None;
        }
        let aad = &record[..5];
        let nonce = self.nonce();
        let pt = self.open(&nonce, &record[5..], aad)?;
        self.seq += 1;

        // TLSInnerPlaintext: content || content_type || zeros. The content type is
        // the last non-zero byte.
        let mut i = pt.len();
        while i > 0 && pt[i - 1] == 0 {
            i -= 1;
        }
        if i == 0 {
            return None;
        }
        Some((pt[i - 1], pt[..i - 1].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        let h: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
        h.chunks(2)
            .map(|c| {
                let hi = (c[0] as char).to_digit(16).unwrap() as u8;
                let lo = (c[1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// RFC 8448 §3: the client `Finished` handshake message, protected with the
    /// client handshake traffic key/IV at sequence 0, equals the trace's record.
    #[test]
    fn rfc8448_client_finished_record() {
        let key = hx("dbfaa693d1762c5b666af5d950258d01");
        let iv = hx("5bd3c71b836e0b76bb73265f");
        let finished =
            hx("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");
        let expected_record = hx(
            "1703030035 75ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d8\
             7f38f80338ac98fc46deb384bd1caeacab6867d726c4054 6",
        );

        let mut enc = RecordCrypto::new(&key, &iv);
        let record = enc.encrypt(0x16, &finished);
        assert_eq!(record, expected_record, "client Finished record (KAT)");

        let mut dec = RecordCrypto::new(&key, &iv);
        let (ct, pt) = dec.decrypt(&record).expect("decrypts");
        assert_eq!(ct, 0x16, "inner content type = handshake");
        assert_eq!(pt, finished, "recovered Finished message");
    }

    #[test]
    fn round_trip_advances_sequence() {
        let key = hx("000102030405060708090a0b0c0d0e0f");
        let iv = hx("000102030405060708090a0b");
        let mut enc = RecordCrypto::new(&key, &iv);
        let r0 = enc.encrypt(0x17, b"first");
        let r1 = enc.encrypt(0x17, b"second");
        assert_ne!(r0, r1);

        let mut dec = RecordCrypto::new(&key, &iv);
        assert_eq!(dec.decrypt(&r0).unwrap(), (0x17, b"first".to_vec()));
        assert_eq!(dec.decrypt(&r1).unwrap(), (0x17, b"second".to_vec()));
    }

    /// AES-256-GCM (32-byte key) round-trips and advances the sequence too.
    #[test]
    fn aes256_round_trip() {
        let key = hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv = hx("aabbccddeeff00112233 4455");
        let mut enc = RecordCrypto::new(&key, &iv);
        let r0 = enc.encrypt(0x17, b"quantum");
        let r1 = enc.encrypt(0x16, b"handshake-ish");
        assert_ne!(r0, r1);

        let mut dec = RecordCrypto::new(&key, &iv);
        assert_eq!(dec.decrypt(&r0).unwrap(), (0x17, b"quantum".to_vec()));
        assert_eq!(dec.decrypt(&r1).unwrap(), (0x16, b"handshake-ish".to_vec()));
    }

    #[test]
    fn tampered_record_fails() {
        let key = hx("000102030405060708090a0b0c0d0e0f");
        let iv = hx("000102030405060708090a0b");
        let mut enc = RecordCrypto::new(&key, &iv);
        let mut r = enc.encrypt(0x17, b"hello");
        let n = r.len();
        r[n - 1] ^= 0xff;
        let mut dec = RecordCrypto::new(&key, &iv);
        assert!(dec.decrypt(&r).is_none(), "AEAD tag mismatch must reject");
    }
}
