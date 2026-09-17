//! M2.2 — TLS 1.3 record protection (RFC 8446 §5.2) for TLS_AES_128_GCM_SHA256
//! and TLS_AES_256_GCM_SHA384. The AEAD is chosen by the key length passed to
//! [`RecordCrypto::new`] (16 → AES-128-GCM, 32 → AES-256-GCM); both use a 12-byte
//! nonce `write_iv XOR seq`, the 5-byte record header `17 03 03 len` as additional
//! data, and `content || content_type` as the inner plaintext (no extra padding).
//! Verified against the RFC 8448 §3 client `Finished` record (AES-128).

// Shared by the async client/server handshakes and the sans-IO transport core.
#![allow(dead_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use std::io;

/// RFC 8446 §5.1: a TLSPlaintext fragment may not exceed 2^14 bytes. `encrypt`
/// fragments at this boundary; anything larger in a single record would overflow the
/// 16-bit length field in the header.
pub const MAX_PLAINTEXT: usize = 16384;

// Below RFC 8446 §5.5's ~2^24.5 full-size AES-GCM records, independently per key
// and direction. Until KeyUpdate is implemented, exhaustion forces reconnect.
const MAX_KEY_RECORDS: u64 = 1 << 24;
const MAX_KEY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

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
    ciphertext_bytes: u64,
    exhausted: bool,
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
            ciphertext_bytes: 0,
            exhausted: false,
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
        // aes-gcm is pinned to 0.10 for reality-tls throughput (0.7.7 regression fix);
        // Nonce::from_slice is the 0.10 API, so its deprecation here is intentional.
        #[allow(deprecated)]
        let n = Nonce::from_slice(nonce);
        let p = Payload { msg: inner, aad };
        match &self.gcm {
            Gcm::Aes128(c) => c.encrypt(n, p),
            Gcm::Aes256(c) => c.encrypt(n, p),
        }
        .expect("AES-GCM encrypt")
    }

    fn open(&self, nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        #[allow(deprecated)] // aes-gcm 0.10 API (throughput pin); see seal() above
        let n = Nonce::from_slice(nonce);
        let p = Payload { msg: ct, aad };
        match &self.gcm {
            Gcm::Aes128(c) => c.decrypt(n, p),
            Gcm::Aes256(c) => c.decrypt(n, p),
        }
        .ok()
    }

    /// Encrypt `plaintext` as one or more TLS records. `content_type` is the real TLS
    /// content type (e.g. 0x16 handshake, 0x17 application_data). Returns the full
    /// record(s) incl. their 5-byte headers. Advances the sequence number once per
    /// record emitted.
    ///
    /// FRAGMENTS at `MAX_PLAINTEXT`, as RFC 8446 §5.1 requires. The previous version
    /// emitted a single record and built its length field with `(total >> 8) as u8` —
    /// the high bits of anything over 65535 were silently dropped, so the header
    /// disagreed with the body and the peer's framing desynchronised. Only `stream.rs`
    /// capped its input, so the two paths that did not (`SansIoClient::seal`, and
    /// `qeli_realtls_seal` across the C ABI) were exposed, as was the server emitting a
    /// borrow target's certificate chain as one flight. realtls is TCP-only, so
    /// back-to-back records are just bytes on the stream and the reader already handles
    /// one record at a time. (Audit 2026-07-27, F3.)
    pub fn encrypt(&mut self, content_type: u8, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        // The inner plaintext is `plaintext || content_type`, so each fragment may carry
        // at most MAX_PLAINTEXT - 1 caller bytes.
        let chunk = MAX_PLAINTEXT - 1;
        let records = plaintext.len().div_ceil(chunk).max(1) as u64;
        let bytes = (plaintext.len() as u64).saturating_add(records.saturating_mul(17));
        // Check the WHOLE call before emitting anything or advancing its sequence.
        if !self.check_budget(records, bytes) {
            return Err(io::Error::other(
                "TLS traffic key budget exhausted; reconnect required",
            ));
        }
        let mut out = Vec::with_capacity(plaintext.len() + 21);
        // `chunks` yields nothing for an empty input, but an empty record is legal and
        // is used as a keepalive — emit exactly one in that case.
        if plaintext.is_empty() {
            out.extend_from_slice(&self.encrypt_one(content_type, &[]));
            return Ok(out);
        }
        for part in plaintext.chunks(chunk) {
            out.extend_from_slice(&self.encrypt_one(content_type, part));
        }
        Ok(out)
    }

    fn check_budget(&mut self, records: u64, bytes: u64) -> bool {
        if self.exhausted
            || self.seq.saturating_add(records) > MAX_KEY_RECORDS
            || self.ciphertext_bytes.saturating_add(bytes) > MAX_KEY_BYTES
        {
            self.exhausted = true;
            return false;
        }
        true
    }

    /// Encrypt exactly one record; `plaintext.len()` must be `< MAX_PLAINTEXT`.
    fn encrypt_one(&mut self, content_type: u8, plaintext: &[u8]) -> Vec<u8> {
        debug_assert!(plaintext.len() < MAX_PLAINTEXT);
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(content_type);

        let total = inner.len() + 16; // + AEAD tag
        let aad = [0x17, 0x03, 0x03, (total >> 8) as u8, total as u8];
        let nonce = self.nonce();
        let ct = self.seal(&nonce, &inner, &aad);
        self.seq += 1;
        self.ciphertext_bytes += ct.len() as u64;

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
        if record.len() != 5 + len || len > MAX_PLAINTEXT + 256 || !self.check_budget(1, len as u64)
        {
            return None;
        }
        let aad = &record[..5];
        let nonce = self.nonce();
        let pt = self.open(&nonce, &record[5..], aad)?;
        self.seq += 1;
        self.ciphertext_bytes += len as u64;

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

    #[test]
    fn key_budget_is_directional_atomic_and_sticky() {
        let mut enc = RecordCrypto::new(&[7; 16], &[3; 12]);
        enc.seq = MAX_KEY_RECORDS - 1;
        let mut dec = RecordCrypto::new(&[7; 16], &[3; 12]);
        dec.seq = enc.seq;
        let final_record = enc.encrypt(0x17, b"last").unwrap();
        assert_eq!(dec.decrypt(&final_record).unwrap().1, b"last");
        assert!(enc.encrypt(0x17, b"next").is_err());
        assert!(dec.decrypt(&final_record).is_none());

        let mut enc = RecordCrypto::new(&[7; 16], &[3; 12]);
        enc.seq = MAX_KEY_RECORDS - 1;
        assert!(enc.encrypt(0x17, &vec![0; MAX_PLAINTEXT]).is_err());
        assert_eq!(enc.seq, MAX_KEY_RECORDS - 1, "no partially emitted call");
        assert!(enc.encrypt(0x17, b"").is_err(), "exhaustion is terminal");

        let mut enc = RecordCrypto::new(&[8; 32], &[4; 12]);
        let mut dec = RecordCrypto::new(&[8; 32], &[4; 12]);
        enc.ciphertext_bytes = MAX_KEY_BYTES - 18;
        dec.ciphertext_bytes = MAX_KEY_BYTES - 18;
        let record = enc.encrypt(0x17, b"x").unwrap();
        assert!(dec.decrypt(&record).is_some());
        assert!(enc.encrypt(0x17, b"").is_err());
        assert!(dec.decrypt(&record).is_none());
    }

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
        let record = enc.encrypt(0x16, &finished).unwrap();
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
        let r0 = enc.encrypt(0x17, b"first").unwrap();
        let r1 = enc.encrypt(0x17, b"second").unwrap();
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
        let r0 = enc.encrypt(0x17, b"quantum").unwrap();
        let r1 = enc.encrypt(0x16, b"handshake-ish").unwrap();
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
        let mut r = enc.encrypt(0x17, b"hello").unwrap();
        let n = r.len();
        r[n - 1] ^= 0xff;
        let mut dec = RecordCrypto::new(&key, &iv);
        assert!(dec.decrypt(&r).is_none(), "AEAD tag mismatch must reject");
    }
}
