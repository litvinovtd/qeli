use crate::crypto::Cipher;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

pub const TLS_RECORD_HEADER: usize = 5;
/// Raw-framing header: a bare 2-byte big-endian length prefix (no TLS record
/// type/version bytes). Used by the `plain` wire mode.
pub const RAW_RECORD_HEADER: usize = 2;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const COUNTER_SIZE: usize = 8;
pub const MAX_RECORD_SIZE: usize = 16384 + NONCE_SIZE + TAG_SIZE + COUNTER_SIZE + 256;
/// Anti-replay window in packets. Sized like WireGuard (~2000) so heavily
/// reordered UDP flows don't trip false `ReplayDetected` (a 64-bit window was
/// easily out-run by reordering). Receiver-side only — no wire/compat impact.
const REPLAY_WINDOW_SIZE: usize = 2048;
const REPLAY_WORDS: usize = REPLAY_WINDOW_SIZE / 64;

/// On-wire record framing for an encrypted packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Framing {
    /// TLS application-data record: `[0x17 0x03 0x03][u16 len][nonce][ct]`. Used
    /// by the fake-tls / obfs / reality-tls wire modes (the qeli payload is
    /// dressed as a TLS 1.2 application-data record).
    Tls,
    /// Bare length-prefixed record: `[u16 len][nonce][ct]`. Used by the `plain`
    /// wire mode — no TLS mimicry at all, just an encrypted tunnel.
    Raw,
}

pub struct PacketCodec {
    cipher: Cipher,
    counter: u64,
    /// 4-byte random seed mixed into every nonce. Unique per session/key.
    /// Prevents nonce reuse across reconnects that might accidentally reuse the same counter.
    nonce_seed: [u8; 4],
    /// Key for the 96-bit Feistel permutation that randomises the on-wire nonce.
    /// Derived from the AEAD key; only the *sender* needs it (the receiver reads
    /// the nonce straight off the wire), so this stays a one-sided transform.
    nonce_prp_key: [u8; 32],
    replay_window: ReplayWindow,
    /// On-wire framing for records this codec produces/consumes.
    framing: Framing,
}

/// Round function for the nonce PRP: first 6 bytes of SHA256(key‖round‖half).
fn prp_round(key: &[u8; 32], round: u8, half: &[u8; 6]) -> [u8; 6] {
    let mut h = Sha256::new();
    h.update(key);
    h.update([round]);
    h.update(half);
    let d = h.finalize();
    let mut out = [0u8; 6];
    out.copy_from_slice(&d[..6]);
    out
}

/// 96-bit balanced Feistel permutation over the raw nonce.
///
/// A Feistel network is bijective for *any* round function, so distinct inputs
/// (our unique per-packet `seed‖counter`) always map to distinct outputs — no
/// AEAD nonce reuse — while the visible "+1 per packet" counter pattern is
/// destroyed. The receiver never inverts this: it reads the nonce off the wire.
fn prp_nonce(key: &[u8; 32], raw: &[u8; NONCE_SIZE]) -> [u8; NONCE_SIZE] {
    let mut l = [0u8; 6];
    let mut r = [0u8; 6];
    l.copy_from_slice(&raw[..6]);
    r.copy_from_slice(&raw[6..]);
    for round in 0..4u8 {
        let f = prp_round(key, round, &r);
        let mut nr = [0u8; 6];
        for i in 0..6 {
            nr[i] = l[i] ^ f[i];
        }
        l = r;
        r = nr;
    }
    let mut out = [0u8; NONCE_SIZE];
    out[..6].copy_from_slice(&l);
    out[6..].copy_from_slice(&r);
    out
}

/// Sliding-window replay protection over a `REPLAY_WINDOW_SIZE`-bit window.
/// The window is a little-endian bit array: bit at *distance* N (i.e. seq
/// `highest - N`) lives in `bits[N/64]` at position `N%64`. Distance 0 is the
/// current highest seq.
struct ReplayWindow {
    highest: u64,
    bits: [u64; REPLAY_WORDS],
    initialized: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bits: [0; REPLAY_WORDS],
            initialized: false,
        }
    }

    #[inline]
    fn get_bit(&self, distance: u64) -> bool {
        let d = distance as usize;
        (self.bits[d / 64] >> (d % 64)) & 1 != 0
    }

    #[inline]
    fn set_bit(&mut self, distance: u64) {
        let d = distance as usize;
        self.bits[d / 64] |= 1u64 << (d % 64);
    }

    /// Shift the whole window toward higher distance by `n` bits (multi-word
    /// left shift), discarding bits that fall off the top (now too old). Makes
    /// room at distance 0 for a newly-advanced highest seq.
    fn shift(&mut self, n: usize) {
        let words = n / 64;
        let off = n % 64;
        if off == 0 {
            for i in (0..REPLAY_WORDS).rev() {
                self.bits[i] = if i >= words { self.bits[i - words] } else { 0 };
            }
        } else {
            for i in (0..REPLAY_WORDS).rev() {
                let lo = if i >= words {
                    self.bits[i - words] << off
                } else {
                    0
                };
                let hi = if i > words {
                    self.bits[i - words - 1] >> (64 - off)
                } else {
                    0
                };
                self.bits[i] = lo | hi;
            }
        }
    }

    fn check_and_record(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.highest = seq;
            self.initialized = true;
            self.bits = [0; REPLAY_WORDS];
            self.set_bit(0);
            return true;
        }

        if seq > self.highest {
            let advance = seq - self.highest;
            if advance >= REPLAY_WINDOW_SIZE as u64 {
                self.bits = [0; REPLAY_WORDS]; // window fully shifted — reset
            } else {
                self.shift(advance as usize);
            }
            self.highest = seq;
            self.set_bit(0); // mark current seq as received
            return true;
        }

        // seq <= highest
        let distance = self.highest - seq;
        if distance >= REPLAY_WINDOW_SIZE as u64 {
            return false; // too old
        }
        if self.get_bit(distance) {
            return false; // duplicate
        }
        self.set_bit(distance);
        true
    }
}

impl PacketCodec {
    pub fn new(key: [u8; 32]) -> Self {
        let mut nonce_seed = [0u8; 4];
        rand::thread_rng().fill(&mut nonce_seed);
        let nonce_prp_key: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"qeli-nonce-prp-v1");
            h.update(key);
            h.finalize().into()
        };
        PacketCodec {
            cipher: Cipher::new(&key),
            counter: 0,
            nonce_seed,
            nonce_prp_key,
            replay_window: ReplayWindow::new(),
            framing: Framing::Tls,
        }
    }

    /// Like [`PacketCodec::new`] but emits/parses bare length-prefixed records
    /// (`[u16 len][nonce][ct]`) for the `plain` wire mode — no TLS dressing.
    pub fn new_raw(key: [u8; 32]) -> Self {
        let mut c = Self::new(key);
        c.framing = Framing::Raw;
        c
    }

    pub fn encrypt_packet(&mut self, data: &[u8], padding: &[u8]) -> Result<Vec<u8>, PacketError> {
        if self.counter >= u64::MAX - 1000 {
            return Err(PacketError::CounterExhausted);
        }
        let counter = self.counter;
        // Counter-based nonce: seed[4] || counter[8], then run through a keyed
        // 96-bit Feistel permutation. The permutation is bijective, so unique
        // (seed,counter) pairs still yield unique nonces (no AEAD reuse), but the
        // value on the wire no longer increments by 1 — removing the trivial DPI
        // fingerprint of a visible per-packet counter. seed is random per session
        // so nonces stay unique across reconnects.
        let mut raw_nonce = [0u8; NONCE_SIZE];
        raw_nonce[..4].copy_from_slice(&self.nonce_seed);
        raw_nonce[4..].copy_from_slice(&counter.to_be_bytes());
        let nonce = prp_nonce(&self.nonce_prp_key, &raw_nonce);

        // The trailer stores the padding length as a u16, so clamp here rather
        // than letting `as u16` silently wrap (which would desync the receiver's
        // padding-strip). Callers cap padding well under u16::MAX; this is a
        // defensive guard against a future caller passing an oversized buffer.
        let padding_len = padding.len().min(u16::MAX as usize);
        let padding = &padding[..padding_len];

        // Inner plaintext = counter(8) || data || padding || padding_len(2); the
        // ciphertext is that plus the 16-byte AEAD tag.
        let plaintext_len = COUNTER_SIZE + data.len() + padding_len + 2;
        // Guard against `as u16` silently wrapping the length prefix if a caller ever
        // passes an oversized `data` (mirror of the receiver's MAX_RECORD_SIZE cap): the
        // whole record payload must fit both the u16 field and the peer's per-record
        // ceiling. Callers feed MTU-bounded TUN packets, so this never fires in practice.
        let record_payload_len = NONCE_SIZE + plaintext_len + TAG_SIZE;
        if record_payload_len > MAX_RECORD_SIZE {
            return Err(PacketError::PacketTooLarge);
        }
        let header_len = match self.framing {
            Framing::Tls => TLS_RECORD_HEADER,
            Framing::Raw => RAW_RECORD_HEADER,
        };
        let payload_len = record_payload_len as u16;

        // Build the whole on-wire record in ONE allocation. The plaintext is
        // written where the ciphertext will live and encrypted in place, then the
        // detached tag is appended — the old path allocated three Vecs (the
        // plaintext, the AEAD output, and the record). Byte-for-byte identical
        // output to the previous allocating path.
        let mut record = Vec::with_capacity(header_len + NONCE_SIZE + plaintext_len + TAG_SIZE);
        if self.framing == Framing::Tls {
            // TLS application-data record header (type=0x17, version=0x0303).
            record.push(0x17);
            record.extend_from_slice(&[0x03, 0x03]);
        }
        record.extend_from_slice(&payload_len.to_be_bytes());
        record.extend_from_slice(&nonce);
        let ct_start = record.len();
        record.extend_from_slice(&counter.to_be_bytes());
        record.extend_from_slice(data);
        record.extend_from_slice(padding);
        record.extend_from_slice(&(padding_len as u16).to_be_bytes());

        self.counter = self.counter.wrapping_add(1);

        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, &mut record[ct_start..])
            .map_err(|_| PacketError::EncryptFailed)?;
        record.extend_from_slice(&tag);

        Ok(record)
    }

    pub fn decrypt_packet(&mut self, record: &[u8]) -> Result<Vec<u8>, PacketError> {
        let header_len = match self.framing {
            Framing::Tls => TLS_RECORD_HEADER,
            Framing::Raw => RAW_RECORD_HEADER,
        };
        if record.len() < header_len + NONCE_SIZE + TAG_SIZE + COUNTER_SIZE {
            return Err(PacketError::PacketTooShort);
        }

        let payload_len = match self.framing {
            Framing::Tls => {
                let content_type = record[0];
                if content_type != 0x17 {
                    return Err(PacketError::WrongContentType(content_type));
                }
                u16::from_be_bytes([record[3], record[4]]) as usize
            }
            Framing::Raw => u16::from_be_bytes([record[0], record[1]]) as usize,
        };
        if payload_len > MAX_RECORD_SIZE {
            return Err(PacketError::PacketTooLarge);
        }
        if record.len() < header_len + payload_len {
            return Err(PacketError::PacketTooShort);
        }

        let payload = &record[header_len..header_len + payload_len];

        // `payload_len` is attacker-controlled (the record's own length field) and
        // is only bounded ABOVE (MAX_RECORD_SIZE) and against `record.len()`, not
        // below. On the UDP path a datagram whose length field is < NONCE_SIZE
        // still clears those checks, so slice with `get(..)` rather than `[..N]`
        // (which would panic — and abort the process under `panic = "abort"`).
        let nonce: [u8; NONCE_SIZE] = payload
            .get(..NONCE_SIZE)
            .and_then(|s| s.try_into().ok())
            .ok_or(PacketError::PacketTooShort)?;

        let ciphertext = &payload[NONCE_SIZE..];

        // Split the trailing 16-byte AEAD tag from the ciphertext body, then
        // decrypt the body in place in a buffer we own. The record is a borrowed
        // read buffer, so one copy is unavoidable — but the old path allocated
        // TWICE (once inside the allocating `decrypt`, and again below to strip
        // the counter prefix). `ciphertext.len()` may be < TAG_SIZE for a crafted
        // short record; reject rather than under-slice.
        if ciphertext.len() < TAG_SIZE {
            return Err(PacketError::PacketTooShort);
        }
        let (ct_body, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);
        let tag: [u8; TAG_SIZE] = tag.try_into().map_err(|_| PacketError::PacketTooShort)?;
        let mut plaintext = ct_body.to_vec();
        self.cipher
            .decrypt_in_place_detached(&nonce, &mut plaintext, &tag)
            .map_err(|_| PacketError::DecryptFailed)?;

        if plaintext.len() < COUNTER_SIZE + 2 {
            return Err(PacketError::PacketTooShort);
        }

        let packet_counter = u64::from_be_bytes([
            plaintext[0],
            plaintext[1],
            plaintext[2],
            plaintext[3],
            plaintext[4],
            plaintext[5],
            plaintext[6],
            plaintext[7],
        ]);

        let padding_len = u16::from_be_bytes([
            plaintext[plaintext.len() - 2],
            plaintext[plaintext.len() - 1],
        ]) as usize;

        if COUNTER_SIZE + padding_len + 2 > plaintext.len() {
            return Err(PacketError::InvalidPadding);
        }

        // Record against the replay window only AFTER the packet fully validates.
        // A packet that authenticated (AEAD passed → it came from the legitimate
        // peer) but carries malformed padding is a peer bug, not an attack; doing
        // the replay-record first would needlessly burn that counter's window slot.
        if !self.replay_window.check_and_record(packet_counter) {
            return Err(PacketError::ReplayDetected);
        }

        let data_len = plaintext.len() - COUNTER_SIZE - 2 - padding_len;
        // Strip the trailer (padding + its 2-byte length) then the 8-byte counter
        // prefix, reusing the decrypt buffer in place — the old path allocated a
        // second Vec here just to return the data slice.
        plaintext.truncate(COUNTER_SIZE + data_len);
        plaintext.drain(..COUNTER_SIZE);

        Ok(plaintext)
    }
}

pub async fn read_tls_record<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<Vec<u8>, PacketError> {
    let mut header = [0u8; TLS_RECORD_HEADER];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| PacketError::ConnectionClosed)?;

    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if payload_len > MAX_RECORD_SIZE {
        return Err(PacketError::PacketTooLarge);
    }

    let mut record = Vec::with_capacity(TLS_RECORD_HEADER + payload_len);
    record.extend_from_slice(&header);
    record.resize(TLS_RECORD_HEADER + payload_len, 0);
    stream
        .read_exact(&mut record[TLS_RECORD_HEADER..])
        .await
        .map_err(|_| PacketError::ConnectionClosed)?;

    Ok(record)
}

/// Read one raw (`plain`-mode) record: a 2-byte big-endian length prefix followed
/// by that many payload bytes. Returns the whole record including the 2-byte
/// header, so `PacketCodec::decrypt_packet` (in `Framing::Raw`) parses it directly.
pub async fn read_raw_record<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<Vec<u8>, PacketError> {
    let mut header = [0u8; RAW_RECORD_HEADER];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| PacketError::ConnectionClosed)?;

    let payload_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    if payload_len > MAX_RECORD_SIZE {
        return Err(PacketError::PacketTooLarge);
    }

    let mut record = Vec::with_capacity(RAW_RECORD_HEADER + payload_len);
    record.extend_from_slice(&header);
    record.resize(RAW_RECORD_HEADER + payload_len, 0);
    stream
        .read_exact(&mut record[RAW_RECORD_HEADER..])
        .await
        .map_err(|_| PacketError::ConnectionClosed)?;

    Ok(record)
}

/// Read one record using the given [`Framing`] (TLS-dressed or raw).
pub async fn read_record<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
    framing: Framing,
) -> Result<Vec<u8>, PacketError> {
    match framing {
        Framing::Tls => read_tls_record(stream).await,
        Framing::Raw => read_raw_record(stream).await,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet too short")]
    PacketTooShort,
    #[error("packet too large")]
    PacketTooLarge,
    #[error("wrong content type: {0}")]
    WrongContentType(u8),
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("invalid padding")]
    InvalidPadding,
    #[error("counter exhausted")]
    CounterExhausted,
    #[error("replay detected")]
    ReplayDetected,
    #[error("connection closed")]
    ConnectionClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_oversized_data_errors_not_truncates() {
        // A buffer whose framed record would exceed MAX_RECORD_SIZE must be rejected
        // (PacketTooLarge), not silently wrapped through the u16 length prefix — the 1.4
        // regression. MTU-bounded callers never reach this in practice.
        let key = [0x11u8; 32];
        let big = vec![0u8; MAX_RECORD_SIZE + 1];
        assert!(matches!(
            PacketCodec::new(key).encrypt_packet(&big, &[]),
            Err(PacketError::PacketTooLarge)
        ));
    }

    #[test]
    fn test_replay_window_basic() {
        let mut rw = ReplayWindow::new();
        assert!(rw.check_and_record(1));
        assert!(rw.check_and_record(2));
        assert!(rw.check_and_record(5));
        assert!(!rw.check_and_record(1)); // duplicate
        assert!(!rw.check_and_record(2)); // duplicate
    }

    #[test]
    fn test_replay_window_out_of_order() {
        let mut rw = ReplayWindow::new();
        assert!(rw.check_and_record(10));
        assert!(rw.check_and_record(8)); // out of order, within window
        assert!(rw.check_and_record(9));
        assert!(rw.check_and_record(12));
        assert!(!rw.check_and_record(8)); // duplicate
    }

    #[test]
    fn test_replay_window_far_ahead() {
        let mut rw = ReplayWindow::new();
        assert!(rw.check_and_record(1));
        // Jump well past the (2048-bit) window so it fully resets.
        assert!(rw.check_and_record(5000));
        assert!(!rw.check_and_record(2)); // too old now (distance > window)
    }

    #[test]
    fn test_replay_window_wide_reordering() {
        // A 64-bit window would have false-rejected these; 2048 must accept the
        // whole reordered burst and still catch a duplicate.
        let mut rw = ReplayWindow::new();
        assert!(rw.check_and_record(2000));
        for s in [1u64, 1000, 1999, 500, 1500] {
            assert!(
                rw.check_and_record(s),
                "seq {s} within 2048 window must pass"
            );
        }
        assert!(!rw.check_and_record(1000)); // duplicate
        assert!(rw.check_and_record(4047)); // advance by 2047 (still < window)
        assert!(!rw.check_and_record(1999)); // now distance 2048 — too old
    }

    /// Invert the Feistel network (test-only) to prove it is a true bijection.
    fn prp_nonce_inverse(key: &[u8; 32], n: &[u8; NONCE_SIZE]) -> [u8; NONCE_SIZE] {
        let mut l = [0u8; 6];
        let mut r = [0u8; 6];
        l.copy_from_slice(&n[..6]);
        r.copy_from_slice(&n[6..]);
        for round in (0..4u8).rev() {
            // undo (l,r) = (r, l ^ F(r_prev)): previous r was current l
            let prev_r = l;
            let f = prp_round(key, round, &prev_r);
            let mut prev_l = [0u8; 6];
            for i in 0..6 {
                prev_l[i] = r[i] ^ f[i];
            }
            l = prev_l;
            r = prev_r;
        }
        let mut out = [0u8; NONCE_SIZE];
        out[..6].copy_from_slice(&l);
        out[6..].copy_from_slice(&r);
        out
    }

    #[test]
    fn prp_nonce_is_invertible() {
        let key = [0x5Au8; 32];
        for c in [0u64, 1, 2, 12345, u64::MAX] {
            let mut raw = [0u8; NONCE_SIZE];
            raw[..4].copy_from_slice(&[1, 2, 3, 4]);
            raw[4..].copy_from_slice(&c.to_be_bytes());
            let n = prp_nonce(&key, &raw);
            assert_eq!(
                prp_nonce_inverse(&key, &n),
                raw,
                "Feistel must be invertible"
            );
        }
    }

    #[test]
    fn prp_nonce_no_collisions_over_many_counters() {
        let key = [0x7Bu8; 32];
        let seed = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut seen = std::collections::HashSet::new();
        for c in 0u64..200_000 {
            let mut raw = [0u8; NONCE_SIZE];
            raw[..4].copy_from_slice(&seed);
            raw[4..].copy_from_slice(&c.to_be_bytes());
            let n = prp_nonce(&key, &raw);
            assert!(seen.insert(n), "nonce collision at counter {c}");
        }
    }

    #[test]
    fn prp_nonce_hides_increment_pattern() {
        // Consecutive counters must NOT produce nonces that differ in just the
        // low byte (the old +1 tell). Expect a large Hamming distance.
        let key = [0x11u8; 32];
        let mk = |c: u64| {
            let mut raw = [0u8; NONCE_SIZE];
            raw[..4].copy_from_slice(&[9, 9, 9, 9]);
            raw[4..].copy_from_slice(&c.to_be_bytes());
            prp_nonce(&key, &raw)
        };
        let a = mk(1000);
        let b = mk(1001);
        let diff_bits: u32 = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum();
        assert!(
            diff_bits > 16,
            "consecutive nonces differ in only {diff_bits} bits — pattern leaks"
        );
    }

    #[test]
    fn prp_nonce_roundtrip_two_packets() {
        // The receiver reads the (permuted) nonce off the wire, so decryption is
        // unaffected by the sender-side permutation.
        let key = [0x42u8; 32];
        let mut enc = PacketCodec::new(key);
        let mut dec = PacketCodec::new(key);
        let p1 = enc.encrypt_packet(b"first", &[]).unwrap();
        let p2 = enc.encrypt_packet(b"second", &[]).unwrap();
        // wire nonces (bytes 5..17) must look unrelated, not +1
        assert_ne!(p1[5..17], p2[5..17]);
        assert_eq!(dec.decrypt_packet(&p1).unwrap(), b"first");
        assert_eq!(dec.decrypt_packet(&p2).unwrap(), b"second");
    }

    #[test]
    fn raw_framing_roundtrip_and_has_no_tls_header() {
        // `plain` mode: records are bare [u16 len][nonce][ct] — no 0x17 0x03 0x03.
        let key = [0x99u8; 32];
        let mut enc = PacketCodec::new_raw(key);
        let mut dec = PacketCodec::new_raw(key);
        let rec = enc.encrypt_packet(b"hello-plain", &[]).unwrap();
        // First byte is the high byte of the payload length, not the TLS type 0x17.
        let payload_len = u16::from_be_bytes([rec[0], rec[1]]) as usize;
        assert_eq!(payload_len, rec.len() - RAW_RECORD_HEADER);
        assert_eq!(dec.decrypt_packet(&rec).unwrap(), b"hello-plain");
    }

    #[test]
    fn raw_and_tls_framings_are_not_interchangeable() {
        // A raw record fed to a TLS codec (or vice-versa) must not decode — the
        // header layouts differ, so the modes can't be silently mixed on a link.
        let key = [0x33u8; 32];
        let raw_rec = PacketCodec::new_raw(key).encrypt_packet(b"x", &[]).unwrap();
        assert!(PacketCodec::new(key).decrypt_packet(&raw_rec).is_err());
    }

    #[test]
    fn short_payload_len_field_errors_not_panics() {
        // Regression (T2): the record's length field is attacker-controlled and only
        // bounded above. A datagram long enough to clear the record.len() floor but
        // whose declared payload is shorter than the nonce must return an error, NOT
        // panic — under `panic = "abort"` a panic here was a remote crash reachable
        // pre-auth with one crafted short UDP datagram.
        let key = [0x7u8; 32];
        // Raw framing: [len=0:2] + (NONCE+TAG+COUNTER) zero bytes clears the floor.
        let raw = vec![0u8; RAW_RECORD_HEADER + NONCE_SIZE + TAG_SIZE + COUNTER_SIZE];
        assert!(matches!(
            PacketCodec::new_raw(key).decrypt_packet(&raw),
            Err(PacketError::PacketTooShort)
        ));
        // TLS framing: content_type 0x17, length field 0, padded to clear the floor.
        let mut tls = vec![0u8; TLS_RECORD_HEADER + NONCE_SIZE + TAG_SIZE + COUNTER_SIZE];
        tls[0] = 0x17; // application_data, else it short-circuits earlier
        assert!(matches!(
            PacketCodec::new(key).decrypt_packet(&tls),
            Err(PacketError::PacketTooShort)
        ));
    }

    /// AsyncRead that hands out at most `chunk` bytes per `poll_read`, so a test can
    /// feed a byte stream through the framing reader at adversarial boundaries — TCP
    /// resegmentation (one record split across reads) and coalescing (many records in
    /// one read), the classic source of framing desync.
    struct ChunkedReader {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }
    impl ChunkedReader {
        fn new(data: Vec<u8>, chunk: usize) -> Self {
            Self {
                data,
                pos: 0,
                chunk: chunk.max(1),
            }
        }
    }
    impl tokio::io::AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = (self.data.len() - self.pos)
                .min(self.chunk)
                .min(buf.remaining());
            if n > 0 {
                let (start, end) = (self.pos, self.pos + n);
                buf.put_slice(&self.data[start..end]);
                self.pos = end;
            }
            // n == 0 here means the stream is exhausted → Ready with 0 filled = EOF,
            // which read_exact surfaces as ConnectionClosed.
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn framing_torture_inner_records_survive_adversarial_chunking() {
        // The inner record framing (shared by every TCP wire mode: plain = Raw,
        // fake-tls / obfs-inner / reality-inner = Tls) must reassemble every record
        // exactly no matter how the transport splits or coalesces the byte stream —
        // the desync class that produced the critical oversized-record tunnel break.
        // Encode a run of varied-size packets, then replay the concatenated wire
        // through the real read path at every chunk granularity.
        let key = [0x42u8; 32];
        let sizes = [
            0usize, 1, 2, 3, 5, 7, 13, 100, 255, 256, 1400, 4096, 8000, 15000,
        ];
        for framing in [Framing::Tls, Framing::Raw] {
            let mk = || match framing {
                Framing::Tls => PacketCodec::new(key),
                Framing::Raw => PacketCodec::new_raw(key),
            };
            let payloads: Vec<Vec<u8>> = sizes
                .iter()
                .enumerate()
                .map(|(i, &n)| vec![(i as u8).wrapping_mul(31).wrapping_add(7); n])
                .collect();
            let mut enc = mk();
            let mut wire = Vec::new();
            for p in &payloads {
                wire.extend_from_slice(&enc.encrypt_packet(p, &[]).unwrap());
            }
            // 1/2/3/7 exercise mid-header and mid-body splits; 64/5000 land inside large
            // records; usize::MAX delivers the whole stream at once (max coalescing).
            for chunk in [1usize, 2, 3, 7, 64, 5000, usize::MAX] {
                let mut dec = mk();
                let mut reader = ChunkedReader::new(wire.clone(), chunk);
                for (i, expected) in payloads.iter().enumerate() {
                    let rec = read_record(&mut reader, framing).await.unwrap_or_else(|e| {
                        panic!("{framing:?} chunk={chunk} rec#{i}: read {e:?}")
                    });
                    let got = dec.decrypt_packet(&rec).unwrap_or_else(|e| {
                        panic!("{framing:?} chunk={chunk} rec#{i}: decrypt {e:?}")
                    });
                    assert_eq!(&got, expected, "{framing:?} chunk={chunk} rec#{i} mismatch");
                }
                // Stream fully consumed → the next framed read is a clean EOF, not a
                // partial record or a hang.
                assert!(
                    matches!(
                        read_record(&mut reader, framing).await,
                        Err(PacketError::ConnectionClosed)
                    ),
                    "{framing:?} chunk={chunk}: expected clean EOF after all records"
                );
            }
        }
    }

    #[tokio::test]
    async fn read_rejects_oversized_record_header() {
        // Receiver-side framing guard: a header declaring a length beyond
        // MAX_RECORD_SIZE is rejected at read time (PacketTooLarge) rather than read
        // into an unbounded buffer. Pairs with the sender-side encrypt guard, and is
        // exactly the error the data path now drops on instead of tearing the tunnel.
        let big = (MAX_RECORD_SIZE + 1) as u16;
        let mut tls = vec![0x17u8, 0x03, 0x03];
        tls.extend_from_slice(&big.to_be_bytes());
        tls.resize(64, 0);
        assert!(matches!(
            read_tls_record(&mut ChunkedReader::new(tls, 3)).await,
            Err(PacketError::PacketTooLarge)
        ));
        let mut raw = big.to_be_bytes().to_vec();
        raw.resize(64, 0);
        assert!(matches!(
            read_raw_record(&mut ChunkedReader::new(raw, 3)).await,
            Err(PacketError::PacketTooLarge)
        ));
    }
}
