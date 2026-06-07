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
const REPLAY_WINDOW_SIZE: usize = 64;

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

/// Sliding-window replay protection.
/// Uses a bitmask where bit 0 corresponds to seq `highest`,
/// bit 1 to seq `highest - 1`, etc.
struct ReplayWindow {
    highest: u64,
    /// Bitmask: bit N is set if seq = (highest - N) was received
    bits: u64,
    initialized: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bits: 0,
            initialized: false,
        }
    }

    fn check_and_record(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.highest = seq;
            self.initialized = true;
            self.bits = 1;
            return true;
        }

        if seq > self.highest {
            let advance = seq - self.highest;
            if advance >= REPLAY_WINDOW_SIZE as u64 {
                // Window fully shifted — reset
                self.bits = 0;
            } else {
                // Shift bits left to make room for new highest
                self.bits <<= advance;
                let mask = if REPLAY_WINDOW_SIZE >= 64 {
                    u64::MAX
                } else {
                    (1u64 << REPLAY_WINDOW_SIZE) - 1
                };
                self.bits &= mask;
            }
            self.highest = seq;
            self.bits |= 1; // mark current seq as received
            return true;
        }

        // seq <= highest
        let distance = self.highest - seq;
        if distance >= REPLAY_WINDOW_SIZE as u64 {
            return false; // too old
        }

        let mask = 1u64 << distance;
        if self.bits & mask != 0 {
            return false; // duplicate
        }
        self.bits |= mask;
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
        // Counter-based nonce: seed[4] || counter[8], then run through a keyed
        // 96-bit Feistel permutation. The permutation is bijective, so unique
        // (seed,counter) pairs still yield unique nonces (no AEAD reuse), but the
        // value on the wire no longer increments by 1 — removing the trivial DPI
        // fingerprint of a visible per-packet counter. seed is random per session
        // so nonces stay unique across reconnects.
        let mut raw_nonce = [0u8; NONCE_SIZE];
        raw_nonce[..4].copy_from_slice(&self.nonce_seed);
        raw_nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        let nonce = prp_nonce(&self.nonce_prp_key, &raw_nonce);

        // The trailer stores the padding length as a u16, so clamp here rather
        // than letting `as u16` silently wrap (which would desync the receiver's
        // padding-strip). Callers cap padding well under u16::MAX; this is a
        // defensive guard against a future caller passing an oversized buffer.
        let padding_len = padding.len().min(u16::MAX as usize);
        let padding = &padding[..padding_len];
        let mut plaintext = Vec::with_capacity(COUNTER_SIZE + data.len() + padding_len + 2);
        plaintext.extend_from_slice(&self.counter.to_be_bytes());
        plaintext.extend_from_slice(data);
        plaintext.extend_from_slice(padding);
        plaintext.extend_from_slice(&(padding_len as u16).to_be_bytes());

        self.counter = self.counter.wrapping_add(1);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, &plaintext)
            .map_err(|_| PacketError::EncryptFailed)?;

        let payload_len = (NONCE_SIZE + ciphertext.len()) as u16;
        let header_len = match self.framing {
            Framing::Tls => TLS_RECORD_HEADER,
            Framing::Raw => RAW_RECORD_HEADER,
        };
        let mut record = Vec::with_capacity(header_len + NONCE_SIZE + ciphertext.len());
        if self.framing == Framing::Tls {
            // TLS application-data record header (type=0x17, version=0x0303).
            record.push(0x17);
            record.extend_from_slice(&[0x03, 0x03]);
        }
        record.extend_from_slice(&payload_len.to_be_bytes());
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);

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

        let nonce: [u8; NONCE_SIZE] = payload[..NONCE_SIZE]
            .try_into()
            .map_err(|_| PacketError::PacketTooShort)?;

        let ciphertext = &payload[NONCE_SIZE..];

        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext)
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

        if !self.replay_window.check_and_record(packet_counter) {
            return Err(PacketError::ReplayDetected);
        }

        let padding_len = u16::from_be_bytes([
            plaintext[plaintext.len() - 2],
            plaintext[plaintext.len() - 1],
        ]) as usize;

        if COUNTER_SIZE + padding_len + 2 > plaintext.len() {
            return Err(PacketError::InvalidPadding);
        }

        let data_len = plaintext.len() - COUNTER_SIZE - 2 - padding_len;
        let data = plaintext[COUNTER_SIZE..COUNTER_SIZE + data_len].to_vec();

        Ok(data)
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
        assert!(rw.check_and_record(100)); // far ahead, resets window
        assert!(!rw.check_and_record(2)); // too old now
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
}
