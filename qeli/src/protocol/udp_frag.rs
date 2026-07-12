//! App-layer fragmentation for the large UDP handshake messages.
//!
//! The post-quantum UDP handshake is big: the ClientHello carries the ML-KEM-768
//! encapsulation key (1184 B) → ~1440 B, and the ServerHello+Certificate+Finished
//! carries the ML-KEM ciphertext (1088 B) + cert chain → ~1959 B. A single ~2 KB
//! UDP datagram is IP-fragmented by the network, and mobile / CGNAT paths routinely
//! DROP IP fragments — so the fragmented ServerHello never reassembles and the UDP
//! handshake silently hangs (works on Wi-Fi, fails on LTE).
//!
//! Fix: split those two messages ourselves into <=[`MAX_CHUNK`]-byte fragments, each
//! in its own datagram that never needs IP fragmentation, and reassemble them at the
//! peer. Only the ClientHello and the ServerHello are fragmented; the small
//! post-handshake auth / auth-ok messages already fit one datagram.
//!
//! Layering: this sits on the cleartext handshake message, BELOW the QUIC-mask and
//! obfs-XOR transforms — each fragment datagram is independently QUIC-wrapped / XORed.
//!
//! Wire: `[MAGIC(3)][msg_id(1)][idx(1)][count(1)][chunk...]`. `MAGIC` cannot open a
//! TLS record (`0x16 0x03`), so a backward-compatible server distinguishes a
//! fragmented ClientHello from a legacy single-datagram one and replies in kind.

use std::time::{Duration, Instant};

/// Per-fragment magic — distinct from a TLS record opener (`0x16 0x03`).
pub const FRAG_MAGIC: [u8; 3] = [0xF0, 0x9B, 0x71];
/// Header length: magic(3) + msg_id(1) + idx(1) + count(1).
pub const FRAG_HDR_LEN: usize = FRAG_MAGIC.len() + 3;
/// Max payload bytes per fragment. Keeps the outer datagram (chunk + header + QUIC
/// wrap + UDP/IP) under the IPv6 minimum MTU (1280) and every LTE/CGNAT path, so no
/// IP fragmentation occurs. Same conservative floor QUIC uses for initial packets.
pub const MAX_CHUNK: usize = 1200;
/// Hard cap on fragments per message (anti-DoS on the reassembly buffer). 24*1200 ≈
/// 28 KB, far above any real handshake (~2 KB / 2 fragments).
pub const MAX_FRAGS: u8 = 24;
/// A partially-reassembled message older than this is dropped (anti-DoS).
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Message ids — which handshake message a fragment belongs to.
pub const MSG_CLIENT_HELLO: u8 = 1;
pub const MSG_SERVER_HELLO: u8 = 2;
/// A throwaway pre-handshake **junk** decoy datagram (AmneziaWG-style `Jc` on UDP).
/// It carries no real data and is dropped by the receiver cheaply — before the
/// new-session rate limiter and any crypto — so it never charges the limiter or
/// pollutes the per-source reassembler. The client may emit `jc` of these before its
/// ClientHello to blur the size/count fingerprint of the first datagrams. Both ends
/// need only agree that junk is DROPPED (they never agree on the count — a lost or
/// reordered junk datagram is harmless), unlike the count-based TCP obfs junk.
pub const MSG_JUNK: u8 = 3;
/// Path-MTU **probe** (client→server): a single-fragment datagram padded so the whole
/// outer datagram is exactly the size being tested. Sent with DF set, so if it exceeds
/// the path MTU it is dropped (not IP-fragmented) → no ACK → that size fails. The body
/// is `[id(2 LE)][outer_size(2 LE)]` then random padding. Rides the same obfs-XOR /
/// QUIC wrap as data, so it measures the REAL data-plane path. Recognized and handled
/// (echoed) before the reassembler, so its oversized "chunk" never hits [`MAX_CHUNK`].
pub const MSG_MTU_PROBE: u8 = 4;
/// Path-MTU probe **ACK** (server→client): a tiny datagram echoing the probe's
/// `[id(2 LE)][outer_size(2 LE)]`, confirming the big probe arrived intact.
pub const MSG_MTU_PROBE_ACK: u8 = 5;

/// Probe/ACK body after the 6-byte fragment header: `id(2) + outer_size(2)`.
pub const PROBE_BODY_LEN: usize = 4;

/// True if `d` (a datagram payload, after obfs/QUIC unwrap) is a qeli handshake
/// fragment. Lets a backward-compatible peer tell fragments from a legacy single
/// datagram (a TLS record, which starts `0x16 0x03`).
#[inline]
pub fn is_fragment(d: &[u8]) -> bool {
    d.len() >= FRAG_HDR_LEN && d[..FRAG_MAGIC.len()] == FRAG_MAGIC
}

/// True if `d` (after obfs/QUIC unwrap) is a path-MTU probe ([`MSG_MTU_PROBE`]).
#[inline]
pub fn is_mtu_probe(d: &[u8]) -> bool {
    is_fragment(d) && d[3] == MSG_MTU_PROBE && d.len() >= FRAG_HDR_LEN + PROBE_BODY_LEN
}

/// True if `d` (after obfs/QUIC unwrap) is a probe ACK ([`MSG_MTU_PROBE_ACK`]).
#[inline]
pub fn is_mtu_probe_ack(d: &[u8]) -> bool {
    is_fragment(d) && d[3] == MSG_MTU_PROBE_ACK && d.len() >= FRAG_HDR_LEN + PROBE_BODY_LEN
}

/// Read `(id, outer_size)` from a probe or probe-ACK datagram (after unwrap).
#[inline]
pub fn parse_mtu_probe(d: &[u8]) -> Option<(u16, u16)> {
    if d.len() < FRAG_HDR_LEN + PROBE_BODY_LEN {
        return None;
    }
    let id = u16::from_le_bytes([d[FRAG_HDR_LEN], d[FRAG_HDR_LEN + 1]]);
    let size = u16::from_le_bytes([d[FRAG_HDR_LEN + 2], d[FRAG_HDR_LEN + 3]]);
    Some((id, size))
}

/// Build a probe datagram padded so the TOTAL outer datagram is `outer_size` bytes.
/// `id` correlates the ACK. `None` if `outer_size` can't hold header+body.
pub fn mtu_probe_datagram(id: u16, outer_size: usize) -> Option<Vec<u8>> {
    use rand::prelude::*;
    let min = FRAG_HDR_LEN + PROBE_BODY_LEN;
    if outer_size < min || outer_size > u16::MAX as usize {
        return None;
    }
    let mut out = Vec::with_capacity(outer_size);
    out.extend_from_slice(&FRAG_MAGIC);
    out.push(MSG_MTU_PROBE);
    out.push(0); // idx
    out.push(1); // count (single fragment)
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(outer_size as u16).to_le_bytes());
    out.resize(outer_size, 0);
    rand::rng().fill_bytes(&mut out[min..]); // random pad, not a zero run
    Some(out)
}

/// Build the tiny ACK for a received probe (echoes its `id` + `outer_size`).
pub fn mtu_probe_ack_datagram(id: u16, outer_size: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAG_HDR_LEN + PROBE_BODY_LEN);
    out.extend_from_slice(&FRAG_MAGIC);
    out.push(MSG_MTU_PROBE_ACK);
    out.push(0);
    out.push(1);
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&outer_size.to_le_bytes());
    out
}

/// True if `d` (after obfs/QUIC unwrap) is an AWG junk decoy datagram ([`MSG_JUNK`]).
#[inline]
pub fn is_junk(d: &[u8]) -> bool {
    is_fragment(d) && d[3] == MSG_JUNK
}

/// Build ONE junk decoy datagram: a single-fragment [`MSG_JUNK`] message with `len`
/// random body bytes. It uses the SAME on-wire framing as a real fragment, so it
/// rides the identical obfs-XOR / QUIC mask and the peer's [`is_junk`] recognizes it
/// after unwrap. The caller picks `len` inside its `[jmin, jmax]` window.
pub fn junk_datagram(len: usize) -> Vec<u8> {
    use rand::prelude::*;
    let mut out = Vec::with_capacity(FRAG_HDR_LEN + len);
    out.extend_from_slice(&FRAG_MAGIC);
    out.push(MSG_JUNK);
    out.push(0); // idx  (single-fragment message)
    out.push(1); // count
    let base = out.len();
    out.resize(base + len, 0);
    rand::rng().fill_bytes(&mut out[base..]);
    out
}

/// Split a handshake message into fragment datagrams (always >= 1). Each is ready to
/// be QUIC-wrapped / sent independently.
pub fn fragment(msg_id: u8, msg: &[u8]) -> Vec<Vec<u8>> {
    let count = msg.len().div_ceil(MAX_CHUNK).max(1);
    debug_assert!(
        count <= MAX_FRAGS as usize,
        "handshake message too large to fragment"
    );
    (0..count)
        .map(|i| {
            let start = i * MAX_CHUNK;
            let end = (start + MAX_CHUNK).min(msg.len());
            let mut out = Vec::with_capacity(FRAG_HDR_LEN + (end - start));
            out.extend_from_slice(&FRAG_MAGIC);
            out.push(msg_id);
            out.push(i as u8);
            out.push(count as u8);
            out.extend_from_slice(&msg[start..end]);
            out
        })
        .collect()
}

/// Reassembles the fragments of ONE message from one peer. Tolerates out-of-order
/// arrival and duplicates; rejects inconsistent fragments. Bounded by [`MAX_FRAGS`]
/// and (via [`age`](Reassembler::age)) [`REASSEMBLY_TIMEOUT`].
pub struct Reassembler {
    msg_id: u8,
    count: u8,
    parts: Vec<Option<Vec<u8>>>,
    have: u8,
    started: Instant,
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler {
            msg_id: 0,
            count: 0,
            parts: Vec::new(),
            have: 0,
            started: Instant::now(),
        }
    }

    /// How long since the first fragment arrived — caller drops stale partials.
    pub fn age(&self) -> Duration {
        self.started.elapsed()
    }

    /// Feed one fragment datagram. `Ok(Some(msg))` once every fragment has arrived,
    /// `Ok(None)` if more are needed, `Err` on a malformed/inconsistent fragment
    /// (the caller should then drop this peer's reassembly state).
    pub fn push(&mut self, d: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
        if !is_fragment(d) {
            return Err("not a fragment");
        }
        let msg_id = d[3];
        let idx = d[4];
        let count = d[5];
        let chunk = &d[FRAG_HDR_LEN..];
        if count == 0 || count > MAX_FRAGS {
            return Err("bad fragment count");
        }
        if idx >= count {
            return Err("fragment index out of range");
        }
        // Bound per-fragment chunk size (anti-DoS: caps a reassembled message at
        // MAX_FRAGS*MAX_CHUNK). Legit senders never exceed MAX_CHUNK — fragment()
        // slices in MAX_CHUNK-sized chunks.
        if chunk.len() > MAX_CHUNK {
            return Err("fragment chunk too large");
        }
        if self.count == 0 {
            // First fragment seen for this message — initialise.
            self.msg_id = msg_id;
            self.count = count;
            self.parts = vec![None; count as usize];
            self.have = 0;
            self.started = Instant::now();
        } else if msg_id != self.msg_id || count != self.count {
            return Err("inconsistent fragment (msg_id/count changed)");
        }
        let slot = &mut self.parts[idx as usize];
        if slot.is_none() {
            *slot = Some(chunk.to_vec());
            self.have += 1;
        }
        // A duplicate fragment is silently ignored.
        if self.have == self.count {
            let total: usize = self.parts.iter().map(|p| p.as_ref().unwrap().len()).sum();
            let mut out = Vec::with_capacity(total);
            for p in &self.parts {
                out.extend_from_slice(p.as_ref().unwrap());
            }
            Ok(Some(out))
        } else {
            Ok(None)
        }
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble_all(frags: &[Vec<u8>]) -> Vec<u8> {
        let mut re = Reassembler::new();
        let mut out = None;
        for f in frags {
            out = re.push(f).unwrap();
        }
        out.expect("complete after all fragments")
    }

    #[test]
    fn mtu_probe_roundtrips_and_is_recognized() {
        let d = mtu_probe_datagram(0xBEEF, 1400).expect("builds");
        assert_eq!(d.len(), 1400, "outer datagram padded to the target size");
        assert!(is_mtu_probe(&d));
        assert!(!is_mtu_probe_ack(&d));
        assert!(!is_junk(&d));
        assert_eq!(parse_mtu_probe(&d), Some((0xBEEF, 1400)));

        // Server echo: tiny, carries the same id/size.
        let ack = mtu_probe_ack_datagram(0xBEEF, 1400);
        assert!(is_mtu_probe_ack(&ack));
        assert!(!is_mtu_probe(&ack));
        assert_eq!(parse_mtu_probe(&ack), Some((0xBEEF, 1400)));
        assert!(
            ack.len() < 32,
            "the ACK is small — only the big probe tests the path"
        );
    }

    #[test]
    fn mtu_probe_rejects_too_small_and_not_confused_with_fragment() {
        // Smaller than header+body → cannot build.
        assert!(mtu_probe_datagram(1, FRAG_HDR_LEN + PROBE_BODY_LEN - 1).is_none());
        // A real handshake fragment is NOT a probe.
        let frag = fragment(MSG_CLIENT_HELLO, b"hello")[0].clone();
        assert!(!is_mtu_probe(&frag));
        assert!(!is_mtu_probe_ack(&frag));
    }

    #[test]
    fn roundtrip_multi_fragment() {
        let msg: Vec<u8> = (0..3000u32).map(|i| i as u8).collect(); // 3000 B -> 3 frags
        let frags = fragment(MSG_CLIENT_HELLO, &msg);
        assert_eq!(frags.len(), 3);
        for f in &frags {
            assert!(is_fragment(f));
            assert!(f.len() <= FRAG_HDR_LEN + MAX_CHUNK);
        }
        assert_eq!(reassemble_all(&frags), msg);
    }

    #[test]
    fn single_fragment_small_message() {
        let msg = b"hello".to_vec();
        let frags = fragment(MSG_SERVER_HELLO, &msg);
        assert_eq!(frags.len(), 1);
        assert_eq!(reassemble_all(&frags), msg);
    }

    #[test]
    fn out_of_order_and_duplicates() {
        let msg: Vec<u8> = (0..2500u32).map(|i| (i * 7) as u8).collect();
        let frags = fragment(MSG_CLIENT_HELLO, &msg);
        assert_eq!(frags.len(), 3);
        let mut re = Reassembler::new();
        // reversed order + a duplicate in the middle
        assert_eq!(re.push(&frags[2]).unwrap(), None);
        assert_eq!(re.push(&frags[0]).unwrap(), None);
        assert_eq!(re.push(&frags[0]).unwrap(), None); // duplicate ignored
        let done = re.push(&frags[1]).unwrap();
        assert_eq!(done.as_deref(), Some(msg.as_slice()));
    }

    #[test]
    fn rejects_non_fragment_and_inconsistent() {
        let mut re = Reassembler::new();
        assert!(re.push(&[0x16, 0x03, 0x03, 0, 0, 0]).is_err()); // looks like TLS, no magic
                                                                 // inconsistent count between two fragments of the "same" stream
        let a = fragment(MSG_CLIENT_HELLO, &vec![1u8; 2500]); // count=3
        let b = fragment(MSG_CLIENT_HELLO, &vec![2u8; 1500]); // count=2
        let mut re2 = Reassembler::new();
        assert_eq!(re2.push(&a[0]).unwrap(), None);
        assert!(re2.push(&b[1]).is_err()); // count changed 3 -> 2
    }

    #[test]
    fn rejects_oversize_chunk() {
        // Hand-build a single fragment whose chunk exceeds MAX_CHUNK.
        let mut frag = Vec::new();
        frag.extend_from_slice(&FRAG_MAGIC);
        frag.push(MSG_CLIENT_HELLO);
        frag.push(0); // idx
        frag.push(1); // count
        frag.extend_from_slice(&vec![0u8; MAX_CHUNK + 1]);
        let mut re = Reassembler::new();
        assert!(re.push(&frag).is_err());
    }

    #[test]
    fn is_fragment_distinguishes_tls() {
        assert!(!is_fragment(&[0x16, 0x03, 0x03, 0x01, 0x00, 0x00])); // TLS ClientHello opener
        assert!(is_fragment(&fragment(MSG_CLIENT_HELLO, b"x")[0]));
        assert!(!is_fragment(&[])); // too short
    }

    #[test]
    fn junk_is_recognized_and_distinct_from_real_messages() {
        let j = junk_datagram(50);
        assert!(is_junk(&j)); // recognized as junk
        assert!(is_fragment(&j)); // shares the fragment envelope (rides the same mask)
        assert_eq!(j.len(), FRAG_HDR_LEN + 50);
        assert_eq!(j[3], MSG_JUNK);
        // a real ClientHello / ServerHello fragment is NOT junk
        assert!(!is_junk(&fragment(MSG_CLIENT_HELLO, b"x")[0]));
        assert!(!is_junk(&fragment(MSG_SERVER_HELLO, b"x")[0]));
        // non-fragment garbage is not junk
        assert!(!is_junk(&[0x16, 0x03, 0x03, 0, 0, 0]));
        assert!(!is_junk(&[]));
        // the reassembler would treat a junk datagram as a complete 1-fragment message
        // (it is dropped BEFORE reaching the reassembler in the server path, but assert
        // it doesn't error if it ever did):
        assert!(Reassembler::new().push(&j).unwrap().is_some());
    }
}
