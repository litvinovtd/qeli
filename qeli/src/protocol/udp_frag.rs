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

/// True if `d` (a datagram payload, after obfs/QUIC unwrap) is a qeli handshake
/// fragment. Lets a backward-compatible peer tell fragments from a legacy single
/// datagram (a TLS record, which starts `0x16 0x03`).
#[inline]
pub fn is_fragment(d: &[u8]) -> bool {
    d.len() >= FRAG_HDR_LEN && d[..FRAG_MAGIC.len()] == FRAG_MAGIC
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
    fn is_fragment_distinguishes_tls() {
        assert!(!is_fragment(&[0x16, 0x03, 0x03, 0x01, 0x00, 0x00])); // TLS ClientHello opener
        assert!(is_fragment(&fragment(MSG_CLIENT_HELLO, b"x")[0]));
        assert!(!is_fragment(&[])); // too short
    }
}
