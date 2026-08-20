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
//! peer.
//!
//! Three messages are fragmented, and the third only sometimes. The ClientHello and the
//! ServerHello always are — they are always too big. The **AuthOK** ([`MSG_AUTH_OK`]) is
//! fragmented only when it exceeds [`MAX_CHUNK`], which happens when the profile pushes
//! enough routes; below that it goes out as the single unframed datagram it always was, and
//! that boundary is what keeps peers predating `MSG_AUTH_OK` working. The client's AUTH is
//! never fragmented — instead the credentials that make up its size are bounded at config
//! load (`config::client::ClientConfig::check_credential_size`).
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
/// IPv6 minimum link MTU (RFC 8200 §5): every path must carry this without
/// fragmenting, so it is the narrowest path we design the handshake to survive.
pub const IPV6_MIN_MTU: usize = 1280;
/// Worst-case outer headers wrapped around one fragment, from the inside out. These
/// are the *emitted* sizes, not protocol minimums — a fragment datagram really does
/// carry all of them at once on an IPv6 + `obfs` + QUIC-mask path.
const OUTER_QUIC: usize = crate::protocol::quic::QUIC_LONG_HEADER_EMITTED;
const OUTER_OBFS_SEAL: usize = crate::protocol::obfs::OBFS_SEAL_OVERHEAD;
const OUTER_UDP: usize = 8;
const OUTER_IPV6: usize = 40;
/// Headroom kept free so that adding one more outer layer (or growing an existing
/// header) does not silently push the handshake back over [`IPV6_MIN_MTU`] — the
/// exact regression [`MAX_CHUNK`] was hard-coded into. `max_chunk_fits_ipv6_min_mtu`
/// fails the build's tests if the budget is ever overspent again.
const OUTER_RESERVE: usize = 32;

/// Max payload bytes per fragment. **Derived**, not chosen: the whole outer datagram
/// (chunk + fragment header + QUIC long-header mask + obfs seal + UDP + IPv6) must fit
/// [`IPV6_MIN_MTU`], so no fragment is ever IP-fragmented on an LTE/CGNAT path.
///
/// This was 1200 — a number borrowed from QUIC's initial-packet floor, which budgets a
/// whole *datagram*, not the payload inside four more layers. The handshake wraps each
/// fragment in a QUIC **long** header (`wrap_quic_long`, 18 B — the data plane's short
/// header is only 9 B), so the real worst case was 1200 + 6 + 18 + 13 + 8 + 40 = 1285:
/// five bytes over the IPv6 minimum, i.e. the PQ handshake could not complete on a
/// 1280-MTU IPv6 path with `obfs` + QUIC masking on.
///
/// This bounds only what we **emit**; [`MAX_CHUNK_ACCEPT`] bounds what we accept. Keeping
/// the two separate is what makes the change compatible in both directions — see there.
/// (Audit 2026-07-30, #14.)
pub const MAX_CHUNK: usize = IPV6_MIN_MTU
    - OUTER_IPV6
    - OUTER_UDP
    - OUTER_OBFS_SEAL
    - OUTER_QUIC
    - OUTER_RESERVE
    - FRAG_HDR_LEN;

/// Largest chunk we **accept**, pinned to the historical 1200 that every build before the
/// #14 fix emitted.
///
/// Reassembly is size-agnostic — fragments are placed by `idx`, with no offset or
/// per-fragment length field — so the only thing a receiver does with a chunk size is bound
/// it from above for anti-DoS. Shrinking [`MAX_CHUNK`] therefore keeps *our* fragments
/// readable by any peer; but had we shrunk the accept bound with it, we would have rejected
/// every fragment from a pre-fix peer and broken the handshake in the other direction. Both
/// bounds must exist for the change to be compatible both ways, and this one must never drop
/// below 1200. It still caps a reassembled message at `MAX_FRAGS * MAX_CHUNK_ACCEPT` ≈ 28 KB,
/// exactly the pre-fix bound.
pub const MAX_CHUNK_ACCEPT: usize = 1200;
/// Hard cap on fragments per message (anti-DoS on the reassembly buffer).
/// `MAX_FRAGS * MAX_CHUNK_ACCEPT` ≈ 28 KB, far above any real handshake (~2 KB / 2 fragments).
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
/// (echoed) before the reassembler, so its oversized "chunk" never hits [`MAX_CHUNK_ACCEPT`].
pub const MSG_MTU_PROBE: u8 = 4;
/// Path-MTU probe **ACK** (server→client): a tiny datagram echoing the probe's
/// `[id(2 LE)][outer_size(2 LE)]`, confirming the big probe arrived intact.
pub const MSG_MTU_PROBE_ACK: u8 = 5;
/// The **AuthOK** (server→client), fragmented for the same reason as the ServerHello.
///
/// Unlike the two handshake messages, this one has no fixed size: it carries the pushed
/// route list, so a profile pushing enough routes puts it past what a fragment-dropping path
/// (mobile, CGNAT) will carry. The failure was indistinguishable from a dead server — the
/// client retransmits AUTH, the network eats the reply every time, and it times out at the
/// AUTHENTICATION step with nothing in either log. (Audit 2026-08-02, §4.)
///
/// Two things make adding this SAFE on a wire that already has deployed clients:
///
/// 1. **The server fragments only when the message exceeds [`MAX_CHUNK`].** At or below it,
///    the AuthOK goes out as the single datagram it always was, byte for byte. So a client
///    that does not know this id sees no change in any case that works today; the only case
///    where it sees fragments is the case where the network was already destroying its
///    unfragmented reply.
/// 2. **The payload is the finished AEAD record, not plaintext.** Fragmentation happens
///    strictly below the session cipher and above the QUIC mask — same layering as the
///    ServerHello — so nothing about the crypto, the transcript or the replay window moves.
///
/// There is no ambiguity against a real record, in either framing: TLS framing opens
/// `0x17 0x03 0x03`, and raw framing opens with a u16 payload length bounded by
/// [`crate::protocol::packet::MAX_RECORD_SIZE`] (0x4124), so its high byte is at most 0x41 —
/// `0xF0` is unreachable both ways. That is the same property [`is_fragment`] already relies
/// on to tell a fragmented ClientHello from a legacy single-datagram one.
///
/// Receivers still test for this id only where an AuthOK is actually expected. Not for
/// safety — the paragraph above is what makes it safe — but because nothing else should ever
/// produce one, so a narrow check is a narrow surface.
pub const MSG_AUTH_OK: u8 = 6;

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

/// Parse a client-to-server path-MTU probe only when its complete wire shape is valid.
///
/// The size field is a claim about this payload before QUIC/obfs wrapping. Echoing it from a
/// short packet would let a spoofed source obtain an ACK for a size that never crossed the
/// server ingress path. The generic [`parse_mtu_probe`] remains deliberately length-agnostic
/// because a probe ACK is tiny while echoing the original (large) probe size.
pub fn parse_mtu_probe_request(d: &[u8]) -> Option<(u16, u16)> {
    if !is_mtu_probe(d) || d[4] != 0 || d[5] != 1 {
        return None;
    }
    let parsed = parse_mtu_probe(d)?;
    (usize::from(parsed.1) == d.len()).then_some(parsed)
}

/// Parse the fixed-size server-to-client ACK form. Trailing bytes and fragment-like
/// `idx/count` values are rejected so the PMTU state machine accepts one unambiguous shape.
pub fn parse_mtu_probe_ack(d: &[u8]) -> Option<(u16, u16)> {
    if !is_mtu_probe_ack(d) || d.len() != FRAG_HDR_LEN + PROBE_BODY_LEN || d[4] != 0 || d[5] != 1 {
        return None;
    }
    parse_mtu_probe(d)
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

/// True if `d` (after obfs/QUIC unwrap) is a fragment of the AuthOK ([`MSG_AUTH_OK`]).
#[inline]
pub fn is_auth_ok_fragment(d: &[u8]) -> bool {
    is_fragment(d) && d[3] == MSG_AUTH_OK
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
///
/// Fails if the message needs more than [`MAX_FRAGS`] fragments: the receiver rejects
/// any `count > MAX_FRAGS`, and the on-wire idx/count are single bytes, so an oversize
/// message would otherwise pack "successfully" here and then fail at the peer as a
/// mysterious handshake hang (or, past 255 fragments, silently misassemble). Failing
/// loudly at the source turns a future too-large handshake (bigger cert / new
/// extensions) into a clear error instead. (Was a `debug_assert`, compiled out of the
/// release build.)
pub fn fragment(msg_id: u8, msg: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let count = msg.len().div_ceil(MAX_CHUNK).max(1);
    if count > MAX_FRAGS as usize {
        return Err("handshake message too large to fragment (exceeds MAX_FRAGS * MAX_CHUNK)");
    }
    Ok((0..count)
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
        .collect())
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
        // MAX_FRAGS*MAX_CHUNK_ACCEPT). Deliberately the ACCEPT bound, not the send
        // budget: a peer built before the #14 budget fix emits 1200-byte chunks, and
        // bounding by our smaller MAX_CHUNK would reject every one of its handshakes.
        if chunk.len() > MAX_CHUNK_ACCEPT {
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
        match slot {
            Some(existing) if existing.as_slice() != chunk => {
                return Err("conflicting duplicate fragment");
            }
            Some(_) => {} // A byte-identical retransmission is idempotent.
            None => {
                *slot = Some(chunk.to_vec());
                self.have += 1;
            }
        }
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

    /// The Rust half of the SHARED UDP-fragmentation KAT (`conformance/udp-frag.json`).
    ///
    /// The reassembler is fed by the NETWORK — out of order, with duplicates, with gaps, and
    /// with whatever an attacker sends — so the malformed cases matter as much as the happy
    /// ones. A handshake that only hangs on LTE is the failure this pins against.
    #[test]
    fn udp_frag_matches_shared_conformance_vectors() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex in fixture"))
                .collect()
        }
        fn hexs(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        let fx: serde_json::Value =
            serde_json::from_str(include_str!("../../../conformance/udp-frag.json"))
                .expect("conformance/udp-frag.json is not valid JSON");
        assert!(
            fx["platforms"]
                .as_array()
                .expect("fixture has no `platforms`")
                .iter()
                .any(|p| p.as_str() == Some("rust")),
            "rust is not listed in `platforms` of udp-frag.json"
        );
        assert_eq!(
            fx["max_chunk"].as_u64(),
            Some(MAX_CHUNK as u64),
            "the fixture was generated for a different MAX_CHUNK than this build uses"
        );
        assert_eq!(
            fx["max_chunk_accept"].as_u64(),
            Some(MAX_CHUNK_ACCEPT as u64),
            "the fixture pins a different MAX_CHUNK_ACCEPT than this build uses — a port that \
             bounds RECEIVE by the send budget rejects every pre-#14 peer"
        );
        assert_eq!(
            fx["max_frags"].as_u64(),
            Some(MAX_FRAGS as u64),
            "the fixture was generated for a different MAX_FRAGS than this build uses"
        );
        assert_eq!(
            fx["msg_auth_ok"].as_u64(),
            Some(MSG_AUTH_OK as u64),
            "the AuthOK message id must be identical in all four ports — a port using a \
             different number silently fails to reassemble a large AuthOK, which looks like a \
             dead server rather than a version mismatch"
        );

        // ── fragment ────────────────────────────────────────────────────────────
        for c in fx["fragment"].as_array().expect("no `fragment` section") {
            let name = c["name"].as_str().unwrap_or("<unnamed>");
            let msg_id = c["msg_id"].as_u64().unwrap() as u8;
            let expect = &c["expect"];

            if expect["reject"].as_bool() == Some(true) {
                // The oversize body is megabytes, so the fixture records its SHAPE.
                let len = c["message_len"].as_u64().unwrap() as usize;
                let msg: Vec<u8> = (0..len).map(|i| ((i * 31 + 7) % 256) as u8).collect();
                assert!(
                    fragment(msg_id, &msg).is_err(),
                    "case {name}: an oversize message was fragmented instead of refused"
                );
            } else {
                let msg = unhex(c["message"].as_str().unwrap());
                let got = fragment(msg_id, &msg)
                    .unwrap_or_else(|e| panic!("case {name}: refused a valid message: {e}"));
                let want: Vec<String> = expect["fragments"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| f.as_str().unwrap().to_string())
                    .collect();
                assert_eq!(
                    got.iter().map(|f| hexs(f)).collect::<Vec<_>>(),
                    want,
                    "case {name}: fragments disagree"
                );
            }
        }

        // ── reassemble ──────────────────────────────────────────────────────────
        for c in fx["reassemble"]
            .as_array()
            .expect("no `reassemble` section")
        {
            let name = c["name"].as_str().unwrap_or("<unnamed>");
            let expect = &c["expect"];

            // A FRESH reassembler per case.
            let mut r = Reassembler::new();
            let mut completed: Option<Vec<u8>> = None;
            let mut rejected = false;
            for d in c["feed"].as_array().unwrap() {
                match r.push(&unhex(d.as_str().unwrap())) {
                    Ok(Some(m)) => {
                        completed = Some(m);
                        break;
                    }
                    Ok(None) => {}
                    Err(_) => {
                        rejected = true;
                        break;
                    }
                }
            }

            if expect["reject"].as_bool() == Some(true) {
                assert!(rejected, "case {name}: a malformed fragment was ACCEPTED");
            } else if expect["incomplete"].as_bool() == Some(true) {
                assert!(
                    !rejected,
                    "case {name}: an incomplete message was rejected outright"
                );
                assert!(
                    completed.is_none(),
                    "case {name}: completed a message that is missing a fragment"
                );
            } else {
                let m = completed.unwrap_or_else(|| {
                    panic!("case {name}: never completed (rejected={rejected})")
                });
                assert_eq!(
                    hexs(&m),
                    expect["message"].as_str().unwrap(),
                    "case {name}: reassembled message disagrees"
                );
            }
        }

        // ── classify ────────────────────────────────────────────────────────────
        for c in fx["classify"].as_array().expect("no `classify` section") {
            let name = c["name"].as_str().unwrap_or("<unnamed>");
            let d = unhex(c["datagram"].as_str().unwrap());
            let e = &c["expect"];
            assert_eq!(
                is_fragment(&d),
                e["is_fragment"].as_bool().unwrap(),
                "case {name}: is_fragment"
            );
            assert_eq!(
                is_junk(&d),
                e["is_junk"].as_bool().unwrap(),
                "case {name}: is_junk"
            );
            assert_eq!(
                is_mtu_probe(&d),
                e["is_mtu_probe"].as_bool().unwrap(),
                "case {name}: is_mtu_probe"
            );
            assert_eq!(
                is_mtu_probe_ack(&d),
                e["is_mtu_probe_ack"].as_bool().unwrap(),
                "case {name}: is_mtu_probe_ack"
            );
            assert_eq!(
                is_auth_ok_fragment(&d),
                e["is_auth_ok"].as_bool().unwrap(),
                "case {name}: is_auth_ok_fragment"
            );
        }
    }

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
        assert_eq!(parse_mtu_probe_request(&d), Some((0xBEEF, 1400)));
        assert_eq!(parse_mtu_probe_ack(&d), None);

        // Server echo: tiny, carries the same id/size.
        let ack = mtu_probe_ack_datagram(0xBEEF, 1400);
        assert!(is_mtu_probe_ack(&ack));
        assert!(!is_mtu_probe(&ack));
        assert_eq!(parse_mtu_probe(&ack), Some((0xBEEF, 1400)));
        assert_eq!(parse_mtu_probe_ack(&ack), Some((0xBEEF, 1400)));
        assert_eq!(parse_mtu_probe_request(&ack), None);
        assert!(
            ack.len() < 32,
            "the ACK is small — only the big probe tests the path"
        );
    }

    #[test]
    fn mtu_probe_parsers_reject_false_size_and_ambiguous_shapes() {
        let mut short_claim = mtu_probe_datagram(7, 1200).unwrap();
        short_claim.truncate(FRAG_HDR_LEN + PROBE_BODY_LEN);
        assert_eq!(parse_mtu_probe(&short_claim), Some((7, 1200)));
        assert_eq!(parse_mtu_probe_request(&short_claim), None);

        let mut multi = mtu_probe_datagram(8, 1200).unwrap();
        multi[5] = 2;
        assert_eq!(parse_mtu_probe_request(&multi), None);

        let mut ack_with_trailing = mtu_probe_ack_datagram(9, 1200);
        ack_with_trailing.push(0);
        assert_eq!(parse_mtu_probe_ack(&ack_with_trailing), None);
        let mut fragmented_ack = mtu_probe_ack_datagram(10, 1200);
        fragmented_ack[4] = 1;
        fragmented_ack[5] = 2;
        assert_eq!(parse_mtu_probe_ack(&fragmented_ack), None);
    }

    #[test]
    fn mtu_probe_rejects_too_small_and_not_confused_with_fragment() {
        // Smaller than header+body → cannot build.
        assert!(mtu_probe_datagram(1, FRAG_HDR_LEN + PROBE_BODY_LEN - 1).is_none());
        // A real handshake fragment is NOT a probe.
        let frag = fragment(MSG_CLIENT_HELLO, b"hello").unwrap()[0].clone();
        assert!(!is_mtu_probe(&frag));
        assert!(!is_mtu_probe_ack(&frag));
    }

    #[test]
    fn roundtrip_multi_fragment() {
        let msg: Vec<u8> = (0..3000u32).map(|i| i as u8).collect(); // 3000 B -> 3 frags
        let frags = fragment(MSG_CLIENT_HELLO, &msg).unwrap();
        assert_eq!(frags.len(), 3);
        for f in &frags {
            assert!(is_fragment(f));
            assert!(f.len() <= FRAG_HDR_LEN + MAX_CHUNK);
        }
        assert_eq!(reassemble_all(&frags), msg);
    }

    #[test]
    fn fragment_rejects_oversize_message() {
        // Exactly MAX_FRAGS chunks is the largest packable message; one byte more needs
        // MAX_FRAGS+1 fragments, which the receiver would reject — so the sender must fail
        // loudly here instead of emitting a count the peer drops.
        let ok = vec![0u8; MAX_FRAGS as usize * MAX_CHUNK];
        assert!(fragment(MSG_CLIENT_HELLO, &ok).is_ok());
        assert_eq!(
            fragment(MSG_CLIENT_HELLO, &ok).unwrap().len(),
            MAX_FRAGS as usize
        );
        let too_big = vec![0u8; MAX_FRAGS as usize * MAX_CHUNK + 1];
        assert!(fragment(MSG_CLIENT_HELLO, &too_big).is_err());
    }

    /// The budget that [`MAX_CHUNK`] is derived from, asserted end to end against the
    /// real emitted header sizes — so growing any outer layer fails here rather than
    /// silently black-holing the PQ handshake on a 1280-MTU IPv6 path.
    #[test]
    fn max_chunk_fits_ipv6_min_mtu() {
        // Worst case, inside out: chunk -> fragment header -> QUIC long header (the
        // handshake path uses wrap_quic_long, NOT the 9-byte short header) -> obfs
        // datagram seal -> UDP -> IPv6.
        let outer =
            MAX_CHUNK + FRAG_HDR_LEN + OUTER_QUIC + OUTER_OBFS_SEAL + OUTER_UDP + OUTER_IPV6;
        assert!(
            outer <= IPV6_MIN_MTU,
            "fragment datagram is {outer} B, over the {IPV6_MIN_MTU} B IPv6 minimum MTU"
        );
        assert_eq!(outer + OUTER_RESERVE, IPV6_MIN_MTU, "reserve fully spent");

        // The regression this replaced: 1200 was over budget by 5 bytes. Kept as a
        // literal so re-introducing that value cannot pass silently.
        let old = 1200 + FRAG_HDR_LEN + OUTER_QUIC + OUTER_OBFS_SEAL + OUTER_UDP + OUTER_IPV6;
        assert_eq!(old, 1285);
        assert!(old > IPV6_MIN_MTU);
        // Compile-time, not run-time: raising MAX_CHUNK back above the legacy 1200 would make
        // every pre-#14 peer reject our fragments, so it must fail the BUILD.
        const { assert!(MAX_CHUNK < 1200, "MAX_CHUNK must shrink, never grow") };
    }

    /// Both directions of the #14 rollout must interoperate, because the send budget and
    /// the accept bound are now different numbers.
    #[test]
    fn smaller_chunks_stay_wire_compatible() {
        // Us -> pre-fix peer: every chunk we emit fits the 1200-byte bound it enforced.
        let msg: Vec<u8> = (0..2100u32).map(|i| (i * 11) as u8).collect();
        let frags = fragment(MSG_SERVER_HELLO, &msg).unwrap();
        assert!(frags.len() >= 2);
        for f in &frags {
            assert!(f.len() - FRAG_HDR_LEN <= MAX_CHUNK_ACCEPT);
        }
        assert_eq!(reassemble_all(&frags), msg);

        // Pre-fix peer -> us: it slices at 1200, which is ABOVE our send budget. Bounding
        // by MAX_CHUNK here would reject it and break every legacy handshake.
        const { assert!(MAX_CHUNK_ACCEPT > MAX_CHUNK) };
        let legacy: Vec<Vec<u8>> = (0..2u8)
            .map(|idx| {
                let mut d = Vec::with_capacity(FRAG_HDR_LEN + 1200);
                d.extend_from_slice(&FRAG_MAGIC);
                d.extend_from_slice(&[MSG_SERVER_HELLO, idx, 2]);
                d.extend(std::iter::repeat_n(b'L', 1200));
                d
            })
            .collect();
        let mut re = Reassembler::new();
        assert!(
            re.push(&legacy[0]).is_ok(),
            "legacy 1200-byte chunk rejected"
        );
        let done = re
            .push(&legacy[1])
            .expect("legacy second fragment rejected");
        assert_eq!(done.expect("message must complete").len(), 2400);

        // The anti-DoS bound still bites one byte above the legacy size.
        let mut over = Vec::new();
        over.extend_from_slice(&FRAG_MAGIC);
        over.extend_from_slice(&[MSG_SERVER_HELLO, 0, 1]);
        over.extend(std::iter::repeat_n(0u8, MAX_CHUNK_ACCEPT + 1));
        assert!(Reassembler::new().push(&over).is_err());
    }

    #[test]
    fn single_fragment_small_message() {
        let msg = b"hello".to_vec();
        let frags = fragment(MSG_SERVER_HELLO, &msg).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(reassemble_all(&frags), msg);
    }

    #[test]
    fn out_of_order_and_duplicates() {
        let msg: Vec<u8> = (0..2500u32).map(|i| (i * 7) as u8).collect();
        let frags = fragment(MSG_CLIENT_HELLO, &msg).unwrap();
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
        let a = fragment(MSG_CLIENT_HELLO, &vec![1u8; 2500]).unwrap(); // count=3
        let b = fragment(MSG_CLIENT_HELLO, &vec![2u8; 1500]).unwrap(); // count=2
        let mut re2 = Reassembler::new();
        assert_eq!(re2.push(&a[0]).unwrap(), None);
        assert!(re2.push(&b[1]).is_err()); // count changed 3 -> 2
    }

    #[test]
    fn rejects_oversize_chunk() {
        // Hand-build a single fragment whose chunk exceeds the ACCEPT bound. Deliberately
        // MAX_CHUNK_ACCEPT, not MAX_CHUNK: a chunk between the two is what a pre-#14 peer
        // legitimately sends, so rejecting there would break every legacy handshake — the
        // case `smaller_chunks_stay_wire_compatible` pins from the other side.
        let build = |chunk_len: usize| {
            let mut frag = Vec::with_capacity(FRAG_HDR_LEN + chunk_len);
            frag.extend_from_slice(&FRAG_MAGIC);
            frag.push(MSG_CLIENT_HELLO);
            frag.push(0); // idx
            frag.push(1); // count
            frag.extend(std::iter::repeat_n(0u8, chunk_len));
            frag
        };
        assert!(Reassembler::new()
            .push(&build(MAX_CHUNK_ACCEPT + 1))
            .is_err());
        // Exactly at the bound is still accepted (and completes, count = 1).
        assert!(Reassembler::new().push(&build(MAX_CHUNK_ACCEPT)).is_ok());
    }

    #[test]
    fn is_fragment_distinguishes_tls() {
        assert!(!is_fragment(&[0x16, 0x03, 0x03, 0x01, 0x00, 0x00])); // TLS ClientHello opener
        assert!(is_fragment(&fragment(MSG_CLIENT_HELLO, b"x").unwrap()[0]));
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
        assert!(!is_junk(&fragment(MSG_CLIENT_HELLO, b"x").unwrap()[0]));
        assert!(!is_junk(&fragment(MSG_SERVER_HELLO, b"x").unwrap()[0]));
        // non-fragment garbage is not junk
        assert!(!is_junk(&[0x16, 0x03, 0x03, 0, 0, 0]));
        assert!(!is_junk(&[]));
        // the reassembler would treat a junk datagram as a complete 1-fragment message
        // (it is dropped BEFORE reaching the reassembler in the server path, but assert
        // it doesn't error if it ever did):
        assert!(Reassembler::new().push(&j).unwrap().is_some());
    }
}
