//! Generator for the shared cross-language KAT fixtures under `conformance/`.
//!
//! WHY THIS EXISTS: the production transport is now the shared Rust core, but retained C#
//! and Swift wire primitives still consume these fixtures for compatibility and regression
//! coverage. Before the unification, every shared primitive was another chance to disagree,
//! and the failure mode was silent — M6 (the counter-derived data-plane nonce) shipped
//! inconsistently for a whole release because nothing compared the implementations.
//! Each fixture's `platforms` list identifies the implementations required to consume it.
//!
//! The vectors are PRODUCED BY THE CANON, never hand-written: a hand-computed vector only
//! proves that the author and the code agree on the same mistake.
//!
//! Usage:
//!   cargo run --features conformance-gen --bin gen-conformance            # write the files
//!   cargo run --features conformance-gen --bin gen-conformance -- --check # CI: fail on drift
//!
//! `--check` regenerates in memory and compares against what is on disk, so a fixture can
//! never quietly drift away from the implementation it is supposed to pin.
//!
//! NB: lives at `src/gen_conformance_main.rs`, NOT `src/bin/` — `.gitignore` carries
//! `**/bin/`, which would silently keep this file out of git (same reason as
//! `src/client_main.rs`).

use std::path::{Path, PathBuf};

/// Repo-root-relative output directory for every fixture.
const OUT_DIR: &str = "conformance";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One PRP-nonce case. `raw` pins the seed‖counter_be layout, `nonce` the permutation —
/// so a port that gets either half wrong fails on the exact step it got wrong.
struct PrpCase {
    name: &'static str,
    why: &'static str,
    key: [u8; 32],
    seed: [u8; 4],
    counter: u64,
}

fn prp_cases() -> Vec<PrpCase> {
    let key_counting = {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    };
    vec![
        PrpCase {
            name: "counter-zero",
            why: "First packet of a session — the counter every implementation starts at.",
            key: key_counting,
            seed: [0xAA, 0xBB, 0xCC, 0xDD],
            counter: 0,
        },
        PrpCase {
            name: "counter-one",
            why: "Second packet: together with counter-zero this pins that consecutive \
                  counters do NOT produce consecutive nonces (the DPI tell M6 removes).",
            key: key_counting,
            seed: [0xAA, 0xBB, 0xCC, 0xDD],
            counter: 1,
        },
        PrpCase {
            name: "counter-two",
            why: "Third packet — catches an off-by-one in the Feistel round loop that \
                  happens to be identity for 0 and 1.",
            key: key_counting,
            seed: [0xAA, 0xBB, 0xCC, 0xDD],
            counter: 2,
        },
        PrpCase {
            name: "counter-mid-range",
            why: "A counter with bytes set across the whole 8-byte field — catches a port \
                  that only shifts the low 32 bits (a real hazard in languages where the \
                  counter is a 32-bit int by default).",
            key: key_counting,
            seed: [0xAA, 0xBB, 0xCC, 0xDD],
            counter: 1_234_567_890,
        },
        PrpCase {
            name: "counter-i64-max",
            why: "0x7FFFFFFFFFFFFFFF — the largest counter representable in the SIGNED 64-bit \
                  integer that Kotlin/C#/Swift use for it. Catches sign-extension bugs in the \
                  big-endian encoding.",
            key: key_counting,
            seed: [0xAA, 0xBB, 0xCC, 0xDD],
            counter: i64::MAX as u64,
        },
        PrpCase {
            name: "different-key-and-seed",
            why: "All-0xFF key with an all-zero seed: proves the output actually depends on \
                  BOTH the PRP key and the seed, so a port that ignores one of them fails \
                  here even though every case above passes.",
            key: [0xFF; 32],
            seed: [0x00; 4],
            counter: 0,
        },
    ]
}

/// Build `conformance/prp-nonce.json`.
///
/// Assembled as text rather than through `serde_json::to_string_pretty` so the key order,
/// the comment block and the one-case-per-line layout stay exactly as intended (serde's
/// map is a BTreeMap and would sort the keys alphabetically). Every value written here is
/// a hex string or a plain integer, so there is nothing to escape.
fn build_prp_nonce() -> String {
    let mut s = String::new();
    s.push_str(
        r#"{
  "_comment": [
    "CONFORMANCE FIXTURES for the data-plane nonce (M6) — the source of truth for the Rust",
    "transport core and the retained C#/desktop and Swift/iOS primitives.",
    "",
    "GENERATED FILE. Do not edit by hand: regenerate with",
    "  cargo run --features conformance-gen --bin gen-conformance",
    "from the qeli/ directory. The vectors come from the Rust canon (protocol/packet.rs",
    "prp_nonce); a hand-written vector only proves that the author and the code agree on",
    "the same mistake.",
    "",
    "WHY: the nonce is derived as PRP(seed(4) || counter_be(8)) — a 4-round balanced Feistel",
    "network, round function SHA256(key || round || half)[..6]. The network is bijective for",
    "ANY round function, so distinct (seed,counter) inputs — the counter is monotonic — can",
    "never collide, which is what removes the birthday risk of a random 96-bit nonce. It also",
    "destroys the visible '+1 per packet' pattern a DPI box could key on.",
    "",
    "THIS FILE EXISTS BECAUSE THE FIX WAS MISSED ONCE: M6 landed in Rust, C# and Swift, but",
    "Android kept generating a random nonce for a full release. Nothing caught it — there was",
    "no PacketCodec test on Android at all, and the only cross-language fixture",
    "(qeli-links.json) covers link parsing, not the wire codec.",
    "",
    "ONE-SIDED TRANSFORM: the nonce travels on the wire and the receiver never inverts the",
    "PRP (it reads the nonce straight off the record), so the PRP key does NOT have to match",
    "the peer's. Rust derives it from the AEAD key; retained C# and Swift use per-instance",
    "randomness. Both are correct precisely because the transform is one-sided — these vectors",
    "pin the FUNCTION, with the key supplied as an explicit input.",
    "",
    "HOW TO USE: feed `key` and `raw` to your prp-nonce function and assert it returns",
    "`nonce`. Also build `raw` yourself from `seed` and `counter` and assert it matches, so",
    "the seed||counter_be layout is pinned too — a port can be right about the permutation",
    "and wrong about what it permutes.",
    "",
    "`platforms` lists the implementations REQUIRED to pass this file. A platform on that",
    "list whose test skips the file must fail, not pass quietly — a green test that verified",
    "nothing is the exact failure this fixture is here to prevent."
  ],
  "primitive": "prp-nonce",
  "generator": "qeli/src/gen_conformance_main.rs",
  "platforms": ["rust", "csharp", "swift"],
  "cases": [
"#,
    );

    let cases = prp_cases();
    for (i, c) in cases.iter().enumerate() {
        let mut raw = [0u8; qeli::protocol::packet::NONCE_SIZE];
        raw[..4].copy_from_slice(&c.seed);
        raw[4..].copy_from_slice(&c.counter.to_be_bytes());
        let nonce = qeli::protocol::packet::conformance_prp_nonce(&c.key, &raw);

        // `why` is written with escaped newlines collapsed — the Rust string literals above
        // wrap for readability, JSON keeps them on one line.
        let why = c.why.split_whitespace().collect::<Vec<_>>().join(" ");
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", c.name));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"key\": \"{}\",\n", hex(&c.key)));
        s.push_str(&format!("      \"seed\": \"{}\",\n", hex(&c.seed)));
        s.push_str(&format!("      \"counter\": {},\n", c.counter));
        s.push_str(&format!("      \"raw\": \"{}\",\n", hex(&raw)));
        s.push_str(&format!("      \"nonce\": \"{}\"\n", hex(&nonce)));
        s.push_str(if i + 1 == cases.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ]\n}\n");
    s
}

/// Build `conformance/packet-decode.json`.
///
/// DECODING is deterministic by construction — given a key and a record, the plaintext is
/// fixed — so this file pins the whole inbound path (framing, AEAD, counter placement,
/// padding-trailer stripping) across the three retained primitives with no test seam: they
/// only need their existing public `decrypt`.
///
/// The records are produced by the REAL encode path (`encrypt_packet`) through a codec with
/// its randomness pinned, not re-assembled here — a generator that built the bytes itself
/// would pin its own idea of the format instead of the codec's.
fn build_packet_decode() -> String {
    use qeli::protocol::packet::conformance_codec;

    let key = {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        k
    };
    let seed = [0x11u8, 0x22, 0x33, 0x44];
    let prp_key = [0x5Au8; 32];

    // (name, why, framing_raw, plaintext, padding, expect_reject, mutate)
    struct Case {
        name: &'static str,
        why: &'static str,
        raw_framing: bool,
        plaintext: Vec<u8>,
        padding: Vec<u8>,
        /// Corrupt the finished record before writing it, to build a negative case.
        mutate: Option<fn(&mut Vec<u8>)>,
    }

    let cases = [
        Case {
            name: "tls-simple",
            why: "The ordinary case: a TLS-framed record carrying a short payload and no padding.",
            raw_framing: false,
            plaintext: b"hello qeli".to_vec(),
            padding: vec![],
            mutate: None,
        },
        Case {
            name: "reject-trailing-bytes",
            why: "A valid authenticated record followed by bytes outside its declared Length \
                  must be rejected; otherwise a datagram has an unauthenticated, malleable tail.",
            raw_framing: false,
            plaintext: b"hello qeli".to_vec(),
            padding: vec![],
            mutate: Some(|r: &mut Vec<u8>| r.extend_from_slice(&[0xAA, 0xBB])),
        },
        Case {
            name: "tls-with-padding",
            why: "Padding is stripped using the 2-byte trailer, not the record length — a \
                  decoder that trusts the length returns the padding as payload.",
            raw_framing: false,
            plaintext: b"payload".to_vec(),
            padding: vec![0xAB; 17],
            mutate: None,
        },
        Case {
            name: "tls-empty-plaintext",
            why: "An empty payload is the heartbeat / idle-cover record. Every client must \
                  decode it and then DROP it rather than injecting a 0-byte packet into the TUN.",
            raw_framing: false,
            plaintext: vec![],
            padding: vec![0x00; 8],
            mutate: None,
        },
        Case {
            name: "raw-framing",
            why: "The `plain` wire mode: a bare 2-byte length prefix instead of the 5-byte TLS \
                  header. A decoder with the header size hardcoded to 5 fails only here.",
            raw_framing: true,
            plaintext: b"raw mode".to_vec(),
            padding: vec![],
            mutate: None,
        },
        Case {
            name: "reject-corrupt-tag",
            why: "Last byte of the Poly1305 tag flipped: authentication must FAIL. A decoder \
                  that ignores the tag would happily return garbage plaintext.",
            raw_framing: false,
            plaintext: b"authenticate me".to_vec(),
            padding: vec![],
            mutate: Some(|r: &mut Vec<u8>| {
                let n = r.len();
                r[n - 1] ^= 0x01;
            }),
        },
        Case {
            name: "reject-truncated",
            why: "The record is cut short of its declared length — the decoder must reject it \
                  instead of reading past the buffer or returning a partial packet.",
            raw_framing: false,
            plaintext: b"truncate me please".to_vec(),
            padding: vec![],
            mutate: Some(|r: &mut Vec<u8>| {
                r.truncate(r.len() - 6);
            }),
        },
        Case {
            name: "reject-flipped-ciphertext",
            why: "A byte inside the ciphertext flipped: AEAD must catch it. Together with \
                  reject-corrupt-tag this proves the tag actually covers the payload.",
            raw_framing: false,
            plaintext: b"integrity matters".to_vec(),
            padding: vec![],
            mutate: Some(|r: &mut Vec<u8>| {
                let n = r.len();
                r[n - 20] ^= 0x80;
            }),
        },
    ];

    let mut s = String::new();
    s.push_str(
        r#"{
  "_comment": [
    "CONFORMANCE FIXTURES for decoding a data-plane record — the source of truth for the",
    "Rust transport core and the retained C#/desktop and Swift/iOS codec primitives.",
    "",
    "GENERATED FILE. Do not edit by hand: regenerate with",
    "  cargo run --features conformance-gen --bin gen-conformance",
    "from the qeli/ directory.",
    "",
    "WHY DECODE AND NOT ENCODE: decoding is deterministic by construction — given a key and a",
    "record, the plaintext is fixed. So this file pins the whole inbound path (framing, AEAD,",
    "counter placement, padding-trailer stripping) in every language WITHOUT any test seam:",
    "each client only needs its existing public decrypt entry point. Encoding draws a random",
    "nonce seed and random padding, so pinning it byte-for-byte needs the randomness injected",
    "— a separate fixture, and a separate decision.",
    "",
    "WIRE LAYOUT: [header][nonce(12)][ChaCha20-Poly1305( counter(8) || plaintext || padding ||",
    "pad_len(2) )]. `header` is the 5-byte TLS application-data record header",
    "([0x17 0x03 0x03][u16 len]) for the fake-tls / obfs / reality wire modes, or a bare",
    "[u16 len] (2 bytes) for the `plain` mode — the `framing` field of each case says which.",
    "",
    "HOW TO USE: build your codec with `key`, feed it `record`, and compare. A case with",
    "`expect.plaintext` must decode to exactly those bytes (hex, possibly empty). A case with",
    "`reject: true` MUST be rejected — an implementation that returns any plaintext for it is",
    "broken, and silently so.",
    "",
    "`expect.counter` is the counter carried INSIDE the record. No implementation's decrypt",
    "returns it (they all yield plaintext only), so it is not asserted — it is recorded so a",
    "failing case can be diagnosed without decrypting by hand.",
    "",
    "NOTE ON THE NONCE: the records were produced with the sender's nonce randomness pinned",
    "so the file is reproducible. Decoders do not care — they read the nonce off the wire.",
    "",
    "`platforms` lists the implementations REQUIRED to pass this file. A platform on that",
    "list whose test skips the file must fail, not pass quietly — a green test that verified",
    "nothing is the exact failure this fixture is here to prevent."
  ],
  "primitive": "packet-decode",
  "generator": "qeli/src/gen_conformance_main.rs",
  "platforms": ["rust", "csharp", "swift"],
  "cases": [
"#,
    );

    for (i, c) in cases.iter().enumerate() {
        // A fresh codec per case so the counter is always 0 and each case stands alone.
        let mut codec = conformance_codec(key, seed, prp_key, c.raw_framing);
        let mut record = codec
            .encrypt_packet(&c.plaintext, &c.padding)
            .expect("conformance case must encode");
        let rejects = c.mutate.is_some();
        if let Some(m) = c.mutate {
            m(&mut record);
        }

        let why = c.why.split_whitespace().collect::<Vec<_>>().join(" ");
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", c.name));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"key\": \"{}\",\n", hex(&key)));
        s.push_str(&format!(
            "      \"framing\": \"{}\",\n",
            if c.raw_framing { "raw" } else { "tls" }
        ));
        s.push_str(&format!("      \"record\": \"{}\",\n", hex(&record)));
        if rejects {
            s.push_str("      \"expect\": { \"reject\": true }\n");
        } else {
            s.push_str(&format!(
                "      \"expect\": {{ \"plaintext\": \"{}\", \"counter\": 0 }}\n",
                hex(&c.plaintext)
            ));
        }
        s.push_str(if i + 1 == cases.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ]\n}\n");
    s
}

/// Build `conformance/replay-window.json`.
///
/// The anti-replay window is a pure state machine — no crypto, no I/O — so it pins as a
/// plain table of (sequence numbers in, accept/reject out), with no test seam beyond making
/// the check visible to the test.
fn build_replay_window() -> String {
    use qeli::protocol::packet::conformance_replay_sequence;

    struct Case {
        name: &'static str,
        why: &'static str,
        seqs: Vec<u64>,
    }

    let cases = [
        Case {
            name: "monotonic",
            why: "The ordinary case: strictly increasing sequence numbers are all fresh.",
            seqs: vec![0, 1, 2, 3, 4],
        },
        Case {
            name: "immediate-duplicate",
            why: "The same sequence number twice — the second is a replay and must be rejected.",
            seqs: vec![0, 1, 1, 2],
        },
        Case {
            name: "in-window-reordering",
            why: "UDP reorders as a matter of course. Arrivals BEHIND the highest but inside \
                  the window are fresh and must be accepted — the strict 'must be greater' \
                  check that predates the window dropped every reordered datagram.",
            seqs: vec![0, 5, 3, 4, 1, 2],
        },
        Case {
            name: "reordered-then-replayed",
            why: "A reordered arrival is accepted once and rejected the second time: the \
                  window must RECORD what it accepted, not merely range-check it.",
            seqs: vec![10, 7, 7, 8, 8],
        },
        Case {
            name: "older-than-window",
            why: "2048-packet window: after seq 5000, seq 1000 is 4000 behind and cannot be \
                  proven fresh, so it must be rejected regardless of whether it was ever seen.",
            seqs: vec![0, 5000, 1000, 5001],
        },
        Case {
            name: "window-edge",
            why: "Exactly at the boundary: with the highest at 3000, distance 2047 is still \
                  inside the 2048-wide window and distance 2048 is not. Off-by-one here either \
                  drops legitimate packets or accepts unprovable ones.",
            seqs: vec![3000, 953, 952],
        },
        Case {
            name: "jump-past-window",
            why: "A forward jump larger than the window clears it entirely; afterwards even a \
                  sequence number that was never seen, but is now too old, must be rejected.",
            seqs: vec![0, 1, 2, 100000, 99999, 50],
        },
        Case {
            name: "starts-nonzero",
            why: "The first sequence number seen initialises the window, whatever its value — \
                  a session that resumes mid-stream must not have its first packet rejected.",
            seqs: vec![42, 43, 42],
        },
        Case {
            name: "high-bit-counter-does-not-disable-the-window",
            why: "The counter is UNSIGNED 64-bit. Kotlin and C# stored it in a SIGNED Long/long \
                  and encoded 'not initialised yet' as the value -1, so the first record with \
                  the top bit set (>= 2^63) made the highest-seen value negative and the \
                  'uninitialised' branch fire on EVERY subsequent packet — returning fresh \
                  unconditionally, i.e. the replay window switched off for the rest of the \
                  session. One record from a hostile server was enough. Rust keeps a separate \
                  `initialized` flag and Swift uses UInt64?, so neither was affected; this \
                  vector exists so the ports cannot regress to a sentinel-in-band design. \
                  After the 2^63 record, replaying 1 (and 2^63 itself) MUST be rejected.",
            seqs: vec![1, 2, 1u64 << 63, 1, 1u64 << 63, 2],
        },
        Case {
            name: "unsigned-wraparound-is-a-forward-jump",
            why: "Follows from the same rule: 2^64-1 is the LARGEST counter, not a negative \
                  one. Reached from a low value it is a huge forward jump that clears the \
                  window, so the earlier numbers become unprovable and must be rejected — an \
                  implementation comparing signed would see it as 'older' and take the \
                  opposite branch.",
            seqs: vec![10, u64::MAX, 10, u64::MAX],
        },
    ];

    let mut s = String::new();
    s.push_str(
        r#"{
  "_comment": [
    "CONFORMANCE FIXTURES for the anti-replay window — the source of truth for the Rust",
    "transport core and the retained C#/desktop and Swift/iOS primitives.",
    "",
    "GENERATED FILE. Do not edit by hand: regenerate with",
    "  cargo run --features conformance-gen --bin gen-conformance",
    "from the qeli/ directory.",
    "",
    "WHY: the window is a sliding 2048-bit bitmap (WireGuard-sized), reimplemented from",
    "scratch in three retained primitives with hand-written multi-word shifts. It is pure state — no",
    "crypto, no I/O — so it pins perfectly as a table, and it is exactly the kind of code",
    "where an off-by-one is invisible in normal use: too tight and legitimate reordered UDP",
    "datagrams are dropped (a real past bug — the pre-window check demanded strictly",
    "increasing sequence numbers), too loose and genuine replays are accepted.",
    "",
    "HOW TO USE: feed `seqs` one at a time to a FRESH window and collect the accept/reject",
    "verdicts; they must equal `verdicts` element for element. The window must RECORD every",
    "acceptance — several cases replay a number that was already accepted out of order, which",
    "a range-check-only implementation gets wrong.",
    "",
    "`platforms` lists the implementations REQUIRED to pass this file. A platform on that",
    "list whose test skips the file must fail, not pass quietly — a green test that verified",
    "nothing is the exact failure this fixture is here to prevent."
  ],
  "primitive": "replay-window",
  "generator": "qeli/src/gen_conformance_main.rs",
  "window_size": 2048,
  "platforms": ["rust", "csharp", "swift"],
  "cases": [
"#,
    );

    for (i, c) in cases.iter().enumerate() {
        let verdicts = conformance_replay_sequence(&c.seqs);
        let why = c.why.split_whitespace().collect::<Vec<_>>().join(" ");
        let seqs = c
            .seqs
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let vs = verdicts
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", c.name));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"seqs\": [{seqs}],\n"));
        s.push_str(&format!("      \"verdicts\": [{vs}]\n"));
        s.push_str(if i + 1 == cases.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ]\n}\n");
    s
}

/// Build `conformance/hkdf.json` — the four directional key-derivation schemes.
///
/// Pure functions of their inputs, and the highest-stakes primitive in the set: the two
/// sides must derive byte-identical keys or the tunnel simply does not come up (and a
/// subtler divergence — say the two directions swapped — produces a tunnel that
/// authenticates and then decrypts nothing).
fn build_hkdf() -> String {
    use qeli::crypto::derive::{
        derive_keys, derive_keys_bound, derive_keys_hybrid, derive_keys_hybrid_bound,
    };

    // Distinct, non-symmetric inputs so a port that mixes up the argument ORDER (a real
    // hazard: three of the four schemes take several 32-byte secrets) fails loudly.
    let x25519 = [0x01u8; 32];
    let mlkem = [0x02u8; 32];
    let es = [0x03u8; 32];
    let counting = {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    };

    struct Case {
        name: &'static str,
        why: &'static str,
        scheme: &'static str,
        inputs: Vec<(&'static str, [u8; 32])>,
        keys: ([u8; 32], [u8; 32]),
    }

    let cases = [
        Case {
            name: "classic",
            why: "The legacy classic-only derivation, still used by the `plain` wire mode \
                  (it has no TLS-shaped handshake to carry an ML-KEM share).",
            scheme: "classic",
            inputs: vec![("shared_secret", x25519)],
            keys: derive_keys(&x25519),
        },
        Case {
            name: "classic-counting-secret",
            why: "A second classic vector with a non-uniform secret — an implementation that \
                  accidentally hashed a constant would pass the all-0x01 case and fail here.",
            scheme: "classic",
            inputs: vec![("shared_secret", counting)],
            keys: derive_keys(&counting),
        },
        Case {
            name: "hybrid",
            why: "The post-quantum default (fake-tls / obfs / reality-tls / UDP): IKM is \
                  x25519 || mlkem with the v2 salt. The ORDER is wire-format — swapping the \
                  two secrets yields different keys and a tunnel that cannot interop.",
            scheme: "hybrid",
            inputs: vec![("x25519_shared", x25519), ("mlkem_shared", mlkem)],
            keys: derive_keys_hybrid(&x25519, &mlkem),
        },
        Case {
            name: "bound",
            why: "`auth.bind_static_to_session` for the plain mode: IKM is ee || es, binding \
                  the data keys to the server's long-lived identity (Noise-IK style).",
            scheme: "bound",
            inputs: vec![("ee", x25519), ("es", es)],
            keys: derive_keys_bound(&x25519, &es),
        },
        Case {
            name: "hybrid-bound",
            why: "Hybrid derivation with the static-ephemeral DH folded in (IKM is \
                  x25519 || mlkem || es) — three secrets, three chances to get the order wrong.",
            scheme: "hybrid-bound",
            inputs: vec![
                ("x25519_shared", x25519),
                ("mlkem_shared", mlkem),
                ("es", es),
            ],
            keys: derive_keys_hybrid_bound(&x25519, &mlkem, &es),
        },
    ];

    let mut s = String::new();
    s.push_str(
        r#"{
  "_comment": [
    "CONFORMANCE FIXTURES for the directional key derivation — the source of truth for the",
    "Rust transport core and the retained C#/desktop and Swift/iOS primitives.",
    "",
    "GENERATED FILE. Do not edit by hand: regenerate with",
    "  cargo run --features conformance-gen --bin gen-conformance",
    "from the qeli/ directory.",
    "",
    "WHY: this is the highest-stakes primitive in the set. Both ends must derive byte-",
    "identical keys or the tunnel does not come up at all — and a subtler divergence, such as",
    "the two DIRECTIONS swapped, produces a tunnel that authenticates and then decrypts",
    "nothing. There are four schemes, three of which take several 32-byte secrets whose ORDER",
    "is wire-format; getting that order wrong is silent until two different implementations",
    "try to talk to each other.",
    "",
    "SCHEMES: `classic` = HKDF over the X25519 secret (the `plain` wire mode only).",
    "`hybrid` = x25519 || mlkem, the post-quantum default for fake-tls / obfs / reality-tls /",
    "UDP. `bound` = ee || es, binding the keys to the server's long-lived identity",
    "(auth.bind_static_to_session). `hybrid-bound` = x25519 || mlkem || es. Each scheme has",
    "its OWN salt, so a peer on one scheme cannot silently interop with a peer on another —",
    "by design: there is no quiet PQ downgrade.",
    "",
    "HOW TO USE: feed the named `inputs` (hex, in the order given) to your implementation of",
    "`scheme` and assert the two derived keys. `server_to_client` and `client_to_server` are",
    "named by DIRECTION rather than enc/dec on purpose — which one is 'encrypt' depends on",
    "which side you are, and that ambiguity is exactly how a port ends up with them swapped.",
    "",
    "`platforms` lists the implementations REQUIRED to pass this file. A platform on that",
    "list whose test skips the file must fail, not pass quietly — a green test that verified",
    "nothing is the exact failure this fixture is here to prevent."
  ],
  "primitive": "hkdf",
  "generator": "qeli/src/gen_conformance_main.rs",
  "platforms": ["rust", "csharp", "swift"],
  "cases": [
"#,
    );

    for (i, c) in cases.iter().enumerate() {
        let why = c.why.split_whitespace().collect::<Vec<_>>().join(" ");
        let inputs = c
            .inputs
            .iter()
            .map(|(n, v)| format!("\"{}\": \"{}\"", n, hex(v)))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", c.name));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"scheme\": \"{}\",\n", c.scheme));
        s.push_str(&format!("      \"inputs\": {{ {inputs} }},\n"));
        s.push_str(&format!(
            "      \"expect\": {{ \"server_to_client\": \"{}\", \"client_to_server\": \"{}\" }}\n",
            hex(&c.keys.0),
            hex(&c.keys.1)
        ));
        s.push_str(if i + 1 == cases.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ]\n}\n");
    s
}

/// Build `conformance/quic.json` — QUIC short-header masking, and the crafted packets a
/// parser must survive.
///
/// The negative half is not hypothetical: a crafted QUIC varint could crash the C# and
/// Kotlin clients into a reconnect loop (a remote DoS) while Rust was already safe. The
/// verdicts here are RECORDED from the canon rather than asserted by hand, so the fixture
/// states what the reference parser actually does.
fn build_quic() -> String {
    use qeli::protocol::quic::{unwrap_quic, wrap_quic_short};

    let cid = [0xDEu8, 0xAD, 0xBE, 0xEF];

    struct Wrap {
        name: &'static str,
        why: &'static str,
        payload: Vec<u8>,
        pn: u32,
    }
    let wraps = [
        Wrap {
            name: "short-header-simple",
            why: "The ordinary masked datagram: flags, 4-byte connection id, 4-byte packet \
                  number, then the payload verbatim.",
            payload: b"qeli payload".to_vec(),
            pn: 1,
        },
        Wrap {
            name: "short-header-pn-zero",
            why: "Packet number 0 — catches a port that treats 0 as 'absent' and omits the \
                  field, shifting every following byte.",
            payload: b"first".to_vec(),
            pn: 0,
        },
        Wrap {
            name: "short-header-pn-high",
            why: "A packet number with all four bytes significant (0xF0E1D2C3): catches a \
                  port that writes it as one byte, or little-endian.",
            payload: b"x".to_vec(),
            pn: 0xF0E1_D2C3,
        },
        Wrap {
            name: "short-header-empty-payload",
            why: "An empty payload must still produce a well-formed header that round-trips.",
            payload: vec![],
            pn: 7,
        },
    ];

    // Crafted inputs for the parser. The verdict is whatever the canon returns — that is
    // the point: the fixture records reference BEHAVIOUR, it does not assert a guess.
    let crafted: Vec<(&str, &str, Vec<u8>)> = vec![
        (
            "empty",
            "Zero bytes must be rejected, not indexed into.",
            vec![],
        ),
        (
            "long-header-flag-only",
            "A single byte with the long-header bit set: the length varint that follows is \
             missing entirely. This is the shape that crashed the C#/Kotlin parsers.",
            vec![0x80],
        ),
        (
            "long-header-truncated-varint",
            "A long header whose varint claims an 8-byte encoding but supplies fewer bytes — \
             a parser that trusts the length prefix reads past the end.",
            vec![
                0xC3, 0x00, 0x00, 0x00, 0x01, // Initial + QUIC v1
                0x04, 0xDE, 0xAD, 0xBE, 0xEF, // four-byte DCID
                0x00, 0x00, // empty SCID + zero Token Length
                0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // eight-byte Length, seven present
            ],
        ),
        (
            "long-header-huge-length",
            "A varint declaring a length far larger than the datagram: must be rejected, and \
             must not be used to size an allocation.",
            vec![
                0xC3, 0x00, 0x00, 0x00, 0x01, // Initial + QUIC v1
                0x04, 0xDE, 0xAD, 0xBE, 0xEF, // four-byte DCID
                0x00, 0x00, // empty SCID + zero Token Length
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // max 62-bit Length
            ],
        ),
        (
            "long-header-length-understates-datagram",
            "Length declares only the four-byte packet number but the datagram carries an \
             extra payload byte; qeli emits one envelope per datagram, so the tail must not \
             be silently accepted.",
            vec![
                0xC3, 0x00, 0x00, 0x00, 0x01, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x01, 0x78,
            ],
        ),
        (
            "long-header-length-overstates-datagram",
            "Length declares one byte beyond the UDP datagram and must be rejected before \
             packet-number or payload slicing.",
            vec![
                0xC3, 0x00, 0x00, 0x00, 0x01, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x06, 0x00,
                0x00, 0x00, 0x01, 0x78,
            ],
        ),
        (
            "long-header-legacy-handshake",
            "The exact Handshake-type spelling emitted by older qeli builds remains readable \
             during a rolling client/server upgrade.",
            vec![
                0xE3, 0x00, 0x00, 0x00, 0x01, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x05, 0x00,
                0x00, 0x00, 0x01, 0x78,
            ],
        ),
        (
            "short-header-truncated",
            "A short header cut off inside the connection id / packet number.",
            vec![0x43, 0xDE, 0xAD],
        ),
    ];

    let mut s = String::new();
    s.push_str(
        r#"{
  "_comment": [
    "CONFORMANCE FIXTURES for the QUIC masking layer — the source of truth for the production",
    "Rust transport core and the retained C#/desktop and Swift/iOS primitives.",
    "",
    "GENERATED FILE. Do not edit by hand: regenerate with",
    "  cargo run --features conformance-gen --bin gen-conformance",
    "from the qeli/ directory.",
    "",
    "WHY: the UDP wire modes dress each datagram as a QUIC packet. The masking itself is",
    "simple and therefore easy to get subtly wrong (endianness of the packet number, a",
    "packet number of 0 treated as absent), and the PARSER is attacker-facing: anyone who can",
    "send the client a datagram controls these bytes. That is not hypothetical — a crafted",
    "QUIC varint could crash the C# and Kotlin clients into a reconnect loop (a remote DoS)",
    "at a time when Rust was already safe.",
    "",
    "NOTE: the QUIC layer only shapes the envelope. It does NOT encrypt — the payload it",
    "carries is already sealed by the inner codec. These vectors pin the envelope, nothing",
    "more.",
    "",
    "HOW TO USE: `wrap` cases give `payload`, `connection_id` and `packet_number`; your",
    "wrapper must emit exactly `expect.packet`, and unwrapping that packet must give the",
    "inputs back. `parse` cases give a crafted `packet`: a case with `reject: true` MUST be",
    "rejected — cleanly, without panicking, aborting, or allocating from an attacker-supplied",
    "length. The verdicts were RECORDED from the reference parser rather than asserted by",
    "hand, so this file states what the canon actually does.",
    "",
    "`platforms` lists the implementations REQUIRED to pass this file. A platform on that",
    "list whose test skips the file must fail, not pass quietly — a green test that verified",
    "nothing is the exact failure this fixture is here to prevent."
  ],
  "primitive": "quic",
  "generator": "qeli/src/gen_conformance_main.rs",
  "platforms": ["rust", "csharp", "swift"],
  "wrap": [
"#,
    );

    for (i, w) in wraps.iter().enumerate() {
        let packet = wrap_quic_short(&w.payload, &cid, w.pn);
        let why = w.why.split_whitespace().collect::<Vec<_>>().join(" ");
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", w.name));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"payload\": \"{}\",\n", hex(&w.payload)));
        s.push_str(&format!("      \"connection_id\": \"{}\",\n", hex(&cid)));
        s.push_str(&format!("      \"packet_number\": {},\n", w.pn));
        s.push_str(&format!(
            "      \"expect\": {{ \"packet\": \"{}\" }}\n",
            hex(&packet)
        ));
        s.push_str(if i + 1 == wraps.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ],\n  \"parse\": [\n");

    for (i, (name, why, packet)) in crafted.iter().enumerate() {
        let why = why.split_whitespace().collect::<Vec<_>>().join(" ");
        let verdict = unwrap_quic(packet);
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{name}\",\n"));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"packet\": \"{}\",\n", hex(packet)));
        match verdict {
            Err(_) => s.push_str("      \"expect\": { \"reject\": true }\n"),
            Ok(p) => s.push_str(&format!(
                "      \"expect\": {{ \"connection_id\": \"{}\", \"packet_number\": {}, \"payload\": \"{}\" }}\n",
                hex(&p.connection_id),
                p.packet_number,
                hex(&p.payload)
            )),
        }
        s.push_str(if i + 1 == crafted.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ]\n}\n");
    s
}

/// Build `conformance/udp-frag.json` — app-layer fragmentation of the big UDP handshake
/// messages, and the reassembler that has to survive whatever the network does to them.
///
/// This exists because IP fragments are routinely DROPPED on mobile / CGNAT paths, so the
/// post-quantum handshake (a ~2 KB ServerHello) is split by us instead. The reassembler is
/// then fed by the network in any order, with duplicates, gaps and outright hostile input —
/// four separate implementations of that, and the failure mode is a handshake that hangs
/// only on LTE.
fn build_udp_frag() -> String {
    use qeli::protocol::udp_frag::{
        fragment, mtu_probe_ack_datagram, Reassembler, FRAG_MAGIC, MAX_CHUNK, MAX_CHUNK_ACCEPT,
        MAX_FRAGS, MSG_AUTH_OK, MSG_CLIENT_HELLO, MSG_JUNK, MSG_MTU_PROBE, MSG_SERVER_HELLO,
    };

    /// Deterministic message body: byte i = (i * 31 + 7) mod 256 — non-repeating enough that
    /// a chunk placed at the wrong offset is obvious in a diff.
    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + 7) % 256) as u8).collect()
    }
    /// Hand-build one fragment datagram. The reassembler does not police chunk SIZE, so the
    /// reassembly cases below use tiny chunks — otherwise every case would carry kilobytes
    /// of hex for no extra coverage.
    fn frag(msg_id: u8, idx: u8, count: u8, chunk: &[u8]) -> Vec<u8> {
        let mut d = Vec::with_capacity(6 + chunk.len());
        d.extend_from_slice(&FRAG_MAGIC);
        d.push(msg_id);
        d.push(idx);
        d.push(count);
        d.extend_from_slice(chunk);
        d
    }

    let mut s = String::new();
    s.push_str(
        r#"{
  "_comment": [
    "CONFORMANCE FIXTURES for UDP handshake fragmentation — the source of truth for the Rust",
    "transport core and the retained C#/desktop and Swift/iOS primitives.",
    "",
    "GENERATED FILE. Do not edit by hand: regenerate with",
    "  cargo run --features conformance-gen --bin gen-conformance",
    "from the qeli/ directory.",
    "",
    "WHY: the post-quantum UDP handshake does not fit one datagram (the ServerHello carries",
    "an ML-KEM ciphertext plus the cert chain, ~2 KB). Left to IP fragmentation it is",
    "silently DROPPED on mobile / CGNAT paths — the classic 'works on Wi-Fi, hangs on LTE'.",
    "So we fragment at the app layer instead. The reassembler is then fed by the NETWORK: out",
    "of order, with duplicates, with gaps, and with whatever an attacker cares to send.",
    "",
    "WIRE: [MAGIC(3) = f0 9b 71][msg_id(1)][idx(1)][count(1)][chunk...]. The magic cannot open",
    "a TLS record (0x16 0x03), which is how a server tells a fragmented ClientHello from a",
    "legacy single-datagram one. This layer sits BELOW the QUIC mask and the obfs XOR — each",
    "fragment is wrapped independently.",
    "",
    "HOW TO USE:",
    "  `fragment`   — split `message` with `msg_id` and compare the datagrams byte for byte,",
    "                 or expect a refusal for a message that needs more than MAX_FRAGS.",
    "  `reassemble` — feed `feed` in the given ORDER to a fresh reassembler. `message` = it",
    "                 must complete with exactly those bytes; `incomplete` = it must return",
    "                 'need more' and NOT invent a message; `reject` = it must refuse.",
    "  `classify`   — the cheap predicates every receive path runs before anything else.",
    "",
    "NOTE ON CHUNK SIZES: the `reassemble` cases use deliberately tiny chunks. The reassembler",
    "bounds a chunk only from ABOVE (`max_chunk_accept`) and otherwise places fragments by idx",
    "with no offset or length field, so an UNDERSIZED chunk exercises exactly the same logic",
    "while keeping this file readable instead of kilobytes of hex.",
    "",
    "TWO CHUNK BOUNDS, AND THEY DIFFER: `max_chunk` is what an implementation may EMIT (derived",
    "from the IPv6-minimum-MTU budget); `max_chunk_accept` is the largest chunk it must still",
    "ACCEPT, pinned at the historical 1200. An implementation that bounds RECEIVE by max_chunk",
    "rejects every handshake from a pre-#14 peer, so both values are pinned here and a port must",
    "match both.",
    "",
    "MSG IDS: 1 ClientHello, 2 ServerHello, 3 junk decoy, 4 MTU probe, 5 probe ACK, 6 AuthOK.",
    "The AuthOK (`msg_auth_ok`) is the one whose size is not fixed — it carries the pushed route",
    "list. It is fragmented ONLY when it exceeds max_chunk, so a peer that predates msg_id 6 is",
    "unaffected in every case that works today; the only case where it meets fragments is the",
    "one where the network was already destroying its unfragmented reply. Its chunks are the",
    "finished AEAD record, not plaintext: reassemble first, decrypt after.",
    "",
    "NOT PINNED HERE: junk decoys and MTU probes carry RANDOM bodies by design, so their bytes",
    "cannot be fixed. Their framing is covered by `classify`, and the deterministic probe ACK",
    "is pinned in full.",
    "",
    "`platforms` lists the implementations REQUIRED to pass this file. A platform on that",
    "list whose test skips the file must fail, not pass quietly — a green test that verified",
    "nothing is the exact failure this fixture is here to prevent."
  ],
  "primitive": "udp-frag",
  "generator": "qeli/src/gen_conformance_main.rs",
  "max_chunk": "#,
    );
    s.push_str(&format!(
        "{MAX_CHUNK},\n  \"max_chunk_accept\": {MAX_CHUNK_ACCEPT},\n  \"max_frags\": {MAX_FRAGS},\n  \"msg_auth_ok\": {MSG_AUTH_OK},\n"
    ));
    s.push_str("  \"platforms\": [\"rust\", \"csharp\", \"swift\"],\n  \"fragment\": [\n");

    struct FragCase {
        name: &'static str,
        why: &'static str,
        msg_id: u8,
        len: usize,
    }
    let frag_cases = [
        FragCase {
            name: "single-fragment",
            why: "A message that fits one datagram still gets the header, with idx 0 and \
                  count 1 — a sender that skips framing for the small case breaks the peer.",
            msg_id: MSG_CLIENT_HELLO,
            len: 10,
        },
        FragCase {
            name: "exact-chunk-boundary",
            why: "Exactly MAX_CHUNK bytes: still ONE fragment. An implementation using `>=` \
                  where it needs `>` emits a spurious empty second fragment here.",
            msg_id: MSG_CLIENT_HELLO,
            len: MAX_CHUNK,
        },
        FragCase {
            name: "one-byte-over-boundary",
            why: "MAX_CHUNK + 1: two fragments, the second carrying a SINGLE byte. The classic \
                  off-by-one, and the shape most likely to be mis-sliced.",
            msg_id: MSG_SERVER_HELLO,
            len: MAX_CHUNK + 1,
        },
        FragCase {
            name: "auth-ok-fragmented",
            why: "msg_id 6 is the AuthOK, the one message here whose size is not fixed — it \
                  carries the pushed route list, so a profile pushing enough routes puts it \
                  past what a fragment-dropping path (mobile, CGNAT) will deliver. The server \
                  splits it ONLY above MAX_CHUNK, so a client that predates msg_id 6 sees no \
                  change in any case that works today; below the budget the AuthOK is still \
                  the single UNFRAMED datagram it always was — which is why there is no \
                  `fragment` case for the small size, and why a port must NOT start framing \
                  small AuthOKs to be tidy.",
            msg_id: MSG_AUTH_OK,
            len: MAX_CHUNK * 2 + 40,
        },
        FragCase {
            name: "too-large-to-fragment",
            why: "More than MAX_FRAGS fragments' worth. It must FAIL AT THE SENDER: idx/count \
                  are single bytes and the receiver rejects count > MAX_FRAGS, so packing it \
                  'successfully' would surface at the peer as a mysterious handshake hang.",
            msg_id: MSG_SERVER_HELLO,
            len: MAX_CHUNK * (MAX_FRAGS as usize) + 1,
        },
    ];

    for (i, c) in frag_cases.iter().enumerate() {
        let msg = body(c.len);
        let why = c.why.split_whitespace().collect::<Vec<_>>().join(" ");
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", c.name));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"msg_id\": {},\n", c.msg_id));
        match fragment(c.msg_id, &msg) {
            Ok(frags) => {
                s.push_str(&format!("      \"message\": \"{}\",\n", hex(&msg)));
                let list = frags
                    .iter()
                    .map(|f| format!("\"{}\"", hex(f)))
                    .collect::<Vec<_>>()
                    .join(", ");
                s.push_str(&format!(
                    "      \"expect\": {{ \"fragments\": [{list}] }}\n"
                ));
            }
            Err(_) => {
                // The body is megabytes; record its shape instead of inlining it.
                s.push_str(&format!("      \"message_len\": {},\n", msg.len()));
                s.push_str("      \"message_fill\": \"i*31+7 mod 256\",\n");
                s.push_str("      \"expect\": { \"reject\": true }\n");
            }
        }
        s.push_str(if i + 1 == frag_cases.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ],\n  \"reassemble\": [\n");

    struct ReCase {
        name: &'static str,
        why: &'static str,
        feed: Vec<Vec<u8>>,
    }
    let a = b"AAAA";
    let bb = b"BBBB";
    let cc = b"CCCC";
    let re_cases = [
        ReCase {
            name: "in-order",
            why: "The easy path: three fragments arriving in order complete the message.",
            feed: vec![
                frag(MSG_SERVER_HELLO, 0, 3, a),
                frag(MSG_SERVER_HELLO, 1, 3, bb),
                frag(MSG_SERVER_HELLO, 2, 3, cc),
            ],
        },
        ReCase {
            name: "out-of-order",
            why: "UDP reorders as a matter of course. Fragments must be placed BY INDEX, not \
                  appended in arrival order — an implementation that concatenates as they \
                  come produces a corrupted handshake message that then fails to parse for \
                  an unrelated-looking reason.",
            feed: vec![
                frag(MSG_SERVER_HELLO, 2, 3, cc),
                frag(MSG_SERVER_HELLO, 0, 3, a),
                frag(MSG_SERVER_HELLO, 1, 3, bb),
            ],
        },
        ReCase {
            name: "duplicate-fragment",
            why: "A retransmitted fragment must be idempotent: counted once, not twice. An \
                  implementation counting arrivals instead of distinct indices completes \
                  early here and returns a message with a hole in it.",
            feed: vec![
                frag(MSG_SERVER_HELLO, 0, 3, a),
                frag(MSG_SERVER_HELLO, 0, 3, a),
                frag(MSG_SERVER_HELLO, 1, 3, bb),
                frag(MSG_SERVER_HELLO, 2, 3, cc),
            ],
        },
        ReCase {
            name: "conflicting-duplicate-fragment",
            why: "The same index cannot authenticate two different byte strings. Keeping the \
                  first silently makes the reconstructed handshake depend on arrival order and \
                  lets an injected duplicate hide corruption instead of failing closed.",
            feed: vec![
                frag(MSG_SERVER_HELLO, 0, 3, a),
                frag(MSG_SERVER_HELLO, 0, 3, bb),
            ],
        },
        ReCase {
            name: "missing-fragment",
            why: "A gap must stay incomplete — never completed with a hole, never padded.",
            feed: vec![
                frag(MSG_SERVER_HELLO, 0, 3, a),
                frag(MSG_SERVER_HELLO, 2, 3, cc),
            ],
        },
        ReCase {
            name: "index-out-of-range",
            why: "idx >= count is malformed and must be refused, not written past the end of \
                  the parts array.",
            feed: vec![frag(MSG_SERVER_HELLO, 5, 3, a)],
        },
        ReCase {
            name: "count-over-max-frags",
            why: "count > MAX_FRAGS must be refused up front: it is the sender's job to fail \
                  early, and an attacker can otherwise make the peer reserve state for a \
                  message that will never arrive.",
            feed: vec![frag(MSG_SERVER_HELLO, 0, MAX_FRAGS + 1, a)],
        },
        ReCase {
            name: "inconsistent-count",
            why: "Two fragments of the same message disagreeing on `count` — the state must be \
                  refused rather than silently re-sized.",
            feed: vec![
                frag(MSG_SERVER_HELLO, 0, 3, a),
                frag(MSG_SERVER_HELLO, 1, 4, bb),
            ],
        },
        ReCase {
            name: "not-a-fragment",
            why: "A datagram without the magic must be refused by the reassembler (the caller \
                  routes it elsewhere), not parsed as if the header were there.",
            feed: vec![vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01]],
        },
    ];

    for (i, c) in re_cases.iter().enumerate() {
        let why = c.why.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut r = Reassembler::new();
        let mut verdict = String::from("      \"expect\": { \"incomplete\": true }\n");
        for d in &c.feed {
            match r.push(d) {
                Ok(Some(msg)) => {
                    verdict = format!("      \"expect\": {{ \"message\": \"{}\" }}\n", hex(&msg));
                    break;
                }
                Ok(None) => {}
                Err(_) => {
                    verdict = String::from("      \"expect\": { \"reject\": true }\n");
                    break;
                }
            }
        }
        let feed = c
            .feed
            .iter()
            .map(|f| format!("\"{}\"", hex(f)))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", c.name));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"feed\": [{feed}],\n"));
        s.push_str(&verdict);
        s.push_str(if i + 1 == re_cases.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ],\n  \"classify\": [\n");

    let ack = mtu_probe_ack_datagram(0xBEEF, 1400);
    let classify: Vec<(&str, &str, Vec<u8>)> = vec![
        (
            "client-hello-fragment",
            "An ordinary fragment: magic present, msg_id 1.",
            frag(MSG_CLIENT_HELLO, 0, 1, b"hi"),
        ),
        (
            "junk-decoy",
            "An AWG junk decoy uses the SAME framing as a real fragment so it rides the \
             identical obfs/QUIC transforms — only msg_id distinguishes it, and the peer must \
             DROP it rather than feed it to the reassembler.",
            frag(MSG_JUNK, 0, 1, b"\x00\x01\x02\x03"),
        ),
        (
            "mtu-probe",
            "A path-MTU probe, likewise same framing, different msg_id.",
            frag(MSG_MTU_PROBE, 0, 1, b"\xef\xbe\x78\x05"),
        ),
        (
            "mtu-probe-ack",
            "The probe ACK is fully deterministic (id + outer_size, little-endian), so it is \
             pinned byte for byte here — id 0xBEEF, outer size 1400.",
            ack.clone(),
        ),
        (
            "auth-ok-fragment",
            "The AuthOK, msg_id 6 — fragment 0 of 2. Unambiguous against a real record in \
             either framing: TLS framing opens 0x17 0x03 0x03, and raw framing opens with a \
             u16 payload length bounded by MAX_RECORD_SIZE (0x4124), so its high byte is at \
             most 0x41 and 0xF0 is unreachable both ways. Same property that lets a server \
             tell a fragmented ClientHello from a legacy single-datagram one.",
            frag(MSG_AUTH_OK, 0, 2, b"\xde\xad\xbe\xef"),
        ),
        (
            "tls-record-not-a-fragment",
            "A real TLS record opener (0x16 0x03) must NOT look like a fragment — that is the \
             whole reason the magic was chosen as it was.",
            vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x01],
        ),
        (
            "too-short",
            "Shorter than the 6-byte header: every predicate must say no without indexing.",
            vec![0xF0, 0x9B],
        ),
    ];

    for (i, (name, why, d)) in classify.iter().enumerate() {
        let why = why.split_whitespace().collect::<Vec<_>>().join(" ");
        use qeli::protocol::udp_frag::{
            is_auth_ok_fragment, is_fragment, is_junk, is_mtu_probe, is_mtu_probe_ack,
        };
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{name}\",\n"));
        s.push_str(&format!("      \"why\": \"{why}\",\n"));
        s.push_str(&format!("      \"datagram\": \"{}\",\n", hex(d)));
        s.push_str(&format!(
            "      \"expect\": {{ \"is_fragment\": {}, \"is_junk\": {}, \"is_mtu_probe\": {}, \"is_mtu_probe_ack\": {}, \"is_auth_ok\": {} }}\n",
            is_fragment(d),
            is_junk(d),
            is_mtu_probe(d),
            is_mtu_probe_ack(d),
            is_auth_ok_fragment(d)
        ));
        s.push_str(if i + 1 == classify.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    s.push_str("  ]\n}\n");
    s
}

/// Locate the repo root by walking up until `conformance/` is found, so the generator works
/// from `qeli/` (where cargo runs it) and from the repo root alike.
fn out_dir() -> PathBuf {
    let mut dir: PathBuf = std::env::current_dir().expect("cannot read the working directory");
    loop {
        if dir.join(OUT_DIR).is_dir() {
            return dir.join(OUT_DIR);
        }
        if !dir.pop() {
            // Not found: fall back to creating it next to the current directory's parent,
            // which is the repo root in the normal `cargo run` layout.
            let d = Path::new("..").join(OUT_DIR);
            std::fs::create_dir_all(&d).expect("cannot create the conformance directory");
            return d;
        }
    }
}

fn main() -> std::io::Result<()> {
    let check = std::env::args().any(|a| a == "--check");
    let dir = out_dir();

    let files: Vec<(&str, String)> = vec![
        ("prp-nonce.json", build_prp_nonce()),
        ("packet-decode.json", build_packet_decode()),
        ("replay-window.json", build_replay_window()),
        ("hkdf.json", build_hkdf()),
        ("quic.json", build_quic()),
        ("udp-frag.json", build_udp_frag()),
    ];

    let mut drifted = Vec::new();
    for (name, want) in &files {
        let path = dir.join(name);
        if check {
            let got = std::fs::read_to_string(&path).unwrap_or_default();
            if got != *want {
                drifted.push(path.display().to_string());
            }
        } else {
            std::fs::write(&path, want)?;
            println!("wrote {}", path.display());
        }
    }

    if check {
        if drifted.is_empty() {
            println!(
                "conformance fixtures are up to date ({} file(s))",
                files.len()
            );
        } else {
            eprintln!(
                "conformance fixtures are STALE — the implementation changed but the shared \
                 vectors were not regenerated:"
            );
            for d in &drifted {
                eprintln!("  {d}");
            }
            eprintln!(
                "Regenerate from qeli/ with:\n  \
                 cargo run --features conformance-gen --bin gen-conformance"
            );
            std::process::exit(1);
        }
    }
    Ok(())
}
