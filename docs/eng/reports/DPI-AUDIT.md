# qeli — DPI detectability audit

This document lists the **tells** by which modern DPI distinguishes qeli traffic from
real HTTPS/QUIC, with code anchors, a severity assessment, and a mitigation priority.
Originally it was an **audit** (with no code edits); since then many tells have been
closed — the **✅** marks in the text track what has already been fixed (the
`reality-tls` mode, WS-fronting/QUIC-shape for obfs, the hardening of fake-tls: the PQ
key_share, ALPN, the sig_algs cleanup).

It complements [AUDIT.md](AUDIT.md) (which has the crypto/auth security model); here —
only detectability on the wire.

## Current 0.8.0 Reality/H2 status (2026-08-26)

Current `reality-tls` is **REALITY TLS 1.3 + genuine HTTP/2**, not the former second
fake-TLS handshake inside outer TLS. It negotiates ALPN `h2`, opens one long-lived
bidirectional `POST /v1/events/stream`, uses real H2 control frames/flow control and batches
private qeli records over randomized 2–8 ms windows. PacketCodec AEAD remains end-to-end but
its nonce and message boundaries are encrypted inside TLS/H2 and are not an outer TLS layout.

In the clean lab corpus, 6/6 H2 sessions authenticated and passed bidirectional traffic; the
classifier trained on the old transport-independent shape detected 0/6 new sessions with 0/6
control false positives. This is a regression result against the old fingerprint, **not** an
industrial-DPI detection probability. Remaining risks include synthetic/OOD JA3 rotation, fixed
H2 SETTINGS and one eternal POST; active-probe, malformed TLS/H2, replay, reconnect and broad
browser-control testing remain required. Evidence:
[the dated PCAP report](../../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md).

The current development branch also implements a negotiated `PACKET_MUX_V1` recordizer above
every carrier. After AUTH it applies identically to TCP `plain`/`fake-tls`/`reality-tls`/`obfs`
and UDP `fake-tls`/QUIC-shape/`obfs`, including AWG variants: it coalesces IP packets, varies
inner record boundaries and can split one IP packet across them. The server owns
`obf.recordizer.*` and pushes the values through the authenticated response. This closes the
transport-independent “one IP packet = one qeli record” correlation beyond Reality/H2, but it
does not repair carrier-specific outer tells.

The 0/6 result above belongs to the earlier Reality/H2 corpus. The common recordizer still needs
a new clean PCAP corpus across every TCP/UDP mode, legacy/required negotiation, IPv4/IPv6 and
load. Until then that result must not be generalized to other carriers or presented as a measured
detection probability.

## The threat model (DPI levels)

| Level | Method | Real examples |
|---|---|---|
| **D1** Passive signature-based | byte-pattern, a static JA3 blocklist | old corporate NGFW |
| **D2** Passive statistical | entropy, JA4/JA4+, the size/timing distribution, SNI↔IP consistency | Russia's TSPU, the GFW (2022+), Iran |
| **D3** Active probing | reaches the server itself, replays/completes the handshake | the GFW, a number of ISPs |

qeli `fake-tls`/`obfs` target **D1** (`obfs` also targets the entropy-based **D2**).
`PACKET_MUX_V1` reduces the size/boundary D2 tell shared by all modes, but does not disguise
the ClientHello, outer frame syntax, endpoint or long-term timing.
`reality-tls` removes the former bare fake-TLS and nested-record tells by using real TLS 1.3
plus H2, and bridges unauthenticated probes to the target. It reduces the catalogued D2/D3
signals but does not close timing, target-correlation or H2-semantic classification universally.
Even with the recordizer, `plain` remains the most visible high-entropy mode and is for trusted
networks only.

Severity: `CRIT` = a single rule catches it deterministically; `HIGH` = a reliable
indicator for D2/D3; `MED` = a contribution to an ML classifier / correlation.

---

## 1. fake-TLS, the client side (ClientHello)

### 1.1 [CRIT] ClientHello without ALPN — ✅ fixed
- **Before:** missing ALPN selected qeli with one rule and doubled as an unauthenticated
  “ours” marker.
- **Status:** both bare `fake-tls` and `reality-tls` always offer `h2`/`http/1.1`;
  REALITY classifies clients only by its cryptographic token/key_share. A regression test
  requires ALPN in the complete Chrome-shaped extension set.

### 1.2 [HIGH] Non-browser cipher-suite set — ✅ fixed
- **Before:** GREASE plus only `1301/1302/1303`, a stable non-browser JA4.
- **Status:** bare `fake-tls` consumes the same single 15-suite Chrome list as
  `reality-tls`, plus a separate GREASE value. Tests pin the exact order and set;
  the erroneous ban on modern `0xCCA9` is gone.

### 1.3 [HIGH] Few supported_groups — ✅ addressed (the PQ group added)
- **Where:** [tls.rs build_supported_groups_extension](../../../qeli/src/protocol/tls.rs).
- **Why it gave it away:** current Chrome sends `X25519MLKEM768` (post-quantum) first,
  plus secp384/521. The absence of a PQ group on a "2026-grade" client is a noticeable
  anomaly for D2.
- **Status — ✅ fixed:** the ClientHello now sends `X25519MLKEM768` (`0x11ec`) **first** in
  supported_groups + the corresponding PQ key_share (1216 B on the wire), like Chrome
  (`build_supported_groups_extension` / `build_key_share_extension`).

### 1.4 [HIGH] Missing always-present browser extensions — ✅ fixed
- **Before:** bare `fake-tls` omitted OCSP, SCT, ec_point_formats, session_ticket,
  renegotiation_info and ALPS.
- **Status:** the builder emits the complete Chrome-shaped set with GREASE, ALPN, TLS
  1.3/1.2, PQ/classic key_share and shuffled middle extensions. The test parses the actual
  extension block and requires every critical type instead of scanning random bytes.

### 1.5 [MED] An outdated signature_algorithms — ✅ fixed
- **Where:** [tls.rs build_signature_algorithms_extension](../../../qeli/src/protocol/tls.rs).
- **Why it gave it away:** the list contained `rsa_pkcs1_sha1` (0x0201), which modern
  browsers have dropped. A contribution to the JA4 mismatch.
- **Status — ✅ fixed:** `rsa_pkcs1_sha1` (0x0201) removed from the list.

### 1.6 [HIGH] SNI↔IP inconsistency (decoy pool) — ✅ default path fixed
- **Before:** a bare IP selected a new Google/Cloudflare/Microsoft name on every reconnect.
- **Status:** the random client decoy pool is gone. `fake-tls` correctly omits SNI for a
  bare IP; WebSocket obfs puts the actual IP in `Host` (bracketed for IPv6); `reality-tls`
  requires an explicit valid DNS `sni` for an IP endpoint. Control characters and invalid
  names fail before connecting. An explicit operator front remains the operator’s
  responsibility: qeli cannot prove CDN/anycast membership from one DNS snapshot without
  false failures.

---

## 2. fake-TLS, the server side (ServerHello / handshake)

### 2.1 [CRIT] The server's handshake messages go in cleartext
- **Where:** [tls.rs build_certificate](../../../qeli/src/protocol/tls.rs),
  [build_finished](../../../qeli/src/protocol/tls.rs) — both wrapped in a `0x16`
  (handshake) record in the clear, like the ServerHello.
- **Why it gives it away:** in real TLS 1.3, after ServerHello+CCS **everything**
  (Encrypted Extensions, Certificate, CertVerify, Finished) rides inside `0x17`
  (application_data, encrypted). A cleartext `0x16` Certificate after ServerHello is a
  signature of TLS 1.2 OR a forgery. D2 (and especially D3) catches it deterministically.

### 2.2 [CRIT] The certificate — pseudo-DER, doesn't parse as X.509
- **Where:** [tls.rs build_certificate](../../../qeli/src/protocol/tls.rs) — 512 bytes
  of partially-structured garbage.
- **Why it gives it away:** a D3 prober, having completed the handshake (or simply parsed
  the Certificate), sees that this isn't a valid X.509 and not a chain to a public CA. A
  real chain for `www.microsoft.com` is ~3–5 KB of several certs. A 512-byte single "cert"
  is an instant classification.
- **Status — concerns only `fake-tls`/proxy-bridge (where the cert is in the cleartext `0x16`).**
  In `reality-tls` the Certificate is **encrypted** inside TLS 1.3 (`0x17`) — invisible to
  passive DPI altogether. With **cert-borrowing** (`handrolled=true`, 2026-06-06) the
  hand-rolled server hands the qeli client the **real captured chain of the target** (not
  self-signed/dummy), with an auto-refresh every 12h — even an active prober that completed
  the handshake sees the real cert `CN=www.microsoft.com` (issuer Microsoft TLS G2). The
  `reality`-proxy mode additionally bridges **foreign** connections to the real site.

### 2.3 [MED] A poor ServerHello
- **Where:** [tls.rs build_server_hello](../../../qeli/src/protocol/tls.rs) — only
  supported_versions + key_share, no other extensions; always cipher `1301`.
- **Why it gives it away:** a real server varies the chosen suite and sends a consistent
  set. A constant `1301` + a minimal SH = a weak but stable indicator for D2.

---

## 3. The data channel (application_data)

### 3.1 [HIGH] An explicit 12-byte nonce in every record (legacy outer framing)
- **Where:** [packet.rs encrypt_packet](../../../qeli/src/protocol/packet.rs) — a record =
  `0x17 ‖ 0303 ‖ len ‖ nonce(12) ‖ ciphertext+tag`.
- **Why it gives it away:** real TLS 1.3 uses an **implicit** nonce (it's not on the wire).
  A constant 12-byte prefix before the ciphertext in every record is a structural
  fingerprint across the whole data plane (the Feistel-PRP in
  [packet.rs](../../../qeli/src/protocol/packet.rs) hides the increment, but the very
  fact of 12 "extra" bytes in every record remains). D2 sees this when analyzing the
  inter-record structure.

### 3.2 [MED] One IP packet → exactly one qeli record (closed by `PACKET_MUX_V1` for every carrier)
- **Why it gives it away:** real TLS cuts/coalesces the stream along boundaries up to 16 KB
  independently of the application messages. The "1 record = 1 MTU packet" correspondence
  (plus the fixed overhead of +33 bytes: 5+12+16) gives a characteristic record-size
  distribution. A contribution to a size ML classifier.
- **Development status:** after authenticated negotiation the common recordizer batches,
  coalesces and splits before PacketCodec AEAD in both TCP and UDP paths. Its metadata is
  encrypted, sizes are clamped to the carrier/path budget, and reassembly has hard timeout,
  memory and inflight limits. `policy=prefer` keeps legacy compatibility; `required` rejects an
  old core fail-closed. “Closed” here describes removal of the direct boundary mapping in the
  implementation; an external all-mode PCAP/DPI result requires a separate repeated report.

---

## 4. The obfs mode (structure-free)

### 4.1 [CRIT against D2] Full entropy from the first byte — ✅ addressed (WS-fronting)
> **Status:** closed by the option `obf.obfs_fronting = websocket` (the default). The start
> of an obfs connection is wrapped in a WebSocket Upgrade handshake (printable HTTP +
> `\r\n\r\n`), the first packet passes the Ex2/Ex3/Ex4 exemptions. See `protocol/obfs.rs`
> (the `ws` module) and `ObfsStream.kt`. The rollback — `front=none`.

- **Where:** [obfs.rs](../../../qeli/src/protocol/obfs.rs) — `[nonce(12)] ‖ ChaCha20-XOR`, no
  structure; the author's comment admits it.
- **Why it gives it away:** exactly the "fully encrypted traffic" category, which the GFW
  has blocked since 2022 (Wu et al., USENIX Security '23) and the TSPU — via heuristics:
  the share of printable bytes, popcount/entropy, the length of printable runs, the
  printable prefix. The qeli-obfs flow passes **none** of them → a block by "everything
  that looks like nothing". "Structure-free" today = a detectable category, not an
  invisible one.

### 4.2 [MED] UDP-obfs: a cleartext nonce(12) in every datagram — ✅ addressed (QUIC-shape)
> **Status:** closed 2026-06-05. The datagram got a QUIC short-header shape
> `[flag(0x40|x)][nonce:12 as conn-id][protected]` — the first byte is in the QUIC
> short-header range (the fixed-bit set), not uniformly random. Mirrored in obfs.rs /
> ObfsStream.kt / ObfsStream.cs. A breaking wire-change for UDP-obfs (a coordinated
> deploy). A deep QUIC parse will still tell it apart (no real handshake) — full QUIC
> mimicry comes with Axis 2 (tells 5.1/5.2).

- **Where:** [obfs.rs obfs_datagram_seal](../../../qeli/src/protocol/obfs.rs).
- **Why it gives it away:** a stable 12-byte high-entropy prefix on each datagram —
  differs both from QUIC (which has structure) and from STUN/DTLS. Recognizable when a
  sample is available.

---

## 5. QUIC-masking (UDP)

### 5.1 [CRIT] The packet number in cleartext, incrementing
- **Where:** [quic.rs wrap_quic_long/short](../../../qeli/src/protocol/quic.rs) write the
  `packet_number` in the clear.
- **Why it gives it away:** real QUIC applies **header protection** — the packet number and
  the low bits of the first byte are encrypted (RFC 9001 §5.4). A visible growing 4-byte PN
  is "not QUIC" deterministically for any QUIC-aware D2.

### 5.2 [CRIT] The Initial packet is not protected per RFC 9001
- **Where:** [quic.rs wrap_quic_long](../../../qeli/src/protocol/quic.rs).
- **Why it gives it away:** the shell now has the Initial `Token Length` and `Length`
  fields, but there is no Initial-secret AEAD, header protection, CRYPTO frame or mandatory
  1200-byte Initial padding. The packet number and protected low header bits remain fixed /
  visible, while a real QUIC Initial protects them.

### 5.3 [MED] Double-nested structure
- **Why it gives it away:** inside the "QUIC payload" an already-structured fake-TLS `0x17`
  record (with its own header and a 12-byte nonce) is placed. Two layers of mismatched
  structure — an extra handle for a deep parse.

---

## 6. Flow behavior (all modes)

### 6.1 [HIGH] The flow shape = "download", not "browsing"
- **Why it gives it away:** the tunnel carries a bidirectional bulky full-MTU flow at a
  ~constant speed. The size/inter-packet-interval distribution differs from web surfing
  (short bursts + idle). Padding ([obfuscate.rs](../../../qeli/src/protocol/obfuscate.rs))
  normalizes a **single** packet, but doesn't reproduce the target protocol's distribution
  → an ML classifier (D2) separates "the tunnel" from "browsing".
- **🟡 Phase 1 (partial):** `obf.traffic_shaping` — idle cover traffic at exponential
  (non-periodic) gaps instead of "dead air" while idle
  ([shaper.rs](../../../qeli/src/protocol/shaper.rs)). Removes the dead-air signal, but does
  **not** reproduce the size/burst distribution under load — that is **Phase 2** (real-packet
  pacing + distribution-matching, opt-in, validated against a capture).

### 6.2 [MED] Heartbeat as a beacon
- **Why it gives it away:** a periodic keepalive (even with jitter) gives a regular
  component in the spectrum of inter-packet intervals — a weak but stable indicator "there's
  a persistent connection".
- **✅ Closed (Phase 1):** with `obf.traffic_shaping.enabled` the fixed heartbeat is
  **replaced** by Poisson cover (exponential gaps) — the regular component in the
  inter-packet-interval spectrum is gone.

---

## The priority summary table

| # | Tell | Severity | Level | Mitigation axis |
|---|---|:---:|:---:|---|
| 1.1 | A ClientHello without ALPN (+ the REALITY marker) | CRIT | D1/D2 | Axis 1 |
| 2.1 | The server's cleartext handshake records | CRIT | D2/D3 | Axis 1 |
| 2.2 | The pseudo-DER certificate | CRIT | D3 | Axis 1 |
| 4.1 | obfs — full entropy | CRIT | D2 | Axis 3 |
| 5.1 | The QUIC PN in cleartext | CRIT | D2 | Axis 2/4 |
| 5.2 | The QUIC Initial not per RFC | CRIT | D2 | Axis 2/4 |
| 1.2 | A non-browser cipher set | HIGH | D2 | Axis 1 |
| 1.3 | Few supported_groups (no PQ) | HIGH | D2 | Axis 1 |
| 1.4 | No mandatory extensions | HIGH | D2 | Axis 1 |
| 1.6 | An SNI↔IP mismatch + SNI rotation | HIGH | D2 | Axis 1 |
| 3.1 | An explicit 12-byte nonce in the record | HIGH | D2 | Axis 1 |
| 6.1 | The flow shape = download | HIGH | D2 | Axis 2 |
| 1.5 | An outdated signature_algorithms | MED | D2 | Axis 1 |
| 2.3 | A poor ServerHello | MED | D2 | Axis 1 |
| 3.2 | 1 packet = 1 record | MED | D2 | Axis 2 |
| 4.2 | The UDP-obfs nonce prefix | MED | D2 | Axis 3 |
| 5.3 | The QUIC double-nesting | MED | D2 | Axis 2 |
| 6.2 | The heartbeat beacon | MED | D2 | Axis 2 |

**Mitigation axes** (see the "Mirage" discussion):
- **Axis 1 — true REALITY — ✅ READY (2026-06):** the `reality-tls` mode — real Chrome TLS
  1.3 on the client (the pure-Rust realtls core) + termination on the server (rustls OR
  hand-rolled with **cert-borrowing** + a mirrored JA3S + the X25519MLKEM768 PQ hybrid +
  NewSessionTicket). It removes 1.1–1.6, 2.1–2.3, 3.1. Plus `fake-tls` itself was hardened
  pointwise (the PQ key_share, ALPN with a REALITY token, the sig_algs cleanup).
- **Axis 2 — carrier/flow shaping — 🟡 PARTIAL (2026-08):** genuine H2 and randomized batching
  break the old record-boundary classifier; Poisson idle cover removes the fixed heartbeat.
  Target-specific browser H2 SETTINGS/priority/window/stream choreography and validated
  under-load distribution matching remain open. UDP QUIC-shape is still not RFC QUIC/H3.
  The QUIC layer (5.x) is deprioritized (the fundamental RFC 9001 ceiling, see ROADMAP).
- **Axis 3 — entropy-fix obfs — ✅ READY (2026-06-05):** WS-fronting (a printable HTTP
  start) + the QUIC-shape for UDP-obfs. It removes 4.1, 4.2.

## Conclusion

"DPI does not see it" is not a defensible absolute. `PACKET_MUX_V1` removes the direct IP-packet
to qeli-record relation across all TCP/UDP carriers; current Reality/H2 additionally closes the
old deterministic fake-TLS/nested-record paths and sends unauthenticated probes to the target.
But the common recordizer does not turn fake-TLS, obfs, QUIC-shape or plain into genuine
HTTPS/QUIC. Carrier syntax, browser-profile differences, endpoint correlation, H2 semantics and
timing remain measurable research items, so no universal D1/D2/D3 closure or numeric detection
probability is claimed. `fake-tls`/`obfs` remain for D1/D2 scenarios (faster, simpler), while
`reality-tls` is preferred when the threat model includes active probing. A new all-mode PCAP
corpus must validate the recordizer regression separately from the earlier 6/6 H2 sessions.
