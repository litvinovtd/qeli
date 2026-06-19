# qeli — DPI detectability audit

This document lists the **tells** by which modern DPI distinguishes qeli traffic from
real HTTPS/QUIC, with code anchors, a severity assessment, and a mitigation priority.
Originally it was an **audit** (with no code edits); since then many tells have been
closed — the **✅** marks in the text track what has already been fixed (the
`reality-tls` mode, WS-fronting/QUIC-shape for obfs, the hardening of fake-tls: the PQ
key_share, ALPN, the sig_algs cleanup).

It complements [AUDIT.md](AUDIT.md) (which has the crypto/auth security model); here —
only detectability on the wire.

## The threat model (DPI levels)

| Level | Method | Real examples |
|---|---|---|
| **D1** Passive signature-based | byte-pattern, a static JA3 blocklist | old corporate NGFW |
| **D2** Passive statistical | entropy, JA4/JA4+, the size/timing distribution, SNI↔IP consistency | Russia's TSPU, the GFW (2022+), Iran |
| **D3** Active probing | reaches the server itself, replays/completes the handshake | the GFW, a number of ISPs |

qeli `fake-tls`/`obfs` target **D1** (`obfs` — also the entropy-based **D2**). Against
**D2/D3** the tells listed below give `fake-tls` away — they are closed by the
**`reality-tls`** mode (real browser TLS 1.3 on the wire: tells 1.1–1.6 are
inapplicable, the client sends a Chrome ClientHello and the server terminates real TLS).
The **`plain`** mode (no obfuscation) is, on the contrary, the most visible: a bare
high-entropy flow with no recognizable protocol is caught by the "fully encrypted"
entropy heuristic (tell 4.x) from the first packet. `plain` is for trusted networks, not
for DPI circumvention.

Severity: `CRIT` = a single rule catches it deterministically; `HIGH` = a reliable
indicator for D2/D3; `MED` = a contribution to an ML classifier / correlation.

---

## 1. fake-TLS, the client side (ClientHello)

### 1.1 [CRIT] A ClientHello without ALPN — and this is also used as the "ours" marker
- **Where:** [tls.rs build_client_hello](../../qeli/src/protocol/tls.rs#L48) doesn't add
  the ALPN extension (`0x0010`). The server detector [reality.rs:46](../../qeli/src/server/reality.rs#L46)
  (`has_alpn_extension`) explicitly relies on this: *ALPN present → a foreigner → bridge to
  the real site; no ALPN → a qeli client*.
- **Why it gives it away:** real Chrome/Firefox/Safari **always** send ALPN (`h2`,
  `http/1.1`). A ClientHello on :443 without ALPN is no longer "like a browser". A single
  DPI rule (`tls.client_hello and not tls.alpn`) deterministically singles out all qeli
  traffic (**D1/D2**). This is probably the worst single tell.
- **Status — ✅ addressed in the REALITY modes:** the "ours/foreigner" discriminator is now
  **cryptographic** (a REALITY token in the `session_id`, not "no ALPN"), and when a token
  is present the ClientHello **adds ALPN** (`h2`/`http/1.1`) — it reads as a browser
  ([tls.rs:88-92](../../qeli/src/protocol/tls.rs#L88)). In `reality-tls` it's a real
  Chrome ClientHello altogether. Bare `fake-tls` without a REALITY token still doesn't
  send ALPN.

### 1.2 [HIGH] A non-browser cipher-suite set
- **Where:** [tls.rs:118-123](../../qeli/src/protocol/tls.rs#L118) — GREASE + exactly 3
  suites (`1301/1302/1303`).
- **Why it gives it away:** Chrome sends ~15+ suites (including legacy ECDHE-RSA/ECDSA for
  compatibility). A 4-element list → the JA4 `ciphers` segment matches no real client. The
  extension shuffle ([tls.rs:83](../../qeli/src/protocol/tls.rs#L83)) does **not** fix this:
  JA4 sorts the fields before hashing, and the cipher set is still "non-Chrome".

### 1.3 [HIGH] Few supported_groups — ✅ addressed (the PQ group added)
- **Where:** [tls.rs build_supported_groups_extension](../../qeli/src/protocol/tls.rs#L455).
- **Why it gave it away:** current Chrome sends `X25519MLKEM768` (post-quantum) first,
  plus secp384/521. The absence of a PQ group on a "2026-grade" client is a noticeable
  anomaly for D2.
- **Status — ✅ fixed:** the ClientHello now sends `X25519MLKEM768` (`0x11ec`) **first** in
  supported_groups + the corresponding PQ key_share (1216 B on the wire), like Chrome
  (`build_supported_groups_extension` / `build_key_share_extension`).

### 1.4 [HIGH] Missing extensions that a browser always sends
- **Where:** the extension list in [tls.rs:75-82](../../qeli/src/protocol/tls.rs#L75).
- **Why it gives it away:** there's no `ec_point_formats` (0x000B), `status_request`/OCSP
  (0x0005), `signed_certificate_timestamp` (0x0012), `renegotiation_info` (0xFF01),
  `application_settings`/ALPS (0x4469), `session_ticket` (0x0023). Their collective absence
  gives a JA4 fingerprint that belongs to no mass-market client → a D2 block by an "unknown
  fingerprint".
- **Status — partial:** added `extended_master_secret` (0x17), `psk_key_exchange_modes`,
  `compress_certificate` (0x1b), and ALPN (in the REALITY modes). In `reality-tls` the
  ClientHello is real Chrome (the full set). Bare `fake-tls` is still incomplete on
  status_request/SCT/renegotiation_info/ALPS.

### 1.5 [MED] An outdated signature_algorithms — ✅ fixed
- **Where:** [tls.rs build_signature_algorithms_extension](../../qeli/src/protocol/tls.rs#L502).
- **Why it gave it away:** the list contained `rsa_pkcs1_sha1` (0x0201), which modern
  browsers have dropped. A contribution to the JA4 mismatch.
- **Status — ✅ fixed:** `rsa_pkcs1_sha1` (0x0201) removed from the list.

### 1.6 [HIGH] SNI↔IP inconsistency (a decoy pool)
- **Where:** [tls.rs DEFAULT_SNI_POOL / pick_random_sni](../../qeli/src/protocol/tls.rs#L10).
- **Why it gives it away:** the client sends the SNI `www.google.com` to an IP that does
  **not** belong to Google. D2 checks the SNI against the destination range (passive DNS /
  ASN) → a mismatch = the classic domain-fronting indicator. Worse: **SNI rotation** to the
  same dst-IP between connections (a different decoy each time) — a signature that
  legitimate clients never have (one host → a stable SNI).

---

## 2. fake-TLS, the server side (ServerHello / handshake)

### 2.1 [CRIT] The server's handshake messages go in cleartext
- **Where:** [tls.rs build_certificate](../../qeli/src/protocol/tls.rs#L262),
  [build_finished](../../qeli/src/protocol/tls.rs#L330) — both wrapped in a `0x16`
  (handshake) record in the clear, like the ServerHello.
- **Why it gives it away:** in real TLS 1.3, after ServerHello+CCS **everything**
  (Encrypted Extensions, Certificate, CertVerify, Finished) rides inside `0x17`
  (application_data, encrypted). A cleartext `0x16` Certificate after ServerHello is a
  signature of TLS 1.2 OR a forgery. D2 (and especially D3) catches it deterministically.

### 2.2 [CRIT] The certificate — pseudo-DER, doesn't parse as X.509
- **Where:** [tls.rs build_certificate](../../qeli/src/protocol/tls.rs#L262) — 512 bytes
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
- **Where:** [tls.rs build_server_hello](../../qeli/src/protocol/tls.rs#L187) — only
  supported_versions + key_share, no other extensions; always cipher `1301`.
- **Why it gives it away:** a real server varies the chosen suite and sends a consistent
  set. A constant `1301` + a minimal SH = a weak but stable indicator for D2.

---

## 3. The data channel (application_data)

### 3.1 [HIGH] An explicit 12-byte nonce in every record
- **Where:** [packet.rs encrypt_packet](../../qeli/src/protocol/packet.rs#L179) — a record =
  `0x17 ‖ 0303 ‖ len ‖ nonce(12) ‖ ciphertext+tag`.
- **Why it gives it away:** real TLS 1.3 uses an **implicit** nonce (it's not on the wire).
  A constant 12-byte prefix before the ciphertext in every record is a structural
  fingerprint across the whole data plane (the Feistel-PRP in
  [packet.rs:44](../../qeli/src/protocol/packet.rs#L44) hides the increment, but the very
  fact of 12 "extra" bytes in every record remains). D2 sees this when analyzing the
  inter-record structure.

### 3.2 [MED] One IP packet → exactly one TLS record
- **Why it gives it away:** real TLS cuts/coalesces the stream along boundaries up to 16 KB
  independently of the application messages. The "1 record = 1 MTU packet" correspondence
  (plus the fixed overhead of +33 bytes: 5+12+16) gives a characteristic record-size
  distribution. A contribution to a size ML classifier.

---

## 4. The obfs mode (structure-free)

### 4.1 [CRIT against D2] Full entropy from the first byte — ✅ addressed (WS-fronting)
> **Status:** closed by the option `obf.obfs_fronting = websocket` (the default). The start
> of an obfs connection is wrapped in a WebSocket Upgrade handshake (printable HTTP +
> `\r\n\r\n`), the first packet passes the Ex2/Ex3/Ex4 exemptions. See `protocol/obfs.rs`
> (the `ws` module) and `ObfsStream.kt`. The rollback — `front=none`.

- **Where:** [obfs.rs](../../qeli/src/protocol/obfs.rs) — `[nonce(12)] ‖ ChaCha20-XOR`, no
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

- **Where:** [obfs.rs obfs_datagram_seal](../../qeli/src/protocol/obfs.rs#L54).
- **Why it gives it away:** a stable 12-byte high-entropy prefix on each datagram —
  differs both from QUIC (which has structure) and from STUN/DTLS. Recognizable when a
  sample is available.

---

## 5. QUIC-masking (UDP)

### 5.1 [CRIT] The packet number in cleartext, incrementing
- **Where:** [quic.rs wrap_quic_long/short](../../qeli/src/protocol/quic.rs#L19) write the
  `packet_number` in the clear.
- **Why it gives it away:** real QUIC applies **header protection** — the packet number and
  the low bits of the first byte are encrypted (RFC 9001 §5.4). A visible growing 4-byte PN
  is "not QUIC" deterministically for any QUIC-aware D2.

### 5.2 [CRIT] The Initial packet structure not per RFC 9000
- **Where:** [quic.rs wrap_quic_long](../../qeli/src/protocol/quic.rs#L19).
- **Why it gives it away:** the long-header has no `Token Length`/`Token` fields (for
  Initial) and no mandatory `Length` (a varint of the payload length). A QUIC parser
  rejects the packet on the very first field. Plus the fixed-bit and reserved bits are set
  to constants (`0xC0|type`, `0x40|0x03`), while in real QUIC after header-protection they
  look random.

### 5.3 [MED] Double-nested structure
- **Why it gives it away:** inside the "QUIC payload" an already-structured fake-TLS `0x17`
  record (with its own header and a 12-byte nonce) is placed. Two layers of mismatched
  structure — an extra handle for a deep parse.

---

## 6. Flow behavior (all modes)

### 6.1 [HIGH] The flow shape = "download", not "browsing"
- **Why it gives it away:** the tunnel carries a bidirectional bulky full-MTU flow at a
  ~constant speed. The size/inter-packet-interval distribution differs from web surfing
  (short bursts + idle). Padding ([obfuscate.rs](../../qeli/src/protocol/obfuscate.rs))
  normalizes a **single** packet, but doesn't reproduce the target protocol's distribution
  → an ML classifier (D2) separates "the tunnel" from "browsing".
- **🟡 Phase 1 (partial):** `obf.traffic_shaping` — idle cover traffic at exponential
  (non-periodic) gaps instead of "dead air" while idle
  ([shaper.rs](../../qeli/src/protocol/shaper.rs)). Removes the dead-air signal, but does
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
- **Axis 2 — distribution-matching shaping — research-track:** a shaper to an empirical
  HTTP/3 distribution (it would remove 6.1, 6.2, partly 3.2). Not implemented: there's no
  target traffic model + a harness to validate against ML (see [ROADMAP.md](ROADMAP.md)).
  The QUIC layer (5.x) is deprioritized (the fundamental RFC 9001 ceiling, see ROADMAP).
- **Axis 3 — entropy-fix obfs — ✅ READY (2026-06-05):** WS-fronting (a printable HTTP
  start) + the QUIC-shape for UDP-obfs. It removes 4.1, 4.2.

## Conclusion

"DPI doesn't see it" in the absolute is unattainable (see *The Parrot is Dead*, Houmansadr
2013): full mimicry loses to an active prober. The achievable goal is to close **D1/D2**
fully and **D3** via a real TLS backend. **Axis 1 (`reality-tls`) is implemented:** real
TLS 1.3 on the wire, an active prober goes to the real `target`, and the qeli client sees
a borrowed real cert chain — the deterministic 2.1/2.2 path for this mode is closed.
`fake-tls`/`obfs` remain for D1/D2 scenarios (faster, simpler), `reality-tls` — when the
threat model includes active probing.
