# qeli — security model and status
<!-- normative-sync: security-ipv6-v1 -->

This document describes qeli's **current** cryptography, authentication, and
obfuscation, as well as an honest list of what is protected and what is not. Past audits
(with open items A1/UDP/C2, etc.) are outdated — the problems listed below are closed or
reconsidered.

> **0.8.0 carrier note.** Current `reality-tls` terminates REALITY TLS 1.3, negotiates
> ALPN `h2` and carries raw private qeli records through one genuine long-lived HTTP/2 POST.
> PacketCodec AEAD remains defence-in-depth; the former second fake-TLS handshake/framing is gone.

## The cryptographic core

| Element | Implementation |
|---|---|
| Key exchange | X25519 (ephemeral per-session), `x25519-dalek`; in all modes except `plain` — the PQ hybrid **X25519MLKEM768** (ML-KEM-768, `ml-kem`, the data keys = `HKDF(x25519 ‖ mlkem)`, `derive_keys_hybrid`). `plain` — classic X25519. The secrets with `zeroize` |
| AEAD | ChaCha20-Poly1305 (`chacha20poly1305`) on the qeli data plane; in `reality-tls` the outer TLS 1.3 — AES-128/256-GCM (`aes-gcm`/rustls-ring) |
| Key derivation | HKDF-SHA256, separate `server→client` / `client→server` keys (in `reality-tls` for `TLS_AES_256_GCM` — SHA-384) |
| Passwords | Argon2id (`argon2` 0.5.3), profile **pinned in code** — `crypto::password_hasher()` builds `Params::new(19456, 2, 1, None)` (m=19456 KiB, t=2, p=1 — the OWASP recommendation), so bumping the crate cannot change it silently. VERIFICATION deliberately uses `Argon2::default()`, because the parameters of an existing hash come from its own PHC string, not from ours — that is what lets old hashes keep verifying after a parameter change |
| Anti-replay | a 2048-bit sliding window on the counter in `protocol::packet` (WireGuard-sized since 0.7.1); a separate replay cache of the captured REALITY ClientHello (anti-replay of active probing) |
| Server identity | a long-term X25519 key **per profile** in `/etc/qeli/identity/<name>.key` (0600) |

## The handshake and authentication (the order matters)

1. **The carrier-specific exchange.** `fake-tls` uses its TLS-shaped ClientHello and X25519
   key_share. `reality-tls` first authenticates REALITY TLS 1.3 and establishes genuine H2;
   the private qeli handshake and hybrid X25519MLKEM768 exchange then run inside that carrier.
2. **Channel binding.** The auth_proof mixes in `transcript_hash =
   SHA256(ClientHello‖ServerHello‖Cert‖Finished)`. Tampering with any message in the
   channel breaks the proof (protection against a split-handshake MITM).
3. **Server → client authentication.** The server proves ownership of the static key:
   `HKDF(static_shared ‖ ephemeral_shared ‖ transcript)`. The client checks the proof and
   compares the static key with the **pinned** one (`auth.server_public_key`). **This
   happens BEFORE the credentials are sent** — a MITM cannot intercept the password.
4. **Client → server authentication.** The client sends (inside the AEAD channel)
   `[client_key_proof(32)] [username:password]`; the password is verified by Argon2id.
5. **Data transfer.** Each IP packet → AEAD → (optional padding) → a record.

**Variants of step 1 by wire mode** (steps 2–5 — channel-binding, mutual
authentication, the data plane — are the same in all modes; only the outer wrapper
changes):
- `plain` — without TLS mimicry: a bare exchange of 32-byte X25519 keys, `[len][nonce][ct]`
  records (TCP-only).
- `fake-tls` / `obfs` / `reality` — a pseudo-TLS-1.3 ClientHello (see above).
- `reality-tls` — a real browser-shaped TLS 1.3 ClientHello with a REALITY token. The server
  recognizes the token, terminates TLS, negotiates ALPN `h2`, and accepts one bidirectional
  HTTP/2 POST carrying the private qeli stream with randomized batching. `handrolled=true`
  borrows the target certificate chain and mirrors JA3S; unauthenticated connections are bridged
  to target. This reduces known tells but is not universal Xray/browser behavioral parity.

## What is implemented for protection

- **Server key pinning** (`auth.server_public_key` on the client). On a mismatch — `SERVER
  KEY MISMATCH`, the connection breaks.
- **`auth.require_client_key_proof`** (server): the client must prove knowledge of the
  pinned key, otherwise it's refused. Additionally: in this mode the server **does not
  transmit** its static key — it's hidden from scanners.
- **Per-profile authorization** (`users.profiles`): a user of one interface won't connect
  to another even with the correct password.
- **Brute-force**: a hard lockout **per source IP only**; by username there is an adaptive
  tarpit with NO lockout, so that guessing a name cannot lock a real user out (L1) (the
  window/threshold/block are
  configurable).
- **UDP anti-amplification**: the client initial is padded to ≥1200 bytes, the server
  rejects small initials — you can't use the server as a reflector.
- **The web admin**: HTML pages authenticate with a **signed session cookie**
  `qeli_session` (HMAC-SHA256, the key = HKDF(signing secret, salt = the admin password
  hash, info = the session generation); the TTL comes from `web.session_ttl_secs` and is
  clamped to 30 days). By DEFAULT (`web.persist_session_key = true`) the signing secret is
  persisted to a 0600 file, so sessions SURVIVE a restart; set it to `false` for a
  per-process secret that ends every session on restart (H-4). `POST /api/logout` bumps the
  session generation, which invalidates every token already issued.
  The cookie is minted by `POST /api/login` after an Argon2id password check. The pages
  **deliberately do not consider** HTTP Basic: otherwise Argon2 would run on every GET
  with no rate limit. Basic remains for the API/`curl` path and goes through the
  rate-limited `AuthGuard`. Plus same-origin CSRF on mutating requests and a
  path-whitelist for writing configs/reading logs.
- **Crash-safe DNS**: restoration of `/etc/resolv.conf` (including the symlink) with a
  persistent backup and self-healing at start.

## Obfuscation (wire modes)

| Mode | What's on the wire | Against what |
|---|---|---|
| `plain` (TCP) | no obfuscation: a bare X25519 exchange + `[len][nonce][ct]` records | nothing (trusted networks); the cheapest on CPU |
| `fake-tls` (TCP/UDP, default) | a pseudo-TLS-1.3 handshake + Application-Data records; GREASE, a random extension order, a PQ key_share | passive/signature-based DPI |
| `obfs` (TCP) | the whole flow XOR'd with a ChaCha20 keystream (a shared PSK); the start masked as a WebSocket Upgrade (printable HTTP) | DPI that catches *known* protocols (fake-TLS/JA3) + the entropy-based "fully encrypted" detection (GFW/TSPU) |
| `reality` (TCP) | "our" ClientHello is recognized **cryptographically** (a token in the `session_id`); a "foreigner"/prober is **proxied to the real `target:443`** | active probing (`openssl s_client` sees the real site) |
| `reality-tls` (TCP) | **real** TLS 1.3 + one genuine H2 streaming POST with randomized batching; with `handrolled`, the target's borrowed cert + mirrored JA3S shape | removes the legacy inner fake-TLS/record-boundary tells and reduces known probe/fingerprint signals; no universal indistinguishability guarantee |
| QUIC-masking (UDP) | datagrams under a QUIC v1 header (over `fake-tls`) | DPI expecting QUIC/HTTP3 |

Additionally: padding (probability/randomize), length normalization, handshake
fragmentation, a mode-dependent idle heartbeat with jitter (forced off in Reality/H2), **a nonce via a 96-bit Feistel permutation**
(there's no incrementing counter on the wire — a frequent fingerprint of homegrown VPNs).

## What qeli does NOT protect (honestly)

- **fake-TLS is not real TLS.** In `fake-tls` mode the certificate is a pseudo-DER stub.
  Against **active** probing REALITY is needed: `reality` (proxy) bridges foreigners to a
  real site, while **`reality-tls`** uses real TLS 1.3 plus genuine H2 and, with
  **cert-borrowing** (`handrolled=true`), hands the client the target's captured cert
  chain and mirrors its JA3S shape (not complete Xray/browser parity; see CONFIG.md/DPI-AUDIT.md). Without REALITY,
  `fake-tls`/`obfs` target passive DPI.
- **Post-quantum** — the **X25519MLKEM768** hybrid is now a working KEX of the **inner**
  qeli tunnel in ALL modes except `plain` (`fake-tls`/`obfs`/`reality-tls`/UDP): a real
  ML-KEM-768 encaps/decaps, the data keys = `HKDF(x25519_shared ‖ mlkem_shared)`
  (`derive_keys_hybrid`). The server REQUIRES the X25519MLKEM768 share for non-`plain` (no
  silent downgrade; domain separation by the salt). Managed clients (C#/Kotlin) take
  ML-KEM from the core via the C-ABI/JNI (BouncyCastle has no ML-KEM). Protection against
  harvest-now-decrypt-later regardless of the wrapper.
- **The `obfs` keystream** is limited to 256 GiB per direction per session — on exceeding
  it the connection fail-safe reconnects (without reusing the keystream).
- **TOFU by default.** If the client hasn't pinned the key and the server doesn't require
  `require_client_key_proof`, the first connection is accepted without a check (the
  candidate key is printed). For strict protection enable `require_client_key_proof`.
- The code **has not undergone an external audit** and has no public CVE history.

## The configuration format

A single **flat-INI** for the server, the client, and the user database (TOML/JSON fully
dropped). Users are `[user:<name>]`/`[group:<name>]` sections. The minimal client config —
the `[qeli]` section, which is also expanded from a `qeli://` link (QR import). Details —
`docs/*/manuals/CONFIG.md`.

## The auth-response transport

After a successful login the server sends (inside the AEAD channel) a self-describing
keyed-JSON `OK:{client_ip, server_ip, dns, dns_port, routes:[…], obfuscation:{…}}` — each
parameter under its own key, which precludes field misalignment. The pushed-DNS is not
sent when the in-tunnel DNS proxy is off (otherwise the client got a dead resolver).
This is an internal wire payload, not a user-facing JSON configuration or file.

## IPv6, TAP, NetworkPlan v2, and DATA_FRAG

- **Capability negotiation.** Inner IPv6, NetworkPlan v2, and UDP DATA_FRAG_V1 are enabled
  only through authenticated capability bits. `required` mode must fail when the peer or
  platform adapter cannot acknowledge the complete requested contract.
- **Family isolation.** Outer IPv4/IPv6 only selects the path to the server; it does not
  select the inner mode. A missing inner family is blocked fail-closed in full-tunnel mode;
  direct egress requires explicit `allow_ipv4_leak`/`allow_ipv6_leak`, both false by default.
- **TUN and TAP.** TUN accepts only valid IPv4/IPv6 packets. TAP is a local Ethernet-framing
  adapter over qeli's L3 wire: IPv4/IPv6 pass, required ARP/NDP/Router Solicitation is handled
  locally, and VLAN/STP/LLDP or arbitrary EtherTypes do not turn it into a transparent bridge.
- **Fragmentation.** DATA_FRAG decouples inner MTU from the outer UDP budget. Fragments are
  accepted only after capability negotiation and authentication, with strict size/count/time
  reassembly bounds and a separately derived MAC context. This limits memory/CPU
  amplification, while reassembly remains a fuzz and soak-test surface.
- **PMTU.** IPv6 routers do not fragment: ICMPv6 Packet Too Big and the live UDP probe are
  critical. Forged or late replies must not raise another path epoch's budget; uncertainty
  uses the conservative budget or rejects the connection.

## Code quality

- Unit tests: **hundreds and growing** (`cargo test --workspace`); the 0.7.16 release gate
  reported 635 library tests plus 8 CLI/config tests. Treat that as a dated snapshot — the
  current CI `build-test` log is the source of truth. Covered: crypto
  round-trip, the **2048-bit replay window** on the server and client, PRP bijectivity, a
  channel-binding simulation, the keyed auth-OK round-trip, the qeli:// link round-trip,
  IpPool/RateLimiter/FailedAuthTracker, the INI round-trip, obfs roundtrip TCP +
  per-datagram UDP, plain raw framing + the TCP-only guard, the REALITY token seal/open,
  the realtls handshake interop with rustls (both cipher suites + the PQ hybrid),
  cert-borrowing, NewSessionTicket, per-profile authorization, the QR render.
- The `cargo build --release` build is clean, **0 warnings**; the tree is
  rustfmt/clippy-normalized.
- CI in 0.7.16: `.github/workflows/ci.yml` — fourteen top-level jobs. The current set is always in the file
  itself (a list here would inevitably rot), so by intent: the hash check of the committed
  native cores (`native-libs`), build + the whole test suite (`build-test`), a real Debian
  package/install check (`deb-package`), installer lint (`shellcheck`), formatting and clippy
  `-D warnings` (`lint`), the documentation and version-consistency checks (`docs` →
  `scripts/check_docs.py` + `scripts/sync_version.py`), `cargo audit` against the RUSTSEC
  database (`security-audit`, marked `# HARD GATE` in the file), compilation of the Android
  / Windows / macOS / iOS clients and the router cross-build (`keenetic-cross`), plus
  fuzzing — a short smoke on push and a long scheduled run. No job carries
  `continue-on-error: true`; `fuzz-smoke` deliberately remains a hard gate even though it
  rides the nightly toolchain. A separate workflow,
  `.github/workflows/dco.yml`, requires a `Signed-off-by` line on every PR commit. A local
  run of the full gate — `scripts/lab_sync_build.py` (sync → build → test → clippy on the
  lab).
