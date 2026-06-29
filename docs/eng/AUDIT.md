# qeli — security model and status

This document describes qeli's **current** cryptography, authentication, and
obfuscation, as well as an honest list of what is protected and what is not. Past audits
(with open items A1/UDP/C2, etc.) are outdated — the problems listed below are closed or
reconsidered.

## The cryptographic core

| Element | Implementation |
|---|---|
| Key exchange | X25519 (ephemeral per-session), `x25519-dalek`; in all modes except `plain` — the PQ hybrid **X25519MLKEM768** (ML-KEM-768, `ml-kem`, the data keys = `HKDF(x25519 ‖ mlkem)`, `derive_keys_hybrid`). `plain` — classic X25519. The secrets with `zeroize` |
| AEAD | ChaCha20-Poly1305 (`chacha20poly1305`) on the qeli data plane; in `reality-tls` the outer TLS 1.3 — AES-128/256-GCM (`aes-gcm`/rustls-ring) |
| Key derivation | HKDF-SHA256, separate `server→client` / `client→server` keys (in `reality-tls` for `TLS_AES_256_GCM` — SHA-384) |
| Passwords | Argon2id (`argon2`), parameters m=16384,t=2,p=1 |
| Anti-replay | a 2048-bit sliding window on the counter in `protocol::packet` (WireGuard-sized since 0.7.1); a separate replay cache of the captured REALITY ClientHello (anti-replay of active probing) |
| Server identity | a long-term X25519 key **per profile** in `/etc/qeli/identity/<name>.key` (0600) |

## The handshake and authentication (the order matters)

1. **The ephemeral exchange.** The client sends a fake-TLS ClientHello (with GREASE and a
   randomized extension order → the JA3 changes per-connection), the server —
   ServerHello/Certificate/Finished. The shared secret — X25519 from the key_share.
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
- `reality-tls` — a **real** browser (Chrome JA4) TLS 1.3 ClientHello with a REALITY token
  in the `session_id` = `HKDF(X25519(eph, reality_pub) ‖ short_id)`. The server
  cryptographically recognizes "ours" (opens the token with the profile private key,
  checks against `short_ids`), terminates real TLS 1.3 (rustls **or** hand-rolled), and
  carries the qeli tunnel INSIDE it; the KEX — the PQ hybrid X25519MLKEM768. A
  "foreigner"/prober is transparently proxied to the real `target:443`. With
  `handrolled=true` the server **borrows the target's real cert chain** (cert-borrowing,
  auto-refresh 12h) and mirrors its JA3S/ServerHello — parity with Xray-REALITY.

## What is implemented for protection

- **Server key pinning** (`auth.server_public_key` on the client). On a mismatch — `SERVER
  KEY MISMATCH`, the connection breaks.
- **`auth.require_client_key_proof`** (server): the client must prove knowledge of the
  pinned key, otherwise it's refused. Additionally: in this mode the server **does not
  transmit** its static key — it's hidden from scanners.
- **Per-profile authorization** (`users.profiles`): a user of one interface won't connect
  to another even with the correct password.
- **Brute-force**: a lockout by the **user+IP pair** (the window/threshold/block are
  configurable).
- **UDP anti-amplification**: the client initial is padded to ≥1200 bytes, the server
  rejects small initials — you can't use the server as a reflector.
- **The web admin**: Basic Auth with Argon2id, same-origin CSRF on mutating requests, a
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
| `reality-tls` (TCP) | **real** TLS 1.3 (Chrome JA4) carries the tunnel inside; with `handrolled` — the target's borrowed real cert + a mirrored JA3S | active probing + JA3/JA4 + entropy-based DPI (indistinguishable from HTTPS on the wire) |
| QUIC-masking (UDP) | datagrams under a QUIC v1 header (over `fake-tls`) | DPI expecting QUIC/HTTP3 |

Additionally: padding (probability/randomize), length normalization, handshake
fragmentation, an idle-heartbeat with jitter, **a nonce via a 96-bit Feistel permutation**
(there's no incrementing counter on the wire — a frequent fingerprint of homegrown VPNs).

## What qeli does NOT protect (honestly)

- **fake-TLS is not real TLS.** In `fake-tls` mode the certificate is a pseudo-DER stub.
  Against **active** probing REALITY is needed: `reality` (proxy) bridges foreigners to a
  real site, while **`reality-tls`** carries the tunnel inside real TLS 1.3 and, with
  **cert-borrowing** (`handrolled=true`), hands the client the target's real captured cert
  chain (parity with Xray-REALITY; see CONFIG.md/DPI-AUDIT.md). Without REALITY,
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
`docs/CONFIG.md`.

## The auth-response transport

After a successful login the server sends (inside the AEAD channel) a self-describing
keyed-JSON `OK:{client_ip, server_ip, dns, dns_port, routes:[…], obfuscation:{…}}` — each
parameter under its own key, which precludes field misalignment. The pushed-DNS is not
sent when the in-tunnel DNS proxy is off (otherwise the client got a dead resolver).

## Code quality

- Unit tests: **225** (crypto round-trip, the **2048-bit replay window** on the server and
  client, PRP bijectivity, a channel-binding simulation, the keyed auth-OK round-trip, the
  qeli:// link round-trip, IpPool/RateLimiter/FailedAuthTracker, the INI round-trip, obfs
  roundtrip TCP + per-datagram UDP, plain raw framing + the TCP-only guard, the REALITY
  token seal/open, the realtls handshake interop with rustls (both cipher suites + the PQ
  hybrid), cert-borrowing, NewSessionTicket, per-profile authorization, the QR render).
- The `cargo build --release` build is clean, **0 warnings**; the tree is
  rustfmt/clippy-normalized.
- CI: `.github/workflows/ci.yml` — **two hard gates** (block a merge): build+test
  (`cargo test --all`) and lint (`cargo fmt --check` + `cargo clippy --all-targets -- -D
  warnings`); **+ three soft gates**: compilation of the Android (gradle) / Windows /
  macOS (dotnet) clients. A local run of the full gate — `scripts/lab_sync_build.py`
  (sync → build → test → clippy on the lab).
