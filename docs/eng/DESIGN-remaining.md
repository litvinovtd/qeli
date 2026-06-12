# qeli — REALITY development stages: status and remainder (updated 2026-06-06)

> A current summary. The detailed design of the axes/applications is below (from
> 2026-06-05) and is **historical**: Axis 1 (REALITY / `reality-tls`), PQ-KEX
> (X25519MLKEM768), NewSessionTicket, and **cert-borrowing are fully implemented and
> verified** on all 4 clients (Rust / Android / Windows / macOS). The lower section is
> kept as a design rationale — not as a list of unsolved items.

## ✅ Done and verified — the SERVER side of REALITY is CLOSED

**The base realtls stack (former M1–M3, A1–A2):** M1 the crypto-detect in
`session_id`; M2.1 the Chrome ClientHello (JA4 `t13d1516h2`); M2.2 the key schedule +
record (verified against RFC 8448); M2.3 `client_handshake` (interop with rustls); M2.4
the server termination (rustls); M3 `RealTlsStream` (the tunnel inside TLS); A1 the
sans-IO core; A2 the C ABI.

**Strengthening REALITY (the 2026-06-06 round, partly beyond the original plan) — 153 tests green, clippy clean:**
- **P1 anti-replay** — a replay of an intercepted ClientHello → bridge (closes active replay probing). e2e on the lab.
- **P2 PQ key_share in the ClientHello** — X25519MLKEM768 in both builders (fake-tls + realtls), 1216 B on the wire.
- **L3.1 TLS_AES_256_GCM_SHA384** — a second cipher suite across the whole realtls stack (the SHA-384 key schedule + the AES-256-GCM record). RFC 8448 KAT (a SHA-256 regression) + an interop of both ciphers.
- **L3.2 the hybrid X25519MLKEM768 KEX** (= the PQ hybrid P3#7, but implemented INSIDE real TLS) — the server ML-KEM-encapsulates / the client decapsulates, the shared secret `ML-KEM ‖ X25519`. An interop of 4 combos.
- **L3.3–L3.5 the borrowed-ServerHello (a hand-rolled server instead of rustls)** — `terminate_handrolled` + `RealTlsStream`, a branch in `reality.rs` under the flag `obf.tls.reality_proxy.handrolled`. **Auto-probe**: at profile start the server itself goes to `target:443`, takes the shape of its ServerHello (cipher / PQ-or-not / extension order) and mirrors it → **the JA3S of our ServerHello == the real site's**. Verified live for **microsoft** (0x1302/[sv,ks]/X25519) AND **cloudflare** (0x1301/[ks,sv]/PQ) — different shapes, any domain from the config, with no hardcode.
- **The Rust realtls client** — the mode `obf.mode = reality-tls` (`client_handshake` + `RealTlsStream`); after L3 it automatically pulls AES-256/hybrid (the suite is learned from the ServerHello).
- **L3.6 the borrowed CERT-CHAIN (cert-borrowing, 2026-06-06)** — beyond the borrowed-ServerHello (L3.3–L3.5 mirrored only the SHAPE of the ServerHello/JA3S): `realtls/server.rs::capture_target_cert` takes from `target:443` the **real certificate chain** (a full TLS handshake with the target, derivation of the ECDHE x25519/hybrid via `mlkem::DecapKey`, decryption of the flight, lifting the body of the Certificate message), and the hand-rolled server hands IT to the qeli client instead of self-signed/dummy (`terminate_handrolled`/`server_handshake` got `borrowed_cert: Option<&[u8]>` → `hs_msg(0x0b, body)`; signed with our own key, the client doesn't validate — the cert is encrypted in TLS 1.3, non-breaking). `BorrowState{profile,cert}` under an `RwLock` on `ProfileRuntime.reality_borrow`; **auto-refresh every 12h** (the target certs rotate; on failure it keeps the cache). Live e2e on .10: "borrowed TLS shape from www.microsoft.com:443 … (real cert chain: captured)" + the client `Auth OK`. Now there's parity with Xray-REALITY both in the ServerHello shape AND in the certificate itself.

The net result on the wire: a browser ClientHello → a valid TLS 1.3 → a ServerHello
indistinguishable from the target by JA3S → an active prober goes to the real site.

## ⏳ Remaining to implement

### The client phase (the main remainder — so that `handrolled` works in production)
1. **Rust client: a live e2e tunnel** through the handrolled server (mode=reality-tls). ✅ **DONE 2026-06-06.** The release binaries: the client (mode=reality-tls) ↔ the handrolled server via `reality.rs`: the log `Qeli client detected → hand-rolled TLS established → AUTH OK → Client connected IP`. The transport+control-plane are proven. *Along the way a critical peek-truncation bug was uncovered and fixed* (`reality.rs` peeked 768 B, while the realtls-CH with PQ is ~1540 B → the x25519 key_share after the 1216-B PQ entry got cut → the token didn't validate → a silent bridge; the fix: peek the whole CH + accumulate segments). **The data plane is closed too:** a two-host run (.10 server + .11 client) → server→client ping through the tunnel 4/4, 0% loss (the loopback EBUSY went away on separate hosts).
2. **The sans-IO / FFI core** (`realtls/sansio.rs`) — ✅ **DONE 2026-06-06.** Both cipher suites (the suite is in the `ExpectFlight` state) + the hybrid X25519MLKEM768 (the ML-KEM `dk` is stored in `ExpectServerHello`, decaps at group 0x11ec) + `finished_verify`/a dynamic Finished length. The tests `sansio_interop_handrolled_pq_sha384` (sans-IO ↔ handrolled, AES-256/SHA-384/PQ) + `sansio_interop_with_rustls` (AES-128) green. `ffi.rs`/`jni.rs` unchanged — the C ABI is as before, the native clients get this transparently.
3. **Android (Kotlin, `qeli-android`)** — ✅ **DONE 2026-06-06.** The JNI bridge (A3+A4) was already there (`RealTls.kt` ↔ `realtls/jni.rs`, `QeliService.RealTlsTransport`/`doRealTlsHandshake`, the dispatch `wireMode=="reality-tls"`, `Config.kt` parses `reality_short_id`/`server_public_key`). The bundled `.so` were stale (pre-item-2 → AES-128-only) → I rebuilt the cdylib via cargo-ndk on .11 (arm64-v8a 567K + x86_64 658K, the recipe in reference_qeli_lab_build), the APK rebuilt+installed on the emulator. **Two live e2e emulator↔handrolled, both ping 0% loss:** target microsoft (AES-256/SHA-384, no-PQ) + target cloudflare (AES-128/SHA-256, **hybrid ML-KEM decaps live**). The C-ABI/JNI code unchanged — item 2 gave SHA-384/hybrid transparently. Covered both cipher suites, both KEX, both ext orders.
4. **qeli-win / qeli-mac (C#)** — ✅ **DONE 2026-06-06.** The P/Invoke bridge (`Vpn/RealTls.cs` → the C-ABI `qeli_realtls_*`) and the reality-tls wiring (`VpnTunnel.cs`) were already there. I rebuilt the native libs from the post-item-2 source on .10: Windows `qeli.dll` (x86_64-pc-windows-gnu+mingw, 3.7MB) + macOS `libqeli.dylib` (zigbuild universal2, 8.8MB, headerpad). **A live Windows e2e** (a .NET harness P/Invoke → the handrolled server): microsoft (AES-256/SHA-384) + cloudflare (hybrid PQ) — both ESTABLISHED, the server `hand-rolled TLS established`. The Windows client rebuilt (dotnet Release). A mac live test is impossible (no Mac), but the dylib = the same code. The remainder (release packaging, not functionality): a signed Qeli.app + a Windows publish — on request.
5. **The production migration** — switch the `maxobf` profile to the token mode of REALITY (`short_ids`) + `handrolled`, coordinated with an update of ALL clients (breaking). **Medium, risky.**

### P4 — minor tell fixes of the authenticated session (server+client)
6. **NewSessionTicket** — ✅ **DONE 2026-06-06.** The handrolled server sends 1-2 post-handshake NST (RFC 8446 §4.6.1, `build_new_session_ticket` on the server app-key); the rustls path — a `ticketer`+`send_tls13_tickets=2`. The client (`RealTlsStream`) skips post-handshake records, the seq stays in sync. Closed the tell "a real TLS server sends tickets, but we don't".
7. **AAD on the REALITY token** — bind the `session_id` to the rest of the ClientHello (currently no AAD). Breaking, both sides, bundle with a client rebuild. **Little code, coordination.**

### The long axes (details below — not started)
- **Axis 2B** distribution-matching shaping (anti-ML, a new `protocol/shaper.rs` ×3 clients).
- **Axis 2A/2C** QUIC per RFC 9001 OR real QUIC (`quinn`/MASQUE).
- **P3#9** multipath / MASQUE / WireGuard-compat / eBPF-fastpath (long-term).

### The recommended next step
The client phase (items 1–4) and cert-borrowing are **finished on all 4 clients**. The
real remainder: **the production migration (item 5)** — switch the live `maxobf` profile
to the token mode of REALITY + `handrolled` (breaking, coordinated with an update of all
clients). The rest — AAD (item 7), shaping (Axis 2B), and QUIC-per-RFC — is
deprioritized/research-track (see [ROADMAP.md](ROADMAP.md)).

---

# qeli — detailed design of the large remaining items

The state as of 2026-06-05. The non-large backlog (P2) is closed. Below — what remains,
the mechanics, concrete steps by component/client, the forks, and a volume estimate.
The basis: fake-TLS (`protocol/tls.rs`), obfs+WS-fronting (`protocol/obfs.rs`),
QUIC-masking (`protocol/quic.rs`), the data-plane AEAD (`protocol/packet.rs`), the
handshake (`server/handler.rs`, `client/mod.rs`), 4 clients
(Rust/Android/qeli-win/qeli-mac).

---

## 🔴 Axis 1 — real REALITY / TLS on the client

### Why
It closes at once DPI tells 1.1–1.6 (no ALPN, a non-browser JA3/JA4, few
cipher/groups/extensions), 2.1–2.3 (the server sends a pseudo-ServerHello and a
pseudo-DER certificate in the clear), 3.1 (an explicit 12-byte nonce in every record),
and — most importantly — **active probing (D3)**. Currently the server distinguishes
"ours" by the *absence of ALPN* (`server/reality.rs::has_alpn_extension`) — this is the
worst single tell and at the same time the reason the client can't send an honest
ClientHello.

### How it will work (the REALITY scheme, as in Xray)
1. **The server identity** — already exists: a per-profile X25519 long-term key
   (`/etc/qeli/identity/<name>.key`), the pubkey is pinned on the client
   (`auth.server_public_key`). In REALITY it's also the "REALITY key".
2. **The client** builds a **real** TLS 1.3 ClientHello for `SNI=<dest>` (a real large
   site, e.g. www.microsoft.com) with a browser fingerprint (uTLS-grade). An
   authenticator is embedded in the ClientHello:
   `auth = HKDF(X25519(eph_priv, reality_pub) ‖ short_id)`, placed in the `session_id`
   (32 bytes) + a `short_id` marker. The client's ephemeral X25519 pair is placed in the
   honest `key_share` (like a browser) — qeli uses it as the ephemeral for the tunnel.
3. **The server** on an incoming TLS:
   - computes `auth` from the client's `key_share` + its REALITY-priv; if it matches a
     known `short_id` → this is a qeli client;
   - **for a qeli client**: it completes TLS 1.3 itself, with an ephemeral self-signed
     certificate (the client does NOT verify it — trust via the X25519 auth), and brings
     up the tunnel INSIDE the established TLS session;
   - **for a foreigner/prober**: it transparently proxies all the TLS to the real
     `dest:443` (as `reality.rs` does now), the prober sees the real site with a real
     certificate.
4. **The data plane**: the VPN frames ride as TLS `application_data` of the REAL session
   (confidentiality is provided by the TLS itself). Our `PacketCodec` (the 0x17 records +
   an explicit nonce) is removed or degenerates into a light framing inside the TLS
   stream. X25519+ChaCha remain for auth/channel-binding, but the encryption on the wire
   is TLS.

The net result on the wire: an honest browser ClientHello to a real domain, a valid TLS
handshake, an active prober gets the real site. The JA3/JA4/ALPN/cert tells disappear,
because the bytes are generated by a real TLS stack.

### What specifically to do
- **The server** (`server/reality.rs` + `handler.rs`): replace the ALPN heuristic with
  the REALITY detect (the auth from key_share+the identity-priv); the "ours" branch →
  terminate TLS (rustls as a server with an on-the-fly cert) and run the tunnel inside;
  the "foreigner" branch → the existing bridge to the target. Config:
  `obf.tls.reality.enabled`, `dest`, `short_ids`.
- **The Rust client** (`client/mod.rs`, a new `protocol/realtls.rs`): replace
  `FakeTlsHandshake::build_client_hello` with an honest TLS stack with the auth embedded.
- **Android / qeli-win**: the same honest ClientHello + the auth-embed.

### The fork (key) — what to do honest TLS with on the clients
- **A uTLS-grade fingerprint requires a customizable TLS stack.** In Go that's uTLS; in
  Rust/Kotlin/C# there's no native equivalent. The options:
  - **(A) A shared Rust TLS core via FFI:** one stack (rustls + a manual tuning of the
    ClientHello to Chrome, or a BoringSSL binding) — on Android via JNI, on Windows via
    P/Invoke. One fingerprint on all clients, full control of the auth-embed. The largest
    volume (NDK/cross-build/the JNI bridge), but the only "correct" one.
  - **(B) Platform TLS:** Android Conscrypt (BoringSSL — close to Chrome), qeli-win
    SChannel (a Windows fingerprint), Rust rustls. Each one separately is plausible, but
    the fingerprints are DIFFERENT, and **embedding auth in the session_id is not
    possible with Conscrypt/SChannel** — that's a blocker. So (B) doesn't really close
    the REALITY auth.
  - **The conclusion:** real REALITY needs (A). A smaller alternative — the **Trojan
    style (ACME cert)**: your own domain + a Let's Encrypt certificate, the client does
    ordinary TLS to your domain, the tunnel inside. Simpler (native TLS will do), but the
    domain is identifiable and SNI=your domain (REALITY hides behind someone else's big
    site).

### Volume: **large** (weeks). First decide (A) the FFI core vs (Trojan/ACME).

---

### DECIDED 2026-06-05: (A1) a pure-Rust `realtls` core, the Rust client first

M1 (the crypto-detect in `session_id` + ALPN) is done and verified live. Next — real TLS
1.3 on the client **with our own code** from the existing primitives
(X25519/HKDF/SHA-256/AEAD), rustls termination on the server; FFI on
Android(JNI)/Windows(P/Invoke) — later, after Rust.

**The auth mechanism is NOT changed:** `crypto::reality::{seal,open}_session_id` is
reused as is (the auth is still in `legacy_session_id`, the ephemeral X25519 — in
`key_share`). What changes: (1) the ClientHello shape → byte-grade Chrome; (2) after the
hello there's a **real** TLS-1.3 handshake; (3) the data plane rides as TLS
`application_data` (not `PacketCodec`).

A new module `src/protocol/realtls/`: `clienthello.rs`, `keyschedule.rs`, `record.rs`,
`client.rs`; on the server — termination via `rustls` in `server/reality.rs`.

- **M2.1 — the Chrome ClientHello** (an offline test). The exact Chrome fingerprint (JA4 `t13d…h2_…`):
  the Chrome set/order of extensions with GREASE (SNI, ext_master_secret, renegotiation_info,
  supported_groups [GREASE,x25519,secp256r1,…], ec_point_formats, session_ticket, ALPN
  [h2,http/1.1], status_request, signature_algorithms (the Chrome list), signed_cert_timestamp,
  key_share [GREASE-empty, x25519], psk_key_exchange_modes, supported_versions [GREASE,1.3,1.2],
  compress_certificate, ALPS). `session_id`=the REALITY token (seal), `key_share.x25519`=our ephemeral.
  Test: compute the JA4/JA3 and check the set against a Chrome reference + stability under a varying GREASE.
- **M2.2 — the key schedule + record layer** (an offline test on **RFC 8448** trace vectors).
  HKDF-Expand-Label (SHA-256), early/handshake/master secrets, traffic keys, the transcript hash;
  record protect/unprotect (ChaCha20-Poly1305 + AES-128-GCM → the `aes-gcm` crate), nonce=iv⊕seq,
  the inner content-type, padding. Test: the byte-for-byte traces of RFC 8448 match.
- **M2.3 — the client state machine** (an integration test against a rustls server). CH → SH (extract
  the server key_share, derive the handshake secrets) → {EncryptedExtensions, Certificate, CertVerify,
  Finished} encrypted (decrypt, transcript; **the cert chain/CertVerify NOT validated** —
  trust is provided by the inner qeli-auth M3; **the server Finished is verified**) → {CCS, client Finished}
  → the application secrets. Test: a local rustls server (self-signed, TLS1.3-only) ↔ our client.
- **M2.4 — the server REALITY termination** (a lab e2e). The "ours" branch → the stream into a rustls
  `ServerConnection` (ServerConfig: TLS1.3-only, an on-the-fly self-signed cert via
  `ResolvesServerCert`, no client-auth) → the established TLS into the tunnel; the "foreigner" → the existing
  proxy-bridge. The `rustls` crate (server-only). Test: a realtls client ↔ a rustls server on the lab.
- **M3.1/3.2/3.3 — the data plane in TLS**: the VPN frames as `application_data`; `PacketCodec`
  for the reality-real mode is removed (confidentiality is provided by TLS), the inner qeli-auth
  (the server-proof + channel-binding) is preserved → mutual-auth, which justifies skip-cert. A sub-mode
  `obf.mode = reality-tls` (the old fake-TLS-reality stays for rollback). A lab e2e: a full tunnel
  through real TLS, the JA4 taken with tcpdump and checked against Chrome, the prober still → microsoft.
- **Then (after Rust):** the FFI realtls core on Android(JNI)+qeli-win(P/Invoke) — a unified fingerprint.

**New dependencies:** `aes-gcm` (the TLS cipher), `rustls` (the server-term). Caution: the manual
record layer is crypto-sensitive → a test on RFC 8448 is mandatory; rustls as a forcing function
for the client's correctness.

---

## 🔵 APPLICATIONS — the FFI realtls core (decided 2026-06-05: sans-IO, Android first)

M3 is closed — real TLS on the Rust client. So that a unified Chrome fingerprint is on
ALL clients (Android/qeli-win are still fake-TLS), we extract the realtls core into a
native lib.

**The architecture: a sans-IO buffer FFI.** The Rust core is a pure byte-in/byte-out
state machine (no tokio/socket). The platform (Kotlin/C#) owns the socket+TUN and calls
Rust for the TLS crypto.

- **A1 — the sans-IO core** (`realtls/sansio.rs`, pure Rust): `SansIoClient` — a handshake
  state machine over the building blocks (clienthello/keyschedule/record). `new(reality_pub,
  short_id, sni, eph) -> (Self, client_hello_bytes)`; `recv(&[u8]) -> Progress{NeedMore |
  Send(Vec<u8>) | Established}`; after Established `seal(pt)->record` / `open(rec)->(type,pt)`.
  It mirrors the logic of the async `client_handshake`, but inverts the IO (buffers the input, emits the output).
  Test: run against rustls, manually shuttle the bytes via duplex/TcpStream.
- **A2 — the C ABI** (`ffi.rs` + `[lib] crate-type=["cdylib","staticlib","rlib"]`):
  `#[no_mangle] extern "C"` over SansIoClient — an opaque handle (Box→raw ptr), buffers (ptr+len),
  out-lengths, error codes, `catch_unwind` (no panics across the FFI). `qeli_realtls_{new,client_hello,
  recv,seal,open,free}`.
- **A3 — the Android NDK cross-build**: `aarch64-linux-android`+`x86_64-linux-android` (the emulator),
  `cargo-ndk`; the .so → `jniLibs/<abi>/`. On .11 (has the NDK/emulator).
- **A4 — the JNI bridge (Kotlin)**: `external fun` + loading the .so; in the client's socket loop, at
  mode=reality-tls — a handshake via the FFI, then seal/open around the existing qeli protocol
  (nested, as in Rust).
- **A5 — an Android e2e** on the .11 emulator against a reality-tls server on .10.
- Then **qeli-win (P/Invoke)**: the target `x86_64-pc-windows-*`, a DllImport in C#, likewise.

New: the `[lib]` cdylib in Cargo.toml; `cargo-ndk` on .11. The last step of the whole project — the **UI**.

---

## 🔴 Axis 2 — shape mimicry + QUIC header-protection

Two relatively independent parts.

### 2A. QUIC header-protection (DPI tells 5.1/5.2)
**Why.** Currently `protocol/quic.rs` writes the packet number **in the clear** and
incrementally; the Initial packet is not per RFC 9000 (no Token Length/Token, no varint
Length). QUIC-aware DPI rejects it on the first field. (UDP-obfs already got a QUIC
short-header shape — tell 4.2 closed — but that's only "looks like QUIC", not real
QUIC.)

**How it will work.** Bring the UDP wrapper to RFC 9001:
- header protection: mask the first byte (the low bits) + the packet number with a mask
  from `AES-ECB`/`ChaCha` over a `sample` of the ciphertext (RFC 9001 §5.4);
- the correct Initial structure (token length, length varint), a packet-number
  encoding of 1–4 bytes; the reserved bits look random after protection.

**What to do.** Rewrite the `quic.rs` wrap/unwrap per RFC 9001 (the header-protection
keys from HKDF), in sync in Android `Quic.kt` and qeli-win `Quic.cs`. Or radically —
item 2C below (real QUIC via `quinn` / MASQUE), which makes 2A unnecessary.

### 2B. Distribution-matching shaping (DPI tells 6.1/6.2)
**Why.** Even with ideal TLS, the flow shape (a bidirectional full-MTU bulky flow + a
periodic heartbeat beacon) ≠ browsing → an ML classifier (D2) separates the tunnel. The
current padding normalizes a *single* packet, but not the distribution.

**How it will work.** A shaper layer between the data plane and the wire:
- **token-bucket / pacing**: packets are released on a schedule sampled from an
  **empirical model** (packet size + inter-packet interval) of a real HTTP/3 session to a
  CDN (video/web);
- **size-shaping**: real frames are cut/padded to the target size distribution;
- **chaff fill**: empty slots are filled with cover traffic (encrypted garbage, dropped
  on receipt);
- **burst smoothing**: bursts are smeared out; the heartbeat dissolves into the general
  pacing (removes the beacon).
A relaxation of the known defenses (FRONT/GLUE, DynaFlow). The shape profile — in the
config (`obf.shaping.profile = http3-video|web|off`), the model — a built-in set of
histograms.

**What to do.** A new `protocol/shaper.rs` (a queue + scheduler + chaff), wedged into
`RunTunnelLoop`/`runTunnelLoop` on send; the receiving side recognizes and drops the
chaff (by frame type). Mirrors in Android/qeli-win. The trade-off: latency and overhead
(chaff) against stealth — configurable.

### 2C. (opt.) Real QUIC / MASQUE instead of 2A
Instead of manual QUIC — take `quinn` (Rust QUIC) and run the tunnel as HTTP/3 datagrams
or MASQUE CONNECT-IP (RFC 9484). Then on the wire — **real** QUIC (header protection,
versions, transport params for free). It overlaps with P3#9 (MASQUE). The volume is
larger, but the stealth is maximal and 2A is not needed.

### Volume: **large**. 2A — medium (rewrite quic.rs ×3 clients). 2B — medium-large
(a new shaper ×3). 2C — large (a new transport). Recommendation: 2B gives the largest
anti-ML effect; 2A/2C — by the decision on the QUIC strategy.

---

## ✅ The PQ hybrid KEX (P3#7) — DONE 2026-06-11

**Why.** "Harvest now, decrypt later": the X25519 traffic recorded today will be
decrypted by a future quantum computer. The X25519+ML-KEM hybrid protects against this
already now (the TLS 1.3 hybrid standard, like Chrome's `X25519MLKEM768`).

**How it's done.** The inner qeli tunnel derives the data-plane keys from BOTH secrets in
all modes except `plain`:
- the client sends an X25519MLKEM768 `key_share` = `ML-KEM-768 ek (1184) ‖ x25519 (32)`
  (+ the classic x25519 share), stores the ML-KEM `dk`;
- the server `extract_client_mlkem_ek` → encapsulate, the ServerHello carries
  `ct (1088) ‖ x25519 (32)`; the client decapsulates;
- the keys: `derive_keys_hybrid` = `HKDF(salt="…v2-hybrid", x25519_shared ‖ mlkem_shared)`
  → the AEAD keys. It breaks only if *both* are broken. `plain` stays classic
  X25519 (`derive_keys`). **The server REQUIRES** the X25519MLKEM768 share for non-`plain` —
  there's no silent PQ downgrade (the domain separation by the salt catches a mismatch as a decrypt-fail).
- ML-KEM-768 ek ~1184 B / ct ~1088 B — the ClientHello is bloated (in addition to the
  size-fingerprint parity with Chrome ≥124).

**The implementation.**
- Rust: the `ml-kem` crate (pure-Rust). `crypto/mlkem.rs` + `crypto/derive.rs`
  (`derive_keys_hybrid`); the handshake `protocol/tls.rs` (`build_client_hello_pq` /
  `build_server_hello_pq` / `parse_server_hello_pq` / `extract_client_mlkem_ek`),
  `server/handler.rs`, `server/udp_handler.rs`, `client/mod.rs`.
- **NOT BouncyCastle** (2.6.2 has no ML-KEM; the `.NET MLKem` is OS-gated) → the managed
  clients call the same Rust crate over the C-ABI/JNI: `realtls/ffi.rs`
  (`qeli_mlkem_keygen/decapsulate/free`), `realtls/jni.rs` (`Java_com_qeli_MlKem_*`).
- C#: `Crypto/Mlkem.cs` (P/Invoke), `TlsHandshake.BuildClientHelloPq/ParseServerHelloPq`,
  `KeyDerivation.DeriveKeysHybrid`, a wedge into `VpnTunnelBase` (the main + JOIN).
- Kotlin: `com/qeli/MlKem.kt` (JNI), the same methods, a wedge into `QeliService`.
- Versioning: not a negotiation flag, but an atomic deploy (the server requires PQ) —
  a single beta 0.6.0, the client↔server roll together.

**It harmonizes with Axis 1**: realtls already carried `X25519MLKEM768` in the OUTER real TLS 1.3
(L3.2); now PQ is also in the INNER tunnel regardless of the wrapper.

---

## 🔵 P3#9 — multipath / MASQUE / WireGuard-compat / eBPF

Four independent experimental directions.

- **MASQUE (CONNECT-IP/CONNECT-UDP, RFC 9484/9298).** An IP tunnel over HTTP/3.
  Maximum stealth (real QUIC/H3 to a real domain) + it passes QUIC-friendly networks.
  It overlaps with Axis 2C. Volume: large (a QUIC stack + H3 + IP proxying).
- **Multipath.** A tunnel over several paths at once (Wi-Fi + LTE): a scheduler spreads
  the packets, on receipt — a reorder buffer. A plus to reliability/speed on mobile.
  Volume: large (a scheduler + reordering + path detection).
- **A WireGuard-compatible mode.** The server speaks the WireGuard protocol → stock WG
  clients connect (broad compatibility). BUT WG has a recognizable fingerprint and no
  obfuscation — against the stealth goal; it makes sense only as a layer under
  obfuscation. Volume: medium-large (Noise-IK + WG framing).
- **An eBPF fastpath (Linux).** The data plane in the kernel via eBPF/XDP — a bypass of
  the userspace copy, a multiple throughput increase. Server/Linux only. Volume: large
  (an XDP program + maps + the verifier), tied to the kernel.

**Volume: each — large/experimental.** This is long-term, not for the nearest iterations.

---

## The recommended order
1. **Axis 1** (REALITY/real TLS) — the biggest lever against active DPI;
   make the decision **FFI-core (A) vs Trojan/ACME**. PQ-KEX (P3#7) is done within it
   (a stock hybrid group).
2. **Axis 2B** (shaping) — independent of Axis 1, hits the ML classifier.
3. **Axis 2A or 2C** (QUIC) — by the decision on the QUIC strategy (a manual RFC 9001 vs quinn/MASQUE).
4. P3#9 — long-term as needed.
