# qeli roadmap

Priorities: **P1** — noticeably affects security/functionality, **P2** — quality,
**P3** — long-term/experimental.

## 0.7.2 (2026-06-18) — peripheral hardening (internal audit 2026-06-18)

Wire-compatible with 0.7.1; no config defaults changed. Tracker — the internal
2026-06-18 audit.

- ✅ **Web panel: closed a brute-force / anti-DoS bypass.** HTML pages ran HTTP
  Basic through Argon2 with no rate-limit (bypassing `AuthGuard`). Pages now use
  the session cookie only (`auth::is_authed_cookie_only`); Basic stays API-only,
  throttled.
- ✅ **Atomic writes for all persistent files** (users/config/identity/secret/
  web-TLS/resolv.conf) — one `crate::util::write_atomic` (temp→fsync→rename, Unix
  `O_EXCL`+`O_NOFOLLOW`, preserves 0600). A crash no longer corrupts the
  password-hash file.
- ✅ **Anti-replay tightened** — padding is validated before the counter is
  recorded in the window.
- ✅ **`SECURITY.md` + threat model** (`THREAT-MODEL.md`) + a **fuzzing harness**
  (`qeli/fuzz/`: clienthello / packet_decrypt / realtls_record).
- ✅ **Versions → 0.7.2**; Android `versionCode=702`. Lab gate .10: build / **203 tests** / clippy / fmt — green.
- ℹ️ Re-checked: a kill-switch ships on ALL desktops (Linux iptables / Win WFP /
  mac pf) — parity, not a gap (the original finding #4 is withdrawn).

## 0.7.1 (2026-06-12) — security hardening (2026-06-12 audit)

External-audit fixes; the default wire was unchanged **except H-1**, which is now
**on by default** (wire-breaking — upgrade the server and all clients in lockstep).
Tracker — [AUDIT-2026-06-12.md](AUDIT-2026-06-12.md).

- ✅ **H-1** — bind the data keys to the server's static identity (Noise-IK): the KDF
  folds in `es = X25519(client_eph, server_static)`. Rust+C#+Kotlin; **default on**
  (`bind_static_to_session` on the server, `bind_static` on the client). An unpinned /
  TOFU client opts out with an explicit `bind_static = false`.
- ✅ **M-13** — anti-replay window 64 → 2048 bits (WireGuard-sized), receiver-only (Rust+C#+Kotlin).
- ✅ **H-5** — atomic resolv.conf write without symlink-follow (O_EXCL+O_NOFOLLOW), Rust client.
- ✅ **H-3** — kill-switch nft-rule sanitization (ifname validation + IP reformat), Rust client.
- ✅ **Versions → 0.7.1**; Android `versionCode=701`. Most audit items turned out to be false positives.

## 0.7.0 (2026-06-11) — the post-quantum tunnel

- ✅ **PQ hybrid X25519+ML-KEM-768** in the inner handshake on all clients
  (Rust/C#/Kotlin); the server requires PQ for non-plain modes.
- ✅ Persistent TOFU; reality requires non-empty `short_ids` (strict config validation).
- ✅ External-audit fixes 2026-06-10/11. Versions → 0.7.0; Android `versionCode=700`.

## 0.6.0 (2026-06-10) — the refactoring release

A code reorganization and visual polish; the protocol/crypto/wire were **unchanged**
(the 0.5.6 measurements are still current). Full list — [CHANGELOG.md](../../CHANGELOG.md),
details of the C# consolidation and Rust fixes — [REFACTOR-PLAN.md](REFACTOR-PLAN.md).

- ✅ **Shared C# layer `qeli-shared`** — crypto, protocol, model (`VpnConfig`), the
  `VpnTunnel` core (behind the `ITunDevice` interface), `RealTls`, and the `Loc`
  localization were consolidated from two win/mac copies into one library (.NET 10);
  ~2700 lines of duplication eliminated.
- ✅ **.NET 10 unification** of both C# clients + unified NuGet versions (BouncyCastle 2.6.2, QRCoder 1.8.0).
- ✅ **Rust web layer**: the `err_json`/`ok_json` helpers + the axum extractor
  `AuthGuard` (auth check at the type level, you can't "forget" it). Lab gate on .10:
  build / 179 tests / clippy — green.
- ✅ **UI alignment** (win/mac `MainWindow`): symmetric columns, the brand band = the
  status card, matching panel bottom edges, a unified 14px spacing rhythm.
- ✅ **`scripts/lab_common.py`** — a shared SSH harness (hosts + connect/run) for the lab scripts.
- ✅ **Versions → 0.6.0** on all components; Android `versionCode=600`.

## Done

- ✅ **Channel-binding** of auth_proof to the handshake transcript (anti-MITM).
- ✅ **Per-profile server identity** (`/etc/qeli/identity/<name>.key`) + the
  `show-identity` / `rotate-identity` CLI.
- ✅ **`require_client_key_proof`** — rejecting unpinned clients + hiding the static
  key from scanners.
- ✅ **Per-profile authorization** (`users.profiles`) — interface isolation.
- ✅ **A new `obfs` wire mode** (ChaCha20 stream) in addition to `fake-tls`.
- ✅ **REALITY proxy** — proxying "non-ours" connections to a real site.
- ✅ **UDP anti-amplification** (padded initial ≥1200, refusing small ones).
- ✅ **Hiding the counter** in the nonce (a 96-bit Feistel-PRP).
- ✅ **Idempotent/crash-safe DNS** with self-recovery and SIGTERM handling.
- ✅ **Client auto-reconnect** (RX-liveness + a correct shutdown of the TUN reader).
- ✅ **Cancellation-safe data plane** (dedicated reader tasks) — the old
  framing-desync "cliff" eliminated.
- ✅ **A single flat-INI config** (`server.conf`/`client.conf`/`users.conf`) — TOML
  and JSON are FULLY DROPPED (one format); the web UI writes INI. Users are
  `[user:<name>]`/`[group:<name>]` sections.
- ✅ **SIGHUP reload** (users + brute-force thresholds).
- ✅ **Logs**: the `YYYY-MM-DD HH:MM:SS:mmm` format, file output, an audit of admin
  actions.
- ✅ Heartbeat idle-gating; padding probability/randomize; capping a UDP datagram < MTU.
- ✅ **Hardening (round 1)**: an OOB read in the DHCP parser (bound-check, test); CSRF
  allowed_hosts for IPv6 (`[::1]`, bracketed bind); `keepalive_secs=0` no longer
  causes EINVAL; config validation catches a missing `[performance]` section with a
  clear error.
- ✅ **Hardening (round 2)**: an OOB panic when parsing the QUIC SCID (bound-check +
  fuzz test); validation of the upstream DNS reply (source + transaction-ID —
  anti-poisoning, plus a txid-normalized cache key); constant-time comparison of the
  auth-proof (`subtle`, all 4 points: TCP/UDP × server/client); a non-blocking
  `try_send` on the client's TUN writer (TCP+UDP — it doesn't stall the select loop
  under backpressure); a DHCP REQUEST checks the allocation from the pool and sends a
  NAK instead of echoing any IP; a bound on the control-command length (anti-OOM); a
  u16 padding clamp; a `gen_range` guard in the fragmenter; `private_bytes()` →
  `Zeroizing`. Confirmed: 99 unit tests + e2e (tcp-plain/obfs/udp, 0% loss,
  throughput with no regression).

## Done (2026-06-04, session #2)

- ✅ **Dropping TOML/JSON → a single flat-INI** (see above). 110 tests green.
- ✅ **Fix for reconnect from a new IP** — supersede a stale session by username
  before the limit check (handler.rs); a base-station/Wi-Fi↔LTE switch no longer
  blocks the client.
- ✅ **Server-side reaping** (former P1#3) — a separate `last_rx`, RX-liveness in the
  idle check: a dead/half-open client is reaped after 3×heartbeat even with
  `idle_timeout=0`, freeing the IP/slot.
- ✅ **Device-ID / multi-device** — the client sends a stable 16-byte device-id in
  auth (`[proof:32][0x00][device_id:16][user:pass]`, the 0x00 marker is
  backward-compat); the server keys sessions/IP pool by `username:hex(device_id)`
  instead of bare username. Several devices on one login coexist (each its own
  tun-IP), the same device on an IP change kicks only ITS OWN old session. All 4
  clients (Rust/Android/Win/Mac) generate+store the device-id. E2E PASS on the lab
  (fake-tls) and production (reality-tls). Identification by device-id, NOT by the
  tun-interface name (which is not sent to the server).
- ✅ **Enforcement of `max_sessions`** (the setting existed before but was not
  applied) — a per-user limit of simultaneous devices (fallback to the group,
  0=unlimited); on exceeding it the user's oldest device is evicted (newest wins). A
  reconnect of the same device doesn't spend a slot. TCP+UDP, E2E PASS. Enabled by
  setting `max_sessions` on the user/group.
- ✅ **Fix for a "stuck" reconnect/Disconnect** — the socket is published to a field
  BEFORE the blocking `connect()` (Android/Win/Mac), so Disconnect can close the
  connecting socket (NIO/Socket are interrupted only by closing, not by cancelling a
  coroutine/token) → the Disconnect button works during a reconnect. Android:
  network-change detection via `registerDefaultNetworkCallback` → an instant
  forceReconnect on the new network. A runtime check on a live phone is up to the
  user (the emulator UI is fragile).
- ✅ **A keyed push format** for auth-OK — `OK:{json}` with keys instead of the
  positional `OK:a:b:c:…` (a whole class of field-misalignment bugs eliminated).
- ✅ **`route_local_networks`** — a client opt-in for routing private networks
  (RFC1918 + server-pushed) into the tunnel.
- ✅ **DNS-push footgun** — the server doesn't push a dead `dns.listen` when the proxy
  is off; the client falls back to its own resolver.
- ✅ **Android client**: refactoring (a Transport abstraction, dedup of TCP/UDP),
  qeli:// import + QR, a replay window, full-tunnel default; audit fixes.
- ✅ **Web UI**: QR/share generation + API; the `qeli add-client` CLI.
- ✅ **Cleanup** (former P2#5): the dead `bypass_*` removed, 0 dead-code warnings.
- ✅ **CI scaffold** (former P2#4): `.github/workflows/ci.yml` (build+test — a gate;
  fmt/clippy — advisory until normalization) + `scripts/ci-check.sh`.
- ✅ **Production deploy** (`YOUR_PROD_HOST`): config migration TOML→INI with
  preservation of the identity key/users/client configs, a fresh keyed build.

## Done (2026-06-05)

- ✅ **Axis 3 — anti-FET fronting for `obfs`** (DPI-AUDIT tell 4.1). The start of an
  obfs connection is masked as a WebSocket Upgrade handshake (printable HTTP +
  `\r\n\r\n` → the first packet passes the Ex2/Ex3/Ex4 exemptions of the GFW/TSPU
  "fully encrypted traffic" entropy detector, Wu et al. USENIX'23). The server
  computes a correct `Sec-WebSocket-Accept` (inline SHA-1, no new dependencies), the
  request is randomized (path/Host/UA/key) — no static signature. A new flag
  `obf.obfs_fronting = websocket|none` (default `websocket`), forwarded into the
  qeli:// link (`front`), INI, and JSON; mirrored in Android
  (`ObfsStream.kt`/`Config.kt`) and **qeli-win** (`ObfsStream.cs`/`VpnConfig.cs`).
  The Rust `ObfsStream` is shared by client and server. Tests: the RFC6455 Accept
  vector, the FET exemptions for the request, fronting round-trip, config round-trip.
  Verified: Rust 114 tests + clippy + e2e (lab .10); Android assembleDebug + APK;
  qeli-win build 0w/0e + selftest ALL PASS + e2e (the client sends a WS GET,
  printable 0.935). All three clients + the server are aligned.

## Done (2026-06-05, continued)

- ✅ **UDP-obfs in qeli-win** — previously the Windows client over UDP could only do
  fake-tls/QUIC. Added `DatagramSeal/DatagramOpen` (ChaCha20 per-datagram) + a
  wrapper in `UdpTransport`. Now **all three** clients (Rust/Android/qeli-win)
  support obfs over UDP. e2e: Auth OK against prod udpobfs:8448.
- ✅ **A ↓/↑ speed indicator** for an active connection — goodput counters in the data
  plane, updated once per second. qeli-win: `BytesUp/BytesDown` + a DispatcherTimer
  (+ stat tiles, a sparkline, profile search in the UI). Android: `AtomicLong` + a
  statsJob broadcast → `tvSpeed`.
- ✅ **A UDP reachability probe** (Android + qeli-win) — instead of a TCP connect
  (which gave a false red on UDP ports) a mode-framed ClientHello is sent, any server
  reply = "reachable".
- ✅ **`quic` in the qeli:// link and INI** — the QUIC flag previously rode only in
  JSON; now `quic=1` (link) / `quic=true` (INI). Parsed by **all three** clients:
  Android, qeli-win, and Rust (`ClientLink.quic`, `client.rs`
  from_link/from_ini/to_link/to_ini_string), and the server generators
  (`qeli add-client`, web `/api/share`) emit it. Lab: 114 tests green.
- ✅ **Axis 3 for UDP — UDP-obfs entropy** (DPI-AUDIT tell 4.2). The per-datagram
  obfs frame got a QUIC short-header shape:
  `[flag(0x40|x)][nonce=12 as conn-id][protected]` instead of a random prefix from
  byte 0. Mirrored in obfs.rs (client+server), Android, qeli-win. ⚠️ A breaking
  wire-change for UDP-obfs — it required a coordinated deploy. **Done 2026-06-05:**
  the prod binary updated (backup `/root/backup/qeli-deploy/`), a new APK + qeli-win
  rebuilt and laid out in dist. e2e against prod: udpobfs `Auth OK` (the new format),
  udpquic `Auth OK` (quic=1).
- ✅ **Android: square shadows** — on the emulator (swiftshader software GPU)
  elevation shadows are drawn square; the native shadows were removed
  (`cardElevation=0`), the cards are flat with a rounded border (stroke). Clean on any
  renderer. On a real device the shadows were round anyway.
- ✅ **Production test bench** (`YOUR_PROD_HOST`): 7 profiles by obfuscation type
  (tcp 443/8443/8444/8445 + udp 8446/8447/8448), firewall/NAT, client configs
  `/etc/qeli/client/test-*.{qeli,conf,json}` (see [[reference_qeli_prod_server]]).

## Done (2026-06-06)

- ✅ **Multi-queue TUN + the client `dev=`** (2026-06-06). Server: `tun.queues`
  (per-profile, default auto=nproc, `IFF_MULTI_QUEUE`) — the data plane opens N TUN
  queues and pumps them with N reader/forwarder/writer tasks, so that both the TUN
  pump and per-queue encrypt run on several cores (previously a single
  reader+forwarder+writer was a ~1.5-core funnel). Server-only, nothing changes on
  the wire, clients are NOT rebuilt. A controlled A/B on a 2-core lab (2 tunnels):
  `queues=1`→`2` gave 607→718 Mbps (+18%), qeli 159%→167%; on the lab the effect is
  limited by host saturation (server-host 93→95%, almost saturated by the `iperf3`
  server on the same host), on larger servers it grows (full A/B and methodology —
  [BENCHMARK.md](BENCHMARK.md)). Client: `dev=` in `[qeli]` (default `vpn0`) —
  choose the tun name so as not to steal another's interface / to bring up several
  clients; + a warn before reclaiming an existing one + a clear error when the
  interface is busy. **169 tests**, e2e on the lab. Probe scripts
  `multicore_probe.py` / `multitunnel_probe.py`.
  - **Refinements (2026-06-06):** (1) **blocking-read** TUN readers — removed the
    nonblocking + `sleep(1ms)` busy-poll (when idle it was N×1000 wakeups/s; now the
    thread sleeps in `read`, idle CPU measured at 0%). (2) **A multi-core UDP pump** —
    N workers on `SO_REUSEPORT` sockets (socket2), the kernel flow-hashes datagrams
    by client; previously a single `recv` loop kept all UDP-decrypt on one core. (3)
    `tun.queues` cap 16→256 (MAX_TAP_QUEUES). (4) A TAP fix in `delete` (iterate over
    both tun+tap modes). e2e: TCP+UDP `Auth OK` + ping, `dev=` live (2 clients
    qtcp/qudp on one host). `scripts/refine_e2e.py`.
- ✅ **A new `plain` wire mode** (raw, no obfuscation) — a raw X25519 exchange + bare
  `[len][nonce][ct]` records (no TLS mimicry); **TCP-only** (UDP+plain is rejected
  with an explicit error). `Framing::{Tls,Raw}` in `packet.rs`, a raw handshake on
  client and server, a guard in profile validation. Benchmark: ≈ fake-tls in speed
  (560↑/707↓ Mbps). The TCP-only invariant is locked in by regression tests
  (`validate_profiles`: plain+udp → error, plain+tcp / fake-tls+udp → ok). 161 unit
  tests green, e2e on the lab.
- ✅ **`rsid=` in the `qeli://` link** — `reality-tls` is now distributed via QR
  (previously full INI only): `ClientLink.reality_sid` + to_uri/from_uri (Rust), the
  Android (`Config.kt`) and .NET win+mac (`VpnConfig.cs`) parsers; `/api/share` and
  the `add-client` CLI emit `mode=reality-tls`+`rsid` for a profile with
  `real_tls`+`short_ids`.
- ✅ **Cert-borrowing (REALITY Path B) — IMPLEMENTED (2026-06-06)** — the hand-rolled
  REALITY terminator (`obf.tls.reality_proxy.handrolled = true`, requires
  `real_tls=true`) at profile start **captures the target's real cert chain**: a full
  TLS handshake with `target:443`, derivation of the ECDHE x25519/hybrid, decryption
  of the flight, lifting the Certificate message
  (`realtls/server.rs::capture_target_cert`) — and hands this chain to the qeli client
  instead of self-signed/dummy (signed with our own key, the client doesn't validate
  — trust via X25519 inner-auth, like Xray; the cert is encrypted in TLS 1.3,
  non-breaking). It mirrors the target's JA3S/ServerHello. `BorrowState{profile,cert}`
  under an `RwLock` on `ProfileRuntime.reality_borrow`. **Auto-refresh**: a background
  task re-probes the target every 12h and updates cert+JA3S (on failure it keeps the
  cache). Live e2e on .10: "borrowed TLS shape from www.microsoft.com:443 … (real cert
  chain: captured)" + the client `Auth OK`. Honestly: the CERT freshness for
  **passive** DPI ≈ zero (the cert is encrypted in TLS 1.3); the value — an **active**
  prober that completed the handshake sees the real microsoft chain, + a fresh
  plaintext JA3S/ServerHello. Config — `CONFIG.md` `handrolled`.
- ✅ **`/api/share`: password → POST body** (it was a query string — a leak into
  access logs/history).
- ✅ **Versions unified → `0.5.6`** (beta) on all components; Android `versionCode=506`.
- ✅ **CI builds the clients** — added android/windows/macos build-jobs to `ci.yml`.
- ✅ **A full benchmark run of all 10 modes** (incl. `plain` + `reality-tls`) with
  process CPU/RSS metrics — see [BENCHMARK.md](BENCHMARK.md).
- 🟡 **reality-tls download ~430 Mbps** (was ~320 on 0.6.0; the hand-rolled TLS server since 0.7.0 lifted it ~320→417→430, measured on 0.7.4) — diagnosed on the lab: nested TLS = double
  AEAD + double framing serially in the client reader (client CPU ~67% of a core,
  AES-NI present on the VM → not software-AES, not a CPU ceiling). The
  `RealTlsStream::poll_read` optimization (batch-decrypt all records per poll + a
  64-KiB buffer + a cursor instead of per-record `drain`/alloc) **was done and kept**
  (161 tests green), but it didn't move the download — the bottleneck is not in
  buffering. The real fix (follow-up, a design change): (a) remove the redundant inner
  AEAD in reality-tls (the outer TLS already encrypts — push inner data in
  `plain`/Raw framing), or (b) parallelize the TLS- and inner-crypto across
  tasks/cores.
- ✅ **NewSessionTicket (P4#6)** — the REALITY server now sends 1-2 post-handshake NST
  like real TLS 1.3 (their absence is a tell). Both paths: rustls
  (`make_server_config`: a ticketer + `send_tls13_tickets=2`) and hand-rolled
  (`server_handshake` sends 2 NST on the server app-key; `build_new_session_ticket`
  RFC 8446 §4.6.1). The client doesn't resume — `RealTlsStream` skips post-handshake
  records, the seq stays in sync. 161 tests.
- ⏸️ **QUIC per RFC (Axis 2A) — DEPRIORITIZED (2026-06-06).** Analysis of `quic.rs`:
  the current QUIC is a structural masking shim (pn in cleartext, no Token Length/HP).
  "Really by the RFC" = almost implementing QUIC, AND there is a **fundamental
  ceiling**: a QUIC Initial is decryptable by anyone (the Initial keys are derived
  from the DCID, RFC 9001 §5.2) — you cannot hide our payload inside a "real" Initial
  (DPI will decrypt it, won't find a CRYPTO frame → a tell). Achievable is only a
  data-plane HP on the short-header (removing the incrementing-pn tell), but that is
  breaking + must be mirrored in Android/.NET. Decision: don't pursue it; for serious
  anti-DPI — `reality-tls`/`obfs`. udp-quic = light masking. AAD-on-the-token (P4#7)
  is also skipped: the token is already cryptographically strong (the eph is bound by
  the key + replay-guard + timestamp), AAD would add only marginal SNI-binding at the
  cost of being breaking.
- 🔬 **Distribution-matching shaping (Axis 2B, tell 6.1) — RESEARCH TRACK
  (2026-06-06).** Not implemented as a placeholder. The mechanism would be
  **non-breaking/Rust-only** (padding + send-pacing on the sender side; the receiver
  strips padding anyway), BUT "done" cannot be defined without (a) a target traffic
  model (the size/timing distribution of real HTTP/3) and (b) a harness to validate
  against an ML classifier — the lab has neither. Naive jitter+padding = a low
  provable anti-ML effect (ML looks at the flow level: volumes/duration/burst/
  asymmetry) at the cost of perf (pacing cuts throughput). Already present: size
  normalization (`round_sizes`), random padding, an idle-gated heartbeat. The missing
  core — timing/pacing. To be taken up when a target model + a measurement harness
  appear.

## Done (2026-06-08) — Stream bonding (multipath)

- ✅ **Stream bonding (multipath)** — N parallel TCP connections are aggregated into
  ONE session (one tun-IP), outgoing packets are spread round-robin; it bypasses the
  single-stream "TCP over TCP" ceiling (in production reality-tls ~6 Mbps on 1 stream,
  while the carrier on UDP/WireGuard gives tens). Multi-stream to a single HTTPS host
  is DPI-clean (a browser opens 6+ TLS). Per-profile `obf.multipath.{enabled,
  max_streams,adaptive}`; the server pushes `max_streams`+`session_token` in AUTH OK,
  the secondary connects present `JOIN_MAGIC‖token‖index` (the server replies
  `JOINOK`). Each connect does ITS OWN qeli-KE → its own nonce-space out of the box.
  - ✅ **Server** — `SessionShared` (Arc) with `streams: Mutex<Vec<StreamHandle>>` +
    round-robin `pick_stream()`; `qeli_handshake`/`parse_first_message` catch a JOIN
    **on any TCP profile of any mode** (mode-agnostic, the profile name is
    irrelevant). 171 tests, clippy 0.
  - ✅ **Rust client** — the pump: 1 upload round-robin + a per-stream reader/heartbeat;
    the modes FIXED (open exactly max_streams) and ADAPTIVE (ramp 1→max by throughput,
    stop at a plateau). Real connectors for **all TCP modes** (reality-tls/fake-tls/
    obfs/plain; `connect_obfs`/`connect_bare_tcp`, the plain branch's raw-KE in
    `tcp_join_handshake`). e2e lab: 4 streams = 1 AUTH + 3 JOIN on one IP — on all
    modes.
  - ✅ **Android client** — a Kotlin port (per-socket `SocketIO`, per-mode
    `openBondedStream`, `runMultipathTunnelLoop`, `performJoinHandshakePlain`); all
    TCP modes. e2e emulator: reality-tls (4 streams, IP 10.9.0.3 in production) +
    fake-tls.
  - ✅ **Production deploy** — the release binary `8b8ee19f` + `obf.multipath` in the
    reality-tls:443 profile (identity 7ff1c274 preserved); e2e under user05 = 4
    streams, the user01 phone NOT affected (backward compatibility: the old app
    ignores the push fields = 1 stream). See [[reference_qeli_prod_server]] deploy
    2026-06-08.
  - ✅ **Docs**: `CONFIG.md` section "Stream bonding — multipath".

**Remaining to finish (multipath):**

1. ✅ **Win/Mac clients — PORT DONE+COMPILES 2026-06-08** (`qeli-win`/`qeli-mac`
   `Vpn/VpnTunnel.cs`): per-socket `SocketIO` + the JOIN handshake (incl. plain
   raw-KE) + a round-robin pump + per-mode `OpenBondedStream` for all TCP modes — an
   exact mirror of Rust/Android. `dotnet build` of both = 0 errors (requires the
   **.NET 10 SDK**: win=net10, mac=net8). ⚠️ RUNTIME e2e NOT run: qeli-win requires
   UAC elevation (Wintun) → a headless test in the CLI can't be launched; a full
   multipath test for Win/Mac = on a live machine with admin (like the phone
   measurement). Remaining: e2e on a real machine + building signed distributions (the
   Win exe is ready in bin; Mac universal — cross-build+rcodesign on .10).
2. 🔴 **P1 — measure the real "4 vs 1" gain** on production/phone — so far only the
   bonding MECHANISM is proven (4 connections → 1 session/IP), the throughput gain
   itself is **NOT measured**. Measure on the phone/Android with the new APK (speedtest
   1 stream vs 4 vs adaptive). NB: the old "CLI client brings up the tun POINTOPOINT
   without a peer / doesn't pump" status is **stale/incorrect** — verified 2026-06-19:
   the client tun is `<ip>/24` + pushed MTU and tunnel-internal pumps (bench 587 Mbps).
   The real CLI bug was the **full-tunnel route** (below, fixed).
   - ✅ **Full-tunnel CLI route FIXED 2026-06-19:** `route::setup_routes` added
     `default via <tun> metric 100`, which loses to the common metric-0 physical default
     → full-tunnel (`mode=full-tunnel`/`add_default_gateway`) silently did not engage.
     Replaced with the `0.0.0.0/1` + `128.0.0.0/1` split via the tun (more specific than
     `/0` → beats any default without deleting it; the server-bypass `/32` and connected
     `/24` stay intact; teardown's `flush dev` removes the halves). Verified in an isolated
     netns: OLD routed 8.8.8.8 via the physical gw, NEW routes it via `dev vpn0`. Gate green.
3. 🟡 **P2 — adaptive mode under load** — implemented (ramp 1→max by throughput), but
   e2e is confirmed only for FIXED; the adaptive ramp itself under real traffic has
   NOT been run (threshold 250 KB/s, step 3s, stop at <10% gain).
4. ✅ **P2 — resilience to the loss of one stream DONE 2026-06-08** — the death of a
   bonded stream now tears down the tunnel ONLY if it was the last one; otherwise the
   stream drops out of the round-robin, the tunnel proceeds on the remaining ones (a
   `live` counter + a per-stream `dead` flag; the distributor lazily removes closed
   channels). All 4 clients (Rust/Android/Win/Mac). E2E: killed 1 of 4 streams on the
   server → Rust and Android survived on 3 (no reconnect, UI "Connected", "stream
   lost; 3 remain"). Win/Mac compile. Remaining (optional): a **re-JOIN** of the
   fallen stream to restore the stream count (currently only degradation).
5. 🔵 **P3 (optional) — a global multipath default** instead of per-profile (the
   profile overrides) — so as not to duplicate `obf.multipath.*` in every TCP profile.

## P1 — next

### Roaming — seamless network change (→ 0.8.0)

**Plan: [ROAMING.md](ROAMING.md).** A client surviving a Wi-Fi↔LTE / IP change without
dropping the user's connections (today this is a *fast reconnect* with a re-handshake +
Argon2, not roaming). Feasibility confirmed against the code:
- **UDP + QUIC** — seamless connection migration. The 4-byte CID is already on every
  upstream packet ([client/mod.rs:1678](../../qeli/src/client/mod.rs#L1678)) but the server
  discards it and demuxes by source address
  ([udp_handler.rs:328](../../qeli/src/server/udp_handler.rs#L328)). Record the client CID,
  migrate the session's peer-addr on an AEAD+replay-valid packet, with a **rotating
  CID** (HKDF) for unlinkability. Mostly server-side + a client soft-rebind.
- **TCP** — no transport migration (kernel 4-tuple), but **make-before-break** over the
  existing multipath JOIN (open a stream on the new network before the old dies) + a
  session **grace period** so a JOIN-resume re-attaches **without re-auth**
  ([handler.rs:766](../../qeli/src/server/handler.rs#L766) tears down too eagerly today).
- **Phase 1 (0.8.0):** UDP migration + TCP grace/JOIN-resume + CID rotation, new
  `[roaming]` config. **Phase 2:** make-before-break + per-interface binding +
  path-validation + MTU re-probe. Key risks: data-plane changes, **nonce reuse on a
  botched client rebind**, grace-period DoS — all addressed in the plan.

1. **Real REALITY** (a TLS 1.3 tunnel + proxying foreign parties to a real site) — the
   Xray-REALITY level. **Path A (an ACME cert of your own domain) REJECTED
   (2026-06-06):** that's the Trojan model — your own domain is blocked without
   collateral, the essence of REALITY ("a domain too big to block") is lost. **Path B
   adopted — borrowing the target's real certificate chain:** a probe captures the
   real cert (e.g. microsoft), the hand-rolled server hands it to its clients instead
   of self-signed/dummy (signed with our own key, the client doesn't validate — as in
   Xray; the cert is encrypted by TLS 1.3, non-breaking). **✅ IMPLEMENTED 2026-06-06**
   — cert-borrowing + auto-refresh (12h); see the entry "Cert-borrowing (REALITY Path
   B)" in the "Done" section above and `CONFIG.md` (`obf.tls.reality_proxy.handrolled`).
   - ✅ **M1 — a cryptographic REALITY authenticator + ALPN** (2026-06-05):
     `crypto/reality.rs` (seal/open `session_id`:
     `auth = HKDF(X25519(eph, reality_pub) ‖ short_id)`), the client ClientHello
     carries the auth in `session_id` + ALPN added (`tls.rs`), the server recognizes
     qeli **cryptographically** (opens `session_id` with the profile private key and
     checks against `short_ids`) instead of the old "no ALPN" heuristic
     (`server/reality.rs`). Config: server `obf.tls.reality_proxy.short_ids`, client
     `reality_sid`. Lab: clippy 0, **120 tests** (the unit covers the full path
     hello→parse→open→short_id + rejecting a foreigner). **Live e2e on .10
     (2026-06-05):** (1) a correct token → `REALITY: Qeli client detected` +
     `AUTH OK`, IP issued; (2) a wrong `reality_sid` (same binary) → NOT recognized →
     proxying → the client `failed to parse ServerHello`; (3) active openssl probing
     without a token → served a **real valid cert** `CN=www.microsoft.com` (issuer
     Microsoft TLS G2). The detect line arises strictly on a correct token — the token
     really gates the detect.
   - ✅ **M2 (done 2026-06-05)** — a real browser TLS client, a pure-Rust `realtls`
     core (decided 2026-06-05, `docs/DESIGN-remaining.md`); interop with rustls proven:
     - ✅ **M2.1 (2026-06-05)** — byte-grade Chrome ClientHello + JA4
       (`protocol/realtls/clienthello.rs`): JA4 `t13d1516h2_8daaf6152771_…` (JA4_b =
       the canonical hash of Chrome's cipher list — verified by a test, byte-accurate
       without a live capture). The REALITY token in `session_id` + the x25519
       `key_share` are recovered by the existing server parser (`extract_key_share`
       taught to skip a GREASE-first `client_shares`). Lab: 125 tests, clippy 0.
     - ✅ **M2.2 (2026-06-05)** — the TLS 1.3 key schedule + AEAD record layer
       (`realtls/keyschedule.rs`, `realtls/record.rs`): HKDF-Expand-Label/Derive-Secret,
       early→handshake→master + traffic keys/iv/finished; record nonce=iv⊕seq,
       AAD=header, inner=content‖type. Verified **byte-for-byte against RFC 8448 §3**
       (the full key schedule + a KAT record of the client Finished) + round-trip +
       tamper-reject. The `aes-gcm` crate added. Lab: 130 tests, clippy 0.
     - ✅ **M2.3 (2026-06-05)** — the client TLS 1.3 handshake machine
       (`realtls/client.rs`): CH→SH→the encrypted flight (EE/Cert/CertVerify/Finished,
       the cert isn't validated — trust via X25519/inner-auth, but the server Finished
       is verified)→client Finished→app keys. Verified by a **loopback interop**
       against a minimal spec-accurate TLS 1.3 server (the full flight,
       coalesced-records, CCS, two-way app-data). Found/fixed a transcript-scope bug
       for the app secrets. Added `hmac`. Lab: 131 tests, clippy 0.
     - ✅ **M2.4 — gold interop (2026-06-05)** — our realtls client completes a **real
       TLS 1.3 handshake against `rustls`** (the ring provider, an on-the-fly
       self-signed cert via `rcgen`, TLS1.3-only/AES-128-GCM): rustls accepted our
       Chrome ClientHello, sent real Certificate/CertVerify, we verified the server
       Finished, rustls accepted our client Finished, app-data in both directions.
       This proves that our hello/handshake is real TLS (loopback couldn't prove it).
       rustls/tokio-rustls/rcgen — dev-deps. Lab: 132 tests, clippy 0.
   - ✅ **M3 — FULLY CLOSED (2026-06-05)** — real REALITY on the Rust stack works e2e:
     - ✅ **M3.1 (2026-06-05)** — the server building block `realtls/server.rs`:
       `PrefixedStream` (replay of the buffered ClientHello) + `make_server_config`
       (rustls TLS1.3/AES-128-GCM, an on-the-fly self-signed cert) + `terminate()`. The
       **peek→replay** test: the server consumes the ClientHello (as the token
       detector does), replays it into rustls — a real handshake with our client
       completes. rustls/tokio-rustls/rcgen → prod dependencies. Lab: 133 tests, clippy
       0.
     - ✅ **M3.2 (2026-06-05)** — the client building block `realtls/stream.rs`:
       `RealTlsStream<S>` — `AsyncRead+AsyncWrite` over established TLS (frames app-data
       via `RecordCrypto`, cap 16384/record, skips non-appdata records). Test against
       rustls (interop + a 20KB bulk round-trip). Now **both sides are streams** (the
       server tokio-rustls `TlsStream`, the client `RealTlsStream`). Lab: 135 tests,
       clippy 0.
     - ✅ **M3.3 — wiring (2026-06-05)**: `SplitStream` for `TlsStream`/`RealTlsStream`;
       the config flag `obf.tls.reality_proxy.real_tls`; server `reality.rs`
       "ours"+real_tls → `terminate()`+`handle_client` INSIDE `TlsStream`; client
       `mode=reality-tls` → `client_handshake`+`RealTlsStream`+`run_tcp_tunnel`. Nested
       (inner fake-TLS+PacketCodec inside real TLS). Lab: compiles, clippy 0, 135 tests.
     - ✅ **M3.4 — lab e2e (2026-06-05)**: a reality-tls client ↔ server on .10 — a REAL
       TLS handshake (Chrome JA4) → the server opened the token from the real
       ClientHello → `real_tls` rustls termination → the nested qeli-auth → **`AUTH
       OK`, IP issued (10.99.0.2)**. An active prober (openssl without a token) →
       proxied to microsoft (a real cert) — the "foreign" path coexists with real_tls.
       JA4=Chrome proven by a unit (M2.1).
     - ✅ **M3.5 — finishing + full e2e (2026-06-05)**: (a) **rustls-cert cache** on the
       profile (built 1× at start, `ProfileRuntime.reality_tls_config`; log `REALITY
       real-TLS termination enabled`); (b) **a full data plane on .11**: a reality-tls
       client (.11) ↔ server (.10), `AUTH OK` IP 10.99.0.2, the client brought up its
       TUN `vpn0`, **ping through the tunnel 4/4 0% loss** ~3.6ms, SENT/RECV two-way;
       (c) **a tcpdump wire check**: SNI `www.microsoft.com` + record types `1603`×2
       (CH/SH) `1403`×2 (CCS) `1703`×11 (the encrypted flight+tunnel) = a reference TLS
       1.3, the cert **encrypted** (not fake-TLS). JA4=`t13d1516h2_8daaf6152771`
       (Chrome) proven by the unit M2.1.
   - ✅ **APPLICATIONS — the FFI realtls core** (the sans-IO core → Android + Windows +
     macOS; `docs/DESIGN-remaining.md`):
     - ✅ **A1 — the sans-IO core (2026-06-05)** — `realtls/sansio.rs`: `SansIoClient`, a
       byte-in/byte-out state machine (`new`→ClientHello; `recv`→NeedMore/Done(CCS+
       client Finished); `seal`/`open_push`). Test against real rustls (bytes shuttled
       by hand, as the FFI caller will do). As a side effect it caught/fixed a
       `build_client_hello` bug: a duplicated GREASE extension (~6% flaky → rustls
       reject) — now grease_first≠grease_last, which hardens ALL realtls handshakes.
       Lab: 136 tests, clippy 0.
     - ✅ **A2 — the C ABI (2026-06-05)** — `realtls/ffi.rs`:
       `qeli_realtls_{new,recv,seal,open,free,buf_free}` (`#[no_mangle] extern "C"`, an
       opaque handle, ptr+len buffers, `catch_unwind`, `# Safety` docs). Test: a full
       handshake + app exchange through the C ABI itself against rustls (the same call
       sequence the JNI/P-Invoke will make). Lab: 137 tests, clippy 0.
     - ✅ **A3 — a native Android lib (2026-06-05)**: a lib+bin refactor (`src/lib.rs`
       `pub mod`, no compile_error for non-Linux; client/server/tun/web — cfg-linux;
       `main.rs`→`use qeli::…`; `[lib] crate-type=["rlib","cdylib","staticlib"]`; a fix
       `impl Default for Obfuscator`). On .11: the rust android-targets + `cargo-ndk`
       v4.1.2 + NDK r26d (sdkmanager). `cargo ndk -t arm64-v8a -t x86_64 build --lib` →
       **`jniLibs/{arm64-v8a,x86_64}/libqeli.so`** (ELF Android 21, NDK r26d), **all 6
       `qeli_realtls_*` exported in both ABIs**. ring/rustls/tokio/aes-gcm built under
       Android without changes. Host: 137 tests, clippy 0. (Debug ~30MB → for the APK
       build `--release`+strip; axum/qrcode/clap can be feature-gated out of the
       android build — an optimization later.)
     - ✅ **A4 — the JNI bridge (2026-06-05)**: Rust `realtls/jni.rs` (7
       `Java_com_qeli_RealTls_*` over `SansIoClient`; built with `cargo ndk`, `nm -D`
       confirmed) + Kotlin `RealTls.kt` (`@JvmStatic external` + `System.loadLibrary`) +
       **integration into `QeliService`**: reality-tls in `connectTcp` →
       `RealTlsTransport` wraps `TcpTransport` (`send`→`tls.seal`, `recvRecord`→
       `tls.open`+slicing inner records; `doRealTlsHandshake` over the raw socket);
       `Config.realityShortId` (INI `reality_sid`/JSON `reality_short_id`). The
       **release `.so`** (arm64 453KB, x86_64 525KB — LTO+strip removed the unreachable
       server/web) downloaded into `qeli-android/app/src/main/jniLibs/`; `Cargo.lock` +
       the sources — locally. (Kotlin is validated on the APK build — A5.)
     - ✅ **A5 — Android e2e WORKS (2026-06-05)**: the APK built on .11 (gradle, Kotlin
       compiles, the `.so` packed), installed on the emulator; a reality-tls profile →
       the client: `REALITY TLS 1.3 established (SNI www.microsoft.com)` → `Auth OK, IP
       10.99.0.2` → tunnel loop; the server .10: `REALITY: Qeli client detected from
       10.66.116.11` → `AUTH OK`; **ping through the tunnel 4/4 0% loss** ~4ms,
       SENT/RECV two-way. The Android client now sends the same **byte-accurate
       Chrome-TLS** (JA4 `t13d1516h2_8daaf6152771`) as Rust — via the shared realtls
       FFI core. **The applications phase A1→A5 for Android is COMPLETE.**
   - ✅ **qeli-win — REALITY works (2026-06-05)**: `qeli.dll` cross-built for win-x64
     (target `x86_64-pc-windows-gnu` + mingw on .10; the C-ABI exports confirmed by
     objdump; the `transport` scaffolding gated under linux — it alone didn't compile
     under windows), embedded into the exe as an `EmbeddedResource` + `NativeLoader`
     (generalized to qeli.dll). C# `Vpn/RealTls.cs` (P/Invoke over `ffi.rs`) +
     `RealTlsTransport` in `VpnTunnel` (nested seal/open) + `Config.RealityShortId`.
     dotnet build: 0 errors. **Headless e2e**: `QeliWin.exe handshake <json>` → exit 0;
     the server .10 (192.168.50.50): `REALITY: Qeli client detected` → `AUTH OK`. **All
     3 clients (Rust / Android / Windows) send one byte-accurate Chrome-TLS via the
     shared realtls FFI core** (sans-io → the C ABI for Windows P/Invoke / JNI for
     Android / natively for Rust).
   - ✅ **qeli-mac — REALITY works (2026-06-06)**: `libqeli.dylib` cross-built universal2
     (`cargo-zigbuild`, arm64+x86_64) on .10, embedded into the C#/Avalonia client
     (`Vpn/RealTls.cs` P/Invoke + reality-tls wiring). A signed universal `Qeli.app`
     built ENTIRELY without a Mac (dotnet publish osx-arm64+osx-x64 → llvm-lipo →
     rcodesign ad-hoc) → `qeli-mac/dist/Qeli-macOS-universal.zip`. The dylib = the same
     realtls core. **All 4 clients (Rust / Android / Windows / macOS) are aligned.**
   - 🔵 **The project's finale — UI polish.**
2. ✅ **Unifying TCP/UDP transport in the Rust server** — crypto/auth moved into the
   shared `handler.rs` helpers (`HandshakeRecords`/`build_handshake_records`,
   `build_server_auth_msg`, `verify_client_auth`); both transports call them, there is
   no more crypto/auth duplication (the only difference is framing/IO: stream vs
   datagram). Lab: TCP+UDP login (AUTH OK, ping 0%), a wrong password and per-profile
   deny work; 0 warnings, 111 tests. The dead `get_session_limit` removed.

### Backlog (internal audit 2026-06-18)
- 🔵 **Independent external audit of the hand-rolled realtls** (`protocol/realtls/*`,
  ~3k lines) — the largest unaudited surface and a trust blocker for serious users.
  Until then, grow continuous fuzzing (`qeli/fuzz/`).
- ✅ **Continuous fuzzing in CI** (2026-06-19) — a `fuzz-nightly` job (`schedule`,
  03:17 UTC): 10 min per `qeli/fuzz/` target, corpus persisted across runs via
  `actions/cache` (coverage accumulates), crash reproducer uploaded as an artifact.
  Plus `fuzz-smoke` (30 s per push, build-break check). Public repo → free Actions.
  (Harness was added in 0.7.2.)
- 🔵 **FFI panic-safety: build the cdylib with `panic = "unwind"`.** The realtls core
  (`libqeli.so`/`.dll`/`.dylib`) is built `cargo build --release --lib`, and
  `[profile.release]` sets `panic = "abort"` → the existing `catch_unwind` guards in
  `protocol/realtls/ffi.rs` are **inert** (abort doesn't unwind): a panic in an FFI
  parser (which processes attacker bytes) aborts the client app (JVM/C#). FFI panic
  safety currently rests only on panic-freedom (T2 triage + continuous fuzzing, the
  `realtls_record` target). Action: build the **FFI cdylib with `panic = "unwind"`**
  (`--config 'profile.release.panic="unwind"'` for the `--lib` builds, or a dedicated
  profile), keeping the server binary on `abort`. Then catch_unwind works → an FFI panic
  returns an error to JVM/C# instead of crashing the app (defense-in-depth on top of
  panic-freedom). Cost: a slightly larger `.so` (unwinding tables). Surfaced by the
  0.7.2 code review (its "no catch_unwind" claim was false — it exists but is inert
  under abort).

## P2 — quality

3. ✅ **fmt/clippy normalization** — a one-time `cargo fmt` + a clippy pass over the
   whole tree (33 warnings: `io_other_error`, `field_reassign_with_default`,
   `inherent_to_string`→`Display`, `unnecessary_cast`, doc-list-indent,
   `type_complexity`→alias, `too_many_arguments`→a targeted `#[allow]`). The CI lint
   job is now a gate: `cargo fmt --check` + `cargo clippy --all-targets -- -D
   warnings` (the `continue-on-error` removed); `scripts/ci-check.sh` is also
   tightened. Lab: fmt clean, clippy 0, 111 tests, a TCP smoke (ping 0%).
4. ✅ **A web editor with comment preservation** (2026-06-05) — a third "Raw INI" view
   on the `/config` page: `GET /api/config/raw` returns the file verbatim, `PUT
   /api/config/raw` validates via `parse_server_config` and writes the text **as is**
   (comments intact). The same path-whitelist guards as the structural PUT
   (logging.file/users_file). Lab: build + clippy + 114 tests. Additive (not
   breaking); the prod binary gets it on the next deploy.
5. ✅ **`quic` in Rust** (2026-06-05) — `ClientLink.quic` + `client.rs`
   (`from_link`/`from_ini`/`to_link`/`to_ini_string`) + the `main.rs` generators
   (`qeli add-client`) and `web/api/share.rs` now emit/parse `quic=1`(link)/
   `quic=true`(INI). The udpquic link from the CLI/web enables QUIC out of the box. All
   three clients are aligned. Lab: 114 tests.

## P3 — long-term / experimental

7. ✅ **Post-quantum hybrid KEX** (2026-06): **X25519MLKEM768** (ML-KEM-768, FIPS 203).
   The inner qeli tunnel derives the data-plane keys from X25519 ⊕ ML-KEM-768
   (`derive_keys_hybrid`, salt `…v2-hybrid`) in ALL modes except `plain`
   (`fake-tls`/`obfs`/`reality-tls`/UDP) — the server encapsulates / the client
   decapsulates; the ClientHello carries a REAL ML-KEM share (not just a
   fingerprint-parity with Chrome). The server REQUIRES X25519MLKEM768 for non-`plain`
   (no silent downgrade). The `ml-kem` crate (pure-Rust); managed clients (C#/Kotlin)
   take ML-KEM from the same core via the C-ABI/JNI (`qeli_mlkem_*` /
   `Java_com_qeli_MlKem_*`) — BouncyCastle has no ML-KEM. Live-verified on the lab
   (tcp-faketls/obfs/udp, 0% loss, 570–700 Mbps TCP).
8. ✅ **obfs for UDP** (per-datagram keyed XOR) — an `ObfsUdp` wrapper (nonce(12) +
   ChaCha20-XOR per datagram, stateless); pure-Kotlin ChaCha20 on Android (javax
   `Cipher("ChaCha20")` is broken on some runtimes); qeli-win — `DatagramSeal/Open`
   (BouncyCastle, added 2026-06-05). Lab: TCP+UDP obfs e2e on all three clients.
   ✅ **UDP-obfs entropy (tell 4.2) closed 2026-06-05** — the datagram took a QUIC
   short-header shape (`[flag][nonce-as-CID][protected]`), not high-entropy from byte
   0. A breaking wire-change — deployed 2026-06-05 (production + dist clients, e2e Auth
   OK).
9. ✅ **Multipath / stream bonding** — IMPLEMENTED (server + Rust + Android, all TCP
   modes; see "Done 2026-06-08" + "Remaining to finish (multipath)" above). What
   remains: **MASQUE**, a **WireGuard-compatible mode**, an **eBPF fastpath**.
10. ⚪ **Multi-core data-plane — NOT planned (measured 2026-06-19: not CPU-bound).**
    Architecture correction: the TUN→client fan-out is **already multi-core** —
    `tun.queues` (default = nproc) + IFF_MULTI_QUEUE + kernel RSS across queues, encrypt
    runs N-way in parallel, serialized only by the per-session codec lock. Multi-user
    scales across cores; single-user high throughput is served by **multipath** (bonding).
    The only remaining case is a single **non-multipath** connection: RSS pins its flow to
    one queue + one codec (monotonic counter → nonce) = one core. **Measured 2026-06-19:**
    prod is **1 vCPU** — its data-plane saturates that single core at ~311 Mbps (CPU-bound
    on one core: crypto+framing+overhead, distinct from raw AES ~8 Gbps); there are no more
    cores to parallelize across. On the lab (faster CPU) single-flow is ~590 Mbps at qeli
    ≤ ~0.8 core = network/VM-bound. Either way the lever is **more cores (a bigger VM)**,
    which the existing multi-queue + multipath already exploit — no code needed. Parallelizing
    one non-multipath flow is the highest-risk change (nonce uniqueness in the hottest path
    under `panic="abort"`) for near-zero gain (multipath already covers single-user
    multi-core). **Lever = VM + uplink, not code.** Closed.
11. 🔵 **Reproducible build + binaries out of git** — the native cores
    (`libqeli.so`/`.dylib`/`qeli.dll`) are currently committed for client
    convenience. Move to publishing via Releases + checksums + a reproducible build;
    drop the blobs from the tree.

## What we will NOT do

- An OpenVPN-compat mode (too much legacy baggage).
- Our own Web UI on a heavy frontend (the current axum + Alpine.js is sufficient).
- Non-Linux servers (TUN/TAP is tied to libc/the Linux kernel).
