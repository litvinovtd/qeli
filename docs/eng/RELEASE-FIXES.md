# qeli — plan to finish off toward a stable release (audit 2026-06-06)

Source: a detailed audit of the codebase. This document is a working checklist:
each item has an ID, a severity, the affected files, an approach, and an acceptance
criterion. Statuses are updated as work proceeds.

Status legend: ⬜ not started · 🟦 in progress · ✅ done · 🧪 awaiting a build/e2e on the lab.

---

## Summary table

| ID | Severity | Topic | Status |
|----|:---:|---|:---:|
| F1 | 🟠 Bug | Reconnect backoff is not reset after a successful session (4 clients) | ✅ |
| F2 | 🟠 Bug | The /24 mask is hardcoded; the server doesn't push the subnet prefix | ✅ |
| S1 | 🟡 Sec | A user-enumeration timing oracle (argon2 only for existing ones) | ✅ |
| S2 | 🟡 Sec | No rejection of an all-zero X25519 shared secret (low-order point) | ✅ |
| S3 | 🟡 Sec | `recv_peek` can truncate a ClientHello → a false bridge of a legitimate client | ✅ |
| H1 | ⚪ Hyg | A stray binary `qeli/local_copy/qeli` in the source tree | ✅ |
| H2 | ⚪ Hyg | ~250 one-off scripts in `scripts/` | ✅ (154 → `scripts/archive/`) |
| B1 | 🔴 Blk | The clients' native cores (.so/.dll/.dylib) older than the realtls sources | ✅ rebuilt+laid out |
| B2 | 🔴 Blk | The artifacts in `release/` are stale relative to the codebase | ✅ (APK/exe/app/server; mac — ad-hoc, notarization in M3) |
| B3 | 🔴 Blk | The release tree is outside VCS (no .git in the working copy) | ⬜ process (commit/tag in the canonical repo) |
| S4 | — | `ObfsUdp::recv` → `Ok(0)` on a corrupt frame | ✅ already closed (`udp_handler.rs:99`) |

> **Current status (2026-06-06): all code fixes (F1, F2, S1, S2, S3, E1–E5, H1, H2)
> are made and built; the native cores and artifacts of all 4 clients + the server
> are rebuilt from a fresh source and laid out in the standard folders; e2e on the lab
> (.10↔.11, tcp/obfs/udp) — PASS, 0% loss. Open: B3 (a VCS tag) and the backlog
> hardening (incl. the mac notarization M3).**

---

## Execution order (batch: first ALL fixes, then ONE build)

The principle: source edits are not interleaved with builds. All code fixes are made
first; then — a single build/test/e2e phase at the end.

**A. Fix phase (sources, no intermediate builds) — ✅ CLOSED:**
- Round 1: F1, F2, S1, S2, S3, H1, H2 — ✅ made (the Rust part run through the gate).
- Round 2: E1, E2, E3, E4, E5 — ✅ made (E6 refuted). The client code F1/F2/E1/E2 — made.

**B. Build phase (ONE run) — ✅ COMPLETED:**
1. The Rust gate `lab_sync_build.py` — ✅ PASS (168 tests, clippy 0).
2. **B1** — client builds: Android Kotlin compile + `assembleDebug` ✅ / Windows `dotnet` 0/0 ✅ /
   macOS `dotnet` 0/0 ✅; the native cdylib cores rebuilt from a fresh `realtls` and re-laid-out ✅.
3. **B2** — `release/qeli-linux-amd64` + APK + the Windows exe + the mac `Qeli.app` from a fresh source ✅.
4. e2e on the lab — ✅ PASS (.10↔.11, tcp/obfs/udp, 0% loss — see "e2e on the lab").

**C. Process:** B3 (a tag under VCS with the current artifacts) — ⬜ remaining.

The point of batching: each edit in Kotlin/C# did **not** require its own build — all
client changes accumulated and were compiled once in phase B (a client build = both
validation and a ready artifact). Details of the result — the "Phase B (build)"
section.

---

## F1 — Resetting the reconnect backoff after an established session

**The problem.** The attempt counter is incremented even after a successfully
established tunnel, and is never zeroed. A long-lived link that broke (roaming)
reconnects with an exponential delay that grows from drop to drop up to `max_delay`.
Systemic in all 4 clients.

**The approach.** Count the counter as the *number of consecutive failures*. Zero it
as soon as the session is established (auth OK / the connection came back without a
connect error). The backoff formula is untouched — only the reset changes.

**Files and points:**
- Rust: `qeli/src/client/mod.rs` — `run_client`, `retry_count` (`:68`, increment `:91`). Reset `retry_count = 0` on `result.is_ok()`.
- Android: `qeli-android/app/src/main/kotlin/com/qeli/QeliService.kt` — `connectWithRetry` (`:219`), `attempt` (`:240/:256`). Reset `attempt = 0` after `runVpnConnection` (session established).
- Windows: `qeli-win/QeliWin/Vpn/VpnTunnel.cs` — `ConnectWithRetry` (`:113/:134`). Reset `attempt = 0` when `_wasConnected` (a session was established).
- macOS: `qeli-mac/QeliMac/Vpn/VpnTunnel.cs` — `ConnectWithRetry` (`:110/:131`). Same as win.

**Acceptance.** A healthy session → a drop → the first reconnect without escalation;
only consecutive connect failures grow the delay. A unit/smoke on Rust; a manual one
— on the clients at build time.

---

## F2 — The server pushes the subnet prefix; the clients apply it

**The problem.** All clients set the mask `255.255.255.0` (Rust `:868`, win
`NetworkConfigurator.cs:99`, mac `:58`, Android `addAddress(ip,24)`). The server
supports any pool CIDR (`pool.rs`, down to /30), but the prefix is not transmitted in
`OK:{…}` → a non-/24 pool breaks on-link client↔client routing.

**The approach (additive, non-breaking).** The server puts a `prefix` field into
auth-OK (the pool's prefix length, int). The clients apply it (default 24 if the
field is absent — compatibility with an old server; an old client ignores the field).

**Files and points:**
- Server: `qeli/src/server/handler.rs` — `build_auth_ok` (`:749`). Compute the prefix
  from `pcfg.pool.cidr` (via `pool::parse_cidr`), add `"prefix"` to the JSON.
- Rust client: `qeli/src/client/mod.rs` — `AuthOk` (+`prefix:u8`), `parse_auth_ok`
  (`:812`, default 24), `setup_tunnel` (`:850`) — replace the hardcode with
  `prefix_to_netmask(prefix)`; add the helper `prefix_to_netmask`.
- Android: `QeliService.kt` — `Session`/`parseOk` (`:336`) add `prefix`
  (`optInt("prefix",24)`); `addAddress(clientIp, prefix)` (`:460`).
- Windows: `VpnTunnel.cs` — `Session` (+`Prefix`), `ParseOk` (`:433`),
  `SetAddress` takes a prefix → a dotted mask (`NetworkConfigurator.cs:99`).
- macOS: `VpnTunnel.cs` + `NetworkConfigurator.cs:58` likewise.

**Acceptance.** A /24 pool works as before; a non-/24 pool (e.g. /23) → the client
gets the correct mask. A unit on `prefix_to_netmask` + parsing `prefix`.

---

## S1 — Eliminate the user-enumeration timing oracle

**The problem.** `verify_client_auth` (`qeli/src/server/handler.rs:650`): for a
non-existent user it returns before Argon2; for an existing one — an expensive Argon2
→ the timing reveals the validity of the name.

**The approach.** For an unknown user, run an argon2 verification against a fixed dummy
hash (to equalize the work), then return an error anyway. The comparison result is
ignored.

**File.** `qeli/src/server/handler.rs` — the `None` branch in `db.find_user`.

**Acceptance.** The response time for an unknown user ≈ the time for a
correct-user-wrong-password.

---

## S2 — Reject a degenerate X25519 shared secret

**The problem.** `exchange.rs::derive_shared` (`:29`, `:95`) accepts any peer pubkey,
including low-order points (the shared secret = all zeros).

**The approach.** After the DH, check that the result is not all-zero, constant-time
(`subtle`). Return an error/empty result on a degenerate input. Since `derive_shared`
currently returns a `SharedSecret` (not a Result), add a checked variant or check at
the handshake sites. Minimally invasive: add `derive_shared_checked() ->
Option<SharedSecret>` and use it in both handshakes (server/client), leaving
`derive_shared` for the internal sites.

**Files.** `qeli/src/crypto/exchange.rs`; the handshake points in
`server/handler.rs`, `client/mod.rs`, `server/udp_handler.rs`.

**Acceptance.** A unit: a low-order/identity pubkey → rejection. An ordinary exchange
— with no regression.

---

## S3 — A robust `recv_peek` (REALITY detection)

**The problem.** `server/reality.rs::recv_peek` (`:250`): a ClientHello arriving in
many small segments can exhaust 40 iterations (with a `continue` on growth without a
sleep) → a truncated peek → the token doesn't parse → a legitimate client goes to the
decoy.

**The approach.** Replace the "by iteration count" budget with a "by time" budget (a
common deadline via `tokio::time::timeout`/`Instant`), with a sleep on each
non-growing iteration; or a short sleep on every iteration regardless of growth. Keep
the existing outer `timeout(1000ms)`.

**File.** `qeli/src/server/reality.rs`.

**Acceptance.** A multi-segment slow ClientHello within the timeout window is
assembled in full; there is no false bridge. A unit (an in-memory segmented stream).

---

## H1 — Remove the stray binary from the tree

`qeli/local_copy/qeli` (≈2.5 MB) — not a build dir, not in `.gitignore`. Remove.
**Acceptance.** The file is gone; builds/tools don't reference it.

---

## H2 — Sort out `scripts/`

~250 one-off scripts. Pull out the maintained ones (`lab_sync_build.py`,
`ci-check.sh`, `add-client.sh`, deploy-*, lab*.py) — keep them in `scripts/`; move the
rest (`check-*`, `debug-*`, `fix-*`, `bench_v*`, `reconnect_*`, probe_* …) to
`scripts/archive/`. Don't delete — archive.
**Acceptance.** The root of `scripts/` contains only live tooling.

---

## B1 — Rebuild the clients' native cores (lab) — ✅ DONE

> The result — the "Phase B (build)" section below: all 4 cores are rebuilt from a
> fresh `realtls` (Win dll/.10, Android .so×2/.11, mac dylib/.10) and laid out in the
> consumers + `native-libs/`. The acceptance criterion (a core ≥ the latest realtls
> change) is met.

The bundled `libqeli.so`/`qeli.dll`/`libqeli.dylib` were built 06-06 15:14–15:38, the
realtls sources were edited until 19:36 → the clients carry the old core. After Phase
1, rebuild the cdylib from the current source and re-lay-out:
- Android: cargo-ndk on .11 (arm64-v8a + x86_64) → `qeli-android/app/src/main/jniLibs/`.
- Windows: `x86_64-pc-windows-gnu` + mingw on .10 → `qeli-win/QeliWin/native/qeli.dll`.
- macOS: cargo-zigbuild universal2 on .10 → `qeli-mac/QeliMac/native/libqeli.dylib`.
Then rebuild the APK / exe / app.
**Acceptance.** The mtime/hash of each core ≥ the latest change in
`qeli/src/protocol/realtls/**`. Desirable: a CI check "the core hash matches the source".

---

## B2 — Rebuild the release artifacts (lab) — ✅ DONE (except the mac notarization)

> The result — the "Phase B (build)" section: `release/qeli-linux-amd64`,
> `release/qeli.apk` (+`qeli-android/dist/`), Windows `qeli-win/dist/QeliWin.exe`,
> macOS `qeli-mac/dist/Qeli.app`+zip — all from a fresh source. mac is signed ad-hoc;
> notarization (Developer ID) — the backlog M3.

`release/qeli-linux-amd64` (06-03) and `release/qeli.apk` (05-31) are stale. After
Phase 1 + B1: `cargo build --release` (the Linux server), a fresh APK, exe, app → replace
in `release/`. Run `scripts/lab_sync_build.py` (build+test+clippy+e2e).
**Acceptance.** All artifacts are built from the current source; the e2e gate is green.

---

## B3 — Release from VCS

The working copy here is not under git. Make sure the edits are synced into the
canonical repository (`/opt/qeli-src` on .10), committed, and the release is cut from
a tag with the fresh B1/B2 artifacts included.
**Acceptance.** A release tag exists; the tree is clean; the artifacts in the tag are
current.

---

## External audit (a second source) — review (2026-06-06)

A second audit was received from an external source. **Checked against the sources,
not taken on faith.** Conclusion: it is **accurate on the at-rest storage of client
secrets and Android IPv6** (valuable new findings — in the plan below), but contains
**substantial errors on the server/web/crypto** (refuted against the code). We take
only the confirmed part.

### ✅ Confirmed against the code — added to the plan

| ID | Ext. | What (with anchors) | Real severity | Approach |
|----|--------|---|:---:|---|
| **E1** | A1/WN1/M1/X1 | Client secrets in plaintext: Android `MainActivity.kt:229/267` (`SharedPreferences`, no `EncryptedSharedPreferences`); Windows `ProfileStore.cs:29`/`ServiceState.cs:39` (JSON, no DPAPI); macOS `ProfileStore.cs:28`/`AppSettings.cs:40` (JSON, no Keychain). The password/obfs_key/pubkey on disk in the clear. | HIGH (at-rest; root/forensic/multi-user) | Android `EncryptedSharedPreferences`+Keystore; Windows `ProtectedData`(CurrentUser DPAPI) or Credential Manager; macOS Keychain or `NSFileProtectionComplete`. A common `SecureStore` interface. |
| **E2** | A4 | An IPv6 leak in full-tunnel: Android `QeliService.kt:497` (only `AF_INET`); Windows/macOS — full-tunnel routed only IPv4 (`0.0.0.0/1`+`128.0.0.0/1`/`-inet`). IPv6 escapes around the tunnel on dual-stack. | HIGH | full-tunnel: route `::/1`+`8000::/1` (+ULA) into the tunnel — Android `addRoute("::",0)`+`allowFamily(AF_INET6)`; Win/mac `NetworkConfigurator.CaptureIPv6()`. An IPv4-only server blackholes it. **All 3 clients.** |
| **E3** | S2 | `mode=obfs` + an empty `obfs_key`: the TCP server (`mod.rs:1204`) derives a **publicly computable** constant key; UDP (`udp_handler.rs`) silently disables obfs. Under the obfuscation it's still X25519+ChaCha20+Argon2 → not an auth break, but a degradation of DPI resistance. | MED (misconfig) | `validate_profiles`: `bail` on `mode=obfs && obfs_key.is_empty()` (both transports); the client — the same. |
| **E4** | W1 + auth | The web panel over HTTP without TLS (`web/mod.rs:94`) and **open with an empty** `password_hash` (`auth.rs:27`). The default `bind=127.0.0.1` (NOT 0.0.0.0 — see below), so it's critical only on a public bind. | MED (depends on bind) | a startup warn when `web.bind` ≠ loopback (especially with an empty password); doc: public access — only behind a TLS reverse-proxy/SSH tunnel. |
| **E5** | C3 | No `cargo audit`/`cargo deny` in CI (only functional tests). | LOW (hygiene) | an advisory job in `ci.yml`. |

### 🟧 Backlog hardening — status of the 2026-06-07 round

**✅ Done:**
- **A5** — a server key change = a security event: Win/mac `catch (SecurityException)`
  → do NOT retry + an explicit warning "identity changed, possible MITM, stop";
  Android already did this (mismatch→SecurityException→stop). Win/mac `dotnet` 0/0.
- **S1-cfg** — the new-session `RateLimiter` is configurable:
  `perf.connection.new_session_rate_max` (def 10) / `new_session_rate_window_secs`
  (def 60); it was hardcoded 10/60. Gate PASS.
- **X2** — an explicit "how to choose a wire mode" block in `CONFIG.md` (fake-tls=D1/D2;
  reality-tls=D3 explicitly; obfs=entropy DPI; plain=trusted networks).
- **A6 (Android)** — a real kill-switch = the system "Always-on VPN + block
  connections without VPN" (Settings→VPN). Our `VpnService` is compatible — it works
  without extra code; the user just needs to flip the toggle.

**⛔ Blocked by objective reasons (we don't do it blindly):**
- **WN5** (BouncyCastle→native) — full removal is impossible: .NET 8 has **no native
  X25519** (the BCL is needed precisely for `Rfc7748.X25519`). A migration to .NET 9 is
  rejected (STS — EOL earlier than .NET 8; and native X25519 in 9/10 is in question).
  **BUT the audit's real claim — the timing CVE-2024-30171 on X25519 in BC 2.4.0 — is
  CLOSED by a bump `BouncyCastle.Cryptography 2.4.0 → 2.5.1`** (win+mac, without a
  runtime change; the API is compatible, builds 0/0). So the security substance of WN5
  is done.
- **WN3** (the service not `LocalSystem`) — Wintun creates the adapter+routes → it
  needs **SYSTEM** (the WireGuard service itself runs under SYSTEM). `LocalService`
  will break the VPN. A Windows rig is needed.
- **WN4** (autostart) — the GUI is `requireAdministrator`: a Run-key → **UAC every
  logon** (worse); a signed Scheduled Task → needs a **Windows code-signing
  certificate** (none — a separate purchase, like M3). The current Scheduled Task `/RL
  HIGHEST` is already optimal.
- **A6 (desktop Win/mac)** — a firewall kill-switch (WFP/pf): cannot be shipped
  untested (a rule-cleanup bug = the user without network with no recovery). The safe
  design — a WFP **dynamic-session** (auto-cleanup on process exit) / a pf-anchor; it
  requires a Windows/macOS rig for a run.

**⏸️ Discussed separately (on request):** A3 (biometrics), M2 (NetworkExtension), M3
(mac Developer-ID + notarization). Essentially WN3/WN4/WN5 belong here too — they need
a certificate / .NET 9 / a Windows rig.

### ❌ Not confirmed / inaccurate (reviewed against the code — NOT taken into work)

| Ext. | The claim | The fact per the code |
|--------|---|---|
| **S3** | the control socket on `0.0.0.0`, any host user calls kick/ban | `control.rs:8,51,55` — a **Unix socket** `/var/run/qeli/control.sock`, permissions **0600** (root only). Wrong. |
| **W2** | `PUT /api/config` without validation = RCE for a low-priv admin | `config.rs:42-69` — a full deserialization into `ServerConfig` + a path-whitelist (`logging.file`/`users_file`) + `check_auth`. There's no low-priv role; changing the config is an admin function. Wrong. |
| **W4** | `/api/logs` without auth, a Bearer token in the URL | `logs.rs:28` — `check_auth` + a path-whitelist (`ALLOWED_LOG_DIRS`). There's no Bearer path. Wrong. |
| **W1** | the default bind `0.0.0.0:8080` | `config/server.rs:441` `default_web_bind()="127.0.0.1"`. The default is localhost; severity reduced (see E4). |
| **S1** | the `auth.brute_force` config is ignored, hardcoded 10/60 | Lockout = `FailedAuthTracker`, built from `auth.brute_force.{max_attempts,window,lockout}` (`mod.rs` run_worker). 10/60 is a separate new-session `RateLimiter`. Wrong in substance; a trifle → backlog. |
| **C1** | `chacha20poly1305 = "0.5"` without zeroize → the key isn't zeroed | In `Cargo.toml` — `"0.10"` (the version is wrong). And 0.10 depends on `zeroize` **non-optionally** → the key is zeroed in `Drop` **always** (there's no feature flag — an attempt to add `features=["zeroize"]` breaks the build). The `cipher.rs` comment was correct. Wrong in substance. |
| **C3** | "CVE-2025-XXX ring JIT bug" | `ring` has no JIT; the CVE number is a placeholder. A fabrication. (The `cargo-audit` recommendation kept → E5.) |
| **Tell 1.3** | fake-tls without `x25519mlkem768` | `tls.rs build_supported_groups`/`build_key_share` send `0x11ec` **first** (1216 B). `DPI-AUDIT.md` 1.3 = ✅. Wrong. |
| **A2** | the password via `Intent.putExtra` | an extra with the password not found; the service reads the profile from storage (→ this is E1, not Intent). Not confirmed. |
| **C2** | no "PAKE binding" on profile rotation | qeli has no PAKE; the session keys are always derived from a fresh handshake transcript. A confusion, not a bug. |
| **DPI 1.x/2.x** | fake-tls tells (ALPN/ext/nonce/size) | Accurate, but **already** in `docs/DPI-AUDIT.md` with statuses; closed by the `reality-tls` mode. Not new. |

## Summary table — round 2 (the external audit)

| ID | Severity | Topic | Status |
|----|:---:|---|:---:|
| E1 | 🟠 HIGH | Client secrets in plaintext (Android/Win/Mac) | ✅ made + built (3 clients) |
| E2 | 🟠 HIGH | An IPv6 leak in full-tunnel (Android+Windows+macOS) | ✅ all 3 clients (routing IPv6 into the tunnel) |
| E3 | 🟡 MED | `obfs` + an empty `obfs_key` (config validation) | ✅ |
| E4 | 🟡 MED | Web: a warn on a public bind + an empty password; doc the TLS-proxy | ✅ (warn; the doc — in this section) |
| E5 | ⚪ LOW | `cargo audit`/`deny` in CI | ✅ |
| E6 | — | chacha zeroize | ❌ refuted — 0.10 zeroes the key always (no feature; the claim is wrong). The comment clarified. |

## Phase B (build) — progress

Locally available are dotnet 8.0.421 + the Android SDK (`C:\Android\Sdk`), so part of
B1 was done right here:
- **The Windows client** (`dotnet build -c Release`) — **0 errors / 0 warnings**. Validates F1/F2/E1 (Windows), the package `System.Security.Cryptography.ProtectedData` was pulled in.
  - 🐞 The build caught a bug: F2 added a duplicate `PrefixToMask` in `NetworkConfigurator.cs` (the method already existed for `AddRoute`). The duplicate removed, `SetAddress` calls the existing one.
- **The macOS client** (`dotnet build -c Release`, TFM `net8.0`) — **0 / 0** (after a guard `!OperatingSystem.IsWindows()` around `SetUnixFileMode`). Validates F1/F2/E1 (macOS, `SecureKey`/AES-GCM).
- **Android** — `gradlew :app:compileDebugKotlin` — **BUILD SUCCESSFUL** (23s). Validates F1/F2/E1/E2 (Kotlin), the dependency `androidx.security:security-crypto` resolved.

**The result of compile validation (the batch build):** all components build cleanly —
the Rust core (the gate, 168 tests) + 3 clients (Win 0/0, mac 0/0, Android Kotlin OK).
All edits from rounds 1–2 (F1, F2, S1, S2, S3, E1, E2, E3, E4, E5) are compiled.

**B1 — the native cores are rebuilt from a fresh `realtls` and placed in the tree (✅):**
- Windows `qeli.dll` — .10 (mingw, `x86_64-pc-windows-gnu`), 3.72 MB, 6 FFI symbols → `qeli-win/QeliWin/native/qeli.dll`.
- Android `libqeli.so` — .11 (cargo-ndk, NDK 26.3), arm64-v8a 567KB + x86_64 658KB, 7 JNI + 6 FFI → `qeli-android/.../jniLibs/`.
- macOS `libqeli.dylib` — .10 (`cargo-zigbuild` + zig 0.13, universal2 x86_64+arm64), 8.83 MB → `qeli-mac/QeliMac/native/libqeli.dylib`. (zigbuild on .10 IS there — an early probe missed `~/.cargo/bin`.)

**B2 — the artifacts are built (✅, including the mac .app):**
- `release/qeli-linux-amd64` — the server, 5.95 MB, from the fresh gate build.
- `release/qeli.apk` — 17.13 MB, both fresh `.so` packed + the F1/F2/E1/E2 edits (`assembleDebug` locally, Android SDK).
- The Windows exe — `dotnet publish -c Release -r win-x64`, 190 KB, the fresh `qeli.dll` embedded as an EmbeddedResource (`qeli-win/.../publish/QeliWin.exe`).

**Layout into the standard folders (2026-06-06):**
- The native cores — both in the consumers (`qeli-android/.../jniLibs`, `qeli-win/QeliWin/native`,
  `qeli-mac/QeliMac/native`), and in the centralized store `native-libs/`
  (`android/{arm64-v8a,x86_64}/libqeli.so` — the folder created; `windows-x64/qeli.dll`,
  `macos-universal/libqeli.dylib` — updated, the old copies replaced).
- The Android APK → `qeli-android/dist/app-debug.apk` (17.96 MB, the previous one rotated to `app-debug.prev.apk`) AND `release/qeli.apk`. `release/qeli-linux-amd64` (5.95 MB) — the server.
- The Windows app → `qeli-win/dist/` (`QeliWin.exe` + the framework-dependent publish, 41 files).
- macOS `qeli-mac/dist/Qeli.app` — ✅ **REBUILT** (universal, the fresh C# E1/F1/F2 + the fresh
  dylib) + `Qeli-macOS-universal.zip` (56 MB). The "without a Mac" flow: `dotnet publish
  osx-arm64+osx-x64 --self-contained` (locally) → `llvm-lipo` merging all Mach-O into a
  universal on .10 → an `rcodesign` ad-hoc signature → zip. Script `scripts/build_mac_universal.py`.
  Verified: apphost + libqeli.dylib + Skia/HarfBuzz/Avalonia + 15 runtime-native = universal (2 arch).

**The remainder (does not block the fixes):**
- **mac notarization** — `Qeli.app` is signed **ad-hoc**; Developer ID + notarytool — a separate M3.
- **e2e on the lab** — a reconnect without escalation (F1), a non-/24 pool (F2), the ordinary modes (regression). It needs orchestration of the emulator(.11)↔server(.10) + a test profile/creds on .10.

## Execution log

- 2026-06-07: **WN5 (the safe part) — a bump `BouncyCastle.Cryptography 2.4.0 → 2.5.1`**
  in qeli-win + qeli-mac (closes the timing CVE-2024-30171 on X25519, without a runtime
  migration). The API is compatible, builds 0/0, the dist repacked (exe + the mac
  `.app`). The server (Rust) doesn't use BouncyCastle → production is not affected.
- 2026-06-07: **Backlog hardening, round 1.** Done: **A5** (Win/mac don't retry a
  server key change + a security warning; Android already did), **S1-cfg** (a
  configurable new-session rate limiter, gate PASS), **X2** (a wire-mode selection
  guide in CONFIG.md), **A6-Android** (a kill-switch via the system always-on/lockdown —
  works without code, documented). Blocked objectively: **WN5** (no native X25519 in
  .NET 8), **WN3** (Wintun requires SYSTEM), **WN4** (an admin app: a Run-key is worse,
  a signature needs a cert), **A6-desktop** (a firewall kill-switch can't be done
  without a rig — a lock-out risk). See the "Backlog hardening — status" section. S1-cfg
  is additive (def 10/60 = the previous), production doesn't need a redeploy.
- 2026-06-07: **A production deploy of a fresh server binary (YOUR_PROD_HOST).** A
  backup (`/root/backup/qeli-deploy/20260607-002649/` + `/root/qeli-rollback.bin`, the
  old 2.0.0/`5fe1cadf`) → a pre-flight (the new binary `0.5.6`/`ba1675ac` runs on the
  prod glibc 2.41, parses the config, the identity `7ff1c274` intact, E3 ok — all
  obfs profiles with a key) → a swap of `/usr/local/bin/qeli` → `systemctl restart
  qeli`. The version 2.0.0→0.5.6 (unification; the code is newer, the wire is
  compatible — F2 is additive). Check: 7 profiles up (4 TCP+3 UDP), 0 errors/panics,
  the identity intact, **a live e2e .11→prod faketls:8443 (client1) → Auth OK, IP
  10.9.1.2, ping 0%/37ms**. The config untouched. A rollback at the ready.
- 2026-06-07: **The E series finished (full coverage).**
  - **E2-desktop** — the IPv6 leak closed on **Windows** and **macOS** too (previously Android only):
    `NetworkConfigurator.CaptureIPv6()` in full-tunnel routes `::/1`+`8000::/1` into the tunnel
    (an ULA on the adapter; an IPv4-only server blackholes it → no leak). All calls are `optional`/best-effort.
  - **E3-clients** — an empty-`obfs_key` guard added in Android (TCP+UDP), Windows (TCP+UDP),
    macOS (TCP+UDP) — symmetric to the Rust client and the server `validate_profiles`.
  - **E1-AppSettings** — verified: `AppSettings.cs` (Win/mac) contains NO secrets (language/theme/
    autostart/profile names) → no encryption needed; the WN2 "CRIT" claim is overstated. The real
    secrets (profiles) are already encrypted in ProfileStore/ServiceState.
  - Build: Win `dotnet` 0/0, mac `dotnet` 0/0, Android `assembleDebug` SUCCESS. The artifacts
    repacked (exe, APK; the mac `.app` rebuilt — the dylib didn't change, reused).
- 2026-06-06: **Phase B completed + e2e PASS.** The native cores ×4 rebuilt from a fresh
  realtls (Win dll/.10, Android .so×2/.11, mac dylib/.10) and laid out (consumers +
  `native-libs/`). Artifacts: `release/qeli-linux-amd64`, the APK (`qeli-android/dist/` +
  `release/`), Windows `qeli-win/dist/`, macOS `qeli-mac/dist/Qeli.app`+zip (universal,
  ad-hoc) — the script `scripts/build_mac_universal.py`. e2e on the lab (.10↔.11)
  tcp/obfs/udp — 0% loss, throughput normal. The lab service restored (active). Open: B3 +
  the backlog.
- 2026-06-06: the document created from the audit results. Started executing Phase 1.
- 2026-06-06: **The fix phase CLOSED — E2 and E1 made (batch, no intermediate builds).**
  - **E2** — Android `QeliService.kt` setupTunInterface: in full-tunnel route IPv6
    (`addAddress("fd00:71e1::1",128)` + `addRoute("::",0)` + `allowFamily(AF_INET6)`),
    the server IPv4-only → IPv6 is dropped, doesn't leak.
  - **E1** — at-rest encryption on all 3 clients (+a migration of the legacy plaintext):
    Android `EncryptedSharedPreferences` (the master key in Keystore, the store
    `vpn_secure`, the legacy `vpn` wiped); Windows `ProfileStore` DPAPI CurrentUser +
    `ServiceState` DPAPI LocalMachine (UI↔service cross-user); macOS AES-256-GCM with a
    key from Keychain (the `security` CLI, `SecureKey.cs`) + a 0600 fallback. New
    dependencies: `androidx.security:security-crypto`,
    `System.Security.Cryptography.ProtectedData`. ⚠️ (at that point) the client edits
    F1/F2/E1/E2 didn't build yet — **since then they've been built in phase B**, all 3
    clients compile, the artifacts rebuilt (see "Phase B").
- 2026-06-06: **Round 2 (the external audit), the server/Rust edits implemented + gate PASS**
  (build OK · **168 tests / 0 failed**, +`obfs_wire_mode_requires_obfs_key`/`_with_key_is_allowed` · clippy 0):
  E3 (validation of a non-empty obfs_key: `validate_profiles` + the client TCP/UDP),
  E4 (a web warn on a non-loopback bind + an empty password), E5 (a `cargo audit` advisory job in CI).
  E6 **refuted** (chacha 0.10 zeroes the key always; an attempt to add a feature broke
  the build — reverted, the `cipher.rs` comment clarified). Remaining from round 2: E1, E2 (the clients).
- 2026-06-06: **The external audit (a second source) reviewed** — see the section above.
  The confirmed part (E1–E6) added to the plan; the wrong/inaccurate claims (S3, W2, W4,
  W1-default, C1-version, C3-CVE, Tell 1.3, A2, C2) refuted against the code. The value
  of the external audit — the at-rest storage of client secrets (E1) and Android IPv6 (E2).
- 2026-06-06: **Phase 1 completed in the sources** (a build/tests on the lab required):
  - **F1** — reset the backoff after an established session: Rust `client/mod.rs`
    (`retry_count=0` on `Ok`); Android `QeliService.kt` (`attempt=0` on
    `liveStatus==CONNECTED`, both paths); Win/Mac `VpnTunnel.cs` (reset on
    `_wasConnected`, both paths).
  - **F2** — the server pushes `prefix` (`handler.rs::build_auth_ok` from `pool.cidr`);
    applied by: Rust (`AuthOk.prefix` + `prefix_to_netmask` + `setup_tunnel`),
    Android (`addAddress(ip, prefix)`), Win/Mac (`Session.Prefix` +
    `NetworkConfigurator.SetAddress(prefix)` → a dotted mask). Default /24.
    Unit tests added (`prefix_to_netmask`, parsing `prefix`).
  - **S1** — `handler.rs`: a throwaway Argon2 verification for an unknown user
    (`dummy_password_hash()`), the response time equalized.
  - **S2** — `exchange.rs::derive_shared_checked` (a constant-time rejection on all-zero);
    wired on ALL ephemeral DH (server TCP/UDP + client plain/fake-tls/udp).
    The static-key derives left as is (auth-proof). + unit tests.
  - **S3** — `reality.rs::recv_peek` rewritten to a time budget (deadline 900ms +
    stall 200ms, sleep 2ms) instead of 40 iterations. + a regression test on a segmented stream.
  - **H1** — `qeli/local_copy/qeli` removed.
  - **H2** — 154 one-off scripts → `scripts/archive/` (+ a README).
  - ⚠️ There's no Rust toolchain on the dev machine → run `cargo test`/`clippy` and the
    client builds on the lab (Phase 2). The edits passed a static self-check.

## The lab gate — ✅ PASS (2026-06-06)

`scripts/lab_sync_build.py` (sync → `/opt/qeli-src` on .10). The final run (after E3):
- `cargo build --release` → **OK** (1m36s).
- `cargo test --all` → **OK, 168 passed / 0 failed** (was 161; +7: `recv_peek_reassembles_segmented_window`, `derive_shared_checked_rejects_low_order_point`, `derive_shared_checked_accepts_normal_exchange`, `prefix_to_netmask_known_values`, `parse_auth_ok_reads_prefix_with_default`, `obfs_wire_mode_requires_obfs_key`, `obfs_wire_mode_with_key_is_allowed`).
- `cargo clippy --all-targets -- -D warnings` → **OK** (0 warnings).
- `qeli-server.service` on .10 — `active`/`enabled` after the run (the lab not left down).

Validated the Rust edits: F1(Rust), F2(server+Rust-client), S1, S2, S3. The edits in
the Kotlin/C# clients are NOT covered by the gate — they'll be checked at the client
build (B1).

## e2e on the lab — ✅ PASS (2026-06-06)

`scripts/sanity_e2e.py` (a fresh release binary on the .10 server + the .11 client, two hosts):
- **tcp-faketls** → `Auth OK`, ping **0% loss** (avg 2.0 ms), 562↑/717↓ Mbps.
- **tcp-obfs** (obfs_key=`benchkey`) → `Auth OK`, ping **0% loss**, 500↑/573↓ Mbps. (E3: a non-empty key → ok.)
- **udp-faketls** → `Auth OK`, ping **0% loss**, the UDP sweep clean up to 400 Mbps (0.49%), saturation at 500.

Confirms the absence of a regression: the tunnels come up and push traffic in all modes
with all the edits (the S2 DH check didn't break the handshake; the F2 prefix gives
correct addressing; E3 obfs works; throughput at the level of the previous benchmarks).
After the run `qeli-server.service` on .10 was returned to `active` (port 443
listening). *(`sanity_e2e.py` itself was fixed — it lagged behind the `benchmark.run_mode`
schema: `mode` → `client_mode`/`server_mode`.)*

Not covered pointwise (requires bespoke tests, not blockers): F1 (reconnect timing on
repeated drops), F2 on a non-/24 pool, S2 with a genuinely malicious low-order key.

## Remaining (open items)

All code fixes, builds, and the e2e regression are closed (see above). Genuinely open:

1. **B3** — a commit to the canonical repository (`/opt/qeli-src` on .10) + a release tag
   with the current artifacts.
2. **Backlog hardening** (not release blockers, a separate wave): A3/A5/A6 (UI:
   biometrics, the TOFU warning, the kill-switch), WN3/WN4/WN5
   (service/task/BouncyCastle→native), M2 (NetworkExtension), **M3 (mac Developer-ID +
   notarization)**, S1-cfg (RateLimiter), X2 (`reality-tls` by default).
