# Android to iOS parity ledger

[Русский](../../ru/reference/IOS-ANDROID-PARITY.md) · English

## Current audit, 28 October 2026

[Detailed matrix, fixes and verification boundaries](../reports/IOS-ANDROID-PARITY-2026-10-28.md).
The following list describes implementation, not an assertion of Apple runtime parity.

- Added opt-in foreground auto-probe of profiles, bounded concurrency/intervals, and
  cancellation on app backgrounding or VPN activation.
- Added bounded current/last-error diagnostic reports, opt-in retention, redaction and
  numeric carrier snapshots through C ABI 1.17. Last-error retention is off by default.
- Preserved imported INI comments/order; corrected selected-language strings in dynamic
  app/widget UI; QR scanning uses AVFoundation instead of an A12-only VisionKit path.
- Initial DNS failure now enters the shared reconnect budget, including cold recovery
  through a physical-interface-scoped lookup. Duplicate NWPath callbacks no longer cancel
  pending recovery. Explicit split-tunnel routes also use `enforceRoutes`.
- A new XCFramework from ABI 1.17 sources is required. Older prebuilt libraries do not
  provide the new symbol; no binary provenance has been re-labelled by this source audit.

## Implemented foundation

- Connection / Profiles / Log navigation and Qeli visual language. Qeli-owned iOS screens use
  the same explicit light/dark palette, header dimensions, segmented pill navigation, card
  outlines and status colours as Android instead of UIKit's grouped-list palette. The Profiles
  action bar adapts to compact widths and Dynamic Type without truncating Russian labels; profile
  rows use the Android card/menu model, including explicit Move up/down actions. Apple permission
  prompts, share sheets, pickers and other operating-system surfaces deliberately remain native.
- Profile CRUD, active-profile selection/deletion locking while connected (refused with an alert, and the
  rows that cannot be picked are dimmed), reorder and reachability — TCP by a connect
  probe, UDP through ABI 1.8 `qeli_client_udp_probe`, which invokes the same Rust
  X25519+ML-KEM first-flight/fragment/QUIC/obfs builder as Android and the live tunnel.
  While the active tunnel is up both protocols measure the exact authenticated tunnel
  gateway rather than the public endpoint; UDP remains a UDP first-flight probe.
- English / Russian UI with an in-app language picker. English is the default on every
  device, matching Android — the app does not follow the system locale.
- Connection-properties card, shown only while connected and driven by the shared
  `ProtectionSummary` decisions so both clients describe the same session identically: wire
  mode and transport, hybrid-PQ vs plain X25519, pinned key vs TOFU, and a warning line that
  replaces the facts when something narrows the tunnel. Tapping it opens the detail sheet
  with everything the server pushed — tunnel IP, DNS, applied MTU, bonded streams and
  whether they ramp adaptively, the advertised routes, and the padding / heartbeat /
  traffic-shaping knobs in force. The route list is capped where the snapshot is built
  (`PushedFacts.routeSample`), because a server may advertise an arbitrarily long set. The
  session token is deliberately never surfaced: it is the credential that authorises a
  bonded stream to join the session.
- Flat-INI file/clipboard import, QR and `qeli://` deep-link import. Legacy JSON is rejected
  as a config format; JSON remains for backups, diagnostic reports and internal ABI messages.
  Editing a connected profile is allowed, with a manual reconnect required to apply it.
- Share link, QR generation and system share sheet.
- Encrypted-at-rest profile store and Android-compatible backup encryption.
- Theme, launch auto-connect, VPN On Demand, full-tunnel-only LAN bypass and log timestamp settings.
- Clear-log-on-disconnect setting, enabled by default as on Android; iOS saves it immediately
  and the packet extension applies it at normal stop without requiring the UI.
  Startup/authentication/transport errors always retain the diagnostic journal.
  Reconnects and resumable network/On Demand pauses retain history; late old-session callbacks
  cannot recreate a cleared journal. New storage/settings XCTest cases require an Xcode run.
- Opt-in, privacy-gated release check matching Android's public release metadata flow.
- Network Extension manager/provider lifecycle and shared status/log channel.
- The production Packet Tunnel uses the current ABI 1.17 core, requiring ABI 1.17 for carrier diagnostics, with optional
  ABI 1.12-1.14 path contracts and ABI 1.15 NOTICE/KICK management events over
  the common Rust whole-client core used by Linux, Android, Windows and macOS. Rust owns
  DNS/connect, plain and
  hybrid-PQ authentication, TCP/UDP/QUIC/obfs/REALITY, packet crypto, heartbeat/shaping,
  MTU discovery, fixed/adaptive bonding and the common TCP/UDP roaming policy. Swift owns
  the Apple path observer, path-scoped DNS/NAT64 probe, socket binding and excluded-route
  executor requested by that policy.
- Swift owns only Apple platform operations: Keychain device/trust state,
  `NEPacketTunnelNetworkSettings`, lifecycle/status and bounded packet batches between
  `NEPacketTunnelFlow` and `qeli_client_tun_push/pull`. It ACKs a `NetworkPlan` only after
  all active-family IPv4/IPv6 routes and supported DNS settings have been applied;
  unsupported plans fail closed.
- Authenticated `NetworkPlan` UI facts keep server-pushed routes distinct from local/client
  routes and report effective post-push padding, heartbeat and shaping values without Swift
  parsing handshake payloads.
- Eight former Swift handshake/transport/runtime files (4,046 lines) were removed from the
  production target. The remaining Swift crypto/protocol sources are conformance/KAT code
  and are excluded from the Packet Tunnel target.
- The iOS packet bridge has a fixed memory budget: two Rust pools of 32 × 65,535-byte
  buffers (4,194,240 bytes), 128-slot queues and at most three reusable 256 KiB Swift
  caller buffers, with backpressure and no fallback allocation on the packet path.
  Separate diagnostic sampling uses at most 64 KiB of native JSON plus bounded decoding/storage.
- `build_native.sh` builds device and simulator slices with
  `transport-core-ffi experimental-roaming` by default, packages the canonical ABI header
  and creates the XCFramework. CI runs that build, compiles the
  generated Xcode project for the simulator and runs its unit tests. A signed physical-device
  build and runtime pass remain outstanding.
- `NWPathMonitor` ignores tunnel/loopback interfaces and submits generation-scoped path or wake
  changes. A UDP `NWConnection` constrained by `requiredInterface` obtains the effective local
  and remote endpoint after DNS/NAT64 resolution. PREPARE keeps old+new exact carrier exclusions,
  BIND applies Darwin interface/source binding to the borrowed socket, COMMIT narrows routes to
  new-only, and ABORT restores old-only. Ordinary TCP and all UDP modes share this Rust transaction;
  explicit `local`/non-zero `lport`, old/default cores and unsupported peers reconnect normally.
- WidgetKit status widget with an authenticated App Intent action and an iOS 18
  Control Center / Lock Screen / Action button control. The toggle drives the installed
  tunnel from the widget process, so it connects without foregrounding the app (matching
  the Android widget / Quick Settings tile); if the extension cannot reach the tunnel the
  request is queued and applied at the next app launch.
- Managed app configuration reader and truthful Per-App VPN / IKEv2 Always On MDM
  templates.

## Remaining verification milestones

1. Build the feature-enabled ABI 1.17 Rust XCFramework and generated project on macOS/Xcode
   16+, then compile both the app and Packet Tunnel targets; the strict
   `aarch64-apple-ios` Rust cross-target Clippy passes on the Linux lab, but cannot substitute
   for Swift/NetworkExtension compilation.
2. Run physical-device interoperability tests against every Android/server wire mode,
   including packet loss, Wi-Fi/cellular transitions, wake, same-network NAT rebinding,
   NAT64, route rollback, per-app/MDM interaction and bonded-stream failure.
3. Measure packet-pump memory, backpressure, throughput, UDP loss and MTU behaviour on
   device. Buffer/queue tuning is intentionally a separate performance pass after the
   architecture migration.
4. Complete App Store signing/provisioning and Apple Network Extension entitlement
   approval for the final bundle identifiers. A runtime capability check now turns an incorrectly
   re-signed build into one actionable signing alert instead of consecutive Keychain/Network
   Extension errors, and `scripts/verify_ios_ipa.py` rejects such an IPA before distribution.

## iOS restrictions (not implementable as a normal consumer app)

- The protection card carries no Apps / Always-on buttons. Android puts two there; on iOS
  per-app routing needs MDM (below) and no app may offer an Always-On switch — VPN On
  Demand in Settings is the closest equivalent, so the card states the routing scope and
  leaves the controls where they actually live. The system lockdown row is Android-only for
  the same reason: `VpnService.isLockdownEnabled` has no iOS counterpart a Packet Tunnel
  Provider can read.

- Per-app routing rules for arbitrary installed applications require MDM-managed apps;
  iOS also does not expose an installed-app enumeration API to a consumer VPN app.
  Because of that, a profile's `apps_mode` is **carried but not applied** here, and the
  protection card says so rather than reporting the mode as the tunnel's scope: the scope
  follows the routes (what the platform enforces) and the unapplied selection appears as a
  warning. Android maps `apps_mode` to the scope directly, because there it is in force —
  this is the one place the two cards deliberately read the same profile differently.
- True Always-On VPN requires supervised MDM and Apple's IKEv2 Always On tunnel;
  Apple does not expose that enforcement mode to Qeli's custom Packet Tunnel Provider.
  VPN On Demand is the closest Qeli/consumer equivalent to Android boot auto-connect.
- There is no battery-optimization exemption flow or Android-style foreground service.

## Q30 source audit, 6 October 2026

[Scoped MDM/provider callback fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-POLICY-SNAPSHOT.md)
reject truncated numeric policies and invalidate stale provider replies across tunnel
transitions. Six new XCTest cases are retained but NOT_RUN on Windows; six Python
IPA-verifier fixture regressions PASS. These are not a simulator/device qualification.
Q30 remains IN_PROGRESS; the user excluded Apple runtime for this audit.

[Q30 Keychain source fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-KEYCHAIN.md) extend
first-writer ownership from the master key to device ID/TOFU and explicitly validate
stored key sizes. Seven Keychain XCTest are NOT_RUN; no cross-process/runtime claim.
The provider/engine completion review remains open.

Explicit malformed/stale provider profile requests now fail rather than falling back
to the persisted profile (Q30-F294); four new selector XCTest NOT_RUN.

[Q30 lifecycle source fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-LIFECYCLE.md) make monitor
Stop terminal, fence provider effects by current engine and serialize OS operations
across engines with callback-owned leases and a shared15s settings budget.13 new
helper XCTest NOT_RUN; real OS callback drain, memory, native joins and Apple build
remain unqualified. Never treat cancellation as an OS operation's completion.

[Q30 application preference fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-APP-PREFERENCES.md)
remove five status/epoch bypasses and serialize full managed reconciliation. Profile
settings are read at admission; connection generations and Task cancellation fence
obsolete preference steps. Three gate XCTest NOT_RUN; Apple runtime excluded.
Q30 remains IN_PROGRESS; provider-message/backup UI and final source review remain.

[Q30 messages/backup fixes](../reports/audit-0.8.2/AUDIT-Q30-IOS-MESSAGES-BACKUP.md)
bound the settings-message caller wait to20s, fence response ownership and admit
one unfinished snapshot poll per status epoch. Backup passwords are captured per
request; filenames derive from actual bytes.11 new XCTest NOT_RUN. Timeout does
not cancel/rollback an OS apply; final source memory/dead-code review remains open.

F302 moves remaining Swift wire-crypto helpers out of the app target into XCTest,
alongside Protocol, and removes unreferenced X25519/auth helper code. Backup storage
still uses CryptoKit directly; Rust/native transport crypto is unchanged. Actual
Xcode compilation and binary-size effects remain NOT_RUN.

[Q30 source/memory reconciliation](../reports/audit-0.8.2/AUDIT-Q30-IOS-SOURCE-MEMORY.md)
closes the source Review/dead-code criterion:92 Swift inputs,12 retained framework
entry points. F303-F306 unify cancellable probe ownership, prune obsolete pings,
bound log bytes (4KiB/message,1MiB encoded archive) and stream update data (1MiB).
11 new XCTest NOT_RUN; actual Apple callbacks/RSS/leaks/worker joins unqualified.
Q30 IN_PROGRESS; this source closure supersedes earlier open-review notes only.

**12 October agreed-scope reconciliation:** Q30 SOURCE REVIEW and portable checks are complete; Swift/Xcode/Apple execution is USER_SKIPPED by direct user decision. XCTest, real callbacks/RSS/leaks, signing and physical network scenarios remain NOT_RUN. Current92 Swift inputs match the reviewed inventory (91 byte-identical, one corrected test profile); project.yml only gained LICENSE/notices resources. Fresh IPA-verifier6,plist10,bindings and read-only-overlay docs9 PASS. This supersedes the historical whole-section IN_PROGRESS scope above; no Apple runtime PASS is claimed.
