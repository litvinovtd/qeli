# Android to iOS parity ledger

## Implemented foundation

- Connection / Profiles / Log navigation and Qeli visual language.
- Profile CRUD, active-profile locking while connected (refused with an alert, and the
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
  as a config format; JSON remains only inside the backup container.
- Share link, QR generation and system share sheet.
- Encrypted-at-rest profile store and Android-compatible backup encryption.
- Theme, launch auto-connect, VPN On Demand, full-tunnel-only LAN bypass and log timestamp settings.
- Opt-in, privacy-gated release check matching Android's public release metadata flow.
- Network Extension manager/provider lifecycle and shared status/log channel.
- The production Packet Tunnel is an ABI 1.11 adapter over the common Rust whole-client
  core used by Linux, Android, Windows and macOS. Rust owns DNS/connect, plain and
  hybrid-PQ authentication, TCP/UDP/QUIC/obfs/REALITY, packet crypto, heartbeat/shaping,
  MTU discovery and fixed/adaptive bonding for one generation; Swift owns only the
  reconnect-policy lifecycle that starts the next Rust generation.
- Swift owns only Apple platform operations: Keychain device/trust state,
  `NEPacketTunnelNetworkSettings`, lifecycle/status and bounded packet batches between
  `NEPacketTunnelFlow` and `qeli_client_tun_push/pull`. It ACKs a `NetworkPlan` only after
  all IPv4 routes and supported DNS settings have been applied; unsupported plans fail closed.
- Authenticated `NetworkPlan` UI facts keep server-pushed routes distinct from local/client
  routes and report effective post-push padding, heartbeat and shaping values without Swift
  parsing handshake payloads.
- Eight former Swift handshake/transport/runtime files (4,046 lines) were removed from the
  production target. The remaining Swift crypto/protocol sources are conformance/KAT code
  and are excluded from the Packet Tunnel target.
- The iOS packet bridge has a fixed memory budget: two Rust pools of 32 × 65,535-byte
  buffers (4,194,240 bytes), 128-slot queues and at most three reusable 256 KiB Swift
  caller buffers, with backpressure and no fallback allocation.
- `build_native.sh` builds device and simulator slices with `transport-core-ffi`, packages
  the canonical ABI header and creates the XCFramework. CI runs that build, compiles the
  generated Xcode project for the simulator and runs its unit tests. A signed physical-device
  build and runtime pass remain outstanding.
- WidgetKit status widget with an authenticated App Intent action and an iOS 18
  Control Center / Lock Screen / Action button control. The toggle drives the installed
  tunnel from the widget process, so it connects without foregrounding the app (matching
  the Android widget / Quick Settings tile); if the extension cannot reach the tunnel the
  request is queued and applied at the next app launch.
- Managed app configuration reader and truthful Per-App VPN / IKEv2 Always On MDM
  templates.

## Remaining verification milestones

1. Build the ABI 1.11 Rust XCFramework and generated project on macOS/Xcode 16+, then compile
   both the app and Packet Tunnel targets; this cannot be substituted by the Linux Rust
   cross-target check.
2. Run physical-device interoperability tests against every Android/server wire mode,
   including packet loss, Wi-Fi/cellular transitions and bonded-stream failure.
3. Measure packet-pump memory, backpressure, throughput, UDP loss and MTU behaviour on
   device. Buffer/queue tuning is intentionally a separate performance pass after the
   architecture migration.
4. Complete App Store signing/provisioning and Apple Network Extension entitlement
   approval for the final bundle identifiers.

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
