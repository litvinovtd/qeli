# Qeli for iOS

Native iPhone client for the qeli protocol. The project mirrors the Android client's
three primary surfaces (Connection, Profiles, Log) and uses a Packet Tunnel Provider
extension for the VPN data plane.

## Status: feature-complete, simulator-built, device-unverified

**Neither a preview nor a release.** Not a preview, because the client is not a sketch —
it mirrors the Android client feature for feature, and that logic is proven in the field.
Not a release, because **the iOS application/extension has not been exercised on a physical
device**. CI builds the device/simulator XCFramework, compiles the generated Xcode project for
the simulator and runs its unit tests, but no real-hardware result exists and nothing ships from
this directory.

Read the Apple-specific list below as *what is implemented*, not *what is verified*.
The common Rust transport is exercised by the repository/lab matrix; the Swift adapter
still needs a signed physical-device pass — install, connect on each wire mode,
background/foreground, a Wi-Fi ↔ cellular switch, and On Demand behaviour — after which
this section should say what was actually observed, not only what was built.

The version tracks the rest of the repository (see `MARKETING_VERSION` in `project.yml`,
kept in step by `scripts/sync_version.py`) because the code is the same generation as
every other client, not because a build of it was released.

## Current implementation

- SwiftUI application shell with connection, profile and live-log tabs.
- Encrypted profile storage shared with the tunnel extension (App Group + Keychain).
- INI and `qeli://` profile import/export.
- QR scanning/generation, profile editing, duplication, ordering and sharing.
- Android-compatible encrypted backups (`QELI-ENC-1`, PBKDF2-SHA256, AES-256-GCM).
- Opt-in release checks that run only with a fail-closed full-tunnel route.
- `NETunnelProviderManager` lifecycle, VPN On Demand and status/statistics bridge.
- `NEPacketTunnelProvider` target with a small ABI 1.11 platform adapter. Swift applies
  authenticated `NetworkPlan` values, persists Keychain identity/trust and moves bounded
  packet batches between `NEPacketTunnelFlow` and Rust.
- The common Rust whole-client core owns each plain/fake-TLS/obfs/REALITY TCP/UDP/QUIC
  generation, X25519+ML-KEM, authentication, packet crypto, heartbeat/shaping, MTU and
  fixed/adaptive bonding. Swift owns only the lifecycle decision to start the next generation
  under the shared reconnect policy; no Swift wire implementation is on the production path.
- `NetworkPlan` application is fail-closed: unsupported DNS ports or routes that cannot be
  installed by the IPv4 Packet Tunnel adapter are rejected before the core receives ACK.
- The status bridge reports server-pushed routes separately from client/local routes and
  uses effective post-push padding, heartbeat and shaping facts supplied by Rust.
- Rust iOS XCFramework build script for the complete `transport-core-ffi` static library,
  including the canonical ABI header and device/simulator slices.
- Home Screen status widget and authenticated connect/disconnect action; iOS 18 adds
  the same action as a Control Center, Lock Screen and Action button control.
- MDM deployment templates, typed managed configuration, enforced profile/On-Demand
  precedence and an App-Group policy gate for managed WidgetKit controls.

The production Packet Tunnel now uses the same ABI 1.11 Rust transport as Linux, Android,
Windows and macOS. Swift applies `NetworkPlan`, persists trust/device identity and copies
bounded IP batches to/from `NEPacketTunnelFlow`; it no longer implements a wire protocol.
CI builds the real device/simulator XCFramework, compiles the generated Xcode project for
the simulator and runs the iOS unit tests. A physical-iPhone smoke test and the complete
interoperability matrix still have to be performed before release. See `PARITY.md` for that
validation work and Apple platform boundaries.

## Requirements

- macOS with Xcode 16 or newer.
- Apple Developer team with the Network Extension entitlement enabled.
- Rust 1.85 or newer with the Apple iOS targets (for the native protocol core).
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`).

## Generate and open

```sh
cd qeli-ios
sh build_native.sh
sh generate_project.sh
open QeliIOS.xcodeproj
```

Set `DEVELOPMENT_TEAM` and, if needed, `QELI_APP_BUNDLE_ID` in
`Config/Signing.xcconfig` — `DEVELOPMENT_TEAM` ships empty on purpose, and no
provisioning profile is committed. Everything else derives from the app bundle ID and can
still be overridden in CI.

### Signing and capabilities

Three App IDs must be registered, and they do **not** get the same capabilities. This
table is the entitlement files (`Config/*.entitlements`), not a recommendation:

| Target | Bundle ID | Network Extension | App Group | Keychain Sharing |
|---|---|:-:|:-:|:-:|
| `QeliIOS` (app) | `ru.qeli.app` | `packet-tunnel-provider` | ✓ | ✓ |
| `QeliPacketTunnel` (extension) | `…app.PacketTunnel` | `packet-tunnel-provider` | ✓ | ✓ |
| `QeliWidgets` (extension) | `…app.Widgets` | — | ✓ | — |

The shared identifiers are `group.ru.qeli.app` (App Group) and
`$(AppIdentifierPrefix)ru.qeli.app.shared` (Keychain Group).

The widget deliberately has **no** Keychain access: it renders status and requests a
desired state, and must never be able to read profile secrets. Granting it Keychain
Sharing to "make things consistent" would quietly widen the blast radius of a widget
compromise — the two extensions are not interchangeable.

The widget and iOS 18 control read status from the App Group. Their authenticated App Intents
write a short-lived, one-time desired-state request and then start/stop the already-installed
`NETunnelProviderManager` directly without foregrounding the main app. The queued request is a
fallback for a missing/unavailable tunnel and is applied on the next app launch. The widget has
no Keychain access and cannot create a profile or read its secrets. The
`qeli-control://status` URL is navigation-only.
Any future command URL must carry a fresh opaque token that already exists in the
App Group, so an arbitrary custom URL cannot authorize connect or disconnect.
WidgetKit controls timeline refresh frequency, so status can briefly lag when the
main app is suspended; the app explicitly reloads widgets on tunnel phase changes.
No universal-link domain is fabricated: Apple `OpenURLIntent` accepts universal
links, and one can only be added after an owned HTTPS domain and its association
file are available.

Packet Tunnel Providers do not run in the iOS simulator. Use a physical iPhone for
VPN testing. The first save/start asks the user to approve the VPN configuration.

## The native core

`QeliCore/Native/Qeli.xcframework` is **not committed** — it is `.gitignore`d and built by
`build_native.sh`, while `project.yml` requires it unconditionally. A clean checkout
therefore cannot generate the Xcode project until you run that script once; if
`generate_project.sh` or `xcodebuild` fails complaining about a missing framework, that is
the reason, not a broken project file.

`build_native.sh` copies the canonical `qeli/include/qeli_transport_core.h`, then compiles
the Rust crate three times — `aarch64-apple-ios` for the device,
plus `aarch64-apple-ios-sim` and `x86_64-apple-ios` lipo'd into one simulator slice — and
packages both with the headers from `QeliCore/Native/include` into the XCFramework. It
builds `--no-default-features --features transport-core-ffi`: the iOS slice is the
whole-client static library, with no server or CLI. `QELI_RUST_MANIFEST` and
`QELI_CARGO_TARGET_DIR` override the paths for out-of-tree builds.

The Swift side talks through the versioned whole-client ABI in
`QeliCore/Native/QeliFFI.swift`: `new/start/run/stop`, lifecycle events, server-identity and
NetworkPlan ACKs, stats, `tun_push/pull`, plus the handle-free UDP diagnostic. Rust owns
record framing, handshakes, crypto, carriers and packet loops. Swift owns only Apple system
APIs, profile storage and UI. The Packet Tunnel target excludes the old Swift
`Crypto/`/`Protocol/` conformance code entirely.

Two consequences worth stating plainly. The XCFramework is a **build artefact of a specific
Rust revision**: change anything under `qeli/src/` that the FFI touches and you must re-run
`build_native.sh`, or Xcode will keep linking the stale archive and the mismatch will surface
as ABI negotiation failure. The build script always packages the canonical transport header,
so a new Rust export cannot silently drift from the Swift module declaration.

The iOS packet bridge has an explicit memory budget: two Rust pools of 32 × 65,535 bytes
(4,194,240 bytes total), 128-slot bounded queues, and three reused Swift caller buffers capped
at 256 KiB each. Backpressure retries a packet prefix; there is no unbounded/fallback packet
allocation. This budget covers the cross-language packet seam, not the complete Network
Extension process, and must be re-measured on a physical device before release.

## Platform differences

- Android's boot receiver maps to VPN On Demand; consumer iOS has no boot callback.
- Arbitrary per-app include/exclude selection requires managed Per-App VPN (MDM) on
  iOS, so the keys round-trip but the consumer build does not claim to apply them.
- Android's Quick Settings tile maps to the iOS 18 WidgetKit control; iOS 17 uses the
  interactive Home Screen widget.
- TCP bonding mirrors Android's JOIN protocol. UDP remains one logical datagram path,
  matching the Android implementation.

Managed Per-App VPN and Apple's IKEv2-only Always On behavior are documented in
[`MDM/README.md`](MDM/README.md). The examples don't claim consumer or custom-provider
capabilities that iOS doesn't expose.
