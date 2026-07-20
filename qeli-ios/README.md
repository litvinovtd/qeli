# Qeli for iOS

Native iPhone client for the qeli protocol. The project mirrors the Android client's
three primary surfaces (Connection, Profiles, Log) and uses a Packet Tunnel Provider
extension for the VPN data plane.

## Current implementation

- SwiftUI application shell with connection, profile and live-log tabs.
- Encrypted profile storage shared with the tunnel extension (App Group + Keychain).
- INI, legacy JSON and `qeli://` profile import/export.
- QR scanning/generation, profile editing, duplication, ordering and sharing.
- Android-compatible encrypted backups (`QELI-ENC-1`, PBKDF2-SHA256, AES-256-GCM).
- Opt-in release checks that run only with a fail-closed full-tunnel route.
- `NETunnelProviderManager` lifecycle, VPN On Demand and status/statistics bridge.
- `NEPacketTunnelProvider` target and Network.framework transport foundation.
- End-to-end plain/TCP, fake-TLS, obfs and REALITY-TLS paths: X25519/ML-KEM,
  static-key binding/TOFU, server and client proofs, credential authentication,
  server-pushed network settings, encrypted uplink/downlink and live counters.
- UDP record transport with mobile-safe ClientHello fragmentation, exact handshake
  retransmission, optional QUIC-shaped masking, stateless obfs, AWG preamble and
  active DF path-MTU discovery. A missed probe window transparently re-authenticates
  without DF and keeps the server-pushed MTU, matching Android's safe fallback.
- Fail-closed reconnect/reassertion, heartbeat/liveness checks, flow-shaping cover,
  TCP JOIN multipath with fixed fan-out or adaptive throughput ramping.
- Protocol primitives already ported to Swift: key derivation, ChaCha20-Poly1305,
  packet framing/anti-replay, UDP fragmentation, QUIC-looking framing and shaping.
- Rust iOS XCFramework build script for REALITY, ML-KEM and canonical fake-TLS hello.
- Home Screen status widget and authenticated connect/disconnect action; iOS 18 adds
  the same action as a Control Center, Lock Screen and Action button control.
- MDM deployment templates, typed managed configuration, enforced profile/On-Demand
  precedence and an App-Group policy gate for managed WidgetKit controls.

The requested protocol paths are now wired into the Packet Tunnel runtime. A real
XCFramework build and interoperability matrix still have to be run on macOS and a
physical iPhone; Windows cannot compile or execute Network Extension targets. See
`PARITY.md` for the remaining validation work and Apple platform boundaries.

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
`Config/Signing.xcconfig`. The Packet Tunnel and Widget bundle IDs, App Group and
Keychain Group are derived from the app bundle ID and can still be overridden in CI.
Register all three App IDs. Enable Network Extensions, App Groups and Keychain
Sharing for the app/provider as appropriate, and the same App Group for the widget.

The widget and iOS 18 control read status from the App Group. Their authenticated
App Intents write a short-lived, one-time desired-state request and bring the main
app forward to apply it through `NETunnelProviderManager`; the widget extension
never starts a tunnel directly. The `qeli-control://status` URL is navigation-only.
Any future command URL must carry a fresh opaque token that already exists in the
App Group, so an arbitrary custom URL cannot authorize connect or disconnect.
WidgetKit controls timeline refresh frequency, so status can briefly lag when the
main app is suspended; the app explicitly reloads widgets on tunnel phase changes.
No universal-link domain is fabricated: Apple `OpenURLIntent` accepts universal
links, and one can only be added after an owned HTTPS domain and its association
file are available.

Packet Tunnel Providers do not run in the iOS simulator. Use a physical iPhone for
VPN testing. The first save/start asks the user to approve the VPN configuration.

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
