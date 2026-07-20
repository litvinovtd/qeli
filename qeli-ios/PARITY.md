# Android to iOS parity ledger

## Implemented foundation

- Connection / Profiles / Log navigation and Qeli visual language.
- Profile CRUD, active-profile locking while connected, reorder and reachability.
- INI, JSON, file, clipboard, QR and `qeli://` deep-link import.
- Share link, QR generation and system share sheet.
- Encrypted-at-rest profile store and Android-compatible backup encryption.
- Theme, launch auto-connect, VPN On Demand, LAN bypass and log timestamp settings.
- Opt-in, privacy-gated release check matching Android's public release metadata flow.
- Network Extension manager/provider lifecycle and shared status/log channel.
- TCP/UDP Network.framework transport abstraction.
- Plain/TCP protocol path: X25519 key exchange, optional static-session binding,
  server proof and TOFU pinning, client/device authentication, server push parsing,
  `NEPacketTunnelNetworkSettings`, encrypted TUN uplink/downlink and traffic stats.
- Hybrid fake-TLS path with the canonical Rust ClientHello, X25519+ML-KEM-768 KDF,
  positional TLS-shaped flight parsing and exact server/client authentication.
- TCP obfs with WebSocket fronting, bidirectional AWG junk, nonce exchange and
  continuous ChaCha20 streams; nested native REALITY TLS transport.
- UDP data path with handshake fragmentation/retransmission, QUIC mask, stateless
  obfs, AWG preamble, authenticated-loss handling, MTU-safe packet padding and an
  active DF path-MTU ladder using Network.framework IP options.
- Reconnect with exponential backoff, 1.5-second anti-flap floor and Network Extension
  `reasserting`; virtual routes remain installed while transport is unavailable.
- Heartbeat, receive watchdog, active-uplink/dead-downlink detection, Poisson cover
  traffic and TCP stealth-rate pacing.
- TCP multipath session-token JOIN, per-stream codecs/heartbeat, round-robin upload,
  loss of one stream without tunnel teardown, fixed and adaptive stream ramping.
- Crypto/protocol primitives: HKDF/HMAC, ChaCha20-Poly1305, packet codec with a
  2048-packet replay window, UDP fragmentation, QUIC mask and traffic shaping.
- Rust XCFramework build path for REALITY TLS, ML-KEM-768 and fake-TLS ClientHello.
- WidgetKit status widget with an authenticated App Intent action and an iOS 18
  Control Center / Lock Screen / Action button control.
- Managed app configuration reader and truthful Per-App VPN / IKEv2 Always On MDM
  templates.

## Remaining verification milestones

1. Build the Rust XCFramework and generated Xcode project on macOS/Xcode 16+.
2. Run physical-device interoperability tests against every Android/server wire mode,
   including packet loss, Wi-Fi/cellular transitions and bonded-stream failure.
3. Capture UDP paths with several carriers and verify the active DF path-MTU ladder.
   Network.framework applies DF at connection creation; a completely missed probe
   window therefore re-authenticates once without DF and keeps the pushed MTU.
4. Complete App Store signing/provisioning and Apple Network Extension entitlement
   approval for the final bundle identifiers.

## iOS restrictions (not implementable as a normal consumer app)

- Per-app routing rules for arbitrary installed applications require MDM-managed apps;
  iOS also does not expose an installed-app enumeration API to a consumer VPN app.
- True Always-On VPN requires supervised MDM and Apple's IKEv2 Always On tunnel;
  Apple does not expose that enforcement mode to Qeli's custom Packet Tunnel Provider.
  VPN On Demand is the closest Qeli/consumer equivalent to Android boot auto-connect.
- There is no battery-optimization exemption flow or Android-style foreground service.
