# Qeli

<p align="center">
  <img src="assets/branding/qeli-logo.png" alt="Qeli logo" width="180">
</p>

**Qeli** (Quick Easy Link IP) — a self-hosted VPN with its own L4 protocol and built-in
obfuscation over TCP or UDP. It aims at resilience against passive / signature-based DPI
while keeping the convenience of a classic full-tunnel TUN VPN, and ships with a web admin
panel.

**Документация на русском → [docs/ru/index.md](docs/ru/index.md)** ·
**Documentation in English → [docs/eng/index.md](docs/eng/index.md)**

---

## What it is

- **A TUN VPN, not a per-application proxy**: routing and DNS are handled at the OS level,
  so every application is covered without being configured. Full-tunnel and split-tunnel are
  both first-class — phones default to full-tunnel, the CLI and desktop clients to split.
- **Wire modes**: `plain` · `fake-tls` (TLS 1.3 mimicry) · `obfs` (ChaCha20 stream +
  WebSocket fronting) · `reality` / `reality-tls` (real TLS 1.3 carries the tunnel) ·
  QUIC-masking for UDP.
- **Post-quantum handshake**: hybrid X25519 + ML-KEM-768, ChaCha20-Poly1305 data plane.
- **Web admin panel** with `qeli://` link / QR issuance, Argon2id login, native HTTPS.
- **Server**: Linux (TUN/TAP). **Clients**: Linux CLI · Windows · macOS · Android ·
  Keenetic / OpenWrt routers — plus iOS, which is feature-complete but has never been run
  on a device and ships nothing yet ([details](qeli-ios/README.md)).

## Works under active DPI

Qeli is built for networks where ordinary VPN protocols (WireGuard, OpenVPN, IKEv2) are
fingerprinted and blocked — Iran, China (the Great Firewall) and Russia (TSPU). The
`reality-tls` mode performs a genuine TLS 1.3 handshake against a real third-party site, so
the connection looks like ordinary HTTPS to that site and resists both active probing and
SNI-based blocking; traffic shaping adds idle cover traffic so the flow does not read as a
bulk download to statistical DPI.

> In spirit a self-hosted alternative to Xray / V2Ray / sing-box (REALITY/VLESS) setups, but
> with its own protocol, native GUI clients and a post-quantum handshake.

## Quick start

**One command on a clean Linux server (Debian/Ubuntu), as root:**

```bash
curl -fsSLO https://raw.githubusercontent.com/litvinovtd/qeli/main/install-qeli-server.sh
```

Review it, then run `bash install-qeli-server.sh`. Download-then-run (rather than
`curl … | bash`) exists so the script can be read before it executes as root; the installer
itself verifies the `.deb` against its SHA256.

The script installs the `.deb` from [Releases](https://github.com/litvinovtd/qeli/releases),
asks for the profile and the listen port (default `443`), writes a config with full-tunnel
NAT, creates users and prints ready-to-use `qeli://` links. Three profiles are offered:

| Profile | When to pick it |
|---------|-----------------|
| `reality-tls` | The default the installer provisions. Real TLS 1.3 over TCP:443 — survives active probing. |
| `fake-tls` | Cheaper on CPU; enough against passive/signature DPI. |
| `udp-quic` | A UDP path with QUIC-shaped datagrams — useful where TCP:443 is throttled, reset or otherwise degraded. |

For a non-interactive run set the answers up front:
`QELI_PROFILE=reality-tls|fake-tls|udp-quic` and/or `QELI_PORT=<1-65535>`.

Then install a client from Releases and paste or scan the link.

**Prefer to do it step by step?**

1. Install the server and create the first user — **[Getting started (EN)](docs/eng/GETTING-STARTED.md)** ·
   **[Установка с нуля (RU)](docs/ru/GETTING-STARTED.md)**.
2. Configure it — **[CONFIG (EN)](docs/eng/CONFIG.md)** · **[CONFIG (RU)](docs/ru/CONFIG.md)**.
3. Issue a `qeli://` link or QR from the web panel and import it into a client —
   **[PANEL (EN)](docs/eng/PANEL.md)** · **[PANEL (RU)](docs/ru/PANEL.md)**.

Something went wrong? → **[Troubleshooting (EN)](docs/eng/TROUBLESHOOTING.md)** ·
**[Диагностика (RU)](docs/ru/TROUBLESHOOTING.md)**.

## Repository layout

| Path | What it is |
|------|------------|
| `qeli/` | Rust daemon: server, client CLI, protocol core, web panel |
| `qeli-win/`, `qeli-mac/` | Desktop GUI clients (C#/.NET, shared core in `qeli-shared/`) — [Windows](qeli-win/README.md) · [macOS](qeli-mac/README.md) |
| `qeli-android/` | Android client (Kotlin) — [README](qeli-android/README.md) |
| `qeli-ios/` | iOS client (Swift), feature-complete but untested on a device — [README](qeli-ios/README.md) · [MDM](qeli-ios/MDM/README.md) |
| `qeli-openwrt/` | Router build (Keenetic / OpenWrt) — [README](qeli-openwrt/README.md) |
| `docs/` | Documentation — start at [docs/ru/index.md](docs/ru/index.md) / [docs/eng/index.md](docs/eng/index.md) |
| `release/` | Packaging: [Docker](release/docker/README.md), deb, release artefacts |
| `site/` | Project website |

## Status

Pre-1.0 / beta — the data plane is stable and covered by unit + end-to-end tests, but the
protocol may still change between minor versions. Release builds are published on the
**GitHub Releases** page and are not committed to git. The client **native cores** are the
exception: `libqeli.so` / `qeli.dll` / `libqeli.dylib` (plus third-party `wintun.dll`) are
committed under `native-libs/` and mirrored into each client tree, so the platform CI jobs
need only their own toolchain. Their hashes are pinned in `native-libs/SHA256SUMS` and
checked by the `native-libs` CI gate. This is an explicit trade-off against reproducibility
— see [THREAT-MODEL §4](docs/eng/THREAT-MODEL.md#4-assurance-status) ·
[Модель угроз §4](docs/ru/THREAT-MODEL.md#4-уровень-проверенности).

- Changes: **[CHANGELOG.md](CHANGELOG.md)**
- Security policy: **[SECURITY.md](SECURITY.md)**
- Contributing: **[CONTRIBUTING.md](CONTRIBUTING.md)**
- Licensing: **[LICENSE](LICENSE)** · **[LICENSING.md](LICENSING.md)**

This is a monorepo with **per-directory licences**: the core and server (`qeli/`) are
**AGPL-3.0-only**, the clients (`qeli-android/`, `qeli-win/`, `qeli-mac/`, `qeli-ios/`) are
**MPL-2.0**.
The full map, including the `libqeli`/AGPL note, is in [LICENSING.md](LICENSING.md).
Contributions use a DCO sign-off, no CLA — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

<sub>**Keywords:** self-hosted VPN, anti-censorship VPN, censorship circumvention, anti-DPI,
DPI bypass, deep packet inspection, REALITY, Reality TLS, TLS camouflage, SNI,
active-probing resistant, traffic obfuscation, fake-TLS, obfs, QUIC VPN, post-quantum VPN,
ML-KEM-768, X25519, ChaCha20-Poly1305, Rust VPN, Android VPN, iOS VPN, Windows VPN, macOS
VPN, Keenetic, OpenWrt, WireGuard alternative, Xray / V2Ray / sing-box alternative, VPN for
Iran, VPN for China / Great Firewall, VPN for Russia / TSPU.</sub>
