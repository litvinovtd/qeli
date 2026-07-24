# Qeli

**Qeli** (Quick Easy Link IP) — a self-hosted VPN with its own L4 protocol and built-in
obfuscation over TCP or UDP. It aims at resilience against passive / signature-based DPI
while keeping the convenience of a classic full-tunnel TUN VPN, and ships with a web admin
panel.

**Документация на русском → [docs/ru/index.md](docs/ru/index.md)** ·
**Documentation in English → [docs/eng/index.md](docs/eng/index.md)**

---

## What it is

- **Full-tunnel TUN VPN**, not a per-application proxy: all traffic and DNS are routed at
  the OS level.
- **Wire modes**: `plain` · `fake-tls` (TLS 1.3 mimicry) · `obfs` (ChaCha20 stream +
  WebSocket fronting) · `reality` / `reality-tls` (real TLS 1.3 carries the tunnel) ·
  QUIC-masking for UDP.
- **Post-quantum handshake**: hybrid X25519 + ML-KEM-768, ChaCha20-Poly1305 data plane.
- **Web admin panel** with `qeli://` link / QR issuance, Argon2id login, native HTTPS.
- **Server**: Linux (TUN/TAP). **Clients**: Linux CLI · Windows · macOS · Android · iOS ·
  Keenetic / OpenWrt routers.

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
curl -fsSLO https://raw.githubusercontent.com/litvinovtd/qeli/main/install-reality-server.sh
```

Review it, then run `bash install-reality-server.sh`. Download-then-run (rather than
`curl … | bash`) exists so the script can be read before it executes as root; the installer
itself verifies the `.deb` against its SHA256.

The script installs the `.deb` from [Releases](https://github.com/litvinovtd/qeli/releases),
asks for the profile (`reality-tls` by default, or `fake-tls`) and the listen port (default
`443`), writes a config with full-tunnel NAT, creates users and prints ready-to-use
`qeli://` links. For a non-interactive run set the answers up front:
`QELI_PROFILE=reality-tls|fake-tls` and/or `QELI_PORT=<1-65535>`.

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
| `qeli-ios/` | iOS client (Swift) — [README](qeli-ios/README.md) · [MDM](qeli-ios/MDM/README.md) |
| `qeli-openwrt/` | Router build (Keenetic / OpenWrt) — [README](qeli-openwrt/README.md) |
| `docs/` | Documentation — start at [docs/ru/index.md](docs/ru/index.md) / [docs/eng/index.md](docs/eng/index.md) |
| `release/` | Packaging: [Docker](release/docker/README.md), deb, release artefacts |
| `site/` | Project website |

## Status

Pre-1.0 / beta — the data plane is stable and covered by unit + end-to-end tests, but the
protocol may still change between minor versions. Released builds are published on the
**GitHub Releases** page (binaries are not committed to git).

- Changes: **[CHANGELOG.md](CHANGELOG.md)**
- Security policy: **[SECURITY.md](SECURITY.md)**
- Contributing: **[CONTRIBUTING.md](CONTRIBUTING.md)**
- Licensing: **[LICENSE](LICENSE)** · **[LICENSING.md](LICENSING.md)**

This is a monorepo with **per-directory licences**: the core and server (`qeli/`) are
**AGPL-3.0-only**, the clients (`qeli-android/`, `qeli-win/`, `qeli-mac/`) are **MPL-2.0**.
The full map, including the `libqeli`/AGPL note, is in [LICENSING.md](LICENSING.md).
Contributions use a DCO sign-off, no CLA — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

<sub>**Keywords:** self-hosted VPN, anti-censorship VPN, censorship circumvention, anti-DPI,
DPI bypass, deep packet inspection, REALITY, Reality TLS, TLS camouflage, SNI,
active-probing resistant, traffic obfuscation, fake-TLS, obfs, QUIC VPN, post-quantum VPN,
ML-KEM-768, X25519, ChaCha20-Poly1305, Rust VPN, Android VPN, iOS VPN, Windows VPN, macOS
VPN, Keenetic, OpenWrt, WireGuard alternative, Xray / V2Ray / sing-box alternative, VPN for
Iran, VPN for China / Great Firewall, VPN for Russia / TSPU.</sub>
