# Qeli — an obfuscated VPN

**Qeli** (Quick Easy Link IP) is a self-hosted VPN with its own L4 protocol and
built-in obfuscation, running over TCP or UDP. The goal is resilience against
passive/signature-based DPI while keeping the convenience of classic TUN/TAP
VPNs, with a built-in web admin panel.

- **Language**: Rust 2021, version 0.8.0 (beta)
- **Crypto stack**: `x25519-dalek`, `ml-kem` (PQ hybrid X25519MLKEM768), `chacha20poly1305`, `chacha20`, `aes-gcm`, `hkdf`, `sha2`, `argon2`, `zeroize`; `rustls`/`ring` — server-side termination of real TLS 1.3 in `reality-tls`
- **Transport**: TCP or UDP; multiple profiles (interfaces) in a single daemon
- **Wire modes**: `plain` · `fake-tls` · `obfs` · `reality` · `reality-tls` (REALITY TLS 1.3 + a genuine HTTP/2 carrier; `handrolled` borrows the target certificate) · QUIC-shaped UDP compatibility masking, not real QUIC/HTTP3
- **Rust daemon/CLI TUN/TAP backend**: Linux only (`libc::ioctl(TUNSETIFF)`); native clients
  use their platform VPN APIs (Wintun, utun, Android `VpnService`, iOS Network Extension)
- **Web admin**: `axum` + `alpine.js`; native HTTPS (rustls, self-signed or your own cert), Argon2id password (fail-closed), IP allowlist, security headers/HSTS, same-origin CSRF, RU/EN localization, `qeli://` link/QR issuance without typing the password; assets embedded (no CDN). Guide — [PANEL.md](PANEL.md)
- **Configs**: a single flat-INI (`server.conf` / `client.conf` / `users.conf`); the client is a `[qeli]` section, expanded from a `qeli://` link (QR)

## Why this was built

Classic VPNs (WireGuard, OpenVPN, IPsec) are fast, but on the wire they have a
**recognizable signature** — in networks with DPI (GFW, Russia's TSPU, corporate
firewalls) they are detected and throttled. Proxy tools (V2Ray/Xray) mask
themselves excellently, but they are **per-application proxies** (SOCKS/HTTP),
not a system-wide VPN: they don't route all traffic/DNS at the OS level and are
heavier to operate.

**Qeli targets this gap** — the convenience of a real full-tunnel TUN VPN (all
traffic, DNS, routes, many clients, a web admin) **plus** REALITY-style masking.
`reality-tls` is designed to resemble ordinary HTTPS to a configured target and sends
unauthorised probes to that site, reducing known **passive** signatures and **active**
probing tells. It is not a universal indistinguishability or censorship-bypass guarantee.

**A fully bespoke stack — not a wrapper.** The protocol, obfuscation, and
REALITY/real TLS 1.3 are written **from scratch in Rust**: this is **NOT** the use
of off-the-shelf REALITY libraries and **NOT** a wrapper over Xray/sing-box. Our
own fake-TLS, our own hand-rolled TLS 1.3 (`realtls`) with cert-borrowing (the target's certificate and JA3S shape,
without claiming full Xray/browser parity), our own crypto channel (X25519 + ML-KEM-768 PQ hybrid,
ChaCha20-Poly1305, channel-binding, key-pinning, PRP-nonce). Full control and
auditability of the code, with no dependency on third-party proxy cores.

**Who it's for:**
- self-hosting a personal/team VPN where WireGuard/OpenVPN are blocked;
- one server with several masking profiles (reality-tls / fake-tls / obfs / QUIC) for different scenarios;
- anyone who needs a **system-wide** VPN, not a per-application proxy, but with DPI protection.

**How it differs:** WireGuard is fast but easily fingerprinted; Xray/V2Ray have
excellent masking, but they are a proxy, not a TUN, and run on third-party cores;
commercial VPNs are not self-hosted. Qeli = self-hosted full-TUN VPN +
REALITY-style masking on a **bespoke implementation** + a built-in multi-client
and admin panel.

## What is implemented in-house

No third-party proxy cores or REALITY libraries — the entire protocol and masking
are written in this repository from scratch:

- **`realtls` — real TLS 1.3 by hand.** A sans-IO core (no socket coupling) +
  client and server: ClientHello/ServerHello, key schedule (HKDF), record layer,
  AEAD. **Cert-borrowing** — the server borrows the target's real certificate, so
  the JA3S shape matches the probed real site; that is one measured dimension, not full Xray/browser parity. Exported to native
  clients via C-ABI FFI and JNI.
- **fake-TLS** — our own TLS-1.3-mimicking handshake: GREASE, randomized
  extension order (JA3 changes per-connection), SNI, X25519MLKEM768 key_share
  (PQ hybrid, like Chrome ≥124) — it carries the real ML-KEM share for the inner
  tunnel.
- **REALITY proxy** — peek-and-decide on accept: a crypto token in the
  ClientHello's `session_id` + anti-replay guard; "foreign" handshakes are
  transparently bridged to a real site (protection against active probing).
- **Genuine HTTP/2 carrier** — authenticated `reality-tls` uses ALPN `h2`, one long-lived
  bidirectional `POST /v1/events/stream`, real SETTINGS/HEADERS/DATA/flow-control and randomized
  2–8 ms batching. There is no user-facing H2 switch and no second inner fake-TLS handshake.
- **Crypto channel** — X25519 + **ML-KEM-768** (PQ hybrid X25519MLKEM768),
  HKDF-SHA256, ChaCha20-Poly1305 / AES-GCM, Argon2id for passwords.
- **Channel-binding authentication** — the server's proof is bound to the
  handshake transcript + key-pinning: a MITM cannot intercept the password before
  it is even sent.
- **PRP-nonce** — a 96-bit Feistel-PRP masks the packet counter: there is no
  incrementing nonce on the wire, nothing for DPI to correlate.
- **obfs** — ChaCha20-stream obfuscation of the entire flow + WebSocket-fronting.
- **Data plane** — multi-queue TUN (parallelism across cores), an IP pool,
  DNS-over-tunnel, server-pushed config (MTU/routes/DNS), per-profile routing.
- **Formats** — flat-INI config (our own parser) and `qeli://` share links/QR
  (our own scheme).
- **Cross-platform clients** — the Rust `realtls` core is built into
  `.so/.dll/.dylib` and linked from Android (Kotlin + JNI), Windows (C# +
  P/Invoke), macOS (C#/Avalonia); the rest of each client is native.

## Repository

Clone into a `qeli_vpn/` folder (`git clone https://github.com/litvinovtd/qeli qeli_vpn`)
so the repository root doesn't clash with the inner Rust crate `qeli/`:

```
qeli_vpn/
├── qeli/                  — Rust sources (daemon + realtls core for native clients)
│   ├── src/
│   │   ├── client/        — TCP/UDP client, routes, DNS, reconnect
│   │   ├── server/        — handler.rs (TCP), udp_handler.rs (UDP), web/, control/, reality.rs
│   │   ├── crypto/        — X25519, ML-KEM-768, ChaCha20-Poly1305, HKDF, auth (channel-binding/pinning), PRP-nonce
│   │   ├── protocol/      — fake-tls, obfs, realtls/, h2_carrier.rs, QUIC-shape, packet codec
│   │   ├── tun/           — TUN/TAP via libc
│   │   ├── web/           — admin UI + REST API
│   │   └── config/        — serde structs + flat-INI loader (format.rs/server_ini.rs)
│   ├── config/            — sample server.conf / client.conf / users.conf (documented)
│   └── debian/            — systemd unit + .deb
├── qeli-android/         — Android client (Kotlin + JNI to the realtls core)
├── qeli-win/             — Windows client (C#/WPF, .NET 10 + P/Invoke to qeli.dll)
├── qeli-mac/             — macOS client (C#/Avalonia, .NET 10 + libqeli.dylib)
├── qeli-shared/          — shared C# code for win+mac (crypto/protocol/model, VpnTunnel core, RealTls, Loc; .NET 10)
├── native-libs/          — built native realtls libs (.so/.dll/.dylib)
├── release/              — built binary + benchmark_results.json + reality-tls/ configs
├── scripts/              — paramiko: deploy, benchmark, debugging, cross-building libs
└── docs/                 — this documentation
```

## What the protocol does on the wire

1. **Carrier handshake.** `fake-tls` sends the qeli TLS-shaped ClientHello; `obfs` performs its
   configured fronting; `plain` starts the private handshake directly. `reality-tls` instead
   establishes authenticated REALITY TLS 1.3 and negotiates ALPN `h2`.
2. **Reality/H2 carrier.** The client opens exactly one long-lived bidirectional
   `POST /v1/events/stream`. The qeli byte stream is carried in genuine HTTP/2 DATA frames;
   randomized 2–8 ms batching deliberately breaks message/record boundary correlation.
3. **Mutual qeli authentication.** The server proof is bound to the handshake transcript and
   checked against the pinned profile key before credentials are sent. The client then proves
   knowledge of that key and authenticates inside the qeli AEAD channel.
4. **Data.** PacketCodec remains end-to-end ChaCha20-Poly1305 with PRP-masked nonces. Legacy
   camouflage modes retain their own framing; current `reality-tls` carries raw private qeli
   records inside H2. This is still outer TLS AEAD plus inner qeli AEAD, but no nested fake-TLS.
Security details — [AUDIT.md](AUDIT.md). Against **active** probing, REALITY does
the work: `reality` bridges foreign parties to a real site, while `reality-tls`
carries the tunnel inside real TLS 1.3 (with `handrolled` — the target's borrowed
real certificate). The X25519MLKEM768 PQ hybrid is now also in the **inner** qeli
tunnel: the data keys = X25519 ⊕ ML-KEM-768 (`derive_keys_hybrid`) in all modes
except `plain` (`fake-tls`/`obfs`/`reality-tls`/UDP), so protection against
harvest-now-decrypt-later does not depend on the wrapper. The server REQUIRES the
PQ share for non-`plain` modes (no silent downgrade). Managed clients (C#/Kotlin)
take ML-KEM from the shared Rust core via FFI/JNI. In `fake-tls`/`obfs` modes the
outer TLS itself is not real (a stub certificate) — they are designed for
passive/entropy-based DPI.

## Quick start

```bash
cd qeli && cargo build --release --features jemalloc

# configs (flat-INI) — samples in qeli/config/
sudo install -Dm644 config/server.conf /etc/qeli/server.conf
sudo /usr/bin/qeli server --config /etc/qeli/server.conf

# the server's public key for pinning on the client:
qeli show-identity --config /etc/qeli/server.conf

sudo /usr/bin/qeli client --config /etc/qeli/client.conf
```

Fully documented examples with all parameters:
[server.conf](../../qeli/config/server.conf) (exhaustive reference) ·
[server-multiprofile.conf](../../qeli/config/server-multiprofile.conf) (ready 10-mode template) ·
[server-ipv6.conf](../../qeli/config/server-ipv6.conf) (runnable dual-stack deployment) ·
[client.conf](../../qeli/config/client.conf) · [users.conf](../../qeli/config/users.conf).
Config reference — [CONFIG.md](CONFIG.md).

> 📘 **New here?** A step-by-step from-scratch guide — from installing the server to
> creating users with routes and connecting a client, via both the CLI and the web
> panel — is in [GETTING-STARTED.md](GETTING-STARTED.md).

## Commands

The full set of CLI subcommands (`qeli <command> --help` for all options).

### Run
| Command | What it does |
|---|---|
| `qeli server --config <path>` | run the server (default `/etc/qeli/server.conf`) |
| `qeli client --config <path>` | run the client (default `/etc/qeli/client.conf`) |

### Provisioning (operate on the config / users files)
| Command | What it does |
|---|---|
| `qeli add-client <user> [--password … --profiles … --static-ip … --max-sessions N --link --host <host>]` | add a user (Argon2 password hash, appended to the users file); with `--link --host` it prints a `qeli://` share link (QR) for one-shot import on a phone |
| `qeli set-web-password [--username admin --password … --no-enable]` | set/generate the **web-panel** login on a fresh install: writes `web.username`/`password_hash` (Argon2id) into the config's `[web]` section, preserving comments, and enables the panel. Without `--password` it generates a random one (printed once) |
| `qeli show-identity --config <path>` | show **each profile's** server identity public key (pin it on clients); creates the keys if absent |

### Live management (via the control socket, no server restart)
| Command | What it does |
|---|---|
| `qeli list-clients` | who is currently connected — including a `CLIENT` column with the build each session reports (`0.7.14/android`), or `-` for a client that does not report one. **Self-reported, not verified** |
| `qeli kick <user>` | disconnect a user |
| `qeli disable-user <user>` | disable (kick + block reconnects) |
| `qeli enable-user <user>` | allow login again |
| `qeli set-bandwidth <user> <mbps>` | bandwidth limit (0 = unlimited) |
| `qeli show-routes <user>` | a user's routes |
| `qeli rotate-identity <profile>` | rotate a profile's identity key (clients must then update `auth.server_public_key`) |

> Live-management commands take the socket path from `--socket` (default
> `/var/run/qeli/control.sock`); `add-client` / `set-web-password` / `show-identity` /
> `rotate-identity` take the config from `--config` (default `/etc/qeli/server.conf`).

## Documentation

**Full documentation map → [index.md](index.md)** — every document grouped by audience
(users · operators · routers · security · design · internals · archive).

Most used:

- **[GETTING-STARTED.md](GETTING-STARTED.md)** — install and first run, step by step.
- **[CONFIG.md](CONFIG.md)** — configuration (flat-INI), every parameter.
- **[IPV6.md](IPV6.md)** — complete dual-stack/IPv6-only, NAT66/route setup and troubleshooting.
- **[CLIENT-CONFIG-MATRIX.md](CLIENT-CONFIG-MATRIX.md)** — the current 80 client keys and refactor history.
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** — diagnostics and error reference.
- **[PANEL.md](PANEL.md)** — web panel: installation and usage.

## Status

Pre-1.0 / beta: the data plane is stable and covered by unit and end-to-end tests, but
the protocol may still change between minor versions.

> **What went into each version is in [CHANGELOG.md](../../CHANGELOG.md).** The version
> history is deliberately not duplicated here: this section used to describe 0.7.0–0.7.4
> and had drifted far from reality.

Confirmed in the lab: auto-reconnect, crash-safe DNS, brute-force lockout,
channel-binding, server key pinning, per-profile authorization, and end-to-end runs of
every wire mode.

Performance (2-VM lab, latest structured run: v0.7.16, 2026-08-16). Methodology and raw data —
[BENCHMARK.md](BENCHMARK.md):

- **TCP, legacy carrier through 0.7.16**: 462–551 ↑ / 358–678 ↓ Mbps. The published
  `reality-tls` result (472 ↑ / 358 ↓ Mbps) used the former inner fake-TLS carrier and must not
  be presented as current H2 throughput. A controlled full-speed H2 benchmark is still required.
- **UDP**: all measured variants were lossless through 400 Mbps; at 500 Mbps loss ranged
  from 6.47% to 21.39%, and at 600 Mbps from 31.25% to 36.55%.
- Average tunnel RTT was 0.831–1.087 ms; measured qeli RSS was 75.9–87.1 MB. Treat these as
  one lab snapshot, not a capacity guarantee for different CPUs, kernels or networks.

## License

A monorepo with **multiple licenses by directory** (full map —
[LICENSING.md](../../LICENSING.md)):

| Part | License |
|---|---|
| Core + server (`qeli/`) and the repository by default | **AGPL-3.0-only** ([LICENSE](../../LICENSE)) |
| Clients (`qeli-android/`, `qeli-win/`, `qeli-mac/`) | **MPL-2.0** (`LICENSE` in each directory) |
| Third-party native binaries (`native-libs/third-party/`) | per upstream licenses |

> **Important:** the clients bundle the native `libqeli` core, built from AGPL
> code. The client sources under MPL-2.0 may be reused separately (with your own
> backend), but **the distributable app together with the `libqeli` core** is
> distributed to third parties under the terms of **AGPL-3.0**. The core is not
> dual-licensed (the monetization model is hosting + a separate closed-source
> control-plane + support); details are in [LICENSING.md](../../LICENSING.md).

## Contributing

Contributions are accepted via pull request. No CLA is required — a lightweight
**DCO** is used: sign your commits with `git commit -s` (`Signed-off-by`). A
contribution is included under the license of the corresponding directory
(inbound = outbound). Details — [CONTRIBUTING.md](../../CONTRIBUTING.md).
