# Qeli — an obfuscated VPN

**Qeli** (Quick Easy Link IP) is a self-hosted VPN with its own L4 protocol and
built-in obfuscation, running over TCP or UDP. The goal is resilience against
passive/signature-based DPI while keeping the convenience of classic TUN/TAP
VPNs, with a built-in web admin panel.

- **Language**: Rust 2021, version 0.7.6 (beta)
- **Crypto stack**: `x25519-dalek`, `ml-kem` (PQ hybrid X25519MLKEM768), `chacha20poly1305`, `chacha20`, `aes-gcm`, `hkdf`, `sha2`, `argon2`, `zeroize`; `rustls`/`ring` — server-side termination of real TLS 1.3 in `reality-tls`
- **Transport**: TCP or UDP; multiple profiles (interfaces) in a single daemon
- **Wire modes**: `plain` (no obfuscation — a bare encrypted tunnel, TCP) · `fake-tls` (mimicry of TLS 1.3) · `obfs` (ChaCha20 stream + WS-fronting) · `reality` (proxying other parties' handshakes to a real site) · `reality-tls` (real TLS 1.3 carries the tunnel; `handrolled` borrows the target's real certificate — cert-borrowing, parity with Xray-REALITY) · QUIC-masking for UDP
- **TUN/TAP**: Linux only (`libc::ioctl(TUNSETIFF)`)
- **Web admin**: `axum` + `alpine.js`; native HTTPS (rustls, self-signed or your own cert), Argon2id password (fail-closed), IP allowlist, security headers/HSTS, same-origin CSRF, RU/EN localization, `qeli://` link/QR issuance without typing the password; assets embedded (no CDN). Guide — [PANEL.md](PANEL.md)
- **Configs**: a single flat-INI (`server.conf` / `client.conf` / `users.conf`); the client is a `[qeli]` section, expanded from a `qeli://` link (QR)

## Why this was built

Classic VPNs (WireGuard, OpenVPN, IPsec) are fast, but on the wire they have a
**recognizable signature** — in networks with DPI (GFW, Russia's TSPU, corporate
firewalls) they are detected and throttled. Proxy tools (V2Ray/Xray) mask
themselves excellently, but they are **per-application proxies** (SOCKS/HTTP),
not a system-wide VPN: they don't route all traffic/DNS at the OS level and are
heavier to operate.

**Qeli closes this gap** — the convenience of a real full-tunnel TUN VPN (all
traffic, DNS, routes, many clients, a web admin) **plus** Xray-REALITY-grade
masking: the traffic looks like ordinary HTTPS to a real site, which holds up
against both **passive** signature-based DPI and **active** probing.

**A fully bespoke stack — not a wrapper.** The protocol, obfuscation, and
REALITY/real TLS 1.3 are written **from scratch in Rust**: this is **NOT** the use
of off-the-shelf REALITY libraries and **NOT** a wrapper over Xray/sing-box. Our
own fake-TLS, our own hand-rolled TLS 1.3 (`realtls`) with cert-borrowing (JA3S
parity with Xray-REALITY), our own crypto channel (X25519 + ML-KEM-768 PQ hybrid,
ChaCha20-Poly1305, channel-binding, key-pinning, PRP-nonce). Full control and
auditability of the code, with no dependency on third-party proxy cores.

**Who it's for:**
- self-hosting a personal/team VPN where WireGuard/OpenVPN are blocked;
- one server with several masking profiles (reality-tls / fake-tls / obfs / QUIC) for different scenarios;
- anyone who needs a **system-wide** VPN, not a per-application proxy, but with DPI protection.

**How it differs:** WireGuard is fast but easily fingerprinted; Xray/V2Ray have
excellent masking, but they are a proxy, not a TUN, and run on third-party cores;
commercial VPNs are not self-hosted. Qeli = self-hosted full-TUN VPN +
REALITY-grade masking on a **bespoke implementation** + a built-in multi-client
and admin panel.

## What is implemented in-house

No third-party proxy cores or REALITY libraries — the entire protocol and masking
are written in this repository from scratch:

- **`realtls` — real TLS 1.3 by hand.** A sans-IO core (no socket coupling) +
  client and server: ClientHello/ServerHello, key schedule (HKDF), record layer,
  AEAD. **Cert-borrowing** — the server borrows the target's real certificate, so
  the JA3S matches the real site (parity with Xray-REALITY). Exported to native
  clients via C-ABI FFI and JNI.
- **fake-TLS** — our own TLS-1.3-mimicking handshake: GREASE, randomized
  extension order (JA3 changes per-connection), SNI, X25519MLKEM768 key_share
  (PQ hybrid, like Chrome ≥124) — it carries the real ML-KEM share for the inner
  tunnel.
- **REALITY proxy** — peek-and-decide on accept: a crypto token in the
  ClientHello's `session_id` + anti-replay guard; "foreign" handshakes are
  transparently bridged to a real site (protection against active probing).
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
│   │   ├── protocol/      — fake-tls, obfs (ChaCha20 stream), realtls/ (real TLS 1.3: client+server+sans-IO/FFI), QUIC-wrap, packet codec
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

1. **Handshake.** The client sends a fake-TLS ClientHello (SNI, x25519 key_share,
   GREASE, randomized extension order → JA3 changes per-connection). The server
   replies with ServerHello/Certificate/Finished. The shared key is X25519, the
   AEAD keys are HKDF-SHA256. (In `obfs` mode the entire flow is additionally
   XOR'd with a ChaCha20 keystream; in `reality`, "foreign" handshakes are proxied
   to a real site.)
2. **Server → client authentication.** The server proves ownership of its
   long-term key; the proof is bound to the **handshake transcript** (channel
   binding). The client checks it against the pinned key (`auth.server_public_key`).
   **Before credentials are sent** — a MITM cannot intercept the password.
3. **Client → server authentication.** The client sends (inside the AEAD channel)
   a proof of knowledge of the server key + `username:password` (Argon2id). With
   `require_client_key_proof`, unpinned clients are rejected.
4. **Data.** Each IP packet → AEAD (ChaCha20-Poly1305; the nonce is masked by a
   96-bit Feistel-PRP — there is no incrementing counter on the wire) → optional
   padding → write: fake-TLS application_data `0x17`; or a bare `[len][nonce][ct]`
   in `plain` mode (no TLS wrapper); or an obfs stream; or a QUIC wrapper; or
   inside real TLS 1.3 in `reality-tls`.

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
cd qeli && cargo build --release

# configs (flat-INI) — samples in qeli/config/
sudo install -Dm644 config/server.conf /etc/qeli/server.conf
sudo /usr/bin/qeli server --config /etc/qeli/server.conf

# the server's public key for pinning on the client:
qeli show-identity --config /etc/qeli/server.conf

sudo /usr/bin/qeli client --config /etc/qeli/client.conf
```

Fully documented examples with all parameters:
[server.conf](../../qeli/config/server.conf) (exhaustive reference) ·
[server-multiprofile.conf](../../qeli/config/server-multiprofile.conf) (ready 9-mode template) ·
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
| `qeli list-clients` | who is currently connected |
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

- **Installation & getting started (step by step, from scratch)**: [GETTING-STARTED.md](GETTING-STARTED.md)
- **Configuration (flat-INI), all parameters**: [CONFIG.md](CONFIG.md)
- **Web panel (install & usage)**: [PANEL.md](PANEL.md)
- **Security model**: [AUDIT.md](AUDIT.md)
- **DPI audit (tells and their mitigation)**: [DPI-AUDIT.md](DPI-AUDIT.md)
- **Benchmarks (all modes)**: [BENCHMARK.md](BENCHMARK.md)
- **Comparison with WireGuard/OpenVPN/V2Ray**: [COMPARISON.md](COMPARISON.md)
- **Roadmap**: [ROADMAP.md](ROADMAP.md)
- **Refactoring plan (eliminating code duplication)**: [REFACTOR-PLAN.md](REFACTOR-PLAN.md)
- **Client for Keenetic routers (dual-arch mipsel+aarch64)**: [KEENETIC-PORT.md](KEENETIC-PORT.md) · step-by-step deployment: [KEENETIC-DEPLOY.md](KEENETIC-DEPLOY.md)

## Status

Pre-1.0 / experimental, but the data plane is stable. 0.7.0 — the post-quantum
tunnel (X25519+ML-KEM hybrid) + audit fixes from 2026-06-11. **0.7.1** — security
hardening from the 2026-06-12 audit (2048-bit replay window, atomic resolv.conf,
kill-switch sanitization) plus **H-1**: binding the session keys to the server's
static identity (Noise-IK), **on by default** — see [ROADMAP.md](ROADMAP.md) and
[AUDIT-2026-06-12.md](AUDIT-2026-06-12.md). **0.7.2–0.7.4**: anti-DPI traffic shaping
+ server NAT (0.7.2), Android INI/TUN fixes + the Linux kill-switch on iptables + audit
hygiene (0.7.3), and UDP handshake fragmentation for LTE/mobile (0.7.4). PQ/H-1 affect only the handshake (a
one-time cost), throughput is unchanged, so the measurements below are still
current ([BENCHMARK.md](BENCHMARK.md), 2 vCPU lab, measured on v0.5.6):

- **TCP**: ~560–571 ↑ / ~690–717 ↓ Mbps (plain/fake-tls/reality), all modes stable
  with no drops; obfs −12%; reality-proxy ≈ plain; reality-tls ↓ ~430 (since 0.7.0; the cost of
  nested real TLS — double AEAD on the client, see BENCHMARK).
- **UDP**: clean up to 300 Mbps, ~400 Mbps at <1% loss, saturation ~500.
- Latency overhead ~1.5–1.9 ms; worker memory ~7–8 MB; the bottleneck is the
  single-core decryption CPU.
- Auto-reconnect, crash-safe DNS, brute-force lockout, channel-binding, pinning,
  per-profile authorization — all working (**225 unit tests** green, e2e of all
  wire modes confirmed in the lab).

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
