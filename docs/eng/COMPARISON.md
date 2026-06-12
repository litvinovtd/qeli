# qeli vs other VPN solutions

Not marketing. The qeli numbers are measured in our lab ([BENCHMARK.md](BENCHMARK.md)),
the numbers for mature solutions are typical published ones on comparable hardware (2
vCPU, a gigabit-class link).

## Positioning map

|  | Goal | Transport | Obfuscation | Anti-DPI |
|---|---|---|---|---|
| **WireGuard** | A minimalist fast VPN | UDP only | No | Low (a unique UDP signature) |
| **OpenVPN** | A universal legacy VPN | TCP / UDP | Opt. (`tls-crypt`) | Medium (TLS is identifiable) |
| **V2Ray / Xray** | A tunnel through everything | TCP/UDP/WS/gRPC | Multi-layered + REALITY | High |
| **Shadowsocks** | Light masking | TCP / UDP | AEAD + obfs-plugin | Medium |
| **qeli** | A self-hosted VPN with a web admin and built-in obfuscation | TCP (plain / fake-tls / obfs / reality / reality-tls) / UDP (+QUIC) | Built-in, several modes | From none (plain) to high (reality-tls) |

qeli is closest to **V2Ray/Xray in the TLS-masking mode**, but with its own L4 protocol, a
built-in TUN/TAP plane, and a web admin — without an nginx front.

## Performance

| solution | TCP @ 2 vCPU | CPU @ ~400 Mbps | RTT overhead | note |
|---|---:|---:|---:|---|
| WireGuard | 800–1500 Mbps | 1–3% | 0.1–0.3 ms | in-kernel |
| OpenVPN UDP (AES-GCM) | 200–400 Mbps | 8–15% | 0.5–1.5 ms | user-space |
| V2Ray (vmess+TLS) | 100–300 Mbps | 5–12% | 1–3 ms | depends on the setup |
| **qeli TCP** (our lab) | **~560–571 ↑ / ~690–717 ↓ Mbps** | ~34% of one core | ~1.7 ms | plain/fake-tls/reality; stable, no drops |
| **qeli UDP** | **~400 Mbps** (<1% loss) | ~34% of one core | ~1.6 ms | saturation ~500 |
| **qeli obfs mode** | **~491 ↑ / ~577 ↓ Mbps** | ~34% | ~1.6 ms | +a ChaCha20 layer (−12%) |
| **qeli reality-tls** | ~515 ↑ / ~319 ↓ Mbps | ~32% | ~2.0 ms | real TLS inside; ↓ lower (double AEAD on the client) |

**What this means:**
- WireGuard is always the fastest. If you need *speed* — take it.
- OpenVPN-UDP and V2Ray are in the same zone as qeli by throughput/CPU; qeli meanwhile
  holds ~560 Mbps TCP stably (above a typical V2Ray).
- qeli's ceiling is limited by the single-core decryption CPU; obfuscation (except `obfs`)
  is almost free.

## What qeli does well

1. **Built-in obfuscation without add-ons** — fake-TLS / `obfs` (a ChaCha20-stream with
   WS-fronting) / a REALITY proxy "out of the box", without nginx/cloak/obfs4.
2. **Several wire modes to choose from** — TLS mimicry; `obfs` with the start masked as a
   WebSocket Upgrade (anti-FET — passes the GFW/TSPU entropy detector); or REALITY
   (proxying foreign handshakes to a real site).
3. **Several profiles in one daemon** (`[profile:<name>]`) — TCP:443, UDP:4443, REALITY at
   once. WireGuard/OpenVPN can't do that.
4. **A native web admin** (Argon2 + same-origin CSRF + a path-whitelist).
5. **Identity protection**: a per-profile static key, pinning + `require_client_key_proof`
   (rejecting the unpinned + hiding the key from scanners).
6. **Per-profile authorization** (interface isolation), a brute-force lockout (user+IP),
   Argon2id for passwords, channel-binding in the handshake, anti-replay, UDP
   anti-amplification.
7. **Crash-safe DNS** and client auto-reconnect (detecting a dead server within tens of
   seconds).

## What mature solutions do better

| solution | how it beats qeli |
|---|---|
| WireGuard | Speed (2–3×). Simplicity. In-kernel. An external audit. |
| OpenVPN | Real TLS + CA-trust. Mature clients for everything. A CVE pipeline. |
| V2Ray / Xray | A large community, maturity, an ecosystem of clients for everything. (On the REALITY certificate qeli reached parity — cert-borrowing, see below.) |
| Shadowsocks | Minimal resources, runs on routers. |

On **active DPI**: qeli has two layers of REALITY. `reality` (proxy) *proxies* foreign
handshakes to a real site (`target`, e.g. microsoft — the prober sees it), but the qeli
client still sends fake-TLS. **`reality-tls` (ready)** — the client sends **real** browser
TLS 1.3 (Chrome JA4), the server terminates it and carries the tunnel inside; on the wire
it's indistinguishable from ordinary HTTPS (it closes tells 1.1–1.6 of DPI-AUDIT).
**Cert-borrowing (`handrolled=true`, 2026-06-06) closed the former gap with Xray-REALITY:**
the hand-rolled server at start **borrows the target's real cert chain** (a probe to
`target:443`) and hands it to the client instead of self-signed — with an auto-refresh
every 12h. This is the same model as Xray (a borrowed cert, the client doesn't validate —
trust via the X25519 token). The `plain` mode carries no obfuscation at all (for trusted
networks); `fake-tls`/`obfs` target passive/signature-based (and entropy-based for obfs)
DPI.

On the **entropy-based "fully encrypted" detection** (GFW 2022+/TSPU): the `obfs` mode
masks the start of a connection as a WebSocket Upgrade (printable HTTP) — the first packet
passes the exemptions, the flow isn't classified as "encrypted garbage" (DPI-AUDIT tell
4.1, [docs/DPI-AUDIT.md](DPI-AUDIT.md)). The limitation: TCP only — UDP-obfs is still
high-entropy for now (tell 4.2).

## When to take qeli

✅ A self-host / small-team VPN where you need: TCP masked as HTTPS (or the
structurally-zero `obfs`), a built-in admin, several profiles, pinning + a password,
authorization by interface.

❌ Don't take it: you need maximum speed → WireGuard; you need a maximally battle-tested,
audited stack with a large community against state-level active DPI → Xray REALITY (qeli
reached parity on reality-tls + cert-borrowing + the PQ hybrid, but is less battle-tested);
audited code + a public CVE history → OpenVPN/WireGuard.

## Feature matrix

| feature | WireGuard | OpenVPN | V2Ray/Xray | qeli |
|---|:---:|:---:|:---:|:---:|
| Speed | ★★★★★ | ★★★ | ★★★ | ★★★★ |
| Obfuscation by default | ✘ | ✘ | ★★★★ | ★★★★ |
| Several wire modes | ✘ | ✘ | ★★★★ | ★★★★ (plain/fake-tls/obfs/reality/reality-tls) |
| TLS masking | ✘ | real TLS | real TLS + REALITY | fake-TLS + real TLS (reality-tls) |
| Built-in admin | ✘ | ✘ | ✘ | ✅ |
| Anti-brute-force (user+IP) | ✘ | a plugin | ✘ | ✅ |
| Pinning + enforcement | a peer key | CA/cert | ✅ | ✅ (`require_client_key_proof`) |
| Authorization by interface | ✘ | ✘ | partial | ✅ |
| UDP anti-amplification | n/a | — | — | ✅ |
| PQ crypto (X25519MLKEM768) | ✘ | ✘ | ◐ opt. | ✅ (the inner tunnel, all modes except plain) |
| Audit / CVE history | ★★★ | ★★★ | ★★★ | ✘ |
| Text config | ✅ (ini-like) | ✘ (ini) | ✘ (JSON) | ✅ (flat-INI) + REST |
| In-kernel | ✅ Linux | ✘ | ✘ | ✘ |
| Multi-profile in one daemon | ✘ | ✘ | ✅ | ✅ |
