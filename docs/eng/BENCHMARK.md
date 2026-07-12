# qeli load testing

This document is versioned: **the fresh measurements are in the "Version 0.7.x" sections**
below (the latest is **0.7.7**, 2026-07-06, a freshly-rebooted clean host); the detailed per-mode tables at the
bottom are the **0.6.0 reference base** (2026-06-11; 2-VM lab, release binary
LTO=fat/strip/panic=abort). The canonical
[release/benchmark_results.json](../../release/benchmark_results.json) always holds the **latest**
run (currently 0.7.7); dated per-version copies sit alongside (`benchmark_results_<date>_v<ver>.json`,
0.6.0 in `benchmark_results_2026-06-11_v0.6.0.json`). The orchestrator —
[scripts/benchmark.py](../../scripts/benchmark.py).

> Release **0.6.0** is a refactoring (the shared C# layer, .NET 10, cleanup); the
> protocol, crypto, and data plane were **unchanged**. A direct measurement of 0.6.0
> confirmed this: on a clean lab it runs at/above the 0.5.6 reference (the 2026-06-07
> run) in all modes — there's no regression (TCP +3…+10%, UDP loss at 500 Mbps half as
> much). The 0.5.6 reference is kept alongside in
> `release/benchmark_results_2026-06-07_v0.5.6.json`.

> 🆕 **Version 0.7.0** (2026-06-12) — a large core refactor (PQ-derive/ml-kem, the
> hand-rolled realtls server, the kill-switch, reality-hardening). The measurements and
> the delta to 0.6.0 — in the section **"Version 0.7.0 — the delta to 0.6.0"** right
> below (before the baseline). The detailed per-mode 0.6.0 tables remain the reference
> base.
>
> **0.7.0** (the post-quantum tunnel + the audit 2026-06-11): the X25519+ML-KEM hybrid
> affects only the handshake (a one-time cost on connect), throughput is unchanged — a
> live `sanity_e2e` run gave the same 570–700 Mbps TCP and 0% UDP loss on the non-`plain`
> modes.

> 🆕 **Version 0.7.1** (2026-06-12) — more core changes + a new wire-breaking **H-1**
> (`bind_static_to_session`, default true, requires pinning) + a functionality run of every
> default config. The section **"Version 0.7.1 — the delta to 0.7.0"** below: no regression,
> reality-tls upload stabilized (σ 99→19).

> 🆕 **Version 0.7.2** (2026-06-20) — anti-DPI traffic shaping (idle-cover), server-side NAT,
> the 2026-06-18 audit fixes, the web client-manager panel. All changes are **off the bench
> data path** (the bench config enables no shaping/NAT). The measurement ran on a host under
> hypervisor CPU steal → this session's absolutes are depressed, so verification is a
> **host-neutral A/B** (0.7.1 vs 0.7.2 interleaved). The section **"Version 0.7.2 — the delta
> to 0.7.1 (A/B)"** below: **no regression**.

> 🆕 **Version 0.7.4** (2026-06-28) — UDP handshake fragmentation (dodges dropped IP fragments
> on LTE/CGNAT) + UDP session fixes (keepalive for idle/download-only tunnels, inbound-byte
> accounting). Measured on a **clean** host (steal 2.1%, baseline 21 Gbps) → direct absolutes,
> comparable to the clean 0.7.1 day. The section **"Version 0.7.4 — the delta to 0.7.1"** below:
> **no regression**, the UDP data plane is untouched by the `udp_handler` refactor.

> 🆕 **Version 0.7.10** (candidate, 2026-07-10) — the Rust core is at **0.7.9** level (the 0.7.10
> WIP is Android/desktop clients only; the data plane is untouched). Cumulative data-plane changes
> 0.7.5→0.7.9: the oversized-record fix (0.7.7), the reality-tls aes-gcm→0.10 revert (0.7.7), server
> udp-quic autodetect + RFC-9001 (0.7.9), jemalloc in server builds. This session's host was moderately
> contended → verified with a **host-neutral A/B to 0.7.4**: **no regression, 0.7.9 is equal-or-faster
> than 0.7.4**.

> 🆕 **Version 0.7.11** (candidate, 2026-07-12) — a large dev batch (RCE→P3 audit, exclude/include
> CIDR routing under full tunnel, per-user static_ip + disconnect notifications, sleep/resume recovery,
> panel) + dep bumps **x25519-dalek 3** / jemallocator 0.7. The binary reports `qeli 0.7.10` (Cargo not
> yet 0.7.11). This session's host was moderately contended → **host-neutral A/B to 0.7.9**: **no
> regression, 0.7.11 is equal-or-faster than 0.7.9 everywhere, including reality-tls (+5.9%/+2.8%)**;
> the major x25519-dalek 3 bump did not touch throughput.

## The rig

| parameter | value |
|---|---|
| Server | `10.66.116.10`, Debian 13, kernel 6.12.88, 2 vCPU (QEMU, AES-NI present), NIC virtio |
| Client | `10.66.116.11`, identical, the same L2 network |
| iperf3 | 3.18 |
| TUN MTU | 1400 in all modes |
| Cipher / KEX | ChaCha20-Poly1305 / X25519 + HKDF-SHA256 (reality-tls: the outer TLS — AES-128-GCM) |

**Methodology.** For each mode we bring up a **separate tunnel** (a flat-INI config of
the server + client), `ping -c 20 -i 0.2`, then `iperf3 -t 12` in both directions for
TCP, or a sweep `iperf3 -u -b {100..500}M -l 1200` for UDP. CPU is taken via
`iperf3 cpu_utilization_percent` (host=the iperf client, remote=the iperf server, % of
2 vCPU) **and** by sampling the `qeli` process on the server.

> ⚠️ The numbers have a spread of ±3–5% between runs (a virtio VM). For pristine numbers
> run on a **freshly rebooted** lab: a background load on the .11 client (e.g. the stock
> Android emulator `qemu -avd test`, ~17% CPU) **inflates UDP loss** at 400–500 Mbps
> several-fold (the open-loop receiver is CPU-starved) and slightly lowers TCP — before a
> benchmark `python scripts/reboot_vms.py`. This run is without drops, `ping` 0% in all
> modes.

> ⚠️ **A second trap — hypervisor CPU steal (a noisy neighbor).** The lab VMs share a
> physical host; when a neighbor loads the host, the guest is starved of CPU even while it
> reports `idle`. Check `vmstat 1` (the `st` column): on a clean host `st≈0`, under
> contention 5–10%. Steal **degrades the no-VPN baseline too** (that's the tell: TCP
> baseline 21 → 18–19 Gbps, UDP loss rises) → absolutes across different days become
> incomparable. **If `st` is high and won't drop**, switch to a *host-neutral A/B* (two
> versions interleaved in one session, see [scripts/ab_071_072.py](../../scripts/ab_071_072.py)):
> both see the same steal, so the delta stays honest. The emulator on .11 may **restart
> itself** mid-session through a long run — re-check `pgrep -f qemu-system`.

> 🔴 **IMPORTANT about the `qeli CPU` columns below.** They were taken with `ps %cpu` =
> an average over the WHOLE life of the process → they **greatly underestimate** (showing
> ~34%). A precise delta measurement by `/proc/<pid>/stat` over the load window
> ([scripts/multicore_probe.py](../../scripts/multicore_probe.py)) gives **~150% = ~1.5
> cores** on ONE tunnel: the data plane is **multi-core** (the decrypt-reader +
> encrypt-writer + TUN-pump are independent tokio tasks on different cores), not "one
> core". The `qeli CPU` columns in the tables are only a relative comparison of the modes
> against each other, NOT the absolute core load.

## Version 0.7.0 (2026-06-12) — the delta to 0.6.0

A large core refactor (`+1484/−327` lines: the PQ `crypto/derive`+`mlkem`, the
hand-rolled realtls server `protocol/tls`, `server/{handler,mod,dns,reality}`,
`client/killswitch`). The binary `qeli 0.7.0` sha `5e40e697`, a freshly rebooted lab,
the gate PASS (build + **191 tests** + clippy). The raw data —
[release/benchmark_results_2026-06-12_v0.7.0.json](../../release/benchmark_results_2026-06-12_v0.7.0.json),
the 0.6.0 reference alongside in `benchmark_results_2026-06-11_v0.6.0.json`.

### ⚠️ Two breaking config changes (accounted for in [benchmark.py](../../scripts/benchmark.py))

1. **Persistent TOFU** — the server key pin is now stored on disk
   (`/var/lib/qeli/known_hosts`), not in the session memory. A stale pin on `host:port`
   survives a reboot and **rejects the connect** with a fresh bench key → the harness
   wipes it before each mode.
2. **`reality_proxy` requires `short_ids`** — the trivially probeable fallback by the
   absence of ALPN was removed; `reality_proxy.enabled` without `short_ids` is **rejected
   at startup** (the worker in a respawn loop → connection refused). The bench tcp-reality:
   the server gets `short_ids`, the client (fake-tls) gets `reality_sid` + the key pin
   (fake-tls seals the sid in the session_id). Additive: `kill_switch`, `peek_timeout_ms`;
   the default `handrolled` switched false→true (real_tls-reality is now hand-rolled, not
   rustls).

### TCP, Mbps (↑up / ↓down)

| mode | 0.6.0 ↑/↓ | 0.7.0 ↑/↓ | Δ |
|---|---|---|---|
| plain | 571 / 714 | 555 / 700 | −2.8% / −2.0% |
| fake-tls | 563 / 697 | 527 / 693 | −6.4% / −0.6% |
| padding | 559 / 704 | 528 / 686 | −5.5% / −2.5% |
| frag | 554 / 702 | 533 / 664 | −3.8% / −5.4% |
| obfs | 498 / 582 | 482 / 568 | −3.1% / −2.5% |
| reality (proxy) | 577 / 721 | 552 / 688 | −4.3% / −4.7% |
| **reality-tls** (5× median) | 488 / 321 | 482 / **417** | −1.2% / **+30%** |

### UDP, loss % (400M / 500M)

| mode | 0.6.0 | 0.7.0 |
|---|---|---|
| udp-fake-tls | 0.35 / 2.97 | 0.20 / 2.98 |
| udp-padding | 0.41 / 3.22 | 0.31 / 3.32 |
| udp-quic | 0.25 / 4.08 | 0.45 / 4.28 |

### reality-tls × 5 runs

- **↑ up:** 0.6.0 median 488 (σ37) → 0.7.0 **482** (σ99, spread 437–688) — the same, a higher spread.
- **↓ down:** 0.6.0 **321** (σ2.4) → 0.7.0 **417** (σ3.4) — **+30%, both stable → a real gain**
  (the hand-rolled TLS server in the new default is faster than rustls + the `protocol/tls` refactor).
  The raw data — [release/reality_tls_5x_v0.7.0_2026-06-12.json](../../release/reality_tls_5x_v0.7.0_2026-06-12.json).

### The precise data-plane CPU (the /proc delta, both binaries back-to-back)

`scripts/multicore_probe.py` — the worker's true CPU by `/proc/<pid>/stat` (not `ps`).
0.6.0 was built in isolation from the committed HEAD ([scripts/probe_060_ab.py](../../scripts/probe_060_ab.py)).

| 1 tunnel | 0.6.0 | 0.7.0 |
|---|---:|---:|
| upload (decrypt) | 146% (1.46 cores) | 153% (1.53 cores) |
| download (encrypt) | 149% (1.49) | 153% (1.53) |
| bidir | 154% @218↑/217↓ | 154% @140↑/138↓ |

The real cost of the refactor on the data plane — **~+3–5% CPU/core per tunnel** (NOT
+15%, as it seemed from the `ps %cpu` sampler in benchmark.py — it's a lifetime-average
and inflates the delta; trust the /proc probe). In production (1-core-bound, ceiling
~311 Mbps) this is **−3–5% of the ceiling (~295–300 Mbps)** — moderate. A nuance: the
bidir CPU is the same, but the throughput is 218→140 at the same saturation of 2 cores —
a slight efficiency dip under a bidirectional load (a noisy sample).

### The 0.7.0 conclusion

Single-stream throughput **with no significant regression** (TCP in the virtio noise,
UDP unchanged); **reality-tls download +30%**; the data-plane CPU **+3–5%**. The detailed
per-mode 0.6.0 numbers below — the reference base.

## Version 0.7.1 (2026-06-12) — the delta to 0.7.0

More core changes on top of 0.7.0 (`protocol/packet.rs`, `client/dns`, `crypto/derive`,
**H-1** — below) + the default configs were rewritten. The binary `qeli 0.7.1` sha `6f997202`,
a freshly rebooted lab, the gate PASS (build + **194 tests** + clippy). Raw data —
[release/benchmark_results_2026-06-12_v0.7.1.json](../../release/benchmark_results_2026-06-12_v0.7.1.json).

### ⚠️ New wire-breaking: H-1 (`bind_static_to_session`, default true)

Since 0.7.1 the session KDF additionally folds in the static-ephemeral DH (Noise-IK): a
failed ephemeral RNG alone no longer exposes the tunnel. Default `true` on BOTH the server
and the client — it **requires pinning the server key**; a TOFU / legacy-0.7.0 client is
rejected. Pairs with `require_client_key_proof = true`. benchmark.py pins the key in EVERY
mode (otherwise the TOFU modes fail, as before with the persistent-TOFU known_hosts). The
default configs already account for it.

### Default-config functionality (e2e on 0.7.1)

A live run of every shipped default config ([scripts/config_functest.py](../../scripts/config_functest.py)):

| config | result |
|---|---|
| **server.conf** (fake-tls, full stack: NAT/DNS/padding/frag/heartbeat/H-1) | ✅ **PASS** — Auth OK, ping gw, **565 Mbps** |
| **server-maxobf.conf** (reality-tls: real_tls + hand-rolled, require_proof, H-1) | ✅ **PASS** — Auth OK, ping gw, **527 Mbps** |
| parse server.conf / server-maxobf.conf / client.conf / client-maxobf.conf / client-reality-tls.conf | ✅ OK |

Fixed a template bug in `client-maxobf.conf` (it was inconsistent with server-maxobf.conf:
user `phone`≠`client1`, mode `fake-tls`≠real_tls) → `user=client1`, `mode=reality-tls`,
`+reality_sid`; verified e2e. `client-reality-tls.conf` / `client-YOUR_DEPLOY_HOST.conf` point
at an external server (parse only).

### TCP, Mbps (↑up / ↓down)

| mode | 0.7.0 ↑/↓ | 0.7.1 ↑/↓ | Δ |
|---|---|---|---|
| plain | 555 / 700 | 549 / 717 | −1% / +2% |
| fake-tls | 527 / 693 | 538 / 685 | +2% / −1% |
| padding | 528 / 686 | 550 / 706 | +4% / +3% |
| frag | 533 / 664 | 540 / 674 | +1% / +2% |
| obfs | 482 / 568 | 501 / 579 | +4% / +2% |
| reality (proxy) | 552 / 688 | 559 / 689 | +1% / ≈0 |
| **reality-tls** (5× median) | 482 / 417 | **518 / 418** | **+7% / ≈0** |

### UDP, loss % (400M / 500M)

| mode | 0.7.0 | 0.7.1 |
|---|---|---|
| udp-fake-tls | 0.32 / 2.95 | 0.32 / 2.95 |
| udp-padding | 0.31 / 3.32 | 0.44 / 11.68¹ |
| udp-quic | 0.45 / 4.28 | 0.20 / 2.37 |

¹ a spike at the saturation knee (400M = 0.44%; fake-tls/quic 500M = 2.4–3%) — noise, not a regression.

### reality-tls × 5 — upload stabilization

- **↑ up:** 0.7.0 median 482 (**σ 99**, spread 437–688) → 0.7.1 median **518** (**σ 19**, 498–551):
  upload is both faster (+7%) and **much more stable** — the "jumpy" 0.7.0 upload is cured.
- **↓ down:** 417 → **418** (σ 5.5) — stable. Raw data —
  [release/reality_tls_5x_v0.7.1_2026-06-12.json](../../release/reality_tls_5x_v0.7.1_2026-06-12.json).

### The 0.7.1 conclusion

No regression (0.7.1 ≈ 0.7.0, mostly slightly higher) despite the packet/dns/derive changes
and H-1; the data-plane CPU is the same (the precise /proc measurement of 0.7.0 = 1.53 cores,
the data-plane core was unchanged). The notable improvement — **reality-tls upload
stabilization** (σ 99→19). Both default server configs are functional end-to-end.

## Version 0.7.2 (2026-06-20) — the delta to 0.7.1 (A/B)

0.7.2 content: anti-DPI traffic shaping (idle-cover Poisson + Stealth), server-side NAT
(iptables), the 2026-06-18 audit fixes, the web client-manager panel. The binary
`qeli 0.7.2` sha `98c6b05a`, a freshly rebooted lab, the gate PASS (build + **213 tests**
(210 lib + 3 bin) + clippy). The A/B raw data —
[release/ab_071_vs_072_2026-06-20.json](../../release/ab_071_vs_072_2026-06-20.json),
the full 0.7.2 run — [release/benchmark_results_2026-06-20_v0.7.2.json](../../release/benchmark_results_2026-06-20_v0.7.2.json).

> 🟡 **Why A/B, not direct absolutes.** This session the hypervisor host was under a noisy
> neighbor — under load **CPU steal 7–9%** (server), and the emulator on .11 restarted
> itself mid-run. Even the no-VPN baseline degraded (TCP 21 → 18.6 Gbps, UDP loss ×3) → a
> direct comparison of absolutes against the clean 0.7.1 day (2026-06-12) would show a
> **false "~13% regression"**. So 0.7.2 was verified with a **host-neutral A/B**: 0.7.1
> (built from tag `v0.7.1`, sha `996c9d98`) and 0.7.2 were run **interleaved in one session**
> ([scripts/ab_071_072.py](../../scripts/ab_071_072.py)) — both see the same steal, so it's
> cancelled out of the delta. This is the same technique `probe_060_ab.py` uses for CPU.

### A/B TCP, Mbps (↑up / ↓down) — both binaries on the same (contended) host

| mode | 0.7.1 ↑/↓ | 0.7.2 ↑/↓ | Δ |
|---|---|---|---|
| plain | 522 / 638 | 505 / 603 | −3.3% / −5.6% |
| fake-tls | 501 / 599 | 508 / 608 | +1.3% / +1.6% |
| padding | 488 / 547 | 483 / 543 | −1.0% / −0.7% |
| frag | 511 / 607 | 435 / 468 | −15% / −23%¹ |
| obfs | 431 / 473 | 452 / 484 | +4.9% / +2.3% |
| reality (proxy) | 503 / 613 | 494 / 591 | −1.7% / −3.7% |
| **reality-tls** (median 3×) | 464 / 420 | 461 / 413 | **−0.6% / −1.6%** |

¹ a single run that caught a steal spike (ping mdev 5.3 ms on the 0.7.2 sample — six times
the neighbors). In **reality-tls** (median of 3× — the most careful mode) and in the other
rows the effect averages out, there is no real delta.

### A/B UDP, loss % (400M / 500M)

| mode | 0.7.1 | 0.7.2 |
|---|---|---|
| udp-fake-tls | 10.3 / 28.8 | 5.0 / 12.8 |
| udp-padding | 5.9 / 16.0 | 5.1 / 16.2 |
| udp-quic | 4.0 / 15.6 | 6.7 / 15.6 |

UDP loss is high on **both** versions (CPU starvation of the open-loop receiver on .11 under
steal+emulator), 0.7.2 ≈ 0.7.1 (on fake-tls even lower) — host noise, not the data plane.

### reality-tls × 5 (0.7.2, the same contended host)

- **↑ up:** median **459.3** (σ 15.2, range 429–474).
- **↓ down:** median **416.4** (σ 7.2, range 405–424) — effectively **matching the clean
  0.7.1 day (418)**: reality-tls download is bound by the client-decrypt on .11 and is barely
  hit by the server-side steal, whereas upload (459 vs 518 on the clean day) sags with the
  host. On this same host the A/B measured 0.7.1 at 464/420 ≈ 0.7.2 459/416 → parity.
  Raw data — [release/reality_tls_5x_v0.7.2_2026-06-20.json](../../release/reality_tls_5x_v0.7.2_2026-06-20.json).

### The 0.7.2 conclusion

**No regression.** The host-neutral A/B: all modes within the ±2–5% noise (some faster on
0.7.2), reality-tls at the median of 3× is **−0.6% / −1.6% = parity**. The only "large" delta
(frag −15/−23%) is a single steal spike, absent in the averaged modes. The anti-DPI traffic
shaping, the server NAT and the client-manager **do not touch the bench data path** (cover
traffic is sent only when idle, NAT is off in the bench config). This session's absolutes are
depressed by the host (steal 7–9%) and must not be compared directly to the 0.7.1 numbers from
2026-06-12 — for the delta see the A/B above. The detailed per-mode 0.6.0 reference tables are below.

## Version 0.7.4 (2026-06-28) — the delta to 0.7.1

0.7.4 content: **UDP handshake fragmentation** (`protocol/udp_frag.rs` — the large PQ ClientHello
is split into pieces to dodge dropped IP fragments on LTE/CGNAT; triggers automatically, **only on
the handshake**, off the data plane) + UDP session fixes (`server/udp_handler.rs`: keepalive for
idle/download-only tunnels without false reconnects, inbound-byte accounting). The binary
`qeli 0.7.4` sha `1c36f802`, a freshly rebooted lab, the gate PASS (build + **225 tests**
(222 lib + 3 bin) + clippy). Raw data —
[release/benchmark_results_2026-06-28_v0.7.4.json](../../release/benchmark_results_2026-06-28_v0.7.4.json).

> 🟢 **The host is clean** (unlike the 0.7.2 session): under load steal **2.1%** (server) /
> 0.9% (client), the no-VPN baseline TCP **21,020 Mbps** ≈ the 21 Gbps reference → no A/B was
> needed, the direct absolutes are comparable to the clean 0.7.1 day (2026-06-12). The intermediate
> 0.7.2 (host-neutral A/B, under contention) and 0.7.3 (not throughput-benchmarked on the lab —
> Android/security fixes off the data path) gave no clean per-mode numbers of their own, so the delta
> is taken to 0.7.1 — the last clean run.

### TCP, Mbps (↑up / ↓down)

| mode | 0.7.1 ↑/↓ | 0.7.4 ↑/↓ | Δ |
|---|---|---|---|
| plain | 549 / 717 | 551 / 718 | +0.4% / +0.1% |
| fake-tls | 538 / 685 | 533 / 715 | −0.9% / +4.4% |
| padding | 550 / 706 | 532 / 698 | −3.3% / −1.1% |
| frag | 540 / 674 | 567 / 689 | +5.0% / +2.2% |
| obfs | 501 / 579 | 496 / 571 | −1.0% / −1.4% |
| reality (proxy) | 559 / 689 | 553 / 709 | −1.1% / +2.9% |
| **reality-tls** (5× median) | 518 / 418 | **549 / 431** | **+5.9% / +3.0%** |

All modes within the ±5% noise (a few even higher) → no regression; reality-tls — the heaviest mode —
is even slightly faster on this host.

### UDP, loss % (400M / 500M) — the main focus of 0.7.4

| mode | 0.7.1 | 0.7.4 |
|---|---|---|
| udp-fake-tls | 0.32 / 2.95 | 0.63 / 4.81 |
| udp-padding | 0.44 / 11.68¹ | 1.01 / 3.71 |
| udp-quic | 0.20 / 2.37 | 0.31 / 3.81 |

The UDP plane is clean (<1% up to 400M on all modes); at the 500M knee the loss is in the usual
saturation-noise range (0.7.1 also had outliers up to 11.68% there). **The `udp_handler` refactor and
the handshake UDP-frag did not hurt UDP throughput/loss** — which was the main release risk.

### reality-tls × 5 (0.7.4, clean host)

- **↑ up:** median **548.8** (σ 24.2, range 521–579) — vs 518 (σ19) on the clean 0.7.1 day.
- **↓ down:** median **430.6** (σ 6.3, range 425–441) — vs 418 (σ5.5). Both stable and slightly higher
  — not a regression. Raw data — [release/reality_tls_5x_v0.7.4_2026-06-28.json](../../release/reality_tls_5x_v0.7.4_2026-06-28.json).

### The 0.7.4 conclusion

**No regression** on a clean host: TCP within ±5% of the clean 0.7.1 day, reality-tls (5× median)
slightly higher (+6%/+3%), UDP loss normal. The key release risk — the UDP-handler refactor and the
handshake fragmentation — **did not touch the UDP data plane** (loss <1% up to 400M, throughput on par).
UDP-frag works on the handshake and is invisible to the load test. The detailed per-mode 0.6.0 reference
tables are below.

## Version 0.7.6 (2026-07-02) — the delta to 0.7.4

What's in 0.7.6: **AmneziaWG-style masking for obfs (F2)** — pre-handshake junk records
(`obf.awg.jc`/`jmin`/`jmax`; `protocol/obfs.rs`) modelled on AmneziaWG; config-gated, **OFF by default**,
`jc` must match on both ends — plus web-panel work. The binary `qeli 0.7.5` (version not yet bumped),
sha `b4ae0897`, a freshly rebooted lab (.11 with no stray qeli service), the gate PASS
(build + **265 tests** (262 lib + 3 bin) + clippy). Raw data —
[release/benchmark_results_v0.7.6_pristine.json](../../release/benchmark_results_v0.7.6_pristine.json).

### TCP, Mbps (↑up / ↓down)

| mode | 0.7.4 ↑/↓ | 0.7.6 ↑/↓ | Δ |
|---|---|---|---|
| plain | 551 / 718 | 565 / 722 | +2.5% / +0.6% |
| fake-tls | 533 / 715 | 567 / 720 | +6.4% / +0.7% |
| padding | 532 / 698 | 566 / 684 | +6.4% / −2.0% |
| frag | 567 / 689 | 578 / 678 | +1.9% / −1.6% |
| obfs | 496 / 571 | 489 / 684 | −1.4% / +19.8%¹ |
| reality (proxy) | 553 / 709 | 467¹ / 677 | / −4.5% |
| **reality-tls** (5× median) | 549 / 431 | 500 / **443** | / **+2.8%** |

¹ Single per-mode runs carry virtio variance: obfs download (571↔684) and reality/reality-tls upload are
historically noisy (± up to 20%). No structural regression; the reliable signal is the **averaged (5×)
reality-tls download, which keeps climbing**: 0.7.1 = 418 → 0.7.4 = 431 → 0.7.6 = **443**.

### UDP, loss % (400M / 500M)

| mode | 0.7.4 | 0.7.6 |
|---|---|---|
| udp-fake-tls | 0.63 / 4.81 | 0.63 / 5.26 |
| udp-padding | 1.01 / 3.71 | 1.08 / 7.51 |
| udp-quic | 0.31 / 3.81 | 0.75 / 6.63 |

UDP is clean up to 400M (<1.1% on all), the 500M knee is the usual saturation noise. Unchanged.

### reality-tls × 5 (0.7.6)

- **↑ up:** median **500.3** (σ4.2) — a variable metric (0.7.4 = 549); within the range of past runs.
- **↓ down:** median **443.1** (σ4.4) — stable, the **best result** (418 → 431 → 443). Raw data —
  [release/reality_tls_5x_v0.7.6.json](../../release/reality_tls_5x_v0.7.6.json).

### AmneziaWG obfs masking (F2) — functional + overhead

The headline 0.7.6 feature. Junk records are exchanged **once, pre-handshake** (`obfs.rs`:
`send_junk`/`recv_junk` before the nonce/data loop), so they should not touch steady-state throughput.
Verified e2e ([scripts/amnezia_obfs_e2e.py](../../scripts/amnezia_obfs_e2e.py) — obfs with `jc=8` junk vs
without; median over a stable tunnel, 3 rounds):

| | connect | ↑ up | ↓ down |
|---|---|---|---|
| obfs baseline (junk off) | ✅ | 501 (σ5.5) | 658 (σ5.0) |
| obfs + junk×8 | ✅ | 496 (σ8.7) | 661 (σ21.7) |

**Overhead ~0** (↑ −0.9%, ↓ +0.5% — within noise). The masking connects, traffic flows, ping 0% — and is
essentially free throughput-wise (junk is handshake-only).

### The 0.7.6 conclusion

**No regression** — TCP within virtio variance, UDP loss normal, the stable reality-tls download metric
keeps climbing (443, the best result). The new **AmneziaWG obfs masking is functional and free**
throughput-wise (junk is a one-time pre-handshake). The gate is green (265 tests). The detailed per-mode
0.6.0 tables — below.

## Version 0.7.7 (2026-07-06) — the delta to 0.7.6

What's in 0.7.7: the **AES-GCM revert** (below), **AmneziaWG junk masking extended to every UDP mode**
(not just TCP obfs), the **jemalloc allocator** for the server (bounds the worker's RSS under handshake
churn — a ~180 MB glibc arena plateau → a ~60 MB ceiling, throughput unchanged), plus the 2026-07-05
audit + `qeli://` share-link fixes. The binary `qeli 0.7.6` (version not yet bumped) sha `11f05305`,
built `--features jemalloc`, a freshly rebooted lab (.11 with no stray qeli service, CPU-steal 0%), the
gate PASS. Raw data —
[release/benchmark_results_v0.7.7_jemalloc.json](../../release/benchmark_results_v0.7.7_jemalloc.json).

### ⚠️ The AES-GCM regression and its revert

The reality-tls outer layer is real TLS 1.3 sealed with **AES-128-GCM** (the `aes-gcm` crate; only
`realtls/record.rs` uses it). A routine dependency bump `aes-gcm 0.10 → 0.11` silently **regressed
reality-tls upload ≈ −20 %** (≈ 500 → 394 Mbps) while every other mode (ChaCha20-Poly1305, untouched)
stayed flat. The bump was **reverted to `aes-gcm 0.10`** (ChaCha stays at 0.11); a re-measure restored
reality-tls to parity. The 0.7.7 numbers below are post-revert.

### TCP, Mbps (↑up / ↓down)

| mode | 0.7.6 ↑/↓ | 0.7.7 ↑/↓ | Δ |
|---|---|---|---|
| plain | 565 / 722 | 574 / 699 | +1.5% / −3.2% |
| fake-tls | 567 / 720 | 574 / 709 | +1.2% / −1.6% |
| padding | 566 / 684 | 585 / 718 | +3.3% / +4.9% |
| frag | 578 / 678 | 596 / 730 | +3.1% / +7.6% |
| obfs | 489 / 684 | 515 / 424 | +5.4% / −38%¹ |
| reality (proxy) | 467 / 677 | 594¹ / 716 | / +5.7% |
| **reality-tls** (5× median) | 500 / 443 | 513 / **451** | +2.7% / **+1.8%** |

¹ Single per-mode runs carry virtio variance (obfs download and reality/reality-tls upload are historically
± up to 20%), and **this run's no-VPN baseline was +12% vs the 0.7.6 day** (host drift), so the raw
single-run deltas read optimistic. The reliable signal is the averaged (5×) **reality-tls download, which
keeps climbing**: 0.7.1 = 418 → 0.7.4 = 431 → 0.7.6 = 443 → 0.7.7 = **451**.

### UDP, loss % (400M / 500M)

| mode | 0.7.6 | 0.7.7 |
|---|---|---|
| udp-fake-tls | 0.63 / 5.26 | 0.83 / 3.79 |
| udp-padding | 1.08 / 7.51 | 1.07 / 3.62 |
| udp-quic | 0.75 / 6.63 | 0.69 / 4.65 |

UDP is clean up to 400M (<1.1% on all). The 500M knee looks lower here only because the .11 Android emulator
(which inflates UDP loss) was stopped for this run — a measurement condition, not a code change.

### reality-tls × 5 (0.7.7)

- **↑ up:** median **513.4** (σ4.0) — the tightest spread yet (0.7.6 = 500, 0.7.4 = 549).
- **↓ down:** median **451.2** (σ5.5) — stable, the **best result** (418 → 431 → 443 → 451). Raw data —
  [release/reality_tls_5x_v0.7.7_jemalloc.json](../../release/reality_tls_5x_v0.7.7_jemalloc.json).

### UDP AWG junk masking — functional on every UDP profile

0.7.7 extends the pre-handshake junk from TCP obfs to **every UDP mode** (obfs / fake-tls / QUIC). Verified
e2e + on the wire ([scripts/pool4_udp_awg.py](../../scripts/pool4_udp_awg.py)): the client emits `jc` decoy
datagrams before the ClientHello, each **≤ 1200 B** (no IP fragmentation), **masked** by the profile's
obfs-XOR / QUIC wrap (0 plaintext fragment-magic on the wire for obfs/quic), and the server drops them as
`MSG_JUNK` before the rate limiter / crypto. `jc=0` → byte-identical wire. On UDP `jc` is sender-only (no
count agreement). Auth OK + ping on all three UDP profiles; junk is handshake-only, so steady-state
throughput is unaffected.

### The 0.7.7 conclusion

**No regression** — reality-tls is back at parity (the AES-GCM 0.11 regression was caught and reverted; the
stable 5× download metric reaches **451**, the best yet). TCP is within virtio variance (single-run deltas
read optimistic on a +12%-faster host). jemalloc bounds the server's RSS without touching throughput. The
gate is green. The detailed per-mode 0.6.0 tables — below.

## Version 0.7.10 (candidate, 2026-07-10) — the delta to 0.7.4 (A/B)

**0.7.10 = the 0.7.9 data plane.** The uncommitted 0.7.10 WIP is clients only (Android profile
overflow menu, qeli:// share+QR, desktop reachability polling); there are no `qeli/src/` (Rust core)
changes. The measured binary is `qeli 0.7.9` sha `7e15d50e`, gate PASS (build `--features jemalloc` +
**290 tests** (287 lib + 3 bin) + clippy), a freshly rebooted lab. Since the last lab run (0.7.4) the
data plane accumulated: the oversized-record-drop fix (0.7.7), the reality-tls aes-gcm→0.10 revert after
a regression (0.7.7), server udp-quic autodetect + QUIC RFC-9001 (0.7.9). A/B raw data —
[release/ab_074_vs_079_2026-07-10.json](../../release/ab_074_vs_079_2026-07-10.json), the full run —
[release/benchmark_results_2026-07-10_v0.7.10.json](../../release/benchmark_results_2026-07-10_v0.7.10.json).

> 🟡 **Why A/B.** This session's host was moderately contended: steal ~2.8%, but the no-VPN baseline was
> 19.2 Gbps (clean ~21) with **high retransmits** (thousands). A direct sweep gave false dips on the
> download-variable modes — a single reality-tls run of 332/369 and obfs-down bouncing **176→430** at
> **low CPU** (10–24% vs ~40% on the stable modes) = NOT CPU-bound, i.e. host-throttled. So the delta is
> taken **host-neutral**: 0.7.4 (built from tag `v0.7.4`, sha `84fd20c1`) and 0.7.9 were run
> **interleaved in one session** ([scripts/ab_074_079.py](../../scripts/ab_074_079.py)) — both see the
> same steal, cancelling it. reality-tls is the median of 3× per version.

### A/B TCP, Mbps (↑up / ↓down) — both binaries on the same (contended) host

| mode | 0.7.4 ↑/↓ | 0.7.9 ↑/↓ | Δ |
|---|---|---|---|
| plain | 536 / 698 | 549 / 726 | +2.5% / +4.1% |
| fake-tls | 523 / 664 | 562 / 682 | +7.6% / +2.6% |
| padding | 513 / 673 | 564 / 656 | +10.0% / −2.5% |
| frag | 521 / 711 | 555 / 625 | +6.6% / −12.2%¹ |
| obfs | 446 / 547 | 453 / **619** | +1.6% / **+13.2%** |
| reality (proxy) | 514 / 702 | 543 / 695 | +5.7% / −1.1% |
| **reality-tls** (median 3×) | 470 / 404 | **499 / 421** | **+6.1% / +4.2%** |

¹ frag down −12% is a single run (like the frag outlier in the 0.7.2 A/B); in the averaged modes
(reality-tls) and every other row 0.7.9 is equal-or-higher. **obfs-down on 0.7.9 is +13%** — direct proof
that the "obfs 430 dip" from the plain sweep was host noise, not a regression.

### A/B UDP, loss % (400M / 500M)

| mode | 0.7.4 | 0.7.9 |
|---|---|---|
| udp-fake-tls | 22.1 / 42.7 | 3.3 / 4.1 |
| udp-padding | 0.4 / 5.1 | 7.7 / 8.7 |
| udp-quic | 0.4 / 15.9 | 0.5 / 3.3 |

UDP is noisy on **both** versions (the open-loop receiver on .11 under contention); 0.7.9 is no worse on
average (fake-tls/quic noticeably cleaner). The spread is the host, not the data plane.

### reality-tls × 5 (0.7.9, same host)

- **↑ up:** median **481.2** (σ 7.6, 467–490).
- **↓ down:** median **429.2** (σ 10.9, 409–439) — **parity with the clean 0.7.4 day (431)** and with the
  0.7.7 re-measure after the aes-gcm revert (443). reality-tls download is deterministic (client-decrypt
  bound) so it matches regardless of contention; up is variable and sags with the host's retransmits.
  Raw data — [release/reality_tls_5x_v0.7.10_2026-07-10.json](../../release/reality_tls_5x_v0.7.10_2026-07-10.json).

### jemalloc: RSS

The server binary now builds with `--features jemalloc` (like the release Linux / .deb). The worker RSS in
these runs is **~46–49 MB** (jemalloc arenas; glibc builds gave ~8 MB). This is **not a leak** — jemalloc
keeps a larger idle pool but caps lower than glibc under handshake churn (in prod 15 vs 183 MB). The RSS
columns in the old 0.6.0 tables below (~7–8 MB) are a glibc build — don't compare directly.

### The 0.7.10 conclusion

**No regression.** The host-neutral A/B: 0.7.9 (= the 0.7.10 data plane) is **equal-or-faster than 0.7.4**
in every TCP mode (up +2…+10%, down mostly + / ≈0), reality-tls at the median of 3× is **+6% / +4%**,
obfs-down **+13%**. The single dips in the plain sweep (reality-tls 332, obfs-down 176–430, frag down −12%)
are host contention (low CPU = throttling, not code), ruled out by the A/B. The cumulative 0.7.5→0.7.9
changes (oversized-record, aes-gcm revert, udp-quic) did not hurt the data plane. The detailed 0.6.0
reference tables are below.

## Version 0.7.11 (candidate, 2026-07-12) — the delta to 0.7.9 (A/B)

A large dev batch (commit `84521de` "land pending 0.7.11 dev batch"): a full-code audit (RCE→P3),
exclude/include CIDR routing under a full tunnel, per-user static_ip + disconnect notifications, fast
recovery from sleep/resume + network change, panel fixes, and **dep bumps `51490bf`: x25519-dalek 3
(major), tikv-jemallocator 0.7, rand 0.10, bytes**. The binary reports `qeli 0.7.10` sha `eff3fcb3`
(Cargo not yet 0.7.11), gate PASS (build `--features jemalloc` + **291 tests** + clippy). A/B raw data —
[release/ab_079_vs_0711_2026-07-12.json](../../release/ab_079_vs_0711_2026-07-12.json), the full run —
[release/benchmark_results_2026-07-12_v0.7.11.json](../../release/benchmark_results_2026-07-12_v0.7.11.json).

> 🟡 **Why A/B.** The host was moderately contended (steal ~2.7%, no-VPN baseline 18.5 Gbps vs clean 21,
> **high retransmits** in the thousands). The direct sweep gave one snag — reality-tls-down 398 (below
> the stable 429 floor) at **low client CPU** (22–27% = not CPU-bound, host-throttled). The batch's main
> risk is the major **x25519-dalek 3** (crypto dep). So the delta is taken **host-neutral**: 0.7.9 (built
> from tag `v0.7.9`, sha `0c5baba5`) and 0.7.11 run **interleaved in one session**
> ([scripts/ab_079_0711.py](../../scripts/ab_079_0711.py)). reality-tls is the median of 3× per version.

### A/B TCP, Mbps (↑up / ↓down) — both binaries on the same (contended) host

| mode | 0.7.9 ↑/↓ | 0.7.11 ↑/↓ | Δ |
|---|---|---|---|
| plain | 530 / 687 | 512 / 724 | −3.5% / +5.4% |
| fake-tls | 530 / 691 | 540 / 707 | +1.9% / +2.2% |
| padding | 524 / 648 | 515 / 705 | −1.7% / +8.9% |
| frag | 528 / 699 | 507 / 695 | −4.1% / −0.6% |
| obfs | 485 / 266¹ | 490 / 630 | +1.0% / (0.7.9 outlier) |
| reality (proxy) | 507 / 714 | 522 / 723 | +3.1% / +1.2% |
| **reality-tls** (median 3×) | 462 / 381 | **489 / 392** | **+5.9% / +2.8%** |

¹ 0.7.9 obfs-down = 266 was a single host outlier in that run (0.7.11 is 630; 0.7.4 was 547); the delta
there is not representative. In every other row 0.7.11 is equal-or-higher. **reality-tls (median 3×)
+5.9% / +2.8%** is the direct answer that the reality-tls-down 398 in the plain sweep was contention
(0.7.9 on the same host did even less, 381), not a regression from x25519-dalek 3.

### A/B UDP, loss % (400M / 500M)

| mode | 0.7.9 | 0.7.11 |
|---|---|---|
| udp-fake-tls | 0.4 / 4.1 | 6.3 / 6.8 |
| udp-padding | 0.7 / 3.7 | 0.7 / 2.7 |
| udp-quic | 0.5 / 5.5 | 1.5 / 4.7 |

UDP is noisy on both versions (the open-loop receiver on .11 under contention); 0.7.11 is comparable on
average (udp-padding cleaner). The spread is the host.

### reality-tls × 5 (0.7.11, same host)

- **↑ up:** median **484.9** (σ 7.9, 470–493).
- **↓ down:** median **397.8** (σ 7.4, 395–415) — below the clean-day 429 floor, BUT on this same host the
  A/B measured 0.7.9 at 381 down → 0.7.11 (392–398) is **higher**. The dip is contention (client-decrypt
  throttled), not code. Raw data — [release/reality_tls_5x_v0.7.11_2026-07-12.json](../../release/reality_tls_5x_v0.7.11_2026-07-12.json).

### The 0.7.11 conclusion

**No regression.** The host-neutral A/B: 0.7.11 is **equal-or-faster than 0.7.9** in every mode, including
the heaviest reality-tls (**+5.9% / +2.8%**). The major **x25519-dalek 3** bump and the other dep bumps
did not hurt the data plane (the crypto handshake is a one-time cost; the data-plane AEAD is ChaCha20,
untouched). The single reality-tls-down dip in the plain sweep is ruled out by the A/B (host contention).
The detailed 0.6.0 reference tables are below.

## The baseline without VPN (0.6.0, reference base)

| | throughput | loss | CPU |
|---|---:|---:|---:|
| TCP direct `.11→.10` | **20,972 Mbps** | — | recv 99% (CPU-bound, not the network) |
| UDP @ 500 Mbps | 500 Mbps | 0.16% | — |
| UDP @ 1 Gbps | **1000 Mbps** | 0.10% | — |

## TCP — all modes (0.6.0, reference base)

_The numbers below are the 0.6.0 run (2026-06-11) with the detailed columns (RTT/retr/CPU/RSS).
The current per-version throughput deltas are in the "Version 0.7.x" sections above; reality-tls
download since 0.7.0 is already ~417→430, not 321._

`up` = client→server (decrypt on the server), `down` = server→client (`iperf3 -R`,
decrypt on the client). `qeli CPU` — the busiest qeli process on the server (% of ONE
core, average/peak over the up run). `RSS` — the resident memory of the worker.

| mode | ↑ up Mbps | ↓ down Mbps | RTT avg | retr ↑/↓ | qeli CPU ↑ avg/peak | RSS |
|---|---:|---:|---:|---:|---:|---:|
| **tcp-plain** (raw, no obfuscation) | 570.8 | 714.3 | 1.24 ms | 619 / 664 | 34.6% / 60.6% | 7.3 MB |
| **tcp-fake-tls** (TLS mimicry) | 562.9 | 697.1 | 1.37 ms | 400 / 53 | 34.2% / 60.1% | 7.8 MB |
| **tcp-padding** (+ random padding) | 558.7 | 704.0 | 1.38 ms | 161 / 695 | 35.4% / 62.6% | 7.9 MB |
| **tcp-frag** (+ fragmentation) | 553.8 | 701.9 | 1.30 ms | 454 / 1063 | 34.3% / 60.3% | 7.5 MB |
| **tcp-obfs** (ChaCha20 stream + WS-fronting) | 497.6 | 582.4 | 1.29 ms | 1463 / 755 | 34.1% / 59.6% | 7.7 MB |
| **tcp-reality** (proxy-bridge, fake-TLS) | **577.2** | **721.4** | 1.37 ms | 1215 / 774 | 34.4% / 61.1% | 7.7 MB |
| **tcp-reality-tls** (real TLS 1.3) | 488¹ | **321** | 1.32 ms | 1612 / 373 | 31.8% / 56.6% | 8.3 MB |

> ¹ `reality-tls` ↑ is highly variable (5 runs: average **470 ± 37** Mbps, median
> **488**, range 421–511) — the heaviest mode, a spread on a single 12-sec run;
> ↓ is **stable 321 ± 2.4**. The row shows the median run (see
> [release/reality_tls_5x_2026-06-11.json](../../release/reality_tls_5x_2026-06-11.json),
> [scripts/reality_tls_repeat.py](../../scripts/reality_tls_repeat.py)).

**Reading:**
- **`plain` ≈ `fake-tls`** (571 vs 563 ↑; 714 vs 697 ↓): the bare tunnel and fake-TLS
  give the same speed — the fake-TLS handshake is one-time, and the framing difference
  (3 bytes/packet) is in the noise. Removing obfuscation does **not** raise throughput
  (the bottleneck is the AEAD).
- **Obfuscation is almost free** on fake-tls: padding/fragmentation/heartbeat within the
  noise.
- **`obfs` ~−12% ↑ / −16% ↓** (498/582 vs 563/697): the cost of the ChaCha20-XOR over the
  whole flow (double encryption).
- **`reality` (proxy) ≈ `fake-tls`** (even the top by throughput: 577/721): peek-and-decide
  once per TCP accept.
- **`reality-tls` — the cost of real TLS, especially on download** (488 ↑ / **321 ↓**).
  See the analysis below.
- The data plane is **multi-core** (the `/proc/stat` delta measurement, not `ps`): one
  tunnel ~1.5 cores, the load from many clients spreads across the cores. Since the
  version with **`tun.queues`** (multi-queue TUN, default auto=nproc — see [CONFIG.md](CONFIG.md))
  the TUN pump itself is parallelized too — a controlled A/B gives **+18% aggregate** with
  2 tunnels, single-flow unchanged (in detail — the [Multi-queue TUN](#multi-queue-tun-tunqueues--ab)
  section below). Memory — **~7–8 MB** RSS. RTT overhead ≈ **1.6–1.9 ms**.

## UDP — all modes (0.6.0, reference base; a sweep by bitrate, % loss)

| mode | 100M | 200M | 300M | 400M | 500M | sustained bandwidth |
|---|---:|---:|---:|---:|---:|---|
| **udp-faketls** (fake-tls, the UDP base) | 0% | 0.05% | 0.06% | 0.35% | 2.97% | **~400 Mbps** (<0.5% up to 400) |
| **udp-padding** | 0% | 0% | 0.14% | 0.41% | 3.22% | ~400 Mbps |
| **udp-quic** (masking) | 0% | 0% | 0.09% | 0.25% | 4.08% | ~400 Mbps |

The UDP plane is clean (<0.15%) up to 300 Mbps, holds ~400 at <0.5% loss, saturates
around 500 (3–4% loss). `plain`/`obfs`/`reality*` — TCP only.

> NB: these UDP numbers are from a **clean** (freshly rebooted) lab. Under a background
> load on the .11 client the loss at 400–500 Mbps balloons several-fold (400M→~8%,
> 500M→~22%) — that's CPU starvation of the open-loop receiver, **not** a degradation of
> the data plane (see ⚠️ above).

### Why there's no `plain` on UDP (by design)

`plain` (raw) is TCP-only, and this is a deliberate decision, not a gap in the tests
(the server rejects `mode = plain` + `transport = udp` at startup, see `server/mod.rs`).
Two reasons:

1. **It wouldn't give speed.** The bottleneck is the AEAD (ChaCha20-Poly1305), not the
   5-byte fake-TLS header per datagram. The same conclusion as for TCP
   (`plain ≈ fake-tls`): removing the wrapper doesn't raise throughput.
2. **It's worse for circumvention.** Raw UDP is a high-entropy flow with no structure,
   i.e. exactly the "fully encrypted traffic" signature by which DPI (GFW/TSPU) throttles
   UDP. `udp-faketls`, on the contrary, provides cover (the datagrams look like TLS
   records). So raw UDP would be a **red flag**, not masking.

So for UDP the base mode is `fake-tls` (the rows above), and it is exactly that which is
benchmarked as "UDP without extra obfuscation".

## reality-tls download: why ~320 and what to do about it (analyzed on the lab)

> 🆕 **Update:** the numbers below are the original **0.6.0 floor (~320)** diagnosis. Since 0.7.0
> (the hand-rolled TLS server instead of rustls) download rose to ~417, and the **0.7.4 measurement
> is ~430 Mbps** (see the version sections above). The bottleneck (double AEAD) is the same — the
> absolute moved, not the nature.

The tunnel in `reality-tls` runs **inside** real TLS 1.3 (rustls on the server, the
hand-rolled `realtls` on the client). On **download** the client reader strips **two
layers sequentially**: the outer TLS record (AES-128-GCM) **and** the inner qeli record
(ChaCha20-Poly1305), with double framing — in a single task. This roughly halves the
download relative to single-layer modes (~700 → ~320).

What has been verified by measurement (a lab diagnosis):
- **AES-NI on the VM is present** (not software-AES).
- The client `qeli` process at reality-tls download peaks at **~67% of one core** (not
  100%) — i.e. this is **not** a pure CPU ceiling, but a combination of double AEAD +
  double framing + await overhead in one reader task.
- **Download is deterministic** (5 runs 2026-06-11: **321 ± 2.4** Mbps), while upload is
  variable (**470 ± 37**, range 421–511): ↓ is bound by the stable two-layer decrypt
  cadence, ↑ fluctuates due to retransmits of the outer TLS under load.

**What did NOT help:** the optimization of the client read path
`RealTlsStream::poll_read` (batch-decrypt of all ready records in one poll, a 64-KiB read
buffer instead of 4-KiB, a cursor instead of a per-record `drain`+allocation) — correct
and kept in the code (161 tests green), but it didn't move the download (317 → 322 → 309
→ 319 Mbps — within the noise), since the bottleneck is **not** in buffering/syscalls.

**The real directions (follow-up, design changes):**
1. **Remove the redundant inner AEAD in reality-tls** — the outer TLS already encrypts
   and authenticates, the inner ChaCha20 on the data plane duplicates this. Inside
   reality-tls the data can be pushed in `plain`/Raw framing (without the second AEAD),
   keeping the qeli handshake/auth — this roughly halves the client's work on download. A
   decision with a security trade-off (defence-in-depth), it requires explicit agreement.
2. **Parallelize the two crypto layers** across tasks/cores (the TLS-decrypt in one, the
   inner in another).

For most scenarios ~320 Mbps download for reality-tls is enough; this is the price for
"real TLS on the wire"-level DPI resistance (it closes tells 1.1–1.6, see
[DPI-AUDIT.md](DPI-AUDIT.md)).

## Multi-queue TUN (`tun.queues`) — A/B

**How it works.** `tun.queues` (per-profile, default `0` = auto = `nproc`) sets how many
`IFF_MULTI_QUEUE` queues are opened on a single TUN device. The data plane pumps them
with N independent reader/forwarder/writer tasks (tokio), and **the kernel RSS-spreads the
outgoing TUN packets across the queues by flow**. This parallelizes the TUN pump itself
(previously — a single reader+forwarder+writer funnel ~1.5 cores) in addition to the
already-multi-core per-connection AEAD. `1` = the old single-threaded pump (for
rollback). UDP is parallelized via N workers on `SO_REUSEPORT` sockets. Nothing changes
on the wire, clients need no rebuild (TUN is a local OS-kernel interface).

**The measurement.** A controlled A/B on a 2-core lab: 2 tunnels in separate netns, a
simultaneous upload, the server worker's CPU — the delta by `/proc/<pid>/stat` (it can
exceed 100%), the host — the delta by `/proc/stat`. The orchestrator —
[scripts/multitunnel_probe.py](../../scripts/multitunnel_probe.py) (`QELI_TUN_QUEUES=1|2`).

| | `queues=1` (legacy) | `queues=2` (multi-queue) | Δ |
|---|---:|---:|---:|
| **1 tunnel**, aggregate | 458 Mbps | 455 Mbps | ≈0% |
| **2 tunnels**, aggregate | 607 Mbps | **718 Mbps** | **+18%** |
| qeli CPU @2 tun. (% of one core) | 159% | 167% | takes more of a core |
| threads in the worker | 9 | 11 | +2 queue readers |
| server-host @2 tun. (% of all cores) | 93% | 95% | saturated |

**Reading:**
- **A single stream isn't sped up by the queues** (458 ≈ 455 Mbps): a single TCP is bound
  by its per-connection decrypt task (~1 core), not the TUN pump — N queues have nothing
  to spread. So the per-segment benchmark above (one tunnel per mode) does **not** show a
  multi-queue gain — that's by design, not a regression.
- **The aggregate of many tunnels is sped up**: 607 → 718 Mbps (**+18%**); qeli mean-while
  pulls more of a core (159→167%) and raises +2 reader threads on the queues.
- **+18% is a lower bound**: both 2-tunnel runs hit host saturation (93–95% of all cores),
  since the `iperf3` sink runs on the SAME 2-core server and eats the free cores. On a
  production server with a remote sink and more cores the gain grows with the number of
  cores/clients.

**Conclusion:** `tun.queues=auto` — a free default (single-flow unchanged, the aggregate
under load is faster); set `=1` only for debugging/rollback.

## Stream bonding under `tc netem` (2026-06-22)

`scripts/bench_bonding.py`: a multipath fake-tls profile on :8505, `max_streams` 1 vs 4
(`adaptive=false`), download through the tunnel under a **filtered** `tc netem` (RTT+loss
applied only to traffic toward the client, so the control SSH is untouched). iperf3 **`-P 8`** —
eight parallel flows (bonding spreads them by flow hash; a single flow uses only one connection).

| link | 1 stream | 4 streams | gain |
|---|---:|---:|---:|
| clean | ~725–846 | ~805–815 | parity |
| RTT 40 ms, 0.05% loss | ~225–420 | ~692–704 | ~1.6–3× |
| RTT 80 ms, 0.1% loss | ~50–65 | ~260–305 | **~5×** (stable over 2 runs) |

**Conclusion:** on a clean link bonding isn't needed (the TUN pump is the ceiling); on a
lossy/latent link it scales. Only traffic with **several concurrent connections** speeds up
(per-flow pinning, `flow_hash % streams`) — a single lone flow won't.

**Gotchas:** use the **release** binary (debug crypto → ~17 Mbps → a false "bonding doesn't
work"); `.11` has no `/opt/qeli-src` → copy the binary to the client; apply netem as a **filter**
on `ens18` or the loss hits the control SSH; clear netem + `systemctl restart qeli-server.service`
in finally.

## Final summary

| | TCP | UDP |
|---|---|---|
| Practical ceiling (2 vCPU) | **~530–570 ↑ / ~700–720 ↓ Mbps** (plain/fake-tls/reality, measured on 0.7.4) | **~400 Mbps** at <0.5% loss |
| Latency overhead | ~1.2–1.4 ms | ~1.2–1.4 ms |
| Memory (worker RSS) | ~7–8 MB | ~7–8 MB |
| The cost of fake-tls obfuscation | ≈0 | small |
| The cost of `obfs` | −12% ↑ / −16% ↓ | (obfs TCP only) |
| The cost of `reality` (proxy) | ≈0 | — |
| The cost of `reality-tls` | ≈0 ↑ / **−40% ↓** (nested TLS; was −54% on 0.6.0, hand-rolled TLS since 0.7.0 → ~430↓ on 0.7.4) | — |
| `plain` (raw) | ≈ fake-tls | n/a (TCP-only) |

The fastest and cheapest on CPU is `plain`/`fake-tls`; the price for DPI resistance is
paid by `obfs` (moderately) and `reality-tls` (noticeably on download).

## Reproduction

```bash
# from a local machine (paramiko); flat-INI configs, write to /etc/qeli/bench-*.conf.
# H-1 (0.7.1): benchmark.py pins the server key in every mode.
python scripts/reboot_vms.py         # a clean lab (reboot both VMs) — before pristine numbers
# host check before a benchmark: on the VM `vmstat 1 4` — the `st` column should be ~0 (else steal → A/B)
python scripts/benchmark.py          # baseline + 10 modes × {ping, iperf, CPU/RSS} ≈ 8 min
python scripts/reality_tls_repeat.py # reality-tls ×5 → median/σ (release/reality_tls_5x_*.json)
python scripts/ab_071_072.py         # host-neutral A/B (0.7.1 from tag vs 0.7.2 interleaved) — when the host is under steal/contention
python scripts/ab_074_079.py         # same for 0.7.4->0.7.9 (0.7.10 candidate); A/B template for any tag<->current pair
python scripts/ab_079_0711.py        # 0.7.9->0.7.11 (dev batch, x25519-dalek 3 bump)
python scripts/e2e_android_faketls.py # Android e2e: rebuild the APK (rebuild_apk.py) -> inject a fake-tls profile -> Connect -> ping through the tunnel
# GOTCHA: a foreign qeli.service may auto-start on .11 (a server on vpn0 10.9.0.1) — it loads the client; `systemctl stop qeli.service` before benchmarking
python scripts/config_functest.py    # default-config functionality: e2e server.conf + server-maxobf.conf + parse all
python scripts/multicore_probe.py    # the precise data-plane CPU (/proc delta: idle/up/down/bidir)
python scripts/probe_060_ab.py       # the CPU A/B vs the previous version (isolated build from git HEAD)
```
The results → `release/benchmark_results.json` and `release/*_v0.7.11_*.json`.
