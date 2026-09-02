# Laboratory VPN protocol benchmark — Qeli 0.8.0

Run period: **2026-09-01T17:05:33Z — 2026-09-02T05:20:05Z (UTC)**. Data status: **complete**.

This document records the completed laboratory run, methodology, configuration parameters, and results. Throughput was measured with `iperf3`. The H/B/T/A attributes describe enabled masking mechanisms and preflight/PCAP observations; they do not measure the probability of classification by an external DPI system.

## 1. Factual summary

- Full `rep1`: **34** available modes. `rep2` and `rep3`: **25** masked modes. By design, the **9** control modes have only `n=1`.
- Preliminary dual-stack gate for new profiles: **19/19**.
- Qeli: **12/12** profiles emitted the runtime marker `PACKET_MUX_V1 active ... policy=required`.
- Mean TCP `P=4` across all 12 Qeli profiles: **1220 Mbit/s**. For each mode, repeat medians were first calculated for all four directions; the resulting mode values were then averaged.
- Highest mean TCP `P=4` in the full set: **WireGuard plain — 3161 Mbit/s**.
- Highest mean TCP `P=4` among masked modes: **AmneziaWG full 3.1 — 2820 Mbit/s**.
- Of **100** masked-mode directions, the `rep1` UDP ceiling rate was confirmed with loss ≤1% in all three repeats for **54** directions; **46** directions produced fewer than 3/3 passes. For Qeli, **24/48** directions were confirmed 3/3, with **113/144** clean windows in total at the `rep1` ceiling rate.
- Baseline drift after the matrix: upload **+1.48%**, download **-1.71%**. No automatic rejection threshold was applied.

### 1.1. Aggregate summary

| Group | Modes | TCP P=4, Mbit/s | UDP rep1 ceiling, Mbit/s |
| --- | --- | --- | --- |
| Qeli: fast TCP profiles | 5 | 1767 | 1365 |
| Qeli: heavyweight TCP profiles | 3 | 1274 | 1048 |
| Qeli: native UDP profiles | 4 | 496 | 409 |
| AmneziaWG full 3.1 | 1 | 2820 | 1256 |
| Xray VLESS TLS/REALITY + Vision | 2 | 995 | 347 |
| Hysteria 2 QUIC TLS/Salamander | 2 | 947 | 375 |
| OpenVPN with wrappers | 6 | 310 | 289 |
| WireGuard with wrappers | 2 | 452 | 403 |

In this table, `TCP P=4` is the mean across the included modes, where each mode value is the mean of four directions calculated from repeat medians. `UDP rep1 ceiling` is the mean offered rate found in `rep1` across IPv4/IPv6 and upload/download; it is not mean achieved goodput. The groups do not have equal H/B/T/A depth, so the table records the performance of the selected configurations rather than ranking their stealth.

Qeli group composition: fast TCP — `tcp-plain-raw`, `tcp-faketls`, `tcp-padding`, `tcp-frag`, `tcp-reality`; heavyweight TCP — `tcp-obfs`, `tcp-reality-tls`, `tcp-obfs-awg`; native UDP — `udp-faketls`, `udp-padding`, `udp-quic`, `udp-faketls-awg`. OpenVPN with wrappers includes stunnel DTLS/TLS, XOR UDP/TCP, and Cloak TCP/UDP; WireGuard with wrappers includes wg-obfuscator STUN and experimental Cloak.

## 2. Laboratory environment and run hygiene

- VM server: `10.66.116.10`; VM client: `10.66.116.11`.
- Both VMs: Debian, kernel `6.12.105+deb13-amd64`, **2 vCPU**, **2 GiB RAM**.
- Both VMs were fully and synchronously rebooted before the numerical run. Server boot ID: `cf04df08-770d-4ce9-a32a-222e5dd7c319`; client: `ffbf54d8-6c2d-46ed-89ba-36db7b2b24e7`.
- Background VPN services and system maintenance timers were stopped before the baseline; Qeli and Android emulator/ADB autostarts were runtime-masked.
- The absence of `qemu-system`, `adb`, and `netem` was verified on both VMs; the IPv6 INPUT/FORWARD/OUTPUT policy was `ACCEPT`.
- More than 21 GiB remained free on each VM after cleanup. No source files or user configurations were removed during cleanup.
- Runtime sysctl settings were identical on both sides: `rmem_max/wmem_max=16777216`, default buffers `1048576`, `netdev_max_backlog=5000`, and UDP minimum buffers `16384`.
- The egress qdisc of the external virtio interfaces was left in the laboratory default state: server `fq_codel`, client `fq`. This state remained unchanged for every mode and matches the previous cycle, but upload and download should be compared within their respective directions rather than treating their difference solely as a VPN property.
- Measurements were performed inside one Proxmox laboratory environment between two VMs. WAN latency, jitter, and loss were not emulated; the results characterize throughput and processing cost under these conditions.

Full-reboot artifact: `release\competitor_repeat_080_reboot_2026-09-01.json`.

## 3. Measurement procedure

1. A direct baseline against the external address `10.66.116.10` was measured on the new boot IDs: five upload/download repeats, 12 seconds, TCP, one stream.
2. `rep1` is a full pass over 34 modes in forward order. `rep2` is a reduced pass over 25 masked modes in reverse order; `rep3` uses the same reduced set in a deterministically shuffled order. This reduces systematic warm-up and cache effects.
3. Each mode was started from scratch for every repeat required by policy. Control modes ran once; masked modes ran three times. Processes, TUN/WG/AWG interfaces, policy routing, and XFRM state were removed before the next mode.
4. IPv4 and IPv6 ping had to pass after startup. Qeli additionally required verification of the Recordizer runtime marker.
5. TCP: IPv4/IPv6 × upload/download. The full `rep1` measured `P=1` and `P=4`; reduced `rep2/rep3` measured only `P=4`. Each window lasted 15 seconds, with the first 3 seconds excluded using `-O 3`.
6. UDP: 1200-byte payload, a 15-second window, and a 3-second warm-up. `rep1` requires 300/450/600 Mbit/s; the offered load is then raised to the actual boundary (30 Gbit/s safety ceiling), and the loss ≤1% boundary is refined to 25 Mbit/s steps. `rep2/rep3` test exactly two points in each direction: the clean ceiling found in `rep1` and the first failed step.
7. `UDP rep1 ceiling` is the offered rate found in the full pass. The `[pass/n; median loss]` format shows how many checks of that same point remained within loss ≤1%. Controls use `n=1`; masked modes use `n=3`. If `pass<n`, the exact sustainable ceiling is below that rate, but the reduced plan did not repeat the search for a lower boundary.
8. Each iperf window was accompanied by samples of `/proc/stat`, userspace process ticks/RSS, softirq, `/proc/net/softnet_stat`, UDP/TCP SNMP, and counters for every interface.
9. After the complete matrix, the direct baseline was repeated on the same boot IDs and drift was calculated.

Tool: `iperf3 3.18`; tunnel MTU 1400; TCP/UDP directions are marked `↑ upload` and `↓ download`. All throughput values are receiver goodput in Mbit/s. UDP 600 in the table belongs to `rep1`; UDP ceiling is the offered rate with repeat confirmation.

## 4. Baseline

| Phase | Upload median | Upload CV | Download median | Download CV |
| --- | --- | --- | --- | --- |
| Before matrix | 23491 | 1.39 | 25708 | 0.64 |
| After matrix | 23839 | 1.18 | 25269 | 0.95 |

## 5. Masking levels

Four independent attributes are used for a transparent comparison:

- **H (Handshake)** — whether the initial handshake is made to resemble a common TLS/QUIC/STUN profile.
- **B (Bulk)** — whether long-flow record sizes and boundaries are changed so the underlying VPN cannot be read directly from a packet-size fingerprint.
- **T (Timing)** — whether batching/delay/burst behavior is deliberately changed rather than only encrypting content.
- **A (Active probe)** — whether an unauthorized scanner receives a legitimate target/redirect response instead of a characteristic VPN error.

`partial` means limited coverage. For example, XTLS Vision/REALITY provides strong handshake and target/probe behavior, but it is not a full equivalent of Qeli Recordizer for independently changing bulk sizes and timing.

## 6. Main results

| Product / mode | Masking | H/B/T/A | Outer transport | TCP P=1 (rep1) v4 ↑/↓ | TCP P=1 (rep1) v6 ↑/↓ | TCP P=4 median v4 ↑/↓ | TCP P=4 median v6 ↑/↓ | UDP 600 (rep1) v4 ↑/↓, goodput (loss) | UDP 600 (rep1) v6 ↑/↓, goodput (loss) | UDP rep1 ceiling v4 ↑/↓ [pass/n; median loss] | UDP rep1 ceiling v6 ↑/↓ [pass/n; median loss] | max CV TCP P=4 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WireGuard plain | no | —/—/—/— | WireGuard/UDP | 2601 / 3266 | 2543 / 3142 | 3147 / 3192 | 3155 / 3150 | 600 (0.00%) / 600 (0.01%) | 600 (0.01%) / 600 (0.00%) | 1400 [1/1; 0.46%] / 1400 [1/1; 0.61%] | 1500 [1/1; 0.91%] / 1425 [1/1; 0.91%] | — |
| WireGuard + wg-obfuscator STUN | yes | partial/partial/—/— | STUN-like/UDP | 529 / 506 | 528 / 497 | 523 / 508 | 517 / 491 | 544 (8.15%) / 541 (9.90%) | 556 (7.31%) / 536 (10.66%) | 450 [3/3; 0.60%] / 450 [2/3; 0.87%] | 450 [3/3; 0.77%] / 425 [3/3; 0.57%] | 3.60 |
| AmneziaWG mask-off | no (control) | —/—/—/— | AWG/UDP | 2643 / 3106 | 3083 / 3121 | 3176 / 3112 | 3080 / 2975 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1500 [1/1; 0.71%] / 1525 [1/1; 0.63%] | 1600 [1/1; 0.93%] / 1575 [1/1; 0.72%] | — |
| AmneziaWG full 3.1 | yes | yes/yes/partial/— | AWG3.1/UDP | 2612 / 2639 | 2802 / 2603 | 2917 / 2612 | 3037 / 2715 | 600 (0.02%) / 600 (0.01%) | 600 (0.01%) / 600 (0.00%) | 1150 [3/3; 0.67%] / 1175 [2/3; 0.93%] | 1350 [3/3; 0.72%] / 1350 [2/3; 1.00%] | 8.00 |
| OpenVPN UDP userspace | no | —/—/—/— | OpenVPN/UDP | 287 / 395 | 319 / 376 | 304 / 383 | 336 / 402 | 400 (33.32%) / 438 (19.34%) | 390 (34.89%) / 461 (23.21%) | 350 [1/1; 0.98%] / 400 [1/1; 0.14%] | 350 [1/1; 0.49%] / 400 [1/1; 0.39%] | — |
| OpenVPN UDP + DCO | no | —/—/—/— | OpenVPN/UDP | 1384 / 1567 | 1415 / 1573 | 1951 / 1902 | 1824 / 1923 | 599 (0.09%) / 600 (0.07%) | 600 (0.03%) / 600 (0.03%) | 725 [1/1; 0.58%] / 700 [1/1; 0.20%] | 700 [1/1; 0.54%] / 750 [1/1; 0.79%] | — |
| OpenVPN UDP + stunnel DTLS | yes | yes/partial/—/— | DTLS/UDP | 155 / 159 | 152 / 154 | 166 / 154 | 165 / 154 | 183 (69.35%) / 201 (65.57%) | 206 (65.35%) / 199 (63.29%) | 175 [3/3; 0.77%] / 200 [3/3; 0.93%] | 175 [3/3; 0.36%] / 200 [2/3; 0.39%] | 4.77 |
| OpenVPN TCP userspace | no | —/—/—/— | OpenVPN/TCP | 309 / 401 | 317 / 406 | 355 / 360 | 317 / 363 | 489 (18.75%) / 485 (19.34%) | 517 (14.21%) / 567 (4.53%) | 375 [1/1; 0.47%] / 450 [1/1; 0.09%] | 350 [1/1; 0.15%] / 375 [1/1; 0.07%] | — |
| OpenVPN TCP + stunnel TLS 1.3 | yes | yes/partial/—/— | TLS 1.3/TCP | 437 / 368 | 435 / 420 | 340 / 475 | 408 / 492 | 552 (8.09%) / 564 (5.94%) | 466 (22.36%) / 541 (9.75%) | 275 [2/3; 0.25%] / 300 [3/3; 0.27%] | 275 [3/3; 0.40%] / 250 [3/3; 0.28%] | 10.86 |
| IPsec strongSwan ESP | no | —/—/—/— | ESP | 914 / 984 | 981 / 1102 | 976 / 1612 | 1009 / 1676 | 600 (0.04%) / 596 (0.73%) | 600 (0.01%) / 600 (0.05%) | 725 [1/1; 0.95%] / 725 [1/1; 0.14%] | 700 [1/1; 0.57%] / 725 [1/1; 0.18%] | — |
| IPsec strongSwan NAT-T | no | —/—/—/— | ESP-in-UDP/4500 | 944 / 1041 | 973 / 1186 | 934 / 1583 | 1011 / 1573 | 599 (0.16%) / 599 (0.11%) | 600 (0.00%) / 597 (0.49%) | 700 [1/1; 0.73%] / 675 [1/1; 0.25%] | 700 [1/1; 0.77%] / 650 [1/1; 0.57%] | — |
| Xray VLESS + TLS + Vision (TUN) | yes | yes/partial/—/— | TLS 1.3/TCP | 1257 / 904 | 1071 / 1018 | 1043 / 944 | 961 / 1026 | 404 (32.74%) / 560 (6.12%) | 326 (45.61%) / 599 (0.08%) | 200 [3/3; 0.73%] / 575 [2/3; 0.04%] | 175 [3/3; 0.68%] / 600 [1/3; 1.23%] | 2.49 |
| Xray VLESS + REALITY + Vision (TUN) | yes | yes/partial/—/yes | REALITY/TCP | 1266 / 907 | 1084 / 954 | 1058 / 939 | 956 / 1033 | 371 (38.09%) / 523 (12.62%) | 332 (44.76%) / 553 (7.86%) | 200 [3/3; 0.77%] / 450 [3/3; 0.83%] | 175 [3/3; 0.58%] / 400 [2/3; 0.86%] | 3.07 |
| Hysteria 2 QUIC TLS (TUN) | partial | yes/partial/—/— | QUIC/TLS/UDP | 1619 / 811 | 1647 / 898 | 1559 / 692 | 1530 / 755 | 323 (46.11%) / 573 (4.45%) | 324 (46.11%) / 583 (2.85%) | 250 [3/3; 0.73%] / 525 [3/3; 0.63%] | 250 [3/3; 0.67%] / 525 [3/3; 0.77%] | 6.48 |
| Hysteria 2 QUIC + Salamander (TUN) | yes | yes/yes/partial/— | Salamander/UDP | 716 / 726 | 719 / 774 | 800 / 720 | 760 / 759 | 307 (48.94%) / 566 (5.64%) | 315 (46.87%) / 566 (5.70%) | 225 [3/3; 0.27%] / 475 [3/3; 0.71%] | 250 [3/3; 0.57%] / 500 [2/3; 0.98%] | 4.64 |
| OpenVPN-XOR build UDP, scramble off | no (paired control) | —/—/—/— | OpenVPN/UDP | 258 / 396 | 322 / 393 | 335 / 432 | 328 / 359 | 399 (33.52%) / 441 (23.61%) | 327 (44.81%) / — (—%) | 350 [1/1; 0.76%] / 375 [1/1; 0.03%] | 350 [1/1; 0.40%] / 350 [1/1; 0.00%] | — |
| OpenVPN UDP + XOR | yes, legacy | partial/—/—/— | scrambled OpenVPN/UDP | 260 / 313 | 263 / 302 | 247 / 311 | 264 / 319 | 312 (47.38%) / — (—%) | 288 (52.13%) / — (—%) | 300 [1/3; 1.85%] / 300 [3/3; 0.47%] | 275 [3/3; 0.18%] / 325 [3/3; 0.13%] | 8.44 |
| OpenVPN-XOR build TCP, scramble off | no (paired control) | —/—/—/— | OpenVPN/TCP | 335 / 409 | 324 / 336 | 316 / 372 | 335 / 355 | 497 (17.46%) / 475 (9.63%) | 542 (9.81%) / 512 (12.95%) | 350 [1/1; 0.22%] / 525 [1/1; 0.82%] | 450 [1/1; 0.19%] / 450 [1/1; 0.26%] | — |
| OpenVPN TCP + XOR | yes, legacy | partial/—/—/— | scrambled OpenVPN/TCP | 262 / 251 | 265 / 300 | 239 / 313 | 262 / 282 | 324 (45.42%) / 448 (25.12%) | 354 (40.40%) / 390 (31.83%) | 300 [3/3; 0.32%] / 325 [2/3; 0.09%] | 275 [3/3; 0.02%] / 325 [1/3; 1.76%] | 9.07 |
| OpenVPN TCP + Cloak | yes | yes/yes/partial/yes | Cloak direct, 4×TCP/443 | 414 / 406 | 424 / 424 | 431 / 492 | 442 / 445 | 543 (9.45%) / 510 (14.72%) | 551 (8.00%) / 543 (9.45%) | 375 [2/3; 0.27%] / 325 [2/3; 0.61%] | 375 [2/3; 0.54%] / 475 [1/3; 8.56%] | 10.58 |
| OpenVPN UDP + Cloak (experimental) | yes | yes/yes/partial/yes | Cloak direct, 4×TCP/443 | 223 / 277 | 264 / 229 | 263 / 259 | 244 / 265 | 302 (49.77%) / 333 (41.84%) | 307 (48.23%) / 381 (36.57%) | 250 [3/3; 0.75%] / 300 [1/3; 1.75%] | 275 [1/3; 1.60%] / 275 [2/3; 0.71%] | 11.14 |
| WireGuard + Cloak (experimental) | yes | yes/yes/partial/yes | Cloak direct, 4×TCP/443 | 372 / 421 | 389 / 419 | 389 / 405 | 383 / 402 | 356 (39.96%) / 490 (18.49%) | 356 (39.92%) / 491 (18.05%) | 325 [1/3; 1.22%] / 400 [2/3; 0.71%] | 300 [3/3; 0.27%] / 425 [1/3; 1.63%] | 1.46 |
| Qeli 0.8.0 tcp-plain-raw + Recordizer | yes (Recordizer required) | —/yes/yes/— | Qeli/tcp | 1819 / 1687 | 1664 / 1726 | 1705 / 1689 | 1825 / 1807 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1300 [2/3; 0.99%] / 1450 [1/3; 1.29%] | 1350 [2/3; 0.98%] / 1425 [3/3; 0.62%] | 6.46 |
| Qeli 0.8.0 tcp-faketls + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/tcp | 1839 / 1598 | 1849 / 1777 | 1752 / 1695 | 1823 / 1820 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1225 [3/3; 0.75%] / 1400 [3/3; 0.91%] | 1300 [2/3; 0.90%] / 1475 [3/3; 0.78%] | 2.99 |
| Qeli 0.8.0 tcp-padding + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/tcp | 1801 / 1668 | 1794 / 1744 | 1751 / 1683 | 1841 / 1799 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1175 [3/3; 0.46%] / 1450 [2/3; 0.86%] | 1325 [2/3; 0.92%] / 1500 [2/3; 0.93%] | 4.20 |
| Qeli 0.8.0 tcp-frag + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/tcp | 1834 / 1633 | 1861 / 1682 | 1774 / 1684 | 1834 / 1800 | 600 (0.00%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1350 [1/3; 1.20%] / 1425 [3/3; 0.70%] | 1250 [3/3; 0.43%] / 1500 [2/3; 0.78%] | 2.35 |
| Qeli 0.8.0 tcp-obfs + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/tcp | 1291 / 1372 | 1414 / 1397 | 1256 / 1293 | 1371 / 1386 | 600 (0.00%) / 600 (0.01%) | 599 (0.05%) / 600 (0.00%) | 925 [1/3; 1.07%] / 1200 [1/3; 1.27%] | 925 [2/3; 0.88%] / 1200 [2/3; 0.90%] | 3.54 |
| Qeli 0.8.0 tcp-reality + Recordizer | yes (Recordizer required) | yes/yes/yes/yes | Qeli/tcp | 1797 / 1636 | 1829 / 1799 | 1741 / 1705 | 1834 / 1786 | 599 (0.05%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 1275 [3/3; 0.65%] / 1400 [3/3; 0.66%] | 1275 [2/3; 0.85%] / 1450 [3/3; 0.61%] | 2.21 |
| Qeli 0.8.0 tcp-reality-tls + Recordizer | yes (Recordizer required) | yes/yes/yes/yes | Qeli/tcp | 1116 / 952 | 1108 / 947 | 1212 / 1066 | 1219 / 1074 | 599 (0.00%) / 600 (0.00%) | 599 (0.04%) / 600 (0.00%) | 925 [3/3; 0.76%] / 1125 [2/3; 0.84%] | 975 [2/3; 0.89%] / 1200 [1/3; 1.18%] | 3.00 |
| Qeli 0.8.0 udp-faketls + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/udp | 490 / 508 | 488 / 509 | 484 / 528 | 458 / 507 | 479 (20.20%) / 516 (13.94%) | 422 (29.71%) / 532 (11.36%) | 350 [3/3; 0.59%] / 450 [3/3; 0.29%] | 325 [3/3; 0.18%] / 450 [3/3; 0.41%] | 4.54 |
| Qeli 0.8.0 udp-padding + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/udp | 452 / 498 | 480 / 496 | 499 / 513 | 468 / 512 | 489 (18.51%) / 520 (13.02%) | 471 (21.43%) / 528 (11.97%) | 375 [2/3; 0.90%] / 450 [3/3; 0.31%] | 375 [2/3; 0.74%] / 500 [1/3; 1.70%] | 5.57 |
| Qeli 0.8.0 udp-quic + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/udp | 472 / 523 | 494 / 528 | 491 / 520 | 473 / 506 | 504 (16.16%) / 522 (12.90%) | 488 (18.70%) / 527 (12.48%) | 350 [3/3; 0.54%] / 475 [2/3; 0.84%] | 325 [3/3; 0.06%] / 475 [3/3; 0.84%] | 5.85 |
| Qeli 0.8.0 tcp-obfs-awg + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/tcp | 1300 / 1367 | 1279 / 1408 | 1312 / 1300 | 1407 / 1389 | 600 (0.01%) / 600 (0.00%) | 600 (0.00%) / 600 (0.00%) | 875 [3/3; 0.38%] / 1175 [2/3; 0.96%] | 875 [3/3; 0.43%] / 1175 [3/3; 0.71%] | 4.53 |
| Qeli 0.8.0 udp-faketls-awg + Recordizer | yes (Recordizer required) | yes/yes/yes/— | Qeli/udp | 489 / 512 | 481 / 517 | 479 / 509 | 479 / 515 | 414 (31.11%) / 560 (6.48%) | 474 (19.85%) / 532 (11.03%) | 375 [1/3; 1.68%] / 450 [3/3; 0.31%] | 350 [3/3; 0.27%] / 475 [2/3; 0.33%] | 5.63 |

`TCP P=1` and `UDP 600` come from the full `rep1`. For masked modes, TCP `P=4` is the median of three repeats; for controls it is the single measurement. The CSV contains `n/min/median/max/CV/span`. `max CV TCP P=4` is shown only when `n>1`; `—` for controls means there were no repeats, not zero variance.

## 7. CPU, RSS, and kernel drops

| Product / mode | TCP P=4 CPU VM S/C, % | UDP ref CPU VM S/C, % | TCP P=4 VPN CPU S/C, % VM | UDP ref VPN CPU S/C, % VM | RSS max S/C, MiB | softnet drops S/C |
| --- | --- | --- | --- | --- | --- | --- |
| WireGuard plain | 80.1 / 82.3 | 76.7 / 78.9 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0 / 0 |
| WireGuard + wg-obfuscator STUN | 69.9 / 71.5 | 62.3 / 61.6 | 32.2 / 32.6 | 25.6 / 25.1 | 1.1 / 1.1 | 0 / 0 |
| AmneziaWG mask-off | 78.7 / 81.7 | 78.9 / 78.4 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0 / 0 |
| AmneziaWG full 3.1 | 75.9 / 78.3 | 76.0 / 74.3 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 | 0 / 0 |
| OpenVPN UDP userspace | 55.5 / 52.2 | 52.2 / 48.8 | 45.7 / 41.7 | 36.5 / 33.0 | 9.8 / 9.6 | 0 / 0 |
| OpenVPN UDP + DCO | 57.6 / 54.9 | 38.3 / 38.6 | 0.0 / 0.0 | 0.0 / 0.0 | 9.8 / 9.6 | 0 / 0 |
| OpenVPN UDP + stunnel DTLS | 77.7 / 55.9 | 72.4 / 53.8 | 71.3 / 48.7 | 62.9 / 42.3 | 19.9 / 19.5 | 0 / 0 |
| OpenVPN TCP userspace | 55.7 / 57.8 | 57.8 / 58.8 | 45.0 / 43.4 | 37.7 / 38.0 | 9.9 / 9.7 | 0 / 0 |
| OpenVPN TCP + stunnel TLS 1.3 | 85.0 / 85.2 | 69.9 / 69.6 | 73.5 / 74.3 | 56.3 / 54.3 | 20.0 / 19.6 | 0 / 0 |
| IPsec strongSwan ESP | 64.2 / 60.8 | 39.5 / 39.3 | 0.0 / 0.0 | 0.0 / 0.0 | 10.3 / 10.4 | 0 / 0 |
| IPsec strongSwan NAT-T | 64.9 / 60.5 | 37.0 / 36.1 | 0.0 / 0.0 | 0.0 / 0.0 | 10.3 / 10.4 | 0 / 0 |
| Xray VLESS + TLS + Vision (TUN) | 22.1 / 75.8 | 57.4 / 62.3 | 15.2 / 65.7 | 42.1 / 46.5 | 51.3 / 97.9 | 0 / 0 |
| Xray VLESS + REALITY + Vision (TUN) | 21.0 / 76.1 | 59.8 / 62.9 | 15.2 / 65.8 | 44.2 / 47.4 | 55.2 / 99.1 | 0 / 0 |
| Hysteria 2 QUIC TLS (TUN) | 69.1 / 89.8 | 71.1 / 69.4 | 62.7 / 80.0 | 56.9 / 56.1 | 109.9 / 116.7 | 0 / 0 |
| Hysteria 2 QUIC + Salamander (TUN) | 68.1 / 86.4 | 71.5 / 70.0 | 58.7 / 76.6 | 57.2 / 57.3 | 43.0 / 59.6 | 0 / 0 |
| OpenVPN-XOR build UDP, scramble off | 56.3 / 50.8 | 51.6 / 46.4 | 46.6 / 41.6 | 33.7 / 30.5 | 9.8 / 9.6 | 0 / 0 |
| OpenVPN UDP + XOR | 54.5 / 53.2 | 52.9 / 51.9 | 46.1 / 43.4 | 40.2 / 35.3 | 9.8 / 9.6 | 0 / 0 |
| OpenVPN-XOR build TCP, scramble off | 55.2 / 55.8 | 60.9 / 61.3 | 44.3 / 43.7 | 39.5 / 42.1 | 9.9 / 9.7 | 0 / 0 |
| OpenVPN TCP + XOR | 53.4 / 54.9 | 58.4 / 58.8 | 43.2 / 44.7 | 41.5 / 41.3 | 10.0 / 9.6 | 0 / 0 |
| OpenVPN TCP + Cloak | 77.3 / 78.0 | 71.5 / 69.8 | 71.5 / 72.6 | 58.4 / 56.6 | 123.7 / 90.6 | 0 / 0 |
| OpenVPN UDP + Cloak (experimental) | 81.4 / 82.0 | 77.6 / 77.4 | 76.3 / 76.6 | 64.9 / 64.0 | 37.4 / 33.7 | 0 / 0 |
| WireGuard + Cloak (experimental) | 81.9 / 83.2 | 73.7 / 75.9 | 47.6 / 51.0 | 36.8 / 41.1 | 25.2 / 61.5 | 0 / 0 |
| Qeli 0.8.0 tcp-plain-raw + Recordizer | 72.7 / 81.6 | 70.8 / 72.5 | 62.8 / 70.6 | 47.5 / 49.5 | 117.5 / 93.6 | 0 / 0 |
| Qeli 0.8.0 tcp-faketls + Recordizer | 74.1 / 82.1 | 69.6 / 70.9 | 64.1 / 70.4 | 46.0 / 48.5 | 118.5 / 94.1 | 0 / 0 |
| Qeli 0.8.0 tcp-padding + Recordizer | 73.8 / 83.1 | 70.2 / 71.1 | 63.6 / 70.6 | 46.2 / 48.6 | 116.7 / 93.9 | 0 / 0 |
| Qeli 0.8.0 tcp-frag + Recordizer | 76.0 / 82.7 | 71.3 / 71.0 | 65.6 / 71.2 | 47.8 / 49.2 | 117.4 / 94.1 | 0 / 0 |
| Qeli 0.8.0 tcp-obfs + Recordizer | 71.5 / 80.1 | 67.5 / 71.8 | 61.9 / 70.5 | 48.3 / 52.3 | 120.4 / 97.7 | 0 / 0 |
| Qeli 0.8.0 tcp-reality + Recordizer | 74.7 / 82.3 | 69.5 / 70.7 | 64.4 / 70.3 | 46.2 / 49.1 | 115.3 / 95.3 | 0 / 0 |
| Qeli 0.8.0 tcp-reality-tls + Recordizer | 62.7 / 70.9 | 70.4 / 71.8 | 54.9 / 61.8 | 50.1 / 52.0 | 123.5 / 106.8 | 0 / 0 |
| Qeli 0.8.0 udp-faketls + Recordizer | 71.7 / 78.5 | 65.7 / 67.5 | 64.8 / 70.3 | 49.7 / 52.2 | 160.9 / 53.0 | 0 / 0 |
| Qeli 0.8.0 udp-padding + Recordizer | 72.1 / 79.4 | 68.0 / 70.2 | 65.3 / 71.1 | 51.4 / 54.6 | 170.9 / 51.8 | 0 / 0 |
| Qeli 0.8.0 udp-quic + Recordizer | 71.8 / 79.6 | 66.6 / 68.4 | 64.7 / 70.9 | 50.1 / 52.6 | 168.7 / 51.5 | 0 / 0 |
| Qeli 0.8.0 tcp-obfs-awg + Recordizer | 70.5 / 80.5 | 66.2 / 70.6 | 62.4 / 71.4 | 47.2 / 50.6 | 122.2 / 97.7 | 0 / 0 |
| Qeli 0.8.0 udp-faketls-awg + Recordizer | 72.2 / 80.8 | 67.5 / 69.0 | 63.9 / 71.7 | 50.8 / 53.5 | 165.2 / 51.8 | 0 / 0 |

CPU VM is the total load of the two-core VM. The table aggregates repeatable TCP `P=4` windows and UDP windows at the `rep1 ceiling`. VPN userspace CPU does not include the WireGuard/AWG kernel datapath; CPU VM is the primary metric for those modes. RSS combines the underlying VPN and its wrapper. `softnet drops` are summed across all TCP windows and UDP ceiling windows; zero does not rule out loss inside the tunnel protocol as reported by iperf.

## 8. Masking cost in matched pairs

| Matched comparison | Control TCP P=1 rep1 avg | Masked TCP P=1 rep1 avg | Change |
| --- | --- | --- | --- |
| WireGuard: plain → wg-obfuscator STUN | 2888 | 515 | -82.2% |
| AmneziaWG: mask-off → full 3.1 | 2988 | 2664 | -10.8% |
| OpenVPN XOR UDP: patched control → XOR | 342 | 284 | -17.0% |
| OpenVPN XOR TCP: patched control → XOR | 351 | 269 | -23.3% |
| OpenVPN TCP: userspace → stunnel TLS | 358 | 415 | +15.9% |
| Xray: VLESS TLS Vision → REALITY Vision | 1062 | 1053 | -0.9% |
| Hysteria 2: QUIC TLS → Salamander | 1244 | 734 | -41.0% |

The matched comparison uses only equivalent `rep1` TCP `P=1` windows across IPv4/IPv6 and upload/download. This preserves equal `n=1` for control and masked profiles; the CV of repeated TCP `P=4` is reported separately to show masked-mode stability.

## 9. Mode configurations

### 9.1. Common cryptography

- OpenVPN userspace/XOR/Cloak: TLS 1.3, X25519, data cipher `CHACHA20-POLY1305`, `tun-mtu 1400`, `mssfix 1360`. XOR operates on top of normal AEAD protection; `cipher none` was not used.
- OpenVPN DCO: the same negotiated cipher/TLS suite, with the kernel DCO datapath.
- strongSwan: ChaCha20-Poly1305; the DTLS mode was excluded after a verified IPv4 preflight defect instead of being replaced with a fabricated number.
- Xray: VLESS Vision through TUN; the TLS variant uses TLS 1.3/browser fingerprinting, while the REALITY variant uses `www.cloudflare.com:443`; both use TUN MTU 1400.
- Hysteria 2: QUIC/TLS and QUIC+Salamander; the bandwidth limit was raised to **10 Gbit/s**, above the actual tunnel capacity of the environment.

### 9.2. OpenVPN-XOR and Cloak

- XOR: OpenVPN 2.7.6 with the five patches from Tunnelblick commit `c9c73dca6c99afbba14b53e291b18f044210a1b5`; `scramble obfuscate`; DCO disabled. Every XOR row has a matched control using the same patched binary without `scramble`.
- Cloak 2.12.0: `Transport=direct`, `BrowserSig=chrome`, `NumConn=4`, `EncryptionMethod=chacha20-poly1305`, `ServerName=RedirAddr=www.cloudflare.com`, `KeepAlive=0`, outer TCP/443.
- OpenVPN UDP+Cloak and WireGuard+Cloak are marked experimental. The PCAP preflight verified that there was no direct UDP bypass: only four Cloak TCP connections to port 443 existed between `.11` and `.10`.
- An unauthorized HTTPS probe of every Cloak arrangement received HTTP 200 from `RedirAddr`, not from the upstream VPN.

### 9.3. Qeli 0.8.0 and mandatory Recordizer

All 12 Qeli profiles use `obf.recordizer.policy=required`. If Recordizer negotiation does not succeed, the connection must not proceed to measurement. Preflight confirmed activation in all 12 cases.

- `obf.recordizer.policy = required`
- `obf.recordizer.batch.delay_min_ms = 2`
- `obf.recordizer.batch.delay_max_ms = 8`
- `obf.recordizer.batch.max_packets = 16`
- `obf.recordizer.batch.max_queue_bytes = 262144`
- `obf.recordizer.record.max_payload_bytes = 0`
- `obf.recordizer.record.small_min_ratio = 0.25`
- `obf.recordizer.record.small_max_ratio = 0.875`
- `obf.recordizer.record.full_probability = 0.72`
- `obf.recordizer.fragment.enabled = true`
- `obf.recordizer.fragment.reassembly_timeout_ms = 3000`
- `obf.recordizer.fragment.max_inflight_packets = 64`
- `obf.recordizer.fragment.max_reassembly_bytes = 4194304`
- `obf.recordizer.fragment.max_fragments_per_packet = 64`

Additional profile parameters: separate padding of 32–256 bytes with probability 0.8 when enabled; 15 s heartbeat; AWG `jc=4`, `jmin=40`, `jmax=200`; dual-stack pools `10.9.0.0/24 + fd42:206:1::/64` for TCP and `10.10.0.0/24 + fd42:206:2::/64` for UDP; TUN MTU 1400. Test credentials, identity keys, XOR/Cloak secrets, and the Qeli obfs key are not exported into the report.

### 9.4. WireGuard, AmneziaWG, strongSwan, Xray, and Hysteria 2

- WireGuard plain: MTU 1400, `PersistentKeepalive=25`. In the wg-obfuscator profile, inner WireGuard uses MTU 1380 and a local endpoint; the outer obfuscator uses UDP/443, client `masking=STUN`, server `masking=AUTO`, `allow-clean=false`, `max-dummy=4`, and `idle-timeout=300`.
- AmneziaWG mask-off: MTU 1380, `Jc/Jmin/Jmax=0`, `S1..S4=0`, fixed `H1..H4=1..4`, `RandomTrailers=off`, `AdvancedSecurity=off`. Full 3.1: MTU 1360, `Jc=8`, `Jmin=40`, `Jmax=70`, `S1/S2/S3/S4=86/73/64/32`, configured nonstandard `H1..H4`, `HeaderProtectionKey`, `ContentPaddingAddition=16-64`, `RandomTrailers=on`, and `AdvancedSecurity=on`.
- strongSwan: IKEv2, PSK, tunnel mode, `mobike=no`, with no reauthentication or rekeying during the test. IKE used `chacha20poly1305-prfsha256-curve25519` and ESP used `chacha20poly1305-curve25519`; ESP and NAT-T differ by `encap=no/yes`.
- Xray: VLESS with `xtls-rprx-vision`, `raw` transport, TUN MTU 1400, and dual-stack routes. The TLS profile uses TLS 1.3 and the Chrome fingerprint; REALITY uses the Chrome fingerprint, target/SNI `www.cloudflare.com:443`, a short ID, and an X25519 keypair. Laboratory ports: 24443 for TLS and 24444 for REALITY.
- Hysteria 2: TUN MTU 1400, QUIC, 8 MiB stream and 20 MiB connection windows, `maxIncomingStreams=1024`, PMTUD enabled, and a 10 s client keepalive. The profiles differ by the presence of Salamander; ports are 24445/24446. During preflight, the `up/down` limits were increased from 1 to 10 Gbit/s so a configuration limit would not restrict the measurement. The TLS client used a laboratory certificate with `insecure=true`; this is a test-environment setting, not a production recommendation.
- All WG/AWG, Xray, Hysteria, and Qeli configurations routed the same control IPv4/IPv6 destinations. Secret keys and passwords are not included in the report.

## 10. PCAP/preflight and limits of DPI conclusions

- All 19 new or changed profiles passed IPv4/IPv6 TCP/UDP smoke tests: OpenVPN-XOR (4), Cloak (3), Qeli Recordizer (12).
- The Cloak PCAP contained only TCP/443; there was no direct UDP/11965 or UDP/51850 traffic between the VMs.
- The first OpenVPN payload bytes in the patched control contained a recognizable original structure, while `scramble obfuscate` changed them; authentication and `CHACHA20-POLY1305` remained enabled.
- H/B/T/A is a technical assessment of enabled mechanisms, not a probability of detection. A publishable claim that a mode “is not detected by DPI” would require independent classifiers, multiple networks, long-lived flows, and an active-probe corpus. This report can correctly state only which surfaces are masked and at what throughput/CPU cost.

### 10.1. Interpretation limits

- Control modes have `n=1`; their run-to-run variance was not measured. Masked modes have `n=3` only for TCP `P=4` and UDP verification points; TCP `P=1` and UDP 600 belong to `rep1`.
- For UDP, the reduced repeats checked the discovered rate and the first failed step, but did not search again for a lower sustainable ceiling. Therefore `pass<n` must not be read as a ceiling confirmed three times.
- The environment does not model WAN latency, jitter, packet reordering, external bottlenecks, or long-running competing load.
- An external DPI classifier, an active-probe corpus, and captures from multiple networks were outside this run. H/B/T/A describes the configuration and observed preflight/PCAP behavior, not a detection probability.
- Group means combine different transports, datapaths, and H/B/T/A levels. They provide a compact summary of measured configurations and do not replace row-by-row comparison.

Preflight artifact: `release\competitor_repeat_080_preflight.json`.

## 11. Errors and exclusions

- `strongswan/natt-stunnel-dtls`: The fixed strongSwan 6.0.7 + stunnel 5.80 DTLS preflight establishes IKE/CHILD SA and IPv6, but IPv4 traffic does not pass through the wrapper. It remains excluded rather than publishing an invalid number.

`strongswan/natt-stunnel-dtls` has no throughput result: the combination established IKE/CHILD SA and IPv6 but did not pass IPv4 through stunnel 5.80 DTLS. The mode was excluded from the numerical comparison because it did not pass the complete dual-stack gate.

## 12. Run continuity and checkpoints

- During the full `rep1`, the controller machine ran out of local disk space. The process stopped in `qeli/udp-quic+recordizer` during a TCP `P=4` IPv6 upload window that had not yet been saved. Atomic JSON retained every previous checkpoint; after disk cleanup, the unsaved window was measured again and the mode and pass were completed.
- During the reduced repeats, the foreground launcher reached an external one-hour command limit. The Python process continued for a while and then stopped. The runner was relaunched in the background from the atomic checkpoint: completed modes were skipped and the incomplete window was measured again.
- The VMs were not rebooted during resumptions: server/client boot IDs remained `cf04df08-770d-4ce9-a32a-222e5dd7c319` / `ffbf54d8-6c2d-46ed-89ba-36db7b2b24e7` from the initial baseline through completion. The background completion stderr was empty.

## 13. Conclusions from measured data

1. Before the matrix, baseline CV was **1.39%** for upload and **0.64%** for download; after the matrix it was **1.18%** and **0.95%**. Median drift was upload **+1.48%**, download **-1.71%**.
2. `rep1` covered 34 modes; `rep2/rep3` were completed for 25 masked modes. All 12 Qeli profiles were measured with `obf.recordizer.policy=required`, and the activation runtime marker was recorded for all 12.
3. Qeli group means: fast TCP profiles — **1767 Mbit/s TCP P=4** and **1365 Mbit/s UDP rep1 ceiling**; heavyweight TCP profiles — **1274 / 1048 Mbit/s**; native UDP profiles — **496 / 409 Mbit/s**.
4. The highest mean TCP `P=4` among masked rows in this environment was **AmneziaWG full 3.1: 2820 Mbit/s**. This row, Qeli, and userspace wrappers use different datapaths and different H/B/T/A mechanisms; the numerical maximum applies only to the tested configuration and environment.
5. The `rep1` UDP ceiling rate was confirmed 3/3 for **54/100** masked-mode directions. For Qeli, 3/3 confirmation was obtained for **24/48** directions; in the remaining directions, the reduced plan did not determine a new lower ceiling confirmed three times.
6. VLESS is represented by TLS+Vision and REALITY+Vision; Hysteria 2 by QUIC TLS and QUIC+Salamander; OpenVPN by controls, DCO, stunnel, XOR, and Cloak; WireGuard by plain, wg-obfuscator, and Cloak; AmneziaWG by mask-off and full 3.1; strongSwan by ESP and NAT-T. `strongswan/natt-stunnel-dtls` was excluded because of the documented dual-stack preflight defect.
7. This run did not measure the probability of detection by an external DPI system. Its data can be used to compare throughput, CPU/RSS, kernel counters, TCP repeatability, UDP point confirmation, and the presence of configured H/B/T/A mechanisms.

## 14. Artifacts and reproducibility

- Raw results: `release\competitor_repeat_080_results_2026-09-01.json`, SHA256 `09cbfdf33ec9bdbfae2f769e0b91d0f7d8144b295a687ea93c362c6df434c435`.
- CSV summary: `release\competitor_repeat_080_summary_2026-09-01.csv`.
- Short Markdown summary: `release\competitor_repeat_080_summary_2026-09-01.md`.
- Benchmark runner (lab-local, not published in the repository): `repeat_080_benchmark.py`.
- Runtime extension (lab-local, not published in the repository): `repeat_080_runtime_ext.py`.
- Qeli profile generator (lab-local, not published in the repository): `repeat_080_qeli.py`.
- Reboot evidence: `release\competitor_repeat_080_reboot_2026-09-01.json`.
- Preflight/PCAP evidence: `release\competitor_repeat_080_preflight.json`.
- Preparation and hashes: `release\competitor_repeat_080_prepare.json` and `release\competitor_artifacts_lock.json`.

| Component | Version | ref | SHA256 |
| --- | --- | --- | --- |
| wg-obfuscator | 1.6 | v1.6 | af30264278c70c2e53ad3234e8050686b3bef4f6564edc9fb068ea8c885b8354 |
| amneziawg-kernel | 3.1.20260812 | v3.1.20260812@46803204e7ec3b068199cd671143bec661d3fe21 | a85817876676d5933385712657bd5525a0a2939baaf057f68e3629c7b4553c82 |
| amneziawg-tools | 3.1.20260812 | v3.1.20260812@ee0f0a9aa34ff0a0da4b3433b9512781cfe02843 | dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493 |
| openvpn | 2.7.6 | official-community-release | 10e24a9385f23cc38cc5cf448f3ca0769f939bc4cbecc4f4647d7e006e52db74 |
| stunnel | 5.80 | official-release | 6d0841d48de07cbbaf4a055919065bf7bb5ebc63cc15c97a2c76caa2bf285513 |
| strongswan | 6.0.7 | official-release | e518e34e159514f4c6ba80d1f926cb151e0dd4e3a1d94213171234b8b9ae6f55 |
| xray | 26.3.27 | v26.3.27 | 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae |
| hysteria | 2.12.2 | app/v2.12.2 | 6493dfffd55b5883f64c76c63880ecc32988f0c568c9ca9014907877b4d55f94 |
| Qeli | 0.8.0 | local release/dist/v0.8.0 | e376bc27eaae30591882648bf7556c70587b2f24a393478df0b3d5d3615b2c49 |
| Cloak client | 2.12.0 | official v2.12.0 | ceabde7e13cf0e9dd7f53f811d6f24c1246755911b06aa40fb541041016348e3 |
| Cloak server | 2.12.0 | official v2.12.0 | f2bea92c99195ac26cd5749e80d07339d5582c103f73934b414150c6070dae4e |
| OpenVPN-XOR binary | 2.7.6 | c9c73dca6c99afbba14b53e291b18f044210a1b5 | ec627f24d7f741d4a7553e91a415dbe834374f1c7aabd329fef69c76a889eddd |

Official sources for configurations and limitations: OpenVPN <https://openvpn.net/community-resources/>, Tunnelblick XOR warning <https://www.tunnelblick.net/cOpenvpn_xorpatch.html>, Cloak <https://github.com/cbeuw/Cloak>, Xray <https://github.com/XTLS/Xray-core>, Hysteria <https://v2.hysteria.network/>, strongSwan <https://docs.strongswan.org/>.
