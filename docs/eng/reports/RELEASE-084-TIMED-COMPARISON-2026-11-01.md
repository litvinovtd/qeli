# 0.8.4: required/timed versus required/opportunistic — 1 November 2026

**Timed: 96/96 load windows completed, VM300/301 restored.** Comparison status: `RESTARTED_SEQUENTIAL_N1_INFORMATIONAL`. Geometric mean of timed/opportunistic TCP speed ratios across 48 matched cells: **+2.55%**. Sequential n=1 comparison of one SHA, not randomized A/B/A or a statistical significance estimate.



## Infrastructure interruption and preservation

Both VMs were found stopped outside the benchmark controller commands; the local controller was absent and its checkpoint contained zero bytes. The shutdown cause is unknown. Only VM300/301 were started. Guest iperf/observation/socket-memory evidence recovered 15 load windows and 4 baselines. Four started windows with missing/corrupt evidence remain retained as incomplete, excluded without speed-based selection and listed in JSON. Only 81 missing load cells plus 8 new baseline windows ran in a separate r02.

After boot, client eth1 fq was restored exactly from before.json instead of reset fq_codel. All other 15 state groups and old-file hashes matched; boot IDs necessarily changed. After r02, all 16 groups were checked against the new initial state. Historical PID receipts were not used to signal new processes. This interruption weakens causal attribution: not all observed deltas can be assigned to batching alone.



## Controlled change

- Same final portable Linux amd64 0.8.4 in `release/dist/v0.8.4`, 15,361,504 bytes. Original dist and both VM copies verified before/after:

  `2a527ccda84f5d6bb4306e2741ec0432223ae9bfcac623f747be77593dea855f`.
- Recordizer policy stays **required**; **only** `obf.recordizer.batch.mode` changes opportunistic→timed. All sections/keys of 26 actually measured connection configs compared: after private-path normalization, client configs match exactly and each server config has one delta. Retained old config SHA values checked.
- Existing timed settings: delay_min_ms=2, delay_max_ms=8, max_packets=16, max_queue_bytes=262144. No new buffers/queues/timers. Every connection confirms active `PACKET_MUX_V1` and negotiated timed in logs.
- Same VM300/server and VM301/client: **2 vCPU / 2 GiB**, i5-8500, Debian **6.12.111+deb13-amd64**, iperf3 3.18; boot IDs changed at the documented outage. Outer IPv4, inner IPv4/IPv6. MTU 1400, TUN tx_queue_len=1000; server eth1 fq_codel, client fq/flow_limit=100. Gateway/DNS/reconnect disabled.
- Same temporary RX policy: `rmem_max=rmem_default=4194304` on both VMs; live Qeli UDP rb≥8388608 and iperf UDP receiver rb≥4194304. TCP receiver rb/tb and Qeli carrier buffers retained/checked. No wmem, CPU/RAM, qdisc/offload changes; not packaged auto-16-MiB qualification.
- Same helper/workloads: **TCP P4, UDP600 payload 1200, 10+2 s**, one valid IPv4/IPv6 up/down window per profile. Resumed missing cells only: 96 load + 12 baseline = **108 valid windows**. Same 0.5-second observer; fsync and guest checkpoints added between measurements, not inside iperf windows. No builds/installs/publication; Proxmox used only for status/start of the two stopped VMs, no VM302 execution.
- The [earlier opportunistic run](RELEASE-084-SPEED12-2026-11-01.md) remains unchanged: 96 load windows and 12 baseline windows across two stages following an observer race. Timed ran separately. Old binaries/raw protected by before/after hashes.

## Profile summary

**O = opportunistic, T = timed.** TCP/UDP are arithmetic means of four directions in Mbps, not repeated-run medians. Δ compares those means. RTX/TUN sum four windows; TUN TX drops sum both VMs. UDP loss max is the worst direction.

| Profile | TCP O | TCP T | Δ T/O | RTX O→T | TCP TUN O→T | UDP O→T | UDP loss max O→T |
|---|---:|---:|---:|---:|---:|---:|---:|
| tcp-plain-raw | 1866.7 | 1971.9 | +5.64% | 4968→4909 | 8001→7659 | 600.0→599.7 | 0.0000%→0.0000% |
| tcp-faketls | 1859.6 | 1978.3 | +6.38% | 5043→4349 | 8386→6271 | 599.9→599.7 | 0.0000%→0.0000% |
| tcp-padding | 1845.5 | 1953.1 | +5.83% | 4991→4687 | 7857→8689 | 600.0→599.8 | 0.0000%→0.0000% |
| tcp-frag | 1864.2 | 1972.1 | +5.79% | 4935→4848 | 10025→7815 | 599.9→599.9 | 0.0000%→0.0000% |
| tcp-obfs | 1341.9 | 1433.6 | +6.83% | 3321→3978 | 7765→7685 | 600.0→599.8 | 0.0000%→0.0000% |
| tcp-reality | 1850.1 | 1966.9 | +6.31% | 4758→4403 | 8431→7313 | 600.0→599.8 | 0.0000%→0.0000% |
| tcp-reality-tls | 1607.0 | 1226.4 | -23.69% | 5105→3056 | 8241→5596 | 599.9→599.8 | 0.0000%→0.0000% |
| udp-faketls | 1134.3 | 1194.6 | +5.32% | 3776→3451 | 7615→7430 | 599.9→599.9 | 0.0000%→0.0000% |
| udp-padding | 1132.3 | 1175.4 | +3.81% | 3679→4281 | 6567→6151 | 599.9→599.8 | 0.0000%→0.0000% |
| udp-quic | 1143.2 | 1179.3 | +3.16% | 4963→4182 | 7493→5792 | 600.0→599.9 | 0.0000%→0.0000% |
| tcp-obfs-awg | 1376.1 | 1462.6 | +6.28% | 3630→3553 | 6910→6747 | 600.0→599.8 | 0.0000%→0.0000% |
| udp-faketls-awg | 1140.4 | 1161.4 | +1.85% | 4904→4536 | 6204→6810 | 600.0→599.8 | 0.0000%→0.0000% |

## All directions

| Profile | IP | Direction | TCP O/T | Δ | RTX O/T | TCP TUN O/T | UDP O/T | Loss % O/T | UDP TUN O/T |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| tcp-plain-raw | IPv4 | upload | 1751.5/1915.7 | +9.38% | 909/1021 | 1536/1653 | 600.0/599.5 | 0.0000/0.0000 | 0/0 |
| tcp-plain-raw | IPv4 | download | 2001.0/2026.0 | +1.25% | 1355/1427 | 2205/1934 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-plain-raw | IPv6 | upload | 1714.2/1905.8 | +11.17% | 920/1192 | 1198/1956 | 600.0/599.4 | 0.0000/0.0000 | 0/0 |
| tcp-plain-raw | IPv6 | download | 2000.1/2040.3 | +2.01% | 1784/1269 | 3062/2116 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-faketls | IPv4 | upload | 1764.3/1940.1 | +9.96% | 656/1111 | 1638/1441 | 599.7/599.3 | 0.0000/0.0000 | 0/0 |
| tcp-faketls | IPv4 | download | 1979.5/2049.7 | +3.54% | 1539/1320 | 2404/2024 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-faketls | IPv6 | upload | 1713.0/1905.8 | +11.25% | 982/838 | 1687/1116 | 600.0/599.5 | 0.0000/0.0000 | 0/0 |
| tcp-faketls | IPv6 | download | 1981.4/2017.5 | +1.82% | 1866/1080 | 2657/1690 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-padding | IPv4 | upload | 1740.8/1919.1 | +10.24% | 941/1167 | 1323/1911 | 600.0/599.4 | 0.0000/0.0000 | 0/0 |
| tcp-padding | IPv4 | download | 1966.4/2023.3 | +2.90% | 1538/1166 | 2463/2392 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-padding | IPv6 | upload | 1699.9/1877.5 | +10.44% | 1093/847 | 1721/1693 | 600.0/599.8 | 0.0000/0.0000 | 0/0 |
| tcp-padding | IPv6 | download | 1975.0/1992.5 | +0.89% | 1419/1507 | 2350/2693 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-frag | IPv4 | upload | 1794.4/1933.7 | +7.76% | 998/1094 | 1683/1766 | 600.0/599.8 | 0.0000/0.0000 | 0/0 |
| tcp-frag | IPv4 | download | 1982.4/2026.1 | +2.20% | 1591/1627 | 2774/2417 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-frag | IPv6 | upload | 1741.0/1909.7 | +9.68% | 829/656 | 1346/1481 | 599.8/599.7 | 0.0000/0.0000 | 0/0 |
| tcp-frag | IPv6 | download | 1939.1/2018.9 | +4.12% | 1517/1471 | 4222/2151 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-obfs | IPv4 | upload | 1244.2/1396.7 | +12.26% | 883/911 | 1648/2419 | 600.0/599.5 | 0.0000/0.0000 | 0/0 |
| tcp-obfs | IPv4 | download | 1409.7/1489.3 | +5.65% | 779/1002 | 1691/1913 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-obfs | IPv6 | upload | 1293.0/1358.2 | +5.04% | 664/1056 | 2780/1737 | 600.0/599.7 | 0.0000/0.0000 | 0/0 |
| tcp-obfs | IPv6 | download | 1420.8/1490.1 | +4.88% | 995/1009 | 1646/1616 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-reality | IPv4 | upload | 1735.1/1928.7 | +11.16% | 828/867 | 1996/2288 | 600.0/599.5 | 0.0000/0.0000 | 0/0 |
| tcp-reality | IPv4 | download | 1957.3/2018.8 | +3.14% | 1316/1175 | 2610/1826 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-reality | IPv6 | upload | 1727.8/1904.9 | +10.25% | 854/967 | 1050/1206 | 600.0/599.6 | 0.0000/0.0000 | 0/0 |
| tcp-reality | IPv6 | download | 1980.4/2015.1 | +1.75% | 1760/1394 | 2775/1993 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-reality-tls | IPv4 | upload | 1609.5/1226.3 | -23.81% | 1258/744 | 1858/1128 | 600.0/599.5 | 0.0000/0.0000 | 0/0 |
| tcp-reality-tls | IPv4 | download | 1645.2/1204.8 | -26.77% | 1398/729 | 2510/1221 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-reality-tls | IPv6 | upload | 1588.3/1208.7 | -23.90% | 1093/725 | 1928/2155 | 599.8/599.7 | 0.0000/0.0000 | 0/0 |
| tcp-reality-tls | IPv6 | download | 1585.1/1265.7 | -20.15% | 1356/858 | 1945/1092 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| udp-faketls | IPv4 | upload | 1009.0/1231.7 | +22.07% | 916/976 | 1483/1684 | 599.8/599.8 | 0.0000/0.0000 | 0/0 |
| udp-faketls | IPv4 | download | 1194.7/1176.6 | -1.52% | 691/454 | 1186/1945 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| udp-faketls | IPv6 | upload | 1083.1/1169.9 | +8.01% | 795/1073 | 1661/1707 | 600.0/599.8 | 0.0000/0.0000 | 0/0 |
| udp-faketls | IPv6 | download | 1250.3/1200.3 | -4.00% | 1374/948 | 3285/2094 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| udp-padding | IPv4 | upload | 1049.0/1183.6 | +12.83% | 961/895 | 1280/1448 | 599.8/599.5 | 0.0000/0.0000 | 0/0 |
| udp-padding | IPv4 | download | 1216.2/1211.5 | -0.39% | 1067/1634 | 1831/1650 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| udp-padding | IPv6 | upload | 1109.0/1137.5 | +2.57% | 542/814 | 1893/1356 | 600.0/599.7 | 0.0000/0.0000 | 0/0 |
| udp-padding | IPv6 | download | 1154.8/1168.8 | +1.22% | 1109/938 | 1563/1697 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| udp-quic | IPv4 | upload | 1135.5/1218.1 | +7.28% | 1028/1164 | 1912/1404 | 600.0/599.8 | 0.0000/0.0000 | 0/0 |
| udp-quic | IPv4 | download | 1185.6/1140.7 | -3.79% | 1074/399 | 1908/537 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| udp-quic | IPv6 | upload | 1084.0/1179.4 | +8.81% | 1456/1181 | 2268/1479 | 600.0/599.7 | 0.0000/0.0000 | 0/0 |
| udp-quic | IPv6 | download | 1167.6/1178.7 | +0.95% | 1405/1438 | 1405/2372 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-obfs-awg | IPv4 | upload | 1286.8/1509.8 | +17.34% | 945/872 | 2310/1293 | 600.0/599.5 | 0.0000/0.0000 | 0/0 |
| tcp-obfs-awg | IPv4 | download | 1487.1/1497.7 | +0.72% | 1077/932 | 2361/1998 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| tcp-obfs-awg | IPv6 | upload | 1307.1/1342.8 | +2.73% | 884/651 | 883/2152 | 600.0/599.7 | 0.0000/0.0000 | 0/0 |
| tcp-obfs-awg | IPv6 | download | 1423.3/1499.9 | +5.38% | 724/1098 | 1356/1304 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| udp-faketls-awg | IPv4 | upload | 1072.9/1133.9 | +5.68% | 1073/1129 | 1497/1602 | 600.0/599.5 | 0.0000/0.0000 | 0/0 |
| udp-faketls-awg | IPv4 | download | 1234.2/1237.9 | +0.31% | 1133/1178 | 1487/2185 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |
| udp-faketls-awg | IPv6 | upload | 1070.0/1109.0 | +3.64% | 988/758 | 1495/1135 | 600.0/599.7 | 0.0000/0.0000 | 0/0 |
| udp-faketls-awg | IPv6 | download | 1184.4/1164.9 | -1.65% | 1710/1471 | 1725/1888 | 600.0/600.0 | 0.0000/0.0000 | 0/0 |

RTX/loss exclude warm-up; TUN/CPU/RSS cover observation including warm-up/tail. Their counters are not interchangeable. JSON retains separate client/server metrics, CPU/RSS, sampled TCP RTT/cwnd and VM-wide UDP errors. FULL_RING was not traced.

## Baseline

| IP / direction | T initial | T resumed before | T after | T overall drift | T resumed drift | O overall drift | O resumed drift |
|---|---:|---:|---:|---:|---:|---:|---:|
| IPv4/upload | 30354.1 | 30279.2 | 30070.2 | -0.94% | -0.69% | -2.00% | -0.66% |
| IPv4/download | 30208.0 | 29753.1 | 29943.2 | -0.88% | +0.64% | +2.70% | +3.04% |
| IPv6/upload | 29931.7 | 29698.7 | 29920.9 | -0.04% | +0.75% | -1.30% | +0.70% |
| IPv6/download | 29837.4 | 30459.7 | 29872.6 | +0.12% | -1.93% | -0.79% | -0.80% |

Timed has the higher four-direction mean for **11/12** profiles. Largest delta: **tcp-obfs +6.83%**; smallest: **tcp-reality-tls -23.69%**. Observations from this n=1 run, not a universal coefficient. Fewer drops/retransmits in a fixed 10-second interval may reflect less delivered traffic rather than improved reliability. UDP600 is offered-rate-limited; nearly identical 600 Mbps does not measure maximum UDP performance differences.

## Verdict and limits

- Overall TCP delta: **+2.55%**, geometric mean of 48 ratios, not a substitute for individual cells. Total RTX **54073→50233**, TCP TUN TX drops **93495→83958**.
- Timed UDP600: **0 of 48** windows exceed 1% loss, TUN TX drops **0**. UDP600 is a fixed load, not the throughput ceiling.
- Maximum timed sampled steal: **0.29%**, an environmental observation, not proof of a sole cause.
- Both runs are n=1: no CV, confidence intervals or alternating A/B/A. Old windows/failures retained, no best-repeat selection. Drift >5% or UDP loss >1% requires reviewing affected conclusions.
- This test **does not measure IRTT p50/p95/p99, VoIP/game jitter or idle delay**. Loaded TCP_INFO RTT cannot replace those tests. A timed speed gain alone does not eliminate batching waits or prescribe one mode for everyone.
- All 16 restoration groups passed per VM; original rmem/wmem max/default restored to 212992, no test processes/TUN/lock remain. Final binary SHA unchanged; old data retained. Release not published.

## Evidence

- [JSON](../../data/release_084_timed_comparison_2026-11-01.json) · [Method](../manuals/RELEASE-SHORT-TEST.md).
- Timed private raw on VM300/301: `/opt/qeli-release-short-084-required-timed12-20261101-r02`.
- Opportunistic private raw: `/opt/qeli-release-short-084-required-quick12-20261101-r01`, `/opt/qeli-release-short-084-required-quick12-20261101-r02`.
- Configs/credentials remain private.
- Interrupted timed raw: `/opt/qeli-release-short-084-required-timed12-20261101-r01`; original corrupt checkpoint/raw preserved.
