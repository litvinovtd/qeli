# Qeli 0.8.2 TCP and UDP on the Linux lab

The tested Linux artifact accepts client `tun.tx_queue_len`; omitting the key
produces an actual queue of 1000 packets. UDP600 met loss ≤1% in all three repeats
of both tested profiles. Neither 900 nor 950 Mbit/s passed every repeat. Only
`udp-faketls` and `udp-quic` were tested here, not all 12 profiles or all release
platforms.

## Artifacts and lab

Current artifact N SHA256:
`1d94d4c412f6c1fd231765b760196b0b4f518c20135bf0ccd1b52b192710cf76`.
The certification manifest identifies source commit
`8b18038849873125219b2a2f6ed8f8d339800ee5`.
Archived artifact O SHA256:
`a3ab7bc6d857892a4258e22a18a03acd6aefbd0a1f9699be4048b60b2f6d96b6`.
Both report version 0.8.2; SHA identifies the actual build. Each session uses the
same artifact at both endpoints. Previous binaries and raw data are retained.

VM300/server and VM301/client each have 2 vCPU and 2 GiB RAM on the Intel i5-8500
lab host, kernel `6.12.111+deb13-amd64`. Isolated IPv4 underlay MTU 1500; client
MTU auto, effective TUN MTU 1400; server TUN queue 1000. Proxmox was used only as
the hypervisor, not for builds or diagnostic processes. VM302 was not used.

Recordizer **required**, with actual `PACKET_MUX_V1 active` verified. Batch 2–8 ms,
max_packets 16, max_queue_bytes 262144, record.max_payload_bytes 0, fragmentation
enabled, heartbeat enabled, padding disabled. Client `gateway=false`, `dns=off`,
`ipv6=required`, `reconnect=false`. The profile names describe native UDP carriers;
the inner workload can be either TCP or UDP.

## Current artifact TCP with client queue 1000

An additional 24 windows of N: four streams, inner IPv4/IPv6 in both directions,
15 seconds, `-O 3`, medians of three repeats, Mbit/s. Both queues are 1000,
effective MTU 1400, Recordizer required. All these TCP windows are **untraced**.
This is a separate session after the main UDP series, not a simultaneous TCP+UDP test.
The TCP windows ran on 17 October, 23:48:15–23:59:39 Moscow time.

| Profile | IPv4 upload | IPv4 download | IPv6 upload | IPv6 download |
|---|---:|---:|---:|---:|
| udp-faketls | 1077.1 | 1168.4 | 1074.6 | 1163.2 |
| udp-quic | 1087.0 | 1174.5 | 1074.2 | 1168.7 |

This TCP raw remains separate on VM300/301 under
`/opt/qeli-release-short-gigabit-readerdiag1d94-20261017`.
Upload still has TUN TX drops; client TX drops in download are zero. Passing UDP600
does not imply the absence of every TUN drop under a different workload.

## Matched TCP P4 with client queue 500

Median of three repeats, Mbit/s, O / N in each cell. The INI is identical within
each profile, with both client queues normalized to 500 before traffic. Windows
are 15 seconds with `-O 3`, four streams, inner IPv4/IPv6 upload/download.

| Profile | IPv4 upload O / N | IPv4 download O / N | IPv6 upload O / N | IPv6 download O / N |
|---|---:|---:|---:|---:|
| udp-faketls | 1123.3 / 1051.4 | 1160.0 / 1155.9 | 1079.1 / 1027.5 | 1155.6 / 1161.2 |
| udp-quic | 1106.7 / 1048.2 | 1153.2 / 1134.4 | 1090.9 / 1025.0 | 1125.3 / 1132.3 |

These are **not default1000 TCP measurements**. N upload is about 4.8–6.4% lower
than O in these conditions; download differs by −1.6…+0.6%. Sequential O then N,
n=3, is not a randomized crossover and does not isolate every source of variance.

## Current artifact UDP with client queue 1000

One inner IPv6 upload stream, payload 1200 bytes, 15 seconds, `-O 3`, n=3.
The queue key is omitted; the actual Linux queue is 1000. Goodput is received
useful throughput, not the offered load.

| Profile | Offered Mbit/s | Median goodput Mbit/s | Median loss | Maximum loss | Repeats with loss ≤1% |
|---|---:|---:|---:|---:|---:|
| udp-faketls | 300 | 299.8 | 0% | 0% | 3/3 |
| udp-faketls | 450 | 449.9 | 0% | 0% | 3/3 |
| udp-faketls | 600 | 599.6 | 0% | 0.0158% | 3/3 |
| udp-faketls | 900 | 885.8 | 1.5400% | 3.1293% | 1/3 |
| udp-quic | 300 | 299.8 | 0% | 0% | 3/3 |
| udp-quic | 450 | 449.8 | 0% | 0% | 3/3 |
| udp-quic | 600 | 599.7 | 0% | 0% | 3/3 |
| udp-quic | 950 | 948.9 | 0.0582% | 4.6690% | 2/3 |

For QUIC UDP950, changing N500 to N1000 raised median goodput from 854.7 to 948.9
Mbit/s and reduced median loss from 10.0308% to 0.0582%, but did not eliminate the
bad repeat. These are fixed offered rates, **not a new exhaustive ceiling search**.
UDP IPv4 and download are not covered; results from another artifact or the
archived 12-profile series cannot fill those cells.

## Method and preservation

Main run: 17 October 2026, 20:22:45–21:10:18 Moscow time, 120 VPN windows plus
20 direct baseline windows. Before/after direct TCP medians were
30602.8/30232.8 Mbit/s upload (−1.21%) and 30367.5/30265.4 download (−0.34%).
All eight direct UDP600 windows had zero loss. Both guests were restored and
previous files and network settings verified unchanged.

Private raw iperf, commands, timestamps, CPU/RSS and counters remain on VM300/301
under `/opt/qeli-release-short-gigabit-target1d94-20261017`. Authentication-bearing
configs are not published. The main measurements had no periodic observer or
tracing. Aggregate CPU does not exclude brief stalls in a single thread; the
remaining high-load TUN drops require separate diagnosis. A deeper queue does not
guarantee loss-free operation or higher throughput on another device or WAN.

[Queue configuration](../manuals/CONFIG.md#client-tun-tx-queue) ·
[Queue range measurements](TUN-QUEUE-SIZE-2026-10-16.md) ·
[Short release-test method](../manuals/RELEASE-SHORT-TEST.md).

[Sanitized individual values for all 24 TCP and 24 UDP table windows](../../../release/lab-results/linux-1d94-20261017.json)
include SHA and timestamps, not authentication-bearing configs. Instrumented
diagnostic windows are excluded from this population.

[Separate remaining-TUN-drop diagnostics with queue 1000](TUN-READER-0.8.2-2026-10-18.md)
distinguish observed counters from reader-wait hypotheses.
