# Linux client TUN queue size tests

16 October 2026. On VM300/301, client queue size materially affects upload, with
transport-dependent benefits. In the main Reality-TLS series, queues of 500 / 1000 /
2000 packets delivered median IPv4 upload of 644.5 / 1150.5 / 1485.2 Mbit/s with
inner TCP RTT of 8.13 / 8.50 / 12.36 ms. A larger queue absorbs bursts but does not
speed up the reader or eliminate all drops. The default remains `1000`, without auto.

The tables describe the **first measured candidate**, not the final build.
After boundary testing, admission was reduced from 65535 to 32767; the final
candidate received separate short functional checks. Data-path source did not
change between these candidates. This is not a historical version comparison.

## Binaries and lab

- Measured client: `2ede49f35ad0f974568df07863aae101be52be0dbdf3a8b78396036a34a53576`.
- Final client accepting `1..32767`: `cbf81924bde599ff8400e19a6ca3d628ba3a038eb8cccbc35643ae2855a2762a`.
- Server: unchanged archived Qeli 0.8.2, `a3ab7bc6d857892a4258e22a18a03acd6aefbd0a1f9699be4048b60b2f6d96b6`.
- VM300/server and VM301/client: 2 vCPU / 2 GiB each, Linux `6.12.111+deb13-amd64`.
  IPv4/IPv6 were tested **inside** the tunnel; the carrier used isolated lab IPv4.
- Builds and unit checks ran only on VM302. No builds, package installs or test
  controllers ran on the Proxmox host. Previous binaries, configs and results remain intact.

The candidate uses source HEAD `e7a90130f0bd206e549d0757819c92dbd0e8e135`
plus the queue feature, not a byte-identical reconstruction of the archived 0.8.2
with only this change. One unchanged client binary was used throughout the main queue sweep.

## Method

Three profiles: `tcp-faketls`, `tcp-reality-tls`, `udp-quic`; Recordizer required
throughout, with genuine H2 verified for Reality. Client INI queues were 250 / 500 /
1000 / 2000. The server queue stayed at 1000, MTU at 1400; before/after queue sizes
were checked on the same ifindex. Other settings within each profile were unchanged.

Each profile/queue received three repetitions of TCP P4 IPv4/IPv6 upload/download,
`iperf3 -t 6 -O 1 -P 4`: 144 windows. Queue order was forward, reverse, then mixed;
profile order rotated. Each queue/repetition started a fresh Qeli session.
UDP used 300 Mbit/s, payload 1200, one window per family/direction at queues 500
and 1000: 24 windows. Six additional observer-free TCP windows bracketed observed
IPv4 upload at queue 1000.

A separate test profile was derived from normalized configs, explicitly setting
client `gateway=false`, `dns=off`, `ipv6=required`, `reconnect=false`.
The updated client rejects the old minimal full-tunnel config without a resolver.
These settings were identical across queues; system network tuning was not changed.

Observers used 4 Hz `ss`/TCP_INFO and bounded metadata-only `kfree_skb` tracing,
filtered by the verified `tun_net_xmit` address range, a single test TUN and
IPv4/IPv6 EtherType. No payload, TLS keys, process memory or management traffic
was captured. Raw includes both Qeli process groups' CPU/RSS, queues, qdisc and
TCP counters; process RSS does not measure kernel TUN queue memory.

## TCP P4 throughput

Three-repetition medians, Mbit/s. All repetitions are retained; the largest
throughput CV across the 48 comparable groups is 3.14%.

| Profile | Queue | IPv4 up | IPv4 down | IPv6 up | IPv6 down |
|---|---:|---:|---:|---:|---:|
| tcp-faketls | 250 | 1675.1 | 2042.2 | 1666.1 | 2012.4 |
| tcp-faketls | 500 | 1923.3 | 2050.4 | 1910.7 | 2015.6 |
| tcp-faketls | 1000 | 2108.5 | 2059.8 | 2105.4 | 2016.3 |
| tcp-faketls | 2000 | 2227.3 | 2042.0 | 2205.3 | 2012.2 |
| tcp-reality-tls | 250 | 326.7 | 1197.7 | 319.3 | 1190.3 |
| tcp-reality-tls | 500 | 644.5 | 1172.2 | 634.5 | 1190.3 |
| tcp-reality-tls | 1000 | 1150.5 | 1159.0 | 1166.7 | 1189.1 |
| tcp-reality-tls | 2000 | 1485.2 | 1155.2 | 1449.3 | 1191.1 |
| udp-quic | 250 | 1031.2 | 1148.2 | 1005.9 | 1124.6 |
| udp-quic | 500 | 1066.7 | 1121.1 | 1030.2 | 1099.8 |
| udp-quic | 1000 | 1107.1 | 1142.6 | 1069.8 | 1112.7 |
| udp-quic | 2000 | 1142.2 | 1141.1 | 1078.5 | 1114.7 |

## Loss and delay during IPv4 upload

FULL_RING is summed across three complete traces including warmup; retransmits
are the median iperf count after `-O 1`. Different intervals mean these counts
must not be equated. Drops ppm is the median TUN TX drop fraction among sent
and dropped packets. cwnd is the median per-flow sample, then median repetition.
RTT is smoothed TCP RTT from `ss`; p95 describes those samples, not every packet's
delay distribution or a complete real-WAN latency-under-load test.

| Profile | Queue | FULL_RING sum | Drops ppm | Retrans median | cwnd MSS/flow | RTT median / p95 ms |
|---|---:|---:|---:|---:|---:|---:|
| tcp-faketls | 250 | 20316 | 6315 | 5353 | 75.0 | 1.71 / 3.03 |
| tcp-faketls | 500 | 9658 | 2666 | 2062 | 137.0 | 2.71 / 4.29 |
| tcp-faketls | 1000 | 3753 | 884 | 781 | 256.0 | 4.90 / 7.53 |
| tcp-faketls | 2000 | 2381 | 542 | 174 | 489.5 | 9.90 / 13.13 |
| tcp-reality-tls | 250 | 4251 | 6512 | 613 | 70.0 | 9.03 / 11.62 |
| tcp-reality-tls | 500 | 6742 | 6665 | 558 | 131.5 | 8.13 / 10.61 |
| tcp-reality-tls | 1000 | 4820 | 2302 | 397 | 249.0 | 8.50 / 11.90 |
| tcp-reality-tls | 2000 | 2956 | 844 | 155 | 534.5 | 12.36 / 17.54 |
| udp-quic | 250 | 9135 | 4223 | 2514 | 74.0 | 3.02 / 4.43 |
| udp-quic | 500 | 4851 | 2285 | 1086 | 133.5 | 5.14 / 7.44 |
| udp-quic | 1000 | 3298 | 1250 | 388 | 239.0 | 8.82 / 13.29 |
| udp-quic | 2000 | 2791 | 1476 | 405 | 332.5 | 13.45 / 19.62 |

Qdisc drops totalled zero. All 24 UDP300 windows had 0% packet loss; this does not
confirm 600 Mbit/s or new UDP ceilings. Full family/direction, repetition and
metric detail is in the [compact evidence](../../../release/certification/evidence/tun-queue-size-20261016.json).

Observed throughput versus the mean of the two controls was −6.72% for FakeTLS,
−2.18% for Reality and −4.97% for QUIC. These are single calibrations per profile,
not precise isolated observer-cost estimates. No correction was applied.
Small differences, especially in QUIC, are not universal speedup promises.

## Choosing a size

- `250/500`: less potential backlog, but bursts hit the limit earlier.
  Shortening the queue does not guarantee lower end-to-end RTT: loss recovery may
  outweigh the saving. Reality upload was especially constrained at 250.
- `1000`: the baseline compromise. Measured Reality upload nearly matched
  download; this is not an optimum for every device or link.
- `2000`: Reality gained another roughly 29% upload over 1000, but RTT rose from
  about 8.50 to 12.36 ms. FakeTLS gained roughly 5.6%, QUIC 3.2% IPv4 upload,
  while both incurred substantially higher RTT. A larger number is not itself a reason to choose it.
- `1..32767` is the admission range, not a recommended operating range.
  The upper bound follows [Linux's S16_MAX limit](https://kernel.googlesource.com/pub/scm/linux/kernel/git/netdev/net/+/66ab4c59b74db7ab53a1c9083feaaede393a96a0).
  Testing 65535 on the first candidate exposed Linux rejection and correct rollback;
  the final build rejects 32768+ before connecting rather than silently clamping it.

See [CONFIG](../manuals/CONFIG.md#client-tun-tx-queue) for syntax, ownership,
client restart and `dev_attach` rules. This is kernel → Qeli, including outgoing
ACKs during downloads, not an H2 window, socket buffer or `tun.queues` count.
This series did not identify why the reader pauses and did not change H2 flow control.

## Final build checks and restoration

The final SHA passed 17 connections: four sizes and omission in all three profiles,
plus actual queues 1 and 32767 for Reality with IPv4/IPv6. There were 48 TCP P4 and
12 UDP windows (`-t 3 -O 1`, UDP300 at queue 1000).
This is functional verification, **not three new performance repetitions of the final SHA**.
The observed default was 1000. Eight invalid inputs, including 32768, 65535, zero,
auto and a fraction, were rejected before connecting.

Final VM302 build/unit checks: fmt PASS; 2469 library PASS, 61 ignored;
54 config-editor PASS; locked jemalloc release PASS. Python contract/example guards
and bilingual documentation checks run separately. Full cross-platform CI is not
claimed: bundled GUI native cores remain unchanged, and the provenance gate reports
STALE, requiring separate rebuild/qualification before release.
MIPS/ARM Keenetic/OpenWrt, TAP performance and real WANs are not qualified by this series.

The original OneDrive atomic-save FAIL is retained. After 71 complete windows,
cleanup finished; a new manifest ran only missing logical windows.
No TCP windows were rerun or discarded; remaining QUIC UDP windows used a new session.
The old minimal DNS-config failure and the rejected 65535 attempt are also retained
separately, not treated as throughput measurements.

After both series, original boot IDs, archived binary SHAs, prior file hashes,
addresses, routes/rules, firewall, qdisc and selected sysctls matched.
There was no Qeli process or TUN before the load tests, and cleanup restored that state.
Final verification also confirmed the main series raw remained unchanged.
No reboot, netem, offload changes or package installations occurred on VM300/301.

Raw on VM300/301: `/opt/qeli-tun-queue-range-20261016` and
`/opt/qeli-tun-queue-final-20261016`. Build receipt/artifacts on VM302:
`/opt/qeli-tun-queue-dev-20261016/review-20261016`. No release, tag, push or PR
was created; previous Proxmox results were not overwritten.
