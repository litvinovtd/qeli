# Recordizer required versus off across 12 Qeli 0.8.2 profiles

Measurement date: **20 October 2026**. Status: **engineering comparison of the same
build, one measurement per cell**, not a public release benchmark or repeatability
qualification.

All 384 performance windows and 48 baseline windows were retained. Required produced
higher mean TCP P4 throughput across the four directions in all 12 profiles. However,
UDP600 exceeded 1% loss in 12 required windows and 31 off windows. High TCP goodput
therefore does not establish that every profile sustains UDP600 without loss.

This report supplements the [Recordizer design reference](../../reference/RECORDIZER.md)
and [configuration manual](../../manuals/OBFUSCATION.md). It does not reinstate the
publication status of previously withdrawn laboratory reports.

## Build and lab identification

| Parameter | Value |
| --- | --- |
| Both endpoints | `qeli 0.8.2`, Linux amd64 |
| Both binary SHA256 values | `e4cb6e055854806bcef7c61f394ea696cbf9cde3de90fef7b5f0f02e60326ddb` |
| Source artifact | `release/dist/v0.8.2/qeli-linux-amd64` at launch time |
| Guests | VM300 server; VM301 client |
| Resources per guest | 2 vCPU, 2048 MiB assigned RAM |
| Kernel | `6.12.111+deb13-amd64` |
| TUN | MTU 1400, `tx_queue_len=1000` at both endpoints; server `tun.queues=2` |
| Outer network | IPv4 on an isolated test path; inner data IPv4 and IPv6 |
| Client | `gateway=false`, `dns=off`, `ipv6=required`, `reconnect=false` |
| Outer interface qdisc | VM301 eth1: `fq`, `flow_limit=100`; VM300 eth1: `fq_codel` |

Both guests were rebooted before measurement at the operator's request. The Android
emulator was not running; its laboratory launcher retains a default-off guard.
Pre-reboot runtime values were restored: `rmem_default/wmem_default=1048576`,
`rmem_max/wmem_max=16777216`, UDP minima 16384, `netdev_max_backlog=5000`, qdisc and
quiet-timer states. This restored conditions rather than tuning for a better result.
Boot IDs, RAM, vCPU, queues and network settings did not change between required and
off. This run performed no builds, installations or test workloads on Proxmox or VM302.

## Changed factor and order

All 12 required profiles, baseline after and cleanup completed first. The same 12 off
profiles, baseline after and cleanup followed. There were no simultaneous workload
controllers. Every cell has `n=1`, not the three repeats of the standard short release
test. This is a separate extended matrix, not full release qualification.

Archived configurations were checked for all 12 profiles. After normalizing raw-root
paths, the only server difference was `obf.recordizer.policy: required → off`. Client
files were identical; effective policy arrived in authenticated server push.
Required was verified by `PACKET_MUX_V1 active`; off by positive
`legacy packet-per-record` and no active mux in every session log.

Reality-TLS retained genuine H2 in both phases: server mode `reality-tls`,
`handrolled=true`, padding/stealth/heartbeat disabled, traffic shaping enabled.
Off does not disable TLS/H2. The `udp-quic` label means QUIC-shaped UDP masking,
not genuine QUIC/HTTP3.

## Method and metrics

Each profile and policy has 16 windows:

- unlimited TCP P1 and P4;
- UDP offered at 300 and 600 Mbps, one stream, payload 1200 bytes;
- every variant over IPv4/IPv6, upload/download, `iperf3 -t10 -O2`.

Before and after each policy, baseline consisted of three TCP P1 windows per family
and direction: 12 before and 12 after. CPU covered the entire Qeli process group and
the VM. Sampled RSS, TCP_INFO, TUN/qdisc, UDP SNMP4/6 and softnet were retained at
0.5-second sampling. Over-budget loss was neither removed nor replaced with a retry.

Table throughput is receiver goodput. UDP offered rate and receiver loss are distinct:
UDP600 is an offered workload, not an established ceiling. Retransmits are from inner
iperf TCP, not outer-carrier loss counts. CPU 100% means one core; RSS is a sampled
maximum, not a guaranteed peak.

TUN drops are the interface's `TX dropped` increment. They and CPU cover observation
including warm-up, about 12 seconds; iperf throughput and retransmits cover the measured
10 seconds. Do not equate different intervals or units packet for packet. FULL_RING
was not traced. Per-window qdisc counters belong to TUN, not eth1; they cannot rule
out eth1 drops.

## Profile summary

TCP P4 is the mean of four directions, not a median of repeats. Off delta is relative
to required. UDP600 loss is the maximum across four directions.

| Profile | TCP P4 required | TCP P4 off | Off delta % | UDP600 max loss required % | UDP600 max loss off % |
| --- | ---: | ---: | ---: | ---: | ---: |
| tcp-plain-raw | 2016.3 | 778.7 | -61.4 | 0 | 12.32762 |
| tcp-faketls | 2023.8 | 773.9 | -61.8 | 0 | 7.76532 |
| tcp-padding | 2031.2 | 743.9 | -63.4 | 0 | 12.85705 |
| tcp-frag | 2026.8 | 730.7 | -63.9 | 0.00912 | 10.20592 |
| tcp-obfs | 1546.2 | 719.0 | -53.5 | 0.05005 | 23.86017 |
| tcp-reality | 2020.5 | 743.4 | -63.2 | 0.00048 | 17.19058 |
| tcp-reality-tls | 1214.1 | 1143.6 | -5.8 | 0.00687 | 0.03456 |
| udp-faketls | 569.6 | 358.5 | -37.1 | 67.19702 | 85.82654 |
| udp-padding | 567.8 | 343.2 | -39.6 | 64.86348 | 96.49569 |
| udp-quic | 555.5 | 348.8 | -37.2 | 61.66047 | 81.64266 |
| tcp-obfs-awg | 1537.6 | 728.1 | -52.6 | 0.00736 | 9.07731 |
| udp-faketls-awg | 577.7 | 366.1 | -36.6 | 37.96974 | 85.30597 |

## Full matrix

Every pair is required → off; throughput in Mbps. ↑ upload, ↓ download. Each TUN cell lists client/server. Loss is percent. All windows are included, including failed workloads.

### tcp-plain-raw

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 1903.6 → 721.2 | — | 61 → 32 | 341/0 → 548/0 |
| IPv4 ↑ | TCP P4 | 2027.6 → 728.1 | — | 1113 → 422 | 1779/0 → 1308/0 |
| IPv4 ↑ | UDP300 | 299.7 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 599.6 → 540.2 | 0 → 8.1318 | — | 0/0 → 59552/0 |
| IPv4 ↓ | TCP P1 | 2064.0 → 752.7 | — | 112 → 110 | 0/118 → 0/1164 |
| IPv4 ↓ | TCP P4 | 2036.4 → 781.7 | — | 1164 → 778 | 0/1919 → 0/799 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 600.0 → 599.7 | 0 → 0.05104 | — | 0/0 → 0/0 |
| IPv6 ↑ | TCP P1 | 1952.4 → 661.0 | — | 72 → 30 | 80/0 → 706/0 |
| IPv6 ↑ | TCP P4 | 1988.5 → 850.4 | — | 976 → 484 | 2003/0 → 598/0 |
| IPv6 ↑ | UDP300 | 299.9 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 599.5 → 527.3 | 0 → 12.32762 | — | 0/0 → 87426/0 |
| IPv6 ↓ | TCP P1 | 2066.3 → 759.7 | — | 76 → 150 | 0/197 → 0/811 |
| IPv6 ↓ | TCP P4 | 2012.6 → 754.4 | — | 1054 → 1944 | 0/2066 → 0/1237 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 600.0 → 599.2 | 0 → 0.12842 | — | 0/0 → 0/0 |

### tcp-faketls

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 1854.8 → 653.0 | — | 70 → 73 | 333/0 → 105/0 |
| IPv4 ↑ | TCP P4 | 2000.2 → 801.2 | — | 783 → 341 | 1108/0 → 1200/0 |
| IPv4 ↑ | UDP300 | 299.7 → 299.9 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 599.6 → 553.2 | 0 → 7.76532 | — | 0/0 → 51186/0 |
| IPv4 ↓ | TCP P1 | 2095.5 → 748.4 | — | 56 → 141 | 0/171 → 0/1260 |
| IPv4 ↓ | TCP P4 | 2070.3 → 783.6 | — | 1404 → 628 | 0/2436 → 0/624 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 600.0 → 597.8 | 0 → 0.13952 | — | 0/0 → 0/0 |
| IPv6 ↑ | TCP P1 | 1901.2 → 681.4 | — | 18 → 8 | 120/0 → 403/0 |
| IPv6 ↑ | TCP P4 | 1972.9 → 751.5 | — | 1110 → 338 | 1637/0 → 1438/0 |
| IPv6 ↑ | UDP300 | 299.9 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 599.8 → 565.7 | 0 → 5.62529 | — | 0/0 → 49086/0 |
| IPv6 ↓ | TCP P1 | 2086.5 → 750.2 | — | 51 → 0 | 0/219 → 0/1158 |
| IPv6 ↓ | TCP P4 | 2051.9 → 759.5 | — | 1616 → 298 | 0/2201 → 0/22 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 600.0 → 599.2 | 0 → 0.07639 | — | 0/0 → 0/0 |

### tcp-padding

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 1850.4 → 633.0 | — | 24 → 4 | 302/0 → 187/0 |
| IPv4 ↑ | TCP P4 | 2040.9 → 774.8 | — | 1080 → 301 | 1619/0 → 390/0 |
| IPv4 ↑ | UDP300 | 299.9 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 599.5 → 535.5 | 0 → 10.96441 | — | 0/0 → 91493/0 |
| IPv4 ↓ | TCP P1 | 2048.0 → 745.1 | — | 45 → 113 | 0/388 → 0/1043 |
| IPv4 ↓ | TCP P4 | 2055.3 → 722.2 | — | 1669 → 28 | 0/2416 → 0/26 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 600.0 → 599.5 | 0 → 0.08027 | — | 0/0 → 0/0 |
| IPv6 ↑ | TCP P1 | 1851.6 → 652.4 | — | 44 → 8 | 103/0 → 985/0 |
| IPv6 ↑ | TCP P4 | 1983.3 → 752.0 | — | 1163 → 484 | 1663/0 → 1169/0 |
| IPv6 ↑ | UDP300 | 299.8 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 599.7 → 523.5 | 0 → 12.85705 | — | 0/0 → 87900/0 |
| IPv6 ↓ | TCP P1 | 2041.7 → 738.8 | — | 47 → 613 | 0/572 → 0/886 |
| IPv6 ↓ | TCP P4 | 2045.2 → 726.5 | — | 1937 → 1118 | 0/2733 → 0/841 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 600.0 → 599.6 | 0 → 0.055 | — | 0/0 → 0/0 |

### tcp-frag

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 1829.2 → 595.2 | — | 67 → 28 | 334/0 → 124/0 |
| IPv4 ↑ | TCP P4 | 2033.5 → 745.5 | — | 1122 → 413 | 1658/0 → 1211/0 |
| IPv4 ↑ | UDP300 | 299.8 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 599.9 → 568.8 | 0 → 5.2021 | — | 0/0 → 31378/0 |
| IPv4 ↓ | TCP P1 | 2061.9 → 736.0 | — | 73 → 75 | 0/157 → 0/559 |
| IPv4 ↓ | TCP P4 | 2059.6 → 729.0 | — | 1414 → 1338 | 0/2243 → 0/1338 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 600.0 → 599.6 | 0 → 0.08542 | — | 0/0 → 0/0 |
| IPv6 ↑ | TCP P1 | 1860.8 → 647.2 | — | 35 → 4 | 169/0 → 248/0 |
| IPv6 ↑ | TCP P4 | 1983.6 → 709.3 | — | 931 → 610 | 1521/0 → 1440/0 |
| IPv6 ↑ | UDP300 | 299.7 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 599.7 → 524.7 | 0.00912 → 10.20592 | — | 0/0 → 67540/0 |
| IPv6 ↓ | TCP P1 | 2065.0 → 743.1 | — | 79 → 248 | 0/420 → 0/1057 |
| IPv6 ↓ | TCP P4 | 2030.7 → 739.0 | — | 1415 → 1174 | 224/2203 → 0/2173 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 600.0 → 598.4 | 0 → 0.05103 | — | 0/0 → 0/0 |

### tcp-obfs

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 1666.7 → 669.8 | — | 48 → 16 | 273/0 → 130/0 |
| IPv4 ↑ | TCP P4 | 1616.2 → 715.8 | — | 1165 → 271 | 2376/0 → 349/0 |
| IPv4 ↑ | UDP300 | 299.8 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 599.8 → 508.2 | 0 → 15.44416 | — | 0/0 → 126805/0 |
| IPv4 ↓ | TCP P1 | 1536.8 → 718.6 | — | 72 → 106 | 0/459 → 0/638 |
| IPv4 ↓ | TCP P4 | 1519.6 → 733.5 | — | 1051 → 87 | 0/1755 → 0/0 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 599.9 → 598.2 | 0.01535 → 0.31381 | — | 0/0 → 0/0 |
| IPv6 ↑ | TCP P1 | 1565.2 → 629.4 | — | 36 → 57 | 882/0 → 154/0 |
| IPv6 ↑ | TCP P4 | 1557.1 → 717.7 | — | 1073 → 214 | 1690/0 → 386/0 |
| IPv6 ↑ | UDP300 | 299.8 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 599.7 → 457.0 | 0 → 23.86017 | — | 0/0 → 177532/0 |
| IPv6 ↓ | TCP P1 | 1521.9 → 717.6 | — | 62 → 562 | 0/178 → 0/562 |
| IPv6 ↓ | TCP P4 | 1491.9 → 708.8 | — | 836 → 47 | 0/1706 → 0/0 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 599.7 → 592.1 | 0.05005 → 1.21978 | — | 0/0 → 0/0 |

### tcp-reality

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 1835.7 → 684.5 | — | 64 → 23 | 69/0 → 353/0 |
| IPv4 ↑ | TCP P4 | 2009.0 → 758.4 | — | 890 → 304 | 1627/0 → 420/0 |
| IPv4 ↑ | UDP300 | 299.9 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 599.9 → 528.6 | 0 → 11.77742 | — | 0/0 → 71503/0 |
| IPv4 ↓ | TCP P1 | 2095.3 → 735.2 | — | 102 → 1588 | 0/405 → 0/1588 |
| IPv4 ↓ | TCP P4 | 2046.6 → 757.3 | — | 1391 → 1798 | 0/2584 → 0/1960 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 600.0 → 601.1 | 0.00048 → 0.00655 | — | 0/0 → 0/0 |
| IPv6 ↑ | TCP P1 | 1919.2 → 693.7 | — | 12 → 30 | 125/0 → 43/0 |
| IPv6 ↑ | TCP P4 | 1987.9 → 734.4 | — | 1010 → 324 | 1478/0 → 865/0 |
| IPv6 ↑ | UDP300 | 299.9 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 599.9 → 496.2 | 0 → 17.19058 | — | 0/0 → 118050/0 |
| IPv6 ↓ | TCP P1 | 2108.3 → 724.0 | — | 76 → 18 | 0/271 → 0/684 |
| IPv6 ↓ | TCP P4 | 2038.5 → 723.5 | — | 1609 → 700 | 0/2471 → 0/1066 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 600.0 → 599.5 | 0 → 0.08382 | — | 0/0 → 0/0 |

### tcp-reality-tls

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 1112.1 → 1041.2 | — | 37 → 28 | 53/0 → 818/0 |
| IPv4 ↑ | TCP P4 | 1196.4 → 1096.7 | — | 733 → 697 | 965/0 → 973/0 |
| IPv4 ↑ | UDP300 | 299.8 → 299.9 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 599.4 → 599.4 | 0 → 0.03456 | — | 0/0 → 0/0 |
| IPv4 ↓ | TCP P1 | 1021.9 → 1081.2 | — | 25 → 11 | 0/100 → 0/321 |
| IPv4 ↓ | TCP P4 | 1197.7 → 1196.5 | — | 835 → 542 | 0/1100 → 0/1596 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 599.9 → 600.0 | 0.00687 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | TCP P1 | 1125.7 → 1051.1 | — | 61 → 45 | 192/0 → 424/0 |
| IPv6 ↑ | TCP P4 | 1205.2 → 1084.6 | — | 787 → 920 | 1344/0 → 1115/0 |
| IPv6 ↑ | UDP300 | 299.7 → 299.9 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 599.6 → 599.5 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | TCP P1 | 1070.6 → 1087.2 | — | 62 → 89 | 0/146 → 0/513 |
| IPv6 ↓ | TCP P4 | 1256.9 → 1196.4 | — | 758 → 1439 | 0/1162 → 0/1882 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 600.0 → 600.0 | 0 → 0 | — | 0/0 → 0/0 |

### udp-faketls

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 583.0 → 347.3 | — | 202 → 6 | 0/0 → 0/0 |
| IPv4 ↑ | TCP P4 | 570.6 → 354.5 | — | 266 → 2125 | 321/0 → 1374/0 |
| IPv4 ↑ | UDP300 | 299.7 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 421.3 → 96.3 | 29.85403 → 85.77835 | — | 0/0 → 277924/0 |
| IPv4 ↓ | TCP P1 | 598.6 → 361.2 | — | 869 → 0 | 0/842 → 0/0 |
| IPv4 ↓ | TCP P4 | 619.7 → 366.0 | — | 48 → 741 | 0/0 → 0/347 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 590.2 → 367.7 | 1.33976 → 38.24445 | — | 0/3721 → 0/0 |
| IPv6 ↑ | TCP P1 | 559.1 → 332.2 | — | 300 → 17 | 501/0 → 829/0 |
| IPv6 ↑ | TCP P4 | 500.3 → 328.7 | — | 1857 → 1643 | 1503/0 → 929/0 |
| IPv6 ↑ | UDP300 | 299.7 → 299.9 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 201.6 → 81.6 | 67.19702 → 85.82654 | — | 0/0 → 176818/0 |
| IPv6 ↓ | TCP P1 | 597.8 → 356.7 | — | 514 → 0 | 0/514 → 0/0 |
| IPv6 ↓ | TCP P4 | 587.7 → 384.8 | — | 21 → 242 | 0/0 → 0/0 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 491.9 → 375.6 | 18.02417 → 36.08279 | — | 0/15 → 0/0 |

### udp-padding

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 513.3 → 338.2 | — | 306 → 168 | 0/0 → 0/0 |
| IPv4 ↑ | TCP P4 | 529.0 → 333.3 | — | 216 → 2309 | 0/0 → 2683/0 |
| IPv4 ↑ | UDP300 | 299.8 → 300.1 | 0 → 0.00512 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 354.6 → 34.7 | 35.7473 → 96.49569 | — | 0/0 → 185292/0 |
| IPv4 ↓ | TCP P1 | 603.5 → 385.5 | — | 487 → 0 | 0/487 → 0/0 |
| IPv4 ↓ | TCP P4 | 615.2 → 359.9 | — | 36 → 457 | 0/0 → 0/0 |
| IPv4 ↓ | UDP300 | 300.0 → 300.4 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 513.3 → 363.7 | 14.24709 → 38.0017 | — | 0/25767 → 0/0 |
| IPv6 ↑ | TCP P1 | 506.5 → 333.4 | — | 352 → 129 | 1319/0 → 672/0 |
| IPv6 ↑ | TCP P4 | 521.4 → 321.4 | — | 183 → 682 | 5/0 → 468/0 |
| IPv6 ↑ | UDP300 | 299.8 → 300.1 | 0 → 0.00608 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 220.2 → 45.3 | 64.86348 → 94.13661 | — | 0/0 → 185212/0 |
| IPv6 ↓ | TCP P1 | 594.2 → 386.6 | — | 716 → 934 | 0/716 → 0/934 |
| IPv6 ↓ | TCP P4 | 605.7 → 358.0 | — | 71 → 1034 | 0/0 → 0/537 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 489.1 → 361.8 | 18.30521 → 38.328 | — | 0/0 → 0/0 |

### udp-quic

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 504.0 → 352.1 | — | 29 → 52 | 12/0 → 0/0 |
| IPv4 ↑ | TCP P4 | 517.2 → 337.0 | — | 1614 → 692 | 1265/0 → 409/0 |
| IPv4 ↑ | UDP300 | 299.7 → 300.0 | 0 → 0.00352 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 294.7 → 166.3 | 50.25264 → 71.34261 | — | 0/0 → 177375/0 |
| IPv4 ↓ | TCP P1 | 598.7 → 361.3 | — | 0 → 0 | 0/0 → 0/0 |
| IPv4 ↓ | TCP P4 | 597.8 → 361.1 | — | 0 → 1675 | 0/325 → 0/1273 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 600.8 → 372.3 | 0.05622 → 37.34951 | — | 0/1284 → 0/0 |
| IPv6 ↑ | TCP P1 | 541.3 → 331.8 | — | 393 → 933 | 216/0 → 889/0 |
| IPv6 ↑ | TCP P4 | 527.5 → 341.8 | — | 1134 → 412 | 1129/0 → 0/0 |
| IPv6 ↑ | UDP300 | 299.8 → 300.0 | 0 → 0.00064 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 234.5 → 120.6 | 61.66047 → 81.64266 | — | 0/0 → 279462/0 |
| IPv6 ↓ | TCP P1 | 584.5 → 383.9 | — | 0 → 0 | 0/0 → 0/0 |
| IPv6 ↓ | TCP P4 | 579.5 → 355.5 | — | 730 → 678 | 0/730 → 0/77 |
| IPv6 ↓ | UDP300 | 300.0 → 300.2 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 597.9 → 376.1 | 0.71127 → 36.93916 | — | 0/2259 → 0/0 |

### tcp-obfs-awg

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 1580.5 → 643.8 | — | 92 → 20 | 171/0 → 34/0 |
| IPv4 ↑ | TCP P4 | 1549.6 → 808.4 | — | 756 → 387 | 1569/0 → 897/0 |
| IPv4 ↑ | UDP300 | 299.9 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 599.6 → 544.2 | 0.00528 → 9.07731 | — | 0/0 → 58815/0 |
| IPv4 ↓ | TCP P1 | 1554.7 → 736.6 | — | 22 → 602 | 0/136 → 0/602 |
| IPv4 ↓ | TCP P4 | 1527.3 → 746.8 | — | 1147 → 831 | 0/2203 → 0/0 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 600.0 → 599.6 | 0 → 0.06575 | — | 0/0 → 0/0 |
| IPv6 ↑ | TCP P1 | 1623.9 → 622.3 | — | 34 → 14 | 259/0 → 73/0 |
| IPv6 ↑ | TCP P4 | 1575.9 → 631.7 | — | 951 → 204 | 3139/0 → 920/0 |
| IPv6 ↑ | UDP300 | 299.8 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 599.5 → 557.8 | 0.00736 → 5.20608 | — | 0/0 → 40056/0 |
| IPv6 ↓ | TCP P1 | 1500.0 → 737.6 | — | 72 → 82 | 0/415 → 0/152 |
| IPv6 ↓ | TCP P4 | 1497.6 → 725.5 | — | 1141 → 434 | 0/1984 → 0/184 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 599.9 → 596.1 | 0.00608 → 0.62647 | — | 0/0 → 0/0 |

### udp-faketls-awg

| IP and direction | Window | Goodput | UDP loss % | TCP retransmits | TUN drops client/server |
| --- | --- | ---: | ---: | ---: | --- |
| IPv4 ↑ | TCP P1 | 549.2 → 334.4 | — | 129 → 0 | 0/0 → 0/0 |
| IPv4 ↑ | TCP P4 | 540.7 → 337.0 | — | 580 → 1052 | 1126/0 → 857/0 |
| IPv4 ↑ | UDP300 | 299.8 → 300.0 | 0.00768 → 0.00032 | — | 0/0 → 0/0 |
| IPv4 ↑ | UDP600 | 263.5 → 220.6 | 36.84411 → 59.04279 | — | 0/0 → 211850/0 |
| IPv4 ↓ | TCP P1 | 624.2 → 383.5 | — | 0 → 332 | 0/598 → 0/332 |
| IPv4 ↓ | TCP P4 | 628.6 → 418.6 | — | 40 → 34 | 0/0 → 0/0 |
| IPv4 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv4 ↓ | UDP600 | 597.8 → 367.7 | 0.37075 → 37.87385 | — | 0/0 → 0/658 |
| IPv6 ↑ | TCP P1 | 522.8 → 334.4 | — | 10 → 59 | 89/0 → 1076/0 |
| IPv6 ↑ | TCP P4 | 536.0 → 345.3 | — | 684 → 1244 | 1091/0 → 432/0 |
| IPv6 ↑ | UDP300 | 299.7 → 300.9 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↑ | UDP600 | 290.1 → 97.7 | 37.96974 → 85.30597 | — | 0/0 → 271215/0 |
| IPv6 ↓ | TCP P1 | 612.5 → 357.6 | — | 133 → 0 | 0/684 → 0/0 |
| IPv6 ↓ | TCP P4 | 605.3 → 363.4 | — | 813 → 0 | 0/698 → 0/0 |
| IPv6 ↓ | UDP300 | 300.0 → 300.0 | 0 → 0 | — | 0/0 → 0/0 |
| IPv6 ↓ | UDP600 | 598.0 → 244.0 | 0.11076 → 58.90091 | — | 0/536 → 0/0 |

## Baseline

| Policy | Direction | Before Mbps | After Mbps | Drift % | CV before / after % |
| --- | --- | ---: | ---: | ---: | ---: |
| required | IPv4 ↑ | 30178.8 | 30555.3 | +1.248 | 1.363 / 0.187 |
| required | IPv4 ↓ | 30437.1 | 29982.5 | -1.493 | 0.886 / 0.242 |
| required | IPv6 ↑ | 29782.1 | 29987.9 | +0.691 | 0.952 / 0.313 |
| required | IPv6 ↓ | 30266.0 | 30267.6 | +0.005 | 0.640 / 0.709 |
| off | IPv4 ↑ | 30559.7 | 30267.0 | -0.958 | 0.454 / 0.869 |
| off | IPv4 ↓ | 30092.1 | 30172.3 | +0.266 | 0.269 / 1.304 |
| off | IPv6 ↑ | 30278.1 | 29967.1 | -1.027 | 0.248 / 0.122 |
| off | IPv6 ↓ | 30160.7 | 30165.3 | +0.015 | 1.660 / 0.670 |

## Loss analysis and limits of interpretation

In ordinary TCP carriers, off increased processing cost per useful traffic. For
plain IPv4 UDP600 upload, client Qeli CPU was 44.5 → 95.2% of one core and server
CPU 37.2 → 106.1%, with goodput 599.6 → 540.2 Mbps. Client TUN TX drops were
0 → 59552, a drop fraction of 8.01% over observation versus 8.13% receiver loss.
UdpSndbufErrors and TUN qdisc drops were zero; server iperf had additional
RcvbufErrors. This differs from outer UDP socket overflow on a UDP carrier.

For plain IPv4 TCP P4 upload, outer RTT was 0.058 → 0.060 ms, but median outer
Send-Q was 0 → 232448 bytes, rwnd_limited 2.980 → 9.872 seconds over about
12 seconds, and inner RTT 6.49 → 12.17 ms. These indicate receiver backpressure
and processing delay rather than increased network RTT. In download for the same
profile, client Recv-Q rose from 38629 to 633600 bytes and inner RTT from 5.37 to
27.36 ms. Aggregate CPU alone cannot identify the responsible function or thread.

UDP carrier required upload600 shows a different confirmed loss point: TUN TX
drops are zero, while server UdpRcvbufErrors rise sharply. For udp-faketls IPv6,
there were 113751 outer IPv4 UDP RcvbufErrors and 1653 client SndbufErrors, with
67.197% iperf loss. The server socket log confirms receive-queue overflow; periodic
server internal-drop categories are zero. Outer datagrams and inner packets differ,
so these counters do not provide a packet-for-packet balance of all loss.

Download is not fully explained by those counters: udp-padding IPv6 required lost
18.305% with zero TUN TX drops and UDP buffer errors. These raw cannot rule out
eth1 qdisc, outer loss or unobserved processing/reassembly. Exact localization
requires separate checks after this comparison, not tuning within a phase.

This experiment did not use a CPU sampling profiler, syscall tracing, captures for
datagram accounting or a FULL_RING tracepoint. It did not identify a specific hot
path or establish that larger TUN/UDP queues fix the cause. One fixed required → off
order, n=1 and one Linux lab do not establish statistical significance, Android or
Windows properties, or real-WAN guarantees. DPI was not tested. This is not a
0.8.0-versus-0.8.2 comparison or verification of the current branch after its SHA changes.

## Restoration and preservation

After each policy, all 16 checks passed on VM300 and all 16 on VM301: boot ID,
protected-file hashes, sysctls, hostname, kernel, CPU, processes, links, addresses,
IPv4/IPv6 routes/rules, qdisc and IPv4/IPv6 firewall. After both phases, read-only
checks also confirmed no test TUN or lock and verified retained binary copies.
The dist artifact still had the same SHA at report time. Earlier results, the
emulator SDK and binaries were not deleted. No release or site was published.

The first attempt stopped before performance windows because a collector guard
mistook the server worker for a foreign process. Its FAIL and baseline were kept;
every table here belongs only to the separate corrected r02 run. The correction
changed process ownership verification, not the binary or workload.

After r02 completed, the report script attempted to read a server config on the
client VM and stopped. The original FAIL was preserved. Tables were recovered by
separate read-only processing of the same completed raw, reading configs on their
respective endpoints, without rerunning measurements or writing to either VM.
This was a reporting error, not missing windows; UDP loss-budget violations remain
failures of the corresponding workload.

## Data and reproduction

- [Shared compact window data](../../../data/benchmarks/recordizer_required_off_2026-10-20.json) includes throughput, loss, retransmits, TUN/qdisc, CPU, RSS, UDP counters, baseline, restoration and the source-summary hash. These are derived data, not complete raw.
- Required raw on both guests: `/opt/qeli-release-short-r12-recordizer-required-20261020-r02`.
- Off raw on both guests: `/opt/qeli-release-short-r12-recordizer-off-20261020-r02`.
- Each raw root contains client `windows/<label>/iperf.json`, both endpoints' `observations.json`, private configs, session logs and before/after snapshots. Required/off controller receipts and the original FAIL remain with the operator.
- The [standard short release test](../../manuals/RELEASE-SHORT-TEST.md) has a different scope; this n=1 matrix does not replace its functional, compatibility and repeated checks.
- [Technologies and measurements](../../reference/TECHNOLOGIES.md) and [Recordizer design](../../reference/RECORDIZER.md).

To reproduce, preserve these exact SHA values, resources, workloads and effective
configuration; set the UDP loss criterion and repetition count in advance. A separate
experiment gets its own raw root and dated report, without overwriting failed windows.
