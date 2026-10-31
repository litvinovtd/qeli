# Three-repeat short test with buffer checks — 31 October 2026

**120/120 windows completed; VM300/301 restored. The complete matrix is NOT an
accepted stable reference:** `PERFORMANCE_REFERENCE_REVIEW_REQUIRED`. Baseline
passed, but two TCP cells exceeded CV 5% and two UDP600 cells exceeded loss 1%
in one repetition. The other 28 of 32 cells meet these numerical criteria.
No failed windows were excluded.

Method: [short test, --buffer-reference scope](../manuals/RELEASE-SHORT-TEST.md).
The previous [n=1 pilot](RELEASE-SHORT-BUFFERS-PILOT-2026-10-31.md) remains separate.

## Artifact and conditions

- Unchanged experimental native Linux amd64 Qeli 0.8.4, SHA256
  `a6da0fa51b53b1efcc88e5d109be7136dd6d666aeccc37b97722e3f80cb2ff6c`.
  No rebuild. This does not test currently modified sources or qualify portable
  release/dist. VM302 was not used; no release was published.
- VM300/server and VM301/client: 2 vCPU/2 GiB each, MemTotal 2020904 KiB,
  Intel i5-8500, Debian `6.12.111+deb13-amd64`, iperf3 3.18. No reboot or
  queue/qdisc/wmem/Qeli-config change relative to the pilot.
- Recordizer required with actual `PACKET_MUX_V1`; genuine H2 for Reality-TLS.
  MTU 1400, both TUN queues 1000, timed batching, previous fixtures,
  `gateway=false`, `dns=off`, outer IPv4. Normalized configs were verified
  identical across repetitions, not just version labels.
- Same temporary policy on both guests: `rmem_max=rmem_default=4194304`, restored
  to 212992 afterwards. Actual Qeli UDP `ss rb=8388608` (explicit 4 MiB request),
  iperf UDP `rb=4194304`, `tb=212992`. Both endpoints checked every UDP window;
  live TCP receiver `rb/tb` and Qeli TCP recorded/checked without a UDP threshold.
- Three fresh sessions per profile; forward, reverse, rotated profile order.
  TCP P4 and UDP600, inner IPv4/IPv6 upload/download, `-t 10 -O 2`, UDP payload
  1200. 96 load windows plus 24 direct TCP P1 baseline windows: three per
  family/direction before and after. No tunneled P1, UDP300, all-12,
  compatibility/mixed or long soak.

## Baseline

Median Mbps; sample CV = standard deviation / mean, n=3. Every baseline CV
and absolute drift meets the predefined 5% threshold.

| IP / direction | Before | Before CV | After | After CV | Drift |
|---|---:|---:|---:|---:|---:|
| IPv4 upload | 31339.90 | 1.17% | 30473.55 | 0.37% | −2.76% |
| IPv4 download | 30403.74 | 0.31% | 30238.53 | 0.29% | −0.54% |
| IPv6 upload | 30365.47 | 0.23% | 30451.41 | 0.93% | +0.28% |
| IPv6 download | 29972.89 | 1.03% | 30183.41 | 0.92% | +0.70% |

## Measurements

Speeds are receiver Mbps medians over **all three** repetitions. TCP retransmits
and TCP TUN TX drops are medians; UDP loss and UDP TUN TX drops are **maxima**,
so zero medians cannot hide the two bad windows. TUN drops sum both guests over
observation including warm-up; iperf retransmits/loss exclude warm-up. Counters
from these intervals/layers must not be treated as one-to-one packet counts.

| Profile | IP | Direction | TCP P4 | TCP CV | RTX med | TCP TUN drops med | UDP600 | UDP loss max | UDP TUN drops max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| tcp-faketls | IPv4 | upload | 1923.2 | 0.71% | 1103 | 1760 | 599.80 | 0% | 0 |
| tcp-faketls | IPv4 | download | 2060.6 | 0.55% | 1697 | 2399 | 600.00 | 0% | 0 |
| tcp-faketls | IPv6 | upload | 1892.6 | 0.55% | 840 | 1533 | 599.77 | 0% | 0 |
| tcp-faketls | IPv6 | download | 2042.8 | 1.15% | 1452 | 2283 | 600.01 | 0% | 0 |
| tcp-reality-tls | IPv4 | upload | 1210.0 | 0.99% | 672 | 1461 | 599.42 | 0% | 0 |
| tcp-reality-tls | IPv4 | download | 1196.4 | 1.35% | 839 | 1788 | 600.02 | 0% | 0 |
| tcp-reality-tls | IPv6 | upload | 1210.3 | 1.86% | 630 | 1240 | 598.97 | 0% | 0 |
| tcp-reality-tls | IPv6 | download | 1267.0 | 1.54% | 763 | 1289 | 600.02 | 0% | 0 |
| udp-faketls | IPv4 | upload | 1176.8 | 2.53% | 757 | 1891 | 599.67 | 0% | 0 |
| udp-faketls | IPv4 | download | 1230.1 | 2.36% | 1265 | 1626 | 600.01 | 0% | 0 |
| udp-faketls | IPv6 | upload | 1099.2 | **17.10%** | 581 | 1062 | 599.48 | **2.5278%** | **7420** |
| udp-faketls | IPv6 | download | 1183.6 | **5.70%** | 1072 | 1872 | 600.00 | 0% | 0 |
| udp-quic | IPv4 | upload | 1136.7 | 0.54% | 695 | 1471 | 599.73 | 0% | 0 |
| udp-quic | IPv4 | download | 1219.9 | 2.02% | 1128 | 1874 | 600.00 | 0% | 0 |
| udp-quic | IPv6 | upload | 1128.9 | 4.81% | 1157 | 1409 | 599.72 | **2.8597%** | **14780** |
| udp-quic | IPv6 | download | 1137.9 | 2.80% | 1366 | 2072 | 600.00 | 0% | 0 |

Unstable UDP-FakeTLS TCP triples:

- IPv6 upload: **820.0 / 1099.2 / 1140.5**, CV 17.0954%.
- IPv6 download: **1164.9 / 1183.6 / 1293.0**, CV 5.7011%.

UDP loss by repetition: UDP-FakeTLS IPv6 upload **2.5278 / 0 / 0%**;
QUIC IPv6 upload **0 / 2.8597 / 0%**. The other 46 of 48 UDP windows reported 0%.
The old single FakeTLS IPv6 upload result of 839 Mbps was not replaced: the
new triple is 1908.8 / 1892.6 / 1889.5. The binary is unchanged; this is not a version fix.

## Evidence from the bad windows

| UDP600 IPv6 upload | UDP-FakeTLS rep1 | QUIC rep2 |
|---|---:|---:|
| Receiver goodput, Mbps | 589.17 | 581.86 |
| Server / client steal | 16.82% / 12.25% | 10.17% / 7.44% |
| Qeli server socket-drop increment | 10957 | 2702 |
| Server IPv4 UdpRcvbufErrors | 10957 | 2702 |
| Server IPv6 Udp6RcvbufErrors | 2043 | 0 |
| Client TUN TX drops | 7420 | 14780 |

The low UDP-FakeTLS IPv6 TCP upload also had server/client steal of
16.69% / 10.89%. QUIC rep2 IPv6 TCP download had 7.31% / 8.58%.
These are window shares from `/proc/stat`, including warm-up, not instantaneous peaks.
Linux defines [steal as involuntary wait](https://www.kernel.org/doc/html/latest/filesystems/proc.html#miscellaneous-kernel-statistics-in-proc-stat):
VM CPU availability was substantially impaired during these windows. Good
before/after baseline does not exclude temporary vCPU contention **inside** the series.

Qeli outer-IPv4 receive sockets overflowed despite actual 4 MiB grants; client
TUN drops occurred too. UDP-FakeTLS also has IPv6 receive errors on the receiving
guest: this global family counter is not strict per-inode iperf attribution.
Do not attribute every loss solely to Qeli, iperf or a small buffer. The source
of CPU contention and exact reader-pause mechanism were not localized here;
no particular neighboring VM/process was identified. A contribution from the
binary's sensitivity to such pauses has not been excluded.

## Verdict

FakeTLS TCP and Reality-TLS repeat well, and passing cells provide useful measured
orientation. The complete set must not be used as an accepted automatic reference
or proof of a version regression. CV/loss thresholds were not relaxed after seeing
results; no best-two-of-three selection. No post-hoc steal admission threshold
was added.

Next: ensure CPU availability without changing the binary/settings and recheck
the affected IPv6 directions with the same counters. Accepting a complete reference
needs a new agreed whole series while retaining this one. No automatic buffer/CPU/RAM
increase, qdisc change or extra run was performed.

## Raw and restoration

- Both guests: `/opt/qeli-release-short-buffer-reference-20261031-r01`.
- UTC `2026-10-31T15:02:37.950543`–`15:37:20.331566`, including archive hashing.
- Method `qeli-release-short-buffer-reference-v2`.
- Receipt `measurements_complete_udp_failed`: nonzero controller exit reflects
  the UDP budget, not incomplete collection/cleanup failure. No windows were rerun.
- Compact result/evidence/fresh-final-check are in workspace directory
  `short-buffer-reference-20261031`; private configs/large raw are not published.

All 16 restoration checks passed on each guest: boot, previous files/binaries,
sysctls, processes, links/addresses/routes/rules, qdisc, iptables/ip6tables.
Independent verification confirmed no Qeli/iperf/IRTT/TUN/netns/lock/owned receipts,
inactive qeli/qeli-client, original rmem/wmem values of 212992 and unchanged SHA.
Previous binaries/results remain intact. No Proxmox/VM302 workloads.

Harness SHA256:

- controller `ba19ebd2a5cd8389f72c4b573053a94b057eeb832fd41fa2c08aadbc1b878f98`
- helper `540d9a1133b3f8e1f98eac429452398e094415efa15a476a1c48be155baa497e`
- buffers `19d1ed5127d8c2fda8a43e24e0e77ef943b465dd8f3f592722d888c6f730098e`
- analyzer `d3078faf025d4b019ca895f3f00ec24cb0917e0c4bee8775d52281329128eecd`

41 local unit tests pass. This does not qualify full release coverage, IRTT,
long soak or ARM64. No release publication or commit.
