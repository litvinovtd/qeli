# Short-test pilot: actual socket buffers, 31 October 2026

Result: **harness validated, 40/40 windows completed, VM300/301 restoration verified**.
All 16 UDP600 windows reported 0% receiver loss and 0 TUN TX drops. This is
`BUFFER_PILOT_ONLY`, not release admission or proof of no regression.
Method: [short test v2](../manuals/RELEASE-SHORT-TEST.md).

## Artifact, lab and scope

- Unchanged experimental native Linux amd64 Qeli 0.8.4 with compressed licenses,
  SHA256 `a6da0fa51b53b1efcc88e5d109be7136dd6d666aeccc37b97722e3f80cb2ff6c`.
  This does **not** qualify portable release/dist or a new build of current sources.
  No rebuild/binary change; VM302 was not used.
- VM300/server and VM301/client: 2 vCPU/2 GiB each (MemTotal 2020904 KiB),
  Intel i5-8500, Debian kernel `6.12.111+deb13-amd64`, iperf3 3.18.
  No Proxmox test/build/install commands.
- Four profiles, Recordizer required with confirmed `PACKET_MUX_V1`; Reality-TLS
  uses genuine H2. MTU 1400, both TUN queues 1000, previous fixtures and timed
  batching, `gateway=false`, `dns=off`. Queues/qdisc/wmem unchanged.
- Per profile: TCP P4 and UDP600, inner IPv4/IPv6 upload/download, **n=1**,
  `-t 10 -O 2`; UDP payload 1200. Outer IPv4. 32 load windows plus eight direct
  TCP P1 before/after baseline windows. No tunneled P1, UDP300, three repetitions,
  all-12 functional matrix, compatibility or mixed in this pilot.
- Explicit temporary lab policy on both guests: `rmem_max=rmem_default=4194304`,
  applied before baseline/socket creation and fully rolled back after traffic.
  This changes measurement conditions; it is not a Qeli fix or a blanket
  recommendation to change users' system settings.

## Live socket evidence

| Object | Actual value | Verification |
|---|---|---|
| Qeli UDP-FakeTLS/QUIC, both ends | `ss rb=8388608` | Normalized explicit 4 MiB request (`rb/2`); every carrier socket, PID/inode |
| iperf UDP, both ends/every window | `ss rb=4194304`, `tb=212992` | Receiver server/upload or client/download; one successful live snapshot |
| Qeli TCP, session start | `ss rb=131072` | No UDP normalization; per-window snapshots retained |
| iperf TCP receiver, including baseline | sampled `rb` 1697795–6291456 bytes | Live data connections, `rb/tb`; autotuning, not a fixed floor |

Linux `ss rb/tb` are kernel-accounted bytes, not guaranteed payload capacity.
Qeli UDP requires the explicit 4 MiB receive floor; iperf UDP without `-w`
requires 4 MiB directly in `rb`, without doubling it again. No UDP threshold
is imposed on TCP. The reduction repeated buffer checks from raw and verified
the measured helper/controller/checker hashes.

## Measurements

Receiver Mbps. TUN TX drops sum both guests over observation including warm-up;
iperf TCP retransmits exclude warm-up. Their intervals differ; exact counter
agreement is not assumed. Every UDP cell below has loss=0%, TUN drops=0.

| Profile | IP | Direction | TCP P4 | Retransmits | TCP TUN TX drops | UDP600 goodput | UDP loss | UDP TUN TX drops |
|---|---|---|---:|---:|---:|---:|---:|---:|
| tcp-faketls | IPv4 | upload | 1931.1 | 1166 | 1303 | 599.74 | 0% | 0 |
| tcp-faketls | IPv4 | download | 1947.9 | 1399 | 1750 | 599.98 | 0% | 0 |
| tcp-faketls | IPv6 | upload | 839.3 | 430 | 918 | 599.59 | 0% | 0 |
| tcp-faketls | IPv6 | download | 2004.4 | 1227 | 1616 | 599.95 | 0% | 0 |
| tcp-reality-tls | IPv4 | upload | 1200.0 | 802 | 1249 | 599.44 | 0% | 0 |
| tcp-reality-tls | IPv4 | download | 1207.0 | 727 | 1104 | 599.96 | 0% | 0 |
| tcp-reality-tls | IPv6 | upload | 1210.8 | 790 | 2164 | 599.28 | 0% | 0 |
| tcp-reality-tls | IPv6 | download | 1297.2 | 633 | 1569 | 599.96 | 0% | 0 |
| udp-faketls | IPv4 | upload | 1128.9 | 1175 | 1175 | 599.83 | 0% | 0 |
| udp-faketls | IPv4 | download | 1216.6 | 508 | 1583 | 599.97 | 0% | 0 |
| udp-faketls | IPv6 | upload | 1118.8 | 449 | 1772 | 599.49 | 0% | 0 |
| udp-faketls | IPv6 | download | 1184.3 | 1154 | 1710 | 599.98 | 0% | 0 |
| udp-quic | IPv4 | upload | 1159.1 | 1036 | 1751 | 599.70 | 0% | 0 |
| udp-quic | IPv4 | download | 1214.2 | 1226 | 2029 | 599.97 | 0% | 0 |
| udp-quic | IPv6 | upload | 1159.9 | 705 | 1777 | 599.57 | 0% | 0 |
| udp-quic | IPv6 | download | 1247.0 | 1429 | 2037 | 599.98 | 0% | 0 |

UDP-FakeTLS/QUIC carrier socket-drop increments were zero during UDP600 windows;
inode sets remained unchanged. Cumulative `d` reached 539 after maximum TCP:
do not attribute it to the following UDP600 window. One sampled iperf UDP `d=0`
does not replace final receiver loss. Sufficient buffers do not eliminate the
remaining maximum-TCP drops/retransmits.

Single-window baseline drift: IPv4 upload −1.98%, download **−5.16%**; IPv6
upload −0.40%, download −0.25%. IPv4 download exceeds the 5% guideline; n=1
cannot establish CV. This pilot is not an accepted performance reference.
The low single FakeTLS IPv6 TCP upload result is unexplained here and needs
repeats for a speed conclusion. Old small-buffer measurements remain intact;
comparing them to this table is not a clean version effect.

## Raw, initial failure and restoration

Both-guest raw: `/opt/qeli-release-short-buffer-pilot-20261031-r02`.
UTC `2026-10-31T14:29:10`–`14:45:57`, including archive hashing;
method `qeli-release-short-buffer-pilot-v2`. Compact local receipts, summary and
independent final check are in workspace directory `short-buffer-pilot-20261031`.
Private configs and large raw are not published.

Initial `r01` failed **before traffic/sysctl mutation**: hashing previous archives
exceeded the old 60-second SSH snapshot timeout. FAIL and server raw were retained;
the client run root had not been created. Snapshot exit, original buffers and idle
guests were verified. Only snapshot timeout was increased to 900 seconds; retry
used a new tag, not blind resume.

All 16 restoration checks passed per guest: boot ID, previous files/binaries,
sysctls, processes, links/addresses, routes/rules, qdisc, iptables/ip6tables.
Independent check confirmed original `rmem_*`/`wmem_*` values of 212992, no
Qeli/iperf/IRTT/TUN/netns/lock/owned receipts, inactive qeli/qeli-client services,
and unchanged candidate/previous SHA. No reboot, release publication or replacement
of release/dist artifacts.

Measured SHA256:

- controller: `c1106c6b270edb1a059b7301f5a28abce7287b485e431ea2a4a97ae15b31e5fd`
- helper: `540d9a1133b3f8e1f98eac429452398e094415efa15a476a1c48be155baa497e`
- buffer checker: `19d1ed5127d8c2fda8a43e24e0e77ef943b465dd8f3f592722d888c6f730098e`

38 local unit tests cover wrong/foreign/missing buffers, Linux accounting,
partial-pilot rejection, partial apply/rollback, lease expiry and ownership checks
before signal escalation. Full v2 and mixed were not run in this pilot;
independent observation overhead has not been established.
