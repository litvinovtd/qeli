# Short laboratory test before a release

The test checks transports and repeatable performance on two dedicated Linux guests.
It replaces broad VPN comparisons in routine speed testing, not CI, platform/security
qualification or mandatory long release-soak gates. Competitors and precise UDP ceilings
remain separate studies.

## Lab and preservation

The [controller](../../../scripts/release_short_test.py) runs on the workstation using
direct pinned SSH to two explicit guests. VM300/301 are test guests; Proxmox executes
no test/build/install commands. VM302 is build-only when a new artifact is needed,
never during measurements.

The controller needs Python 3/Paramiko; guests need Python 3, iperf3, iproute2 and
firewall snapshot tools. Nothing is installed. SSH keys are used in place, not copied;
credential/identity fixtures remain private.

Each run creates a new `/opt/qeli-release-short-<tag>` on both guests, with private
binary copies/configs/raw. Preflight records SHA, boot IDs, kernel/CPU, network state
and hashes of previous `/opt/qeli-*` files. Existing VPN/TUN/iperf/build/emulator,
netem or locks cause refusal, not termination of other work. No reboot, package
installation or service/sysctl/qdisc/offload tuning. Cleanup signals only owned
process groups with verified PID/start identity. Network/firewall, selected sysctls,
boot IDs and old files must match before/after; mismatches are failures, not PASS.

## Version 1 plan

Core profiles: `tcp-faketls`, `tcp-reality-tls`, `udp-faketls`, `udp-quic`.
Performance: required, MTU 1400, client/server queue 1000. Client: `gateway=false`,
`dns=off`, `ipv6=required`, `reconnect=false`; this is transport testing, not DNS/full-tunnel
admission. Reality-TLS uses genuine H2, handrolled, no padding/stealth/heartbeat and
enabled traffic shaping. Other variants explicitly select padding/fragmentation/AWG;
heartbeat is off, idle timeout 300 seconds. Session configs and SHA are retained.

| Stage | Connections | Windows |
|---|---:|---:|
| All 12 profiles, required and off | 24 | 96 |
| Prefer on four core profiles | 4 | 16 |
| Outer IPv6 on four profiles | 4 | 16 |
| Previous server/new client and reverse, four profiles | 8 | 32 |
| Three performance repetitions on four profiles | 12 | 192 |
| Longer windows on four profiles | 4 | 8 |
| Baseline before/after performance | — | 24 |
| Main matrix | 56 | 384 |

After its final baseline and cleanup, run `--mixed-only` separately: four connections,
two 30+2-second IPv4/IPv6 groups each. A group simultaneously runs TCP P4 download
and UDP upload at the lower fixed rate (pilot 300 Mbps) on distinct iperf ports.
This adds 16 iperf measurements in eight groups; timestamp overlap must be at least
27 seconds. Main plus mixed: 60 connections, 400 iperf measurements and roughly five
extra minutes. Mixed has separate raw/receipt and cleanup. Never run both controllers
simultaneously.

Functional sessions include inner IPv4/IPv6 ping and four two-second transfers:
TCP IPv4 upload, UDP IPv4 download, TCP IPv6 download, UDP IPv6 upload.
This is not all eight combinations; performance fully covers both directions/families.
Outer IPv6 is verified independently. Required/prefer need active PACKET_MUX_V1;
off a positive legacy marker without active mux. Prefer uses capable clients;
negative negotiation retains its protocol gates.

Each performance repetition uses a fresh connection; orders are forward, reverse,
then rotated. Each has 16 windows: TCP P1/P4 and two fixed UDP rates, IPv4/IPv6 ×
upload/download. `-t 10 -O 2`: 10 measured seconds plus two warm-up seconds.
UDP has one stream, 1200-byte payload; offered rate, receiver goodput and loss are
distinct. Sequential directions are not replaced by bidir. Rates are fixed before
testing, never reduced using candidate results. Pilot 300/600 Mbps are control loads,
not claimed 50/80% capacity points or ceilings. New rates need a new plan/reference.

The longer block is TCP P4, 20+2 seconds, IPv4 upload and IPv6 download per profile.
It is **not a long soak or mixed load** by itself; the short mixed block is separate
above. The matrix exercises repeated connections; mandatory long mixed-load,
fault/reconnect/roaming gates remain in place.
Baseline follows functional checks, precedes performance and follows the final session:
three TCP P1 windows per family/direction, 10+2 seconds. Pure iperf time is about
50 minutes plus SSH/setup/cleanup. 60–90 minutes is an estimate, not a timeout that
converts missing work into PASS.

## Metrics and admission

The [helper](../../../scripts/release_short_guest.py) samples VM/process-group CPU,
sampled RSS, TCP_INFO via ss, TUN/qdisc, SNMP and softnet every 0.5 seconds.
SS is restricted to test ports. No payload, TLS key or memory capture.
Window qdisc counters describe the observed TUN, not every physical queue.
Global IPv4/IPv6 UDP SNMP cannot distinguish individual sockets in that family.
The early pilot helper captured only `/proc/net/snmp` (IPv4); absent snmp6 is
unmeasured, not zero. The current helper also retains snmp6.
FULL_RING is not continuously traced; TX drops alone do not prove it.
The [analyzer](../../../scripts/release_short_report.py) checks completeness, three
repeats, baseline and restoration. RTT/cwnd are sampled TCP_INFO; p95 is nearest-rank
over snapshots, not per-packet or ICMP latency. CPU/RSS/drop observation includes warm-up;
iperf throughput/retransmits exclude it. Different intervals cannot prove exact
drop/retransmission agreement.

Initial thresholds need calibration: absolute baseline drift or CV >5% means INVALID;
performance-cell CV >5% needs confirmation; UDP loss >1% in any repetition fails to
confirm the load; median throughput down >10% against a compatible reference means
NEEDS_CONFIRMATION. Failed window/marker/direction/cleanup is FAIL, not skipped.

Without a reference, passing criteria yield `PILOT_NO_REGRESSION_BASELINE`, not proof
of no regression. Failed UDP/repeatability criteria yield `PILOT_REVIEW_REQUIRED`.
`--reference` requires matching method, rates, kernel/CPU/guests, CPU model, memory,
iperf version, measurement controller/helper SHA, qdisc/sysctl/link settings and normalized performance configs.
Do not hide new defaults in version comparisons. Previous SHA
is explicit: an older binary with the same version label need not be the previous
published release.

`LAB_COMPARISON_PASS` covers only implemented Linux throughput/loss checks.
CPU/RSS/drops/delay also require review. Warnings cover sampled RTT p95 up by both
20% and 2 ms, CPU per Mbps >15%, RSS up by both 20% and 10 MiB, or TUN drop ppm
more than doubled with an increase >1000 ppm. Warnings require confirmation and
prevent automatic LAB_COMPARISON_PASS. They are initial heuristics, not proof of a
leak or a particular cause. Observation is identical for candidate/reference; independent cost
is not established. Recheck suspicious cells in pairs, retain first raw/FAIL, never
substitute the best repetition for a failure.

## Running

A private JSON specifies `hosts`, `hostnames`, `known_hosts`, `ssh_key`,
`candidate_source` (client guest path), `candidate_sha256`, `previous_binary`
(both guest paths), `previous_sha256`, `fixture` (server/client), `outer_server`,
`inner_server` keyed by `"4"`/`"6"`, `outer_iface`, and two increasing `udp_rates`
per core profile. Fixtures contain one prepared server profile/identity and its
matching client INI. Use lab credentials only.

```bash
python scripts/release_short_test.py --config private-lab.json --tag rc1 --output rc1.json --plan-only
# Optional harness check: four profiles, 16 windows, not release admission.
python scripts/release_short_test.py --config private-lab.json --tag setup-smoke --output setup-smoke.json --smoke-only
python -u scripts/release_short_test.py --config private-lab.json --tag rc1 --output rc1.json
# Only after main-matrix complete + final baseline + cleanup:
python -u scripts/release_short_test.py --config private-lab.json --tag rc1-mixed --output rc1-mixed.json --mixed-only
python scripts/release_short_report.py --config private-lab.json --result rc1.json --mixed-result rc1-mixed.json --output rc1-summary.json
python scripts/release_short_report.py --config private-lab.json --result rc2.json --mixed-result rc2-mixed.json --output rc2-summary.json --reference rc1-summary.json --require-pass
```

When every window/baseline completed and cleanup is verified,
`measurements_complete_udp_failed` retains complete data: mixed may follow as a
diagnostic stage before reporting. This does not erase FAIL. Do not continue loads
after an incomplete window or restoration error.

Use a launcher that survives the run, not a short external foreground timeout.
Checkpoints are atomic between windows. No blind resume: retain FAIL, verify cleanup,
diagnose before a new tag. Locks exclude another instance; coordinate other workloads
too. Large raw stays on guests, local receipts/summaries are compact. Preserve runner/helper
hashes, tool versions and report; never commit secret configs. Controller errors in measurement
or restoration return nonzero. Without `--require-pass`, analyzer success means the report
was created, not release admission. With the flag, only LAB_COMPARISON_PASS returns zero;
pilot/no-reference, INVALID and NEEDS_CONFIRMATION do not pass. A comparison PASS
requires valid mixed receipts for candidate/reference; mixed UDP loss >1% needs
review and prevents automatic PASS. This is a short concurrent-load check, not
discovery of its sustainable ceiling. `--smoke-only` uses
a separate method/SMOKE_ONLY status and is rejected by the full-plan analyzer.
The current helper stores client device-id in the run directory, not global
`/var/lib/qeli`. No automatic release publication.

See the [0.8.0 matrix](../reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md),
[TUN queue](../reports/TUN-QUEUE-SIZE-2026-10-16.md),
[load studies](../reports/BENCHMARK.md).

[Pilot publication status](../reports/RELEASE-SHORT-PILOT-2026-10-16.md):
`PILOT_REVIEW_REQUIRED`, not an accepted reference or release qualification.
