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
installation or service/qdisc/offload tuning. The only optional sysctl change is
the explicitly authorized lab receive-buffer policy below. Cleanup signals only owned
process groups with verified PID/start identity. Network/firewall, selected sysctls,
boot IDs and old files must match before/after; mismatches are failures, not PASS.

## Version 2 plan

The v1 matrix and workloads remain unchanged; v2 adds mandatory live socket-buffer
checks. Old raw is never rewritten. Do not treat v1/v2 speed differences as a clean
version A/B: buffers/observation changed, requiring a fresh reference.

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

### Actual Qeli and iperf buffers

Configuration and `rmem_max` describe requests/limits, not the memory granted to a
live socket. V2 retains test-port-restricted `ss -uanmpeH` (UDP) / `ss -tanmpeH`
(TCP): inode, PID and `skmem rb/tb/d`. Qeli is checked after connection and each
window; its PID must belong to the private run. TCP values are recorded as observed:
their autotuning is not replaced with a fixed UDP threshold.
For the iperf TCP receiver, the analyzer also requires live `rb/tb` samples of
the data connection (`bytes_received` above 1 MB), excluding the control connection;
missing evidence fails full v2 admission.

The Qeli UDP receive floor is a 4 MiB request. Linux doubles explicit `SO_RCVBUF`
accounting, so `ss rb >= 8388608` is required (normalized `rb/2 >= 4 MiB`). A new
iperf UDP socket without `-w` uses `rmem_default`: require `ss rb >= 4194304`
**without dividing/doubling it again**. These are kernel-accounted bytes, not
guaranteed payload capacity. One successful iperf snapshot per endpoint/UDP window
is taken while traffic is live; bounded early polls may precede socket creation.
The receiver is server for upload, client for download, server for mixed UDP.
Send `tb` and socket drops `d` are also retained; neither replaces final receiver
loss or global SNMP. Missing/foreign socket evidence or an insufficient actual
buffer is FAIL, not zero/skipped. The v2 analyzer repeats these checks from raw,
including mixed, rather than trusting a PASS flag.

The private JSON now requires:

```json
"udp_buffers": {
  "apply": false,
  "qeli_receive_bytes": 4194304,
  "iperf_receive_rb_bytes": 4194304
}
```

`apply=false` changes nothing and refuses insufficient host receive limits. On
dedicated lab guests only, explicitly select `apply=true` to temporarily set
`net.core.rmem_max=4194304` and `net.core.rmem_default=4194304` on **both guests**
before baseline/socket creation. This affects all new guest sockets; concurrent
foreign workloads are forbidden. This policy version fixes the sizes; another
experiment needs a new methodology. `wmem_*`, TUN queues and qdisc remain unchanged.
No iperf `-w`: it changes send/receive buffers at both endpoints. Original values
and policy are saved before the first mutation. Session/window guards reject
unexpected drift. `finally` restores both guests before lengthy protected-file
hashing; an independent guest lease stops owned traffic and rolls back buffers
after 180 seconds without controller heartbeat. Unknown foreign values are not
overwritten: restoration fails visibly. Nothing is persisted in `/etc/sysctl*`.
New baseline/reference runs must use the same policy. Independent observation
overhead has not yet been established.

Accounting reference: [Linux 6.12, net/core/sock.c](https://github.com/torvalds/linux/blob/v6.12/net/core/sock.c).
The effect of `-w` on both endpoints is documented in the [iperf3 manual](https://software.es.net/iperf/invoking.html).

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
# Harness pilot: 4 required profiles, TCP P4/UDP600, v4/v6 up/down, n=1,
# baseline before/after; 40 windows. NOT release admission/regression proof.
python -u scripts/release_short_test.py --config private-lab.json --tag buffers-pilot --output buffers-pilot.json --buffer-pilot
# Same limited workloads, n=3 plus n=3 baseline: 120 windows.
# Four-profile required-only performance reference, NOT full release admission.
python -u scripts/release_short_test.py --config private-lab.json --tag buffers-reference --output buffers-reference.json --buffer-reference
python scripts/release_short_report.py --config private-lab.json --result buffers-reference.json --output buffers-reference-summary.json
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

`--buffer-pilot` has its own method/qualification (`BUFFER_PILOT_ONLY`) and is also
rejected by the full-plan analyzer. Full coverage still requires three repetitions,
functional/compatibility checks and separate mixed. Legacy v1 may be analyzed
historically, but cannot earn new admission without buffer evidence.

`--buffer-reference` repeats the pilot workloads (TCP P4 and UDP600, 10+2 s,
IPv4/IPv6 up/down) using three fresh connections per core profile. Profile order
is forward, reverse, then rotated. This means 96 load windows and 24 direct TCP
P1 baseline windows (three per family/direction before and after).
Method `qeli-release-short-buffer-reference-v2` differs from the full plan.
`PERFORMANCE_REFERENCE_ACCEPTED` means only a limited performance reference:
all 32 cells have n=3, each CV <=5%, every UDP repetition has loss <=1%,
baseline CV/absolute drift <=5%, and buffers/restoration verified.
Instability yields `PERFORMANCE_REFERENCE_REVIEW_REQUIRED`; bad baseline yields
`INVALID_BASELINE`. Do not replace the initial set with better repetitions.
This scope omits tunneled P1, UDP300, all-12 checks, compatibility/mixed and
cannot earn LAB_COMPARISON_PASS/release admission; `--require-pass` rejects it.

Buffer-check pilot:
[method, SHA, results and VM300/301 restoration](../reports/RELEASE-SHORT-BUFFERS-PILOT-2026-10-31.md).

[Three repetitions on four profiles with n=3 baseline](../reports/RELEASE-SHORT-BUFFERS-REFERENCE-2026-10-31.md):
`PERFORMANCE_REFERENCE_REVIEW_REQUIRED`, not an accepted reference. Bad windows
had high CPU steal despite good before/after baseline; inspect it per window
rather than treating baseline as proof of uninterrupted CPU availability.

See the [0.8.0 matrix](../reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md),
[TUN queue](../reports/TUN-QUEUE-SIZE-2026-10-16.md),
[load studies](../reports/BENCHMARK.md).

[Pilot publication status](../reports/RELEASE-SHORT-PILOT-2026-10-16.md):
`PILOT_REVIEW_REQUIRED`, not an accepted reference or release qualification.
