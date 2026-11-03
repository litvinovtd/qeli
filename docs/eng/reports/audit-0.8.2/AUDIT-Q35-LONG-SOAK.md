# Q35 — concurrent extended TCP and UDP roaming soak

<!-- normative-sync: audit-q35-long-soak-v1 -->

## 13 October: the complete current CLI gate passed

<!-- normative-sync: q35-current-full-endurance-20261013 -->

[Independent qualification and cleanup](../../../../release/certification/evidence/q35-current-endurance-20261013.json).
The declared full run of CLI `52511ceb` completed on .11 in 47,036.8 seconds,
about 13 h 4 min, passing all eight phases: 10,000 TCP cycles, 10,000 UDP QUIC
cycles, 1,000 each for UDP fake-TLS/obfs/obfs-awg, performance and cross-node.
There are 9,403 snapshots and 18,786 process observations; the largest sample
gap was 5.009 seconds. Declared RSS/fd/socket/thread budgets passed. The cgroup
memory peak was 274,624,512 bytes, swap peak zero and task peak 38; no OOM,
memory max/high or CPU throttling events were recorded.

Upload off/required medians were 511/495 Mbps, download 628/603 Mbps:
3.1311% and 3.9809% reductions, both below the unchanged 5% threshold.
Combined CPU passed as well. Cross-node passed 28 checks using two independent
server processes in separate network namespaces on one VM. This does not
claim handover between physical servers.

Both qualifier failures are retained. Bash dynamic scoping let an inner loop
overwrite the caller's phase marker. Qualification of the completed run
independently checked inner markers, completion boundaries and all adapter
ordering; the source now makes that variable local. Nine actual Bash cases
verify the fix and refusals for missing markers. The second failure concerned
different third-decimal CPU rounding in AWK and the decimal helper. The
qualifier accepts only adjacent floor/ceil values implied by the original
samples and evaluates the budget against the upper median. Thresholds and
samples were unchanged; throughput is checked exactly.

The archive and all inputs passed SHA verification. The owned root and remote
archive were removed; structural host state, services and production/staged
CLI were preserved. The previous 13-hour upload -6.8627% FAIL remains a FAIL
with its cause unestablished. This new PASS neither replaces those results
nor establishes the cause of their difference.

The full endurance debt is closed. Q35 still needs final mapping of its
fuzz/concurrency/DoS criteria to accumulated evidence and remains IN_PROGRESS.
This CLI is distinct from the separately qualified panel build `15c34473`.
The overall plan remains 32/37 (86.5%). `NO_PUSH_DEPLOY_RELEASE`.

On 10 October 2026, lab .11 ran two real VPN scenarios concurrently: TCP fake-TLS and UDP QUIC, with **900 route switches each**. Both finished without failures: respectively 16 and 17 scenario assertions passed. Total elapsed time was **1850.9 seconds**; 368 complete process snapshots show **1835.9 seconds** of simultaneous live VPN activity, exceeding the predeclared 1800-second minimum.

The scenarios ran in distinct network and PID namespaces inside an isolated environment, with separate directories and control sockets. Their checkpoints verified the working tunnel and route; TCP left no orphan sessions, while UDP left no candidates and retained three CID aliases. The collector sampled each transport's client and worker every five seconds, including stable process/config identity, RSS, threads, file descriptors and sockets. Maximum growth was **12,584 KiB RSS** (UDP client), **11 descriptors**, **2 sockets** and **3 threads**, within the declared 32-MiB, 16, 8 and 8 peak limits. Final descriptor growth was at most 4, socket growth at most 1, and thread growth at most 1. The scenarios' built-in resource checks also passed.

The run reused the previously qualified binary SHA256 `98335046d0c16b2126b22334102011ecfaff8390e0a3b09be5e6c7df87104bc2` and input archive SHA256 `89405cacf3923c8c8b4caccae701b0e6650d694250630cccd0e9a0034e977617`, overlaying seven current scripts with individual SHA checks. Production Qeli source has not changed since that qualification; no new Rust build is claimed here. Complete before/after host snapshots were retained and matched structurally after normalizing only packet and byte counters in built-in firewall chains. The service retained PIDs 777/845 and `/usr/bin/qeli` SHA. All 67 regular files from the test root were backed up with SHA verification; its owned directory was removed after process, descriptor and mount ownership checks. The initial CRLF `outer.sh` harness failure is preserved separately; it was fixed before VPN execution.

This qualifies 900 cycles and 30 minutes for these two transports, not the full 10,000/1,000-cycle release endurance, an eight-hour stress test, other adapters, or complete DoS coverage. Q35 remains `IN_PROGRESS`; the overall ledger is **30/37 DONE (81.1%)**, with seven sections open. Raw logs, samples, thresholds and cleanup proof reside in the local, out-of-Git packet `audit-debt-20260924/q35-long-soak-20261010`. `LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE`.

## Release endurance on 11–12 October: resource phases complete, performance gate FAIL

<!-- normative-sync: audit-q35-release-endurance-failed-perf-v1 -->

The next isolated run on lab .11 lasted **46,992.3 seconds (13 h 3 min)**.
It completed 10,000 TCP switches, 10,000 UDP QUIC switches, and 1,000 each for
UDP fake-TLS, obfs and obfs-awg. The five resource scenarios independently
verified 4,014 / 4,013 / 402 / 401 / 400 snapshots of stable client and worker
processes. RSS, threads, descriptors and sockets stayed within the predeclared
limits; maximum built-in RSS growth was 18,984 KiB against a 32-MiB budget.
Every archived file was SHA-verified, and the owned root and remote archive
were removed. Structural host state and production/staged binaries were preserved.

The overall release gate returned **FAIL** on phase seven of eight.
Negotiated TCP roaming produced a median upload rate of **475 Mbps versus
510 Mbps** for the roaming-off baseline: **6.8627%** lower against the unchanged
**5%** budget. Three upload results were baseline 510 / 513 / 445 and
roaming-required 475 / 487 / 409 Mbps. Download (597 versus 587 Mbps) and
combined CPU (159.962% versus 162.747%) passed their comparisons.
The cause of the upload decrease is not established. The budget was not changed,
and the failure remains preserved. The final cross-node phase did not run.
The completed resource scenarios do not need replay; neither full release PASS
nor Q35 closure is claimed.

The run used the previous qualified CLI SHA-256
`35da83fd0a727a31a93c4527f8c814777aabcc7ef48dd92e0a0de65f5cbc7050`
with this job's pinned inputs. It is not the new lazy wire-pool candidate and
does not establish whole-current-HEAD source equivalence. Raw results,
independent completed-prefix qualification, the original FAIL and cleanup
proof remain in the out-of-Git packet `audit-debt-20260924/q35-release-endurance-20261011`.
Q35 remains `IN_PROGRESS`; `NO_PUSH_DEPLOY_RELEASE`.

### 12 October: separate performance and cross-node verification

<!-- normative-sync: q35-bounded-performance-crossnode-20261012 -->

[Qualified results](../../../../release/certification/evidence/q35-bounded-performance-crossnode-20261012.json).
Lab .11 ran four predeclared independent checks: performance and cross-node
for the previous CLI `35da83fd` and current pool-fixed CLI `52511ceb`. Both
performance runs retained three 20-second rounds, the 5% threshold, the 2-CPU
limit and the upload/download/combined-CPU assertions. Receiver rates were
checked against raw iperf3 output separately by policy and direction, and medians
were independently recalculated. No measurement was excluded or replaced by a retry.

| Binary | Upload off / required, Mbps | Upload decrease | Download off / required, Mbps | CPU off / required, % | Performance: failed criteria | Cross-node |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| Previous CLI | 515 / 518 | -0.5825% | 626 / 620 | 159.921 / 160.140 | PASS: — | 28 PASS / 0 FAIL |
| CLI with pool fix | 515 / 538 | -4.4660% | 615 / 624 | 160.560 / 163.601 | PASS: — | 28 PASS / 0 FAIL |

Cross-node here means two independent server processes and registries in separate
network namespaces on one VM. Checks cover foreign-locator JOIN rejection,
primary-carrier loss, fallback to full AUTH, a new address and traffic through
the secondary process. This does not certify physical-server failover.

The original 13-hour release gate remains FAIL: upload decreased 6.8627%
against a 5% limit. Comparing off/required on one binary does not measure a
regression between software versions. The old failure's cause is not established;
these checks do not prove an effect from the pool fix or background load. The five
completed resource scenarios were not repeated and belong to the previous SHA.
This packet does not certify a full 8-hour release gate on the current CLI.

Every input and retained file was SHA-verified; observed processes ran in private
mount/net/PID namespaces. Services, PID/start ticks/binaries and staged CLI were
preserved. The owned root, remote archive and transient unit were cleaned.
Full structural comparison across all host backends passed.
Q35 remains IN_PROGRESS; the ledger remains 31/37 (83.8%), six sections open.
Full release and hosted CI are not certified. `NO_PUSH_DEPLOY_RELEASE`.

### 12 October: Q35 performance measurement order

<!-- normative-sync: q35-performance-order-20261012 -->

[Raw results and independent qualification](../../../../release/certification/evidence/q35-performance-order-20261012.json).
Lab .11 executed four predeclared measurements on previous CLI `35da83fd`,
ordered off → required → required → off. Each policy retains three 20-second
rounds, the unchanged 5% budget and CPUQuota 200%. All four functional cases
passed (44 assertions). These are order diagnostics, not a new full release gate.

| Order | Policy | Upload Mbps | Download Mbps | CPU % | Host steal % |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | off | 511 | 633 | 159.861 | 0.004 |
| 2 | required | 513 | 635 | 159.519 | 0.008 |
| 3 | required | 527 | 630 | 161.851 | 0.008 |
| 4 | off | 524 | 632 | 161.849 | 0.004 |

- off-first / required-second: upload -0.3914%, download -0.3160%; gates {"upload": true, "download": true, "cpu": true}; PASS.
- off-last / required-third: upload -0.5725%, download 0.3165%; gates {"upload": true, "download": true, "cpu": true}; PASS.

All 24 iperf3 receiver results were independently checked, and medians and both
comparisons recalculated. Observations retain host CPU steal, PSI, memory and
cgroup with available raw counters. The private sysfs mount does not expose a
cgroup filesystem: all cgroup observations are empty. Quota throttling and memory
cgroup events were not measured. Every input and retained file was SHA-verified;
private namespaces were confirmed. Full host comparisons passed before/after/after
cleanup; production services and staged CLI remained intact. The owned root,
remote archive and transient unit were removed.

In the original 13-hour run, both performance policies used fresh process pairs;
their PID/start ticks do not overlap the resource prefix in 9395 snapshots.
The performance helpers are unchanged. Thus the 6.8627% FAIL does not demonstrate
degradation of the same long-lived VPN session. The original observer retained no
host CPU steal/PSI/cgroup telemetry; this short diagnostic cannot reconstruct those
conditions. Even different forward/reverse comparisons cannot establish the
historical failure's cause. The budget and original failure remain intact;
root cause is NOT_ESTABLISHED. The 13-hour resource prefix was not replayed.

Q35 remains IN_PROGRESS; the current CLI's full eight-hour gate is not certified.
The ledger stays 31/37 (83.8%), with six sections open. `NO_PUSH_DEPLOY_RELEASE`.
