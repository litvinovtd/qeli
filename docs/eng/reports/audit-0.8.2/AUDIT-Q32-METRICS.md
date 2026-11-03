# Q32: metrics across missing samples and worker changes

<!-- normative-sync: q32-metrics-v2 -->

October 7–8, 2026. F380–F383 fix dashboard values in `qeli/src/server/metrics.rs`.
Q32 remains IN_PROGRESS: this packet covers metrics, not all usage/logs/notify.

## F380 / Q32-F002: false throughput spike after a control failure

An unavailable `list-clients` became `(0,0,0)` and was saved as a valid previous
sample. Recovery treated the entire cumulative value as one interval of traffic.
A real private Unix socket reproduces a false 16002 Mbps upload on the old source.

Missing replies now invalidate the baseline. The first valid reply after a gap
warms up; the next provides the normal rate. A genuinely empty client list is a
valid zero. The API shape is unchanged: client count and throughput still show
zero for missing data. No availability indicator or lost-interval reconstruction
is added. Aggregated byte counters use checked addition instead of panic/wrap.

## F381 / Q32-F003: CPU accounting and counter resets

Summing every `/proc/stat` column counted guest/guest_nice twice. The kernel already
includes them in user/nice: [Linux account_guest_time](https://github.com/torvalds/linux/blob/master/kernel/sched/cputime.c).
Only the first eight columns now contribute to the total. The old fixture gave
busy/total 260/1070 instead of 190/1000. Invalid fields fail parsing rather than
shifting later columns, and parser arithmetic checks overflow.

Unchecked busy subtraction could panic in debug or wrap in release after a reset.
A synthetic reset reproduced a panic in the original sampler. This interval now
reports zero; host CPU is bounded to 100% for inconsistent deltas.
[iowait can decrease](https://docs.kernel.org/filesystems/proc.html), so individual
samples are not guaranteed to provide an exact CPU delta.

## F382 / Q32-F004: worker CPU across process identities

The previous `utime+stime` was compared with a new process if its counter happened
to be large enough. Comparison now requires both PID and field-22 starttime from
`/proc/PID/stat`, including PID reuse. New workers, missing samples and decreasing
process counters warm up with zero. The top(1) scale, one saturated core = 100%,
is preserved. RSS remains best effort; tick addition/page multiplication is checked.


## F383: the sysctl fixture must not equal the test PID

A full Linux run passed2421 methods and exposed three failures in the existing
namespace fixture. Its mock treats PID42 as dead but reports starttime100 for
its own PID. A controlled old-binary execution at actual PID42 reproduces all
three failures (33/36PASS); at PID43 all36PASS. The fixture now uses valid
`i32::MAX`, distinct from the test process. Only cfg(test) data changes; production
sysctl recovery is unchanged. The initial fork-count error (actualPID44) is retained
as invalid preparation. The corrected PID42 repeat and full suite are in evidence.

The first full-crate compile also found an incorrect control_io namespace import
in the new test. The fixture now receives requests with a regular BufReader and
writes replies with Tokio; the sampler calls the actual production control client.
Preparation errors and intermediate native snapshots are retained. Actual A/B
commands qualify the final source digest; old records are not relabeled as new
builds. Desktop passA can reuse its own partial cache after an interrupted attempt;
passB uses a separate target/cache. Native functions/profiles are unchanged;
no cold/hermetic build claim. Mac cross-build xcrun/SDK warnings are retained.

## Validation and limits

Three reproductions fail as expected on the old source in a small Linux harness.
Only CPU fixture reading and an explicit private socket path are adapted; product
wire framing and send_command are used. This is not a full daemon build.

Eight patched-module tests pass: seven new and one existing. They exercise actual
Unix disconnect/recovery, normal traffic and real zero, guest/old four-column
format, malformed fields/overflow, resets/iowait, PID/starttime/counter resets,
actual current-process procfs and process-owned sockets. A repeat as UID/GID65534 also passes 8/8 without privileged operations.
The first after run reused
a stale harness binary through a shared target and is not qualification; the final
run uses its own target directory.

Final:2424 library PASS,60preexisting ignored;strict all-targets Clippy with
transport-core-ffi/client-bin and debug daemon PASS.36namespace atPID42PASS.
All four native artifacts have independentA/B and complete exports;both macOS
ADHOC signatures/load commands PASS.WindowsABI22 and AndroidARTJNI23 use the
exact final bytes;originalAVDuserdata/host preserved.14SHA entries/current
native provenance PASS.Only two source files transferred for corrected snapshot;
other315 verified before,all317 after transfer and after builds.Seven generated roots and a separate target directory removed after Git archives/8A-B binaries/daemon/test binaries/DEX/log
backups and process/mount guards.Running services and lab network policy preserved.

Full Linux qualification and genuine independent native A/B are recorded in
[machine evidence](../../../../release/certification/evidence/q32-metrics-20261007.json).
Native build functions remain unchanged; the harness overrides private source,
output and offline-cache paths. This is not a new ABI or platform VPN E2E.

Metrics still sum **live** sessions: a departing session can reduce the aggregate
and understate rates. Exact final-packet accounting, quotas and crash recovery
belong to the remaining usage review. Next: usage fold/reset/flush/corrupt store,
trace/log endpoints and notify trust/SSRF. Q29 SIGKILL/ENONET, Q30 callback drain/
Apple, remaining Q31 and D06 ACCEPTED_LIMITATION are unchanged. Overall:28/37 DONE.
