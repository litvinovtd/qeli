# Q34/Q25 — memory across 100 release handovers

<!-- normative-sync: audit-q34-release-soak-v5 -->
Historical24September checkpoint: debt statuses below refer to that date. The current [ledger](../../plans/AUDIT-DEBT.md) includes later closures; the new Q35 scope is recorded at the end.


24 September 2026. Rust 1.97.0, Linux x86_64, `release --features jemalloc`;
core sources match `ea87fd49`. This is developer integration, not final 0.8.2
certification, a throughput benchmark or A/B reproducibility.

## Measurements

100 TCP fake-tls and 100 UDP quic-shape handovers, sampled every 10 switches.
Both scenarios: **15/15 assertions PASS**, **30/30** total; exit codes `0/0`.
One authenticated session, original processes and TUN, connectivity, exactly
100 client/server COMMITs and one exact carrier bypass were preserved.

| Transport / process | RSS baseline → final, KiB | Final / sampled peak growth, KiB | fd baseline → final | socket fd baseline → final |
|---|---:|---:|---:|---:|
| TCP client | 47736 → 49496 | 1760 / 1904 | 15 → 15 | 5 → 5 |
| TCP server | 53644 → 56036 | 2392 / 2392 | 18 → 18 | 6 → 6 |
| UDP client | 49592 → 50292 | 700 / 3764 | 15 → 16 | 5 → 6 |
| UDP server | 61668 → 74248 | 12580 / 12580 | 18 → 18 | 6 → 6 |

UDP retains one additional client socket, stable from the first sample to the end;
this is not zero growth. Pending candidate=0 and CID aliases=3 after handover;
TCP orphan=0. The existing **32768 KiB RSS growth criterion is unchanged**.
Scripts now print baseline, final and sampled peak deltas, retaining the inputs.
Bash syntax and 6 Python harness tests PASS.

The [previous debug FAIL](AUDIT-Q34-LINUX-MATRIX.md) remains in the evidence.
Debug and this release differ in allocator/build profile and source revision;
this result does not isolate the cause of the earlier growth or turn that result
into PASS. It confirms the criterion for this measured release executable.

## Reproducibility and remaining scope

Worker SHA256: `93ee5dce2fc0e1066d7a1c5943b02dfaca608c1bee67323cabd6e9b52dc3b027`.
Source archive: `4ac2dbae65e440b872ff4a15222e12e60927c238d955ce02872fd448ff12d3a7`
(320 files; includes gateway fix, excludes the subsequent route deadline fix).
Lab `.11`, private net/mount/PID namespaces; server `.10` unchanged.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`:
`release-gateway.log`, `roaming-release-soak-100/` with TCP/UDP logs, rc, executed
scripts and worker SHA; `packet-matrix-phase/roaming-scripts-measured-sha256.json`,
`harness-checks/` and `release-soak-phase/evidence.json`.

D13 stays IN_PROGRESS: stop/reconnect, failure/multiprofile cases, before/after
threads/tasks, routes/firewall/journals and final-source measurements remain.
D11/D12/D14 are also open. Windows VM/Mac/iOS/router runtime is skipped by user
decision. [Register](../../plans/AUDIT-DEBT.md).

## Q35: soak admission, 10 October 2026

F506 / Q35-F003: positive-integer validation accepted00/000/08/0100 and arbitrarily
large digit strings. Bash treats these differently in test and arithmetic. The
exact prior TCP helper with iterations=00 skipped its loop and passed8final
resource checks. The fixture used the current Bash process's actual /proc and
controlled ip/control-counter/worker-selector replies; it claims no real VPN
migration. The zero-loop false admission was reproduced by executing the original
helper, not by copying its condition.

The common scripts/roaming_soak_parameters.sh now requires canonical decimal
integers1..2147483647, without leading zeros, signs, whitespace or overflow;
sample_every cannot exceed iterations. TCP/UDP helpers and three wrappers share
the validation. Both primary netns runners validate soak parameters before
mktemp, cleanup or any network command. Standalone case helpers also validate;
a missing common helper returns/exits2. Defaults are unchanged.

F507 / Q35-F004: the old UDP matrix reported full
ROAMING_UDP_RESOURCE_SOAK_MATRIX_PASS after17QUIC/3adapter switches; the overall
endurance wrapper reported TCP_10K_PASS with100TCP. Actual previous Bash wrappers
with controlled successful child receipts reproduced this; no complete VPN run
is claimed. Standalone UDP now reports qualification and actual iteration/sample
counts and emits *_SMOKE if QUIC<10000 or adapters<1000. Successful standalone
smoke still exits0 but cannot emit *_PASS. Sufficient counts and successful
children retain the existing endurance PASS markers. Child failure stops later
modes.

roaming_resource_release_gate.sh is the full endurance gate: before its first
phase, it refuses TCP/QUIC<10000, adapters<1000 and invalid sampling intervals.
The separate mandatory linux_roaming_release_soak.sh retains minimum100 for
TCP/UDP QUIC, sample_every=iterations/10 and existing strict assertions. Extra
CLI arguments are refused; executable paths with spaces are quoted for version
probing. This correction does not substitute a10k requirement for the agreed
bounded release gate.

28Linux methods without skips:14new admission,4UDP wrapper,4endurance wrapper,
4worker identity and2control stats. Actual Bash/Python/proc/filesystems with
controlled network/child/counter seams. Cases cover minimum/boundary/overflow,
pre-network parent/helper refusal, missing helper, smoke/full labels, bounded100
dispatch, child failures and existing SHA/order guards.57Windows methods:
8IPv6 matrix contracts,38native recipes,11workflow checks; shell suites are not
claimed as Windows PASS. Pinned actionlint accepts4workflows; the three admission
suites now run in CI. All transferred Bash scripts pass syntax checks.

Lab.11 used an owned temporary root; source TAR and20inputs read back exact/SHA;
21known files removed after exact-set/SHA/process/fd/mount guards. Service777/845
and CLI75bc preserved; .10unused. Initial patch generator had an IndentationError
before writing/connecting; corrected. No new100/10k,30–60min/8h VPN-soak, peak
between samples, task churn or current hosted CI was executed. Prior core/native/
runtime results retain their scope; core,14native,e3fb digest,protected/OpenWrt
cut unchanged. Q34/Q35IN_PROGRESS,Q36TODO;30/37DONE81.1percent,7remain.
Q29SIGKILL/ENONET,Q30/Q31,F459,D06accepted/USER_EXCLUDED retained.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F506-F507 evidence: q35-soak-admission-20261010; SEALED 38 files / 1646848 bytes; manifest SHA256 c3feba0ad1c0e010693765f4142a3011a88ac17afa0ef13f9089b38166109f75.

## Q35: concurrent netns runner isolation, 10 October 2026

F508 / Q35-F005: both TCP/UDP runners used fixed namespace names and destroyed
preexisting processes during initial cleanup. UDP family-switch also changed
shared `/etc/netns/qru-cli/hosts`. Exact previous cleanup was executed inside an
independently isolated outer fixture: both runners really killed preexisting
sentinels and removed their namespaces. Host production processes were excluded
from this reproduction.

Each invocation now creates separate network/mount/PID namespaces before mktemp,
cleanup or network actions. Shared `roaming_netns_isolation.sh` verifies namespace
identities, breaks mount propagation, and creates private `/run`, an overlay view
of `/etc`, and `/sys`. Fixed veth names, the namespace registry and family-switch
hosts files belong to that run. Wrappers calling these runners inherit isolation.
Missing helpers/supervisor, denied privileges, failed unshare or mounts refuse
before mutable runner setup; there is no unsafe fallback or environment opt-out.

`roaming_netns_supervisor.py` preserves exit status and handles SIGINT, SIGTERM,
and supervisor death. Parent-death SIGKILL chains through unshare/private PID
init to all descendants. The first unshare-only prototype failed the actual
SIGTERM test; a subsequent handler reentering Popen.wait deadlocked on its lock.
Both prototypes were corrected before commit: the signal unwinds wait, and
kill/wait occur afterward. Failed attempts and initial incomplete upload lists
remain in evidence.

Verification: 7 actual Linux kernel methods cover parallel identical names/veth,
private hosts, neighboring sentinels, exit37, actual EPERM, controlled overlay
failure and SIGINT/SIGTERM/SIGKILL without descendants; 35 Linux script methods
(7 new + 28 dependent), no skips. Kernel execution is real; fixture processes
are controlled and no Qeli binary/VPN traffic was executed in this block. No
new100/10k/30min/8h VPN soak claim. Unchanged core/native execution is inherited
with SHA checks.

On .11, service PID777/845/CLI SHA75bc, routes, links, firewall rule structure,
sysctl, resolver/hosts and mounts were preserved. Only live builtin NAT-chain
packet/byte counters differed; structural comparison normalizes only those
counters, retaining raw snapshots/diff. Exact source/TAR readback and guarded
owned-root cleanup passed; absence confirmed. .10 unused; no compiler/SDK caches.

Q34/Q35 IN_PROGRESS,Q36TODO;30/37DONE81.1percent,7remain. Harness isolation is
closed; wholeQ35 is not complete. Q29SIGKILL/ENONET,Q30/Q31,F459,D06 accepted
limitation and USER_EXCLUDED remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F508 evidence: q35-isolation-20261010; SEALED 48 files / 3037712 bytes; manifest SHA256 cf6b60799473f333c870bd94b412462b9abac406cee18c6ff92c9b4710f3cd83.

## Q35: actual bounded soak after runner isolation, 10 October 2026

Q35-V001 qualifies the updated runners with a real VPN:
`linux_roaming_release_soak.sh` executed100 TCP fake-tls and100 QUIC handovers,
sample_every=10. Total duration **440.95 seconds**, exit0; TCP **16/16** and
QUIC **17/17** assertions PASS. Current scripts from
`5d9e792ce4d6e6d2c2635e3cb5c0cdd3ed5c99f1` include mandatory F508 isolation.
An independent outer isolation and timeout480s bounded the actual test.

The previously compiled Linux x86_64 release0.8.2 default server/client+jemalloc
ELF was executed, SHA256
`98335046d0c16b2126b22334102011ecfaff8390e0a3b09be5e6c7df87104bc2`.
All **318 effective Cargo/src compiler inputs** are byte-identical to current
Git. Original build source TAR SHA256
`4e9718ca2bec0434796e1b97eb67eecbdde386f02af381ad281676bab3bd955c`.
Broader qeli-tree differences are limited to the independent fuzz Cargo.lock/
README excluded by the actual Docker compiler COPY recipe. This reuses an
actual qualified executable; no new build of the current Docker recipe is
claimed. No new native/SDK caches were created.

| Process | RSS baseline → final, KiB | Final / sampled peak growth, KiB | fd baseline → final | socket fd baseline → final |
|---|---:|---:|---:|---:|
| TCP client | 50192 → 52556 | 2364 / 2660 | 18 → 18 | 6 → 6 |
| TCP server | 58520 → 63184 | 4664 / 4664 | 21 → 21 | 7 → 7 |
| QUIC client | 56324 → 56932 | 608 / 3232 | 18 → 19 | 6 → 7 |
| QUIC server | 66560 → 73932 | 7372 / 8924 | 21 → 21 | 7 → 7 |

The RSS32768KiB threshold is unchanged. One additional client QUIC socket
remained stable after the first sample. A single authenticated session,
original client/server workers and TUN, tunnel connectivity and exact carrier
bypass were retained; each client/server committed exactly100 transactions.
TCP orphan/grace/failure=0; QUIC candidates=0,CID aliases=3. Reverse-path
filters were restored and sysctl leases released.

The initial SSH launch channel timed out while a background shell group kept
its descriptors open. The actual job continued under its own deadline, as
independent read-only polls confirmed. It was not relaunched. A collector
expected-label error (missing TCP /single) was corrected from the retained
log before cleanup. Both failures and initial source-binding refusals remain
in evidence; they are not reported as VPN failures.

All64 exact regular files were SHA checked before deletion; original inputs
are retained in the local TAR and all generated regular files backed up
separately. One stale Unix socket was classified via lstat, then removed only
after process/cwd/exe/root/fd/argv and mount owner guards. Root absence was
independently confirmed. Service PID777/845/CLI SHA75bc, routes, links,
firewall rules, sysctl, hosts/resolver and mounts were preserved. Only builtin
NAT-chain packet/byte counters changed; raw snapshots/diff are retained and
structural comparison normalizes only builtin counters. .10 unused; host
service and packages unchanged.

**Limits:**200 actual handovers and33 assertions over7m21s, sampling every10.
Unsampled peaks, tasks/threads churn,10k endurance,30–60min/8h, other adapters
and throughput benchmarks are not qualified here. Q35 remains IN_PROGRESS;
overall30/37DONE(81.1%),7sections remain. Existing Q29/Q30/Q31/F459/D06 and
USER_EXCLUDED limitations remain. No product implementation changes in this
block.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Q35-V001 evidence: q35-runtime-isolation-20261010; SEALED 68 files / 15738597 bytes; manifest SHA256 02427686f08ea2ce22fcdfea86f3f52c5af979101d9d0a015ef93874a33722a2.

## Q35: faults, concurrency and short control sockets, 10 October 2026

F509 / Q35-F006: TCP/UDP runner control sockets depended on WORK/TMPDIR length.
With a deep directory, the family-switch server worker actually exited with
`path must be shorter than SUN_LEN`; the initial session never authenticated.
Original failure and respawn/client logs are retained. This is a Unix address
length limit, not an IPv6 handover or authentication defect. The runner now uses
`/run/qeli-roaming-control/control.sock` and separate `control-secondary.sock`.
The mode0700 directory is created after mounting private /run tmpfs, so fixed
short names belong to one run. TCP/UDP soak counters and bonding bandwidth/revoke
consumers share the same path. Logs remain under requested TMPDIR; no core or
user INI changes.

Actual release ELF SHA98335046 (318exact Cargo/src compiler inputs, as Q35-V001)
executed **14 cases / 320 assertions**, zero failures, over**331.95s**,
in7pairs with max2concurrent cases. Each pair has a live /proc snapshot of two
authenticated client/worker groups in different PID namespaces. The repeat uses
even deeper WORK paths, including family-switch. No native/SDK builds. Original
input archive is reused with SHA verification; no new local binary/14MB TAR copy.
Changed script bytes were separately qualified.

| Case execution | PASS assertions | FAIL |
|---|---:|---:|
| tcp-success-a | 20 | 0 |
| tcp-success-b | 20 | 0 |
| tcp-resume | 20 | 0 |
| udp-rollback | 23 | 0 |
| tcp-grace-expiry | 19 | 0 |
| udp-commit-race | 28 | 0 |
| tcp-starvation | 19 | 0 |
| udp-supersede | 28 | 0 |
| udp-family-switch | 35 | 0 |
| udp-loss-replay | 21 | 0 |
| tcp-soak-smoke | 16 | 0 |
| udp-soak-smoke | 17 | 0 |
| tcp-bonding | 26 | 0 |
| tcp-multinode | 28 | 0 |

Soak here is **3flips/sample1** each for TCP/QUIC control consumers; no new
bounded100 or full10k endorsement. Bonding exercises real bandwidth/revoke API;
multinode exercises the secondary service/socket. Other cases exercise TCP
reset/resume, full AUTH after grace expiry, carrier starvation, UDP rollback/
supersede/platform commit race, lost challenge/commit retry/replay and two
IPv4↔IPv6 family commits. Seven real kernel methods cover isolation and two
simultaneous Unix listeners sharing a short path;35Linux script methods, no
skips. Unchanged core/native/CI execution is inherited with SHA checks;
documentation passes9checks.

The initial external observer only recognized TCP `connected on profile`,
missing UDP `authenticated on profile`. Both actual markers are now recognized.
Initial execution retains9successful cases, family-switch SUN_LEN/timeout and
exit1; it is not rewritten as PASS. An early read-only retry refused before any
changes because the first job was unfinished. After fixes, all14cases and
7concurrent snapshots passed. External observer issues remain distinct from
F509 in the runner sources. All original logs are retained.

Generated owned files were retained before exact-set/type/SHA/proc/fd/argv/mount
checks and cleanup; root absence confirmed. Production service777/845/CLI75bc,
routes, links, firewall rules, sysctl, mounts and hosts/resolver preserved.
Only builtin packet/byte counters normalized for structural comparison;
raw snapshots/diff retained. .10unused; host packages unchanged.

Q35 remains IN_PROGRESS:14executions do not qualify failure injection at every
acquire/apply/save,30–60min/8h,10k, unsampled RSS/tasks peaks or whole DoS/fuzz
coverage. Overall30/37DONE81.1%,7sections remain;Q29/Q30/Q31/F459/D06 and
USER_EXCLUDED limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

F509 evidence: q35-fault-concurrency-20261010; SEALED 486 files / 2884066 bytes; manifest SHA256 bbc5177343dd68a617e36a48929f6afd9b3dfd6d103329e4fc30ab0feb285c6a.
