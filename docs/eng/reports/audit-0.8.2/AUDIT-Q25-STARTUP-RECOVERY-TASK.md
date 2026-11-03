# Q25-F109: startup recovery on a joined worker

25 September 2026. Base `5fbfde6e`. D05/D09, Linux.

## Defect and change

After reading credentials, `run_client_inner` synchronously reserved its namespace,
recovered physical-route journals and inspected DNS markers. Waiting for the real route
journal flock blocked a current-thread executor: heartbeat and SIGTERM handling could
not run until recovery completed. Per-command budgets did not resolve this blocking.

TUN/kill-switch lease admission, route recovery and DNS recovery now run on one owning
worker through the existing `network_task::prepared`. A ready stop prevents admission.
Once admitted, work is joined through its actual result: stop cannot release the lease
prematurely or replace an error with successful cancellation. A successful lease transfers
to the caller and retains its existing lifetime across reconnect/cleanup. Failure or a
rejected result releases it on the worker. The shared helper inherits and verifies
NET/mount context; forced Drop joins the thread.

A stop received during successful recovery returns before configuring hooks/firewall
or starting another connection. Journal, DNS and deadline errors retain `failed` and
exit 1. Ordering remains routes → DNS. `dev_attach = true` skips route recovery but
still checks DNS. Startup still never mutates a live resolver solely from a saved
marker. No duplicate recovery algorithm, new INI fields or public C ABI changes.

## Validation

- 3 new Linux regressions: real namespace lease retained after stop and transferred
  to the caller; late error retained with lease release; forced Drop joins before
  releasing the lease. Existing pre-stop, namespace, panic and cancellation tests for
  the shared helper remain in the full run.
- 2 baseline + 6 fixed real-client scenarios on a current-thread runtime. The real
  `client-routes.state.lock` is held and SIGTERM sent. Baseline produced 0 heartbeat
  ticks; fixed produced 7–8 in each approximately 800 ms interval before/after stop.
  The process remains alive until recovery finishes; competing starts are rejected.
  Both the TUN claim and shared kill-switch claim with a different TUN name are tested.
  The baseline without kill-switch also delivered 6 UDP packets to the server listener
  after lock release despite earlier SIGTERM; fixed delivered 0.
- Fixed scenarios: clean stop with/without kill-switch, malformed route journal, legacy
  DNS refusal after stop, the 15-second lock deadline, attach with a locked malformed
  route journal. Attach reaches DNS refusal without waiting for the route lock.
  Every fixed listener received **0** handshake packets; successful stops retained
  `stopped`/0, faults retained `failed`/1. Namespace claims were free after exit.
- DNS: only the stale absent-ifindex marker was retired in clean scenarios; live, busy,
  foreign and legacy markers remained byte-identical. Malformed/legacy evidence stayed.
  Routes, operator IPv4/IPv6 firewall rules, interfaces and resolver matched before/after.
- 38/38 hostname network cells, 34 crash/recovery, 1220 main + 806 nested checks
  PASS. Both IPv4/IPv6 nft/legacy arrangements, including private firewalld:
  1088 denied UDP attempts blocked, 656 allowed probes received.
- Final snapshot: **1564 host + 71 config; 2128 Linux + 47 privileged + 8 lifecycle PASS**.
  All 9 host/cross/feature/lint/format commands PASS. The existing Clippy
  `chunks_exact_to_as_chunks` allowance remains. RU/EN docs and `git diff --check`
  are verified separately.

## Evidence and limits

Only lab `10.66.116.11` was used; working server `10.66.116.10` was untouched. Runtime
uses separate NET/mount/PID and private `/etc`, `/var/lib`, `/run`, `/var/log`, `/tmp`.
Linux 6.12.105+deb13, Rust 1.97; host Windows/Rust 1.98. The new recovery scenario
needs no installed services or external network.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`.
`startup-recovery-phase/evidence.json` verifies 351 source files, the archive, binary
hashes, runtime results, snapshots and matrix packet assertions.
`audit_startup_recovery.py` retains commands, INI, status, logs, heartbeat and DNS-evidence
hashes. The matrix reuses the frozen 22 scenarios in `udp-local-scripts-v1`; fixture
hashes are compared with the previous run. Driver source/Cargo.lock and baseline source
manifest are retained separately.

- Worker: `ab51edd03b9b9a4428ea2c72a2f89089bfd186bfa88ca2df55d79476f5792960`.
- Fixed heartbeat driver: `e2ecdd3e2f597f8f3059d313fa2583984818ebb6a526775c0b566eebf62c7e81`.
- Baseline heartbeat driver (`5fbfde6e`): `4ec30901b504400418a04757291806ff20aba6bcf0ad189964e46679299191ab`.
- Final jobs: `startup-recovery-linux-v2`, `startup-recovery-runtime-v2`,
  `startup-recovery-matrix-v1`; all exit 0. Exit 1 inside fault scenarios is expected.

The first host run remains **FAIL**: new Linux lease tests lacked platform cfg gates.
The `linux + client` restriction fixes this; the rerun passes. Original log/checks remain.
Linux-v1 passed before this test correction; final evidence refers to v2.
Runtime-v1 remains **FAIL** before client start: private `/etc` hid iptables alternatives.
The fixture now pins executables before mounting; corrected runtime-v2 is retained separately.

**D05 remains IN_PROGRESS.** Early error/Drop paths, remaining synchronous locks/I/O/
diagnostics and whole NetworkPlan/shutdown deadlines remain open. A route budget cannot
bound an arbitrary stuck syscall. Forced Drop may synchronously join the worker.
DNS filesystem/kernel stalls were not separately injected. This is neither a benchmark
nor certification of the full D10 matrix. Windows VM, Mac/iOS and physical router are
SKIPPED by user decision; the final Android snapshot remains pending.
Debt: 4/15 DONE, 9 IN_PROGRESS, 2 TODO.

Reconciled after Q25-F110: Linux TUN pump startup and its early rollback now use a joined worker; pure recordizer/budget checks precede platform apply. Other D05 boundaries remain. [Report](AUDIT-Q25-PUMP-START.md).
