# Q25-F110: TUN pump startup and early rollback on a joined worker

25 September 2026. Base `667920a3`. D05/D09, Linux.

## Defect and fix

After applying NetworkPlan, TCP and UDP called `LinuxTunPump::start` on the async thread.
This includes fcntl, buffer allocation and reader/writer creation. If the second thread
fails, startup joins the first; the following `?` then dropped the platform TunGuard on
the same async thread. A delayed route deletion stopped neighboring heartbeat work.
Recordizer/MTU and UDP budget validation could also return after platform mutation and
packet-worker startup.

Shared `start_linux_tun_pump` now takes TunGuard and both owned fds. The existing network
worker starts the pump, joins partially created threads on failure and rolls back the
guard before returning. A successful result transfers to the caller without awaiting
after adoption. If the future is lost, its original worker drops/joins the unadopted
pump before releasing the guard; returned tuple field order explicitly enforces this.

An inner startup error and a worker error are distinct results. Ordinary fcntl/thread
creation failure followed by successful cleanup is not reported as a cleanup failure.
Context/thread-spawn/panic failures are sticky `Resource::Transaction` failures;
DNS/routes/forwarding owners continue recording their own cleanup errors. Incomplete
cleanup therefore prevents reconnect and kill-switch release, including after stop.

Pure TCP MTU/recordizer and UDP record/control-budget/recordizer checks now run before
`prepare_tunnel`. Algorithms and limits are reused. These checks belong to shared client
TCP/UDP code; the new worker boundary is Linux-specific. No INI, wire-protocol or public
C ABI changes. NetworkPlan ACK and `post_up` retain their existing order before pump
startup; this phase does not change the full data-plane readiness contract.

## Validation

- **4 baseline + 8 fixed runtime scenarios**: TCP/UDP × fcntl/writer-creation failure;
  fixed additionally injects route-deletion failure during rollback and sends SIGTERM.
  Test-only LD_PRELOAD is applied only to private lab clients. The fcntl fault selects
  the actual TUN through TUNGETIFF after post_up; writer fault returns EAGAIN on the
  startup thread's second pthread_create while retaining its already started reader.
- Baseline heartbeat stays at **0** during held syscalls and route rollback; fixed
  produces **7–8** ticks in each approximately 800 ms interval. Before writer
  failure, `/proc/<pid>/task` contains the reader and no writer. Both packet workers are
  absent before route cleanup. With fcntl failure neither worker is created.
- All 12 competing starts fail with `cannot reserve TUN` during rollback. The original
  interface and IPv4/IPv6 DROP remain until cleanup completes. Injected failures retain
  `failed`/exit 1 and the original OS error.
- **4/4 cleanup faults** retain kill-switch and error after SIGTERM. **4/4 fresh explicit
  starts** recover remaining state and stop cleanly. Routes and operator firewall rules
  match the initial snapshot after successful cleanup/recovery; TUN is absent. Incomplete
  cleanup permits only routes observed in the active generation and preserves initial
  operator routes.
- **38/38 network cells**, 34 crash/recovery, 1220 main + 806 nested checks PASS.
  Both IPv4/IPv6 nft/legacy arrangements, including private firewalld:
  1088 denied UDP attempts blocked, 656 allowed probes received.
- **1564 host + 71 config; 2128 Linux + 47 privileged + 8 lifecycle PASS**. All 9 host/
  cross/feature/lint/format commands PASS; the existing Clippy `chunks_exact_to_as_chunks`
  allowance remains. RU/EN docs and diff are checked before commit. New regression
  coverage is the actual runtime fault scenario; existing Rust pump/network-worker
  tests were rerun successfully.

The full Linux suite and network matrix refer to v1. Final v2 changes only the short
error message (the OS cause is now visible in `last_error`) and the TunGuard comment.
`final-only.patch` and source comparison verify this boundary. V2 reruns all 9 host/cross
commands, the build, 8 lifecycle and 12 runtime scenarios including `last_error` checks.
Network algorithms did not change after the full run; the matrix is not attributed to
a different executable.

## Evidence and limits

Only lab `10.66.116.11` was used; working server `10.66.116.10` was untouched. Each cell
uses separate NET/mount/PID and private `/run`, `/var/lib`, `/var/log`, `/tmp`, `/etc/qeli`;
its client uses an additional NET namespace and veth. Linux 6.12.105+deb13/Rust 1.97;
Windows/Rust 1.98. The shim is compiled with `-Wall -Wextra -Werror`. Installed Qeli
and system libraries are not replaced.

`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/pump-start-phase/evidence.json`
verifies 351 source files, tar contents, shim source/binary, snapshots, errors, thread
lists, baseline/fixed hashes and matrix packet assertions. Jobs: `pump-start-linux-v1`,
`pump-start-linux-final-v2`, `pump-start-runtime-v1/v2`, `pump-start-matrix-v1`. Driver source
and Cargo.lock are retained in `pump-start-driver-evidence-v1/v2`. The matrix reuses 22 frozen
`udp-local-scripts-v1` scenarios with verified fixture hashes. Baseline is the frozen
heartbeat driver from the previous commit; its source manifest is retained.

Matrix/v1 worker `1af48032b2bca32b1ec5924ca01f79430177c02596b1410b525ddb6ef60d3b3a`.

Final/v2 worker `3e2cd6487e380eb225bc5d8cd2829b42a169e393fadcf5d4ef8e45f8a4e5787f`.

Fixed driver `a1756289c39dbebab52bf9e9510311e615f5f2af82d9a4c41dede142b598c085`.

Baseline driver `e2ecdd3e2f597f8f3059d313fa2583984818ebb6a526775c0b566eebf62c7e81`.

Test shim `98db0518ea1cf0e9acec3521c31552123d0c2e9b76defeebe999c7e5b4889562`.

**D05 remains IN_PROGRESS.** Forced Drop and inability to start a cleanup worker may
synchronously wait for rollback; the whole NetworkPlan/shutdown deadline remains open.
Other locks/I/O/diagnostics and early paths before this boundary still need inspection.
Recordizer-validation ordering was checked in code and existing tests; no malformed
remote-push injection was performed here. This is not a benchmark or D10 certification.
Windows VM, Mac/iOS and physical router remain SKIPPED by user decision; final Android
validation remains D12. Debt: 4/15 DONE, 9 IN_PROGRESS, 2 TODO.

25 September 2026 reconciliation: blocking client diagnostics writes are addressed in [Q25-F111](AUDIT-Q25-STATUS-WRITER.md). Other D05 limits remain.
