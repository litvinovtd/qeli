# Q25-F114: owned TOFU worker, handshake cancellation and late errors

25 September 2026. Baseline `c5cd6526`. D05/D09, Linux.

## Change

After F112/F113, file-backed TOFU still ran synchronously inside an async identity
callback. Flock, read and fsync stalled a current-thread runtime: heartbeat, stop signals
and handshake timers could not progress until the syscall returned.

A Linux client without an explicit `key` now owns one `qeli-identity` thread for its run.
The worker inherits the original client OS context. A semaphore admits one verification
at a time and retains its permit until the caller consumes the result or an abandoned
response records its error. No file I/O runs under the queue mutex. Cancellation while
waiting for admission queues no request and changes no file. Trust results are not cached:
every admitted request uses the normal known_hosts checks again.

A handshake may stop waiting on cancellation or `timeout`. TOFU waiting uses
`connection_timeout_secs` for both TCP and UDP; the outer TCP handshake timer remains.
Admitted file work remains owned by the client. Before reconnect, egress release and
final return, the client asynchronously waits for its outcome. A successful pin may be
persisted after timeout/stop; that does not authorize the cancelled handshake to create a tunnel.

An abandoned response retains the first unread error, including a result already sent
through a oneshot but never polled. Evidence is capped at 2048 characters. Late trust or
persistence failure terminates the run before reconnect and cannot become successful
SIGTERM. Network resources use normal cleanup; a trust error alone is not a firewall
cleanup failure. Terminal diagnostics are published after joining the worker. Normally
consumed errors follow existing reconnect policy and are not reported twice.

Explicit `key` verification stays in memory, with no TOFU worker or known_hosts access.
INI, wire protocol, public C ABI and other platforms' native adapters are unchanged.

## Validation

- **9 new portable regressions** cover cancelled admission, responsive timeout, late and
  delivered-but-unobserved errors, single reporting of observed errors, serialized/cancelled
  waiting requests, resumable finish, admitted stop, panic and joined forced Drop.
- **16 native cases, 8 baseline + 8 fixed**: TCP/UDP × stop/timeout × successful/failing
  fsync. A C shim holds real TOFU file-fsync until explicit release. Until release, the
  original store is unchanged, the process stays alive and post_up has not run. Baseline
  records 0 heartbeat ticks; fixed records **5 in 500 ms** and
  **12 in the next 1.2 s**. Fixed starts no tunnel after cancellation;
  late fsync errors yield exit 1/`failed`. Timeout-fault with `reconnect = true` terminates
  after one admitted write. Successful-fsync stop yields exit 0/`stopped`. Every case
  verifies original routes/firewall and absence of qnt0 after completion.
- **16 F112/F113 file cases** were rerun: corrupt TOFU with both allow_unpinned_tofu values,
  device-id locking and preservation of the old store on fsync failure.
- **6 established TCP/UDP teardown cases + 2 recoveries** verify successful TOFU,
  a working tunnel, stop and recovery after cleanup failure.
- **1584 host + 71 config; 2157 Linux + 48 privileged + 8 lifecycle PASS**.
  All 9 host/cross/feature/lint/format commands PASS; RU/EN docs and staged diff are checked.

## Evidence and limits

Only `10.66.116.11`, private NET/mount/PID namespaces and state paths. Working server
`10.66.116.10` and installed services were unchanged. Windows/Rust 1.98, Linux/Rust 1.97.
The first Linux job stopped before compilation because the source guard detected the old
manifest; its FAIL is retained and the manifest corrected. Final job:
`identity-worker-linux-v2`. The first host run is retained; checks were repeated after
making one test independent of scheduler timing.

`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/identity-worker-phase/evidence.json`
verifies 358 sources, tar, hashes and all 38 native cases plus 2 recoveries.

Worker `c53dec6b253a144c6bca41e0dcde97e18527c9add13a0c7c917f90b07fa83c97`.

Fixed driver `6e97d3dbe0b85030ab7932a1f87a2c7ade292392566a24f7eb4f1cef5fb6adf8`.

Baseline driver `b6b518fe033e731832eab3bb18a62ecd37bca3f5e8da17940bdf11016d3289e7`.

**D05 remains IN_PROGRESS.** Timeout stops handshake waiting, not an admitted syscall;
correct shutdown awaits completion. Forced owner Drop may synchronously join the worker.
Whole NetworkPlan/shutdown deadlines and other startup I/O/Drop paths remain. Path and
interprocess context remain D06. The packet/firewall matrix and benchmark were not rerun.
Windows VM, Mac/iOS and router runtime are user-approved SKIPPED; final Android remains D12.
Debt: 4/15 DONE, 9 IN_PROGRESS, 2 TODO.
