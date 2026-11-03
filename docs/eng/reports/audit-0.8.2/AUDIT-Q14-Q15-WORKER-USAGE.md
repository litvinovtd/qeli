# Q14/Q15: worker background services and complete session accounting

Date: 23 September 2026. Baseline: `556deffb`. Sections 14 and 15: **IN_PROGRESS**.

## Findings and fixes

**Q14-F016, P1 — detached worker services and incomplete shutdown persistence.**
The worker discarded the handles of usage_sweep, udp_drop_report and the packet trace
watcher. Losing quota enforcement to a task panic was invisible to the worker. During
shutdown, a sweep could still remove sessions/routes while profiles were being torn
down. Its retained ServerState also made destructor-based persistence unreliable on
fatal exits; the explicit final flush only ran on the signal path.

WorkerServices now owns these tasks. An unexpected return or panic of either required
periodic service triggers worker failure and cleanup. The optional trace watcher may
return normally when tracing is disabled. Stop prevents the next periodic cycle while
allowing the current cycle to finish, including quota-driven route and lease cleanup.
Accepted control operations and worker services drain before profiles stop. A cancelled
shutdown waiter retains the join handles. Dropping the owner is an emergency abort
fallback, not a substitute for graceful transaction completion.

After profile cleanup, both signal and fatal paths explicitly collect and persist
usage while holding the worker lease. Failure is logged and returns a nonzero outcome;
a signal-driven exit no longer reports success after a failed final write.

**Q14-F017, P1 — a rejected second worker could overwrite accounting.**
A writable UsageStore was loaded before acquiring the control socket lease. If another
worker already owned that socket, the rejected instance dropped its store, flushing a
snapshot that could already be stale. The lease is now acquired before loading writable
accounting. Local declaration order also releases the store before the lease on errors.
The supervisor's read-only accounting behavior is unchanged.

**Q15-F001, P1 — short sessions and shutdown tails were omitted from usage.**
Only sessions still present in the live registry were folded during the ten-second
sweep. A connection that opened and closed between sweeps contributed nothing; an
ordinary disconnect lost bytes after its last sweep. Serializing already-folded totals
at shutdown did not recover these bytes. This also understated download quota usage.

TCP and UDP now register their existing atomic counter pair once. UsageStore retains
these counters independently of the live registry and includes them during collection,
flush and reset. It does not retain the session, TUN or socket. A baseline remains until
both counters have no outside owners; Arc::get_mut establishes exclusivity before the
final sample and retirement. Thus a writer can finish after session removal without
losing its tail or counting earlier bytes again. Reset first collects pending traffic
and advances live baselines; only subsequent traffic is charged after reset. Failed
persistence restores the totals including the newly collected bytes.

The packet path is unchanged. Retired counters and their markers are removed on the
next collection. The old live-registry-based prune and production fold entry point
were removed. The persisted accounting schema is unchanged; configuration remains INI.

## Validation

- Six new task lifecycle tests: required return/panic, optional completion, finishing a
  cycle before resource release with cancellation/retry of the waiter, stop priority and
  closed owner, emergency owner-drop cancellation. All 13 lifecycle tests PASS.
- Six new accounting tests: a whole session between sweeps, a writer outliving its
  session, reset with pending traffic, final Drop tail, concurrent updates and collection,
  repeated registration/empty flush. The existing failed-reset test now covers unswept
  counters and subsequent increments. All 14 accounting tests PASS.
- The accounting module is now exercised by host tests as well as Linux server tests;
  eight existing tests therefore join the Windows suite. Unique temporary fixtures avoid
  pre-test recursive deletion.
- Full Windows unit suite: **777 PASS**; editor/policy **52**, examples **7**, server INI
  **12**: **848 Rust tests PASS**. Linux all-targets Clippy passes with the prior
  chunks_exact_to_as_chunks exception in unchanged ndp_proxy.rs. Minimal FFI, rustfmt,
  diff checks and nine documentation checks PASS.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/worker-services-audit-20260923 includes
baseline, source snapshots, build/test logs, diff and verification record. Linux code
was cross-compiled, not executed. No live TUN/firewall, external notifications, SSH or
benchmark was run.

## Limits and continuation

This covers the three named worker services, not every detached notification sender.
Notification queue ownership/bounds and graceful delivery remain for another pass.
Forced cancellation of the outer worker future is not a verified transactional rollback.
Linux signal/restart/accounting E2E still needs a Linux runtime. SIGKILL or a crash can
lose changes since the last successful persistence; a flush error cannot recover disk
contents by itself. Quota enforcement still runs periodically, not on every packet.

Continue with notification task ownership, config trust tied to parsed bytes, and Linux
worker/profile startup-failure and shutdown E2E. Neither section nor the full audit is
complete.
