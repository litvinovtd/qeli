# Q25-F111: ordered diagnostics writes outside the async executor

25 September 2026. Baseline `300a6c78`. D05/D09, Linux.

## Defect and fix

`ClientStatusReporter::publish` created directories, serialized snapshots and performed
atomic writes with fsync on the async executor. Slow storage delayed neighboring tasks,
stop registration/handling and client completion. On a multithreaded runtime, sampler
and event publications could write concurrently: copying state under a mutex did not
order subsequent writes, so an older snapshot could overwrite a newer one. The earlier
`client_tasks::finish` already protected terminal state from a live sampler, but did not
remove file I/O stalls or intermediate snapshot reordering.

Each Linux client with `QELI_CLIENT_STATUS` now creates one `qeli-status` thread.
It inherits its caller's NET/mount context and performs I/O sequentially. At most one
in-flight and one pending snapshot are retained; a new pending snapshot replaces the
previous one. The state mutex stays held through enqueue, while file operations and
byte serialization run outside that mutex. Status remains a current snapshot, not a
log of every transition.

The writer owner is separate from cloneable senders. Ordinary exit stops and joins
sampler/watchers, publishes terminal state, closes admission, awaits the last accepted
write and joins the writer. Cancelling `finish` retains ownership so it can be retried.
Forced Drop synchronously joins, including the pending snapshot, without leaving a
write running after owner release. A writer panic closes admission and is observed by
join. No status path means no writer thread; spawn failure disables diagnostics with
a warning.

Atomic replacement, file/directory fsync and `0600` still use the existing shared helper.
Write errors remain best effort: they do not change the VPN result or trigger reconnect.
If terminal publication fails, the file may contain older state; inspect exit status
and logs separately. Schema 1, API fields and INI configuration are unchanged; internal
status JSON remains part of the agreed contract.

## Validation

- **5 new portable regressions**: slow writer with a responsive current-thread runtime;
  10,000 updates occupying one pending slot; terminal last; rejection after close;
  cancelled/retried finish; live sender clones; joined Drop, panic and slow callback
  destruction.
- **1 new privileged Linux regression**: the writer inherits the calling thread's
  private NET/mount namespaces without changing the main process's namespaces.
- **2 baseline + 4 fixed fsync scenarios** against real `run_client` on a current-thread
  runtime. Both baseline controls reproduce 0 heartbeat ticks during initial and final
  writes; fixed records **7–8** ticks per roughly 800 ms interval. Holding the final
  write prevents early client return. Cases cover `failed` after password-command
  failure, SIGTERM `stopped`, publication recovery after initial-write EIO and retained
  previous status after final-write EIO. These cases finish before connection; TCP/UDP
  are configuration selections.
- Separately, **2 baseline + 4 fixed established TCP/UDP tunnel scenarios** repeat the
  existing teardown harness: `running` → `stopped`, or sticky `failed` on route cleanup
  failure; **2/2 explicit restarts** clean up retained kill-switch state. Original routes
  and operator firewall rules are restored and the TUN is removed.
- The fsync fixture checks the private mount view (the original file outside the bind
  mount is unchanged), `0600`, no unfinished temporary files, stable final content and
  unchanged networking. LD_PRELOAD applies only to the fixture client.
- **1569 host + 71 config; 2133 Linux + 48 privileged + 8 lifecycle PASS**.
  All 9 host/cross/feature/lint/format commands PASS; the existing Clippy
  `chunks_exact_to_as_chunks` exception is retained. RU/EN docs and diff are checked
  before commit.

## Evidence and limits

Only lab `10.66.116.11` was used; working server `10.66.116.10` was untouched. Runtime
fixtures have private NET/mount/PID namespaces; established-tunnel tests also isolate
`/run`, `/var/lib`, `/var/log`, `/tmp`, `/etc/qeli`. Privileged Rust tests run in private
namespaces too. Windows/Rust 1.98, Linux/Rust 1.97; the C shim uses
`-Wall -Wextra -Werror`. Installed services and binaries were not replaced.

`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/status-writer-phase/evidence.json`
verifies 353 source files, their tar, fixture/driver versions, logs and scenarios.
Runs: `status-writer-linux-v1`, `status-writer-runtime-v1`, `status-writer-teardown-v1`.
All Linux checks use the same v1 source snapshot. The historical packet/firewall matrix
was not rerun in this phase and is not attributed to the new binary.

Worker `280354840c416acea076e328c0b4fe2cd68994e727df44e1993ffc60dce0a065`.

Fixed driver `dc58d95673f5ba06f5f8e8b51ec97877ef1bd0bd603ddc43b8976ffa30fb15b1`.

Baseline status driver `a1756289c39dbebab52bf9e9510311e615f5f2af82d9a4c41dede142b598c085` (frozen parent snapshot).

Shim `d2cb5c5af319b4dea9d42c0defbc09462c2e7b49a3d0196e34528f17afb8c4db`.

**D05 remains IN_PROGRESS.** A stuck syscall cannot safely be interrupted: ordinary
finish awaits it asynchronously; forced Drop waits synchronously. There is no single
hard NetworkPlan/shutdown deadline. Other early error/Drop paths and locks/I/O
(including device-id and known-hosts), interprocess and process-global context D06
remain open. One writer orders one client's writes, not separate processes sharing
a path. This is not a benchmark, D10/D13 completion or cross-platform certification.
Windows VM, Mac/iOS and physical router runtime are user-approved SKIPPED;
final Android validation remains D12. Debt: 4/15 DONE, 9 IN_PROGRESS, 2 TODO.

25 September 2026 reconciliation: device-id and TOFU integrity are addressed in [Q25-F112/F113](AUDIT-Q25-IDENTITY-FILES.md). The synchronous TOFU callback and overall deadline remain D05.
