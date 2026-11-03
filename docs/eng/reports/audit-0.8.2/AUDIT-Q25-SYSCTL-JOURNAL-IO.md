# Q25 — safe sysctl journal reads and lock waits

<!-- normative-sync: audit-q25-sysctl-journal-io-v1 -->

Date: 24 September 2026. Baseline: `d56bf1ce`. Part of D02/D05 in the
[debt register](../../plans/AUDIT-DEBT.md); neither group is fully closed yet.

## Findings and fixes

| ID | Problem | Fix |
|---|---|---|
| Q25-F069, P2 | `symlink_metadata` checked one pathname snapshot, then unbounded `fs::read` reopened the path. Growth could bypass the 128 KiB limit; hardlinked or group/world-writable journals could authorize stale recovery. | Open with O_NOFOLLOW/NONBLOCK/CLOEXEC; validate regular/single-link/mode/size on that fd. Read at most limit+1 and recheck the opened file’s size and Stamp. Failure cannot authorize pruning, kernel writes or journal retirement. |
| Q25-F070, P2 | Shared `FileLock` opened its sidecar O_WRONLY: a FIFO without a reader blocked before the promised metadata check. | NONBLOCK precedes type validation. Regular files still use advisory flock; a FIFO never waits for a peer or reaches chown. |
| Q25-F071, P2 | The sysctl mutex and flock could wait indefinitely; namespace selection happened after waiting. | A shared 15-second contention budget covers both locks. The new `FileLock::acquire_timeout` leaves other callers’ wait policy unchanged. Capture net/PID/time context at entry and compare after locking, before loading/pruning/persistence. |

Snapshot validation reuses `config_source::Stamp`. sysctls.state remains version 2;
INI, ABI and wire formats do not change. Errors preserve saved values. This does not
make pathname operations atomic against a privileged external writer.

## Verification

- 12 new Linux tests: 6 file snapshot, 2 untrusted-journal stale-recovery refusals,
  2 namespace/local-lock and 2 FileLock FIFO/contention. Five are portable to Windows.
- Baseline `d56bf1ce` plus regression fixtures: **3 expected FAIL** — writable journal,
  hardlinked journal and FIFO lock. The old FIFO test opens its own fixture reader
  after 300 ms, so the reproduction itself does not hang.
- Host: **1426 unit + 71 config integration PASS**. Feature/cross/lint matrix PASS;
  four needless-borrow findings in the new Unix tests were fixed and Clippy repeated.
- Linux: **1874 ordinary tests + 18 privileged regressions PASS**; all
  **8 worker lifecycle E2E PASS** again. Results: `sysctl-fixed.log` and `lifecycle-sysctl/`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/sysctl-phase/`,
`sysctl-baseline-more.log`, `sysctl-fixed.log`, `linux-source-final-manifest.json`.
Environment/isolation commands match the [preceding Linux pass](AUDIT-Q14-RETAINED-CLEANUP.md).

## Remaining D02/D05 work

Original-interface evidence during per-link restore, individual sysctl-operation
checks, durable namespace identity reuse and parent-directory trust still need separate
closure. Only mutex/flock contention is bounded; file I/O, external-command sequences
and the complete cleanup transaction have no new shared deadline. Synchronous preflight
in async handlers also remains D05. Successful unit/cross/native checks do not hide these limits.

Internal I/O boundaries were subsequently guarded in [Q25-F077](AUDIT-Q25-SYSCTL-CONTEXT-IO.md); this does not fully close D02.
