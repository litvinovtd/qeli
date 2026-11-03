# Q05 — panel transactions, preflight and cancellation

<!-- normative-sync: audit-q05-panel-transactions-v1 -->

Date: 24 September 2026. Baseline: `89d3961e`. Partial closure of D05 in the
[debt register](../../plans/AUDIT-DEBT.md). Full sections 05/07/14 remain open.

## Q05-F002, P2 — synchronous network probes under the write lock

Form/INI/history/Quick Start and restart invoked synchronous preflight from async
handlers. Four commands had separate 15-second limits, occupying the executor and
the lock required by other config writers. Quick Start could also synchronously
probe ip6tables availability.

The panel now runs children directly through the shared async runner. IPv4/IPv6
collection and optional ip6tables discovery share a 15-second budget, including
probe admission. Four observations may run concurrently; request cancellation
releases admission and stops its owned command. Synchronous startup/check-config/
restore also share a 15-second budget across the four `ip` commands while retaining
the synchronous ordering those callers need.

The panel observes networking before taking the config write lock. Once observations
finish, five seconds remain to acquire the lock and prepare a candidate for checking.
Expired observations refuse the operation with a retry message. Busy admission or a
lock timeout is never converted into an unknown-network fail-open result. Current
INI, revision, hooks, users and final writes remain in one critical section.
An `ip` read failure retains the existing warning/fail-open policy; IPv6 failures
preserve successful IPv4 data, and observed collisions still refuse the operation.

## Q05-F003, P1 — cancelled restore released the lock before its writes finished

`spawn_blocking` keeps running after its async waiter is cancelled. Previously the
request held the lock: cancelling it allowed another save to mutate the same tree
while restore continued. Cancelling a download could likewise admit a writer before
archive reads finished.

The shared `config_transaction::blocking` transfers the owned guard to the blocking
operation. It returns the guard with the result for successive download phases.
On cancellation the worker keeps the guard until completion; panic releases it
during unwinding. Lock lifetime now matches actual work. Restore may finish after
request cancellation; cancelling a request does not promise rollback of published files.

## Q05-F004, P2 — restart waits held config writes indefinitely

Worker restart now immediately reports a busy/closed supervisor queue instead of
waiting indefinitely on send under the config lock. Polkit checks run outside that
lock. Delayed full restart obtains a new observation, acquires the lock and validates
the latest config. `systemctl restart` uses the shared runner with a 15-second limit
and 64 KiB per output stream. Unknown outcomes ask the operator to inspect the unit
and journal: timeout does not prove systemd did not accept the request.

## Verification and limits

Portable regressions cover cancellation of a blocking writer, lease continuity
between phases, panic, sync/async policy equivalence, executor responsiveness and
termination of a real child on cancellation, and a shared sequential probe deadline.
Linux API-helper tests cover busy/expired snapshots and availability of a sibling
writer during preflight. The full Linux/feature suite and worker lifecycle run in an
isolated source snapshot; final results are recorded below.

Final snapshot: **1444 host unit + 71 config integration PASS**, all nine
feature/cross/lint commands PASS. Linux: **1898 ordinary + 25 privileged tests and
8 worker lifecycle E2E PASS**. Linux worker SHA256:
`14370928a9414ebb9e1ed6601459aecea9c18b0d232c4dc19b25706ee486609e`.
One child fixture is included in the new test count; these results do not constitute
complete HTTP/systemd, client packet or benchmark evidence.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/panel-transaction-phase/`,
`panel-preflight-final.log` and `lifecycle-panel-final/`. Commands, stdout, exit status,
source manifest and SHA are retained separately from the active server.

D05 remains open: `tar`/archive/restore publication and other network mutation
sequences need overall budgets and partial-outcome handling. Uninterruptible
filesystem/kernel I/O and final kill/reap do not acquire a hard upper bound from an
async timer. Multiple-command snapshots are not atomic against manual network
changes. Re-reading config protects concurrent panel saves but cannot turn external
`systemctl` or third-party editors into a transaction. Actual systemd supervisor
replacement and complete HTTP/fault E2E remain D09. No new INI fields, JSON config
support or ABI changes were introduced.

[Previous preflight](AUDIT-Q05-PREFLIGHT.md) · [Instructions](../../manuals/TROUBLESHOOTING.md)

D05/D09 update: [backup/restore budget and snapshot completeness](AUDIT-Q05-ARCHIVE-BUDGET.md). Other network sequences and filesystem fault E2E remain open.

D05/D09 continuation: [async Status/Transport health probes](AUDIT-Q05-HEALTH-PROBES.md) and a neighboring HTTP request on a current-thread executor.
