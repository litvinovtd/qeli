# Q25: unknown route outcomes and release of orphaned reservations

Date: 23 September 2026. Baseline: `06759c30`.
Q25-F031/F032 are fixed within the following boundaries. Sections 22/23/25 remain **IN_PROGRESS**.

## Findings

**Q25-F031, P2 — stopping could lose track of an unknown mutation outcome.**
Managed roaming correctly returned `PlatformStateUnknown` but retained no separate
uncertain-operation record. An applied add with lost completion left a route without
an ownership record. Cleanup could report success, the final lease release the name,
and another owner accept and borrow the leftover as an external route. A failed replace
could lose its last record when cleanup observed changed parameters. Restoration of
an earlier retirement with an unreadable post-query had the same gap. An unknown
command outcome does not establish authority to delete that route.

A failed commit also did not itself close admission to the adapter. Until cleanup
started, another commit could invoke gateway refresh. This included failed rollback
of a known owned route without a separate uncertain add.

**Q25-F032, P2 — an orphan record blocked reuse forever even after removal of leftovers.**
If physical-route cleanup failed, both interface flushes completed and the final guard
was released, the reservation remained without a recheck path. Even after external
removal of the leftover, a new connection in that process was always rejected.

## Changes

The journal stores `pending` separately from proven ownership records. Unknown roaming
add/replace/retirement outcomes and unconfirmed restoration with a possible leftover
reserve the destination. A pending record neither counts as a route created by Qeli nor
authorizes deletion. Other Qeli owners cannot borrow or replace that key, including
equivalent host-prefix notation. The reservation survives the final lease.

Every `RouteCommitStateUnknown` returned by commit closes admission under the operation
lock before returning to the controller. A repeated commit cannot reach the gateway
callback. A confirmed reversible rejection retains its previous behavior.

Cleanup first processes previously proven ownership records with the existing selectors,
then checks pending records. Only confirmed absence clears pending; any present route,
including a matching or foreign route, or a query error retains the reservation and
reports cleanup failure. A live guard can retry. Successful cleanup retry does not
reactivate the stopped owner.

The journal records final lease release and interface-flush results separately.
A new connection may release an old reservation only after the final guard is gone,
the previous cleanup completed both interface flush families, all recorded destinations
are now absent, and IPv4/IPv6 read-only queries confirm empty interface routes.
Checks hold the operation lock without holding the registry mutex across commands.

Recovery does not delete, adopt or restore routes. A present route, malformed/ambiguous
snapshot, failed query or nonempty interface retains the old entry. Without cleanup or
after a failed interface flush there is no automatic release. The new owner receives
a new identity; repeating the interface and generation cannot revive an old plan.

## Validation

Seven targeted tests failed on the original `06759c30`. Final review added a regression
that reproduced gateway callback admission after rollback failure; it failed before
that branch was fixed. All eight scenarios now pass. Nine additional recovery controls
bring the total to **17 new permanent tests**.

Coverage includes both IP families, cleanup/retry, final lease release, another owner,
unknown replace, unreadable restore verification, a live guard, omitted cleanup, failed
flush, external replacement, malformed/ambiguous/non-UTF-8 snapshots and interface routes.
Tests exercise the real commit/cleanup/new-owner functions through a command model.

**1123 host unit + 52 editor/policy + 7 examples + 12 server INI = 1194 Rust tests PASS.**
All nine matrix commands passed: host/config tests, Linux all-targets Clippy, client-only,
server-only, client without roaming, minimal FFI, compatibility without features and
rustfmt. Rust 1.98.0; the existing `chunks_exact_to_as_chunks` exception and no-roaming
`terminal_sender` warning remain. No new exceptions were added. The final matrix was
rerun after centralizing admission closure; the earlier run is preserved separately
and not added to the test count. RU/EN documents use the shared docs gate.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/route-pending-audit-20260923.
Linux code was cross-checked. No real ip/firewall commands, Linux E2E, devices, native
release or new benchmark were run. User INI, API and ABI are unchanged.

## Limits and next pass

This tracks unknown outcomes and releases proven-absent leftovers read-only within
a running process. The journal is not durable; crash/restart recovery, automatic removal
of unconfirmed routes and cross-process ownership remain unsupported. A matching snapshot
after an unknown result does not establish who installed the route. The previous flush
gate uses existing command-status handling; orphan release additionally verifies empty
interface routes. Live teardown and its flush postconditions still require review.

Pending records are integrated with the roaming transaction in this pass. Initial
carrier/exclude/blackhole setup and other route mutations still need the same lost-result
audit. Next: those setup branches, then route/kill-switch/gateway command deadlines.
A hung command can still hold the operation lock, including the new read-only orphan
queries. Kernel CAS, complete identity/multipath/VRF, overall gateway rollback, Q14-F027
TUN workers/FD, native certification and a full benchmark remain open.

Previous pass: [verified retirement/restore](AUDIT-Q25-ROUTE-POSTCONDITIONS.md).

Follow-up: [Q25-F033/F034](AUDIT-Q25-SETUP-FLUSH.md) extends pending tracking to initial
carrier/exclude/blackhole setup and verifies interface-flush postconditions. Negative
status with confirmed absence no longer fails cleanup; a missing TUN requires a separate
link inventory check. Durable crash recovery remains open.

D04 follow-up: [Q25-F100](AUDIT-Q25-ROUTE-JOURNAL.md) adds durable physical route ownership and crash recovery. The process-local contract described here is extended with intent/confirmed state; uncertain operations still grant no delete authority.
