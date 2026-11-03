# Q25: verified carrier-route retirement and restoration

Date: 23 September 2026. Baseline: `8eca565d`.
Q25-F029/F030 are fixed within the boundaries below. Sections 22, 23 and 25 remain **IN_PROGRESS**.

## Findings

**Q25-F029, P2 — retirement trusted command status instead of route state.**
During handover, a successful `ip route del` or an already-absent diagnostic dropped
the ownership record without another query. A surviving route could therefore be
left behind by a successful commit. Conversely, an applied deletion with a lost
result was considered unknown even when absence could be confirmed. The already-absent
branch also omitted the deleted route from restoration if a later retirement failed.

**Q25-F030, P2 — rollback treated successful status as proof of restoration.**
Both replace rollback and restoration of earlier retirements trusted `add/replace`.
A command could report success without restoring the previous snapshot; the journal
would claim the old specification and the transaction report reversible rejection.
A lost result after actual restoration could instead cause an unnecessary unknown
outcome. Carrier snapshots accepted an invalid destination and lossy UTF-8 although
the ownership reader already required a valid snapshot.

The precondition is managed Linux roaming with a partial route-command failure/lost
result or a route change between transaction steps. A deterministic command model
exercises the real route adapter. It neither measures the frequency of such events
on Linux nor establishes atomic protection against an external operator.

## Changes

Retirement rechecks the complete saved snapshot before deletion. A route that has
disappeared or changed is neither deleted nor recreated, and stale ownership is dropped.
After delete, only confirmed absence completes retirement, regardless of exit status
or I/O error. Every confirmed deletion enters the rollback list in case a later step
fails. A surviving route rejects the commit.

Replace rollback and retirement restoration share `restore_carrier_snapshot`.
A write targets only an absent destination or the observed owned candidate. A different
observed route is preserved. After the command, the complete token sequence is read again
and compared with the previous snapshot. Only an exact match confirms restoration
and records the previous cleanup specification, including when command completion was
lost. Apparent success, a different snapshot or a query error does not claim restoration;
there is no second blind overwrite.

Ordinary rejection retaining the previous path requires all necessary rollbacks and
the unchanged failed retirement to be confirmed. Otherwise `RouteCommitStateUnknown`
reaches the controller as `PlatformStateUnknown`, requiring the current connection
generation to stop.

Carrier and ownership readers share `parse_route_snapshot`: strict UTF-8, at most one
nonempty line and a valid matching destination. Ambiguous, malformed or wrong-destination
output cannot establish route state. Redundant stored IPv6 flags were removed; the
address determines the family.

User INI, the parameter matrix, API and ABI are unchanged. Internal JSON audit artifacts
are not a configuration format.

## Validation

All **16 new regression tests failed on the baseline**. The same 16 scenarios pass
after the fix. The full suite reports **1106 host unit + 52 editor/policy +
7 examples + 12 server INI = 1177 Rust tests PASS**. Filter reruns and the 72 route tests
already included in the host suite are not added to that total.

Coverage includes both IP families, false success and false already-absent diagnostics,
lost/negative completion after actual delete/restore, restoration of earlier retirement
after a later failure, disappearance before deletion, external replacement, query errors,
ambiguous output, wrong destinations and invalid UTF-8. Assertions inspect the route
model, owner records and safe cleanup behavior as well as the returned error.

All nine matrix commands passed: host/config tests, Linux all-targets Clippy,
client-only, server-only, client without roaming, minimal FFI, compatibility without
features and rustfmt. Rust 1.98.0; the existing `chunks_exact_to_as_chunks` Clippy
exception remains for an unrelated migration, as does the existing no-roaming
`terminal_sender` warning. No new exceptions were added.

Linux shell fixtures now track mutable host snapshots and were cross-compiled, not
executed on Linux. Host fixtures execute no real ip/firewall commands. RU/EN documents
are checked by the shared docs gate.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/route-postconditions-audit-20260923.

## Limits and next pass

Snapshot verification is not kernel compare-and-swap. Another process can change a
route after the check; full identity, multipath/VRF and semantic normalization of all
attributes remain unsupported. Reordered/dynamic attributes can conservatively yield
an unknown outcome. The host suite does not certify multiple complete clients.

Unknown adds, restoration with an unreadable post-query, orphaned owners and crash/restart
recovery remain open. An actually restored route with a failed query can remain without
newly proven ownership. Stopping a generation does not prove every uncertain route was
removed. A previously proven record, if present, remains for subsequent cleanup checks.

Next: define pending-operation and orphan-record recovery, then bound route/kill-switch/
gateway commands. The registry remains in process memory and a hung command can still
hold the shared operation lock. Complete gateway rollback, Q14-F027 TUN workers/FD,
Linux E2E, native certification and a new benchmark remain open.

Previous pass: [connection owners](AUDIT-Q25-ROUTE-SCOPE.md).

Follow-up: [Q25-F031/F032](AUDIT-Q25-ROUTE-PENDING.md) retains separate pending reservations
for unknown roaming outcomes and closes admission on every unknown commit result.
Read-only orphan release is possible after confirming absent leftovers within the process;
durable crash recovery remains open.
