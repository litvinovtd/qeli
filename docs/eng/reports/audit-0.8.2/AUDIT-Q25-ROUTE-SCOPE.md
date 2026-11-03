# Q25: route ownership scoped to a connection lifetime

Date: 23 September 2026. Baseline: `1f857209`.
Q25-F027/F028 are fixed within the boundaries below. Sections 22, 23 and 25 remain **IN_PROGRESS**.

## Findings

**Q25-F027, P2 — cleanup and roaming used an ownerless process journal.**
`cleanup_routes(ifname, ...)` drained every process entry although its flush targeted one
interface. Cleanup could delete another connection's carrier/exclude/blackhole route.
A destination record could also make roaming treat another Qeli owner's route as its own.
Separate lists alone would not suffice: a second connection could accept a matching route
as external and depend on it without retaining its creator.

**Q25-F028, P2 — a prepared route commit outlived the start of cleanup.**
The projection had generation/candidate IDs but no checked owner lifetime. Calling the
adapter after cleanup could reinstall routes. An interface name and generation number
alone are insufficient when those values are reused.

Two targeted baseline tests reproduced both failures. They exercise the route-adapter
boundary; they do not assert support for multiple complete Linux clients in one process.

## Changes

`route/journal.rs` separates records by a unique process-local `RouteOwner` identity,
interface and generation. The owner is allocated before TUN reclaim/create. The same lease
flows through setup, partial rollback, TunGuard and TCP/UDP cleanup. The roaming controller
and prepared projection hold weak references, which cannot keep a finished connection alive.
Prepare/commit validate admission and generation.

Cleanup closes admission before its first command even if it subsequently fails. It drains
and retains retry records only for its owner. In-process setup/prepare/commit/cleanup are
serialized. An interface name cannot be reused while the old guard is alive; after successful
cleanup and final lease release it becomes available. An old projection cannot revive even
when the interface and generation number are repeated.

Add/replace reject a route key held by another owner. Other Qeli owners' carrier, exclude
and blackhole routes cannot be borrowed. Operator records remain unclaimed. Equivalent
host notation `IP` versus `IP/32` or `IP/128` cannot bypass the check. This rejects unsupported
shared ownership; it does not implement shared-route reference counting.

If the final lease is released with remaining records or a failed flush, its reservation
remains in memory so a new connection cannot adopt the leftovers. A live guard can retry
cleanup. Automatic recovery of an orphaned owner is not implemented.

Gateway refresh now runs inside commit only after the live-owner check, under the
same operation lock. A late commit does not invoke that callback. A dedicated
regression checks both the live and stopped owner.

Linux `dev_attach=true` no longer advertises `ROAMING_PATH` or receives a managed route scope:
the external manager owns routes and `auto` uses reconnect. `required` lacks the necessary
platform contract. Legacy IPv4 setup/helpers now compile only for tests; obsolete `pin_target`
and unused cleanup arguments were removed. User INI and C ABI are unchanged; the internal
Rust route API now requires an owner.

## Validation

**1090 host unit + 52 editor/policy + 7 examples + 12 server INI = 1161 Rust tests PASS.**
17 new permanent regressions cover two owners on one WAN, both IP families, isolated cleanup/
retirement/rollback, failed cleanup and retry, late commit, interface/generation reuse,
expired leases, dropped owners with residual routes, failed flush, equivalent host prefixes,
blackholes and the real exclude setup path. Another case runs cleanup and late commit on
separate threads through a controlled command boundary.

The baseline `scope_` filter produced **2 targeted expected failures**. Four unrelated tests
sharing that name fragment passed and are not counted as new controls. All 17 new scenarios
pass in the fixed host suite. No real ip/firewall commands are executed by these fixtures.

All nine matrix commands passed: host/config, Linux all-targets Clippy, client-only,
server-only, client without roaming, minimal FFI, compatibility without features and rustfmt.
The existing no-roaming `terminal_sender` warning remains; warnings introduced by this change
were removed. The existing `chunks_exact_to_as_chunks` Clippy exception remains.
Linux guards/capability test/shell fixtures were cross-compiled, not executed on Linux.
RU/EN documentation was checked. Evidence: C:/Users/litvi/OneDrive/Documents/qeli/route-scope-audit-20260923.

## Limits and next pass

The registry is process-local and not durable. Other Qeli processes/operators, unknown add
outcomes, complete kernel identity, multipath/VRF and crash/restart recovery remain open.
This is not certification of concurrent full clients: other global client, firewall and
DNS state still requires review. Unfinished TUN workers and descriptor reuse remain part
of Q14-F027; a route lease alone does not close that work.

Next: verify retirement/restore outcomes and define pending-operation recovery. Commands
still lack deadlines; the operation mutex means a hung command delays other route operations
in the process. No real Linux TUN/firewall/handover, native release, devices or new benchmark
were run here.
Previous pass: [selectors and verified cleanup](AUDIT-Q25-ROUTE-OWNERSHIP.md).

Follow-up: [Q25-F029/F030](AUDIT-Q25-ROUTE-POSTCONDITIONS.md) verifies retirement/restore
outcomes. Confirmed absence or exact restoration is now accepted even with negative/lost
completion; apparent success alone is not proof. Pending unknown/orphan recovery and
command deadlines remain open.

Follow-up: [Q25-F031/F032](AUDIT-Q25-ROUTE-PENDING.md) retains separate pending reservations
for unknown roaming outcomes and closes admission on every unknown commit result.
Read-only orphan release is possible after confirming absent leftovers within the process;
durable crash recovery remains open.

D04 follow-up: [Q25-F100](AUDIT-Q25-ROUTE-JOURNAL.md) adds durable physical route ownership and crash recovery. The process-local contract described here is extended with intent/confirmed state; uncertain operations still grant no delete authority.
