# Q25 — shared deadline for client route transactions

<!-- normative-sync: audit-q25-route-budget-v1 -->

24 September 2026. Code baseline `ea87fd49` (subsequent `d5779b4a` changes only
measurement scripts and documentation). D05/D09 continuation.

## Q25-F092, P2 — route admission and sequences had no shared deadline

Route owner creation, setup, prepare, COMMIT and cleanup each receive 15 seconds
for the process-local operation mutex and sequence of `ip` queries/mutations.
IPv4/IPv6, FIB verification, route_local discovery and delete verification share
the attempt's deadline. Late responses cannot acknowledge success; no new child
starts after expiry.

Rollback after an unsuccessful COMMIT receives a separate 15 seconds for the complete
reverse sequence, without resetting the deadline per route. Incomplete rollback means
`RouteCommitStateUnknown` and stops this owner's COMMIT admission. Pending records
cannot authorize deletion of a route with unknown provenance. Cleanup closes admission
before waiting for the mutex, retains unverified records and permits a separate verified retry.

A thread-local RAII scope carries the deadline through strictly synchronous code holding
the operation mutex. The guard is `!Send` and never crosses await; unwinding restores the
parent deadline. Rollback temporarily replaces the deadline, not the saved owner or namespace.

## Validation

7 new portable + 1 Linux tests: expired/busy admission; cleanup admission stop on timeout;
late refresh without route I/O; unknown add without delete authority; late FIB and one
fresh rollback budget; cleanup across both families; RAII unwind; real `sleep 5` child
with a 120 ms deadline (2-second outer test allowance).

**1491 host unit + 71 config**, all **9 feature/cross/lint checks PASS**.
**2009 ordinary Linux + 32 privileged + 8 worker lifecycle E2E PASS**.
Disabling deadline guards in a private copy gives **6 expected FAILs**; restoration gives
**196 route tests PASS**, with 7 privileged/fixtures explicitly ignored in that focused run
(privileged tests were executed in the full run above). The first two local regressions
included preparatory fixture queries in their operation counts; corrected counts pass,
and the initial failure log is retained. Runtime criteria were not weakened.

All 322 source files were verified by SHA before/after full and counterfactual runs.
Source archive: `99eeff06b596dd2a3d287fae2dfba7ff7d54b313dba3f2a33fe3ef0ab725197a`.
Debug worker: `24f87dc8765c37014c79506492895aa7a1f48fba97471654c520681b6341230c`.
Linux Rust 1.97 / host 1.98; existing Clippy exception `chunks_exact_to_as_chunks`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/route-budget-phase/`,
`route-budget-final.log`, `route-budget-counterfactual/`, `lifecycle-route-budget/`.
Lab `.11`, private namespaces; live server `.10` unchanged.

The real client [packet matrix](AUDIT-Q34-LINUX-MATRIX.md) was rerun on this same debug worker: **17/17 rows, 297 assertions PASS**, including stop with TUN removal and direct-route restoration. DNS packets are real, resolvectl remains a stub: this does not verify D-Bus context. Evidence: `packet-matrix-route-budget/` and its log.

## Boundaries

The 15 seconds bound operation admission and child commands, not the whole NetworkPlan/shutdown.
Internal registry locks, filesystem/sysctl I/O and synchronous external refresh callbacks
are not preempted; expired results are rejected when they return. Executor isolation remains
D05, persistent crash recovery D04, resolver context D06 and full fault/resource coverage
D09/D10/D13. Root can alter the network between verification and command; the process-local
mutex is not a kernel CAS. No new INI parameters. Windows VM/Mac/iOS/router runtime is
skipped by user decision.

[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/CONFIG.md)
