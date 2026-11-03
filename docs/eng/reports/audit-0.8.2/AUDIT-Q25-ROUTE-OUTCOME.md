# Q25: failed carrier-route mutation outcomes

Date: 23 September 2026. Baseline: `c6c64c70`.
Sections 22, 23 and 25 remain **IN_PROGRESS**. Q25-F023/F024 are fixed.

## Findings and changes

**Q25-F023, P2 — a partially applied route command could be reported as a reversible rejection.**
`LinuxPreparedPathRoutes::commit` records an applied step only after command success.
On failed add/replace it rolled back earlier steps, without verifying the failed step.
Retirement similarly restored earlier deletions but did not check the failed deletion.
If the kernel state changed before the command returned an error, earlier rollback could
succeed and the adapter still returned an ordinary error. Linux mapped that to `Rejected`,
although that outcome requires no change or a fully restored prior state.

After earlier rollback, Qeli now checks the failed destination again. A failed add is
unchanged only if no exact route is present. A failed replace or retirement requires the
same complete token snapshot recorded before mutation. A missing former route, unreadable snapshot or changed result
returns `RouteCommitStateUnknown`, including the original command error and verification
failure. Confirmed unchanged state retains ordinary rejection. Earlier rollback failures
remain unknown regardless of this check.

The existing controller maps the typed error to `PlatformStateUnknown`; the core fails
the correlated command and invalidates the candidate rather than queueing a normal ABORT
and continuing under an assumption of intact routes. Existing transport error handling
must stop the current generation. This pass changes the route executor's outcome,
not the control-plane ABI or that state machine.

**Q25-F024, P2 — multi-line route snapshots silently discarded all but the first route.**
`exact_route_tokens` accepted the first nonempty line and ignored the rest. A multi-route
or multi-line result was not a complete snapshot for comparison/restoration. It now
rejects more than one nonempty line. Before mutation this is an ordinary rejection;
after a failed mutation it prevents claiming that state is unchanged. Whitespace within
one line is normalized into tokens. Multipath/multi-route reconstruction is not implemented.

The command call boundary is injectable in tests. Production continues to invoke `ip`
with the same argv and the existing unbounded runner. The host test build includes the
portable route code; only interface-index resolution remains Linux-gated.
New fixtures use per-thread command injection and serialize the ownership journal with
the existing Linux shim tests. They do not modify process PATH or host networking.

## Validation

**1057 host unit + 52 editor/policy + 7 examples + 12 server INI = 1128 Rust tests PASS.**
This adds 15 transaction regressions and executes eight existing pure route tests on the
host for the first time; it is not 23 newly written tests.
All nine matrix commands pass: host/config, Linux all-targets Clippy, client-only,
server-only, client without roaming, minimal FFI, compatibility without features and
rustfmt. Existing feature warnings and the `chunks_exact_to_as_chunks` exception remain.

The 15 regressions run actual commit, rollback and ownership functions against a stateful
command fixture: both families; add/replace/retirement; mutation followed by nonzero or
injected TimedOut/InvalidData/BrokenPipe; unchanged failure; unreadable/multiple snapshots;
concurrent operator changes; rollback of earlier additions; restoration of earlier
retirements; rollback failure; successful paths and operator-owned match/conflict.
Assertions cover result type, route state, ownership and absence of blind undo for the
failed step.

A separate reproduction extracts the baseline/fixed transaction and runs those same tests.
Only the command boundary is injected; baseline transaction/rollback/snapshot behavior
is retained. Baseline: **10 expected failures, 5 passing controls**. Fixed: **15/15 PASS**.
These are repetitions of the permanent tests, not additional tests added to 1128.
Evidence and reproduction: C:/Users/litvi/OneDrive/Documents/qeli/route-outcome-audit-20260923.
RU/EN documentation checks pass.

## Boundaries and remaining work

The fixed defect is the false reversible outcome, not complete recovery of an uncertain
mutation. Qeli does not blindly claim/delete a route after an unsuccessful add, nor blindly
restore a failed replace: a concurrent operator may own the observed route.
An uncertain new route can remain without a cleanup entry; prior known entries remain.
Persistent pending-operation ownership, exact identity for retry/cleanup and recovery of
that state remain open. Snapshots do not make external route changes atomic.

No command deadlines are introduced here; timeout/overflow are injected I/O results,
not real timed-out processes. Read-only route queries and mutating route/kill-switch/
gateway commands still need separate migration with ownership verification.
No live Linux netlink/iptables/TUN/handover, device tests, native release or new benchmark
ran. INI/API/ABI are unchanged; the complete audit remains open.

Previous pass: [gateway WAN](AUDIT-Q25-GATEWAY-WAN.md).

Follow-up: [Q25-F025/F026](AUDIT-Q25-ROUTE-OWNERSHIP.md) adds supplied delete selectors,
changed-route checks and verified cleanup. Global/pending ownership and atomic recovery remain open.

Follow-up: [Q25-F029/F030](AUDIT-Q25-ROUTE-POSTCONDITIONS.md) verifies retirement/restore
outcomes. Confirmed absence or exact restoration is now accepted even with negative/lost
completion; apparent success alone is not proof. Pending unknown/orphan recovery and
command deadlines remain open.
