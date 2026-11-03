# Q25: initial physical-route setup and verified interface flush

Date: 23 September 2026. Baseline: `78f74e14`.
Q25-F033/F034 are fixed within the boundaries below. Sections 22/23/25 remain **IN_PROGRESS**.

## Findings

**Q25-F033, P2 — initial setup lost unknown outcomes and trusted apparent success.**
Carrier pinning, excludes and blackholes recorded ownership solely from successful
`ip route add` status. An applied command with lost/negative completion left an
unrecorded route and allowed cleanup to report success. Conversely, successful status
without installation accepted setup and created an unproven ownership record.
These branches did not use the pending contract previously added for roaming.

**Q25-F034, P2 — interface flush did not verify that routes were actually absent.**
Success or an interface-absent diagnostic completed cleanup even with surviving routes.
Lost completion after an applied flush instead reported failure despite empty state.
After TUN deletion, a repeated route query may fail; that alone proves neither presence
nor absence of the device without a separate check.

Eight regressions reproduced both groups on the original production code. The command
model gained actual flush effects scoped by family and interface. No real ip/firewall
commands were executed on the host.

## Changes

`install_physical_route` unifies carrier, exclude and blackhole installation. Before
writing, it checks other Qeli ownership/pending reservations and reads a strict exact
destination snapshot. A matching existing route is used without add or new ownership;
a conflict is rejected before mutation. Unreadable/malformed/ambiguous snapshots also
prevent a write.

Every attempted add is followed by another snapshot. Only successful status together
with matching parameters establishes new ownership. Confirmed absence rejects setup
without a claim. A present unconfirmed route or failed verification creates pending,
closes owner admission and fails setup. Even `File exists` after confirmed initial
absence cannot authorize borrowing the newly appearing route. Pending does not grant
delete authority; matching parameters after lost completion do not prove authorship.

Three separate add-result implementations were removed. These initial setup branches
no longer use weak substring checks and separate direct route-show calls.
Pending is available without experimental roaming. Other TUN/pushed/local-route
installation functions were not replaced by this helper.

Cleanup executes IPv4 and IPv6 flush independently, verifying an empty `route show dev`
for each family. Failure in one family does not skip the other. Command status or an
I/O error alone does not determine the result: confirmed empty state permits success,
while a surviving route or failed verification retains cleanup failure.

After negative route-query status, Qeli also runs read-only `ip -o link show`. Only a
successful valid UTF-8 inventory without the exact interface name (accounting for an
`@peer` suffix) confirms a disappeared TUN. Similar names do not match. Execution/I/O
failure, malformed inventory or a present interface cannot complete cleanup. An I/O
error from the route query itself remains unverified.

Cleanup and orphan release share this check. `interface_flushed` now represents confirmed
postconditions for both families. Retry after TUN deletion does not blindly accept
`Cannot find device`. Matching such diagnostic strings remains only in Linux test
fixtures, not production cleanup outcome classification.

## Validation

**8/8 targeted baseline tests FAIL → 8/8 PASS after the fix.** Twelve additional controls
cover successful add/cleanup for all three branches and both families, an existing
operator route, conflicts and on-link/via identity, a `File exists` race, invalid UTF-8/
ambiguous/wrong-destination snapshots, stopped owners and pending borrowing rejection,
a disappeared TUN, similar names, invalid link inventory and failed flush on empty state.

**1143 host unit + 52 editor/policy + 7 examples + 12 server INI = 1214 Rust tests PASS.**
20 new permanent tests. Existing failed-flush fixtures now contain actual leftovers:
negative status with confirmed absence must no longer fail cleanup.

All nine matrix commands passed: host/config, Linux all-targets Clippy, client-only,
server-only, client without roaming, minimal FFI, compatibility without features and
rustfmt. Rust 1.98.0; the existing `chunks_exact_to_as_chunks` Clippy exception and
no-roaming `terminal_sender` warning remain. No new exceptions were added.
RU/EN documents use the docs gate.

Linux shell fixtures now model prefix snapshots, show dev and family/device-scoped flush.
They were cross-compiled, not run on Linux. New host tests call production functions
through a command model. Evidence:
C:/Users/litvi/OneDrive/Documents/qeli/route-setup-flush-audit-20260923.

## Limits and next pass

There is no atomic kernel CAS or proof of authorship across external races. Checks use
the normal route show/flush context without extending support to arbitrary policy
tables, VRFs or multipath. Link inventory validates index/name structure, not every
device attribute. The journal remains in memory; crash/restart recovery is not added.

Next: route/kill-switch/gateway command deadlines and output bounds while retaining
the pending contract. A hung process can still hold the operation mutex. Other
TUN/pushed/local-route paths, overall gateway rollback, Q14-F027 TUN workers/FD,
cross-process isolation and Q05 preflight deadlines/async waits remain in the plan.
No real Linux E2E, native certification, devices or new benchmark were run.
User INI, API and ABI are unchanged.

Previous pass: [pending and orphan records](AUDIT-Q25-ROUTE-PENDING.md).

The next pass is complete within its stated scope: [command bounds and IPv4 protection](AUDIT-Q25-CLIENT-COMMANDS.md).
