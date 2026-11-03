# Q25 — kill-switch refresh budget and unknown inspections

<!-- normative-sync: audit-q25-killswitch-refresh-v1 -->

Date: 24 September 2026. Base: `2bc5faff107ef5b8bc100cb345515c9ae59f43d2`.
D05/D09 continuation in the [debt register](../../plans/AUDIT-DEBT.md).

## Q25-F086, P2 — refresh renewed the deadline for every command

Server-address refresh before reconnect waited for the operation mutex without a
limit and granted each inspection/mutation its own 15 seconds. The queue, IPv4 and
IPv6 shared no deadline. The earlier `disengage` fix did not cover this path.

`refresh_server_ips` now receives 15 seconds at entry. Name resolution, operation-mutex
admission, both families and all commands share one absolute deadline. The system
resolver remains synchronous: the timer cannot interrupt a stalled DNS/NSS call, but
its late return cannot start firewall commands. Cleanup reuses the same `Budget` and
retains its previous guarantees.

Context checks the deadline before spawn and after command completion; refresh checks
again before reporting success. Timeout retains ownership and does not remove DROP or
OUTPUT/FORWARD hooks. When insertion applied but was not confirmed before expiry, the
previous address remains allowed. A separate invocation receives a new budget and
verifies actual rules. The Linux connect loop handles refresh failure by stopping
reconnect and retaining protection; automatic same-session retry was not added here.

## Q25-F087, P2 — unknown inspection authorized insertion

The initial `-C <chain> -d <server> -j ACCEPT` used a boolean helper:
permission/backend/timeout errors became `false`, followed by insertion. Existing
rules could not be distinguished from failed inspection. `present_checked` now has
three outcomes: present skips insertion; confirmed absence permits it; unknown reports
an error without inserting that rule. Unverified replacements retain old allowances.
Independent, successfully checked addresses may have been added before another failure;
refresh is not an atomic transaction across the entire set.

## Validation

Six new Linux regressions cover:

- Expiry before/during resolver execution: no firewall commands after a late reply.
- Busy operation mutex: timeout without starting commands.
- Queue time consumes the first command's budget instead of granting a new deadline.
- IPv4/IPv6 share a deadline and retain ownership for a separate verified retry.
- Actual insertion into a private fixture before delaying acknowledgement: old allowance
  and DROP remain, no second-family command starts; retry confirms the new address and
  retires the old one.
- Unknown initial inspection: no insertion/deletion, followed by a successful separate retry.

These use real shell children/the production collector, actual pinned namespaces and
private rule-model files without modifying the host firewall. PATH/environment are
unchanged. Existing privileged tests additionally cover address rotation and kernel
firewall work; the new fixtures do not measure a delayed kernel backend.

A counterfactual restored only independent command deadlines and boolean inspection,
preserving ownership and bounded admission. Three targeted scenarios failed as expected
(exit 101): the shared family budget, unverified insertion, and unknown → mutation.
Both sources were then restored byte-for-byte. Cleaning only the qeli package in its
private target forced a fresh build: **6 refresh + 5 cleanup tests PASS**.
This compares old behavior at the same boundaries, not an entire previous commit.

Full fixed snapshot before the counterfactual: **1471 host unit + 71 config PASS**,
all **9 feature/cross/lint commands PASS**, **1954 ordinary Linux + 30 privileged PASS**,
**8 worker lifecycle E2E PASS**, TCP/UDP × off/manual/route/nat66. Two ignored child
helpers run through parent tests. Worker E2E is a broader server regression.
Host Rust 1.98, Linux Rust 1.97; previous Clippy `chunks_exact_to_as_chunks` allowance.
All 312 source hashes were verified before/after the full and counterfactual phases.

Worker SHA256: `4a6bd59329a6ac137e15e592b685239ef369d76955a311203e1b5dd27f96d59f`.
Source archive SHA256: `350e2ae01a8b9d6e2840c3504a5042bfb02329059367d123e9cf5e6aa46b400f` (312 files, pre-commit snapshot).
Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/killswitch-refresh-phase/`,
`killswitch-refresh-final.log`, `lifecycle-killswitch-refresh/`,
`killswitch-refresh-counterfactual/`. Work ran on `.11` in private namespaces;
the active `.10` server was unchanged. No release or benchmark ran.

## Remaining boundaries

This is a shared admission/command deadline accounting for resolver time, not a hard
wall-clock bound for reconnect. DNS/NSS, short registry mutexes, filesystem/namespace
inspection, spawn and kill/reap cannot be forcibly interrupted by the timer. The API
remains synchronous. Failures may leave partial additions or already confirmed deletions
of stale addresses. Process-local ownership is not persistent crash recovery; after
process exit remaining rules require inspection. INI parameters and ABI are unchanged.
[Setup and rollback](AUDIT-Q25-KILL-SWITCH-SETUP.md) are addressed by the following phase.
NAT/routes/gateway, other lock waits and full D04/D05/D09 remain open.

[Previous cleanup phase](AUDIT-Q25-KILL-SWITCH-BUDGET.md) ·
[Manual](../../manuals/CONFIG.md#kill-switch-kill_switch) ·
[Troubleshooting](../../manuals/TROUBLESHOOTING.md)

Follow-up: [Q25-F098](AUDIT-Q25-KILL-SWITCH-REBUILD.md) fixes the crash-rebuild leak window. Exact temporary DROP guards survive failure/repeated SIGKILL and retire after replacements are ready; the earlier limitations describe the historical snapshot. Overall deadlines, external firewall writers and remaining D04 criteria stay separate.

D05 follow-up: [Q25-F103 — shared system resolver](AUDIT-Q25-SYSTEM-RESOLVER.md) bounds DNS/NSS waiting and call count, supports cancellation and avoids blocking-pool waits during runtime destruction. Earlier synchronous DNS-wait statements refer to the previous snapshot; network mutations and full D05 remain open.
