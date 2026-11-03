# Q14 — NAT, forwarding and DNS REDIRECT setup deadlines

<!-- normative-sync: audit-q14-nat-setup-budget-v1 -->

24 September 2026. Base: `c2f97aeb469c3ff48e4295c4ea5f0fc5cf17d22c`.
D05/D09 continuation; [debt register](../../plans/AUDIT-DEBT.md).

## Q14-F036, P2 — independent command deadlines and unbounded setup admission

NAT44, IPv4 forwarding, managed IPv6 routing and DNS REDIRECT waited for the firewall
mutex without a deadline, then renewed 15 seconds for every insertion, check and deletion.
Setup errors ran a tag sweep with independent command budgets. Exact records survived,
but incomplete immediate rollback was not part of the returned setup error.

Each setup boundary now shares 15 seconds across queueing, discovery, WAN reads,
old-tag cleanup, registries, rule insertion and verification. Checks before/after sysctl
calls do not interrupt their internal I/O. An expired observation cannot authorize
FORWARD/ACCEPT fallback or successful completion. Exact specs are retained before mutation.

A common wrapper handles every error after admission and verifies rollback of all retained
NAT rules for the profile and its IPv6 sysctls with a separate shared 15-second deadline.
These are profile startup boundaries: a failed profile cannot continue. Rollback keeps the
firewall mutex; failed admission never cleans up another operation. Incomplete rollback
adds `NAT rollback incomplete` and keeps records for lifecycle retry. Global IPv4 forwarding
still belongs to the worker and is released at final cleanup.

DNS INPUT and REDIRECT UDP/TCP now share one `DNS firewall setup` deadline. A redirect
failure runs NAT rollback, followed by the INPUT lease's separately bounded Drop cleanup.
This is not a 30-second whole-DNS-teardown guarantee: distinct sequential cleanup operations
have distinct budgets. Manual IPv6 keeps firewall/forwarding with the administrator.
Unused bool REDIRECT, IPv4 WAN and per-command cleanup helpers were removed.
INI, public C ABI and wire format are unchanged.

## Validation

10 new Linux regressions: expired/busy admission, registry contention before mutation,
shared insert deadline with fresh rollback, queue time, two-family rollback, retained failed
deletion, expired FORWARD inventory, late success, IPv4/IPv6 REDIRECT and INPUT consuming
DNS setup time. Fixtures run real child processes with private rule files and never change
the host firewall.

1475 host unit + 71 config tests, all 9 feature/cross/lint commands PASS.
**1991 ordinary Linux + 31 privileged + 8 worker E2E PASS**.
Seven disabled-deadline controls fail on the expected assertions (exit 101); restored
sources pass **10 setup + 7 DNS + 8 cleanup + 2 native tests**. The first control runner
stopped before modifying sources because its template did not handle CRLF;
v2 retained registry admission deadlines and therefore still rejected a late queued
operation; v3 also restores the old blocking lock behavior. All early outcomes are retained.

Linux Rust 1.97, host Rust 1.98; existing Clippy `chunks_exact_to_as_chunks` allowance.
318 source hashes verified before/after full and counterfactual runs.
Worker SHA256: `c7acda0f71a49029475c4b371b23a56a83256a320009938dc494742f5348c9c9`.
Source archive SHA256: `f81268c81ec758e62365159522f3b39797dd5d68f357e3105212900e20668150`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/nat-setup-phase/`,
`nat-setup-final.log`, `lifecycle-nat-setup/`, `nat-setup-counterfactual-v3/`.
Private namespaces on `.11`; live `.10` was unchanged.

## Open obligations

D05 remains open: client routes/gateway, scheduler isolation and internal sysctl/I/O need
further work. These deadlines do not interrupt synchronous metadata/spawn/kill/reap or
bound the entire sequence of several families/profiles. Crash journaling, backend identity
and external mutations retain D02/D04/D06 limitations. This run adds no current benchmark
or release provenance.

[Manual](../../manuals/CONFIG.md) · [Troubleshooting](../../manuals/TROUBLESHOOTING.md)
