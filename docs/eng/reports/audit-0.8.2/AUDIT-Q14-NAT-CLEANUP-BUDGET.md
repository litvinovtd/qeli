# Q14 — shared NAT cleanup deadline

<!-- normative-sync: audit-q14-nat-cleanup-budget-v1 -->

Date: 24 September 2026. Base: `bdfc0a5ebb60018ca68d660aea2e2128b8aa03c3`.
D05/D09 continuation in the [debt register](../../plans/AUDIT-DEBT.md).

## Q14-F034, P2 — cleanup renewed deadlines across rules and families

Server cleanup waited for the firewall-programming mutex without a deadline. Each
inventory, exact check, deletion and fallback probe then received its own 15 seconds.
A large set of rules or a delayed backend could consume many consecutive budgets;
the per-command limit did not constrain one cleanup attempt.

`cleanup(profile)`, startup `cleanup_all()` and final `finish_owned_cleanup()` now each
receive a 15-second deadline at entry. The firewall mutex, exact-rule/DNS/IPv6-lease
registry admission, tool discovery, sweeps, exact IPv4/IPv6 rules and retired DNS UDP/TCP
rules share the attempt's remaining time. No new command starts after expiry and a
late acknowledgement is not successful cleanup. The xtables `--wait 5` remains inside
the shared deadline, and the existing output bounds still apply.

Only confirmed absence removes an exact rule or retired DNS generation from its
registry. A deletion may already have applied when its acknowledgement times out;
the record stays pending until a separate attempt checks actual state. Successfully
verified earlier removals are retired normally. Individual failures still allow
other work while budget remains; expiry stops new external operations without
forgetting unverified records. A new invocation receives a fresh budget.

Sysctl recovery/release is checked before and after its synchronous call. An expired
attempt cannot start the next sysctl step or turn a late return into success. This
does not interrupt an in-flight sysctl operation: its journal/lock/I/O boundaries keep
their own semantics. An already released IPv6 scope may retain an in-memory retry
record after a late return; a later no-op release can verify and retire it.

Historical tag sweeps retain their best-effort mixed-nft policy for non-deadline errors.
Expiration is separately fatal even when there are no exact rules left. This does not
make an unlistable historical ruleset verified, nor add durable firewall ownership.
The independent DNS-lease cleanup callback now shares 15 seconds across its two
transports, but its preceding Drop/setup mutex waits remain outside that callback budget.

## Validation

Eight Linux tests use the production process collector and private shell rule models,
with thread-local tool paths, no PATH changes and no host firewall/sysctl mutations:

- Expired/busy admission for profile, startup and final cleanup starts no commands or callbacks.
- Blocked exact-rule, DNS and IPv6 registries exhaust the deadline without discarding ownership.
- Firewall-queue time consumes the first sweep command's remaining budget.
- Exact IPv4/IPv6 share a deadline; an applied but unacknowledged deletion stays pending and a separate cleanup succeeds.
- Retired DNS UDP/TCP share a deadline; a partial generation blocks replacement until verified retry.
- Final NAT and DNS cleanup share a deadline; expired work does not start IPv4 sysctl release, while a fresh retry does.
- Startup sweeps share a deadline; late synchronous recovery/release callbacks cannot report success or start further commands.
- A delayed fallback probe is bounded by the remaining deadline.

Full fixed snapshot: **1471 host unit + 71 config tests PASS**, all **9 feature/cross/lint
commands PASS**, **1970 ordinary Linux + 30 privileged PASS**, and **8 worker lifecycle E2E PASS**,
TCP/UDP × off/manual/route/nat66. Two ignored child helpers run through parent tests.
The full privileged run includes actual duplicate-rule removal for both families and
preservation of a sibling profile. The delay tests use short injected deadlines (30–650 ms) and model command outcomes
rather than measuring a stalled kernel backend; production uses 15 seconds. Worker E2E is broader server lifecycle verification.

A subsequent counterfactual restored independent command deadlines and accepted late
results while keeping bounded mutex admission. Four targeted scenarios failed as
expected (exit 101): exact families, retired DNS transports, final cleanup and startup
sweeps. The source was restored byte-for-byte; cleaning only the qeli package in its
private target forced recompilation. **8 deadline regressions + 1 privileged exact-rule
test PASS** on the restored code. This restores those old behaviors, not a whole old commit.

Host Rust 1.98, Linux Rust 1.97; existing Clippy `chunks_exact_to_as_chunks` allowance.
All 315 source hashes verified before/after the full and counterfactual phases.
Worker SHA256: `b0509ba484573adcbc92c3c554e6d7ed387171cf03d2c74335cb7b7a55c37e90`.
Source archive SHA256: `e771bf6b9eb8b8a0dedb5363bf0ea396d9f96239f03fb927a668463a80a85df5` (315 files, pre-commit snapshot).
Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/nat-cleanup-phase/`,
`nat-cleanup-final.log`, `lifecycle-nat-cleanup/`, `nat-cleanup-counterfactual/`.
Checks ran on `.11` in private namespaces; the active `.10` server was unchanged.
No release, benchmark or device certification ran. INI/API/ABI/wire contracts are unchanged.

## Remaining boundaries

This is one cleanup attempt's admission/command deadline, not a hard 15-second bound
for worker shutdown or restart. Each profile cleanup and the final worker pass are
separate invocations. Filesystem metadata, sysctl internals, spawn, kill/reap and kernel
waits are not forcibly interrupted by this timer. The APIs remain synchronous.

NAT setup and its legacy rollback sweeps, DNS lease Drop/setup admission, client routes
and gateway sequences remain D05. Crash persistence, namespace/backend identity across
workers and unlistable mixed nft resources remain D04/D06/D10. Cleanup is not atomic
against privileged external changes; after process exit, memory registries cannot
prove which remaining rules belong to the old worker. D05/D09 are not fully closed.

[Exact ownership](AUDIT-Q14-RETAINED-CLEANUP.md) ·
[Earlier command limits](AUDIT-Q14-NAT-COMMANDS.md) ·
[Manual](../../manuals/CONFIG.md) · [Troubleshooting](../../manuals/TROUBLESHOOTING.md)

Follow-up: [Q14-F035 — DNS INPUT setup/Drop](AUDIT-Q14-DNS-INPUT-BUDGET.md)
covers their shared deadlines including admission and retirement without lock waits.
Earlier results above describe their own snapshot. Exact generic NAT and older-generation
outcomes are addressed in [D01](AUDIT-Q14-RETAINED-CLEANUP.md); persistent recovery,
DNS REDIRECT and other NAT setup remain open.
