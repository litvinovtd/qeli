# Q25 — kill-switch setup deadline and verified rollback

<!-- normative-sync: audit-q25-killswitch-setup-v1 -->

Date: 24 September 2026. Base: `db7fb09e32aa523913e5c92130deac21f4ef1e07`.
D05/D09 continuation in the [debt register](../../plans/AUDIT-DEBT.md).

## Q25-F088, P2 — setup renewed command deadlines and waited without a limit

`engage` previously waited for the operation mutex without a deadline and gave each
command its own 15 seconds. Discovery, admission, IPv4/IPv6 and egress checks did not
share a budget. The earlier cleanup and refresh fixes did not cover installation.

Setup now starts a 15-second absolute deadline at entry. Resolver elapsed time, mutex
admission, tool fallback probes, firewall admission, both families and egress queries
consume that deadline. No command starts after expiry, and a late command result cannot
produce success. DNS/NSS is still synchronous; its late return prevents firewall work
but the resolver itself cannot be interrupted by this timer.

Rollback must still work after setup expires. Its separate 15-second deadline starts
lazily at the first rollback and is shared by inner family recovery and final recovery
across both families. It is never renewed within the attempt. Cleanup uses the same
pinned namespace and remembered tool paths. An error before ownership binding does not
trigger rollback of an existing policy; an error after binding attempts recovery of
recorded families and retains ownership until verified explicit cleanup/retry.

## Q25-F089, P2 — leak overrides could accept incomplete rollback

If family programming failed, `engage_family` attempted cleanup but its caller treated
both a clean refusal and failed rollback as merely an unprotected family. With
`allow_ipv4_leak = true` or `allow_ipv6_leak = true`, setup could report success despite
an unresolved partially installed chain.

The attempt now retains the first rollback failure and checks it before evaluating leak
overrides. Incomplete recovery rejects setup, even with both overrides enabled. Final
recovery may still remove more rules; the call remains a failure. If final cleanup fails,
the error says `kill-switch setup rollback incomplete; ownership retained` and preserves
process-local evidence for a separate verified cleanup. No successful ENGAGED result is
reported for this case. Overrides still permit an explicitly accepted unprotected family
when its failed installation was completely rolled back.

## Validation

Eight Linux regressions use real subprocesses, the production collector, pinned
namespaces and private rule-model files, without changing PATH or the host firewall:

- Expiry before/during resolution starts no commands and does not claim ownership.
- A busy operation mutex expires without firewall admission.
- Queue time consumes the first inventory command's remaining budget.
- IPv4/IPv6 share setup time; expiry during the second family rolls back the armed first.
- A mutation applied before a delayed acknowledgement is removed using the separate rollback budget.
- Inner and final rollback share one deadline; incomplete cleanup retains evidence and a separate cleanup succeeds after the fault is removed.
- A no-op chain deletion cannot be accepted by either leak override.
- Tool fallback and egress probes use the owned command deadline; failed inventory remains unknown.

The first full attempt failed five tests: the new shell fixture missed `-t filter`, and
unrelated timing fixtures competed for the operation mutex. The tool model now handles
that argument prefix; setup/refresh/cleanup timing fixtures share a test-only serial guard.
The queue assertion also requires an actual deadline error. That failed attempt is retained
under `killswitch-setup-phase/initial/` and `killswitch-setup-final.log`; it is not counted as a pass.

The corrected snapshot passed **1471 host unit + 71 config tests**, all **9 feature/cross/lint
commands**, **1962 ordinary Linux + 30 privileged tests**, and **8 worker lifecycle E2E**,
TCP/UDP × off/manual/route/nat66. Two ignored child helpers run through their parent tests.
The new tests model rule storage; existing privileged tests exercise real kernel rules.
Worker E2E is a broader server regression, not a measurement of a delayed client kernel backend.

After that full run, a counterfactual restored independent command deadlines and ignored
rollback failure while preserving namespace ownership and bounded mutex admission.
The shared-family deadline and incomplete-rollback tests both failed as expected (exit 101).
Both files were restored byte-for-byte and the private qeli target cleaned to force a
fresh compile: **8 setup + 6 refresh + 5 cleanup tests PASS**. This reproduces the old
behavior at those boundaries, not an entire previous commit.

Host Rust 1.98; Linux Rust 1.97; existing Clippy `chunks_exact_to_as_chunks` allowance.
All 313 source hashes were verified before/after the full and counterfactual phases.
Worker SHA256: `608b0633c4d0f7b0a0cdcb97e5b2f9a84942de47797797b6dc07169c6c49b39c`.
Source archive SHA256: `802696d0813f87ac7034aa1a5019897d3b27cf7ea5dec14fa9db0ee752aa58cc` (313 files, pre-commit snapshot).
Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/killswitch-setup-phase/`,
`killswitch-setup-verified.log`, `lifecycle-killswitch-setup/`, `killswitch-setup-counterfactual/`.
Checks ran on `.11` in private namespaces; the running `.10` server was unchanged.
No release or benchmark ran.

## Remaining boundaries

The two budgets are not a hard 30-second wall-clock guarantee. DNS/NSS, short registry
mutexes, filesystem/namespace checks, spawn and kill/reap are not forcibly interrupted
by this timer. The public API is synchronous. Setup and recovery are not atomic:
some rules may already be gone, so failed rollback does not prove intact protection.
Process-local ownership does not provide persistent crash recovery. After process exit,
inspect exact chains in the original namespace before manual recovery. INI and ABI are unchanged.
NAT/routes/gateway deadlines, durable recovery and full D04/D05/D09 remain open.

[Previous refresh phase](AUDIT-Q25-KILL-SWITCH-REFRESH.md) ·
[Manual](../../manuals/CONFIG.md#kill-switch-kill_switch) ·
[Troubleshooting](../../manuals/TROUBLESHOOTING.md)

Follow-up: [Q25-F098](AUDIT-Q25-KILL-SWITCH-REBUILD.md) fixes the crash-rebuild leak window. Exact temporary DROP guards survive failure/repeated SIGKILL and retire after replacements are ready; the earlier limitations describe the historical snapshot. Overall deadlines, external firewall writers and remaining D04 criteria stay separate.

D05 follow-up: [Q25-F103 — shared system resolver](AUDIT-Q25-SYSTEM-RESOLVER.md) bounds DNS/NSS waiting and call count, supports cancellation and avoids blocking-pool waits during runtime destruction. Earlier synchronous DNS-wait statements refer to the previous snapshot; network mutations and full D05 remain open.

Follow-up: [Q25-F104](AUDIT-Q25-RESOLVER-FILES.md) moves resolver-file reads before firewall setup, shares bounded admission with NSS and unifies the reader/parser with stub detection. Historical results above are unchanged.

Follow-up: [Q25-F107/F108](AUDIT-Q25-FIREWALL-TASK.md) moves firewall operations to joined workers and prevents flushing a chain when hook removal is unconfirmed. Historical results above are retained; overall D05 remains open.
