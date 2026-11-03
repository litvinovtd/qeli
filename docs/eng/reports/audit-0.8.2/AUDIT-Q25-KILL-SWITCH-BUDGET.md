# Q25 — shared standalone kill-switch cleanup deadline

<!-- normative-sync: audit-q25-killswitch-cleanup-budget-v1 -->

Date: 24 September 2026. Base: `082bf305ae35cda104d53f8f60792badd170ea09`.
Partial closure of D05/D09 in the [debt register](../../plans/AUDIT-DEBT.md).

## Q25-F085, P2 — each command received a fresh timeout

`disengage` waited for the operation mutex without a limit. Every subsequent jump/chain
inspection or deletion received its own 15 seconds. IPv4 and IPv6 had no shared deadline.
With a slow backend, even a finite number of deletion attempts could delay shutdown:
a per-command timeout did not bound the sequence. Owner/namespace evidence was retained,
but this operation had no shared time budget.

## Fix

Each `disengage` attempt receives 15 seconds at entry. Operation-mutex admission via
`try_lock`, all inspections and mutations across both families share one absolute
deadline. Checks occur before/after admission, before spawn and after command completion,
and before removing the owner from the registry. Expired attempts start no new children;
a late successful acknowledgement cannot report overall success.

The deadline belongs to the attempt's context, not its owner. Failure retains both
original families, tool paths and the pinned namespace. A new `disengage` receives a
fresh budget, verifies actual jumps/chains and releases ownership only after success.
A mutation may already have applied before timeout: cleanup can be partial, so this
does not promise every protection rule is retained. Identity/exact-target checks remain.

INI parameters, ABI, persisted formats and connection admission are unchanged. This
covers the Linux standalone kill-switch; engage/refresh and gateway/NAT/routes budgets
remain open. Setup/refresh retain their previous per-command timeouts.

## Validation

Five new regressions cover:

- Expired admission rejects even an available mutex; a held mutex returns timeout.
- Expired cleanup contexts start no commands.
- Successful acknowledgements arriving after the deadline are rejected.
- Both families share one budget; no new second-family command starts after expiry,
  ownership remains and a separate attempt succeeds.
- A fixture command actually deletes a private jump file before delaying its reply.
  Timeout preserves ownership and the chain, and starts no second-family command;
  retry verifies the remainder, completes both families and releases ownership.

Three checks are portable. Two use real Linux shell children/the collector, private
fixture files and a real pinned namespace without modifying the host firewall.
Command substitution changes neither PATH nor environment. This establishes orchestration
and process-boundary behavior; existing privileged regressions cover kernel firewall work.

A counterfactual changed only budget checks and `output_until` back to independent
command deadlines while preserving ownership/admission. Both Linux regressions failed
as expected (exit 101). Sources were restored byte-for-byte; after `cargo clean -p qeli`
in the private target all five focused tests passed. This restores old behavior at the
same boundary, not a full previous-commit baseline. The full run below preceded the
counterfactual and used the identical fixed source snapshot; all 311 source hashes were
verified before/after both phases.

**1471 host unit + 71 config integration PASS**; all 9 feature/cross/lint commands PASS.
Linux: **1948 ordinary + 30 privileged PASS**, **8 worker lifecycle E2E PASS**
(TCP/UDP × off/manual/route/nat66). Two ignored child helpers run through their parents.
Host Rust 1.98; Linux Rust 1.97; the previous Clippy `chunks_exact_to_as_chunks` allowance
remains. Worker lifecycle is a broader server regression, not a new client kill-switch test.

Worker SHA256: `61ba915fb4d423271d6761747579081a9fc351cb5d03237751b127422d0edf3e`.
Source archive SHA256: `f182b2f503277efecacad4c164bc358379539c11cd83c8f835819af2cb0e26f3` (311 files, pre-commit snapshot).
Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/killswitch-budget-phase/`,
`killswitch-budget-final.log`, `lifecycle-killswitch-budget/`,
`killswitch-budget-counterfactual/`. Linux checks ran on `.11` in private namespaces;
the running `.10` server was unchanged. No release or benchmark ran in this phase.

## Remaining boundaries

This is a shared command/admission deadline, not a hard wall-clock bound for complete
client shutdown. Namespace verification, short registry mutexes, filesystem I/O, spawn
and kill/reap cannot be forcibly interrupted by this timer. This API is synchronous.
Deadline expiration does not make earlier deletions atomic or provide persistent crash
recovery. Once the process exits its registry is unavailable; remaining firewall rules
require administrator verification. D04/D05/D09 are not fully closed.

[Ownership and identity](AUDIT-Q25-KILL-SWITCH-IDENTITY.md) ·
[Manual](../../manuals/CONFIG.md#kill-switch-kill_switch) ·
[Troubleshooting](../../manuals/TROUBLESHOOTING.md)

Next phase: [shared refresh deadline and unknown inspections](AUDIT-Q25-KILL-SWITCH-REFRESH.md). The refresh command sequence is addressed within the stated limits; [setup and rollback](AUDIT-Q25-KILL-SWITCH-SETUP.md) are addressed by the following phase. Synchronous DNS/NSS remains open.
