# Q14 — DNS INPUT lease admission, deadlines and retirement

<!-- normative-sync: audit-q14-dns-input-budget-v1 -->

Date: 24 September 2026. Base: `93f968d9348020dd6e924163a669feb9e29eecf1`.
D05/D09 continuation in the [debt register](../../plans/AUDIT-DEBT.md).

## Q14-F035, P2 — DNS lease waits and setup lacked a shared deadline

The preceding NAT-cleanup phase bounded the DNS cleanup callback, but lease Drop and
setup still waited for firewall/registry mutexes without a deadline. Installation also
gave UDP, TCP and verification commands separate budgets. One DNS INPUT ruleset could
therefore consume multiple command deadlines after an unbounded queue.

Installation of one ruleset now shares 15 seconds from entry across mutex admission,
tool discovery, cleanup of previously retired generations, UDP/TCP insertion and checks,
and the empty-INPUT/ACCEPT fallback. A late command result cannot report success or start
another setup command. A failed installation drops its armed lease after releasing the
setup lock; rollback receives a separate 15-second cleanup budget.

Lease cleanup shares 15 seconds across both mutexes, tool discovery, UDP/TCP checks and
deletions. Deadline expiration preserves exact pending evidence. A separate profile or
worker cleanup can verify actual absence; an applied but late-acknowledged deletion does
not establish success for the expired attempt. The shared NAT budget implementation now
labels the operation in its error message. The obsolete unbounded INPUT-policy helper
was removed; INI parameters, API/ABI and wire format are unchanged.

## Retirement must precede fallible admission

Simply replacing blocking locks with timed admission would leave an active registry
entry after a lease expires before obtaining the lock. Active entries are intentionally
excluded from retry. Each lease now holds a unique generation token sharing an atomic
retirement flag with its registry entry. Cleanup publishes retirement before any lock
wait; dropping the token publishes it too, without locking or performing I/O. The
registry retains exact rules until verified cleanup, including after timeout or unwind.
An old token cannot mark a replacement generation because each generation has its own flag.

Atomic publication can occur during a cleanup callback, after retry took its snapshot.
Two guards are required for this new concurrency model: reservation rechecks for observed
pending entries before creating a generation; final shutdown reports every remaining
entry, whether active or newly retired. A late retirement cannot disappear between the
retry snapshot and a check that only looked for active owners. These guards are consequences
of the new design, not claims that the earlier mutex-serialized boolean had those races.

## Validation

Four portable domain regressions cover token Drop while the registry is locked, stale
tokens, retirement during final cleanup, and retirement during replacement reservation.
Seven new Linux tests cover expired/busy setup and cleanup admission, actual Drop behind
a busy firewall mutex, queue time consuming the next command budget, UDP/TCP sharing
setup time, pending-generation cleanup consuming setup time, fresh rollback time after
expiry, and failed rollback blocking replacement until a verified retry.

The Linux delay tests use real child processes/the production collector, private rule
files and thread-local tool paths. Short injected deadlines are 0–650 ms; production
uses 15 seconds. NAT and DNS timing tests share one fixture and serialization guard.
No PATH changes or host firewall/sysctl writes occur in these fixtures.

One additional privileged regression installs and removes real DNS UDP/TCP rules in
both IPv4 and IPv6 under INPUT DROP, retaining an unrelated administrator rule. It checks
kernel rules, not actual DNS packet delivery. Full snapshot: **1475 host unit + 71 config
PASS**, all **9 feature/cross/lint commands PASS**, **1981 ordinary Linux + 31 privileged
PASS**, **8 worker lifecycle E2E PASS**, TCP/UDP × off/manual/route/nat66. Two ignored child
helpers run through parent tests; worker E2E is broader server lifecycle verification.

Two counterfactuals restoring independent command deadlines failed as expected. Three
additional guard-removal checks failed for delayed retirement publication and the two
new retirement races. All five returned exit 101. These are targeted behavior variants,
not a build of the entire old commit. Three source files were restored byte-for-byte;
a private qeli-package clean forced recompilation. Restored checks passed: **20 domain +
7 DNS deadline + 8 NAT deadline + 2 privileged native tests**.

Host Rust 1.98, Linux Rust 1.97; existing Clippy `chunks_exact_to_as_chunks` allowance.
All 317 source hashes verified before/after full and counterfactual phases.
Worker SHA256: `bcb7f64c4d7387bbf58e22b22e03c78c3d169519f2da26f1d3e2772ecd3a8640`.
Source archive SHA256: `9ff463bf3f51e44bc151ea3d31bfa1127278f564baaee31015eaf0dd7e3dc982` (317 files, pre-commit snapshot).
Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/dns-input-phase/`,
`dns-input-final.log`, `lifecycle-dns-input/`, `dns-input-counterfactual/`.
Checks used `.11` private namespaces; the active `.10` server was unchanged.
No release, benchmark or device certification ran.

## Remaining boundaries

These are per-ruleset INPUT setup/cleanup deadlines. Combined DNS setup can also install
NAT port-53 redirects, whose setup/rollback sequence remains D05, as do other NAT setup,
client routes and gateway operations. Multiple rulesets and cleanup calls each get their
own budgets; this is not a hard 15/30-second worker shutdown or connection guarantee.
Synchronous metadata, allocation/logging, spawn and kill/reap cannot be forcibly interrupted
by this timer. The API and Drop remain synchronous; this is not async scheduler isolation.

Retirement is process-local, with no autonomous background retry or persistent crash
journal. Retry happens at explicit profile/setup/final-cleanup boundaries. After process
exit, exact ownership must be verified separately. Backend/namespace identity, mixed nft,
external mutation and crash recovery retain their D04/D06/D10 limits. D05/D09 are not fully closed.

[Previous NAT cleanup phase](AUDIT-Q14-NAT-CLEANUP-BUDGET.md) ·
[DNS ownership](AUDIT-Q14-DNS-OWNERSHIP.md) · [Manual](../../manuals/CONFIG.md) ·
[Troubleshooting](../../manuals/TROUBLESHOOTING.md)
