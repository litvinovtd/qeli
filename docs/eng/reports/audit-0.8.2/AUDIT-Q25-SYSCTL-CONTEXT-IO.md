# Q25 — namespace checks at internal sysctl boundaries

<!-- normative-sync: audit-q25-sysctl-context-io-v1 -->

Date: 24 September 2026. Baseline: `b2ce6e1d`. Partial closure of D02 in the
[debt register](../../plans/AUDIT-DEBT.md).

## Q25-F077, P2 — post-lock admission did not guard subsequent I/O

Namespace admission was checked once after locking. Subsequent PID probes, sysctl
reads/writes and journal persistence used the current context without rechecking it.
A context change inside the operation could reinterpret old PIDs/paths in another
namespace and discard journal evidence of an uncertain result.

Each transaction now retains a `namespace::Guard`. It checks network/PID/time namespace
and procfs compatibility before and after PID/sysctl reads/writes, PID/interface presence
probes, after loading the journal and around persistence. Observed context loss makes the
guard unusable for the rest of the transaction. Returning to the original namespace does
not authorize committing that transaction's already modified in-memory state.

Context errors take precedence over `NotFound`: they cannot prove PID death or interface
absence. Context loss after a write preserves the previously persisted original/owner
evidence. A separate operation in the original namespaces can verify and clean up.
Journal format remains version 2; no new INI configuration or ABI changes are required.

## Verification

Four new regressions use real temporary journal files with fault injection at the shared
host I/O boundary:

- namespace change during PID inspection never probes existence in the foreign context
  or drops the record;
- change after reading the original sysctl cannot acquire in another network;
- change between managed-value inspection and restoration cannot write into another network;
- change after an actual write preserves evidence; the invalidated transaction cannot clear
  it after returning, while a separate release in the original context succeeds.

Results: **1452 host unit + 71 config integration PASS**, all nine feature/cross/lint commands PASS.
Linux: **1909 ordinary + 27 privileged tests and 8 worker lifecycle E2E PASS**.
New tests inject context changes; worker E2E exercise normal production I/O and real
namespace forwarding/RA restoration. These are distinct kinds of evidence.
Linux worker SHA256: `c3f01aec70a4714fc4fba26625e670d7172073334aaf3ec16e568a54f6365576`.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/sysctl-context-phase/`,
`sysctl-context-final.log`, `lifecycle-sysctl-context/`, manifests and commands.

## Remaining D02 work

The guard checks I/O boundaries but does not create an atomic kernel transaction or pin
a network namespace fd. Durable namespace identity reuse, replaced/renamed interfaces
during per-link sysctl recovery and journal parent-directory trust remain open.
Privileged changes between a check and syscall have no atomic protection. Errors detected
after persistence do not promise rollback of a completed journal write.

A separate exploratory Linux probe, `interface-fd-probe.sh`, observed that renaming an
interface makes its open `accept_ra` fd return ENOENT although ifindex stays unchanged;
after delete/recreate the old fd also does not address the replacement. This informs the
next design but is not an implemented sysctl lease contract yet.

[Previous stage](AUDIT-Q25-SYSCTL-JOURNAL-IO.md) · [Instructions](../../manuals/TROUBLESHOOTING.md)

Continuation: [temporary-file cleanup and directory fsync](AUDIT-Q25-ATOMIC-STATE.md).

Subsequent parent-trust closure: [state directory and shared lock](AUDIT-Q25-STATE-DIRECTORY.md).

Continuation: [Q25-F083 — v3 and original sysctl fd](AUDIT-Q25-SYSCTL-TARGET.md). Historical limitations above describe this report’s snapshot; name disappearance no longer permits forgetting the original.
