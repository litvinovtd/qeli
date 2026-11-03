# Q25 — ownership of the original interface sysctl

<!-- normative-sync: audit-q25-sysctl-target-v1 -->

Date: 24 September 2026. Base: `1b466a8328f7fb6bba63222170d9bf1005d3706c`.
Partial closure of D02 in the [debt register](../../plans/AUDIT-DEBT.md).

## Q25-F083, P1 — name-based restoration changed a replacement or lost the original

An actual worker at `1b466a83` changed WAN `accept_ra` from 1 to 2. Stopping after
`wan0 → wan-old` rename removed the journal while leaving the original interface at 2.
After deleting/recreating `wan0`, stop wrote the old value 1 into the replacement,
which had been set to 2. Forcing reuse of the original ifindex produced the same result.
All three defects were reproduced on `.11` in separate network/mount/PID namespaces;
the running `.10` server was unchanged. Zero baseline probe exit codes mean successful
defect reproduction, not correct old behavior.

Name, existence and ifindex do not prove object continuity. An absent old pathname is
also insufficient: the original interface survives rename.

## Fix and boundaries

`sysctls.state` moves to version 3. Named-interface `rp_filter`/`accept_ra` entries contain
a random lease identifier and an open procfs file stamp, `dev:inode:ctime_sec:ctime_nsec`.
The read/write fd is captured before reading the original and publishing ownership.
Reads, writes, verification and restoration use that fd at offset 0. Procfs, file type,
errors/short writes, a read limit and namespace Guard around I/O are checked. `all`/`default`
and global settings do not receive per-interface identity.

A bounded process-local registry retains the fd together with its pinned namespace Context.
Validated loaded/persisted journal snapshots release unused entries; the limit is 256
objects per process, not 256 total fds. Uncertain publication evidence remains until the
next validated journal snapshot. Internal state is not a user config: configs remain INI,
with no new parameters or ABI changes.

Another process may share a lease only with a matching stamp and a confirmed live v3
owner. The owner is checked **after** opening the candidate: otherwise death between
PID checking and open could free the old inode. The stamp includes ctime because procfs
uses a wrapping inode counter. This is evidence backed by a live owner, not a durable
interface generation. The relevant mechanisms are in
[Linux v6.12 proc_sysctl.c](https://github.com/torvalds/linux/blob/v6.12/fs/proc/proc_sysctl.c).

Restoration never reopens the pathname. After rename/delete/recreate the old fd may
return ENOENT; Qeli retains the original, reports failure and continues independent
cleanup. Once all live descriptors are lost, including SIGKILL, even a matching current
stamp cannot authorize automatic replay. Startup recovery refuses before starting a
profile. When `original == managed`, there is nothing to write and the entry can be
released without accessing the interface. Verified external changes to the original
object remain intact.

Unsafe writes into replacements and silent loss of originals are therefore closed by
refusing uncertain operations. Transparent rename/crash recovery is not claimed: manual
inspection or a planned reboot is required. Durable namespace generation for global entries
after namespace destruction remains D02. Concurrent privileged administrator mutations
do not receive an atomic kernel transaction. Persistent firewall/DNS/routes and independent
worker firewall coexistence remain D04/D10.

## Moving from v2 to v3

Nonempty v1/v2 state from the current boot is preserved without automatic migration.
V2 reports `legacy v2 host sysctl journal lacks live descriptor ownership`. Stop old
participants and complete recovery before upgrading while original interfaces remain
verified. Do not blindly run old name-based recovery after rename/replacement. A planned
host reboot is the alternative. Empty v1/v2 and valid previous-boot state are accepted
without replaying old values. Corrupt state and unknown versions cannot bypass validation
using an old boot-id. Concurrent mixed journal versions are unsupported. Manually changing
version/boot-id or removing entries to force startup loses original evidence.
[Troubleshooting](../../manuals/TROUBLESHOOTING.md).

## Final snapshot validation

- 11 new portable regressions: last owner, replacement/rename/delete, replacement
  between original read and write, crash cache loss, unchanged values, cross-cache sharing,
  witness death during open, migration, registry limit and same inode with different ctime.
  Removed the obsolete check that allowed forgetting an original after name disappearance;
  the interface inventory probe is no longer used.
- Native Linux: the production fd of the original dummy interface cannot read or change
  a replacement with the same name and forcibly reused ifindex 42. The old fd returns
  ENOENT and the replacement stays at 2.
- **1468 host unit + 71 config integration PASS**. All nine host/feature/cross/lint commands
  PASS; Windows Rust 1.98, Linux-target Clippy with only the existing
  `chunks_exact_to_as_chunks` allowance.
- Linux Rust 1.97: **1932 ordinary + 29 privileged PASS**. Two child helper tests are
  not invoked standalone; their parent tests invoke them. **8 worker lifecycle E2E PASS**:
  TCP/UDP × off/manual/route/nat66, setup, rejected reload, control lease and stop/cleanup.
- **5 additional worker E2E PASS**: rename, replacement, reused ifindex, SIGKILL/restart
  and two separate processes sharing sysctl. The first three retain the original and
  report cleanup failure without changing replacements; after SIGKILL no new profile
  starts and independent global settings are restored. Two processes retain 2 → 1 → 0
  owners and restore RA 1 only on the last stop. This verifies shared sysctl ownership,
  not independent worker firewall isolation.

Tests used private namespaces; production namespaces/services were unchanged. These are
lifecycle checks, not a benchmark or evidence for external packet traffic, systemd
supervision, release builds or all platforms.

Worker SHA256: `671b639d1fc8b002cbbe344540dc2fe9e890519dc562dce189f235f06cd5e2f6`.
Source archive SHA256: `1f7d8d5ee80d6f59f1db2da5985cfccc80f13534116ef01546ed7e0e5a9cbd70`
(306 `qeli`/`conformance` files; code tested before committing).

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`,
`interface-recovery-phase/` (commands, host logs, manifest, fixture scripts),
`interface-recovery-final.log`, `lifecycle-interface-recovery-final/`,
`sysctl-target-final-{rename,replace,reuse-index,crash,shared}/` and matching logs/rc,
`sysctl-baseline-{rename,replace,reuse-index}/`. The earlier `interface-recovery-first`
run tested an intermediate snapshot and does not replace these final results.

[Previous namespace pin phase](AUDIT-Q25-NAMESPACE-PIN.md) ·
[Configuration contract](../../manuals/CONFIG.md)

Subsequent D02 closure: [namespace generation and journal v4](AUDIT-Q25-NAMESPACE-GENERATION.md). V3 results above describe the earlier snapshot; per-interface witness remains required.
