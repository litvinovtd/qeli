# Q25: refuse unscoped legacy global DNS recovery

Date: 24 September 2026. Baseline: `da27ec6b`. Q25-F101 is fixed within the stated scope.
D04 remains **IN_PROGRESS**: live persistent TUN and the full mixed firewall matrix remain.

## Finding

**Q25-F101, P2 — an old snapshot authorized changes to a foreign resolver without ownership evidence.**
`dns-backup.json` records only kind/target/content/mode, without boot ID, network or
mount namespace, the current `/etc/resolv.conf` inode or evidence that Qeli still owns
it. Startup nevertheless restored it automatically. PID-only `dns-holders` was checked
in the caller's PID namespace; the lock was released before changing the resolver.
Trusted state directory permissions could not supply the missing identity.

A real baseline client in private namespaces confirmed four changes to the administrator's
resolver: content replacement, deletion, symlink replacement and `1.1.1.1`/`8.8.8.8`
substitution for `managed-no-original`. The snapshot was then removed. A dangling
backup symlink counted as absence; FIFO input and a held `dns-holders.lock` delayed
startup until forced test termination. Malformed backup paths retained the snapshot
but could still create a lock/change holder state.

## Decision and removed code

Automatic replay is removed: old records cannot safely distinguish Qeli crash leftovers
from DNS already reconfigured by its owner. The trusted held state directory is checked
for `dns-backup.json` and `dns-holders` using metadata without following the final symlink.
Any entry, including empty, corrupt, directory or FIFO, requires administrator recovery
and stops client startup before DNS commands.

Contents are not read, PIDs are not interpreted, and legacy locks are neither opened
nor awaited. `/etc/resolv.conf`, backups, holders and their locks remain untouched.
Metadata errors do not mean absence. A stable `dns-holders.lock` alone does not block
a new client: a sidecar without backup/holders does not establish pending recovery.

Removed `dns_backup` automatic restore/unlink/symlink/chmod and public DNS fallback,
PID refcount helpers and unused capture/write test implementations. Tests of withdrawn
behavior are replaced with refusal regressions; per-link DNS tests remain. The lower
test count is intentional, not a skipped suite. Configuration remains INI; no new config,
recovery command or legacy snapshot format is added. New sessions still use systemd-resolved.

## Validation

- **1526 host + 71 config; all 9 feature/cross/lint checks PASS**.
- **2078 Linux + 43 privileged + 8 worker lifecycle PASS**.
- 4 portable and 3 Unix regressions cover absence/lock-only, payload kinds/corruption,
  holder-only/live/stale PID, directories, ordinary/dangling symlinks, FIFO and metadata errors.
- New `scripts/audit_legacy_dns_recovery.py`: 12 real client starts in separate
  network/mount/PID namespaces, with private `/etc`, `/var/lib`, `/run` and `/var/log`.
  Checks cover resolver content/type/inode, exact legacy evidence preservation, explicit
  refusal and prompt completion. `dns = off` does not permit legacy replay either.
- **Baseline 15/47 PASS, 32 FAIL** against the new contract; four checks detect actual
  resolver changes. These are 32 failed assertions, not 32 independent defects.
  In file/absent/symlink/fallback cases the timeout reflects reconnect after the dangerous
  operation, not blocked recovery. FIFO/locked-holder stop before connection. The
  no-legacy control reaches connection to the test address.
- **Fixed client: 47/47 PASS**. The no-legacy control preserves the resolver
  and reaches connection; the other 11 cases refuse explicitly and promptly.
- Linux packet matrix: **17/17 cases, 489 assertions PASS**;
  real resolved DNS and SIGKILL/restart, route crash recovery, kill-switch, IPv4/IPv6,
  TCP/UDP, split/TAP and MTU/PMTU checks remain enabled.

Source snapshot: 340 files, archive SHA256 `4df30a4035df14b6fdb6165b51fafddc75690a8588397a7388d276107e909b5b`.
Worker SHA256: `3f52a9d5c1b3484592d5df9214372eebb7f90e44b30265df20b5d714325de8c0`.
Baseline worker SHA256: `de18b1b171701704e548c0d4067fbfa7d398f9567f434c95aedc1d97ab228fed`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/legacy-dns-phase/`,
`legacy-dns-baseline-v2/`, `legacy-dns-fixed-v1/`, `legacy-dns-final-v1.log`,
`lifecycle-legacy-dns/`, `packet-matrix-legacy-dns-v1/`. Baseline and fixed runs use the
same runtime harness; source is verified before/after Linux and against the git index.
Symlink/FIFO fixtures remain in the original tar files; only regular files/directories
and metadata evidence are extracted on Windows. Initial collection refused FIFO
extraction; this was an artifact extraction limit, not a client failure.
Linux Rust 1.97, host Rust 1.98; the existing Clippy `chunks_exact_to_as_chunks` exception remains.

## Operations and boundaries

This is an intentional compatibility boundary: automatic global snapshot restoration
from old releases is no longer supported. Stop the old client cleanly before upgrading.
If legacy state remains, verify the original network/mount view, stop its owners,
restore DNS through its network manager or a verified original, then archive only the
resolved backup/holder records outside their active names. Unknown originals do not
choose public DNS for the administrator. See
[§6.20](../../manuals/TROUBLESHOOTING.md#620-linux-legacy-resolver-recovery-failed-backup-kept).

Concurrent older binaries or another root are outside this coordination contract.
Metadata checks and subsequent operations are not atomic; internal filesystem I/O
has no hard wall-clock interruption. None of these boundaries enables automatic replay.
D04 legacy global DNS is closed through safe refusal and documented manual migration,
not automatic repair of arbitrary old hosts. Live persistent TUN and mixed nft/firewalld
remain; overall **3/15 groups DONE (20%)**. `.10` was untouched; native tests used isolated
namespaces on `.11`. Windows VM/Mac/iOS/router runtime remain SKIPPED by user decision.

[Debt register](../../plans/AUDIT-DEBT.md) · [Operations](../../manuals/OPERATIONS.md)

24 September follow-up: [persistent TUN/TAP validated in 17 crash scenarios](AUDIT-Q25-PERSISTENT-TUN.md). Safe refusal and explicit removal of a verified orphan close this portion of D04; the full mixed firewall matrix remains open.

Final D04 follow-up: [client mixed packet/recovery matrix and Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) completed; D04 is DONE in the current register. Historical IN_PROGRESS statements above refer to earlier snapshots. D10 (broader policies/topologies) and D13 (state growth) remain open.
