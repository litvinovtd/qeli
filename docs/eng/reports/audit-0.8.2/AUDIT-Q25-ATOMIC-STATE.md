# Q25 — atomic state publication failures and durability

<!-- normative-sync: audit-q25-atomic-state-v1 -->

Date: 24 September 2026. Base: `e92ccd53`. Partial closure of D02/D05/D09 in the
[debt ledger](../../plans/AUDIT-DEBT.md); no new full-audit sections are opened.

## Q25-F078, P2 — partial writes left temporary files

Shared `util::write_atomic[_private]` removed the temporary file after rename
failure, but early returns from `write_all` or `sync_all` bypassed cleanup.
Space/quota exhaustion or I/O errors left `.qeli-tmp-*`, including fragments of
private state. Mode 0600 remained intact, but unused copies and disk usage accumulated.

A guard now owns the file created by this operation until successful rename.
Preparation errors and unwinding close the descriptor before removing the file;
removal errors are logged. Publication disarms the guard so it cannot delete the
new destination. This guard cannot guarantee cleanup after SIGKILL or on an
unavailable/failing filesystem.

## Q25-F079, P2 — syncing data did not persist the filename change

After file fsync and rename the function returned success without syncing the
parent directory. Sysctl also removed its final journal without directory fsync.
A completed operation therefore did not confirm durability of the filename change.

On Unix the directory is opened before writing, followed by file fsync → rename →
directory fsync. Removing `sysctls.state` syncs its directory too. Retrying removal
of an already absent file repeats fsync: the previous attempt may have completed
unlink but failed synchronization.

Errors before rename leave the previous destination. A directory fsync failure
after rename returns `published ... persistence is uncertain`: new bytes are
already visible, without automatic rollback. Removal reports the equivalent state.
Reread configuration and revision before retrying a save; a write error alone does
not prove that nothing changed. INI and public ABIs are unchanged. Windows retains
its previous file-sync/rename behavior; Unix directory durability is not claimed
for Windows.

## Verification

- 4 new portable regressions cover failed rename, parent open, directory fsync
  after publication, and retrying synchronization after completed unlink.
- On Linux a child process with `RLIMIT_FSIZE=1024` and SIGXFSZ handling triggers
  an actual partial 8192-byte write. Ordinary/private replacement and private
  creation preserve old data and leave no fragments. The main test runner's
  resource limit remains unchanged.
- A separate `LD_PRELOAD` observer in a disposable process observes four pairs
  of file/directory fsync. Injected EIO in file fsync confirms no publication or
  temporary fragments; EIO in directory fsync confirms published bytes and an
  explicit uncertain-durability error. Two child tests intentionally exit 101
  at unwrap; the outer verifier requires that failure and checks the files.
  These are expected fault probes, not full-suite failures.

Results: **1456 host unit + 71 config integration PASS**, all 9 feature/cross/lint commands PASS.
Linux: **1915 ordinary + 27 privileged + 8 worker lifecycle E2E PASS**.
Worker SHA256: `4dfcfc2f7465c4db65ae42b55ac01058d5089257f5f06501cc8c5a4dbe2a5107`.
Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/atomic-state-phase/`,
`atomic-state-final.log`, `atomic-state-syscalls/`, `lifecycle-atomic-state/`.

Power loss, controller failure, and every HTTP publication scenario were not tested.
Directory fsync does not turn multi-file backup/restore into a transaction. Parent
trust, durable namespace/interface identity, other network budgets and persistent
firewall/DNS/routes recovery remain open. D02/D05/D09 remain IN_PROGRESS.

[Previous phase](AUDIT-Q25-SYSCTL-CONTEXT-IO.md) · [Troubleshooting](../../manuals/TROUBLESHOOTING.md)
