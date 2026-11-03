# Q25 — state-directory trust and lock identity

<!-- normative-sync: audit-q25-state-directory-v1 -->

Date: 24 September 2026. Base: `ebe7aa8d`. Partial closure of D02/D05/D09 in the
[debt ledger](../../plans/AUDIT-DEBT.md).

## Q25-F080, P2 — trusting the final file did not protect its parent path

`sysctls.state` rejected symlinks/hardlinks and unsafe file modes, but
`create_dir_all` and subsequent operations traversed the parent path repeatedly.
Replacing the directory could redirect locking, reading and writing into different
trees; the journal's owner was not independently checked.

The state directory is now opened from `/` component by component using `openat`
with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`. The absolute path must contain neither
`..` nor symlinks and is limited to 64 components. Permissions/ownership are checked
before creating descendants. Missing directories are created with mode 0700;
creation is synced through the parent fd.

The final directory cannot be group/world-writable. An intermediate root-owned
sticky directory is allowed, but its next component must belong to root or the
calling UID: root does not adopt a foreign pre-planted `/tmp/qeli`. The chain
allows root, the caller, and one owner delegated a protected child by root, such
as `/var/lib/qeli`. This preserves root CLI/`User=qeli` cooperation while rejecting
unrelated ownership changes along the chain.

The directory remains open for the transaction; lock, journal, temp, rename and
unlink use `/proc/self/fd/<fd>/...`. Renaming the original directory cannot redirect
the operation into its replacement. The journal and strict sysctl lock admit root
or the directory owner, reject group/world write and require a single hardlink.
The lock inherits the admitted directory's owner, not an unread journal's owner.
Journal v2, INI and public ABIs remain unchanged.

## Q25-F081, P2 — waiting for flock could acquire an obsolete lock domain

An opened lock could be renamed/replaced while a process waited for flock. After
acquiring the old inode it continued, although another process could already own
the replacement at the original pathname.

Shared `FileLock` now rechecks regular/single-link status after flock and compares
the fd's dev/inode with the current pathname without following a final symlink.
Strict sysctl policy also checks ownership and permissions before/after waiting.
Replacement protection also applies to ordinary shared FileLock callers. A mismatch
returns `lock changed while waiting` without deleting the other lock.

## Verification

Two portable ownership/permissions-policy regressions. Linux regressions cover
symlinks, unsafe parents, relative/parent paths, preserving the original tree after
rename, unsafe lock mode, changed directory permissions and lock replacement during
waiting under both policies. The latter waits for the second thread's actual open fd.

A privileged test creates a service-owned UID 65534 directory beneath a protected
root directory. Root creates journal/lock with the right uid/0600; another process
running as UID 65534 reads, locks and rewrites them. Foreign UID 65533 inodes are
refused without silently normalizing their ownership or data. Fixtures are temporary;
real service credentials/configuration are not replaced.

Results: **1458 host unit + 71 config integration PASS**, all 9 feature/cross/lint commands PASS.
Linux: **1922 ordinary + 28 privileged + 8 worker lifecycle E2E PASS**.
Worker SHA256: `21fbf2ae272c0e6810948cfedf664c1589c4385bbccb25aa2f80f565c5d9637e`.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/state-directory-phase/`,
`state-directory-shared-final.log`, `lifecycle-state-directory-shared/`.
The intermediate run before extending protection to shared FileLock is retained
separately in `before-shared-lock/`; it does not substitute for final evidence.

## Limits

The admitted directory owner remains a trusted participant in shared coordination.
Arbitrary privileged mount/permission changes between checks and syscalls do not
become an atomic transaction. Matching procfs and access to the process's own fds
are required. Symlink-based `STATE_DIRECTORY` values must use the actual trusted path
for all participants. The shipped unit uses `StateDirectory=qeli` without DynamicUser
and needs no change. A new root-private directory does not itself delegate access to
a future service: the service directory must be owned by its intended UID.

Parent trust is closed within these boundaries. Durable namespace identity and the
original interface generation for per-link sysctl recovery remain open in D02; the
whole group remains IN_PROGRESS. Other network budgets and persistent recovery also
remain open.

[Previous phase](AUDIT-Q25-ATOMIC-STATE.md) · [Troubleshooting](../../manuals/TROUBLESHOOTING.md)
