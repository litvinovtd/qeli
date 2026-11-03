# Q05/Q07 — backup/restore budget and snapshot completeness

<!-- normative-sync: audit-q05-archive-budget-v1 -->

Date: 24 September 2026. Baseline: `96d222f8`. Continuation of D05/D09 in the
[debt register](../../plans/AUDIT-DEBT.md).

## Q05-F005, P2 — unbounded tar commands and stdin writers

Uploaded archive validation already had limits, but download, archived INI reads,
snapshot and extraction used separate unbounded commands. Archive input was fed by
a separate thread. A child could stop reading, endlessly write stdout/stderr or hang
while holding the config lock.

The shared runner now supports optional stdin in the same owned future that drains
both outputs and waits for the child. Deadline/output errors stop all three pipe
operations, then kill and reap the child. The separate archive writer thread is gone.
Synchronous callers retain the joined worker with a private runtime. Ordinary network
commands and hooks continue to receive closed stdin.

Download/restore share a **60-second preparation budget**, including config-lock
admission, structural validation, tar and network preflight. Remaining time is passed
between phases. An expired restore refuses before publication. Once publication
begins, filesystem renames/pruning/cleanup finish under the lock: the timer must not
itself create a half-restored tree. I/O failures remain failures; whole-tree atomicity
and automatic rollback were not introduced.

Output limits: portable gzip **16 MiB**, matching panel upload admission; pre-restore
gzip **64 MiB**; listing/archived INI/extraction diagnostics **16 MiB** per stream.
Overflow discards partial output. A complete snapshot is first successfully collected
in a bounded buffer and then atomically saved with mode 0600. Failed new commands do
not rotate previous valid snapshots. Restore structural limits of **5000 entries /
64 MiB expanded data** remain intact.

All tar phases use the same explicit options, `LC_ALL=C`, and remove `TAR_OPTIONS`
and `GZIP` from their environment. This prevents listing/extraction interpretation
from diverging. Configurations remain INI; the internal API format is unchanged.

## Q05-F006, P1 — incomplete rollback snapshot reported success

The pre-restore snapshot used `--ignore-failed-read`. GNU tar could omit an unreadable
file and return exit 0, allowing restore without the promised complete copy of the
old tree. The flag is removed for snapshots; non-successful tar refuses restore before
publication. Portable download retains its optional-file policy and verifies required
runtime dependencies against the actual archive.

## Q05-F007, P2 — duplicate restore was queued

The internal restore try-lock was acquired after the shared config lock. A second
HTTP request waited for the first, then performed another restore despite the promised
concurrent refusal. Admission is now reserved before waiting for the config lock and
transferred to the blocking worker. A duplicate immediately receives HTTP 409, including
while the first restore waits for another config writer. Cancelling the first request
does not release admission from its still-running worker.

## Verification

- **1448 host unit + 71 config integration PASS**, all nine feature/cross/lint commands PASS.
- Linux: **1905 ordinary + 27 privileged tests PASS**, all **8 worker E2E PASS**.
- New pipe regressions cover simultaneous stdin/stdout/stderr, a child not reading stdin,
  output overflow, cancellation and expiry before spawn. A real loopback child witness
  must close after failure/cancellation.
- Native GNU tar under UID 65534 succeeds on a readable file and refuses mode 000;
  restoring the old `--ignore-failed-read` reproduces false exit 0 on the same fixture.
- Expired restore never reaches archive/path handling; lock admission timeout does not
  release the active writer. Existing tar/listing/permission tests PASS.

Linux worker SHA256: `130c2912ef920ec837452eb8e91c85f01c198e19f14efd6efa2de26b4aaaa1e5`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/archive-budget-phase/`,
`archive-admission-final.log`, `lifecycle-archive-admission/`, manifests and check commands.
The complete handler roundtrip download → overlay → exact restore and malformed gzip
refusal passed in separate mount/network namespaces. It checks INI, key preservation,
extra-file removal only in exact mode, no staging/upload residue and two mode-0600
rollback snapshots. These invoke production handlers; auth middleware and actual HTTP
transport are not tested here.

## Remaining boundaries

D05 is not fully closed: other network sequences and waits still need shared budgets.
Filesystem/kernel I/O and kill/reap can exceed the soft deadline; this does not promise
a hard 60-second response. After publication begins, disk failures may leave a partial
result; the pre-restore snapshot provides a manual recovery path. Crash/ENOSPC at each
publication boundary and full HTTP/systemd E2E remain D07/D09. A compressed size limit
does not replace other restore acceptance checks. The lab host's active `/etc/qeli`
was not changed.

[Previous stage](AUDIT-Q05-PANEL-TRANSACTIONS.md) · [Instructions](../../manuals/TROUBLESHOOTING.md)

RU/EN documentation: 232 Markdown files, all nine gates PASS.
