# Q25-F112/F113: bounded identity files and fail-closed TOFU

25 September 2026. Baseline `e1323803`. D05/D09, Linux.

## Changes

**F112 — device-id.** The previous code read the entire file for its first 16 bytes,
could block opening a FIFO or wait indefinitely for flock. If storage was unavailable,
it generated a fresh ID on each connection attempt despite promising one per-run fallback.
It now reads only 16 bytes from a regular file, preserving the existing nonzero-prefix
contract including trailing bytes. Missing/short/all-zero files allow generation under
the lock; read errors and special files do not authorize replacement.

The Linux adapter loads the ID once on a joined network worker after obtaining the
password, before the network lease, kill-switch and first carrier/handshake. It caches
the result, including random fallback, for the entire client run. Stop before admission
creates no file; after admission it awaits the worker and starts no new connection.
Lock contention is limited to 15 seconds; failure retains the temporary-ID policy.
Write failure does not discard the chosen ID: it remains in use until exit. Forced Drop
may synchronously join the worker; this does not establish a hard overall I/O deadline.

**F113 — known_hosts.** UTF-8/read errors from `read_to_string` were treated as a missing
pin. A corrupted comment could therefore hide a different existing key and admit a new
one. Returning on the first matching record also hid conflicting duplicates. Appending
without a separator merged a new pin with an unterminated last line, and write/fsync
failure could leave a partially modified store.

TOFU now reads a regular file of at most 1 MiB (at most 1 MiB + 1 bytes to check the
limit). Read, UTF-8, size, malformed target-pin and conflicting-duplicate errors reject
trust, including with `allow_unpinned_tofu = true`. A missing file remains valid first
use. Every matching record is checked; identical duplicates and hex case remain
compatible. Comments and unrelated legacy lines are not treated as the target's pin.

Under the sidecar lock, the store is read again and the new pin is published through
shared `write_atomic_private`, with a line separator, `0600`, file/parent fsync and atomic
replacement. Partial-write/file-fsync failure preserves the original file. Parent-fsync
failure after rename may already leave the new file, but is not reported as successful
persistence. `allow_unpinned_tofu` only allows lock/persistence failure for a new pin after
a validated snapshot; it does not bypass unreadable/corrupt existing storage or size
limits. An explicit `key` is still checked independently of the TOFU file.

Implementations moved from the large client module into `identity_files`, without copies.
INI, wire protocol, public C ABI and other platforms' file adapters are unchanged.

## Validation

- **15 new regressions**: 6 portable reader/pin tests, 6 Linux file tests and 3 adapter
  tests. Coverage includes an infinite reader, UTF-8/size, conflicting/malformed pins,
  a 16 GiB sparse file retaining its ID, FIFO without a writer, lock timeout,
  atomic/private store, missing newline, adapter-lifetime fallback and stop before/after admission.
- **16 native scenarios: 8 baseline + 8 fixed**, TCP/UDP × device-lock, corrupt TOFU
  with both allow_unpinned_tofu values, and TOFU fsync failure. Baseline records 0
  heartbeat ticks under the lock; fixed records **8** per roughly 800 ms interval
  and waits for lock release before exit. After stop, fixed starts no carrier/TUN or TOFU.
- **4 baseline corrupt-store cases connect with a different key** and append to the
  file; all 4 fixed cases reject without post_up or file mutation. This reproduces the
  consequences of local store corruption, not a remote ability to modify that file.
- **2 baseline fsync faults** mutate the old file despite returning a client error;
  **2 fixed faults** preserve original bytes and remove temporary files. Every case
  restores original routes/firewall and leaves no client TUN.
- An additional **6 established TCP/UDP teardown cases** (2 baseline + 4 fixed) and
  **2 explicit recoveries** verify successful first TOFU, later connections, `stopped`,
  sticky cleanup-fault `failed` and retained kill-switch recovery.
- **1575 host + 71 config; 2148 Linux + 48 privileged + 8 lifecycle PASS**.
  All 9 host/cross/feature/lint/format commands PASS. RU/EN docs and diff are checked.

## Evidence and limits

Only lab `10.66.116.11` was used, with private NET/mount/PID namespaces and separate
`/run`, `/var/lib`, `/var/log`, `/tmp`, `/etc/qeli`; working server `10.66.116.10` was
untouched. The C shim intercepts only fixture TOFU-file fsync in the test client.
Installed services were not changed. Windows/Rust 1.98, Linux/Rust 1.97.

`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/identity-files-phase/evidence.json`
verifies 356 source files, frozen tar, hashes, 16 identity cases and 6 teardown cases.
All final Linux checks use build v2. In v1, a new test incorrectly sent to an already closed
admission channel; only the test was changed to use a shared flag. Original FAIL logs
are retained. Runtime-v1 had two baseline startup failures from a long Unix socket;
runtime-v2 exposed the dedicated 0700 directory requirement. Fixture-v4 uses a short path
in a private directory; runtime-v3 reruns all 16 cases with the same binaries. The initial
method-placement failure log is also retained. The packet/firewall matrix was not rerun.

Worker `c7f8f9a2a6b23b1480489fbc1a74ce5b7050b811be611da206ad5835bc82d509`.

Fixed driver `b6b518fe033e731832eab3bb18a62ecd37bca3f5e8da17940bdf11016d3289e7`.

Baseline driver `dc58d95673f5ba06f5f8e8b51ec97877ef1bd0bd603ddc43b8976ffa30fb15b1`.

**D05 remains IN_PROGRESS.** TOFU read/lock/atomic-write still run synchronously in the
async identity callback; handshake timeout/stop cannot interrupt an admitted syscall.
Moving this to a detached thread would be insufficient: ownership, joining and trust
decisions must survive cancellation. Whole NetworkPlan/shutdown deadlines and other
startup I/O/Drop paths remain. Path/interprocess context belongs to D06; this is not a
benchmark or whole D08/D10/D13 completion. Windows VM, Mac/iOS and router runtime are
user-approved SKIPPED; final Android validation remains D12.
Debt: 4/15 DONE, 9 IN_PROGRESS, 2 TODO.

25 September 2026 reconciliation: synchronous TOFU callback I/O moved to the [joined Q25-F114 worker](AUDIT-Q25-IDENTITY-WORKER.md). Overall shutdown deadlines remain D05.
