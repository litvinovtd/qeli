# Q32: usage reset at the atomic publication boundary

<!-- normative-sync: q32-usage-v1 -->

8 October 2026. F384 / Q32-F005. Review covers `server/usage.rs`, TCP/UDP counter
registration, quota sweep, shutdown and the reset API. Q32 remains IN_PROGRESS:
logs, trace, roaming metrics and notification trust still need qualification.

## Failure and fix

`write_atomic` syncs the temporary file, renames it, then syncs its directory.
A final-step error returns `PublishedWriteError`: new bytes are visible, but
survival after power loss is uncertain. `reset_and_flush` restored old memory
on every error even though the file already contained zero. String error
wrapping also discarded the typed cause. Control incorrectly said no reset occurred.

The fix preserves the cause through `anyhow::Context`. Pre-publication errors
restore previous usage. After successful rename, memory retains the published
reset. The response remains `ok=false` and explicitly reports uncertain durability.
A later successful flush confirms persistence and counts only new traffic.
The API schema is unchanged.

## Reproduction

The Linux harness uses the actual `UsageStore`, production atomic writer and
`atomic_file.rs`. A writer seam executes creation, writing, file fsync and rename,
then injects failure only at directory sync. This is injected I/O failure, not an
actual power-loss test. The baseline changes only the writer call seam and retains
the old rollback and string error wrapping.

Old behavior reproduces zero on disk versus 700 bytes in memory. The fixed harness
passes 16 tests: 15 usage and one atomic-file. The new test verifies the typed cause,
both directions, another user's unchanged totals, new 20+5 bytes, repeated flush
and retirement. An existing negative test verifies pre-publication rollback.
A separate control test uses the real writer to check both response messages.

The first fixed harness stopped on an incorrect test assumption that
`Error::to_string()` prints the full `anyhow::Context` chain. The assertion now
uses `{error:#}`; the failed log is retained. The small harness has an unused-import
warning for the complete writer. Strict Clippy qualification concerns the full crate.

## Qualified behavior and limits

Supervisor uses a read-only store and reloads before its API response. Worker
acquires exclusive ownership before loading writable state. Unreadable or corrupt
existing accounting prevents startup without erasing the file. Legacy total
migration attributes old bytes to download and is idempotent. Existing tests cover
monotonic folding, saturating totals, short sessions, the last writer's tail,
reset of an active session and concurrent accumulation.

Download quota is checked by a periodic sweep, not enforced at every packet.
Hard SIGKILL skips final flush; unpersisted traffic since the last successful
periodic write may be lost. This does not establish power-loss durability, disk-hang
handling or VPN E2E. `usage.json` is internal state; configs remain INI only.

## Full Linux qualification

Immutable `49d20c01` snapshot: 2426 library tests PASS, 60 existing ignored
retained; strict all-targets Clippy with `-D warnings` and debug daemon build
PASS. Tests ran in isolated net/mount/PID namespaces with temporary `/run`,
`/var/lib`, `/var/log` and `/tmp`. Host/service baseline on `.11` matched.
The same patched harness16 passed as UID/GID65534 without extra privileges.
Snapshot and failed preparations are retained in raw evidence.

## Evidence

Packet: `audit-debt-20260924/q32-usage-20261008`. Baseline and patched harness,
immutable Git archive and all logs are retained separately. Three legacy host
firewall rules appeared during the initial baseline. The harness executes no
network-policy commands; their origin remains unknown. That initial host snapshot
is not claimed unchanged. The corrected repeat preserved its network/service
baseline. No unrelated rules were removed.

Windows/macOS and Android arm64/x86_64 passed independent A/B from `49d20c01`.
All317 transferred inputs were verified before and after builds. Exports, macOS
load commands and ADHOC signature structures were checked. WindowsABI22 and Android
ARTJNI23 passed on exact new bytes; originalAVDuserdata, package list and links
were preserved. This is not a managed-app rebuild, ARM runtime, Mac/iOS/router/
Windows VPN E2E or power-loss test. Cross-Mac missing-Xcode-SDK warnings retained.
Different private Cargo roots can change bytes versus the previous packet;
no cross-path hermeticity claim.

Initial native preparation stopped on a path-verifier typo before compilation.
Corrected retry used the same317 verified inputs and independent A/B targets.
On `.10`, only the same three legacy rules changed again. The retry guard excludes
only those exact lines; raw snapshots are retained and wholehost firewall equality
is not claimed. All other snapshot fields and services matched. On `.11`, full
Linux, Android native and JNI snapshots are checked separately. No unrelated rules
were removed.

Full results: `release/certification/evidence/q32-usage-20261008.json`.
Overall remains 28/37 DONE (75.7%), with nine items open.

All six created lab roots removed after saving Git archive, three harness
binaries, full test binary/daemon, eight A/B artifacts, JNI source/DEX and logs.
Resolved paths, absence of process cwd/FD and mounts checked; `.10`745/901
and `.11`777/845 services retained.
