# Q28: macOS storage and profile keys

<!-- normative-sync: audit-q28-macos-storage-v1 -->

**5 October 2026: stage PASS; Q28 IN_PROGRESS. Plan 27/37 (73.0%), 10 sections remain.**

## Fixes

| ID | Problem and resulting behavior |
|---|---|
| F240 | Native Keychain lookup treated every failure as absence; concurrent instances could also select different generated keys. ProfileKeyCoordinator serializes selection, creation and migration through `.store.key.lock`, with a 1-second contention budget. Native lookup distinguishes item absence from failure; first creation cannot update a duplicate item. Without a known key, encrypted/invalid current archives or backups prohibit first-key generation. Only a completely parsed legacy array authorizes it. |
| F241 | Key files used unbounded reads and malformed/unreadable files looked absent. Daemon ReadChild checked fstat size then copied without a growth budget. BoundedStorage enforces limit+1 maximum consumption, including growth and nonseekable streams. Fallback/journal must contain exactly 32 bytes; invalid/inaccessible files are retained and errors propagate. |
| F242 | Key-provider errors inside the corruption catch quarantined valid archives and returned empty profiles. MacProfileArchive obtains its key before decoding/corruption handling. Access, Save and migration failures propagate without quarantining readable archives. Strict UTF-8, authenticated backups, stale-writer protection, atomic writes and quarantine of genuinely damaged bytes remain. Decrypted plaintext buffers are cleared after use. |

Production coordinator/archive objects are path scoped, with injected native boundaries for isolated tests, not separate test algorithms. Removed unsafe lookup catch-all, unbounded key reads and racy Security/CoreFoundation module initialization; handles use process-lifetime Lazy initialization. Fallback files use UnixCreateMode 0600. Key/profile sidecar locks are separate and never nested.

Unavailable Keychain can use an established valid fallback or migration recovery key. Unknown keys cannot be replaced; conflicting Keychain/fallback/journal sources fail closed. Legacy `/usr/bin/security` ACL/base64 migration retains its recovery journal and exact existing key bytes.

## Verification and limits

- Release QeliMac on Windows/.NET 10: PASS, no errors/warnings.
- `storage-selftest`: **54/54 PASS**: 3 envelope and 51 production coordinator/archive/bounded-reader checks. Includes 16 concurrent coordinator instances, two independent processes, sidecar contention timeout, duplicate item, unavailable/missing/malformed keys, source conflicts, legacy ACL/base64/interrupted migration, backups/stale writers/UTF-8 and Save/migration failure.
- Baseline **5/5 expected FAIL**, exit 1. Original GetOrCreate/FileFind/FileStore and ProfileStore.Load/Save bodies have mechanically injected paths/native calls and static-to-instance adaptation. Rejected Store uses a barrier for deterministic racing. Growth case uses the original post-fstat CopyTo tail. No old Darwin/Keychain API runtime claim.
- Seekable 2 GiB input rejects before Read; growing nonseekable input consumes exactly 33 bytes at a 32-byte budget. Darwin ReadChild calls the tested helper after fd/owner/mode checks; actual syscalls were not executed.
- Shared/Windows source hashes match Q27. Rust/native and 14 checksum rows are unchanged; no fresh Linux/JNI/soak/benchmark claims.
- The Windows `qeli.dll` copied into ignored build output supplies computed config properties during serialization only. These are C#/AES/storage and host FFI tests; not dylib/Intel/ARM ABI, launchd/utun/pf/entitlements or actual Keychain qualification.

Tests create/remove isolated temporary directories; real user profiles/keys and daemon state are not opened. Test secrets are not printed. Actual Mac runtime/sleep/wake/Network Extension/Keychain checks remain **USER SKIPPED**, not PASS. Configuration remains INI-only; JSON is internal DTO/encrypted archive storage.

The lock bounds contention between cooperating Qeli processes, not the owner's native prompts/I/O or direct same-user filesystem edits. The Unix 0600 assertion runs on Unix only; it was not executed or counted in this Windows 54-check run. Missing Keychain/recovery/fallback key requires explicit archive recovery; automatic key rotation is prohibited. Manual replacement with another valid key is unsupported recovery.

## Evidence and next stage

`release/certification/evidence/q28-macos-storage-20261005.json`; immutable execution snapshots: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-storage-20261005`. Original baseline sources, adaptations, logs and SHA-256 are separate from fixed execution results.

Next: daemon/helper and selected profile, plist/IPC/status/log trust, utun/pf/DNS cleanup, Swift Network Extension and build contracts. These Q28 criteria remain open; a partial stage does not increase the full-plan completion percentage.
