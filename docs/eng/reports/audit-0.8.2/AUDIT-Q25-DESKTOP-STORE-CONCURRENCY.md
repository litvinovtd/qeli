# Q25-F178: cross-process desktop profile-store writes

1 October 2026. Base: 627af020. D08 remains **IN_PROGRESS**.

Windows/macOS profile stores used one fixed temporary file and replaced profiles.json without checking changes since Load. Two instances could overwrite newer profiles, interfere through the same temporary path or quarantine a valid file another instance had replaced. This risked losing profile updates and their stored secrets.

Shared ProfileStoreFile now serializes instances through a sidecar lock, records a hash of the exact bytes read and verifies the file has not changed before writing or quarantining it. A conflict throws IOException and preserves the newer disk version; the user must restart the stale instance. Each write gets a unique temporary file, created as mode 0600 on Unix; after data flush it atomically replaces the main version and preserves the prior one as .bak. Profile paths and Windows DPAPI/macOS Keychain plus AES-GCM encryption stay the same. Both READMEs describe the conflict and lock file.

Conformance selftest covered stale create, stale update with .bak preservation, refusal to quarantine a newer file, successful quarantine/recovery, a held lock and writing after release. QeliWin and QeliMac --no-restore builds had no warnings or errors; git diff --check passed.

Only instances using shared ProfileStoreFile cooperate. An external editor ignoring the lock can still write between hash comparison and replace. Mac runtime was not tested without a lab; other adapters and runtime reconnect remain in D08.

Reconciliation on 2 October: [Q25-F210](../../plans/AUDIT-DEBT.md) closes available D08 with iOS single-writer/read-only ownership and explicit external-writer boundaries; 511 .NET, 167 JVM and 12 instrumentation PASS. Earlier counts and pending statements above are historical; Apple runtime is SKIPPED by user decision, not PASS.
