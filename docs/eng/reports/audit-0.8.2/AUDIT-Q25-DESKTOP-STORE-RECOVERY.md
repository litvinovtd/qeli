# Q25-F172: desktop profile-store recovery

1 October 2026. Base: 6d24736f. D08 remains **IN_PROGRESS**.

Windows and macOS previously attempted to move a damaged profiles.json to .corrupt-* but ignored File.Move failures and returned an empty list. A later save could then overwrite the original recoverable file. Legacy/Id migration writes also sat inside the read-error handler: a write failure misclassified a readable file as corrupt and moved it. On macOS, backup-restoration write errors were hidden inside the backup error handler.

Shared ProfileStoreRecovery.PreserveUnreadable now uses a unique GUID name and requires a successful move before opening an empty store or restoring .bak. If the move fails, load throws IOException and leaves the original file in place. Migration writes are outside read-error handling. A failed write of recovered macOS backup now reaches the caller. Client configs remain INI; JSON here is only the internal local profile-store container.

Conformance selftest passed, including exact damaged-file byte preservation and rejection when the move fails. QeliWin and QeliMac dotnet builds with --no-restore passed without warnings or errors; git diff --check passed. UI loading on Mac and Windows VM was not tested because those agreed lab environments are unavailable. Transactional profile editing and reconnect remain in D08.
