# Q25-F192 — shared Windows/macOS settings storage

Status: code and local checks completed on 1 October 2026; physical macOS runtime is skipped per the user's lab decision.

Both clients independently read settings.json without a size limit. On load failure they ignored a failed move of the original to .corrupt and returned backup settings or defaults, so a later save could overwrite the unreadable original. File.Exists could also misclassify an access error as an absent file.

Shared AppSettingsStore preserves the internal format and UTF-16 BOM compatibility. It bounds reads and writes to 1 MiB, rejects malformed UTF-8, writes through a private atomic temporary file, and distinguishes a missing file from an access failure. A corrupt primary must be preserved under a unique .corrupt name before fallback; failed preservation stops loading. Windows and macOS now use the same file layer.

Seven targeted file conformance checks passed: first run, backup, malformed UTF-8, oversized write, UTF-16 BOM, oversized input, and failed Windows quarantine of an open file. Full managed selftest with host native ABI 1.16: ALL PASS. QeliWin and QeliMac --no-restore builds: zero warnings and errors. External-writer concurrency and physical macOS runtime remain unverified; D08 stays IN_PROGRESS.
