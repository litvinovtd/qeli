# Q25-F161: directory-enumeration errors during archive restore

1 October 2026. Base: 5ceeb390. D07 remains **IN_PROGRESS**.

The archive import used flatten() in four directory scans. If read_dir opened a directory but failed on an individual entry, the code silently skipped it. During staging this could omit a file from validation or the archive name set; during publication it could report success for an incomplete restore; during exact cleanup it could conceal an uninspected live file.

An entry-read error in staging now aborts before publication, and one during publication returns a server error. An error while scanning the live directory during exact cleanup appears in the incomplete-cleanup warning. A staging scan failure receives HTTP 500 like other server-side I/O failures. The archive format and INI format are unchanged.

On isolated lab .11, formatting, 26 ordinary backup tests, strict Clippy, and two native root tests passed: backup → overlay/exact restore inside a separate mount/network namespace, and rollback snapshot refusal for an unreadable file. The live .10 service was untouched. Logs: archivels1.log and archivenative1.log in C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase. An individual read_dir iterator failure was not fault-injected; that rare branch was reviewed in code, while existing tests cover the normal path.

The external-editor race when the editor ignores the advisory lock, and other mixed save/reload/import paths, remain in D07. Register: **5/15 DONE**.