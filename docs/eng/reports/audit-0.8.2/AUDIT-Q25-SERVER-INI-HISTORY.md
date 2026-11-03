# Q25-F190 — server INI history errors

Status: code fix prepared; targeted Linux verification awaits access to VM .11.

The history API previously returned ok: true with an empty or incomplete list when directory enumeration or snapshot reads failed. Snapshot rotation silently skipped enumeration and removal errors, potentially exceeding its ten-entry limit.

The listing now treats only a missing history directory as an empty initial state and propagates other metadata, enumeration, file-type and read errors. Rotation aborts a config save before replacing the live INI if scanning or removal fails. A regression test covers the absent directory, a valid snapshot and an invalid UTF-8 snapshot.

Windows rustfmt --check passed. Portable cargo test --lib passed 1551 tests (one ignored), but does NOT compile the server web module or execute the new test. SSH to .11 still rejected the previously supplied root credential after the VM reset. D07 remains IN_PROGRESS until the Linux server test and API check run. Unrelated user edits to CHANGELOG.md and users.html were left untouched.

Continuation on 2 October: [Q25-F209 in the register](../../plans/AUDIT-DEBT.md) closes mixed API save/INI/history/Quick Start/archive/restart checks for D07 and specifies the mandatory external-writer sidecar lock. Historical counts above are not a new execution. Network combinations and final certification remain D10/D15.
