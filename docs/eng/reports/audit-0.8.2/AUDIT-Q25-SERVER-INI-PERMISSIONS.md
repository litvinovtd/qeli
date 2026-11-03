# Q25-F140: private permissions after panel writes server INI

26 September 2026. Base: `85d51e57`. D07 remains **IN_PROGRESS**.

Five panel paths that save the active server INI used ordinary `write_atomic`.
That function inherits an existing file's mode and uses `0644` for a new file.
The server INI contains the administrator password hash, inline user hashes,
and may contain other secrets. An old `0644` file therefore remained readable
by local users after a panel edit. The `set-web-password` CLI already used a
private atomic write; archive restore separately normalizes extracted files
to `0600`.

All five panel paths now use one `write_server_config` helper that publishes a
new inode through `write_atomic_private` with mode `0600`: structured form,
raw INI, Quick Start, history and lockout settings. History snapshots were
already private. The existing size, revision and rollback-snapshot checks
remain in place.

On isolated Linux lab host `.11`, a direct test started with an existing
`0644` INI, saved through the same helper used by the panel, and checked the
`0600` mode and exact bytes. All 34 editor-module tests, `cargo fmt --check`,
and strict `cargo clippy --lib --bins -- -D warnings` passed. Log:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/serveriniprivate.log`.

The fix protects **subsequent** writes; it cannot undo prior access to
secrets. D07 remains open for the full field matrix and guarantees against
external writes between the last check and atomic publication.
