# Q25-F138: one size limit for server INI

25 September 2026. Base: `f996209c`. D07 remains **IN_PROGRESS**.

Previously the worker read the server INI through a stable descriptor without a
size limit. `check-config` and several CLI and panel paths used unbounded
`read_to_string`. The panel limited HTTP bodies to 16 MiB, but form
serialization and archive restore could still produce a larger INI. On read
errors, the form and raw editors could substitute the startup snapshot for
revision checks and accept a stale request.

`config_source` now limits the server INI to **16 MiB before reading**. The
worker, server CLI commands, panel, Quick Start, history, preflight and archive
restore use the same loader. Panel writes check the serialized result before
creating a rollback snapshot or publishing the file; `set-web-password` also
checks its result. An active-file read error stops editing. The panel's
brute-force settings path checks that the source INI has not changed between
its initial read and snapshot creation. JSON remains an internal HTTP API
transport; flat-INI remains the sole configuration file format.

Checks on isolated Linux lab host `.11`: 16 `config_source` tests, 33 editor
and Quick Start tests, one archive-restore rejection test, `cargo fmt
--check`, strict `cargo clippy --lib --bins -- -D warnings`, a binary build,
and a real `check-config` refusal for a sparse 16 MiB + 1 byte INI. Tests
confirm rejection before parsing and no rollback snapshot on oversized writes.
Logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/serverinilimitv3.log`
and `serverinicliruntime.log` in the same directory.

D07 remains open for the full field → parse/validate/runtime/serialize table,
the combined check-config/startup/SIGHUP/HTTP/Quick Start matrix, and file
replacement **after** the last check but before atomic publication. This
change does not establish compare-and-swap semantics for writes.
