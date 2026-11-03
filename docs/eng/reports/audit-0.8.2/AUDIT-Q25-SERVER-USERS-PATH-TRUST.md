# Q25-F144: trust boundary for custom auth.users_file

1 October 2026. Base: `d10e6452`. D07 remains **IN_PROGRESS**.

`auth.users_file` names a file written by CLI `add-client`, a `share-link --reset` password reset, the panel and the control socket. Previously worker/supervisor and `check-config` admitted a custom path from a mode-`0666` or symlink server.conf; the CLI could reach `UsersDb::update_locked` as well. Such an INI could redirect a privileged write to another absent path or an existing valid INI file.

The gate now uses the trust decision for the same opened inode that supplied the values. When `auth.users_file` differs from the fixed `/etc/qeli/users.conf`, `check-config`, both startup paths and `add-client` require a regular file owned by root or the effective UID, with no group/world write and no symlink. `share-link` checks immediately before an actual password reset; reissuing an already recoverable password remains read-only. Worker/supervisor reject before creating the state from which panel and control-socket writes obtain the path. The fixed default path remains usable without authorization for arbitrary paths.

Verification: one unit test retains denial after a later `chmod 600` of the same pathname and confirms a newly trusted snapshot; `cargo fmt --check`, strict Clippy and Linux CLI matrix on isolated .11: `check-config`, `server`, `_worker`, `add-client` reject mode `0666`; symlink rejects; no users file is created; then mode `0600` permits `check-config` and `add-client` and creates a private users file. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/userspathtrust3.log`.

D07 still needs the complete field/path matrix, combined save/reload/import coverage and the external-write race between panel validation and publication. This change does not alter configuration formats: the users file and server config remain INI.
