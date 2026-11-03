# Q25-F145: SIGHUP and restart parity for users_file

1 October 2026. Base: `28e07945`. D07 remains **IN_PROGRESS**.

After Q25-F144, SIGHUP still discarded the trust decision for the opened INI. It could accept a custom `auth.users_file` from a mode-`0666` file and replace live VPN-auth users even though startup and `check-config` reject that file. If the path changed, SIGHUP loaded the new users while the panel and control socket continued writing to the path retained from startup. Reads and writes then targeted different databases.

SIGHUP now retains trust for the same opened inode and rejects a path change or an untrusted INI with a custom path. Rejection keeps live users and brute-force state intact. A full process restart applies a path change. Form, INI and history responses also set `needs_full_restart` for `auth.users_file` and `web.persist_session_key`. The direct worker-only restart endpoint rejects these before stopping the live worker. Full/worker restart preflight re-reads one file snapshot and verifies `users_file` and explicit `identity_key` trust before dispatch; otherwise restart could stop the working process without a viable replacement.

Verification on isolated .11: existing SIGHUP failure/success test; new async regression for a path change, untrusted INI and later trusted reload; full-restart decision test; direct restart API tests including rejection before systemd/worker dispatch; `cargo fmt --check` and strict Clippy. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/sighupuserspath5.log`. No live systemd restart was invoked: the isolated test verifies refusal before dispatch, not a complete deployment scenario.

The complete D07 field/path matrix, combined save/reload/import coverage and external-write race between final panel validation and publication remain. Register: **5/15 DONE**.
