# Q25-F141: consistent server INI admission across CLI, panel and runtime

26 September 2026. Base: `b3ce4196`. D07 remains **IN_PROGRESS**.

Two mismatches were found. `check-config` loaded external `users.conf` with the strict helper and rejected an absent file without inline entries, while the worker and supervisor accept that first-run state with an empty database. Shared `validate_profiles` skipped disabled profiles and accepted an INI with every profile disabled; the worker then refused to start. The supervisor did not call this validator before opening the panel. On the isolated `.11` lab host, baseline CLI failed the missing-file case with “No such file”, while reporting `OK` for all-disabled with an existing empty `users.conf`.

`check-config` now uses the same `load_users_db_for_runtime` as runtime. An absent external file is accepted, including when inline entries exist; a malformed or unreadable file remains an error. The common profile rule rejects all-disabled. `check-config`, panel saves, worker and supervisor share it; supervisor applies it before opening the panel. The worker's duplicate check is removed.

Verification: focused unit test of shared validation, `cargo fmt --check`, strict Clippy and a CLI matrix on isolated Linux lab host `.11`: absent users file with an enabled profile, all-disabled and malformed users file; separate supervisor and worker startup rejection for all-disabled. Logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/disabledfixed.log` and `disabledstartup.log` in the same directory. Running services and host `.10` were untouched.

D07 remains open for the full field → parse/validate/runtime/serialize matrix, save/reload/import combinations, and the race against an external write between final validation and publication.
