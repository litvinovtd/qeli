# Q25-F142: profile names cannot escape the server key directory

30 September 2026. Base: `fba54679`. D07 remains **IN_PROGRESS**.

Profile names previously rejected commas but allowed `/` and `\`. The default private identity-key path is built as `/etc/qeli/identity/<profile>.key`, so `[profile:../escape]` changes the target to `/etc/qeli/escape.key`. A safe `qeli check-config` baseline on isolated lab host `.11` reported `OK` for that INI. The baseline did not write a key outside the private directory.

Shared `is_valid_profile_name` now rejects both path separators as well as commas. The INI parser, panel form, user profile references and startup validation use this rule. The public identity-key load and rotate helpers also check the name immediately before filesystem access, including for programmatically created `ProfileConfig` values. An explicit `identity_key` remains the administrator's way to choose a different path.

Verification: two focused unit tests for names and absence of filesystem effects, `server_ini_audit` tests, `cargo fmt --check`, strict Clippy, and a Linux CLI pair: unsafe name rejected, ordinary name with `@` accepted. Logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/identitybaseline.log` and `identityfixed.log`.

Existing profiles with path separators need manual renaming, including `users.conf` references. To preserve the old private key and client pinning, set `identity_key` to the old absolute path after renaming. D07 remains open for the full field/path matrix; trust in an arbitrary `identity_key` from external INI needs a separate audit.
