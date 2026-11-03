# Q25-F153: panel authentication validation before saving INI

1 October 2026. Base: `c96c4062`. D07 remains **IN_PROGRESS**.

Review found a save/apply mismatch for `[web]`: an enabled panel with an empty `password_hash` and `insecure_no_auth = false` passed both editors and history restore. After writing, `reload_web_settings` refused to apply the change although the API claimed live application; after a full restart, `web::start` did not start the panel. This can happen when removing the hash in the raw editor or turning off explicit no-auth mode in the structured editor.

A shared guard now checks the final hash after restoring masked secrets and rejects this edit before creating a snapshot or replacing the working INI. It covers structured and raw saves and history restore. A disabled panel may still preserve dormant settings; `insecure_no_auth = true` still explicitly permits unauthenticated access. An obsolete source comment claiming that the raw API exposes the unmasked hash was also corrected.

On isolated lab .11, four authentication combinations after INI parsing, the raw-editor test group, `cargo fmt --check`, and strict Clippy passed. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/panlauth6.log`. Running services were unchanged.

The remaining server-field runtime matrix and the race with manual editors that do not take the advisory lock remain under D07. Register: **5/15 DONE**.
