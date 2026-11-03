# Q25-F157: truthful panel live-reload result

1 October 2026. Base: `77172048`. D07 remains **IN_PROGRESS**.

The four server-INI write paths — Quick Start, structured form, raw INI editor, and snapshot restore — all called `reload_web_settings`, ignored its refusal, and responded as if live application had succeeded. Re-reading the newly written INI could fail because of I/O, an external concurrent edit, or parse/validation errors. The previous panel password and settings remained active while the operator saw “applied live”. The reload also changed the login limiter before waiting for the panel-settings write lock; cancelling the request there left a partial update.

`reload_web_settings` now returns success or failure, logs the reason, and retains the previous state after read, parse, or validation errors. All four responses include `web_settings_applied`; when false, the message says the INI was written but panel settings were not applied and asks the operator to inspect the file/log before restarting. The limiter and settings change only after both locks have been acquired, with no suspension between mutations. This changes an internal JSON API response; the persisted configuration remains INI.

On isolated lab `.11`, 37 editor and Quick Start tests, two focused live-reload tests (including a held web lock), `cargo fmt --check`, and strict `cargo clippy --lib --bin qeli -- -D warnings` passed. A diagnostic run exposed the reverse lock order in the first version; the final version acquires the web lock before the limiter lock. Logs: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/webreload1.log` and `webreload4.log`. Running services were unchanged.

A manual editor that does not take the advisory lock can still rewrite the INI after panel publication. The remaining D07 runtime matrix is also open. Register: **5/15 DONE**.
