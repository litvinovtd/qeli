# Q25-F156: panel hash validation at admission and live reload

1 October 2026. Base: `68301826`. D07 remains **IN_PROGRESS**.

Panel save paths already required a valid nonempty Argon2 PHC admin hash, but the shared `WebConfig::validate_active` checked the other active fields without checking the hash format. A manually edited INI could therefore pass `check-config` and the startup gate. On live reload, a malformed hash replaced the working in-memory hash and made login to the running panel fail. The same INI submitted through the panel was rejected before saving.

Argon2 PHC validation now lives in the common configuration validator also used by the user API. An enabled panel with a malformed nonempty hash fails the common `check-config`/startup gate. On live reload, the prior password, panel settings, and lockout counters remain active. Hidden values of a disabled panel remain dormant until it is enabled. Empty hashes and deliberate `insecure_no_auth` retain their separate existing policy.

Checks on isolated lab `.11`: focused validation **1/1**, live reload **1/1**, the web validation group **3/3**, `cargo fmt --check`, and strict `cargo clippy --lib --bin qeli -- -D warnings` passed. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/webhash1.log`. Running services were unchanged.

The remaining runtime matrix and the race with external manual editors without the advisory lock remain under D07. Register: **5/15 DONE**.
