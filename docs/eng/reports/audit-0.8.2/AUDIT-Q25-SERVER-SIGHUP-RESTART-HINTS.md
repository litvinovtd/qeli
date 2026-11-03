# Q25-F155: SIGHUP restart hints for unapplied changes

1 October 2026. Base: `127975d9`. D07 remains **IN_PROGRESS**.

The SIGHUP audit found two gaps in its applied-state diagnostics. The worker compared live profile names with every profile in the INI, including disabled ones, so an ordinary disabled profile produced a false profile-set warning. At the same time, bind/TUN/routing edits to a live profile that kept its name produced no warning. Changes to two handshake options (`auth.require_client_key_proof`, `auth.bind_static_to_session`) and three active logging fields (`logging.level`, `logging.file`, `logging.time_format`) were also unnamed after a successful users and VPN lockout-policy reload, even though the worker retained its startup values.

After validating and applying the reloadable subset, SIGHUP now reports those changes and the need to restart. Profile-set comparison includes only enabled profiles. When that set is unchanged, all parsed settings of live profiles are compared structurally, independent of map insertion order. Disabled profiles and unchanged settings do not generate warnings. Persisted configuration remains INI-only; the internal structural comparison does not introduce a JSON configuration format.

On isolated lab `.11`, the focused test **1/1**, SIGHUP group **3/3**, `cargo fmt --check`, and strict `cargo clippy --lib --bin qeli -- -D warnings` passed. Log: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase/sighuphint1.log`. Running services were unchanged.

The remaining server-field runtime matrix and the race with external manual editors that do not take the advisory lock remain under D07. Register: **5/15 DONE**.
