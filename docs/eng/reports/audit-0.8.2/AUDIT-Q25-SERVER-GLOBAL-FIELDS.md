# D07: global server INI fields

1 October 2026. This pass covers 34 fixed keys: 7 in [auth], 4 in [logging], and 23 in [web]. Users, groups, dynamic keys, and the 116 fixed profile keys are outside this scope. The inventory comes from the [fixture generator](../../../../scripts/gen_roundtrip_fixture.py) and [exhaustive round-trip test](../../../../qeli/src/config/server_ini.rs). Running python scripts/gen_roundtrip_fixture.py --check on the current tree passed (163 parser key names and three dynamic families).

| Fields | Validation | Runtime consumer | Apply boundary |
|---|---|---|---|
| auth.users_file | Path trust and effective users load | Supervisor, worker and panel read the selected file | Full restart on path change |
| auth.require_client_key_proof, auth.bind_static_to_session | Shared config validation | Key proof and session-key binding during handshake | Worker restart |
| auth.brute_force.enabled, max_attempts, window_secs, lockout_secs | BruteForceConfig::validate | Worker VPN-auth tracker | SIGHUP after a panel edit |
| logging.level, file, time_format | INI and output-file trust | Early init_logging and timestamp formatting | Full restart |
| logging.format | INI round-trip | Intentionally inert compatibility field; logs stay plain | No restart needed |
| web.enabled, bind, port, base_path | WebConfig::validate_active | Panel listener and router | Full restart |
| web.tls, tls_cert, tls_key | Path trust, size and PEM-pair checks | HTTPS listener | Full restart |
| web.persist_session_key | Config checks | Session-signing key source | Full restart |
| web.username, password_hash, insecure_no_auth | Argon2 and enabled-panel admission | Login and auth guard read live_web | Live reload |
| web.secure_cookie, session_ttl_secs | WebConfig::validate_active | Login cookie and token lifetime | Live reload |
| web.allowed_ips, trusted_proxies | IP/CIDR validation | Request middleware reads live_web | Live reload |
| web.public_host, allowed_origins, csrf | Host/origin validation | CSRF and panel links | Live reload |
| web.brute_force.enabled, max_attempts, window_secs, lockout_secs | BruteForceConfig::validate | Panel FailedAuthTracker | Live reload |
| web.update_check | INI boolean | Status API sends browser opt-in | Read from disk per request |

The form, raw INI editor and Quick Start share server validation before publication. After a write, [reload_web_settings](../../../../qeli/src/server/mod.rs) swaps live [web] fields while retaining listener/router fields from startup; [needs_full_restart_for_config](../../../../qeli/src/web/api/config.rs) and SIGHUP hints cover startup-only fields. Direct web-runtime reads of startup state.config.web are for bind, port, tls and base_path. The status API reads update_check from the current INI. The UI disables JSON log output: logging.format=json survives as a legacy value but does not claim to produce JSON logs.

This is a static consumer audit backed by previously run targeted regressions, not a new end-to-end run for each of the 34 keys. D07 remains open for 116 profile keys, mixed import/restart scenarios and the race with an external editor that ignores the lock file.

Continuation on 2 October: [Q25-F209 in the register](../../plans/AUDIT-DEBT.md) closes mixed API save/INI/history/Quick Start/archive/restart checks for D07 and specifies the mandatory external-writer sidecar lock. Historical counts above are not a new execution. Network combinations and final certification remain D10/D15.
