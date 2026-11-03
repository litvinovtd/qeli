use crate::server::web::auth::{self, AuthError};
use crate::server::{ServerState, WorkerCmd};
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

/// Return a display-safe host name for identifying this server in the panel.
/// The status endpoint is authenticated, so this does not expose host metadata
/// on the public login page.
fn system_hostname() -> Option<String> {
    #[cfg(unix)]
    let native = {
        let mut buf = [0u8; 256];
        // SAFETY: `buf` is writable for exactly the length passed to gethostname.
        // We inspect only bytes inside that buffer and do not assume NUL termination.
        let result = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if result == 0 {
            let len = buf.iter().position(|&byte| byte == 0).unwrap_or(buf.len());
            std::str::from_utf8(&buf[..len])
                .ok()
                .and_then(clean_hostname)
        } else {
            None
        }
    };

    #[cfg(not(unix))]
    let native: Option<String> = None;

    native.or_else(|| {
        std::env::var("HOSTNAME")
            .ok()
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .and_then(|value| clean_hostname(&value))
    })
}

fn clean_hostname(raw: &str) -> Option<String> {
    let value: String = raw
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .take(253)
        .collect();
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[derive(Deserialize)]
pub struct ProfileQuery {
    profile: Option<String>,
}

/// Send a JSON command to the data-plane worker's control socket and parse the
/// reply. Returns None if the worker is unreachable (e.g. mid-restart) — the
/// panel then shows an empty / offline view rather than erroring.
pub(super) async fn control(cmd: Value) -> Option<Value> {
    let reply = crate::server::control::send_command(
        &crate::server::control::control_socket_path(),
        &cmd.to_string(),
    )
    .await
    .ok()?;
    serde_json::from_str::<Value>(&reply).ok()
}

/// Re-read the on-disk config so the panel reflects the live profile set even
/// after a Quick-Start / Apply (the supervisor's in-memory config is the one it
/// was started with).
pub(super) async fn current_config(
    state: &Arc<ServerState>,
) -> Option<crate::config::server::ServerConfig> {
    super::current_server_config(state).await.ok()
}

pub(super) fn client_array(reply: &Option<Value>) -> Vec<Value> {
    reply
        .as_ref()
        .and_then(|v| v.get("clients"))
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default()
}
fn roaming_profiles(reply: &Option<Value>) -> std::collections::HashMap<String, Value> {
    let Some(message) = reply
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
    else {
        return std::collections::HashMap::new();
    };
    let Ok(payload) = serde_json::from_str::<Value>(message) else {
        return std::collections::HashMap::new();
    };
    payload
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let name = entry.get("name").and_then(Value::as_str)?.to_string();
            let mut entry = entry.clone();
            entry
                .as_object_mut()?
                .insert("runtime_available".into(), Value::Bool(true));
            Some((name, entry))
        })
        .collect()
}

fn unavailable_roaming_profile(
    profile: &crate::config::server::ProfileConfig,
) -> serde_json::Value {
    json!({
        "name": profile.name,
        "enabled": profile.roaming.enabled,
        "feature_compiled": null,
        "runtime_available": false,
        "transport": profile.bind.transport,
        "worker_lifetime": true,
        "tcp": {
            "attempts_total": 0,
            "commits_total": 0,
            "failures_total": 0,
            "grace_expired_total": 0,
            "active_sessions": 0,
            "orphaned_sessions": 0,
            "orphaned_bytes": 0,
        },
        "udp": {
            "attempts_total": 0,
            "commits_total": 0,
            "failures_total": 0,
            "active_sessions": 0,
            "active_candidates": 0,
            "cid_aliases": 0,
        },
    })
}

pub async fn status(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let (live, roaming_live) = tokio::join!(
        control(json!({"cmd": "list-clients"})),
        control(json!({"cmd": "roaming-stats"}))
    );
    let worker_ok = live
        .as_ref()
        .map(|v| v["ok"].as_bool().unwrap_or(false))
        .unwrap_or(false);
    let clients = client_array(&live);
    let roaming_by_profile = roaming_profiles(&roaming_live);

    // Per-profile connected counts.
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for c in &clients {
        if let Some(p) = c["profile"].as_str() {
            *counts.entry(p.to_string()).or_default() += 1;
        }
    }

    // Profile list from the on-disk config (so newly-applied profiles show up).
    let cfg = current_config(&state).await;
    let profile_list: Vec<Value> = match &cfg {
        Some(cfg) => cfg
            .profiles
            .iter()
            .map(|p| {
                let roaming = roaming_by_profile
                    .get(&p.name)
                    .cloned()
                    .unwrap_or_else(|| unavailable_roaming_profile(p));
                json!({
                    "name": p.name,
                    "enabled": p.enabled,
                    "client_count": counts.get(&p.name).copied().unwrap_or(0),
                    "bind": p.bind,
                    "roaming": roaming,
                })
            })
            .collect(),
        None => Vec::new(),
    };

    // Surface operational problems the operator can't see otherwise. A profile asking
    // for NAT masquerade does nothing without `iptables` installed, so flag it loudly
    // here (the data-plane worker also logs an ERROR).
    let mut warnings: Vec<String> = Vec::new();
    if let Some(cfg) = &cfg {
        if let Some(warning) = super::firewall::nat_warning(cfg).await {
            warnings.push(warning.message);
        }
    }
    // A restart that was ACCEPTED but never happened. `full_restart` has to answer before
    // systemd replaces the process, so it always replied `ok: true`; when systemctl then
    // refused, the panel showed success while the server kept running the old config and
    // the operator only found out by reading the journal. If the restart had worked this
    // process would be gone, so the message existing at all means it did not. (S-18)
    if let Some(msg) = super::control::last_restart_failure() {
        warnings.push(format!("Restart did NOT take effect: {msg}"));
    }
    // Health alerts derived from the live host snapshot (Tier-3). Surfaced in the
    // dashboard's existing warnings banner so the operator sees trouble at a glance.
    if !worker_ok {
        warnings.push(
            "Data-plane worker is not responding — VPN profiles may be down. \
             Check: journalctl -u qeli -e"
                .to_string(),
        );
    }
    let sys = state.metrics.latest_json().await;
    let f = |k: &str| sys.get(k).and_then(serde_json::Value::as_f64);
    if let Some(c) = f("cpu_pct") {
        if c >= 90.0 {
            warnings.push(format!(
                "Host CPU at {c:.0}% — sustained load can throttle throughput."
            ));
        }
    }
    if let Some(m) = f("mem_pct") {
        if m >= 90.0 {
            warnings.push(format!("Host memory at {m:.0}% — risk of OOM-kill."));
        }
    }
    if let Some(d) = f("disk_pct") {
        if d >= 90.0 {
            warnings.push(format!(
                "Disk {d:.0}% full — log / identity writes may start failing."
            ));
        }
    }

    Ok(Json(json!({
        "ok": true,
        "worker_ok": worker_ok,
        "version": env!("CARGO_PKG_VERSION"),
        "hostname": system_hostname(),
        // Opt-in flag (default false): tells the panel front-end whether it may do a
        // browser-side GitHub Releases check and show an "update available" banner.
        "update_check": cfg.as_ref().map(|c| c.web.update_check).unwrap_or(false),
        // How this server was installed ("deb" | "docker" | "other") so the update
        // banner shows the matching copy-paste command.
        "install_kind": crate::server::update::install_kind(),
        "client_count": clients.len(),
        "profiles": profile_list,
        "warnings": warnings,
    })))
}

#[cfg(test)]
mod tests {
    use super::{clean_hostname, roaming_profiles, validate_bf_edit_candidate};

    #[test]
    fn brute_force_edit_rejects_unservable_or_invalid_live_candidates() {
        let no_auth = "[profile:a]\n[web]\nenabled = true\n";
        assert!(
            validate_bf_edit_candidate(no_auth, "/etc/qeli/users.conf", false)
                .unwrap_err()
                .contains("web.password_hash")
        );

        let bad_hash = "[profile:a]\n[web]\nenabled = true\npassword_hash = broken\n";
        assert!(
            validate_bf_edit_candidate(bad_hash, "/etc/qeli/users.conf", false)
                .unwrap_err()
                .contains("Argon2")
        );

        let disabled_profile = "[profile:a]\nenabled = false\n";
        assert!(
            validate_bf_edit_candidate(disabled_profile, "/etc/qeli/users.conf", false)
                .unwrap_err()
                .contains("all profiles are disabled")
        );

        let changed_users = "[auth]\nusers_file = /etc/qeli/other-users.conf\n[profile:a]\n";
        assert!(
            validate_bf_edit_candidate(changed_users, "/etc/qeli/users.conf", true)
                .unwrap_err()
                .contains("full restart")
        );

        let valid_panel_only = "[profile:a]\n[web]\nenabled = false\n";
        assert!(
            validate_bf_edit_candidate(valid_panel_only, "/etc/qeli/users.conf", false).is_ok()
        );
    }

    #[tokio::test]
    async fn blocked_settings_distinguishes_saved_and_active_panel_policy() {
        use crate::config::server::{ProfileConfig, ServerConfig};
        use crate::server::test_api_state;
        use crate::server::web::auth::AuthGuard;
        use axum::extract::State;

        let dir = std::env::temp_dir().join(format!(
            "qeli-blocked-settings-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.ini");
        let mut startup = ServerConfig::default();
        startup.web.enabled = false;
        startup.profiles.push(ProfileConfig::baseline());
        std::fs::write(&path, startup.to_ini_string()).unwrap();
        let state = test_api_state(startup.clone(), &path);

        let initial = super::blocked_settings(State(state.clone()), AuthGuard)
            .await
            .unwrap()
            .0;
        assert_eq!(initial["panel_applied"], true);
        assert_eq!(
            initial["revision"],
            super::super::config::config_revision(&startup.to_ini_string())
        );

        let mut saved = startup;
        saved.web.brute_force.max_attempts = 2;
        std::fs::write(&path, saved.to_ini_string()).unwrap();
        let pending = super::blocked_settings(State(state.clone()), AuthGuard)
            .await
            .unwrap()
            .0;
        assert_eq!(pending["panel_applied"], false);
        assert_eq!(pending["settings"]["panel"]["max_attempts"], 2);
        assert_eq!(
            pending["revision"],
            super::super::config::config_revision(&saved.to_ini_string())
        );
        assert_ne!(pending["revision"], initial["revision"]);
        assert_eq!(pending["live_panel"]["max_attempts"], 5);

        assert!(state.reload_web_settings().await);
        let applied = super::blocked_settings(State(state), AuthGuard)
            .await
            .unwrap()
            .0;
        assert_eq!(applied["panel_applied"], true);
        assert_eq!(applied["live_panel"]["max_attempts"], 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hostname_is_safe_for_panel_display() {
        assert_eq!(
            clean_hostname("  vpn-edge-01\n"),
            Some("vpn-edge-01".into())
        );
        assert_eq!(
            clean_hostname("vpn\u{0000}-edge\u{0007}"),
            Some("vpn-edge".into())
        );
        assert_eq!(clean_hostname(" \r\n\t "), None);
        assert_eq!(clean_hostname(&"a".repeat(300)).unwrap().len(), 253);
    }
    #[test]
    fn roaming_control_payload_is_joined_by_profile_without_exposing_raw_message() {
        let reply = Some(serde_json::json!({
            "ok": true,
            "message": serde_json::json!({
                "profiles": [{
                    "name": "mobile",
                    "enabled": true,
                    "transport": "udp",
                    "udp": { "commits_total": 3, "cid_aliases": 3 }
                }]
            }).to_string()
        }));
        let profiles = roaming_profiles(&reply);
        let mobile = profiles.get("mobile").expect("profile telemetry");
        assert_eq!(mobile["udp"]["commits_total"], 3);
        assert_eq!(mobile["udp"]["cid_aliases"], 3);
        assert_eq!(mobile["runtime_available"], true);
        assert!(roaming_profiles(&Some(serde_json::json!({
            "ok": true,
            "message": "not-json"
        })))
        .is_empty());
    }
}

pub async fn clients(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Query(qs): Query<ProfileQuery>,
) -> Result<Json<Value>, AuthError> {
    let live = control(json!({"cmd": "list-clients"})).await;
    let mut clients = client_array(&live);
    if let Some(ref filter) = qs.profile {
        clients.retain(|c| c["profile"].as_str() == Some(filter.as_str()));
    }
    Ok(Json(json!({ "ok": true, "clients": clients })))
}

pub async fn kick_client(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let profile = body["profile"].as_str().unwrap_or("");
    let reply = control(json!({"cmd": "kick", "username": username, "profile": profile}))
        .await
        .unwrap_or_else(|| super::err_json("data-plane worker unavailable"));
    Ok(Json(reply))
}

pub async fn set_bandwidth(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    if let Err(error) = super::require_json_object(&body) {
        return Ok(Json(super::err_json(error)));
    }
    if body.get("profile").is_some_and(|value| !value.is_string()) {
        return Ok(Json(super::err_json("profile must be a string")));
    }
    // Reject an invalid/oversized number rather than coercing to 0 (= unlimited); the
    // worker's control `Request.mbps` is a u32, so an out-of-range value would also be
    // dropped there as "invalid JSON" while the panel reported success.
    let mbps = match body.get("mbps") {
        None | Some(serde_json::Value::Null) => 0u64,
        Some(v) => match v.as_u64() {
            Some(n) if n <= u32::MAX as u64 => n,
            _ => {
                return Ok(Json(super::err_json(format!(
                    "mbps must be a whole number between 0 and {} (got {v}); 0 = unlimited",
                    u32::MAX
                ))))
            }
        },
    };
    let profile = body["profile"].as_str().unwrap_or("");
    let reply = control(
        json!({"cmd": "set-bandwidth", "username": username, "mbps": mbps, "profile": profile}),
    )
    .await
    .unwrap_or_else(|| super::err_json("data-plane worker unavailable"));
    Ok(Json(reply))
}

/// Which brute-force surface a blocked-IP request targets: the VPN-auth journal
/// (kept by the data-plane worker) or the panel-login journal (kept by this
/// supervisor process). Two independent policies → two independent journals.
#[derive(Deserialize)]
pub struct SurfaceQuery {
    surface: Option<String>,
}

fn is_panel_surface(q: &SurfaceQuery) -> bool {
    q.surface.as_deref() == Some("panel")
}

/// Serialize the supervisor's own (panel-login) blocked list to the same JSON
/// shape the worker returns for the VPN journal.
async fn panel_blocked_json(state: &Arc<ServerState>) -> Value {
    let tracker = state.failed_auth.lock().await;
    let list: Vec<Value> = tracker
        .list_blocked_ips()
        .into_iter()
        .map(|(ip, failures, secs)| {
            json!({ "ip": ip.to_string(), "failures": failures, "unblock_in_secs": secs })
        })
        .collect();
    Value::Array(list)
}

/// GET /api/blocked — IPs currently locked by brute-force protection, split into
/// the two independent journals: `vpn` (data-plane worker) and `panel` (this
/// supervisor's admin-login tracker). The worker returns its list as a JSON array
/// inside `message`; the panel list is read in-process.
pub async fn blocked(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let live = control(json!({"cmd": "list-blocked"})).await;
    let vpn: Value = live
        .as_ref()
        .and_then(|v| v["message"].as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!([]));
    let panel = panel_blocked_json(&state).await;
    Ok(Json(json!({
        "ok": true,
        "blocked": { "vpn": vpn, "panel": panel },
    })))
}

/// POST /api/blocked/{ip}/unblock — release one IP from brute-force lockout.
/// `?surface=panel` targets the panel-login journal (this process); anything else
/// (default) targets the VPN-auth journal on the worker.
pub async fn unblock(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Query(q): Query<SurfaceQuery>,
    Path(ip): Path<String>,
) -> Result<Json<Value>, AuthError> {
    if is_panel_surface(&q) {
        let reply = match ip.parse::<std::net::IpAddr>() {
            Ok(addr) => {
                if state.failed_auth.lock().await.unblock_ip(addr) {
                    json!({ "ok": true, "message": format!("IP {} unblocked (panel)", addr) })
                } else {
                    super::err_json(format!("IP {} was not blocked (panel)", addr))
                }
            }
            Err(_) => super::err_json(format!(
                "'{}' is not a valid IP address",
                crate::util::log_sanitize(&ip)
            )),
        };
        return Ok(Json(reply));
    }
    let reply = control(json!({"cmd": "unblock", "ip": ip}))
        .await
        .unwrap_or_else(|| super::err_json("data-plane worker unavailable"));
    Ok(Json(reply))
}

/// POST /api/blocked/clear — release every currently-blocked IP on the selected
/// journal (`?surface=panel` for panel-login, else the VPN-auth journal).
pub async fn unblock_all(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Query(q): Query<SurfaceQuery>,
) -> Result<Json<Value>, AuthError> {
    if is_panel_surface(&q) {
        let n = state.failed_auth.lock().await.clear_all_ips();
        return Ok(Json(json!({
            "ok": true,
            "message": format!("cleared {} blocked/penalized IP(s) (panel)", n),
        })));
    }
    let reply = control(json!({"cmd": "unblock-all"}))
        .await
        .unwrap_or_else(|| super::err_json("data-plane worker unavailable"));
    Ok(Json(reply))
}

/// Serialize one brute-force policy to the panel's JSON shape.
fn bf_settings_json(bf: &crate::config::server::BruteForceConfig) -> Value {
    json!({
        "enabled": bf.enabled,
        "max_attempts": bf.max_attempts,
        "window_secs": bf.window_secs,
        "lockout_secs": bf.lockout_secs,
    })
}

fn bf_policy_matches(
    saved: &crate::config::server::BruteForceConfig,
    live: &crate::config::server::BruteForceConfig,
) -> bool {
    saved.enabled == live.enabled
        && saved.max_attempts == live.max_attempts
        && saved.window_secs == live.window_secs
        && saved.lockout_secs == live.lockout_secs
}

/// Bounds-check one brute-force policy from a JSON object. `as_u64` yields 0 for a
/// missing/non-numeric field, which then fails the lower bound and returns a clear
/// error (not an axum 422). Returns `(enabled, max_attempts, window_secs,
/// lockout_secs)`.
fn validate_bf(v: &Value) -> Result<(bool, u32, u64, u64), String> {
    let enabled = v["enabled"].as_bool().unwrap_or(true);
    let max_attempts = v["max_attempts"].as_u64().unwrap_or(0);
    let window_secs = v["window_secs"].as_u64().unwrap_or(0);
    let lockout_secs = v["lockout_secs"].as_u64().unwrap_or(0);
    // The bounds themselves live on BruteForceConfig, so this handler and the config
    // gate (`validate_profiles`) can no longer drift apart — they used to, and everything
    // except this handler wrote the keys unchecked. (Audit 2026-07-27, C1.)
    let max_attempts_u32 = u32::try_from(max_attempts).unwrap_or(u32::MAX);
    crate::config::server::BruteForceConfig {
        enabled,
        max_attempts: max_attempts_u32,
        window_secs,
        lockout_secs,
    }
    .validate("")
    .map_err(|e| e.trim_start().to_string())?;
    Ok((enabled, max_attempts_u32, window_secs, lockout_secs))
}

/// The four dotted keys a brute-force policy occupies inside its `[section]`.
fn bf_updates(enabled: bool, max: u32, window: u64, lockout: u64) -> [(&'static str, String); 4] {
    [
        ("brute_force.enabled", enabled.to_string()),
        ("brute_force.max_attempts", max.to_string()),
        ("brute_force.window_secs", window.to_string()),
        ("brute_force.lockout_secs", lockout.to_string()),
    ]
}

/// Check the exact edited INI against the live-reload contract before publishing it.
/// VPN-auth SIGHUP cannot switch the supervisor's startup users-file path.
fn validate_bf_edit_candidate(
    raw: &str,
    startup_users_file: &str,
    reload_vpn: bool,
) -> Result<(), String> {
    let candidate = crate::config::parse_server_config(raw)
        .map_err(|error| format!("edited config no longer parses: {error}"))?;
    super::config::validate_web_auth_for_save(&candidate.web)?;
    crate::server::validate_profiles(&candidate)
        .map_err(|error| format!("edited config would be rejected at startup: {error}"))?;
    if reload_vpn {
        if candidate.auth.users_file != startup_users_file {
            return Err(
                "auth.users_file differs from the supervisor startup path; full restart is required before VPN brute-force settings can be applied live"
                    .into(),
            );
        }
        super::effective_users(&candidate)
            .map_err(|error| format!("VPN brute-force reload would fail: {error}"))?;
    }
    Ok(())
}

/// GET /api/blocked/settings — saved policies plus the supervisor's applied
/// panel-login policy. The VPN worker's applied policy is not observable here.
/// `vpn` = `[auth] brute_force` (enforced by the data-plane
/// worker on VPN user authentication); `panel` = `[web] brute_force` (enforced by
/// this supervisor on admin login). Each carries its own on/off switch, attempt
/// count, window and lockout.
pub async fn blocked_settings(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let (cfg, revision) = match super::current_server_config_with_revision(&state).await {
        Ok(config) => config,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let vpn = cfg.auth.brute_force.clone();
    let panel = cfg.web.brute_force.clone();
    let live_panel = state.live_web.read().await.brute_force.clone();
    Ok(Json(json!({
        "ok": true,
        "revision": revision,
        "settings": {
            "vpn": bf_settings_json(&vpn),
            "panel": bf_settings_json(&panel),
        },
        "panel_applied": bf_policy_matches(&panel, &live_panel),
        "live_panel": bf_settings_json(&live_panel),
    })))
}

/// POST /api/blocked/settings — update either or both brute-force policies.
///
/// Body: `{ "expected_revision": "<GET revision>", "vpn": {…}, "panel": {…} }`.
/// A surface is only touched when its object is present. (A legacy flat body —
/// `{max_attempts,…}` from an older API client — is treated as the `vpn`
/// surface.) The relevant dotted keys are patched into the on-disk config **in
/// place** (comments preserved — unlike the whole-config PUT which re-serializes
/// and strips them), then live application is attempted without dropping sessions:
/// the `vpn` keys land in `[auth] brute_force.*` and the worker is SIGHUP'd
/// (`ReloadUsers`) so `reload_on_sighup` rebuilds ITS tracker; the `panel` keys land
/// in `[web] brute_force.*` and the supervisor reloads its live settings
/// and lockout tracker together.
///
/// Applying changed thresholds live resets that surface's failure counters. If the VPN
/// worker cannot be signaled, its saved policy takes effect on its next start.
pub async fn set_blocked_settings(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let _config_write_guard = state.config_write_lock.lock().await;
    let vpn_in = body.get("vpn");
    let panel_in = body.get("panel");
    // Back-compat: a flat body with no vpn/panel wrapper is an old panel posting
    // the (then-shared) VPN thresholds.
    let legacy_flat = vpn_in.is_none() && panel_in.is_none() && body.get("max_attempts").is_some();
    let vpn_src = vpn_in.or(if legacy_flat { Some(&body) } else { None });
    if vpn_src.is_none() && panel_in.is_none() {
        return Ok(Json(super::err_json(
            "expected at least one of 'vpn' or 'panel' brute-force settings",
        )));
    }

    // Validate everything present up front — fail before any write.
    let vpn = match vpn_src {
        Some(v) => match validate_bf(v) {
            Ok(t) => Some(t),
            Err(e) => return Ok(Json(super::err_json(format!("vpn: {}", e)))),
        },
        None => None,
    };
    let panel = match panel_in {
        Some(v) => match validate_bf(v) {
            Ok(t) => Some(t),
            Err(e) => return Ok(Json(super::err_json(format!("panel: {}", e)))),
        },
        None => None,
    };

    // Resolve + validate the write target (defense in depth, as put_config does).
    let target = match state.config_path.lock().await.clone() {
        Some(p) => p,
        None => {
            return Ok(Json(super::err_json(
                "config_path not set — running from in-memory config",
            )))
        }
    };
    let canon =
        match super::paths::validate_in_whitelist(&target, super::paths::ALLOWED_CONFIG_DIRS) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Refused brute-force settings write to '{}': {}", target, e);
                return Ok(Json(super::err_json(format!(
                    "config path rejected: {}",
                    e
                ))));
            }
        };
    let _file_write_guard = match super::config::lock_server_config(&canon).await {
        Ok(guard) => guard,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let mut raw = match super::config::read_trusted_config_text(
        std::path::Path::new(&target),
        "panel brute-force save",
    ) {
        Ok(raw) => raw,
        Err(error) => return Ok(Json(super::err_json(error))),
    };

    let checked_raw = raw.clone();
    if let Some(conflict) = super::config::revision_conflict(&body, &checked_raw) {
        return Ok(Json(conflict));
    }

    // Surgical, comment-preserving patch: VPN keys under [auth], panel keys under [web].
    if let Some((enabled, max, window, lockout)) = vpn {
        let updates = bf_updates(enabled, max, window, lockout);
        raw = crate::config::set_section_keys(&raw, "auth", &updates);
    }
    if let Some((enabled, max, window, lockout)) = panel {
        let updates = bf_updates(enabled, max, window, lockout);
        raw = crate::config::set_section_keys(&raw, "web", &updates);
    }

    // SIGHUP validates the complete candidate before changing the VPN policy.
    // Apply the same gate before writing, including the panel's startup auth rule.
    if let Err(error) =
        validate_bf_edit_candidate(&raw, &state.config.auth.users_file, vpn.is_some())
    {
        return Ok(Json(super::err_json(error)));
    }
    let old_raw = match super::config::read_trusted_config_text(&canon, "panel brute-force save") {
        Ok(raw) => raw,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    if old_raw != checked_raw {
        return Ok(Json(super::err_json(
            "config changed on disk while editing brute-force settings; reload and retry",
        )));
    }
    if let Err(error) = super::config::snapshot_before_changed_write(&canon, &old_raw, &raw) {
        return Ok(Json(super::err_json(format!(
            "refusing to save without a rollback snapshot: {error}"
        ))));
    }
    if let Err(e) = super::config::write_server_config(&canon, &raw) {
        return Ok(Json(super::err_json(format!("write error: {}", e))));
    }

    // Apply the panel policy through the same atomic web-settings reload used by
    // other INI saves. A failed re-read leaves both the live policy and tracker old.
    let panel_applied = if let Some((enabled, max, window, lockout)) = panel {
        let reloaded = state.reload_web_settings().await;
        let live = state.live_web.read().await;
        Some(
            reloaded
                && live.brute_force.enabled == enabled
                && live.brute_force.max_attempts == max
                && live.brute_force.window_secs == window
                && live.brute_force.lockout_secs == lockout,
        )
    } else {
        None
    };
    // VPN policy → SIGHUP the worker so it rebuilds ITS tracker. No restart,
    // no dropped sessions. Report a failed signal as pending, not live-applied.
    let mut vpn_reload_requested = None;
    if let Some((enabled, max, window, lockout)) = vpn {
        let sent = match &state.worker_tx {
            Some(tx) => tx.send(WorkerCmd::ReloadUsers).await.is_ok(),
            None => false,
        };
        vpn_reload_requested = Some(sent);
        if !sent {
            log::warn!(
                "VPN brute-force settings persisted, but the data-plane worker reload \
                 could not be signaled; the worker will pick up the new policy on its next start"
            );
        }
        log::info!(
            "VPN-auth brute-force policy updated via panel (enabled={}, max_attempts={}, window={}s, lockout={}s)",
            enabled, max, window, lockout
        );
    }

    let message = match (panel_applied, vpn_reload_requested) {
        (Some(false), Some(false)) => {
            "brute-force settings saved; panel reload failed and VPN policy awaits worker restart"
        }
        (Some(false), _) => {
            "brute-force settings saved; panel reload failed, check the INI and logs before restart"
        }
        (_, Some(false)) => "brute-force settings saved; VPN policy applies on next worker start",
        (_, Some(true)) => "brute-force settings saved; VPN worker reload requested",
        _ => "brute-force settings saved and applied live",
    };
    Ok(Json(json!({
        "ok": true,
        "message": message,
        "panel_applied": panel_applied,
        "vpn_reload_requested": vpn_reload_requested,
        "path": canon.display().to_string(),
        "revision": super::config::config_revision(&raw),
    })))
}
