use crate::server::web::auth::{self, AuthError};
use crate::server::{FailedAuthTracker, ServerState, WorkerCmd};
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ProfileQuery {
    profile: Option<String>,
}

/// Send a JSON command to the data-plane worker's control socket and parse the
/// reply. Returns None if the worker is unreachable (e.g. mid-restart) — the
/// panel then shows an empty / offline view rather than erroring.
async fn control(cmd: Value) -> Option<Value> {
    let reply = crate::server::control::send_command(
        crate::server::control::CONTROL_SOCKET,
        &cmd.to_string(),
    )
    .await
    .ok()?;
    serde_json::from_str::<Value>(&reply).ok()
}

/// Re-read the on-disk config so the panel reflects the live profile set even
/// after a Quick-Start / Apply (the supervisor's in-memory config is the one it
/// was started with).
async fn current_config(state: &Arc<ServerState>) -> Option<crate::config::server::ServerConfig> {
    let path = state.config_path.lock().await.clone()?;
    let s = std::fs::read_to_string(path).ok()?;
    crate::config::parse_server_config(&s).ok()
}

fn client_array(reply: &Option<Value>) -> Vec<Value> {
    reply
        .as_ref()
        .and_then(|v| v.get("clients"))
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default()
}

pub async fn status(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let live = control(json!({"cmd": "list-clients"})).await;
    let worker_ok = live
        .as_ref()
        .map(|v| v["ok"].as_bool().unwrap_or(false))
        .unwrap_or(false);
    let clients = client_array(&live);

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
                json!({
                    "name": p.name,
                    "client_count": counts.get(&p.name).copied().unwrap_or(0),
                    "bind": p.bind,
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
        if cfg.profiles.iter().any(|p| p.routing.nat.enabled) && !crate::server::nat::available() {
            warnings.push(
                "NAT masquerade is enabled on a profile, but `iptables` is not installed — \
                full-tunnel internet egress will NOT work. Install it: apt install iptables."
                    .to_string(),
            );
        }
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
    let mbps = body["mbps"].as_u64().unwrap_or(0);
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

/// Bounds-check one brute-force policy from a JSON object. `as_u64` yields 0 for a
/// missing/non-numeric field, which then fails the lower bound and returns a clear
/// error (not an axum 422). Returns `(enabled, max_attempts, window_secs,
/// lockout_secs)`.
fn validate_bf(v: &Value) -> Result<(bool, u32, u64, u64), String> {
    let enabled = v["enabled"].as_bool().unwrap_or(true);
    let max_attempts = v["max_attempts"].as_u64().unwrap_or(0);
    let window_secs = v["window_secs"].as_u64().unwrap_or(0);
    let lockout_secs = v["lockout_secs"].as_u64().unwrap_or(0);
    // 0 attempts would lock on the very first check; the upper bounds just reject
    // absurd values (window ≤ 1 day, lockout ≤ 30 days). Bounds are validated even
    // when disabled, so re-enabling later can't silently activate a bad policy.
    if !(1..=10_000).contains(&max_attempts) {
        return Err("max_attempts must be between 1 and 10000".into());
    }
    if !(1..=86_400).contains(&window_secs) {
        return Err("window_secs must be between 1 and 86400 (24h)".into());
    }
    if !(1..=2_592_000).contains(&lockout_secs) {
        return Err("lockout_secs must be between 1 and 2592000 (30d)".into());
    }
    Ok((enabled, max_attempts as u32, window_secs, lockout_secs))
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

/// GET /api/blocked/settings — the two independent brute-force policies, read from
/// the live on-disk config. `vpn` = `[auth] brute_force` (enforced by the data-plane
/// worker on VPN user authentication); `panel` = `[web] brute_force` (enforced by
/// this supervisor on admin login). Each carries its own on/off switch, attempt
/// count, window and lockout.
pub async fn blocked_settings(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let cfg = current_config(&state).await;
    let vpn = cfg
        .as_ref()
        .map(|c| c.auth.brute_force.clone())
        .unwrap_or_default();
    let panel = cfg
        .as_ref()
        .map(|c| c.web.brute_force.clone())
        .unwrap_or_default();
    Ok(Json(json!({
        "ok": true,
        "settings": {
            "vpn": bf_settings_json(&vpn),
            "panel": bf_settings_json(&panel),
        }
    })))
}

/// POST /api/blocked/settings — update either or both brute-force policies.
///
/// Body: `{ "vpn": {enabled,max_attempts,window_secs,lockout_secs}, "panel": {…} }`.
/// A surface is only touched when its object is present. (A legacy flat body —
/// `{max_attempts,…}` from an older cached panel — is treated as the `vpn`
/// surface.) The relevant dotted keys are patched into the on-disk config **in
/// place** (comments preserved — unlike the whole-config PUT which re-serializes
/// and strips them), then applied live with no session drop and no full restart:
/// the `vpn` keys land in `[auth] brute_force.*` and the worker is SIGHUP'd
/// (`ReloadUsers`) so `reload_on_sighup` rebuilds ITS tracker; the `panel` keys land
/// in `[web] brute_force.*` and this (supervisor) process rebuilds its own tracker
/// directly.
///
/// Applying a new policy resets that surface's current failure counters (same
/// semantics a SIGHUP config reload has always had).
pub async fn set_blocked_settings(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
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
    let mut raw = match std::fs::read_to_string(&canon) {
        Ok(s) => s,
        Err(e) => return Ok(Json(super::err_json(format!("read error: {}", e)))),
    };

    // Surgical, comment-preserving patch: VPN keys under [auth], panel keys under [web].
    if let Some((enabled, max, window, lockout)) = vpn {
        let updates = bf_updates(enabled, max, window, lockout);
        raw = crate::config::set_section_keys(&raw, "auth", &updates);
    }
    if let Some((enabled, max, window, lockout)) = panel {
        let updates = bf_updates(enabled, max, window, lockout);
        raw = crate::config::set_section_keys(&raw, "web", &updates);
    }

    // Safety net: never write a config that no longer parses.
    if let Err(e) = crate::config::parse_server_config(&raw) {
        return Ok(Json(super::err_json(format!(
            "internal error: edited config no longer parses: {}",
            e
        ))));
    }
    if let Err(e) = crate::util::write_atomic(&canon, raw.as_bytes()) {
        return Ok(Json(super::err_json(format!("write error: {}", e))));
    }

    // Apply live. (1) Panel policy → rebuild THIS process's tracker directly.
    if let Some((enabled, max, window, lockout)) = panel {
        *state.failed_auth.lock().await = FailedAuthTracker::new(enabled, max, window, lockout);
        log::info!(
            "panel-login brute-force policy updated via panel (enabled={}, max_attempts={}, window={}s, lockout={}s)",
            enabled, max, window, lockout
        );
    }
    // (2) VPN policy → SIGHUP the worker so it rebuilds ITS tracker. No restart,
    // no dropped sessions. Best-effort: the values are already persisted, so a
    // missed signal still takes effect on the worker's next (re)start.
    if let Some((enabled, max, window, lockout)) = vpn {
        if let Some(tx) = &state.worker_tx {
            if tx.send(WorkerCmd::ReloadUsers).await.is_err() {
                log::warn!(
                    "VPN brute-force settings persisted, but the data-plane worker reload \
                     could not be signaled (worker channel closed); the worker will pick \
                     up the new policy on its next start"
                );
            }
        }
        log::info!(
            "VPN-auth brute-force policy updated via panel (enabled={}, max_attempts={}, window={}s, lockout={}s)",
            enabled, max, window, lockout
        );
    }

    Ok(Json(json!({
        "ok": true,
        "message": "brute-force settings saved and applied",
        "path": canon.display().to_string(),
    })))
}
