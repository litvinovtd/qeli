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

/// GET /api/blocked — IPs currently locked by brute-force protection. The worker
/// returns the list as a JSON array inside `message`; unwrap it into `blocked`.
pub async fn blocked(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let live = control(json!({"cmd": "list-blocked"})).await;
    let blocked: Value = live
        .as_ref()
        .and_then(|v| v["message"].as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!([]));
    Ok(Json(json!({ "ok": true, "blocked": blocked })))
}

/// POST /api/blocked/{ip}/unblock — release one IP from brute-force lockout.
pub async fn unblock(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(ip): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let reply = control(json!({"cmd": "unblock", "ip": ip}))
        .await
        .unwrap_or_else(|| super::err_json("data-plane worker unavailable"));
    Ok(Json(reply))
}

/// POST /api/blocked/clear — release every currently-blocked IP.
pub async fn unblock_all(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let reply = control(json!({"cmd": "unblock-all"}))
        .await
        .unwrap_or_else(|| super::err_json("data-plane worker unavailable"));
    Ok(Json(reply))
}

/// GET /api/blocked/settings — the brute-force lockout thresholds (read from the
/// live on-disk config). ONE policy governs BOTH surfaces: the VPN-auth lockouts
/// listed on this page AND the web-panel login lockout — they share the same
/// `[auth] brute_force` config and the same tracker logic.
pub async fn blocked_settings(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let bf = current_config(&state)
        .await
        .map(|c| c.auth.brute_force)
        .unwrap_or_default();
    Ok(Json(json!({
        "ok": true,
        "settings": {
            "max_attempts": bf.max_attempts,
            "window_secs": bf.window_secs,
            "lockout_secs": bf.lockout_secs,
        }
    })))
}

/// POST /api/blocked/settings — update the brute-force lockout thresholds.
///
/// The three `[auth]` keys are patched into the on-disk config **in place**
/// (comments preserved — unlike the whole-config PUT which re-serializes and
/// strips them), then applied live with no session drop and no full restart:
///  1. this (supervisor) process's tracker is rebuilt directly — it governs the
///     **web-panel login** lockout;
///  2. the data-plane worker is SIGHUP'd (`ReloadUsers`) so `reload_on_sighup`
///     rebuilds ITS tracker from the new config — it governs **VPN auth**.
///
/// Applying a new policy resets the current failure counters on both trackers
/// (same semantics a SIGHUP config reload has always had).
pub async fn set_blocked_settings(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    // Read + bounds-check. `as_u64` yields 0 for a missing/!numeric field, which
    // then fails the lower bound and returns a clear error (not an axum 422).
    let max_attempts = body["max_attempts"].as_u64().unwrap_or(0);
    let window_secs = body["window_secs"].as_u64().unwrap_or(0);
    let lockout_secs = body["lockout_secs"].as_u64().unwrap_or(0);
    // 0 attempts would lock on the very first check; the upper bounds just reject
    // absurd values (window ≤ 1 day, lockout ≤ 30 days).
    if !(1..=10_000).contains(&max_attempts) {
        return Ok(Json(super::err_json(
            "max_attempts must be between 1 and 10000",
        )));
    }
    if !(1..=86_400).contains(&window_secs) {
        return Ok(Json(super::err_json(
            "window_secs must be between 1 and 86400 (24h)",
        )));
    }
    if !(1..=2_592_000).contains(&lockout_secs) {
        return Ok(Json(super::err_json(
            "lockout_secs must be between 1 and 2592000 (30d)",
        )));
    }
    let max_attempts = max_attempts as u32;

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
    let raw = match std::fs::read_to_string(&canon) {
        Ok(s) => s,
        Err(e) => return Ok(Json(super::err_json(format!("read error: {}", e)))),
    };

    // Surgical, comment-preserving patch of the three keys under [auth].
    let updates = [
        ("brute_force.max_attempts", max_attempts.to_string()),
        ("brute_force.window_secs", window_secs.to_string()),
        ("brute_force.lockout_secs", lockout_secs.to_string()),
    ];
    let new_cfg = crate::config::set_section_keys(&raw, "auth", &updates);

    // Safety net: never write a config that no longer parses.
    if let Err(e) = crate::config::parse_server_config(&new_cfg) {
        return Ok(Json(super::err_json(format!(
            "internal error: edited config no longer parses: {}",
            e
        ))));
    }
    if let Err(e) = crate::util::write_atomic(&canon, new_cfg.as_bytes()) {
        return Ok(Json(super::err_json(format!("write error: {}", e))));
    }

    // Apply live. (1) Rebuild this process's tracker (web-panel login).
    *state.failed_auth.lock().await =
        FailedAuthTracker::new(max_attempts, window_secs, lockout_secs);
    // (2) SIGHUP the worker so it rebuilds its own tracker (VPN auth). No restart,
    // no dropped sessions. Best-effort: the supervisor half above already applied
    // and the new values are persisted, so a missed signal still takes effect on the
    // worker's next (re)start — but log it, since the reply claims "applied".
    if let Some(tx) = &state.worker_tx {
        if tx.send(WorkerCmd::ReloadUsers).await.is_err() {
            log::warn!(
                "brute-force settings persisted and applied to the panel, but the \
                 data-plane worker reload could not be signaled (worker channel closed); \
                 the worker will pick up the new thresholds on its next start"
            );
        }
    }
    log::info!(
        "brute-force thresholds updated via panel (max_attempts={}, window={}s, lockout={}s)",
        max_attempts,
        window_secs,
        lockout_secs
    );

    Ok(Json(json!({
        "ok": true,
        "message": "brute-force settings saved and applied",
        "path": canon.display().to_string(),
    })))
}
