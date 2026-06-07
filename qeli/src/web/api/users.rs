use crate::config::users::UserEntry;
use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

/// Reject anything that isn't a parseable Argon2 PHC string. Without this,
/// callers can store plaintext in `password_hash` and the server happily
/// accepts it on next login (because PasswordHash::new would fail at verify
/// time and the user could never log in — but the record is still persisted).
fn validate_argon2_hash(hash: &str) -> Result<(), String> {
    if !hash.starts_with("$argon2id$")
        && !hash.starts_with("$argon2i$")
        && !hash.starts_with("$argon2d$")
    {
        return Err("password_hash must be an Argon2 PHC string ($argon2id$…)".into());
    }
    argon2::PasswordHash::new(hash)
        .map(|_| ())
        .map_err(|e| format!("invalid Argon2 hash: {}", e))
}

/// Ask the supervisor to SIGHUP the data-plane worker so it hot-reloads the
/// users file after a panel-side change (the panel owns its own users_db copy;
/// the worker is a separate process that re-reads the file on signal).
async fn reload_worker(state: &Arc<ServerState>) {
    if let Some(tx) = &state.worker_tx {
        let _ = tx.send(crate::server::WorkerCmd::ReloadUsers).await;
    }
}

/// Send a command to the worker's control socket (for live effects on active
/// sessions: kick / set-bandwidth). Best-effort — ignored if the worker is down.
async fn worker_control(cmd: Value) {
    let _ = crate::server::control::send_command(
        crate::server::control::CONTROL_SOCKET,
        &cmd.to_string(),
    )
    .await;
}

pub async fn list_users(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;
    let users = state.users_db.read().await;
    Ok(Json(
        json!({ "ok": true, "users": users.users, "groups": users.groups }),
    ))
}

pub async fn get_user(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;
    let users = state.users_db.read().await;
    match users.users.iter().find(|u| u.username == username) {
        Some(user) => Ok(Json(json!({ "ok": true, "user": user }))),
        None => Ok(Json(
            json!({"ok": false, "error": format!("user '{}' not found", username)}),
        )),
    }
}

pub async fn create_user(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;

    let username = body["username"].as_str().unwrap_or("").to_string();
    if username.is_empty() {
        return Ok(Json(json!({"ok": false, "error": "username required"})));
    }
    let password_hash = body["password_hash"].as_str().unwrap_or("").to_string();
    if password_hash.is_empty() {
        return Ok(Json(
            json!({"ok": false, "error": "password_hash required"}),
        ));
    }
    if let Err(e) = validate_argon2_hash(&password_hash) {
        return Ok(Json(json!({"ok": false, "error": e})));
    }

    let mut users = state.users_db.write().await;
    if users.users.iter().any(|u| u.username == username) {
        return Ok(Json(
            json!({"ok": false, "error": format!("user '{}' already exists", username)}),
        ));
    }

    let new_user = UserEntry {
        username: username.clone(),
        password_hash,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        static_ip: body["static_ip"].as_str().map(|s| s.to_string()),
        bandwidth: crate::config::users::BandwidthLimit {
            limit_mbps: body["bandwidth"]["limit_mbps"].as_u64().unwrap_or(0) as u32,
            burst_mbps: body["bandwidth"]["burst_mbps"].as_u64().unwrap_or(0) as u32,
        },
        group: body["group"].as_str().map(|s| s.to_string()),
        allowed_networks: body["allowed_networks"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        max_sessions: body["max_sessions"].as_u64().unwrap_or(0) as u32,
        ..Default::default()
    };
    users.users.push(new_user);
    let users_file = state.config.auth.users_file.clone();
    if let Err(e) = users.save(&users_file) {
        log::error!("Failed to save users file after create: {}", e);
    }
    drop(users);
    reload_worker(&state).await;
    Ok(Json(
        json!({"ok": true, "message": format!("user '{}' created", username)}),
    ))
}

pub async fn update_user(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;

    let mut users = state.users_db.write().await;
    let existing = users.users.iter_mut().find(|u| u.username == username);

    match existing {
        Some(user) => {
            if let Some(v) = body["password_hash"].as_str() {
                if !v.is_empty() {
                    if let Err(e) = validate_argon2_hash(v) {
                        return Ok(Json(json!({"ok": false, "error": e})));
                    }
                    user.password_hash = v.to_string();
                }
            }
            if let Some(v) = body["enabled"].as_bool() {
                user.enabled = v;
            }
            if let Some(static_ip) = body["static_ip"].as_str() {
                user.static_ip = if static_ip.is_empty() {
                    None
                } else {
                    Some(static_ip.to_string())
                };
            }
            if let Some(group) = body["group"].as_str() {
                user.group = if group.is_empty() {
                    None
                } else {
                    Some(group.to_string())
                };
            }
            let mut new_bw_limit: Option<u64> = None;
            if let Some(bw) = body.get("bandwidth") {
                if let Some(limit) = bw["limit_mbps"].as_u64() {
                    user.bandwidth.limit_mbps = limit as u32;
                    new_bw_limit = Some(limit); // applied live via the control socket below
                }
                if let Some(burst) = bw["burst_mbps"].as_u64() {
                    user.bandwidth.burst_mbps = burst as u32;
                }
            }
            if let Some(v) = body["max_sessions"].as_u64() {
                user.max_sessions = v as u32;
            }
            if let Some(v) = body["allowed_networks"].as_array() {
                user.allowed_networks = v
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect();
            }
            let users_file = state.config.auth.users_file.clone();
            if let Err(e) = users.save(&users_file) {
                log::error!("Failed to save users file after update: {}", e);
            }
            drop(users);
            if let Some(limit) = new_bw_limit {
                worker_control(json!({"cmd": "set-bandwidth", "username": username, "mbps": limit}))
                    .await;
            }
            reload_worker(&state).await;
            Ok(Json(
                json!({"ok": true, "message": format!("user '{}' updated", username)}),
            ))
        }
        None => Ok(Json(
            json!({"ok": false, "error": format!("user '{}' not found", username)}),
        )),
    }
}

pub async fn delete_user(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;

    let mut users = state.users_db.write().await;
    let len_before = users.users.len();
    users.users.retain(|u| u.username != username);
    if users.users.len() < len_before {
        let users_file = state.config.auth.users_file.clone();
        if let Err(e) = users.save(&users_file) {
            log::error!("Failed to save users file after delete: {}", e);
        }
        drop(users);
        reload_worker(&state).await;
        Ok(Json(
            json!({"ok": true, "message": format!("user '{}' deleted", username)}),
        ))
    } else {
        Ok(Json(
            json!({"ok": false, "error": format!("user '{}' not found", username)}),
        ))
    }
}

pub async fn enable_user(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;
    set_user_enabled(&state, &username, true).await
}

pub async fn disable_user(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;

    // disable in users.json
    let result = set_user_enabled(&state, &username, false).await?;

    // also kick the user's active sessions in the worker if just disabled
    if result["ok"].as_bool().unwrap_or(false) {
        worker_control(json!({"cmd": "kick", "username": username})).await;
    }

    Ok(result)
}

async fn set_user_enabled(
    state: &Arc<ServerState>,
    username: &str,
    enabled: bool,
) -> Result<Json<Value>, AuthError> {
    let mut users = state.users_db.write().await;
    match users.users.iter_mut().find(|u| u.username == username) {
        Some(user) => {
            user.enabled = enabled;
            let status = if enabled { "enabled" } else { "disabled" };
            let users_file = state.config.auth.users_file.clone();
            if let Err(e) = users.save(&users_file) {
                log::error!("Failed to save users file after set_enabled: {}", e);
            }
            drop(users);
            reload_worker(state).await;
            Ok(Json(
                json!({"ok": true, "message": format!("user '{}' {}", username, status), "enabled": enabled}),
            ))
        }
        None => Ok(Json(
            json!({"ok": false, "error": format!("user '{}' not found", username)}),
        )),
    }
}

pub async fn set_user_bandwidth(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;

    let limit_mbps = body["limit_mbps"].as_u64().unwrap_or(0) as u32;
    let burst_mbps = body["burst_mbps"].as_u64().unwrap_or(0) as u32;

    // persist to the users file
    let mut users = state.users_db.write().await;
    let found = match users.users.iter_mut().find(|u| u.username == username) {
        Some(user) => {
            user.bandwidth.limit_mbps = limit_mbps;
            user.bandwidth.burst_mbps = burst_mbps;
            let users_file = state.config.auth.users_file.clone();
            if let Err(e) = users.save(&users_file) {
                log::error!("Failed to save users file after set-bandwidth: {}", e);
            }
            true
        }
        None => false,
    };
    drop(users);

    if !found {
        return Ok(Json(
            json!({"ok": false, "error": format!("user '{}' not found", username)}),
        ));
    }

    // apply live to the worker's active sessions, then reload its users file
    worker_control(json!({"cmd": "set-bandwidth", "username": username, "mbps": limit_mbps})).await;
    reload_worker(&state).await;

    Ok(Json(
        json!({"ok": true, "message": format!("bandwidth for '{}' set to {} Mbps (burst {})", username, limit_mbps, burst_mbps)}),
    ))
}
