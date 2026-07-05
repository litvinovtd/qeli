use crate::config::users::{GroupTemplate, UserEntry, UserRoute};
use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
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

/// Hash a plaintext password (Argon2id) and reversibly-encrypt it under the panel
/// key, so the config/QR can be re-issued later without the plaintext. Encryption
/// is best-effort: on key failure we still return the hash (enc = None) so user
/// creation isn't blocked — re-issue then needs a one-time reset.
pub(crate) fn hash_and_enc(pw: &str) -> Result<(String, Option<String>), String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2::Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| format!("hashing failed: {}", e))?
        .to_string();
    let enc = match crate::crypto::secret::encrypt_password(pw) {
        Ok(e) => Some(e),
        Err(e) => {
            log::warn!("could not encrypt password for re-issue: {}", e);
            None
        }
    };
    Ok((hash, enc))
}

/// Generate a strong random alphanumeric password (unambiguous alphabet).
pub(crate) fn gen_password(len: usize) -> String {
    use rand::Rng;
    const CS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CS[rng.gen_range(0..CS.len())] as char)
        .collect()
}

/// Parse a JSON string array (e.g. `profiles`, `allowed_networks`) into a Vec,
/// dropping non-strings and blanks. Returns empty for a missing/!array field.
fn strings_from_json(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a JSON array of `{cidr, gateway?, metric?}` into per-user routes,
/// skipping entries without a cidr.
fn routes_from_json(v: &Value) -> Vec<UserRoute> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| {
                    let cidr = r["cidr"].as_str().unwrap_or("").trim().to_string();
                    if cidr.is_empty() {
                        return None;
                    }
                    Some(UserRoute {
                        cidr,
                        gateway: r["gateway"]
                            .as_str()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                        metric: r["metric"].as_u64().map(|m| m as u32),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
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
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let users = state.users_db.read().await;
    Ok(Json(
        json!({ "ok": true, "users": users.users, "groups": users.groups }),
    ))
}

pub async fn get_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let users = state.users_db.read().await;
    match users.users.iter().find(|u| u.username == username) {
        Some(user) => Ok(Json(json!({ "ok": true, "user": user }))),
        None => Ok(Json(super::err_json(format!(
            "user '{}' not found",
            username
        )))),
    }
}

pub async fn create_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let username = body["username"].as_str().unwrap_or("").to_string();
    if username.is_empty() {
        return Ok(Json(super::err_json("username required")));
    }
    // Restrict to a safe charset (alnum + . _ -) and a sane length so a username can't
    // break the INI users file / control-channel JSON / downstream find() matching.
    if username.len() > 64
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Ok(Json(super::err_json(
            "username must be 1-64 chars of letters, digits, '.', '_', '-'",
        )));
    }
    // Accept a plaintext `password` (server hashes + reversibly-encrypts it so the
    // config can be re-issued later) or a pre-computed `password_hash` (legacy, not
    // re-issuable). Argon2 runs before we take the users lock.
    let (password_hash, password_enc) = {
        let plaintext = body["password"].as_str().unwrap_or("");
        if !plaintext.is_empty() {
            match hash_and_enc(plaintext) {
                Ok(v) => v,
                Err(e) => return Ok(Json(super::err_json(e))),
            }
        } else {
            let h = body["password_hash"].as_str().unwrap_or("").to_string();
            if h.is_empty() {
                return Ok(Json(super::err_json(
                    "password (or password_hash) required",
                )));
            }
            if let Err(e) = validate_argon2_hash(&h) {
                return Ok(Json(super::err_json(e)));
            }
            (h, None)
        }
    };

    let mut users = state.users_db.write().await;
    if users.users.iter().any(|u| u.username == username) {
        return Ok(Json(super::err_json(format!(
            "user '{}' already exists",
            username
        ))));
    }

    let new_user = UserEntry {
        username: username.clone(),
        password_hash,
        password_enc,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        static_ip: body["static_ip"].as_str().map(|s| s.to_string()),
        bandwidth: crate::config::users::BandwidthLimit {
            limit_mbps: body["bandwidth"]["limit_mbps"].as_u64().unwrap_or(0) as u32,
            burst_mbps: body["bandwidth"]["burst_mbps"].as_u64().unwrap_or(0) as u32,
        },
        group: body["group"].as_str().map(|s| s.to_string()),
        allowed_networks: strings_from_json(&body["allowed_networks"]),
        max_sessions: body["max_sessions"].as_u64().unwrap_or(0) as u32,
        profiles: strings_from_json(&body["profiles"]),
        routes: routes_from_json(&body["routes"]),
        ..Default::default()
    };
    users.users.push(new_user);
    let users_file = state.config.auth.users_file.clone();
    if let Err(e) = users.save(&users_file) {
        log::error!("Failed to save users file after create: {}", e);
        return Ok(Json(super::err_json(format!(
            "could not write the users file '{}': {} — change NOT applied",
            users_file, e
        ))));
    }
    drop(users);
    reload_worker(&state).await;
    Ok(Json(
        json!({"ok": true, "message": format!("user '{}' created", username)}),
    ))
}

pub async fn update_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let mut users = state.users_db.write().await;
    let existing = users.users.iter_mut().find(|u| u.username == username);

    match existing {
        Some(user) => {
            // New password: plaintext (re-hashed + re-encrypted for re-issue) is
            // preferred; a bare password_hash is still accepted (legacy) but clears
            // the re-issue copy since we can't encrypt what we never see.
            if let Some(pw) = body["password"].as_str() {
                if !pw.is_empty() {
                    match hash_and_enc(pw) {
                        Ok((h, e)) => {
                            user.password_hash = h;
                            user.password_enc = e;
                        }
                        Err(err) => return Ok(Json(super::err_json(err))),
                    }
                }
            } else if let Some(v) = body["password_hash"].as_str() {
                if !v.is_empty() {
                    if let Err(e) = validate_argon2_hash(v) {
                        return Ok(Json(super::err_json(e)));
                    }
                    user.password_hash = v.to_string();
                    user.password_enc = None;
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
            if body.get("allowed_networks").is_some() {
                user.allowed_networks = strings_from_json(&body["allowed_networks"]);
            }
            if body.get("profiles").is_some() {
                user.profiles = strings_from_json(&body["profiles"]);
            }
            if body.get("routes").is_some() {
                user.routes = routes_from_json(&body["routes"]);
            }
            let users_file = state.config.auth.users_file.clone();
            if let Err(e) = users.save(&users_file) {
                log::error!("Failed to save users file after update: {}", e);
                return Ok(Json(super::err_json(format!(
                    "could not write the users file '{}': {} — change NOT applied",
                    users_file, e
                ))));
            }
            drop(users);
            if let Some(limit) = new_bw_limit {
                worker_control(
                    json!({"cmd": "set-bandwidth", "username": username, "mbps": limit}),
                )
                .await;
            }
            reload_worker(&state).await;
            Ok(Json(
                json!({"ok": true, "message": format!("user '{}' updated", username)}),
            ))
        }
        None => Ok(Json(super::err_json(format!(
            "user '{}' not found",
            username
        )))),
    }
}

pub async fn delete_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let mut users = state.users_db.write().await;
    let len_before = users.users.len();
    users.users.retain(|u| u.username != username);
    if users.users.len() < len_before {
        let users_file = state.config.auth.users_file.clone();
        if let Err(e) = users.save(&users_file) {
            log::error!("Failed to save users file after delete: {}", e);
            return Ok(Json(super::err_json(format!(
                "could not write the users file '{}': {} — change NOT applied",
                users_file, e
            ))));
        }
        drop(users);
        reload_worker(&state).await;
        Ok(Json(
            json!({"ok": true, "message": format!("user '{}' deleted", username)}),
        ))
    } else {
        Ok(Json(super::err_json(format!(
            "user '{}' not found",
            username
        ))))
    }
}

pub async fn enable_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    set_user_enabled(&state, &username, true).await
}

pub async fn disable_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
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
                return Ok(Json(super::err_json(format!(
                    "could not write the users file '{}': {} — change NOT applied",
                    users_file, e
                ))));
            }
            drop(users);
            reload_worker(state).await;
            Ok(Json(
                json!({"ok": true, "message": format!("user '{}' {}", username, status), "enabled": enabled}),
            ))
        }
        None => Ok(Json(super::err_json(format!(
            "user '{}' not found",
            username
        )))),
    }
}

pub async fn set_user_bandwidth(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let limit_mbps = body["limit_mbps"].as_u64().unwrap_or(0) as u32;
    let burst_mbps = body["burst_mbps"].as_u64().unwrap_or(0) as u32;

    // persist to the users file
    let mut users = state.users_db.write().await;
    let outcome: Result<bool, String> =
        match users.users.iter_mut().find(|u| u.username == username) {
            Some(user) => {
                user.bandwidth.limit_mbps = limit_mbps;
                user.bandwidth.burst_mbps = burst_mbps;
                let users_file = state.config.auth.users_file.clone();
                match users.save(&users_file) {
                    Ok(()) => Ok(true),
                    Err(e) => {
                        log::error!("Failed to save users file after set-bandwidth: {}", e);
                        Err(format!(
                            "could not write the users file '{}': {} — change NOT applied",
                            users_file, e
                        ))
                    }
                }
            }
            None => Ok(false),
        };
    drop(users);

    match outcome {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Json(super::err_json(format!(
                "user '{}' not found",
                username
            ))))
        }
        Err(msg) => return Ok(Json(super::err_json(msg))),
    }

    // apply live to the worker's active sessions, then reload its users file
    worker_control(json!({"cmd": "set-bandwidth", "username": username, "mbps": limit_mbps})).await;
    reload_worker(&state).await;

    Ok(Json(
        json!({"ok": true, "message": format!("bandwidth for '{}' set to {} Mbps (burst {})", username, limit_mbps, burst_mbps)}),
    ))
}

// ───────────────────────────── group templates ─────────────────────────────
// Groups live in the users file alongside users (state.users_db.groups). A user
// inherits a group's bandwidth / max_sessions / allowed_networks unless it sets
// its own. Optional fields are null = "unset" (inherit nothing for that field).

pub async fn list_groups(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let users = state.users_db.read().await;
    Ok(Json(json!({ "ok": true, "groups": users.groups })))
}

/// Create or update a group template by name.
pub async fn upsert_group(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    if name.trim().is_empty() {
        return Ok(Json(super::err_json("group name required")));
    }
    // u64::as_u64 then narrow; absent / null → None (field unset).
    let group = GroupTemplate {
        bandwidth_limit_mbps: body["bandwidth_limit_mbps"].as_u64().map(|v| v as u32),
        max_sessions: body["max_sessions"].as_u64().map(|v| v as u32),
        allowed_networks: if body.get("allowed_networks").is_some_and(|v| v.is_array()) {
            Some(strings_from_json(&body["allowed_networks"]))
        } else {
            None
        },
    };

    let mut users = state.users_db.write().await;
    users.groups.insert(name.clone(), group);
    let users_file = state.config.auth.users_file.clone();
    if let Err(e) = users.save(&users_file) {
        log::error!("Failed to save users file after group upsert: {}", e);
        return Ok(Json(super::err_json(format!(
            "group saved in memory but persisting failed: {}",
            e
        ))));
    }
    drop(users);
    reload_worker(&state).await;
    Ok(Json(
        json!({"ok": true, "message": format!("group '{}' saved", name)}),
    ))
}

pub async fn delete_group(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(name): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let mut users = state.users_db.write().await;
    if users.groups.remove(&name).is_none() {
        return Ok(Json(super::err_json(format!("group '{}' not found", name))));
    }
    let users_file = state.config.auth.users_file.clone();
    if let Err(e) = users.save(&users_file) {
        log::error!("Failed to save users file after group delete: {}", e);
        return Ok(Json(super::err_json(format!(
            "could not write the users file '{}': {} — change NOT applied",
            users_file, e
        ))));
    }
    drop(users);
    reload_worker(&state).await;
    Ok(Json(
        json!({"ok": true, "message": format!("group '{}' deleted", name)}),
    ))
}
