use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

async fn control(cmd: Value) -> Option<Value> {
    let reply = crate::server::control::send_command(
        crate::server::control::CONTROL_SOCKET,
        &cmd.to_string(),
    )
    .await
    .ok()?;
    serde_json::from_str::<Value>(&reply).ok()
}

/// Cache the parsed users DB keyed on the file's mtime, so `get_usage` doesn't
/// re-read + parse the whole users file on every request. The worker bumps the
/// file's mtime whenever it flushes an edit, so the cache invalidates exactly when
/// the file actually changes — no staleness (the reason the load is done fresh).
/// (audit 3.6)
static USERS_CACHE: std::sync::LazyLock<
    std::sync::Mutex<Option<(std::time::SystemTime, crate::config::users::UsersDb)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

fn load_users_cached(path: &str) -> Option<crate::config::users::UsersDb> {
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    let mut cache = USERS_CACHE.lock().ok()?;
    if let Some((cached_mtime, db)) = cache.as_ref() {
        if *cached_mtime == mtime {
            return Some(db.clone());
        }
    }
    let db = crate::config::users::UsersDb::load(path).ok()?;
    *cache = Some((mtime, db.clone()));
    Some(db)
}

/// Per-user lifetime usage + caps for the panel. Reloads the worker-flushed
/// `usage.json` sidecar, marks who is currently online, and joins each user's
/// configured data cap / expiry from the users DB.
pub async fn get_usage(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    state.usage.reload();
    let snap = state.usage.snapshot();

    let online: HashSet<String> = control(json!({ "cmd": "list-clients" }))
        .await
        .and_then(|v| v.get("clients").and_then(|c| c.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c.get("username").and_then(|u| u.as_str()).map(String::from))
        .collect();

    // Read the users fresh from disk: the worker (a separate process) persists
    // cap/expiry edits to the users file, so the supervisor's in-memory copy can
    // be stale. Fall back to the in-memory copy only if the file can't be read
    // (e.g. inline `[user:*]` in the server config).
    let db = match load_users_cached(&state.config.auth.users_file) {
        Some(u) => u,
        None => state.users_db.read().await.clone(),
    };
    let mut out: Vec<Value> = Vec::new();
    for u in &db.users {
        let us = snap.get(&u.username);
        out.push(json!({
            "username": u.username,
            "used_bytes": us.map(|x| x.used_bytes).unwrap_or(0),
            "used_down": us.map(|x| x.used_down).unwrap_or(0),
            "used_up": us.map(|x| x.used_up).unwrap_or(0),
            "last_seen": us.map(|x| x.last_seen).unwrap_or(0),
            "data_limit_gb": u.data_limit_gb,
            "expire_at": u.expire_at,
            "online": online.contains(&u.username),
        }));
    }
    Ok(Json(json!({ "ok": true, "usage": out })))
}

/// Set a user's data cap (GB; 0 = unlimited) and/or expiry (unix seconds; null =
/// never). Goes through the worker so it edits the authoritative users DB, saves
/// the file, and the enforcement sees it immediately.
pub async fn set_limit(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    let gb = body["data_limit_gb"].as_u64().unwrap_or(0);
    let expire = body.get("expire_at").and_then(Value::as_i64);
    let reply = control(json!({
        "cmd": "set-limit", "username": username, "data_limit_gb": gb, "expire_at": expire
    }))
    .await
    .unwrap_or_else(|| super::err_json("data-plane worker unavailable"));
    Ok(Json(reply))
}

/// Reset a user's lifetime usage counter to zero.
pub async fn reset_usage(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let reply = control(json!({ "cmd": "reset-usage", "username": username }))
        .await
        .unwrap_or_else(|| super::err_json("data-plane worker unavailable"));
    Ok(Json(reply))
}
