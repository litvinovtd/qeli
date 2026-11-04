use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

async fn control(cmd: Value) -> Option<Value> {
    let reply = crate::server::control::send_command(
        &crate::server::control::control_socket_path(),
        &cmd.to_string(),
    )
    .await
    .ok()?;
    serde_json::from_str::<Value>(&reply).ok()
}

fn online_session_counts(reply: &Option<Value>) -> HashMap<String, usize> {
    reply
        .as_ref()
        .and_then(|v| v.get("clients"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|client| client.get("username").and_then(Value::as_str))
        .fold(HashMap::new(), |mut counts, username| {
            *counts.entry(username.to_string()).or_default() += 1;
            counts
        })
}

/// Per-user lifetime usage + caps for the panel. Reloads the worker-flushed
/// `usage.json` sidecar, marks who is currently online (including the active
/// session count), and joins each user's configured data cap / expiry from the users DB.
pub async fn get_usage(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let snap = match state.usage.reload_snapshot_async().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            log::error!("usage API: cannot refresh accounting state: {error}");
            return Ok(Json(super::err_json(format!(
                "usage accounting is unavailable: {error}"
            ))));
        }
    };

    let live = control(json!({ "cmd": "list-clients" })).await;
    let clients = match super::status::checked_client_array(&live) {
        Ok(clients) => clients,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let online_sessions = online_session_counts(&Some(json!({"clients":clients})));

    // Join against the exact external + inline users union selected by current server.conf.
    // A read/parse failure is surfaced instead of silently serving a boot-time ACL snapshot.
    let (_, db) = match super::current_config_and_users(&state).await {
        Ok(current) => current,
        Err(error) => return Ok(Json(super::err_json(error))),
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
            "sessions": us.map(|x| x.sessions).unwrap_or(0),
            "data_limit_gb": u.data_limit_gb,
            "expire_at": u.expire_at,
            "online": online_sessions.contains_key(&u.username),
            "online_sessions": online_sessions.get(&u.username).copied().unwrap_or(0),
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
    if let Err(error) = super::require_json_object(&body) {
        return Ok(Json(super::err_json(error)));
    }
    // Do not reconstitute a full edit from a stale panel or supervisor snapshot.
    // The worker merges only supplied fields under the authoritative users-file lock.
    if let Err(error) = crate::server::control::validate_limit_patch(&body) {
        return Ok(Json(super::err_json(error)));
    }
    let reply = control(json!({
        "cmd": "patch-limit", "username": username, "limit_patch": body
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_session_counts_groups_sessions_by_user() {
        let reply = Some(json!({
            "clients": [
                { "username": "alice" },
                { "username": "bob" },
                { "username": "alice" },
                { "profile": "missing-username" }
            ]
        }));

        let counts = online_session_counts(&reply);
        assert_eq!(counts.get("alice"), Some(&2));
        assert_eq!(counts.get("bob"), Some(&1));
        assert_eq!(counts.len(), 2);
        assert!(online_session_counts(&None).is_empty());
    }
}
