use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
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
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;

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
    let profile_list: Vec<Value> = match current_config(&state).await {
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

    Ok(Json(json!({
        "ok": true,
        "worker_ok": worker_ok,
        "version": env!("CARGO_PKG_VERSION"),
        "client_count": clients.len(),
        "profiles": profile_list,
    })))
}

pub async fn clients(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(qs): Query<ProfileQuery>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;

    let live = control(json!({"cmd": "list-clients"})).await;
    let mut clients = client_array(&live);
    if let Some(ref filter) = qs.profile {
        clients.retain(|c| c["profile"].as_str() == Some(filter.as_str()));
    }
    Ok(Json(json!({ "ok": true, "clients": clients })))
}

pub async fn kick_client(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;
    let profile = body["profile"].as_str().unwrap_or("");
    let reply = control(json!({"cmd": "kick", "username": username, "profile": profile}))
        .await
        .unwrap_or_else(|| json!({"ok": false, "error": "data-plane worker unavailable"}));
    Ok(Json(reply))
}

pub async fn set_bandwidth(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;
    let mbps = body["mbps"].as_u64().unwrap_or(0);
    let profile = body["profile"].as_str().unwrap_or("");
    let reply = control(
        json!({"cmd": "set-bandwidth", "username": username, "mbps": mbps, "profile": profile}),
    )
    .await
    .unwrap_or_else(|| json!({"ok": false, "error": "data-plane worker unavailable"}));
    Ok(Json(reply))
}
