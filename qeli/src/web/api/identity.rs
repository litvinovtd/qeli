//! Server identity keys over the API — the panel equivalent of the
//! `qeli show-identity` / `qeli rotate-identity` CLI commands. Each profile has
//! its own static X25519 identity; clients pin the matching public key
//! (`auth.server_public_key`). Surfacing this in the UI removes the "SSH in and
//! run show-identity" step the dashboard used to instruct.

use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

/// Re-read the on-disk config so newly-applied profiles are reflected (the
/// supervisor's in-memory config is its startup snapshot).
async fn current_config(state: &Arc<ServerState>) -> Option<crate::config::server::ServerConfig> {
    let path = state.config_path.lock().await.clone()?;
    let s = std::fs::read_to_string(path).ok()?;
    crate::config::parse_server_config(&s).ok()
}

fn hex_public(kp: &crate::crypto::StaticKeypair) -> String {
    kp.public
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// List each profile's pinned server public key (loading or first-time
/// generating the key file, exactly like `show-identity`).
pub async fn list_identity(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let cfg = match current_config(&state).await {
        Some(c) => c,
        None => return Ok(Json(super::err_json("cannot read server config"))),
    };
    let mut profiles = Vec::new();
    for p in &cfg.profiles {
        let entry = match crate::server::load_or_generate_profile_key(p) {
            Ok(kp) => json!({
                "name": p.name,
                "bind": format!("{}://{}:{}", p.bind.transport, p.bind.address, p.bind.port),
                "public_key": hex_public(&kp),
            }),
            Err(e) => json!({ "name": p.name, "error": e.to_string() }),
        };
        profiles.push(entry);
    }
    Ok(Json(json!({ "ok": true, "profiles": profiles })))
}

/// Rotate (regenerate) one profile's identity key. The running worker keeps the
/// old key until a restart, and clients of that profile must update their pinned
/// `auth.server_public_key` afterwards — surfaced in the response message.
pub async fn rotate_identity(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(profile): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let cfg = match current_config(&state).await {
        Some(c) => c,
        None => return Ok(Json(super::err_json("cannot read server config"))),
    };
    let p = match cfg.profiles.iter().find(|p| p.name == profile) {
        Some(p) => p,
        None => {
            return Ok(Json(super::err_json(format!(
                "profile '{}' not found",
                profile
            ))))
        }
    };
    match crate::server::generate_profile_key(p) {
        Ok(kp) => {
            log::info!("CONTROL action='rotate-identity' profile='{}'", profile);
            Ok(Json(json!({
                "ok": true,
                "public_key": hex_public(&kp),
                "message": format!(
                    "rotated identity for '{}' — restart to apply, then update auth.server_public_key on its clients",
                    profile
                ),
            })))
        }
        Err(e) => Ok(Json(super::err_json(format!("rotate failed: {}", e)))),
    }
}
