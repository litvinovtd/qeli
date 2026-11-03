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

fn hex_public(kp: &crate::crypto::StaticKeypair) -> String {
    kp.public
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}
fn format_bind_endpoint(transport: impl std::fmt::Display, address: &str, port: u16) -> String {
    let address = address.trim();
    let host = if address.starts_with('[') && address.ends_with(']') {
        address.to_owned()
    } else if address.contains(':') {
        format!("[{address}]")
    } else {
        address.to_owned()
    };
    format!("{transport}://{host}:{port}")
}

/// List each profile's pinned server public key (loading or first-time
/// generating the key file, exactly like `show-identity`).
pub async fn list_identity(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let cfg = match super::current_server_config(&state).await {
        Ok(config) => config,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let mut profiles = Vec::new();
    for p in &cfg.profiles {
        let entry = match crate::server::load_or_generate_profile_key(p) {
            Ok(kp) => json!({
                "name": p.name,
                "bind": format_bind_endpoint(&p.bind.transport, &p.bind.address, p.bind.port),
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
    let cfg = match super::current_server_config(&state).await {
        Ok(config) => config,
        Err(error) => return Ok(Json(super::err_json(error))),
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

#[cfg(test)]
mod tests {
    use super::format_bind_endpoint;

    #[cfg(unix)]
    #[tokio::test]
    async fn identity_endpoints_reject_untrusted_config_before_creating_a_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "qeli-panel-identity-trust-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let key = dir.join("profile.key");
        let config_path = dir.join("server.conf");
        let raw = format!("[profile:p]\nidentity_key = {}\n", key.display());
        std::fs::write(&config_path, &raw).unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let config = crate::config::parse_server_config(&raw).unwrap();
        let state = crate::server::test_api_state(config, &config_path);

        let listed = super::list_identity(
            axum::extract::State(state.clone()),
            crate::server::web::auth::AuthGuard,
        )
        .await
        .unwrap()
        .0;
        assert_eq!(listed["ok"], false);
        assert!(listed["error"].as_str().unwrap().contains("identity_key"));
        let rotated = super::rotate_identity(
            axum::extract::State(state.clone()),
            crate::server::web::auth::AuthGuard,
            axum::extract::Path("p".into()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(rotated["ok"], false);
        assert!(!key.exists());

        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let listed = super::list_identity(
            axum::extract::State(state),
            crate::server::web::auth::AuthGuard,
        )
        .await
        .unwrap()
        .0;
        assert_eq!(listed["ok"], true, "{listed}");
        assert!(key.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn formats_ipv4_and_hostnames_without_brackets() {
        assert_eq!(
            format_bind_endpoint("tcp", "0.0.0.0", 443),
            "tcp://0.0.0.0:443"
        );
        assert_eq!(
            format_bind_endpoint("udp", "vpn.example.test", 8449),
            "udp://vpn.example.test:8449"
        );
    }

    #[test]
    fn brackets_ipv6_literals_once() {
        assert_eq!(
            format_bind_endpoint("tcp", "2001:db8:85a3::8a2e:370:7334", 443),
            "tcp://[2001:db8:85a3::8a2e:370:7334]:443"
        );
        assert_eq!(format_bind_endpoint("udp", "[::]", 8449), "udp://[::]:8449");
        assert_eq!(
            format_bind_endpoint("udp", "fe80::1%eth0", 8449),
            "udp://[fe80::1%eth0]:8449"
        );
    }
}
