mod backup;
mod client;
mod config;
mod control;
mod hash;
mod identity;
mod login;
mod logs;
mod notify;
mod paths;
mod share;
mod status;
mod system;
mod transport;
mod usage;
mod users;

use crate::server::ServerState;
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn routes() -> Router<Arc<ServerState>> {
    // Path params use axum-0.8 brace syntax (`{name}`, `{*rest}`).
    Router::new()
        // Status & clients
        .route("/status", get(status::status))
        .route("/clients", get(status::clients))
        // Host + tunnel metrics (dashboard observability)
        .route("/system", get(system::get_system))
        .route("/metrics", get(system::get_metrics))
        .route("/transport/health", get(transport::health))
        // Per-user lifetime usage + data caps / expiry (Tier-2)
        .route("/usage", get(usage::get_usage))
        .route("/usage/{username}/limit", post(usage::set_limit))
        .route("/usage/{username}/reset", post(usage::reset_usage))
        .route("/clients/{username}/kick", post(status::kick_client))
        .route("/clients/{username}/bandwidth", post(status::set_bandwidth))
        // Brute-force blocked IPs
        .route("/blocked", get(status::blocked))
        .route("/blocked/{ip}/unblock", post(status::unblock))
        .route("/blocked/clear", post(status::unblock_all))
        // Lockout policy (one [auth] brute_force config → web-panel login + VPN auth)
        .route(
            "/blocked/settings",
            get(status::blocked_settings).post(status::set_blocked_settings),
        )
        // Config
        .route("/config", get(config::get_config))
        .route("/config", put(config::put_config))
        // Canonical UI defaults (single source of truth for new profiles)
        .route("/config/defaults", get(config::get_config_defaults))
        // Canonical, server-validated Quick Start profiles. Keeping construction in Rust
        // means all ten modes are exercised by the same validator that starts the worker.
        .route(
            "/config/quickstart/{mode}",
            get(config::get_quickstart_profile).post(config::apply_quickstart_profile),
        )
        // Raw-text config editor (preserves INI comments)
        .route("/config/raw", get(config::get_config_raw))
        .route("/config/raw", put(config::put_config_raw))
        // Bounded private snapshots created before every panel config write.
        .route("/config/history", get(config::list_config_history))
        .route(
            "/config/history/{id}/restore",
            post(config::restore_config_history),
        )
        // Users CRUD
        .route("/users", get(users::list_users))
        .route("/users", post(users::create_user))
        .route("/users/{username}", get(users::get_user))
        .route("/users/{username}", put(users::update_user))
        .route("/users/{username}", delete(users::delete_user))
        .route("/users/{username}/enable", post(users::enable_user))
        .route("/users/{username}/disable", post(users::disable_user))
        .route(
            "/users/{username}/bandwidth",
            post(users::set_user_bandwidth),
        )
        // Group templates (live in the users file alongside users)
        .route("/groups", get(users::list_groups))
        .route("/groups/{name}", put(users::upsert_group))
        .route("/groups/{name}", delete(users::delete_group))
        // Auth (form login → session cookie)
        // Login is the one UNAUTHENTICATED endpoint and it runs Argon2, so it gets a
        // tight ceiling of its own instead of the 16 MiB the restore upload needs. The
        // brute-force limiter already caps Argon2 work per IP, but the body is buffered
        // and JSON-parsed BEFORE the limiter is consulted — so without this a
        // locked-out client could still make the server hold 16 MiB per request (and
        // the limit doubles as the password-length bound).
        .route(
            "/login",
            post(login::login).layer(axum::extract::DefaultBodyLimit::max(8 * 1024)),
        )
        .route("/logout", post(login::logout))
        // Outbound notifications — Telegram + generic webhook (Tier-3)
        .route("/notify", get(notify::get_notify).put(notify::put_notify))
        .route("/notify/test", post(notify::test_notify))
        // Server control
        .route("/server/restart", post(control::restart))
        .route("/server/full-restart", post(control::full_restart))
        // Off-box backup of /etc/qeli (config + users + identity) as a .tar.gz
        .route("/backup", get(backup::download_backup))
        // Restore /etc/qeli from an uploaded backup .tar.gz (reversible)
        .route("/restore", post(backup::restore_backup))
        // Server identity keys (show / rotate — pin these on clients)
        .route("/identity", get(identity::list_identity))
        .route(
            "/identity/{profile}/rotate",
            post(identity::rotate_identity),
        )
        // Utilities
        .route("/hash-password", post(hash::hash_password))
        .route("/logs", get(logs::get_logs))
        // qeli:// share link / QR for a user+profile. POST (not GET) so the
        // user's password rides in the request body, never in the URL/query
        // (which would leak into access logs and browser history).
        .route("/share", post(share::share_link))
        // Client manager — outbound tunnels this box dials to other qeli servers
        .route("/client/profiles", get(client::list_profiles))
        .route("/client/profiles", post(client::save_profile))
        .route("/client/import", post(client::import_link))
        .route("/client/profiles/{name}", get(client::get_profile))
        .route("/client/profiles/{name}", delete(client::delete_profile))
        .route("/client/profiles/{name}/connect", post(client::connect))
        .route(
            "/client/profiles/{name}/disconnect",
            post(client::disconnect),
        )
        // Explicit request-body ceiling (axum's implicit default is 2 MiB): large enough
        // for an /api/restore tar.gz, but bounded so a huge body can't exhaust memory.
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
}

/// Standard API error body: `{"ok": false, "error": <msg>}`. Centralizes the
/// response shape repeated across the API handlers (docs/REFACTOR-PLAN.md R8).
pub(crate) fn err_json(msg: impl Into<String>) -> Value {
    json!({"ok": false, "error": msg.into()})
}

/// Standard bare API success body: `{"ok": true}`.
pub(crate) fn ok_json() -> Value {
    json!({"ok": true})
}

/// Re-read the canonical on-disk server config. The supervisor's ServerState.config is
/// intentionally the boot-time snapshot because it owns socket-bound panel settings; using
/// that snapshot for worker/profile/user operations after an in-process restart is stale.
pub(super) async fn current_server_config(
    state: &Arc<ServerState>,
) -> Result<crate::config::server::ServerConfig, String> {
    let path = state.config_path.lock().await.clone();
    let Some(path) = path else {
        return Ok(state.config.clone());
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read current server config '{}': {error}", path))?;
    let (config, findings) = crate::config::parse_server_config_reporting(&text)
        .map_err(|error| format!("cannot parse current server config '{}': {error}", path))?;
    if !findings.is_empty() {
        return Err(format!(
            "current server config '{}' has {} unreadable or ambiguous value(s): {}",
            path,
            findings.len(),
            findings.join("; ")
        ));
    }
    Ok(config)
}

/// Load exactly the users union the data-plane will use for this config: the external
/// users file plus inline user/group sections, with the file taking precedence.
pub(super) fn effective_users(
    config: &crate::config::server::ServerConfig,
) -> Result<crate::config::users::UsersDb, String> {
    crate::server::load_users_db_for_runtime(config).map_err(|error| {
        format!(
            "cannot load users configuration '{}': {error}",
            config.auth.users_file
        )
    })
}

/// Merge a freshly locked external users DB with inline config entries and validate the
/// complete candidate before it is written. This closes the race where a concurrent file
/// edit was valid by itself but conflicted with an inline user or profile reservation.
pub(super) fn effective_users_from_external(
    config: &crate::config::server::ServerConfig,
    db: crate::config::users::UsersDb,
) -> anyhow::Result<crate::config::users::UsersDb> {
    crate::server::effective_users_from_external(config, db)
}

/// Return a mutually matching config/users view without consulting the supervisor's stale
/// boot-time ACL snapshot. Callers that mutate either file still take config_write_lock.
pub(super) async fn current_config_and_users(
    state: &Arc<ServerState>,
) -> Result<
    (
        crate::config::server::ServerConfig,
        crate::config::users::UsersDb,
    ),
    String,
> {
    let config = current_server_config(state).await?;
    let users = effective_users(&config)?;
    Ok((config, users))
}

#[cfg(test)]
mod current_state_tests {
    use super::effective_users_from_external;
    use crate::config::server::ServerConfig;
    use crate::config::users::{UserEntry, UsersDb};

    fn user(name: &str, enabled: bool) -> UserEntry {
        UserEntry {
            username: name.to_string(),
            password_hash: "test-hash".to_string(),
            enabled,
            ..Default::default()
        }
    }

    #[test]
    fn candidate_union_keeps_file_precedence_and_inline_only_entries() {
        let mut config = ServerConfig::default();
        config.auth.users = vec![user("alice", true), user("bob", true)];
        let external = UsersDb {
            users: vec![user("alice", false)],
            ..Default::default()
        };

        let effective = effective_users_from_external(&config, external).unwrap();
        assert_eq!(effective.users.len(), 2);
        assert!(
            !effective
                .users
                .iter()
                .find(|entry| entry.username == "alice")
                .unwrap()
                .enabled
        );
        assert!(effective.users.iter().any(|entry| entry.username == "bob"));
    }
}
