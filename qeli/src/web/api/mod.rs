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
        // Raw-text config editor (preserves INI comments)
        .route("/config/raw", get(config::get_config_raw))
        .route("/config/raw", put(config::put_config_raw))
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
        .route("/login", post(login::login))
        .route("/logout", post(login::logout))
        // Outbound notifications — Telegram + generic webhook (Tier-3)
        .route("/notify", get(notify::get_notify).put(notify::put_notify))
        .route("/notify/test", post(notify::test_notify))
        // Server control
        .route("/server/restart", post(control::restart))
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
