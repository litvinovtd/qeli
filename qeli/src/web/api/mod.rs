mod config;
mod control;
mod hash;
mod login;
mod logs;
mod paths;
mod share;
mod status;
mod users;

use crate::server::ServerState;
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<ServerState>> {
    Router::new()
        // Status & clients
        .route("/status", get(status::status))
        .route("/clients", get(status::clients))
        .route("/clients/{username}/kick", post(status::kick_client))
        .route("/clients/{username}/bandwidth", post(status::set_bandwidth))
        // Config
        .route("/config", get(config::get_config))
        .route("/config", put(config::put_config))
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
        // Auth (form login → session cookie)
        .route("/login", post(login::login))
        .route("/logout", post(login::logout))
        // Server control
        .route("/server/restart", post(control::restart))
        // Utilities
        .route("/hash-password", post(hash::hash_password))
        .route("/logs", get(logs::get_logs))
        // qeli:// share link / QR for a user+profile. POST (not GET) so the
        // user's password rides in the request body, never in the URL/query
        // (which would leak into access logs and browser history).
        .route("/share", post(share::share_link))
}
