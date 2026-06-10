pub mod api;
pub mod auth;
pub mod pages;

use crate::server::ServerState;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};
use std::sync::Arc;

/// Reject mutating requests whose Origin/Referer doesn't match the server's
/// own bind. Browsers send these headers automatically for fetch/XHR/form
/// submissions, so a malicious page cannot trick a logged-in admin into a
/// state-changing request.
async fn csrf_same_origin(
    State(state): State<Arc<ServerState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    if matches!(&method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return Ok(next.run(req).await);
    }

    let web_cfg = &state.config.web;
    let port = web_cfg.port;
    // IPv6 literals must be bracketed in a Host/Origin (`[::1]:8080`), so format
    // the bind accordingly and always allow the IPv6 loopback too.
    let bind_host = if web_cfg.bind.contains(':') {
        format!("[{}]:{}", web_cfg.bind, port)
    } else {
        format!("{}:{}", web_cfg.bind, port)
    };
    let allowed_hosts = [
        bind_host,
        format!("127.0.0.1:{}", port),
        format!("localhost:{}", port),
        format!("[::1]:{}", port),
    ];

    let headers: &HeaderMap = req.headers();
    let raw = headers
        .get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok());

    let host_matches = |s: &str| -> bool {
        let after_scheme = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
        let host_port = after_scheme.split('/').next().unwrap_or("");
        allowed_hosts.iter().any(|h| host_port == h.as_str())
    };

    match raw {
        Some(v) if host_matches(v) => Ok(next.run(req).await),
        _ => {
            log::warn!(
                "CSRF: rejected {} {} (origin/referer={:?})",
                method,
                req.uri(),
                raw
            );
            Err(StatusCode::FORBIDDEN)
        }
    }
}

pub async fn start(state: Arc<ServerState>) {
    let web_cfg = &state.config.web;
    let addr = format!("{}:{}", web_cfg.bind, web_cfg.port);

    // The panel is served over plain HTTP. On loopback (the default) that's fine —
    // reach it via an SSH tunnel. On a non-loopback bind it would expose admin
    // credentials/session cookies in cleartext, so warn loudly; and if no admin
    // password is set, the API is wide open. (See docs/RELEASE-FIXES.md E4.)
    let bind = web_cfg.bind.as_str();
    let is_loopback = matches!(bind, "127.0.0.1" | "::1" | "[::1]" | "localhost");
    if !is_loopback {
        log::warn!(
            "Web panel bound to non-loopback {addr} over plain HTTP — put it behind a TLS \
             reverse proxy or an SSH tunnel, otherwise admin credentials transit in cleartext"
        );
        if web_cfg.password_hash.is_empty() {
            log::warn!(
                "Web panel has NO admin password (web.password_hash empty) AND a non-loopback \
                 bind — the admin API is OPEN to anyone who can reach {addr}"
            );
        }
    }

    let api_router = api::routes().route_layer(middleware::from_fn_with_state(
        state.clone(),
        csrf_same_origin,
    ));

    let app = Router::new()
        .route("/", axum::routing::get(pages::dashboard::dashboard))
        .route("/login", axum::routing::get(pages::login::login_page))
        .route("/users", axum::routing::get(pages::users::users_page))
        .route("/config", axum::routing::get(pages::config::config_page))
        .route("/logs", axum::routing::get(pages::logs::logs_page))
        .nest("/api", api_router)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await;
    match listener {
        Ok(l) => {
            log::info!("Web UI listening on http://{}", addr);
            // `into_make_service_with_connect_info` exposes the peer SocketAddr to
            // handlers (the login route uses it to rate-limit by source IP).
            axum::serve(
                l,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .ok();
        }
        Err(e) => {
            log::error!("Web UI failed to bind {}: {}", addr, e);
        }
    }
}
