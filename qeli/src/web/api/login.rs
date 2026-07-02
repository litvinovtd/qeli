use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;

/// Verify the admin credentials and, on success, set the session cookie.
pub async fn login(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // Live web settings (hot-reloadable: a panel password change applies without a
    // full restart). Cloned so no read guard is held across the Argon2 await.
    let web = state.live_web.read().await.clone();
    let web = &web;
    // Brute-force limiter identity: the socket peer, unless it is a configured
    // trusted reverse proxy — then the real client from X-Forwarded-For (so the
    // per-IP lockout/tarpit isn't collapsed into one global bucket behind a proxy).
    let client_ip =
        crate::server::web::effective_client_ip(&headers, peer.ip(), &web.trusted_proxies);
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");

    // Rate-limit panel logins (reuse the VPN brute-force tracker) so an attacker
    // can't grind the deliberately-slow Argon2 admin hash. Hard lockout is per
    // source IP only; the admin username is never hard-locked, so it can't be
    // DoS'd — instead it is tarpitted under active guessing. Locks are held only
    // for the quick check/record, never across the Argon2 verify below. Behind a
    // reverse proxy the peer is the proxy (one shared bucket = a global limit); a
    // directly-exposed panel sees the real client IP.
    {
        let tracker = state.failed_auth.lock().await;
        if let Err(msg) = tracker.check_ip(client_ip) {
            log::warn!(
                "PANEL LOGIN BLOCKED from {} user='{}': {}",
                client_ip,
                crate::util::log_sanitize(username),
                msg
            );
            // Notify (Tier-3) — throttled to once/10 min per source IP.
            let key = format!("lockout:{}", client_ip);
            let detail = format!(
                "panel login blocked from {} (user '{}')",
                client_ip,
                crate::util::log_sanitize(username)
            );
            tokio::spawn(async move {
                crate::server::notify::fire_throttled(
                    &key,
                    600,
                    crate::server::notify::Event::LoginLockout,
                    &detail,
                )
                .await;
            });
            return (StatusCode::TOO_MANY_REQUESTS, Json(super::err_json(msg))).into_response();
        }
    }
    let tarpit = state.failed_auth.lock().await.user_tarpit(username);
    if !tarpit.is_zero() {
        tokio::time::sleep(tarpit).await;
    }

    if !auth::verify_credentials(username, password, web).await {
        state
            .failed_auth
            .lock()
            .await
            .record_failure(username, client_ip);
        log::warn!(
            "PANEL LOGIN FAIL from {} user='{}'",
            client_ip,
            crate::util::log_sanitize(username)
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(super::err_json("Invalid username or password")),
        )
            .into_response();
    }
    state.failed_auth.lock().await.record_success(username);

    // `Secure` when the panel is served over HTTPS — either native TLS (web.tls)
    // or behind a TLS proxy (web.secure_cookie). Never on plain HTTP, or the
    // browser would never send the cookie back.
    let secure = if web.secure_cookie || web.tls {
        "; Secure"
    } else {
        ""
    };
    // Cookie Max-Age tracks the signed token's TTL (operator-configurable via
    // `web.session_ttl_secs`); fall back to the default on a non-positive misconfig
    // so the cookie can't outlive/undershoot the token.
    let ttl = if web.session_ttl_secs > 0 {
        web.session_ttl_secs
    } else {
        auth::SESSION_TTL_SECS
    };
    let cookie = format!(
        "{}={}; HttpOnly; Path=/; Max-Age={}; SameSite=Strict{}",
        auth::COOKIE_NAME,
        auth::make_session_token(web),
        ttl,
        secure,
    );
    with_cookie(super::ok_json(), &cookie)
}

/// Clear the session cookie.
pub async fn logout() -> Response {
    let cookie = format!(
        "{}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict",
        auth::COOKIE_NAME,
    );
    with_cookie(super::ok_json(), &cookie)
}

fn with_cookie(body: Value, cookie: &str) -> Response {
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}
