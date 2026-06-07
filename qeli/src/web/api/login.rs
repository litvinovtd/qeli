use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

/// Verify the admin credentials and, on success, set the session cookie.
pub async fn login(State(state): State<Arc<ServerState>>, Json(body): Json<Value>) -> Response {
    let web = &state.config.web;
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");

    if !auth::verify_credentials(username, password, web) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "error": "Invalid username or password"})),
        )
            .into_response();
    }

    // `Secure` only when the panel is served over HTTPS (web.secure_cookie) — adding
    // it on a plain-HTTP panel would stop the browser from ever sending the cookie.
    let secure = if web.secure_cookie { "; Secure" } else { "" };
    let cookie = format!(
        "{}={}; HttpOnly; Path=/; Max-Age={}; SameSite=Strict{}",
        auth::COOKIE_NAME,
        auth::make_session_token(web),
        auth::SESSION_TTL_SECS,
        secure,
    );
    with_cookie(json!({"ok": true}), &cookie)
}

/// Clear the session cookie.
pub async fn logout() -> Response {
    let cookie = format!(
        "{}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict",
        auth::COOKIE_NAME,
    );
    with_cookie(json!({"ok": true}), &cookie)
}

fn with_cookie(body: Value, cookie: &str) -> Response {
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    if let Ok(value) = HeaderValue::from_str(cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}
