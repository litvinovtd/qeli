use crate::config::server::WebConfig;
use crate::server::ServerState;
use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub type AuthError = (StatusCode, Json<Value>);

/// Name of the session cookie set after a successful form login.
pub const COOKIE_NAME: &str = "qeli_session";
/// Lifetime of a login session, in seconds.
pub const SESSION_TTL_SECS: i64 = 86_400;

fn unauth() -> AuthError {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"ok": false, "error": "Unauthorized"})),
    )
}

/// True when the request is authenticated — by a valid session cookie (browser
/// form login) or HTTP Basic credentials (curl / API). Open when no password set.
pub fn is_authed(headers: &HeaderMap, web_cfg: &WebConfig) -> bool {
    if web_cfg.password_hash.is_empty() {
        return true;
    }
    cookie_authed(headers, web_cfg) || basic_authed(headers, web_cfg)
}

/// Guard for API handlers: Ok if authenticated, else a 401 JSON error.
pub fn check_auth(headers: &HeaderMap, web_cfg: &WebConfig) -> Result<(), AuthError> {
    if is_authed(headers, web_cfg) {
        Ok(())
    } else {
        Err(unauth())
    }
}

/// Verify a username + plaintext password against the configured admin account.
pub fn verify_credentials(username: &str, password: &str, web_cfg: &WebConfig) -> bool {
    username == web_cfg.username && verify_password(password, &web_cfg.password_hash)
}

/// Mint a stateless, signed session token: `<exp>.<hmac>`. The HMAC key is the
/// admin password hash, so changing the password invalidates every session and
/// no server-side session store is needed (survives restarts).
pub fn make_session_token(web_cfg: &WebConfig) -> String {
    let exp = now() + SESSION_TTL_SECS;
    let payload = exp.to_string();
    let sig = sign(&payload, web_cfg);
    format!("{payload}.{sig}")
}

fn cookie_authed(headers: &HeaderMap, web_cfg: &WebConfig) -> bool {
    match cookie_value(headers, COOKIE_NAME) {
        Some(token) => verify_session_token(&token, web_cfg),
        None => false,
    }
}

fn verify_session_token(token: &str, web_cfg: &WebConfig) -> bool {
    let (payload, sig) = match token.split_once('.') {
        Some(parts) => parts,
        None => return false,
    };
    let expected = sign(payload, web_cfg);
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return false;
    }
    match payload.parse::<i64>() {
        Ok(exp) => exp > now(),
        Err(_) => false,
    }
}

fn sign(payload: &str, web_cfg: &WebConfig) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(web_cfg.password_hash.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(payload.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get("cookie").and_then(|v| v.to_str().ok())?;
    let prefix = format!("{name}=");
    raw.split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix(&prefix))
        .map(str::to_string)
}

fn basic_authed(headers: &HeaderMap, web_cfg: &WebConfig) -> bool {
    let encoded = match headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
    {
        Some(e) => e,
        None => return false,
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
        .and_then(|b| String::from_utf8(b).ok());
    match decoded.as_deref().and_then(|c| c.split_once(':')) {
        Some((user, pass)) => verify_credentials(user, pass, web_cfg),
        None => false,
    }
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::PasswordHash;
    use argon2::PasswordVerifier;
    match PasswordHash::new(hash) {
        Ok(parsed) => argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Axum extractor that enforces authentication on a route: a handler taking an
/// `AuthGuard` parameter only runs for authenticated requests, otherwise the request
/// is rejected with the same 401 JSON as `check_auth`. Replaces the per-handler
/// `auth::check_auth(&headers, ...)?` boilerplate (docs/REFACTOR-PLAN.md R9).
pub struct AuthGuard;

#[async_trait]
impl FromRequestParts<Arc<ServerState>> for AuthGuard {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ServerState>,
    ) -> Result<Self, Self::Rejection> {
        check_auth(&parts.headers, &state.config.web)?;
        Ok(AuthGuard)
    }
}
