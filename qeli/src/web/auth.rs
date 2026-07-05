use crate::config::server::WebConfig;
use crate::server::ServerState;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::net::SocketAddr;
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

fn too_many(msg: String) -> AuthError {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"ok": false, "error": msg})),
    )
}

/// Authentication check for **HTML page** handlers: a valid session cookie only
/// (or an open panel). Deliberately does NOT consider HTTP Basic credentials.
///
/// Pages are reached by a browser, which authenticates with the `qeli_session`
/// cookie minted at `/api/login`; Basic auth is for API / curl clients and goes
/// through the rate-limited [`AuthGuard`]. Honouring Basic here (as the old
/// `is_authed` did) ran Argon2 on every page request with NO rate-limit or
/// tarpit — letting an attacker grind the admin hash, and flood the blocking
/// pool with memory-hard Argon2, simply by hammering `GET /` with `Authorization:
/// Basic …`. This path is synchronous (a cheap HMAC) and never touches Argon2.
pub fn is_authed_cookie_only(headers: &HeaderMap, web_cfg: &WebConfig) -> bool {
    web_cfg.password_hash.is_empty() || cookie_authed(headers, web_cfg)
}

/// Verify a username + plaintext password against the configured admin account.
/// The Argon2 verification is offloaded to a blocking thread so it never stalls an
/// async worker (Argon2 is intentionally slow and memory-hard).
pub async fn verify_credentials(username: &str, password: &str, web_cfg: &WebConfig) -> bool {
    let supplied_user = username.to_string();
    let supplied_pass = password.to_string();
    let cfg_user = web_cfg.username.clone();
    let cfg_hash = web_cfg.password_hash.clone();
    tokio::task::spawn_blocking(move || {
        // Constant-time username compare (avoids a timing side-channel on the admin
        // username), and use a non-short-circuiting `&` so the Argon2 verify always
        // runs regardless of whether the username matched — otherwise the presence
        // (or absence) of the ~memory-hard Argon2 delay would itself leak whether the
        // supplied username was correct.
        let user_ok = constant_time_eq(supplied_user.as_bytes(), cfg_user.as_bytes());
        let pass_ok = verify_password(&supplied_pass, &cfg_hash);
        user_ok & pass_ok
    })
    .await
    .unwrap_or(false)
}

/// Mint a stateless, signed session token: `<exp>.<hmac>`. The HMAC key is a
/// per-process random secret (HKDF, see [`sign`]) — NOT the admin password hash —
/// so reading the config can't forge tokens (H-4). The password hash is mixed in
/// as the HKDF salt, so changing the password still invalidates every session.
/// No server-side session store is needed; sessions end on a daemon restart.
pub fn make_session_token(web_cfg: &WebConfig) -> String {
    // Session lifetime is operator-configurable (`web.session_ttl_secs`); the const
    // is just the default. Guard against a zero/negative misconfig so a bad value
    // can't mint an already-expired (or never-expiring) token.
    let ttl = if web_cfg.session_ttl_secs > 0 {
        // 30-day upper bound so an absurdly large misconfig can't mint a near-eternal token.
        web_cfg.session_ttl_secs.min(30 * 24 * 3600)
    } else {
        SESSION_TTL_SECS
    };
    let exp = now() + ttl;
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

/// Per-process random secret for signing session tokens. Generated once on first
/// use from the OS CSPRNG and never written anywhere, so a leak of the config /
/// admin password hash does NOT reveal the session-signing key (H-4). It is
/// regenerated on restart — live sessions then end and the admin re-logs in.
fn session_secret() -> &'static [u8; 32] {
    static SECRET: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    SECRET.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
        k
    })
}

fn sign(payload: &str, web_cfg: &WebConfig) -> String {
    use hkdf::Hkdf;
    use zeroize::Zeroize;
    // HMAC key = HKDF(ikm = per-process random secret, salt = admin password hash).
    // The random ikm means a config/hash leak can't forge tokens; the password-hash
    // salt means changing the admin password invalidates every existing session.
    let hk = Hkdf::<Sha256>::new(Some(web_cfg.password_hash.as_bytes()), session_secret());
    let mut key = [0u8; 32];
    hk.expand(b"qeli-web-session-v1", &mut key)
        .expect("HKDF expand for the session key");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts a key of any length");
    key.zeroize();
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

/// Parse an HTTP Basic `Authorization: Basic base64(user:pass)` header into
/// `(user, pass)`. Cheap and synchronous — the expensive Argon2 verification is
/// done separately in `verify_credentials` (off the async runtime).
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let encoded = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
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

// axum 0.8: `FromRequestParts` uses a native `async fn` (no `#[async_trait]`).
impl FromRequestParts<Arc<ServerState>> for AuthGuard {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ServerState>,
    ) -> Result<Self, Self::Rejection> {
        // Live web settings (hot-reloadable: a panel password/allowlist change
        // applies without a full restart). Cloned so no read guard is held across
        // the Argon2 await below.
        let web = state.live_web.read().await.clone();
        // Open panel, or a valid session cookie (cheap HMAC) — done.
        if web.password_hash.is_empty() || cookie_authed(&parts.headers, &web) {
            return Ok(AuthGuard);
        }
        // HTTP Basic path. Rate-limit it like the form login (W1b) so the Argon2
        // admin hash can't be ground via API calls — but ONLY count an attempt that
        // actually presented (wrong) credentials. A request with no Authorization
        // header is a normal probe / expired session; counting it would let anyone
        // lock the admin out, and an invalid session cookie must not count either.
        let (user, pass) = match basic_credentials(&parts.headers) {
            Some(c) => c,
            None => return Err(unauth()),
        };
        let peer_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        if let Some(ip) = peer_ip {
            if let Err(msg) = state.failed_auth.lock().await.check_ip(ip) {
                return Err(too_many(msg));
            }
        }
        // Per-username tarpit (never a hard lock on the admin account, so it
        // can't be DoS'd) — throttles distributed grinding of the admin hash.
        let tarpit = state.failed_auth.lock().await.user_tarpit(&user);
        if !tarpit.is_zero() {
            tokio::time::sleep(tarpit).await;
        }
        if verify_credentials(&user, &pass, &web).await {
            state.failed_auth.lock().await.record_success(&user);
            Ok(AuthGuard)
        } else {
            if let Some(ip) = peer_ip {
                state.failed_auth.lock().await.record_failure(&user, ip);
            }
            Err(unauth())
        }
    }
}
