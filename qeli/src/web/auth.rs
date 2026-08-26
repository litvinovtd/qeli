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
    // Same rule as `AuthGuard`: an empty hash only opens the panel when the operator
    // explicitly asked for an unauthenticated one.
    (web_cfg.password_hash.is_empty() && web_cfg.insecure_no_auth)
        || cookie_authed(headers, web_cfg)
}

/// Verify a username + plaintext password against the configured admin account.
/// The Argon2 verification is offloaded to a blocking thread so it never stalls an
/// async worker (Argon2 is intentionally slow and memory-hard).
pub async fn verify_credentials(username: &str, password: &str, web_cfg: &WebConfig) -> bool {
    let supplied_user = username.to_string();
    let supplied_pass = password.to_string();
    let cfg_user = web_cfg.username.clone();
    let cfg_hash = web_cfg.password_hash.clone();
    // Bound concurrent memory-hard work: a login burst used to start one ~19 MiB Argon2
    // job per request, because no failure is recorded until a hash finishes. Held across
    // the verify below.
    let _permit = crate::server::argon2_gate().acquire().await;
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

/// Mint a stateless, signed session token: `<exp>.<hmac>`. The HMAC key is derived
/// (HKDF, see [`sign`]) from a signing secret that — by default
/// (`web.persist_session_key`) — is persisted to a 0600 file so logins survive a full
/// restart; with the flag off it is a per-process random value that ends every session on
/// restart (H-4). The admin password hash is mixed in as the HKDF salt, so changing the
/// password still invalidates every session. No server-side session store is needed.
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

/// Secret for signing session tokens. By DEFAULT (`web.persist_session_key`, on) it is
/// loaded from — or created in — a 0600 file, so panel logins SURVIVE a full restart. With
/// the flag off it is a per-process random value (H-4: a config/hash leak can't forge tokens,
/// but every restart ends all sessions and forces a re-login). Initialised once per process
/// (a flag change needs a restart).
fn session_secret(web_cfg: &WebConfig) -> &'static [u8; 32] {
    static SECRET: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let persist = web_cfg.persist_session_key;
    SECRET.get_or_init(move || {
        if persist {
            match load_or_create_persistent_secret() {
                Ok(key) => return key,
                Err(error) => log::warn!(
                    "web.persist_session_key is on but the key file could not be used ({error}) — \
                     falling back to a per-process key (sessions won't survive a restart)"
                ),
            }
        }
        let mut k = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut k);
        k
    })
}

/// Monotonic session GENERATION, mixed into the signing key so existing tokens can be
/// invalidated without a server-side session store.
///
/// The token is stateless — `<exp>.<hmac>` with nothing but an expiry inside — and there was
/// no way to revoke one. `logout` sent `Max-Age=0`, which asks the BROWSER to forget the
/// cookie and does nothing to the token: anyone holding its value (a reverse-proxy access
/// log, a browser extension, a shared workstation's cookie jar) kept full API access until
/// `exp`, up to 24 hours by default and 30 days at the configured maximum. Restarting the
/// service did not help either, because `persist_session_key` is on by default and the key is
/// read back from disk. The only existing lever was changing the admin password, which
/// changes the HKDF salt — not something an operator reaching for "Log out" expects to need.
///
/// Bumping this counter re-derives the HMAC key, so every previously issued token stops
/// verifying at once. It is deliberately global: a single-admin panel has no per-device
/// notion of "this session", and "log out everywhere" is the behaviour that actually helps
/// when a token is suspected stolen. (Audit 2026-08-04.)
static SESSION_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

fn read_session_generation(path: &std::path::Path) -> anyhow::Result<Option<u64>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => anyhow::bail!("cannot read {}: {error}", path.display()),
    };
    let generation = contents
        .trim()
        .parse::<u64>()
        .map_err(|error| anyhow::anyhow!("cannot parse {}: {error}", path.display()))?;
    if generation == u64::MAX {
        anyhow::bail!(
            "{} contains the reserved generation sentinel",
            path.display()
        );
    }
    Ok(Some(generation))
}

fn random_session_generation() -> u64 {
    loop {
        let generation = rand::random::<u64>();
        // Leave room for at least one revocation and never publish the cache sentinel.
        if generation < u64::MAX - 1 {
            return generation;
        }
    }
}

fn session_generation() -> u64 {
    use std::sync::atomic::Ordering;
    // u64::MAX is the "not loaded yet" sentinel — a real generation never reaches it.
    let cached = SESSION_GEN.load(Ordering::Acquire);
    if cached != u64::MAX {
        return cached;
    }
    let path = session_gen_path();
    let loaded = match read_session_generation(&path) {
        Ok(Some(generation)) => generation,
        Ok(None) => 0,
        Err(error) => {
            // Never fall back to generation zero: that would make old generation-zero tokens
            // valid precisely when the revocation state became unreadable. A random
            // process-local generation invalidates every persisted token for this process.
            let generation = random_session_generation();
            log::error!(
                "web: session generation is unavailable ({error}); using fail-closed \
                 process-local generation {generation}. Repair the file and change the admin \
                 password before restarting so older tokens cannot reappear."
            );
            generation
        }
    };
    match SESSION_GEN.compare_exchange(u64::MAX, loaded, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => loaded,
        Err(existing) => existing,
    }
}

/// Invalidate every session token issued so far. Returns the new generation.
pub fn revoke_all_sessions() -> anyhow::Result<u64> {
    use std::sync::atomic::Ordering;
    let path = session_gen_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // The sidecar lock survives the atomic rename and serialises concurrent panel processes.
    let _lock = crate::util::FileLock::acquire(&path)?;
    let persisted = read_session_generation(&path)?.unwrap_or(0);
    let cached = SESSION_GEN.load(Ordering::Acquire);
    let current = if cached == u64::MAX {
        persisted
    } else {
        persisted.max(cached)
    };
    let next = current
        .checked_add(1)
        .filter(|generation| *generation != u64::MAX)
        .ok_or_else(|| anyhow::anyhow!("session generation counter is exhausted"))?;

    crate::util::write_atomic_private(&path, next.to_string().as_bytes())?;
    // Publish immediately after the successful rename: from this point old tokens are invalid
    // in the running process even if the directory durability check below reports an error.
    SESSION_GEN.store(next, Ordering::Release);
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    log::info!("web: all panel sessions revoked (generation {next})");
    Ok(next)
}

/// Sibling of the session key: `$STATE_DIRECTORY/session.gen`, else `/etc/qeli/.session_gen`.
fn session_gen_path() -> std::path::PathBuf {
    let mut p = session_key_path();
    p.set_file_name(if p.to_string_lossy().contains(".session_key") {
        ".session_gen"
    } else {
        "session.gen"
    });
    p
}

/// Where the persisted session key lives: `$STATE_DIRECTORY/session.key` (systemd
/// `StateDirectory=qeli` → /var/lib/qeli) when set, else `/etc/qeli/.session_key`.
fn session_key_path() -> std::path::PathBuf {
    if let Some(dir) = std::env::var_os("STATE_DIRECTORY") {
        let d = dir.to_string_lossy();
        if let Some(first) = d.split(':').next().filter(|p| !p.is_empty()) {
            return std::path::Path::new(first).join("session.key");
        }
    }
    std::path::PathBuf::from("/etc/qeli/.session_key")
}

/// Read the persisted 32-byte session key, or create it atomically (0600) on first use.
fn load_or_create_persistent_secret() -> anyhow::Result<[u8; 32]> {
    let path = session_key_path();
    load_or_create_persistent_secret_at(&path)
}

fn load_or_create_persistent_secret_at(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _lock = crate::util::FileLock::acquire(path)?;
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            log::info!(
                "web: session-signing key loaded from {} — panel logins survive restarts",
                path.display()
            );
            return Ok(k);
        }
        Ok(bytes) => anyhow::bail!(
            "{} has {} bytes instead of 32; refusing to overwrite the damaged key",
            path.display(),
            bytes.len()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => anyhow::bail!("cannot read {}: {error}", path.display()),
    }
    let mut k = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut k);
    crate::util::write_atomic_private(path, &k)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    log::info!(
        "web: session-signing key created at {} (0600) — panel logins survive restarts",
        path.display()
    );
    Ok(k)
}

fn sign(payload: &str, web_cfg: &WebConfig) -> String {
    use hkdf::Hkdf;
    use zeroize::Zeroize;
    // HMAC key = HKDF(ikm = per-process random secret, salt = admin password hash).
    // The random ikm means a config/hash leak can't forge tokens; the password-hash
    // salt means changing the admin password invalidates every existing session.
    let hk = Hkdf::<Sha256>::new(
        Some(web_cfg.password_hash.as_bytes()),
        session_secret(web_cfg),
    );
    let mut key = [0u8; 32];
    // The GENERATION is part of the HKDF info, so `revoke_all_sessions` re-derives a
    // different key and every token minted under the old one stops verifying.
    // (Audit 2026-08-04.)
    let info = format!("qeli-web-session-v1:{}", session_generation());
    hk.expand(info.as_bytes(), &mut key)
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
/// `auth::check_auth(&headers, ...)?` boilerplate (docs/*/archive/plans/REFACTOR-PLAN.md R9).
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
        // An empty hash alone is no longer a pass — it must be the deliberate
        // `insecure_no_auth`, which the startup gate has already announced.
        if (web.password_hash.is_empty() && web.insecure_no_auth)
            || cookie_authed(&parts.headers, &web)
        {
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
        // Attribute the attempt to the REAL client, not the reverse proxy. This was the
        // only one of the three enforcement points still using the raw socket peer
        // (`login.rs` and the `ip_allowlist` middleware both resolve it properly), so
        // behind a configured proxy every Basic-auth request collapsed into one bucket:
        // five failures from anyone locked out EVERY user for the lockout window.
        // `effective_client_ip` still refuses the header unless the peer is a configured
        // `trusted_proxies` entry, so this cannot be spoofed by a direct client.
        let peer_ip = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|ci| {
            crate::server::web::effective_client_ip(&parts.headers, ci.0.ip(), &web.trusted_proxies)
        });
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

#[cfg(test)]
mod tests {
    //! This module decides whether an HTTP request is authorised, and it had NO tests at
    //! all — a regression in any of it would pass CI in silence. The neighbouring
    //! `web/mod.rs` tests cover CSP nonces and X-Forwarded-For, none of them authorisation.
    //!
    //! What is pinned here is the token contract: a forged signature is refused, an expired
    //! or malformed expiry is refused, a token minted under a DIFFERENT admin password stops
    //! verifying (that is what makes a password change end every session), the TTL is
    //! clamped at both ends, and an empty `password_hash` does NOT open the panel unless the
    //! operator explicitly asked for it. (Audit 2026-08-04.)
    use super::*;

    /// `persist_session_key = false` keeps the signing secret in-process, so the tests never
    /// touch /etc or $STATE_DIRECTORY.
    fn cfg(hash: &str) -> WebConfig {
        WebConfig {
            username: "admin".into(),
            password_hash: hash.into(),
            persist_session_key: false,
            ..Default::default()
        }
    }

    fn headers_with_cookie(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("{COOKIE_NAME}={token}")).unwrap(),
        );
        h
    }

    #[test]
    fn session_generation_reader_distinguishes_missing_and_corrupt_state() {
        let path = std::env::temp_dir().join(format!(
            "qeli-session-generation-test-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_session_generation(&path).unwrap(), None);

        std::fs::write(&path, "17\n").unwrap();
        assert_eq!(read_session_generation(&path).unwrap(), Some(17));

        std::fs::write(&path, "not-a-generation").unwrap();
        assert!(read_session_generation(&path).is_err());

        std::fs::write(&path, u64::MAX.to_string()).unwrap();
        assert!(read_session_generation(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_session_key_creation_converges_and_corruption_is_preserved() {
        let dir =
            std::env::temp_dir().join(format!("qeli-session-key-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.key");

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || load_or_create_persistent_secret_at(&path).unwrap())
            })
            .collect();
        let keys: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(keys.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(std::fs::read(&path).unwrap(), keys[0]);

        std::fs::write(&path, b"truncated").unwrap();
        assert!(load_or_create_persistent_secret_at(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"truncated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_freshly_minted_token_verifies() {
        let c = cfg("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA");
        let t = make_session_token(&c);
        assert!(verify_session_token(&t, &c), "our own token must verify");
        assert!(cookie_authed(&headers_with_cookie(&t), &c));
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let c = cfg("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA");
        let t = make_session_token(&c);
        let (payload, sig) = t.split_once('.').expect("token is <exp>.<hmac>");

        // Flip one hex digit of the MAC.
        let mut bytes: Vec<char> = sig.chars().collect();
        bytes[0] = if bytes[0] == 'a' { 'b' } else { 'a' };
        let forged: String = bytes.into_iter().collect();
        assert!(!verify_session_token(&format!("{payload}.{forged}"), &c));

        // No separator at all, and an empty MAC.
        assert!(!verify_session_token(payload, &c));
        assert!(!verify_session_token(&format!("{payload}."), &c));
        assert!(!verify_session_token("", &c));
    }

    #[test]
    fn an_expired_or_unparseable_expiry_is_refused() {
        let c = cfg("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA");
        // Sign a payload that is already in the past — the signature is VALID, so this
        // isolates the expiry check from the MAC check.
        let past = (now() - 60).to_string();
        let expired = format!("{past}.{}", sign(&past, &c));
        assert!(!verify_session_token(&expired, &c), "exp in the past");

        for junk in ["abc", "", "9999999999999999999999", "-1"] {
            let t = format!("{junk}.{}", sign(junk, &c));
            assert!(
                !verify_session_token(&t, &c),
                "non-numeric/absurd exp must not pass: {junk:?}"
            );
        }
    }

    /// Changing the admin password must invalidate every existing session. The mechanism is
    /// the HKDF salt, so a token signed under one hash must not verify under another.
    #[test]
    fn a_password_change_invalidates_existing_tokens() {
        let old = cfg("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$b2xkaGFzaA");
        let new = cfg("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$bmV3aGFzaA");
        let t = make_session_token(&old);
        assert!(verify_session_token(&t, &old));
        assert!(
            !verify_session_token(&t, &new),
            "a token signed under the previous password hash must stop verifying"
        );
    }

    #[test]
    fn the_ttl_is_clamped_at_both_ends() {
        let mut c = cfg("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA");
        let exp_of = |t: &str| -> i64 { t.split_once('.').unwrap().0.parse().unwrap() };

        // Zero / negative fall back to the default rather than minting an already-dead token.
        for bad in [0, -1, -86400] {
            c.session_ttl_secs = bad;
            assert!(
                exp_of(&make_session_token(&c)) > now(),
                "ttl {bad} must not mint an expired token"
            );
        }
        // Absurdly large is capped at 30 days, not honoured verbatim.
        c.session_ttl_secs = i64::MAX / 2;
        let exp = exp_of(&make_session_token(&c));
        assert!(
            exp <= now() + 30 * 24 * 3600 + 5,
            "a huge ttl must be clamped to 30 days, got exp {exp}"
        );
    }

    /// An empty `password_hash` is a misconfiguration, not an invitation. It opens the panel
    /// only together with the explicit `insecure_no_auth` flag.
    #[test]
    fn an_empty_hash_alone_does_not_open_the_panel() {
        let mut c = cfg("");
        let empty = HeaderMap::new();
        assert!(
            !is_authed_cookie_only(&empty, &c),
            "empty hash WITHOUT insecure_no_auth must not authenticate"
        );
        c.insecure_no_auth = true;
        assert!(
            is_authed_cookie_only(&empty, &c),
            "empty hash WITH insecure_no_auth is the documented passwordless mode"
        );
    }

    #[test]
    fn constant_time_eq_matches_ordinary_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        // Different lengths must never compare equal (and must not panic).
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
