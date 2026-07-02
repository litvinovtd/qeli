//! Outbound notifications (Tier-3): Telegram bot + generic webhook.
//!
//! Config lives in a sidecar `/etc/qeli/notify.json` (same pattern as
//! `usage.json`) so editing it from the panel needs no main-config reload, and
//! both the supervisor (server-start / login-lockout / restore events) and the
//! worker (quota sweep) can read it independently. Sends are fire-and-forget with
//! a hard timeout and never touch the data-plane hot path. Outbound HTTPS reuses
//! the existing rustls(ring) stack + the Mozilla root bundle (webpki-roots) so
//! certificates are properly verified — no MITM hole for the notification path.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Sidecar config file (qeli-owned, beside the main config).
pub const NOTIFY_PATH: &str = "/etc/qeli/notify.json";
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Which events a single channel sends. Defaults to all-on, so a freshly enabled
/// channel notifies everything until the admin trims it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEvents {
    #[serde(default = "d_true")]
    pub on_server_start: bool,
    #[serde(default = "d_true")]
    pub on_quota_breach: bool,
    #[serde(default = "d_true")]
    pub on_login_lockout: bool,
    #[serde(default = "d_true")]
    pub on_auth_lockout: bool,
    #[serde(default = "d_true")]
    pub on_restore: bool,
}

impl Default for ChannelEvents {
    fn default() -> Self {
        Self {
            on_server_start: true,
            on_quota_breach: true,
            on_login_lockout: true,
            on_auth_lockout: true,
            on_restore: true,
        }
    }
}

/// Telegram and the generic webhook are fully independent channels — each has its
/// own enable switch, credentials, and event selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// Optional label identifying THIS server in notification messages, so several
    /// servers reporting to the same Telegram chat / webhook are distinguishable.
    /// Empty = omit. Set it here in `/etc/qeli/notify.json` or on the panel's
    /// Notifications page.
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub telegram_enabled: bool,
    #[serde(default)]
    pub telegram_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,
    #[serde(default)]
    pub telegram_events: ChannelEvents,
    #[serde(default)]
    pub webhook_enabled: bool,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub webhook_events: ChannelEvents,
}

fn d_true() -> bool {
    true
}

#[derive(Clone, Copy)]
pub enum Event {
    ServerStart,
    QuotaBreach,
    LoginLockout,
    AuthLockout,
    Restore,
}

impl Event {
    fn id(self) -> &'static str {
        match self {
            Event::ServerStart => "server_start",
            Event::QuotaBreach => "quota_breach",
            Event::LoginLockout => "login_lockout",
            Event::AuthLockout => "auth_lockout",
            Event::Restore => "restore",
        }
    }
    fn title(self) -> &'static str {
        match self {
            Event::ServerStart => "\u{1F7E2} qeli server started",
            Event::QuotaBreach => "\u{26D4} Quota breach",
            Event::LoginLockout => "\u{1F512} Panel login lockout",
            Event::AuthLockout => "\u{1F6AB} VPN auth IP lockout",
            Event::Restore => "\u{267B} Config restored from backup",
        }
    }
    fn enabled_in(self, c: &ChannelEvents) -> bool {
        match self {
            Event::ServerStart => c.on_server_start,
            Event::QuotaBreach => c.on_quota_breach,
            Event::LoginLockout => c.on_login_lockout,
            Event::AuthLockout => c.on_auth_lockout,
            Event::Restore => c.on_restore,
        }
    }
}

/// Read the sidecar. Absent → defaults (normal). Present-but-unparsable →
/// defaults too, but LOUD: a corrupt `notify.json` silently disabled every channel
/// before, so the admin got no alert that alerting itself had stopped.
pub fn load() -> NotifyConfig {
    let s = match std::fs::read_to_string(NOTIFY_PATH) {
        Ok(s) => s,
        Err(_) => return NotifyConfig::default(),
    };
    match serde_json::from_str(&s) {
        Ok(cfg) => cfg,
        Err(e) => {
            log::warn!(
                "notify: {NOTIFY_PATH} exists but is unparsable ({e}) — all notifications \
                 DISABLED until it is fixed (using defaults)."
            );
            NotifyConfig::default()
        }
    }
}

/// Persist atomically (temp + rename) so a crash can't truncate the file.
pub fn save(cfg: &NotifyConfig) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(cfg).unwrap_or_default();
    crate::util::write_atomic(NOTIFY_PATH, &json)
}

fn now_unix() -> i64 {
    crate::server::usage::now_unix()
}

/// Per-key cooldown so recurring conditions (a user repeatedly reconnecting over
/// quota, an IP hammering the locked panel) alert at most once per window.
fn throttle_ok(key: &str, cooldown: i64) -> bool {
    static MAP: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    let m = MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let now = now_unix();
    let mut g = m.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(&t) = g.get(key) {
        if now - t < cooldown {
            return false;
        }
    }
    g.insert(key.to_string(), now);
    if g.len() > 512 {
        g.retain(|_, t| now - *t < 86_400);
    }
    true
}

/// `"[name] "` prefix identifying the server in messages, or empty when unset.
fn server_prefix(name: &str) -> String {
    let n = name.trim();
    if n.is_empty() {
        String::new()
    } else {
        format!("[{n}] ")
    }
}

/// Fire an event to every configured channel (fire-and-forget). No-op if notify
/// is disabled or this event's toggle is off.
pub async fn fire(event: Event, detail: &str) {
    let cfg = load();
    let text = format!(
        "{}{}\n{}",
        server_prefix(&cfg.server_name),
        event.title(),
        detail
    );
    if cfg.telegram_enabled
        && event.enabled_in(&cfg.telegram_events)
        && !cfg.telegram_token.is_empty()
        && !cfg.telegram_chat_id.is_empty()
    {
        let (t, c, m) = (
            cfg.telegram_token.clone(),
            cfg.telegram_chat_id.clone(),
            text.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = send_telegram(&t, &c, &m).await {
                log::warn!("notify telegram failed: {e}");
            }
        });
    }
    if cfg.webhook_enabled && event.enabled_in(&cfg.webhook_events) && !cfg.webhook_url.is_empty() {
        let url = cfg.webhook_url.clone();
        let body = serde_json::json!({
            "event": event.id(), "server": cfg.server_name, "detail": detail, "text": text, "ts": now_unix()
        })
        .to_string();
        tokio::spawn(async move {
            if let Err(e) = send_webhook(&url, &body).await {
                log::warn!("notify webhook failed: {e}");
            }
        });
    }
}

/// Like [`fire`], but at most once per `cooldown` seconds for the given `key`.
pub async fn fire_throttled(key: &str, cooldown: i64, event: Event, detail: &str) {
    if throttle_ok(key, cooldown) {
        fire(event, detail).await;
    }
}

/// Send a Telegram test message, returning the result (status code or error) so
/// the panel's per-channel "Test" button can show exactly what happened.
pub async fn test_telegram(cfg: &NotifyConfig) -> serde_json::Value {
    if cfg.telegram_token.is_empty() || cfg.telegram_chat_id.is_empty() {
        return serde_json::json!({ "ok": false, "error": "set the bot token and chat id first" });
    }
    match send_telegram(
        &cfg.telegram_token,
        &cfg.telegram_chat_id,
        &format!(
            "{}\u{2705} qeli test notification",
            server_prefix(&cfg.server_name)
        ),
    )
    .await
    {
        Ok(code) => serde_json::json!({ "ok": code < 400, "status": code }),
        Err(e) => serde_json::json!({ "ok": false, "error": e }),
    }
}

/// Send a webhook test POST, returning the result (status code or error).
pub async fn test_webhook(cfg: &NotifyConfig) -> serde_json::Value {
    if cfg.webhook_url.is_empty() {
        return serde_json::json!({ "ok": false, "error": "set the webhook URL first" });
    }
    let body = serde_json::json!({
        "event": "test", "server": cfg.server_name,
        "text": format!("{}\u{2705} qeli test notification", server_prefix(&cfg.server_name)),
        "ts": now_unix()
    })
    .to_string();
    match send_webhook(&cfg.webhook_url, &body).await {
        Ok(code) => serde_json::json!({ "ok": code < 400, "status": code }),
        Err(e) => serde_json::json!({ "ok": false, "error": e }),
    }
}

async fn send_telegram(token: &str, chat_id: &str, text: &str) -> Result<u16, String> {
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let body = serde_json::json!({ "chat_id": chat_id, "text": text }).to_string();
    http_post(&url, "application/json", body.as_bytes()).await
}

async fn send_webhook(url: &str, json_body: &str) -> Result<u16, String> {
    http_post(url, "application/json", json_body.as_bytes()).await
}

// ── minimal one-shot HTTP/1.1 POST (TLS via rustls, or plain TCP) ──────────────
// Outbound notifications only — never on the hot path. No redirects, no keep-alive.

async fn http_post(url: &str, content_type: &str, body: &[u8]) -> Result<u16, String> {
    match tokio::time::timeout(SEND_TIMEOUT, http_post_inner(url, content_type, body)).await {
        Ok(r) => r,
        Err(_) => Err("timed out".into()),
    }
}

async fn http_post_inner(url: &str, content_type: &str, body: &[u8]) -> Result<u16, String> {
    let (https, host, port, path) = parse_url(url)?;
    // SSRF guard: resolve the host and dial a validated PUBLIC address. Checking
    // the RESOLVED ip (not just the hostname) also defeats DNS rebinding to an
    // internal target (cloud metadata 169.254.169.254, localhost, LAN).
    let addr = resolve_public(&host, port).await?;
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let req = build_request(&host, &path, content_type, body);
    if https {
        let connector = tls_connector()?;
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| format!("invalid TLS host '{host}'"))?;
        let mut tls = connector
            .connect(name, stream)
            .await
            .map_err(|e| format!("tls handshake: {e}"))?;
        tls.write_all(&req)
            .await
            .map_err(|e| format!("write: {e}"))?;
        read_status(&mut tls).await
    } else {
        let mut s = stream;
        s.write_all(&req).await.map_err(|e| format!("write: {e}"))?;
        read_status(&mut s).await
    }
}

/// SSRF guard: an address we must never dial for an outbound notification —
/// loopback, private/LAN, link-local (incl. 169.254.169.254 cloud metadata),
/// CGNAT, multicast, unspecified/broadcast. Applied to the RESOLVED ip.
fn ip_is_forbidden(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0 // 0.0.0.0/8
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            if let Some(m) = v6.to_ipv4_mapped() {
                return ip_is_forbidden(&IpAddr::V4(m));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Resolve `host:port` and return the first PUBLIC socket address. Errors if the
/// host does not resolve or resolves only to forbidden (SSRF) addresses. The
/// error text is deliberately generic so it can't be used to probe which
/// internal host/port is reachable.
async fn resolve_public(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "cannot resolve host".to_string())?;
    let mut resolved = false;
    for a in addrs {
        resolved = true;
        if !ip_is_forbidden(&a.ip()) {
            return Ok(a);
        }
    }
    if resolved {
        Err("refused: destination resolves to a private/loopback/link-local address".into())
    } else {
        Err("host did not resolve".into())
    }
}

pub(crate) fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

fn build_request(host: &str, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: qeli\r\nAccept: */*\r\n\
         Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    req
}

/// Read just enough of the response to parse the status line.
async fn read_status<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Result<u16, String> {
    let mut out: Vec<u8> = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    for _ in 0..8 {
        let n = s.read(&mut tmp).await.map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
        if out.windows(2).any(|w| w == b"\r\n") || out.len() > 4096 {
            break;
        }
    }
    let line = String::from_utf8_lossy(&out);
    let first = line.lines().next().unwrap_or("");
    first
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| {
            format!(
                "bad response: {}",
                first.chars().take(80).collect::<String>()
            )
        })
}

/// Split `scheme://host[:port][/path]` → (https?, host, port, path). IPv6 literals
/// (bracketed) are not supported — notification endpoints are hostnames.
pub(crate) fn parse_url(url: &str) -> Result<(bool, String, u16, String), String> {
    // Reject control characters (incl. CR/LF/DEL) to prevent header injection
    // when the host/path are spliced into the raw HTTP request in build_request.
    if url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("URL contains control characters".into());
    }
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("URL must start with http:// or https://".into());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err("missing host".into());
    }
    let (host, port) = match authority.rfind(':') {
        Some(i)
            if !authority[i + 1..].is_empty()
                && authority[i + 1..].bytes().all(|b| b.is_ascii_digit()) =>
        {
            (
                authority[..i].to_string(),
                authority[i + 1..]
                    .parse::<u16>()
                    .map_err(|_| "invalid port".to_string())?,
            )
        }
        _ => (authority.to_string(), if https { 443 } else { 80 }),
    };
    let path = if path.is_empty() {
        "/".into()
    } else {
        path.into()
    };
    Ok((https, host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_variants() {
        assert_eq!(
            parse_url("https://api.telegram.org/bot123/sendMessage").unwrap(),
            (
                true,
                "api.telegram.org".into(),
                443,
                "/bot123/sendMessage".into()
            )
        );
        assert_eq!(
            parse_url("http://hook.local:9000/x").unwrap(),
            (false, "hook.local".into(), 9000, "/x".into())
        );
        assert_eq!(
            parse_url("https://example.com").unwrap(),
            (true, "example.com".into(), 443, "/".into())
        );
        assert!(parse_url("ftp://nope").is_err());
    }

    #[test]
    fn parse_url_rejects_control_chars() {
        assert!(parse_url("https://host/a\r\nX-Injected: 1").is_err());
        assert!(parse_url("https://ho\nst/x").is_err());
        assert!(parse_url("https://host/\x7f").is_err());
        // A clean URL with the same shape still parses.
        assert!(parse_url("https://host/a").is_ok());
    }

    #[test]
    fn default_config_is_off_events_on() {
        let c = NotifyConfig::default();
        assert!(!c.telegram_enabled && !c.webhook_enabled);
        // Per-channel events default to all-on.
        assert!(Event::ServerStart.enabled_in(&c.telegram_events));
        assert!(Event::Restore.enabled_in(&c.webhook_events));
    }

    #[test]
    fn ssrf_guard_blocks_internal_allows_public() {
        use std::net::IpAddr;
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1", // IPv4-mapped loopback
        ] {
            assert!(
                ip_is_forbidden(&s.parse::<IpAddr>().unwrap()),
                "{s} must be blocked"
            );
        }
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "149.154.167.220", // telegram
            "2001:4860:4860::8888",
        ] {
            assert!(
                !ip_is_forbidden(&s.parse::<IpAddr>().unwrap()),
                "{s} must be allowed"
            );
        }
    }
}
