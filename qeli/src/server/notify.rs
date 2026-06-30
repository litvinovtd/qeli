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
    pub on_restore: bool,
}

impl Default for ChannelEvents {
    fn default() -> Self {
        Self {
            on_server_start: true,
            on_quota_breach: true,
            on_login_lockout: true,
            on_restore: true,
        }
    }
}

/// Telegram and the generic webhook are fully independent channels — each has its
/// own enable switch, credentials, and event selection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyConfig {
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
    Restore,
}

impl Event {
    fn id(self) -> &'static str {
        match self {
            Event::ServerStart => "server_start",
            Event::QuotaBreach => "quota_breach",
            Event::LoginLockout => "login_lockout",
            Event::Restore => "restore",
        }
    }
    fn title(self) -> &'static str {
        match self {
            Event::ServerStart => "\u{1F7E2} qeli server started",
            Event::QuotaBreach => "\u{26D4} Quota breach",
            Event::LoginLockout => "\u{1F512} Panel login lockout",
            Event::Restore => "\u{267B} Config restored from backup",
        }
    }
    fn enabled_in(self, c: &ChannelEvents) -> bool {
        match self {
            Event::ServerStart => c.on_server_start,
            Event::QuotaBreach => c.on_quota_breach,
            Event::LoginLockout => c.on_login_lockout,
            Event::Restore => c.on_restore,
        }
    }
}

/// Read the sidecar (defaults if absent / unparsable).
pub fn load() -> NotifyConfig {
    std::fs::read_to_string(NOTIFY_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
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

/// Fire an event to every configured channel (fire-and-forget). No-op if notify
/// is disabled or this event's toggle is off.
pub async fn fire(event: Event, detail: &str) {
    let cfg = load();
    let text = format!("{}\n{}", event.title(), detail);
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
            "event": event.id(), "detail": detail, "text": text, "ts": now_unix()
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
        "\u{2705} qeli test notification",
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
        "event": "test", "text": "\u{2705} qeli test notification", "ts": now_unix()
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
    let stream = tokio::net::TcpStream::connect((host.as_str(), port))
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

fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
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
fn parse_url(url: &str) -> Result<(bool, String, u16, String), String> {
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
    fn default_config_is_off_events_on() {
        let c = NotifyConfig::default();
        assert!(!c.telegram_enabled && !c.webhook_enabled);
        // Per-channel events default to all-on.
        assert!(Event::ServerStart.enabled_in(&c.telegram_events));
        assert!(Event::Restore.enabled_in(&c.webhook_events));
    }
}
