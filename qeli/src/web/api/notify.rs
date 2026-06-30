use crate::server::notify::{self, ChannelEvents, NotifyConfig};
use crate::server::web::auth::{self, AuthError};
use axum::Json;
use serde_json::{json, Value};

/// Mask a secret for display: keep the last 4 chars, hide the rest.
fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n == 0 {
        String::new()
    } else if n <= 4 {
        "\u{2022}".repeat(n)
    } else {
        let tail: String = s.chars().skip(n - 4).collect();
        format!("\u{2026}{tail}")
    }
}

/// Current notify config. The Telegram token is never sent back in clear — only a
/// "set" flag and a masked hint — so the panel shows it's configured without
/// leaking it to the browser. Telegram and the webhook are independent.
pub async fn get_notify(_guard: auth::AuthGuard) -> Result<Json<Value>, AuthError> {
    let c = notify::load();
    Ok(Json(json!({
        "ok": true,
        "config": {
            "telegram_enabled": c.telegram_enabled,
            "telegram_token_set": !c.telegram_token.is_empty(),
            "telegram_token_hint": mask(&c.telegram_token),
            "telegram_chat_id": c.telegram_chat_id,
            "telegram_events": c.telegram_events,
            "webhook_enabled": c.webhook_enabled,
            "webhook_url": c.webhook_url,
            "webhook_events": c.webhook_events,
        }
    })))
}

fn merge_events(ev: &mut ChannelEvents, v: Option<&Value>) {
    let Some(v) = v else {
        return;
    };
    if let Some(b) = v.get("on_server_start").and_then(Value::as_bool) {
        ev.on_server_start = b;
    }
    if let Some(b) = v.get("on_quota_breach").and_then(Value::as_bool) {
        ev.on_quota_breach = b;
    }
    if let Some(b) = v.get("on_login_lockout").and_then(Value::as_bool) {
        ev.on_login_lockout = b;
    }
    if let Some(b) = v.get("on_restore").and_then(Value::as_bool) {
        ev.on_restore = b;
    }
}

/// Build an updated config from the request body, layered over the saved one. An
/// empty `telegram_token` means "keep the existing one" (write-only field), so
/// saving other settings never wipes a configured token.
fn merge(body: &Value) -> NotifyConfig {
    let mut c = notify::load();
    if let Some(v) = body.get("telegram_enabled").and_then(Value::as_bool) {
        c.telegram_enabled = v;
    }
    if let Some(t) = body.get("telegram_token").and_then(Value::as_str) {
        if !t.trim().is_empty() {
            c.telegram_token = t.trim().to_string();
        }
    }
    if let Some(v) = body.get("telegram_chat_id").and_then(Value::as_str) {
        c.telegram_chat_id = v.trim().to_string();
    }
    merge_events(&mut c.telegram_events, body.get("telegram_events"));
    if let Some(v) = body.get("webhook_enabled").and_then(Value::as_bool) {
        c.webhook_enabled = v;
    }
    if let Some(v) = body.get("webhook_url").and_then(Value::as_str) {
        c.webhook_url = v.trim().to_string();
    }
    merge_events(&mut c.webhook_events, body.get("webhook_events"));
    c
}

/// Persist the notify config.
pub async fn put_notify(
    _guard: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    let c = merge(&body);
    Ok(Json(match notify::save(&c) {
        Ok(_) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }))
}

/// Send a test notification to ONE channel (`channel` = "telegram" | "webhook"),
/// merging the request body over the saved config so edits can be tested before
/// saving. Returns the channel result (status code or error).
pub async fn test_notify(
    _guard: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    let c = merge(&body);
    let result = match body.get("channel").and_then(Value::as_str).unwrap_or("") {
        "telegram" => notify::test_telegram(&c).await,
        "webhook" => notify::test_webhook(&c).await,
        _ => json!({ "ok": false, "error": "unknown channel" }),
    };
    Ok(Json(json!({ "ok": true, "result": result })))
}
