use super::paths::{
    validate_in_whitelist, validate_path_field, ALLOWED_CONFIG_DIRS, ALLOWED_LOG_DIRS,
};
use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn get_config(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    // Return the live on-disk config so the panel reflects Quick-Start / Apply
    // changes (the supervisor's in-memory `config` is only its startup snapshot).
    if let Some(path) = state.config_path.lock().await.clone() {
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = crate::config::parse_server_config(&s) {
                return Ok(Json(json!({ "ok": true, "config": cfg })));
            }
        }
    }
    Ok(Json(json!({ "ok": true, "config": &state.config })))
}

/// Canonical defaults for the UI: a fully-defaulted profile template (every
/// serde `default_*` applied). The panel builds new
/// profiles / quick-start presets from this instead of hard-coding the schema in
/// JS — single source of truth, so the form never drifts from the Rust structs.
pub async fn get_config_defaults(_guard: auth::AuthGuard) -> Result<Json<Value>, AuthError> {
    let profile = crate::config::server::ProfileConfig::baseline();
    Ok(Json(json!({
        "ok": true,
        "profile": profile,
    })))
}

pub async fn put_config(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let new_config_value = match body.get("config") {
        Some(v) => v.clone(),
        None => return Ok(Json(super::err_json("config field required"))),
    };

    // Deserialize-validate the structure first.
    let mut parsed: crate::config::server::ServerConfig =
        match serde_json::from_value(new_config_value.clone()) {
            Ok(c) => c,
            Err(e) => return Ok(Json(super::err_json(format!("invalid config: {}", e)))),
        };

    // Reject configs whose logging.file would let GET /api/logs read arbitrary
    // files (e.g. /etc/shadow). Empty / None means "no file logging".
    if let Some(ref log_file) = parsed.logging.file {
        if let Err(e) = validate_path_field(log_file, ALLOWED_LOG_DIRS) {
            return Ok(Json(json!({
                "ok": false,
                "error": format!("logging.file: {}", e),
            })));
        }
    }

    // Reject users_file pointed outside config whitelist.
    if let Err(e) = validate_path_field(&parsed.auth.users_file, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!("auth.users_file: {}", e),
        })));
    }

    // Reject profile identity_key / web TLS cert+key paths outside the config whitelist —
    // otherwise `/api/identity/*/rotate` (or `/api/share`, which generates a missing key)
    // would create/overwrite an arbitrary file (e.g. /etc/cron.d/x) with key bytes.
    for p in &parsed.profiles {
        if let Some(ref id_key) = p.identity_key {
            if let Err(e) = validate_path_field(id_key, ALLOWED_CONFIG_DIRS) {
                return Ok(Json(json!({
                    "ok": false,
                    "error": format!("profile '{}' identity_key: {}", p.name, e),
                })));
            }
        }
    }
    if let Err(e) = validate_path_field(&parsed.web.tls_cert, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(
            json!({ "ok": false, "error": format!("web.tls_cert: {}", e) }),
        ));
    }
    if let Err(e) = validate_path_field(&parsed.web.tls_key, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(
            json!({ "ok": false, "error": format!("web.tls_key: {}", e) }),
        ));
    }

    // Resolve and validate the write target. config_path is set at startup and
    // never mutated, but we re-check on every write as defense in depth.
    let config_path = state.config_path.lock().await;
    let target = match config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return Ok(Json(json!({
                "ok": false,
                "error": "config_path not set — running from in-memory config",
            })));
        }
    };
    drop(config_path);

    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Refused config write to '{}': {}", target, e);
            return Ok(Json(json!({
                "ok": false,
                "error": format!("config path rejected: {}", e),
            })));
        }
    };

    // SECURITY: post_up/post_down run arbitrary commands as root. They are
    // FILE-ONLY — the panel/API must never set or change them, or a panel
    // compromise becomes RCE. Restore each profile's hooks from the current
    // on-disk config (discarding whatever the request sent); if the file can't be
    // read, force-clear them so the panel can never introduce a hook.
    match std::fs::read_to_string(&canon)
        .ok()
        .and_then(|s| crate::config::parse_server_config(&s).ok())
    {
        Some(cur) => {
            for p in &mut parsed.profiles {
                let (up, down) = cur
                    .profiles
                    .iter()
                    .find(|c| c.name == p.name)
                    .map(|c| (c.routing.post_up.clone(), c.routing.post_down.clone()))
                    .unwrap_or_default();
                p.routing.post_up = up;
                p.routing.post_down = down;
            }
            // Inline [user:*] password secrets are #[serde(skip_serializing)], so GET
            // stripped them and the structured editor holds no field for them. Restore
            // each inline user's hash/enc from disk (matched by username) so a structured
            // save can't silently wipe them and lock the user out.
            for u in &mut parsed.auth.users {
                if u.password_hash.is_empty() {
                    if let Some(cur_u) = cur.auth.users.iter().find(|c| c.username == u.username) {
                        u.password_hash = cur_u.password_hash.clone();
                        u.password_enc = cur_u.password_enc.clone();
                    }
                }
            }
            // The web ADMIN password_hash is #[serde(skip_serializing)] too (stripped
            // from GET so the browser never sees it), so a structured save carries an
            // empty hash. Restore it from disk — otherwise every config save wiped the
            // admin password, and on the next restart the panel refused to start
            // (non-loopback bind + empty password = fail-closed) and locked the operator
            // out. Only the explicit "set password" flow (hashAdminPw) sends a new hash.
            if parsed.web.password_hash.is_empty() {
                parsed.web.password_hash = cur.web.password_hash.clone();
            }
        }
        None => {
            // Can't read the current config to preserve secrets: if inline users exist,
            // refuse rather than overwrite them with empty hashes and lock everyone out.
            if !parsed.auth.users.is_empty() {
                return Ok(Json(super::err_json(
                    "cannot save: current config is unreadable, so inline [user:*] passwords \
                     can't be preserved — refusing to overwrite and lock users out",
                )));
            }
            for p in &mut parsed.profiles {
                p.routing.post_up.clear();
                p.routing.post_down.clear();
            }
        }
    }

    // Write flat-INI (the canonical on-disk format) so the file stays
    // consistent with hand-edited configs. Note: structured editing through the
    // UI cannot preserve hand-written comments — for comment-heavy configs, edit
    // the file directly. We serialize the validated struct so the output is a
    // faithful, lossless round-trip of the config.
    // Did the PANEL's own socket change (web.bind/port/tls/enabled)? Those are bound by the
    // supervisor at startup and NOT reapplied by the worker restart — they need a FULL restart.
    // Compare against config.web, the boot-time snapshot = what the panel is bound to now.
    let cur = &state.config.web;
    let w = &parsed.web;
    let needs_full_restart = w.bind != cur.bind
        || w.port != cur.port
        || w.enabled != cur.enabled
        || w.tls != cur.tls
        || w.tls_cert != cur.tls_cert
        || w.tls_key != cur.tls_key;

    let config_str = parsed.to_ini_string();
    // Fail-closed defense-in-depth: never write a config we can't read back. The
    // value-level control-char backstop (config/format.rs) already neutralizes INI
    // injection through string fields; this catches any residual serialization
    // corruption before it reaches disk (mirrors set_blocked_settings).
    if let Err(e) = crate::config::parse_server_config(&config_str) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!("refusing to write a config that fails re-parse: {}", e),
        })));
    }
    if let Err(e) = crate::util::write_atomic(&canon, config_str.as_bytes()) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!("write error: {}", e),
        })));
    }

    // Apply the panel's own settings (admin password/username, IP allowlist, CSRF
    // origins, public host) LIVE — the supervisor serves the panel from this copy,
    // so they take effect without a restart. Profile/bind/tun/TLS still need one.
    state.reload_web_settings().await;

    let message = if needs_full_restart {
        "config saved. This changes the PANEL socket (web.bind/port/tls/enabled) — apply with a \
         FULL restart (the Full restart button, or `systemctl restart qeli`). Other changes take \
         the worker restart."
    } else {
        "config saved — web/panel settings applied live; restart to apply profile/bind/tun changes"
    };
    Ok(Json(json!({
        "ok": true,
        "needs_full_restart": needs_full_restart,
        "message": message,
        "path": canon.display().to_string(),
    })))
}

/// Return the on-disk config file **verbatim** (raw INI text, comments intact).
/// The structured `GET /api/config` reflects the parsed struct; this is the
/// actual file the server loads, for the raw-text editor.
pub async fn get_config_raw(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let config_path = state.config_path.lock().await;
    let target = match config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return Ok(Json(json!({
                "ok": false,
                "error": "config_path not set — running from in-memory config",
            })))
        }
    };
    drop(config_path);

    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(p) => p,
        Err(e) => {
            return Ok(Json(super::err_json(format!(
                "config path rejected: {}",
                e
            ))))
        }
    };
    match std::fs::read_to_string(&canon) {
        Ok(raw) => Ok(Json(
            json!({"ok": true, "raw": raw, "path": canon.display().to_string()}),
        )),
        Err(e) => Ok(Json(super::err_json(format!("read error: {}", e)))),
    }
}

/// Write raw INI text **verbatim** (preserving hand-written comments/formatting),
/// after validating it parses into a `ServerConfig`. Same path-field guards as the
/// structured PUT, so a hostile config can't redirect log/users reads outside the
/// whitelist.
pub async fn put_config_raw(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let raw = match body.get("raw").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Ok(Json(super::err_json("raw field required"))),
    };

    // Validate by parsing — catches INI syntax errors and invalid/missing values.
    let parsed = match crate::config::parse_server_config(&raw) {
        Ok(c) => c,
        Err(e) => return Ok(Json(super::err_json(format!("invalid config: {}", e)))),
    };

    if let Some(ref log_file) = parsed.logging.file {
        if let Err(e) = validate_path_field(log_file, ALLOWED_LOG_DIRS) {
            return Ok(Json(super::err_json(format!("logging.file: {}", e))));
        }
    }
    if let Err(e) = validate_path_field(&parsed.auth.users_file, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(super::err_json(format!("auth.users_file: {}", e))));
    }
    for p in &parsed.profiles {
        if let Some(ref id_key) = p.identity_key {
            if let Err(e) = validate_path_field(id_key, ALLOWED_CONFIG_DIRS) {
                return Ok(Json(super::err_json(format!(
                    "profile '{}' identity_key: {}",
                    p.name, e
                ))));
            }
        }
    }
    if let Err(e) = validate_path_field(&parsed.web.tls_cert, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(super::err_json(format!("web.tls_cert: {}", e))));
    }
    if let Err(e) = validate_path_field(&parsed.web.tls_key, ALLOWED_CONFIG_DIRS) {
        return Ok(Json(super::err_json(format!("web.tls_key: {}", e))));
    }

    let config_path = state.config_path.lock().await;
    let target = match config_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            return Ok(Json(json!({
                "ok": false,
                "error": "config_path not set — running from in-memory config",
            })))
        }
    };
    drop(config_path);

    let canon = match validate_in_whitelist(&target, ALLOWED_CONFIG_DIRS) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Refused raw config write to '{}': {}", target, e);
            return Ok(Json(super::err_json(format!(
                "config path rejected: {}",
                e
            ))));
        }
    };

    // SECURITY: post_up/post_down are file-only (they execute commands as root).
    // The raw editor must not introduce or change them — reject if the submitted
    // config's hooks differ from what's currently on disk.
    let on_disk = std::fs::read_to_string(&canon)
        .ok()
        .and_then(|s| crate::config::parse_server_config(&s).ok());
    for p in &parsed.profiles {
        let (cur_up, cur_down) = on_disk
            .as_ref()
            .and_then(|c| c.profiles.iter().find(|x| x.name == p.name))
            .map(|x| (x.routing.post_up.as_str(), x.routing.post_down.as_str()))
            .unwrap_or(("", ""));
        if p.routing.post_up != cur_up || p.routing.post_down != cur_down {
            return Ok(Json(super::err_json(format!(
                "profile '{}': post_up/post_down can only be set by editing the config file directly, not via the panel",
                p.name
            ))));
        }
    }

    if let Err(e) = crate::util::write_atomic(&canon, raw.as_bytes()) {
        return Ok(Json(super::err_json(format!("write error: {}", e))));
    }

    // Apply the panel's own settings live (see put_config); restart still needed
    // for profile/bind/tun/TLS.
    state.reload_web_settings().await;

    Ok(Json(json!({
        "ok": true,
        "message": "raw config saved (comments preserved) — web/panel settings applied live; restart to apply profile/bind/tun changes",
        "path": canon.display().to_string(),
    })))
}
