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

    // SECURITY: profile/user/group names are serialized as INI section instances
    // (`[profile:<name>]`) and metadata keys as `metadata.<key>` — unlike values,
    // both are emitted BARE. A control character in one splits the line and forges
    // extra config lines on re-parse, which is enough to smuggle a
    // `routing.post_up` hook past the file-only hook restore below and get it run
    // through `/bin/sh -c` on the next start. Reject at the boundary so the
    // operator sees a clear error; `config/format.rs` also strips control chars at
    // serialize time as a fail-closed backstop.
    let name_err = |what: &str, name: &str| {
        format!(
            "{what} {name:?} is invalid — it must be non-empty, at most 128 bytes, and carry no \
             control characters or surrounding whitespace (names become INI section headers, so a \
             newline there could forge config lines)"
        )
    };
    let bad_name = parsed
        .profiles
        .iter()
        .find(|p| !crate::util::is_valid_ident(&p.name))
        .map(|p| name_err("profile name", &p.name))
        .or_else(|| {
            parsed
                .auth
                .groups
                .keys()
                .find(|g| !crate::util::is_valid_ident(g))
                .map(|g| name_err("group name", g))
        })
        .or_else(|| {
            parsed
                .auth
                .users
                .iter()
                .find(|u| !crate::util::is_valid_ident(&u.username))
                .map(|u| name_err("username", &u.username))
        })
        .or_else(|| {
            parsed
                .auth
                .users
                .iter()
                .flat_map(|u| u.metadata.keys())
                .find(|k| !crate::util::is_valid_ident(k))
                .map(|k| name_err("metadata key", k))
        });
    if let Some(e) = bad_name {
        return Ok(Json(super::err_json(e)));
    }

    // A non-empty admin password_hash must be a REAL Argon2 PHC string. It is applied
    // verbatim, and the hash doubles as the session-signing salt — so a truncated
    // paste or a typed plaintext invalidated every session and could then never
    // verify, locking the operator out of the panel (recoverable only by editing the
    // config on the host). Empty is legal and means "keep the hash already on disk"
    // (see the restore below) — NOT "open access".
    if !parsed.web.password_hash.is_empty() {
        if let Err(e) = super::users::validate_argon2_hash(&parsed.web.password_hash) {
            return Ok(Json(super::err_json(format!(
                "web.password_hash: {e} — use the \"Set password\" button (it hashes for you); \
                 leaving the field empty keeps the current password"
            ))));
        }
    }

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
        // Reject advertised routes whose CIDR is missing/malformed, or whose
        // gateway is not a bare next hop. Without this the panel happily saves a
        // route with an EMPTY CIDR field (subnet typed into `gateway` instead):
        // it serializes to `route = " gateway=172.16.20.0/24 metric=100"`, parses
        // back with an empty cidr, and every client silently drops it — the admin
        // sees a saved route that never reaches anyone. Fail loudly at authoring time.
        for r in &p.routing.advertised_routes {
            if !crate::util::is_valid_cidr(&r.cidr) {
                return Ok(Json(json!({
                    "ok": false,
                    "error": format!(
                        "profile '{}': route CIDR is missing or invalid ({:?}). \
                         The network goes in the CIDR field, e.g. 172.16.20.0/24 — \
                         `gateway` takes a next-hop IP, not a subnet.",
                        p.name, r.cidr
                    ),
                })));
            }
            if let Some(ref gw) = r.gateway {
                if !crate::util::is_valid_gateway(gw) {
                    return Ok(Json(json!({
                        "ok": false,
                        "error": format!(
                            "profile '{}': route {} — gateway must be a bare next-hop IP \
                             (e.g. 10.0.0.1) or left empty to use the profile's tun address; got {:?}.",
                            p.name, r.cidr, gw
                        ),
                    })));
                }
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
        || w.tls_key != cur.tls_key
        // The router is NESTED under the boot-time base_path (web/mod.rs), and the
        // base-href rewrite middleware reads the same startup snapshot — so a change
        // here does NOT take effect on a worker restart, only on a full process
        // restart. Without this the panel said "applied live" while still serving on
        // the old prefix, sending the operator on a 404 hunt behind their proxy.
        || w.base_path != cur.base_path;

    let config_str = parsed.to_ini_string();
    // Fail-closed defense-in-depth: never write a config we can't read back. The
    // control-char backstops (config/format.rs) already neutralize INI injection
    // through values, names and keys; this catches any residual serialization
    // corruption before it reaches disk (mirrors set_blocked_settings).
    let reparsed = match crate::config::parse_server_config(&config_str) {
        Ok(c) => c,
        Err(e) => {
            return Ok(Json(json!({
                "ok": false,
                "error": format!("refusing to write a config that fails re-parse: {}", e),
            })));
        }
    };
    // SECURITY: the restore loop above is the ONLY thing permitted to set
    // post_up/post_down. Re-parsing successfully is not enough — a forged section
    // or hook line would also parse. Assert the text we are about to write reads
    // back with EXACTLY the hooks we intended and no extra profile: anything else
    // means a name/key smuggled a hook past the guard, and it would run via
    // `/bin/sh -c` on the next start.
    let intended: std::collections::HashMap<&str, (&str, &str)> = parsed
        .profiles
        .iter()
        .map(|p| {
            (
                p.name.as_str(),
                (p.routing.post_up.as_str(), p.routing.post_down.as_str()),
            )
        })
        .collect();
    for p in &reparsed.profiles {
        let ok = intended
            .get(p.name.as_str())
            .is_some_and(|(up, down)| *up == p.routing.post_up && *down == p.routing.post_down);
        if !ok {
            log::error!(
                "Refused config write: profile '{}' re-parsed with unexpected lifecycle hooks \
                 (possible INI injection through a name/key)",
                crate::util::log_sanitize(&p.name)
            );
            return Ok(Json(json!({
                "ok": false,
                "error": format!(
                    "refusing to write: profile {:?} reads back with lifecycle hooks the panel \
                     did not intend — post_up/post_down are file-only and cannot be set through \
                     the API",
                    p.name
                ),
            })));
        }
    }
    // Run the SAME profile validation the worker runs at startup, against the text we
    // are about to write. Without this the panel happily saved a config the worker
    // then refused to load (duplicate profile names, `plain` over UDP, obfs with no
    // key, REALITY with no short_id, zero perf params, out-of-range heartbeat) — the
    // operator saw "saved OK" and only found out when Apply/Restart left the data
    // plane down. Validating `reparsed` (not `parsed`) checks exactly what the worker
    // will see on disk.
    if let Err(e) = crate::server::validate_profiles(&reparsed) {
        return Ok(Json(json!({
            "ok": false,
            "error": format!(
                "refusing to write a config the server would reject at startup: {}", e
            ),
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
    // Same Argon2 check as the structured path — the raw editor is the likelier place
    // to hand-type a bad hash and lock yourself out of the panel.
    if !parsed.web.password_hash.is_empty() {
        if let Err(e) = super::users::validate_argon2_hash(&parsed.web.password_hash) {
            return Ok(Json(super::err_json(format!("web.password_hash: {e}"))));
        }
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

    // Same startup validation as the structured path: the raw editor is the EASIER
    // way to produce a config the worker refuses (deleting a whole `performance`
    // object yields derived-Default zeros, not the documented defaults), so it must
    // not be the unchecked one. `parsed` here is the submitted text already parsed.
    if let Err(e) = crate::server::validate_profiles(&parsed) {
        return Ok(Json(super::err_json(format!(
            "refusing to write a config the server would reject at startup: {}",
            e
        ))));
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
