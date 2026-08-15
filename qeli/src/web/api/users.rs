use crate::config::users::{GroupTemplate, UserEntry, UserRoute, UsersDb};
use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

/// Reject anything that isn't a parseable Argon2 PHC string. Without this,
/// callers can store plaintext in `password_hash` and the server happily
/// accepts it on next login (because PasswordHash::new would fail at verify
/// time and the user could never log in — but the record is still persisted).
pub(super) fn validate_argon2_hash(hash: &str) -> Result<(), String> {
    if !hash.starts_with("$argon2id$")
        && !hash.starts_with("$argon2i$")
        && !hash.starts_with("$argon2d$")
    {
        return Err("password_hash must be an Argon2 PHC string ($argon2id$…)".into());
    }
    argon2::PasswordHash::new(hash)
        .map(|_| ())
        .map_err(|e| format!("invalid Argon2 hash: {}", e))
}

/// Hash a plaintext password (Argon2id) and reversibly-encrypt it under the panel
/// key, so the config/QR can be re-issued later without the plaintext. Encryption
/// is best-effort: on key failure we still return the hash (enc = None) so user
/// creation isn't blocked — re-issue then needs a one-time reset.
pub(crate) fn hash_and_enc(pw: &str) -> Result<(String, Option<String>), String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    let hash = crate::crypto::password_hasher()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| format!("hashing failed: {}", e))?
        .to_string();
    let enc = match crate::crypto::secret::encrypt_password(pw) {
        Ok(e) => Some(e),
        Err(e) => {
            log::warn!("could not encrypt password for re-issue: {}", e);
            None
        }
    };
    Ok((hash, enc))
}

/// Generate a strong random alphanumeric password (unambiguous alphabet).
pub(crate) fn gen_password(len: usize) -> String {
    use rand::prelude::*;
    const CS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| CS[rng.random_range(0..CS.len())] as char)
        .collect()
}

/// Parse a JSON string array (e.g. `profiles`, `allowed_networks`) into a Vec,
/// dropping non-strings and blanks. Returns empty for a missing/!array field.
/// Validate `allowed_networks` entries: each must be an IPv4 CIDR (`10.0.0.0/8`) or a
/// bare IPv4 address (a /32 host route).
///
/// This matters more than it used to: the destination ACL is now ENFORCED in the data
/// plane. Runtime compilation fails closed for an entirely malformed configured list,
/// but that would unexpectedly lock the user out. Reject at authoring time so the
/// operator sees the mistake. Blank rows (the panel's empty repeater row) are ignored,
/// matching the compiler.
fn validate_allowed_networks(nets: &[String]) -> Result<(), String> {
    crate::config::users::validate_allowed_networks(nets, "allowed_networks")
}

/// Validate a `static_ip` value: must be a bare IPv4 address.
///
/// The runtime parses it with `.ok()` and falls back to a dynamic address on failure —
/// SILENTLY, with no log line — so a typo looked saved in the panel while the user
/// quietly got a different address and any firewall rule keyed to the intended one
/// stopped matching. (Pool-membership is still checked at connect time, where the
/// profile's pool is known; that path does warn.)
fn validate_static_ip(ip: &str) -> Result<(), String> {
    let s = ip.trim();
    if s.is_empty() {
        return Ok(()); // empty = "no static IP", handled by the callers
    }
    if s.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!(
            "static_ip {s:?} is not a valid IPv4 address (e.g. 10.10.10.50); leave empty for a \
             dynamic address"
        ));
    }
    Ok(())
}

/// The other user already holding `ip` as their static address, if any.
///
/// Two users cannot share one static address: `IpPool::allocate_fixed` hands it to
/// whoever connects last and evicts the previous holder, so a duplicate makes the pair
/// flap — each reconnect steals the address back from the other, forever. Nothing
/// downstream can resolve that, so reject it where it is authored.
fn static_ip_owner(
    users: &crate::config::users::UsersDb,
    ip: &str,
    except: &str,
) -> Option<String> {
    users
        .users
        .iter()
        .find(|u| u.username != except && u.static_ip.as_deref() == Some(ip))
        .map(|u| u.username.clone())
}

/// Narrow a JSON-supplied limit to `u32`, REJECTING an out-of-range value instead of
/// letting `as u32` wrap.
///
/// The panel sends JSON numbers (parsed as `u64`) while the stored fields are `u32`. A
/// bare `as u32` wraps silently: `4294967296` becomes `0` — and `0` means UNLIMITED for
/// both bandwidth (`RateBucket::consume` short-circuits on 0) and `max_sessions` (the cap
/// is only enforced `if max_sessions > 0`). So an out-of-range number quietly REMOVED the
/// limit instead of erroring, and the update path additionally shipped the untruncated
/// `u64` to the worker while writing the truncated value to disk.
/// Read an OPTIONAL numeric limit from a JSON body, distinguishing "absent" from
/// "present but invalid".
///
/// `Value::as_u64()` returns `None` for a negative (`-5`), fractional (`1.5`) or
/// string (`"abc"`) value exactly as it does for a missing key — so the old
/// `.as_u64().unwrap_or(0)` turned an operator typo into `0`, which means UNLIMITED
/// for bandwidth, sessions and data caps. That is a fail-OPEN default reported as
/// success. Returns `Ok(None)` only when the key is genuinely absent/null.
fn opt_u32_limit(body: &Value, key: &str) -> Result<Option<u32>, String> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_u64() {
            Some(n) => u32_limit(n, key).map(Some),
            None => Err(format!(
                "{key} must be a non-negative whole number (got {v}); 0 means unlimited"
            )),
        },
    }
}

fn u32_limit(n: u64, what: &str) -> Result<u32, String> {
    if n <= u32::MAX as u64 {
        Ok(n as u32)
    } else {
        Err(format!(
            "{what} must be between 0 and {} (got {}); 0 means unlimited",
            u32::MAX,
            n
        ))
    }
}

fn strings_from_json(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a JSON array of `{cidr, gateway?, metric?}` into per-user routes.
///
/// REJECTS (instead of silently skipping) an entry whose CIDR is missing or
/// malformed, or whose gateway is not a bare next-hop IP. Silently dropping such
/// an entry is how a route typed in the panel could vanish without a word and
/// never reach any client — the admin sees it "saved" and nothing happens.
fn routes_from_json(v: &Value) -> Result<Vec<UserRoute>, String> {
    let Some(arr) = v.as_array() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(arr.len());
    for r in arr {
        let cidr = r["cidr"].as_str().unwrap_or("").trim().to_string();
        if !crate::util::is_valid_cidr(&cidr) {
            return Err(format!(
                "route CIDR is missing or invalid ({:?}). The network goes in the CIDR field, \
                 e.g. 172.16.20.0/24 — `gateway` takes a next-hop IP, not a subnet.",
                cidr
            ));
        }
        let gateway = r["gateway"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(gw) = &gateway {
            if !crate::util::is_valid_gateway(gw) {
                return Err(format!(
                    "route {} — gateway must be a bare next-hop IP (e.g. 10.0.0.1) or empty; got {:?}.",
                    cidr, gw
                ));
            }
        }
        let metric = match r.get("metric") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let raw = value.as_u64().ok_or_else(|| {
                    format!(
                        "route {cidr} — metric must be an integer from 0 to {}",
                        u32::MAX
                    )
                })?;
                Some(
                    u32::try_from(raw)
                        .map_err(|_| format!("route {cidr} — metric {raw} exceeds {}", u32::MAX))?,
                )
            }
        };
        out.push(UserRoute {
            cidr,
            gateway,
            metric,
        });
    }
    Ok(out)
}

/// Ask the supervisor to SIGHUP the data-plane worker so it hot-reloads the
/// users file after a panel-side change (the panel owns its own users_db copy;
/// the worker is a separate process that re-reads the file on signal).
async fn reload_worker(state: &Arc<ServerState>) {
    if let Some(tx) = &state.worker_tx {
        let _ = tx.send(crate::server::WorkerCmd::ReloadUsers).await;
    }
}

/// Send a command to the worker's control socket (for live effects on active
/// sessions: kick / set-bandwidth). Best-effort — ignored if the worker is down.
async fn worker_control(cmd: Value) {
    let _ = crate::server::control::send_command(
        &crate::server::control::control_socket_path(),
        &cmd.to_string(),
    )
    .await;
}

pub async fn list_users(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let users = state.users_db.read().await;
    Ok(Json(
        json!({ "ok": true, "users": users.users, "groups": users.groups }),
    ))
}

pub async fn get_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let users = state.users_db.read().await;
    match users.users.iter().find(|u| u.username == username) {
        Some(user) => Ok(Json(json!({ "ok": true, "user": user }))),
        None => Ok(Json(super::err_json(format!(
            "user '{}' not found",
            username
        )))),
    }
}

pub async fn create_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let username = body["username"].as_str().unwrap_or("").to_string();
    if username.is_empty() {
        return Ok(Json(super::err_json("username required")));
    }
    // Restrict to a safe charset (alnum + . _ -) and a sane length so a username can't
    // break the INI users file / control-channel JSON / downstream find() matching.
    if username.len() > 64
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Ok(Json(super::err_json(
            "username must be 1-64 chars of letters, digits, '.', '_', '-'",
        )));
    }
    // Accept a plaintext `password` (server hashes + reversibly-encrypts it so the
    // config can be re-issued later) or a pre-computed `password_hash` (legacy, not
    // re-issuable). Argon2 runs before we take the users lock.
    let (password_hash, password_enc) = {
        let plaintext = body["password"].as_str().unwrap_or("");
        if !plaintext.is_empty() {
            match hash_and_enc(plaintext) {
                Ok(v) => v,
                Err(e) => return Ok(Json(super::err_json(e))),
            }
        } else {
            let h = body["password_hash"].as_str().unwrap_or("").to_string();
            if h.is_empty() {
                return Ok(Json(super::err_json(
                    "password (or password_hash) required",
                )));
            }
            if let Err(e) = validate_argon2_hash(&h) {
                return Ok(Json(super::err_json(e)));
            }
            (h, None)
        }
    };

    let mut users = state.users_db.write().await;
    if users.users.iter().any(|u| u.username == username) {
        return Ok(Json(super::err_json(format!(
            "user '{}' already exists",
            username
        ))));
    }
    if let Some(ip) = body["static_ip"].as_str().filter(|s| !s.is_empty()) {
        if let Err(e) = validate_static_ip(ip) {
            return Ok(Json(super::err_json(e)));
        }
        if let Some(other) = static_ip_owner(&users, ip, &username) {
            return Ok(Json(super::err_json(format!(
                "static_ip {} is already assigned to user '{}' — two users cannot share one \
                 address (they would evict each other on every reconnect)",
                ip, other
            ))));
        }
    }

    let routes = match routes_from_json(&body["routes"]) {
        Ok(r) => r,
        Err(e) => return Ok(Json(super::err_json(e))),
    };
    // Range-check the numeric limits BEFORE building the user: a wrapped `as u32` would
    // silently mean "unlimited" (see `u32_limit`).
    let bw = &body["bandwidth"];
    let limit_mbps = match opt_u32_limit(bw, "limit_mbps") {
        Ok(v) => v.unwrap_or(0),
        Err(e) => return Ok(Json(super::err_json(e))),
    };
    let burst_mbps = match opt_u32_limit(bw, "burst_mbps") {
        Ok(v) => v.unwrap_or(0),
        Err(e) => return Ok(Json(super::err_json(e))),
    };
    let max_sessions = match opt_u32_limit(&body, "max_sessions") {
        Ok(v) => v.unwrap_or(0),
        Err(e) => return Ok(Json(super::err_json(e))),
    };
    let allowed_networks_new = strings_from_json(&body["allowed_networks"]);
    if let Err(e) = validate_allowed_networks(&allowed_networks_new) {
        return Ok(Json(super::err_json(e)));
    }
    let new_user = UserEntry {
        username: username.clone(),
        password_hash,
        password_enc,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        static_ip: body["static_ip"].as_str().map(|s| s.to_string()),
        bandwidth: crate::config::users::BandwidthLimit {
            limit_mbps,
            burst_mbps,
        },
        group: body["group"].as_str().map(|s| s.to_string()),
        allowed_networks: allowed_networks_new,
        max_sessions,
        profiles: strings_from_json(&body["profiles"]),
        routes,
        client_subnets: strings_from_json(&body["client_subnets"]),
        ..Default::default()
    };
    // Append on a freshly re-read copy: this process's view may lag the file (the worker
    // rewrites it on any control-socket change), and writing it back verbatim reverted
    // whatever it had missed. Re-check the name there too — it may have appeared since.
    let users_file = state.config.auth.users_file.clone();
    let taken = match UsersDb::update_locked(&users_file, |db| {
        if db.users.iter().any(|u| u.username == new_user.username) {
            return true;
        }
        db.users.push(new_user);
        false
    }) {
        Ok((fresh, taken)) => {
            *users = fresh;
            taken
        }
        Err(e) => {
            log::error!("Failed to save users file after create: {}", e);
            return Ok(Json(super::err_json(format!(
                "could not write the users file '{}': {} — change NOT applied",
                users_file, e
            ))));
        }
    };
    if taken {
        return Ok(Json(super::err_json(format!(
            "user '{}' already exists (created concurrently)",
            username
        ))));
    }
    drop(users);
    reload_worker(&state).await;
    Ok(Json(
        json!({"ok": true, "message": format!("user '{}' created", username)}),
    ))
}

/// Copy onto `slot` only the fields that differ between `before` (the entry as this
/// process last saw it) and `after` (the same entry with this request's edits applied).
///
/// A wholesale `*slot = after` reverts anything ANOTHER writer changed in the meantime —
/// the worker applies `set-bandwidth`, `set-limit` and expiry over the control socket, and
/// the panel's snapshot can easily predate that. Comparing field by field means an edit to
/// the password touches the password and nothing else, so two writers only collide when
/// they genuinely edit the SAME field.
///
/// `username` is deliberately not merged: it is the key we matched on.
fn merge_changed_fields(
    before: &crate::config::users::UserEntry,
    after: &crate::config::users::UserEntry,
    slot: &mut crate::config::users::UserEntry,
) {
    if after.password_hash != before.password_hash {
        slot.password_hash = after.password_hash.clone();
    }
    if after.password_enc != before.password_enc {
        slot.password_enc = after.password_enc.clone();
    }
    if after.static_ip != before.static_ip {
        slot.static_ip = after.static_ip.clone();
    }
    if after.enabled != before.enabled {
        slot.enabled = after.enabled;
    }
    if after.allowed_networks != before.allowed_networks {
        slot.allowed_networks = after.allowed_networks.clone();
    }
    if after.group != before.group {
        slot.group = after.group.clone();
    }
    if after.max_sessions != before.max_sessions {
        slot.max_sessions = after.max_sessions;
    }
    if after.data_limit_gb != before.data_limit_gb {
        slot.data_limit_gb = after.data_limit_gb;
    }
    if after.expire_at != before.expire_at {
        slot.expire_at = after.expire_at;
    }
    if after.profiles != before.profiles {
        slot.profiles = after.profiles.clone();
    }
    if after.bandwidth != before.bandwidth {
        slot.bandwidth = after.bandwidth.clone();
    }
    if after.metadata != before.metadata {
        slot.metadata = after.metadata.clone();
    }
    if after.routes != before.routes {
        slot.routes = after.routes.clone();
    }
    if after.client_subnets != before.client_subnets {
        slot.client_subnets = after.client_subnets.clone();
    }
}

pub async fn update_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let mut users = state.users_db.write().await;
    // Check the static-IP collision BEFORE taking the mutable borrow below (and before
    // any mutation): two users sharing one static address evict each other forever.
    if let Some(ip) = body["static_ip"].as_str().filter(|s| !s.is_empty()) {
        if let Err(e) = validate_static_ip(ip) {
            return Ok(Json(super::err_json(e)));
        }
        if let Some(other) = static_ip_owner(&users, ip, &username) {
            return Ok(Json(super::err_json(format!(
                "static_ip {} is already assigned to user '{}' — two users cannot share one \
                 address (they would evict each other on every reconnect)",
                ip, other
            ))));
        }
    }
    // Build the complete candidate on a clone. Validation errors must not mutate
    // the panel's in-memory database when nothing was written to disk.
    let existing = users
        .users
        .iter()
        .find(|user| user.username == username)
        .cloned();

    match existing {
        Some(before) => {
            let mut edited = before.clone();
            // New password: plaintext (re-hashed + re-encrypted for re-issue) is
            // preferred; a bare password_hash is still accepted (legacy) but clears
            // the re-issue copy since we can't encrypt what we never see.
            // Empty `password` falls through to `password_hash` (was: an empty-but-present
            // password entered this branch and no-op'd, ignoring a supplied hash).
            if let Some(pw) = body["password"].as_str().filter(|p| !p.is_empty()) {
                match hash_and_enc(pw) {
                    Ok((h, e)) => {
                        edited.password_hash = h;
                        edited.password_enc = e;
                    }
                    Err(err) => return Ok(Json(super::err_json(err))),
                }
            } else if let Some(v) = body["password_hash"].as_str().filter(|v| !v.is_empty()) {
                if let Err(e) = validate_argon2_hash(v) {
                    return Ok(Json(super::err_json(e)));
                }
                edited.password_hash = v.to_string();
                edited.password_enc = None;
            }
            if let Some(v) = body["enabled"].as_bool() {
                edited.enabled = v;
            }
            if let Some(static_ip) = body["static_ip"].as_str() {
                edited.static_ip = if static_ip.is_empty() {
                    None
                } else {
                    Some(static_ip.to_string())
                };
            }
            if let Some(group) = body["group"].as_str() {
                edited.group = if group.is_empty() {
                    None
                } else {
                    Some(group.to_string())
                };
            }
            // An INVALID value is now an error, not a silent no-op: `as_u64()` returns
            // None for "-5"/"1.5"/"abc" exactly as for a missing key, so the old
            // `if let Some(..)` reported success while leaving the limit untouched.
            let mut new_bw_limit: Option<u64> = None;
            if let Some(bw) = body.get("bandwidth") {
                match opt_u32_limit(bw, "limit_mbps") {
                    Ok(Some(limit)) => {
                        edited.bandwidth.limit_mbps = limit;
                        // Send the SAME range-checked value the file gets — the old code
                        // shipped the raw u64 here while writing a wrapped u32 to disk.
                        new_bw_limit = Some(limit as u64); // applied live below
                    }
                    Ok(None) => {}
                    Err(e) => return Ok(Json(super::err_json(e))),
                }
                match opt_u32_limit(bw, "burst_mbps") {
                    Ok(Some(v)) => edited.bandwidth.burst_mbps = v,
                    Ok(None) => {}
                    Err(e) => return Ok(Json(super::err_json(e))),
                }
            }
            match opt_u32_limit(&body, "max_sessions") {
                Ok(Some(v)) => edited.max_sessions = v,
                Ok(None) => {}
                Err(e) => return Ok(Json(super::err_json(e))),
            }
            if body.get("allowed_networks").is_some() {
                let nets = strings_from_json(&body["allowed_networks"]);
                if let Err(e) = validate_allowed_networks(&nets) {
                    return Ok(Json(super::err_json(e)));
                }
                edited.allowed_networks = nets;
            }
            if body.get("profiles").is_some() {
                edited.profiles = strings_from_json(&body["profiles"]);
            }
            if body.get("routes").is_some() {
                match routes_from_json(&body["routes"]) {
                    Ok(r) => edited.routes = r,
                    Err(e) => return Ok(Json(super::err_json(e))),
                }
            }
            if body.get("client_subnets").is_some() {
                edited.client_subnets = strings_from_json(&body["client_subnets"]);
            }
            // Persist just THIS entry onto a freshly re-read file. Writing the whole
            // in-memory database back is what let one edit revert another writer's — most
            // visibly its own follow-up `set-bandwidth`, which the worker applied to its
            // older snapshot and saved over the password this call had just written.
            //
            // But writing the whole ENTRY was still wrong for the same reason one level
            // down: the mutable entry used to be a handle into this process's snapshot,
            // which may predate a field the worker changed over the control socket
            // (bandwidth, data limit, expiry). Overwriting the fresh entry wholesale
            // reverted those. So diff the
            // entry against its pre-edit state and copy over ONLY what this request
            // actually changed, leaving every other field at whatever the file now holds.
            let users_file = state.config.auth.users_file.clone();
            let applied = match UsersDb::update_locked(&users_file, |db| {
                match db.users.iter_mut().find(|u| u.username == username) {
                    Some(slot) => {
                        merge_changed_fields(&before, &edited, slot);
                        true
                    }
                    None => false,
                }
            }) {
                Ok((fresh, applied)) => {
                    *users = fresh;
                    applied
                }
                Err(e) => {
                    log::error!("Failed to save users file after update: {}", e);
                    return Ok(Json(super::err_json(format!(
                        "could not write the users file '{}': {} — change NOT applied",
                        users_file, e
                    ))));
                }
            };
            if !applied {
                return Ok(Json(super::err_json(format!(
                    "user '{}' was deleted concurrently — change NOT applied",
                    username
                ))));
            }
            drop(users);
            if let Some(limit) = new_bw_limit {
                worker_control(
                    json!({"cmd": "set-bandwidth", "username": username, "mbps": limit}),
                )
                .await;
            }
            reload_worker(&state).await;
            Ok(Json(
                json!({"ok": true, "message": format!("user '{}' updated", username)}),
            ))
        }
        None => Ok(Json(super::err_json(format!(
            "user '{}' not found",
            username
        )))),
    }
}

pub async fn delete_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let users_file = state.config.auth.users_file.clone();
    let mut users = state.users_db.write().await;
    // Delete on a freshly re-read copy: this process's snapshot may predate changes the
    // worker made over the control socket, and writing it back verbatim reverted them.
    let outcome = UsersDb::update_locked(&users_file, |db| {
        let before = db.users.len();
        db.users.retain(|u| u.username != username);
        db.users.len() < before
    });
    let removed = match outcome {
        Ok((fresh, removed)) => {
            *users = fresh;
            removed
        }
        Err(e) => {
            log::error!("Failed to save users file after delete: {}", e);
            return Ok(Json(super::err_json(format!(
                "could not write the users file '{}': {} — change NOT applied",
                users_file, e
            ))));
        }
    };
    if removed {
        drop(users);
        reload_worker(&state).await;
        Ok(Json(
            json!({"ok": true, "message": format!("user '{}' deleted", username)}),
        ))
    } else {
        Ok(Json(super::err_json(format!(
            "user '{}' not found",
            username
        ))))
    }
}

pub async fn enable_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    set_user_enabled(&state, &username, true).await
}

pub async fn disable_user(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
) -> Result<Json<Value>, AuthError> {
    // disable in users.json
    let result = set_user_enabled(&state, &username, false).await?;

    // also kick the user's active sessions in the worker if just disabled
    if result["ok"].as_bool().unwrap_or(false) {
        worker_control(json!({"cmd": "kick", "username": username})).await;
    }

    Ok(result)
}

async fn set_user_enabled(
    state: &Arc<ServerState>,
    username: &str,
    enabled: bool,
) -> Result<Json<Value>, AuthError> {
    let users_file = state.config.auth.users_file.clone();
    let mut users = state.users_db.write().await;
    // Flip the flag on a freshly re-read copy (see delete_user).
    let outcome = UsersDb::update_locked(&users_file, |db| {
        match db.users.iter_mut().find(|u| u.username == username) {
            Some(u) => {
                u.enabled = enabled;
                true
            }
            None => false,
        }
    });
    let found = match outcome {
        Ok((fresh, found)) => {
            *users = fresh;
            found
        }
        Err(e) => {
            log::error!("Failed to save users file after set_enabled: {}", e);
            return Ok(Json(super::err_json(format!(
                "could not write the users file '{}': {} — change NOT applied",
                users_file, e
            ))));
        }
    };
    match found {
        true => {
            let status = if enabled { "enabled" } else { "disabled" };
            drop(users);
            reload_worker(state).await;
            Ok(Json(
                json!({"ok": true, "message": format!("user '{}' {}", username, status), "enabled": enabled}),
            ))
        }
        false => Ok(Json(super::err_json(format!(
            "user '{}' not found",
            username
        )))),
    }
}

pub async fn set_user_bandwidth(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    let limit_mbps = match opt_u32_limit(&body, "limit_mbps") {
        Ok(v) => v.unwrap_or(0),
        Err(e) => return Ok(Json(super::err_json(e))),
    };
    let burst_mbps = match opt_u32_limit(&body, "burst_mbps") {
        Ok(v) => v.unwrap_or(0),
        Err(e) => return Ok(Json(super::err_json(e))),
    };

    // persist to the users file
    let users_file = state.config.auth.users_file.clone();
    let mut users = state.users_db.write().await;
    // Apply on a freshly re-read copy (see create_user).
    let outcome: Result<bool, String> = {
        match UsersDb::update_locked(&users_file, |db| {
            match db.users.iter_mut().find(|u| u.username == username) {
                Some(user) => {
                    user.bandwidth.limit_mbps = limit_mbps;
                    user.bandwidth.burst_mbps = burst_mbps;
                    true
                }
                None => false,
            }
        }) {
            Ok((fresh, found)) => {
                *users = fresh;
                Ok(found)
            }
            Err(e) => {
                log::error!("Failed to save users file after set-bandwidth: {}", e);
                Err(format!(
                    "could not write the users file '{}': {} — change NOT applied",
                    users_file, e
                ))
            }
        }
    };
    drop(users);

    match outcome {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Json(super::err_json(format!(
                "user '{}' not found",
                username
            ))))
        }
        Err(msg) => return Ok(Json(super::err_json(msg))),
    }

    // apply live to the worker's active sessions, then reload its users file
    worker_control(json!({"cmd": "set-bandwidth", "username": username, "mbps": limit_mbps})).await;
    reload_worker(&state).await;

    Ok(Json(
        json!({"ok": true, "message": format!("bandwidth for '{}' set to {} Mbps (burst {})", username, limit_mbps, burst_mbps)}),
    ))
}

// ───────────────────────────── group templates ─────────────────────────────
// Groups live in the users file alongside users (state.users_db.groups). A user
// inherits a group's bandwidth / max_sessions / allowed_networks unless it sets
// its own. Optional fields are null = "unset" (inherit nothing for that field).

pub async fn list_groups(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    let users = state.users_db.read().await;
    Ok(Json(json!({ "ok": true, "groups": users.groups })))
}

/// Create or update a group template by name.
pub async fn upsert_group(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, AuthError> {
    if name.trim().is_empty() {
        return Ok(Json(super::err_json("group name required")));
    }
    // The name becomes an INI section instance (`[group:<name>]`), which serializes
    // bare — a control character there could forge extra config lines on re-read.
    // (config/format.rs strips them as a backstop; reject here so the operator sees why.)
    if !crate::util::is_valid_ident(&name) {
        return Ok(Json(super::err_json(
            "group name must be non-empty, at most 128 bytes, and carry no control \
             characters or surrounding whitespace",
        )));
    }
    // Range-check before narrowing; absent / null → None (field unset), invalid → 400.
    let bandwidth_limit_mbps = match opt_u32_limit(&body, "bandwidth_limit_mbps") {
        Ok(v) => v,
        Err(e) => return Ok(Json(super::err_json(e))),
    };
    let max_sessions = match opt_u32_limit(&body, "max_sessions") {
        Ok(v) => v,
        Err(e) => return Ok(Json(super::err_json(e))),
    };
    let group_nets = if body.get("allowed_networks").is_some_and(|v| v.is_array()) {
        let nets = strings_from_json(&body["allowed_networks"]);
        if let Err(e) = validate_allowed_networks(&nets) {
            return Ok(Json(super::err_json(e)));
        }
        Some(nets)
    } else {
        None
    };
    let group = GroupTemplate {
        bandwidth_limit_mbps,
        max_sessions,
        allowed_networks: group_nets,
    };

    let mut users = state.users_db.write().await;
    // Snapshot before mutating so a failed write can be undone (see create_user) —
    // the group no longer lingers in memory after a failed persist, so the message
    // below is now literally true.
    let users_file = state.config.auth.users_file.clone();
    if let Err(e) = UsersDb::update_locked(&users_file, |db| {
        db.groups.insert(name.clone(), group);
    })
    .map(|(fresh, ())| *users = fresh)
    {
        log::error!("Failed to save users file after group upsert: {}", e);
        return Ok(Json(super::err_json(format!(
            "could not persist the group: {} — change NOT applied",
            e
        ))));
    }
    drop(users);
    reload_worker(&state).await;
    Ok(Json(
        json!({"ok": true, "message": format!("group '{}' saved", name)}),
    ))
}

pub async fn delete_group(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Path(name): Path<String>,
) -> Result<Json<Value>, AuthError> {
    let mut users = state.users_db.write().await;
    // Snapshot before mutating so a failed write can be undone (see create_user).
    let users_file = state.config.auth.users_file.clone();
    let existed = match UsersDb::update_locked(&users_file, |db| db.groups.remove(&name).is_some())
    {
        Ok((fresh, existed)) => {
            *users = fresh;
            existed
        }
        Err(e) => {
            log::error!("Failed to save users file after group delete: {}", e);
            return Ok(Json(super::err_json(format!(
                "could not write the users file '{}': {} — change NOT applied",
                users_file, e
            ))));
        }
    };
    if !existed {
        return Ok(Json(super::err_json(format!("group '{}' not found", name))));
    }
    drop(users);
    reload_worker(&state).await;
    Ok(Json(
        json!({"ok": true, "message": format!("group '{}' deleted", name)}),
    ))
}

#[cfg(test)]
mod merge_tests {
    //! The field-wise merge is what keeps two writers from clobbering each other. The
    //! panel edits a user from a snapshot that may already be stale — the worker changes
    //! bandwidth/limits/expiry over the control socket — so writing the whole entry back
    //! reverted whatever it had not seen. These pin that only the edited fields travel.
    use super::{merge_changed_fields, routes_from_json};
    use crate::config::users::UserEntry;

    fn user(name: &str) -> UserEntry {
        UserEntry {
            username: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn only_the_edited_field_is_written() {
        let before = user("alice");
        let mut after = before.clone();
        after.password_hash = "$argon2id$new".into();

        // The file meanwhile got a bandwidth limit from the worker.
        let mut slot = before.clone();
        slot.bandwidth.limit_mbps = 50;

        merge_changed_fields(&before, &after, &mut slot);

        assert_eq!(slot.password_hash, "$argon2id$new", "the edit must apply");
        assert_eq!(
            slot.bandwidth.limit_mbps, 50,
            "a field this request did not touch must keep the file's value"
        );
    }

    #[test]
    fn an_unrelated_concurrent_change_survives() {
        // Panel disables the user; worker had just set an expiry and a data limit.
        let before = user("bob");
        let mut after = before.clone();
        after.enabled = false;

        let mut slot = before.clone();
        slot.expire_at = Some(1_800_000_000);
        slot.data_limit_gb = 100;

        merge_changed_fields(&before, &after, &mut slot);

        assert!(!slot.enabled);
        assert_eq!(slot.expire_at, Some(1_800_000_000));
        assert_eq!(slot.data_limit_gb, 100);
    }

    #[test]
    fn a_genuine_conflict_still_takes_the_edit() {
        // Both writers touched the SAME field — last writer wins, by design.
        let before = user("carol");
        let mut after = before.clone();
        after.max_sessions = 3;

        let mut slot = before.clone();
        slot.max_sessions = 9;

        merge_changed_fields(&before, &after, &mut slot);
        assert_eq!(slot.max_sessions, 3);
    }

    #[test]
    fn no_edits_leaves_the_file_entry_untouched() {
        let before = user("dave");
        let after = before.clone();
        let mut slot = before.clone();
        slot.bandwidth.limit_mbps = 7;
        slot.static_ip = Some("10.0.0.9".into());

        merge_changed_fields(&before, &after, &mut slot);
        assert_eq!(slot.bandwidth.limit_mbps, 7);
        assert_eq!(slot.static_ip.as_deref(), Some("10.0.0.9"));
    }

    #[test]
    fn route_metric_must_fit_u32() {
        let too_large = serde_json::json!([{
            "cidr": "10.20.0.0/16",
            "metric": u64::from(u32::MAX) + 1
        }]);
        assert!(routes_from_json(&too_large).is_err());

        let fractional = serde_json::json!([{
            "cidr": "10.20.0.0/16",
            "metric": 1.5
        }]);
        assert!(routes_from_json(&fractional).is_err());

        let maximum = serde_json::json!([{
            "cidr": "10.20.0.0/16",
            "metric": u32::MAX
        }]);
        assert_eq!(
            routes_from_json(&maximum).unwrap()[0].metric,
            Some(u32::MAX)
        );
    }
}
