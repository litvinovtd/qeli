use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// Build a `qeli://` share link (for a QR code) for a given user + profile —
/// **without the admin typing the password**.
///
/// The connection essentials the server knows (port, transport, obf mode, SNI,
/// pinned key) are filled automatically. The password comes from the user's
/// reversibly-encrypted copy (`password_enc`, decrypted with the panel key), so
/// an existing user's config can be re-issued at any time. For legacy users with
/// no stored copy, the link can only be produced by **resetting** the password
/// (caller passes `allow_reset:"true"`); a fresh one is generated, stored, and
/// returned — the user's old config then stops working.
///
/// `POST /api/share` body:
/// `{"profile":"tcp","host":"vpn.example.com","user":"alice","label":"My VPN","allow_reset":"true"}`
pub async fn share_link(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(params): Json<HashMap<String, String>>,
) -> Json<Value> {
    let profile_name = params
        .get("profile")
        .map(String::as_str)
        .unwrap_or("default");
    // Keep profile selection and a possible password reset on one serialized config
    // revision; the supervisor's state.config is only the boot-time socket snapshot.
    let _config_write_guard = state.config_write_lock.lock().await;
    let config = match super::current_server_config(&state).await {
        Ok(config) => config,
        Err(error) => return Json(super::err_json(error)),
    };
    let profiles = &config.profiles;
    let profile = match profiles.iter().find(|p| p.name == profile_name) {
        Some(p) => p,
        None => {
            let loaded: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
            return Json(super::err_json(format!(
                "profile '{}' is not loaded (currently loaded: {}).",
                profile_name,
                loaded.join(", ")
            )));
        }
    };

    // Host: explicit param wins; otherwise fall back to the configured default
    // (web.public_host, live copy) so the admin needn't retype it for every link.
    let default_host = state.live_web.read().await.public_host.clone();
    let host_input = params
        .get("host")
        .cloned()
        .filter(|h| !h.is_empty())
        .unwrap_or(default_host);
    if host_input.is_empty() {
        return Json(super::err_json(
            "no host: pass `host` or set web.public_host (the server's public address)",
        ));
    }
    // Validate before a legacy user's password is reset below. A bad/IPv6 endpoint must not
    // perform that destructive action and only then discover that no usable link can be made.
    let (host, port) =
        match crate::config::share::supported_public_endpoint(&host_input, profile.bind.port) {
            Ok(endpoint) => endpoint,
            Err(error) => return Json(super::err_json(error)),
        };
    let user = params.get("user").cloned().unwrap_or_default();
    if user.is_empty() {
        return Json(super::err_json("user query param required"));
    }
    let allow_reset = params.get("allow_reset").map(String::as_str) == Some("true");

    // Resolve the password without admin input: decrypt the stored copy, else
    // (legacy / decrypt failure) reset on demand. `reset` is reported back so the
    // UI can warn that the old config was invalidated.
    let effective_users = match super::effective_users(&config) {
        Ok(users) => users,
        Err(error) => return Json(super::err_json(error)),
    };
    let enc = match effective_users
        .users
        .iter()
        .find(|entry| entry.username == user)
    {
        Some(entry) => entry.password_enc.clone(),
        None => return Json(super::err_json(format!("user '{}' not found", user))),
    };
    let recovered = enc
        .as_deref()
        .and_then(|e| crate::crypto::secret::decrypt_password(e).ok());
    let (pass, was_reset) = match recovered {
        Some(p) => (p, false),
        None => {
            if !allow_reset {
                return Json(json!({
                    "ok": false,
                    "needs_reset": true,
                    "error": "No recoverable password for this user (created before re-issue was enabled, or the key changed). Reset to issue a new config — the user's old config will stop working.",
                }));
            }
            // Reset: new password, persisted (hash + encrypted copy), worker reloaded.
            let new_pw = super::users::gen_password(20);
            let (hash, enc2) = match super::users::hash_and_enc(&new_pw) {
                Ok(v) => v,
                Err(e) => return Json(super::err_json(e)),
            };
            {
                let users_file = config.auth.users_file.clone();
                let mut users = state.users_db.write().await;
                // Re-read under the lock and set the new credentials there. Writing this
                // process's whole copy back could revert a change the worker had just
                // persisted — and here the field at stake is a password hash, so the two
                // ends would disagree about what the user's password even is.
                match crate::config::users::UsersDb::update_locked_checked(&users_file, |db| {
                    let mut found = false;
                    if let Some(entry) = db.users.iter_mut().find(|entry| entry.username == user) {
                        entry.password_hash = hash.clone();
                        entry.password_enc = enc2.clone();
                        found = true;
                    } else if let Some(inline) = config
                        .auth
                        .users
                        .iter()
                        .find(|entry| entry.username == user)
                    {
                        let mut entry = inline.clone();
                        entry.password_hash = hash.clone();
                        entry.password_enc = enc2.clone();
                        db.users.push(entry);
                        found = true;
                    }
                    let effective = super::effective_users_from_external(&config, db.clone())?;
                    Ok((found, effective))
                }) {
                    Ok((_fresh, (true, effective))) => *users = effective,
                    Ok((_fresh, (false, _))) => {
                        return Json(super::err_json(format!(
                            "user '{}' was deleted concurrently; password was not reset",
                            user
                        )));
                    }
                    Err(e) => {
                        log::error!("share/reset: failed to save users file: {}", e);
                        return Json(super::err_json(format!("could not persist reset: {}", e)));
                    }
                }
            }
            if let Some(tx) = &state.worker_tx {
                let _ = tx.send(crate::server::WorkerCmd::ReloadUsers).await;
            }
            (new_pw, true)
        }
    };

    // The profile's pinned static public key (loads the existing identity key).
    let server_key = match crate::server::load_or_generate_profile_key(profile) {
        Ok(kp) => kp
            .public
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>(),
        Err(e) => return Json(super::err_json(format!("identity key unavailable: {}", e))),
    };

    // Every profile-dependent field (wire mode, rsid, sni, obfs key, fronting, quic, awg)
    // comes from the shared builder, so this endpoint and `qeli share-link` / `add-client
    // --link` can never disagree about what a profile's clients need.
    let link = crate::config::share::ClientLink::for_profile(
        profile,
        host,
        port,
        user,
        pass,
        server_key,
        params.get("label").cloned().filter(|s| !s.is_empty()),
    );

    let uri = link.to_uri();
    let qr_svg = render_qr_svg(&uri);
    Json(json!({
        "ok": true,
        "uri": uri,
        "qr_svg": qr_svg,
        "reset": was_reset,
        // Surface the freshly-generated password only when we reset, so the admin
        // can record it (it's also embedded in the URI).
        "new_password": if was_reset { Some(link.pass.clone()) } else { None },
    }))
}

/// Render a `qeli://` URI to a self-contained SVG QR code (no JS/CDN needed —
/// the UI percent-encodes it into an `<img>` data URI; it is never injected as HTML).
/// The returned markup STARTS at `<svg`: the panel's `svgDataUri` guard
/// (`web/templates/users.html`) refuses anything that does not, because an `<img>` data
/// URI is the only thing it will build. Returns `null` on the rare failure (e.g. payload
/// exceeds QR capacity), so the UI can still show the URI.
fn render_qr_svg(data: &str) -> Option<String> {
    use qrcode::{render::svg, QrCode};
    let code = QrCode::new(data.as_bytes()).ok()?;
    let markup = code
        .render::<svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build();
    // The renderer prefixes an XML prolog (`<?xml version="1.0" standalone="yes"?>`).
    // The panel requires the payload to BEGIN with `<svg`, so that prolog turned every
    // share into a blank <img> next to a perfectly good link — a 200 whose failure was
    // invisible on both sides. Searched rather than stripped as a fixed literal so a
    // future crate release rewording the prolog cannot silently reintroduce this.
    let start = markup.find("<svg")?;
    Some(markup[start..].to_string())
}

#[cfg(test)]
mod tests {
    use super::render_qr_svg;

    #[test]
    fn renders_svg_qr_for_a_share_uri() {
        let uri = "qeli://alice:pw@vpn.example.com:443?proto=tcp&mode=fake-tls\
                   &key=0a33d308295d5dc49bff020ca8a73e86b3f6797cbcc7d3aa440eee754729223a";
        let svg = render_qr_svg(uri).expect("QR should render for a normal share URI");
        // STARTS with, not merely contains. `contains` passed happily while the renderer's
        // XML prolog sat in front of `<svg`, which is exactly what the panel's data-URI
        // guard rejects — so the old assertion could not see the bug it was there to catch.
        assert!(
            svg.starts_with("<svg"),
            "output must begin with SVG markup, or the panel renders a blank <img>: {}",
            &svg[..svg.len().min(80)]
        );
        assert!(
            !svg.contains("<?xml"),
            "an XML prolog must not survive into the panel payload"
        );
        assert!(svg.contains("</svg>"));
        assert!(
            svg.len() > 200,
            "SVG unexpectedly tiny ({} bytes)",
            svg.len()
        );
    }
}
