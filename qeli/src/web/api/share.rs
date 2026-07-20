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
    // Read profiles FRESH from disk so a config change applied via the panel (new SNI,
    // port, mode) is reflected in the generated link WITHOUT a full process restart:
    // "apply & restart" only restarts the WORKER and does NOT refresh the supervisor's
    // frozen `state.config`, so the link kept the boot-time SNI until `systemctl restart`
    // (issue #69). Fall back to the startup snapshot if the file is momentarily unreadable.
    let fresh = state
        .config_path
        .lock()
        .await
        .clone()
        .and_then(|p| std::fs::read_to_string(&p).ok())
        .and_then(|s| crate::config::parse_server_config(&s).ok());
    let profiles = match fresh.as_ref() {
        Some(c) => &c.profiles,
        None => &state.config.profiles,
    };
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
    let host = params
        .get("host")
        .cloned()
        .filter(|h| !h.is_empty())
        .unwrap_or(default_host);
    if host.is_empty() {
        return Json(super::err_json(
            "no host: pass `host` or set web.public_host (the server's public address)",
        ));
    }
    let user = params.get("user").cloned().unwrap_or_default();
    if user.is_empty() {
        return Json(super::err_json("user query param required"));
    }
    let allow_reset = params.get("allow_reset").map(String::as_str) == Some("true");

    // Resolve the password without admin input: decrypt the stored copy, else
    // (legacy / decrypt failure) reset on demand. `reset` is reported back so the
    // UI can warn that the old config was invalidated.
    let enc = {
        let users = state.users_db.read().await;
        match users.users.iter().find(|u| u.username == user) {
            Some(u) => u.password_enc.clone(),
            None => return Json(super::err_json(format!("user '{}' not found", user))),
        }
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
                let users_file = state.config.auth.users_file.clone();
                let mut users = state.users_db.write().await;
                // Re-read under the lock and set the new credentials there. Writing this
                // process's whole copy back could revert a change the worker had just
                // persisted — and here the field at stake is a password hash, so the two
                // ends would disagree about what the user's password even is.
                match crate::config::users::UsersDb::update_locked(&users_file, |db| {
                    if let Some(u) = db.users.iter_mut().find(|u| u.username == user) {
                        u.password_hash = hash;
                        u.password_enc = enc2;
                    }
                }) {
                    Ok((fresh, ())) => *users = fresh,
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

    let obf = &profile.obfuscation;
    // A real-TLS REALITY profile → client wire mode `reality-tls`; a fake-tls
    // reality-proxy (peek-and-decide) profile keeps mode=fake-tls. In BOTH cases the
    // client must seal the reality short_id into the ClientHello so the server
    // recognises it instead of relaying to the real target — surface `rsid` whenever
    // the reality proxy is enabled with a short_id, not only for real_tls. Plain
    // (non-reality) profiles keep their wire mode and carry no short_id.
    let rp = &obf.tls.reality_proxy;
    let mode = if rp.real_tls && !rp.short_ids.is_empty() {
        "reality-tls".to_string()
    } else {
        obf.mode.clone()
    };
    let reality_sid = if rp.enabled && !rp.short_ids.is_empty() {
        Some(rp.short_ids[0].clone())
    } else {
        None
    };
    let link = crate::config::share::ClientLink {
        host,
        port: profile.bind.port,
        user,
        pass,
        proto: profile.bind.transport.clone(),
        mode,
        server_key,
        sni: Some(obf.tls.server_name.clone()).filter(|s| !s.is_empty()),
        reality_sid,
        obfs_key: Some(obf.obfs_key.clone()).filter(|s| !s.is_empty()),
        fronting: Some(obf.fronting.clone()).filter(|s| !s.is_empty() && s != "websocket"),
        quic: obf.quic.enabled,
        // mtu=0 (auto): client adopts the server-pushed TUN MTU.
        mtu: 0,
        label: params.get("label").cloned().filter(|s| !s.is_empty()),
        // AmneziaWG-style junk masking: surface the profile's awg params so the
        // client matches (jc must agree). Junk is emitted only where the handshake
        // sends it: TCP obfs (protocol::obfs) and every UDP mode (jc junk datagrams
        // before the ClientHello — sender-only). On TCP fake-tls/reality-tls junk
        // would break the TLS mimicry, so don't advertise awg there (misleading no-op).
        awg: obf.awg.enabled && (obf.mode == "obfs" || profile.bind.transport == "udp"),
        jc: obf.awg.jc,
        jmin: obf.awg.jmin,
        jmax: obf.awg.jmax,
    };

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
/// the markup is injected straight into the page). Returns `null` on the rare
/// failure (e.g. payload exceeds QR capacity), so the UI can still show the URI.
fn render_qr_svg(data: &str) -> Option<String> {
    use qrcode::{render::svg, QrCode};
    let code = QrCode::new(data.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(240, 240)
            .quiet_zone(true)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::render_qr_svg;

    #[test]
    fn renders_svg_qr_for_a_share_uri() {
        let uri = "qeli://alice:pw@vpn.example.com:443?proto=tcp&mode=fake-tls\
                   &key=0a33d308295d5dc49bff020ca8a73e86b3f6797cbcc7d3aa440eee754729223a";
        let svg = render_qr_svg(uri).expect("QR should render for a normal share URI");
        assert!(
            svg.contains("<svg"),
            "output should be SVG markup: {}",
            &svg[..svg.len().min(80)]
        );
        assert!(svg.contains("</svg>"));
        assert!(
            svg.len() > 200,
            "SVG unexpectedly tiny ({} bytes)",
            svg.len()
        );
    }
}
