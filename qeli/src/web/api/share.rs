use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// Build a `qeli://` share link (for a QR code) for a given user + profile.
///
/// The connection essentials that the server knows — port, wire transport,
/// obfuscation mode, SNI, the profile's pinned public key — are filled in
/// automatically. The two things the server cannot derive are supplied by the
/// admin in the JSON POST body:
///   * `host` — the server's *public* reachable address (the bind is 0.0.0.0).
///   * `pass` — the user's password. The server only stores an Argon2 hash and
///     genuinely cannot recover the plaintext, so it must be provided here (it
///     is not persisted).
///
/// `POST /api/share` with a JSON body:
/// `{"profile":"tcp","host":"vpn.example.com","user":"alice","pass":"secret","label":"My VPN"}`
///
/// The password travels in the request body (not the URL) so it never lands in
/// reverse-proxy access logs or browser history.
pub async fn share_link(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(params): Json<HashMap<String, String>>,
) -> Json<Value> {
    let profile_name = params
        .get("profile")
        .map(String::as_str)
        .unwrap_or("default");
    let profile = match state
        .config
        .profiles
        .iter()
        .find(|p| p.name == profile_name)
    {
        Some(p) => p,
        None => {
            return Json(super::err_json(format!(
                "unknown profile '{}'",
                profile_name
            )))
        }
    };

    let host = params.get("host").cloned().unwrap_or_default();
    if host.is_empty() {
        return Json(super::err_json(
            "host query param required (server's public address)",
        ));
    }
    let user = params.get("user").cloned().unwrap_or_default();
    if user.is_empty() {
        return Json(super::err_json("user query param required"));
    }
    let pass = params.get("pass").cloned().unwrap_or_default();

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
    // For a real-TLS REALITY profile the *client* wire mode is `reality-tls` and
    // it needs the short_id (sealed into the real ClientHello) — surface both in
    // the link so a QR import is one-shot. Plain profiles keep their wire mode.
    let rp = &obf.tls.reality_proxy;
    let (mode, reality_sid) = if rp.real_tls && !rp.short_ids.is_empty() {
        ("reality-tls".to_string(), Some(rp.short_ids[0].clone()))
    } else {
        (obf.mode.clone(), None)
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
    };

    let uri = link.to_uri();
    let qr_svg = render_qr_svg(&uri);
    Json(json!({ "ok": true, "uri": uri, "qr_svg": qr_svg }))
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
