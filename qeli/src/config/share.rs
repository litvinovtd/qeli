//! `qeli://` share links — the compact, QR-friendly representation of the
//! minimal client config, modelled on the VLESS/Trojan URI scheme so existing
//! QR scanners and the Android app can import a connection in one shot.
//!
//! Shape:
//! ```text
//! qeli://<user>:<pass>@<host>:<port>?proto=tcp&mode=fake-tls&key=<hex>&sni=<host>&obfs=<key>#<label>
//! ```
//!
//! Everything in [`ClientLink`] is exactly the set of fields the client cannot
//! derive or receive from the server at handshake time — credentials, where to
//! connect, the pinned server key, and the wire mode that must match the
//! server's profile. Routes, DNS, MTU and the obfuscation *parameters* are
//! pushed by the server after auth, so they deliberately do not appear here.
//!
//! Pure `std` (manual percent-encoding, no `url` crate), so it builds and is
//! tested on every platform.

/// The minimal, QR-encodable client connection descriptor. Maps 1:1 onto the
/// `[qeli]` section of a client config and onto a `qeli://` URI.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientLink {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    /// Wire transport: `tcp` or `udp`.
    pub proto: String,
    /// Wire obfuscation mode: `fake-tls` or `obfs`. Must match the server
    /// profile.
    pub mode: String,
    /// Hex-encoded pinned server static public key (anti-MITM). Empty = TOFU.
    pub server_key: String,
    /// SNI to present in fake-tls mode (optional).
    pub sni: Option<String>,
    /// REALITY short_id (hex) for `mode = reality-tls`. Pairs with `server_key`
    /// to seal the auth token into the real ClientHello. Absent for other modes.
    pub reality_sid: Option<String>,
    /// Pre-shared key for `obfs` mode (optional / mode-dependent).
    pub obfs_key: Option<String>,
    /// `obfs` fronting mode (`websocket`/`none`); `None` means the default
    /// (`websocket`). Only present in the link when it diverges from the default.
    pub fronting: Option<String>,
    /// QUIC masking for the UDP transport (`quic=1` in the link). Required for a
    /// udp+quic profile — without it the client sends plain UDP and a quic-mode
    /// server stays silent. Off by default.
    pub quic: bool,
    /// Explicit TUN MTU override (`mtu=` in the link). `0`/absent = auto: the
    /// client adopts the MTU the server pushes at auth. Only present in the link
    /// when set to a non-zero override.
    pub mtu: i32,
    /// Human label shown in the client UI (URI fragment).
    pub label: Option<String>,
}

impl ClientLink {
    /// Render to a `qeli://` URI suitable for a QR code.
    pub fn to_uri(&self) -> String {
        let mut uri = String::from("qeli://");
        if !self.user.is_empty() || !self.pass.is_empty() {
            uri.push_str(&pct_encode(&self.user));
            uri.push(':');
            uri.push_str(&pct_encode(&self.pass));
            uri.push('@');
        }
        uri.push_str(&self.host);
        uri.push(':');
        uri.push_str(&self.port.to_string());

        let mut query: Vec<(String, String)> = Vec::new();
        if !self.proto.is_empty() {
            query.push(("proto".into(), self.proto.clone()));
        }
        if !self.mode.is_empty() {
            query.push(("mode".into(), self.mode.clone()));
        }
        if !self.server_key.is_empty() {
            query.push(("key".into(), self.server_key.clone()));
        }
        if let Some(sni) = self.sni.as_ref().filter(|s| !s.is_empty()) {
            query.push(("sni".into(), sni.clone()));
        }
        if let Some(rsid) = self.reality_sid.as_ref().filter(|s| !s.is_empty()) {
            query.push(("rsid".into(), rsid.clone()));
        }
        if let Some(ok) = self.obfs_key.as_ref().filter(|s| !s.is_empty()) {
            query.push(("obfs".into(), ok.clone()));
        }
        if let Some(fr) = self.fronting.as_ref().filter(|s| !s.is_empty()) {
            query.push(("front".into(), fr.clone()));
        }
        if self.quic {
            query.push(("quic".into(), "1".into()));
        }
        if self.mtu > 0 {
            query.push(("mtu".into(), self.mtu.to_string()));
        }
        if !query.is_empty() {
            uri.push('?');
            let parts: Vec<String> = query
                .iter()
                .map(|(k, v)| format!("{}={}", k, pct_encode(v)))
                .collect();
            uri.push_str(&parts.join("&"));
        }

        if let Some(label) = self.label.as_ref().filter(|s| !s.is_empty()) {
            uri.push('#');
            uri.push_str(&pct_encode(label));
        }
        uri
    }

    /// Parse a `qeli://` URI back into a [`ClientLink`].
    pub fn from_uri(uri: &str) -> Result<ClientLink, LinkError> {
        let rest = uri
            .strip_prefix("qeli://")
            .ok_or(LinkError("missing qeli:// scheme"))?;

        // Split off fragment (#label), then query (?...).
        let (rest, fragment) = match rest.split_once('#') {
            Some((r, f)) => (r, Some(pct_decode(f))),
            None => (rest, None),
        };
        let (authority, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };

        // userinfo@host:port
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (host, port_str) = hostport
            .rsplit_once(':')
            .ok_or(LinkError("authority missing :port"))?;
        if host.is_empty() {
            return Err(LinkError("empty host"));
        }
        let port: u16 = port_str.parse().map_err(|_| LinkError("invalid port"))?;

        let (user, pass) = match userinfo {
            Some(ui) => match ui.split_once(':') {
                Some((u, p)) => (pct_decode(u), pct_decode(p)),
                None => (pct_decode(ui), String::new()),
            },
            None => (String::new(), String::new()),
        };

        let mut link = ClientLink {
            host: host.to_string(),
            port,
            user,
            pass,
            proto: String::new(),
            mode: String::new(),
            server_key: String::new(),
            sni: None,
            reality_sid: None,
            obfs_key: None,
            fronting: None,
            quic: false,
            mtu: 0,
            label: fragment,
        };

        if let Some(q) = query {
            for pair in q.split('&').filter(|s| !s.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                let v = pct_decode(v);
                match k {
                    "proto" => link.proto = v,
                    "mode" => link.mode = v,
                    "key" => link.server_key = v,
                    "sni" => link.sni = Some(v),
                    "rsid" => link.reality_sid = Some(v),
                    "obfs" => link.obfs_key = Some(v),
                    "front" => link.fronting = Some(v),
                    "quic" => link.quic = matches!(v.as_str(), "1" | "true"),
                    "mtu" => link.mtu = v.parse().unwrap_or(0),
                    _ => {} // forward-compatible: ignore unknown params
                }
            }
        }
        Ok(link)
    }
}

/// Error parsing a `qeli://` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkError(pub &'static str);

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid qeli:// link: {}", self.0)
    }
}

impl std::error::Error for LinkError {}

/// Percent-encode everything outside the RFC 3986 unreserved set
/// (`A-Z a-z 0-9 - _ . ~`). Conservative on purpose so the result is safe in
/// userinfo, query, and fragment positions alike.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0x0f));
            }
        }
    }
    out
}

/// Decode percent-escapes. Invalid escapes are passed through literally rather
/// than erroring — a scanned QR with a stray `%` should still import.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + (n - 10)) as char,
    }
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientLink {
        ClientLink {
            host: "vpn.example.com".into(),
            port: 443,
            user: "alice".into(),
            pass: "p@ss w0rd".into(),
            proto: "tcp".into(),
            mode: "fake-tls".into(),
            server_key: "0a33d308295d5dc49bff020ca8a73e86b3f6797cbcc7d3aa440eee754729223a".into(),
            sni: Some("www.cloudflare.com".into()),
            reality_sid: None,
            obfs_key: None,
            fronting: None,
            quic: false,
            mtu: 0,
            label: Some("My VPN".into()),
        }
    }

    #[test]
    fn round_trip_full() {
        let link = sample();
        let uri = link.to_uri();
        let back = ClientLink::from_uri(&uri).unwrap();
        assert_eq!(link, back);
    }

    #[test]
    fn encodes_special_chars_in_password_and_label() {
        let uri = sample().to_uri();
        // '@' and space in the password must be escaped so the authority parses.
        assert!(uri.contains("p%40ss%20w0rd@"), "uri was: {}", uri);
        // space in label escaped in the fragment
        assert!(uri.ends_with("#My%20VPN"), "uri was: {}", uri);
    }

    #[test]
    fn obfs_mode_round_trip() {
        let link = ClientLink {
            host: "1.2.3.4".into(),
            port: 8443,
            user: "bob".into(),
            pass: "x".into(),
            proto: "udp".into(),
            mode: "obfs".into(),
            server_key: String::new(),
            sni: None,
            reality_sid: None,
            obfs_key: Some("shared-secret".into()),
            fronting: Some("none".into()),
            quic: true,
            mtu: 1280,
            label: None,
        };
        let back = ClientLink::from_uri(&link.to_uri()).unwrap();
        assert_eq!(back.mode, "obfs");
        assert_eq!(back.obfs_key.as_deref(), Some("shared-secret"));
        assert_eq!(back.fronting.as_deref(), Some("none"));
        assert!(back.quic);
        assert_eq!(back.server_key, "");
        assert_eq!(back.label, None);
    }

    #[test]
    fn host_with_colon_in_ipv6_like_authority_uses_last_colon() {
        // We don't claim full IPv6 support, but rsplit on ':' must not choke on
        // a host that contains none beyond the port separator.
        let link = ClientLink::from_uri("qeli://u:p@host.tld:9000").unwrap();
        assert_eq!(link.host, "host.tld");
        assert_eq!(link.port, 9000);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(ClientLink::from_uri("http://x").is_err());
        assert!(ClientLink::from_uri("qeli://hostonly").is_err());
        assert!(ClientLink::from_uri("qeli://h:notaport").is_err());
    }

    #[test]
    fn forward_compatible_unknown_params_ignored() {
        let link = ClientLink::from_uri("qeli://u:p@h:1?proto=tcp&future=xyz").unwrap();
        assert_eq!(link.proto, "tcp");
    }

    #[test]
    fn reality_sid_round_trips() {
        let mut link = sample();
        link.mode = "reality-tls".into();
        link.reality_sid = Some("0123456789abcdef".into());
        let back = ClientLink::from_uri(&link.to_uri()).unwrap();
        assert_eq!(back.mode, "reality-tls");
        assert_eq!(back.reality_sid.as_deref(), Some("0123456789abcdef"));
    }
}
