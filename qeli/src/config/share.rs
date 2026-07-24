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
    /// AmneziaWG junk-record pre-handshake (`awg=1` in the link; F2). When true,
    /// `jc`/`jmin`/`jmax` are also carried. Off by default; only present in the
    /// link when enabled.
    pub awg: bool,
    /// Junk record count (`jc=` in the link). Must match the server. Sender sizes
    /// each record in `jmin..=jmax`.
    pub jc: u32,
    /// Minimum junk record length (`jmin=` in the link). Sender-only.
    pub jmin: u16,
    /// Maximum junk record length (`jmax=` in the link). Sender-only.
    pub jmax: u16,
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
        // Bracket-wrap a bare IPv6 literal for the URI authority (RFC 3986:
        // `qeli://user@[2001:db8::1]:443`) so the address colons aren't confused
        // with the `:port` separator; IPv4 / hostnames pass through unchanged.
        if self.host.contains(':') && !self.host.starts_with('[') {
            uri.push('[');
            uri.push_str(&self.host);
            uri.push(']');
        } else {
            uri.push_str(&self.host);
        }
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
        // AmneziaWG junk (F2): emit awg/jc/jmin/jmax only when enabled so default
        // links stay compact and byte-identical to pre-F2 output.
        if self.awg {
            query.push(("awg".into(), "1".into()));
            query.push(("jc".into(), self.jc.to_string()));
            query.push(("jmin".into(), self.jmin.to_string()));
            query.push(("jmax".into(), self.jmax.to_string()));
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
        // A bracketed IPv6 literal (`[2001:db8::1]:443`) must be split on the `]:`
        // boundary, not the last `:`, or the address's own colons break parsing.
        let (host, port_str) = if let Some(rest) = hostport.strip_prefix('[') {
            let (h, p) = rest
                .split_once("]:")
                .ok_or(LinkError("malformed IPv6 [host]:port"))?;
            (h, p)
        } else {
            hostport
                .rsplit_once(':')
                .ok_or(LinkError("authority missing :port"))?
        };
        if host.is_empty() {
            return Err(LinkError("empty host"));
        }
        // Reject port 0 explicitly: it parses fine as a u16 but is not connectable, so
        // accepting it just defers the failure to an opaque socket error at connect time.
        // Swift and C# already rejected it; Rust and Kotlin did not — a divergence the
        // conformance fixtures (conformance/qeli-links.json) exist to catch.
        let port: u16 = port_str.parse().map_err(|_| LinkError("invalid port"))?;
        if port == 0 {
            return Err(LinkError("port must be 1..65535"));
        }

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
            awg: false,
            jc: 0,
            jmin: 0,
            jmax: 0,
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
                    "awg" => link.awg = matches!(v.as_str(), "1" | "true"),
                    "jc" => link.jc = v.parse().unwrap_or(0),
                    "jmin" => link.jmin = v.parse().unwrap_or(0),
                    "jmax" => link.jmax = v.parse().unwrap_or(0),
                    "mtu" => link.mtu = v.parse().unwrap_or(0),
                    _ => {} // forward-compatible: ignore unknown params
                }
            }
        }
        // Alias convenience: `mode=udp-quic` / `udp-obfs` fold transport+QUIC into the
        // wire mode. Split it back into proto + wire mode + quic.
        match link.mode.as_str() {
            "udp-quic" => {
                link.proto = "udp".into();
                link.mode = "fake-tls".into();
                link.quic = true;
            }
            "udp-obfs" => {
                link.proto = "udp".into();
                link.mode = "obfs".into();
            }
            _ => {}
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
            awg: false,
            jc: 0,
            jmin: 0,
            jmax: 0,
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
            awg: false,
            jc: 0,
            jmin: 0,
            jmax: 0,
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
    fn ipv6_literal_is_bracketed_and_round_trips() {
        // A bare IPv6 host must be emitted bracketed (RFC 3986) and parse back to
        // the unbracketed address — without the brackets the address colons would
        // be mistaken for the :port separator across clients.
        let mut link = sample();
        link.host = "2001:db8::1".into();
        link.port = 8443;
        let uri = link.to_uri();
        assert!(
            uri.contains("@[2001:db8::1]:8443"),
            "IPv6 host must be bracketed, uri was: {}",
            uri
        );
        let back = ClientLink::from_uri(&uri).unwrap();
        assert_eq!(back.host, "2001:db8::1");
        assert_eq!(back.port, 8443);
        assert_eq!(link, back);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(ClientLink::from_uri("http://x").is_err());
        assert!(ClientLink::from_uri("qeli://hostonly").is_err());
        assert!(ClientLink::from_uri("qeli://h:notaport").is_err());
        assert!(ClientLink::from_uri("qeli://u:p@[2001:db8::1]").is_err()); // bracket, no port
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

    #[test]
    fn awg_params_round_trip_and_absent_when_disabled() {
        // Enabled: awg/jc/jmin/jmax appear in the URI and round-trip.
        let mut link = sample();
        link.awg = true;
        link.jc = 6;
        link.jmin = 40;
        link.jmax = 300;
        let uri = link.to_uri();
        assert!(uri.contains("awg=1"), "uri was: {uri}");
        assert!(uri.contains("jc=6"), "uri was: {uri}");
        let back = ClientLink::from_uri(&uri).unwrap();
        assert!(back.awg);
        assert_eq!(back.jc, 6);
        assert_eq!(back.jmin, 40);
        assert_eq!(back.jmax, 300);
        // Disabled (default sample): no awg keys in the URI (compact/byte-identical).
        let uri = sample().to_uri();
        assert!(
            !uri.contains("awg"),
            "disabled awg must not appear, uri was: {uri}"
        );
    }
}

#[cfg(test)]
mod conformance {
    //! Cross-implementation conformance for the `qeli://` link.
    //!
    //! The fixtures in `conformance/qeli-links.json` are shared with the Kotlin, C# and
    //! Swift parsers. The link format is implemented four separate times, so every field
    //! is four chances to disagree — and the failure is silent (the link "imports", with a
    //! field quietly dropped or re-defaulted). Writing these fixtures immediately exposed
    //! one such divergence: Swift and C# rejected an out-of-range port, Rust accepted 0 and
    //! Kotlin accepted anything at all.
    use super::*;
    use serde_json::Value;

    fn fixtures() -> Value {
        // Compiled in, so the test cannot silently pass because a path moved.
        serde_json::from_str(include_str!("../../../conformance/qeli-links.json"))
            .expect("conformance/qeli-links.json is not valid JSON")
    }

    /// Compare an expected JSON value against the parsed field. `null` means "absent".
    fn opt_eq(expected: &Value, actual: Option<&String>) -> bool {
        match expected {
            Value::Null => actual.is_none() || actual.map(|s| s.is_empty()).unwrap_or(false),
            Value::String(s) => actual.map(|a| a == s).unwrap_or(false),
            _ => false,
        }
    }

    #[test]
    fn accepts_every_valid_fixture_with_the_expected_fields() {
        let fx = fixtures();
        let cases = fx["cases"].as_array().expect("cases[]");
        assert!(!cases.is_empty(), "fixture file has no cases");
        for c in cases {
            let name = c["name"].as_str().unwrap_or("?");
            let uri = c["uri"].as_str().expect("case.uri");
            let link = match ClientLink::from_uri(uri) {
                Ok(l) => l,
                Err(e) => panic!("case '{name}': expected the link to parse, got error: {e:?}"),
            };
            let e = &c["expect"];
            if let Some(v) = e.get("host").and_then(Value::as_str) {
                assert_eq!(link.host, v, "case '{name}': host");
            }
            if let Some(v) = e.get("port").and_then(Value::as_u64) {
                assert_eq!(link.port as u64, v, "case '{name}': port");
            }
            if let Some(v) = e.get("user").and_then(Value::as_str) {
                assert_eq!(link.user, v, "case '{name}': user");
            }
            if let Some(v) = e.get("pass").and_then(Value::as_str) {
                assert_eq!(link.pass, v, "case '{name}': pass");
            }
            if let Some(v) = e.get("proto").and_then(Value::as_str) {
                assert_eq!(link.proto, v, "case '{name}': proto");
            }
            if let Some(v) = e.get("mode").and_then(Value::as_str) {
                assert_eq!(link.mode, v, "case '{name}': mode");
            }
            if let Some(v) = e.get("server_key").and_then(Value::as_str) {
                assert_eq!(link.server_key, v, "case '{name}': server_key");
            }
            if let Some(v) = e.get("sni") {
                assert!(
                    opt_eq(v, link.sni.as_ref()),
                    "case '{name}': sni = {:?}",
                    link.sni
                );
            }
            if let Some(v) = e.get("reality_sid") {
                assert!(
                    opt_eq(v, link.reality_sid.as_ref()),
                    "case '{name}': reality_sid = {:?}",
                    link.reality_sid
                );
            }
            if let Some(v) = e.get("obfs_key") {
                assert!(
                    opt_eq(v, link.obfs_key.as_ref()),
                    "case '{name}': obfs_key = {:?}",
                    link.obfs_key
                );
            }
            if let Some(v) = e.get("quic").and_then(Value::as_bool) {
                assert_eq!(link.quic, v, "case '{name}': quic");
            }
            if let Some(v) = e.get("awg").and_then(Value::as_bool) {
                assert_eq!(link.awg, v, "case '{name}': awg");
            }
            if let Some(v) = e.get("jc").and_then(Value::as_u64) {
                assert_eq!(link.jc as u64, v, "case '{name}': jc");
            }
            if let Some(v) = e.get("jmin").and_then(Value::as_u64) {
                assert_eq!(link.jmin as u64, v, "case '{name}': jmin");
            }
            if let Some(v) = e.get("jmax").and_then(Value::as_u64) {
                assert_eq!(link.jmax as u64, v, "case '{name}': jmax");
            }
        }
    }

    #[test]
    fn rejects_every_invalid_fixture() {
        let fx = fixtures();
        for c in fx["reject"].as_array().expect("reject[]") {
            let name = c["name"].as_str().unwrap_or("?");
            let uri = c["uri"].as_str().expect("case.uri");
            assert!(
                ClientLink::from_uri(uri).is_err(),
                "case '{name}': this link MUST be rejected, but it parsed: {uri}"
            );
        }
    }

    #[test]
    fn every_valid_fixture_survives_a_round_trip() {
        // Emitting a link and re-importing it must preserve the connection-essential
        // fields. This is the check that would have caught Android emitting `mtu` with no
        // parser for it on the way back.
        let fx = fixtures();
        for c in fx["cases"].as_array().expect("cases[]") {
            let name = c["name"].as_str().unwrap_or("?");
            let link = ClientLink::from_uri(c["uri"].as_str().unwrap()).unwrap();
            let again = ClientLink::from_uri(&link.to_uri())
                .unwrap_or_else(|e| panic!("case '{name}': re-emitted link does not parse: {e:?}"));
            assert_eq!(link.host, again.host, "case '{name}': host round-trip");
            assert_eq!(link.port, again.port, "case '{name}': port round-trip");
            assert_eq!(link.user, again.user, "case '{name}': user round-trip");
            assert_eq!(link.pass, again.pass, "case '{name}': pass round-trip");
            assert_eq!(link.proto, again.proto, "case '{name}': proto round-trip");
            assert_eq!(link.mode, again.mode, "case '{name}': mode round-trip");
            assert_eq!(
                link.server_key, again.server_key,
                "case '{name}': key round-trip"
            );
            assert_eq!(link.sni, again.sni, "case '{name}': sni round-trip");
            assert_eq!(
                link.reality_sid, again.reality_sid,
                "case '{name}': rsid round-trip"
            );
            assert_eq!(
                link.obfs_key, again.obfs_key,
                "case '{name}': obfs round-trip"
            );
            assert_eq!(link.quic, again.quic, "case '{name}': quic round-trip");
            assert_eq!(link.awg, again.awg, "case '{name}': awg round-trip");
            if link.awg {
                assert_eq!(link.jc, again.jc, "case '{name}': jc round-trip");
                assert_eq!(link.jmin, again.jmin, "case '{name}': jmin round-trip");
                assert_eq!(link.jmax, again.jmax, "case '{name}': jmax round-trip");
            }
        }
    }
}
