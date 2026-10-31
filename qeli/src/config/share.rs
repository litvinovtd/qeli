//! `qeli://` share links — the compact, QR-friendly representation of the
//! minimal client config, modelled on the VLESS/Trojan URI scheme so existing
//! QR scanners and the Android app can import a connection in one shot.
//!
//! Shape:
//! ```text
//! qeli://<user>:<pass>@<host>:<port>?proto=tcp&mode=fake-tls&key=<hex>&sni=<host>&obfs=<key>#<label>
//! ```
//!
//! Everything in [`ClientLink`] is the connection descriptor needed before the
//! authenticated server push: credentials, endpoint, pinned key and the wire/framing
//! settings that must already match. NetworkPlan supplies tunnel addresses, routes, DNS
//! and the automatic inner MTU after auth; an explicit client MTU may appear here as an
//! override. Device-local policy such as per-app routing deliberately stays in flat INI.
//!
//! Pure `std` (manual percent-encoding, no `url` crate), so it builds and is
//! tested on every platform.

/// The minimal, QR-encodable client connection descriptor. It is the portable
/// connection-bearing subset of the larger flat-INI `[qeli]` section.
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
    /// Client session-migration policy (`off`, `auto`, or `required`). `auto` is
    /// the default and is omitted from compact links; non-default policy must
    /// survive sharing between clients.
    pub roaming: String,
    /// Local acceptance of pushed routes. True/absent preserves legacy behavior.
    pub pull_routes: bool,
    /// Human label shown in the client UI (URI fragment).
    pub label: Option<String>,
}

/// Parse an operator-supplied public endpoint. IPv6 literals use the URI-compatible
/// `[address]:port` form when a port is present; a bare literal inherits `default_port`.
fn supported_dns_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    let without_root_dot = host.strip_suffix('.').unwrap_or(host);
    if without_root_dot.is_empty() {
        return false;
    }
    without_root_dot.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// One host grammar for client INI, share links and panel public endpoints.
/// Names are ASCII (use IDNA/Punycode for internationalized DNS names); underscores
/// retain compatibility with existing local hostnames. IPv6 is passed unbracketed.
pub(crate) fn supported_endpoint_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok() || supported_dns_host(host)
}

/// TLS DNS names deliberately exclude bare IPs and the fake-TLS marker tokens.
pub(crate) fn valid_tls_hostname(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// The legacy client `sni` key is an HTTP Host override for WebSocket obfs.
/// Keep this grammar identical for server link generation and client admission.
pub(crate) fn valid_websocket_host(value: &str) -> bool {
    value.len() <= 253
        && value.is_ascii()
        && value.trim() == value
        && (value.parse::<std::net::IpAddr>().is_ok() || valid_tls_hostname(value))
}

pub fn supported_public_endpoint(input: &str, default_port: u16) -> Result<(String, u16), String> {
    let value = input.trim();
    if value.is_empty() {
        return Err("public endpoint is empty".into());
    }
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or_else(|| {
            format!("invalid public endpoint '{value}' (missing closing IPv6 bracket)")
        })?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| format!("invalid IPv6 public endpoint address in '{value}'"))?;
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')
                .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
                .ok_or_else(|| format!("invalid public endpoint '{value}' (expected [IPv6]:port)"))?
                .parse::<u16>()
                .map_err(|_| format!("invalid public endpoint port in '{value}'"))?
        };
        (host.to_string(), port)
    } else if value.parse::<std::net::Ipv6Addr>().is_ok() {
        (value.to_string(), default_port)
    } else if value.matches(':').count() > 1 {
        return Err(format!(
            "invalid public endpoint '{value}' (IPv6 literals with a port must use [address]:port)"
        ));
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) => {
                if host.is_empty()
                    || port.is_empty()
                    || !port.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(format!(
                        "invalid public endpoint '{value}' (expected host or host:port)"
                    ));
                }
                let port = port
                    .parse::<u16>()
                    .map_err(|_| format!("invalid public endpoint port in '{value}'"))?;
                (host.to_string(), port)
            }
            None => (value.to_string(), default_port),
        }
    };
    if !supported_endpoint_host(&host) {
        return Err(format!(
            "invalid public endpoint host '{host}' (expected an IP address or DNS hostname)"
        ));
    }
    if port == 0 {
        return Err("public endpoint port must be 1..65535".into());
    }
    Ok((host, port))
}

/// SNI is also the HTTP Host override for TCP WebSocket obfs. Other obfs
/// carriers and plain TCP do not consume it. Keep this rule shared by both
/// client and server link generators and semantic validation.
pub(crate) fn uses_server_name(proto: &str, mode: &str, front: &str) -> bool {
    matches!(mode, "fake-tls" | "reality-tls")
        || (proto == "tcp" && mode == "obfs" && front == "websocket")
}

impl ClientLink {
    /// Derive every profile-dependent field of a share link from the profile itself,
    /// leaving the caller only what the profile cannot know: where the server is reachable
    /// from outside (`host`/`port`), who the link is for (`user`/`pass`), its pinned
    /// identity (`server_key`, loaded by the caller — this module must not depend on the
    /// server module, which does not exist in router/client-only builds) and the label.
    ///
    /// Single source of truth for the mapping. It previously existed as two hand-kept
    /// copies — the panel's `POST /api/share` and the CLI's `add-client --link` — which is
    /// exactly the kind of pair that silently diverges: a rule like "advertise awg only
    /// where the handshake actually sends junk" has to be repeated correctly in every
    /// copy, and a link that misstates the wire mode produces a client that cannot connect.
    #[allow(clippy::too_many_arguments)]
    pub fn for_profile(
        profile: &super::server::ProfileConfig,
        host: String,
        port: u16,
        user: String,
        pass: String,
        server_key: String,
        label: Option<String>,
    ) -> ClientLink {
        let obf = &profile.obfuscation;
        // A real-TLS REALITY profile → client wire mode `reality-tls`; a fake-tls
        // reality-proxy (peek-and-decide) profile keeps mode=fake-tls. In BOTH cases the
        // client must seal the reality short_id into its ClientHello so the server
        // recognises it instead of relaying to the real target — so carry `rsid` whenever
        // the reality proxy is enabled with a short_id, not only for real_tls.
        let rp = &obf.tls.reality_proxy;
        // BOTH conditions gate on `rp.enabled`.
        //
        // They used to disagree: the mode looked at `rp.real_tls` while the short_id looked
        // at `rp.enabled`. A profile with `reality_proxy.enabled = false` but
        // `real_tls = true` and a `short_ids` list passes `validate_profiles` untouched —
        // every REALITY check there is itself gated on `rp.enabled` — and this function,
        // the single source of truth for `qeli add-client --link`, `qeli share-link` and
        // the panel's /api/share, then emitted `mode = reality-tls` with NO `reality_sid`.
        //
        // Two failures from one line. The link is dead on arrival: the client refuses it
        // with "'mode = reality-tls' requires 'reality_sid'", and the message points at the
        // client rather than at the server config that produced it. Worse is the half that
        // still works — the link ADVERTISES the strongest masking mode for a profile on
        // which REALITY proxying is switched off, so the operator hands out, and the user
        // believes they have, resistance to active probing that is not there; the wire will
        // carry plain fake-TLS. (Audit 2026-08-04.)
        let reality_on = rp.enabled && !rp.short_ids.is_empty();
        let mode = if reality_on && rp.real_tls {
            "reality-tls".to_string()
        } else {
            obf.mode.clone()
        };
        let reality_sid = if reality_on {
            Some(rp.short_ids[0].clone())
        } else {
            None
        };
        // The proxy forwards probes to this target and borrows its TLS identity.
        // A separate server_name can disagree with it (including its default), so
        // generated REALITY links must derive SNI from the active target itself.
        let link_sni = if mode == "obfs" {
            // `sni` is the backwards-compatible URI/INI name for HTTP Host in
            // WebSocket obfs. Never copy TLS defaults or !/~/@ marker tokens here.
            obf.ws_host.clone()
        } else if reality_on {
            Some(rp.target.clone())
        } else {
            Some(obf.tls.server_name.clone())
        };
        ClientLink {
            host,
            port,
            user,
            pass,
            proto: profile.bind.transport.clone(),
            mode: mode.clone(),
            server_key,
            sni: link_sni.filter(|s| {
                !s.is_empty() && uses_server_name(&profile.bind.transport, &mode, &obf.fronting)
            }),
            reality_sid,
            obfs_key: Some(obf.obfs_key.clone()).filter(|s| !s.is_empty()),
            fronting: Some(obf.fronting.clone()).filter(|s| !s.is_empty() && s != "websocket"),
            quic: obf.quic.enabled,
            // mtu=0 (auto): the client adopts the server-pushed TUN MTU. Omitted from the
            // URI; set a non-zero value only to force a client-side override.
            mtu: 0,
            roaming: "auto".into(),
            pull_routes: true,
            label,
            // AmneziaWG-style junk masking. Junk is emitted only where the handshake
            // actually sends it: on TCP the obfs wire mode (protocol::obfs), and on UDP
            // every mode (jc junk datagrams before the ClientHello — sender-only). On TCP
            // fake-tls/reality-tls junk before the real TLS ClientHello would break the
            // mimicry, so the handshake never sends it — advertising awg there would be a
            // no-op that gives a false sense of masking.
            awg: obf.awg.enabled && (obf.mode == "obfs" || profile.bind.transport == "udp"),
            jc: obf.awg.jc,
            jmin: obf.awg.jmin,
            jmax: obf.awg.jmax,
        }
    }

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
        if !self.pull_routes {
            query.push(("pull_routes".into(), "0".into()));
        }
        if !self.roaming.is_empty() && self.roaming != "auto" {
            query.push(("roaming".into(), self.roaming.clone()));
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
        // The document service already caps imported INI and links at 256 KiB, but
        // direct callers (including the panel import API) bypass that entry point.
        // Bound the raw URI before percent decoding or splitting an attacker-sized query.
        if uri.len() > 256 * 1024 {
            return Err(LinkError("qeli:// link exceeds 256 KiB"));
        }
        let rest = uri
            .strip_prefix("qeli://")
            .ok_or(LinkError("missing qeli:// scheme"))?;

        // Split off fragment (#label), then query (?...).
        let (rest, fragment) = match rest.split_once('#') {
            Some((r, f)) => (r, Some(pct_decode(f)?)),
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
            h.parse::<std::net::Ipv6Addr>()
                .map_err(|_| LinkError("invalid IPv6 address"))?;
            (h, p)
        } else {
            let (h, p) = hostport
                .rsplit_once(':')
                .ok_or(LinkError("authority missing :port"))?;
            if h.contains(':') || h.contains('[') || h.contains(']') {
                return Err(LinkError("IPv6 authority must be [address]:port"));
            }
            (h, p)
        };
        if host.is_empty() {
            return Err(LinkError("empty host"));
        }
        if !supported_endpoint_host(host) {
            return Err(LinkError(
                "host must be an IP address or ASCII DNS hostname",
            ));
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
                Some((u, p)) => (pct_decode(u)?, pct_decode(p)?),
                None => (pct_decode(ui)?, String::new()),
            },
            None => (String::new(), String::new()),
        };

        let awg_defaults = crate::config::AwgConfig::default();
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
            jmin: awg_defaults.jmin,
            jmax: awg_defaults.jmax,
            mtu: 0,
            roaming: "auto".into(),
            pull_routes: true,
            label: fragment,
        };

        if let Some(q) = query {
            let mut seen = std::collections::HashSet::new();
            for pair in q.split('&').filter(|s| !s.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                let v = pct_decode(v)?;
                if matches!(
                    k,
                    "proto"
                        | "mode"
                        | "key"
                        | "sni"
                        | "rsid"
                        | "obfs"
                        | "front"
                        | "quic"
                        | "awg"
                        | "jc"
                        | "jmin"
                        | "jmax"
                        | "mtu"
                        | "roaming"
                        | "pull_routes"
                ) && !seen.insert(k)
                {
                    return Err(LinkError("duplicate connection parameter"));
                }
                match k {
                    "proto" => link.proto = v,
                    "mode" => link.mode = v,
                    "key" => link.server_key = v,
                    "sni" => link.sni = Some(v),
                    "rsid" => link.reality_sid = Some(v),
                    "obfs" => link.obfs_key = Some(v),
                    "front" => link.fronting = Some(v),
                    "quic" => link.quic = parse_link_bool(&v)?,
                    "pull_routes" => link.pull_routes = parse_link_bool(&v)?,
                    "awg" => link.awg = parse_link_bool(&v)?,
                    "jc" => link.jc = v.parse().map_err(|_| LinkError("invalid jc number"))?,
                    "jmin" => {
                        link.jmin = v.parse().map_err(|_| LinkError("invalid jmin number"))?
                    }
                    "jmax" => {
                        link.jmax = v.parse().map_err(|_| LinkError("invalid jmax number"))?
                    }
                    "mtu" => link.mtu = v.parse().map_err(|_| LinkError("invalid mtu number"))?,
                    "roaming" => match v.trim().to_ascii_lowercase().as_str() {
                        "off" | "auto" | "required" => link.roaming = v.trim().to_ascii_lowercase(),
                        _ => {
                            return Err(LinkError("roaming must be off, auto or required"));
                        }
                    },
                    _ => {} // forward-compatible: ignore unknown params
                }
            }
        }
        // Apply the same bounded AWG policy as client config loading before an
        // imported link is displayed, shared again or passed to the native core.
        let mut awg = crate::config::AwgConfig {
            enabled: link.awg,
            jc: link.jc,
            jmin: link.jmin,
            jmax: link.jmax,
        };
        awg.sanitize("qeli link");
        link.jc = awg.jc;
        link.jmin = awg.jmin;
        link.jmax = awg.jmax;
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

#[cfg(test)]
mod endpoint_tests {
    use super::supported_public_endpoint;

    #[test]
    fn accepts_supported_public_endpoints() {
        assert_eq!(
            supported_public_endpoint("vpn.example.com", 443).unwrap(),
            ("vpn.example.com".into(), 443)
        );
        assert_eq!(
            supported_public_endpoint("vpn.example.com:8443", 443).unwrap(),
            ("vpn.example.com".into(), 8443)
        );
        assert_eq!(
            supported_public_endpoint("198.51.100.8:9443", 443).unwrap(),
            ("198.51.100.8".into(), 9443)
        );
        assert_eq!(
            supported_public_endpoint("2001:db8::1", 443).unwrap(),
            ("2001:db8::1".into(), 443)
        );
        assert_eq!(
            supported_public_endpoint("[2001:db8::1]:8443", 443).unwrap(),
            ("2001:db8::1".into(), 8443)
        );
    }

    #[test]
    fn rejects_malformed_endpoints_and_invalid_ports() {
        for endpoint in [
            "[2001:db8::1",
            "[2001:db8::1]:nope",
            "2001:db8::1:443:garbage",
            "host:0",
            "host:nope",
            "evil@attacker.example",
            "host/path",
            "host?query",
            "host#fragment",
            "host name",
            "host%40name",
            ".example.com",
            "example..com",
            "-example.com",
            "example-.com",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
        ] {
            assert!(
                supported_public_endpoint(endpoint, 443).is_err(),
                "{endpoint} must be refused"
            );
        }
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

fn parse_link_bool(value: &str) -> Result<bool, LinkError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(LinkError("boolean must be true, false, 1 or 0")),
    }
}

/// Decode a complete UTF-8 value without silently changing credentials.
fn pct_decode(s: &str) -> Result<String, LinkError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let h = bytes.get(i + 1).copied().and_then(from_hex);
            let l = bytes.get(i + 2).copied().and_then(from_hex);
            let (Some(h), Some(l)) = (h, l) else {
                return Err(LinkError("invalid percent escape"));
            };
            out.push((h << 4) | l);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let value =
        String::from_utf8(out).map_err(|_| LinkError("percent-decoded value is not UTF-8"))?;
    // Validate before URI aliases, trimming or INI serialization can silently
    // remove a character and turn a malformed endpoint/key into a valid one.
    // Tabs remain lossless in quoted INI credentials and labels.
    if value.chars().any(|c| c.is_control() && c != '\t') {
        return Err(LinkError("unsupported control character in decoded value"));
    }
    Ok(value)
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
        let awg_defaults = crate::config::AwgConfig::default();
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
            jmin: awg_defaults.jmin,
            jmax: awg_defaults.jmax,
            mtu: 0,
            roaming: "auto".into(),
            pull_routes: true,
            label: Some("My VPN".into()),
        }
    }

    #[test]
    fn reality_share_sni_uses_target_even_when_fake_tls_name_differs() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.obfuscation.tls.server_name = "wrong.example".into();
        let rp = &mut profile.obfuscation.tls.reality_proxy;
        rp.enabled = true;
        rp.target = "decoy.example".into();
        rp.short_ids = vec!["0123456789abcdef".into()];
        let link = |profile: &crate::config::server::ProfileConfig| {
            ClientLink::for_profile(
                profile,
                "vpn.example".into(),
                443,
                "alice".into(),
                "password".into(),
                "0a33d308295d5dc49bff020ca8a73e86b3f6797cbcc7d3aa440eee754729223a".into(),
                None,
            )
        };
        for real_tls in [false, true] {
            profile.obfuscation.tls.reality_proxy.real_tls = real_tls;
            let generated = link(&profile);
            assert_eq!(generated.sni.as_deref(), Some("decoy.example"));
            assert_eq!(generated.reality_sid.as_deref(), Some("0123456789abcdef"));
            assert_eq!(
                ClientLink::from_uri(&generated.to_uri()).unwrap().sni,
                generated.sni
            );
        }
        profile.obfuscation.tls.reality_proxy.enabled = false;
        assert_eq!(link(&profile).sni.as_deref(), Some("wrong.example"));
    }

    #[test]
    fn profile_links_omit_only_unused_server_names() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        for (proto, mode, front, included) in [
            ("tcp", "fake-tls", "websocket", true),
            ("udp", "fake-tls", "websocket", true),
            ("tcp", "obfs", "websocket", false),
            ("tcp", "obfs", "none", false),
            ("udp", "obfs", "websocket", false),
            ("tcp", "plain", "websocket", false),
        ] {
            profile.bind.transport = proto.into();
            profile.obfuscation.mode = mode.into();
            profile.obfuscation.fronting = front.into();
            let link = ClientLink::for_profile(
                &profile,
                "vpn.example".into(),
                443,
                "user".into(),
                "pass".into(),
                "11".repeat(32),
                None,
            );
            assert_eq!(link.sni.is_some(), included, "{proto} {mode} {front}");
        }
    }

    #[test]
    fn websocket_links_never_inherit_tls_names_or_markers() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.obfuscation.mode = "obfs".into();
        profile.obfuscation.obfs_key = "test-key".into();
        for tls_name in ["www.cloudflare.com", "!", "~", "@", "decoy.example"] {
            profile.obfuscation.tls.server_name = tls_name.into();
            for host in [
                None,
                Some("front.example"),
                Some("192.0.2.5"),
                Some("2001:db8::5"),
            ] {
                profile.obfuscation.ws_host = host.map(str::to_string);
                let link = ClientLink::for_profile(
                    &profile,
                    "vpn.example".into(),
                    443,
                    "user".into(),
                    "pass".into(),
                    "11".repeat(32),
                    None,
                );
                assert_eq!(link.sni.as_deref(), host);
                let imported = crate::config::client::ClientConfig::from_link(
                    &ClientLink::from_uri(&link.to_uri()).unwrap(),
                );
                imported
                    .validate()
                    .expect("server link must pass native client admission");
                assert_eq!(
                    imported.effective_fronting_host(),
                    match host {
                        Some("2001:db8::5") => "[2001:db8::5]",
                        Some(value) => value,
                        None => "vpn.example",
                    }
                );
            }
        }
        for invalid in [
            "!",
            "~",
            "@",
            "https://front.example",
            "front.example:443",
            " front.example",
            "front.example\r\nX-Test: yes",
            "[2001:db8::5]",
        ] {
            assert!(!valid_websocket_host(invalid), "accepted {invalid:?}");
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
            roaming: "required".into(),
            pull_routes: true,
            label: None,
        };
        let back = ClientLink::from_uri(&link.to_uri()).unwrap();
        assert_eq!(back.mode, "obfs");
        assert_eq!(back.obfs_key.as_deref(), Some("shared-secret"));
        assert_eq!(back.fronting.as_deref(), Some("none"));
        assert!(back.quic);
        assert_eq!(back.server_key, "");
        assert_eq!(back.mtu, 1280);
        assert_eq!(back.roaming, "required");
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
        assert!(ClientLink::from_uri("qeli://u:p@2001:db8::443").is_err()); // bare IPv6
        assert!(ClientLink::from_uri("qeli://u:p@[2001:db8:::1]:443").is_err());
        assert!(ClientLink::from_uri("qeli://u:p@[vpn.example.com]:443").is_err());
    }

    #[test]
    fn rejects_oversized_uri_before_query_decoding() {
        let prefix = "qeli://u:p@host:443?future=";
        let at_limit = format!("{prefix}{}", "x".repeat(256 * 1024 - prefix.len()));
        assert!(ClientLink::from_uri(&at_limit).is_ok());
        let too_large = format!("{at_limit}x");
        assert_eq!(
            ClientLink::from_uri(&too_large).unwrap_err().0,
            "qeli:// link exceeds 256 KiB"
        );
    }

    #[test]
    fn rejects_controls_before_uri_normalization_or_ini_serialization() {
        for control in ["%00", "%07", "%0A", "%0D", "%7F", "%C2%85"] {
            let mut uris = vec![
                format!("qeli://u{control}:p@host:443"),
                format!("qeli://u:p{control}@host:443"),
                format!("qeli://u:p@host:443#name{control}"),
                format!("qeli://u:p@host:443?roaming={control}auto"),
                format!("qeli://u:p@host:443?proto=t{control}cp&mode=udp-quic"),
            ];
            for key in ["proto", "mode", "key", "sni", "rsid", "obfs", "front"] {
                uris.push(format!("qeli://u:p@host:443?{key}=x{control}y"));
            }
            for uri in uris {
                assert!(ClientLink::from_uri(&uri).is_err(), "{uri}");
            }
        }
        for control in ['\0', '\u{7}', '\t', '\n', '\r', '\u{7f}', '\u{85}'] {
            let uri = format!("qeli://u:p@exa{control}mple.com:443");
            assert!(ClientLink::from_uri(&uri).is_err());
        }
        let link = ClientLink::from_uri("qeli://u:p%09q@host:443#tab%09label").unwrap();
        assert_eq!(link.pass, "p\tq");
        assert_eq!(link.label.as_deref(), Some("tab\tlabel"));
    }

    #[test]
    fn rejects_malformed_authority_hosts() {
        for host in [
            "exa mple.com",
            "host/path",
            "host[",
            "-host",
            "host..example",
            "vpn%20example",
        ] {
            assert!(ClientLink::from_uri(&format!("qeli://u:p@{host}:443")).is_err());
        }
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
    //! Swift adapters. All clients now use this Rust parser; the fixtures continue to
    //! catch field loss or changed defaults at the FFI/model boundary. Historically,
    //! independent parsers disagreed even on whether port 0 was valid.
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
            // `front` picks the obfs framing, so losing it breaks the handshake rather
            // than degrading gracefully — and it was asserted by none of the four runners,
            // which is how C# came to parse it without ever emitting it.
            if let Some(v) = e.get("front") {
                assert!(
                    opt_eq(v, link.fronting.as_ref()),
                    "case '{name}': front = {:?}",
                    link.fronting
                );
            }
            // `mtu` has its own history of silent loss (Android emitted it with no case
            // to read it back), and no runner asserted it either.
            if let Some(v) = e.get("mtu").and_then(Value::as_i64) {
                assert_eq!(link.mtu, v as i32, "case '{name}': mtu");
            }
            if let Some(v) = e.get("roaming").and_then(Value::as_str) {
                assert_eq!(link.roaming, v, "case '{name}': roaming");
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
        let accepted: Vec<_> = fx["reject"]
            .as_array()
            .expect("reject[]")
            .iter()
            .filter(|c| ClientLink::from_uri(c["uri"].as_str().expect("case.uri")).is_ok())
            .map(|c| c["name"].as_str().unwrap_or("?"))
            .collect();
        assert!(
            accepted.is_empty(),
            "invalid fixtures accepted: {accepted:?}"
        );
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
            assert_eq!(
                link.roaming, again.roaming,
                "case '{name}': roaming round-trip"
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
