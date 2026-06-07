use super::*;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientConfig {
    #[serde(default)]
    pub server: ServerConnConfig,
    #[serde(default)]
    pub auth: ClientAuthConfig,
    #[serde(default)]
    pub tun: ClientTunConfig,
    #[serde(default)]
    pub routing: ClientRoutingConfig,
    #[serde(default)]
    pub dns: ClientDnsConfig,
    #[serde(default)]
    pub obfuscation: ClientObfuscationConfig,
    #[serde(default)]
    pub performance: ClientPerformanceConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ServerConnConfig {
    #[serde(default = "default_server_addr")]
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_conn_timeout")]
    pub connection_timeout_secs: u64,
    #[serde(default = "default_keepalive")]
    pub tcp_keepalive_secs: u64,
    #[serde(default)]
    pub reconnect: ReconnectConfig,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ReconnectConfig {
    /// Auto-reconnect after a disconnect. Default true: a client left running
    /// while the server is down will keep retrying (exponential backoff capped
    /// at max_delay_secs) and reattach once the server returns.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_retries_inf")]
    pub max_retries: i32,
    #[serde(default = "default_reconnect_base")]
    pub base_delay_secs: u64,
    #[serde(default = "default_reconnect_max")]
    pub max_delay_secs: u64,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientAuthConfig {
    #[serde(default = "default_client_user")]
    pub username: String,
    /// Password directly in the config (simplest). Takes precedence over
    /// password_file / password_command if set.
    pub password: Option<String>,
    pub password_file: Option<String>,
    pub password_command: Option<String>,
    /// Hex-encoded expected server static public key for MITM protection.
    /// Get it from the server log line "Server static public key (pin in Android): ...".
    /// If absent, the key is logged on first connect (TOFU) but not verified.
    pub server_public_key: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientTunConfig {
    #[serde(default = "default_client_tun_name")]
    pub name: String,
    /// TUN MTU. **`0` (default) = auto**: adopt the MTU the server pushes at
    /// auth; if the server is too old to push one, fall back to 1400. Any value
    /// `> 0` is an explicit override that wins over the server-pushed value.
    #[serde(default = "default_mtu")]
    pub mtu: i32,
    #[serde(default = "default_device_type")]
    pub device_type: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientRoutingConfig {
    #[serde(default = "default_routing_mode")]
    pub mode: String,
    /// Route ALL client traffic through the tunnel (install a default route via
    /// the tun). Use this to make the client a full-tunnel VPN. Default false:
    /// only the tunnel subnet + explicit `include` routes go through the tunnel.
    #[serde(default = "default_false")]
    pub add_default_gateway: bool,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Route private/local networks (RFC1918) through the tunnel. When `true`,
    /// the client adds the private ranges (10/8, 172.16/12, 192.168/16) and
    /// applies any networks the server pushed in its auth response, so LAN
    /// resources reachable behind the server work through the VPN. When `false`
    /// (default), local networks are NOT sent into the tunnel and server-pushed
    /// networks are ignored.
    #[serde(default = "default_false")]
    pub route_local_networks: bool,
    #[serde(default)]
    pub custom_routes: Vec<CustomRoute>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct CustomRoute {
    pub dest: String,
    #[serde(default = "default_route_via")]
    pub via: String,
    #[serde(default = "default_route_metric")]
    pub metric: u32,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientDnsConfig {
    #[serde(default = "default_dns_mode")]
    pub mode: String,
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default = "default_false")]
    pub redirect_all: bool,
    #[serde(default = "default_fallback_dns")]
    pub fallback_servers: Vec<String>,
    #[serde(default)]
    pub search_domains: Vec<String>,
    #[serde(default = "default_dns_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientObfuscationConfig {
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// Wire mode: "fake-tls" (default) or "obfs". Must match the server.
    #[serde(default = "default_wire_mode")]
    pub mode: String,
    /// Pre-shared key for "obfs" mode. Must match the server.
    #[serde(default)]
    pub obfs_key: String,
    /// `obfs` anti-FET fronting: "websocket" (default) or "none". Must match the
    /// server. See `ServerObfuscationConfig::fronting`.
    #[serde(default = "default_obfs_fronting")]
    pub fronting: String,
    /// REALITY short_id (hex). When set, the client sends a browser-like fake-TLS
    /// ClientHello carrying a REALITY auth token (built from this id + the pinned
    /// `auth.server_public_key`) in the session_id. Empty = no REALITY.
    #[serde(default)]
    pub reality_short_id: Option<String>,
    /// SNI to present in the fake-tls ClientHello. When empty, the client uses
    /// the connect hostname (or a random decoy SNI when connecting to a bare
    /// IP). Lets a QR/link pin a specific front domain.
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub padding: PaddingConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    #[serde(default)]
    pub fragmentation: FragmentationConfig,
    #[serde(default)]
    pub traffic_normalization: TrafficNormalizationConfig,
    #[serde(default)]
    pub quic: crate::config::QuicMaskingConfig,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientPerformanceConfig {
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u32,
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u32,
    #[serde(default = "default_tun_buf")]
    pub tun_buffer_size: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

fn default_server_addr() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    443
}
fn default_protocol() -> String {
    "tcp".into()
}
fn default_conn_timeout() -> u64 {
    30
}
fn default_max_retries_inf() -> i32 {
    -1
}
fn default_reconnect_base() -> u64 {
    1
}
fn default_reconnect_max() -> u64 {
    60
}
fn default_client_user() -> String {
    "client".into()
}
fn default_client_tun_name() -> String {
    "vpn0".into()
}
fn default_routing_mode() -> String {
    "split-tunnel".into()
}
fn default_route_via() -> String {
    "10.0.0.1".into()
}
fn default_route_metric() -> u32 {
    100
}
fn default_dns_mode() -> String {
    "tunnel".into()
}
fn default_fallback_dns() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}
fn default_cipher() -> String {
    "chacha20-poly1305".into()
}
fn default_wire_mode() -> String {
    "fake-tls".into()
}
fn default_obfs_fronting() -> String {
    "websocket".into()
}
fn default_keepalive() -> u64 {
    60
}
/// Client TUN MTU default: `0` = auto (adopt the server-pushed MTU; fall back to
/// 1400 if none is pushed). Set a positive value in the config/link to override.
fn default_mtu() -> i32 {
    0
}
/// Fallback MTU when the client is on auto (mtu=0) and the server pushed nothing
/// (e.g. an older server). 1400 matches the server's own default TUN MTU.
pub const MTU_AUTO_FALLBACK: i32 = 1400;
fn default_dns_timeout() -> u64 {
    5
}
fn default_idle_timeout() -> u64 {
    300
}
fn default_device_type() -> String {
    "tun".into()
}

use crate::config::format::IniDoc;
use crate::config::share::ClientLink;

/// A fully-defaulted client config.
///
/// `ClientConfig::default()` (derive) yields zero/empty fields because the real
/// defaults live in serde `#[serde(default = "...")]` functions, which only fire
/// during deserialization when the containing object is present. So we
/// deserialize a skeleton with every nested object spelled out as `{}` to make
/// serde apply each per-field default (mtu=1500, routing.mode="split-tunnel", …).
fn baseline() -> ClientConfig {
    const SKELETON: &str = r#"{
        "server":{"reconnect":{}},
        "auth":{},
        "tun":{},
        "routing":{},
        "dns":{},
        "obfuscation":{"padding":{},"fragmentation":{},"heartbeat":{},"traffic_normalization":{},"quic":{}},
        "performance":{},
        "logging":{}
    }"#;
    serde_json::from_str(SKELETON).expect("baseline client config skeleton is valid")
}

impl ClientConfig {
    /// Build a minimal client config from the new flat-INI `[qeli]` section.
    ///
    /// Only connection essentials live in the file; everything else (routes,
    /// DNS, MTU, obfuscation parameters) is defaulted here and overwritten by
    /// the server at handshake time. This is the format a `qeli://` QR expands
    /// into.
    ///
    /// ```ini
    /// [qeli]
    /// server = vpn.example.com:443
    /// proto  = tcp                 ; tcp | udp
    /// user   = alice
    /// pass   = p@ss
    /// key    = 0a33..23a           ; pinned server pubkey (optional, TOFU if absent)
    /// mode   = fake-tls            ; fake-tls | obfs
    /// sni    = www.cloudflare.com  ; optional, fake-tls only
    /// obfs_key = shared-secret     ; optional, obfs only
    /// mtu    = 0                   ; optional; 0 = auto (use server-pushed MTU)
    ///
    /// [logging]                    ; optional
    /// level = info
    /// ```
    pub fn from_ini(doc: &IniDoc) -> anyhow::Result<ClientConfig> {
        let q = doc
            .section("qeli")
            .ok_or_else(|| anyhow::anyhow!("client config: missing [qeli] section"))?;

        let server = q
            .get("server")
            .ok_or_else(|| anyhow::anyhow!("[qeli] missing required key 'server'"))?;
        let (address, port) = split_host_port(server)?;

        let mut cfg = baseline();
        cfg.server.address = address;
        cfg.server.port = port;
        cfg.server.protocol = q.get_or("proto", "tcp").to_string();

        cfg.auth.username = q.get_or("user", "client").to_string();
        cfg.auth.password = q.get("pass").filter(|p| !p.is_empty()).map(str::to_string);
        cfg.auth.server_public_key = q.get("key").filter(|k| !k.is_empty()).map(str::to_string);

        cfg.obfuscation.mode = q.get_or("mode", "fake-tls").to_string();
        cfg.obfuscation.obfs_key = q.get_or("obfs_key", "").to_string();
        cfg.obfuscation.fronting = q.get_or("front", "websocket").to_string();
        cfg.obfuscation.reality_short_id =
            q.get("reality_sid").filter(|s| !s.is_empty()).map(str::to_string);
        cfg.obfuscation.quic.enabled =
            matches!(q.get("quic"), Some("true") | Some("1") | Some("yes"));
        cfg.obfuscation.sni = q.get("sni").filter(|s| !s.is_empty()).map(str::to_string);

        // TUN/TAP interface name (default vpn0). Lets the user avoid clashing with
        // an existing interface or run more than one client on a host.
        if let Some(d) = q.get("dev").filter(|s| !s.is_empty()) {
            cfg.tun.name = d.to_string();
        }

        // TUN MTU. Omitted or 0 = auto (adopt the server-pushed MTU); a positive
        // value is an explicit override.
        if let Some(m) = q.get("mtu").and_then(|s| s.trim().parse::<i32>().ok()) {
            cfg.tun.mtu = m;
        }

        // Route private/local networks (RFC1918 + server-pushed) through the VPN.
        cfg.routing.route_local_networks =
            matches!(q.get("route_local"), Some("true") | Some("1") | Some("yes"));

        if let Some(log) = doc.section("logging") {
            cfg.logging.level = log.get_or("level", "info").to_string();
            cfg.logging.file = log
                .get("file")
                .filter(|f| !f.is_empty())
                .map(str::to_string);
        }
        Ok(cfg)
    }

    /// Project the connection essentials into a [`ClientLink`] (for emitting a
    /// `qeli://` share URI / QR).
    pub fn to_link(&self, label: Option<String>) -> ClientLink {
        ClientLink {
            host: self.server.address.clone(),
            port: self.server.port,
            user: self.auth.username.clone(),
            pass: self.auth.password.clone().unwrap_or_default(),
            proto: self.server.protocol.clone(),
            mode: self.obfuscation.mode.clone(),
            server_key: self.auth.server_public_key.clone().unwrap_or_default(),
            sni: self.obfuscation.sni.clone(),
            reality_sid: self.obfuscation.reality_short_id.clone(),
            obfs_key: Some(self.obfuscation.obfs_key.clone()).filter(|s| !s.is_empty()),
            // Only emit `front` when it diverges from the default, keeping links compact.
            fronting: Some(self.obfuscation.fronting.clone()).filter(|s| s != "websocket"),
            quic: self.obfuscation.quic.enabled,
            mtu: self.tun.mtu,
            label,
        }
    }

    /// Expand a scanned/imported [`ClientLink`] into a full client config
    /// (defaults for everything the link does not carry).
    pub fn from_link(link: &ClientLink) -> ClientConfig {
        let mut cfg = baseline();
        cfg.server.address = link.host.clone();
        cfg.server.port = link.port;
        cfg.server.protocol = if link.proto.is_empty() {
            "tcp".into()
        } else {
            link.proto.clone()
        };
        cfg.auth.username = if link.user.is_empty() {
            "client".into()
        } else {
            link.user.clone()
        };
        cfg.auth.password = Some(link.pass.clone()).filter(|s| !s.is_empty());
        cfg.auth.server_public_key = Some(link.server_key.clone()).filter(|s| !s.is_empty());
        cfg.obfuscation.mode = if link.mode.is_empty() {
            "fake-tls".into()
        } else {
            link.mode.clone()
        };
        cfg.obfuscation.obfs_key = link.obfs_key.clone().unwrap_or_default();
        cfg.obfuscation.fronting = link
            .fronting
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "websocket".into());
        cfg.obfuscation.quic.enabled = link.quic;
        cfg.obfuscation.sni = link.sni.clone();
        cfg.obfuscation.reality_short_id = link.reality_sid.clone();
        // 0 = auto (adopt server-pushed MTU); a positive value overrides.
        cfg.tun.mtu = link.mtu;
        cfg
    }

    /// Render this config's `[qeli]` section back to INI text (the inverse of
    /// [`from_ini`], emitting only the minimal keys).
    pub fn to_ini_string(&self) -> String {
        use crate::config::format::Section;
        let mut doc = IniDoc::new();
        let mut q = Section::new("qeli", None);
        q.set(
            "server",
            format!("{}:{}", self.server.address, self.server.port),
        )
        .set("proto", &self.server.protocol)
        .set("user", &self.auth.username);
        if let Some(p) = &self.auth.password {
            q.set("pass", p);
        }
        if let Some(k) = &self.auth.server_public_key {
            q.set("key", k);
        }
        q.set("mode", &self.obfuscation.mode);
        if let Some(sni) = &self.obfuscation.sni {
            q.set("sni", sni);
        }
        if !self.obfuscation.obfs_key.is_empty() {
            q.set("obfs_key", &self.obfuscation.obfs_key);
        }
        if self.obfuscation.fronting != "websocket" {
            q.set("front", &self.obfuscation.fronting);
        }
        if self.obfuscation.quic.enabled {
            q.set("quic", "true");
        }
        if self.routing.route_local_networks {
            q.set("route_local", "true");
        }
        if self.tun.name != "vpn0" {
            q.set("dev", &self.tun.name);
        }
        // Emit mtu only when explicitly overridden (>0). 0/absent = auto = adopt
        // the server-pushed MTU.
        if self.tun.mtu > 0 {
            q.set("mtu", self.tun.mtu.to_string());
        }
        doc.push(q);
        doc.to_string()
    }
}

/// Split `host:port` (IPv4/hostname). Returns an error if the port is missing
/// or not a `u16`.
fn split_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("'server' must be host:port, got '{}'", s))?;
    if host.is_empty() {
        anyhow::bail!("'server' has empty host: '{}'", s);
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("'server' has invalid port: '{}'", s))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod ini_tests {
    use super::*;

    #[test]
    fn minimal_qeli_section() {
        let src = "\
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = alice
pass   = p@ss
key    = 0a33d308295d5dc49bff020ca8a73e86b3f6797cbcc7d3aa440eee754729223a
mode   = fake-tls
sni    = www.cloudflare.com
";
        let doc = IniDoc::parse(src).unwrap();
        let c = ClientConfig::from_ini(&doc).unwrap();
        assert_eq!(c.server.address, "vpn.example.com");
        assert_eq!(c.server.port, 443);
        assert_eq!(c.server.protocol, "tcp");
        assert_eq!(c.auth.username, "alice");
        assert_eq!(c.auth.password.as_deref(), Some("p@ss"));
        assert!(c.auth.server_public_key.is_some());
        assert_eq!(c.obfuscation.mode, "fake-tls");
        assert_eq!(c.obfuscation.sni.as_deref(), Some("www.cloudflare.com"));
        // untouched fields keep their defaults (server will push the real ones);
        // mtu defaults to 0 = auto (adopt the server-pushed MTU)
        assert_eq!(c.tun.mtu, 0);
        assert_eq!(c.routing.mode, "split-tunnel");
    }

    #[test]
    fn link_round_trip_through_config() {
        let src = "[qeli]\nserver = 1.2.3.4:8443\nproto = udp\nuser = bob\npass = x\nmode = obfs\nobfs_key = shared\n";
        let c = ClientConfig::from_ini(&IniDoc::parse(src).unwrap()).unwrap();
        let link = c.to_link(Some("Edge".into()));
        let uri = link.to_uri();
        let c2 = ClientConfig::from_link(&ClientLink::from_uri(&uri).unwrap());
        assert_eq!(c2.server.address, "1.2.3.4");
        assert_eq!(c2.server.port, 8443);
        assert_eq!(c2.server.protocol, "udp");
        assert_eq!(c2.auth.username, "bob");
        assert_eq!(c2.obfuscation.mode, "obfs");
        assert_eq!(c2.obfuscation.obfs_key, "shared");
    }

    #[test]
    fn ini_string_reparses() {
        let src = "[qeli]\nserver = h:443\nproto = tcp\nuser = u\npass = p\nmode = fake-tls\n";
        let c = ClientConfig::from_ini(&IniDoc::parse(src).unwrap()).unwrap();
        let out = c.to_ini_string();
        let c2 = ClientConfig::from_ini(&IniDoc::parse(&out).unwrap()).unwrap();
        assert_eq!(c2.server.address, "h");
        assert_eq!(c2.auth.username, "u");
    }

    #[test]
    fn dev_tun_name_parses_and_round_trips() {
        // No `dev` key -> default vpn0.
        let def = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:443\nuser = u\npass = p\n").unwrap(),
        )
        .unwrap();
        assert_eq!(def.tun.name, "vpn0");
        // Explicit `dev` -> that name, and it survives an INI round-trip.
        let c = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:443\nuser = u\npass = p\ndev = vpn7\n").unwrap(),
        )
        .unwrap();
        assert_eq!(c.tun.name, "vpn7");
        let back = ClientConfig::from_ini(&IniDoc::parse(&c.to_ini_string()).unwrap()).unwrap();
        assert_eq!(back.tun.name, "vpn7");
    }
}
