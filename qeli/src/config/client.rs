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
    /// Auto-connect this profile when the supervisor (panel) starts. Set it in the
    /// panel's Client tab OR directly with `autostart = true` in `[qeli]`. The client
    /// runtime itself ignores it — it's read by the panel's client manager at boot.
    #[serde(default)]
    pub autostart: bool,
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
    /// Read the password from this file's contents (trimmed). Lower precedence than
    /// `password`.
    pub password_file: Option<String>,
    /// Run this command via `sh -c` and use its stdout (trimmed) as the password — for
    /// integrating a secret manager (`pass`, `vault`, …). TRUSTED INPUT: it runs with
    /// the client's own privileges, and its output is the credential, so it is never
    /// logged. Lowest precedence (after `password` and `password_file`).
    pub password_command: Option<String>,
    /// Hex-encoded expected server static public key for MITM protection.
    /// Get it from the server log line "Server static public key (pin in Android): ...".
    /// If absent, the key is logged on first connect (TOFU) but not verified.
    pub server_public_key: Option<String>,
    /// Bind the data-plane keys to the server's static identity (H-1): the session
    /// KDF folds in the static-ephemeral DH. Must match the server's
    /// `auth.bind_static_to_session`, and REQUIRES `server_public_key` to be pinned.
    /// WIRE-BREAKING. **Default true (secure-by-default since 0.7.1)** — pin the
    /// server key, or set `bind_static = false` to talk to a legacy 0.7.0 server.
    #[serde(default = "default_true")]
    pub bind_static_to_session: bool,
    /// Escape hatch for TOFU on a host with an UNWRITABLE `known_hosts` store.
    /// When `false` (default), an unpinned client that cannot persist the pin
    /// fails CLOSED (aborts the connect) rather than silently accepting any key,
    /// closing the first-connect MITM window. Set `true` only on ephemeral/
    /// read-only hosts where you accept unauthenticated TOFU; pinning
    /// `server_public_key` is always the safer alternative.
    #[serde(default = "default_false")]
    pub allow_unpinned_tofu: bool,
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
    /// Active path-MTU probing on **UDP** transports when `mtu = 0` (auto). The
    /// client sends DF-marked probe datagrams from the server-pushed ceiling
    /// downward and sets the tunnel MTU to the largest that traverses the path
    /// unfragmented — so a narrow LTE/CGNAT path is discovered instead of guessed.
    /// Default `true`. Set `false` to keep auto = "just adopt the pushed MTU" (no
    /// probing) — a kill switch if a network mishandles the probes. No effect on
    /// TCP transports (the kernel does PMTUD there) or when `mtu > 0` (explicit).
    #[serde(default = "default_true")]
    pub mtu_probe: bool,
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
    /// Firewall kill-switch (Linux/iptables): when `true` AND full-tunnel, block
    /// ALL egress except loopback, the tun device, DHCP and the VPN server's IP —
    /// so a tunnel drop can't leak traffic onto the physical interface during the
    /// reconnect window. The iptables chain persists across reconnects and is removed
    /// only on a clean stop (a crash leaves it = fail-safe). Default false.
    #[serde(default = "default_false")]
    pub kill_switch: bool,
    /// Escape hatch for the kill-switch on hosts without `ip6tables`: by default the
    /// kill-switch FAILS CLOSED (refuses to engage, so the client won't connect) when
    /// this host has a global IPv6 address but `ip6tables` is unavailable — otherwise
    /// IPv6 egress would leak onto the physical link while the switch reports ENGAGED.
    /// Set `true` to connect anyway and accept the IPv6 leak (e.g. an IPv4-only server
    /// on a host where IPv6 is disabled by other means). Default false.
    #[serde(default = "default_false")]
    pub allow_ipv6_leak: bool,
    /// Gateway/router NAT (Linux/iptables). When `true`, the client programs
    /// `ip_forward` + `MASQUERADE` out the tun device + a FORWARD accept + a TCP
    /// MSS-clamp, so a LAN *behind* this client reaches the internet through the
    /// tunnel without any manual iptables. Idempotent (verified with `-C`),
    /// (re)applied on start, removed on a clean stop; a crash leaves it (fail-safe,
    /// like the kill-switch). Linux-only. Default false.
    #[serde(default = "default_false")]
    pub gateway_nat: bool,
    /// Restrict `gateway_nat` to this source CIDR (e.g. `192.168.254.0/24`) —
    /// only that LAN is masqueraded. Empty = masquerade everything leaving the tun.
    #[serde(default)]
    pub lan_subnet: String,
    /// Command run once when the client starts, AFTER the kill-switch/gateway NAT
    /// is in place (Linux only, runs as the client's user — typically root). Use
    /// for custom routing/firewall. SECURITY: honoured ONLY from a trusted local
    /// config file (root-owned, not world-writable); the panel/API never writes it.
    #[serde(default)]
    pub post_up: String,
    /// Command run on a clean stop (SIGINT/SIGTERM / reconnect disabled), mirroring
    /// `post_up`. Same security rules. A crash does NOT run it.
    #[serde(default)]
    pub post_down: String,
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
    /// Flow-shaping cover traffic (client->server idle cover; DPI-AUDIT 6.1/6.2).
    /// Normally received pushed from the server, not set locally.
    #[serde(default)]
    pub traffic_shaping: crate::config::TrafficShapingConfig,
    #[serde(default)]
    pub quic: crate::config::QuicMaskingConfig,
    /// AmneziaWG-style junk-record pre-handshake (obfs mode only; F2). Must match
    /// the server's `jc`. Off by default.
    #[serde(default)]
    pub awg: crate::config::AwgConfig,
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
/// serde apply each per-field default (mtu=0 = auto, routing.mode="split-tunnel", …).
fn baseline() -> ClientConfig {
    const SKELETON: &str = r#"{
        "server":{"reconnect":{}},
        "auth":{},
        "tun":{},
        "routing":{},
        "dns":{},
        "obfuscation":{"padding":{},"fragmentation":{},"heartbeat":{},"traffic_normalization":{},"quic":{},"awg":{}},
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
    /// key    = 0a33..23a           ; pinned server pubkey (REQUIRED unless bind_static=false)
    /// bind_static = true           ; H-1, on by default; false = unpinned/TOFU client
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
        // Connection tuning — honored by the client but previously not parsed from the
        // file (ghost keys): TCP keepalive probe interval and Nagle's-algorithm toggle.
        cfg.server.tcp_keepalive_secs = q.parse_or("keepalive", cfg.server.tcp_keepalive_secs);
        cfg.performance.tcp_nodelay = q.bool_or("tcp_nodelay", cfg.performance.tcp_nodelay);

        cfg.auth.username = q.get_or("user", "client").to_string();
        cfg.auth.password = q.get("pass").filter(|p| !p.is_empty()).map(str::to_string);
        // File / command password sources (headless clients that don't inline the
        // secret). Honored by the client (client/mod.rs) but were never parsed from the
        // config file — a documented key that silently did nothing until now.
        cfg.auth.password_file = q
            .get("password_file")
            .filter(|p| !p.is_empty())
            .map(str::to_string);
        cfg.auth.password_command = q
            .get("password_command")
            .filter(|p| !p.is_empty())
            .map(str::to_string);
        cfg.auth.server_public_key = q.get("key").filter(|k| !k.is_empty()).map(str::to_string);
        // H-1: bind the session keys to the server's static identity. ON by default
        // (baseline already true); requires a pinned `key`. Set `bind_static = false`
        // for an unpinned/TOFU client or to talk to a legacy 0.7.0 server.
        cfg.auth.bind_static_to_session = q.bool_or("bind_static", cfg.auth.bind_static_to_session);
        // Escape hatch (default OFF = fail closed): allow accept-any TOFU when the
        // known_hosts store is unwritable and no key is pinned. See client/mod.rs.
        cfg.auth.allow_unpinned_tofu =
            q.bool_or("allow_unpinned_tofu", cfg.auth.allow_unpinned_tofu);

        cfg.obfuscation.mode = q.get_or("mode", "fake-tls").to_string();
        cfg.obfuscation.obfs_key = q.get_or("obfs_key", "").to_string();
        cfg.obfuscation.fronting = q.get_or("front", "websocket").to_string();
        cfg.obfuscation.reality_short_id = q
            .get("reality_sid")
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        cfg.obfuscation.quic.enabled = q.bool_or("quic", cfg.obfuscation.quic.enabled);
        cfg.obfuscation.sni = q.get("sni").filter(|s| !s.is_empty()).map(str::to_string);

        // AmneziaWG junk-record pre-handshake (F2, obfs mode). `awg` toggles it,
        // `jc`/`jmin`/`jmax` size the junk. jc must match the server. Clamped below.
        cfg.obfuscation.awg.enabled = q.bool_or("awg", cfg.obfuscation.awg.enabled);
        cfg.obfuscation.awg.jc = q.parse_or("jc", cfg.obfuscation.awg.jc);
        cfg.obfuscation.awg.jmin = q.parse_or("jmin", cfg.obfuscation.awg.jmin);
        cfg.obfuscation.awg.jmax = q.parse_or("jmax", cfg.obfuscation.awg.jmax);
        cfg.obfuscation.awg.sanitize("client obfuscation");

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
        // Active UDP path-MTU probing when mtu=0. Default ON — fall back to `true`
        // explicitly (not cfg.tun.mtu_probe, which is derive-Default `false` here).
        cfg.tun.mtu_probe = q.bool_or("mtu_probe", true);

        // Route private/local networks (RFC1918 + server-pushed) through the VPN.
        cfg.routing.route_local_networks =
            q.bool_or("route_local", cfg.routing.route_local_networks);

        // Firewall kill-switch (Linux/iptables, full-tunnel only) — block egress
        // leaks while the tunnel is down. A file key, not in the qeli:// link.
        cfg.routing.kill_switch = q.bool_or("kill_switch", cfg.routing.kill_switch);
        cfg.routing.allow_ipv6_leak = q.bool_or("allow_ipv6_leak", cfg.routing.allow_ipv6_leak);

        // Ключи для роутера/шлюза (только в файле, в qeli://-ссылку НЕ входят —
        // она для телефонов):
        //   gateway = true → full-tunnel: весь трафик в VPN (клиент ставит default
        //     через tun; в паре с NAT на роутере это заворачивает весь LAN). Дефолт
        //     off (split-tunnel — только подсеть туннеля).
        //   dns = off → НЕ управлять резолвером хоста: на роутере /etc/resolv.conf
        //     принадлежит прошивке (ndnsproxy/dnsmasq). dns.rs делает early-return
        //     при mode != "tunnel". Дефолт "tunnel".
        cfg.routing.add_default_gateway = q.bool_or("gateway", cfg.routing.add_default_gateway);
        if let Some(d) = q.get("dns").filter(|s| !s.is_empty()) {
            cfg.dns.mode = d.to_string();
        }

        // Gateway/router NAT + hooks — file-only keys (NOT in the qeli:// link).
        //   gateway_nat = true → client programs ip_forward + MASQUERADE out the tun
        //     so a LAN behind it reaches the internet through the tunnel (router mode).
        //   lan_subnet = <CIDR> → restrict that NAT to one source subnet.
        //   post_up / post_down → custom commands at start / clean stop (root).
        cfg.routing.gateway_nat = q.bool_or("gateway_nat", cfg.routing.gateway_nat);
        if let Some(s) = q.get("lan_subnet").filter(|s| !s.is_empty()) {
            cfg.routing.lan_subnet = s.to_string();
        }
        if let Some(s) = q.get("post_up").filter(|s| !s.is_empty()) {
            cfg.routing.post_up = s.to_string();
        }
        if let Some(s) = q.get("post_down").filter(|s| !s.is_empty()) {
            cfg.routing.post_down = s.to_string();
        }

        // Explicit per-CIDR routing lists (file-only; JSON configs set the same fields).
        // Comma-separated CIDRs. `exclude` carves specific subnets OUT of the tunnel
        // (routed via the physical gateway, so it works even in full-tunnel); `include`
        // forces subnets INTO the tunnel (split-tunnel). Malformed entries are dropped.
        if let Some(s) = q.get("exclude").filter(|s| !s.is_empty()) {
            cfg.routing.exclude = parse_cidr_list(s);
        }
        if let Some(s) = q.get("include").filter(|s| !s.is_empty()) {
            cfg.routing.include = parse_cidr_list(s);
        }

        // Auto-connect this profile when the supervisor/panel starts. File-level key
        // (also toggled by the panel's Client tab) — the `qeli client` runtime ignores
        // it; the client manager reads it at boot.
        cfg.autostart = matches!(
            q.get("autostart"),
            Some("true") | Some("1") | Some("yes") | Some("on")
        );

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
            // AmneziaWG junk (F2): only carried in the link when enabled.
            awg: self.obfuscation.awg.enabled,
            jc: self.obfuscation.awg.jc,
            jmin: self.obfuscation.awg.jmin,
            jmax: self.obfuscation.awg.jmax,
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
        // AmneziaWG junk (F2) from the link; clamp defensively.
        cfg.obfuscation.awg.enabled = link.awg;
        cfg.obfuscation.awg.jc = link.jc;
        cfg.obfuscation.awg.jmin = link.jmin;
        cfg.obfuscation.awg.jmax = link.jmax;
        cfg.obfuscation.awg.sanitize("client link");
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
        // Only emit when disabled — H-1 is on by default, so this preserves an
        // explicit opt-out across a config → INI → config round-trip.
        if !self.auth.bind_static_to_session {
            q.set("bind_static", "false");
        }
        // Only emit when enabled — the secure default (fail-closed) stays absent.
        if self.auth.allow_unpinned_tofu {
            q.set("allow_unpinned_tofu", "true");
        }
        if let Some(pf) = &self.auth.password_file {
            q.set("password_file", pf);
        }
        if let Some(pc) = &self.auth.password_command {
            q.set("password_command", pc);
        }
        // Connection-tuning ghosts: emit only when non-default (keepalive 60s, nodelay on)
        // so default configs stay compact.
        if self.server.tcp_keepalive_secs != 60 {
            q.set("keepalive", self.server.tcp_keepalive_secs.to_string());
        }
        if !self.performance.tcp_nodelay {
            q.set("tcp_nodelay", "false");
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
        // AmneziaWG junk (F2): emit only when enabled, keeping default configs compact.
        if self.obfuscation.awg.enabled {
            q.set("awg", "true");
            q.set("jc", self.obfuscation.awg.jc.to_string());
            q.set("jmin", self.obfuscation.awg.jmin.to_string());
            q.set("jmax", self.obfuscation.awg.jmax.to_string());
        }
        if self.routing.route_local_networks {
            q.set("route_local", "true");
        }
        if !self.routing.include.is_empty() {
            q.set("include", &self.routing.include.join(", "));
        }
        if !self.routing.exclude.is_empty() {
            q.set("exclude", &self.routing.exclude.join(", "));
        }
        if self.routing.kill_switch {
            q.set("kill_switch", "true");
        }
        if self.routing.allow_ipv6_leak {
            q.set("allow_ipv6_leak", "true");
        }
        if self.routing.add_default_gateway {
            q.set("gateway", "true");
        }
        if self.routing.gateway_nat {
            q.set("gateway_nat", "true");
        }
        if !self.routing.lan_subnet.is_empty() {
            q.set("lan_subnet", &self.routing.lan_subnet);
        }
        if !self.routing.post_up.is_empty() {
            q.set("post_up", &self.routing.post_up);
        }
        if !self.routing.post_down.is_empty() {
            q.set("post_down", &self.routing.post_down);
        }
        if self.dns.mode != "tunnel" {
            q.set("dns", &self.dns.mode);
        }
        if self.tun.name != "vpn0" {
            q.set("dev", &self.tun.name);
        }
        // Emit mtu only when explicitly overridden (>0). 0/absent = auto = adopt
        // the server-pushed MTU.
        if self.tun.mtu > 0 {
            q.set("mtu", self.tun.mtu.to_string());
        }
        // Emit only the non-default (disabled); default true stays implicit.
        if !self.tun.mtu_probe {
            q.set("mtu_probe", "false");
        }
        if self.autostart {
            q.set("autostart", "true");
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

/// Split a comma-separated CIDR list and keep only well-formed entries. These values
/// are spliced into `ip route ...` argument lines, so a malformed token is dropped
/// rather than passed through (defence against argument injection).
fn parse_cidr_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| is_cidr(p))
        .map(str::to_string)
        .collect()
}

/// True only for a bare `addr/prefix` CIDR: no leading `-` (an `ip` option), the address
/// parses as an `IpAddr`, and the prefix is in range for its family.
fn is_cidr(s: &str) -> bool {
    if s.starts_with('-') {
        return false;
    }
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(pfx) = prefix.parse::<u8>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(_) => pfx <= 32,
        std::net::IpAddr::V6(_) => pfx <= 128,
    }
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

    #[test]
    fn awg_junk_keys_parse_clamp_and_round_trip() {
        // Enabled with in-range values: parsed as-is and survive INI + link round-trips.
        let src = "[qeli]\nserver = h:443\nuser = u\npass = p\nmode = obfs\nawg = true\njc = 4\njmin = 50\njmax = 200\n";
        let c = ClientConfig::from_ini(&IniDoc::parse(src).unwrap()).unwrap();
        assert!(c.obfuscation.awg.enabled);
        assert_eq!(c.obfuscation.awg.jc, 4);
        assert_eq!(c.obfuscation.awg.jmin, 50);
        assert_eq!(c.obfuscation.awg.jmax, 200);
        // INI round-trip.
        let back = ClientConfig::from_ini(&IniDoc::parse(&c.to_ini_string()).unwrap()).unwrap();
        assert!(back.obfuscation.awg.enabled);
        assert_eq!(back.obfuscation.awg.jc, 4);
        assert_eq!(back.obfuscation.awg.jmin, 50);
        assert_eq!(back.obfuscation.awg.jmax, 200);
        // qeli:// link round-trip carries awg/jc/jmin/jmax.
        let uri = c.to_link(None).to_uri();
        let c2 = ClientConfig::from_link(&ClientLink::from_uri(&uri).unwrap());
        assert!(c2.obfuscation.awg.enabled);
        assert_eq!(c2.obfuscation.awg.jc, 4);
        assert_eq!(c2.obfuscation.awg.jmin, 50);
        assert_eq!(c2.obfuscation.awg.jmax, 200);

        // Out-of-range values are clamped at load (jc<=128, jmax<=1400, jmin<=jmax).
        let bad = "[qeli]\nserver = h:443\nuser = u\npass = p\nawg = true\njc = 999\njmin = 5000\njmax = 9000\n";
        let c = ClientConfig::from_ini(&IniDoc::parse(bad).unwrap()).unwrap();
        assert_eq!(c.obfuscation.awg.jc, 128);
        assert_eq!(c.obfuscation.awg.jmax, 1400);
        assert_eq!(c.obfuscation.awg.jmin, 1400); // clamped down to jmax

        // jc=0 / awg absent => disabled default, and NO awg keys in the emitted INI
        // (regression guard: the disabled path must stay byte-identical / compact).
        let d = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:443\nuser = u\npass = p\n").unwrap(),
        )
        .unwrap();
        assert!(!d.obfuscation.awg.enabled);
        assert_eq!(d.obfuscation.awg.jc, 0);
        let ini = d.to_ini_string();
        assert!(
            !ini.contains("awg"),
            "disabled awg must not emit any awg key, got:\n{ini}"
        );
    }

    #[test]
    fn router_gateway_and_dns_keys() {
        // gateway/dns — файловые ключи для роутера (full-tunnel + не трогать DNS).
        let src = "[qeli]\nserver = h:443\nuser = u\npass = p\ngateway = true\ndns = off\n";
        let c = ClientConfig::from_ini(&IniDoc::parse(src).unwrap()).unwrap();
        assert!(c.routing.add_default_gateway);
        assert_eq!(c.dns.mode, "off");
        // переживают round-trip через to_ini_string()
        let back = ClientConfig::from_ini(&IniDoc::parse(&c.to_ini_string()).unwrap()).unwrap();
        assert!(back.routing.add_default_gateway);
        assert_eq!(back.dns.mode, "off");
        // дефолты без ключей: split-tunnel + dns=tunnel
        let d = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:443\nuser = u\npass = p\n").unwrap(),
        )
        .unwrap();
        assert!(!d.routing.add_default_gateway);
        assert_eq!(d.dns.mode, "tunnel");
    }

    #[test]
    fn security_bools_accept_all_bool_spellings_and_fail_closed_on_garbage() {
        // kill_switch must honor yes/on/True (previously fail-open OFF),
        // and fall back to its default (false) on an unrecognized value.
        for tok in ["yes", "on", "True", "1"] {
            let ini = format!("[qeli]\nserver = h:1\nkill_switch = {tok}\n");
            let doc = IniDoc::parse(&ini).unwrap();
            let c = ClientConfig::from_ini(&doc).unwrap();
            assert!(
                c.routing.kill_switch,
                "kill_switch should be ON for {tok:?}"
            );
        }
        let doc = IniDoc::parse("[qeli]\nserver = h:1\nkill_switch = maybe\n").unwrap();
        let c = ClientConfig::from_ini(&doc).unwrap();
        assert!(
            !c.routing.kill_switch,
            "kill_switch should default OFF on garbage"
        );
        // bind_static (default ON) must stay ON when absent.
        assert!(c.auth.bind_static_to_session);

        // allow_ipv6_leak: default OFF (kill-switch fails closed on the IPv6 leg),
        // honours bool spellings, and survives a to_ini_string() round-trip.
        assert!(
            !c.routing.allow_ipv6_leak,
            "allow_ipv6_leak must default OFF (fail-closed)"
        );
        let on = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:1\nallow_ipv6_leak = yes\n").unwrap(),
        )
        .unwrap();
        assert!(
            on.routing.allow_ipv6_leak,
            "allow_ipv6_leak should be ON for 'yes'"
        );
        let back = ClientConfig::from_ini(&IniDoc::parse(&on.to_ini_string()).unwrap()).unwrap();
        assert!(
            back.routing.allow_ipv6_leak,
            "allow_ipv6_leak must round-trip through to_ini_string"
        );
    }

    #[test]
    fn ghost_keys_parse_and_round_trip() {
        // password_file / password_command / keepalive / tcp_nodelay were honored by the
        // client but never parsed from the file (6.1) — a documented key that silently
        // did nothing. They must now parse AND survive a to_ini_string() round-trip.
        let ini = "[qeli]\nserver = h:443\nuser = u\npassword_file = /etc/qeli/pw\n\
                   password_command = pass show qeli\nkeepalive = 15\ntcp_nodelay = false\n";
        let c = ClientConfig::from_ini(&IniDoc::parse(ini).unwrap()).unwrap();
        assert_eq!(c.auth.password_file.as_deref(), Some("/etc/qeli/pw"));
        assert_eq!(c.auth.password_command.as_deref(), Some("pass show qeli"));
        assert_eq!(c.server.tcp_keepalive_secs, 15);
        assert!(!c.performance.tcp_nodelay);
        let back = ClientConfig::from_ini(&IniDoc::parse(&c.to_ini_string()).unwrap()).unwrap();
        assert_eq!(back.auth.password_file.as_deref(), Some("/etc/qeli/pw"));
        assert_eq!(
            back.auth.password_command.as_deref(),
            Some("pass show qeli")
        );
        assert_eq!(back.server.tcp_keepalive_secs, 15);
        assert!(!back.performance.tcp_nodelay);

        // Defaults stay ABSENT from a serialized default config (compactness).
        let d =
            ClientConfig::from_ini(&IniDoc::parse("[qeli]\nserver = h:443\n").unwrap()).unwrap();
        let s = d.to_ini_string();
        assert!(
            !s.contains("keepalive"),
            "default keepalive must not be emitted"
        );
        assert!(
            !s.contains("tcp_nodelay"),
            "default tcp_nodelay must not be emitted"
        );
    }
}
