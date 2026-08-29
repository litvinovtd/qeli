use super::*;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientConfig {
    /// Session migration policy (`off|auto|required`).
    #[serde(default)]
    pub roaming: ClientRoamingPolicy,
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

impl Drop for ClientConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        // ClientConfig is cloned into reconnect/bonding owners. Wiping only ClientCore's
        // original copy left the same credentials in those heap allocations after teardown.
        // Put the guarantee on the type itself so every current and future clone is covered.
        self.auth.password.zeroize();
        self.auth.password_command.zeroize();
        self.obfuscation.obfs_key.zeroize();
    }
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
    /// OpenVPN-parity source binding for the primary Windows/macOS carrier.
    /// Mobile ports accept and preserve the keys but deliberately do not apply them.
    #[serde(default)]
    pub local_address: Option<String>,
    #[serde(default)]
    pub local_port: u16,
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
    /// If absent, the first server-proven key is persisted (TOFU) and verified on
    /// subsequent connections.
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
    /// fails CLOSED (aborts the connect) rather than silently continuing without a
    /// durable pin and reopening the MITM window on every connect. Set `true` only on ephemeral/
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
    /// Attach to a PRE-EXISTING interface (`name`/`dev`) that an external manager
    /// created and owns, instead of creating our own. qeli only opens it for packet IO:
    /// it does NOT create it, set its address, bring the link up, install routes, or
    /// delete it on teardown — L3 and routing belong to the owner (some managers only
    /// route through an interface they configured themselves). The server-assigned
    /// tunnel IP is written to `$QELI_TUNIP_FILE` (when set) so the owner can apply it.
    /// If the interface is absent at connect time, qeli errors and the reconnect loop
    /// retries. Default false (create and own the interface).
    #[serde(default = "default_false")]
    pub attach_existing: bool,
}

/// Client policy for accepting an inner IPv6 plan from the server.
///
/// This does not select the server profile's family mode. `required` fails closed when either
/// the server or the platform adapter cannot provide complete IPv6 support; `off` requests the
/// IPv4 side of a dual profile and refuses an IPv6-only profile.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClientIpv6Policy {
    #[default]
    Auto,
    Required,
    Off,
}

impl std::fmt::Display for ClientIpv6Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Required => "required",
            Self::Off => "off",
        })
    }
}

impl std::str::FromStr for ClientIpv6Policy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "required" => Ok(Self::Required),
            "off" => Ok(Self::Off),
            _ => Err(format!(
                "expected one of auto, required, off; got '{value}'"
            )),
        }
    }
}

/// Client policy for preserving a logical VPN session across carrier changes.
///
/// `auto` uses negotiated roaming when the server, core and platform expose the complete
/// contract and otherwise falls back to a normal reconnect. `required` fails closed instead of
/// reconnecting when safe migration is unavailable. `off` never advertises roaming capability.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClientRoamingPolicy {
    Off,
    #[default]
    Auto,
    Required,
}

impl std::fmt::Display for ClientRoamingPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Auto => "auto",
            Self::Required => "required",
        })
    }
}

impl std::str::FromStr for ClientRoamingPolicy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "auto" => Ok(Self::Auto),
            "required" => Ok(Self::Required),
            _ => Err(format!(
                "expected one of off, auto, required; got '{value}'"
            )),
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientRoutingConfig {
    /// Inner IPv6 acceptance policy (`auto|required|off`).
    #[serde(default)]
    pub ipv6: ClientIpv6Policy,
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
    /// Route private/local networks (RFC1918) through the tunnel: the BLANKET ranges
    /// (10/8, 172.16/12, 192.168/16), so LAN resources behind the server work through
    /// the VPN. `false` (the default) leaves them on the physical interface.
    ///
    /// It does NOT gate the server's pushed routes — those are applied either way since
    /// 0.7.12. This used to say they were ignored when `false`, which was the historical
    /// trap it describes: an operator pushing a route saw nothing happen and had to set
    /// this flag, which then also pulled in all of RFC1918. Only the blanket ranges are
    /// this flag's business now. (Audit 2026-08-02, follow-up.)
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
    /// Symmetric escape hatch for an IPv6-only full tunnel. The secure default blocks native
    /// IPv4 egress instead of silently bypassing the tunnel.
    #[serde(default = "default_false")]
    pub allow_ipv4_leak: bool,
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
    /// Optional IPv6 source prefix for gateway NAT/forwarding. Kept separate from
    /// `lan_subnet` so each firewall family receives a CIDR it can actually parse.
    #[serde(default)]
    pub lan_subnet_ipv6: String,
    /// #13: pure L3 forwarding for a LAN *behind* this client WITHOUT NAT — enable
    /// `ip_forward` + a FORWARD accept + MSS-clamp, but NO MASQUERADE, so the tunnel↔LAN
    /// transit keeps real source IPs (site-to-site routing). Use INSTEAD of `gateway_nat`
    /// when the far side has a route back to this LAN (the server's `client_subnets` for
    /// this user / `advertised_routes`). Linux/router only. Default false.
    #[serde(default = "default_false")]
    pub forward: bool,
    /// Exit-node (Linux/iptables). The MIRROR of `gateway_nat`: when `true`, this client
    /// forwards + MASQUERADEs traffic that arrived FROM the tunnel OUT its physical WAN, so
    /// OTHER tunnel clients reach the internet under THIS host's IP (e.g. a grey/NAT'd
    /// residential line). Pairs with the server: the profile needs `client_to_client` and
    /// this user needs `client_subnet = 0.0.0.0/0` (and `::/0` for IPv6). A consumer's
    /// matching server-side `route = .../0` is an authorization marker; the consumer opts
    /// into full-tunnel capture locally with `gateway = true`. This host must be
    /// SPLIT-tunnel (`gateway = false`) — its own
    /// internet stays on the WAN, which is what carries the forwarded traffic. Linux/router
    /// only. Default false.
    #[serde(default = "default_false")]
    pub exit_node: bool,
    /// Command run once after the first authenticated NetworkPlan has created the TUN
    /// and installed its active-family gateway/exit firewall (Linux only, runs as the
    /// client's user — typically root). Use
    /// for custom routing/firewall. SECURITY: honoured ONLY from a trusted local
    /// config file (root-owned, not world-writable); the panel/API never writes it.
    #[serde(default)]
    pub post_up: String,
    /// Command run on a clean stop (SIGINT/SIGTERM / reconnect disabled), mirroring
    /// `post_up`. Same security rules. A crash does NOT run it.
    #[serde(default)]
    pub post_down: String,
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
    /// Emit a compact X25519-only REALITY-TLS ClientHello. This keeps the full
    /// discriminator below one TCP MSS on mobile paths that drop a segmented
    /// post-quantum ClientHello. It affects only `mode = reality-tls`.
    #[serde(default)]
    pub reality_compact: bool,
    /// Split the REALITY-TLS ClientHello across writes to evade DPI that only
    /// parses the first payload segment. Values: empty/none, sni, record, first.
    #[serde(default)]
    pub reality_split: String,
    /// Delay between the two ClientHello writes when `reality_split` is active.
    #[serde(default = "default_reality_split_delay")]
    pub reality_split_delay_ms: u64,
    /// SNI/front host. When empty, fake-tls uses the connect hostname and omits
    /// SNI for a literal IP; WebSocket obfs uses the actual connect host. reality-tls
    /// requires a DNS name when the connect endpoint is an IP.
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

/// 4 MB: enough to absorb a scheduling stall at tunnel speeds without queueing so much
/// that latency suffers under sustained overload.
fn default_udp_recv_buffer() -> u32 {
    crate::transport_core::udp_buffer::AUTO_INITIAL_RECV_BYTES
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct ClientPerformanceConfig {
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
    /// `SO_SNDBUF`. `0` (the default) leaves the kernel value alone — deliberately: an
    /// undersized send buffer only applies backpressure, it never loses data, and pinning
    /// an explicit size here would *lower* it on a host whose `net.core.wmem_default` was
    /// raised for exactly this workload.
    #[serde(default)]
    pub send_buffer_size: u32,
    /// `SO_RCVBUF`. Unlike TCP, UDP has no buffer autotuning: the socket keeps whatever
    /// `net.core.rmem_default` was at creation (208 KB on a stock kernel), which at tunnel
    /// speeds is only tens of milliseconds of traffic — a stall then drops datagrams, and
    /// each lost datagram costs a TCP segment *inside* the tunnel. Hence a real default
    /// rather than "leave it alone". `0` opts back out to the kernel value.
    #[serde(default = "default_udp_recv_buffer")]
    pub recv_buffer_size: u32,
    /// Runtime policy bit, deliberately not a new INI key. An absent `recv_buffer_size`
    /// selects bounded auto-grow from the 4 MiB baseline; spelling the key explicitly keeps
    /// that exact value as a fixed manual override (including `0` = OS default).
    #[serde(skip, default = "default_true")]
    pub recv_buffer_auto: bool,
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
fn default_reality_split_delay() -> u64 {
    100
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
fn default_dns_mode() -> String {
    "tunnel".into()
}
/// EMPTY on purpose. This used to be `["1.1.1.1", "8.8.8.8"]`, which quietly cancelled the
/// R5 fix next to it in `client/dns.rs`: that code refuses to hand a user's DNS to a third
/// party when nothing is configured, but it consults `fallback_servers` first — so the default
/// meant the refusal could never fire and every query went to Cloudflare unasked. For a
/// censorship-circumvention tool that is a privacy decision the user did not make. With no
/// default, an unconfigured client keeps the host's resolvers (a warning says so), which is
/// also what GETTING-STARTED has always documented. (Audit 2026-07-30, #8.)
fn default_fallback_dns() -> Vec<String> {
    Vec::new()
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
        // The managed transports consumed these values before carrier ownership moved into
        // Rust. They must cross the native boundary now rather than becoming GUI ghost keys.
        cfg.server.connection_timeout_secs =
            q.parse_or("timeout", cfg.server.connection_timeout_secs);
        cfg.server.local_address = q
            .get("local")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        cfg.server.local_port = q.parse_or("lport", 0);
        cfg.roaming = q.parse_or("roaming", cfg.roaming);
        // Connection tuning — honored by the client but previously not parsed from the
        // file (ghost keys): TCP keepalive probe interval and Nagle's-algorithm toggle.
        cfg.server.tcp_keepalive_secs = q.parse_or("keepalive", cfg.server.tcp_keepalive_secs);
        cfg.performance.tcp_nodelay = q.bool_or("tcp_nodelay", cfg.performance.tcp_nodelay);
        // Socket buffers. Both fields existed in the model but nothing parsed them and
        // nothing applied them — dead knobs. They now size the UDP socket (see
        // client/mod.rs), where they matter most: UDP has no buffer autotuning, so an
        // undersized receive buffer silently drops datagrams under load.
        cfg.performance.recv_buffer_auto = q.get("recv_buffer_size").is_none();
        cfg.performance.recv_buffer_size =
            q.parse_or("recv_buffer_size", cfg.performance.recv_buffer_size);
        cfg.performance.send_buffer_size =
            q.parse_or("send_buffer_size", cfg.performance.send_buffer_size);

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
        // An ALL-ZERO key means TOFU, exactly as the shipped `client.conf` documents it
        // ("Empty / all-zero = TOFU"). Only the empty string was filtered here, so the zeros
        // became a real pin and `verify_server_key` compared the server's actual key against
        // them — every copy of the shipped example failed its first connect with
        // "SERVER KEY MISMATCH — possible MITM attack!", which is both wrong and the most
        // alarming way to be wrong. The C# port has always read it this way.
        // (Audit 2026-08-03, P2.)
        cfg.auth.server_public_key = q
            .get("key")
            .filter(|k| !k.is_empty() && k.chars().any(|c| c != '0'))
            .map(str::to_string);
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
        cfg.obfuscation.reality_compact =
            q.bool_or("reality_compact", cfg.obfuscation.reality_compact);
        cfg.obfuscation.reality_split = q.get_or("reality_split", "").to_string();
        cfg.obfuscation.reality_split_delay_ms = q.parse_or(
            "reality_split_delay",
            cfg.obfuscation.reality_split_delay_ms,
        );
        cfg.obfuscation.quic.enabled = q.bool_or("quic", cfg.obfuscation.quic.enabled);
        cfg.obfuscation.sni = q.get("sni").filter(|s| !s.is_empty()).map(str::to_string);

        // AmneziaWG junk-record pre-handshake (F2, obfs mode). `awg` toggles it,
        // `jc`/`jmin`/`jmax` size the junk. jc must match the server. Clamped below.
        cfg.obfuscation.awg.enabled = q.bool_or("awg", cfg.obfuscation.awg.enabled);
        cfg.obfuscation.awg.jc = q.parse_or("jc", cfg.obfuscation.awg.jc);
        cfg.obfuscation.awg.jmin = q.parse_or("jmin", cfg.obfuscation.awg.jmin);
        cfg.obfuscation.awg.jmax = q.parse_or("jmax", cfg.obfuscation.awg.jmax);
        cfg.obfuscation.awg.sanitize("client obfuscation");

        // Fallback data-plane values used when the server sends no obfuscation push. Every
        // GUI serializer kept writing these after the native migration; the shared parser
        // must read them or the profile silently falls back to unrelated Rust defaults.
        cfg.obfuscation.padding.enabled = q.bool_or("padding", cfg.obfuscation.padding.enabled);
        cfg.obfuscation.padding.min_bytes =
            q.parse_or("padding_min", cfg.obfuscation.padding.min_bytes);
        cfg.obfuscation.padding.max_bytes =
            q.parse_or("padding_max", cfg.obfuscation.padding.max_bytes);
        cfg.obfuscation.heartbeat.enabled =
            q.bool_or("heartbeat", cfg.obfuscation.heartbeat.enabled);
        cfg.obfuscation.heartbeat.interval_ms =
            q.parse_or("heartbeat_interval", cfg.obfuscation.heartbeat.interval_ms);
        cfg.obfuscation.heartbeat.data_size_bytes =
            q.parse_or("heartbeat_size", cfg.obfuscation.heartbeat.data_size_bytes);
        cfg.obfuscation.heartbeat.jitter_ms =
            q.parse_or("heartbeat_jitter", cfg.obfuscation.heartbeat.jitter_ms);
        cfg.obfuscation.traffic_shaping.enabled =
            q.bool_or("shaping", cfg.obfuscation.traffic_shaping.enabled);
        cfg.obfuscation.traffic_shaping.idle_gap_mean_ms = q.parse_or(
            "shaping_gap_mean",
            cfg.obfuscation.traffic_shaping.idle_gap_mean_ms,
        );
        cfg.obfuscation.traffic_shaping.idle_gap_min_ms = q.parse_or(
            "shaping_gap_min",
            cfg.obfuscation.traffic_shaping.idle_gap_min_ms,
        );
        cfg.obfuscation.traffic_shaping.idle_gap_max_ms = q.parse_or(
            "shaping_gap_max",
            cfg.obfuscation.traffic_shaping.idle_gap_max_ms,
        );
        cfg.obfuscation.traffic_shaping.budget_bytes_per_sec = q.parse_or(
            "shaping_budget",
            cfg.obfuscation.traffic_shaping.budget_bytes_per_sec,
        );
        cfg.obfuscation.traffic_shaping.min_size =
            q.parse_or("shaping_min_size", cfg.obfuscation.traffic_shaping.min_size);
        cfg.obfuscation.traffic_shaping.max_size =
            q.parse_or("shaping_max_size", cfg.obfuscation.traffic_shaping.max_size);
        cfg.obfuscation.traffic_shaping.stealth =
            q.bool_or("shaping_stealth", cfg.obfuscation.traffic_shaping.stealth);
        cfg.obfuscation.traffic_shaping.stealth_rate_mbps = q.parse_or(
            "shaping_stealth_mbps",
            cfg.obfuscation.traffic_shaping.stealth_rate_mbps,
        );

        // TUN/TAP interface name (default vpn0). Lets the user avoid clashing with
        // an existing interface or run more than one client on a host.
        if let Some(d) = q.get("dev").filter(|s| !s.is_empty()) {
            cfg.tun.name = d.to_string();
        }
        // Linux can create either an L3 TUN or an emulated L2 TAP. This field already
        // drives NetworkPlan prefixes, interface creation and packet framing; failing to
        // read it made every flat-INI client silently stay in the default TUN mode.
        if let Some(device_type) = q.get("device_type").filter(|value| !value.is_empty()) {
            cfg.tun.device_type = device_type.to_string();
        }
        // Attach to an existing, externally-owned interface named `dev` instead of
        // creating our own. See ClientTunConfig::attach_existing.
        cfg.tun.attach_existing = q.bool_or("dev_attach", cfg.tun.attach_existing);

        // TUN MTU. Omitted or 0 = auto (adopt the server-pushed MTU); a positive
        // value is an explicit override.
        // A present-but-unparseable `mtu = abc` used to fall through this `if` and leave the
        // MTU at auto — indistinguishable from having written nothing. Record it like any other
        // unreadable value so `validate()` refuses. (Audit 2026-07-31, §9.)
        if let Some(raw) = q.get("mtu").map(str::trim).filter(|s| !s.is_empty()) {
            if raw.parse::<i32>().is_err() {
                q.record_bad_value(format!(
                    "key 'mtu' has an unrecognised value '{raw}'; using auto"
                ));
            }
        }
        if let Some(m) = q.get("mtu").and_then(|s| s.trim().parse::<i32>().ok()) {
            // A positive override must fit one PacketCodec record before any negotiated UDP
            // DATA_FRAG splitting and must remain a plausible interface MTU. Reject negative,
            // tiny or over-format values instead of silently accepting them. This is the same
            // MTU_MIN..=MTU_MAX range used for the server-pushed MTU (0 stays "auto").
            if m != 0 && !crate::config::server::mtu_in_range(m as i64) {
                anyhow::bail!(
                    "invalid mtu {} — expected 0 (auto) or {}..={}",
                    m,
                    crate::config::server::MTU_MIN,
                    crate::config::server::MTU_MAX
                );
            }
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
        cfg.routing.ipv6 = q.parse_or("ipv6", cfg.routing.ipv6);
        cfg.routing.allow_ipv6_leak = q.bool_or("allow_ipv6_leak", cfg.routing.allow_ipv6_leak);
        cfg.routing.allow_ipv4_leak = q.bool_or("allow_ipv4_leak", cfg.routing.allow_ipv4_leak);

        // Ключи для роутера/шлюза (только в файле, в qeli://-ссылку НЕ входят —
        // она для телефонов):
        //   gateway = true → full-tunnel: весь трафик в VPN (клиент ставит default
        //     через tun; в паре с NAT на роутере это заворачивает весь LAN). Дефолт
        //     off (split-tunnel — только подсеть туннеля).
        //   dns = off → НЕ управлять резолвером хоста: на роутере /etc/resolv.conf
        //     принадлежит прошивке (ndnsproxy/dnsmasq). dns.rs делает early-return
        //     при mode != "tunnel". Дефолт "tunnel" и требует активный per-link
        //     systemd-resolved; постоянная подмена resolv.conf больше не допускается.
        cfg.routing.add_default_gateway = q.bool_or("gateway", cfg.routing.add_default_gateway);
        if let Some(d) = q.get("dns").filter(|s| !s.is_empty()) {
            cfg.dns.mode = d.to_string();
        }
        // dns_servers = <ip>[, <ip>…] → resolver(s) to install when `dns = tunnel` and the
        // server pushes none. Without this key the flat INI could set the MODE but never a
        // SERVER, so the "configure a resolver" advice was impossible to follow from an INI.
        if let Some(s) = q.get("dns_servers").filter(|s| !s.trim().is_empty()) {
            cfg.dns.servers = s
                .split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
        }

        // Gateway/router NAT + hooks — file-only keys (NOT in the qeli:// link).
        //   gateway_nat = true → client programs ip_forward + MASQUERADE out the tun
        //     so a LAN behind it reaches the internet through the tunnel (router mode).
        //   lan_subnet = <CIDR> → restrict that NAT to one source subnet.
        //   post_up / post_down → custom commands at start / clean stop (root).
        cfg.routing.gateway_nat = q.bool_or("gateway_nat", cfg.routing.gateway_nat);
        cfg.routing.forward = q.bool_or("forward", cfg.routing.forward);
        // exit_node = true → this client is an internet EXIT for other tunnel clients
        // (mirror of gateway_nat: MASQUERADE tun-forwarded traffic out the physical WAN).
        cfg.routing.exit_node = q.bool_or("exit_node", cfg.routing.exit_node);
        if let Some(s) = q.get("lan_subnet").filter(|s| !s.is_empty()) {
            cfg.routing.lan_subnet = s.to_string();
        }
        if let Some(s) = q.get("lan_subnet_ipv6").filter(|s| !s.is_empty()) {
            cfg.routing.lan_subnet_ipv6 = s.to_string();
        }
        if let Some(s) = q.get("post_up").filter(|s| !s.is_empty()) {
            cfg.routing.post_up = s.to_string();
        }
        if let Some(s) = q.get("post_down").filter(|s| !s.is_empty()) {
            cfg.routing.post_down = s.to_string();
        }

        // Explicit per-CIDR routing lists in the flat-INI client config.
        // Comma-separated CIDRs. `exclude` carves specific subnets OUT of the tunnel
        // (routed via the physical gateway, so it works even in full-tunnel); `include`
        // forces subnets INTO the tunnel (split-tunnel). A malformed entry is fatal: silently
        // changing either list changes the operator's routing/security policy.
        if let Some(s) = q.get("exclude").filter(|s| !s.is_empty()) {
            cfg.routing.exclude = parse_cidr_list("exclude", s)?;
        }
        if let Some(s) = q.get("include").filter(|s| !s.is_empty()) {
            cfg.routing.include = parse_cidr_list("include", s)?;
        }

        // Auto-connect this profile when the supervisor/panel starts. File-level key
        // (also toggled by the panel's Client tab) — the `qeli client` runtime ignores
        // it; the client manager reads it at boot.
        // Through the shared parser, not a hand-rolled `matches!`: that one was
        // case-SENSITIVE and knew no false-spellings, so `autostart = TRUE` read as false and
        // `autostart = ture` was never recorded as unparseable. (Audit 2026-07-31, §9.)
        cfg.autostart = q.bool_or("autostart", false);

        if let Some(log) = doc.section("logging") {
            cfg.logging.level = log.get_or("level", "info").to_string();
            cfg.logging.file = log
                .get("file")
                .filter(|f| !f.is_empty())
                .map(str::to_string);
            cfg.logging.time_format = log.get_or("time_format", "datetime").to_string();
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
        // 0 = auto (adopt server-pushed MTU); a positive value overrides. Validate the
        // same MTU_MIN..=MTU_MAX range `from_ini` enforces — a scanned/pasted `qeli://…?mtu=999999`
        // (or a negative) would otherwise become an out-of-range TUN MTU the file path
        // rejects. This entry point is infallible (returns ClientConfig, not Result), so an
        // out-of-range value falls back to auto rather than failing the import. (M6)
        cfg.tun.mtu = if link.mtu != 0 && !crate::config::server::mtu_in_range(link.mtu as i64) {
            log::warn!(
                "qeli:// link mtu {} is out of range (expected 0 or {}..={}) — using auto",
                link.mtu,
                crate::config::server::MTU_MIN,
                crate::config::server::MTU_MAX
            );
            0
        } else {
            link.mtu
        };
        cfg
    }

    /// Render this config's `[qeli]` section back to INI text (the inverse of
    /// [`from_ini`], emitting only the minimal keys).
    /// Reject unknown values for the string-enum fields, the same way `validate_profiles`
    /// does on the server.
    ///
    /// Every one of these is compared verbatim against ONE literal at its use site, so an
    /// unrecognised value does not error — it silently selects the other branch:
    ///
    ///   * `proto` — anything but exactly `udp` connects over TCP, so `proto = UDP` or a typo
    ///     quietly uses a different transport than the config says.
    ///   * `mode` — falls through the obfs / reality-tls / plain branches to fake-tls, so
    ///     `mode = realty-tls` runs fake-tls and the peer disagrees about the wire.
    ///   * `front` — compared against `websocket`, so `front = webscoket` drops the WebSocket
    ///     framing the profile was configured for.
    ///   * `dns` — DNS setup early-returns unless the mode is exactly `tunnel`, so `dns = of`
    ///     leaves the host resolver in place: in a full tunnel that is a DNS leak.
    ///   * `device_type` / routing `mode` — same shape, quieter consequences.
    ///
    /// The server got this treatment in #23; the client parser was left accepting anything.
    /// (Audit 2026-07-30, #7.)
    /// True when `dns` asks us NOT to touch the host resolver.
    ///
    /// Both `off` and `system` mean that; `tunnel` (the default) is the only mode that
    /// installs anything. Comparing against `"off"` alone was the bug this replaces — it made
    /// `system` fall through to the tunnel branch and apply the pushed resolver, which is the
    /// exact opposite of what the mode requests. A predicate rather than a string comparison
    /// so a future spelling is added in ONE place. (Audit 2026-08-02, follow-up.)
    pub fn leaves_resolver_alone(&self) -> bool {
        matches!(self.dns.mode.as_str(), "off" | "system")
    }

    /// Refuse credentials that cannot fit the AUTH message in one datagram.
    ///
    /// The AUTH goes out UNFRAGMENTED, unlike the ClientHello beside it and the AuthOK coming
    /// back. Its size was always small, so nobody bounded it — but nothing bounded the
    /// credentials either, and they are what it carries. A long generated token used as a
    /// password pushes the record past `MAX_CHUNK`, the datagram then needs IP fragmentation,
    /// and a mobile or CGNAT path drops it. The symptom is an endless handshake timeout that
    /// reproduces only on those networks: indistinguishable from a dead server, with nothing
    /// in either log.
    ///
    /// **Called twice, and it has to be.** `validate()` runs at config load, where only an
    /// inline `pass` exists; `password_file` and `password_command` are read at connect time,
    /// long after. The first version of this check lived inline in `validate()` and therefore
    /// bounded only the inline case — i.e. it covered the credential that is easy to eyeball
    /// and missed the ones these keys exist for, headless setups feeding in a long secret.
    /// `password` names which source is being judged so the error points at the right key.
    /// (Audit 2026-08-02, §3 and §2 of the follow-up.)
    ///
    /// TCP has no such limit, but the bound applies to both: profiles move between transports,
    /// and working on one while hanging on the other is the failure being removed here. The
    /// budget is enormous next to any real credential — a 64-character password uses ~6 % of
    /// it — so this rejects nothing legitimate.
    pub fn check_credential_size(&self, password: &str, source: &str) -> anyhow::Result<()> {
        // proof(32) + the optional [0x00 device_id(16)] prefix, then `user:pass`.
        const AUTH_OVERHEAD: usize = 32 + 17;
        let budget = crate::protocol::udp_frag::MAX_CHUNK - AUTH_OVERHEAD;
        let len = self.auth.username.len() + password.len() + 1; // + the ':' separator
        if len > budget {
            anyhow::bail!(
                "'user' + '{source}' are {len} bytes, over the {budget} a UDP AUTH datagram can \
                 carry — the handshake would be dropped by any path that discards IP fragments \
                 (mobile, CGNAT) and would look like an unreachable server. Shorten them."
            );
        }
        Ok(())
    }

    pub(crate) fn effective_fake_tls_sni(&self) -> &str {
        match self
            .obfuscation
            .sni
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            Some(value) => value,
            None if self.server.address.parse::<std::net::IpAddr>().is_ok() => "!",
            None => &self.server.address,
        }
    }

    pub(crate) fn effective_reality_sni(&self) -> &str {
        self.obfuscation
            .sni
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.server.address)
    }

    pub(crate) fn effective_fronting_host(&self) -> String {
        let host = self
            .obfuscation
            .sni
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.server.address);
        match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(_)) => format!("[{host}]"),
            _ => host.to_string(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        fn check(field: &str, got: &str, allowed: &[&str]) -> anyhow::Result<()> {
            if allowed.contains(&got) {
                return Ok(());
            }
            anyhow::bail!(
                "unknown {field} '{got}' — expected {}",
                allowed
                    .iter()
                    .map(|a| format!("'{a}'"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            )
        }

        fn valid_dns_hostname(value: &str) -> bool {
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

        // A value that is present is a cryptographic X25519 public key, not an opaque
        // label. The native adapters already reject malformed pins at import time; keep
        // the Rust CLI/panel on the same fail-closed rule instead of accepting a placeholder
        // and failing much later inside the handshake decoder.
        if let Some(raw) = self.auth.server_public_key.as_deref() {
            let key = raw.trim();
            if key.len() != 64
                || !key.chars().all(|c| c.is_ascii_hexdigit())
                || key.chars().all(|c| c == '0')
            {
                anyhow::bail!("'key' must be 64 hex digits and not all zero, got '{key}'");
            }
        }

        // Parsed as u16, so 0 slipped through: a port nothing can ever connect to. The panel
        // rejected it; a file-based start did not. (Audit 2026-07-31, §9.)
        if self.server.port == 0 {
            anyhow::bail!("'server' port must be 1..65535, got 0");
        }
        if !(1..=300).contains(&self.server.connection_timeout_secs) {
            anyhow::bail!(
                "'timeout' must be 1..300, got {}",
                self.server.connection_timeout_secs
            );
        }
        for (field, value) in [
            ("recv_buffer_size", self.performance.recv_buffer_size),
            ("send_buffer_size", self.performance.send_buffer_size),
        ] {
            if value > crate::transport_core::udp_buffer::MAX_CONFIGURED_SOCKET_BUFFER_BYTES {
                anyhow::bail!(
                    "'{field}' = {value} exceeds the per-socket UDP buffer limit {}",
                    crate::transport_core::udp_buffer::MAX_CONFIGURED_SOCKET_BUFFER_BYTES
                );
            }
        }
        if let Some(address) = self.server.local_address.as_deref() {
            address.parse::<std::net::IpAddr>().map_err(|_| {
                anyhow::anyhow!("'local' must be an IPv4 or IPv6 address, got '{address}'")
            })?;
        }

        if self.roaming == ClientRoamingPolicy::Required
            && (self.server.local_address.is_some() || self.server.local_port != 0)
        {
            anyhow::bail!(
                "'roaming = required' cannot be combined with an explicit 'local' address or non-zero 'lport': those values pin the carrier socket and make cross-interface migration impossible"
            );
        }

        // Only the INLINE password can be judged here. `password_file` / `password_command`
        // are resolved at connect time, so the client re-runs this on what they produced —
        // see `check_credential_size`, which exists precisely so the two callers cannot drift.
        self.check_credential_size(self.auth.password.as_deref().unwrap_or(""), "pass")?;
        check("proto", &self.server.protocol, &["tcp", "udp"])?;
        check(
            "mode",
            &self.obfuscation.mode,
            &["fake-tls", "obfs", "plain", "reality-tls"],
        )?;
        // Both fields are individually valid and the PAIR is not. The server refuses these two
        // combinations (server/mod.rs), so a client that accepts them cannot reach any working
        // profile — it just fails later and less clearly. Worse for `reality-tls`: nothing about
        // the name says TCP, so the operator believes they have the strongest masking available
        // while the datagram path quietly falls back to fake-tls framing.
        // (Audit 2026-08-03, P2.)
        if self.server.protocol == "udp" {
            if self.obfuscation.mode == "plain" {
                anyhow::bail!(
                    "'mode = plain' is TCP-only (raw framing has no datagram form) — set \
                     proto = tcp, or pick obfs/fake-tls for a UDP profile"
                );
            }
            if self.obfuscation.mode == "reality-tls" {
                anyhow::bail!(
                    "'mode = reality-tls' is TCP-only — it terminates a REAL TLS 1.3 session, \
                     which UDP cannot carry. Set proto = tcp, or pick obfs for a UDP profile"
                );
            }
        }
        if let Some(raw) = self.obfuscation.sni.as_deref() {
            let value = raw.trim();
            if value != raw || value.chars().any(char::is_control) {
                anyhow::bail!("'sni' contains surrounding whitespace or control characters");
            }
            match self.obfuscation.mode.as_str() {
                "fake-tls" if !matches!(value, "!" | "~" | "@") && !valid_dns_hostname(value) => {
                    anyhow::bail!("'sni' must be a DNS hostname or one of !, ~, @ for fake-tls");
                }
                "obfs"
                    if !valid_dns_hostname(value) && value.parse::<std::net::IpAddr>().is_err() =>
                {
                    anyhow::bail!("'sni' must be a DNS hostname or IP address for WebSocket obfs");
                }
                "reality-tls" if !valid_dns_hostname(value) => {
                    anyhow::bail!("'sni' must be a DNS hostname for reality-tls");
                }
                _ => {}
            }
        }
        if self.obfuscation.mode == "reality-tls"
            && !valid_dns_hostname(self.effective_reality_sni())
        {
            anyhow::bail!(
                "'mode = reality-tls' needs an explicit DNS 'sni' when 'server' is an IP; \
                 a random unrelated decoy would create an SNI-to-destination mismatch"
            );
        }
        // A mode that needs a secret must HAVE it, or the profile is valid and unusable.
        //
        // Each of these was checked at the use site or not at all, so `check-config` and the
        // GUIs called the profile fine and the failure surfaced mid-handshake — where it reads
        // as a server or network problem rather than a missing line in the file.
        //
        // The short_id is the sharpest case: this side parses hex LENIENTLY (non-hex characters
        // are dropped), the server parses it STRICTLY, so `reality_sid = deadbeeg` became
        // `deadbee` here and matched nothing there. Rejecting the malformed value is the only
        // way the two ends can agree about what was configured. (Audit 2026-08-03, P2.)
        if self.obfuscation.mode == "reality-tls" {
            check(
                "reality_split",
                &self.obfuscation.reality_split,
                &["", "none", "sni", "record", "first"],
            )?;
            if self.obfuscation.reality_split_delay_ms > 5_000 {
                anyhow::bail!("'reality_split_delay' must be 0..5000 ms");
            }
            let sid = self
                .obfuscation
                .reality_short_id
                .as_deref()
                .unwrap_or("")
                .trim();
            if sid.is_empty() {
                anyhow::bail!(
                    "'mode = reality-tls' requires 'reality_sid' — it is the token the server \
                     uses to tell qeli clients from probes; without it the server treats this \
                     client as a probe and proxies it to the decoy site"
                );
            }
            if !sid.len().is_multiple_of(2)
                || sid.len() > 16
                || !sid.chars().all(|c| c.is_ascii_hexdigit())
                || sid.chars().all(|c| c == '0')
            {
                anyhow::bail!(
                    "'reality_sid' must be 1..8 bytes of hex (2..16 hex digits, not all zero), \
                     got '{sid}' — this client parses hex leniently and the SERVER does not, so \
                     a malformed value silently becomes a different token and never matches"
                );
            }
            if self
                .auth
                .server_public_key
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                anyhow::bail!(
                    "'mode = reality-tls' requires a pinned server 'key' — REALITY's whole \
                     point is that an unauthenticated peer is proxied to the decoy site, which \
                     a TOFU client cannot tell apart from the real server"
                );
            }
            if !self.auth.bind_static_to_session {
                anyhow::bail!(
                    "'mode = reality-tls' requires 'bind_static = true' — the borrowed outer \
                     certificate is camouflage, not the server-authentication boundary; the \
                     pinned static key must be folded into the inner session keys"
                );
            }
        }
        if self.obfuscation.mode == "obfs" && self.obfuscation.obfs_key.trim().is_empty() {
            anyhow::bail!(
                "'mode = obfs' requires a non-empty 'obfs_key' — an empty key is publicly \
                 derivable, so the stream is obfuscated against nobody (the server refuses the \
                 same combination)"
            );
        }
        check("front", &self.obfuscation.fronting, &["websocket", "none"])?;
        // `tun_buffer_size` is the exact size of the buffer the TUN reader reads into, and
        // the client validated no numeric performance value at all — while the SERVER bails
        // on the very same class of value (`perf.tun.read_buffer_size`, server/mod.rs) with a
        // comment explaining exactly why. The asymmetry is the bug: the two ends read the
        // same kind of config and only one of them checked it.
        //
        // Zero is the worst case and the easiest to reach (an omitted section, a typo, a
        // profile from an older GUI): `libc::read` into an empty buffer returns Ok(0), the
        // reader treats that as EOF and exits — so the tunnel comes up, the interface is
        // created, routes and the kill-switch are applied, and nothing is ever read from TUN.
        // The user sees "connected" with no traffic, and with the kill-switch on that is a
        // total loss of connectivity with no diagnosable cause. Below the MTU is subtler:
        // every frame that fills the interface is silently truncated.
        // (Audit 2026-08-04.)
        {
            let is_tap = self.tun.device_type.eq_ignore_ascii_case("tap");
            // TAP frames carry a 14-byte Ethernet header on top of the IP MTU. With
            // `mtu = 0` the pushed MTU is unknown at load time, so this enforces the
            // absolute protocol floor; the TCP/UDP runtime expands the read buffer to the
            // negotiated MTU (plus TAP/utun framing) before starting the pump.
            let mtu = if self.tun.mtu > 0 {
                self.tun.mtu as usize
            } else {
                576
            };
            let min_buf = mtu + if is_tap { 14 } else { 0 };
            if self.performance.tun_buffer_size < min_buf {
                anyhow::bail!(
                    "'tun_buffer_size' = {} is smaller than {} ({} mtu {}{}) — every frame that \
                     fills the interface would be truncated, and 0 reads as EOF and stops the \
                     data plane while the tunnel still looks connected",
                    self.performance.tun_buffer_size,
                    min_buf,
                    if is_tap { "TAP" } else { "TUN" },
                    mtu,
                    if is_tap { " + 14 ethernet" } else { "" }
                );
            }
            // Same ceiling the server uses. Far above any real frame.
            const MAX_TUN_BUFFER: usize = 1024 * 1024;
            if self.performance.tun_buffer_size > MAX_TUN_BUFFER {
                anyhow::bail!(
                    "'tun_buffer_size' = {} exceeds {}",
                    self.performance.tun_buffer_size,
                    MAX_TUN_BUFFER
                );
            }
        }
        // `system` is an accepted SPELLING of `off`, not a third behaviour.
        //
        // The GUI ports have shipped it for a while and treat it exactly as `off` (leave the
        // device resolver alone), while this client rejected it at load and, had it got
        // through, would have fallen into the `tunnel` branch and applied the pushed resolver
        // — the opposite of what the word asks for. A profile is routinely moved between a
        // phone and the CLI, so the same file has to mean the same thing on both.
        // See `leaves_resolver_alone`. (Audit 2026-08-02, follow-up.)
        // A resolver LIST in `dns` is the desktop clients' old spelling — point at the right
        // key instead of just listing the modes. Without this the operator sees "expected
        // 'tunnel' or 'off' or 'system'" over a perfectly reasonable `dns = 1.1.1.1, 9.9.9.9`
        // and has no way to guess that the list belongs in `dns_servers`. Newer desktop builds
        // write the documented key; an older profile copied straight onto a router hits this.
        // (Audit 2026-08-03, D2.)
        if !["tunnel", "off", "system"].contains(&self.dns.mode.as_str())
            && self.dns.mode.contains('.')
        {
            anyhow::bail!(
                "'dns' is the resolver MODE ('tunnel', 'off' or 'system'), but this config has \
                 an address list in it: dns = {}. The list belongs in its own key — write \
                 `dns_servers = {}` and either drop `dns` or set `dns = tunnel`. (Older \
                 Windows/macOS builds wrote the list into `dns`; re-saving the profile in the \
                 current client migrates it.)",
                self.dns.mode,
                self.dns.mode
            );
        }
        check("dns", &self.dns.mode, &["tunnel", "off", "system"])?;
        for (source, servers) in [
            ("dns_servers", &self.dns.servers),
            ("fallback DNS", &self.dns.fallback_servers),
        ] {
            for server in servers {
                if server.trim().parse::<std::net::IpAddr>().is_err() {
                    anyhow::bail!("'{source}' contains invalid resolver '{server}'");
                }
            }
        }
        // `is_tap_mode` compares case-insensitively, so accept either spelling here rather
        // than rejecting a value the runtime would have honoured.
        check(
            "device_type",
            &self.tun.device_type.to_ascii_lowercase(),
            &["tun", "tap"],
        )?;
        #[cfg(not(target_os = "linux"))]
        if self.tun.device_type.eq_ignore_ascii_case("tap") {
            anyhow::bail!(
                "'device_type = tap' is supported only by the Linux client; this platform \
                 provides an L3 TUN interface"
            );
        }
        #[cfg(target_os = "linux")]
        {
            // TUNSETIFF accepts at most IFNAMSIZ-1 bytes and writes back the truncated name.
            // Every later `ip ... dev <configured-name>` call uses this exact string, so a
            // truncation or path-like value creates/configures two different names.
            const MAX_IFNAME_LEN: usize = 15;
            let name = self.tun.name.as_str();
            if name.is_empty()
                || name.len() > MAX_IFNAME_LEN
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\\')
                || name.contains('\0')
                || name.contains(char::is_whitespace)
            {
                anyhow::bail!(
                    "'dev = {}' is not a valid Linux interface name (use 1..={} bytes without whitespace, '/', '\\' or NUL)",
                    name,
                    MAX_IFNAME_LEN
                );
            }
        }
        if self.routing.ipv6 == ClientIpv6Policy::Required
            && self.tun.mtu > 0
            && self.tun.mtu < 1280
        {
            anyhow::bail!(
                "'ipv6 = required' needs an explicit 'mtu' of at least 1280 (or 0 for auto), got {}",
                self.tun.mtu
            );
        }
        check(
            "routing mode",
            &self.routing.mode,
            &["split-tunnel", "full-tunnel", "all"],
        )?;
        if self.routing.exit_node
            && (self.routing.add_default_gateway
                || self.routing.mode == "full-tunnel"
                || self.routing.mode == "all")
        {
            anyhow::bail!(
                "'exit_node = true' requires split-tunnel routing (`gateway = false` and `routing = split-tunnel`) so the physical WAN remains available"
            );
        }
        if !self.routing.lan_subnet.trim().is_empty()
            && self
                .routing
                .lan_subnet
                .trim()
                .parse::<ipnet::Ipv4Net>()
                .is_err()
        {
            anyhow::bail!(
                "'lan_subnet' must be one IPv4 CIDR (got '{}'); use lan_subnet_ipv6 for IPv6",
                self.routing.lan_subnet
            );
        }
        if !self.routing.lan_subnet_ipv6.trim().is_empty() {
            if self
                .routing
                .lan_subnet_ipv6
                .trim()
                .parse::<ipnet::Ipv6Net>()
                .is_err()
            {
                anyhow::bail!(
                    "'lan_subnet_ipv6' must be one IPv6 CIDR (got '{}')",
                    self.routing.lan_subnet_ipv6
                );
            }
            if self.routing.ipv6 == ClientIpv6Policy::Off {
                anyhow::bail!("'lan_subnet_ipv6' cannot be used with ipv6 = off");
            }
        }
        if self.obfuscation.padding.min_bytes > self.obfuscation.padding.max_bytes
            || self.obfuscation.padding.max_bytes > crate::config::MAX_PADDING_BYTES
        {
            anyhow::bail!(
                "padding range invalid: {}..{} (expected 0..{})",
                self.obfuscation.padding.min_bytes,
                self.obfuscation.padding.max_bytes,
                crate::config::MAX_PADDING_BYTES
            );
        }
        if self.obfuscation.heartbeat.interval_ms == 0 {
            anyhow::bail!("'heartbeat_interval' must be at least 1 ms");
        }
        let shaping = &self.obfuscation.traffic_shaping;
        if shaping.idle_gap_mean_ms == 0
            || shaping.idle_gap_min_ms == 0
            || shaping.idle_gap_max_ms == 0
            || shaping.budget_bytes_per_sec == 0
            || shaping.min_size == 0
            || shaping.max_size == 0
            || shaping.stealth_rate_mbps == 0
        {
            anyhow::bail!("shaping durations, sizes, budget and stealth rate must be positive");
        }
        if shaping.idle_gap_min_ms > shaping.idle_gap_max_ms || shaping.min_size > shaping.max_size
        {
            anyhow::bail!("shaping min/max range is inverted");
        }
        if shaping.enabled && shaping.budget_bytes_per_sec < u32::from(shaping.max_size) {
            anyhow::bail!(
                "shaping budget_bytes_per_sec ({}) must be at least max_size ({}) so each scheduled cover record can be emitted",
                shaping.budget_bytes_per_sec,
                shaping.max_size
            );
        }
        Ok(())
    }

    pub fn to_ini_string(&self) -> String {
        use crate::config::format::Section;
        let mut doc = IniDoc::new();
        let mut q = Section::new("qeli", None);
        q.set(
            "server",
            crate::util::join_host_port(&self.server.address, self.server.port),
        )
        .set("proto", &self.server.protocol)
        .set("user", &self.auth.username);
        if self.roaming != ClientRoamingPolicy::Auto {
            q.set("roaming", self.roaming.to_string());
        }
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
        if self.server.connection_timeout_secs != default_conn_timeout() {
            q.set("timeout", self.server.connection_timeout_secs.to_string());
        }
        if let Some(address) = self.server.local_address.as_deref() {
            q.set("local", address);
        }
        if self.server.local_port != 0 {
            q.set("lport", self.server.local_port.to_string());
        }
        if !self.performance.tcp_nodelay {
            q.set("tcp_nodelay", "false");
        }
        // Emit only when they differ from their serde defaults, so a config written from
        // defaults stays as sparse as it was before these keys became live.
        if !self.performance.recv_buffer_auto
            || self.performance.recv_buffer_size != default_udp_recv_buffer()
        {
            q.set(
                "recv_buffer_size",
                self.performance.recv_buffer_size.to_string(),
            );
        }
        if self.performance.send_buffer_size != 0 {
            q.set(
                "send_buffer_size",
                self.performance.send_buffer_size.to_string(),
            );
        }
        q.set("mode", &self.obfuscation.mode);
        if let Some(sni) = &self.obfuscation.sni {
            q.set("sni", sni);
        }
        if !self.obfuscation.obfs_key.is_empty() {
            q.set("obfs_key", &self.obfuscation.obfs_key);
        }
        // REALITY short-id was parse-only, so a config→INI→config cycle (the panel
        // client-manager / autostart persist path) silently dropped it and left a
        // reality-tls profile that fails to connect. Emit it for a lossless round-trip
        // (the qeli:// link already carries it as `rsid`).
        if let Some(sid) = &self.obfuscation.reality_short_id {
            q.set("reality_sid", sid);
        }
        if self.obfuscation.reality_compact {
            q.set("reality_compact", "true");
        }
        if !self.obfuscation.reality_split.is_empty() && self.obfuscation.reality_split != "none" {
            q.set("reality_split", &self.obfuscation.reality_split);
            q.set(
                "reality_split_delay",
                self.obfuscation.reality_split_delay_ms.to_string(),
            );
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
        if !self.obfuscation.padding.enabled {
            q.set("padding", "false");
        }
        if self.obfuscation.padding.min_bytes != 32 {
            q.set(
                "padding_min",
                self.obfuscation.padding.min_bytes.to_string(),
            );
        }
        if self.obfuscation.padding.max_bytes != 512 {
            q.set(
                "padding_max",
                self.obfuscation.padding.max_bytes.to_string(),
            );
        }
        if !self.obfuscation.heartbeat.enabled {
            q.set("heartbeat", "false");
        }
        if self.obfuscation.heartbeat.interval_ms != 15_000 {
            q.set(
                "heartbeat_interval",
                self.obfuscation.heartbeat.interval_ms.to_string(),
            );
        }
        if self.obfuscation.heartbeat.data_size_bytes != 16 {
            q.set(
                "heartbeat_size",
                self.obfuscation.heartbeat.data_size_bytes.to_string(),
            );
        }
        if self.obfuscation.heartbeat.jitter_ms != 20 {
            q.set(
                "heartbeat_jitter",
                self.obfuscation.heartbeat.jitter_ms.to_string(),
            );
        }
        let shaping = &self.obfuscation.traffic_shaping;
        if shaping.enabled {
            q.set("shaping", "true");
        }
        if shaping.idle_gap_mean_ms != 700 {
            q.set("shaping_gap_mean", shaping.idle_gap_mean_ms.to_string());
        }
        if shaping.idle_gap_min_ms != 40 {
            q.set("shaping_gap_min", shaping.idle_gap_min_ms.to_string());
        }
        if shaping.idle_gap_max_ms != 6_000 {
            q.set("shaping_gap_max", shaping.idle_gap_max_ms.to_string());
        }
        if shaping.budget_bytes_per_sec != 16_384 {
            q.set("shaping_budget", shaping.budget_bytes_per_sec.to_string());
        }
        if shaping.min_size != 64 {
            q.set("shaping_min_size", shaping.min_size.to_string());
        }
        if shaping.max_size != 1_024 {
            q.set("shaping_max_size", shaping.max_size.to_string());
        }
        if shaping.stealth {
            q.set("shaping_stealth", "true");
        }
        if shaping.stealth_rate_mbps != 2 {
            q.set(
                "shaping_stealth_mbps",
                shaping.stealth_rate_mbps.to_string(),
            );
        }
        if self.routing.route_local_networks {
            q.set("route_local", "true");
        }
        if !self.routing.include.is_empty() {
            q.set("include", self.routing.include.join(", "));
        }
        if !self.routing.exclude.is_empty() {
            q.set("exclude", self.routing.exclude.join(", "));
        }
        if self.routing.kill_switch {
            q.set("kill_switch", "true");
        }
        if self.routing.ipv6 != ClientIpv6Policy::Auto {
            q.set("ipv6", self.routing.ipv6.to_string());
        }
        if self.routing.allow_ipv6_leak {
            q.set("allow_ipv6_leak", "true");
        }
        if self.routing.allow_ipv4_leak {
            q.set("allow_ipv4_leak", "true");
        }
        if self.routing.add_default_gateway {
            q.set("gateway", "true");
        }
        if self.routing.gateway_nat {
            q.set("gateway_nat", "true");
        }
        if self.routing.forward {
            q.set("forward", "true");
        }
        if self.routing.exit_node {
            q.set("exit_node", "true");
        }
        if !self.routing.lan_subnet.is_empty() {
            q.set("lan_subnet", &self.routing.lan_subnet);
        }
        if !self.routing.lan_subnet_ipv6.is_empty() {
            q.set("lan_subnet_ipv6", &self.routing.lan_subnet_ipv6);
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
        if !self.dns.servers.is_empty() {
            q.set("dns_servers", self.dns.servers.join(", "));
        }
        if self.tun.name != "vpn0" {
            q.set("dev", &self.tun.name);
        }
        // Sparse default: Linux TUN is implicit. Canonicalize case so a value accepted by
        // the case-insensitive runtime does not produce multiple serialized spellings.
        if !self.tun.device_type.eq_ignore_ascii_case("tun") {
            q.set("device_type", self.tun.device_type.to_ascii_lowercase());
        }
        // Emit only when enabled (default false = own the interface).
        if self.tun.attach_existing {
            q.set("dev_attach", "true");
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
        // [logging]: the client PARSES this section (level / file / time_format,
        // honoured by the router/headless client) but used to never re-emit it, so
        // a config -> INI -> config cycle silently reset the user's logging choice —
        // the same read-but-not-persisted class as `reality_sid` and the server's
        // `time_format`. Emit only the non-defaults, so default configs stay compact
        // while an explicit choice round-trips losslessly.
        let mut lg = Section::new("logging", None);
        let mut any = false;
        if self.logging.level != "info" {
            lg.set("level", &self.logging.level);
            any = true;
        }
        if let Some(f) = &self.logging.file {
            if !f.is_empty() {
                lg.set("file", f);
                any = true;
            }
        }
        if self.logging.time_format != "datetime" {
            lg.set("time_format", &self.logging.time_format);
            any = true;
        }
        if any {
            doc.push(lg);
        }
        doc.to_string()
    }
}

/// Split `host:port` (IPv4 / hostname, or a bracketed IPv6 literal `[2001:db8::1]:443`).
/// Returns an error if the port is missing or not a `u16`.
fn split_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    // A bracketed IPv6 authority must be split on `]:`, not the last `:`, or the address's
    // own colons break the parse. And a BARE IPv6 (`2001:db8::1`, no brackets, no port)
    // used to silently misparse as host=`2001:db8:`, port=`1` — reject it with a clear
    // message instead. (L5)
    if let Some(rest) = s.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("'server' IPv6 must be [host]:port, got '{}'", s))?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| anyhow::anyhow!("'server' has invalid IPv6 address: '{}'", s))?;
        let port: u16 = port
            .parse()
            .map_err(|_| anyhow::anyhow!("'server' has invalid port: '{}'", s))?;
        if port == 0 {
            anyhow::bail!("'server' port must be 1..65535: '{}'", s);
        }
        return Ok((host.to_string(), port));
    }
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("'server' must be host:port, got '{}'", s))?;
    if host.is_empty() {
        anyhow::bail!("'server' has empty host: '{}'", s);
    }
    // An unbracketed host that still contains ':' is a bare IPv6 literal — the port split
    // above just chopped its last group. Require brackets rather than misparse it. (L5)
    if host.contains(':') {
        anyhow::bail!(
            "'server' looks like a bare IPv6 address — wrap it as [host]:port: '{}'",
            s
        );
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("'server' has invalid port: '{}'", s))?;
    if port == 0 {
        anyhow::bail!("'server' port must be 1..65535: '{}'", s);
    }
    Ok((host.to_string(), port))
}

/// Split one comma-separated routing list. These values become route arguments, so accept
/// only bare CIDRs and fail the complete config when any element is invalid. Dropping one
/// element is not a safe recovery: it silently reverses that subnet's include/exclude policy.
fn parse_cidr_list(key: &str, s: &str) -> anyhow::Result<Vec<String>> {
    let mut parsed = Vec::new();
    for raw in s.split(',') {
        let value = raw.trim();
        if value.is_empty() {
            anyhow::bail!("key '{key}' contains an empty routing-list element");
        }
        if !is_cidr(value) {
            anyhow::bail!(
                "key '{key}' contains invalid CIDR '{value}' (expected a bare address/prefix, e.g. 192.168.1.0/24 or 2001:db8::7/128)"
            );
        }
        parsed.push(value.to_string());
    }
    Ok(parsed)
}

/// True only for a bare `addr/prefix` CIDR: no leading `-` (an `ip` option), the address
/// parses as an `IpAddr`, the prefix is in range, and every host bit is zero.
fn is_cidr(s: &str) -> bool {
    crate::util::is_valid_cidr(s)
}

#[cfg(test)]
mod auth_size_tests {
    use super::*;

    fn cfg_with(user: &str, pass: &str) -> ClientConfig {
        let ini = format!("[qeli]\nserver = vpn.example.com:443\nuser = {user}\npass = {pass}\n");
        let doc = crate::config::format::IniDoc::parse(&ini).expect("valid INI");
        ClientConfig::from_ini(&doc).expect("parses")
    }

    #[test]
    fn invalid_include_or_exclude_cidr_rejects_the_complete_ini() {
        for (key, value) in [
            ("include", "10.20.0.0/16, not-a-cidr"),
            ("exclude", "192.168.0.0/33"),
            ("include", "10.20.7.9/16"),
            ("exclude", "2001:db8::7/64"),
            ("include", "-6 route add ::/0"),
        ] {
            let ini = format!("[qeli]\nserver = vpn.example.com:443\n{key} = {value}\n");
            let document = crate::config::format::IniDoc::parse(&ini).unwrap();
            let error = ClientConfig::from_ini(&document).unwrap_err();
            let message = error.to_string();
            assert!(message.contains(key), "missing key in error: {message}");
            assert!(
                message.contains("invalid CIDR"),
                "unexpected error: {message}"
            );
        }
    }

    #[test]
    fn valid_dual_family_routing_lists_are_preserved() {
        let ini = "[qeli]\nserver = vpn.example.com:443\ninclude = 10.20.0.0/16, 2001:db8:20::/48\nexclude = 192.168.0.7/32, fc00::/7\n";
        let document = crate::config::format::IniDoc::parse(ini).unwrap();
        let config = ClientConfig::from_ini(&document).unwrap();
        assert_eq!(
            config.routing.include,
            vec!["10.20.0.0/16".to_string(), "2001:db8:20::/48".to_string()]
        );
        assert_eq!(
            config.routing.exclude,
            vec!["192.168.0.7/32".to_string(), "fc00::/7".to_string()]
        );
    }

    #[test]
    fn empty_routing_list_element_is_not_silently_skipped() {
        let ini = "[qeli]\nserver = vpn.example.com:443\nexclude = 10.0.0.0/8,\n";
        let document = crate::config::format::IniDoc::parse(ini).unwrap();
        let error = ClientConfig::from_ini(&document).unwrap_err().to_string();
        assert!(error.contains("exclude"), "unexpected error: {error}");
        assert!(error.contains("empty"), "unexpected error: {error}");
    }

    /// Credentials that do not fit one datagram are refused at load, not discovered as a
    /// handshake that hangs only on mobile networks.
    ///
    /// The AUTH message is sent UNFRAGMENTED while everything around it is fragmented, and
    /// its size is the credentials. Past the budget the datagram needs IP fragmentation,
    /// which mobile and CGNAT paths drop — so the client retransmits into a void and times
    /// out looking exactly like an unreachable server. (Audit 2026-08-02, §3.)
    #[test]
    fn credentials_too_large_for_one_datagram_are_refused() {
        let budget = crate::protocol::udp_frag::MAX_CHUNK - (32 + 17);

        // A realistic credential is nowhere near the bound — this must not become a
        // limit anyone trips over legitimately.
        let ordinary = cfg_with("alice", &"x".repeat(64));
        assert!(
            ordinary.validate().is_ok(),
            "a 64-char password must be fine"
        );

        let over = cfg_with("alice", &"x".repeat(budget));
        let err = over
            .validate()
            .expect_err("credentials past the budget must be refused")
            .to_string();
        assert!(
            err.contains("user"),
            "the error must name the fields: {err}"
        );
        assert!(
            err.contains("fragment"),
            "the error must say WHY it matters: {err}"
        );

        // Exactly at the bound still loads: the check is a ceiling, not an off-by-one.
        let exact = cfg_with("a", &"x".repeat(budget - 3));
        assert!(
            exact.validate().is_ok(),
            "the boundary itself must be valid"
        );
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
    fn required_ipv6_rejects_an_explicit_mtu_below_1280() {
        let required = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = vpn.example.com:443\nipv6 = required\nmtu = 1200\n")
                .unwrap(),
        )
        .unwrap();
        let error = required
            .validate()
            .expect_err("required IPv6 cannot run below its minimum link MTU")
            .to_string();
        assert!(error.contains("at least 1280"), "unexpected error: {error}");

        for mtu in [0, 1280] {
            let config = ClientConfig::from_ini(
                &IniDoc::parse(&format!(
                    "[qeli]\nserver = vpn.example.com:443\nipv6 = required\nmtu = {mtu}\n"
                ))
                .unwrap(),
            )
            .unwrap();
            config
                .validate()
                .unwrap_or_else(|error| panic!("mtu {mtu} must remain valid: {error}"));
        }
    }

    #[test]
    fn exit_node_rejects_every_full_tunnel_spelling() {
        let gateway = ClientConfig::from_ini(
            &IniDoc::parse(
                "[qeli]\nserver = vpn.example.com:443\nexit_node = true\ngateway = true\n",
            )
            .unwrap(),
        )
        .unwrap();
        let error = gateway
            .validate()
            .expect_err("an exit node needs its physical default route")
            .to_string();
        assert!(error.contains("requires split-tunnel"), "{error}");

        // `routing.mode` is retained as an internal/legacy representation; current flat
        // configs select full tunnel with `gateway`. Keep programmatic callers safe too.
        for mode in ["full-tunnel", "all"] {
            let mut config = ClientConfig::from_ini(
                &IniDoc::parse("[qeli]\nserver = vpn.example.com:443\nexit_node = true\n").unwrap(),
            )
            .unwrap();
            config.routing.mode = mode.to_string();
            assert!(config.validate().is_err(), "mode {mode} must be rejected");
        }

        let split = ClientConfig::from_ini(
            &IniDoc::parse(
                "[qeli]\nserver = vpn.example.com:443\nexit_node = true\ngateway = false\n",
            )
            .unwrap(),
        )
        .unwrap();
        split.validate().unwrap();
    }

    #[test]
    fn reality_tls_rejects_disabled_static_session_binding() {
        let src = concat!(
            "[qeli]
",
            "server = vpn.example.com:443
",
            "user = alice
",
            "pass = secret
",
            "mode = reality-tls
",
            "reality_sid = 0123456789abcdef
",
            "key = 0a33d308295d5dc49bff020ca8a73e86b3f6797cbcc7d3aa440eee754729223a
",
            "bind_static = false
",
        );
        let config = ClientConfig::from_ini(&IniDoc::parse(src).unwrap()).unwrap();
        let error = config
            .validate()
            .expect_err("REALITY must not run without static-key session binding")
            .to_string();
        assert!(
            error.contains("bind_static = true"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn camouflage_names_are_stable_and_fail_closed() {
        let bare_ip = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = 192.0.2.10:443\nmode = fake-tls\n").unwrap(),
        )
        .unwrap();
        bare_ip.validate().unwrap();
        assert_eq!(bare_ip.effective_fake_tls_sni(), "!");
        assert_eq!(bare_ip.effective_fronting_host(), "192.0.2.10");

        let base = "[qeli]\nserver = 192.0.2.10:443\nmode = reality-tls\nreality_sid = 0123456789abcdef\nkey = 0a33d308295d5dc49bff020ca8a73e86b3f6797cbcc7d3aa440eee754729223a\n";
        let missing = ClientConfig::from_ini(&IniDoc::parse(base).unwrap()).unwrap();
        let error = missing.validate().unwrap_err().to_string();
        assert!(error.contains("explicit DNS 'sni'"), "{error}");

        let valid = ClientConfig::from_ini(
            &IniDoc::parse(&(base.to_string() + "sni = www.cloudflare.com\n")).unwrap(),
        )
        .unwrap();
        valid.validate().unwrap();
        assert_eq!(valid.effective_reality_sni(), "www.cloudflare.com");

        let mut injected = bare_ip;
        injected.obfuscation.sni = Some("safe.example\r\nX-Probe: yes".to_string());
        assert!(injected
            .validate()
            .unwrap_err()
            .to_string()
            .contains("control"));
    }

    #[test]
    fn malformed_pinned_server_keys_are_rejected_before_connect() {
        for key in [
            "PASTE_64_HEX_KEY_FROM_qeli_show-identity",
            "abcd",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ] {
            let src = format!("[qeli]\nserver = vpn.example.com:443\nkey = {key}\n");
            let doc = IniDoc::parse(&src).expect("valid INI");
            let cfg = ClientConfig::from_ini(&doc).expect("configuration parses");
            let error = cfg
                .validate()
                .expect_err("a malformed X25519 pin must fail before connect")
                .to_string();
            assert!(error.contains("64 hex digits"), "unexpected error: {error}");
        }
    }

    /// Every string-enum the client compares verbatim must be rejected when unknown, because
    /// the failure mode is not an error but a SILENT branch change: `proto = UDP` connects over
    /// TCP, `dns = of` skips DNS setup (a leak in a full tunnel), `front = webscoket` drops the
    /// WebSocket framing. (Audit 2026-07-30, #7.)
    #[test]
    fn unknown_enum_values_are_rejected() {
        let base = concat!(
            "[qeli]\n",
            "server = 1.2.3.4:443\n",
            "user = u\n",
            "pass = p\n",
        );
        let parse = |extra: &str| {
            let src = format!("{base}{extra}");
            ClientConfig::from_ini(&IniDoc::parse(&src).unwrap()).unwrap()
        };

        // The defaults must pass, or this test proves nothing about the negatives below.
        parse("")
            .validate()
            .expect("a default client config must validate");

        for (line, what) in [
            ("proto = UDP\n", "proto"), // case matters: `== \"udp\"` is exact
            ("proto = ucp\n", "proto"),
            ("mode = realty-tls\n", "mode"),
            ("front = webscoket\n", "front"),
            ("dns = of\n", "dns"),
        ] {
            let err = parse(line)
                .validate()
                .expect_err(&format!("`{}` must be rejected", line.trim()));
            assert!(
                err.to_string().contains(what),
                "the message must name the field: {err}"
            );
        }

        // Valid non-default values must still be accepted. `obfs` now carries its key: an
        // empty `obfs_key` is publicly derivable, so the mode obfuscates against nobody and
        // the server refuses the same pairing. (Audit 2026-08-03, P2.)
        for line in [
            "proto = udp\n",
            "mode = obfs\nobfs_key = deadbeefcafe\n",
            "front = none\n",
            "dns = off\n",
        ] {
            parse(line)
                .validate()
                .unwrap_or_else(|e| panic!("`{}` must be accepted: {e}", line.trim()));
        }
    }

    /// `dns_servers` must survive a flat-INI round trip. Without the key an INI could set the
    /// dns MODE but never a SERVER, so `dns = tunnel` against a server that pushes none had no
    /// in-file remedy — and the error message advising one was impossible to follow.
    /// (Audit 2026-07-30, #8.)
    #[test]
    fn dns_servers_round_trips_through_the_flat_ini() {
        let src = concat!(
            "[qeli]\n",
            "server = 1.2.3.4:443\n",
            "user = u\n",
            "pass = p\n",
            "dns = tunnel\n",
            "dns_servers = 9.9.9.9, 149.112.112.112\n",
        );
        let c = ClientConfig::from_ini(&IniDoc::parse(src).unwrap()).unwrap();
        assert_eq!(c.dns.servers, vec!["9.9.9.9", "149.112.112.112"]);

        let out = c.to_ini_string();
        assert!(
            out.contains("dns_servers"),
            "key must be written back: {out}"
        );
        let back = ClientConfig::from_ini(&IniDoc::parse(&out).unwrap()).unwrap();
        assert_eq!(back.dns.servers, c.dns.servers);
    }

    #[test]
    fn ipv6_dns_is_valid_and_round_trips() {
        let src = concat!(
            "[qeli]\n",
            "server = 1.2.3.4:443\n",
            "user = u\n",
            "pass = p\n",
            "dns = tunnel\n",
            "dns_servers = 2001:4860:4860::8888\n",
        );
        let config = ClientConfig::from_ini(&IniDoc::parse(src).unwrap()).unwrap();
        config.validate().unwrap();
        let output = config.to_ini_string();
        let reparsed = ClientConfig::from_ini(&IniDoc::parse(&output).unwrap()).unwrap();
        assert_eq!(reparsed.dns.servers, ["2001:4860:4860::8888"]);
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
    fn ipv6_server_and_local_address_validate_and_round_trip() {
        let src = "[qeli]\nserver = [2001:db8::10]:443\nlocal = 2001:db8::20\nuser = u\npass = p\n";
        let config = ClientConfig::from_ini(&IniDoc::parse(src).unwrap()).unwrap();
        config.validate().unwrap();
        assert_eq!(config.server.address, "2001:db8::10");
        assert_eq!(config.server.local_address.as_deref(), Some("2001:db8::20"));

        let output = config.to_ini_string();
        assert!(output.contains("server = [2001:db8::10]:443"));
        let reparsed = ClientConfig::from_ini(&IniDoc::parse(&output).unwrap()).unwrap();
        assert_eq!(reparsed.server.address, config.server.address);
        assert_eq!(reparsed.server.local_address, config.server.local_address);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_dev_name_validation_prevents_tunsetiff_truncation_and_path_names() {
        for invalid in ["", "abcdefghijklmnop", ".", "..", "bad/name", "bad name"] {
            let mut config = ClientConfig::from_ini(
                &IniDoc::parse("[qeli]\nserver = h:443\nuser = u\npass = p\n").unwrap(),
            )
            .unwrap();
            config.tun.name = invalid.to_string();
            let error = config.validate().unwrap_err().to_string();
            assert!(
                error.contains("not a valid Linux interface name"),
                "{invalid}: {error}"
            );
        }

        let mut valid = ClientConfig::from_ini(
            &IniDoc::parse(
                "[qeli]\nserver = h:443\nuser = u\npass = p\ndev = ext0\ndevice_type = tap\ndev_attach = true\n",
            )
            .unwrap(),
        )
        .unwrap();
        // The configured external TAP name is literal; its type is a separate fact.
        valid.tun.name = "ext0".into();
        valid.validate().unwrap();
        assert_eq!(valid.tun.name, "ext0");
    }

    #[test]
    fn device_type_tap_parses_validates_per_platform_and_round_trips() {
        let defaults = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:443\nuser = u\npass = p\n").unwrap(),
        )
        .unwrap();
        assert_eq!(defaults.tun.device_type, "tun");
        assert!(!defaults.to_ini_string().contains("device_type"));

        let tap = ClientConfig::from_ini(
            &IniDoc::parse(
                "[qeli]\nserver = h:443\nuser = u\npass = p\ndev = qstun0\ndevice_type = TAP\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(tap.tun.device_type, "TAP");
        #[cfg(target_os = "linux")]
        tap.validate().unwrap();
        #[cfg(not(target_os = "linux"))]
        assert!(tap
            .validate()
            .unwrap_err()
            .to_string()
            .contains("supported only by the Linux client"));

        let output = tap.to_ini_string();
        assert!(output.contains("device_type = tap"));
        let reparsed = ClientConfig::from_ini(&IniDoc::parse(&output).unwrap()).unwrap();
        assert_eq!(reparsed.tun.device_type, "tap");
    }

    #[test]
    fn dev_attach_parses_and_round_trips() {
        // Absent -> default false (own the interface).
        let def = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:443\nuser = u\npass = p\n").unwrap(),
        )
        .unwrap();
        assert!(!def.tun.attach_existing);
        // The secure default (false) is not emitted back.
        assert!(!def.to_ini_string().contains("dev_attach"));
        // Explicit `dev_attach = true` parses and survives a round-trip.
        let c = ClientConfig::from_ini(
            &IniDoc::parse(
                "[qeli]\nserver = h:443\nuser = u\npass = p\ndev = ext0\ndev_attach = true\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(c.tun.attach_existing);
        assert_eq!(c.tun.name, "ext0");
        let back = ClientConfig::from_ini(&IniDoc::parse(&c.to_ini_string()).unwrap()).unwrap();
        assert!(back.tun.attach_existing);
        assert_eq!(back.tun.name, "ext0");
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

        // The IPv6-only mirror has the same fail-closed default and round-trip contract.
        assert!(!c.routing.allow_ipv4_leak);
        let on = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:1\nallow_ipv4_leak = on\n").unwrap(),
        )
        .unwrap();
        assert!(on.routing.allow_ipv4_leak);
        let back = ClientConfig::from_ini(&IniDoc::parse(&on.to_ini_string()).unwrap()).unwrap();
        assert!(back.routing.allow_ipv4_leak);
    }

    #[test]
    fn ipv6_acceptance_policy_defaults_parses_and_round_trips() {
        let default =
            ClientConfig::from_ini(&IniDoc::parse("[qeli]\nserver = h:443\n").unwrap()).unwrap();
        assert_eq!(default.routing.ipv6, ClientIpv6Policy::Auto);
        assert!(!default.to_ini_string().contains("\nipv6 ="));

        for (raw, expected) in [
            ("auto", ClientIpv6Policy::Auto),
            ("required", ClientIpv6Policy::Required),
            ("off", ClientIpv6Policy::Off),
        ] {
            let text = format!("[qeli]\nserver = h:443\nipv6 = {raw}\n");
            let parsed = ClientConfig::from_ini(&IniDoc::parse(&text).unwrap()).unwrap();
            assert_eq!(parsed.routing.ipv6, expected);
            let back =
                ClientConfig::from_ini(&IniDoc::parse(&parsed.to_ini_string()).unwrap()).unwrap();
            assert_eq!(back.routing.ipv6, expected);
        }

        let error =
            crate::config::parse_client_config_strict("[qeli]\nserver = h:443\nipv6 = sometimes\n")
                .unwrap_err()
                .to_string();
        assert!(error.contains("ipv6"), "{error}");
    }

    #[test]
    fn roaming_policy_defaults_parses_validates_and_round_trips() {
        let default =
            ClientConfig::from_ini(&IniDoc::parse("[qeli]\nserver = h:443\n").unwrap()).unwrap();
        assert_eq!(default.roaming, ClientRoamingPolicy::Auto);
        assert!(!default.to_ini_string().contains("\nroaming ="));

        for (raw, expected) in [
            ("off", ClientRoamingPolicy::Off),
            ("auto", ClientRoamingPolicy::Auto),
            ("required", ClientRoamingPolicy::Required),
        ] {
            let text = format!("[qeli]\nserver = h:443\nroaming = {raw}\n");
            let parsed = ClientConfig::from_ini(&IniDoc::parse(&text).unwrap()).unwrap();
            assert_eq!(parsed.roaming, expected);
            let back =
                ClientConfig::from_ini(&IniDoc::parse(&parsed.to_ini_string()).unwrap()).unwrap();
            assert_eq!(back.roaming, expected);
        }

        let invalid = crate::config::parse_client_config_strict(
            "[qeli]\nserver = h:443\nroaming = sometimes\n",
        )
        .unwrap_err()
        .to_string();
        assert!(invalid.contains("roaming"), "{invalid}");

        for pin in ["local = 192.0.2.10", "lport = 41000"] {
            let text = format!("[qeli]\nserver = h:443\nroaming = required\n{pin}\n");
            let parsed = crate::config::parse_client_config_strict(&text).unwrap();
            let error = parsed.validate().unwrap_err().to_string();
            assert!(error.contains("pin the carrier socket"), "{error}");
        }
    }

    #[test]
    fn udp_socket_buffer_keys_are_live_and_default_correctly() {
        // recv_buffer_size / send_buffer_size existed in the model but nothing parsed or
        // applied them. Two things must hold now, and neither is obvious from the type:
        //
        // 1. A config that never mentions them still gets the 4 MB receive default. The
        //    struct derives Default, and #[derive(Default)] IGNORES serde attributes — it
        //    would yield 0 (= leave the kernel's 208 KB alone, i.e. the bug we fixed). Only
        //    the serde path via baseline() produces the real default, so pin it here: a
        //    future refactor that swaps baseline() for Default::default() must fail loudly
        //    rather than silently restore packet loss under load.
        // 2. The send default is deliberately the OPPOSITE (0 = leave the kernel alone),
        //    because pinning a value would LOWER the buffer on a tuned host.
        let bare = ClientConfig::from_ini(&IniDoc::parse("[qeli]\nserver = h:443\n").unwrap())
            .expect("minimal config parses");
        assert_eq!(
            bare.performance.recv_buffer_size,
            4 * 1024 * 1024,
            "an unset recv_buffer_size must default to 4 MB, not to the kernel value"
        );
        assert!(
            bare.performance.recv_buffer_auto,
            "an omitted size must select bounded auto-grow"
        );
        assert_eq!(
            bare.performance.send_buffer_size, 0,
            "send_buffer_size must default to 0 (leave the kernel alone)"
        );
        // Defaults stay out of the emitted file (it is a sparse format).
        let sparse = bare.to_ini_string();
        assert!(
            !sparse.contains("recv_buffer_size") && !sparse.contains("send_buffer_size"),
            "default buffer sizes must not be emitted"
        );

        // Explicit values parse and survive a round-trip.
        let ini = "[qeli]\nserver = h:443\nrecv_buffer_size = 8388608\nsend_buffer_size = 262144\n";
        let c = ClientConfig::from_ini(&IniDoc::parse(ini).unwrap()).unwrap();
        assert_eq!(c.performance.recv_buffer_size, 8 * 1024 * 1024);
        assert!(!c.performance.recv_buffer_auto, "an explicit size is fixed");
        assert_eq!(c.performance.send_buffer_size, 262_144);
        let back = ClientConfig::from_ini(&IniDoc::parse(&c.to_ini_string()).unwrap()).unwrap();
        assert_eq!(back.performance.recv_buffer_size, 8 * 1024 * 1024);
        assert!(!back.performance.recv_buffer_auto);
        assert_eq!(back.performance.send_buffer_size, 262_144);

        // 0 must be honoured as an explicit opt-out, not confused with "unset".
        let off = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:443\nrecv_buffer_size = 0\n").unwrap(),
        )
        .unwrap();
        assert_eq!(
            off.performance.recv_buffer_size, 0,
            "an explicit 0 must opt back out to the kernel default"
        );
        assert!(!off.performance.recv_buffer_auto);

        // Explicitly pinning the numeric default must not be laundered back into an omitted
        // auto setting by sparse serialization.
        let fixed_default = ClientConfig::from_ini(
            &IniDoc::parse("[qeli]\nserver = h:443\nrecv_buffer_size = 4194304\n").unwrap(),
        )
        .unwrap();
        assert!(!fixed_default.performance.recv_buffer_auto);
        let fixed_text = fixed_default.to_ini_string();
        assert!(fixed_text.contains("recv_buffer_size = 4194304"));
        let fixed_back = ClientConfig::from_ini(&IniDoc::parse(&fixed_text).unwrap()).unwrap();
        assert!(!fixed_back.performance.recv_buffer_auto);

        // A typo must not turn every UDP socket into a multi-gigabyte kernel allocation.
        for key in ["recv_buffer_size", "send_buffer_size"] {
            let oversized = ClientConfig::from_ini(
                &IniDoc::parse(&format!("[qeli]\nserver = h:443\n{key} = 67108865\n")).unwrap(),
            )
            .unwrap();
            let error = oversized.validate().unwrap_err().to_string();
            assert!(error.contains(key), "wrong validation error: {error}");
        }
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

    #[test]
    fn native_transport_owned_gui_keys_parse_validate_and_round_trip() {
        let ini = r#"[qeli]
server = h:443
timeout = 47
local = 192.0.2.10
lport = 34567
padding = false
padding_min = 7
padding_max = 255
heartbeat = false
heartbeat_interval = 17000
heartbeat_size = 24
heartbeat_jitter = 2000
shaping = true
shaping_gap_mean = 800
shaping_gap_min = 50
shaping_gap_max = 7000
shaping_budget = 20000
shaping_min_size = 72
shaping_max_size = 1100
shaping_stealth = true
shaping_stealth_mbps = 3
"#;
        let config = ClientConfig::from_ini(&IniDoc::parse(ini).unwrap()).unwrap();
        config.validate().unwrap();
        assert_eq!(config.server.connection_timeout_secs, 47);
        assert_eq!(config.server.local_address.as_deref(), Some("192.0.2.10"));
        assert_eq!(config.server.local_port, 34_567);
        assert!(!config.obfuscation.padding.enabled);
        assert_eq!(config.obfuscation.padding.min_bytes, 7);
        assert!(!config.obfuscation.heartbeat.enabled);
        assert_eq!(config.obfuscation.heartbeat.jitter_ms, 2_000);
        assert!(config.obfuscation.traffic_shaping.enabled);
        assert!(config.obfuscation.traffic_shaping.stealth);

        let output = config.to_ini_string();
        let back = ClientConfig::from_ini(&IniDoc::parse(&output).unwrap()).unwrap();
        assert_eq!(back.server.connection_timeout_secs, 47);
        assert_eq!(back.server.local_address, config.server.local_address);
        assert_eq!(back.server.local_port, config.server.local_port);
        assert_eq!(back.obfuscation.padding.min_bytes, 7);
        assert_eq!(back.obfuscation.heartbeat.jitter_ms, 2_000);
        assert_eq!(back.obfuscation.traffic_shaping.stealth_rate_mbps, 3);
    }

    #[test]
    fn native_transport_owned_gui_keys_fail_closed_on_invalid_values() {
        for (line, needle) in [
            ("timeout = 0", "timeout"),
            ("local = not-an-ip", "local"),
            ("padding_min = 100\npadding_max = 50", "padding"),
            ("heartbeat_interval = 0", "heartbeat_interval"),
            ("shaping_min_size = 200\nshaping_max_size = 100", "shaping"),
            (
                "shaping = true\nshaping_budget = 63\nshaping_max_size = 64",
                "shaping",
            ),
            ("exit_node = true\ngateway = true", "exit_node"),
        ] {
            let ini = format!("[qeli]\nserver = h:443\n{line}\n");
            let config = ClientConfig::from_ini(&IniDoc::parse(&ini).unwrap()).unwrap();
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains(needle), "{line}: {error}");
        }
    }

    /// EXHAUSTIVE client round-trip: every key client.rs reads is set to a
    /// non-default value in the fixture (coverage proven by
    /// scripts/test_native_config_keys.py), then parse ->
    /// to_ini_string must re-emit each one. A value appears in the output only
    /// if it was BOTH parsed into the struct AND written back, so a missing
    /// token is a read-but-not-persisted key (the reality_sid / server
    /// time_format bug class). ClientConfig is Deserialize-only, so this checks
    /// the serialized form directly rather than via serde_json equality.
    #[test]
    fn exhaustive_round_trip_every_client_key() {
        let fixture = r####"
[qeli]
server = vpn.example.com:8443
proto = udp
user = carol
pass = topsecret
key = 1111111111111111111111111111111111111111111111111111111111111111
bind_static = false
allow_unpinned_tofu = true
password_file = /tmp/pw.txt
password_command = echo pw
keepalive = 45
tcp_nodelay = false
timeout = 47
local = 192.0.2.10
lport = 34567
recv_buffer_size = 8388608
send_buffer_size = 262144
mode = reality-tls
sni = www.apple.com
obfs_key = obfskey123
reality_sid = deadbeef
reality_compact = true
reality_split = sni
reality_split_delay = 37
front = none
quic = true
awg = true
jc = 5
jmin = 30
jmax = 150
padding = false
padding_min = 0
padding_max = 255
heartbeat = false
heartbeat_interval = 17000
heartbeat_size = 24
heartbeat_jitter = 2000
shaping = true
shaping_gap_mean = 800
shaping_gap_min = 50
shaping_gap_max = 7000
shaping_budget = 20000
shaping_min_size = 72
shaping_max_size = 1100
shaping_stealth = true
shaping_stealth_mbps = 3
route_local = true
ipv6 = required
include = 10.0.0.0/8, 172.16.0.0/12
exclude = 192.168.9.0/24
kill_switch = true
allow_ipv6_leak = true
allow_ipv4_leak = true
gateway = true
gateway_nat = true
forward = true
exit_node = true
lan_subnet = 192.168.50.0/24
lan_subnet_ipv6 = 2001:db8:50::/64
post_up = echo up
post_down = echo down
dns = off
dns_servers = 9.9.9.9, 149.112.112.112
dev = mytun0
device_type = tap
dev_attach = true
mtu = 1380
mtu_probe = false
autostart = true

[logging]
level = debug
time_format = rfc3339
file = /tmp/client.log
"####;
        let c = ClientConfig::from_ini(&IniDoc::parse(fixture).unwrap()).unwrap();
        let out = c.to_ini_string();
        let qeli_tokens = [
            "server = vpn.example.com:8443",
            "proto = udp",
            "user = carol",
            "pass = topsecret",
            "key = 1111",
            "bind_static = false",
            "allow_unpinned_tofu = true",
            "password_file = /tmp/pw.txt",
            "password_command = echo pw",
            "keepalive = 45",
            "tcp_nodelay = false",
            "timeout = 47",
            "local = 192.0.2.10",
            "lport = 34567",
            "recv_buffer_size = 8388608",
            "send_buffer_size = 262144",
            "mode = reality-tls",
            "sni = www.apple.com",
            "obfs_key = obfskey123",
            "reality_sid = deadbeef",
            "reality_compact = true",
            "reality_split = sni",
            "reality_split_delay = 37",
            "front = none",
            "quic = true",
            "awg = true",
            "jc = 5",
            "jmin = 30",
            "jmax = 150",
            "padding = false",
            "padding_min = 0",
            "padding_max = 255",
            "heartbeat = false",
            "heartbeat_interval = 17000",
            "heartbeat_size = 24",
            "heartbeat_jitter = 2000",
            "shaping = true",
            "shaping_gap_mean = 800",
            "shaping_gap_min = 50",
            "shaping_gap_max = 7000",
            "shaping_budget = 20000",
            "shaping_min_size = 72",
            "shaping_max_size = 1100",
            "shaping_stealth = true",
            "shaping_stealth_mbps = 3",
            "route_local = true",
            "ipv6 = required",
            "include = 10.0.0.0/8",
            "exclude = 192.168.9.0/24",
            "kill_switch = true",
            "allow_ipv6_leak = true",
            "allow_ipv4_leak = true",
            "gateway = true",
            "gateway_nat = true",
            "forward = true",
            "exit_node = true",
            "lan_subnet = 192.168.50.0/24",
            "lan_subnet_ipv6 = 2001:db8:50::/64",
            "post_up = echo up",
            "post_down = echo down",
            "dns = off",
            "dns_servers = 9.9.9.9, 149.112.112.112",
            "dev = mytun0",
            "device_type = tap",
            "dev_attach = true",
            "mtu = 1380",
            "mtu_probe = false",
            "autostart = true",
        ];

        for t in qeli_tokens {
            assert!(
                out.contains(t),
                "client to_ini dropped [qeli] key: {}
--- out ---
{}",
                t,
                out
            );
        }
        // `[logging]` round-trip: the client parses this section (level / file /
        // time_format, honoured by the router/headless client) AND now re-emits it,
        // so an explicit logging choice survives a config -> INI -> config cycle.
        // This closes the read-but-not-persisted gap of the `reality_sid` /
        // server-`time_format` class. Only non-defaults are emitted, and all three
        // fixture values are non-default (debug / rfc3339 / a file path), so each
        // must appear.
        let log_tokens = [
            "level = debug",
            "time_format = rfc3339",
            "file = /tmp/client.log",
        ];
        for t in log_tokens {
            assert!(
                out.contains(t),
                "client to_ini dropped [logging] key: {}\n--- out ---\n{}",
                t,
                out
            );
        }
    }
}
