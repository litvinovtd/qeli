use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct DhcpConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_dhcp_listen")]
    pub listen: String,
    #[serde(default)]
    pub pool_start: Option<String>,
    #[serde(default)]
    pub pool_end: Option<String>,
    #[serde(default = "default_dhcp_lease")]
    pub lease_time_secs: u32,
    #[serde(default = "default_dhcp_domain")]
    pub domain_name: String,
}

fn default_dhcp_listen() -> String {
    "0.0.0.0:67".into()
}
fn default_dhcp_lease() -> u32 {
    86400
}
fn default_dhcp_domain() -> String {
    "vpn".into()
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    #[serde(default)]
    pub profiles: Vec<ProfileConfig>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub web: WebConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProfileConfig {
    // NB: scalar fields are declared BEFORE sub-table fields so TOML
    // serialization (web "save config") stays valid — TOML requires all values
    // to precede any table within the same table.
    #[serde(default = "default_profile_name")]
    pub name: String,
    /// Path to this profile's server identity (static X25519) private key.
    /// Defaults to `/etc/qeli/identity/<name>.key` — each profile/interface has
    /// its own identity, so clients pin a key that is specific to the interface
    /// they connect to.
    #[serde(default)]
    pub identity_key: Option<String>,
    /// Whether this profile is active. `true` (default) = bound and served;
    /// `false` = kept in the config but skipped at startup (turn a profile off
    /// without deleting it). Omitting the key keeps the profile enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub bind: BindConfig,
    #[serde(default)]
    pub tun: TunConfig,
    #[serde(default)]
    pub pool: PoolConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub dhcp: DhcpConfig,
    #[serde(default)]
    pub obfuscation: ServerObfuscationConfig,
    #[serde(default)]
    pub performance: ServerPerformanceConfig,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            name: default_profile_name(),
            bind: BindConfig::default(),
            tun: TunConfig::default(),
            pool: PoolConfig::default(),
            routing: RoutingConfig::default(),
            dns: DnsConfig::default(),
            dhcp: DhcpConfig::default(),
            obfuscation: ServerObfuscationConfig::default(),
            performance: ServerPerformanceConfig::default(),
            identity_key: None,
            enabled: true,
        }
    }
}

fn default_profile_name() -> String {
    "default".into()
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct BindConfig {
    #[serde(default = "default_bind_addr")]
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_transport")]
    pub transport: String,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TunConfig {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_tun_addr")]
    pub address: String,
    #[serde(default = "default_tun_mask")]
    pub netmask: String,
    #[serde(default = "default_mtu")]
    pub mtu: i32,
    #[serde(default = "default_tx_queue")]
    pub tx_queue_len: u32,
    #[serde(default = "default_device_type")]
    pub device_type: String,
    /// Number of TUN queues (Linux `IFF_MULTI_QUEUE`) for the data-plane pump.
    /// `0` = auto (= CPU count). `>1` lets the kernel RSS-spread packets so the
    /// server reads/writes the interface — and runs the per-queue encrypt — on
    /// multiple cores. `1` = single queue (legacy single-pump behaviour).
    #[serde(default = "default_tun_queues")]
    pub queues: usize,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct AuthConfig {
    #[serde(default = "default_users_file")]
    pub users_file: String,
    #[serde(default = "default_hash_type")]
    pub password_hash: String,
    #[serde(default = "default_token_ttl")]
    pub token_ttl_secs: u64,
    /// Require the client to prove it already knows this server's static public
    /// key (i.e. has it pinned in `auth.server_public_key`). When true, clients
    /// that did not pin the key are rejected — closing the "unpinned client is
    /// still admitted" gap. Default false (TOFU allowed).
    #[serde(default = "default_false")]
    pub require_client_key_proof: bool,
    // tables/table-arrays after scalars (TOML serialization ordering):
    #[serde(default)]
    pub brute_force: BruteForceConfig,
    /// Users defined inline in the server config (with Argon2 password hashes).
    /// If non-empty, these are used instead of `users_file`.
    #[serde(default)]
    pub users: Vec<crate::config::users::UserEntry>,
    /// Optional group templates for inline users.
    #[serde(default)]
    pub groups: std::collections::HashMap<String, crate::config::users::GroupTemplate>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BruteForceConfig {
    /// Max failed auth attempts before lockout
    #[serde(default = "default_bf_max_attempts")]
    pub max_attempts: u32,
    /// Time window in seconds to count failures
    #[serde(default = "default_bf_window")]
    pub window_secs: u64,
    /// Lockout duration in seconds after max_attempts exceeded
    #[serde(default = "default_bf_lockout")]
    pub lockout_secs: u64,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_bf_max_attempts(),
            window_secs: default_bf_window(),
            lockout_secs: default_bf_lockout(),
        }
    }
}

fn default_bf_max_attempts() -> u32 {
    5
}
fn default_bf_window() -> u64 {
    300
} // 5 minutes
fn default_bf_lockout() -> u64 {
    900
} // 15 minutes

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct PoolConfig {
    #[serde(default = "default_cidr")]
    pub cidr: String,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_lease_time")]
    pub lease_time_secs: u64,
    #[serde(default)]
    pub static_reservations: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct PushedRoute {
    pub cidr: String,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub metric: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct RoutingConfig {
    // scalars before tables (TOML serialization ordering)
    #[serde(default = "default_false")]
    pub client_to_client: bool,
    #[serde(default = "default_true")]
    pub forward_private: bool,
    #[serde(default)]
    pub nat: NatConfig,
    #[serde(default, alias = "push_routes")]
    pub advertised_routes: Vec<PushedRoute>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct NatConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_nat_iface")]
    pub interface: String,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct DnsConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_dns_listen")]
    pub listen: String,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default = "default_upstream")]
    pub upstream: Vec<String>,
    #[serde(default = "default_upstream_proto")]
    pub upstream_protocol: String,
    #[serde(default = "default_dns_cache")]
    pub cache_size: usize,
    #[serde(default = "default_dns_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub blocklist: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ServerObfuscationConfig {
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// Wire mode: "fake-tls" (default, TLS-1.3-mimicking handshake) or "obfs"
    /// (ChaCha20 stream obfuscation, structure-free). TCP only.
    #[serde(default = "default_wire_mode")]
    pub mode: String,
    /// Pre-shared key for "obfs" mode. Must match the client.
    #[serde(default)]
    pub obfs_key: String,
    /// `obfs` anti-FET fronting: "websocket" (default) wraps the nonce exchange in
    /// a WebSocket Upgrade handshake so the connection's first bytes are printable
    /// HTTP text (defeats GFW/TSPU "fully encrypted traffic" heuristics); "none"
    /// is the legacy raw nonce. Must match the client.
    #[serde(default = "default_obfs_fronting")]
    pub fronting: String,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub padding: PaddingConfig,
    #[serde(default)]
    pub fragmentation: FragmentationConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    #[serde(default)]
    pub http2_masking: Http2MaskingConfig,
    #[serde(default)]
    pub traffic_normalization: TrafficNormalizationConfig,
    #[serde(default)]
    pub anti_fingerprinting: AntiFingerprintingConfig,
    #[serde(default)]
    pub quic: crate::config::QuicMaskingConfig,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// Pool of decoy SNI hostnames for camouflage. Defaults to a built-in set of
    /// high-traffic domains (the same list as `protocol::tls::DEFAULT_SNI_POOL`),
    /// surfaced here so operators can override it per profile in the config
    /// instead of it being hard-coded. (Client-side SNI rotation that consumes
    /// this list is a follow-up; today the field is config-surfaced and parsed.)
    #[serde(default = "default_server_names")]
    pub server_names: Vec<String>,
    #[serde(default = "default_true")]
    pub session_id: bool,
    #[serde(default = "default_supported_groups")]
    pub supported_groups: Vec<String>,
    #[serde(default = "default_key_share_entropy")]
    pub key_share_entropy_bytes: u16,
    #[serde(default)]
    pub reality_proxy: RealityProxyConfig,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct RealityProxyConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_reality_target")]
    pub target: String,
    #[serde(default = "default_reality_target_port")]
    pub target_port: u16,
    /// REALITY short_ids (hex, ≤8 bytes) accepted from clients. When non-empty,
    /// the server discriminates qeli clients by a crypto token in the ClientHello
    /// session_id (`crypto::reality`) instead of by ALPN absence. Empty = legacy
    /// ALPN-absence detection.
    #[serde(default)]
    pub short_ids: Vec<String>,
    /// When true, an authenticated ("our") client is terminated with a genuine
    /// TLS 1.3 session (rustls) and the qeli tunnel runs inside it — real TLS on
    /// the wire (M3). False = legacy fake-TLS handshake directly on the socket.
    #[serde(default = "default_false")]
    pub real_tls: bool,
    /// When `real_tls` is set, terminate with the hand-rolled byte-grade TLS 1.3
    /// stack instead of rustls — a ServerHello whose JA3S matches the target
    /// (TLS_AES_256_GCM_SHA384 + classic X25519, as `www.microsoft.com` sends a
    /// PQ-capable Chrome). Requires clients on the realtls stack (L3).
    #[serde(default = "default_false")]
    pub handrolled: bool,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct AntiFingerprintingConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_rotate_ciphers")]
    pub rotate_ciphers_every: u64,
    #[serde(default = "default_true")]
    pub add_jitter_to_handshake: bool,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ServerPerformanceConfig {
    #[serde(default)]
    pub tcp: TcpConfig,
    #[serde(default)]
    pub tun: TunPerfConfig,
    #[serde(default)]
    pub connection: ConnectionConfig,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct WebConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_web_bind")]
    pub bind: String,
    #[serde(default = "default_web_port")]
    pub port: u16,
    #[serde(default = "default_web_username")]
    pub username: String,
    #[serde(default)]
    pub password_hash: String,
    /// Add the `Secure` attribute to the session cookie. Enable when the panel is
    /// reached over HTTPS (TLS reverse proxy). Leave off for plain-HTTP localhost /
    /// SSH-tunnel access — a `Secure` cookie is never sent over HTTP, which would
    /// lock you out of an HTTP panel.
    #[serde(default = "default_false")]
    pub secure_cookie: bool,
}

fn default_bind_addr() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    443
}
fn default_transport() -> String {
    "tcp".into()
}
fn default_tun_name() -> String {
    "vpn0".into()
}
fn default_tun_addr() -> String {
    "10.0.0.1".into()
}
fn default_tun_mask() -> String {
    "255.255.255.0".into()
}
fn default_mtu() -> i32 {
    1500
}
fn default_tx_queue() -> u32 {
    1000
}
fn default_tun_queues() -> usize {
    0 // auto: resolved to CPU count at profile start
}
fn default_users_file() -> String {
    "/etc/qeli/users.conf".into()
}
fn default_hash_type() -> String {
    "argon2id".into()
}
fn default_token_ttl() -> u64 {
    86400
}
fn default_cidr() -> String {
    "10.0.0.0/24".into()
}
fn default_lease_time() -> u64 {
    3600
}
fn default_nat_iface() -> String {
    "eth0".into()
}
fn default_dns_listen() -> String {
    "10.0.0.1".into()
}
fn default_dns_port() -> u16 {
    53
}
fn default_upstream() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}
fn default_upstream_proto() -> String {
    "udp".into()
}
fn default_dns_cache() -> usize {
    1000
}
fn default_dns_timeout() -> u64 {
    5
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
fn default_server_name() -> String {
    "www.cloudflare.com".into()
}
/// Default decoy SNI pool — kept in sync with `protocol::tls::DEFAULT_SNI_POOL`.
/// Surfacing it here lets operators override the set per profile via the config.
fn default_server_names() -> Vec<String> {
    vec![
        "www.cloudflare.com".into(),
        "www.google.com".into(),
        "www.microsoft.com".into(),
        "www.apple.com".into(),
        "www.amazon.com".into(),
    ]
}
fn default_supported_groups() -> Vec<String> {
    vec!["x25519".into(), "secp256r1".into()]
}
fn default_key_share_entropy() -> u16 {
    32
}
fn default_rotate_ciphers() -> u64 {
    300
}
fn default_web_bind() -> String {
    "127.0.0.1".into()
}
fn default_web_port() -> u16 {
    8080
}
fn default_web_username() -> String {
    "admin".into()
}
fn default_reality_target() -> String {
    "www.cloudflare.com".into()
}
fn default_reality_target_port() -> u16 {
    443
}
fn default_device_type() -> String {
    "tun".into()
}
