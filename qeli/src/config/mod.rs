pub mod server;
// Config data definitions + qeli:// link helpers: several fields/methods are
// declarative API surface or used only by tests / the Android port.
#[allow(dead_code)]
pub mod client;
pub mod format;
mod server_ini;
#[allow(dead_code)]
pub mod share;
pub mod users;

use serde::{Deserialize, Serialize};

/// Parse a server config. The one and only on-disk format is flat INI
/// (`[auth]` / `[web]` / `[logging]` singletons + `[profile:<name>]` sections);
/// see [`server::ServerConfig::from_ini`].
pub fn parse_server_config(s: &str) -> anyhow::Result<server::ServerConfig> {
    let doc = format::IniDoc::parse(s)?;
    server::ServerConfig::from_ini(&doc)
}

/// Parse a client config. The one and only format is flat INI with a `[qeli]`
/// section; see [`client::ClientConfig::from_ini`].
pub fn parse_client_config(s: &str) -> anyhow::Result<client::ClientConfig> {
    let doc = format::IniDoc::parse(s)?;
    client::ClientConfig::from_ini(&doc)
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    pub file: Option<String>,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default)]
    pub rotation: Option<LogRotation>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct LogRotation {
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    #[serde(default = "default_max_files")]
    pub max_files: u32,
    #[serde(default = "default_true")]
    pub compress: bool,
}

/// Obfuscation parameters the server pushes to the client at handshake time, so
/// the client no longer has to carry (and keep in sync) these in its own config.
/// Only the params used in the post-auth data phase are pushed — the wire `mode`,
/// `obfs_key`, `cipher` and QUIC masking are needed *before* auth to wrap the
/// handshake itself and therefore stay in the client link/config.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct PushedObf {
    #[serde(default)]
    pub padding: PaddingConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    #[serde(default)]
    pub traffic_normalization: TrafficNormalizationConfig,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct PaddingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_padding_min")]
    pub min_bytes: u16,
    #[serde(default = "default_padding_max")]
    pub max_bytes: u16,
    #[serde(default = "default_true")]
    pub randomize: bool,
    #[serde(default = "default_one")]
    pub probability: f64,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct FragmentationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_frag_min")]
    pub min_chunk_size: u16,
    #[serde(default = "default_frag_max")]
    pub max_chunk_size: u16,
    #[serde(default = "default_frag_max_per_packet")]
    pub max_fragments_per_packet: u16,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct HeartbeatConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_heartbeat_interval")]
    pub interval_ms: u64,
    #[serde(default = "default_heartbeat_data_size")]
    pub data_size_bytes: u16,
    #[serde(default = "default_heartbeat_jitter")]
    pub jitter_ms: u64,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Http2MaskingConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_masking_ratio")]
    pub ratio: f64,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TrafficNormalizationConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_round_sizes")]
    pub round_sizes: Vec<u16>,
    #[serde(default = "default_false")]
    pub randomize_sequence: bool,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TcpConfig {
    #[serde(default = "default_true")]
    pub nodelay: bool,
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u32,
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u32,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TunPerfConfig {
    #[serde(default = "default_tun_buf")]
    pub read_buffer_size: usize,
    #[serde(default = "default_tun_buf")]
    pub write_buffer_size: usize,
    #[serde(default = "default_tun_timeout")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_max_pending")]
    pub max_pending_packets: u32,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ConnectionConfig {
    #[serde(default = "default_max_clients")]
    pub max_clients: u32,
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_packets_per_sec: u32,
    /// New-connection rate limit (per source IP): at most `new_session_rate_max`
    /// fresh sessions per `new_session_rate_window_secs`. Throttles connection
    /// floods without affecting established tunnels. Was hardcoded 10/60.
    #[serde(default = "default_new_session_rate_max")]
    pub new_session_rate_max: usize,
    #[serde(default = "default_new_session_rate_window_secs")]
    pub new_session_rate_window_secs: u64,
}

fn default_log_level() -> String {
    "info".into()
}

#[cfg(test)]
mod tests {

    #[test]
    fn user_profile_authorization() {
        let all = crate::config::users::UserEntry {
            username: "all".into(),
            password_hash: "x".into(),
            ..Default::default()
        };
        let tcp_only = crate::config::users::UserEntry {
            username: "tcp_only".into(),
            password_hash: "x".into(),
            profiles: vec!["tcp".into()],
            ..Default::default()
        };
        // empty profiles list => allowed on every interface
        assert!(all.allowed_on_profile("tcp"));
        assert!(all.allowed_on_profile("udp"));
        // restricted user: only its listed profile, blocked elsewhere
        assert!(tcp_only.allowed_on_profile("tcp"));
        assert!(!tcp_only.allowed_on_profile("udp"));
    }
}
fn default_log_format() -> String {
    "plain".into()
}
fn default_max_size_mb() -> u64 {
    100
}
fn default_max_files() -> u32 {
    7
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_padding_min() -> u16 {
    32
}
fn default_padding_max() -> u16 {
    512
}
fn default_one() -> f64 {
    1.0
}
fn default_frag_min() -> u16 {
    64
}
fn default_frag_max() -> u16 {
    512
}
fn default_frag_max_per_packet() -> u16 {
    16
}
fn default_heartbeat_interval() -> u64 {
    15_000
}
fn default_heartbeat_data_size() -> u16 {
    16
}
fn default_heartbeat_jitter() -> u64 {
    20
}
fn default_masking_ratio() -> f64 {
    0.1
}
fn default_round_sizes() -> Vec<u16> {
    vec![64, 128, 256, 512, 1024, 1500]
}
fn default_keepalive() -> u64 {
    60
}
fn default_buffer_size() -> u32 {
    262144
}
fn default_tun_buf() -> usize {
    65535
}
fn default_tun_timeout() -> u64 {
    10
}
fn default_max_pending() -> u32 {
    256
}
fn default_max_clients() -> u32 {
    128
}
fn default_handshake_timeout() -> u64 {
    10
}
fn default_idle_timeout() -> u64 {
    300
}
fn default_new_session_rate_max() -> usize {
    10
}
fn default_new_session_rate_window_secs() -> u64 {
    60
}
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct QuicMaskingConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_quic_cid_len")]
    pub cid_length: u8,
    #[serde(default = "default_quic_version")]
    pub version: u32,
}

fn default_quic_cid_len() -> u8 {
    4
}
fn default_quic_version() -> u32 {
    1
}
fn default_rate_limit() -> u32 {
    10000
}
