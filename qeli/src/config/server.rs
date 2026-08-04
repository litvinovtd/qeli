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

/// EMPTY on purpose — `run_profile` substitutes the profile's tun address.
///
/// This used to be `0.0.0.0:67`, i.e. an unauthenticated DHCP server on every interface the
/// moment `dhcp.enabled = true` was set, which is the only key an operator touches. The
/// resolver has always refused an unspecified `dns.listen` outright; DHCP only logged a
/// warning and served anyway. Defaulting to the tun address makes the safe case the silent
/// one, and `validate_profiles` now rejects an explicit `0.0.0.0` the same way it does for
/// DNS. (Audit 2026-08-04.)
fn default_dhcp_listen() -> String {
    String::new()
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

impl ProfileConfig {
    /// A profile with every per-field serde default applied — the canonical
    /// "new profile" template. The nested objects are spelled out so serde runs
    /// the `default_*` functions rather than the derived `Default` (which would
    /// give "" / 0 / false for sub-tables). The web UI fetches this via
    /// `GET /api/config/defaults` so the form never hard-codes (and drifts from)
    /// the schema. Keep the skeleton in sync with the struct's sub-tables.
    pub fn baseline() -> Self {
        const SKELETON: &str = r#"{
            "bind":{},"tun":{},"pool":{},
            "routing":{"nat":{}},
            "dns":{},"dhcp":{},
            "obfuscation":{"padding":{},"fragmentation":{},"heartbeat":{},
                "tls":{"reality_proxy":{}},
                "traffic_normalization":{},"traffic_shaping":{},"anti_fingerprinting":{},"quic":{},
                "multipath":{},"awg":{}},
            "performance":{"tcp":{},"tun":{},"connection":{}}
        }"#;
        serde_json::from_str(SKELETON).expect("baseline profile skeleton is valid")
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
    /// Extra listeners beyond the primary `address:port` above, sharing this profile's ONE
    /// TUN / pool / identity / users (#12). Each entry is a bare `addr:port` on the SAME
    /// `transport` as the profile — so one profile can be reached on several ports/addresses
    /// (e.g. 443 + 8443) without cloning it. A profile is ONE transport; use a separate
    /// profile for the other. INI key `listen` (repeatable).
    #[serde(default)]
    pub listen: Vec<String>,
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
    /// Require the client to prove it already knows this server's static public
    /// key (i.e. has it pinned in `auth.server_public_key`). When true, clients
    /// that did not pin the key are rejected — closing the "unpinned client is
    /// still admitted" gap. Default false (TOFU allowed).
    #[serde(default = "default_false")]
    pub require_client_key_proof: bool,
    /// Bind the data-plane keys to the server's static identity (H-1): the session
    /// KDF additionally folds in the static-ephemeral DH, so a failed ephemeral RNG
    /// alone no longer exposes the tunnel (Noise-IK property). WIRE-BREAKING — only
    /// clients that also pin the key AND set `bind_static_to_session` can connect.
    /// **Default true (secure-by-default since 0.7.1)**: a server with the default
    /// only admits H-1 clients (which must pin the key). To interoperate with a
    /// legacy 0.7.0 / TOFU fleet, set this to `false` until all clients are upgraded.
    #[serde(default = "default_true")]
    pub bind_static_to_session: bool,
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

/// Brute-force lockout policy. Applied independently to two surfaces, each with its
/// own instance (so panel-login limits and VPN-auth limits are set apart):
/// `[auth] brute_force` governs VPN user authentication (the data-plane worker) and
/// `[web] brute_force` governs web-panel admin login (the supervisor). `enabled =
/// false` turns the policy off entirely for that surface (no lockout, no tarpit, no
/// tracking) — useful behind an external limiter or on a trusted network.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BruteForceConfig {
    /// Master switch for this surface. `false` = no rate-limiting at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
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
            enabled: true,
            max_attempts: default_bf_max_attempts(),
            window_secs: default_bf_window(),
            lockout_secs: default_bf_lockout(),
        }
    }
}

/// The usable tunnel MTU range, shared by every component that checks one.
///
/// There used to be three different answers. The INI parser enforced nothing, the server
/// accepted the kernel's full `68..=65535`, and the client — both its own config
/// (`config/client.rs`) and the value pushed to it in AuthOK (`client/mod.rs`) — accepted
/// only `576..=9000`, silently discarding anything else and falling back to
/// `MTU_AUTO_FALLBACK`. So `tun.mtu = 300` passed `check-config`, passed startup, brought
/// the server's TUN up at 300, and left every client on 1400: a one-way MTU mismatch that
/// dropped anything larger than 300 bytes, with nothing in the logs on either side.
/// 576 is the IPv4 minimum reassembly buffer (RFC 791).
///
/// The ceiling is DERIVED from the record format, not chosen. It used to be a flat 9000 —
/// "conventional jumbo", an Ethernet convention with nothing to do with qeli — which turned
/// away perfectly workable configurations: a 10G NIC doing 16348-byte jumbo frames has room
/// for a far larger tunnel MTU, and the codec can carry it. What actually bounds a packet is
/// [`MAX_RECORD_SIZE`]: a record holds nonce + counter + payload + padding-length + tag, and
/// anything past that the PEER REJECTS. So the largest inner packet is that budget minus the
/// per-record overhead, and going higher is a wire error rather than a matter of taste.
///
/// Note the units: this is the TUNNEL (inner) MTU. The link still adds IP + UDP/TCP + the
/// record and any obfs/QUIC framing on top — about 76 bytes worst case — so on a 16348-byte
/// link the largest inner MTU that avoids outer fragmentation is nearer 16270.
/// (Audit 2026-07-27, C4; ceiling derived 2026-07-31.)
pub const MTU_MIN: u32 = 576;
pub const MTU_MAX: u32 = crate::protocol::packet::MAX_TUNNEL_MTU as u32;

/// Resolve the DHCP pool bounds for a profile, defaulting them from the tunnel subnet
/// and refusing a pool that lies outside it.
///
/// `DhcpConfig.pool_start`/`pool_end` have no serde defaults, and both places that needed
/// a fallback hard-coded `10.0.0.2`/`10.0.0.254` — an address range that has nothing to do
/// with the shipped tunnel default of `10.9.0.1/24`. Turning `dhcp.enabled` on without
/// naming a pool therefore passed validation and handed clients 10.0.0.x addresses on a
/// 10.9.0.0/24 interface, where they simply did not route. Nothing checked containment
/// either, so an explicitly-configured pool on the wrong subnet was equally silent.
/// Deriving the default from `tun.address`/`tun.netmask` and rejecting anything outside
/// that subnet fixes both, and keeping it in ONE function stops the validation path and
/// the runtime path from drifting apart again. (Audit 2026-07-27, C9.)
pub fn dhcp_pool_bounds(
    dhcp: &DhcpConfig,
    tun_address: &str,
    tun_netmask: &str,
) -> Result<(std::net::Ipv4Addr, std::net::Ipv4Addr), String> {
    use std::net::Ipv4Addr;
    let addr: Ipv4Addr = tun_address
        .parse()
        .map_err(|e| format!("invalid tun.address '{tun_address}': {e}"))?;
    let mask: Ipv4Addr = tun_netmask
        .parse()
        .map_err(|e| format!("invalid tun.netmask '{tun_netmask}': {e}"))?;
    let (a, m) = (u32::from(addr), u32::from(mask));
    let network = a & m;
    let broadcast = network | !m;
    if broadcast.saturating_sub(network) < 3 {
        return Err(format!(
            "tun subnet {tun_address}/{tun_netmask} is too small to host a DHCP pool"
        ));
    }
    // Usable host range, skipping the network address and the gateway (network|1, which
    // is what the tunnel itself uses), and the broadcast address.
    let lo = network + 2;
    let hi = broadcast - 1;

    let parse = |field: &str, val: &Option<String>, dflt: u32| -> Result<Ipv4Addr, String> {
        match val.as_deref().filter(|v| !v.trim().is_empty()) {
            Some(v) => v.trim().parse::<Ipv4Addr>().map_err(|e| {
                format!("invalid dhcp.{field} '{v}': {e} — expected a plain IPv4 address")
            }),
            None => Ok(Ipv4Addr::from(dflt)),
        }
    };
    let start = parse("pool_start", &dhcp.pool_start, lo)?;
    let end = parse("pool_end", &dhcp.pool_end, hi)?;

    if u32::from(end) < u32::from(start) {
        return Err(format!(
            "dhcp.pool_end ({end}) must not be below dhcp.pool_start ({start})"
        ));
    }
    for (field, ip) in [("pool_start", start), ("pool_end", end)] {
        let v = u32::from(ip);
        if v < lo || v > hi {
            return Err(format!(
                "dhcp.{field} ({ip}) is outside the tunnel subnet's usable range \
                 {}–{} (tun.address {tun_address}, netmask {tun_netmask}) — clients would \
                 receive addresses that cannot route on this interface",
                Ipv4Addr::from(lo),
                Ipv4Addr::from(hi)
            ));
        }
    }
    Ok((start, end))
}

/// `true` when `mtu` is inside [`MTU_MIN`]..=[`MTU_MAX`].
///
/// Takes `i64` because the same value is typed differently at each site it is checked —
/// `u32` in the server config, `i32` in the client config, `i64` when parsed out of
/// AuthOK — and having every caller open-code its own comparison is precisely how the
/// three ranges drifted apart in the first place. Callers pass `x as i64`.
pub fn mtu_in_range(mtu: i64) -> bool {
    (MTU_MIN as i64..=MTU_MAX as i64).contains(&mtu)
}

#[cfg(test)]
mod dhcp_pool_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn dhcp(start: Option<&str>, end: Option<&str>) -> DhcpConfig {
        DhcpConfig {
            enabled: true,
            pool_start: start.map(str::to_string),
            pool_end: end.map(str::to_string),
            ..Default::default()
        }
    }

    /// With no pool configured the default must come from the TUNNEL subnet, not from a
    /// hard-coded 10.0.0.x that has nothing to do with it. (Audit 2026-07-27, C9.)
    #[test]
    fn default_pool_is_derived_from_the_tun_subnet() {
        let (s, e) = dhcp_pool_bounds(&dhcp(None, None), "10.9.0.1", "255.255.255.0").unwrap();
        assert_eq!(s, "10.9.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(e, "10.9.0.254".parse::<Ipv4Addr>().unwrap());

        let (s, e) = dhcp_pool_bounds(&dhcp(None, None), "192.168.7.1", "255.255.255.0").unwrap();
        assert_eq!(s, "192.168.7.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(e, "192.168.7.254".parse::<Ipv4Addr>().unwrap());
    }

    /// A pool on a different subnet must be refused, not silently handed out.
    #[test]
    fn pool_outside_the_tun_subnet_is_rejected() {
        // The old hard-coded default, against the shipped tunnel default.
        let err = dhcp_pool_bounds(
            &dhcp(Some("10.0.0.2"), Some("10.0.0.254")),
            "10.9.0.1",
            "255.255.255.0",
        )
        .unwrap_err();
        assert!(err.contains("outside the tunnel subnet"), "got: {err}");

        // Only one end outside is enough.
        assert!(dhcp_pool_bounds(
            &dhcp(Some("10.9.0.10"), Some("10.9.1.10")),
            "10.9.0.1",
            "255.255.255.0"
        )
        .is_err());
    }

    #[test]
    fn valid_pool_and_ordering_still_work() {
        let (s, e) = dhcp_pool_bounds(
            &dhcp(Some("10.9.0.100"), Some("10.9.0.200")),
            "10.9.0.1",
            "255.255.255.0",
        )
        .unwrap();
        assert_eq!(s, "10.9.0.100".parse::<Ipv4Addr>().unwrap());
        assert_eq!(e, "10.9.0.200".parse::<Ipv4Addr>().unwrap());

        let err = dhcp_pool_bounds(
            &dhcp(Some("10.9.0.200"), Some("10.9.0.100")),
            "10.9.0.1",
            "255.255.255.0",
        )
        .unwrap_err();
        assert!(err.contains("must not be below"), "got: {err}");
    }
}

impl BruteForceConfig {
    /// Reject a policy that cannot rate-limit anything. `label` names the section
    /// (`[auth]` / `[web]`) so the operator knows which one to fix.
    ///
    /// These bounds existed only inside the panel's `POST /api/blocked/settings`
    /// handler, so every other way of setting the same four keys — the INI file,
    /// `PUT /api/config`, `PUT /api/config/raw` — wrote them unchecked. Two values were
    /// quietly catastrophic:
    ///
    /// * `window_secs = 0` — `record_ip_failure` retains only entries newer than the
    ///   window, and `now.duration_since(t) < ZERO` is false even for the entry it just
    ///   pushed, so the deque is cleared on every attempt and its length never exceeds 1.
    ///   Lockout NEVER fires, while the panel keeps reporting the policy as enabled.
    /// * `max_attempts = 0` — `len() >= 0` holds always, so the first wrong password
    ///   locks the source out. A self-inflicted denial of service.
    ///
    /// Bounds are enforced even when `enabled = false`, so flipping the switch later
    /// cannot activate a policy that was never checked. (Audit 2026-07-27, C1.)
    pub fn validate(&self, label: &str) -> Result<(), String> {
        if !(1..=10_000).contains(&self.max_attempts) {
            return Err(format!(
                "{label} brute_force.max_attempts must be between 1 and 10000 (got {}) — \
                 0 would lock out on the first failed attempt",
                self.max_attempts
            ));
        }
        if !(1..=86_400).contains(&self.window_secs) {
            return Err(format!(
                "{label} brute_force.window_secs must be between 1 and 86400 (24h) (got {}) — \
                 0 clears the failure history on every attempt, so lockout never triggers",
                self.window_secs
            ));
        }
        if !(1..=2_592_000).contains(&self.lockout_secs) {
            return Err(format!(
                "{label} brute_force.lockout_secs must be between 1 and 2592000 (30d) (got {})",
                self.lockout_secs
            ));
        }
        Ok(())
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
    /// Command run once after this profile's TUN + NAT are up (Linux only, root).
    /// SECURITY: honoured ONLY from a trusted local config file (not group/world-
    /// writable); the panel/API never writes it — so a panel compromise can't run
    /// arbitrary code. Empty = no hook.
    #[serde(default)]
    pub post_up: String,
    /// Command run when the profile/server stops cleanly, mirroring `post_up`.
    /// A crash does NOT run it.
    #[serde(default)]
    pub post_down: String,
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
    /// Resolver IP(s) pushed to clients — the client applies the FIRST entry in its
    /// `tunnel` DNS mode, INDEPENDENTLY of the in-tunnel proxy. Set this to hand
    /// clients a specific resolver (a LAN / AdGuard / NextDNS box) without running
    /// the full `dns.enabled` proxy. Empty = fall back to the proxy's listen IP when
    /// `enabled`, else push nothing. Must be a bare IP (the client strict-IP-validates
    /// the pushed value before touching resolv.conf).
    #[serde(default)]
    pub push_servers: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ServerObfuscationConfig {
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
    pub traffic_normalization: TrafficNormalizationConfig,
    /// Flow-shaping cover traffic (idle browsing-like cover; DPI-AUDIT 6.1/6.2).
    #[serde(default)]
    pub traffic_shaping: crate::config::TrafficShapingConfig,
    #[serde(default)]
    pub anti_fingerprinting: AntiFingerprintingConfig,
    #[serde(default)]
    pub quic: crate::config::QuicMaskingConfig,
    /// Stream bonding: aggregate several parallel connections into one tunnel
    /// session to beat the single-stream TCP-over-TCP throughput ceiling.
    #[serde(default)]
    pub multipath: MultipathConfig,
    /// AmneziaWG-style junk-record pre-handshake (obfs mode only; F2). Both ends
    /// must share the same `jc`. Off by default.
    #[serde(default)]
    pub awg: crate::config::AwgConfig,
}

/// Per-profile stream bonding (multipath). When enabled, a client may open up to
/// `max_streams` parallel connections that the server aggregates into ONE session
/// (one tun IP). The cap is pushed to the client in AUTH OK; the client opens
/// `min(its desired, max_streams)`. Mode-agnostic, but only useful for TCP modes
/// (UDP has no head-of-line blocking) — leave disabled / max_streams=1 on UDP
/// profiles. `max_clients * max_streams` bounds the server's total connections.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MultipathConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Hard ceiling on parallel streams per session (server-enforced, pushed to
    /// the client). Also the fixed stream count when `adaptive = false`.
    #[serde(default = "default_max_streams")]
    pub max_streams: u32,
    /// When true the client auto-ramps the stream count from 1 up to
    /// `max_streams` based on measured throughput (so `max_streams` becomes a
    /// CEILING, not a fixed target). When false the client opens exactly
    /// `max_streams` streams. Pushed to the client.
    #[serde(default)]
    pub adaptive: bool,
}

impl Default for MultipathConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_streams: default_max_streams(),
            adaptive: false,
        }
    }
}

fn default_max_streams() -> u32 {
    4
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
    /// REALITY short_ids (hex, ≤8 bytes) accepted from clients. The server discriminates qeli
    /// clients by a crypto token in the ClientHello session_id (`crypto::reality`).
    ///
    /// At least one non-empty entry is REQUIRED when `enabled` — `validate_profiles` refuses to
    /// start otherwise. This note used to say an empty list meant "legacy ALPN-absence
    /// detection", which was true of an older build and is now the opposite of what happens: an
    /// active prober defeats that heuristic trivially, so the fallback was removed rather than
    /// left as a quiet downgrade. (Audit 2026-08-03, P3.)
    #[serde(default)]
    pub short_ids: Vec<String>,
    /// When true, an authenticated ("our") client is terminated with a genuine
    /// TLS 1.3 session and the qeli tunnel runs inside it — real TLS on the wire
    /// (M3). False = legacy fake-TLS handshake directly on the socket.
    #[serde(default = "default_false")]
    pub real_tls: bool,
    /// When `real_tls` is set, terminate with the hand-rolled byte-grade TLS 1.3
    /// stack (the **default**) — it borrows the target's real certificate chain and
    /// mirrors its ServerHello JA3S (Xray-REALITY parity). Set to `false` to fall
    /// back to rustls (self-signed cert + rustls JA3S — weaker camouflage). Both
    /// require clients on the realtls stack.
    #[serde(default = "default_true")]
    pub handrolled: bool,
    /// How long (ms) to spend peeking the ClientHello before classifying the peer as
    /// a qeli client vs a probe. A ClientHello that dribbles in over a high-latency
    /// link must not be cut short and wrongly bridged to the decoy. Default 1500.
    #[serde(default = "default_peek_timeout_ms")]
    pub peek_timeout_ms: u64,
}

fn default_peek_timeout_ms() -> u64 {
    1500
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct AntiFingerprintingConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub add_jitter_to_handshake: bool,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ServerPerformanceConfig {
    #[serde(default)]
    pub tcp: TcpConfig,
    #[serde(default)]
    pub udp: UdpPerfConfig,
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
    /// The admin argon2 hash — never sent over the JSON API (`/api/config`). Written to
    /// disk by the hand-rolled INI codec (not serde), so skipping serialization is safe.
    /// NB: `/api/config/raw` still returns the file verbatim incl. this hash — a separate
    /// masking fix is needed there, taking care of the raw-editor save round-trip.
    #[serde(default, skip_serializing)]
    pub password_hash: String,
    /// Add the `Secure` attribute to the session cookie. Enable when the panel is
    /// reached over HTTPS (TLS reverse proxy). Leave off for plain-HTTP localhost /
    /// SSH-tunnel access — a `Secure` cookie is never sent over HTTP, which would
    /// lock you out of an HTTP panel.
    #[serde(default = "default_false")]
    pub secure_cookie: bool,
    /// Serve the panel with NO authentication at all.
    ///
    /// An empty `password_hash` used to mean exactly this on a loopback bind — the auth
    /// guard let every request through — so a box that had simply not run
    /// `qeli set-web-password` yet handed full admin (users, hashes, config) to any local
    /// process, and to any service on the host that can be talked into making a request
    /// for someone else (SSRF). "I have not set a password yet" and "I want no password"
    /// are different intentions and now need different configuration.
    #[serde(default = "default_false")]
    pub insecure_no_auth: bool,
    /// Persist the session-signing key to a 0600 file (in `$STATE_DIRECTORY`, else
    /// `/etc/qeli/.session_key`) so panel logins SURVIVE a full process restart instead of
    /// being dropped. Default ON. Trade-off vs the per-process-random default (H-4): a leak
    /// of BOTH the config hash AND this key file could forge a token — but the key lives in a
    /// separate 0600 file (not the config, not backups), so a config-only leak still can't.
    /// Set false to keep the stricter per-process key (sessions end on every restart).
    #[serde(default = "default_true")]
    pub persist_session_key: bool,
    /// Serve the panel over HTTPS (rustls) directly — so it can be safely exposed
    /// on a public bind without a separate reverse proxy. When true, `Secure` is
    /// added to the session cookie automatically. See `tls_cert`/`tls_key`.
    #[serde(default = "default_false")]
    pub tls: bool,
    /// PEM certificate chain path. Empty = auto self-signed (generated once and
    /// persisted to /etc/qeli/web-tls-cert.pem; browsers warn but traffic is
    /// encrypted). Set this + `tls_key` to use a real (e.g. Let's Encrypt) cert.
    #[serde(default)]
    pub tls_cert: String,
    /// PEM private key path (pairs with `tls_cert`). Empty = auto self-signed.
    #[serde(default)]
    pub tls_key: String,
    /// Source-IP allowlist (CIDRs or bare IPs). When non-empty, only these peers
    /// may reach the panel — everyone else gets 403. Empty = no IP restriction.
    /// The strongest barrier when the panel is on a public IP.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Default public host (the server's reachable address, optionally `host:port`)
    /// used to pre-fill share links/QRs so the admin doesn't retype it each time.
    /// The share dialog still lets it be edited. Empty = no default.
    /// Also accepted as a CSRF same-origin host (see `allowed_origins`).
    #[serde(default)]
    pub public_host: String,
    /// Extra browser origins allowed past the CSRF same-origin check, for when the
    /// panel is reached via a domain / reverse proxy whose host differs from `bind`
    /// (e.g. `panel.example.com` or `panel.example.com:8443`). Without this, a
    /// publicly-bound panel loads but every mutating request is rejected with 403,
    /// because the browser's `Origin` never matches the raw bind address. Entries
    /// are `host[:port]` (a full `https://host:port/...` URL is also accepted — only
    /// the host:port is used). `public_host`, loopback and the bind are always
    /// allowed implicitly.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Reverse-proxy source IPs/CIDRs whose `X-Forwarded-For` is trusted. Behind a
    /// TLS reverse proxy the socket peer is the PROXY, which makes `allowed_ips`
    /// all-or-nothing and collapses login rate-limiting into one global bucket. List
    /// the proxy addresses here and the real client IP (the rightmost XFF hop the
    /// proxy set) is used for the allowlist + brute-force limiter instead. Empty =
    /// trust no proxy and use the socket peer directly (a directly-exposed panel).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Opt-in: let the web panel check GitHub Releases for a newer qeli version and show
    /// a dismissible "update available" banner. OFF by default. The check is performed
    /// BY THE OPERATOR'S BROWSER (like the marketing site does) — no server-side beacon,
    /// no telemetry, no identifying data; the panel only runs it when this is true.
    /// See docs/CONFIG.md.
    #[serde(default = "default_false")]
    pub update_check: bool,
    /// Base path when the panel is served behind a reverse proxy under a sub-path
    /// (e.g. "/qeli"). Empty = served at the web root. A request's
    /// `X-Forwarded-Prefix` header overrides this per-request. See docs/CONFIG.md.
    #[serde(default)]
    pub base_path: String,
    /// CSRF same-origin protection for mutating panel requests. **Keep `true`.**
    /// `false` disables the Origin/Referer check entirely — only acceptable on a
    /// loopback-only bind reached via an SSH forward, NEVER on a public/LAN bind (any
    /// site you open in the same browser could then drive your logged-in panel).
    /// Loopback origins are already trusted on any port, so a normal SSH forward works
    /// WITHOUT disabling this. See docs/CONFIG.md.
    #[serde(default = "default_true")]
    pub csrf: bool,
    /// Panel login-session lifetime in seconds — governs BOTH the session cookie's
    /// `Max-Age` and the signed token's expiry. Lower it for shorter-lived admin
    /// sessions. Default 24h. (Distinct from `auth.token_ttl_secs`, the VPN client
    /// token, which does not affect the panel.)
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: i64,
    /// Brute-force lockout policy for **web-panel admin login** — independent of the
    /// VPN-auth policy in `[auth] brute_force`. Own attempt count, window and lockout
    /// so the panel and the tunnel can be tuned separately; set `enabled = false` to
    /// turn panel-login rate-limiting off entirely. See docs/CONFIG.md.
    #[serde(default)]
    pub brute_force: BruteForceConfig,
}

fn default_session_ttl() -> i64 {
    86_400
}
fn default_bind_addr() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    443
}
fn default_true() -> bool {
    true
}
fn default_transport() -> String {
    "tcp".into()
}
fn default_tun_name() -> String {
    "vpn0".into()
}
/// 10.9.x, not 10.0.0.x: a config that omits `tun.address` must not land on one of the
/// most common VPS gateway subnets. Taking the gateway's address onto the TUN black-holes
/// the host's egress and cuts the box off the network — `server::preflight` now refuses to
/// start on that collision, but the default should not walk into it in the first place.
fn default_tun_addr() -> String {
    "10.9.0.1".into()
}
fn default_tun_mask() -> String {
    "255.255.255.0".into()
}
fn default_mtu() -> i32 {
    1400
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
/// Paired with [`default_tun_addr`] — same reasoning, see there.
fn default_cidr() -> String {
    "10.9.0.0/24".into()
}
fn default_nat_iface() -> String {
    "eth0".into()
}
/// The in-tunnel resolver listens on the tunnel gateway, so this tracks
/// [`default_tun_addr`] — a mismatch would push clients a resolver that answers nowhere.
fn default_dns_listen() -> String {
    "10.9.0.1".into()
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
fn default_wire_mode() -> String {
    "fake-tls".into()
}
fn default_obfs_fronting() -> String {
    "websocket".into()
}
fn default_server_name() -> String {
    "www.cloudflare.com".into()
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
