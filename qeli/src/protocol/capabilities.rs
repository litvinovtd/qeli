//! Backward-compatible capability negotiation carried inside the authenticated handshake.
//!
//! The server trailer is appended to the existing 32-byte proof-only or 64-byte
//! `static-key || proof` message. Legacy clients already verify only the proof prefix and
//! ignore trailing bytes, so the server can advertise support without breaking them. A new
//! client sends its extension only after seeing `AUTH_EXT_V1`; an old server therefore receives
//! the byte-for-byte legacy auth layout.

use crate::config::client::{ClientIpv6Policy, ClientRoamingPolicy};

const SERVER_MAGIC: &[u8; 4] = b"QSCP";
const CLIENT_MAGIC: &[u8; 4] = b"QCCP";
const WIRE_VERSION: u8 = 1;
const SERVER_PAYLOAD_LEN: usize = 8;
const CLIENT_PAYLOAD_LEN: usize = 17;
const HEADER_LEN: usize = 6;
const CLIENT_MARKER: u8 = 0;

/// Features implemented by the server data plane, not merely understood by its parser.
pub mod server_capability {
    /// The server understands the client-auth extension defined in this module.
    pub const AUTH_EXT_V1: u64 = 1 << 0;
    pub const INNER_IPV6: u64 = 1 << 1;
    pub const NETWORK_PLAN_V2: u64 = 1 << 2;
    pub const UDP_DATA_FRAG_V1: u64 = 1 << 3;
    pub const PACKET_MUX_V1: u64 = 1 << 4;
    /// Stable wire bits for the staged roaming implementation. Advertising remains tied to the
    /// corresponding data-plane implementation; unsupported stages keep their bit clear in
    /// `implemented_server_capabilities()`.
    pub const CONTROL_V2: u64 = 1 << 5;
    pub const UDP_ROAM_V1: u64 = 1 << 6;
    pub const TCP_RESUME_V1: u64 = 1 << 7;
    pub const TCP_HANDOVER_V1: u64 = 1 << 8;
    pub const TCP_RESUME_V2: u64 = 1 << 9;
    pub const TCP_HANDOVER_V2: u64 = 1 << 10;
    pub const MANAGEMENT_V1: u64 = 1 << 11;
    pub const ROAMING_RESERVED: u64 =
        UDP_ROAM_V1 | TCP_RESUME_V1 | TCP_HANDOVER_V1 | TCP_RESUME_V2 | TCP_HANDOVER_V2;
}

/// Features implemented by the client core. Platform operations are advertised separately.
pub mod client_capability {
    pub const INNER_IPV6: u64 = 1 << 0;
    pub const NETWORK_PLAN_V2: u64 = 1 << 1;
    pub const UDP_DATA_FRAG_V1: u64 = 1 << 2;
    pub const PACKET_MUX_V1: u64 = 1 << 3;
    /// Stable client-side wire bits. The core advertises only the stages whose runtime paths are
    /// active; platform-specific operations are negotiated separately.
    pub const CONTROL_V2: u64 = 1 << 4;
    pub const UDP_ROAM_V1: u64 = 1 << 5;
    pub const TCP_RESUME_V1: u64 = 1 << 6;
    pub const TCP_HANDOVER_V1: u64 = 1 << 7;
    pub const TCP_RESUME_V2: u64 = 1 << 8;
    pub const TCP_HANDOVER_V2: u64 = 1 << 9;
    pub const MANAGEMENT_V1: u64 = 1 << 10;
    pub const ROAMING_RESERVED: u64 =
        UDP_ROAM_V1 | TCP_RESUME_V1 | TCP_HANDOVER_V1 | TCP_RESUME_V2 | TCP_HANDOVER_V2;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServerCapabilities {
    pub bits: u64,
}

impl ServerCapabilities {
    pub const fn contains(self, required: u64) -> bool {
        self.bits & required == required
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientCapabilities {
    pub core_bits: u64,
    pub platform_bits: u64,
    pub ipv6_policy: ClientIpv6Policy,
}

impl Default for ClientCapabilities {
    fn default() -> Self {
        Self {
            core_bits: 0,
            platform_bits: 0,
            ipv6_policy: ClientIpv6Policy::Auto,
        }
    }
}

/// Capabilities safe to advertise from the current server build.
///
/// These bits describe the complete negotiated implementation, not parser/schema support.
pub const fn implemented_server_capabilities() -> ServerCapabilities {
    let bits = server_capability::AUTH_EXT_V1
        | server_capability::INNER_IPV6
        | server_capability::NETWORK_PLAN_V2
        | server_capability::UDP_DATA_FRAG_V1
        | server_capability::PACKET_MUX_V1;
    #[cfg(feature = "experimental-roaming")]
    let bits = bits
        | server_capability::CONTROL_V2
        | server_capability::MANAGEMENT_V1
        | server_capability::TCP_RESUME_V2
        | server_capability::TCP_HANDOVER_V2;
    ServerCapabilities { bits }
}

/// Apply the profile's explicit rollout policy to TCP/server-generic capabilities.
pub const fn server_capabilities_for_profile(roaming_enabled: bool) -> ServerCapabilities {
    let mut capabilities = implemented_server_capabilities();
    if !roaming_enabled {
        capabilities.bits &= !server_capability::ROAMING_RESERVED;
    }
    capabilities
}

/// Capabilities safe for every UDP transport mode. After authenticated opt-in, all modes switch
/// to the same eight-byte CID envelope; QUIC masking, fake-TLS and obfs remain handshake/profile
/// choices rather than separate roaming implementations.
pub const fn implemented_udp_server_capabilities() -> ServerCapabilities {
    let capabilities = implemented_server_capabilities();
    #[cfg(feature = "experimental-roaming")]
    {
        ServerCapabilities {
            bits: capabilities.bits | server_capability::UDP_ROAM_V1,
        }
    }
    #[cfg(not(feature = "experimental-roaming"))]
    {
        capabilities
    }
}

/// Apply the same profile rollout policy to the UDP-specific capability set.
pub const fn udp_server_capabilities_for_profile(roaming_enabled: bool) -> ServerCapabilities {
    let mut capabilities = implemented_udp_server_capabilities();
    if !roaming_enabled {
        capabilities.bits &= !server_capability::ROAMING_RESERVED;
    }
    capabilities
}

/// CONTROL_V2 becomes live only after authenticated client opt-in. Individual roaming
/// operations still require their own capability bits; CONTROL_V2 alone is just framing.
pub fn control_v2_supported(client: Option<ClientCapabilities>) -> bool {
    cfg!(feature = "experimental-roaming")
        && client
            .is_some_and(|capabilities| capabilities.core_bits & client_capability::CONTROL_V2 != 0)
}

pub fn management_v1_negotiated(
    server: Option<ServerCapabilities>,
    client: Option<ClientCapabilities>,
) -> bool {
    cfg!(feature = "experimental-roaming")
        && server.is_some_and(|capabilities| {
            capabilities.contains(server_capability::CONTROL_V2 | server_capability::MANAGEMENT_V1)
        })
        && client.is_some_and(|capabilities| {
            let required = client_capability::CONTROL_V2 | client_capability::MANAGEMENT_V1;
            capabilities.core_bits & required == required
        })
}

/// UDP migration is entered only after both authenticated capability trailers confirm the
/// complete protocol prerequisites. Keeping the server value explicit prevents a client from
/// activating a reserved bit that this server deliberately did not advertise yet.
pub fn udp_roaming_negotiated(
    server: Option<ServerCapabilities>,
    client: Option<ClientCapabilities>,
) -> bool {
    let required_server = server_capability::CONTROL_V2
        | server_capability::UDP_ROAM_V1
        | server_capability::UDP_DATA_FRAG_V1;
    let required_client = client_capability::CONTROL_V2
        | client_capability::UDP_ROAM_V1
        | client_capability::UDP_DATA_FRAG_V1;
    cfg!(feature = "experimental-roaming")
        && server.is_some_and(|capabilities| capabilities.contains(required_server))
        && client
            .is_some_and(|capabilities| capabilities.core_bits & required_client == required_client)
}

/// Server-side support can be advertised before a client supervisor opts in.  A session only
/// enters the roaming lifecycle after the authenticated client extension confirms this bit.
pub fn tcp_resume_supported(client: Option<ClientCapabilities>) -> bool {
    cfg!(feature = "experimental-roaming")
        && client.is_some_and(|capabilities| {
            capabilities.core_bits & client_capability::TCP_RESUME_V2 != 0
        })
}

/// Make-before-break is negotiated separately from ordinary TCP resume. A client that only
/// opts in to `TCP_RESUME_V2` may replace a missing path, but cannot temporarily exceed the
/// stream cap or drain a still-active transport.
pub fn tcp_handover_supported(client: Option<ClientCapabilities>) -> bool {
    cfg!(feature = "experimental-roaming")
        && client.is_some_and(|capabilities| {
            let required_core =
                client_capability::TCP_RESUME_V2 | client_capability::TCP_HANDOVER_V2;
            let required_platform = crate::transport_core::platform_capability::ROAMING_PATH;
            capabilities.core_bits & required_core == required_core
                && capabilities.platform_bits & required_platform == required_platform
        })
}

/// Client data-plane features safe to advertise from this revision.
///
/// The common dual-family packet parser, NetworkPlan v2 and UDP record fragmentation are all
/// active. Platform operations remain separate and can still downgrade `auto` or fail
/// `required` before an IPv6 lease is allocated.
pub const fn implemented_client_core_capabilities() -> u64 {
    let bits = client_capability::INNER_IPV6
        | client_capability::NETWORK_PLAN_V2
        | client_capability::UDP_DATA_FRAG_V1
        | client_capability::PACKET_MUX_V1;
    // The shared supervisor owns terminal close, management events, TCP resume/handover,
    // and the UDP path actor. Negotiation below strips each migration bit unless this exact
    // transport and platform can use it.
    #[cfg(feature = "experimental-roaming")]
    let bits = bits
        | client_capability::CONTROL_V2
        | client_capability::MANAGEMENT_V1
        | client_capability::UDP_ROAM_V1
        | client_capability::TCP_RESUME_V2
        | client_capability::TCP_HANDOVER_V2;
    bits
}

/// True only when the authenticated client extension confirms the complete mux
/// data plane. `None` is a legacy client and must remain on legacy records.
pub fn packet_mux_supported(client: Option<ClientCapabilities>) -> bool {
    client
        .is_some_and(|capabilities| capabilities.core_bits & client_capability::PACKET_MUX_V1 != 0)
}

pub fn negotiate_recordizer(
    config: &crate::config::RecordizerConfig,
    client: Option<ClientCapabilities>,
) -> anyhow::Result<Option<crate::config::RecordizerConfig>> {
    if config.is_off() {
        return Ok(None);
    }
    if packet_mux_supported(client) {
        return Ok(Some(config.clone()));
    }
    if config.is_required() {
        anyhow::bail!(
            "packet recordizer is required but the client does not advertise PACKET_MUX_V1"
        );
    }
    Ok(None)
}

pub fn negotiate_client_capabilities(
    config: &crate::config::client::ClientConfig,
    server: Option<ServerCapabilities>,
    platform_bits: u64,
) -> anyhow::Result<Option<ClientCapabilities>> {
    let Some(server) = server else {
        if config.roaming == ClientRoamingPolicy::Required {
            anyhow::bail!(
                "roaming is required but the server does not advertise capability negotiation"
            );
        }
        if config.routing.ipv6 == ClientIpv6Policy::Required {
            anyhow::bail!(
                "inner IPv6 is required but the server does not advertise capability negotiation"
            );
        }
        return Ok(None);
    };
    if !server.contains(server_capability::AUTH_EXT_V1) {
        if config.roaming == ClientRoamingPolicy::Required {
            anyhow::bail!(
                "roaming is required but the server does not support the authenticated capability extension"
            );
        }
        if config.routing.ipv6 == ClientIpv6Policy::Required {
            anyhow::bail!(
                "inner IPv6 is required but the server does not support the authenticated capability extension"
            );
        }
        return Ok(None);
    }

    let roaming_path = crate::transport_core::platform_capability::ROAMING_PATH;
    let mut core_bits = implemented_client_core_capabilities();
    let explicit_mtu_blocks_ipv6 = config.tun.mtu > 0 && config.tun.mtu < 1280;
    if explicit_mtu_blocks_ipv6 {
        if config.routing.ipv6 == ClientIpv6Policy::Required {
            anyhow::bail!(
                "inner IPv6 is required but the explicit tunnel MTU {} is below the IPv6 minimum 1280",
                config.tun.mtu
            );
        }
        // `auto` is explicitly a downgrade policy. Do not advertise an IPv6 data plane that
        // the resulting NetworkPlan must reject later; let a dual profile select IPv4 before
        // either family lease is allocated.
        core_bits &= !client_capability::INNER_IPV6;
    }
    let mut required_platform = crate::transport_core::platform_capability::IPV6_TUN
        | crate::transport_core::platform_capability::IPV6_ROUTES
        | crate::transport_core::platform_capability::IPV6_DNS;
    // The NetworkPlan activates the kill switch only for a full tunnel. Requiring the
    // platform IPv6 kill-switch bit for a split profile makes an intentionally ignored
    // `kill_switch = true` downgrade `auto` (or reject `required`) even though the adapter
    // never has to install that policy.
    if config.routing.kill_switch && crate::transport_core::network::is_full_tunnel(config) {
        required_platform |= crate::transport_core::platform_capability::IPV6_KILL_SWITCH;
    }
    if platform_bits & required_platform != required_platform {
        // `auto` must downgrade instead of claiming a plan that its adapter cannot apply.
        core_bits &= !client_capability::INNER_IPV6;
    }
    if platform_bits & roaming_path != roaming_path {
        // A handover proof permits replacing a still-live carrier. Never advertise that wire
        // authority unless the adapter can transactionally prepare and bind the exact path.
        core_bits &= !client_capability::TCP_HANDOVER_V2;
    }
    if platform_bits & crate::transport_core::platform_capability::MANAGEMENT_EVENTS == 0 {
        // A newer native core can be loaded by an older GUI because ABI minors are forward
        // compatible. Do not negotiate events that the concrete adapter did not explicitly
        // promise to understand.
        core_bits &= !client_capability::MANAGEMENT_V1;
    }
    match config.server.protocol.as_str() {
        "tcp" => core_bits &= !client_capability::UDP_ROAM_V1,
        "udp" => {
            core_bits &= !(client_capability::TCP_RESUME_V2 | client_capability::TCP_HANDOVER_V2)
        }
        _ => core_bits &= !client_capability::ROAMING_RESERVED,
    }
    let udp_roaming_eligible = config.server.protocol == "udp"
        && server.contains(server_capability::UDP_ROAM_V1)
        && platform_bits & roaming_path == roaming_path;
    if !udp_roaming_eligible {
        // UDP roaming changes the post-auth wire envelope and starts a candidate path actor.
        // Advertise it only for a UDP connection whose platform can transactionally bind and
        // commit the replacement socket. Wire masking remains independent of migration.
        core_bits &= !client_capability::UDP_ROAM_V1;
    }
    if config.roaming == ClientRoamingPolicy::Off {
        core_bits &= !client_capability::ROAMING_RESERVED;
    } else if config.roaming == ClientRoamingPolicy::Required {
        if config.server.local_address.is_some() || config.server.local_port != 0 {
            anyhow::bail!(
                "roaming is required but explicit local/lport settings pin the carrier socket"
            );
        }
        let missing_platform = roaming_path & !platform_bits;
        if missing_platform != 0 {
            anyhow::bail!(
                "roaming is required but the platform adapter is missing capabilities 0x{missing_platform:x}"
            );
        }
        let (required_server, required_core) = match config.server.protocol.as_str() {
            "tcp" => (
                server_capability::CONTROL_V2
                    | server_capability::TCP_RESUME_V2
                    | server_capability::TCP_HANDOVER_V2,
                client_capability::CONTROL_V2
                    | client_capability::TCP_RESUME_V2
                    | client_capability::TCP_HANDOVER_V2,
            ),
            "udp" => (
                server_capability::CONTROL_V2
                    | server_capability::UDP_ROAM_V1
                    | server_capability::UDP_DATA_FRAG_V1,
                client_capability::CONTROL_V2
                    | client_capability::UDP_ROAM_V1
                    | client_capability::UDP_DATA_FRAG_V1,
            ),
            protocol => anyhow::bail!(
                "roaming is required but protocol '{protocol}' does not support migration"
            ),
        };
        let missing_server = required_server & !server.bits;
        if missing_server != 0 {
            anyhow::bail!(
                "roaming is required but the server is missing capabilities 0x{missing_server:x}"
            );
        }
        let missing_core = required_core & !core_bits;
        if missing_core != 0 {
            anyhow::bail!(
                "roaming is required but this client core is missing capabilities 0x{missing_core:x}"
            );
        }
    }

    if config.routing.ipv6 == ClientIpv6Policy::Required {
        let required_server = server_capability::INNER_IPV6
            | server_capability::NETWORK_PLAN_V2
            | server_capability::UDP_DATA_FRAG_V1;
        let missing_server = required_server & !server.bits;
        if missing_server != 0 {
            anyhow::bail!(
                "inner IPv6 is required but the server is missing capabilities 0x{missing_server:x}"
            );
        }
        let required_core = client_capability::INNER_IPV6
            | client_capability::NETWORK_PLAN_V2
            | client_capability::UDP_DATA_FRAG_V1;
        let missing_platform = required_platform & !platform_bits;
        if missing_platform != 0 {
            anyhow::bail!(
                "inner IPv6 is required but the platform adapter is missing capabilities 0x{missing_platform:x}"
            );
        }
        let missing_core = required_core & !core_bits;
        if missing_core != 0 {
            anyhow::bail!(
                "inner IPv6 is required but this client core is missing capabilities 0x{missing_core:x}"
            );
        }
    }

    Ok(Some(ClientCapabilities {
        core_bits,
        platform_bits,
        ipv6_policy: config.routing.ipv6,
    }))
}

/// Select the inner family mode before any pool lease is allocated.
///
/// A dual profile degrades to legacy IPv4 for an old/incapable/off client. An IPv6-only
/// profile never does: it rejects the connection while the address pools are untouched.
pub fn negotiated_profile_ip_mode(
    profile_mode: crate::config::server::IpMode,
    client: Option<ClientCapabilities>,
) -> anyhow::Result<crate::config::server::IpMode> {
    use crate::config::server::IpMode;

    let policy = client
        .map(|capabilities| capabilities.ipv6_policy)
        .unwrap_or(ClientIpv6Policy::Auto);
    let required_core = client_capability::INNER_IPV6
        | client_capability::NETWORK_PLAN_V2
        | client_capability::UDP_DATA_FRAG_V1;
    let required_platform = crate::transport_core::platform_capability::IPV6_TUN
        | crate::transport_core::platform_capability::IPV6_ROUTES
        | crate::transport_core::platform_capability::IPV6_DNS;
    let ipv6_capable = client.is_some_and(|capabilities| {
        capabilities.core_bits & required_core == required_core
            && capabilities.platform_bits & required_platform == required_platform
    });

    match (profile_mode, policy, ipv6_capable) {
        (IpMode::Ipv4, ClientIpv6Policy::Required, _) => {
            anyhow::bail!("client requires inner IPv6 but this profile is IPv4-only")
        }
        (IpMode::Ipv4, _, _) => Ok(IpMode::Ipv4),
        (IpMode::Dual, ClientIpv6Policy::Off, _) => Ok(IpMode::Ipv4),
        (IpMode::Dual, _, true) => Ok(IpMode::Dual),
        (IpMode::Dual, ClientIpv6Policy::Required, false) => {
            anyhow::bail!("client requires inner IPv6 but its negotiated core/platform capabilities are incomplete")
        }
        (IpMode::Dual, _, false) => Ok(IpMode::Ipv4),
        (IpMode::Ipv6, ClientIpv6Policy::Off, _) => {
            anyhow::bail!("client disabled inner IPv6 but this profile is IPv6-only")
        }
        (IpMode::Ipv6, _, true) => Ok(IpMode::Ipv6),
        (IpMode::Ipv6, _, false) => {
            anyhow::bail!(
                "IPv6-only profile requires complete client core/platform IPv6 capabilities"
            )
        }
    }
}

pub fn append_server_capabilities(message: &mut Vec<u8>, capabilities: ServerCapabilities) {
    message.extend_from_slice(SERVER_MAGIC);
    message.push(WIRE_VERSION);
    message.push(SERVER_PAYLOAD_LEN as u8);
    message.extend_from_slice(&capabilities.bits.to_le_bytes());
}

/// Return the legacy proof prefix and an optional understood server capability set.
///
/// A recognized magic with a malformed v1 body is rejected instead of being silently treated as
/// legacy. An unknown version is ignored, allowing a future server to retain legacy auth.
pub fn split_server_capabilities(
    message: &[u8],
) -> anyhow::Result<(&[u8], Option<ServerCapabilities>)> {
    let trailer_offset = if message.len() >= 64 + HEADER_LEN
        && message.get(64..68) == Some(SERVER_MAGIC.as_slice())
    {
        Some(64)
    } else if message.len() >= 32 + HEADER_LEN
        && message.get(32..36) == Some(SERVER_MAGIC.as_slice())
    {
        Some(32)
    } else {
        None
    };
    let Some(offset) = trailer_offset else {
        return Ok((message, None));
    };
    let version = message[offset + 4];
    let payload_len = usize::from(message[offset + 5]);
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| anyhow::anyhow!("server capability trailer length overflow"))?;
    if message.len() != offset + total {
        anyhow::bail!(
            "malformed server capability trailer: declared {payload_len} payload bytes, got {}",
            message.len().saturating_sub(offset + HEADER_LEN)
        );
    }
    if version != WIRE_VERSION {
        return Ok((&message[..offset], None));
    }
    if payload_len != SERVER_PAYLOAD_LEN {
        anyhow::bail!(
            "malformed server capability v1 payload length {payload_len}; expected {SERVER_PAYLOAD_LEN}"
        );
    }
    let bits = u64::from_le_bytes(
        message[offset + HEADER_LEN..offset + HEADER_LEN + 8]
            .try_into()
            .expect("validated server capability payload length"),
    );
    Ok((&message[..offset], Some(ServerCapabilities { bits })))
}

/// Insert a client extension between the stable device id and UTF-8 credentials.
///
/// This function must only be called after the server advertised `AUTH_EXT_V1`.
pub fn append_client_capabilities(message: &mut Vec<u8>, capabilities: ClientCapabilities) {
    message.push(CLIENT_MARKER);
    message.extend_from_slice(CLIENT_MAGIC);
    message.push(WIRE_VERSION);
    message.push(CLIENT_PAYLOAD_LEN as u8);
    message.extend_from_slice(&capabilities.core_bits.to_le_bytes());
    message.extend_from_slice(&capabilities.platform_bits.to_le_bytes());
    message.push(match capabilities.ipv6_policy {
        ClientIpv6Policy::Auto => 0,
        ClientIpv6Policy::Required => 1,
        ClientIpv6Policy::Off => 2,
    });
}

/// Split the optional capability prefix from the UTF-8 `username:password` bytes.
pub fn split_client_capabilities(
    bytes: &[u8],
) -> anyhow::Result<(Option<ClientCapabilities>, &[u8])> {
    if bytes.first() != Some(&CLIENT_MARKER) || bytes.get(1..5) != Some(CLIENT_MAGIC.as_slice()) {
        return Ok((None, bytes));
    }
    if bytes.len() < 1 + HEADER_LEN {
        anyhow::bail!("truncated client capability trailer");
    }
    let version = bytes[5];
    let payload_len = usize::from(bytes[6]);
    if version != WIRE_VERSION {
        anyhow::bail!("unsupported client capability version {version}");
    }
    if payload_len != CLIENT_PAYLOAD_LEN {
        anyhow::bail!(
            "malformed client capability v1 payload length {payload_len}; expected {CLIENT_PAYLOAD_LEN}"
        );
    }
    let extension_len = 1 + HEADER_LEN + payload_len;
    if bytes.len() < extension_len {
        anyhow::bail!(
            "truncated client capability payload: declared {payload_len} bytes, got {}",
            bytes.len().saturating_sub(1 + HEADER_LEN)
        );
    }
    let payload = &bytes[1 + HEADER_LEN..extension_len];
    let core_bits = u64::from_le_bytes(payload[..8].try_into().expect("8-byte core bits"));
    let platform_bits =
        u64::from_le_bytes(payload[8..16].try_into().expect("8-byte platform bits"));
    let ipv6_policy = match payload[16] {
        0 => ClientIpv6Policy::Auto,
        1 => ClientIpv6Policy::Required,
        2 => ClientIpv6Policy::Off,
        value => anyhow::bail!("invalid client IPv6 policy value {value}"),
    };
    Ok((
        Some(ClientCapabilities {
            core_bits,
            platform_bits,
            ipv6_policy,
        }),
        &bytes[extension_len..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_trailer_preserves_both_legacy_proof_shapes() {
        for proof_len in [32usize, 64] {
            let proof = vec![0xA5; proof_len];
            let mut message = proof.clone();
            append_server_capabilities(
                &mut message,
                ServerCapabilities {
                    bits: server_capability::AUTH_EXT_V1 | server_capability::NETWORK_PLAN_V2,
                },
            );
            let (parsed_proof, capabilities) =
                split_server_capabilities(&message).expect("valid trailer");
            assert_eq!(parsed_proof, proof);
            assert!(capabilities
                .expect("capabilities")
                .contains(server_capability::AUTH_EXT_V1));
        }
    }

    #[test]
    fn legacy_server_message_has_no_capabilities() {
        let proof = vec![7u8; 64];
        let (parsed, capabilities) = split_server_capabilities(&proof).unwrap();
        assert_eq!(parsed, proof);
        assert_eq!(capabilities, None);
    }

    #[test]
    fn malformed_known_server_trailer_fails_closed() {
        let mut message = vec![0u8; 32];
        message.extend_from_slice(SERVER_MAGIC);
        message.extend_from_slice(&[WIRE_VERSION, SERVER_PAYLOAD_LEN as u8, 1, 2]);
        assert!(split_server_capabilities(&message).is_err());
    }

    #[test]
    fn client_extension_roundtrips_without_consuming_credentials() {
        let capabilities = ClientCapabilities {
            core_bits: client_capability::INNER_IPV6 | client_capability::NETWORK_PLAN_V2,
            platform_bits: 0x1234,
            ipv6_policy: ClientIpv6Policy::Required,
        };
        let mut bytes = Vec::new();
        append_client_capabilities(&mut bytes, capabilities);
        bytes.extend_from_slice(b"alice:secret");
        let (parsed, credentials) = split_client_capabilities(&bytes).unwrap();
        assert_eq!(parsed, Some(capabilities));
        assert_eq!(credentials, b"alice:secret");
    }

    #[test]
    fn udp_roaming_requires_bidirectional_explicit_opt_in_and_data_frag() {
        let server = ServerCapabilities {
            bits: server_capability::CONTROL_V2
                | server_capability::UDP_ROAM_V1
                | server_capability::UDP_DATA_FRAG_V1,
        };
        let client = ClientCapabilities {
            core_bits: client_capability::CONTROL_V2
                | client_capability::UDP_ROAM_V1
                | client_capability::UDP_DATA_FRAG_V1,
            ..ClientCapabilities::default()
        };
        #[cfg(feature = "experimental-roaming")]
        assert!(udp_roaming_negotiated(Some(server), Some(client)));
        #[cfg(not(feature = "experimental-roaming"))]
        assert!(!udp_roaming_negotiated(Some(server), Some(client)));

        assert!(!udp_roaming_negotiated(None, Some(client)));
        assert!(!udp_roaming_negotiated(Some(server), None));
        assert!(!udp_roaming_negotiated(
            Some(server),
            Some(ClientCapabilities {
                core_bits: client.core_bits & !client_capability::UDP_DATA_FRAG_V1,
                ..client
            })
        ));
    }

    #[test]
    fn management_requires_bidirectional_opt_in_and_is_not_disabled_with_roaming() {
        let server = ServerCapabilities {
            bits: server_capability::CONTROL_V2 | server_capability::MANAGEMENT_V1,
        };
        let client = ClientCapabilities {
            core_bits: client_capability::CONTROL_V2 | client_capability::MANAGEMENT_V1,
            ..ClientCapabilities::default()
        };
        #[cfg(feature = "experimental-roaming")]
        {
            assert!(management_v1_negotiated(Some(server), Some(client)));
            assert!(server_capabilities_for_profile(false)
                .contains(server_capability::CONTROL_V2 | server_capability::MANAGEMENT_V1));
        }
        #[cfg(not(feature = "experimental-roaming"))]
        assert!(!management_v1_negotiated(Some(server), Some(client)));
        assert!(!management_v1_negotiated(None, Some(client)));
        assert!(!management_v1_negotiated(Some(server), None));
        assert!(!management_v1_negotiated(
            Some(server),
            Some(ClientCapabilities {
                core_bits: client.core_bits & !client_capability::MANAGEMENT_V1,
                ..client
            })
        ));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn management_wire_capability_requires_platform_event_opt_in() {
        let config = crate::config::client::ClientConfig::default();
        let server = Some(implemented_server_capabilities());
        let legacy_gui = negotiate_client_capabilities(&config, server, 0)
            .unwrap()
            .expect("authenticated capability extension");
        assert_eq!(legacy_gui.core_bits & client_capability::MANAGEMENT_V1, 0);

        let aware_gui = negotiate_client_capabilities(
            &config,
            server,
            crate::transport_core::platform_capability::MANAGEMENT_EVENTS,
        )
        .unwrap()
        .expect("authenticated capability extension");
        assert_ne!(aware_gui.core_bits & client_capability::MANAGEMENT_V1, 0);
        assert!(management_v1_negotiated(server, Some(aware_gui),));
    }

    #[test]
    fn udp_roaming_server_advertisement_is_feature_and_transport_scoped() {
        assert!(!implemented_server_capabilities().contains(server_capability::UDP_ROAM_V1));
        #[cfg(feature = "experimental-roaming")]
        assert!(implemented_udp_server_capabilities()
            .contains(server_capability::CONTROL_V2 | server_capability::UDP_ROAM_V1));
        #[cfg(not(feature = "experimental-roaming"))]
        assert!(!implemented_udp_server_capabilities().contains(server_capability::UDP_ROAM_V1));
    }

    #[test]
    fn profile_policy_is_default_off_for_both_transport_families() {
        let tcp = server_capabilities_for_profile(false);
        let udp = udp_server_capabilities_for_profile(false);
        assert_eq!(tcp.bits & server_capability::ROAMING_RESERVED, 0);
        assert_eq!(udp.bits & server_capability::ROAMING_RESERVED, 0);
        assert!(tcp.contains(server_capability::AUTH_EXT_V1));
        assert!(udp.contains(server_capability::UDP_DATA_FRAG_V1));

        assert_eq!(
            server_capabilities_for_profile(true),
            implemented_server_capabilities()
        );
        assert_eq!(
            udp_server_capabilities_for_profile(true),
            implemented_udp_server_capabilities()
        );
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn udp_roaming_client_opt_in_requires_exact_transport_server_and_platform() {
        let mut config = crate::config::client::ClientConfig::default();
        config.server.protocol = "udp".to_string();
        let server = Some(implemented_udp_server_capabilities());
        for (mode, quic, awg) in [
            ("fake-tls", false, false),
            ("fake-tls", true, false),
            ("obfs", false, false),
            ("obfs", false, true),
        ] {
            config.obfuscation.mode = mode.to_string();
            config.obfuscation.quic.enabled = quic;
            config.obfuscation.awg.enabled = awg;
            let complete = negotiate_client_capabilities(
                &config,
                server,
                crate::transport_core::platform_capability::ROAMING_PATH,
            )
            .unwrap()
            .expect("authenticated capability extension");
            assert_ne!(
                complete.core_bits & client_capability::UDP_ROAM_V1,
                0,
                "UDP roaming must not depend on camouflage mode={mode}, quic={quic}, awg={awg}",
            );
        }

        let no_path = negotiate_client_capabilities(&config, server, 0)
            .unwrap()
            .expect("authenticated capability extension");
        assert_eq!(no_path.core_bits & client_capability::UDP_ROAM_V1, 0);

        config.server.protocol = "tcp".to_string();
        let tcp = negotiate_client_capabilities(
            &config,
            server,
            crate::transport_core::platform_capability::ROAMING_PATH,
        )
        .unwrap()
        .expect("authenticated capability extension");
        assert_eq!(tcp.core_bits & client_capability::UDP_ROAM_V1, 0);

        config.server.protocol = "udp".to_string();
        let generic_server = negotiate_client_capabilities(
            &config,
            Some(implemented_server_capabilities()),
            crate::transport_core::platform_capability::ROAMING_PATH,
        )
        .unwrap()
        .expect("authenticated capability extension");
        assert_eq!(generic_server.core_bits & client_capability::UDP_ROAM_V1, 0);
    }

    #[test]
    fn legacy_credentials_are_unchanged() {
        let credentials = b"alice:secret";
        let (capabilities, parsed) = split_client_capabilities(credentials).unwrap();
        assert_eq!(capabilities, None);
        assert_eq!(parsed, credentials);
    }

    #[test]
    fn invalid_client_policy_is_rejected() {
        let mut bytes = Vec::new();
        append_client_capabilities(&mut bytes, ClientCapabilities::default());
        bytes[1 + HEADER_LEN + 16] = 9;
        bytes.extend_from_slice(b"alice:secret");
        assert!(split_client_capabilities(&bytes).is_err());
    }

    #[test]
    fn required_ipv6_fails_closed_against_legacy_server() {
        let mut config = crate::config::client::ClientConfig::default();
        config.routing.ipv6 = ClientIpv6Policy::Required;
        let error = negotiate_client_capabilities(&config, None, 0).unwrap_err();
        assert!(error.to_string().contains("does not advertise"));
    }

    #[test]
    fn enabled_build_advertises_the_complete_inner_ipv6_contract() {
        let server = implemented_server_capabilities();
        assert!(server.contains(
            server_capability::AUTH_EXT_V1
                | server_capability::INNER_IPV6
                | server_capability::NETWORK_PLAN_V2
                | server_capability::UDP_DATA_FRAG_V1
        ));
        assert_eq!(
            implemented_client_core_capabilities()
                & (client_capability::INNER_IPV6
                    | client_capability::NETWORK_PLAN_V2
                    | client_capability::UDP_DATA_FRAG_V1),
            client_capability::INNER_IPV6
                | client_capability::NETWORK_PLAN_V2
                | client_capability::UDP_DATA_FRAG_V1
        );
    }

    #[test]
    fn roaming_policy_is_legacy_compatible_and_required_is_fail_closed_for_both_transports() {
        let platform = crate::transport_core::platform_capability::ROAMING_PATH;
        for protocol in ["tcp", "udp"] {
            let mut config = crate::config::client::ClientConfig::default();
            config.server.protocol = protocol.to_string();
            config.roaming = ClientRoamingPolicy::Auto;

            assert_eq!(
                negotiate_client_capabilities(&config, None, platform).unwrap(),
                None,
                "{protocol} auto must keep the byte-for-byte legacy AUTH layout"
            );
            assert_eq!(
                negotiate_client_capabilities(
                    &config,
                    Some(ServerCapabilities::default()),
                    platform,
                )
                .unwrap(),
                None,
                "{protocol} auto must also accept a pre-AUTH_EXT_V1 peer"
            );

            config.roaming = ClientRoamingPolicy::Required;
            let no_trailer = negotiate_client_capabilities(&config, None, platform).unwrap_err();
            assert!(no_trailer.to_string().contains("does not advertise"));
            let pre_extension = negotiate_client_capabilities(
                &config,
                Some(ServerCapabilities::default()),
                platform,
            )
            .unwrap_err();
            assert!(pre_extension.to_string().contains("does not support"));
        }
    }

    #[test]
    fn explicit_small_mtu_downgrades_auto_and_rejects_required_ipv6() {
        let server = implemented_server_capabilities();
        let platform = crate::transport_core::platform_capability::IPV6_TUN
            | crate::transport_core::platform_capability::IPV6_ROUTES
            | crate::transport_core::platform_capability::IPV6_DNS;
        let mut config = crate::config::client::ClientConfig::default();
        config.tun.mtu = 1200;
        let auto = negotiate_client_capabilities(&config, Some(server), platform)
            .unwrap()
            .expect("capability extension");
        assert_eq!(auto.core_bits & client_capability::INNER_IPV6, 0);

        config.routing.ipv6 = ClientIpv6Policy::Required;
        let error = negotiate_client_capabilities(&config, Some(server), platform).unwrap_err();
        assert!(error.to_string().contains("below the IPv6 minimum 1280"));
    }

    #[test]
    fn split_tunnel_does_not_require_an_unused_ipv6_kill_switch() {
        let server = implemented_server_capabilities();
        let platform = crate::transport_core::platform_capability::IPV6_TUN
            | crate::transport_core::platform_capability::IPV6_ROUTES
            | crate::transport_core::platform_capability::IPV6_DNS;
        let mut config = crate::config::client::ClientConfig::default();
        config.routing.mode = "split-tunnel".to_string();
        config.routing.add_default_gateway = false;
        config.routing.kill_switch = true;

        let auto = negotiate_client_capabilities(&config, Some(server), platform)
            .unwrap()
            .expect("capability extension");
        assert_ne!(auto.core_bits & client_capability::INNER_IPV6, 0);

        config.routing.ipv6 = ClientIpv6Policy::Required;
        let required = negotiate_client_capabilities(&config, Some(server), platform)
            .unwrap()
            .expect("capability extension");
        assert_ne!(required.core_bits & client_capability::INNER_IPV6, 0);
    }

    #[test]
    fn full_tunnel_still_requires_the_ipv6_kill_switch_capability() {
        let server = implemented_server_capabilities();
        let platform = crate::transport_core::platform_capability::IPV6_TUN
            | crate::transport_core::platform_capability::IPV6_ROUTES
            | crate::transport_core::platform_capability::IPV6_DNS;
        let mut config = crate::config::client::ClientConfig::default();
        config.routing.add_default_gateway = true;
        config.routing.kill_switch = true;

        let auto = negotiate_client_capabilities(&config, Some(server), platform)
            .unwrap()
            .expect("capability extension");
        assert_eq!(auto.core_bits & client_capability::INNER_IPV6, 0);

        config.routing.ipv6 = ClientIpv6Policy::Required;
        let error = negotiate_client_capabilities(&config, Some(server), platform).unwrap_err();
        assert!(error.to_string().contains("platform adapter is missing"));
    }
    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn client_roaming_policy_masks_or_requires_the_complete_transport_contract() {
        let platform = crate::transport_core::platform_capability::ROAMING_PATH;
        let mut config = crate::config::client::ClientConfig::default();
        config.server.protocol = "tcp".to_string();
        config.roaming = ClientRoamingPolicy::Off;
        let off = negotiate_client_capabilities(
            &config,
            Some(implemented_server_capabilities()),
            platform,
        )
        .unwrap()
        .expect("capability extension");
        assert_eq!(off.core_bits & client_capability::ROAMING_RESERVED, 0);

        config.roaming = ClientRoamingPolicy::Auto;
        let tcp = negotiate_client_capabilities(
            &config,
            Some(implemented_server_capabilities()),
            platform,
        )
        .unwrap()
        .expect("capability extension");
        assert_eq!(tcp.core_bits & client_capability::UDP_ROAM_V1, 0);
        assert_eq!(
            tcp.core_bits
                & (client_capability::CONTROL_V2
                    | client_capability::TCP_RESUME_V2
                    | client_capability::TCP_HANDOVER_V2),
            client_capability::CONTROL_V2
                | client_capability::TCP_RESUME_V2
                | client_capability::TCP_HANDOVER_V2
        );

        config.server.protocol = "udp".to_string();
        let udp = negotiate_client_capabilities(
            &config,
            Some(implemented_udp_server_capabilities()),
            platform,
        )
        .unwrap()
        .expect("capability extension");
        assert_eq!(
            udp.core_bits & (client_capability::TCP_RESUME_V2 | client_capability::TCP_HANDOVER_V2),
            0
        );
        assert_ne!(udp.core_bits & client_capability::UDP_ROAM_V1, 0);

        config.roaming = ClientRoamingPolicy::Required;
        let required = negotiate_client_capabilities(
            &config,
            Some(implemented_udp_server_capabilities()),
            platform,
        )
        .unwrap()
        .expect("capability extension");
        assert_ne!(required.core_bits & client_capability::UDP_ROAM_V1, 0);
        let error =
            negotiate_client_capabilities(&config, Some(implemented_udp_server_capabilities()), 0)
                .unwrap_err();
        assert!(error.to_string().contains("platform adapter is missing"));

        config.server.protocol = "tcp".to_string();
        let server_without_handover = ServerCapabilities {
            bits: implemented_server_capabilities().bits & !server_capability::TCP_HANDOVER_V2,
        };
        let error = negotiate_client_capabilities(&config, Some(server_without_handover), platform)
            .unwrap_err();
        assert!(error.to_string().contains("server is missing"));
    }

    #[test]
    fn packet_mux_is_advertised_and_server_policy_negotiates_safely() {
        assert!(implemented_server_capabilities().contains(server_capability::PACKET_MUX_V1));
        assert_ne!(
            implemented_client_core_capabilities() & client_capability::PACKET_MUX_V1,
            0
        );

        let capable = Some(ClientCapabilities {
            core_bits: client_capability::PACKET_MUX_V1,
            ..ClientCapabilities::default()
        });
        let mut config = crate::config::RecordizerConfig::default();
        assert!(negotiate_recordizer(&config, capable).unwrap().is_none());

        config.policy = "prefer".to_string();
        assert!(negotiate_recordizer(&config, capable).unwrap().is_some());
        assert!(negotiate_recordizer(&config, None).unwrap().is_none());

        config.policy = "required".to_string();
        assert!(negotiate_recordizer(&config, capable).unwrap().is_some());
        assert!(negotiate_recordizer(&config, None)
            .unwrap_err()
            .to_string()
            .contains("PACKET_MUX_V1"));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn client_handover_requires_the_complete_platform_path_contract() {
        let mut config = crate::config::client::ClientConfig::default();
        config.server.protocol = "tcp".to_string();
        let server = Some(implemented_server_capabilities());
        let without_path = negotiate_client_capabilities(&config, server, 0)
            .unwrap()
            .expect("authenticated capability extension");
        assert_eq!(
            without_path.core_bits & client_capability::TCP_HANDOVER_V2,
            0
        );

        let transactions_only = negotiate_client_capabilities(
            &config,
            server,
            crate::transport_core::platform_capability::PATH_TRANSACTIONS,
        )
        .unwrap()
        .expect("authenticated capability extension");
        assert_eq!(
            transactions_only.core_bits & client_capability::TCP_HANDOVER_V2,
            0
        );

        let complete = negotiate_client_capabilities(
            &config,
            server,
            crate::transport_core::platform_capability::ROAMING_PATH,
        )
        .unwrap()
        .expect("authenticated capability extension");
        assert_ne!(complete.core_bits & client_capability::TCP_HANDOVER_V2, 0);
    }

    #[test]
    fn tcp_roaming_server_bits_follow_the_build_gate_and_require_client_opt_in() {
        let server = implemented_server_capabilities();
        #[cfg(feature = "experimental-roaming")]
        assert!(server.contains(
            server_capability::CONTROL_V2
                | server_capability::TCP_RESUME_V2
                | server_capability::TCP_HANDOVER_V2
        ));
        assert_eq!(
            server.bits & (server_capability::TCP_RESUME_V1 | server_capability::TCP_HANDOVER_V1),
            0
        );
        #[cfg(not(feature = "experimental-roaming"))]
        assert_eq!(server.bits & server_capability::ROAMING_RESERVED, 0);

        // Server capability alone never changes a session. The authenticated client
        // extension and complete platform contract must opt in.
        #[cfg(feature = "experimental-roaming")]
        assert_eq!(
            implemented_client_core_capabilities() & client_capability::ROAMING_RESERVED,
            client_capability::CONTROL_V2
                | client_capability::UDP_ROAM_V1
                | client_capability::TCP_RESUME_V2
                | client_capability::TCP_HANDOVER_V2
        );
        #[cfg(not(feature = "experimental-roaming"))]
        assert_eq!(
            implemented_client_core_capabilities() & client_capability::ROAMING_RESERVED,
            0
        );
        assert!(!tcp_resume_supported(None));
        let legacy_v1 = Some(ClientCapabilities {
            core_bits: client_capability::TCP_RESUME_V1 | client_capability::TCP_HANDOVER_V1,
            platform_bits: crate::transport_core::platform_capability::ROAMING_PATH,
            ..ClientCapabilities::default()
        });
        assert!(!tcp_resume_supported(legacy_v1));
        assert!(!tcp_handover_supported(legacy_v1));
        let opted_in = Some(ClientCapabilities {
            core_bits: client_capability::CONTROL_V2 | client_capability::TCP_RESUME_V2,
            ..ClientCapabilities::default()
        });
        #[cfg(feature = "experimental-roaming")]
        {
            assert!(control_v2_supported(opted_in));
            assert!(tcp_resume_supported(opted_in));
            assert!(!tcp_handover_supported(opted_in));
            let handover_without_path = Some(ClientCapabilities {
                core_bits: client_capability::TCP_RESUME_V2 | client_capability::TCP_HANDOVER_V2,
                ..ClientCapabilities::default()
            });
            assert!(!tcp_handover_supported(handover_without_path));
            let handover = Some(ClientCapabilities {
                core_bits: client_capability::TCP_RESUME_V2 | client_capability::TCP_HANDOVER_V2,
                platform_bits: crate::transport_core::platform_capability::ROAMING_PATH,
                ..ClientCapabilities::default()
            });
            assert!(tcp_handover_supported(handover));
        }
        #[cfg(not(feature = "experimental-roaming"))]
        {
            assert!(!control_v2_supported(opted_in));
            assert!(!tcp_resume_supported(opted_in));
            assert!(!tcp_handover_supported(opted_in));
        }
    }
}
