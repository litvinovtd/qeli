//! Platform-neutral values produced by the qeli authentication handshake.
//!
//! Keep server-push parsing here so Linux and every FFI client validate exactly the same
//! untrusted response before a platform network plan is constructed.

use crate::config::PushedObf;
#[cfg(any(feature = "client", test))]
use crate::crypto::{
    derive_keys, derive_keys_bound, derive_keys_hybrid, derive_keys_hybrid_bound,
    handshake_transcript_hash, Keypair,
};
#[cfg(feature = "experimental-roaming")]
#[cfg(any(feature = "client", test))]
use crate::crypto::{
    derive_session_material, derive_session_material_bound, derive_session_material_hybrid,
    derive_session_material_hybrid_bound,
};
#[cfg(any(feature = "client", test))]
use crate::protocol::stream_io::WriteAllFlush;
#[cfg(any(feature = "client", test))]
use crate::protocol::{read_record, read_tls_record, FakeTlsHandshake, Framing, PacketCodec};
#[cfg(any(feature = "client", test))]
use std::future::Future;
#[cfg(any(feature = "client", test))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// One REALITY ClientHello policy for Linux CLI and every native app runtime.
/// Compact is explicit: there is no failure-triggered downgrade from the PQ offer.
#[cfg(any(feature = "client", test))]
pub(crate) async fn establish_reality_tls<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
) -> anyhow::Result<crate::protocol::realtls::client::EstablishedTls> {
    let short_id = config
        .obfuscation
        .reality_short_id
        .as_deref()
        .and_then(crate::crypto::reality::parse_short_id)
        .ok_or_else(|| anyhow::anyhow!("reality-tls requires a valid reality_sid"))?;
    let public = config
        .auth
        .server_public_key
        .as_deref()
        .and_then(crate::crypto::parse_pubkey_hex)
        .filter(|key| key.iter().any(|byte| *byte != 0))
        .ok_or_else(|| anyhow::anyhow!("reality-tls requires a pinned server_public_key"))?;
    let ephemeral = Keypair::generate();
    let session_id = crate::crypto::reality::seal_session_id(
        &crate::crypto::PublicKey::from_bytes(&public),
        &ephemeral,
        &short_id,
    );
    let policy = &config.obfuscation;
    if policy.reality_compact {
        log::info!("REALITY compact: small X25519 outer ClientHello; mandatory INNER_PQ_V1 inside TLS before AUTH (X25519 + ML-KEM-768, no classical fallback)");
    }
    if !policy.reality_split.is_empty() && policy.reality_split != "none" {
        log::info!(
            "REALITY-TLS ClientHello split={} delay={}ms compact={}",
            policy.reality_split,
            policy.reality_split_delay_ms,
            policy.reality_compact
        );
    }
    crate::protocol::realtls::client::client_handshake_evasive(
        stream,
        ephemeral,
        session_id,
        config.effective_reality_sni(),
        policy.reality_compact,
        &policy.reality_split,
        policy.reality_split_delay_ms,
    )
    .await
    .map_err(anyhow::Error::from)
}

#[derive(Debug)]
pub(crate) struct AuthOk {
    pub family_mode: crate::transport_core::NetworkFamilyMode,
    pub addresses: Vec<crate::transport_core::NetworkAddress>,
    pub client_ip: String,
    pub server_ip: String,
    pub prefix: u8,
    pub mtu: i32,
    pub dns_ip: String,
    pub dns_port: String,
    pub dns_servers: Vec<crate::transport_core::NetworkDns>,
    pub routes_json: String,
    pub pushed_obf: Option<PushedObf>,
    #[cfg(any(feature = "client", test))]
    pub session_token: String,
    pub max_streams: u32,
    pub adaptive: bool,
    /// Present only after bidirectional UDP_ROAM_V1 negotiation. Hex avoids JSON's lossy
    /// numeric representation in app-layer parsers while retaining the protocol's full u64.
    #[cfg(any(feature = "client", test))]
    pub udp_roaming_session_id: Option<u64>,
}

/// Complete result of the authenticated primary TCP handshake.
///
/// Roaming builds retain only the domain-separated resume secret from the original
/// authentication KDF. It is never serialized, cloned into diagnostics, or reused as a
/// data-plane key. Default builds do not carry the field at all.
#[cfg(any(feature = "client", test))]
pub(crate) struct TcpAuthentication {
    pub client_rx: PacketCodec,
    pub client_tx: PacketCodec,
    pub auth: AuthOk,
    pub server_capabilities: Option<crate::protocol::capabilities::ServerCapabilities>,
    #[cfg(feature = "experimental-roaming")]
    pub client_capabilities: Option<crate::protocol::capabilities::ClientCapabilities>,
    #[cfg(feature = "experimental-roaming")]
    pub resume_secret: zeroize::Zeroizing<[u8; 32]>,
}

/// One hybrid UDP ClientHello flight shared by the live tunnel and native diagnostics.
/// Keeping construction here prevents a reachability check from growing a second TLS/PQ/
/// fragmentation implementation that can silently drift from the data plane.
#[cfg(any(feature = "client", test))]
pub(crate) struct UdpClientHelloFlight {
    pub client_keypair: Keypair,
    pub mlkem_decapsulation_key: crate::crypto::mlkem::DecapKey,
    pub client_hello: Vec<u8>,
    pub fragments: Vec<Vec<u8>>,
}

#[cfg(any(feature = "client", test))]
pub(crate) fn build_udp_client_hello_flight(
    config: &crate::config::client::ClientConfig,
) -> anyhow::Result<UdpClientHelloFlight> {
    if config.server.protocol != "udp" {
        anyhow::bail!("UDP ClientHello flight requires proto = udp");
    }
    if !matches!(config.obfuscation.mode.as_str(), "fake-tls" | "obfs") {
        anyhow::bail!(
            "UDP ClientHello flight does not support mode = {}",
            config.obfuscation.mode
        );
    }
    let client_keypair = Keypair::generate();
    let server_name = config.effective_fake_tls_sni();
    let (client_hello, mlkem_decapsulation_key) =
        FakeTlsHandshake::build_client_hello_pq(client_keypair.public(), server_name, 1200, None);
    let fragments = crate::protocol::udp_frag::fragment(
        crate::protocol::udp_frag::MSG_CLIENT_HELLO,
        &client_hello,
    )
    .map_err(|error| anyhow::anyhow!("ClientHello too large to fragment: {error}"))?;
    Ok(UdpClientHelloFlight {
        client_keypair,
        mlkem_decapsulation_key,
        client_hello,
        fragments,
    })
}

pub(crate) fn parse_auth_ok(response: &str) -> anyhow::Result<AuthOk> {
    let json = response
        .strip_prefix("OK:")
        .ok_or_else(|| anyhow::anyhow!("auth failed: {response}"))?;
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| anyhow::anyhow!("malformed auth OK json: {error}"))?;

    let has_family_mode = value.get("family_mode").is_some();
    let has_addresses = value.get("addresses").is_some();
    if has_family_mode != has_addresses {
        anyhow::bail!("auth OK NetworkPlan v2 must contain both family_mode and addresses");
    }
    let v2 = has_family_mode;

    let client_ip = value["client_ip"].as_str().unwrap_or("").to_string();
    if client_ip.is_empty() {
        anyhow::bail!("auth OK missing client_ip");
    }
    let server_ip = value["server_ip"].as_str().unwrap_or("").to_string();

    let dns_port = match &value["dns_port"] {
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::String(text) => text.clone(),
        _ => "53".to_string(),
    };
    let prefix_limit = if v2 { 128 } else { 32 };
    let prefix = match value.get("prefix").and_then(serde_json::Value::as_u64) {
        Some(number) if (1..=prefix_limit).contains(&number) => number as u8,
        Some(_) | None if v2 => {
            anyhow::bail!("auth OK NetworkPlan v2 contains an invalid legacy prefix projection")
        }
        // Older IPv4-only servers omitted this field, and legacy clients historically
        // treated an invalid value as the old /24 default. Keep that compatibility only
        // outside NetworkPlan v2; v2 is self-describing and must agree exactly with the
        // selected address below.
        Some(_) | None => 24,
    };
    let mtu = value["mtu"]
        .as_i64()
        .filter(|mtu| crate::config::server::mtu_in_range(*mtu))
        .map(|mtu| mtu as i32)
        .unwrap_or(0);

    let (family_mode, addresses, dns_servers) = if v2 {
        let family_mode: crate::transport_core::NetworkFamilyMode =
            serde_json::from_value(value["family_mode"].clone())
                .map_err(|error| anyhow::anyhow!("invalid auth OK family_mode: {error}"))?;
        let addresses: Vec<crate::transport_core::NetworkAddress> =
            serde_json::from_value(value["addresses"].clone())
                .map_err(|error| anyhow::anyhow!("invalid auth OK addresses: {error}"))?;
        if addresses.is_empty() || addresses.len() > 2 {
            anyhow::bail!("auth OK must contain one address per active IP family");
        }
        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        for assigned in &addresses {
            let address: std::net::IpAddr = assigned.address.parse().map_err(|_| {
                anyhow::anyhow!("invalid auth OK tunnel address '{}'", assigned.address)
            })?;
            let (expected_family, max_prefix) = if address.is_ipv4() {
                if has_ipv4 {
                    anyhow::bail!("auth OK contains duplicate IPv4 addresses");
                }
                has_ipv4 = true;
                (crate::transport_core::NetworkAddressFamily::Ipv4, 32)
            } else {
                if has_ipv6 {
                    anyhow::bail!("auth OK contains duplicate IPv6 addresses");
                }
                has_ipv6 = true;
                (crate::transport_core::NetworkAddressFamily::Ipv6, 128)
            };
            if assigned.family != expected_family
                || assigned.prefix_len == 0
                || assigned.prefix_len > max_prefix
                || assigned.on_link_prefix_len == 0
                || assigned.on_link_prefix_len > assigned.prefix_len
            {
                anyhow::bail!(
                    "invalid auth OK address metadata for '{}'",
                    assigned.address
                );
            }
            if let std::net::IpAddr::V6(address) = address {
                crate::config::server::validate_tunnel_ipv6_address("auth OK address", address)
                    .map_err(anyhow::Error::msg)?;
            }
            if let Some(gateway) = &assigned.gateway {
                let gateway: std::net::IpAddr = gateway
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid auth OK tunnel gateway '{gateway}'"))?;
                if gateway.is_ipv4() != address.is_ipv4() {
                    anyhow::bail!(
                        "auth OK address '{}' and gateway '{}' use different families",
                        assigned.address,
                        gateway
                    );
                }
                if let std::net::IpAddr::V6(gateway) = gateway {
                    crate::config::server::validate_tunnel_ipv6_address(
                        "auth OK tunnel gateway",
                        gateway,
                    )
                    .map_err(anyhow::Error::msg)?;
                }
            }
        }
        let expected_mode = match (has_ipv4, has_ipv6) {
            (true, false) => crate::transport_core::NetworkFamilyMode::Ipv4,
            (true, true) => crate::transport_core::NetworkFamilyMode::Dual,
            (false, true) => crate::transport_core::NetworkFamilyMode::Ipv6,
            (false, false) => unreachable!("empty address list rejected"),
        };
        if family_mode != expected_mode {
            anyhow::bail!("auth OK family_mode does not match its address families");
        }
        if has_ipv6 && mtu < 1280 {
            anyhow::bail!("auth OK IPv6 plan MTU {mtu} is below the IPv6 minimum 1280");
        }
        let projection = addresses
            .iter()
            .find(|address| address.family == crate::transport_core::NetworkAddressFamily::Ipv4)
            .unwrap_or(&addresses[0]);
        if client_ip != projection.address
            || prefix != projection.on_link_prefix_len
            || server_ip != projection.gateway.as_deref().unwrap_or("")
        {
            anyhow::bail!("auth OK legacy projection disagrees with NetworkPlan v2");
        }
        let dns_servers: Vec<crate::transport_core::NetworkDns> =
            serde_json::from_value(value["dns_servers"].clone())
                .map_err(|error| anyhow::anyhow!("invalid auth OK dns_servers: {error}"))?;
        if dns_servers.len() > 8 {
            anyhow::bail!("auth OK contains too many DNS servers");
        }
        for dns in &dns_servers {
            let address: std::net::IpAddr = dns.address.parse().map_err(|_| {
                anyhow::anyhow!("invalid auth OK DNS server '{}:{}'", dns.address, dns.port)
            })?;
            if dns.port == 0 {
                anyhow::bail!("invalid auth OK DNS server '{}:0'", dns.address);
            }
            if (address.is_ipv4() && !has_ipv4) || (address.is_ipv6() && !has_ipv6) {
                anyhow::bail!(
                    "auth OK DNS server '{}' uses a family absent from the tunnel",
                    dns.address
                );
            }
            if let std::net::IpAddr::V6(address) = address {
                crate::config::server::validate_tunnel_ipv6_address("auth OK DNS server", address)
                    .map_err(anyhow::Error::msg)?;
            }
        }
        (family_mode, addresses, dns_servers)
    } else {
        if client_ip.parse::<std::net::Ipv4Addr>().is_err() {
            anyhow::bail!(
                "auth OK client_ip {:?} is not a valid IPv4 address - refusing to configure the tunnel with it",
                client_ip
            );
        }
        if !server_ip.is_empty() && server_ip.parse::<std::net::Ipv4Addr>().is_err() {
            anyhow::bail!(
                "auth OK server_ip {:?} is not a valid IPv4 address - refusing to install routes through it",
                server_ip
            );
        }
        let addresses = vec![crate::transport_core::NetworkAddress {
            family: crate::transport_core::NetworkAddressFamily::Ipv4,
            address: client_ip.clone(),
            prefix_len: prefix,
            on_link_prefix_len: prefix,
            gateway: (!server_ip.is_empty()).then(|| server_ip.clone()),
        }];
        let dns_servers = value["dns"]
            .as_str()
            .filter(|address| !address.is_empty())
            .and_then(|address| address.parse::<std::net::Ipv4Addr>().ok())
            .map(|address| {
                vec![crate::transport_core::NetworkDns {
                    address: address.to_string(),
                    port: dns_port.parse::<u16>().unwrap_or(53),
                }]
            })
            .unwrap_or_default();
        (
            crate::transport_core::NetworkFamilyMode::Ipv4,
            addresses,
            dns_servers,
        )
    };

    let pushed_obf = value
        .get("obfuscation")
        .filter(|obfuscation| !obfuscation.is_null())
        .map(|obfuscation| {
            let pushed: PushedObf = serde_json::from_value(obfuscation.clone())
                .map_err(|error| anyhow::anyhow!("invalid auth OK obfuscation: {error}"))?;
            pushed.validate("auth OK obfuscation")?;
            Ok::<PushedObf, anyhow::Error>(pushed)
        })
        .transpose()?;

    let _udp_roaming_session_id = match value.get("udp_roaming_session") {
        None => None,
        Some(serde_json::Value::String(encoded))
            if encoded.len() == 16 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            let session_id = u64::from_str_radix(encoded, 16)
                .map_err(|_| anyhow::anyhow!("invalid auth OK UDP roaming session id"))?;
            if session_id == 0 {
                anyhow::bail!("auth OK UDP roaming session id must be non-zero");
            }
            Some(session_id)
        }
        Some(_) => {
            anyhow::bail!(
                "auth OK UDP roaming session id must be exactly 16 hexadecimal characters"
            )
        }
    };

    Ok(AuthOk {
        family_mode,
        addresses,
        client_ip,
        server_ip,
        prefix,
        mtu,
        dns_ip: value["dns"].as_str().unwrap_or("").to_string(),
        dns_port,
        dns_servers,
        routes_json: value
            .get("routes")
            .map(ToString::to_string)
            .unwrap_or_else(|| "[]".into()),
        pushed_obf,
        #[cfg(any(feature = "client", test))]
        session_token: value["session_token"].as_str().unwrap_or("").to_string(),
        max_streams: value["max_streams"].as_u64().unwrap_or(1).clamp(1, 16) as u32,
        adaptive: value["multipath_adaptive"].as_bool().unwrap_or(false),
        #[cfg(any(feature = "client", test))]
        udp_roaming_session_id: _udp_roaming_session_id,
    })
}

/// Shared raw key exchange for primary AUTH and secondary JOIN/resume carriers.
/// Compact REALITY MUST NOT enter the classic branch, even after peer failure.
#[cfg(any(feature = "client", test))]
pub(crate) struct RawClientKeys {
    pub rx: PacketCodec,
    pub tx: PacketCodec,
    pub shared: zeroize::Zeroizing<[u8; 32]>,
    pub transcript_hash: [u8; 32],
    #[cfg(feature = "experimental-roaming")]
    pub resume_secret: zeroize::Zeroizing<[u8; 32]>,
}

#[cfg(any(feature = "client", test))]
pub(crate) async fn raw_client_keys<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    client: &Keypair,
) -> anyhow::Result<RawClientKeys> {
    if config.obfuscation.mode == "reality-tls" && config.obfuscation.reality_compact {
        let pinned = config
            .auth
            .server_public_key
            .as_deref()
            .and_then(crate::crypto::parse_pubkey_hex)
            .ok_or_else(|| anyhow::anyhow!("INNER_PQ_V1 requires a pinned server key"))?;
        let exchange = crate::protocol::inner_pq::client_exchange(stream, client, &pinned).await?;
        let (s2c, c2s) = exchange.material.data_keys();
        return Ok(RawClientKeys {
            rx: PacketCodec::new_raw(s2c),
            tx: PacketCodec::new_raw(c2s),
            shared: exchange.ephemeral_shared,
            transcript_hash: exchange.transcript_hash,
            #[cfg(feature = "experimental-roaming")]
            resume_secret: zeroize::Zeroizing::new(*exchange.material.resume_secret()),
        });
    }
    stream.write_all_flush(client.public().as_bytes()).await?;
    let mut public = [0u8; 32];
    stream.read_exact(&mut public).await?;
    let shared = client
        .derive_shared_checked(&crate::crypto::PublicKey::from_bytes(&public))
        .ok_or_else(|| anyhow::anyhow!("rejected low-order server public key"))?;
    let transcript_hash = handshake_transcript_hash(&[client.public().as_bytes(), &public]);
    let es = static_es(config, client)?;
    let (s2c, c2s) = match es {
        Some(es) => derive_keys_bound(&shared.0, &es),
        None => derive_keys(&shared.0),
    };
    #[cfg(feature = "experimental-roaming")]
    let material = match es {
        Some(es) => derive_session_material_bound(&shared.0, &es),
        None => derive_session_material(&shared.0),
    };
    Ok(RawClientKeys {
        rx: PacketCodec::new_raw(s2c),
        tx: PacketCodec::new_raw(c2s),
        shared: zeroize::Zeroizing::new(shared.0),
        transcript_hash,
        #[cfg(feature = "experimental-roaming")]
        resume_secret: zeroize::Zeroizing::new(*material.resume_secret()),
    })
}

/// Run the primary authenticated TCP handshake without any platform state access.
///
/// Device identity and server trust are explicit inputs: Linux can keep its persistent
/// known-hosts policy, while Android/iOS/Windows provide their own storage adapters. The
/// wire protocol and cryptographic transcript therefore have one implementation.
#[cfg(any(feature = "client", test))]
pub(crate) async fn authenticate_tcp<S, V, F>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    password: &str,
    device_id: &[u8; crate::protocol::DEVICE_ID_LEN],
    platform_capabilities: u64,
    mut verify_key: V,
) -> anyhow::Result<TcpAuthentication>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: FnMut([u8; 32]) -> F,
    F: Future<Output = anyhow::Result<()>>,
{
    let client_kp = Keypair::generate();

    if matches!(config.obfuscation.mode.as_str(), "plain" | "reality-tls") {
        let RawClientKeys {
            rx: mut client_rx,
            tx: mut client_tx,
            shared,
            transcript_hash,
            #[cfg(feature = "experimental-roaming")]
            resume_secret,
        } = raw_client_keys(stream, config, &client_kp).await?;

        let auth_proof_record = read_record(stream, Framing::Raw)
            .await
            .map_err(|error| anyhow::anyhow!("failed to read auth proof (raw inner): {error}"))?;
        let auth_proof = client_rx.decrypt_packet(&auth_proof_record)?;
        let (_, server_capabilities) =
            crate::protocol::capabilities::split_server_capabilities(&auth_proof)?;
        #[cfg(feature = "experimental-roaming")]
        let client_capabilities = crate::protocol::capabilities::negotiate_client_capabilities(
            config,
            server_capabilities,
            platform_capabilities,
        )?;
        let server_static = verify_server_identity(
            &auth_proof,
            &client_kp,
            &shared,
            &transcript_hash,
            &config.auth.server_public_key,
        )?;
        verify_key(server_static).await?;
        if config.obfuscation.mode == "reality-tls" && config.obfuscation.reality_compact {
            log::info!("INNER_PQ_V1 confirmed: hybrid data/resume keys and pinned server identity verified before AUTH");
        }
        log::info!("Server identity verified (raw inner)");

        let auth_plaintext = build_client_auth_plaintext(
            config,
            &client_kp,
            &shared,
            &transcript_hash,
            device_id,
            password,
            server_capabilities,
            platform_capabilities,
        )?;
        let auth_packet = client_tx.encrypt_packet(&auth_plaintext, &[])?;
        stream.write_all_flush(&auth_packet).await?;

        let auth_response_record = read_record(stream, Framing::Raw).await.map_err(|error| {
            anyhow::anyhow!("failed to read auth response (raw inner): {error}")
        })?;
        let auth_response = client_rx.decrypt_packet(&auth_response_record)?;
        let auth = parse_auth_ok(&String::from_utf8(auth_response)?)?;
        log::info!("Auth OK (raw inner), assigned IP: {}", auth.client_ip);
        return Ok(TcpAuthentication {
            client_rx,
            client_tx,
            auth,
            server_capabilities,
            #[cfg(feature = "experimental-roaming")]
            client_capabilities,
            #[cfg(feature = "experimental-roaming")]
            resume_secret,
        });
    }

    let server_name = config.effective_fake_tls_sni();
    let reality_session_id = match (
        config
            .obfuscation
            .reality_short_id
            .as_deref()
            .filter(|value| !value.is_empty()),
        config
            .auth
            .server_public_key
            .as_deref()
            .filter(|value| !value.is_empty())
            .and_then(crate::crypto::parse_pubkey_hex),
    ) {
        (Some(short_id), Some(public)) => {
            let reality_public = crate::crypto::PublicKey::from_bytes(&public);
            let short_id = crate::crypto::reality::short_id_from_hex(short_id);
            Some(crate::crypto::reality::seal_session_id(
                &reality_public,
                &client_kp,
                &short_id,
            ))
        }
        _ => None,
    };

    let (client_hello, mlkem_decapsulation_key) = FakeTlsHandshake::build_client_hello_pq(
        client_kp.public(),
        server_name,
        0,
        reality_session_id.as_ref(),
    );
    stream.write_all_flush(&client_hello).await?;
    let server_hello = read_tls_record(stream)
        .await
        .map_err(|error| anyhow::anyhow!("failed to read ServerHello: {error}"))?;
    let (mlkem_ciphertext, server_x25519) = FakeTlsHandshake::parse_server_hello_pq(&server_hello)
        .ok_or_else(|| anyhow::anyhow!("failed to parse hybrid ServerHello"))?;
    let server_pub = crate::crypto::PublicKey::from_bytes(&server_x25519);
    let change_cipher_spec = read_tls_record(stream)
        .await
        .map_err(|error| anyhow::anyhow!("failed to read ChangeCipherSpec: {error}"))?;
    if change_cipher_spec.first() != Some(&0x14) {
        anyhow::bail!("expected ChangeCipherSpec before the encrypted handshake flight");
    }
    let certificate = read_tls_record(stream)
        .await
        .map_err(|error| anyhow::anyhow!("failed to read Certificate: {error}"))?;
    let finished = read_tls_record(stream)
        .await
        .map_err(|error| anyhow::anyhow!("failed to read Finished: {error}"))?;
    let _new_session_ticket = read_tls_record(stream)
        .await
        .map_err(|error| anyhow::anyhow!("failed to read NewSessionTicket: {error}"))?;

    let shared = client_kp
        .derive_shared_checked(&server_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order server public key"))?;
    let mlkem_shared =
        crate::crypto::mlkem::mlkem768_decapsulate(&mlkem_decapsulation_key, &mlkem_ciphertext)
            .ok_or_else(|| anyhow::anyhow!("ML-KEM decapsulation failed"))?;
    let mlkem_shared: [u8; 32] = mlkem_shared
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ML-KEM shared secret not 32 bytes"))?;
    let static_shared = static_es(config, &client_kp)?;
    let (server_to_client, client_to_server) = match static_shared {
        Some(static_shared) => derive_keys_hybrid_bound(&shared.0, &mlkem_shared, &static_shared),
        None => derive_keys_hybrid(&shared.0, &mlkem_shared),
    };
    #[cfg(feature = "experimental-roaming")]
    let resume_secret = {
        let material = match static_shared {
            Some(static_shared) => {
                derive_session_material_hybrid_bound(&shared.0, &mlkem_shared, &static_shared)
            }
            None => derive_session_material_hybrid(&shared.0, &mlkem_shared),
        };
        zeroize::Zeroizing::new(*material.resume_secret())
    };
    let mut client_rx = PacketCodec::new(server_to_client);
    let mut client_tx = PacketCodec::new(client_to_server);
    let transcript_hash =
        handshake_transcript_hash(&[&client_hello, &server_hello, &certificate, &finished]);

    log::info!("Handshake complete, reading server auth proof");
    let auth_proof_record = read_tls_record(stream)
        .await
        .map_err(|error| anyhow::anyhow!("failed to read auth proof: {error}"))?;
    let auth_proof = client_rx.decrypt_packet(&auth_proof_record)?;
    let (_, server_capabilities) =
        crate::protocol::capabilities::split_server_capabilities(&auth_proof)?;
    #[cfg(feature = "experimental-roaming")]
    let client_capabilities = crate::protocol::capabilities::negotiate_client_capabilities(
        config,
        server_capabilities,
        platform_capabilities,
    )?;
    let server_static = verify_server_identity(
        &auth_proof,
        &client_kp,
        &shared.0,
        &transcript_hash,
        &config.auth.server_public_key,
    )?;
    verify_key(server_static).await?;
    log::info!("Server identity verified");

    let auth_plaintext = build_client_auth_plaintext(
        config,
        &client_kp,
        &shared.0,
        &transcript_hash,
        device_id,
        password,
        server_capabilities,
        platform_capabilities,
    )?;
    let auth_packet = client_tx.encrypt_packet(&auth_plaintext, &[])?;
    stream.write_all_flush(&auth_packet).await?;
    let auth_response_record = read_tls_record(stream)
        .await
        .map_err(|error| anyhow::anyhow!("failed to read auth response: {error}"))?;
    let auth_response = client_rx.decrypt_packet(&auth_response_record)?;
    let auth = parse_auth_ok(&String::from_utf8(auth_response)?)?;
    log::info!("Auth OK, assigned IP: {}", auth.client_ip);
    if auth.pushed_obf.is_some() {
        log::info!("Applying server-pushed obfuscation params");
    }
    if auth.routes_json != "[]" && !auth.routes_json.is_empty() {
        log::info!(
            "Server pushed {} route(s)",
            auth.routes_json.matches("cidr").count()
        );
    }
    Ok(TcpAuthentication {
        client_rx,
        client_tx,
        auth,
        server_capabilities,
        #[cfg(feature = "experimental-roaming")]
        client_capabilities,
        #[cfg(feature = "experimental-roaming")]
        resume_secret,
    })
}

#[cfg(any(feature = "client", test))]
pub(crate) fn effective_mtu(client_mtu: i32, pushed_mtu: i32) -> i32 {
    if client_mtu > 0 {
        client_mtu
    } else if pushed_mtu > 0 {
        pushed_mtu
    } else {
        crate::config::client::MTU_AUTO_FALLBACK
    }
}

#[cfg(any(feature = "client", test))]
pub(crate) fn verify_server_identity(
    auth_proof: &[u8],
    client_keypair: &Keypair,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
    pinned: &Option<String>,
) -> anyhow::Result<[u8; 32]> {
    let (auth_proof, _) = crate::protocol::capabilities::split_server_capabilities(auth_proof)?;
    if auth_proof.len() >= 64 {
        crate::crypto::verify_server_auth_message(
            auth_proof,
            client_keypair,
            ephemeral_shared,
            transcript_hash,
        )
    } else {
        let pin = pinned
            .as_deref()
            .and_then(crate::crypto::parse_pubkey_hex)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "server sent proof-only (require-pinned mode) but client has no server_public_key pinned"
                )
            })?;
        crate::crypto::verify_server_proof_only(
            auth_proof,
            client_keypair,
            &pin,
            ephemeral_shared,
            transcript_hash,
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(feature = "client", test))]
pub(crate) fn build_client_auth_plaintext(
    config: &crate::config::client::ClientConfig,
    client_keypair: &Keypair,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
    device_id: &[u8; crate::protocol::DEVICE_ID_LEN],
    password: &str,
    server_capabilities: Option<crate::protocol::capabilities::ServerCapabilities>,
    platform_capabilities: u64,
) -> anyhow::Result<Vec<u8>> {
    let proof = config
        .auth
        .server_public_key
        .as_deref()
        .and_then(crate::crypto::parse_pubkey_hex)
        .map(|public| {
            let shared =
                client_keypair.derive_shared(&crate::crypto::PublicKey::from_bytes(&public));
            crate::crypto::compute_client_key_proof(&shared.0, ephemeral_shared, transcript_hash)
        })
        .unwrap_or([0u8; 32]);
    let credentials = format!("{}:{password}", config.auth.username);
    let negotiated = crate::protocol::capabilities::negotiate_client_capabilities(
        config,
        server_capabilities,
        platform_capabilities,
    )?;
    let extension_capacity = if negotiated.is_some() { 24 } else { 0 };
    let mut plaintext =
        Vec::with_capacity(32 + 1 + device_id.len() + extension_capacity + credentials.len());
    plaintext.extend_from_slice(&proof);
    plaintext.push(0);
    plaintext.extend_from_slice(device_id);
    if let Some(capabilities) = negotiated {
        crate::protocol::capabilities::append_client_capabilities(&mut plaintext, capabilities);
    }
    plaintext.extend_from_slice(credentials.as_bytes());
    Ok(plaintext)
}

#[cfg(any(feature = "client", test))]
pub(crate) fn static_es(
    config: &crate::config::client::ClientConfig,
    client_keypair: &Keypair,
) -> anyhow::Result<Option<[u8; 32]>> {
    if !config.auth.bind_static_to_session {
        return Ok(None);
    }
    let pinned = config.auth.server_public_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "auth.bind_static_to_session is on but no server key is pinned; set auth.server_public_key (qeli show-identity) or set bind_static = false"
        )
    })?;
    let public = crate::crypto::parse_pubkey_hex(pinned)
        .ok_or_else(|| anyhow::anyhow!("invalid auth.server_public_key hex"))?;
    if public.iter().all(|byte| *byte == 0) {
        anyhow::bail!(
            "auth.bind_static_to_session is on but server_public_key is the all-zero TOFU sentinel; pin the real server key or set bind_static = false"
        );
    }
    let server_static = crate::crypto::PublicKey::from_bytes(&public);
    let shared = client_keypair
        .derive_shared_checked(&server_static)
        .ok_or_else(|| anyhow::anyhow!("auth.server_public_key is a low-order X25519 point"))?;
    Ok(Some(shared.0))
}

#[cfg(test)]
mod static_binding_tests {
    use super::*;

    #[derive(Default)]
    struct HelloCapture(Vec<Vec<u8>>);

    impl AsyncRead for HelloCapture {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(())) // EOF after the first flight: never retry/downgrade.
        }
    }
    impl AsyncWrite for HelloCapture {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.push(data.to_vec());
            std::task::Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn shared_reality_policy_preserves_token_pq_offer_and_explicit_split() {
        let identity = crate::crypto::StaticKeypair::generate();
        let mut config = crate::config::client::ClientConfig::default();
        config.auth.server_public_key = Some(
            identity
                .public
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        config.obfuscation.reality_short_id = Some("0123456789abcdef".into());
        config.obfuscation.sni = Some("decoy.example".into());
        config.obfuscation.reality_split_delay_ms = 0;
        for compact in [false, true] {
            for split in ["", "none", "first", "record", "sni"] {
                config.obfuscation.reality_compact = compact;
                config.obfuscation.reality_split = split.into();
                let mut stream = HelloCapture::default();
                assert!(establish_reality_tls(&mut stream, &config).await.is_err());
                let split_active = !matches!(split, "" | "none");
                assert_eq!(stream.0.len(), if split_active { 2 } else { 1 });
                if split == "first" {
                    assert_eq!(stream.0[0].len(), 1);
                }
                if split == "record" {
                    assert_eq!(stream.0[0].len(), 5);
                }
                let hello = stream.0.concat();
                assert_eq!(
                    hello.len(),
                    5 + usize::from(u16::from_be_bytes([hello[3], hello[4]]))
                );
                assert_eq!(hello.len() < 1200, compact, "compact={compact}");
                let (sid, key) = FakeTlsHandshake::parse_client_hello_full(&hello).unwrap();
                let public = crate::crypto::PublicKey::from_bytes(&key.try_into().unwrap());
                assert_eq!(
                    crate::crypto::reality::open_session_id(&identity, &public, &sid, 120),
                    crate::crypto::reality::parse_short_id("0123456789abcdef")
                );
                assert!(hello
                    .windows(b"decoy.example".len())
                    .any(|w| w == b"decoy.example"));
                // Inspect the extension vector, not random bytes that might resemble a group.
                let mut p = 44 + usize::from(hello[43]);
                p += 2 + usize::from(u16::from_be_bytes([hello[p], hello[p + 1]]));
                p += 1 + usize::from(hello[p]);
                p += 2;
                let mut hybrid = false;
                while p < hello.len() {
                    let kind = u16::from_be_bytes([hello[p], hello[p + 1]]);
                    let len = usize::from(u16::from_be_bytes([hello[p + 2], hello[p + 3]]));
                    p += 4;
                    if kind == 0x33 {
                        let mut k = p + 2;
                        while k < p + len {
                            let group = u16::from_be_bytes([hello[k], hello[k + 1]]);
                            let size =
                                usize::from(u16::from_be_bytes([hello[k + 2], hello[k + 3]]));
                            if group == crate::crypto::mlkem::X25519MLKEM768 {
                                hybrid = true;
                                assert_eq!(size, 1216);
                            }
                            k += 4 + size;
                        }
                    }
                    p += len;
                }
                assert_eq!(
                    hybrid, !compact,
                    "default must retain the PQ offer; no fallback on EOF"
                );
            }
        }
        config.obfuscation.reality_short_id = None;
        let mut stream = HelloCapture::default();
        assert!(establish_reality_tls(&mut stream, &config).await.is_err());
        assert!(
            stream.0.is_empty(),
            "reject missing authentication before sending"
        );
    }

    #[test]
    fn static_binding_rejects_degenerate_pins_before_kdf() {
        fn hex(bytes: impl AsRef<[u8]>) -> String {
            bytes
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }
        let mut config = crate::config::client::ClientConfig::default();
        config.auth.bind_static_to_session = true;
        let client = Keypair::generate();
        for pin in [None, Some("invalid".into()), Some(hex([0u8; 32]))] {
            config.auth.server_public_key = pin;
            assert!(static_es(&config, &client).is_err());
        }
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        config.auth.server_public_key = Some(hex(low_order));
        assert!(static_es(&config, &client).is_err());
        let identity = crate::crypto::StaticKeypair::generate();
        config.auth.server_public_key = Some(hex(identity.public.as_bytes()));
        assert_eq!(
            static_es(&config, &client).unwrap().unwrap(),
            identity.derive_shared(client.public()).0
        );
        config.auth.bind_static_to_session = false;
        config.auth.server_public_key = Some(hex(low_order));
        assert!(static_es(&config, &client).unwrap().is_none());
    }
    #[tokio::test]
    async fn credentials_wait_for_proof_and_trust_admission() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use std::time::Duration;
        for tamper_proof in [true, false] {
            let (mut client, mut peer) = tokio::io::duplex(4096);
            let server = tokio::spawn(async move {
                let mut public = [0u8; 32];
                peer.read_exact(&mut public).await.unwrap();
                let kp = Keypair::generate();
                peer.write_all_flush(kp.public().as_bytes()).await.unwrap();
                let shared = kp
                    .derive_shared_checked(&crate::crypto::PublicKey::from_bytes(&public))
                    .unwrap();
                let transcript = handshake_transcript_hash(&[&public, kp.public().as_bytes()]);
                let identity = crate::crypto::StaticKeypair::generate();
                let mut proof = crate::crypto::build_server_auth_message(
                    &identity,
                    &crate::crypto::PublicKey::from_bytes(&public),
                    &shared.0,
                    &transcript,
                );
                if tamper_proof {
                    proof[63] ^= 1;
                }
                let (tx, _) = derive_keys(&shared.0);
                let packet = PacketCodec::new_raw(tx)
                    .encrypt_packet(&proof, &[])
                    .unwrap();
                peer.write_all_flush(&packet).await.unwrap();
                peer
            });
            let mut config = crate::config::client::ClientConfig::default();
            config.obfuscation.mode = "plain".into();
            config.auth.bind_static_to_session = false;
            config.auth.username = "must-never-be-sent".into();
            let calls = Arc::new(AtomicUsize::new(0));
            let verifier_calls = calls.clone();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                authenticate_tcp(
                    &mut client,
                    &config,
                    "secret-password",
                    &[7; crate::protocol::DEVICE_ID_LEN],
                    0,
                    move |_| {
                        verifier_calls.fetch_add(1, Ordering::Relaxed);
                        async { anyhow::bail!("fixture trust rejection") }
                    },
                ),
            )
            .await
            .expect("failed admission must finish before waiting for AuthOK");
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::Relaxed), usize::from(!tamper_proof));
            let mut peer = server.await.unwrap();
            let mut byte = [0u8; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(30), peer.read_exact(&mut byte))
                    .await
                    .is_err(),
                "no credentials may follow a failed proof or trust policy"
            );
        }
    }
}
