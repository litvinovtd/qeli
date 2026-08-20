//! Platform-neutral values produced by the qeli authentication handshake.
//!
//! Keep server-push parsing here so Linux and every FFI client validate exactly the same
//! untrusted response before a platform network plan is constructed.

use crate::config::PushedObf;
use crate::crypto::{
    derive_keys, derive_keys_bound, derive_keys_hybrid, derive_keys_hybrid_bound,
    handshake_transcript_hash, Keypair,
};
use crate::protocol::{
    pick_random_sni, read_record, read_tls_record, FakeTlsHandshake, Framing, PacketCodec,
};
use std::future::Future;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    pub session_token: String,
    pub max_streams: u32,
    pub adaptive: bool,
}

/// One hybrid UDP ClientHello flight shared by the live tunnel and native diagnostics.
/// Keeping construction here prevents a reachability check from growing a second TLS/PQ/
/// fragmentation implementation that can silently drift from the data plane.
pub(crate) struct UdpClientHelloFlight {
    pub client_keypair: Keypair,
    pub mlkem_decapsulation_key: crate::crypto::mlkem::DecapKey,
    pub client_hello: Vec<u8>,
    pub fragments: Vec<Vec<u8>>,
}

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
    let server_name = match config.obfuscation.sni.as_deref() {
        Some(name) if !name.is_empty() => name,
        _ if config.server.address.parse::<std::net::IpAddr>().is_ok() => pick_random_sni(),
        _ => &config.server.address,
    };
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
        pushed_obf: value
            .get("obfuscation")
            .and_then(|obfuscation| serde_json::from_value(obfuscation.clone()).ok()),
        session_token: value["session_token"].as_str().unwrap_or("").to_string(),
        max_streams: value["max_streams"].as_u64().unwrap_or(1).clamp(1, 16) as u32,
        adaptive: value["multipath_adaptive"].as_bool().unwrap_or(false),
    })
}

/// Run the primary authenticated TCP handshake without any platform state access.
///
/// Device identity and server trust are explicit inputs: Linux can keep its persistent
/// known-hosts policy, while Android/iOS/Windows provide their own storage adapters. The
/// wire protocol and cryptographic transcript therefore have one implementation.
pub(crate) async fn authenticate_tcp<S, V, F>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    password: &str,
    device_id: &[u8; crate::protocol::DEVICE_ID_LEN],
    platform_capabilities: u64,
    mut verify_key: V,
) -> anyhow::Result<(PacketCodec, PacketCodec, AuthOk)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: FnMut([u8; 32]) -> F,
    F: Future<Output = anyhow::Result<()>>,
{
    let client_kp = Keypair::generate();

    if config.obfuscation.mode == "plain" {
        stream.write_all(client_kp.public().as_bytes()).await?;
        let mut server_public = [0u8; 32];
        stream
            .read_exact(&mut server_public)
            .await
            .map_err(|error| anyhow::anyhow!("failed to read server key (plain): {error}"))?;
        let server_pub = crate::crypto::PublicKey::from_bytes(&server_public);
        let transcript_hash =
            handshake_transcript_hash(&[client_kp.public().as_bytes(), &server_public]);
        let shared = client_kp
            .derive_shared_checked(&server_pub)
            .ok_or_else(|| anyhow::anyhow!("rejected low-order server public key"))?;
        let (server_to_client, client_to_server) = match static_es(config, &client_kp)? {
            Some(static_shared) => derive_keys_bound(&shared.0, &static_shared),
            None => derive_keys(&shared.0),
        };
        let mut client_rx = PacketCodec::new_raw(server_to_client);
        let mut client_tx = PacketCodec::new_raw(client_to_server);

        let auth_proof_record = read_record(stream, Framing::Raw)
            .await
            .map_err(|error| anyhow::anyhow!("failed to read auth proof (plain): {error}"))?;
        let auth_proof = client_rx.decrypt_packet(&auth_proof_record)?;
        let (_, server_capabilities) =
            crate::protocol::capabilities::split_server_capabilities(&auth_proof)?;
        let server_static = verify_server_identity(
            &auth_proof,
            &client_kp,
            &shared.0,
            &transcript_hash,
            &config.auth.server_public_key,
        )?;
        verify_key(server_static).await?;
        log::info!("Server identity verified (plain)");

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
        stream.write_all(&auth_packet).await?;

        let auth_response_record = read_record(stream, Framing::Raw)
            .await
            .map_err(|error| anyhow::anyhow!("failed to read auth response (plain): {error}"))?;
        let auth_response = client_rx.decrypt_packet(&auth_response_record)?;
        let auth = parse_auth_ok(&String::from_utf8(auth_response)?)?;
        log::info!("Auth OK (plain), assigned IP: {}", auth.client_ip);
        return Ok((client_rx, client_tx, auth));
    }

    let server_name = match config.obfuscation.sni.as_deref() {
        Some(name) if !name.is_empty() => name,
        _ if config.server.address.parse::<std::net::IpAddr>().is_ok() => pick_random_sni(),
        _ => &config.server.address,
    };
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
    stream.write_all(&client_hello).await?;
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
    let (server_to_client, client_to_server) = match static_es(config, &client_kp)? {
        Some(static_shared) => derive_keys_hybrid_bound(&shared.0, &mlkem_shared, &static_shared),
        None => derive_keys_hybrid(&shared.0, &mlkem_shared),
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
    stream.write_all(&auth_packet).await?;
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
    Ok((client_rx, client_tx, auth))
}

pub(crate) fn effective_mtu(client_mtu: i32, pushed_mtu: i32) -> i32 {
    if client_mtu > 0 {
        client_mtu
    } else if pushed_mtu > 0 {
        pushed_mtu
    } else {
        crate::config::client::MTU_AUTO_FALLBACK
    }
}

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
    Ok(Some(client_keypair.derive_shared(&server_static).0))
}
