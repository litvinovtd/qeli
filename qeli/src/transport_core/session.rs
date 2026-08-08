//! Platform-neutral values produced by the qeli authentication handshake.
//!
//! Keep server-push parsing here so Linux and every FFI client validate exactly the same
//! untrusted response before a platform network plan is constructed.

use crate::config::PushedObf;
use crate::crypto::Keypair;

#[derive(Debug)]
pub(crate) struct AuthOk {
    pub client_ip: String,
    pub server_ip: String,
    pub prefix: u8,
    pub mtu: i32,
    pub dns_ip: String,
    pub dns_port: String,
    pub routes_json: String,
    pub pushed_obf: Option<PushedObf>,
    pub session_token: String,
    pub max_streams: u32,
    pub adaptive: bool,
}

pub(crate) fn parse_auth_ok(response: &str) -> anyhow::Result<AuthOk> {
    let json = response
        .strip_prefix("OK:")
        .ok_or_else(|| anyhow::anyhow!("auth failed: {response}"))?;
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| anyhow::anyhow!("malformed auth OK json: {error}"))?;

    let client_ip = value["client_ip"].as_str().unwrap_or("").to_string();
    if client_ip.is_empty() {
        anyhow::bail!("auth OK missing client_ip");
    }
    if client_ip.parse::<std::net::Ipv4Addr>().is_err() {
        anyhow::bail!(
            "auth OK client_ip {:?} is not a valid IPv4 address - refusing to configure the tunnel with it",
            client_ip
        );
    }
    let server_ip = value["server_ip"].as_str().unwrap_or("").to_string();
    if !server_ip.is_empty() && server_ip.parse::<std::net::Ipv4Addr>().is_err() {
        anyhow::bail!(
            "auth OK server_ip {:?} is not a valid IPv4 address - refusing to install routes through it",
            server_ip
        );
    }

    let dns_port = match &value["dns_port"] {
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::String(text) => text.clone(),
        _ => "53".to_string(),
    };
    let prefix = value["prefix"]
        .as_u64()
        .map(|number| number as u8)
        .filter(|prefix| (1..=32).contains(prefix))
        .unwrap_or(24);
    let mtu = value["mtu"]
        .as_i64()
        .filter(|mtu| crate::config::server::mtu_in_range(*mtu))
        .map(|mtu| mtu as i32)
        .unwrap_or(0);

    Ok(AuthOk {
        client_ip,
        server_ip,
        prefix,
        mtu,
        dns_ip: value["dns"].as_str().unwrap_or("").to_string(),
        dns_port,
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

pub(crate) fn build_client_auth_plaintext(
    config: &crate::config::client::ClientConfig,
    client_keypair: &Keypair,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
    device_id: &[u8; crate::protocol::DEVICE_ID_LEN],
    password: &str,
) -> Vec<u8> {
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
    let mut plaintext = Vec::with_capacity(32 + 1 + device_id.len() + credentials.len());
    plaintext.extend_from_slice(&proof);
    plaintext.push(0);
    plaintext.extend_from_slice(device_id);
    plaintext.extend_from_slice(credentials.as_bytes());
    plaintext
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
