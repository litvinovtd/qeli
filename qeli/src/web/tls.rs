//! Panel HTTPS — build a rustls `ServerConfig` (ring provider) so the admin panel
//! can be exposed on a public IP with encrypted transport and no reverse proxy.
//!
//! Cert source: an operator-provided PEM pair (`web.tls_cert`/`web.tls_key`), or
//! an auto-generated self-signed cert (rcgen) persisted to `/etc/qeli/web-tls-*.pem`
//! so it stays stable across restarts. We pin the `ring` provider explicitly (the
//! rest of the crate uses ring; aws-lc-rs needs cmake which the build host lacks).

use crate::config::server::WebConfig;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

const DEFAULT_CERT: &str = "/etc/qeli/web-tls-cert.pem";
const DEFAULT_KEY: &str = "/etc/qeli/web-tls-key.pem";

/// Resolve the cert/key paths (operator-provided or the self-signed defaults).
fn resolve_paths(web: &WebConfig) -> (String, String) {
    let cert = if web.tls_cert.is_empty() {
        DEFAULT_CERT.to_string()
    } else {
        web.tls_cert.clone()
    };
    let key = if web.tls_key.is_empty() {
        DEFAULT_KEY.to_string()
    } else {
        web.tls_key.clone()
    };
    (cert, key)
}

/// Build the panel's rustls `ServerConfig`, generating a self-signed cert on first
/// use when none is configured.
pub fn build_server_config(web: &WebConfig) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let (cert_path, key_path) = resolve_paths(web);

    if !(Path::new(&cert_path).exists() && Path::new(&key_path).exists()) {
        // A *configured* cert that's missing is a config error; only the default
        // (self-signed) location is auto-generated.
        if !web.tls_cert.is_empty() || !web.tls_key.is_empty() {
            anyhow::bail!(
                "web.tls_cert/tls_key set but file(s) missing: {} / {}",
                cert_path,
                key_path
            );
        }
        generate_self_signed(web, &cert_path, &key_path)?;
    }

    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let f = std::fs::File::open(path).map_err(|e| anyhow::anyhow!("open cert {}: {}", path, e))?;
    let mut r = BufReader::new(f);
    let certs: Vec<_> = rustls_pemfile::certs(&mut r).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates in {}", path);
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).map_err(|e| anyhow::anyhow!("open key {}: {}", path, e))?;
    let mut r = BufReader::new(f);
    rustls_pemfile::private_key(&mut r)?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", path))
}

/// Generate a self-signed cert (ECDSA P-256) covering localhost + the bind host,
/// persist it (key 0600), and warn — browsers will flag it, but transport is
/// encrypted. Operators wanting a clean cert set `web.tls_cert`/`tls_key`.
fn generate_self_signed(web: &WebConfig, cert_path: &str, key_path: &str) -> anyhow::Result<()> {
    use rcgen::{CertificateParams, KeyPair, SanType};
    use std::net::IpAddr;

    let mut sans: Vec<String> = vec!["localhost".into(), "127.0.0.1".into()];
    // Bind 0.0.0.0 isn't a usable SAN; otherwise add the bind host/IP so the cert
    // matches when the panel is reached at that address.
    if !web.bind.is_empty() && web.bind != "0.0.0.0" {
        sans.push(web.bind.clone());
    }

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    for s in &sans {
        match s.parse::<IpAddr>() {
            Ok(ip) => params.subject_alt_names.push(SanType::IpAddress(ip)),
            Err(_) => params
                .subject_alt_names
                .push(SanType::DnsName(s.clone().try_into()?)),
        }
    }
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    if let Some(parent) = Path::new(cert_path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    crate::util::write_atomic(cert_path, cert.pem().as_bytes())?;
    // Private key is born 0600 (no world-readable window between write and chmod,
    // and no readable key left if the process crashes mid-way). Cert stays public.
    crate::util::write_atomic_private(key_path, key_pair.serialize_pem().as_bytes())?;
    log::warn!(
        "web: generated self-signed TLS cert at {} — browsers will warn; set \
         web.tls_cert/web.tls_key for a real (e.g. Let's Encrypt) cert",
        cert_path
    );
    Ok(())
}
