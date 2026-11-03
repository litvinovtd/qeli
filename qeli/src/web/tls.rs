//! Panel HTTPS — build a rustls `ServerConfig` (ring provider) so the admin panel
//! can be exposed on a public IP with encrypted transport and no reverse proxy.
//!
//! Cert source: an operator-provided PEM pair (`web.tls_cert`/`web.tls_key`), or
//! an auto-generated self-signed cert (rcgen) persisted to `/etc/qeli/web-tls-*.pem`
//! so it stays stable across restarts. We pin the `ring` provider explicitly (the
//! rest of the crate uses ring; aws-lc-rs needs cmake which the build host lacks).

use crate::config::server::WebConfig;
use rustls::pki_types::pem::PemObject;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

const DEFAULT_CERT: &str = "/etc/qeli/web-tls-cert.pem";
const DEFAULT_KEY: &str = "/etc/qeli/web-tls-key.pem";
const MAX_TLS_PEM_BYTES: u64 = 4 * 1024 * 1024;

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
    ensure_cert_pair(web, &cert_path, &key_path)?;
    build_existing_pair(&cert_path, &key_path)
}

/// Check TLS files without creating the default self-signed pair.
pub fn check_config_files(web: &WebConfig) -> anyhow::Result<()> {
    if !web.enabled || !web.tls {
        return Ok(());
    }
    let (cert_path, key_path) = resolve_paths(web);
    if pair_present(web, &cert_path, &key_path)? {
        build_existing_pair(&cert_path, &key_path)?;
    }
    Ok(())
}

fn build_existing_pair(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

/// Presence is based on the directory entry, not Path::exists(): a dangling
/// symlink is not permission to overwrite an operator-managed PEM path.
fn pem_path_present(path: &str) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow::anyhow!("inspect TLS PEM {}: {}", path, error)),
    }
}

fn ensure_cert_pair(web: &WebConfig, cert_path: &str, key_path: &str) -> anyhow::Result<()> {
    if pair_present(web, cert_path, key_path)? {
        return Ok(());
    }
    generate_self_signed(web, cert_path, key_path)
}

/// Return false only for a wholly absent default pair, which startup may generate.
fn pair_present(web: &WebConfig, cert_path: &str, key_path: &str) -> anyhow::Result<bool> {
    let cert_present = pem_path_present(cert_path)?;
    let key_present = pem_path_present(key_path)?;
    if cert_present && key_present {
        return Ok(true);
    }
    if !web.tls_cert.is_empty() || !web.tls_key.is_empty() {
        anyhow::bail!(
            "web.tls_cert/tls_key set but file(s) missing: {} / {}",
            cert_path,
            key_path
        );
    }
    if cert_present || key_present {
        anyhow::bail!(
            "incomplete auto-generated panel TLS pair: {} / {}; restore the missing file, or remove both to rotate the pair",
            cert_path,
            key_path
        );
    }
    Ok(false)
}

/// Bound PEM reads and reject devices/FIFOs before parsing. O_NONBLOCK makes
/// opening a FIFO safe even if the configured path changes after presence check.
/// Symlinks remain supported for operator-managed certificate rotations.
fn read_pem(path: &str, kind: &str) -> anyhow::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("open TLS {kind} {path}: {error}"))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "TLS {kind} {} is not a regular file",
        path
    );
    anyhow::ensure!(
        metadata.len() <= MAX_TLS_PEM_BYTES,
        "TLS {kind} {} is {} bytes; maximum is {}",
        path,
        metadata.len(),
        MAX_TLS_PEM_BYTES
    );
    let mut input = file.take(MAX_TLS_PEM_BYTES + 1);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    input.read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_TLS_PEM_BYTES,
        "TLS {kind} {} exceeds {} bytes while reading",
        path,
        MAX_TLS_PEM_BYTES
    );
    Ok(bytes)
}

fn load_certs(path: &str) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let pem = read_pem(path, "certificate")?;
    let certs: Vec<_> =
        rustls::pki_types::CertificateDer::pem_slice_iter(&pem).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates in {}", path);
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let pem = read_pem(path, "private key")?;
    rustls::pki_types::PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|error| anyhow::anyhow!("parse private key in {}: {}", path, error))
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
        std::fs::create_dir_all(parent).map_err(|error| {
            anyhow::anyhow!(
                "cannot create TLS certificate directory {}: {error}",
                parent.display()
            )
        })?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qeli-web-tls-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn pem_chain_skips_unrelated_blocks_and_preserves_order() {
        let dir = fixture();
        let path = dir.join("chain.pem");
        std::fs::write(
            &path,
            b"ignored text\n-----BEGIN PUBLIC KEY-----\nAQ==\n-----END PUBLIC KEY-----\n\
              -----BEGIN CERTIFICATE-----\nAQI=\n-----END CERTIFICATE-----\n\
              -----BEGIN CERTIFICATE-----\nAwQ=\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let certs = load_certs(path.to_str().unwrap()).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), &[1, 2]);
        assert_eq!(certs[1].as_ref(), &[3, 4]);
        // A malformed later certificate must fail the whole chain, not silently truncate it.
        std::fs::write(
            &path,
            b"-----BEGIN CERTIFICATE-----\nAQI=\n-----END CERTIFICATE-----\n\
              -----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(load_certs(path.to_str().unwrap()).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn pem_keys_accept_pkcs1_sec1_pkcs8_and_reject_missing_or_malformed() {
        use rustls::pki_types::PrivateKeyDer;
        let dir = fixture();
        let path = dir.join("key.pem");
        for label in ["RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"] {
            let pem = format!(
                "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n\
                 -----BEGIN {label}-----\nAQID\n-----END {label}-----\n\
                 -----BEGIN PRIVATE KEY-----\nBA==\n-----END PRIVATE KEY-----\n"
            );
            std::fs::write(&path, pem).unwrap();
            let key = load_key(path.to_str().unwrap()).unwrap();
            assert_eq!(key.secret_der(), &[1, 2, 3]);
            assert!(matches!(
                (label, key),
                ("RSA PRIVATE KEY", PrivateKeyDer::Pkcs1(_))
                    | ("EC PRIVATE KEY", PrivateKeyDer::Sec1(_))
                    | ("PRIVATE KEY", PrivateKeyDer::Pkcs8(_))
            ));
        }
        for pem in [
            "",
            "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n",
            "-----BEGIN PRIVATE KEY-----\n!invalid!\n-----END PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\nAQ==\n",
        ] {
            std::fs::write(&path, pem).unwrap();
            assert!(load_key(path.to_str().unwrap()).is_err());
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn both_missing_auto_pems_generate_a_readable_private_pair() {
        let dir = fixture();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        ensure_cert_pair(
            &WebConfig::default(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        )
        .unwrap();
        assert!(!load_certs(cert.to_str().unwrap()).unwrap().is_empty());
        load_key(key.to_str().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(cert).unwrap();
        std::fs::remove_file(key).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn missing_cert_does_not_replace_the_surviving_auto_key() {
        let dir = fixture();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&key, b"existing private key").unwrap();
        let error = ensure_cert_pair(
            &WebConfig::default(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("incomplete auto-generated"),
            "{error}"
        );
        assert!(!cert.exists());
        assert_eq!(std::fs::read(&key).unwrap(), b"existing private key");
        std::fs::remove_file(key).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn oversized_tls_pem_is_rejected_before_parsing() {
        let dir = fixture();
        let cert = dir.join("cert.pem");
        let file = std::fs::File::create(&cert).unwrap();
        file.set_len(MAX_TLS_PEM_BYTES + 1).unwrap();
        let error = read_pem(cert.to_str().unwrap(), "certificate").unwrap_err();
        assert!(error.to_string().contains("maximum is 4194304"), "{error}");
        std::fs::remove_file(cert).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let dir = fixture();
        let fifo = dir.join("cert.fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let path = fifo.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = tx.send(read_pem(path.to_str().unwrap(), "certificate").map(|_| ()));
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(2));
        if result.is_err() {
            let _wake = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .unwrap();
            reader.join().unwrap();
            panic!("TLS PEM open waited for a FIFO writer");
        }
        reader.join().unwrap();
        assert!(result
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));
        std::fs::remove_file(fifo).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn regular_symlinked_pem_remains_supported() {
        let dir = fixture();
        let target = dir.join("target.pem");
        let link = dir.join("cert.pem");
        std::fs::write(&target, b"operator-managed PEM").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            read_pem(link.to_str().unwrap(), "certificate").unwrap(),
            b"operator-managed PEM"
        );
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn absent_default_pair_is_valid_without_generation() {
        let dir = fixture();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        assert!(!pair_present(
            &WebConfig::default(),
            cert.to_str().unwrap(),
            key.to_str().unwrap()
        )
        .unwrap());
        assert!(!cert.exists());
        assert!(!key.exists());
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn check_config_rejects_invalid_explicit_pem_without_writing() {
        let dir = fixture();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, b"not a certificate").unwrap();
        std::fs::write(&key, b"not a private key").unwrap();
        let web = WebConfig {
            enabled: true,
            tls: true,
            tls_cert: cert.to_str().unwrap().into(),
            tls_key: key.to_str().unwrap().into(),
            ..Default::default()
        };
        let error = check_config_files(&web).unwrap_err();
        assert!(error.to_string().contains("no certificates"), "{error}");
        assert_eq!(std::fs::read(&cert).unwrap(), b"not a certificate");
        assert_eq!(std::fs::read(&key).unwrap(), b"not a private key");
        std::fs::remove_file(cert).unwrap();
        std::fs::remove_file(key).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn check_config_accepts_valid_explicit_pair_without_writing() {
        let dir = fixture();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        generate_self_signed(
            &WebConfig::default(),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        )
        .unwrap();
        let cert_before = std::fs::read(&cert).unwrap();
        let key_before = std::fs::read(&key).unwrap();
        let web = WebConfig {
            enabled: true,
            tls: true,
            tls_cert: cert.to_str().unwrap().into(),
            tls_key: key.to_str().unwrap().into(),
            ..Default::default()
        };
        check_config_files(&web).unwrap();
        assert_eq!(std::fs::read(&cert).unwrap(), cert_before);
        assert_eq!(std::fs::read(&key).unwrap(), key_before);
        std::fs::remove_file(cert).unwrap();
        std::fs::remove_file(key).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
