//! Reversible at-rest encryption for the panel's stored user passwords, so the
//! admin can re-issue a `qeli://` config/QR for an existing user **without
//! knowing the plaintext** (which Argon2 hashing alone makes unrecoverable).
//!
//! The symmetric key lives in `/var/lib/qeli/panel-secret.key` (0600), generated on
//! first use and deliberately kept outside portable `/etc/qeli` backups. Both the
//! panel (supervisor) and the `add-client` CLI read it so a
//! password captured at creation time can be decrypted later for re-issue.
//!
//! Trade-off (chosen deliberately over hash-only): a server compromise that
//! reads the key file AND the users file can recover these passwords. They are
//! VPN-only credentials. ChaCha20-Poly1305 AEAD, random 96-bit nonce; the stored
//! value is `base64(nonce ‖ ciphertext+tag)`.

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

/// Default key-file path (created 0600 on first use).
///
/// Deliberately NOT in /etc/qeli, which is where `users.conf` (and its `password_enc`
/// ciphertexts) lives.
///
/// The documented trade-off for reversible password storage is that an attacker needs BOTH
/// the key and the users file. Shipping them in the same directory collapsed that to a
/// single read — and, worse, `/api/backup` tars up all of /etc/qeli unencrypted, so every
/// downloaded backup carried the key together with everything it decrypts. One stolen
/// backup archive (a mailbox, a Downloads folder, an S3 bucket) yielded the cleartext VPN
/// password of every user, which is precisely what Argon2id hashing is there to prevent.
///
/// /var/lib/qeli is machine-local STATE, not configuration: it is not in the backup, and it
/// is where the panel session key already lives. Existing installs keep working — the loader
/// falls back to the legacy path and migrates on next write. (Audit 2026-08-04.)
pub const PANEL_KEY_PATH: &str = "/var/lib/qeli/panel-secret.key";

/// Where the key used to live. Read-only fallback so an upgrade does not lose the ability to
/// decrypt existing `password_enc` values.
pub const PANEL_KEY_PATH_LEGACY: &str = "/etc/qeli/panel-secret.key";

/// Load the 32-byte panel key, generating+persisting it (0600) if absent.
pub fn load_or_create_key(path: &str) -> anyhow::Result<[u8; 32]> {
    load_or_create_key_at(
        std::path::Path::new(path),
        (path == PANEL_KEY_PATH).then(|| std::path::Path::new(PANEL_KEY_PATH_LEGACY)),
    )
}

fn load_or_create_key_at(
    path: &std::path::Path,
    legacy: Option<&std::path::Path>,
) -> anyhow::Result<[u8; 32]> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    // Modern load, migration and generation share one lock and re-check. Migration
    // must never replace a modern key published while this process was waiting.
    let _lock = crate::util::FileLock::acquire(path)?;
    if let Some(key) = super::key_file::read(path)? {
        return Ok(*key);
    }
    if let Some(legacy) = legacy {
        if let Some(key) = super::key_file::read(legacy)? {
            match crate::util::write_atomic_private(path, &key[..]) {
                Ok(()) => log::info!("panel key moved {} -> {} (outside portable backups); confirm reissue before removing the old file", legacy.display(), path.display()),
                Err(error) => log::warn!("panel key: could not write {} ({error}); still using {}", path.display(), legacy.display()),
            }
            return Ok(*key);
        }
    }
    use rand::prelude::*;
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *key);
    crate::util::write_atomic_private(path, &key[..])?;
    Ok(*key)
}

/// Encrypt `plaintext` → `base64(nonce ‖ ct)`.
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> anyhow::Result<String> {
    use rand::prelude::*;
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid key length");
    let mut nb = [0u8; 12];
    rand::rng().fill_bytes(&mut nb);
    let ct = cipher
        .encrypt(&Nonce::from(nb), plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt: {}", e))?;
    let mut out = nb.to_vec();
    out.extend_from_slice(&ct);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Decrypt a value produced by [`encrypt`].
pub fn decrypt(key: &[u8; 32], b64: &str) -> anyhow::Result<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("base64: {}", e))?;
    if raw.len() < 12 {
        anyhow::bail!("ciphertext too short");
    }
    let (nb, ct) = raw.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid key length");
    let n = Nonce::try_from(nb).map_err(|e| anyhow::anyhow!("nonce: {}", e))?;
    let pt = cipher
        .decrypt(&n, ct)
        .map_err(|e| anyhow::anyhow!("decrypt: {}", e))?;
    String::from_utf8(pt).map_err(|e| anyhow::anyhow!("utf8: {}", e))
}

/// Convenience: encrypt with the default panel key (creating it if needed).
pub fn encrypt_password(plaintext: &str) -> anyhow::Result<String> {
    encrypt(
        &zeroize::Zeroizing::new(load_or_create_key(PANEL_KEY_PATH)?),
        plaintext,
    )
}

/// Convenience: decrypt with the default panel key.
pub fn decrypt_password(b64: &str) -> anyhow::Result<String> {
    decrypt(
        &zeroize::Zeroizing::new(load_or_create_key(PANEL_KEY_PATH)?),
        b64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_waits_for_modern_lock_and_keeps_the_winner() {
        use std::sync::mpsc;
        let dir = std::env::temp_dir().join(format!(
            "qeli-panel-migrate-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let modern = dir.join("modern.key");
        let legacy = dir.join("legacy.key");
        std::fs::write(&legacy, [3; 32]).unwrap();
        let lock = crate::util::FileLock::acquire(&modern).unwrap();
        let (tx, rx) = mpsc::channel();
        let m = modern.clone();
        let l = legacy.clone();
        let thread =
            std::thread::spawn(move || tx.send(load_or_create_key_at(&m, Some(&l))).unwrap());
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        crate::util::write_atomic_private(&modern, &[8; 32]).unwrap();
        drop(lock);
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            [8; 32]
        );
        thread.join().unwrap();
        assert_eq!(std::fs::read(&modern).unwrap(), [8; 32]);
        std::fs::remove_file(&modern).unwrap();
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let m = modern.clone();
                let l = legacy.clone();
                std::thread::spawn(move || load_or_create_key_at(&m, Some(&l)).unwrap())
            })
            .collect();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), [3; 32]);
        }
        assert_eq!(std::fs::read(&modern).unwrap(), [3; 32]);
        std::fs::remove_file(&modern).unwrap();
        std::fs::write(&legacy, b"damaged").unwrap();
        assert!(load_or_create_key_at(&modern, Some(&legacy)).is_err());
        assert!(
            !modern.exists(),
            "corrupt legacy must not silently replace the encryption key"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let ct = encrypt(&key, "s3cr3t-pä$$").unwrap();
        assert_ne!(ct, "s3cr3t-pä$$");
        assert_eq!(decrypt(&key, &ct).unwrap(), "s3cr3t-pä$$");
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&[1u8; 32], "hello").unwrap();
        assert!(decrypt(&[2u8; 32], &ct).is_err());
    }

    #[test]
    fn distinct_nonces_distinct_ciphertext() {
        let key = [9u8; 32];
        assert_ne!(encrypt(&key, "x").unwrap(), encrypt(&key, "x").unwrap());
    }
}
