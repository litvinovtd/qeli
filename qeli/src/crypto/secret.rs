//! Reversible at-rest encryption for the panel's stored user passwords, so the
//! admin can re-issue a `qeli://` config/QR for an existing user **without
//! knowing the plaintext** (which Argon2 hashing alone makes unrecoverable).
//!
//! The symmetric key lives in `/etc/qeli/panel-secret.key` (0600), generated on
//! first use; both the panel (supervisor) and the `add-client` CLI read it so a
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
    use std::path::Path;
    // Migration: if the new location has no key but the legacy one does, adopt it rather
    // than generating a fresh key — a new key would make every stored `password_enc`
    // undecryptable, i.e. silently break "re-issue this user's link".
    if path == PANEL_KEY_PATH && !Path::new(path).exists() {
        if let Ok(b) = std::fs::read(PANEL_KEY_PATH_LEGACY) {
            if b.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                if let Some(parent) = Path::new(path).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                match crate::util::write_atomic_private(path, &k) {
                    Ok(()) => log::info!(
                        "panel key moved {PANEL_KEY_PATH_LEGACY} -> {PANEL_KEY_PATH} (out of the \
                         backed-up config directory). Delete the old file once you have \
                         confirmed the panel still re-issues links."
                    ),
                    Err(e) => log::warn!(
                        "panel key: could not write {PANEL_KEY_PATH} ({e}) — still using \
                         {PANEL_KEY_PATH_LEGACY}"
                    ),
                }
                return Ok(k);
            }
        }
    }
    // `exists → generate → write` is a race: two processes starting together (supervisor
    // and worker, or a CLI alongside a running server) both saw "absent", both generated,
    // and the later write won — leaving the earlier one holding a key that is no longer
    // on disk. Everything sealed under it (re-issuable passwords, panel sessions) then
    // fails to decrypt. Serialize the create path and re-check inside the lock.
    // Take the lock ONCE and do create-or-read entirely inside it.
    //
    // The previous shape was `if !exists { lock; create }` followed by a second
    // `if exists { read } else { generate + write }` — and that trailing `else` was an
    // UNLOCKED generate/write path, reintroducing exactly the race the lock exists to
    // prevent. It is reachable whenever the file disappears between the two `exists()`
    // calls (a key rotation, a parallel cleanup of /etc/qeli), and then two processes can
    // generate and write concurrently, last writer wins, and whatever the loser sealed —
    // re-issuable passwords, panel sessions — can never be decrypted again. It also set
    // permissions differently from the locked branch, which relies on
    // `write_atomic_private`. (Audit 2026-07-27, R8.)
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let _lock = crate::util::FileLock::acquire(path)?;
    if Path::new(path).exists() {
        let b = std::fs::read(path)?;
        if b.len() != 32 {
            anyhow::bail!("panel secret key {} has wrong length {}", path, b.len());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&b);
        return Ok(k);
    }
    use rand::prelude::*;
    let mut k = [0u8; 32];
    rand::rng().fill_bytes(&mut k);
    crate::util::write_atomic_private(path, &k)?;
    Ok(k)
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
    encrypt(&load_or_create_key(PANEL_KEY_PATH)?, plaintext)
}

/// Convenience: decrypt with the default panel key.
pub fn decrypt_password(b64: &str) -> anyhow::Result<String> {
    decrypt(&load_or_create_key(PANEL_KEY_PATH)?, b64)
}

#[cfg(test)]
mod tests {
    use super::*;

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
