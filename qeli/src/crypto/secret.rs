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
pub const PANEL_KEY_PATH: &str = "/etc/qeli/panel-secret.key";

/// Load the 32-byte panel key, generating+persisting it (0600) if absent.
pub fn load_or_create_key(path: &str) -> anyhow::Result<[u8; 32]> {
    use std::path::Path;
    if Path::new(path).exists() {
        let b = std::fs::read(path)?;
        if b.len() != 32 {
            anyhow::bail!("panel secret key {} has wrong length {}", path, b.len());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&b);
        Ok(k)
    } else {
        use rand::prelude::*;
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        crate::util::write_atomic(path, &k)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(k)
    }
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
