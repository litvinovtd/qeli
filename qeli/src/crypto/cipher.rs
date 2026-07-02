use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

pub struct Cipher {
    // chacha20poly1305 0.10 depends on `zeroize` non-optionally and wipes the key
    // in its `Drop` impl, so the AEAD key does not linger in freed heap. (There is
    // no `zeroize` cargo feature to toggle in 0.10 — it is always on.)
    cipher: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid key length");
        Cipher { cipher }
    }

    /// Строит 12-байтовый nonce: [counter_be(8)] || [extra(4)]
    /// Exercised by the crypto test-suite; the live codec builds nonces inline.
    #[allow(dead_code)]
    pub fn generate_nonce(counter: u64, extra: &[u8; 4]) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());
        nonce[8..].copy_from_slice(extra);
        nonce
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptFailed)
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptFailed)
    }

    /// In-place AEAD seal with a detached tag. `buffer` holds the plaintext on
    /// entry and the (same-length) ciphertext on return; the 16-byte tag is
    /// returned separately for the caller to append. Produces the identical
    /// ciphertext+tag as [`Cipher::encrypt`] (same key/nonce, empty associated
    /// data) but without its fresh output `Vec` — the caller encrypts inside a
    /// buffer it already owns. Used on the per-packet hot path.
    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8; NONCE_SIZE],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_SIZE], CryptoError> {
        let nonce = Nonce::from_slice(nonce);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, b"", buffer)
            .map_err(|_| CryptoError::EncryptFailed)?;
        let mut out = [0u8; TAG_SIZE];
        out.copy_from_slice(tag.as_slice());
        Ok(out)
    }

    /// In-place AEAD open with a detached tag. `buffer` holds the tag-less
    /// ciphertext on entry and the (same-length) plaintext on return; the tag is
    /// supplied separately. Same result as [`Cipher::decrypt`] without its
    /// intermediate `Vec`. On authentication failure `Err` is returned and the
    /// buffer is NOT turned into plaintext — RustCrypto verifies the Poly1305 tag
    /// (constant-time) before applying the keystream — so a forged packet never
    /// exposes recovered plaintext.
    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; NONCE_SIZE],
        buffer: &mut [u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);
        self.cipher
            .decrypt_in_place_detached(nonce, b"", buffer, tag)
            .map_err(|_| CryptoError::DecryptFailed)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
}
