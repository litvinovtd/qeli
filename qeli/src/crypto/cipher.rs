use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

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
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
}
