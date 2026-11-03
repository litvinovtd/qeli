use chacha20poly1305::{
    aead::{Aead, AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

pub struct Cipher {
    // chacha20poly1305 0.11 depends on `zeroize` non-optionally and wipes the key
    // in its `Drop` impl, so the AEAD key does not linger in freed heap. (There is
    // no `zeroize` cargo feature to toggle — it is always on.)
    cipher: ChaCha20Poly1305,
}

impl Cipher {
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid key length");
        Cipher { cipher }
    }

    // NOTE: there used to be a `generate_nonce(counter, extra)` helper here building
    // `[counter_be(8)] || [extra(4)]`. It had no callers, and its layout had already
    // diverged from the live one — `PacketCodec` builds `[seed(4)] || [counter_be(8)]` and
    // then runs it through a Feistel PRP (see protocol/packet.rs). A second "source of
    // truth" for nonce construction that disagrees with the real one is a trap: the unused
    // helper and its green test would have reassured anyone who reached for it, and nonce
    // layout is exactly where a mistake is unrecoverable. Removed rather than corrected —
    // there is nothing for it to do. (Audit 2026-07-27, X1.)

    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let n = Nonce::from(*nonce);
        self.cipher
            .encrypt(&n, plaintext)
            .map_err(|_| CryptoError::EncryptFailed)
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let n = Nonce::from(*nonce);
        self.cipher
            .decrypt(&n, ciphertext)
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
        let n = Nonce::from(*nonce);
        let tag = self
            .cipher
            .encrypt_inout_detached(&n, b"", buffer.into())
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
        let n = Nonce::from(*nonce);
        let t = Tag::from(*tag);
        self.cipher
            .decrypt_inout_detached(&n, b"", buffer.into(), &t)
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

#[cfg(test)]
mod known_answer_tests {
    use super::*;
    use chacha20poly1305::aead::Payload;

    #[test]
    fn rfc8439_and_independent_empty_aad_wrapper_vectors() {
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/chacha20poly1305-rfc8439.json"
        ))
        .unwrap();
        let bytes = |name: &str| -> Vec<u8> {
            data[name]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        };
        let key = bytes("key").try_into().unwrap();
        let nonce: [u8; NONCE_SIZE] = bytes("nonce").try_into().unwrap();
        let plaintext = bytes("plaintext");
        let aad = bytes("aad");
        let cipher = Cipher::new(&key);
        let expected = bytes("rfc_ciphertext_tag");
        assert_eq!(
            cipher
                .cipher
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &aad
                    }
                )
                .unwrap(),
            expected
        );
        let empty_aad = bytes("empty_aad_ciphertext_tag");
        assert_eq!(cipher.encrypt(&nonce, &plaintext).unwrap(), empty_aad);
        assert_eq!(cipher.decrypt(&nonce, &empty_aad).unwrap(), plaintext);
        let mut buffer = plaintext.clone();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &mut buffer)
            .unwrap();
        assert_eq!(buffer, empty_aad[..plaintext.len()]);
        assert_eq!(tag, empty_aad[plaintext.len()..]);
        // Each ciphertext/tag byte must authenticate. Failed detached open leaves no plaintext.
        for index in 0..empty_aad.len() {
            let mut altered = empty_aad.clone();
            altered[index] ^= 1;
            assert!(cipher.decrypt(&nonce, &altered).is_err());
            let split = altered.len() - TAG_SIZE;
            let tag = altered[split..].try_into().unwrap();
            let mut body = altered[..split].to_vec();
            let before = body.clone();
            assert!(cipher
                .decrypt_in_place_detached(&nonce, &mut body, &tag)
                .is_err());
            assert_eq!(body, before);
        }
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        assert!(cipher.decrypt(&wrong_nonce, &empty_aad).is_err());
        assert!(cipher
            .cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &expected,
                    aad: b"wrong aad"
                }
            )
            .is_err());
        for length in 0..TAG_SIZE {
            assert!(cipher.decrypt(&nonce, &empty_aad[..length]).is_err());
        }
    }
}
