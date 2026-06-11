use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const SALT: &[u8] = b"qeli-key-derivation-v1";
/// Domain-separation salt for the hybrid (post-quantum) KDF. Distinct from the v1
/// salt so a hybrid endpoint and a classic one can NEVER derive matching keys —
/// the difference is caught as a decrypt failure, not a silent downgrade.
const SALT_HYBRID: &[u8] = b"qeli-key-derivation-v2-hybrid";

/// Derive the directional data-plane AEAD keys from the tunnel's **classic X25519**
/// shared secret: `(server→client, client→server)`.
///
/// POST-QUANTUM SCOPE: this is the legacy classic-only derivation, kept for the
/// `plain` wire mode (which has no TLS-shaped handshake to carry an ML-KEM share).
/// The fake-tls / obfs / reality-tls / UDP modes use [`derive_keys_hybrid`], whose
/// keys also depend on an ML-KEM-768 secret and are therefore harvest-now/
/// decrypt-later resistant. See [`crate::crypto::mlkem`].
pub fn derive_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(SALT), shared_secret);

    let mut enc_key = [0u8; 32];
    let mut dec_key = [0u8; 32];

    hk.expand(b"server-to-client-enc-key", &mut enc_key)
        .expect("expand enc key");
    hk.expand(b"client-to-server-enc-key", &mut dec_key)
        .expect("expand dec key");

    (enc_key, dec_key)
}

/// Hybrid post-quantum key derivation: the directional AEAD keys depend on BOTH
/// the classic X25519 shared secret AND the ML-KEM-768 shared secret, concatenated
/// as the HKDF input keying material (`x25519 ‖ mlkem`, 64 bytes).
///
/// This is the standard "hybrid" construction (TLS 1.3 X25519MLKEM768, WireGuard-PQ,
/// Signal PQXDH): the result stays secure as long as EITHER primitive holds — a
/// classical break of ML-KEM (it is young) is covered by X25519, and a quantum
/// break of X25519 is covered by ML-KEM. So the tunnel is at least as strong as the
/// old classic derivation and additionally resists harvest-now/decrypt-later.
///
/// The order `x25519 ‖ mlkem` and the `v2` salt are wire-format: both peers must
/// match exactly, and a hybrid peer cannot interop with a classic (`derive_keys`)
/// one — by design (no silent PQ downgrade).
pub fn derive_keys_hybrid(
    x25519_shared: &[u8; 32],
    mlkem_shared: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_shared);
    ikm[32..].copy_from_slice(mlkem_shared);

    let hk = Hkdf::<Sha256>::new(Some(SALT_HYBRID), &ikm);
    let mut enc_key = [0u8; 32];
    let mut dec_key = [0u8; 32];
    hk.expand(b"server-to-client-enc-key", &mut enc_key)
        .expect("expand enc key");
    hk.expand(b"client-to-server-enc-key", &mut dec_key)
        .expect("expand dec key");

    // The concatenated secret is sensitive — wipe the stack copy after use.
    ikm.zeroize();
    (enc_key, dec_key)
}

#[cfg(test)]
mod hybrid_tests {
    use super::*;

    #[test]
    fn hybrid_is_deterministic_and_distinct_from_classic() {
        let x = [0x11u8; 32];
        let ml = [0x22u8; 32];
        let (e1, d1) = derive_keys_hybrid(&x, &ml);
        let (e2, d2) = derive_keys_hybrid(&x, &ml);
        assert_eq!((e1, d1), (e2, d2), "deterministic");
        assert_ne!(e1, d1, "directions differ");
        // Domain separation: the hybrid keys must NOT equal the classic derivation
        // over the same X25519 secret (no accidental downgrade interop).
        let (ce, _) = derive_keys(&x);
        assert_ne!(e1, ce, "hybrid must be domain-separated from classic");
    }

    #[test]
    fn hybrid_depends_on_both_secrets() {
        let base = derive_keys_hybrid(&[1u8; 32], &[2u8; 32]);
        assert_ne!(
            base,
            derive_keys_hybrid(&[9u8; 32], &[2u8; 32]),
            "changing the X25519 half changes the keys"
        );
        assert_ne!(
            base,
            derive_keys_hybrid(&[1u8; 32], &[9u8; 32]),
            "changing the ML-KEM half changes the keys"
        );
    }
}
