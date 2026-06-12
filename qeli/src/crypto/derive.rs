use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const SALT: &[u8] = b"qeli-key-derivation-v1";
/// Domain-separation salt for the hybrid (post-quantum) KDF. Distinct from the v1
/// salt so a hybrid endpoint and a classic one can NEVER derive matching keys —
/// the difference is caught as a decrypt failure, not a silent downgrade.
const SALT_HYBRID: &[u8] = b"qeli-key-derivation-v2-hybrid";
/// Salts for the `bind_static_to_session` variants (H-1): the data keys also fold
/// in the static-ephemeral DH so they are bound to the server's long-lived
/// identity. Distinct from the unbound salts → a bound and an unbound peer can
/// never derive matching keys (caught as a decrypt failure, never a silent
/// downgrade), exactly like the classic↔hybrid separation.
const SALT_BOUND: &[u8] = b"qeli-key-derivation-v1-static-bound";
const SALT_HYBRID_BOUND: &[u8] = b"qeli-key-derivation-v2-hybrid-static-bound";

/// Expand the two directional AEAD keys from an HKDF instance (shared helper).
fn expand_dir(hk: &Hkdf<Sha256>) -> ([u8; 32], [u8; 32]) {
    let mut enc_key = [0u8; 32];
    let mut dec_key = [0u8; 32];
    hk.expand(b"server-to-client-enc-key", &mut enc_key)
        .expect("expand enc key");
    hk.expand(b"client-to-server-enc-key", &mut dec_key)
        .expect("expand dec key");
    (enc_key, dec_key)
}

/// Like [`derive_keys`] but additionally folds the **static-ephemeral** DH
/// `es = X25519(client_ephemeral, server_static)` into the IKM, binding the data
/// keys to the server's long-lived identity (Noise-IK style). An attacker must
/// then break BOTH the ephemeral DH AND obtain the server static key to recover
/// the session — a failed ephemeral RNG alone no longer exposes the data. Gated
/// behind `auth.bind_static_to_session`; requires the client to have pinned the
/// server static key. `plain`-mode counterpart of [`derive_keys_hybrid_bound`].
pub fn derive_keys_bound(ee: &[u8; 32], es: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ee);
    ikm[32..].copy_from_slice(es);
    let keys = expand_dir(&Hkdf::<Sha256>::new(Some(SALT_BOUND), &ikm));
    ikm.zeroize();
    keys
}

/// Hybrid PQ derivation [`derive_keys_hybrid`] with the static-ephemeral DH `es`
/// additionally folded in (IKM = `x25519_ee ‖ mlkem ‖ es`). See [`derive_keys_bound`].
pub fn derive_keys_hybrid_bound(
    x25519_shared: &[u8; 32],
    mlkem_shared: &[u8; 32],
    es: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(x25519_shared);
    ikm[32..64].copy_from_slice(mlkem_shared);
    ikm[64..].copy_from_slice(es);
    let keys = expand_dir(&Hkdf::<Sha256>::new(Some(SALT_HYBRID_BOUND), &ikm));
    ikm.zeroize();
    keys
}

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
    fn bound_handshake_keys_agree_end_to_end() {
        use crate::crypto::{Keypair, StaticKeypair};
        let server_static = StaticKeypair::generate();
        let server_eph = Keypair::generate();
        let client_eph = Keypair::generate();
        // ephemeral-ephemeral DH — both sides agree.
        let ee = client_eph.derive_shared(server_eph.public()).0;
        assert_eq!(ee, server_eph.derive_shared(client_eph.public()).0);
        // static-ephemeral DH: the client computes it from the PINNED server static
        // pub, the server from its static private + the client ephemeral pub. X25519
        // is symmetric, so the two `es` values match — the crux of the H-1 wiring.
        let es_client = client_eph.derive_shared(&server_static.public).0;
        let es_server = server_static.derive_shared(client_eph.public()).0;
        assert_eq!(es_client, es_server, "client/server must agree on es");
        // → both ends derive identical bound session keys (handshake succeeds).
        assert_eq!(
            derive_keys_bound(&ee, &es_client),
            derive_keys_bound(&ee, &es_server)
        );
        // A wrong pin yields a different es → different keys → the handshake would
        // fail to decrypt (which is the correct anti-MITM behaviour).
        let wrong = StaticKeypair::generate();
        let es_wrong = client_eph.derive_shared(&wrong.public).0;
        assert_ne!(
            derive_keys_bound(&ee, &es_wrong),
            derive_keys_bound(&ee, &es_server)
        );
    }

    #[test]
    fn static_bound_binds_identity_and_is_domain_separated() {
        let ee = [1u8; 32];
        let ml = [2u8; 32];
        let es = [3u8; 32];
        // deterministic
        assert_eq!(derive_keys_bound(&ee, &es), derive_keys_bound(&ee, &es));
        // depends on the static-ephemeral half
        assert_ne!(
            derive_keys_bound(&ee, &es),
            derive_keys_bound(&ee, &[9u8; 32])
        );
        assert_ne!(
            derive_keys_hybrid_bound(&ee, &ml, &es),
            derive_keys_hybrid_bound(&ee, &ml, &[9u8; 32])
        );
        // bound must NOT match the unbound derivation over the same ee/ml (no
        // silent interop between a bound and an unbound peer)
        assert_ne!(derive_keys_bound(&ee, &es), derive_keys(&ee));
        assert_ne!(
            derive_keys_hybrid_bound(&ee, &ml, &es),
            derive_keys_hybrid(&ee, &ml)
        );
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
