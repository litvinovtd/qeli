use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

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
const SALT_DATA_FRAG: &[u8] = b"qeli-data-fragment-mac-v1";

const LABEL_RESUME_SECRET: &[u8] = b"qeli-resume-secret-v1";
const LABEL_C2S_CID_SECRET: &[u8] = b"qeli-c2s-cid-secret-v1";
const LABEL_S2C_CID_SECRET: &[u8] = b"qeli-s2c-cid-secret-v1";
const LABEL_CONTROL_SECRET: &[u8] = b"qeli-control-secret-v1";

/// Domain-separated secrets derived from the original authenticated handshake IKM.
///
/// The type deliberately implements neither `Debug`, `Clone` nor serde traits. Every field is
/// held in a zeroizing container, and callers can only borrow secret material. The existing
/// `derive_keys*` functions remain the production data-key API during roaming stage 0, so merely
/// compiling this foundation cannot change live session keys or advertise roaming support.
pub struct SessionKeyMaterial {
    server_to_client_key: Zeroizing<[u8; 32]>,
    client_to_server_key: Zeroizing<[u8; 32]>,
    resume_secret: Zeroizing<[u8; 32]>,
    client_to_server_cid_secret: Zeroizing<[u8; 32]>,
    server_to_client_cid_secret: Zeroizing<[u8; 32]>,
    control_secret: Zeroizing<[u8; 32]>,
}

impl SessionKeyMaterial {
    pub fn data_keys(&self) -> ([u8; 32], [u8; 32]) {
        (*self.server_to_client_key, *self.client_to_server_key)
    }

    pub fn resume_secret(&self) -> &[u8; 32] {
        &self.resume_secret
    }

    pub fn client_to_server_cid_secret(&self) -> &[u8; 32] {
        &self.client_to_server_cid_secret
    }

    pub fn server_to_client_cid_secret(&self) -> &[u8; 32] {
        &self.server_to_client_cid_secret
    }

    pub fn control_secret(&self) -> &[u8; 32] {
        &self.control_secret
    }
}

fn expand_secret(hk: &Hkdf<Sha256>, label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0u8; 32]);
    hk.expand(label, secret.as_mut())
        .expect("32-byte HKDF expansion is valid");
    secret
}

fn expand_session_material(hk: &Hkdf<Sha256>) -> SessionKeyMaterial {
    let (server_to_client_key, client_to_server_key) = expand_dir(hk);
    SessionKeyMaterial {
        server_to_client_key: Zeroizing::new(server_to_client_key),
        client_to_server_key: Zeroizing::new(client_to_server_key),
        resume_secret: expand_secret(hk, LABEL_RESUME_SECRET),
        client_to_server_cid_secret: expand_secret(hk, LABEL_C2S_CID_SECRET),
        server_to_client_cid_secret: expand_secret(hk, LABEL_S2C_CID_SECRET),
        control_secret: expand_secret(hk, LABEL_CONTROL_SECRET),
    }
}

/// Derive a dedicated fragment-MAC subkey from one directional AEAD key. Fragment
/// authentication and record encryption never reuse a key, while both remain bound to the
/// same session and direction.
pub fn derive_data_frag_key(aead_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SALT_DATA_FRAG), aead_key);
    let mut key = [0u8; 32];
    hk.expand(b"fragment-mac-key", &mut key)
        .expect("expand data fragment MAC key");
    key
}

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

/// Stage-0 roaming material for the classic X25519 authentication mode.
pub fn derive_session_material(shared_secret: &[u8; 32]) -> SessionKeyMaterial {
    expand_session_material(&Hkdf::<Sha256>::new(Some(SALT), shared_secret))
}

/// Like [`derive_keys`] but additionally folds the **static-ephemeral** DH
/// `es = X25519(client_ephemeral, server_static)` into the IKM, binding the data
/// keys to the server's long-lived identity (Noise-IK style). An attacker must
/// then break BOTH the ephemeral DH AND obtain the server static key to recover
/// the session — a failed ephemeral RNG alone no longer exposes the data. Gated
/// behind `auth.bind_static_to_session`; requires the client to have pinned the
/// server static key. `plain`-mode counterpart of [`derive_keys_hybrid_bound`].
pub fn derive_session_material_bound(ee: &[u8; 32], es: &[u8; 32]) -> SessionKeyMaterial {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ee);
    ikm[32..].copy_from_slice(es);
    let material = expand_session_material(&Hkdf::<Sha256>::new(Some(SALT_BOUND), &ikm));
    ikm.zeroize();
    material
}

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
pub fn derive_session_material_hybrid_bound(
    x25519_shared: &[u8; 32],
    mlkem_shared: &[u8; 32],
    es: &[u8; 32],
) -> SessionKeyMaterial {
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(x25519_shared);
    ikm[32..64].copy_from_slice(mlkem_shared);
    ikm[64..].copy_from_slice(es);
    let material = expand_session_material(&Hkdf::<Sha256>::new(Some(SALT_HYBRID_BOUND), &ikm));
    ikm.zeroize();
    material
}

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
pub fn derive_session_material_hybrid(
    x25519_shared: &[u8; 32],
    mlkem_shared: &[u8; 32],
) -> SessionKeyMaterial {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_shared);
    ikm[32..].copy_from_slice(mlkem_shared);
    let material = expand_session_material(&Hkdf::<Sha256>::new(Some(SALT_HYBRID), &ikm));
    ikm.zeroize();
    material
}

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

    /// The Rust half of the SHARED key-derivation KAT (`conformance/hkdf.json`).
    ///
    /// Both ends must derive byte-identical keys or the tunnel does not come up; a subtler
    /// divergence (the two DIRECTIONS swapped) yields a tunnel that authenticates and then
    /// decrypts nothing. Rust generates the file, so the happy path is a tautology by
    /// design — the job here is to fail when the fixture is hand-edited or the code changes
    /// without regenerating, which is how the other three would start disagreeing with a
    /// file they still believe is authoritative.
    #[test]
    fn hkdf_matches_shared_conformance_vectors() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex in fixture"))
                .collect()
        }
        fn arr32(v: &serde_json::Value, k: &str) -> [u8; 32] {
            unhex(
                v[k].as_str()
                    .unwrap_or_else(|| panic!("missing input `{k}`")),
            )
            .try_into()
            .expect("input is not 32 bytes")
        }
        fn hexs(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        let fx: serde_json::Value =
            serde_json::from_str(include_str!("../../../conformance/hkdf.json"))
                .expect("conformance/hkdf.json is not valid JSON");
        assert!(
            fx["platforms"]
                .as_array()
                .expect("fixture has no `platforms`")
                .iter()
                .any(|p| p.as_str() == Some("rust")),
            "rust is not listed in `platforms` of hkdf.json"
        );

        let cases = fx["cases"].as_array().expect("fixture has no `cases`");
        assert!(!cases.is_empty(), "fixture file has no cases");

        for c in cases {
            let name = c["name"].as_str().unwrap_or("<unnamed>");
            let inp = &c["inputs"];
            let (s2c, c2s) = match c["scheme"].as_str().unwrap() {
                "classic" => derive_keys(&arr32(inp, "shared_secret")),
                "hybrid" => {
                    derive_keys_hybrid(&arr32(inp, "x25519_shared"), &arr32(inp, "mlkem_shared"))
                }
                "bound" => derive_keys_bound(&arr32(inp, "ee"), &arr32(inp, "es")),
                "hybrid-bound" => derive_keys_hybrid_bound(
                    &arr32(inp, "x25519_shared"),
                    &arr32(inp, "mlkem_shared"),
                    &arr32(inp, "es"),
                ),
                other => panic!("case {name}: unknown scheme `{other}`"),
            };
            assert_eq!(
                hexs(&s2c),
                c["expect"]["server_to_client"].as_str().unwrap(),
                "case {name}: server_to_client key disagrees"
            );
            assert_eq!(
                hexs(&c2s),
                c["expect"]["client_to_server"].as_str().unwrap(),
                "case {name}: client_to_server key disagrees"
            );
        }
    }

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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn assert_material(
        material: &SessionKeyMaterial,
        expected_data: ([u8; 32], [u8; 32]),
        resume: &str,
        c2s_cid: &str,
        s2c_cid: &str,
        control: &str,
    ) {
        assert_eq!(
            material.data_keys(),
            expected_data,
            "legacy data keys drifted"
        );
        assert_eq!(hex(material.resume_secret()), resume);
        assert_eq!(hex(material.client_to_server_cid_secret()), c2s_cid);
        assert_eq!(hex(material.server_to_client_cid_secret()), s2c_cid);
        assert_eq!(hex(material.control_secret()), control);
    }

    /// Known-answer vectors for every authenticated key schedule. These pin both the new labels
    /// and the requirement that the two existing directional data keys remain byte-identical.
    #[test]
    fn roaming_material_known_answers_cover_all_auth_modes() {
        let ee = [1u8; 32];
        let mlkem = [2u8; 32];
        let es = [3u8; 32];

        assert_material(
            &derive_session_material(&ee),
            derive_keys(&ee),
            "82dd44d2709965a090ca509e5b03695dfa90e7e8ebad9376d1a2390381efc3b0",
            "8cd62d7a67c9af2189c4b112791d4fd14032b5931f7df34e26995f5456715e4a",
            "f1cea967fb75d7b6a7d29c576d2dc10a8e095f07fd61345655de19c26af8148d",
            "8eb55ca0503f17c0f36121289cd99acba8aa5a8ef8fcdfe6a1085c9a53d19458",
        );
        assert_material(
            &derive_session_material_hybrid(&ee, &mlkem),
            derive_keys_hybrid(&ee, &mlkem),
            "fb3e7c7e6e89ef1548e61a6114e50c9feb44f5f61677b0f26f92b2d3a9cadf1d",
            "4091a5b9a821c4ea371f5e1a52a131d539c52cf9a768ea1f9ee00259738f26c2",
            "864b22904fe66d55b9741e7efdc5bc2e2f1ba7e71188d619d5913d1cce01b016",
            "a74a99d27c703f99b0fc79311aabab248bf8780ec263d2525b59e344bd2b95de",
        );
        assert_material(
            &derive_session_material_bound(&ee, &es),
            derive_keys_bound(&ee, &es),
            "c0f181993f81d56911f078c1758e6be573195be95400e438df577e558a5168cb",
            "19de79e888f87c889ada740ab4fa303059a75bc669f11d4ed354c11b9764a23e",
            "374cb3417269aaacbb4e3c39e19a3d998422aac6a9114c3aafa12b8fbfe73480",
            "c87a20eefcf413fe7088839b31cd0a2f4b1b70c6bfa73d4572cd710431e0ebba",
        );
        assert_material(
            &derive_session_material_hybrid_bound(&ee, &mlkem, &es),
            derive_keys_hybrid_bound(&ee, &mlkem, &es),
            "897908b7d912e866229041fef26093eeca8df655b62514df54ccb1c1073e2aee",
            "cd45f0ce7e382c95b4c7aac1f92def33f7fb0677e1385dc8d626a80617436ffe",
            "75419fb48b77d9c308dead8a2378850081c91452af48d80733d32345541b5b50",
            "b89e1ee8a23a4b3df44c2d13a220a1bd299b2c4791f5b954b1895c6af18e966c",
        );
    }
}
