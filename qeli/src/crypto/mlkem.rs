//! Hybrid X25519MLKEM768 (TLS named group 0x11ec) key exchange.
//!
//! qeli uses the hybrid group in two distinct layers:
//!
//! 1. **Inner legacy camouflage tunnel** (`fake-tls`, `obfs`, `reality`, UDP):
//!    clients retain a real ML-KEM-768 decapsulation key; servers require the PQ
//!    share and both sides combine X25519 and ML-KEM in `derive_keys_hybrid`.
//! 2. **Outer real TLS 1.3** (`reality-tls`): the TLS handshake can negotiate
//!    X25519MLKEM768, or classic X25519 according to the selected target/server.
//!    The private inner H2-carried qeli exchange uses classic X25519 with static
//!    identity binding. It is not a second mandatory PQ exchange. `plain` also
//!    uses classic X25519, without an outer TLS layer.
//!
//! Live paths use [`x25519_mlkem768_share_from_ek`] and retain the matching
//! decapsulation key so the ML-KEM secret is actually used.

use ml_kem::{Decapsulate, Encapsulate, EncapsulationKey, Kem, Key, KeyExport, MlKem768};

/// IANA TLS supported-group code point for X25519MLKEM768.
pub const X25519MLKEM768: u16 = 0x11ec;

/// ML-KEM-768 encapsulation-key length (FIPS 203): 1184 bytes.
pub const MLKEM768_EK_LEN: usize = 1184;

/// ML-KEM-768 ciphertext length — the server's key_exchange PQ component: 1088 bytes.
pub const MLKEM768_CT_LEN: usize = 1088;

/// A retained ML-KEM-768 decapsulation key: the client keeps it after sending the
/// ClientHello so it can open the server's ciphertext during the real (L3) hybrid
/// key exchange.
pub type DecapKey = ml_kem::DecapsulationKey<MlKem768>;

/// Build the X25519MLKEM768 client `key_exchange` from a CALLER-PROVIDED ML-KEM
/// encapsulation key, so the caller keeps the matching decapsulation key for a real
/// hybrid handshake: `ek (1184) ‖ x25519_pub (32)` = 1216 bytes. Same wire layout as
/// the negotiated hybrid group. The caller must retain the corresponding secret key.
pub fn x25519_mlkem768_share_from_ek(ek: &[u8], x25519_pub: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ek.len() + x25519_pub.len());
    out.extend_from_slice(ek);
    out.extend_from_slice(x25519_pub);
    out
}

/// Client: a fresh ML-KEM-768 keypair for a real hybrid handshake. Returns the
/// decapsulation key to keep and the 1184-byte encapsulation key for the
/// ClientHello key_share. The caller retains `dk` through decapsulation.
pub fn mlkem768_keypair() -> (DecapKey, Vec<u8>) {
    let (dk, ek) = MlKem768::generate_keypair();
    (dk, ek.to_bytes().as_slice().to_vec())
}

/// Server: encapsulate against the client's encapsulation-key bytes. Returns the
/// 1088-byte ciphertext (the ServerHello key_share PQ component) and the 32-byte
/// shared secret. `None` if `client_ek` is the wrong length or malformed.
pub fn mlkem768_encapsulate(client_ek: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let key = Key::<EncapsulationKey<MlKem768>>::try_from(client_ek).ok()?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).ok()?;
    let (ct, ss) = ek.encapsulate();
    let ss = zeroize::Zeroizing::new(ss);
    Some((ct.as_slice().to_vec(), ss.as_slice().to_vec()))
}

/// Client: decapsulate the server's ciphertext with the retained decapsulation
/// key. Returns the 32-byte shared secret, or `None` for a wrong-length ciphertext.
/// A full-length invalid ciphertext produces an implicit-rejection secret (FIPS 203);
/// the subsequent authenticated handshake must reject it, rather than revealing
/// whether decapsulation accepted the ciphertext.
pub fn mlkem768_decapsulate(dk: &DecapKey, ct: &[u8]) -> Option<Vec<u8>> {
    dk.decapsulate_slice(ct).ok().map(|ss| {
        let ss = zeroize::Zeroizing::new(ss);
        ss.as_slice().to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_pq_encap_decap_roundtrip() {
        // The server's encapsulated shared secret must equal what the client
        // decapsulates — the PQ half of the hybrid key exchange.
        let (dk, ek) = mlkem768_keypair();
        assert_eq!(ek.len(), MLKEM768_EK_LEN);
        let (ct, server_ss) = mlkem768_encapsulate(&ek).expect("encapsulate");
        assert_eq!(ct.len(), MLKEM768_CT_LEN, "ML-KEM-768 ciphertext is 1088 B");
        assert_eq!(server_ss.len(), 32);
        let client_ss = mlkem768_decapsulate(&dk, &ct).expect("decapsulate");
        assert_eq!(client_ss, server_ss, "ML-KEM shared secrets must agree");
    }

    #[test]
    fn encapsulate_rejects_malformed_ek() {
        assert!(mlkem768_encapsulate(&[0u8; 10]).is_none());
    }

    #[test]
    fn share_layout_and_size() {
        let x = [7u8; 32];
        let (_dk, ek) = mlkem768_keypair();
        let s = x25519_mlkem768_share_from_ek(&ek, &x);
        assert_eq!(
            s.len(),
            MLKEM768_EK_LEN + 32,
            "ek(1184) ‖ x25519(32) = 1216"
        );
        assert_eq!(
            &s[MLKEM768_EK_LEN..],
            &x,
            "x25519 pub follows the ML-KEM ek"
        );
    }

    #[test]
    fn fresh_ek_each_call() {
        let x = [0u8; 32];
        let (_a, a_ek) = mlkem768_keypair();
        let (_b, b_ek) = mlkem768_keypair();
        let a = x25519_mlkem768_share_from_ek(&a_ek, &x);
        let b = x25519_mlkem768_share_from_ek(&b_ek, &x);
        assert_ne!(a, b, "each call must generate a fresh ML-KEM key");
    }
}

#[cfg(test)]
mod nist_tests {
    use super::*;
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../conformance/mlkem768-nist.json")).unwrap()
    }
    fn bytes(case: &serde_json::Value, field: &str) -> Vec<u8> {
        case[field]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn decapsulation_key_has_zeroize_on_drop() {
        fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        requires_zeroize_on_drop::<DecapKey>();
    }

    #[test]
    #[allow(deprecated)] // Only NIST's published expanded-key vectors use this format.
    fn nist_mlkem768_keygen_known_answers() {
        let data = vectors();
        assert_eq!(data["keygen"].as_array().unwrap().len(), 25);
        for case in data["keygen"].as_array().unwrap() {
            let mut seed = bytes(case, "d");
            seed.extend(bytes(case, "z"));
            let dk = DecapKey::from_seed(ml_kem::Seed::try_from(seed.as_slice()).unwrap());
            assert_eq!(
                dk.encapsulation_key().to_bytes().as_slice(),
                bytes(case, "ek"),
                "ek tcId {}",
                case["tcId"]
            );
            assert_eq!(
                dk.to_expanded_bytes().as_slice(),
                bytes(case, "dk"),
                "dk tcId {}",
                case["tcId"]
            );
        }
    }

    #[test]
    fn nist_mlkem768_encapsulation_known_answers() {
        let data = vectors();
        assert_eq!(data["encapsulation"].as_array().unwrap().len(), 25);
        for case in data["encapsulation"].as_array().unwrap() {
            let key =
                Key::<EncapsulationKey<MlKem768>>::try_from(bytes(case, "ek").as_slice()).unwrap();
            let ek = EncapsulationKey::<MlKem768>::new(&key).unwrap();
            let m = ml_kem::B32::try_from(bytes(case, "m").as_slice()).unwrap();
            let (ct, ss) = ek.encapsulate_deterministic(&m);
            assert_eq!(
                ct.as_slice(),
                bytes(case, "c"),
                "ciphertext tcId {}",
                case["tcId"]
            );
            assert_eq!(
                ss.as_slice(),
                bytes(case, "k"),
                "secret tcId {}",
                case["tcId"]
            );
        }
    }

    #[test]
    #[allow(deprecated)] // Production uses seeds; this imports independent NIST dk vectors.
    fn nist_mlkem768_decapsulation_and_implicit_rejection_known_answers() {
        let data = vectors();
        assert_eq!(data["decapsulation"].as_array().unwrap().len(), 10);
        let mut rejected = 0;
        for case in data["decapsulation"].as_array().unwrap() {
            let expanded = ml_kem::ExpandedDecapsulationKey::<MlKem768>::try_from(
                bytes(case, "dk").as_slice(),
            )
            .unwrap();
            let dk = DecapKey::from_expanded(&expanded).unwrap();
            let ct = bytes(case, "c");
            assert_eq!(
                mlkem768_decapsulate(&dk, &ct).unwrap(),
                bytes(case, "k"),
                "tcId {}",
                case["tcId"]
            );
            assert!(mlkem768_decapsulate(&dk, &ct[..ct.len() - 1]).is_none());
            if case["reason"] == "modify ciphertext" {
                rejected += 1;
            }
        }
        assert_eq!(rejected, 5, "pin independent invalid-ciphertext coverage");
        // 12-bit polynomial coefficients must be canonical (< q = 3329).
        assert!(mlkem768_encapsulate(&[255; MLKEM768_EK_LEN]).is_none());
    }
}
