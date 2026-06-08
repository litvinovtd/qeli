//! Hybrid X25519MLKEM768 (TLS named group 0x11ec) client key share.
//!
//! This is the post-quantum key exchange that current Chrome (≥124, on by
//! default) offers in every ClientHello. We include it purely for fingerprint
//! parity: a Chrome-grade ClientHello that lacks the ~1.2 KB PQ share is an
//! increasingly anomalous shape as real Chrome traffic carries it, and that
//! divergence is passively observable. Our REALITY server negotiates classic
//! X25519 (it does not implement ML-KEM), so the freshly generated ML-KEM
//! decapsulation key is discarded immediately — only the encapsulation key
//! travels on the wire, exactly as a real client's would.

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

/// Full client `key_exchange` for X25519MLKEM768: `ML-KEM-768 ek (1184) ‖ X25519
/// pub (32)` = 1216 bytes. The ML-KEM key comes first per draft-ietf-tls-ecdhe-mlkem
/// for the 0x11ec code point (the order is reversed from the older
/// X25519Kyber768Draft00 0x6399, where X25519 came first).
///
/// A fresh ML-KEM-768 keypair is generated each call and its secret (decapsulation)
/// half is dropped — the server selects X25519, so the PQ secret is never used.
pub fn x25519_mlkem768_client_share(x25519_pub: &[u8]) -> Vec<u8> {
    // `generate_keypair` uses the OS RNG (getrandom) — secure and free of any
    // rand_core version coupling. The decapsulation key is dropped immediately.
    let (_dk, ek) = MlKem768::generate_keypair();
    let ek_bytes = ek.to_bytes(); // KeyExport: 1184-byte encapsulation key
    let mut out = Vec::with_capacity(MLKEM768_EK_LEN + x25519_pub.len());
    out.extend_from_slice(ek_bytes.as_slice());
    out.extend_from_slice(x25519_pub);
    out
}

/// Client: a fresh ML-KEM-768 keypair for a real hybrid handshake. Returns the
/// decapsulation key to keep and the 1184-byte encapsulation key for the
/// ClientHello key_share. (Unlike [`x25519_mlkem768_client_share`], which throws
/// the secret away for fingerprint-only parity, here the caller retains `dk`.)
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
    Some((ct.as_slice().to_vec(), ss.as_slice().to_vec()))
}

/// Client: decapsulate the server's ciphertext with the retained decapsulation
/// key. Returns the 32-byte shared secret, or `None` on a malformed ciphertext.
pub fn mlkem768_decapsulate(dk: &DecapKey, ct: &[u8]) -> Option<Vec<u8>> {
    dk.decapsulate_slice(ct)
        .ok()
        .map(|ss| ss.as_slice().to_vec())
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
        let s = x25519_mlkem768_client_share(&x);
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
        let a = x25519_mlkem768_client_share(&x);
        let b = x25519_mlkem768_client_share(&x);
        assert_ne!(a, b, "each call must generate a fresh ML-KEM key");
    }
}
