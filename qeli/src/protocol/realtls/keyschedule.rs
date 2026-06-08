//! M2.2 — TLS 1.3 key schedule (RFC 8446 §7.1), parameterised over the cipher
//! suite hash so it serves both TLS_AES_128_GCM_SHA256 (SHA-256, 16-byte AES key)
//! and TLS_AES_256_GCM_SHA384 (SHA-384, 32-byte AES key). Secrets are carried as
//! `Vec<u8>` whose length is the suite hash length (32 or 48). The SHA-256 path is
//! verified byte-for-byte against the RFC 8448 §3 "Simple 1-RTT Handshake" trace;
//! the SHA-384 path runs the identical algorithm and is exercised by the realtls
//! client↔server interop tests.

// M2.2 scaffolding: consumed by the client/server handshakes.
#![allow(dead_code)]

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

pub const IV_LEN: usize = 12;

/// The TLS 1.3 cipher suites the realtls stack implements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suite {
    /// TLS_AES_128_GCM_SHA256 (0x1301).
    Aes128Sha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302).
    Aes256Sha384,
}

impl Suite {
    pub fn from_code(code: u16) -> Option<Suite> {
        match code {
            0x1301 => Some(Suite::Aes128Sha256),
            0x1302 => Some(Suite::Aes256Sha384),
            _ => None,
        }
    }
    pub fn code(self) -> u16 {
        match self {
            Suite::Aes128Sha256 => 0x1301,
            Suite::Aes256Sha384 => 0x1302,
        }
    }
    /// Hash output length, which is also the secret length: 32 or 48.
    pub fn hash_len(self) -> usize {
        match self {
            Suite::Aes128Sha256 => 32,
            Suite::Aes256Sha384 => 48,
        }
    }
    /// AEAD key length: 16 (AES-128) or 32 (AES-256).
    pub fn key_len(self) -> usize {
        match self {
            Suite::Aes128Sha256 => 16,
            Suite::Aes256Sha384 => 32,
        }
    }
}

/// Hash of the concatenated handshake messages, per the suite.
pub fn transcript_hash(suite: Suite, messages: &[u8]) -> Vec<u8> {
    match suite {
        Suite::Aes128Sha256 => Sha256::digest(messages).to_vec(),
        Suite::Aes256Sha384 => Sha384::digest(messages).to_vec(),
    }
}

/// HKDF-Extract (RFC 5869) = HMAC-Hash(salt, ikm), per the suite hash.
pub fn hkdf_extract(suite: Suite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match suite {
        Suite::Aes128Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
        Suite::Aes256Sha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
    }
}

/// HKDF-Expand-Label (RFC 8446 §7.1):
/// `HKDF-Expand(secret, HkdfLabel{length, "tls13 "+label, context}, length)`.
pub fn hkdf_expand_label(
    suite: Suite,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut okm = vec![0u8; length];
    match suite {
        Suite::Aes128Sha256 => Hkdf::<Sha256>::from_prk(secret)
            .expect("PRK is hash-length")
            .expand(&info, &mut okm)
            .expect("valid OKM length"),
        Suite::Aes256Sha384 => Hkdf::<Sha384>::from_prk(secret)
            .expect("PRK is hash-length")
            .expand(&info, &mut okm)
            .expect("valid OKM length"),
    }
    okm
}

/// Derive-Secret(secret, label, messages) with a precomputed transcript hash.
pub fn derive_secret(suite: Suite, secret: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    hkdf_expand_label(suite, secret, label, transcript, suite.hash_len())
}

/// AEAD write key + IV for a traffic secret (RFC 8446 §7.3).
#[derive(Clone)]
pub struct TrafficKeys {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

pub fn traffic_keys(suite: Suite, secret: &[u8]) -> TrafficKeys {
    TrafficKeys {
        key: hkdf_expand_label(suite, secret, b"key", b"", suite.key_len()),
        iv: hkdf_expand_label(suite, secret, b"iv", b"", IV_LEN),
    }
}

/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length).
pub fn finished_key(suite: Suite, secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(suite, secret, b"finished", b"", suite.hash_len())
}

/// Finished `verify_data` = HMAC-Hash(finished_key, transcript_hash) (RFC 8446 §4.4.4).
pub fn finished_verify(suite: Suite, finished_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    match suite {
        Suite::Aes128Sha256 => {
            let mut m = <Hmac<Sha256>>::new_from_slice(finished_key).expect("HMAC accepts any key");
            m.update(transcript_hash);
            m.finalize().into_bytes().to_vec()
        }
        Suite::Aes256Sha384 => {
            let mut m = <Hmac<Sha384>>::new_from_slice(finished_key).expect("HMAC accepts any key");
            m.update(transcript_hash);
            m.finalize().into_bytes().to_vec()
        }
    }
}

fn empty_hash(suite: Suite) -> Vec<u8> {
    transcript_hash(suite, b"")
}

/// Early Secret = HKDF-Extract(0, PSK). With no PSK, IKM and salt are both
/// Hash.length zeros (RFC 5869: an absent salt defaults to zeros).
pub fn early_secret(suite: Suite) -> Vec<u8> {
    let zeros = vec![0u8; suite.hash_len()];
    hkdf_extract(suite, &zeros, &zeros)
}

/// Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), (EC)DHE).
pub fn handshake_secret(suite: Suite, early: &[u8], ecdhe: &[u8]) -> Vec<u8> {
    let derived = derive_secret(suite, early, b"derived", &empty_hash(suite));
    hkdf_extract(suite, &derived, ecdhe)
}

/// Master Secret = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0).
pub fn master_secret(suite: Suite, handshake: &[u8]) -> Vec<u8> {
    let derived = derive_secret(suite, handshake, b"derived", &empty_hash(suite));
    let zeros = vec![0u8; suite.hash_len()];
    hkdf_extract(suite, &derived, &zeros)
}

pub fn client_handshake_traffic_secret(suite: Suite, hs: &[u8], th_ch_sh: &[u8]) -> Vec<u8> {
    derive_secret(suite, hs, b"c hs traffic", th_ch_sh)
}
pub fn server_handshake_traffic_secret(suite: Suite, hs: &[u8], th_ch_sh: &[u8]) -> Vec<u8> {
    derive_secret(suite, hs, b"s hs traffic", th_ch_sh)
}
pub fn client_application_traffic_secret(suite: Suite, ms: &[u8], th_full: &[u8]) -> Vec<u8> {
    derive_secret(suite, ms, b"c ap traffic", th_full)
}
pub fn server_application_traffic_secret(suite: Suite, ms: &[u8], th_full: &[u8]) -> Vec<u8> {
    derive_secret(suite, ms, b"s ap traffic", th_full)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        let h: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
        h.chunks_exact(2)
            .map(|c| {
                let hi = (c[0] as char).to_digit(16).unwrap() as u8;
                let lo = (c[1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// All intermediate values from RFC 8448 §3 "Simple 1-RTT Handshake" — the
    /// SHA-256 path must stay byte-exact after the suite parameterisation.
    #[test]
    fn rfc8448_key_schedule() {
        let s = Suite::Aes128Sha256;
        let early = early_secret(s);
        assert_eq!(
            early,
            hx("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
            "early secret"
        );

        let derived = derive_secret(s, &early, b"derived", &empty_hash(s));
        assert_eq!(
            derived,
            hx("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"),
            "derived (for handshake)"
        );

        let ecdhe = hx("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let hs = handshake_secret(s, &early, &ecdhe);
        assert_eq!(
            hs,
            hx("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"),
            "handshake secret"
        );

        let th = hx("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let c_hs = client_handshake_traffic_secret(s, &hs, &th);
        assert_eq!(
            c_hs,
            hx("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"),
            "client handshake traffic secret"
        );
        let s_hs = server_handshake_traffic_secret(s, &hs, &th);
        assert_eq!(
            s_hs,
            hx("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
            "server handshake traffic secret"
        );

        let ck = traffic_keys(s, &c_hs);
        assert_eq!(
            ck.key,
            hx("dbfaa693d1762c5b666af5d950258d01"),
            "client write_key"
        );
        assert_eq!(ck.iv, hx("5bd3c71b836e0b76bb73265f"), "client write_iv");
        let sk = traffic_keys(s, &s_hs);
        assert_eq!(
            sk.key,
            hx("3fce516009c21727d0f2e4e86ee403bc"),
            "server write_key"
        );
        assert_eq!(sk.iv, hx("5d313eb2671276ee13000b30"), "server write_iv");

        let ms = master_secret(s, &hs);
        assert_eq!(
            ms,
            hx("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"),
            "master secret"
        );
    }

    #[test]
    fn suite_params() {
        assert_eq!(Suite::from_code(0x1301), Some(Suite::Aes128Sha256));
        assert_eq!(Suite::from_code(0x1302), Some(Suite::Aes256Sha384));
        assert_eq!(Suite::from_code(0x1303), None);
        assert_eq!(Suite::Aes128Sha256.hash_len(), 32);
        assert_eq!(Suite::Aes128Sha256.key_len(), 16);
        assert_eq!(Suite::Aes256Sha384.hash_len(), 48);
        assert_eq!(Suite::Aes256Sha384.key_len(), 32);
    }

    /// The SHA-384 path produces hash-length (48-byte) secrets and 32-byte AES
    /// keys, and is internally consistent (derive twice ⇒ same value).
    #[test]
    fn sha384_lengths_and_determinism() {
        let s = Suite::Aes256Sha384;
        let early = early_secret(s);
        assert_eq!(early.len(), 48, "SHA-384 secret is 48 bytes");
        let ecdhe = [0x11u8; 32];
        let hs = handshake_secret(s, &early, &ecdhe);
        assert_eq!(hs.len(), 48);
        let th = transcript_hash(s, b"clienthello-serverhello");
        assert_eq!(th.len(), 48);
        let secret = server_handshake_traffic_secret(s, &hs, &th);
        let keys = traffic_keys(s, &secret);
        assert_eq!(keys.key.len(), 32, "AES-256 key");
        assert_eq!(keys.iv.len(), 12);
        // Deterministic.
        assert_eq!(traffic_keys(s, &secret).key, keys.key);
    }

    #[test]
    fn empty_transcript_is_sha256_of_nothing() {
        assert_eq!(
            empty_hash(Suite::Aes128Sha256),
            hx("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }
}
