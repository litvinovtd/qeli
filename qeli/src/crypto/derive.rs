use hkdf::Hkdf;
use sha2::Sha256;

const SALT: &[u8] = b"qeli-key-derivation-v1";

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
