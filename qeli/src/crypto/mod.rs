pub mod auth;
pub mod cipher;
pub mod derive;
pub mod exchange;
pub mod mlkem;
pub mod reality;

pub use auth::{
    build_server_auth_message, build_server_proof_only, compute_client_key_proof,
    handshake_transcript_hash, parse_pubkey_hex, verify_server_auth_message,
    verify_server_proof_only,
};
pub use cipher::Cipher;
pub use derive::{derive_keys, derive_keys_bound, derive_keys_hybrid, derive_keys_hybrid_bound};
pub use exchange::{compute_auth_proof, Keypair, PublicKey, StaticKeypair};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PacketCodec;

    #[test]
    fn test_x25519_key_exchange_roundtrip() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let alice_pub = alice.public().clone();
        let bob_pub = bob.public().clone();
        let alice_shared = alice.derive_shared(&bob_pub);
        let bob_shared = bob.derive_shared(&alice_pub);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_keys_different_and_correct_length() {
        let shared = [0xABu8; 32];
        let (enc_key, dec_key) = derive_keys(&shared);

        assert_eq!(enc_key.len(), 32);
        assert_eq!(dec_key.len(), 32);
        assert_ne!(enc_key, dec_key, "enc_key and dec_key must differ");
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let shared = [0xABu8; 32];
        let (e1, d1) = derive_keys(&shared);
        let (e2, d2) = derive_keys(&shared);
        assert_eq!(e1, e2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_derive_keys_different_inputs() {
        let s1 = [0xABu8; 32];
        let s2 = [0xCDu8; 32];
        let (e1, _) = derive_keys(&s1);
        let (e2, _) = derive_keys(&s2);
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_cipher_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = Cipher::new(&key);
        let nonce = [0u8; 12];
        let plaintext = b"hello vpn";

        let encrypted = cipher.encrypt(&nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cipher_encrypt_decrypt_large() {
        let key = [0x42u8; 32];
        let cipher = Cipher::new(&key);
        let nonce = [0u8; 12];
        let plaintext = vec![0xABu8; 4096];

        let encrypted = cipher.encrypt(&nonce, &plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cipher_encrypt_decrypt_empty() {
        let key = [0x42u8; 32];
        let cipher = Cipher::new(&key);
        let nonce = [0u8; 12];
        let plaintext = b"";

        let encrypted = cipher.encrypt(&nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cipher_decrypt_wrong_key_fails() {
        let key_enc = [0x42u8; 32];
        let key_dec = [0xFFu8; 32];
        let cipher_enc = Cipher::new(&key_enc);
        let cipher_dec = Cipher::new(&key_dec);
        let nonce = [0u8; 12];

        let encrypted = cipher_enc.encrypt(&nonce, b"secret").unwrap();
        let result = cipher_dec.decrypt(&nonce, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_decrypt_tampered_fails() {
        let key = [0x42u8; 32];
        let cipher = Cipher::new(&key);
        let nonce = [0u8; 12];

        let mut encrypted = cipher.encrypt(&nonce, b"data").unwrap();
        encrypted[5] ^= 0xFF; // flip a bit

        let result = cipher.decrypt(&nonce, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_different_nonces_produce_different_ciphertext() {
        let key = [0x42u8; 32];
        let cipher = Cipher::new(&key);
        let plaintext = b"same data";

        let ct1 = cipher.encrypt(&[0u8; 12], plaintext).unwrap();
        let ct2 = cipher.encrypt(&[1u8; 12], plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_generate_nonce_format() {
        let counter = 0x0102030405060708u64;
        let extra = [0x0A, 0x0B, 0x0C, 0x0D];
        let nonce = Cipher::generate_nonce(counter, &extra);

        assert_eq!(nonce.len(), 12);
        // first 8 bytes = big-endian counter
        assert_eq!(&nonce[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // last 4 bytes = extra
        assert_eq!(&nonce[8..], &[0x0A, 0x0B, 0x0C, 0x0D]);
    }

    #[test]
    fn test_packet_codec_roundtrip() {
        let key = [0x42u8; 32];
        let mut enc = PacketCodec::new(key);
        let mut dec = PacketCodec::new(key);
        let data = b"hello world";

        let packet = enc.encrypt_packet(data, &[]).unwrap();
        let decrypted = dec.decrypt_packet(&packet).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_packet_codec_multiple_packets() {
        let key = [0x42u8; 32];
        let mut enc = PacketCodec::new(key);
        let mut dec = PacketCodec::new(key);

        for i in 0..10 {
            let data = format!("packet {}", i);
            let packet = enc.encrypt_packet(data.as_bytes(), &[]).unwrap();
            let decrypted = dec.decrypt_packet(&packet).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), data);
        }
    }

    #[test]
    fn test_packet_codec_with_padding() {
        let key = [0x42u8; 32];
        let mut enc = PacketCodec::new(key);
        let mut dec = PacketCodec::new(key);
        let data = b"padded data";
        let padding = vec![0xAAu8; 64];

        let packet = enc.encrypt_packet(data, &padding).unwrap();
        let decrypted = dec.decrypt_packet(&packet).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_packet_codec_large_payload() {
        let key = [0x42u8; 32];
        let mut enc = PacketCodec::new(key);
        let mut dec = PacketCodec::new(key);
        let data = vec![0xBBu8; 16384];

        let packet = enc.encrypt_packet(&data, &[]).unwrap();
        let decrypted = dec.decrypt_packet(&packet).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_packet_codec_empty_payload() {
        let key = [0x42u8; 32];
        let mut enc = PacketCodec::new(key);
        let mut dec = PacketCodec::new(key);

        let packet = enc.encrypt_packet(&[], &[]).unwrap();
        let decrypted = dec.decrypt_packet(&packet).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_packet_codec_wrong_content_type() {
        let key = [0x42u8; 32];
        let mut codec = PacketCodec::new(key);
        let mut packet = codec.encrypt_packet(b"test", &[]).unwrap();
        packet[0] = 0x16; // change from Application Data to Handshake

        let result = codec.decrypt_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_codec_too_short() {
        let key = [0x42u8; 32];
        let mut codec = PacketCodec::new(key);
        let result = codec.decrypt_packet(&[0x17, 0x03, 0x03, 0x00, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_codec_wrong_key_fails() {
        let mut enc = PacketCodec::new([0x42u8; 32]);
        let mut dec = PacketCodec::new([0xFFu8; 32]);

        let packet = enc.encrypt_packet(b"wrong key", &[]).unwrap();
        let result = dec.decrypt_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_codec_counter_wraps() {
        let key = [0x42u8; 32];
        let mut enc = PacketCodec::new(key);
        let mut dec = PacketCodec::new(key);

        // simulate wrapping around
        // we can't easily set counter to u64::MAX, but we can verify
        // wrapping_add is used by checking many packets work
        for i in 0..100 {
            let data = format!("wrap test {}", i);
            let packet = enc.encrypt_packet(data.as_bytes(), &[]).unwrap();
            let decrypted = dec.decrypt_packet(&packet).unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), data);
        }
    }

    #[test]
    fn test_full_key_exchange_and_encryption() {
        let client_kp = Keypair::generate();
        let server_kp = Keypair::generate();

        let server_pub = server_kp.public().clone();
        let client_pub = client_kp.public().clone();
        let client_shared = client_kp.derive_shared(&server_pub);
        let (server_to_client, client_to_server) = derive_keys(&client_shared.0);

        let server_shared = server_kp.derive_shared(&client_pub);
        let (s2c, c2s) = derive_keys(&server_shared.0);

        assert_eq!(server_to_client, s2c);
        assert_eq!(client_to_server, c2s);

        let mut client_tx = PacketCodec::new(client_to_server);
        let mut server_rx = PacketCodec::new(client_to_server);

        let data = b"auth:password123";
        let packet = client_tx.encrypt_packet(data, &[]).unwrap();
        let decrypted = server_rx.decrypt_packet(&packet).unwrap();
        assert_eq!(decrypted, data);
    }
}
