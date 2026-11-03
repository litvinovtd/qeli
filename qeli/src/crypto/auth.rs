//! Shared server-authentication handshake logic.
//!
//! Both the TCP and UDP handlers (server side) and both client paths used to
//! open-code the same "build static_pub||proof" / "verify proof" dance. That
//! duplication is centralised here (roadmap A2 / #5) and, in the same move,
//! the proof is now bound to the fake-TLS handshake transcript (roadmap #2 /
//! C2): a man-in-the-middle who swaps the ServerHello, Certificate or Finished
//! changes the transcript hash, so the proof no longer verifies.
//!
//! Wire compatibility note: this is the `v2` proof. A `v2` client cannot
//! authenticate against a `v1` server and vice-versa — both ends must be
//! deployed together.

use crate::crypto::{compute_auth_proof, Keypair, PublicKey, StaticKeypair};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Constant-time equality for authentication proofs / MACs. Avoids a timing
/// side-channel where an attacker could recover a valid proof byte-by-byte by
/// measuring how far a `==`/`!=` comparison ran before diverging.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// SHA-256 over the in-order concatenation of the handshake messages.
///
/// Both peers feed the identical wire bytes (ClientHello, ServerHello,
/// Certificate, Finished), giving a TLS-like transcript binding without a real
/// TLS `Finished`. `read_tls_record` returns whole records, so the bytes the
/// client observes are byte-for-byte the bytes the server produced.
pub fn handshake_transcript_hash(messages: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for m in messages {
        h.update(m);
    }
    h.finalize().into()
}

/// Server side: build the 64-byte auth message `static_public(32) || proof(32)`.
///
/// The proof binds three things: the server's long-lived static key (anti-MITM
/// identity), the per-session ephemeral DH secret (freshness), and the
/// handshake transcript (channel binding).
pub fn build_server_auth_message(
    static_kp: &StaticKeypair,
    client_pub: &PublicKey,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Vec<u8> {
    let static_shared = static_kp.derive_shared(client_pub);
    let proof = compute_auth_proof(&static_shared.0, ephemeral_shared, transcript_hash);
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(static_kp.public.as_bytes());
    msg.extend_from_slice(&proof);
    msg
}

/// Server side, "hide identity" variant: returns ONLY the 32-byte proof, not
/// the static public key. Used when the client is required to have pinned the
/// key (`require_client_key_proof`) — the server then never transmits its static
/// public key, hiding its identity from scanners. The client verifies the proof
/// using its pinned key.
pub fn build_server_proof_only(
    static_kp: &StaticKeypair,
    client_pub: &PublicKey,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> [u8; 32] {
    let static_shared = static_kp.derive_shared(client_pub);
    compute_auth_proof(&static_shared.0, ephemeral_shared, transcript_hash)
}

/// Client side, "hide identity" variant: verify a proof-only server message
/// against the client's PINNED static public key. Returns the pinned key bytes
/// on success. Used when the server did not transmit its static key.
pub fn verify_server_proof_only(
    proof: &[u8],
    client_kp: &Keypair,
    pinned_server_pub: &[u8; 32],
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    if proof.len() < 32 {
        anyhow::bail!("server proof too short");
    }
    let server_pub = PublicKey::from_bytes(pinned_server_pub);
    let static_shared = client_kp
        .derive_shared_checked(&server_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order server identity key"))?;
    let expected = compute_auth_proof(&static_shared.0, ephemeral_shared, transcript_hash);
    if !ct_eq(&proof[..32], &expected[..]) {
        anyhow::bail!("server auth proof verification failed");
    }
    Ok(*pinned_server_pub)
}

/// Client side: verify the server auth message against the transcript the
/// client computed over the same handshake messages it observed.
///
/// On success returns the server's static public key bytes so the caller can
/// pin them. Returns an error if the message is too short or the proof does not
/// match (wrong static key, replayed proof, or a tampered handshake).
pub fn verify_server_auth_message(
    msg: &[u8],
    client_kp: &Keypair,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    if msg.len() < 64 {
        anyhow::bail!("server auth proof too short");
    }
    let mut static_pub = [0u8; 32];
    static_pub.copy_from_slice(&msg[0..32]);
    let received = &msg[32..64];

    let server_static_pub = PublicKey::from_bytes(&static_pub);
    let static_shared = client_kp
        .derive_shared_checked(&server_static_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order server identity key"))?;
    let expected = compute_auth_proof(&static_shared.0, ephemeral_shared, transcript_hash);

    if !ct_eq(received, expected.as_slice()) {
        anyhow::bail!("server auth proof verification failed");
    }
    Ok(static_pub)
}

/// Client→server proof that the *client* already knew the server's static
/// public key (i.e. it has it pinned in config). Bound to the same ephemeral DH
/// and transcript as the server proof but domain-separated. Only a client holding
/// the pinned key can compute it; the server (holding the static private key)
/// verifies it. Lets the server reject clients that have not pinned its key.
pub fn compute_client_key_proof(
    static_shared: &[u8; 32],
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(static_shared), ephemeral_shared);
    let mut info = Vec::with_capacity(24 + 32);
    info.extend_from_slice(b"vpn-client-key-proof-v1");
    info.extend_from_slice(transcript_hash);
    let mut proof = [0u8; 32];
    hk.expand(&info, &mut proof)
        .expect("HKDF expand for client key proof");
    proof
}

/// Parse a 32-byte public key from a hex string (tolerating `:`/`-`/space
/// separators and case). Returns None on malformed input.
pub fn parse_pubkey_hex(s: &str) -> Option<[u8; 32]> {
    let clean: Vec<u8> = s
        .bytes()
        .filter(|b| !matches!(b, b':' | b'-' | b' '))
        .collect();
    // Screen for ASCII hex BEFORE any slicing. The previous version collected into a
    // `String`, so `len()` counted BYTES while the slice `&clean[i*2..i*2+2]` indexed by
    // char boundary: a 64-BYTE string of multi-byte characters (e.g. 21×'€' + 'a') passed
    // the length check and then panicked with "byte index is not a char boundary". That
    // input arrives straight from an untrusted `qeli://` link (`config/client.rs`, the
    // `key=` parameter), and the binary is built with `panic = "abort"` — so importing a
    // hostile QR killed the client process. Operating on bytes plus an explicit
    // is_ascii_hexdigit gate removes the panic entirely. (Audit 2026-07-27, F1.)
    if clean.len() != 64 || !clean.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (clean[i * 2] as char).to_digit(16)?;
        let lo = (clean[i * 2 + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Keypair, StaticKeypair};

    /// Simulate the full handshake at the byte level (no sockets): the client
    /// and server each derive the transcript from the same messages and the
    /// proof must verify. This is the faithful stand-in for an e2e tunnel run.
    fn run_handshake(
        tamper_server_hello: bool,
    ) -> (Keypair, StaticKeypair, [u8; 32], [u8; 32], Vec<u8>) {
        // Ephemeral DH
        let client_kp = Keypair::generate();
        let server_eph = Keypair::generate();
        let server_static = StaticKeypair::generate();

        let client_shared = client_kp.derive_shared(server_eph.public());
        let server_shared = server_eph.derive_shared(client_kp.public());
        assert_eq!(client_shared.0, server_shared.0, "ephemeral DH must agree");

        // Stand-in handshake messages (opaque bytes, like the fake-TLS records)
        let client_hello = b"CLIENT_HELLO_BYTES".to_vec();
        let server_hello = b"SERVER_HELLO_BYTES".to_vec();
        let cert = b"CERTIFICATE_BYTES".to_vec();
        let finished = b"FINISHED_BYTES".to_vec();

        // Server computes its transcript over what it sent/received
        let server_tx =
            handshake_transcript_hash(&[&client_hello, &server_hello, &cert, &finished]);
        let auth_msg = build_server_auth_message(
            &server_static,
            client_kp.public(),
            &server_shared.0,
            &server_tx,
        );

        // Client computes its transcript over what it observed (optionally tampered)
        let observed_sh = if tamper_server_hello {
            b"EVIL_SERVER_HELLO".to_vec()
        } else {
            server_hello.clone()
        };
        let client_tx = handshake_transcript_hash(&[&client_hello, &observed_sh, &cert, &finished]);

        (
            client_kp,
            server_static,
            client_shared.0,
            client_tx,
            auth_msg,
        )
    }

    #[test]
    fn attacker_computable_proofs_for_low_order_identities_are_refused() {
        let client = Keypair::generate();
        let ephemeral = [4; 32];
        let transcript = [5; 32];
        for first in [0u8, 1] {
            let mut public = [0; 32];
            public[0] = first;
            assert_eq!(client.derive_shared(&PublicKey(public)).0, [0; 32]);
            let proof = compute_auth_proof(&[0; 32], &ephemeral, &transcript);
            let mut message = public.to_vec();
            message.extend_from_slice(&proof);
            assert!(
                verify_server_auth_message(&message, &client, &ephemeral, &transcript)
                    .unwrap_err()
                    .to_string()
                    .contains("low-order")
            );
            assert!(
                verify_server_proof_only(&proof, &client, &public, &ephemeral, &transcript)
                    .unwrap_err()
                    .to_string()
                    .contains("low-order")
            );
        }
        let server = StaticKeypair::generate();
        let message = build_server_auth_message(&server, client.public(), &ephemeral, &transcript);
        assert_eq!(
            verify_server_auth_message(&message, &client, &ephemeral, &transcript).unwrap(),
            server.public.0
        );
    }

    #[test]
    fn proof_verifies_on_clean_handshake() {
        let (client_kp, server_static, client_shared, client_tx, auth_msg) = run_handshake(false);
        let pinned = verify_server_auth_message(&auth_msg, &client_kp, &client_shared, &client_tx)
            .expect("clean handshake must verify");
        assert_eq!(
            &pinned,
            server_static.public.as_bytes(),
            "returns server static pub for pinning"
        );
    }

    #[test]
    fn proof_fails_when_server_hello_tampered() {
        // Active MITM swaps the ServerHello: client's transcript diverges → fail
        let (client_kp, _server_static, client_shared, client_tx, auth_msg) = run_handshake(true);
        let res = verify_server_auth_message(&auth_msg, &client_kp, &client_shared, &client_tx);
        assert!(res.is_err(), "tampered handshake must be rejected");
    }

    #[test]
    fn proof_fails_with_wrong_ephemeral() {
        let (client_kp, _server_static, _client_shared, client_tx, auth_msg) = run_handshake(false);
        let wrong_shared = [0x11u8; 32];
        assert!(
            verify_server_auth_message(&auth_msg, &client_kp, &wrong_shared, &client_tx).is_err()
        );
    }

    #[test]
    fn proof_fails_when_too_short() {
        let client_kp = Keypair::generate();
        assert!(
            verify_server_auth_message(&[0u8; 40], &client_kp, &[0u8; 32], &[0u8; 32]).is_err()
        );
    }

    #[test]
    fn ct_eq_matches_plain_equality() {
        assert!(ct_eq(b"abcdef", b"abcdef"));
        assert!(!ct_eq(b"abcdef", b"abcdeg"));
        assert!(!ct_eq(b"abc", b"abcd")); // differing lengths
        assert!(ct_eq(&[], &[]));
        assert!(!ct_eq(&[0u8; 32], &[1u8; 32]));
    }

    #[test]
    fn transcript_is_order_sensitive() {
        let a = handshake_transcript_hash(&[b"AAA", b"BBB"]);
        let b = handshake_transcript_hash(&[b"BBB", b"AAA"]);
        assert_ne!(a, b, "transcript must depend on message order");
    }

    #[test]
    fn client_key_proof_matches_only_with_correct_key() {
        let client_kp = Keypair::generate();
        let server_static = StaticKeypair::generate();
        let server_eph = Keypair::generate();
        let eph = client_kp.derive_shared(server_eph.public()).0;
        let tr = handshake_transcript_hash(&[b"ch", b"sh"]);

        // client computes proof from the (pinned) server static public key
        let cs_client = client_kp.derive_shared(&server_static.public).0;
        let proof = compute_client_key_proof(&cs_client, &eph, &tr);
        // server computes from its static private key + client ephemeral public
        let cs_server = server_static.derive_shared(client_kp.public()).0;
        let expected = compute_client_key_proof(&cs_server, &eph, &tr);
        assert_eq!(proof, expected, "client and server must agree");

        // a client that does NOT know the real server key cannot match
        let wrong = StaticKeypair::generate();
        let cs_wrong = client_kp.derive_shared(&wrong.public).0;
        assert_ne!(compute_client_key_proof(&cs_wrong, &eph, &tr), expected);
    }

    #[test]
    fn parse_pubkey_hex_works() {
        let kp = StaticKeypair::generate();
        let hex: String = kp
            .public
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(parse_pubkey_hex(&hex), Some(*kp.public.as_bytes()));
        assert_eq!(parse_pubkey_hex("deadbeef"), None); // wrong length
        assert_eq!(parse_pubkey_hex("zz"), None);
    }

    /// A 64-BYTE string that is not 64 CHARACTERS must be rejected, not panic.
    ///
    /// The length gate counts bytes, so multi-byte input can satisfy it while the
    /// per-pair slice lands inside a character — which used to abort the process
    /// (`panic = "abort"`). The value reaches here straight from an untrusted
    /// `qeli://` link, so this is a remote kill switch, not a theoretical edge.
    /// (Audit 2026-07-27, F1.)
    #[test]
    fn parse_pubkey_hex_rejects_non_ascii_without_panicking() {
        // 21 × '€' (3 bytes each) + 'a' = 64 bytes, 22 characters.
        let s = "€".repeat(21) + "a";
        assert_eq!(s.len(), 64, "fixture must hit the byte-length gate");
        assert!(s.chars().count() != 64);
        assert_eq!(parse_pubkey_hex(&s), None);

        // Same shape, but the multi-byte character sits at the very end.
        let s2 = "a".repeat(61) + "€";
        assert_eq!(s2.len(), 64);
        assert_eq!(parse_pubkey_hex(&s2), None);

        // Separators are still tolerated, and a non-hex ASCII byte still fails.
        let kp = StaticKeypair::generate();
        let hex: String = kp
            .public
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let spaced: String = hex
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse_pubkey_hex(&spaced), Some(*kp.public.as_bytes()));
        assert_eq!(parse_pubkey_hex(&("g".to_string() + &hex[1..])), None);
    }
}
