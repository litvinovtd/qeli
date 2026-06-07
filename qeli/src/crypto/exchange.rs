use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroize;

/// Constant-time test for a degenerate all-zero X25519 shared secret. Such a
/// result means the peer supplied a low-order / identity public key (RFC 7748
/// §6.1) and the "shared" secret is attacker-known — the handshake must abort.
fn is_all_zero(bytes: &[u8; 32]) -> bool {
    bytes[..].ct_eq(&[0u8; 32][..]).into()
}

pub struct Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

#[derive(Clone)]
pub struct PublicKey(pub [u8; 32]);

pub struct SharedSecret(pub [u8; 32]);

impl Keypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = XPublic::from(&secret);
        Keypair {
            secret,
            public: PublicKey(public.to_bytes()),
        }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn derive_shared(&self, peer_public: &PublicKey) -> SharedSecret {
        let peer = XPublic::from(peer_public.0);
        let shared = self.secret.diffie_hellman(&peer);
        SharedSecret(shared.to_bytes())
    }

    /// Like [`derive_shared`] but rejects a degenerate all-zero shared secret —
    /// the result of a peer sending a low-order/identity public key. Returns
    /// `None` so the caller aborts rather than proceeding with a key an active
    /// attacker can predict (contributory-behaviour check, RFC 7748 §6.1).
    pub fn derive_shared_checked(&self, peer_public: &PublicKey) -> Option<SharedSecret> {
        let ss = self.derive_shared(peer_public);
        if is_all_zero(&ss.0) {
            None
        } else {
            Some(ss)
        }
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        PublicKey(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl SharedSecret {
    #[allow(dead_code)] // raw-secret accessor kept for API completeness
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// ── Static identity key pair (long-lived, for server authentication) ──────────

pub struct StaticKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl StaticKeypair {
    /// Generate a new random static key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey(XPublic::from(&secret).to_bytes());
        StaticKeypair { secret, public }
    }

    /// Restore from 32 raw private-key bytes (loaded from disk).
    pub fn from_private_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey(XPublic::from(&secret).to_bytes());
        StaticKeypair { secret, public }
    }

    /// Export the raw private-key bytes for persistence. Wrapped in `Zeroizing`
    /// so the caller's transient copy is wiped from the stack after use rather
    /// than lingering (the in-struct secret is already zeroized on Drop).
    pub fn private_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.secret.to_bytes())
    }

    /// X25519(static_private, peer_ephemeral_public) → shared secret
    pub fn derive_shared(&self, peer: &PublicKey) -> SharedSecret {
        let peer_pub = XPublic::from(peer.0);
        SharedSecret(self.secret.diffie_hellman(&peer_pub).to_bytes())
    }
}

impl Drop for StaticKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// HKDF-SHA256 proof that the holder of `static_keypair` produced this session.
///
/// proof = HKDF-Expand(PRK, info="vpn-server-auth-proof-v2" || transcript_hash, len=32)
/// PRK   = HMAC-SHA256(salt=static_shared, ikm=ephemeral_shared)
///
/// Both parties can compute `static_shared` only if they know the static private key
/// (server) or the static public key + their own ephemeral private key (client).
///
/// `transcript_hash` binds the proof to the fake-TLS handshake: any modification
/// of ClientHello/ServerHello/Certificate/Finished in flight changes the hash and
/// breaks verification (channel binding). The `v2` info string is a wire-format
/// break from the unbound `v1` proof.
pub fn compute_auth_proof(
    static_shared: &[u8; 32],
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(static_shared), ephemeral_shared);
    let mut info = Vec::with_capacity(24 + 32);
    info.extend_from_slice(b"vpn-server-auth-proof-v2");
    info.extend_from_slice(transcript_hash);
    let mut proof = [0u8; 32];
    hk.expand(&info, &mut proof)
        .expect("HKDF expand for auth proof");
    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_shared_checked_rejects_low_order_point() {
        let kp = Keypair::generate();
        // The all-zero public key is a low-order point → all-zero shared secret.
        let zero_pub = PublicKey([0u8; 32]);
        assert!(
            kp.derive_shared_checked(&zero_pub).is_none(),
            "low-order/identity peer key must be rejected"
        );
    }

    #[test]
    fn derive_shared_checked_accepts_normal_exchange() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let sa = a
            .derive_shared_checked(b.public())
            .expect("normal exchange ok");
        let sb = b
            .derive_shared_checked(a.public())
            .expect("normal exchange ok");
        assert_eq!(sa.0, sb.0, "both sides agree on the shared secret");
    }
}
