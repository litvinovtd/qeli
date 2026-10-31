//! INNER_PQ_V1, exclusively inside the established REALITY TLS/H2 carrier.
//!
//! Client: zero X25519 sentinel(32), header(32), X25519(32), ML-KEM ek(1184).
//! Server: header(32), X25519(32), ML-KEM ciphertext(1088).
//! Headers strictly fix role/version/group/required-PQ+static-binding/length;
//! reserved bytes must be zero. There is NO algorithm/version negotiation or
//! classic fallback. The sentinel is not an admissible legacy X25519 key.
//! Subsequent existing AEAD server identity proof confirms the hybrid keys and
//! complete transcript BEFORE the client sends AUTH, JOIN or resume credentials.
//! This protects confidentiality against harvest-now/decrypt-later, not PQ
//! identity signatures; pinned server authentication remains classical X25519.

use crate::crypto::mlkem::{self, MLKEM768_CT_LEN, MLKEM768_EK_LEN};
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
use crate::crypto::StaticKeypair;
use crate::crypto::{Keypair, PublicKey, SessionKeyMaterial};
use crate::protocol::stream_io::WriteAllFlush;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

pub(crate) const SENTINEL: [u8; 32] = [0; 32];
pub(crate) const CLIENT_LEN: usize = 32 + 32 + 32 + MLKEM768_EK_LEN;
pub(crate) const SERVER_LEN: usize = 32 + 32 + MLKEM768_CT_LEN;
const TRANSCRIPT_DOMAIN: &[u8] = b"qeli-reality-inner-pq-v1 transcript\0";

fn header(server: bool) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(if server { b"QELIPQ\0S" } else { b"QELIPQ\0C" });
    h[8..10].copy_from_slice(&1u16.to_be_bytes());
    h[10..12].copy_from_slice(&mlkem::X25519MLKEM768.to_be_bytes());
    h[12..14].copy_from_slice(&3u16.to_be_bytes()); // PQ required + static bound
    let length = 32
        + if server {
            MLKEM768_CT_LEN
        } else {
            MLKEM768_EK_LEN
        };
    h[14..16].copy_from_slice(&(length as u16).to_be_bytes());
    h
}

fn check_header(received: &[u8; 32], server: bool) -> anyhow::Result<()> {
    anyhow::ensure!(*received == header(server),
        "REALITY compact requires INNER_PQ_V1: unsupported or altered {} header; no classical fallback",
        if server { "server" } else { "client" });
    Ok(())
}

fn transcript(client: &[u8], server: &[u8], identity: &[u8; 32]) -> [u8; 32] {
    crate::crypto::handshake_transcript_hash(&[TRANSCRIPT_DOMAIN, client, server, identity])
}

pub(crate) struct Exchange {
    #[cfg_attr(not(all(target_os = "linux", feature = "server")), allow(dead_code))]
    pub peer_public: PublicKey,
    pub ephemeral_shared: zeroize::Zeroizing<[u8; 32]>,
    pub transcript_hash: [u8; 32],
    pub material: SessionKeyMaterial,
}

/// Requires an explicit pin. Returns keys, not trust: the caller must decrypt
/// and verify the existing server identity proof before sending ANY credentials.
pub(crate) async fn client_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    client: &Keypair,
    pinned: &[u8; 32],
) -> anyhow::Result<Exchange> {
    let static_shared = client
        .derive_shared_checked(&PublicKey::from_bytes(pinned))
        .ok_or_else(|| anyhow::anyhow!("INNER_PQ_V1 rejected low-order pinned server key"))?;
    let (dk, ek) = mlkem::mlkem768_keypair();
    let mut hello = Vec::with_capacity(CLIENT_LEN);
    hello.extend_from_slice(&SENTINEL);
    hello.extend_from_slice(&header(false));
    hello.extend_from_slice(client.public().as_bytes());
    hello.extend_from_slice(&ek);
    stream.write_all_flush(&hello).await?;
    let mut received_header = [0u8; 32];
    stream.read_exact(&mut received_header).await.map_err(|e| {
        anyhow::anyhow!(
            "INNER_PQ_V1 server response: {e}; update the server, no classical fallback"
        )
    })?;
    check_header(&received_header, true)?;
    // Fixed bounds: never allocate based on an untrusted length field.
    let mut response = vec![0u8; SERVER_LEN];
    response[..32].copy_from_slice(&received_header);
    stream.read_exact(&mut response[32..]).await?;
    let public = PublicKey::from_bytes(response[32..64].try_into()?);
    let shared = client
        .derive_shared_checked(&public)
        .ok_or_else(|| anyhow::anyhow!("INNER_PQ_V1 rejected low-order server share"))?;
    let ml = zeroize::Zeroizing::new(
        mlkem::mlkem768_decapsulate(&dk, &response[64..])
            .ok_or_else(|| anyhow::anyhow!("INNER_PQ_V1 invalid ML-KEM ciphertext"))?,
    );
    let hash = transcript(&hello, &response, pinned);
    let material = crate::crypto::derive::derive_reality_inner_pq_material(
        &shared.0,
        ml.as_slice().try_into()?,
        &static_shared.0,
        &hash,
    );
    Ok(Exchange {
        peer_public: public,
        ephemeral_shared: zeroize::Zeroizing::new(shared.0),
        transcript_hash: hash,
        material,
    })
}

/// Call ONLY after the outer TLS discriminator succeeded and the exact sentinel
/// was consumed. Malformed PQ requests must never re-enter the legacy parser.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
pub(crate) async fn server_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server: &Keypair,
    identity: &StaticKeypair,
) -> anyhow::Result<Exchange> {
    let mut received_header = [0u8; 32];
    stream.read_exact(&mut received_header).await?;
    check_header(&received_header, false)?;
    let mut hello = vec![0u8; CLIENT_LEN];
    hello[..32].copy_from_slice(&SENTINEL);
    hello[32..64].copy_from_slice(&received_header);
    stream.read_exact(&mut hello[64..]).await?;
    let public = PublicKey::from_bytes(hello[64..96].try_into()?);
    let shared = server
        .derive_shared_checked(&public)
        .ok_or_else(|| anyhow::anyhow!("INNER_PQ_V1 rejected low-order client share"))?;
    let static_shared = identity
        .derive_shared_checked(&public)
        .ok_or_else(|| anyhow::anyhow!("INNER_PQ_V1 rejected low-order identity binding"))?;
    let (ct, ml) = mlkem::mlkem768_encapsulate(&hello[96..])
        .ok_or_else(|| anyhow::anyhow!("INNER_PQ_V1 invalid ML-KEM encapsulation key"))?;
    let ml = zeroize::Zeroizing::new(ml);
    let mut response = Vec::with_capacity(SERVER_LEN);
    response.extend_from_slice(&header(true));
    response.extend_from_slice(server.public().as_bytes());
    response.extend_from_slice(&ct);
    let hash = transcript(&hello, &response, identity.public.as_bytes());
    let material = crate::crypto::derive::derive_reality_inner_pq_material(
        &shared.0,
        ml.as_slice().try_into()?,
        &static_shared.0,
        &hash,
    );
    stream.write_all_flush(&response).await?;
    Ok(Exchange {
        peer_public: public,
        ephemeral_shared: zeroize::Zeroizing::new(shared.0),
        transcript_hash: hash,
        material,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn strict_version_policy_lengths_and_kdf_known_answers() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../conformance/inner-pq-v1.json")).unwrap();
        assert_eq!(hex(&header(false)), vectors["client_header"]);
        assert_eq!(hex(&header(true)), vectors["server_header"]);
        assert_eq!(CLIENT_LEN, 1280);
        assert_eq!(SERVER_LEN, 1152);
        for server in [false, true] {
            check_header(&header(server), server).unwrap();
            for byte in 0..32 {
                let mut changed = header(server);
                changed[byte] ^= 1;
                assert!(
                    check_header(&changed, server).is_err(),
                    "changed header byte {byte}"
                );
            }
            assert!(check_header(&header(!server), server).is_err());
        }
        let ee = std::array::from_fn(|i| i as u8);
        let ml = std::array::from_fn(|i| (i + 32) as u8);
        let es = std::array::from_fn(|i| (i + 64) as u8);
        let th = crate::crypto::handshake_transcript_hash(&[b"INNER_PQ_V1 KAT transcript"]);
        assert_eq!(hex(&th), vectors["transcript"]);
        let derive = crate::crypto::derive::derive_reality_inner_pq_material;
        let material = derive(&ee, &ml, &es, &th);
        let keys = material.data_keys();
        assert_eq!(hex(&keys.0), vectors["s2c"]);
        assert_eq!(hex(&keys.1), vectors["c2s"]);
        assert_eq!(hex(material.resume_secret()), vectors["resume"]);
        assert_ne!(keys, crate::crypto::derive_keys_hybrid_bound(&ee, &ml, &es));
        for field in 0..4 {
            let mut inputs = [ee, ml, es, th];
            inputs[field][0] ^= 1;
            let other = derive(&inputs[0], &inputs[1], &inputs[2], &inputs[3]);
            assert_ne!(keys, other.data_keys());
            assert_ne!(material.resume_secret(), other.resume_secret());
        }
    }

    #[tokio::test]
    async fn hybrid_exchange_agrees_on_data_and_resume_keys() {
        let identity = StaticKeypair::generate();
        let pinned = *identity.public.as_bytes();
        let (mut client_io, mut server_io) = tokio::io::duplex(1); // arbitrary fragmentation
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 32];
            server_io.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix, SENTINEL);
            server_exchange(&mut server_io, &Keypair::generate(), &identity)
                .await
                .unwrap()
        });
        let client = client_exchange(&mut client_io, &Keypair::generate(), &pinned)
            .await
            .unwrap();
        let server = server.await.unwrap();
        assert_eq!(client.transcript_hash, server.transcript_hash);
        assert_eq!(*client.ephemeral_shared, *server.ephemeral_shared);
        assert_eq!(client.material.data_keys(), server.material.data_keys());
        assert_eq!(
            client.material.resume_secret(),
            server.material.resume_secret()
        );
    }

    #[tokio::test]
    async fn malformed_request_and_low_order_client_are_rejected_without_reply() {
        use tokio::io::AsyncWriteExt;
        for attack in ["version", "low-order", "bad-ek"] {
            let (mut peer, mut server_io) = tokio::io::duplex(4096);
            let mut request = header(false).to_vec();
            if attack == "version" {
                request[8] ^= 1;
            } // unsupported version
            let client = Keypair::generate();
            request.extend_from_slice(if attack == "bad-ek" {
                client.public().as_bytes()
            } else {
                &[0u8; 32]
            });
            request.extend_from_slice(&vec![0xffu8; MLKEM768_EK_LEN]); // noncanonical ML-KEM coefficients
            peer.write_all(&request).await.unwrap();
            peer.shutdown().await.unwrap();
            assert!(server_exchange(
                &mut server_io,
                &Keypair::generate(),
                &StaticKeypair::generate()
            )
            .await
            .is_err());
            drop(server_io);
            let mut reply = Vec::new();
            peer.read_to_end(&mut reply).await.unwrap();
            assert!(reply.is_empty());
        }
    }

    #[tokio::test]
    async fn client_rejects_missing_or_low_order_pin_before_sending_anything() {
        let mut memory = MemoryPeer::default();
        assert!(client_exchange(&mut memory, &Keypair::generate(), &[0; 32])
            .await
            .is_err());
        assert!(memory.output.is_empty());
        let mut c = config(&[7; 32]);
        c.auth.server_public_key = None;
        assert!(crate::transport_core::session::raw_client_keys(
            &mut memory,
            &c,
            &Keypair::generate()
        )
        .await
        .is_err());
        assert!(memory.output.is_empty());
    }

    #[test]
    fn transcript_binds_roles_version_shares_ciphertext_and_identity() {
        let client = vec![1u8; CLIENT_LEN];
        let server = vec![2u8; SERVER_LEN];
        let identity = [3u8; 32];
        let expected = transcript(&client, &server, &identity);
        for offset in [0, 32, 40, 44, 64, 96, CLIENT_LEN - 1] {
            let mut modified = client.clone();
            modified[offset] ^= 1;
            assert_ne!(transcript(&modified, &server, &identity), expected);
        }
        for offset in [0, 8, 12, 32, 64, SERVER_LEN - 1] {
            let mut modified = server.clone();
            modified[offset] ^= 1;
            assert_ne!(transcript(&client, &modified, &identity), expected);
        }
        assert_ne!(transcript(&client, &server, &[4u8; 32]), expected);
        assert_ne!(transcript(&server, &client, &identity), expected);
    }

    #[derive(Default)]
    struct MemoryPeer {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl AsyncRead for MemoryPeer {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let pos = self.input.position() as usize;
            let count = buf.remaining().min(self.input.get_ref().len() - pos);
            buf.put_slice(&self.input.get_ref()[pos..pos + count]);
            self.input.set_position((pos + count) as u64);
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for MemoryPeer {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.output.extend_from_slice(data);
            std::task::Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn config(pinned: &[u8; 32]) -> crate::config::client::ClientConfig {
        let mut c = crate::config::client::ClientConfig::default();
        c.obfuscation.mode = "reality-tls".into();
        c.obfuscation.reality_compact = true;
        c.obfuscation.reality_short_id = Some("0123456789abcdef".into());
        c.obfuscation.sni = Some("decoy.example".into());
        c.auth.server_public_key = Some(hex(pinned));
        c.auth.username = "must-remain-private".into();
        c.roaming = crate::config::client::ClientRoamingPolicy::Off;
        c
    }

    /// Real server exchange + existing identity proof and packet AEAD, with an
    /// optional active attacker mutating the bytes BEFORE the client sees them.
    async fn scripted_peer<S: AsyncRead + AsyncWrite + Unpin>(
        io: &mut S,
        identity: StaticKeypair,
        attack: &'static str,
        hidden: bool,
    ) -> Option<[u8; 32]> {
        let mut hello = vec![0u8; CLIENT_LEN];
        io.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello[..32], &SENTINEL);
        assert_eq!(&hello[32..64], &header(false));
        let mut memory = MemoryPeer {
            input: std::io::Cursor::new(hello[32..].to_vec()),
            ..Default::default()
        };
        let exchange = server_exchange(&mut memory, &Keypair::generate(), &identity)
            .await
            .unwrap();
        let (s2c, c2s) = if attack == "classic-kdf" {
            let es = identity.derive_shared(&exchange.peer_public);
            crate::crypto::derive_keys_bound(&exchange.ephemeral_shared, &es.0)
        } else {
            exchange.material.data_keys()
        };
        let mut tx = crate::protocol::PacketCodec::new_raw(s2c);
        let mut rx = crate::protocol::PacketCodec::new_raw(c2s);
        match attack {
            "legacy" => memory.output = Keypair::generate().public().as_bytes().to_vec(),
            "version" => memory.output[8] ^= 1,
            "algorithm" => memory.output[10] ^= 1,
            "policy" => memory.output[12] ^= 1,
            "length" => memory.output[14] ^= 1,
            "reserved" => memory.output[31] = 1,
            "low-order" => memory.output[32..64].fill(0),
            "ciphertext" => memory.output[64] ^= 1,
            _ => {}
        }
        io.write_all_flush(&memory.output).await.unwrap();
        if attack != "legacy" {
            let mut proof = if hidden {
                crate::crypto::build_server_proof_only(
                    &identity,
                    &exchange.peer_public,
                    &exchange.ephemeral_shared,
                    &exchange.transcript_hash,
                )
                .to_vec()
            } else {
                crate::crypto::build_server_auth_message(
                    &identity,
                    &exchange.peer_public,
                    &exchange.ephemeral_shared,
                    &exchange.transcript_hash,
                )
            };
            if attack == "proof" {
                let last = proof.len() - 1;
                proof[last] ^= 1;
            }
            io.write_all_flush(&tx.encrypt_packet(&proof, &[]).unwrap())
                .await
                .unwrap();
        }
        if attack != "ok" {
            let mut following = Vec::new();
            io.read_to_end(&mut following).await.unwrap();
            assert!(
                following.is_empty(),
                "credentials or classic retry after {attack}"
            );
            return None;
        }
        let record = crate::protocol::read_record(io, crate::protocol::Framing::Raw)
            .await
            .unwrap();
        let auth = rx.decrypt_packet(&record).unwrap();
        assert!(auth.ends_with(b"must-remain-private:secret-password"));
        let static_shared = identity.derive_shared(&exchange.peer_public);
        let expected = crate::crypto::compute_client_key_proof(
            &static_shared.0,
            &exchange.ephemeral_shared,
            &exchange.transcript_hash,
        );
        assert_eq!(&auth[..32], &expected);
        io.write_all_flush(
            &tx.encrypt_packet(
                br#"OK:{"client_ip":"10.9.0.2","server_ip":"10.9.0.1","mtu":1280}"#,
                &[],
            )
            .unwrap(),
        )
        .await
        .unwrap();
        io.write_all_flush(&tx.encrypt_packet(b"server-data", &[]).unwrap())
            .await
            .unwrap();
        let record = crate::protocol::read_record(io, crate::protocol::Framing::Raw)
            .await
            .unwrap();
        assert_eq!(rx.decrypt_packet(&record).unwrap(), b"client-data");
        Some(*exchange.material.resume_secret())
    }

    async fn authenticated_client<S: AsyncRead + AsyncWrite + Unpin>(
        io: &mut S,
        c: &crate::config::client::ClientConfig,
        reject_trust: bool,
    ) -> anyhow::Result<crate::transport_core::session::TcpAuthentication> {
        crate::transport_core::session::authenticate_tcp(
            io,
            c,
            "secret-password",
            &[7; crate::protocol::DEVICE_ID_LEN],
            0,
            move |_| async move {
                anyhow::ensure!(!reject_trust, "fixture trust rejection");
                Ok(())
            },
        )
        .await
    }

    async fn data_roundtrip<S: AsyncRead + AsyncWrite + Unpin>(
        io: &mut S,
        auth: &mut crate::transport_core::session::TcpAuthentication,
    ) {
        let record = crate::protocol::read_record(io, crate::protocol::Framing::Raw)
            .await
            .unwrap();
        assert_eq!(
            auth.client_rx.decrypt_packet(&record).unwrap(),
            b"server-data"
        );
        io.write_all_flush(&auth.client_tx.encrypt_packet(b"client-data", &[]).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn compact_pq_confirms_identity_before_auth_and_protects_data_and_resume() {
        for hidden in [false, true] {
            for bind_static in [false, true] {
                let identity = StaticKeypair::generate();
                let mut c = config(identity.public.as_bytes());
                c.auth.bind_static_to_session = bind_static; // v1 always binds identity
                let (mut client_io, mut server_io) = tokio::io::duplex(32 * 1024);
                let server = tokio::spawn(async move {
                    scripted_peer(&mut server_io, identity, "ok", hidden).await
                });
                let mut auth = authenticated_client(&mut client_io, &c, false)
                    .await
                    .unwrap();
                data_roundtrip(&mut client_io, &mut auth).await;
                let resume = server.await.unwrap().unwrap();
                #[cfg(feature = "experimental-roaming")]
                assert_eq!(*auth.resume_secret, resume);
                #[cfg(not(feature = "experimental-roaming"))]
                let _ = resume;
            }
        }
    }

    #[tokio::test]
    async fn compact_pq_never_sends_auth_or_retries_classic_after_failed_admission() {
        for attack in [
            "legacy",
            "version",
            "algorithm",
            "policy",
            "length",
            "reserved",
            "low-order",
            "ciphertext",
            "classic-kdf",
            "proof",
            "wrong-pin",
            "trust",
        ] {
            let identity = StaticKeypair::generate();
            let mut c = config(identity.public.as_bytes());
            if attack == "wrong-pin" {
                c.auth.server_public_key = Some(hex(StaticKeypair::generate().public.as_bytes()));
            }
            let (mut client_io, mut server_io) = tokio::io::duplex(32 * 1024);
            let server = tokio::spawn(async move {
                scripted_peer(&mut server_io, identity, attack, false).await
            });
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                authenticated_client(&mut client_io, &c, attack == "trust"),
            )
            .await
            .unwrap();
            assert!(result.is_err(), "admitted {attack}");
            drop(client_io);
            assert!(server.await.unwrap().is_none());
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn compact_pq_auth_and_data_traverse_genuine_classic_tls_and_http2() {
        let identity = StaticKeypair::generate();
        let c = config(identity.public.as_bytes());
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let tls = crate::protocol::realtls::server::terminate_handrolled(
                server_io,
                Keypair::generate(),
                crate::protocol::realtls::server::BorrowProfile {
                    suite: crate::protocol::realtls::keyschedule::Suite::Aes128Sha256,
                    prefer_pq: true,
                    key_share_first: false,
                },
                None,
            )
            .await
            .unwrap();
            let mut carrier = crate::protocol::h2_carrier::accept(tls).await.unwrap();
            scripted_peer(&mut carrier, identity, "ok", true).await
        });
        let established = crate::transport_core::session::establish_reality_tls(&mut client_io, &c)
            .await
            .unwrap();
        let tls = crate::protocol::realtls::stream::RealTlsStream::new(client_io, established);
        let mut carrier = crate::protocol::h2_carrier::connect(tls, c.effective_reality_sni())
            .await
            .unwrap();
        let mut auth = authenticated_client(&mut carrier, &c, false).await.unwrap();
        data_roundtrip(&mut carrier, &mut auth).await;
        assert!(server.await.unwrap().is_some());
    }
}
