//! M2.3 — TLS 1.3 client handshake state machine.
//!
//! Drives a full TLS 1.3 (EC)DHE handshake over an async stream using the
//! Chrome-grade ClientHello (M2.1) and the key schedule / record layer (M2.2):
//!
//! 1. send ClientHello (ephemeral x25519 in `key_share`, REALITY token in
//!    `session_id`);
//! 2. read ServerHello, recover the server `key_share`, derive handshake secrets;
//! 3. read the encrypted flight (EncryptedExtensions, Certificate,
//!    CertificateVerify, Finished). The certificate chain and CertificateVerify
//!    are **not** validated — REALITY trust comes from X25519 and the inner qeli
//!    auth (M3) — but the server `Finished` IS verified;
//! 4. send the client `Finished`;
//! 5. switch to application traffic keys.
//!
//! On success returns [`EstablishedTls`]: the application-data record crypto for
//! each direction. Only TLS_AES_128_GCM_SHA256 is supported (the server must
//! negotiate it — our REALITY server is configured to).

// Wired into the client data-plane (`client/mod.rs`, `mode = "reality-tls"`) and the
// Android/Windows/macOS FFI clients. The module-level allow stays because a few
// items are exercised only through the sans-io / FFI paths or the interop tests,
// not via the Rust client's direct `client_handshake` entry point.
#![allow(dead_code)]

use super::clienthello::build_client_hello;
use super::keyschedule::{
    client_application_traffic_secret, client_handshake_traffic_secret, early_secret, finished_key,
    finished_verify, handshake_secret, master_secret, server_application_traffic_secret,
    server_handshake_traffic_secret, traffic_keys, transcript_hash, Suite,
};
use super::record::RecordCrypto;
use crate::crypto::mlkem::{mlkem768_decapsulate, MLKEM768_CT_LEN};
use crate::crypto::{Keypair, PublicKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_RECORD: usize = 16384 + 256;

/// Established TLS 1.3 connection: application-data record protection per
/// direction. `send` protects client→server, `recv` opens server→client.
pub struct EstablishedTls {
    pub send: RecordCrypto,
    pub recv: RecordCrypto,
}

fn ierr(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub(crate) fn hmac256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

pub(crate) fn u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
}

/// Read one TLS record: returns `(content_type, full_record_bytes)` including the
/// 5-byte header (the header is the AEAD additional data for encrypted records).
pub(crate) async fn read_record<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_RECORD {
        return Err(ierr("record too large"));
    }
    let mut rec = Vec::with_capacity(5 + len);
    rec.extend_from_slice(&hdr);
    rec.resize(5 + len, 0);
    s.read_exact(&mut rec[5..]).await?;
    Ok((hdr[0], rec))
}

/// Recover the x25519 `key_share` from a (standard) ServerHello handshake message
/// and confirm the negotiated cipher suite is TLS_AES_128_GCM_SHA256.
pub(crate) fn parse_server_hello(msg: &[u8]) -> io::Result<(Suite, u16, Vec<u8>)> {
    if msg.len() < 39 || msg[0] != 0x02 {
        return Err(ierr("not a ServerHello"));
    }
    let sid_len = msg[38] as usize;
    let mut o = 39 + sid_len;
    if o + 3 > msg.len() {
        return Err(ierr("ServerHello truncated"));
    }
    let cipher = u16::from_be_bytes([msg[o], msg[o + 1]]);
    let suite = Suite::from_code(cipher)
        .ok_or_else(|| ierr("server negotiated an unsupported cipher suite"))?;
    o += 3; // cipher suite (2) + legacy_compression (1)
    if o + 2 > msg.len() {
        return Err(ierr("ServerHello missing extensions"));
    }
    let ext_len = u16::from_be_bytes([msg[o], msg[o + 1]]) as usize;
    o += 2;
    let end = (o + ext_len).min(msg.len());
    while o + 4 <= end {
        let et = u16::from_be_bytes([msg[o], msg[o + 1]]);
        let el = u16::from_be_bytes([msg[o + 2], msg[o + 3]]) as usize;
        o += 4;
        if o + el > end {
            break;
        }
        if et == 0x0033 && el >= 4 {
            let group = u16::from_be_bytes([msg[o], msg[o + 1]]);
            let klen = u16::from_be_bytes([msg[o + 2], msg[o + 3]]) as usize;
            if o + 4 + klen <= o + el {
                return Ok((suite, group, msg[o + 4..o + 4 + klen].to_vec()));
            }
        }
        o += el;
    }
    Err(ierr("ServerHello has no key_share"))
}

/// Run the TLS 1.3 client handshake. `ephemeral` is the x25519 key whose public
/// half is the ClientHello `key_share`; `session_id` is the 32-byte REALITY token
/// (or any 32 bytes for a plain TLS peer).
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ephemeral: Keypair,
    session_id: [u8; 32],
    sni: &str,
) -> io::Result<EstablishedTls> {
    // 1. ClientHello.
    let (ch, mlkem_dk) = build_client_hello(ephemeral.public(), sni, &session_id);
    stream.write_all(&ch).await?;
    let mut transcript: Vec<u8> = ch[5..].to_vec();

    // 2. ServerHello (skipping any ChangeCipherSpec).
    let sh_record = loop {
        let (ct, rec) = read_record(stream).await?;
        match ct {
            0x14 => continue,
            0x16 => break rec,
            0x15 => return Err(ierr("server sent alert")),
            _ => return Err(ierr("expected ServerHello")),
        }
    };
    let sh_msg = &sh_record[5..];
    let (suite, group, server_ks) = parse_server_hello(sh_msg)?;
    transcript.extend_from_slice(sh_msg);

    // Compute the (EC)DHE / hybrid shared secret per the group the server chose,
    // then derive handshake secrets under the negotiated cipher suite.
    let ecdhe: Vec<u8> = match group {
        0x001d => {
            // Classic X25519.
            let sp = PublicKey::from_bytes(
                &<[u8; 32]>::try_from(server_ks.as_slice())
                    .map_err(|_| ierr("server x25519 key_share not 32 bytes"))?,
            );
            ephemeral.derive_shared(&sp).as_bytes().to_vec()
        }
        0x11ec => {
            // Hybrid X25519MLKEM768: server key_share = ML-KEM ct(1088) ‖ x25519(32);
            // combined secret is ML-KEM shared ‖ X25519 shared (ML-KEM first).
            if server_ks.len() != MLKEM768_CT_LEN + 32 {
                return Err(ierr("server hybrid key_share has the wrong length"));
            }
            let ml_shared = mlkem768_decapsulate(&mlkem_dk, &server_ks[..MLKEM768_CT_LEN])
                .ok_or_else(|| ierr("ML-KEM decapsulate failed"))?;
            let sp = PublicKey::from_bytes(
                &<[u8; 32]>::try_from(&server_ks[MLKEM768_CT_LEN..])
                    .map_err(|_| ierr("server x25519 in hybrid not 32 bytes"))?,
            );
            let x_shared = ephemeral.derive_shared(&sp);
            let mut h = ml_shared;
            h.extend_from_slice(x_shared.as_bytes());
            h
        }
        _ => return Err(ierr("server chose an unsupported key_share group")),
    };
    let early = early_secret(suite);
    let hs = handshake_secret(suite, &early, &ecdhe);
    let th_chsh = transcript_hash(suite, &transcript);
    let s_hs = server_handshake_traffic_secret(suite, &hs, &th_chsh);
    let c_hs = client_handshake_traffic_secret(suite, &hs, &th_chsh);
    let server_hs_keys = traffic_keys(suite, &s_hs);
    let client_hs_keys = traffic_keys(suite, &c_hs);

    // 3. Encrypted flight: EE, Certificate, CertificateVerify, Finished. Messages
    // may be coalesced into one record or split across several.
    let mut server_rec = RecordCrypto::new(&server_hs_keys.key, &server_hs_keys.iv);
    let mut hs_buf: Vec<u8> = Vec::new();
    'flight: loop {
        // Process whatever complete handshake messages we already have.
        while hs_buf.len() >= 4 {
            let mlen = 4 + u24(&hs_buf[1..4]);
            if hs_buf.len() < mlen {
                break;
            }
            let mtype = hs_buf[0];
            if mtype == 0x14 {
                // Server Finished: verify against the CH..CertVerify transcript.
                let th = transcript_hash(suite, &transcript);
                let expected = finished_verify(suite, &finished_key(suite, &s_hs), &th);
                if hs_buf[4..mlen] != expected {
                    return Err(ierr("server Finished verify_data mismatch"));
                }
                transcript.extend_from_slice(&hs_buf[..mlen]);
                hs_buf.drain(..mlen);
                break 'flight;
            }
            // EE / Certificate / CertificateVerify: fold into the transcript; the
            // certificate is intentionally not validated (trust is via X25519).
            transcript.extend_from_slice(&hs_buf[..mlen]);
            hs_buf.drain(..mlen);
        }
        // Need more bytes.
        let (ct, rec) = read_record(stream).await?;
        match ct {
            0x14 => continue,
            0x17 => {
                let (inner, pt) = server_rec
                    .decrypt(&rec)
                    .ok_or_else(|| ierr("failed to decrypt handshake record"))?;
                if inner != 0x16 {
                    return Err(ierr("expected handshake content inside record"));
                }
                hs_buf.extend_from_slice(&pt);
            }
            0x15 => return Err(ierr("server sent encrypted alert")),
            _ => return Err(ierr("unexpected record in flight")),
        }
    }

    // 4. Client Finished over the CH..server-Finished transcript.
    let th_full = transcript_hash(suite, &transcript);
    let client_verify = finished_verify(suite, &finished_key(suite, &c_hs), &th_full);
    let mut fin = vec![0x14, 0x00, 0x00];
    fin.push(client_verify.len() as u8);
    fin.extend_from_slice(&client_verify);

    // Dummy ChangeCipherSpec (middlebox compatibility), then the encrypted
    // Finished under the client handshake key.
    stream
        .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await?;
    let mut client_hs_rec = RecordCrypto::new(&client_hs_keys.key, &client_hs_keys.iv);
    let fin_record = client_hs_rec.encrypt(0x16, &fin);
    stream.write_all(&fin_record).await?;

    // 5. Application traffic keys (RFC 8446 §7.3) from the master secret.
    let master = master_secret(suite, &hs);
    let c_ap = client_application_traffic_secret(suite, &master, &th_full);
    let s_ap = server_application_traffic_secret(suite, &master, &th_full);
    let c_ap_keys = traffic_keys(suite, &c_ap);
    let s_ap_keys = traffic_keys(suite, &s_ap);

    Ok(EstablishedTls {
        send: RecordCrypto::new(&c_ap_keys.key, &c_ap_keys.iv),
        recv: RecordCrypto::new(&s_ap_keys.key, &s_ap_keys.iv),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{reality, StaticKeypair};
    use crate::protocol::FakeTlsHandshake;

    fn hs_msg(mtype: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![mtype, 0, 0, 0];
        m.extend_from_slice(body);
        let l = m.len() - 4;
        m[1] = (l >> 16) as u8;
        m[2] = (l >> 8) as u8;
        m[3] = l as u8;
        m
    }

    /// A minimal but spec-faithful TLS 1.3 server (EC)DHE handshake, reusing the
    /// same key schedule / record layer. It sends a full flight (EE + dummy
    /// Certificate + dummy CertificateVerify + Finished) so the client's parsing
    /// and transcript handling are exercised exactly as against a real server.
    /// Returns the application bytes received from the client after replying.
    async fn test_server<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        server_eph: Keypair,
    ) -> io::Result<Vec<u8>> {
        // ClientHello.
        let (ct, ch_rec) = read_record(stream).await?;
        assert_eq!(ct, 0x16);
        let (sid, client_ks) = FakeTlsHandshake::parse_client_hello_full(&ch_rec)
            .ok_or_else(|| ierr("bad ClientHello"))?;
        let client_pub =
            PublicKey::from_bytes(&<[u8; 32]>::try_from(client_ks.as_slice()).unwrap());
        let mut transcript: Vec<u8> = ch_rec[5..].to_vec();
        let suite = Suite::Aes128Sha256;

        // ServerHello (standard layout: supported_versions + x25519 key_share).
        let mut sh_body = Vec::new();
        sh_body.extend_from_slice(&[0x03, 0x03]);
        sh_body.extend_from_slice(&[0x11u8; 32]); // random
        sh_body.push(0x20);
        sh_body.extend_from_slice(&sid); // echo legacy_session_id
        sh_body.extend_from_slice(&suite.code().to_be_bytes());
        sh_body.push(0x00);
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions 1.3
        ext.extend_from_slice(&[0x00, 0x33]);
        ext.extend_from_slice(&36u16.to_be_bytes());
        ext.extend_from_slice(&[0x00, 0x1d, 0x00, 0x20]);
        ext.extend_from_slice(server_eph.public().as_bytes());
        sh_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&ext);
        let sh = hs_msg(0x02, &sh_body);
        let mut sh_record = vec![0x16, 0x03, 0x03];
        sh_record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
        sh_record.extend_from_slice(&sh);
        stream.write_all(&sh_record).await?;
        transcript.extend_from_slice(&sh);

        // Handshake secrets.
        let shared = server_eph.derive_shared(&client_pub);
        let early = early_secret(suite);
        let hs = handshake_secret(suite, &early, shared.as_bytes());
        let th_chsh = transcript_hash(suite, &transcript);
        let s_hs = server_handshake_traffic_secret(suite, &hs, &th_chsh);
        let c_hs = client_handshake_traffic_secret(suite, &hs, &th_chsh);
        let s_keys = traffic_keys(suite, &s_hs);
        let c_keys = traffic_keys(suite, &c_hs);

        // Flight: EE + dummy Certificate + dummy CertificateVerify, then Finished.
        let ee = hs_msg(0x08, &[0x00, 0x00]);
        let mut cert_body = vec![0x00]; // cert_request_context len 0
        let cert_data = [0xAAu8; 16];
        let mut cert_list = Vec::new();
        cert_list.extend_from_slice(&[0, 0, cert_data.len() as u8]);
        cert_list.extend_from_slice(&cert_data);
        cert_list.extend_from_slice(&[0x00, 0x00]); // entry extensions len 0
        cert_body.extend_from_slice(&[0, 0, cert_list.len() as u8]);
        cert_body.extend_from_slice(&cert_list);
        let cert = hs_msg(0x0b, &cert_body);
        let mut cv_body = vec![0x08, 0x04]; // signature scheme
        let sig = [0xBBu8; 16];
        cv_body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        cv_body.extend_from_slice(&sig);
        let cv = hs_msg(0x0f, &cv_body);

        transcript.extend_from_slice(&ee);
        transcript.extend_from_slice(&cert);
        transcript.extend_from_slice(&cv);
        let s_verify = hmac256(
            &finished_key(suite, &s_hs),
            &transcript_hash(suite, &transcript),
        );
        let sfin = hs_msg(0x14, &s_verify);
        transcript.extend_from_slice(&sfin);

        let mut flight = Vec::new();
        flight.extend_from_slice(&ee);
        flight.extend_from_slice(&cert);
        flight.extend_from_slice(&cv);
        flight.extend_from_slice(&sfin);
        let mut s_rec = RecordCrypto::new(&s_keys.key, &s_keys.iv);
        stream
            .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
            .await?; // CCS
        let flight_record = s_rec.encrypt(0x16, &flight);
        stream.write_all(&flight_record).await?;

        // Read client CCS (skip) + client Finished.
        let mut c_rec = RecordCrypto::new(&c_keys.key, &c_keys.iv);
        let cfin = loop {
            let (ct, rec) = read_record(stream).await?;
            match ct {
                0x14 => continue,
                0x17 => break c_rec.decrypt(&rec).ok_or_else(|| ierr("decrypt cfin"))?,
                _ => return Err(ierr("expected client Finished")),
            }
        };
        let (cfin_type, cfin_msg) = cfin;
        assert_eq!(cfin_type, 0x16);
        let expect_c = hmac256(
            &finished_key(suite, &c_hs),
            &transcript_hash(suite, &transcript),
        );
        if cfin_msg[4..] != expect_c {
            return Err(ierr("client Finished mismatch"));
        }

        // Application keys derive from the CH..server-Finished transcript (the
        // client Finished is NOT included), matching the client. A ping/pong
        // exchange confirms both directions.
        let master = master_secret(suite, &hs);
        let th_full = transcript_hash(suite, &transcript);
        let c_ap = client_application_traffic_secret(suite, &master, &th_full);
        let s_ap = server_application_traffic_secret(suite, &master, &th_full);
        let c_ap_keys = traffic_keys(suite, &c_ap);
        let s_ap_keys = traffic_keys(suite, &s_ap);
        let mut recv = RecordCrypto::new(&c_ap_keys.key, &c_ap_keys.iv);
        let mut send = RecordCrypto::new(&s_ap_keys.key, &s_ap_keys.iv);

        let (_, ping_rec) = read_record(stream).await?;
        let (_, ping) = recv
            .decrypt(&ping_rec)
            .ok_or_else(|| ierr("decrypt ping"))?;
        let pong = send.encrypt(0x17, b"pong");
        stream.write_all(&pong).await?;
        Ok(ping)
    }

    #[tokio::test]
    async fn handshake_interop_loopback() {
        let (mut client_io, mut server_io) = tokio::io::duplex(32 * 1024);
        let server_eph = Keypair::generate();
        let server = tokio::spawn(async move { test_server(&mut server_io, server_eph).await });

        let eph = Keypair::generate();
        let reality = StaticKeypair::generate();
        let sid = reality::seal_session_id(
            &reality.public,
            &eph,
            &reality::short_id_from_hex("0123456789abcdef"),
        );

        let mut tls = client_handshake(&mut client_io, eph, sid, "www.microsoft.com")
            .await
            .expect("client handshake completes against a real TLS 1.3 server");

        // Application data both directions.
        let ping = tls.send.encrypt(0x17, b"ping");
        client_io.write_all(&ping).await.unwrap();

        // Surface any server-side handshake error before reading the reply.
        let received_ping = server.await.unwrap().expect("server handshake completes");
        assert_eq!(received_ping, b"ping");

        let (_, pong_rec) = read_record(&mut client_io).await.unwrap();
        let (ct, pong) = tls.recv.decrypt(&pong_rec).expect("decrypt pong");
        assert_eq!(ct, 0x17);
        assert_eq!(pong, b"pong");
    }

    /// Gold interop: our hand-rolled client completes a real TLS 1.3 handshake
    /// against the `rustls` reference stack. This is what the loopback test can't
    /// prove — that our ClientHello and handshake are genuine TLS, not just
    /// self-consistent.
    #[tokio::test]
    async fn handshake_interop_with_rustls() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // On-the-fly self-signed cert for the borrowed domain. The client does not
        // validate it; rustls just needs a cert to complete the handshake.
        let gen =
            rcgen::generate_simple_self_signed(vec!["www.microsoft.com".to_string()]).unwrap();
        let cert_der = gen.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(gen.key_pair.serialize_der()));

        // TLS 1.3 only, AES-128-GCM only (what our record layer implements).
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap();
        config.send_tls13_tickets = 0; // keep the post-handshake stream to app-data only
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let (mut client_io, server_io) = tokio::io::duplex(32 * 1024);
        let server = tokio::spawn(async move {
            let mut tls = acceptor
                .accept(server_io)
                .await
                .expect("rustls accepts our hand-rolled ClientHello");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.expect("read ping");
            tls.write_all(b"pong").await.expect("write pong");
            tls.flush().await.expect("flush");
            buf
        });

        let eph = Keypair::generate();
        let reality = StaticKeypair::generate();
        let sid = reality::seal_session_id(
            &reality.public,
            &eph,
            &reality::short_id_from_hex("0123456789abcdef"),
        );
        let mut tls = client_handshake(&mut client_io, eph, sid, "www.microsoft.com")
            .await
            .expect("realtls client completes a real TLS 1.3 handshake with rustls");

        let ping = tls.send.encrypt(0x17, b"ping");
        client_io.write_all(&ping).await.unwrap();
        client_io.flush().await.unwrap();

        // Read the server's reply, skipping any non-application records.
        let pong = loop {
            let (_, rec) = read_record(&mut client_io).await.unwrap();
            let (inner, pt) = tls.recv.decrypt(&rec).expect("decrypt server app record");
            if inner == 0x17 {
                break pt;
            }
        };
        assert_eq!(pong, b"pong");
        assert_eq!(&server.await.unwrap(), b"ping");
    }
}
