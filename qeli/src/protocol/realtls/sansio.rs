//! A1 — sans-IO TLS 1.3 client handshake state machine (the FFI core).
//!
//! Same handshake as [`super::client::client_handshake`], but with the IO
//! inverted: the caller owns the socket and feeds inbound bytes via [`recv`],
//! receiving outbound bytes back. This is the byte-in/byte-out shape the C ABI
//! (and the Android/Windows clients) need — no async runtime, no fd ownership.
//!
//! Flow: [`SansIoClient::new`] returns the ClientHello to send; feed server bytes
//! to [`recv`] until it returns [`Progress::Done`] (carrying the final flight to
//! send: ChangeCipherSpec + client Finished). After that, [`seal`] frames
//! application data and [`open_push`] decrypts inbound application data.

// A1 building block: wrapped by the C ABI in A2.
#![allow(dead_code)]

use super::client::{parse_server_hello, u24};
use super::keyschedule::{
    client_application_traffic_secret, client_handshake_traffic_secret, early_secret, finished_key,
    finished_verify, handshake_secret, master_secret, server_application_traffic_secret,
    server_handshake_traffic_secret, traffic_keys, transcript_hash, Suite, TrafficKeys,
};
use super::record::RecordCrypto;
use crate::crypto::mlkem::{mlkem768_decapsulate, DecapKey, MLKEM768_CT_LEN};
use crate::crypto::reality::{seal_session_id, SHORT_ID_LEN};
use crate::crypto::{Keypair, PublicKey};
use std::io;

fn ierr(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Drain one complete TLS record (5-byte header + body) from `buf`, if present.
fn take_record(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 5 {
        return None;
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + len {
        return None;
    }
    Some(buf.drain(..5 + len).collect())
}

// The handshake states differ in size (AEAD key schedules), but `SansIoClient`
// lives behind a heap allocation (the FFI handle), so the variant size gap is
// immaterial; boxing would only clutter the state transitions.
#[allow(clippy::large_enum_variant)]
enum State {
    ExpectServerHello {
        eph: Keypair,
        mlkem_dk: DecapKey,
        transcript: Vec<u8>,
    },
    ExpectFlight {
        suite: Suite,
        s_hs: Vec<u8>,
        c_hs: Vec<u8>,
        hs: Vec<u8>,
        server_rec: RecordCrypto,
        client_hs_keys: TrafficKeys,
        transcript: Vec<u8>,
        hs_buf: Vec<u8>,
    },
    Established {
        send: RecordCrypto,
        recv: RecordCrypto,
    },
    Failed,
}

/// Result of feeding bytes to [`SansIoClient::recv`].
pub enum Progress {
    /// Need more inbound bytes.
    NeedMore,
    /// Handshake complete — send these bytes (ChangeCipherSpec + client Finished),
    /// then use [`SansIoClient::seal`] / [`SansIoClient::open_push`].
    Done(Vec<u8>),
}

/// A sans-IO TLS 1.3 client (REALITY) handshake + record layer.
pub struct SansIoClient {
    state: State,
    in_buf: Vec<u8>,
    /// The initial ClientHello (kept so callers like the JNI bridge can fetch it
    /// after `new`, which returns one value to Java).
    client_hello: Vec<u8>,
}

impl SansIoClient {
    /// Start a handshake. Returns the client and the ClientHello to send. The
    /// REALITY token is sealed into the ClientHello's session_id with a fresh
    /// ephemeral, exactly as the native client does.
    pub fn new(
        reality_pub: &PublicKey,
        short_id: &[u8; SHORT_ID_LEN],
        sni: &str,
    ) -> (Self, Vec<u8>) {
        let eph = Keypair::generate();
        let session_id = seal_session_id(reality_pub, &eph, short_id);
        // Keep the ML-KEM decapsulation key to open the server's ciphertext if it
        // selects the hybrid X25519MLKEM768 group.
        let (ch, mlkem_dk) = super::clienthello::build_client_hello(eph.public(), sni, &session_id);
        let transcript = ch[5..].to_vec();
        (
            SansIoClient {
                state: State::ExpectServerHello { eph, mlkem_dk, transcript },
                in_buf: Vec::new(),
                client_hello: ch.clone(),
            },
            ch,
        )
    }

    /// The initial ClientHello to send (also returned by `new`).
    pub fn client_hello(&self) -> &[u8] {
        &self.client_hello
    }

    pub fn established(&self) -> bool {
        matches!(self.state, State::Established { .. })
    }

    /// Feed inbound bytes; drive the handshake.
    pub fn recv(&mut self, data: &[u8]) -> io::Result<Progress> {
        self.in_buf.extend_from_slice(data);
        loop {
            match std::mem::replace(&mut self.state, State::Failed) {
                State::ExpectServerHello { eph, mlkem_dk, mut transcript } => match take_record(&mut self.in_buf) {
                    None => {
                        self.state = State::ExpectServerHello { eph, mlkem_dk, transcript };
                        return Ok(Progress::NeedMore);
                    }
                    Some(rec) if rec[0] == 0x14 => {
                        self.state = State::ExpectServerHello { eph, mlkem_dk, transcript };
                        continue;
                    }
                    Some(rec) if rec[0] == 0x16 => {
                        let sh_msg = &rec[5..];
                        let (suite, group, server_ks) = parse_server_hello(sh_msg)?;
                        transcript.extend_from_slice(sh_msg);
                        // (EC)DHE / hybrid shared secret per the group the server chose
                        // (0x001d = classic X25519, 0x11ec = X25519MLKEM768 hybrid).
                        let ecdhe: Vec<u8> = match group {
                            0x001d => {
                                let sp = PublicKey::from_bytes(
                                    &<[u8; 32]>::try_from(server_ks.as_slice())
                                        .map_err(|_| ierr("server x25519 key_share not 32 bytes"))?,
                                );
                                eph.derive_shared(&sp).as_bytes().to_vec()
                            }
                            0x11ec => {
                                if server_ks.len() != MLKEM768_CT_LEN + 32 {
                                    return Err(ierr("server hybrid key_share has the wrong length"));
                                }
                                let ml_shared =
                                    mlkem768_decapsulate(&mlkem_dk, &server_ks[..MLKEM768_CT_LEN])
                                        .ok_or_else(|| ierr("ML-KEM decapsulate failed"))?;
                                let sp = PublicKey::from_bytes(
                                    &<[u8; 32]>::try_from(&server_ks[MLKEM768_CT_LEN..])
                                        .map_err(|_| ierr("server x25519 in hybrid not 32 bytes"))?,
                                );
                                let mut h = ml_shared; // ML-KEM shared ‖ X25519 shared
                                h.extend_from_slice(eph.derive_shared(&sp).as_bytes());
                                h
                            }
                            _ => return Err(ierr("server chose an unsupported key_share group")),
                        };
                        let hs = handshake_secret(suite, &early_secret(suite), &ecdhe);
                        let th = transcript_hash(suite, &transcript);
                        let s_hs = server_handshake_traffic_secret(suite, &hs, &th);
                        let c_hs = client_handshake_traffic_secret(suite, &hs, &th);
                        let s_keys = traffic_keys(suite, &s_hs);
                        let client_hs_keys = traffic_keys(suite, &c_hs);
                        self.state = State::ExpectFlight {
                            suite,
                            s_hs,
                            c_hs,
                            hs,
                            server_rec: RecordCrypto::new(&s_keys.key, &s_keys.iv),
                            client_hs_keys,
                            transcript,
                            hs_buf: Vec::new(),
                        };
                        continue;
                    }
                    Some(_) => return Err(ierr("unexpected record before ServerHello")),
                },
                State::ExpectFlight {
                    suite,
                    s_hs,
                    c_hs,
                    hs,
                    mut server_rec,
                    client_hs_keys,
                    mut transcript,
                    mut hs_buf,
                } => {
                    // Process any complete handshake messages already buffered.
                    if hs_buf.len() >= 4 {
                        let mlen = 4 + u24(&hs_buf[1..4]);
                        if hs_buf.len() >= mlen {
                            if hs_buf[0] == 0x14 {
                                // Server Finished — verify, then emit client Finished.
                                let expected = finished_verify(
                                    suite,
                                    &finished_key(suite, &s_hs),
                                    &transcript_hash(suite, &transcript),
                                );
                                if hs_buf[4..mlen] != expected {
                                    return Err(ierr("server Finished verify_data mismatch"));
                                }
                                transcript.extend_from_slice(&hs_buf[..mlen]);
                                let th_full = transcript_hash(suite, &transcript);
                                let client_verify =
                                    finished_verify(suite, &finished_key(suite, &c_hs), &th_full);
                                let mut fin = vec![0x14, 0x00, 0x00, client_verify.len() as u8];
                                fin.extend_from_slice(&client_verify);
                                let mut out = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]; // CCS
                                let mut client_hs_rec =
                                    RecordCrypto::new(&client_hs_keys.key, &client_hs_keys.iv);
                                out.extend_from_slice(&client_hs_rec.encrypt(0x16, &fin));
                                let master = master_secret(suite, &hs);
                                let c_ap = client_application_traffic_secret(suite, &master, &th_full);
                                let s_ap = server_application_traffic_secret(suite, &master, &th_full);
                                let c_ap_keys = traffic_keys(suite, &c_ap);
                                let s_ap_keys = traffic_keys(suite, &s_ap);
                                self.state = State::Established {
                                    send: RecordCrypto::new(&c_ap_keys.key, &c_ap_keys.iv),
                                    recv: RecordCrypto::new(&s_ap_keys.key, &s_ap_keys.iv),
                                };
                                return Ok(Progress::Done(out));
                            }
                            // EE / Certificate / CertificateVerify: fold in, skip validation.
                            transcript.extend_from_slice(&hs_buf[..mlen]);
                            hs_buf.drain(..mlen);
                            self.state = State::ExpectFlight {
                                suite,
                                s_hs,
                                c_hs,
                                hs,
                                server_rec,
                                client_hs_keys,
                                transcript,
                                hs_buf,
                            };
                            continue;
                        }
                    }
                    // Need another record to make progress.
                    match take_record(&mut self.in_buf) {
                        None => {
                            self.state = State::ExpectFlight {
                                suite,
                                s_hs,
                                c_hs,
                                hs,
                                server_rec,
                                client_hs_keys,
                                transcript,
                                hs_buf,
                            };
                            return Ok(Progress::NeedMore);
                        }
                        Some(rec) if rec[0] == 0x14 => {
                            self.state = State::ExpectFlight {
                                suite,
                                s_hs,
                                c_hs,
                                hs,
                                server_rec,
                                client_hs_keys,
                                transcript,
                                hs_buf,
                            };
                            continue;
                        }
                        Some(rec) if rec[0] == 0x17 => match server_rec.decrypt(&rec) {
                            Some((0x16, pt)) => {
                                hs_buf.extend_from_slice(&pt);
                                self.state = State::ExpectFlight {
                                    suite,
                                    s_hs,
                                    c_hs,
                                    hs,
                                    server_rec,
                                    client_hs_keys,
                                    transcript,
                                    hs_buf,
                                };
                                continue;
                            }
                            Some(_) => {
                                self.state = State::ExpectFlight {
                                    suite,
                                    s_hs,
                                    c_hs,
                                    hs,
                                    server_rec,
                                    client_hs_keys,
                                    transcript,
                                    hs_buf,
                                };
                                continue;
                            }
                            None => return Err(ierr("failed to decrypt handshake record")),
                        },
                        Some(_) => return Err(ierr("unexpected record in flight")),
                    }
                }
                State::Established { send, recv } => {
                    self.state = State::Established { send, recv };
                    return Ok(Progress::NeedMore);
                }
                State::Failed => return Err(ierr("handshake already failed")),
            }
        }
    }

    /// Frame application data as one TLS record (call only after `Done`).
    pub fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        match &mut self.state {
            State::Established { send, .. } => Ok(send.encrypt(0x17, plaintext)),
            _ => Err(ierr("seal before handshake complete")),
        }
    }

    /// Feed inbound bytes after the handshake; returns any complete
    /// application-data payloads (non-application records, e.g. tickets, skipped).
    pub fn open_push(&mut self, data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        if !self.established() {
            return Err(ierr("open before handshake complete"));
        }
        self.in_buf.extend_from_slice(data);
        let mut out = Vec::new();
        while let Some(rec) = take_record(&mut self.in_buf) {
            if let State::Established { recv, .. } = &mut self.state {
                match recv.decrypt(&rec) {
                    Some((0x17, pt)) => out.push(pt),
                    Some(_) => {}
                    None => return Err(ierr("application record decrypt failed")),
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::reality::short_id_from_hex;
    use crate::crypto::StaticKeypair;
    use crate::protocol::realtls::server::{make_server_config, terminate};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Drive the sans-IO client (shuttling its bytes over a socket by hand, as the
    /// FFI caller will) against a real rustls server.
    #[tokio::test]
    async fn sansio_interop_with_rustls() {
        let (mut io, server_io) = tokio::io::duplex(32 * 1024);
        let config = make_server_config("www.microsoft.com");
        let server = tokio::spawn(async move {
            let mut tls = terminate(Vec::new(), server_io, config).await.unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
        });

        let reality = StaticKeypair::generate();
        let (mut client, ch) =
            SansIoClient::new(&reality.public, &short_id_from_hex("0123456789abcdef"), "www.microsoft.com");
        io.write_all(&ch).await.unwrap();
        io.flush().await.unwrap();

        // Drive the handshake.
        let mut rbuf = [0u8; 4096];
        loop {
            let n = io.read(&mut rbuf).await.unwrap();
            assert!(n > 0, "unexpected EOF during handshake");
            if let Progress::Done(to_send) = client.recv(&rbuf[..n]).unwrap() {
                io.write_all(&to_send).await.unwrap();
                io.flush().await.unwrap();
                break;
            }
        }
        assert!(client.established());

        // Application data via seal/open_push.
        let ping = client.seal(b"ping").unwrap();
        io.write_all(&ping).await.unwrap();
        io.flush().await.unwrap();
        let pong = loop {
            let n = io.read(&mut rbuf).await.unwrap();
            assert!(n > 0, "unexpected EOF awaiting reply");
            let msgs = client.open_push(&rbuf[..n]).unwrap();
            if let Some(m) = msgs.into_iter().next() {
                break m;
            }
        };
        assert_eq!(pong, b"pong");
        server.await.unwrap();
    }

    /// Drive the sans-IO client against the hand-rolled REALITY server with the PQ
    /// hybrid + SHA-384/AES-256 suite — exercises ML-KEM decapsulation and the
    /// SHA-384 key schedule end-to-end through the FFI core.
    #[tokio::test]
    async fn sansio_interop_handrolled_pq_sha384() {
        use crate::protocol::realtls::server::{terminate_handrolled, BorrowProfile};
        let (mut io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut tls = terminate_handrolled(
                server_io,
                Keypair::generate(),
                BorrowProfile { suite: Suite::Aes256Sha384, prefer_pq: true, key_share_first: false },
                None,
            )
            .await
            .expect("handrolled server terminates");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
        });

        let reality = StaticKeypair::generate();
        let (mut client, ch) = SansIoClient::new(
            &reality.public,
            &short_id_from_hex("0123456789abcdef"),
            "www.microsoft.com",
        );
        io.write_all(&ch).await.unwrap();
        io.flush().await.unwrap();

        let mut rbuf = [0u8; 4096];
        loop {
            let n = io.read(&mut rbuf).await.unwrap();
            assert!(n > 0, "unexpected EOF during handshake");
            if let Progress::Done(to_send) = client.recv(&rbuf[..n]).unwrap() {
                io.write_all(&to_send).await.unwrap();
                io.flush().await.unwrap();
                break;
            }
        }
        assert!(client.established());

        let ping = client.seal(b"ping").unwrap();
        io.write_all(&ping).await.unwrap();
        io.flush().await.unwrap();
        let pong = loop {
            let n = io.read(&mut rbuf).await.unwrap();
            assert!(n > 0, "unexpected EOF awaiting reply");
            if let Some(m) = client.open_push(&rbuf[..n]).unwrap().into_iter().next() {
                break m;
            }
        };
        assert_eq!(pong, b"pong");
        server.await.unwrap();
    }
}
