//! M3.2 — client-side application-data stream over an established TLS 1.3 session.
//!
//! [`super::client::client_handshake`] returns the per-direction record crypto
//! ([`super::client::EstablishedTls`]); this wraps it plus the raw socket into a
//! plain `AsyncRead + AsyncWrite` duplex that frames writes as `application_data`
//! records and decrypts reads. It is the client-side mirror of tokio-rustls'
//! server `TlsStream`, so the qeli tunnel can run inside a real TLS session.

// Used by both the native reality-tls client and the hand-rolled server terminator.
// Feature-specific constructors still leave a few helpers unused in some builds.
#![allow(dead_code)]

use super::application::ApplicationRecords;
use super::client::{EstablishedTls, MAX_RECORD};
use super::record::RecordCrypto;
use crate::protocol::obfs::SplitStream;
use crate::protocol::stream_io::StallGuard;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

/// Max TLSPlaintext fragment (RFC 8446 §5.1). Writes larger than this are split
/// across records.
const MAX_PLAINTEXT: usize = 16384;

/// Socket read granularity. A TLS record is up to ~16 KiB; reading in 64-KiB
/// chunks pulls several records per syscall instead of fragmenting one record
/// across many 4-KiB reads (the old behaviour that throttled download).
const READ_CHUNK: usize = 64 * 1024;

/// An `AsyncRead + AsyncWrite` duplex over an established TLS 1.3 session.
pub struct RealTlsStream<S> {
    inner: StallGuard<S>,
    send: RecordCrypto,
    recv: RecordCrypto,
    /// Raw inbound bytes not yet framed into a complete record.
    in_buf: Vec<u8>,
    /// Reusable scratch for the inner-socket read (avoids a per-poll allocation
    /// and re-zeroing; sized to [`READ_CHUNK`]).
    rbuf: Vec<u8>,
    /// Decrypted application bytes ready to hand to the reader.
    plain: Vec<u8>,
    plain_pos: usize,
    /// A valid TLS close_notify was consumed; return clean EOF after buffered app data.
    records: ApplicationRecords,
    /// Encrypted outbound record pending write to the inner socket.
    out_buf: Vec<u8>,
    out_pos: usize,
}

impl<S> RealTlsStream<S> {
    pub fn new(inner: S, est: EstablishedTls) -> Self {
        Self::from_crypto(inner, est.send, est.recv)
    }

    /// Wrap a socket with the per-direction record crypto directly. Lets the
    /// server side (whose `EstablishedServerTls` has the same shape) reuse this
    /// stream without depending on the client's `EstablishedTls` type.
    pub fn from_crypto(inner: S, send: RecordCrypto, recv: RecordCrypto) -> Self {
        RealTlsStream {
            inner: StallGuard::new(inner),
            send,
            recv,
            in_buf: Vec::new(),
            rbuf: vec![0u8; READ_CHUNK],
            plain: Vec::new(),
            plain_pos: 0,
            records: ApplicationRecords::default(),
            out_buf: Vec::new(),
            out_pos: 0,
        }
    }
}

/// Write as much of `out_buf[out_pos..]` to `inner` as the socket accepts.
fn flush_out<S: AsyncWrite + Unpin>(
    inner: &mut S,
    out_buf: &[u8],
    out_pos: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *out_pos < out_buf.len() {
        match Pin::new(&mut *inner).poll_write(cx, &out_buf[*out_pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "inner stream accepted no bytes",
                )))
            }
            Poll::Ready(Ok(n)) => *out_pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

impl<S: AsyncRead + Unpin> AsyncRead for RealTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            // 1. Serve any already-decrypted plaintext.
            if me.plain_pos < me.plain.len() {
                let n = (me.plain.len() - me.plain_pos).min(buf.remaining());
                buf.put_slice(&me.plain[me.plain_pos..me.plain_pos + n]);
                me.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if let Some(error) = me.records.error() {
                return Poll::Ready(Err(error));
            }
            if me.records.peer_closed {
                return Poll::Ready(Ok(()));
            }
            // 2. Batch: decrypt EVERY complete record currently buffered into
            // `plain` in one pass, then drain the consumed prefix ONCE (not the
            // old per-record drain+alloc, which memmoved the residual and
            // allocated a Vec per record). The reader then serves `plain` across
            // many small read_exacts without touching the socket again.
            me.plain.clear();
            me.plain_pos = 0;
            let mut pos = 0usize;
            while me.in_buf.len() - pos >= 5 {
                let len = u16::from_be_bytes([me.in_buf[pos + 3], me.in_buf[pos + 4]]) as usize;
                // RFC 8446 §5.2 caps a TLSCiphertext fragment at 2^14 + 256. The handshake
                // reader (`client.rs::read_record`) has always enforced that; this adapter —
                // which carries ALL traffic of an established session, on both the client and
                // the server (`terminate_handrolled`) — accepted anything the 16-bit length
                // field could express, i.e. up to 65535 + 5. A peer could therefore make us
                // buffer ~4x the legal maximum per record before the AEAD ever ran, and a
                // real TLS stack would have refused the record outright — so it is both a
                // memory-amplification lever and a deviation from the thing we impersonate.
                // (Audit 2026-08-04.)
                if len > MAX_RECORD {
                    me.records.fail(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TLS record exceeds the RFC 8446 maximum",
                    ));
                    break;
                }
                let total = 5 + len;
                if me.in_buf.len() - pos < total {
                    break; // incomplete record — need more bytes
                }
                let result = me
                    .recv
                    .decrypt(&me.in_buf[pos..pos + total])
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "TLS record decrypt failed")
                    })
                    .and_then(|(kind, pt)| me.records.accept(kind, pt));
                pos += total;
                match result {
                    Ok(Some(plaintext)) => me.plain.extend_from_slice(&plaintext),
                    Ok(None) => {}
                    Err(error) => {
                        me.records.fail(error);
                        break;
                    }
                }
                if me.records.peer_closed {
                    break;
                }
            }
            if me.records.error().is_some() || me.records.peer_closed {
                me.in_buf.clear();
            } else if pos > 0 {
                me.in_buf.drain(..pos);
            }
            if !me.plain.is_empty() {
                continue; // serve what we just decrypted
            }
            if let Some(error) = me.records.error() {
                return Poll::Ready(Err(error));
            }
            if me.records.peer_closed {
                // close_notify was consumed above; do not wait for transport EOF.
                return Poll::Ready(Ok(()));
            }

            // 3. No complete record yet — pull a large chunk into the reused
            // scratch buffer and append. Big reads keep whole records together
            // (one syscall yields several records instead of fragmenting one).
            let mut rb = ReadBuf::new(&mut me.rbuf);
            match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        if me.in_buf.is_empty() {
                            me.records.peer_closed = true;
                            return Poll::Ready(Ok(())); // clean record boundary EOF
                        }
                        me.records.fail(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TLS stream ended in the middle of a record",
                        ));
                        return Poll::Ready(Err(me.records.error().unwrap()));
                    }
                    me.in_buf.extend_from_slice(filled);
                    continue;
                }
                Poll::Ready(Err(error)) => {
                    me.records.fail(error);
                    return Poll::Ready(Err(me.records.error().unwrap()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RealTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if let Some(error) = me.records.error() {
            return Poll::Ready(Err(error));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Finish flushing a record left pending from a previous call before
        // encrypting new data (preserves record order and the AEAD sequence).
        if me.out_pos < me.out_buf.len() {
            match flush_out(&mut me.inner, &me.out_buf, &mut me.out_pos, cx) {
                Poll::Ready(Ok(())) => {
                    me.out_buf.clear();
                    me.out_pos = 0;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        // Encrypt up to one max-size fragment as an application_data record;
        // write_all loops for anything larger.
        let n = buf.len().min(MAX_PLAINTEXT);
        me.out_buf = match me.send.encrypt(0x17, &buf[..n]) {
            Ok(record) => record,
            Err(error) => return Poll::Ready(Err(error)),
        };
        me.out_pos = 0;
        match flush_out(&mut me.inner, &me.out_buf, &mut me.out_pos, cx) {
            Poll::Ready(Ok(())) => {
                me.out_buf.clear();
                me.out_pos = 0;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            // Record buffered; the leftover flushes on the next poll_write/flush.
            Poll::Pending => Poll::Ready(Ok(n)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if let Some(error) = me.records.error() {
            return Poll::Ready(Err(error));
        }
        match flush_out(&mut me.inner, &me.out_buf, &mut me.out_pos, cx) {
            Poll::Ready(Ok(())) => {
                me.out_buf.clear();
                me.out_pos = 0;
                Pin::new(&mut me.inner).poll_flush(cx)
            }
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if let Some(error) = me.records.error() {
            return Poll::Ready(Err(error));
        }
        match flush_out(&mut me.inner, &me.out_buf, &mut me.out_pos, cx) {
            Poll::Ready(Ok(())) => {
                me.out_buf.clear();
                me.out_pos = 0;
                Pin::new(&mut me.inner).poll_shutdown(cx)
            }
            other => other,
        }
    }
}

/// Owned read/write halves so the tunnel data-plane stays generic over wire
/// modes (mirrors the `TcpStream`/`ObfsStream` impls).
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> SplitStream for RealTlsStream<S> {
    type R = ReadHalf<RealTlsStream<S>>;
    type W = StallGuard<WriteHalf<RealTlsStream<S>>>;
    fn write_progress(&self) -> Option<crate::protocol::stream_io::WriteProgress> {
        Some(self.inner.progress())
    }
    fn split_io(self) -> (Self::R, Self::W) {
        let progress = self.inner.progress();
        let (read, write) = tokio::io::split(self);
        (read, StallGuard::observing(write, Some(progress)))
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use crate::crypto::{reality, Keypair, StaticKeypair};
    use crate::protocol::realtls::client::client_handshake;
    use crate::protocol::realtls::server::{make_server_config, terminate};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn q11_prior_plaintext_precedes_sticky_tls_failure() {
        let key = [0x31; 16];
        let iv = [0x42; 12];
        for bad in [vec![0x18, 0, 0, 1, 0], vec![0x19, 0, 0, 0]] {
            let (mut peer, inner) = tokio::io::duplex(512);
            let mut crypto = RecordCrypto::new(&key, &iv);
            let mut wire = crypto.encrypt(0x17, b"terminal-policy").unwrap();
            wire.extend(crypto.encrypt(0x16, &bad).unwrap());
            wire.extend(crypto.encrypt(0x17, b"must-not-arrive").unwrap());
            peer.write_all(&wire).await.unwrap();
            let mut stream = RealTlsStream::from_crypto(
                inner,
                RecordCrypto::new(&key, &iv),
                RecordCrypto::new(&key, &iv),
            );
            let mut got = [0; 15];
            stream
                .read_exact(&mut got)
                .await
                .expect("already validated data must be delivered before fatal error");
            assert_eq!(&got, b"terminal-policy");
            let mut byte = [0; 1];
            let error = stream.read(&mut byte).await.unwrap_err();
            assert_eq!(
                stream.read(&mut byte).await.unwrap_err().kind(),
                error.kind(),
                "fatal error is sticky"
            );
            assert!(stream.write_all(b"after-failure").await.is_err());
        }
    }

    #[tokio::test]
    async fn q11_fragmented_ticket_preserves_following_application_data() {
        let key = [0x31; 16];
        let iv = [0x42; 12];
        let (mut peer, inner) = tokio::io::duplex(512);
        let mut crypto = RecordCrypto::new(&key, &iv);
        let ticket = [4, 0, 0, 14, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 1, 42, 0, 0];
        let mut wire = Vec::new();
        for fragment in ticket.chunks(3) {
            wire.extend(crypto.encrypt(0x16, fragment).unwrap());
        }
        wire.extend(crypto.encrypt(0x17, b"ok").unwrap());
        peer.write_all(&wire).await.unwrap();
        let mut stream = RealTlsStream::from_crypto(
            inner,
            RecordCrypto::new(&key, &iv),
            RecordCrypto::new(&key, &iv),
        );
        let mut got = [0; 2];
        stream
            .read_exact(&mut got)
            .await
            .expect("TLS handshake fragmentation is legal");
        assert_eq!(&got, b"ok");
    }

    #[tokio::test]
    async fn eof_in_partial_record_is_an_error() {
        let (mut peer, inner) = tokio::io::duplex(32);
        peer.write_all(&[0x17, 0x03]).await.unwrap();
        peer.shutdown().await.unwrap();

        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let mut stream = RealTlsStream::from_crypto(
            inner,
            RecordCrypto::new(&key, &iv),
            RecordCrypto::new(&key, &iv),
        );
        let mut byte = [0u8; 1];
        let error = stream
            .read(&mut byte)
            .await
            .expect_err("truncated TLS framing must not be reported as clean EOF");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn close_notify_is_clean_eof_and_key_update_is_explicitly_rejected() {
        let key = [0x31u8; 16];
        let iv = [0x42u8; 12];

        let (mut peer, inner) = tokio::io::duplex(256);
        let mut peer_crypto = RecordCrypto::new(&key, &iv);
        peer.write_all(&peer_crypto.encrypt(0x15, &[1, 0]).unwrap())
            .await
            .unwrap();
        let mut stream = RealTlsStream::from_crypto(
            inner,
            RecordCrypto::new(&key, &iv),
            RecordCrypto::new(&key, &iv),
        );
        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut byte))
                .await
                .expect("close_notify must not wait for transport EOF")
                .unwrap(),
            0
        );

        let (mut peer, inner) = tokio::io::duplex(256);
        let mut peer_crypto = RecordCrypto::new(&key, &iv);
        // Handshake type 0x18 (KeyUpdate), uint24 body length 1, request_update=0.
        peer.write_all(&peer_crypto.encrypt(0x16, &[0x18, 0, 0, 1, 0]).unwrap())
            .await
            .unwrap();
        let mut stream = RealTlsStream::from_crypto(
            inner,
            RecordCrypto::new(&key, &iv),
            RecordCrypto::new(&key, &iv),
        );
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("KeyUpdate rejection must not wait for another record")
            .expect_err("unsupported KeyUpdate must not be silently skipped");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    /// Wrap the realtls client's established session in `RealTlsStream` and talk to
    /// a real rustls server purely through the `AsyncRead + AsyncWrite` interface.
    #[tokio::test]
    async fn realtls_stream_interop_with_rustls() {
        let (mut client_io, server_io) = tokio::io::duplex(32 * 1024);
        let config = make_server_config("www.microsoft.com").expect("server config");
        let server = tokio::spawn(async move {
            let mut tls = terminate(Vec::new(), server_io, config)
                .await
                .expect("rustls accepts our ClientHello");
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.expect("read hello");
            assert_eq!(&buf, b"hello");
            tls.write_all(b"world!!").await.expect("write world");
            tls.flush().await.expect("flush");
        });

        let eph = Keypair::generate();
        let reality = StaticKeypair::generate();
        let sid = reality::seal_session_id(
            &reality.public,
            &eph,
            &reality::short_id_from_hex("0123456789abcdef"),
        );
        let est = client_handshake(&mut client_io, eph, sid, "www.microsoft.com")
            .await
            .expect("client handshake");

        let mut stream = RealTlsStream::new(client_io, est);
        stream.write_all(b"hello").await.expect("write hello");
        stream.flush().await.expect("flush");
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.expect("read world");
        assert_eq!(&buf, b"world!!");

        server.await.unwrap();
    }

    /// Larger payloads spanning multiple reads/records round-trip intact.
    #[tokio::test]
    async fn realtls_stream_bulk_roundtrip() {
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let config = make_server_config("www.microsoft.com").expect("server config");
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();
        let server = tokio::spawn(async move {
            let mut tls = terminate(Vec::new(), server_io, config).await.unwrap();
            let mut got = vec![0u8; expect.len()];
            tls.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expect);
            tls.write_all(&got).await.unwrap();
            tls.flush().await.unwrap();
        });

        let eph = Keypair::generate();
        let reality = StaticKeypair::generate();
        let sid =
            reality::seal_session_id(&reality.public, &eph, &reality::short_id_from_hex("aa"));
        let est = client_handshake(&mut client_io, eph, sid, "www.microsoft.com")
            .await
            .unwrap();
        let mut stream = RealTlsStream::new(client_io, est);
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut back = vec![0u8; payload.len()];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(back, payload);
        server.await.unwrap();
    }
}
