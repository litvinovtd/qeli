//! `obfs` wire mode — a polymorphic, structure-free transport obfuscation.
//!
//! Unlike `fake-tls` (which mimics a TLS 1.3 handshake), this mode XORs the
//! *entire* connection with a ChaCha20 keystream keyed by a pre-shared key. On
//! the wire there is no protocol structure at all — just a short random nonce
//! prelude followed by random-looking bytes. This is the right choice against
//! DPI that signatures *known* protocols (incl. fake-TLS / JA3); the trade-off
//! is that "looks like nothing" can itself be blocked by allow-list DPI.
//!
//! Keying: each side sends a random 12-byte nonce in the clear at connection
//! start, then derives its send keystream from `(psk, own_nonce)` and its
//! receive keystream from `(psk, peer_nonce)`. ChaCha20's seekable keystream
//! lets `poll_write` rewind on partial writes, so the transform is exact and
//! never desyncs.
//!
//! Limit: the IETF ChaCha20 keystream is 256 GiB per direction. If a single
//! session transfers more than that one way, `poll_write` returns an error and
//! the connection reconnects with a fresh nonce — fail-safe, never reusing
//! keystream. Document for very-high-volume long-lived links.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use sha2::{Digest, Sha256};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const NONCE_LEN: usize = 12;

/// Derive the 32-byte obfuscation key from the configured pre-shared key.
pub fn derive_obfs_key(psk: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"qeli-obfs-key-v1");
    h.update(psk.as_bytes());
    h.finalize().into()
}

fn cipher_from(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> ChaCha20 {
    ChaCha20::new_from_slices(key, nonce).expect("valid chacha20 key/nonce length")
}

/// WebSocket-Upgrade fronting for the `obfs` wire mode.
///
/// Plain `obfs` puts a high-entropy random nonce on the wire from byte 1 — exactly
/// the "fully encrypted traffic" shape that the GFW (Wu et al., USENIX'23) and the
/// Russian TSPU block via byte-distribution heuristics: a connection whose first
/// packet matches none of the exemptions (first 6 bytes printable / >50% printable
/// / >20-byte printable run) is classified as encrypted and dropped.
///
/// We prepend a real-looking WebSocket Upgrade handshake (printable HTTP text
/// terminated by `\r\n\r\n`) before the nonce exchange. The first packet is now
/// dominated by ASCII text → all three exemptions fire → it is let through. After
/// the `101 Switching Protocols` a binary stream is exactly what a real WebSocket
/// carries, so the remaining (random) bytes are unremarkable. The request is
/// randomised per connection (path / Host / key) so there is no static signature,
/// and the server computes a spec-correct `Sec-WebSocket-Accept` so the exchange
/// also survives a WebSocket-aware parser.
mod ws {
    use super::super::tls::DEFAULT_SNI_POOL;
    use base64::Engine;
    use rand::Rng;
    use std::io;
    use tokio::io::{AsyncRead, AsyncReadExt};

    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const MAX_HEAD: usize = 4096;

    /// A few realistic desktop browser User-Agents; one is picked per connection.
    const USER_AGENTS: &[&str] = &[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ];

    /// Minimal inline SHA-1 (RFC 3174). Used only to compute the
    /// `Sec-WebSocket-Accept` token — avoids pulling in a `sha1` crate dependency.
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [
            0x6745_2301,
            0xEFCD_AB89,
            0x98BA_DCFE,
            0x1032_5476,
            0xC3D2_E1F0,
        ];
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 80];
            for (i, word) in w.iter_mut().take(16).enumerate() {
                *word = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
            for (i, &wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                    _ => (b ^ c ^ d, 0xCA62_C1D6),
                };
                let tmp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = tmp;
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }
        let mut out = [0u8; 20];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    /// `Sec-WebSocket-Accept` for a client-supplied `Sec-WebSocket-Key` (RFC 6455).
    pub fn accept_token(ws_key: &str) -> String {
        let mut buf = ws_key.as_bytes().to_vec();
        buf.extend_from_slice(GUID.as_bytes());
        b64(&sha1(&buf))
    }

    /// Build a randomised WebSocket Upgrade request (the client's first bytes).
    pub fn build_request() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let host = DEFAULT_SNI_POOL[rng.gen_range(0..DEFAULT_SNI_POOL.len())];
        let ua = USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())];

        // Random URL path: '/' + 12..28 url-safe chars (keeps the request-line's
        // printable run well over the 20-byte FET exemption threshold).
        let path_len = rng.gen_range(12..=28);
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut path = String::with_capacity(1 + path_len);
        path.push('/');
        for _ in 0..path_len {
            path.push(ALPHABET[rng.gen_range(0..ALPHABET.len())] as char);
        }

        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce);
        let ws_key = b64(&nonce);

        format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: {ua}\r\n\
             Accept: */*\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {ws_key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        )
        .into_bytes()
    }

    /// Build the `101 Switching Protocols` response for a received request head.
    /// If the request carries a `Sec-WebSocket-Key`, the `Accept` is spec-correct;
    /// otherwise a random token is used (the exchange still looks like a WS upgrade).
    pub fn build_response(req_head: &[u8]) -> Vec<u8> {
        let accept = match header_value(req_head, "sec-websocket-key") {
            Some(k) => accept_token(&k),
            None => {
                let mut rng = rand::thread_rng();
                let mut r = [0u8; 20];
                rng.fill(&mut r);
                b64(&r)
            }
        };
        format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             \r\n"
        )
        .into_bytes()
    }

    /// Case-insensitive lookup of a header value in a raw HTTP head.
    fn header_value(head: &[u8], name_lower: &str) -> Option<String> {
        let text = String::from_utf8_lossy(head);
        for line in text.split("\r\n") {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case(name_lower) {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }

    /// Read an HTTP head (up to and including `\r\n\r\n`) from `inner`, bounded to
    /// [`MAX_HEAD`] bytes (anti-OOM). Reads one byte at a time — the head is a few
    /// hundred bytes and happens exactly once per connection.
    pub async fn read_head<S: AsyncRead + Unpin>(inner: &mut S) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            inner.read_exact(&mut byte).await?;
            buf.push(byte[0]);
            if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                return Ok(buf);
            }
            if buf.len() > MAX_HEAD {
                return Err(io::Error::other("obfs ws: handshake head too large"));
            }
        }
    }
}

// ── per-datagram obfs (UDP) ─────────────────────────────────────────────────
//
// UDP is message-oriented and lossy/reorderable, so the streaming TCP keystream
// (which must stay in lock-step) does not apply. Instead each datagram is
// self-contained: a fresh random 12-byte nonce prefix + `ChaCha20(key, nonce)`
// XOR of the payload. Stateless — a dropped/reordered datagram can't desync the
// rest. There is no nonce-exchange handshake (each datagram carries its own).

/// Seal one datagram: `[flag:1][nonce:12][ChaCha20(key,nonce) XOR payload]`.
///
/// The leading `flag` byte has the QUIC fixed bit (0x40) set and the long-header
/// bit (0x80) clear, so each datagram reads as a QUIC **short-header** packet
/// (`[flags][connection-id][protected payload]`) rather than a high-entropy
/// random blob from byte 0 — the 12-byte nonce doubles as a plausible QUIC
/// connection id (DPI-AUDIT tell 4.2). The flag's low bits are random (like a
/// real header after protection) and are ignored on open, so the two sides need
/// not agree on it.
pub fn obfs_datagram_seal(key: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let flag: u8 = 0x40 | (rand::random::<u8>() & 0x3f);
    let mut out = Vec::with_capacity(1 + NONCE_LEN + payload.len());
    out.push(flag);
    out.extend_from_slice(&nonce);
    let body_start = out.len();
    out.extend_from_slice(payload);
    cipher_from(key, &nonce).apply_keystream(&mut out[body_start..]);
    out
}

/// Open one sealed datagram, or `None` if it is too short / malformed.
pub fn obfs_datagram_open(key: &[u8; 32], datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() < 1 + NONCE_LEN {
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&datagram[1..1 + NONCE_LEN]); // [0] = QUIC-shaped flag byte
    let mut body = datagram[1 + NONCE_LEN..].to_vec();
    cipher_from(key, &nonce).apply_keystream(&mut body);
    Some(body)
}

/// A `tokio::net::UdpSocket` with transparent per-datagram obfs. When `key` is
/// `None` it is a pass-through, so the UDP data-plane code is written once and
/// works for both `fake-tls` and `obfs` wire modes. Mirrors the subset of the
/// socket API the handlers use (`send_to`/`recv_from` on the server, the
/// connected `send`/`recv` on the client).
pub struct ObfsUdp {
    sock: tokio::net::UdpSocket,
    key: Option<[u8; 32]>,
}

impl ObfsUdp {
    pub fn new(sock: tokio::net::UdpSocket, key: Option<[u8; 32]>) -> Self {
        Self { sock, key }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        let (n, addr) = self.sock.recv_from(buf).await?;
        match &self.key {
            Some(k) => match obfs_datagram_open(k, &buf[..n]) {
                Some(plain) => {
                    let m = plain.len().min(buf.len());
                    buf[..m].copy_from_slice(&plain[..m]);
                    Ok((m, addr)) // m may be < real len if buf too small (won't happen: payload<recv buf)
                }
                None => Ok((0, addr)), // malformed obfs frame → caller skips (n==0)
            },
            None => Ok((n, addr)),
        }
    }

    pub async fn send_to(&self, data: &[u8], addr: std::net::SocketAddr) -> io::Result<usize> {
        match &self.key {
            Some(k) => self.sock.send_to(&obfs_datagram_seal(k, data), addr).await,
            None => self.sock.send_to(data, addr).await,
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.sock.recv(buf).await?;
        match &self.key {
            Some(k) => match obfs_datagram_open(k, &buf[..n]) {
                Some(plain) => {
                    let m = plain.len().min(buf.len());
                    buf[..m].copy_from_slice(&plain[..m]);
                    Ok(m)
                }
                None => Ok(0),
            },
            None => Ok(n),
        }
    }

    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        match &self.key {
            Some(k) => self.sock.send(&obfs_datagram_seal(k, data)).await,
            None => self.sock.send(data).await,
        }
    }
}

fn seek_err(e: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("obfs keystream exhausted: {:?}", e))
}

/// XOR-obfuscated duplex stream used during the handshake phase.
pub struct ObfsStream<S> {
    inner: S,
    read_cipher: ChaCha20,
    write_cipher: ChaCha20,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ObfsStream<S> {
    /// Client side: send our nonce, read the server's, derive keystreams. When
    /// `fronting` is set, a WebSocket Upgrade handshake is performed first (see
    /// the [`ws`] module) so the connection's first bytes survive FET heuristics.
    pub async fn connect(mut inner: S, key: &[u8; 32], fronting: bool) -> io::Result<Self> {
        if fronting {
            inner.write_all(&ws::build_request()).await?;
            inner.flush().await?;
            let head = ws::read_head(&mut inner).await?;
            if !head.starts_with(b"HTTP/1.1 101") {
                return Err(io::Error::other("obfs ws: server did not switch protocols"));
            }
        }
        let mut local = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut local);
        inner.write_all(&local).await?;
        inner.flush().await?;
        let mut peer = [0u8; NONCE_LEN];
        inner.read_exact(&mut peer).await?;
        Ok(Self {
            read_cipher: cipher_from(key, &peer),
            write_cipher: cipher_from(key, &local),
            inner,
        })
    }

    /// Server side: read the client's nonce, send ours, derive keystreams. When
    /// `fronting` is set, the client's WebSocket Upgrade request is consumed and a
    /// spec-correct `101 Switching Protocols` is sent before the nonce exchange.
    pub async fn accept(mut inner: S, key: &[u8; 32], fronting: bool) -> io::Result<Self> {
        if fronting {
            let head = ws::read_head(&mut inner).await?;
            inner.write_all(&ws::build_response(&head)).await?;
            inner.flush().await?;
        }
        let mut peer = [0u8; NONCE_LEN];
        inner.read_exact(&mut peer).await?;
        let mut local = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut local);
        inner.write_all(&local).await?;
        inner.flush().await?;
        Ok(Self {
            read_cipher: cipher_from(key, &peer),
            write_cipher: cipher_from(key, &local),
            inner,
        })
    }
}

impl ObfsStream<TcpStream> {
    /// Split into independent halves for the reader-task / writer architecture.
    pub fn into_split(self) -> (ObfsReadHalf, ObfsWriteHalf) {
        let (r, w) = self.inner.into_split();
        (
            ObfsReadHalf {
                inner: r,
                cipher: self.read_cipher,
            },
            ObfsWriteHalf {
                inner: w,
                cipher: self.write_cipher,
            },
        )
    }
}

/// A duplex stream that can be split into owned read/write halves. Lets the
/// TCP data-plane code be generic over the plain (`fake-tls`) and `obfs` wire
/// modes without boxing.
pub trait SplitStream {
    type R: AsyncRead + Unpin + Send + 'static;
    type W: AsyncWrite + Unpin + Send + 'static;
    fn split_io(self) -> (Self::R, Self::W);
}

impl SplitStream for TcpStream {
    type R = OwnedReadHalf;
    type W = OwnedWriteHalf;
    fn split_io(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        self.into_split()
    }
}

impl SplitStream for ObfsStream<TcpStream> {
    type R = ObfsReadHalf;
    type W = ObfsWriteHalf;
    fn split_io(self) -> (ObfsReadHalf, ObfsWriteHalf) {
        self.into_split()
    }
}

/// XOR a freshly-read region of a `ReadBuf` in place.
fn read_xor<R: AsyncRead + Unpin>(
    inner: &mut R,
    cipher: &mut ChaCha20,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    let pre = buf.filled().len();
    ready!(Pin::new(inner).poll_read(cx, buf))?;
    let post = buf.filled().len();
    if post > pre {
        cipher.apply_keystream(&mut buf.filled_mut()[pre..post]);
    }
    Poll::Ready(Ok(()))
}

/// Encrypt `buf`, write what the socket accepts, and rewind the keystream to
/// match exactly the bytes written (so partial writes never desync).
fn write_xor<W: AsyncWrite + Unpin>(
    inner: &mut W,
    cipher: &mut ChaCha20,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }
    let pos: u64 = cipher.try_current_pos().map_err(seek_err)?;
    let mut tmp = buf.to_vec();
    cipher.apply_keystream(&mut tmp);
    match Pin::new(inner).poll_write(cx, &tmp) {
        Poll::Ready(Ok(n)) => {
            cipher.try_seek(pos + n as u64).map_err(seek_err)?;
            Poll::Ready(Ok(n))
        }
        Poll::Pending => {
            cipher.try_seek(pos).map_err(seek_err)?;
            Poll::Pending
        }
        Poll::Ready(Err(e)) => {
            let _ = cipher.try_seek(pos);
            Poll::Ready(Err(e))
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObfsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        read_xor(&mut this.inner, &mut this.read_cipher, cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        write_xor(&mut this.inner, &mut this.write_cipher, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Read half of a split [`ObfsStream`].
pub struct ObfsReadHalf {
    inner: OwnedReadHalf,
    cipher: ChaCha20,
}

impl AsyncRead for ObfsReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        read_xor(&mut this.inner, &mut this.cipher, cx, buf)
    }
}

/// Write half of a split [`ObfsStream`].
pub struct ObfsWriteHalf {
    inner: OwnedWriteHalf,
    cipher: ChaCha20,
}

impl AsyncWrite for ObfsWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        write_xor(&mut this.inner, &mut this.cipher, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_deterministic_and_psk_sensitive() {
        assert_eq!(derive_obfs_key("secret"), derive_obfs_key("secret"));
        assert_ne!(derive_obfs_key("secret"), derive_obfs_key("other"));
    }

    #[tokio::test]
    async fn obfs_roundtrip_over_duplex() {
        // Wire two ObfsStreams back-to-back via an in-memory duplex and confirm
        // the plaintext survives, while the bytes on the wire are not the
        // plaintext (i.e. actually obfuscated).
        let key = derive_obfs_key("test-psk");
        let (a, b) = tokio::io::duplex(64 * 1024);

        let key_c = key;
        let cli = tokio::spawn(async move {
            let mut s = ObfsStream::connect(a, &key_c, false).await.unwrap();
            s.write_all(b"hello-qeli-obfs").await.unwrap();
            s.flush().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            buf
        });

        let mut srv = ObfsStream::accept(b, &key, false).await.unwrap();
        let mut got = vec![0u8; 15];
        srv.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello-qeli-obfs");
        srv.write_all(b"world").await.unwrap();
        srv.flush().await.unwrap();

        assert_eq!(&cli.await.unwrap(), b"world");
    }

    #[test]
    fn udp_datagram_obfs_roundtrips_and_obscures() {
        let key = derive_obfs_key("udp-psk");
        let plain = b"the inner fake-tls record / AEAD packet bytes";
        let sealed = obfs_datagram_seal(&key, plain);
        // QUIC short-header shape: fixed bit set, long-header bit clear.
        assert_eq!(sealed[0] & 0xc0, 0x40);
        // wire bytes after flag+nonce are not the plaintext
        assert_ne!(&sealed[1 + NONCE_LEN..], &plain[..]);
        assert_eq!(sealed.len(), 1 + NONCE_LEN + plain.len());
        // round-trips
        assert_eq!(obfs_datagram_open(&key, &sealed).unwrap(), plain);
        // two seals of the same payload differ (fresh nonce each time)
        assert_ne!(
            obfs_datagram_seal(&key, plain),
            obfs_datagram_seal(&key, plain)
        );
        // wrong key => garbage (not the plaintext)
        assert_ne!(
            obfs_datagram_open(&derive_obfs_key("other"), &sealed).unwrap(),
            plain
        );
        // too-short frame rejected
        assert!(obfs_datagram_open(&key, &[0u8; 4]).is_none());
    }

    #[tokio::test]
    async fn wrong_psk_yields_garbage() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let kc = derive_obfs_key("psk-A");
        let cli = tokio::spawn(async move {
            let mut s = ObfsStream::connect(a, &kc, false).await.unwrap();
            s.write_all(b"plaintext-payload").await.unwrap();
            s.flush().await.unwrap();
        });
        let mut srv = ObfsStream::accept(b, &derive_obfs_key("psk-B"), false)
            .await
            .unwrap();
        let mut got = vec![0u8; 17];
        srv.read_exact(&mut got).await.unwrap();
        assert_ne!(
            &got, b"plaintext-payload",
            "mismatched PSK must not decrypt"
        );
        cli.await.unwrap();
    }

    /// RFC 6455 §1.3 worked example: the canonical key must map to the canonical
    /// accept token, proving the inline SHA-1 + base64 are correct.
    #[test]
    fn ws_accept_matches_rfc6455_vector() {
        assert_eq!(
            ws::accept_token("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// The client's first bytes (the WS Upgrade request) must satisfy at least one
    /// GFW "fully encrypted traffic" exemption so the connection is not dropped.
    /// We assert all three of the printable-based exemptions hold.
    #[test]
    fn ws_request_passes_fet_exemptions() {
        let printable = |b: u8| (0x20..=0x7e).contains(&b);
        for _ in 0..64 {
            let req = ws::build_request();
            // Ex2: first 6 bytes printable ("GET /x").
            assert!(
                req[..6].iter().all(|&b| printable(b)),
                "first 6 not printable"
            );
            // Ex3: >50% of bytes printable.
            let frac = req.iter().filter(|&&b| printable(b)).count() as f64 / req.len() as f64;
            assert!(frac > 0.5, "printable fraction {frac} <= 0.5");
            // Ex4: a contiguous printable run > 20.
            let mut run = 0usize;
            let mut max_run = 0usize;
            for &b in &req {
                if printable(b) {
                    run += 1;
                    max_run = max_run.max(run);
                } else {
                    run = 0;
                }
            }
            assert!(max_run > 20, "longest printable run {max_run} <= 20");
        }
    }

    #[tokio::test]
    async fn obfs_fronting_roundtrip() {
        // With fronting on both ends, the WS handshake completes and the obfs
        // payload still round-trips.
        let key = derive_obfs_key("front-psk");
        let (a, b) = tokio::io::duplex(64 * 1024);
        let kc = key;
        let cli = tokio::spawn(async move {
            let mut s = ObfsStream::connect(a, &kc, true).await.unwrap();
            s.write_all(b"fronted-payload").await.unwrap();
            s.flush().await.unwrap();
        });
        let mut srv = ObfsStream::accept(b, &key, true).await.unwrap();
        let mut got = vec![0u8; 15];
        srv.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"fronted-payload");
        cli.await.unwrap();
    }
}
