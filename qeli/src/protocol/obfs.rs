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
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const NONCE_LEN: usize = 12;

/// Hard caps for the AmneziaWG-style junk feature (F2), to bound memory.
const AWG_JC_CAP: u32 = 128;
const AWG_LEN_CAP: u16 = 1400;

/// Maximum WebSocket payload we emit per binary frame (F3). Reads still accept
/// the 8-byte extended-length form, but we never produce frames larger than this.
const WS_FRAME_MAX: usize = 16384;

/// AmneziaWG-style pre-handshake junk parameters (F2). Config-gated, OFF by
/// default. Both ends MUST agree on `jc` (the count of junk records exchanged);
/// `jmin`/`jmax` bound each record's random length and are sender-only.
#[derive(Clone, Copy, Debug)]
pub struct AwgParams {
    pub enabled: bool,
    pub jc: u32,
    pub jmin: u16,
    pub jmax: u16,
}

impl Default for AwgParams {
    fn default() -> Self {
        Self {
            enabled: false,
            jc: 0,
            jmin: 40,
            jmax: 300,
        }
    }
}

impl AwgParams {
    /// Effective junk-record count after applying the config gate and cap.
    /// Zero when disabled or `jc == 0` (→ byte-identical to the pre-F2 wire).
    /// `pub` so the UDP junk path (client/mod.rs) applies the identical gate/cap.
    pub fn effective_jc(&self) -> u32 {
        if self.enabled {
            self.jc.min(AWG_JC_CAP)
        } else {
            0
        }
    }

    /// Clamp the per-record length window into `[jmin, min(jmax, CAP)]`.
    /// `pub` so the UDP junk path reuses the identical clamp as the TCP obfs path.
    pub fn clamp_window(&self) -> (u16, u16) {
        let jmax = self.jmax.min(AWG_LEN_CAP);
        let jmin = self.jmin.min(jmax);
        (jmin, jmax)
    }
}

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

// ── WebSocket binary framing (F3) ───────────────────────────────────────────
//
// After the `101 Switching Protocols` handshake, the ENTIRE post-101 stream
// (junk, the nonce exchange, and all data) is carried as RFC-6455 binary frames
// (opcode 0x2, FIN=1). This is applied ONLY on the `fronting=websocket` path;
// when fronting is off the post-nonce stream stays a raw continuous ChaCha20-XOR
// exactly as before (regression-critical).
//
// Transform order (client→server): ChaCha20-XOR the plaintext FIRST, then apply
// the WS mask XOR on top of the ciphertext. server→client frames are unmasked
// (per RFC 6455). The ChaCha20 keystream is continuous over PAYLOAD bytes only.

/// Encode one RFC-6455 binary frame header for a payload of length `len`.
/// `mask`: `Some(4-byte key)` for client→server (MASK=1), `None` for server→client.
/// Returns the header bytes (frame = header ++ payload, where a masked payload is
/// XORed with the mask by the caller).
fn ws_frame_header(len: usize, mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(14);
    out.push(0x82); // FIN=1, opcode=0x2 (binary)
    let mask_bit: u8 = if mask.is_some() { 0x80 } else { 0x00 };
    if len <= 125 {
        out.push(mask_bit | (len as u8));
    } else if len <= 65535 {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if let Some(m) = mask {
        out.extend_from_slice(&m);
    }
    out
}

/// Wrap already-ciphered bytes into one or more WS binary frames, chunking the
/// payload into `<= WS_FRAME_MAX` slices. When `masked`, each frame gets a fresh
/// random 4-byte mask and the payload is `cipherbyte[i] ^ mask[i % 4]`.
fn ws_encode_frames(cipher_bytes: &[u8], masked: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(cipher_bytes.len() + 14);
    if cipher_bytes.is_empty() {
        return out;
    }
    let mut rng = rand::thread_rng();
    for chunk in cipher_bytes.chunks(WS_FRAME_MAX) {
        if masked {
            let mut mask = [0u8; 4];
            rng.fill(&mut mask);
            out.extend_from_slice(&ws_frame_header(chunk.len(), Some(mask)));
            for (i, &b) in chunk.iter().enumerate() {
                out.push(b ^ mask[i % 4]);
            }
        } else {
            out.extend_from_slice(&ws_frame_header(chunk.len(), None));
            out.extend_from_slice(chunk);
        }
    }
    out
}

/// Stateful reader-side reframer for the WS binary stream (F3). TCP can split a
/// frame header across reads or coalesce a frame tail with the next header, so
/// this buffers all unconsumed raw wire bytes and extracts whole frames on
/// demand. It keeps NO ChaCha20 state — the returned bytes are the UNMASKED
/// ciphertext, which the caller's read cipher decrypts (keystream continuous over
/// payload bytes only).
#[derive(Default)]
struct WsReframer {
    /// Raw wire bytes read but not yet parsed into completed frames.
    buf: Vec<u8>,
    /// Delivered (binary) payload bytes ready to hand to the caller.
    pending: Vec<u8>,
    /// Read cursor into `pending` (bytes before it were already returned).
    pending_off: usize,
}

impl WsReframer {
    /// Append newly-read raw wire bytes.
    fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to parse and consume ONE complete frame from `self.buf`. On success,
    /// binary-frame payloads are appended (unmasked) to `self.pending`; control /
    /// non-binary frames are consumed and discarded. Returns the outcome so callers
    /// can distinguish "consumed a binary frame" (even a zero-length one) from
    /// "consumed a control frame" and from "need more bytes".
    fn parse_one_frame(&mut self) -> io::Result<FrameParse> {
        if self.buf.len() < 2 {
            return Ok(FrameParse::NeedMore);
        }
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        let opcode = b0 & 0x0f;
        let masked = (b1 & 0x80) != 0;
        let len7 = (b1 & 0x7f) as usize;
        let mut off = 2usize;
        let payload_len: usize = if len7 == 126 {
            if self.buf.len() < off + 2 {
                return Ok(FrameParse::NeedMore);
            }
            let l = u16::from_be_bytes([self.buf[off], self.buf[off + 1]]) as usize;
            off += 2;
            l
        } else if len7 == 127 {
            if self.buf.len() < off + 8 {
                return Ok(FrameParse::NeedMore);
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(&self.buf[off..off + 8]);
            off += 8;
            u64::from_be_bytes(a) as usize
        } else {
            len7
        };
        if payload_len > WS_FRAME_MAX {
            return Err(io::Error::other("obfs ws: frame payload exceeds cap"));
        }
        let mut mask = [0u8; 4];
        if masked {
            if self.buf.len() < off + 4 {
                return Ok(FrameParse::NeedMore);
            }
            mask.copy_from_slice(&self.buf[off..off + 4]);
            off += 4;
        }
        if self.buf.len() < off + payload_len {
            return Ok(FrameParse::NeedMore); // full payload not yet buffered
        }
        // opcode 0x2 = binary (deliver); 0x0 continuation (deliver); others skip.
        let deliver = opcode == 0x2 || opcode == 0x0;
        if deliver {
            for (i, &b) in self.buf[off..off + payload_len].iter().enumerate() {
                let plain = if masked { b ^ mask[i % 4] } else { b };
                self.pending.push(plain);
            }
        }
        self.buf.drain(..off + payload_len);
        Ok(if deliver {
            FrameParse::Binary
        } else {
            FrameParse::Control
        })
    }

    /// Parse as many complete frames as are fully buffered.
    fn drain_frames(&mut self) -> io::Result<()> {
        while !matches!(self.parse_one_frame()?, FrameParse::NeedMore) {}
        Ok(())
    }

    /// Number of delivered payload bytes available to read.
    fn available(&self) -> usize {
        self.pending.len() - self.pending_off
    }

    /// Move up to `dst.len()` delivered payload bytes into `dst`; returns count.
    fn read_pending(&mut self, dst: &mut [u8]) -> usize {
        let n = self.available().min(dst.len());
        dst[..n].copy_from_slice(&self.pending[self.pending_off..self.pending_off + n]);
        self.pending_off += n;
        // Compact once fully drained to keep the buffer bounded.
        if self.pending_off == self.pending.len() {
            self.pending.clear();
            self.pending_off = 0;
        }
        n
    }

    /// Junk-phase helper: try to consume exactly ONE complete binary (delivered)
    /// frame from `self.buf`, discarding its payload. Returns `Ok(true)` if a
    /// binary frame was consumed (including a zero-length one). Non-binary/control
    /// frames are skipped without counting. `Ok(false)` means more bytes needed.
    fn try_discard_one_binary_frame(&mut self) -> io::Result<bool> {
        loop {
            match self.parse_one_frame()? {
                FrameParse::Binary => {
                    // Discard the delivered junk payload.
                    self.pending.clear();
                    self.pending_off = 0;
                    return Ok(true);
                }
                FrameParse::Control => continue, // skip, keep looking
                FrameParse::NeedMore => return Ok(false),
            }
        }
    }
}

/// Outcome of parsing one WS frame from the reframer buffer.
enum FrameParse {
    /// A binary (delivered) frame was consumed; its payload is in `pending`.
    Binary,
    /// A control / non-binary frame was consumed and discarded.
    Control,
    /// Not enough bytes buffered yet.
    NeedMore,
}

// ── AmneziaWG junk records (F2) ─────────────────────────────────────────────

/// Emit `jc` junk records on `inner` in the non-websocket wire form:
/// `[u16 BE len][len random bytes]`, `len` uniform in `[jmin, jmax]`.
async fn send_junk_raw<S: AsyncWrite + Unpin>(
    inner: &mut S,
    jc: u32,
    jmin: u16,
    jmax: u16,
) -> io::Result<()> {
    for _ in 0..jc {
        let len = {
            let mut rng = rand::thread_rng();
            if jmin >= jmax {
                jmin
            } else {
                rng.gen_range(jmin..=jmax)
            }
        } as usize;
        let mut rec = Vec::with_capacity(2 + len);
        rec.extend_from_slice(&(len as u16).to_be_bytes());
        let body_start = rec.len();
        rec.resize(body_start + len, 0);
        rand::thread_rng().fill(&mut rec[body_start..]);
        inner.write_all(&rec).await?;
    }
    if jc > 0 {
        inner.flush().await?;
    }
    Ok(())
}

/// Read and DISCARD exactly `jc` junk records in the non-websocket wire form.
async fn recv_junk_raw<S: AsyncRead + Unpin>(inner: &mut S, jc: u32) -> io::Result<()> {
    for _ in 0..jc {
        let mut lb = [0u8; 2];
        inner.read_exact(&mut lb).await?;
        let len = u16::from_be_bytes(lb);
        if len > AWG_LEN_CAP {
            return Err(io::Error::other("obfs awg: junk record exceeds cap"));
        }
        let mut sink = vec![0u8; len as usize];
        inner.read_exact(&mut sink).await?;
    }
    Ok(())
}

/// Emit `jc` junk records as WS binary frames (F3 form): each record is one WS
/// binary frame whose payload is `len` random bytes, `len` uniform in
/// `[jmin, jmax]`. `masked` selects client→server (true) vs server→client.
async fn send_junk_ws<S: AsyncWrite + Unpin>(
    inner: &mut S,
    jc: u32,
    jmin: u16,
    jmax: u16,
    masked: bool,
) -> io::Result<()> {
    for _ in 0..jc {
        let len = {
            let mut rng = rand::thread_rng();
            if jmin >= jmax {
                jmin
            } else {
                rng.gen_range(jmin..=jmax)
            }
        } as usize;
        let mut body = vec![0u8; len];
        rand::thread_rng().fill(&mut body[..]);
        // Junk is raw random bytes (no ChaCha20); it is framed like any WS binary
        // frame. The `cipherbyte` here is simply the random junk payload.
        let frame = ws_encode_frames(&body, masked);
        inner.write_all(&frame).await?;
    }
    if jc > 0 {
        inner.flush().await?;
    }
    Ok(())
}

/// Read and DISCARD exactly `jc` junk records carried as WS binary frames. Feeds
/// the shared [`WsReframer`] so a partial frame is buffered correctly; any wire
/// bytes read past the `jc`-th junk frame stay inside `reframer.buf` for the
/// caller's subsequent nonce / data reads (TCP may coalesce the last junk frame
/// with the following nonce/data frames — nothing is over-consumed).
async fn recv_junk_ws<S: AsyncRead + Unpin>(
    inner: &mut S,
    jc: u32,
    reframer: &mut WsReframer,
) -> io::Result<()> {
    // This runs BEFORE the nonce exchange / auth, and the server's accept path has no
    // outer timeout around the handshake — so bound what an unauthenticated peer can
    // impose here:
    //  * a wall-clock deadline, so a slowloris dribbling bytes can't pin the accept
    //    task open forever; and
    //  * a total-bytes budget, because control frames are skipped WITHOUT counting
    //    toward `jc` (try_discard_one_binary_frame) — a control-frame flood would
    //    otherwise loop reading indefinitely. `jc` binary frames + a little slack,
    //    each at most WS_FRAME_MAX payload plus a 14-byte max header.
    const JUNK_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
    let byte_budget = (jc as usize)
        .saturating_add(8)
        .saturating_mul(WS_FRAME_MAX + 14);
    let mut total_read = 0usize;
    let mut buf = [0u8; 2048];
    let mut discarded = 0u32;
    let deadline = tokio::time::sleep(JUNK_PHASE_TIMEOUT);
    tokio::pin!(deadline);
    // Discard exactly `jc` binary frames. The reframer buffers all raw bytes, so
    // any coalesced post-junk frame bytes stay in `reframer.buf` for the nonce /
    // data phase — nothing is over-consumed.
    while discarded < jc {
        // Consume any whole junk frames already buffered before reading more.
        while discarded < jc && reframer.try_discard_one_binary_frame()? {
            discarded += 1;
        }
        if discarded >= jc {
            break;
        }
        let n = tokio::select! {
            _ = &mut deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "obfs ws junk: handshake timed out",
                ));
            }
            r = inner.read(&mut buf) => r?,
        };
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        total_read = total_read.saturating_add(n);
        if total_read > byte_budget {
            return Err(io::Error::other("obfs ws junk: exceeded byte budget"));
        }
        reframer.feed(&buf[..n]);
    }
    Ok(())
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

/// Read the peer's 12-byte nonce over the WS-framed stream (F3): the peer sends
/// the raw nonce as a single WS binary frame (NOT ChaCha20-encrypted — no
/// keystream exists yet). Consumes only the nonce frame; any coalesced post-nonce
/// wire bytes remain buffered in `reframer` for the data phase.
async fn read_ws_nonce<S: AsyncRead + Unpin>(
    inner: &mut S,
    reframer: &mut WsReframer,
) -> io::Result<[u8; NONCE_LEN]> {
    let mut buf = [0u8; 512];
    loop {
        reframer.drain_frames()?;
        if reframer.available() >= NONCE_LEN {
            let mut nonce = [0u8; NONCE_LEN];
            let n = reframer.read_pending(&mut nonce);
            debug_assert_eq!(n, NONCE_LEN);
            return Ok(nonce);
        }
        let n = inner.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        reframer.feed(&buf[..n]);
    }
}

/// XOR-obfuscated duplex stream used during the handshake phase.
pub struct ObfsStream<S> {
    inner: S,
    read_cipher: ChaCha20,
    write_cipher: ChaCha20,
    /// When `Some`, the post-nonce stream is carried as RFC-6455 WS binary frames
    /// (F3, `fronting=websocket` only). `masked` = this side masks its writes
    /// (`true` = client→server). `None` = raw continuous ChaCha20-XOR (as before).
    ws: Option<WsState>,
}

/// Per-connection WebSocket binary-framing state (F3), present only on the
/// `fronting=websocket` path. `masked` selects the write direction's MASK bit;
/// `reframer` holds cross-read parsing state seeded with any bytes buffered
/// during the handshake.
struct WsState {
    masked: bool,
    reframer: WsReframer,
    /// Outbound framed bytes not yet fully written to the socket.
    out_buf: Vec<u8>,
    /// Write cursor into `out_buf`.
    out_off: usize,
    /// Plaintext byte count to report once `out_buf` is fully flushed.
    pending_plain: usize,
    /// Scratch buffer for socket reads before reframing.
    read_scratch: Vec<u8>,
}

impl WsState {
    fn new(masked: bool, reframer: WsReframer) -> Self {
        Self {
            masked,
            reframer,
            out_buf: Vec::new(),
            out_off: 0,
            pending_plain: 0,
            read_scratch: vec![0u8; WS_FRAME_MAX + 32],
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ObfsStream<S> {
    /// Client side: send our nonce, read the server's, derive keystreams. When
    /// `fronting` is set, a WebSocket Upgrade handshake is performed first (see
    /// the [`ws`] module) so the connection's first bytes survive FET heuristics.
    ///
    /// `awg` carries the AmneziaWG junk parameters (F2). When enabled with `jc>0`,
    /// `jc` junk records are exchanged immediately after the WS handshake (or after
    /// TCP connect when `fronting=false`) and before the nonce exchange. Both ends
    /// MUST be configured with the same `jc`.
    pub async fn connect(
        mut inner: S,
        key: &[u8; 32],
        fronting: bool,
        awg: AwgParams,
    ) -> io::Result<Self> {
        if fronting {
            inner.write_all(&ws::build_request()).await?;
            inner.flush().await?;
            let head = ws::read_head(&mut inner).await?;
            if !head.starts_with(b"HTTP/1.1 101") {
                return Err(io::Error::other("obfs ws: server did not switch protocols"));
            }
        }
        let jc = awg.effective_jc();
        let (jmin, jmax) = awg.clamp_window();
        let mut reframer = WsReframer::default();
        // F2: client is the sender first — emit jc junk, then discard jc junk.
        if jc > 0 {
            if fronting {
                send_junk_ws(&mut inner, jc, jmin, jmax, true).await?;
                recv_junk_ws(&mut inner, jc, &mut reframer).await?;
            } else {
                send_junk_raw(&mut inner, jc, jmin, jmax).await?;
                recv_junk_raw(&mut inner, jc).await?;
            }
        }

        let mut local = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut local);
        let peer: [u8; NONCE_LEN];
        if fronting {
            // Nonce carried as a WS binary frame (masked: client→server).
            inner.write_all(&ws_encode_frames(&local, true)).await?;
            inner.flush().await?;
            peer = read_ws_nonce(&mut inner, &mut reframer).await?;
        } else {
            inner.write_all(&local).await?;
            inner.flush().await?;
            let mut p = [0u8; NONCE_LEN];
            inner.read_exact(&mut p).await?;
            peer = p;
        }
        Ok(Self {
            read_cipher: cipher_from(key, &peer),
            write_cipher: cipher_from(key, &local),
            ws: fronting.then(|| WsState::new(true, reframer)),
            inner,
        })
    }

    /// Server side: read the client's nonce, send ours, derive keystreams. When
    /// `fronting` is set, the client's WebSocket Upgrade request is consumed and a
    /// spec-correct `101 Switching Protocols` is sent before the nonce exchange.
    /// `awg` mirrors [`connect`](Self::connect); the server discards `jc` junk
    /// records then emits `jc` of its own before the nonce exchange.
    pub async fn accept(
        mut inner: S,
        key: &[u8; 32],
        fronting: bool,
        awg: AwgParams,
    ) -> io::Result<Self> {
        if fronting {
            let head = ws::read_head(&mut inner).await?;
            inner.write_all(&ws::build_response(&head)).await?;
            inner.flush().await?;
        }
        let jc = awg.effective_jc();
        let (jmin, jmax) = awg.clamp_window();
        let mut reframer = WsReframer::default();
        // F2: server is the receiver first — discard jc junk, then emit jc junk.
        if jc > 0 {
            if fronting {
                recv_junk_ws(&mut inner, jc, &mut reframer).await?;
                send_junk_ws(&mut inner, jc, jmin, jmax, false).await?;
            } else {
                recv_junk_raw(&mut inner, jc).await?;
                send_junk_raw(&mut inner, jc, jmin, jmax).await?;
            }
        }

        let peer: [u8; NONCE_LEN];
        let mut local = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut local);
        if fronting {
            peer = read_ws_nonce(&mut inner, &mut reframer).await?;
            // Nonce carried as a WS binary frame (unmasked: server→client).
            inner.write_all(&ws_encode_frames(&local, false)).await?;
            inner.flush().await?;
        } else {
            let mut p = [0u8; NONCE_LEN];
            inner.read_exact(&mut p).await?;
            peer = p;
            inner.write_all(&local).await?;
            inner.flush().await?;
        }
        Ok(Self {
            read_cipher: cipher_from(key, &peer),
            write_cipher: cipher_from(key, &local),
            ws: fronting.then(|| WsState::new(false, reframer)),
            inner,
        })
    }
}

impl ObfsStream<TcpStream> {
    /// Split into independent halves for the reader-task / writer architecture.
    pub fn into_split(self) -> (ObfsReadHalf, ObfsWriteHalf) {
        let (r, w) = self.inner.into_split();
        // Partition the single WS state into read-side (reframer) and write-side
        // (mask + outbound buffer). Present only on the ws-fronting path.
        let (ws_read, ws_write) = match self.ws {
            Some(st) => (
                Some(WsReadState {
                    reframer: st.reframer,
                    read_scratch: st.read_scratch,
                }),
                Some(WsWriteState {
                    masked: st.masked,
                    out_buf: st.out_buf,
                    out_off: st.out_off,
                    pending_plain: st.pending_plain,
                }),
            ),
            None => (None, None),
        };
        (
            ObfsReadHalf {
                inner: r,
                cipher: self.read_cipher,
                ws: ws_read,
            },
            ObfsWriteHalf {
                inner: w,
                cipher: self.write_cipher,
                ws: ws_write,
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

/// XOR a freshly-read region of a `ReadBuf` in place (raw, non-WS path).
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
/// match exactly the bytes written (so partial writes never desync). Raw
/// (non-WS) path only.
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

/// Read-side WS state carried by [`ObfsReadHalf`] / [`ObfsStream`] on the
/// `fronting=websocket` path.
struct WsReadState {
    reframer: WsReframer,
    read_scratch: Vec<u8>,
}

/// Write-side WS state carried by [`ObfsWriteHalf`] / [`ObfsStream`] on the
/// `fronting=websocket` path.
struct WsWriteState {
    masked: bool,
    out_buf: Vec<u8>,
    out_off: usize,
    pending_plain: usize,
}

/// WS-framed read (F3): decode complete binary frames buffered in the reframer,
/// ChaCha20-decrypt their (unmasked) ciphertext payload into `buf`. When nothing
/// is buffered, read more raw wire bytes and reframe. Keystream is continuous
/// over payload bytes only.
fn ws_read<R: AsyncRead + Unpin>(
    inner: &mut R,
    cipher: &mut ChaCha20,
    ws: &mut WsReadState,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    loop {
        ws.reframer.drain_frames()?;
        if ws.reframer.available() > 0 && buf.remaining() > 0 {
            let want = ws.reframer.available().min(buf.remaining());
            let mut tmp = vec![0u8; want];
            let n = ws.reframer.read_pending(&mut tmp);
            cipher.apply_keystream(&mut tmp[..n]);
            buf.put_slice(&tmp[..n]);
            return Poll::Ready(Ok(()));
        }
        // Need more wire bytes.
        let mut rb = ReadBuf::new(&mut ws.read_scratch);
        ready!(Pin::new(&mut *inner).poll_read(cx, &mut rb))?;
        let filled = rb.filled().len();
        if filled == 0 {
            // EOF from the socket. If nothing is pending, signal EOF (empty read).
            return Poll::Ready(Ok(()));
        }
        let bytes = rb.filled().to_vec();
        ws.reframer.feed(&bytes);
    }
}

/// WS-framed write (F3): ChaCha20-encrypt `buf`, wrap into binary frames, and
/// stream them to the socket. Only accepts new plaintext when the previous
/// frame batch has been fully flushed, so the keystream advances exactly once
/// per accepted plaintext (no rewind needed).
fn ws_write<W: AsyncWrite + Unpin>(
    inner: &mut W,
    cipher: &mut ChaCha20,
    ws: &mut WsWriteState,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    // Drain any outstanding framed bytes first.
    if ws.out_off < ws.out_buf.len() {
        match Pin::new(&mut *inner).poll_write(cx, &ws.out_buf[ws.out_off..]) {
            Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Poll::Ready(Ok(n)) => {
                ws.out_off += n;
                if ws.out_off < ws.out_buf.len() {
                    return Poll::Pending;
                }
            }
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
        // Fully flushed — report the plaintext bytes committed earlier.
        ws.out_buf.clear();
        ws.out_off = 0;
        let done = ws.pending_plain;
        ws.pending_plain = 0;
        return Poll::Ready(Ok(done));
    }

    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }
    // Commit to buffering the whole plaintext: cipher once, then frame.
    let mut cipher_bytes = buf.to_vec();
    cipher.apply_keystream(&mut cipher_bytes);
    ws.out_buf = ws_encode_frames(&cipher_bytes, ws.masked);
    ws.out_off = 0;
    ws.pending_plain = buf.len();

    match Pin::new(&mut *inner).poll_write(cx, &ws.out_buf) {
        Poll::Ready(Ok(0)) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
        Poll::Ready(Ok(n)) => {
            ws.out_off = n;
            if ws.out_off < ws.out_buf.len() {
                // Partial: keep the rest buffered; report Pending. The keystream
                // has already advanced over the whole plaintext (committed).
                Poll::Pending
            } else {
                ws.out_buf.clear();
                ws.out_off = 0;
                let done = ws.pending_plain;
                ws.pending_plain = 0;
                Poll::Ready(Ok(done))
            }
        }
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObfsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.ws {
            Some(st) => {
                let mut rs = WsReadState {
                    reframer: std::mem::take(&mut st.reframer),
                    read_scratch: std::mem::take(&mut st.read_scratch),
                };
                let r = ws_read(&mut this.inner, &mut this.read_cipher, &mut rs, cx, buf);
                st.reframer = rs.reframer;
                st.read_scratch = rs.read_scratch;
                r
            }
            None => read_xor(&mut this.inner, &mut this.read_cipher, cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.ws {
            Some(st) => {
                let mut ws = WsWriteState {
                    masked: st.masked,
                    out_buf: std::mem::take(&mut st.out_buf),
                    out_off: st.out_off,
                    pending_plain: st.pending_plain,
                };
                let r = ws_write(&mut this.inner, &mut this.write_cipher, &mut ws, cx, buf);
                st.out_buf = ws.out_buf;
                st.out_off = ws.out_off;
                st.pending_plain = ws.pending_plain;
                r
            }
            None => write_xor(&mut this.inner, &mut this.write_cipher, cx, buf),
        }
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
    ws: Option<WsReadState>,
}

impl AsyncRead for ObfsReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.ws {
            Some(st) => ws_read(&mut this.inner, &mut this.cipher, st, cx, buf),
            None => read_xor(&mut this.inner, &mut this.cipher, cx, buf),
        }
    }
}

/// Write half of a split [`ObfsStream`].
pub struct ObfsWriteHalf {
    inner: OwnedWriteHalf,
    cipher: ChaCha20,
    ws: Option<WsWriteState>,
}

impl AsyncWrite for ObfsWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.ws {
            Some(st) => ws_write(&mut this.inner, &mut this.cipher, st, cx, buf),
            None => write_xor(&mut this.inner, &mut this.cipher, cx, buf),
        }
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
            let mut s = ObfsStream::connect(a, &key_c, false, AwgParams::default())
                .await
                .unwrap();
            s.write_all(b"hello-qeli-obfs").await.unwrap();
            s.flush().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            buf
        });

        let mut srv = ObfsStream::accept(b, &key, false, AwgParams::default())
            .await
            .unwrap();
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
            let mut s = ObfsStream::connect(a, &kc, false, AwgParams::default())
                .await
                .unwrap();
            s.write_all(b"plaintext-payload").await.unwrap();
            s.flush().await.unwrap();
        });
        let mut srv = ObfsStream::accept(b, &derive_obfs_key("psk-B"), false, AwgParams::default())
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
            let mut s = ObfsStream::connect(a, &kc, true, AwgParams::default())
                .await
                .unwrap();
            s.write_all(b"fronted-payload").await.unwrap();
            s.flush().await.unwrap();
        });
        let mut srv = ObfsStream::accept(b, &key, true, AwgParams::default())
            .await
            .unwrap();
        let mut got = vec![0u8; 15];
        srv.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"fronted-payload");
        cli.await.unwrap();
    }

    // ── F3: WebSocket binary-framing tests ───────────────────────────────────

    /// MANDATORY cross-language vector (F3 masking layer): post-cipher bytes
    /// `[0x01,0x02,0x03]` with mask `[0xAA,0xBB,0xCC,0xDD]` MUST emit exactly
    /// `[0x82,0x83,0xAA,0xBB,0xCC,0xDD,0xAB,0xB9,0xCF]`. Built by hand (not via
    /// `ws_encode_frames`, which uses a random mask) to pin the wire byte-for-byte.
    #[test]
    fn ws_masking_vector_matches_spec() {
        let cipher_bytes = [0x01u8, 0x02, 0x03];
        let mask = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let mut frame = ws_frame_header(cipher_bytes.len(), Some(mask));
        for (i, &b) in cipher_bytes.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        assert_eq!(
            frame,
            vec![0x82, 0x83, 0xAA, 0xBB, 0xCC, 0xDD, 0xAB, 0xB9, 0xCF]
        );
    }

    /// The header encoder must pick the correct length form (7-bit / 16-bit /
    /// 64-bit) and set the MASK bit only when a mask is supplied.
    #[test]
    fn ws_frame_header_length_forms() {
        // <=125 → single length byte, no mask.
        assert_eq!(ws_frame_header(5, None), vec![0x82, 0x05]);
        // masked small.
        let h = ws_frame_header(5, Some([1, 2, 3, 4]));
        assert_eq!(h, vec![0x82, 0x85, 1, 2, 3, 4]);
        // 126..=65535 → 126 + u16 BE.
        assert_eq!(ws_frame_header(200, None), vec![0x82, 126, 0x00, 0xC8]);
        // >65535 → 127 + u64 BE (read-only path; writer caps at WS_FRAME_MAX).
        assert_eq!(
            ws_frame_header(70000, None),
            vec![0x82, 127, 0, 0, 0, 0, 0, 0x01, 0x11, 0x70]
        );
    }

    /// A WS binary stream must round-trip through the stateful [`WsReframer`] even
    /// when the wire is delivered ONE BYTE AT A TIME (adversarial chunking that
    /// splits every frame header across reads).
    #[test]
    fn ws_reframer_roundtrip_byte_at_a_time() {
        // Two masked frames carrying known payloads.
        let p1 = b"the-first-frame-payload".to_vec();
        let p2 = vec![0x00u8, 0xFF, 0x10, 0x20, 0x30, 0x40];
        let mut wire = ws_encode_frames(&p1, true);
        wire.extend_from_slice(&ws_encode_frames(&p2, true));

        let mut rf = WsReframer::default();
        for b in &wire {
            rf.feed(std::slice::from_ref(b));
            rf.drain_frames().unwrap();
        }
        let mut out = vec![0u8; p1.len() + p2.len()];
        let n = rf.read_pending(&mut out);
        assert_eq!(n, p1.len() + p2.len());
        let mut expect = p1.clone();
        expect.extend_from_slice(&p2);
        assert_eq!(out, expect);
    }

    /// Unmasked (server→client) frames round-trip too, and coalesced reads (a
    /// whole multi-frame batch delivered in one `feed`) are handled.
    #[test]
    fn ws_reframer_unmasked_and_coalesced() {
        let p = b"server-to-client-unmasked".to_vec();
        let wire = ws_encode_frames(&p, false);
        // Server→client frames carry no mask bytes.
        assert_eq!(wire[1] & 0x80, 0, "server frame must not set MASK bit");
        let mut rf = WsReframer::default();
        rf.feed(&wire);
        rf.drain_frames().unwrap();
        let mut out = vec![0u8; p.len()];
        assert_eq!(rf.read_pending(&mut out), p.len());
        assert_eq!(out, p);
    }

    /// End-to-end fronted round-trip over the WS-framed data plane, with a large
    /// payload that forces multi-frame chunking (`> WS_FRAME_MAX`).
    #[tokio::test]
    async fn ws_fronting_large_payload_roundtrip() {
        let key = derive_obfs_key("ws-big-psk");
        let (a, b) = tokio::io::duplex(1024 * 1024);
        let payload: Vec<u8> = (0..(WS_FRAME_MAX * 2 + 777) as u32)
            .map(|i| (i % 251) as u8)
            .collect();
        let expect = payload.clone();
        let kc = key;
        let cli = tokio::spawn(async move {
            let mut s = ObfsStream::connect(a, &kc, true, AwgParams::default())
                .await
                .unwrap();
            s.write_all(&payload).await.unwrap();
            s.flush().await.unwrap();
        });
        let mut srv = ObfsStream::accept(b, &key, true, AwgParams::default())
            .await
            .unwrap();
        let mut got = vec![0u8; expect.len()];
        srv.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expect);
        cli.await.unwrap();
    }

    // ── F2: AmneziaWG junk tests ─────────────────────────────────────────────

    /// Non-websocket junk round-trip: with `jc>0`, the sender emits `jc`
    /// `[u16 len][bytes]` junk records and the receiver discards exactly `jc`,
    /// after which the real payload still round-trips.
    #[tokio::test]
    async fn awg_junk_roundtrip_raw() {
        let key = derive_obfs_key("awg-raw-psk");
        let (a, b) = tokio::io::duplex(256 * 1024);
        let awg = AwgParams {
            enabled: true,
            jc: 5,
            jmin: 40,
            jmax: 300,
        };
        let kc = key;
        let cli = tokio::spawn(async move {
            let mut s = ObfsStream::connect(a, &kc, false, awg).await.unwrap();
            s.write_all(b"post-junk-raw-payload").await.unwrap();
            s.flush().await.unwrap();
        });
        let mut srv = ObfsStream::accept(b, &key, false, awg).await.unwrap();
        let mut got = vec![0u8; 21];
        srv.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"post-junk-raw-payload");
        cli.await.unwrap();
    }

    /// Junk over the websocket path: junk records are WS binary frames, discarded
    /// by count, then the payload round-trips through the WS data plane.
    #[tokio::test]
    async fn awg_junk_roundtrip_ws() {
        let key = derive_obfs_key("awg-ws-psk");
        let (a, b) = tokio::io::duplex(256 * 1024);
        let awg = AwgParams {
            enabled: true,
            jc: 7,
            jmin: 40,
            jmax: 300,
        };
        let kc = key;
        let cli = tokio::spawn(async move {
            let mut s = ObfsStream::connect(a, &kc, true, awg).await.unwrap();
            s.write_all(b"post-junk-ws-payload").await.unwrap();
            s.flush().await.unwrap();
        });
        let mut srv = ObfsStream::accept(b, &key, true, awg).await.unwrap();
        let mut got = vec![0u8; 20];
        srv.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"post-junk-ws-payload");
        cli.await.unwrap();
    }

    /// REGRESSION GUARD: `jc=0` + `fronting=none` must be byte-identical to the
    /// pre-F2/F3 wire. We capture the exact wire bytes a sender emits for a fixed
    /// payload with `AwgParams::default()` (disabled) and assert no junk / no WS
    /// framing was added — i.e. the wire is exactly `nonce(12) ++ ChaCha20(payload)`.
    #[tokio::test]
    async fn jc0_no_fronting_wire_unchanged() {
        let key = derive_obfs_key("regress-psk");
        // Client half writes into a duplex whose other end we read raw off the wire.
        let (a, mut wire) = tokio::io::duplex(64 * 1024);
        let kc = key;
        let cli = tokio::spawn(async move {
            // Server side of the nonce exchange: feed a server nonce so connect()
            // completes, then observe what the client put on the wire.
            let mut s = ObfsStream::connect(a, &kc, false, AwgParams::default())
                .await
                .unwrap();
            s.write_all(b"REGRESSION").await.unwrap();
            s.flush().await.unwrap();
        });

        // Read client nonce (12 raw bytes — no junk, no WS frame).
        let mut client_nonce = [0u8; NONCE_LEN];
        wire.read_exact(&mut client_nonce).await.unwrap();
        // Send a fixed server nonce back so the client derives keystreams.
        let server_nonce = [7u8; NONCE_LEN];
        wire.write_all(&server_nonce).await.unwrap();
        wire.flush().await.unwrap();

        // Next 10 wire bytes must be exactly ChaCha20(key, client_nonce) XOR payload
        // with NO framing/junk overhead.
        let mut body = [0u8; 10];
        wire.read_exact(&mut body).await.unwrap();
        let mut expect = b"REGRESSION".to_vec();
        cipher_from(&key, &client_nonce).apply_keystream(&mut expect);
        assert_eq!(&body, expect.as_slice(), "jc=0/no-fronting wire changed");
        cli.await.unwrap();
    }

    /// The junk-length window is enforced: a `jmax` above the 1400 cap is clamped,
    /// and `jc` above 128 is capped, so memory stays bounded regardless of config.
    #[test]
    fn awg_caps_are_enforced() {
        let a = AwgParams {
            enabled: true,
            jc: 10_000,
            jmin: 40,
            jmax: 9_000,
        };
        assert_eq!(a.effective_jc(), AWG_JC_CAP);
        let (jmin, jmax) = a.clamp_window();
        assert_eq!(jmax, AWG_LEN_CAP);
        assert!(jmin <= jmax);
        // Disabled → zero effective junk regardless of jc.
        let d = AwgParams {
            enabled: false,
            jc: 50,
            ..AwgParams::default()
        };
        assert_eq!(d.effective_jc(), 0);
    }
}
