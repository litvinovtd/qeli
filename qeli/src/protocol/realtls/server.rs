//! M3 — server-side TLS 1.3 termination for REALITY, via `rustls`.
//!
//! The REALITY detector must read the ClientHello first (to open the token from
//! `session_id`), but `rustls` also needs to read that ClientHello to drive the
//! handshake. So the detector buffers the ClientHello and we **replay** it into
//! rustls through [`PrefixedStream`]: rustls sees the buffered bytes first, then
//! continues from the live socket. For "our" clients this terminates a genuine
//! TLS session that the qeli tunnel then runs inside; "foreign"/prober traffic is
//! proxied elsewhere (unchanged).

// M3 building block: wired into `server/reality.rs` in the next step.
#![allow(dead_code)]

use super::client::{parse_server_hello, read_record, u24};
use super::keyschedule::{
    client_application_traffic_secret, client_handshake_traffic_secret, early_secret, finished_key,
    finished_verify, handshake_secret, master_secret, server_application_traffic_secret,
    server_handshake_traffic_secret, traffic_keys, transcript_hash, Suite,
};
use super::record::RecordCrypto;
use super::stream::RealTlsStream;
use crate::crypto::{mlkem, Keypair, PublicKey};
use crate::protocol::obfs::SplitStream;
use crate::protocol::FakeTlsHandshake;
use rustls::ServerConfig;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// A stream that yields a fixed prefix (the buffered ClientHello) before
/// delegating to the inner stream. Writes go straight to the inner stream.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.pos < me.prefix.len() {
            let remaining = &me.prefix[me.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            me.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, b)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Build a rustls server config for REALITY termination: TLS 1.3 only,
/// AES-128-GCM only (matching the client's record layer), no client auth, with an
/// on-the-fly self-signed certificate for `sni` (the client does not validate it;
/// trust is via X25519 + the inner qeli auth). Emits a couple of post-handshake
/// NewSessionTickets like a real TLS 1.3 server (a server that sends none is itself
/// a fingerprint tell); the qeli client does not resume and simply skips them.
/// Generate once and reuse.
pub fn make_server_config(sni: &str) -> Arc<ServerConfig> {
    let gen =
        rcgen::generate_simple_self_signed(vec![sni.to_string()]).expect("self-signed cert gen");
    let cert = gen.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        gen.signing_key.serialize_der(),
    ));

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];

    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("valid cert/key");
    // A real TLS 1.3 server sends post-handshake NewSessionTickets; sending zero
    // is a tell. The client never resumes (it skips post-handshake records), so
    // tickets are transparent to it.
    config.ticketer = rustls::crypto::ring::Ticketer::new().expect("ticketer");
    config.send_tls13_tickets = 2;
    Arc::new(config)
}

/// Terminate TLS for an "our" REALITY client: replay the buffered `client_hello`
/// into rustls, then complete the handshake. The returned stream carries
/// application data (the qeli tunnel runs inside it).
pub async fn terminate<S>(
    client_hello: Vec<u8>,
    stream: S,
    config: Arc<ServerConfig>,
) -> io::Result<TlsStream<PrefixedStream<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    TlsAcceptor::from(config)
        .accept(PrefixedStream::new(client_hello, stream))
        .await
}

/// Owned read/write halves so `handler::handle_client` can run the tunnel inside
/// the terminated TLS session (mirrors the `TcpStream`/`ObfsStream` impls).
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> SplitStream for TlsStream<S> {
    type R = ReadHalf<TlsStream<S>>;
    type W = WriteHalf<TlsStream<S>>;
    fn split_io(self) -> (Self::R, Self::W) {
        tokio::io::split(self)
    }
}

// ── Hand-rolled REALITY server handshake (P3, step 1) ────────────────────────
//
// A byte-grade TLS 1.3 server that mirrors `realtls::client::client_handshake`,
// so the qeli tunnel runs inside a genuine TLS session we control end-to-end —
// the prerequisite for borrowing the target's ServerHello (next step), which
// `rustls` cannot do. Step 1 still self-generates the ServerHello; the borrow
// (capture target's ServerHello, swap in our key_share) lands on top of this.

fn ierr(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn hs_msg(mtype: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![mtype, 0, 0, 0];
    m.extend_from_slice(body);
    let l = m.len() - 4;
    m[1] = (l >> 16) as u8;
    m[2] = (l >> 8) as u8;
    m[3] = l as u8;
    m
}

/// A plausible post-handshake NewSessionTicket (RFC 8446 §4.6.1). The client never
/// resumes (it skips post-handshake handshake records), so the ticket body is
/// opaque random — its only purpose is to make the hand-rolled server look like a
/// real TLS 1.3 server, which emits 1-2 tickets right after the handshake.
fn build_new_session_ticket() -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(&7200u32.to_be_bytes()); // ticket_lifetime: 2h
    body.extend_from_slice(&rng.next_u32().to_be_bytes()); // ticket_age_add
    let mut nonce = [0u8; 8];
    rng.fill_bytes(&mut nonce);
    body.push(nonce.len() as u8); // ticket_nonce<0..255>
    body.extend_from_slice(&nonce);
    let mut ticket = [0u8; 48];
    rng.fill_bytes(&mut ticket);
    body.extend_from_slice(&(ticket.len() as u16).to_be_bytes()); // ticket<1..2^16-1>
    body.extend_from_slice(&ticket);
    body.extend_from_slice(&[0x00, 0x00]); // extensions<0..2^16-2>: empty
    hs_msg(0x04, &body)
}

/// Extract the client's key_exchange bytes for a given supported-group from a
/// ClientHello record (5-byte TLS header included), or `None` if absent.
fn extract_client_key_share(ch_record: &[u8], group: u16) -> Option<Vec<u8>> {
    let inner = ch_record.get(5..)?;
    if inner.len() < 39 || inner[0] != 0x01 {
        return None;
    }
    let sid_len = *inner.get(38)? as usize;
    let mut o = 39 + sid_len;
    let cs_len = u16::from_be_bytes([*inner.get(o)?, *inner.get(o + 1)?]) as usize;
    o += 2 + cs_len;
    let comp_len = *inner.get(o)? as usize;
    o += 1 + comp_len;
    let ext_total = u16::from_be_bytes([*inner.get(o)?, *inner.get(o + 1)?]) as usize;
    o += 2;
    let ext_end = (o + ext_total).min(inner.len());
    while o + 4 <= ext_end {
        let et = u16::from_be_bytes([inner[o], inner[o + 1]]);
        let el = u16::from_be_bytes([inner[o + 2], inner[o + 3]]) as usize;
        o += 4;
        if o + el > ext_end {
            break;
        }
        if et == 0x0033 && el >= 2 {
            let shares_len = u16::from_be_bytes([inner[o], inner[o + 1]]) as usize;
            let shares_end = (o + 2 + shares_len).min(o + el);
            let mut q = o + 2;
            while q + 4 <= shares_end {
                let g = u16::from_be_bytes([inner[q], inner[q + 1]]);
                let klen = u16::from_be_bytes([inner[q + 2], inner[q + 3]]) as usize;
                q += 4;
                if q + klen > shares_end {
                    break;
                }
                if g == group {
                    return Some(inner[q..q + klen].to_vec());
                }
                q += klen;
            }
        }
        o += el;
    }
    None
}

/// Established TLS 1.3 server connection: application-data record protection per
/// direction. `send` protects server→client, `recv` opens client→server.
pub struct EstablishedServerTls {
    pub send: RecordCrypto,
    pub recv: RecordCrypto,
}

/// The TLS-shape fingerprint of the borrowed target's ServerHello: which cipher
/// suite it picks, whether it negotiates the post-quantum group, and whether it
/// lists `key_share` before `supported_versions`. The hand-rolled server mirrors
/// these so its ServerHello's JA3S matches the target — and these differ per host
/// (microsoft: 0x1302/no-PQ/[sv,ks]; amazon: 0x1301/PQ/[sv,ks]; cloudflare:
/// 0x1301/PQ/[ks,sv]). Probed once per profile via [`probe_borrow_profile`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BorrowProfile {
    pub suite: Suite,
    pub prefer_pq: bool,
    pub key_share_first: bool,
}

impl Default for BorrowProfile {
    /// www.microsoft.com's shape — used when a target probe is unavailable.
    fn default() -> Self {
        BorrowProfile {
            suite: Suite::Aes256Sha384,
            prefer_pq: false,
            key_share_first: false,
        }
    }
}

/// Per-profile borrowed REALITY state: the target's ServerHello shape (mirrored on
/// the wire → JA3S) plus its real Certificate chain (presented to our clients).
/// Held behind a lock so a periodic refresh task can update it as the target
/// rotates. NB only the shape is observable on the wire (ServerHello is plaintext);
/// the borrowed cert rides inside the encrypted TLS 1.3 flight.
pub struct BorrowState {
    pub profile: BorrowProfile,
    pub cert: Option<Vec<u8>>,
}

/// Connect to the borrowed `target:port`, send a Chrome-grade ClientHello, read its
/// ServerHello to learn the shape the hand-rolled server must mirror (cipher, PQ
/// group, extension order), AND continue the handshake far enough to capture the
/// target's real Certificate chain (REALITY cert-borrowing). Returns the shape plus
/// the captured Certificate message body (`None` if it could not be captured — the
/// caller then falls back to a self-signed/dummy cert). A target probe error
/// (unreachable / unimplemented cipher) lets the caller fall back to a default shape.
pub async fn probe_borrow_profile(
    target_host: &str,
    target_port: u16,
) -> io::Result<(BorrowProfile, Option<Vec<u8>>)> {
    let addr = format!("{target_host}:{target_port}");
    let mut stream = tokio::net::TcpStream::connect(&addr).await?;
    let eph = Keypair::generate();
    let sid: [u8; 32] = rand::random();
    let (ch, mlkem_dk) = super::clienthello::build_client_hello(eph.public(), target_host, &sid);
    stream.write_all(&ch).await?;
    stream.flush().await?;
    let sh = loop {
        let (ct, rec) = read_record(&mut stream).await?;
        match ct {
            0x14 => continue, // skip a TLS 1.2 ChangeCipherSpec
            0x16 => break rec,
            0x15 => return Err(ierr("target sent a TLS alert")),
            _ => return Err(ierr("unexpected record from target")),
        }
    };
    let profile = parse_borrow_profile(&sh[5..])?;
    let cert = capture_target_cert(&mut stream, &ch, &sh, &eph, &mlkem_dk)
        .await
        .ok()
        .flatten();
    Ok((profile, cert))
}

/// Continue the (CH-sent / SH-read) handshake against the target far enough to
/// decrypt the encrypted flight and lift its Certificate message **body** (for
/// REALITY cert-borrowing). Mirrors the client flight crypto; best-effort — any
/// hiccup yields `Ok(None)`. Runs once per profile start, so it is not perf-critical.
async fn capture_target_cert<S: AsyncRead + Unpin>(
    stream: &mut S,
    ch: &[u8],
    sh: &[u8],
    eph: &Keypair,
    mlkem_dk: &mlkem::DecapKey,
) -> io::Result<Option<Vec<u8>>> {
    let (suite, group, server_ks) = parse_server_hello(&sh[5..])?;
    // (EC)DHE shared secret per the group the target negotiated.
    let ecdhe: Vec<u8> = match group {
        0x001d => {
            let sp = PublicKey::from_bytes(
                &<[u8; 32]>::try_from(server_ks.as_slice()).map_err(|_| ierr("x25519 ks"))?,
            );
            eph.derive_shared(&sp).as_bytes().to_vec()
        }
        g if g == mlkem::X25519MLKEM768 => {
            if server_ks.len() != mlkem::MLKEM768_CT_LEN + 32 {
                return Ok(None);
            }
            let ml = mlkem::mlkem768_decapsulate(mlkem_dk, &server_ks[..mlkem::MLKEM768_CT_LEN])
                .ok_or_else(|| ierr("ml-kem decap"))?;
            let sp = PublicKey::from_bytes(
                &<[u8; 32]>::try_from(&server_ks[mlkem::MLKEM768_CT_LEN..])
                    .map_err(|_| ierr("x25519 in hybrid"))?,
            );
            let mut e = ml;
            e.extend_from_slice(eph.derive_shared(&sp).as_bytes());
            e
        }
        _ => return Ok(None),
    };
    let mut transcript: Vec<u8> = ch[5..].to_vec();
    transcript.extend_from_slice(&sh[5..]);
    let early = early_secret(suite);
    let hs = handshake_secret(suite, &early, &ecdhe);
    let th = transcript_hash(suite, &transcript);
    let keys = traffic_keys(suite, &server_handshake_traffic_secret(suite, &hs, &th));
    let mut rec = RecordCrypto::new(&keys.key, &keys.iv);

    // Read the encrypted flight; reassemble handshake messages; return the body of
    // the first Certificate (0x0b). Bail to `None` if Finished arrives first.
    let mut hs_buf: Vec<u8> = Vec::new();
    for _ in 0..64 {
        let (ct, record) = read_record(stream).await?;
        match ct {
            0x14 => continue,
            0x17 => {
                let (inner, pt) = rec.decrypt(&record).ok_or_else(|| ierr("decrypt flight"))?;
                if inner != 0x16 {
                    continue;
                }
                hs_buf.extend_from_slice(&pt);
            }
            _ => return Ok(None),
        }
        while hs_buf.len() >= 4 {
            let mlen = 4 + u24(&hs_buf[1..4]);
            if hs_buf.len() < mlen {
                break;
            }
            match hs_buf[0] {
                0x0b => return Ok(Some(hs_buf[4..mlen].to_vec())),
                0x14 => return Ok(None),
                _ => {
                    hs_buf.drain(..mlen);
                }
            }
        }
    }
    Ok(None)
}

/// Parse a ServerHello handshake message into a [`BorrowProfile`].
fn parse_borrow_profile(sh_msg: &[u8]) -> io::Result<BorrowProfile> {
    if sh_msg.len() < 39 || sh_msg[0] != 0x02 {
        return Err(ierr("not a ServerHello"));
    }
    let sid_len = sh_msg[38] as usize;
    let mut o = 39 + sid_len;
    if o + 3 > sh_msg.len() {
        return Err(ierr("ServerHello truncated"));
    }
    let cipher = u16::from_be_bytes([sh_msg[o], sh_msg[o + 1]]);
    let suite = Suite::from_code(cipher)
        .ok_or_else(|| ierr("target cipher suite not implemented by the realtls stack"))?;
    o += 3; // cipher_suite(2) + legacy_compression(1)
    if o + 2 > sh_msg.len() {
        return Err(ierr("ServerHello missing extensions"));
    }
    let ext_len = u16::from_be_bytes([sh_msg[o], sh_msg[o + 1]]) as usize;
    o += 2;
    let end = (o + ext_len).min(sh_msg.len());
    let (mut prefer_pq, mut key_share_first, mut seen_sv) = (false, false, false);
    while o + 4 <= end {
        let et = u16::from_be_bytes([sh_msg[o], sh_msg[o + 1]]);
        let el = u16::from_be_bytes([sh_msg[o + 2], sh_msg[o + 3]]) as usize;
        match et {
            0x002b => seen_sv = true,
            0x0033 => {
                if !seen_sv {
                    key_share_first = true;
                }
                if el >= 2 {
                    let group = u16::from_be_bytes([sh_msg[o + 4], sh_msg[o + 5]]);
                    prefer_pq = group == mlkem::X25519MLKEM768;
                }
            }
            _ => {}
        }
        o += 4 + el;
    }
    Ok(BorrowProfile {
        suite,
        prefer_pq,
        key_share_first,
    })
}

/// Run the server side of a TLS 1.3 (EC)DHE handshake against a qeli realtls
/// client. Reads the ClientHello from `stream`, recovers the client x25519
/// `key_share`, sends ServerHello + the encrypted flight (EncryptedExtensions, a
/// placeholder Certificate / CertificateVerify the client does not validate —
/// REALITY trust is via X25519 + the inner qeli auth — and Finished), verifies
/// the client Finished, and returns the application-data record crypto.
pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server_eph: Keypair,
    borrow: BorrowProfile,
    borrowed_cert: Option<&[u8]>,
) -> io::Result<EstablishedServerTls> {
    let (suite, prefer_pq) = (borrow.suite, borrow.prefer_pq);
    // 1. ClientHello.
    let (ct, ch_rec) = read_record(stream).await?;
    if ct != 0x16 {
        return Err(ierr("expected ClientHello record"));
    }
    let (sid, client_ks) = FakeTlsHandshake::parse_client_hello_full(&ch_rec)
        .ok_or_else(|| ierr("bad ClientHello"))?;
    let client_pub = PublicKey::from_bytes(
        &<[u8; 32]>::try_from(client_ks.as_slice())
            .map_err(|_| ierr("client key_share not 32 bytes"))?,
    );
    let mut transcript: Vec<u8> = ch_rec[5..].to_vec();

    // 2a. Choose the key exchange: hybrid X25519MLKEM768 if requested and the
    // client offered it (matching what a real server sends a PQ-capable Chrome),
    // else classic X25519. The X25519 half is shared either way.
    let x_shared = server_eph.derive_shared(&client_pub);
    let pq_ek = if prefer_pq {
        extract_client_key_share(&ch_rec, mlkem::X25519MLKEM768)
    } else {
        None
    };
    let (ks_group, ks_value, ecdhe): (u16, Vec<u8>, Vec<u8>) = match pq_ek {
        Some(pq) if pq.len() >= mlkem::MLKEM768_EK_LEN => {
            let (ct, ml_shared) = mlkem::mlkem768_encapsulate(&pq[..mlkem::MLKEM768_EK_LEN])
                .ok_or_else(|| ierr("ML-KEM encapsulate failed"))?;
            let mut value = ct; // ML-KEM ciphertext (1088 B)
            value.extend_from_slice(server_eph.public().as_bytes()); // ‖ x25519 (32 B)
            let mut e = ml_shared; // hybrid secret: ML-KEM shared ‖ X25519 shared
            e.extend_from_slice(x_shared.as_bytes());
            (mlkem::X25519MLKEM768, value, e)
        }
        _ => (
            0x001d,
            server_eph.public().as_bytes().to_vec(),
            x_shared.as_bytes().to_vec(),
        ),
    };

    // 2b. ServerHello (supported_versions + the chosen key_share).
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&[0x03, 0x03]);
    let random: [u8; 32] = rand::random();
    sh_body.extend_from_slice(&random);
    sh_body.push(0x20);
    sh_body.extend_from_slice(&sid); // echo legacy_session_id
    sh_body.extend_from_slice(&suite.code().to_be_bytes()); // negotiated cipher suite
    sh_body.push(0x00);
    // Emit supported_versions + key_share in the borrowed target's order so the
    // ServerHello's JA3S matches it (microsoft/amazon: [sv, ks]; cloudflare: [ks, sv]).
    let sv_ext: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]; // supported_versions 1.3
    let mut ks_ext = Vec::new();
    ks_ext.extend_from_slice(&[0x00, 0x33]); // key_share
    ks_ext.extend_from_slice(&((4 + ks_value.len()) as u16).to_be_bytes());
    ks_ext.extend_from_slice(&ks_group.to_be_bytes());
    ks_ext.extend_from_slice(&(ks_value.len() as u16).to_be_bytes());
    ks_ext.extend_from_slice(&ks_value);
    let mut ext = Vec::new();
    if borrow.key_share_first {
        ext.extend_from_slice(&ks_ext);
        ext.extend_from_slice(&sv_ext);
    } else {
        ext.extend_from_slice(&sv_ext);
        ext.extend_from_slice(&ks_ext);
    }
    sh_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    sh_body.extend_from_slice(&ext);
    let sh = hs_msg(0x02, &sh_body);
    let mut sh_record = vec![0x16, 0x03, 0x03];
    sh_record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
    sh_record.extend_from_slice(&sh);
    stream.write_all(&sh_record).await?;
    transcript.extend_from_slice(&sh);

    // 3. Handshake secrets from the (hybrid) shared secret + CH..SH transcript.
    let early = early_secret(suite);
    let hs = handshake_secret(suite, &early, &ecdhe);
    let th_chsh = transcript_hash(suite, &transcript);
    let s_hs = server_handshake_traffic_secret(suite, &hs, &th_chsh);
    let c_hs = client_handshake_traffic_secret(suite, &hs, &th_chsh);
    let s_keys = traffic_keys(suite, &s_hs);
    let c_keys = traffic_keys(suite, &c_hs);

    // 4. Encrypted flight: EE + placeholder Certificate + CertificateVerify + Finished.
    let ee = hs_msg(0x08, &[0x00, 0x00]);
    // Certificate: borrow the target's REAL chain when the probe captured it
    // (REALITY cert-borrowing — indistinguishable from the real site); otherwise a
    // placeholder the client never validates (trust is X25519 + the inner qeli auth).
    let cert = match borrowed_cert {
        Some(body) => hs_msg(0x0b, body),
        None => {
            let mut cert_body = vec![0x00]; // certificate_request_context len 0
            let cert_data = [0xAAu8; 16];
            let mut cert_list = Vec::new();
            cert_list.extend_from_slice(&[0, 0, cert_data.len() as u8]);
            cert_list.extend_from_slice(&cert_data);
            cert_list.extend_from_slice(&[0x00, 0x00]); // entry extensions len 0
            cert_body.extend_from_slice(&[0, 0, cert_list.len() as u8]);
            cert_body.extend_from_slice(&cert_list);
            hs_msg(0x0b, &cert_body)
        }
    };
    let mut cv_body = vec![0x08, 0x04]; // signature scheme
    let sig = [0xBBu8; 16];
    cv_body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    cv_body.extend_from_slice(&sig);
    let cv = hs_msg(0x0f, &cv_body);

    transcript.extend_from_slice(&ee);
    transcript.extend_from_slice(&cert);
    transcript.extend_from_slice(&cv);
    let s_verify = finished_verify(
        suite,
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
        .await?; // dummy CCS
    let flight_record = s_rec.encrypt(0x16, &flight);
    stream.write_all(&flight_record).await?;

    // 5. Client CCS (skip) + encrypted client Finished.
    let mut c_rec = RecordCrypto::new(&c_keys.key, &c_keys.iv);
    let (cfin_type, cfin_msg) = loop {
        let (ct, rec) = read_record(stream).await?;
        match ct {
            0x14 => continue,
            0x17 => {
                break c_rec
                    .decrypt(&rec)
                    .ok_or_else(|| ierr("decrypt client Finished"))?
            }
            0x15 => return Err(ierr("client sent alert")),
            _ => return Err(ierr("expected client Finished")),
        }
    };
    if cfin_type != 0x16 || cfin_msg.len() < 4 {
        return Err(ierr("client Finished malformed"));
    }
    let expect_c = finished_verify(
        suite,
        &finished_key(suite, &c_hs),
        &transcript_hash(suite, &transcript),
    );
    if cfin_msg[4..] != expect_c {
        return Err(ierr("client Finished verify_data mismatch"));
    }

    // 6. Application traffic keys (RFC 8446 §7.3) over CH..server-Finished.
    let master = master_secret(suite, &hs);
    let th_full = transcript_hash(suite, &transcript);
    let c_ap = client_application_traffic_secret(suite, &master, &th_full);
    let s_ap = server_application_traffic_secret(suite, &master, &th_full);
    let c_ap_keys = traffic_keys(suite, &c_ap);
    let s_ap_keys = traffic_keys(suite, &s_ap);
    let mut send = RecordCrypto::new(&s_ap_keys.key, &s_ap_keys.iv);

    // Post-handshake NewSessionTickets: a real TLS 1.3 server emits 1-2 right after
    // the handshake — sending none is a fingerprint tell. The client does not resume
    // (RealTlsStream skips post-handshake handshake records), so these are
    // transparent; the send-sequence advances and stays in sync with the client.
    for _ in 0..2 {
        let rec = send.encrypt(0x16, &build_new_session_ticket());
        stream.write_all(&rec).await?;
    }

    Ok(EstablishedServerTls {
        send,
        recv: RecordCrypto::new(&c_ap_keys.key, &c_ap_keys.iv),
    })
}

/// Terminate a TLS 1.3 session for a qeli REALITY client with the hand-rolled
/// stack (the borrowed-ServerHello path), returning an `AsyncRead + AsyncWrite +
/// SplitStream` the qeli tunnel runs inside — the realtls counterpart to the
/// rustls `terminate`. `stream` must be positioned at the ClientHello (the REALITY
/// detector peeks, so it is not consumed).
pub async fn terminate_handrolled<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    server_eph: Keypair,
    borrow: BorrowProfile,
    borrowed_cert: Option<&[u8]>,
) -> io::Result<RealTlsStream<S>> {
    let mut stream = stream;
    let est = server_handshake(&mut stream, server_eph, borrow, borrowed_cert).await?;
    Ok(RealTlsStream::from_crypto(stream, est.send, est.recv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{reality, Keypair, StaticKeypair};
    use crate::protocol::realtls::client::client_handshake;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The REALITY peek-and-replay path: the server consumes the full ClientHello
    /// (as the token detector does), then hands the buffered bytes to rustls,
    /// which still completes a real handshake with our hand-rolled client.
    #[tokio::test]
    async fn peek_then_replay_terminates() {
        let (mut client_io, server_io) = tokio::io::duplex(32 * 1024);
        let config = make_server_config("www.microsoft.com");

        let server = tokio::spawn(async move {
            let mut server_io = server_io;
            // Consume the whole ClientHello record (the detector would open the
            // REALITY token from these bytes here).
            let mut hdr = [0u8; 5];
            server_io.read_exact(&mut hdr).await.unwrap();
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut ch = vec![0u8; 5 + len];
            ch[..5].copy_from_slice(&hdr);
            server_io.read_exact(&mut ch[5..]).await.unwrap();

            // Replay it into rustls.
            let mut tls = terminate(ch, server_io, config)
                .await
                .expect("rustls terminates the replayed ClientHello");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
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
            .expect("client completes handshake against the replayed ClientHello");

        let ping = tls.send.encrypt(0x17, b"ping");
        client_io.write_all(&ping).await.unwrap();
        client_io.flush().await.unwrap();

        let pong = loop {
            let mut hdr = [0u8; 5];
            client_io.read_exact(&mut hdr).await.unwrap();
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut rec = vec![0u8; 5 + len];
            rec[..5].copy_from_slice(&hdr);
            client_io.read_exact(&mut rec[5..]).await.unwrap();
            let (inner, pt) = tls.recv.decrypt(&rec).expect("decrypt server record");
            if inner == 0x17 {
                break pt;
            }
        };
        assert_eq!(pong, b"pong");
        assert_eq!(&server.await.unwrap(), b"ping");
    }

    /// The hand-rolled `server_handshake` interops with the real `client_handshake`:
    /// a full TLS 1.3 (EC)DHE session is established and application data flows both
    /// ways — no rustls on either side.
    #[tokio::test]
    async fn handshake_interop_client_to_server() {
        // Cover both cipher suites (0x1301 → SHA-256/AES-128, 0x1302 →
        // SHA-384/AES-256) and both key exchanges (classic X25519 and hybrid
        // X25519MLKEM768) — a full session is established in every combination.
        for suite in [Suite::Aes128Sha256, Suite::Aes256Sha384] {
            for prefer_pq in [false, true] {
                run_interop(suite, prefer_pq).await;
            }
        }
    }

    async fn run_interop(suite: Suite, prefer_pq: bool) {
        use crate::crypto::{reality, StaticKeypair};
        use crate::protocol::realtls::client::{client_handshake, read_record};

        let (mut client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let server_eph = Keypair::generate();
        let server = tokio::spawn(async move {
            let mut tls = server_handshake(
                &mut server_io,
                server_eph,
                BorrowProfile {
                    suite,
                    prefer_pq,
                    key_share_first: false,
                },
                None,
            )
            .await
            .expect("server completes handshake");
            let (_, rec) = read_record(&mut server_io).await.unwrap();
            let (inner, ping) = tls.recv.decrypt(&rec).expect("decrypt ping");
            assert_eq!(inner, 0x17);
            let pong = tls.send.encrypt(0x17, b"pong");
            server_io.write_all(&pong).await.unwrap();
            server_io.flush().await.unwrap();
            ping
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
            .unwrap_or_else(|e| panic!("client handshake ({suite:?}): {e}"));

        let ping = tls.send.encrypt(0x17, b"ping");
        client_io.write_all(&ping).await.unwrap();
        client_io.flush().await.unwrap();

        let pong = loop {
            let (_, rec) = read_record(&mut client_io).await.unwrap();
            let (inner, pt) = tls.recv.decrypt(&rec).expect("decrypt server record");
            if inner == 0x17 {
                break pt;
            }
        };
        assert_eq!(pong, b"pong", "suite {suite:?}");
        assert_eq!(&server.await.unwrap(), b"ping", "suite {suite:?}");
    }

    /// Full server-side stream path (L3.4): the realtls client and the hand-rolled
    /// `terminate_handrolled` server talk through `RealTlsStream` — the adapter the
    /// qeli tunnel runs inside — for every cipher suite × key-exchange combination.
    #[tokio::test]
    async fn realtls_stream_server_interop() {
        use crate::crypto::{reality, StaticKeypair};
        use crate::protocol::realtls::client::client_handshake;
        use crate::protocol::realtls::stream::RealTlsStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for suite in [Suite::Aes128Sha256, Suite::Aes256Sha384] {
            for prefer_pq in [false, true] {
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                let server = tokio::spawn(async move {
                    let mut tls = terminate_handrolled(
                        server_io,
                        Keypair::generate(),
                        BorrowProfile {
                            suite,
                            prefer_pq,
                            key_share_first: false,
                        },
                        None,
                    )
                    .await
                    .expect("server terminates");
                    let mut got = vec![0u8; 5000];
                    tls.read_exact(&mut got).await.unwrap();
                    tls.write_all(&got).await.unwrap(); // echo back
                    tls.flush().await.unwrap();
                    got
                });

                let mut client_io = client_io;
                let eph = Keypair::generate();
                let reality = StaticKeypair::generate();
                let sid = reality::seal_session_id(
                    &reality.public,
                    &eph,
                    &reality::short_id_from_hex("0123456789abcdef"),
                );
                let est = client_handshake(&mut client_io, eph, sid, "www.microsoft.com")
                    .await
                    .unwrap_or_else(|e| panic!("client handshake ({suite:?}/{prefer_pq}): {e}"));
                let mut stream = RealTlsStream::new(client_io, est);

                let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut back = vec![0u8; payload.len()];
                stream.read_exact(&mut back).await.unwrap();
                assert_eq!(back, payload, "{suite:?} prefer_pq={prefer_pq}");
                assert_eq!(server.await.unwrap(), payload);
            }
        }
    }

    #[test]
    fn borrow_profile_parses_serverhello() {
        // Build a ServerHello handshake message with a given cipher + raw extensions.
        fn sh(cipher: u16, exts: &[u8]) -> Vec<u8> {
            let mut body = vec![0x03, 0x03];
            body.extend_from_slice(&[0x11u8; 32]); // random
            body.push(0x00); // empty legacy_session_id
            body.extend_from_slice(&cipher.to_be_bytes());
            body.push(0x00); // legacy_compression
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(exts);
            hs_msg(0x02, &body)
        }
        let sv: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]; // supported_versions
        let mut ks_x = vec![0x00u8, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]; // key_share x25519
        ks_x.extend_from_slice(&[0u8; 32]);
        let ks_pq: [u8; 12] = [
            0x00, 0x33, 0x00, 0x08, 0x11, 0xec, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
        ];

        // microsoft shape: 0x1302, [supported_versions, key_share x25519].
        let mut e = sv.to_vec();
        e.extend_from_slice(&ks_x);
        let bp = parse_borrow_profile(&sh(0x1302, &e)).unwrap();
        assert_eq!(bp.suite, Suite::Aes256Sha384);
        assert!(!bp.prefer_pq);
        assert!(!bp.key_share_first);

        // cloudflare shape: 0x1301, [key_share PQ, supported_versions].
        let mut e2 = ks_pq.to_vec();
        e2.extend_from_slice(&sv);
        let bp2 = parse_borrow_profile(&sh(0x1301, &e2)).unwrap();
        assert_eq!(bp2.suite, Suite::Aes128Sha256);
        assert!(bp2.prefer_pq);
        assert!(bp2.key_share_first);

        // A cipher our stack does not implement (ChaCha20 0x1303) is rejected.
        let mut e3 = sv.to_vec();
        e3.extend_from_slice(&ks_x);
        assert!(parse_borrow_profile(&sh(0x1303, &e3)).is_err());
    }

    /// REALITY cert-borrowing: a (large, arbitrary) borrowed Certificate body is
    /// presented instead of the dummy, and the realtls client still completes the
    /// handshake — the transcript stays consistent because the client hashes
    /// whatever Certificate it receives (it never validates the chain).
    #[tokio::test]
    async fn handrolled_presents_borrowed_cert() {
        use crate::crypto::{reality, StaticKeypair};
        use crate::protocol::realtls::client::client_handshake;

        let (mut client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        // ~1.8 KB "borrowed chain" — opaque to the client (folded into transcript).
        let chain = vec![0x42u8; 1800];
        let chain_srv = chain.clone();
        let server_eph = Keypair::generate();
        let server = tokio::spawn(async move {
            server_handshake(
                &mut server_io,
                server_eph,
                BorrowProfile {
                    suite: Suite::Aes128Sha256,
                    prefer_pq: false,
                    key_share_first: false,
                },
                Some(&chain_srv),
            )
            .await
            .expect("server completes with a borrowed cert");
        });

        let eph = Keypair::generate();
        let reality = StaticKeypair::generate();
        let sid =
            reality::seal_session_id(&reality.public, &eph, &reality::short_id_from_hex("aa"));
        client_handshake(&mut client_io, eph, sid, "www.microsoft.com")
            .await
            .expect("client completes against a borrowed-cert server");
        server.await.unwrap();
    }
}
