//! Genuine HTTP/2 carrier for the maximum-stealth Reality-TLS profile.
//!
//! The public wire is now TLS 1.3 + real HTTP/2 (preface, SETTINGS, HEADERS,
//! flow-control and DATA), rather than a second sequence of TLS-looking qeli
//! records.  The qeli byte stream is bridged through one long-lived request and
//! response body.  A short randomized batching window deliberately combines
//! several inner writes into one DATA frame, so an outer TLS record boundary no
//! longer identifies one TUN packet or one qeli record.

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use rand::RngExt;
use std::future::poll_fn;
use std::io;
use std::time::Duration;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
};

/// RFC 9113 client connection preface.  The server uses this only after the
/// outer REALITY discriminator and TLS authentication, to select the new carrier
/// while preserving the legacy inner-handshake path for already-installed clients.
pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const BRIDGE_CAPACITY: usize = 256 * 1024;
const H2_FRAME_MAX: usize = 16 * 1024;
const H2_WINDOW: u32 = 2 * 1024 * 1024;

fn h2_error(context: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{context}: {error}"))
}

async fn send_with_flow_control(
    stream: &mut SendStream<Bytes>,
    data: Bytes,
    end_of_stream: bool,
) -> io::Result<()> {
    if data.is_empty() {
        stream
            .send_data(data, end_of_stream)
            .map_err(|error| h2_error("HTTP/2 DATA send failed", error))?;
        return Ok(());
    }

    stream.reserve_capacity(data.len());
    while stream.capacity() < data.len() {
        match poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(Ok(_)) => {}
            Some(Err(error)) => {
                return Err(h2_error("HTTP/2 flow-control wait failed", error));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "HTTP/2 stream closed while waiting for flow-control capacity",
                ));
            }
        }
    }
    stream
        .send_data(data, end_of_stream)
        .map_err(|error| h2_error("HTTP/2 DATA send failed", error))
}

/// Read the private byte stream, then jointly randomize the carrier's DATA size
/// and timing.  The first byte is never held longer than 2..8 ms; under load the
/// batch normally grows toward a browser-like 16 KiB DATA frame.  At low rates a
/// shorter frame is emitted at the randomized deadline instead of manufacturing
/// a fixed-rate beacon or excessive cover traffic.
async fn outbound(
    mut source: ReadHalf<DuplexStream>,
    mut stream: SendStream<Bytes>,
) -> io::Result<()> {
    let mut scratch = vec![0u8; H2_FRAME_MAX];
    loop {
        let first = source.read(&mut scratch).await?;
        if first == 0 {
            return send_with_flow_control(&mut stream, Bytes::new(), true).await;
        }

        let (target, delay_ms) = {
            let mut rng = rand::rng();
            let target = if rng.random_bool(0.72) {
                H2_FRAME_MAX
            } else {
                rng.random_range(4 * 1024..=14 * 1024)
            };
            (target, rng.random_range(2..=8))
        };
        let deadline = tokio::time::Instant::now() + Duration::from_millis(delay_ms);
        let mut batch = Vec::with_capacity(target);
        batch.extend_from_slice(&scratch[..first]);

        while batch.len() < target {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let want = (target - batch.len()).min(scratch.len());
            match tokio::time::timeout(remaining, source.read(&mut scratch[..want])).await {
                Ok(Ok(0)) => {
                    send_with_flow_control(&mut stream, Bytes::from(batch), false).await?;
                    return send_with_flow_control(&mut stream, Bytes::new(), true).await;
                }
                Ok(Ok(read)) => batch.extend_from_slice(&scratch[..read]),
                Ok(Err(error)) => return Err(error),
                Err(_) => break,
            }
        }

        send_with_flow_control(&mut stream, Bytes::from(batch), false).await?;
    }
}

async fn inbound(mut stream: RecvStream, mut sink: WriteHalf<DuplexStream>) -> io::Result<()> {
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(|error| h2_error("HTTP/2 DATA receive failed", error))?;
        let consumed = chunk.len();
        sink.write_all(&chunk).await?;
        stream
            .flow_control()
            .release_capacity(consumed)
            .map_err(|error| h2_error("HTTP/2 WINDOW_UPDATE failed", error))?;
    }
    sink.shutdown().await
}

fn bridge(send: SendStream<Bytes>, recv: RecvStream) -> DuplexStream {
    let (application, worker) = tokio::io::duplex(BRIDGE_CAPACITY);
    let (source, sink) = tokio::io::split(worker);
    tokio::spawn(async move {
        if let Err(error) = outbound(source, send).await {
            log::debug!("HTTP/2 carrier outbound ended: {error}");
        }
    });
    tokio::spawn(async move {
        if let Err(error) = inbound(recv, sink).await {
            log::debug!("HTTP/2 carrier inbound ended: {error}");
        }
    });
    application
}

fn configure_client() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(H2_WINDOW)
        .initial_connection_window_size(H2_WINDOW)
        .max_frame_size(H2_FRAME_MAX as u32);
    builder
}

fn configure_server() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(H2_WINDOW)
        .initial_connection_window_size(H2_WINDOW)
        .max_frame_size(H2_FRAME_MAX as u32)
        .max_concurrent_streams(100);
    builder
}

/// Establish the client side of a genuine h2 streaming exchange over an already
/// authenticated REALITY-TLS stream.
pub async fn connect<S>(io: S, authority: &str) -> io::Result<DuplexStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = configure_client()
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|error| h2_error("HTTP/2 client handshake failed", error))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::debug!("HTTP/2 client connection ended: {error}");
        }
    });

    let mut send_request = send_request
        .ready()
        .await
        .map_err(|error| h2_error("HTTP/2 client was not ready", error))?;
    let uri = format!("https://{authority}/v1/events/stream");
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("accept", "application/grpc")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("cache-control", "no-cache")
        .body(())
        .map_err(|error| h2_error("HTTP/2 request build failed", error))?;
    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|error| h2_error("HTTP/2 request send failed", error))?;
    let response = response
        .await
        .map_err(|error| h2_error("HTTP/2 response failed", error))?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP/2 carrier returned status {}", response.status()),
        ));
    }
    Ok(bridge(send, response.into_body()))
}

/// Accept the first h2 request on an already authenticated REALITY-TLS stream.
/// Later streams receive a normal 404 response; the tunnel itself uses exactly
/// one bidirectional streaming request, which keeps connection-level h2 state
/// and flow-control genuine for its whole lifetime.
pub async fn accept<S>(io: S) -> io::Result<DuplexStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = configure_server()
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|error| h2_error("HTTP/2 server handshake failed", error))?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP/2 client sent no request",
            )
        })?
        .map_err(|error| h2_error("HTTP/2 request accept failed", error))?;
    if request.method() != Method::POST {
        let response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .map_err(|error| h2_error("HTTP/2 rejection build failed", error))?;
        let _ = respond.send_response(response, true);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/2 carrier requires a streaming POST",
        ));
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("cache-control", "no-cache")
        .body(())
        .map_err(|error| h2_error("HTTP/2 response build failed", error))?;
    let send = respond
        .send_response(response, false)
        .map_err(|error| h2_error("HTTP/2 response send failed", error))?;
    let recv = request.into_body();

    tokio::spawn(async move {
        while let Some(next) = connection.accept().await {
            match next {
                Ok((_request, mut respond)) => {
                    if let Ok(response) = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header("content-length", "0")
                        .body(())
                    {
                        let _ = respond.send_response(response, true);
                    }
                }
                Err(error) => {
                    log::debug!("HTTP/2 server connection ended: {error}");
                    break;
                }
            }
        }
    });
    Ok(bridge(send, recv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bidirectional_stream_round_trip() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server = tokio::spawn(async move { accept(server_io).await.unwrap() });
        let mut client = connect(client_io, "example.com").await.unwrap();
        let mut server = server.await.unwrap();

        let up = vec![0x41; 23_000];
        client.write_all(&up).await.unwrap();
        client.flush().await.unwrap();
        let mut got_up = vec![0u8; up.len()];
        tokio::time::timeout(Duration::from_secs(2), server.read_exact(&mut got_up))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got_up, up);

        let down = vec![0xB7; 19_000];
        server.write_all(&down).await.unwrap();
        server.flush().await.unwrap();
        let mut got_down = vec![0u8; down.len()];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut got_down))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got_down, down);
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn round_trip_over_handrolled_reality_tls() {
        use crate::crypto::{reality, Keypair, StaticKeypair};
        use crate::protocol::realtls::client::client_handshake;
        use crate::protocol::realtls::server::{terminate_handrolled, BorrowProfile};
        use crate::protocol::realtls::stream::RealTlsStream;

        let (client_io, server_io) = tokio::io::duplex(512 * 1024);
        let server = tokio::spawn(async move {
            let tls = terminate_handrolled(
                server_io,
                Keypair::generate(),
                BorrowProfile::default(),
                None,
            )
            .await
            .expect("server terminates REALITY TLS");
            let mut carrier = accept(tls).await.expect("server accepts h2");
            let mut request = vec![0u8; 25_000];
            carrier.read_exact(&mut request).await.unwrap();
            carrier.write_all(&request).await.unwrap();
            request
        });

        let mut client_io = client_io;
        let ephemeral = Keypair::generate();
        let identity = StaticKeypair::generate();
        let session_id = reality::seal_session_id(
            &identity.public,
            &ephemeral,
            &reality::short_id_from_hex("0123456789abcdef"),
        );
        let established =
            client_handshake(&mut client_io, ephemeral, session_id, "www.microsoft.com")
                .await
                .expect("client completes REALITY TLS");
        let tls = RealTlsStream::new(client_io, established);
        let mut carrier = connect(tls, "www.microsoft.com")
            .await
            .expect("client establishes h2");

        let request: Vec<u8> = (0..25_000u32).map(|value| (value % 251) as u8).collect();
        carrier.write_all(&request).await.unwrap();
        let mut response = vec![0u8; request.len()];
        tokio::time::timeout(Duration::from_secs(3), carrier.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, request);
        assert_eq!(server.await.unwrap(), request);
    }
}
