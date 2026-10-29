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
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};

/// RFC 9113 client connection preface.  The server uses this only after the
/// outer REALITY discriminator and TLS authentication, to select the new carrier
/// while preserving the legacy inner-handshake path for already-installed clients.
pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const BRIDGE_CAPACITY: usize = 256 * 1024;
const H2_FRAME_MAX: usize = 16 * 1024;
const H2_WINDOW: u32 = 2 * 1024 * 1024;
const CARRIER_PATH: &str = "/v1/events/stream";
const GRPC_MEDIA_TYPE: &str = "application/grpc";

// A generation retains joins after Carrier Drop requests cancellation. Standalone
// callers keep their existing cancellation behavior without a generation registry.
#[derive(Default)]
enum TaskSpawner {
    #[default]
    Standalone,
    #[cfg(any(
        test,
        all(target_os = "linux", feature = "client"),
        feature = "transport-core-ffi"
    ))]
    Connection(crate::transport_core::tasks::Spawner),
    #[cfg(any(test, all(target_os = "linux", feature = "server")))]
    Profile(crate::profile_tasks::ProfileSpawner),
}

impl TaskSpawner {
    fn spawn(
        &self,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> io::Result<tokio::task::AbortHandle> {
        let abort = match self {
            Self::Standalone => Some(tokio::spawn(future).abort_handle()),
            #[cfg(any(
                test,
                all(target_os = "linux", feature = "client"),
                feature = "transport-core-ffi"
            ))]
            Self::Connection(owner) => owner.spawn_abortable(future),
            #[cfg(any(test, all(target_os = "linux", feature = "server")))]
            Self::Profile(owner) => owner.spawn_abortable(future),
        };
        abort.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Interrupted, "HTTP/2 task owner has stopped")
        })
    }
}

/// Cancels the bridge AND connection driver, including while connect is pending.
#[derive(Default, Debug)]
struct Tasks(Vec<tokio::task::AbortHandle>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

#[derive(Debug)]
pub struct Carrier {
    application: DuplexStream,
    opportunistic: Arc<AtomicBool>,
    _tasks: Tasks,
}

impl crate::protocol::obfs::SplitStream for Carrier {
    type R = ReadHalf<Self>;
    type W = WriteHalf<Self>;
    fn set_opportunistic_batching(&mut self, enabled: bool) {
        self.opportunistic.store(enabled, Ordering::Release);
    }
    fn split_io(self) -> (Self::R, Self::W) {
        tokio::io::split(self)
    }
}

impl AsyncRead for Carrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.application).poll_read(cx, buf)
    }
}

impl AsyncWrite for Carrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.application).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.application).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.application).poll_shutdown(cx)
    }
}

fn h2_error(context: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{context}: {error}"))
}

async fn ping_once(ping: &mut h2::PingPong, deadline: Duration) -> io::Result<()> {
    tokio::time::timeout(deadline, ping.ping(h2::Ping::opaque()))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP/2 PING acknowledgement timed out",
            )
        })?
        .map_err(|error| h2_error("HTTP/2 PING failed", error))?;
    Ok(())
}

/// Standard h2 connection health, independent of the application writer and of
/// qeli cover/heartbeat policy. An ACK proves only the outer connection is alive;
/// it never renews a DATA flow-control deadline. One outstanding probe at a time.
async fn connection_health(mut ping: h2::PingPong) -> io::Result<()> {
    loop {
        let delay = Duration::from_secs(rand::rng().random_range(20..=30));
        tokio::time::sleep(delay).await;
        ping_once(&mut ping, crate::protocol::stream_io::WRITE_STALL_TIMEOUT).await?;
    }
}

async fn send_with_flow_control(
    stream: &mut SendStream<Bytes>,
    data: Bytes,
    end_of_stream: bool,
) -> io::Result<()> {
    send_with_flow_control_budget(
        stream,
        data,
        end_of_stream,
        crate::protocol::stream_io::WRITE_STALL_TIMEOUT,
    )
    .await
}

async fn send_with_flow_control_budget(
    stream: &mut SendStream<Bytes>,
    mut data: Bytes,
    end_of_stream: bool,
    budget: Duration,
) -> io::Result<()> {
    if data.is_empty() {
        stream
            .send_data(data, end_of_stream)
            .map_err(|error| h2_error("HTTP/2 DATA send failed", error))?;
        return Ok(());
    }

    // Capacity belongs to this stream, not to a healthy sibling or to the local
    // DuplexStream. Zero/spurious notifications must not renew this deadline.
    let mut deadline = tokio::time::Instant::now() + budget;
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        while stream.capacity() == 0 {
            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP/2 stream made no DATA progress while waiting for capacity",
                ));
            }
            let capacity =
                tokio::time::timeout_at(deadline, poll_fn(|cx| stream.poll_capacity(cx)))
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HTTP/2 stream made no DATA progress while waiting for capacity",
                        )
                    })?;
            match capacity {
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
        let size = stream.capacity().min(data.len());
        let part = data.split_to(size);
        stream
            .send_data(part, end_of_stream && data.is_empty())
            .map_err(|error| h2_error("HTTP/2 DATA send failed", error))?;
        // Enqueued to h2, not proof of peer delivery. The underlying TLS socket
        // has its own write-progress guard for a blocked connection driver.
        deadline = tokio::time::Instant::now() + budget;
    }
    Ok(())
}

/// Read the private byte stream and form bounded DATA batches. Before authenticated
/// mode selection, and in `timed`, a randomized 2..8 ms accumulation deadline is
/// used (not an end-to-end latency bound). In `opportunistic`, poll only immediately
/// available bytes and flush on Pending; H2 flow-control/backpressure still applies.
async fn outbound(
    mut source: ReadHalf<DuplexStream>,
    mut stream: SendStream<Bytes>,
    opportunistic: Arc<AtomicBool>,
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
            if opportunistic.load(Ordering::Acquire) {
                // Poll available bytes once; Pending ends the batch rather than
                // starting a new timer. EOF, capacity and driver ownership keep
                // their existing semantics. The target bounds each drain.
                let available = poll_fn(|cx| {
                    let mut buf = ReadBuf::new(&mut scratch[..want]);
                    match Pin::new(&mut source).poll_read(cx, &mut buf) {
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(buf.filled().len()))),
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Pending => Poll::Ready(Ok(None)),
                    }
                })
                .await?;
                match available {
                    Some(0) => {
                        send_with_flow_control(&mut stream, Bytes::from(batch), false).await?;
                        return send_with_flow_control(&mut stream, Bytes::new(), true).await;
                    }
                    Some(read) => {
                        batch.extend_from_slice(&scratch[..read]);
                        continue;
                    }
                    None => break,
                }
            }
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

fn bridge(
    send: SendStream<Bytes>,
    recv: RecvStream,
    mut tasks: Tasks,
    spawner: &TaskSpawner,
) -> io::Result<Carrier> {
    let (application, worker) = tokio::io::duplex(BRIDGE_CAPACITY);
    let opportunistic = Arc::new(AtomicBool::new(false));
    let outbound_mode = opportunistic.clone();
    let (source, sink) = tokio::io::split(worker);
    let driver = Tasks(tasks.0.clone());
    let worker = spawner.spawn(async move {
        let mut driver = driver;
        // A failure in either direction drops the other future and the driver.
        // A clean half-close may still receive a reply until the owner is dropped.
        match tokio::try_join!(outbound(source, send, outbound_mode), inbound(recv, sink)) {
            Err(error) => log::warn!("HTTP/2 carrier ended: {error}"),
            // Both halves ended cleanly. Leave the owner in charge so the driver can
            // flush the queued END_STREAM before the application drops the carrier.
            Ok(_) => driver.0.clear(),
        }
    })?;
    tasks.0.push(worker);
    Ok(Carrier {
        application,
        opportunistic,
        _tasks: tasks,
    })
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

fn carrier_rejection(request: &Request<RecvStream>) -> Option<(StatusCode, &'static str)> {
    if request.method() != Method::POST {
        return Some((
            StatusCode::METHOD_NOT_ALLOWED,
            "HTTP/2 carrier requires a streaming POST",
        ));
    }
    if request.uri().path() != CARRIER_PATH {
        return Some((
            StatusCode::NOT_FOUND,
            "HTTP/2 carrier path is not available",
        ));
    }
    let content_type_ok = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let media_type = value.split(';').next().unwrap_or_default().trim();
            media_type.eq_ignore_ascii_case(GRPC_MEDIA_TYPE)
                || media_type
                    .get(..GRPC_MEDIA_TYPE.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(GRPC_MEDIA_TYPE))
                    && media_type.as_bytes().get(GRPC_MEDIA_TYPE.len()) == Some(&b'+')
        })
        .unwrap_or(false);
    if !content_type_ok {
        return Some((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "HTTP/2 carrier requires gRPC content",
        ));
    }
    let trailers = request
        .headers()
        .get("te")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("trailers"));
    if !trailers {
        return Some((
            StatusCode::BAD_REQUEST,
            "HTTP/2 carrier requires TE trailers",
        ));
    }
    None
}

/// Establish the client side of a genuine h2 streaming exchange over an already
/// authenticated REALITY-TLS stream.
pub async fn connect<S>(io: S, authority: &str) -> io::Result<Carrier>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_with_tasks(io, authority, TaskSpawner::default()).await
}

/// Keep every spawned worker in the generation registry, including during a pending response.
#[cfg(any(
    test,
    all(target_os = "linux", feature = "client"),
    feature = "transport-core-ffi"
))]
pub(crate) async fn connect_owned<S>(
    io: S,
    authority: &str,
    owner: &crate::transport_core::tasks::Spawner,
) -> io::Result<Carrier>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_with_tasks(io, authority, TaskSpawner::Connection(owner.clone())).await
}

async fn connect_with_tasks<S>(io: S, authority: &str, spawner: TaskSpawner) -> io::Result<Carrier>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, mut connection) = configure_client()
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|error| h2_error("HTTP/2 client handshake failed", error))?;
    let ping = connection
        .ping_pong()
        .ok_or_else(|| io::Error::other("HTTP/2 PING owner unavailable"))?;
    let driver = spawner.spawn(async move {
        tokio::select! {
            biased;
            result = connection_health(ping) => {
                if let Err(error) = result { log::warn!("HTTP/2 client health failed: {error}"); }
            }
            result = connection => {
                if let Err(error) = result { log::debug!("HTTP/2 client connection ended: {error}"); }
            }
        }
    })?;
    let tasks = Tasks(vec![driver]);

    let mut send_request = send_request
        .ready()
        .await
        .map_err(|error| h2_error("HTTP/2 client was not ready", error))?;
    let uri = format!("https://{authority}{CARRIER_PATH}");
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
    bridge(send, response.into_body(), tasks, &spawner)
}

/// Accept the first h2 request on an already authenticated REALITY-TLS stream.
/// Later streams receive a normal 404 response; the tunnel itself uses exactly
/// one bidirectional streaming request, which keeps connection-level h2 state
/// and flow-control genuine for its whole lifetime.
pub async fn accept<S>(io: S) -> io::Result<Carrier>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    accept_with_tasks(io, TaskSpawner::default(), ())
        .await
        .map(|(carrier, ())| carrier)
}

/// Keep the driver, bridge and bounded rejection flush in the profile's task registry.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
pub(crate) async fn accept_owned<S, G>(
    io: S,
    owner: &crate::profile_tasks::ProfileSpawner,
    admission: G,
) -> io::Result<(Carrier, G)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    G: Send + 'static,
{
    // Success hands admission to the inner authentication handler. Rejection transfers
    // it to the bounded response flush, so a live pre-auth socket remains accounted for.
    accept_with_tasks(io, TaskSpawner::Profile(owner.clone()), admission).await
}

// Field order releases the connection before its admission guard, including when the
// registered future is cancelled before its first poll or rejected by a closed profile.
struct RejectionFlush<S, G> {
    connection: h2::server::Connection<S, Bytes>,
    _admission: G,
}

async fn flush_rejection<S, G>(mut pending: RejectionFlush<S, G>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(next) = pending.connection.accept().await {
            if next.is_err() {
                break;
            }
        }
    })
    .await;
}

async fn accept_with_tasks<S, G>(
    io: S,
    spawner: TaskSpawner,
    admission: G,
) -> io::Result<(Carrier, G)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    G: Send + 'static,
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
    if let Some((status, message)) = carrier_rejection(&request) {
        let response = Response::builder()
            .status(status)
            .header("content-length", "0")
            .body(())
            .map_err(|error| h2_error("HTTP/2 rejection build failed", error))?;
        respond
            .send_response(response, true)
            .map_err(|error| h2_error("HTTP/2 rejection send failed", error))?;
        // `send_response` only queues the frame. Keep polling the connection briefly so
        // an authenticated but invalid request receives the deliberate HTTP status rather
        // than an incidental reset when this function returns its local validation error.
        spawner.spawn(flush_rejection(RejectionFlush {
            connection,
            _admission: admission,
        }))?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, message));
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

    let ping = connection
        .ping_pong()
        .ok_or_else(|| io::Error::other("HTTP/2 PING owner unavailable"))?;
    let driver = spawner.spawn(async move {
        let requests = async {
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
        };
        tokio::select! {
            biased;
            result = connection_health(ping) => {
                if let Err(error) = result { log::warn!("HTTP/2 server health failed: {error}"); }
            }
            _ = requests => {},
        }
        // Dropping the connection fails both body handles and wakes the bridge.
    })?;
    bridge(send, recv, Tasks(vec![driver]), &spawner).map(|carrier| (carrier, admission))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "server")]
    #[tokio::test(start_paused = true)]
    async fn opportunistic_echo_does_not_advance_the_clock() {
        use crate::protocol::obfs::SplitStream;
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut carrier = accept(server_io).await.unwrap();
            assert!(!carrier.opportunistic.load(Ordering::Acquire));
            carrier.set_opportunistic_batching(true);
            let mut bytes = [0; 128];
            carrier.read_exact(&mut bytes).await.unwrap();
            carrier.write_all(&bytes).await.unwrap();
            carrier.read_u8().await.unwrap(); // retain bridge until peer receipt
        });
        let carrier = connect(client_io, "example.com").await.unwrap();
        assert!(!carrier.opportunistic.load(Ordering::Acquire));
        let mut carrier = crate::protocol::stream_io::StallGuard::new(carrier);
        carrier.set_opportunistic_batching(true);
        let start = tokio::time::Instant::now();
        carrier.write_all(&[42; 128]).await.unwrap();
        let mut reply = [0; 128];
        carrier.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [42; 128]);
        assert_eq!(start.elapsed(), Duration::ZERO);
        carrier.write_u8(1).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn healthy_connection_pings_do_not_renew_a_stalled_stream_window() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.initial_window_size(0);
            let mut connection = builder.handshake::<_, Bytes>(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let _send = respond.send_response(Response::new(()), false).unwrap();
            let _body = request.into_body();
            // Poll connection control traffic while intentionally retaining the
            // zero receive window for this in-memory application stream.
            while connection.accept().await.is_some() {}
        });
        let (send, mut connection) = configure_client()
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        let mut ping = connection.ping_pong().unwrap();
        let driver = tokio::spawn(connection);
        let mut send = send.ready().await.unwrap();
        let (response, mut body) = send
            .send_request(
                Request::builder()
                    .uri("https://example.com/")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let _response = response.await.unwrap();
        // Quiet but healthy connection still responds. These outer ACKs are not
        // credited to DATA and must not suppress the stream-capacity deadline.
        let pings = async {
            for _ in 0..3 {
                ping_once(&mut ping, Duration::from_secs(1)).await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let sending = send_with_flow_control_budget(
            &mut body,
            Bytes::from_static(b"data"),
            false,
            Duration::from_millis(100),
        );
        let (_, result) = tokio::join!(pings, sending);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        server.abort();
        driver.abort();
        let _ = server.await;
        let _ = driver.await;
    }

    #[tokio::test]
    async fn missing_ping_ack_has_a_bounded_deadline() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = configure_server()
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            // Return ownership without driving it: the socket remains open but
            // cannot ACK a subsequent probe. No external network is involved.
            (connection, request, respond)
        });
        let (send, mut connection) = configure_client()
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        let mut ping = connection.ping_pong().unwrap();
        let driver = tokio::spawn(connection);
        let mut send = send.ready().await.unwrap();
        let (_response, _body) = send
            .send_request(
                Request::builder()
                    .uri("https://example.com/")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let held_server = server.await.unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            ping_once(&mut ping, Duration::from_millis(30)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(held_server);
        driver.abort();
        let _ = driver.await;
    }

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
            // Drop now cancels the buffered bridge; keep ownership until the peer
            // acknowledges receiving the echo (AsyncWrite::write_all is not an ACK).
            carrier.read_u8().await.unwrap();
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
        carrier.write_u8(1).await.unwrap();
        assert_eq!(server.await.unwrap(), request);
    }
}

#[cfg(test)]
mod hardening_tests;

#[cfg(test)]
mod ownership_tests;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod server_ownership_tests;
