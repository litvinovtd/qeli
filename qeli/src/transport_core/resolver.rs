//! Bounded admission/waiting for system DNS/NSS and resolver-file discovery.
//!
//! libc resolution cannot be forcibly cancelled. A dedicated, capacity-limited thread
//! owns read-only work and its permit, never a platform/network mutation callback. It
//! inherits the spawning thread's OS context and cannot hold up Tokio runtime shutdown.
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, LazyLock};
use tokio::sync::{oneshot, Semaphore};
use tokio::time::Instant;

static SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));

fn check_deadline(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "system DNS resolution deadline expired",
        ))
    } else {
        Ok(())
    }
}

pub(crate) async fn lookup(host: &str, port: u16, until: Instant) -> io::Result<Vec<SocketAddr>> {
    check_deadline(until)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let host = host.to_owned();
    lookup_with(SLOTS.clone(), until, move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .map(Iterator::collect)
    })
    .await
}

async fn lookup_with(
    slots: Arc<Semaphore>,
    until: Instant,
    resolve: impl FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
) -> io::Result<Vec<SocketAddr>> {
    check_deadline(until)?;
    let permit = tokio::time::timeout_at(until, slots.acquire_owned())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "system DNS resolver queue expired"))?
        .map_err(|_| io::Error::other("system DNS resolver unavailable"))?;
    check_deadline(until)?;
    let (send, receive) = oneshot::channel();
    std::thread::Builder::new()
        .name("qeli-system-dns".into())
        .spawn(move || {
            // Cancellation/timeouts may drop the receiver, but never free a live NSS slot.
            let _permit = permit;
            if send.is_closed() {
                return;
            }
            let result = check_deadline(until).and_then(|()| resolve());
            let _ = send.send(result);
        })?;
    let result = tokio::time::timeout_at(until, receive)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "system DNS resolution timed out"))?
        .map_err(|_| io::Error::other("system DNS resolver worker terminated"))?;
    // timeout_at may return an already-ready result after its deadline.
    check_deadline(until)?;
    result
}

#[cfg(test)]
mod tests;

// Resolver-file discovery is read-only and shares the same bounded worker admission.
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
pub(crate) async fn system_upstreams(until: Instant) -> io::Result<Vec<SocketAddr>> {
    lookup_with(SLOTS.clone(), until, || {
        system_config::snapshot(&[
            std::path::Path::new("/run/systemd/resolve/resolv.conf"),
            std::path::Path::new("/etc/resolv.conf"),
        ])
    })
    .await
}

#[cfg(any(test, all(target_os = "linux", feature = "client")))]
pub(crate) mod system_config;
