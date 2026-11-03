//! Panel listener and accepted-connection lifetime, including TLS handshakes.
use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};
use tokio::sync::watch;

const DRAIN_GRACE: Duration = Duration::from_secs(2);

pub(super) struct StopOnDrop(pub(super) axum_server::Handle<SocketAddr>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// axum-server watches shutdown only after Accept completes. Cancel an in-flight
/// TLS handshake as well, so silent peers cannot outlive the supervisor generation.
#[derive(Clone)]
pub(super) struct StoppableAccept<A> {
    pub(super) inner: A,
    pub(super) shutdown: watch::Receiver<bool>,
}
impl<A, I, S> axum_server::accept::Accept<I, S> for StoppableAccept<A>
where
    A: axum_server::accept::Accept<I, S>,
    A::Future: Send + 'static,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = A::Stream;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;
    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accept = self.inner.accept(stream, service);
        let mut shutdown = self.shutdown.clone();
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = crate::server_supervisor::wait_for_shutdown(&mut shutdown) => {
                    Err(io::Error::new(io::ErrorKind::Interrupted, "panel stopping"))
                },
                result = accept => result,
            }
        })
    }
}

pub(super) async fn serve(
    future: impl Future<Output = io::Result<()>>,
    guard: StopOnDrop,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tokio::pin!(future);
    let result = tokio::select! {
        biased;
        _ = crate::server_supervisor::wait_for_shutdown(shutdown) => {
            guard.0.graceful_shutdown(Some(DRAIN_GRACE));
            future.await
        },
        result = &mut future => result,
    };
    // A failed serve or expired graceful wait must close accepted connections too.
    guard.0.shutdown();
    tokio::time::timeout(DRAIN_GRACE, async {
        while guard.0.connection_count() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("panel connection drain exceeded its deadline"))?;
    result.map_err(Into::into)
}
