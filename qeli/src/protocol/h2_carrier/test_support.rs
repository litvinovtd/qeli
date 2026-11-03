use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub(super) const DEADLINE: Duration = Duration::from_secs(5);
pub(super) const PROBE: Duration = Duration::from_millis(30);

pub(super) struct ObservedIo {
    io: DuplexStream,
    released: Arc<AtomicBool>,
    gate: Option<(
        tokio::sync::oneshot::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
}

impl Drop for ObservedIo {
    fn drop(&mut self) {
        if let Some((started, wait)) = self.gate.take() {
            let _ = started.send(());
            let _ = wait.recv_timeout(DEADLINE);
        }
        self.released.store(true, Ordering::Release);
    }
}

impl AsyncRead for ObservedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ObservedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

pub(super) fn observed_pair() -> (ObservedIo, DuplexStream, Arc<AtomicBool>) {
    let (io, peer) = tokio::io::duplex(64 * 1024);
    let released = Arc::new(AtomicBool::new(false));
    (
        ObservedIo {
            io,
            released: released.clone(),
            gate: None,
        },
        peer,
        released,
    )
}

pub(super) fn hold_drop(
    io: &mut ObservedIo,
) -> (
    std::sync::mpsc::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    io.gate = Some((started, wait));
    (release, ready)
}
