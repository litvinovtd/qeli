use portable_atomic::AtomicU64;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{atomic::Ordering, Arc};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// A conservative initial budget for a *pending* write with no byte progress.
/// This is not an idle lifetime or a deadline for completing a whole record.
pub(crate) const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Bytes accepted at a particular lower I/O boundary. This is not a peer ACK or
/// application-delivery counter. Buffered adapters share their raw-write counter
/// with their outer guard so a slowly draining TLS/WS record is not timed out.
#[derive(Clone, Debug, Default)]
pub struct WriteProgress(Arc<AtomicU64>);

impl WriteProgress {
    pub(crate) fn snapshot(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn advance(&self, bytes: usize) {
        self.0.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// Terminal no-progress guard. Its timer is polled by the blocked I/O future,
/// independently of the session select loop. A timed-out partial record must
/// never be retried on this carrier; all subsequent writes fail as well.
#[derive(Debug)]
pub struct StallGuard<W> {
    inner: W,
    progress: WriteProgress,
    report_writes: bool,
    observed: u64,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    budget: Duration,
    failed: bool,
}

impl<W> StallGuard<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self::observing(inner, None)
    }

    pub(crate) fn observing(inner: W, progress: Option<WriteProgress>) -> Self {
        let report_writes = progress.is_none();
        let progress = progress.unwrap_or_default();
        Self {
            inner,
            observed: progress.snapshot(),
            progress,
            report_writes,
            timer: None,
            budget: WRITE_STALL_TIMEOUT,
            failed: false,
        }
    }

    pub(crate) fn progress(&self) -> WriteProgress {
        self.progress.clone()
    }
    pub(crate) fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    fn timeout_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "carrier write made no progress; carrier is terminal",
        )
    }

    fn pending<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        let progress = self.progress.snapshot();
        if self.timer.is_none() || progress != self.observed {
            self.observed = progress;
            self.timer = Some(Box::pin(tokio::time::sleep(self.budget)));
        }
        if self.timer.as_mut().unwrap().as_mut().poll(cx).is_ready() {
            self.failed = true;
            log::warn!(
                "Carrier closed: pending write/flush made no progress for {}s",
                self.budget.as_secs()
            );
            Poll::Ready(Err(Self::timeout_error()))
        } else {
            Poll::Pending
        }
    }
}

impl<W: AsyncRead + Unpin> AsyncRead for StallGuard<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for StallGuard<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.failed {
            return Poll::Ready(Err(Self::timeout_error()));
        }
        match Pin::new(&mut me.inner).poll_write(cx, buf) {
            Poll::Pending => me.pending(cx),
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    if me.report_writes {
                        me.progress.advance(n);
                    }
                    // Acceptance at an outer buffered boundary does not reset the
                    // lower-boundary clock; pending() observes the shared counter.
                    if me.report_writes {
                        me.timer = None;
                    }
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(error)) => {
                me.failed = true;
                Poll::Ready(Err(error))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.failed {
            return Poll::Ready(Err(Self::timeout_error()));
        }
        match Pin::new(&mut me.inner).poll_flush(cx) {
            Poll::Pending => me.pending(cx),
            Poll::Ready(result) => {
                me.timer = None;
                me.failed = result.is_err();
                Poll::Ready(result)
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.failed {
            return Poll::Ready(Err(Self::timeout_error()));
        }
        match Pin::new(&mut me.inner).poll_shutdown(cx) {
            Poll::Pending => me.pending(cx),
            Poll::Ready(result) => {
                me.timer = None;
                me.failed = result.is_err();
                Poll::Ready(result)
            }
        }
    }
}

/// Finish one protocol write before waiting for a peer response or recording delivery.
/// Buffered wire adapters may accept plaintext before their socket is writable.
/// Keep this boundary identical in daemon and native-core session/data pumps.
pub(crate) trait WriteAllFlush: AsyncWrite + Unpin {
    async fn write_all_flush(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.write_all(bytes).await?;
        self.flush().await
    }
}
impl<W: AsyncWrite + Unpin + ?Sized> WriteAllFlush for W {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct PartialThenPending {
        calls: Arc<AtomicUsize>,
    }
    impl AsyncWrite for PartialThenPending {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Poll::Ready(Ok(1))
            } else {
                Poll::Pending
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn partial_record_stall_is_terminal_and_never_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut writer = StallGuard::new(PartialThenPending {
            calls: calls.clone(),
        });
        writer.budget = Duration::from_millis(30);
        let error = tokio::time::timeout(Duration::from_secs(2), writer.write_all(b"record"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let before = calls.load(Ordering::Relaxed);
        assert_eq!(
            writer.write_all(b"next record").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            before,
            "poisoned carrier reached inner writer"
        );
    }

    #[tokio::test]
    async fn idle_carrier_does_not_arm_a_write_deadline() {
        let mut writer = StallGuard::new(tokio::io::sink());
        writer.budget = Duration::from_millis(20);
        tokio::time::sleep(Duration::from_millis(60)).await;
        writer
            .write_all_flush(b"first record after idle")
            .await
            .unwrap();
        assert!(writer.timer.is_none());
    }

    // Models an adapter that accepts plaintext, then drains a record slowly at
    // its lower I/O boundary while its public flush remains Pending throughout.
    struct BufferedDrain {
        progress: WriteProgress,
        remaining: usize,
        delay: Pin<Box<tokio::time::Sleep>>,
    }
    impl AsyncWrite for BufferedDrain {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let me = self.get_mut();
            if me.remaining == 0 {
                return Poll::Ready(Ok(()));
            }
            if me.delay.as_mut().poll(cx).is_ready() {
                me.progress.advance(1);
                me.remaining -= 1;
                me.delay
                    .as_mut()
                    .reset(tokio::time::Instant::now() + Duration::from_millis(20));
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    #[tokio::test]
    async fn lower_byte_progress_keeps_a_long_buffered_flush_alive() {
        let progress = WriteProgress::default();
        let inner = BufferedDrain {
            progress: progress.clone(),
            remaining: 15,
            delay: Box::pin(tokio::time::sleep(Duration::from_millis(20))),
        };
        let mut writer = StallGuard::observing(inner, Some(progress));
        writer.budget = Duration::from_millis(100);
        let start = tokio::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(3),
            writer.write_all_flush(b"buffered record"),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            start.elapsed() > writer.budget,
            "test must exceed a whole-record deadline"
        );
    }

    #[tokio::test]
    async fn buffered_acceptance_does_not_hide_a_stalled_flush() {
        let progress = WriteProgress::default();
        let inner = BufferedDrain {
            progress: progress.clone(),
            remaining: 1,
            delay: Box::pin(tokio::time::sleep(Duration::from_secs(60))),
        };
        let mut writer = StallGuard::observing(inner, Some(progress));
        writer.budget = Duration::from_millis(30);
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            writer.write_all_flush(b"buffered record"),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(writer.failed);
    }
}
