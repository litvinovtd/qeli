//! A hook owns its file preparation, process runtime and file cleanup on one thread.
//! Normal waiting is async. Forced Drop signals stop and joins; it cannot preempt a
//! filesystem syscall, but no hook file mutation or shell spawn can outlive the owner.
use std::{future::Future, io, thread::JoinHandle};
use tokio::sync::oneshot;

struct Job<T> {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<io::Result<T>>>,
}
impl<T> Job<T> {
    fn finish(mut self) -> io::Result<T> {
        self.thread
            .take()
            .expect("hook worker")
            .join()
            .map_err(|_| io::Error::other("hook worker panicked"))?
    }
}
impl<T> Drop for Job<T> {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                log::warn!("hook worker panicked during cancellation");
            }
        }
    }
}

pub(super) async fn run<T: Send + 'static, F: Future<Output = T> + 'static>(
    work: impl FnOnce(oneshot::Receiver<()>) -> F + Send + 'static,
) -> io::Result<T> {
    let (stop, cancelled) = oneshot::channel();
    let (done, completion) = oneshot::channel();
    // A fresh thread inherits the caller's namespaces; a pooled thread need not.
    let thread = std::thread::Builder::new()
        .name("qeli-hook".into())
        .spawn(move || {
            let result = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                Ok(runtime.block_on(work(cancelled)))
            })();
            let _ = done.send(()); // Includes work's destructors and runtime shutdown.
            result
        })?;
    let job = Job {
        stop: Some(stop),
        thread: Some(thread),
    };
    let _ = completion.await;
    job.finish()
}
