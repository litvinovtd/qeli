//! One owned diagnostics writer: at most one in-flight and one pending snapshot.
//! A fresh thread inherits the caller's OS context; no pooled thread changes namespaces.
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

struct Queue<T> {
    latest: Option<T>,
    closed: bool,
}
struct Shared<T> {
    queue: Mutex<Queue<T>>,
    ready: Condvar,
}
impl<T> Shared<T> {
    fn close(&self) {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        self.ready.notify_one();
    }
}

pub(super) struct Sender<T>(Arc<Shared<T>>);
impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> Sender<T> {
    /// Snapshot ordering is established by the caller's state lock, not file I/O.
    pub(super) fn submit(&self, snapshot: T) -> bool {
        let mut queue = self.0.queue.lock().unwrap_or_else(|e| e.into_inner());
        if queue.closed {
            return false;
        }
        queue.latest = Some(snapshot);
        self.0.ready.notify_one();
        true
    }
}

pub(super) struct Writer<T> {
    shared: Arc<Shared<T>>,
    thread: Option<JoinHandle<()>>,
    completion: Option<tokio::sync::oneshot::Receiver<()>>,
}
impl<T: Send + 'static> Writer<T> {
    pub(super) fn start(
        mut write: impl FnMut(T) + Send + 'static,
    ) -> std::io::Result<(Sender<T>, Self)> {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                latest: None,
                closed: false,
            }),
            ready: Condvar::new(),
        });
        let worker = shared.clone();
        let (done, completion) = tokio::sync::oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("qeli-status".into())
            .spawn(move || {
                // Close admission even on panic. No sender owns the worker lifetime.
                struct Exit<T>(Arc<Shared<T>>);
                impl<T> Drop for Exit<T> {
                    fn drop(&mut self) {
                        self.0.close();
                    }
                }
                let exit = Exit(worker.clone());
                loop {
                    let next = {
                        let mut queue = worker.queue.lock().unwrap_or_else(|e| e.into_inner());
                        while queue.latest.is_none() && !queue.closed {
                            queue = worker.ready.wait(queue).unwrap_or_else(|e| e.into_inner());
                        }
                        queue.latest.take()
                    };
                    let Some(snapshot) = next else { break };
                    write(snapshot);
                }
                drop(write);
                drop(exit);
                let _ = done.send(());
            })?;
        Ok((
            Sender(shared.clone()),
            Self {
                shared,
                thread: Some(thread),
                completion: Some(completion),
            },
        ))
    }

    /// Close, flush the last accepted snapshot and join. Cancelling this wait retains
    /// ownership, so it can be retried; dropping the owner instead uses the joined fallback.
    pub(super) async fn finish(&mut self) -> anyhow::Result<()> {
        self.shared.close();
        if let Some(completion) = self.completion.as_mut() {
            let _ = completion.await;
            self.completion.take();
        }
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("client diagnostics writer panicked"))?;
        }
        Ok(())
    }
}
impl<T> Drop for Writer<T> {
    fn drop(&mut self) {
        self.shared.close();
        // No detached file writes may outlive this client. Forced Drop can block on I/O;
        // ordinary shutdown awaits completion without occupying the async executor.
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                log::error!("client diagnostics writer panicked during shutdown");
            }
        }
    }
}

#[cfg(test)]
#[path = "status_writer_tests.rs"]
mod tests;
