//! One owned TOFU worker. A cancelled handshake never detaches admitted file work.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::JoinHandle;
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

type Key = [u8; 32];
struct Request {
    key: Key,
    reply: oneshot::Sender<Receipt>,
    permit: Admission,
}
struct Shared {
    sender: Mutex<Option<mpsc::Sender<Request>>>,
    admission: Arc<Semaphore>,
    unobserved: Mutex<Option<String>>,
    outstanding: AtomicBool,
    settled: tokio::sync::Notify,
}
impl Shared {
    fn close(&self) {
        self.admission.close();
        self.sender.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
    fn outcome(&self) -> anyhow::Result<()> {
        match self
            .unobserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            Some(error) => anyhow::bail!("unobserved identity verification failure: {error}"),
            None => Ok(()),
        }
    }
}
struct Admission {
    shared: Arc<Shared>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Admission {
    fn drop(&mut self) {
        self.shared.outstanding.store(false, Ordering::Release);
        self.shared.settled.notify_one();
    }
}
struct Receipt {
    result: Option<anyhow::Result<()>>,
    shared: Arc<Shared>,
    // Released only after observation or recording the abandoned error, so a drain
    // cannot race the result's delivery through the oneshot channel.
    _permit: Admission,
}
impl Drop for Receipt {
    fn drop(&mut self) {
        if let Some(Err(error)) = self.result.take() {
            let mut slot = self
                .shared
                .unobserved
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            slot.get_or_insert_with(|| format!("{error:#}").chars().take(2048).collect());
        }
    }
}
#[derive(Clone)]
pub(super) struct Verifier(Arc<Shared>);
impl Verifier {
    pub(super) async fn verify(&self, key: Key, cancel: Arc<AtomicBool>) -> anyhow::Result<()> {
        let stopped = async {
            while !cancel.load(Ordering::Acquire) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::pin!(stopped);
        let permit = tokio::select! {
            biased;
            _ = &mut stopped => anyhow::bail!("identity verification cancelled before admission"),
            permit = self.0.admission.clone().acquire_owned() => permit.map_err(|_| anyhow::anyhow!("identity worker is closed"))?,
        };
        let (reply, response) = oneshot::channel();
        {
            let sender = self.0.sender.lock().unwrap_or_else(|e| e.into_inner());
            let sender = sender
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("identity worker is closed"))?;
            self.0.outstanding.store(true, Ordering::Release);
            sender
                .send(Request {
                    key,
                    reply,
                    permit: Admission {
                        shared: self.0.clone(),
                        _permit: permit,
                    },
                })
                .map_err(|_| anyhow::anyhow!("identity worker stopped"))?;
        }
        // The owner, not this handshake future, retains and joins the worker. Dropping
        // response records a late error even if the result was already delivered.
        let mut receipt = tokio::select! {
            biased;
            _ = &mut stopped => anyhow::bail!("identity verification cancelled after admission"),
            result = response => result.map_err(|_| anyhow::anyhow!("identity worker stopped before replying"))?,
        };
        receipt.result.take().expect("unobserved identity result")
    }
    /// Called only after every handshake in the attempt has stopped. No subsequent
    /// attempt may begin while a cancelled request still owns its permit.
    pub(super) async fn drain(&self) -> anyhow::Result<()> {
        let _permit = self
            .0
            .admission
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("identity worker is closed"))?;
        self.0.outcome()
    }
}
pub(super) struct Worker {
    shared: Arc<Shared>,
    completion: Option<oneshot::Receiver<()>>,
    thread: Option<JoinHandle<()>>,
}
impl Worker {
    pub(super) fn start(
        mut verify: impl FnMut(Key) -> anyhow::Result<()> + Send + 'static,
    ) -> std::io::Result<(Verifier, Self)> {
        let (sender, requests) = mpsc::channel::<Request>();
        let shared = Arc::new(Shared {
            sender: Mutex::new(Some(sender)),
            admission: Arc::new(Semaphore::new(1)),
            unobserved: Mutex::new(None),
            outstanding: AtomicBool::new(false),
            settled: tokio::sync::Notify::new(),
        });
        let worker = shared.clone();
        let (done, completion) = oneshot::channel();
        // A fresh thread inherits this client's mount/network context. Admission
        // permits bound both the channel and unacknowledged results to one request.
        let thread = std::thread::Builder::new()
            .name("qeli-identity".into())
            .spawn(move || {
                struct Exit(Arc<Shared>);
                impl Drop for Exit {
                    fn drop(&mut self) {
                        self.0.close();
                    }
                }
                let exit = Exit(worker.clone());
                while let Ok(request) = requests.recv() {
                    let result = verify(request.key);
                    let _ = request.reply.send(Receipt {
                        result: Some(result),
                        shared: worker.clone(),
                        _permit: request.permit,
                    });
                }
                drop(verify);
                drop(exit);
                let _ = done.send(());
            })?;
        Ok((
            Verifier(shared.clone()),
            Self {
                shared,
                completion: Some(completion),
                thread: Some(thread),
            },
        ))
    }
    pub(super) async fn finish(&mut self) -> anyhow::Result<()> {
        self.shared.close();
        if let Some(completion) = self.completion.as_mut() {
            let _ = completion.await;
            self.completion.take();
        }
        // A oneshot may already contain a result that its handshake never polled.
        // Wait for acknowledgement/drop before reading unobserved errors.
        loop {
            let settled = self.shared.settled.notified();
            if !self.shared.outstanding.load(Ordering::Acquire) {
                break;
            }
            settled.await;
        }
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("identity worker panicked"))?;
        }
        self.shared.outcome()
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.shared.close();
        // Forced owner cancellation must not leave a file mutation behind. Ordinary
        // shutdown awaits finish; only this fallback may synchronously wait on I/O.
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                log::error!("identity worker panicked during shutdown");
            }
        }
        if let Err(error) = self.shared.outcome() {
            log::error!("{error:#}");
        }
    }
}
#[cfg(test)]
#[path = "identity_worker_tests.rs"]
mod tests;
