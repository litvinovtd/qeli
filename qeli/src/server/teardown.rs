//! Resource-teardown evidence and bounded joining of generation-owned TUN threads.
use crate::server_shutdown::Failures;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Run a synchronous host operation away from the Tokio executor. A cancelled
/// waiter joins its worker before the caller can release its outer resources.
/// An unadopted result (including a firewall lease with a blocking Drop) is
/// destroyed on that worker, in the network namespace where it was created.
pub(crate) async fn blocking<R: Send + 'static>(
    name: &'static str,
    operation: impl FnOnce() -> R + Send + 'static,
) -> anyhow::Result<R> {
    struct JoinOnDrop<R> {
        adopt: Option<std::sync::mpsc::Sender<()>>,
        thread: Option<JoinHandle<Option<R>>>,
    }
    impl<R> Drop for JoinOnDrop<R> {
        fn drop(&mut self) {
            // Closing admission makes the worker drop an unadopted result first.
            self.adopt.take();
            if let Some(thread) = self.thread.take() {
                if thread.join().is_err() {
                    log::error!("server host worker panicked during cancelled cleanup");
                }
            }
        }
    }

    let (finished, waiting) = tokio::sync::oneshot::channel();
    let (adopt, decision) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let result = operation();
            let _ = finished.send(());
            if decision.recv().is_ok() {
                Some(result)
            } else {
                drop(result);
                None
            }
        })?;
    let mut owned = JoinOnDrop {
        adopt: Some(adopt),
        thread: Some(thread),
    };
    let _ = waiting.await; // A panic closes the sender; join below reports it.
                           // No await after adoption: a cancelled future closes the channel instead and
                           // joins rollback in Drop, before its enclosing profile guard can disappear.
    if let Some(adopt) = owned.adopt.take() {
        let _ = adopt.send(());
    }
    owned
        .thread
        .take()
        .expect("server host worker")
        .join()
        .map_err(|_| anyhow::anyhow!("server host worker '{name}' panicked"))?
        .ok_or_else(|| anyhow::anyhow!("server host worker '{name}' was not adopted"))
}

/// The wrapper reads this after dropping its guard. Sharing preserves the existing
/// RAII cleanup order without running resource teardown a second time.
#[derive(Clone, Default)]
pub(crate) struct Report(Arc<Mutex<Failures>>);
impl Report {
    pub(crate) fn record(&self, label: &str, result: anyhow::Result<()>) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(label, result);
    }
    pub(crate) fn result(&self) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .result()
    }
}

/// Worker-owned resources awaiting asynchronous joining after a scope is cancelled.
/// Take only one entry into another requeue-on-drop scope before awaiting it.
/// If the owner itself disappears, unresolved resources remain quarantined until
/// process exit instead of running destructors ahead of their async descendants.
pub(crate) struct Deferred<T> {
    entries: Mutex<Vec<T>>,
    #[cfg(all(target_os = "linux", feature = "server"))]
    pub(crate) failures: Report,
}

impl<T> Default for Deferred<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            #[cfg(all(target_os = "linux", feature = "server"))]
            failures: Report::default(),
        }
    }
}

impl<T> Deferred<T> {
    pub(crate) fn retain(&self, entry: T) {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(entry);
    }

    pub(crate) fn take(&self) -> Option<T> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
    }
}

impl<T> Drop for Deferred<T> {
    fn drop(&mut self) {
        let entries = self
            .entries
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !entries.is_empty() {
            log::error!("{} deferred profile cleanup(s) have no async owner; resources retained until process exit", entries.len());
        }
        for entry in entries.drain(..) {
            std::mem::forget(entry);
        }
    }
}

/// A transient generation failure may be retried only after its resource cleanup succeeded.
/// Cleanup failure must reach the worker: otherwise a backoff/replacement loses old evidence.
pub(crate) struct Outcome {
    result: anyhow::Result<()>,
    restart_safe: bool,
}

impl Outcome {
    pub(crate) fn new(run: anyhow::Result<()>, cleanup: anyhow::Result<()>) -> Self {
        let restart_safe = cleanup.is_ok();
        let mut failures = Failures::default();
        failures.record("generation", run);
        failures.record("generation cleanup", cleanup);
        Self {
            result: failures.result(),
            restart_safe,
        }
    }

    pub(crate) fn can_restart(&self) -> bool {
        self.restart_safe
    }
    pub(crate) fn result(&self) -> &anyhow::Result<()> {
        &self.result
    }
    pub(crate) fn into_result(self) -> anyhow::Result<()> {
        self.result
    }
}

/// Caller raises stop flags and wakes channels first. Retain all handles during wakes
/// so pthread identifiers cannot be reused before the final wake; join only finished threads.
pub(crate) fn stop_threads(
    handles: Vec<JoinHandle<()>>,
    grace: Duration,
    mut wake: impl FnMut(),
) -> anyhow::Result<()> {
    let deadline = Instant::now() + grace;
    let mut failures = Failures::default();
    loop {
        wake();
        if handles.iter().all(JoinHandle::is_finished) {
            break;
        }
        if Instant::now() >= deadline {
            let pending = handles
                .iter()
                .filter(|handle| !handle.is_finished())
                .count();
            failures.record("TUN queues", Err(anyhow::anyhow!("{pending} queue thread(s) did not stop within {grace:?}; detached threads may retain the device")));
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    for handle in handles {
        if handle.is_finished() {
            let name = handle.thread().name().unwrap_or("unnamed").to_string();
            if let Err(panic) = handle.join() {
                let detail = panic
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("non-string panic payload");
                failures.record(
                    &format!("TUN queue thread {name}"),
                    Err(anyhow::anyhow!("panicked: {detail}")),
                );
            }
        }
    }
    failures.result()
}

#[cfg(test)]
#[path = "teardown/tests.rs"]
mod tests;
