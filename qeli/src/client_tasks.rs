//! Finish client-owned background work before publishing the terminal status.
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

#[cfg(target_os = "linux")]
static CLIENT_INSTANCE: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(1)));

/// The Linux runtime uses process-global carrier state. Admission precedes all
/// startup side effects and lasts through final publication. Forced cancellation
/// permanently closes admission: nested transport groups can only request abort
/// in Drop and cannot prove that all their async/blocking children have stopped.
pub(crate) struct Owner {
    tasks: JoinSet<()>,
    _permit: OwnedSemaphorePermit,
    gate: Arc<Semaphore>,
    completed: bool,
}

impl Owner {
    #[cfg(target_os = "linux")]
    pub(crate) fn acquire() -> anyhow::Result<Self> {
        Self::with_gate(CLIENT_INSTANCE.clone())
    }

    fn with_gate(gate: Arc<Semaphore>) -> anyhow::Result<Self> {
        let permit = gate
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => {
                    anyhow::anyhow!("a Linux client is already running in this process")
                }
                tokio::sync::TryAcquireError::Closed => anyhow::anyhow!(
                "previous Linux client was cancelled before cleanup completed; restart the process"
            ),
            })?;
        Ok(Self {
            tasks: JoinSet::new(),
            _permit: permit,
            gate,
            completed: false,
        })
    }

    pub(crate) fn spawn(&mut self, work: impl std::future::Future<Output = ()> + Send + 'static) {
        self.tasks.spawn(work);
    }

    pub(crate) async fn finish(&mut self) {
        finish(&mut self.tasks, || {}).await;
    }

    /// Only the outer runtime calls this after all cleanup and final publication.
    pub(crate) fn complete(mut self) {
        assert!(
            self.tasks.is_empty(),
            "client tasks must finish before release"
        );
        self.completed = true;
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        if !self.completed {
            self.gate.close();
        }
    }
}

pub(crate) async fn finish(tasks: &mut JoinSet<()>, publish: impl FnOnce()) {
    tasks.abort_all();
    // Aborting does not wait for a synchronous publish already in progress. Keep the
    // handles in the owner's JoinSet until every writer ends, including after a waiter
    // is cancelled and retried. No older diagnostic snapshot can then overwrite final.
    while let Some(result) = tasks.join_next().await {
        if result.is_err_and(|error| !error.is_cancelled()) {
            log::error!("client background task failed during shutdown");
        }
    }
    publish();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(5);

    async fn blocked_writer(
        tasks: &mut JoinSet<()>,
        events: Arc<Mutex<Vec<&'static str>>>,
    ) -> std::sync::mpsc::Sender<()> {
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        tasks.spawn(async move {
            started.send(()).unwrap();
            // Simulate an in-flight synchronous status-file write. Aborting a Tokio task
            // cannot interrupt it; dropping release also unblocks on a failed assertion.
            let _ = blocked.recv();
            events.lock().unwrap().push("old snapshot");
        });
        tokio::time::timeout(DEADLINE, ready)
            .await
            .unwrap()
            .unwrap();
        release
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn final_publication_waits_for_an_inflight_writer() {
        let mut tasks = JoinSet::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let release = blocked_writer(&mut tasks, events.clone()).await;
        let output = events.clone();
        let mut finishing = tokio::spawn(async move {
            finish(&mut tasks, || output.lock().unwrap().push("final")).await;
            assert!(tasks.is_empty());
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut finishing)
                .await
                .is_err()
        );
        assert!(events.lock().unwrap().is_empty());
        release.send(()).unwrap();
        tokio::time::timeout(DEADLINE, finishing)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*events.lock().unwrap(), vec!["old snapshot", "final"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_finish_can_be_retried_without_losing_the_writer() {
        let mut tasks = JoinSet::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let release = blocked_writer(&mut tasks, events.clone()).await;
        assert!(tokio::time::timeout(
            Duration::from_millis(30),
            finish(&mut tasks, || panic!("published before writer ended"))
        )
        .await
        .is_err());
        assert!(!tasks.is_empty());
        release.send(()).unwrap();
        tokio::time::timeout(
            DEADLINE,
            finish(&mut tasks, || events.lock().unwrap().push("final")),
        )
        .await
        .unwrap();
        assert_eq!(*events.lock().unwrap(), vec!["old snapshot", "final"]);
    }

    #[tokio::test]
    async fn panic_does_not_skip_other_destructors_or_final_status() {
        struct Lease(Arc<AtomicBool>);
        impl Drop for Lease {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let released = Arc::new(AtomicBool::new(false));
        let lease = Lease(released.clone());
        let mut tasks = JoinSet::new();
        let (started, ready) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            started.send(()).unwrap();
            panic!("fixture task panic");
        });
        tasks.spawn(async move {
            let _lease = lease;
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        finish(&mut tasks, || assert!(released.load(Ordering::Acquire))).await;
        assert!(tasks.is_empty());
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn finish_holds_admission_until_terminal_completion() {
        let gate = Arc::new(Semaphore::new(1));
        let mut owner = Owner::with_gate(gate.clone()).unwrap();
        assert!(Owner::with_gate(gate.clone()).is_err());
        owner.spawn(std::future::pending());
        owner.finish().await;
        assert!(Owner::with_gate(gate.clone()).is_err());
        owner.complete();
        assert!(Owner::with_gate(gate).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborted_owner_requires_process_restart_even_after_child_finishes() {
        let gate = Arc::new(Semaphore::new(1));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let (ended, child_done) = tokio::sync::oneshot::channel();
        let task_gate = gate.clone();
        let parent = tokio::spawn(async move {
            let mut owner = Owner::with_gate(task_gate).unwrap();
            owner.spawn(async move {
                started.send(()).unwrap();
                let _ = blocked.recv_timeout(Duration::from_secs(5));
                let _ = ended.send(());
            });
            std::future::pending::<()>().await;
            owner.finish().await;
        });
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        parent.abort();
        assert!(parent.await.unwrap_err().is_cancelled());
        assert!(Owner::with_gate(gate.clone()).is_err());
        assert!(gate.is_closed());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), child_done)
            .await
            .unwrap()
            .unwrap();
        let error = Owner::with_gate(gate).err().unwrap();
        assert!(error.to_string().contains("restart the process"));
    }

    #[tokio::test]
    async fn child_panic_does_not_release_parent_admission() {
        let gate = Arc::new(Semaphore::new(1));
        let mut owner = Owner::with_gate(gate.clone()).unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        owner.spawn(async move {
            started.send(()).unwrap();
            panic!("admission test panic");
        });
        ready.await.unwrap();
        owner.finish().await;
        assert!(Owner::with_gate(gate.clone()).is_err());
        owner.complete();
        assert!(Owner::with_gate(gate).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn simultaneous_admission_has_one_winner() {
        let gate = Arc::new(Semaphore::new(1));
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut contenders = JoinSet::new();
        for _ in 0..2 {
            let gate = gate.clone();
            let barrier = barrier.clone();
            contenders.spawn(async move {
                barrier.wait().await;
                Owner::with_gate(gate)
            });
        }
        barrier.wait().await;
        let first = contenders.join_next().await.unwrap().unwrap();
        let second = contenders.join_next().await.unwrap().unwrap();
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        for owner in [first, second].into_iter().flatten() {
            owner.complete();
        }
        assert!(Owner::with_gate(gate).is_ok());
    }

    #[cfg(all(target_os = "linux", feature = "client"))]
    #[tokio::test]
    async fn public_client_rejects_overlap_before_config_and_releases_after_startup_error() {
        let owner = Owner::acquire().unwrap();
        let missing = format!(
            "/qeli-missing-config-{}-{}.ini",
            std::process::id(),
            rand::random::<u64>()
        );
        let error = crate::client::run_client(&missing).await.unwrap_err();
        assert!(error.to_string().contains("already running"), "{error:#}");
        owner.complete();
        // An ordinary startup error must release admission for a subsequent call.
        for _ in 0..2 {
            let error = crate::client::run_client(&missing).await.unwrap_err();
            assert!(!error.to_string().contains("already running"), "{error:#}");
            assert!(format!("{error:#}").contains("No such file"), "{error:#}");
        }
    }
}
