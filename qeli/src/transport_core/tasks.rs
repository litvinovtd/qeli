//! One connection generation owns both its producers and their child tasks.
use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex, Weak};
use tokio::task::JoinSet;

#[derive(Default)]
struct State {
    closed: bool,
    tasks: JoinSet<()>,
}

#[derive(Default)]
pub(crate) struct TaskGroup(Arc<Mutex<State>>);

// A producer must not keep its own owner alive through the task registry.
#[derive(Clone)]
pub(crate) struct Spawner(Weak<Mutex<State>>);

/// A cancelled attempt must close task admission BEFORE dropping its network resources.
/// The outer TaskGroup keeps the join handles and can still finish after this scope is gone.
pub(crate) struct TaskScope<F> {
    future: std::pin::Pin<Box<F>>,
    owner: Spawner,
}

impl<F: Future> Future for TaskScope<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.get_mut().future.as_mut().poll(cx)
    }
}

impl<F> Drop for TaskScope<F> {
    fn drop(&mut self) {
        if let Some(shared) = self.owner.0.upgrade() {
            close(&shared);
        }
        // Fields drop after this body, so captured network guards see closed admission.
    }
}

/// Per-path cancellation, while the generation retains the authoritative join handle.
/// Moving this handle transfers the path; dropping it requests cancellation, never detach.
pub(crate) struct TaskHandle {
    abort: Option<tokio::task::AbortHandle>,
    completed: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl TaskHandle {
    pub(crate) async fn finish(&mut self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
        if let Some(completed) = self.completed.as_mut() {
            let _ = completed.await;
            self.completed = None;
        }
    }
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }
}

// Construct this before spawning, so even a never-polled task releases its captures before
// notifying a path waiter. Explicit drop order also covers cancellation and panic unwinding.
struct TaskCompletion<F> {
    future: Option<std::pin::Pin<Box<F>>>,
    completed: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<F> Drop for TaskCompletion<F> {
    fn drop(&mut self) {
        drop(self.future.take());
        if let Some(completed) = self.completed.take() {
            let _ = completed.send(());
        }
    }
}

fn report(result: Result<(), tokio::task::JoinError>) {
    if result.is_err_and(|error| !error.is_cancelled()) {
        // Do not copy a possibly sensitive panic payload into connection diagnostics.
        log::error!("connection background task failed");
    }
}

fn close(shared: &Mutex<State>) {
    let mut state = crate::util::lock_or_recover(shared, "connection_tasks");
    state.closed = true;
    state.tasks.abort_all();
}

impl TaskGroup {
    pub(crate) fn spawner(&self) -> Spawner {
        Spawner(Arc::downgrade(&self.0))
    }

    pub(crate) async fn finish(&mut self) {
        close(&self.0);
        // Keep handles in the group while pending: cancelling this waiter cannot detach
        // in-flight work. A retry waits for the same tasks, including blocking closures.
        while let Some(result) = poll_fn(|cx| {
            crate::util::lock_or_recover(&self.0, "connection_tasks")
                .tasks
                .poll_join_next(cx)
        })
        .await
        {
            report(result);
        }
    }
}

impl Drop for TaskGroup {
    fn drop(&mut self) {
        // Drop cannot join asynchronously or interrupt a running blocking closure. It does
        // close admission and request cancellation even if producers still hold Spawners.
        close(&self.0);
    }
}

impl Spawner {
    pub(crate) fn scope<F: Future>(&self, future: F) -> TaskScope<F> {
        TaskScope {
            future: Box::pin(future),
            owner: self.clone(),
        }
    }

    fn admit(&self, spawn: impl FnOnce(&mut JoinSet<()>)) -> bool {
        let Some(shared) = self.0.upgrade() else {
            return false;
        };
        let mut state = crate::util::lock_or_recover(&shared, "connection_tasks");
        if state.closed {
            // Drop rejected captures outside the mutex: their destructors may use a Spawner.
            drop(state);
            return false;
        }
        // Long-lived handovers must not accumulate completed task allocations.
        let mut completed = Vec::new();
        while let Some(result) = state.tasks.try_join_next() {
            completed.push(result);
        }
        // Admission and actual spawning share the shutdown lock. No already-spawned handle
        // can arrive after the drain, and Tokio does not synchronously poll the new future.
        spawn(&mut state.tasks);
        drop(state);
        for result in completed {
            report(result);
        }
        true
    }

    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) -> bool {
        self.spawn_abortable(future).is_some()
    }

    /// The caller may cancel one worker; the group retains its join obligation.
    pub(crate) fn spawn_abortable(
        &self,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Option<tokio::task::AbortHandle> {
        let mut abort = None;
        self.admit(|tasks| {
            abort = Some(tasks.spawn(future));
        });
        abort
    }

    pub(crate) fn spawn_owned(
        &self,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> TaskHandle {
        let (send, receive) = tokio::sync::oneshot::channel();
        let mut completion = TaskCompletion {
            future: Some(Box::pin(future)),
            completed: Some(send),
        };
        let mut abort = None;
        self.admit(|tasks| {
            abort = Some(tasks.spawn(async move {
                completion.future.as_mut().expect("owned task future").await;
                drop(completion);
            }));
        });
        // A rejected admission has already dropped completion and its future. The handle
        // remains safely awaitable, without spawning an obsolete task or panicking at shutdown.
        TaskHandle {
            abort,
            completed: Some(receive),
        }
    }

    #[cfg(any(test, all(target_os = "linux", feature = "experimental-roaming")))]
    pub(crate) async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (send, receive) = tokio::sync::oneshot::channel();
        if !self.admit(|tasks| {
            tasks.spawn_blocking(move || {
                let _ = send.send(work());
            });
        }) {
            return None;
        }
        receive.await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(5);
    const PROBE: Duration = Duration::from_millis(30);

    struct Lease(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Lease {
        fn drop(&mut self) {
            if let Some(send) = self.0.take() {
                let _ = send.send(());
            }
        }
    }

    fn pending_lease(group: &TaskGroup) -> tokio::sync::oneshot::Receiver<()> {
        let (send, receive) = tokio::sync::oneshot::channel();
        let lease = Lease(Some(send));
        assert!(group.spawner().spawn(async move {
            let _lease = lease;
            std::future::pending::<()>().await;
        }));
        receive
    }

    async fn await_release(receive: tokio::sync::oneshot::Receiver<()>) {
        tokio::time::timeout(DEADLINE, receive)
            .await
            .unwrap()
            .unwrap();
    }

    async fn blocked_producer(
        group: &TaskGroup,
    ) -> (
        std::sync::mpsc::Sender<()>,
        tokio::sync::oneshot::Receiver<bool>,
    ) {
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let (result, rejected) = tokio::sync::oneshot::channel();
        let spawner = group.spawner();
        assert!(group.spawner().spawn(async move {
            started.send(()).unwrap();
            let _ = blocked.recv();
            // Abort cannot interrupt this synchronous section, but admission must be sealed.
            let admitted = spawner.spawn(async { panic!("obsolete child must never run") });
            let _ = result.send(admitted);
        }));
        await_release(ready).await;
        (release, rejected)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_joins_producer_and_rejects_its_late_child() {
        let mut group = TaskGroup::default();
        let (release, admitted) = blocked_producer(&group).await;
        let mut finishing = tokio::spawn(async move {
            group.finish().await;
            assert!(crate::util::lock_or_recover(&group.0, "test")
                .tasks
                .is_empty());
        });
        assert!(tokio::time::timeout(PROBE, &mut finishing).await.is_err());
        release.send(()).unwrap();
        tokio::time::timeout(DEADLINE, finishing)
            .await
            .unwrap()
            .unwrap();
        assert!(!admitted.await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_shutdown_retains_handles_for_retry() {
        let mut group = TaskGroup::default();
        let (release, admitted) = blocked_producer(&group).await;
        assert!(tokio::time::timeout(PROBE, group.finish()).await.is_err());
        assert!(!crate::util::lock_or_recover(&group.0, "test")
            .tasks
            .is_empty());
        release.send(()).unwrap();
        tokio::time::timeout(DEADLINE, group.finish())
            .await
            .unwrap();
        assert!(!admitted.await.unwrap());
        group.finish().await; // Idempotent after drain; admission stays closed.
        assert!(!group.spawner().spawn(async {}));
    }

    #[tokio::test]
    async fn owner_drop_aborts_children_despite_surviving_spawner() {
        let group = TaskGroup::default();
        let spawner = group.spawner();
        let released = pending_lease(&group);
        drop(group);
        assert!(!spawner.spawn(async { panic!("dropped generation") }));
        await_release(released).await;
        assert!(spawner.0.upgrade().is_none());
    }

    #[tokio::test]
    async fn early_error_and_unwind_abort_owned_children() {
        async fn fail(
            receive: &mut Option<tokio::sync::oneshot::Receiver<()>>,
        ) -> anyhow::Result<()> {
            let group = TaskGroup::default();
            *receive = Some(pending_lease(&group));
            Err(anyhow::anyhow!("setup rejected"))?;
            Ok(())
        }
        let mut released = None;
        assert!(fail(&mut released).await.is_err());
        await_release(released.take().unwrap()).await;
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let group = TaskGroup::default();
            released = Some(pending_lease(&group));
            panic!("fixture unwind");
        }));
        assert!(unwind.is_err());
        await_release(released.unwrap()).await;
    }

    #[tokio::test]
    async fn replacement_reaps_completed_handles_and_keeps_active_tasks() {
        let mut group = TaskGroup::default();
        let (send, receive) = tokio::sync::oneshot::channel();
        group.spawner().spawn(async move {
            send.send(()).unwrap();
        });
        receive.await.unwrap();
        let first = pending_lease(&group);
        assert_eq!(
            crate::util::lock_or_recover(&group.0, "test").tasks.len(),
            1
        );
        let second = pending_lease(&group);
        assert_eq!(
            crate::util::lock_or_recover(&group.0, "test").tasks.len(),
            2
        );
        group.finish().await;
        await_release(first).await;
        await_release(second).await;
    }

    #[tokio::test]
    async fn panic_does_not_skip_other_destructors() {
        let mut group = TaskGroup::default();
        let (started, ready) = tokio::sync::oneshot::channel();
        group.spawner().spawn(async move {
            started.send(()).unwrap();
            panic!("fixture panic");
        });
        let released = pending_lease(&group);
        ready.await.unwrap();
        group.finish().await;
        await_release(released).await;
    }

    #[tokio::test]
    async fn blocking_worker_is_joined_even_after_its_async_waiter_is_aborted() {
        let mut group = TaskGroup::default();
        let spawner = group.spawner();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let complete = Arc::new(AtomicBool::new(false));
        let completed = complete.clone();
        group.spawner().spawn(async move {
            spawner
                .blocking(move || {
                    started.send(()).unwrap();
                    let _ = blocked.recv();
                    completed.store(true, Ordering::Release);
                })
                .await;
        });
        await_release(ready).await;
        assert!(tokio::time::timeout(PROBE, group.finish()).await.is_err());
        assert!(!complete.load(Ordering::Acquire));
        release.send(()).unwrap();
        tokio::time::timeout(DEADLINE, group.finish())
            .await
            .unwrap();
        assert!(
            complete.load(Ordering::Acquire),
            "network cleanup must follow the worker"
        );
    }

    #[tokio::test]
    async fn closed_group_rejects_blocking_work_and_drops_its_captures() {
        let mut group = TaskGroup::default();
        group.finish().await;
        let (send, receive) = tokio::sync::oneshot::channel();
        let lease = Lease(Some(send));
        assert_eq!(
            group
                .spawner()
                .blocking(move || {
                    let _lease = lease;
                    panic!("obsolete blocking work must never run");
                })
                .await,
            None::<()>
        );
        await_release(receive).await;
    }

    #[tokio::test]
    async fn rejected_future_can_use_spawner_in_its_destructor() {
        struct Reentrant(Spawner, Arc<AtomicBool>);
        impl Drop for Reentrant {
            fn drop(&mut self) {
                assert!(!self.0.spawn(async {}));
                self.1.store(true, Ordering::Release);
            }
        }
        let mut group = TaskGroup::default();
        group.finish().await;
        let dropped = Arc::new(AtomicBool::new(false));
        let capture = Reentrant(group.spawner(), dropped.clone());
        assert!(!group.spawner().spawn(async move {
            let _capture = capture;
            std::future::pending::<()>().await;
        }));
        assert!(dropped.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn never_polled_and_rejected_owned_tasks_release_captures() {
        let mut group = TaskGroup::default();
        let (send, receive) = tokio::sync::oneshot::channel();
        let lease = Lease(Some(send));
        let mut handle = group.spawner().spawn_owned(async move {
            let _lease = lease;
            panic!("aborted before first poll");
        });
        handle.finish().await;
        await_release(receive).await;
        handle.finish().await; // Repeated per-path cleanup is also safe.
        group.finish().await;
        let (send, receive) = tokio::sync::oneshot::channel();
        let lease = Lease(Some(send));
        let mut rejected = group.spawner().spawn_owned(async move {
            let _lease = lease;
            panic!("closed generation must reject before spawn");
        });
        assert!(rejected.abort.is_none());
        rejected.finish().await;
        await_release(receive).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn per_path_wait_finishes_after_captured_resource_destructor() {
        struct BlockingDrop {
            started: Option<tokio::sync::oneshot::Sender<()>>,
            release: std::sync::mpsc::Receiver<()>,
            released: Arc<AtomicBool>,
        }
        impl Drop for BlockingDrop {
            fn drop(&mut self) {
                self.started.take().unwrap().send(()).unwrap();
                let _ = self.release.recv();
                self.released.store(true, Ordering::Release);
            }
        }
        let mut group = TaskGroup::default();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let released = Arc::new(AtomicBool::new(false));
        let lease = BlockingDrop {
            started: Some(started),
            release: blocked,
            released: released.clone(),
        };
        let mut handle = group.spawner().spawn_owned(async move {
            let _lease = lease;
            std::future::pending::<()>().await;
        });
        handle.abort.as_ref().unwrap().abort();
        await_release(ready).await;
        assert!(tokio::time::timeout(PROBE, handle.finish()).await.is_err());
        assert!(!released.load(Ordering::Acquire));
        release.send(()).unwrap();
        tokio::time::timeout(DEADLINE, handle.finish())
            .await
            .unwrap();
        assert!(
            released.load(Ordering::Acquire),
            "rollback cannot precede resource Drop"
        );
        group.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_path_wait_and_dropped_handle_keep_group_join_ownership() {
        let mut group = TaskGroup::default();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let committed = Arc::new(AtomicBool::new(false));
        let worker_commit = committed.clone();
        let mut handle = group.spawner().spawn_owned(async move {
            started.send(()).unwrap();
            let _ = blocked.recv();
            worker_commit.store(true, Ordering::Release);
        });
        await_release(ready).await;
        assert!(tokio::time::timeout(PROBE, handle.finish()).await.is_err());
        drop(handle);
        assert!(tokio::time::timeout(PROBE, group.finish()).await.is_err());
        release.send(()).unwrap();
        tokio::time::timeout(DEADLINE, group.finish())
            .await
            .unwrap();
        assert!(
            committed.load(Ordering::Acquire),
            "path lookup/rollback must follow connect completion"
        );
    }

    #[tokio::test]
    async fn successful_and_panicked_owned_tasks_are_waitable() {
        let mut group = TaskGroup::default();
        for panics in [false, true] {
            let (send, receive) = tokio::sync::oneshot::channel();
            let lease = Lease(Some(send));
            let (started, ready) = tokio::sync::oneshot::channel();
            let mut handle = group.spawner().spawn_owned(async move {
                let _lease = lease;
                started.send(()).unwrap();
                assert!(!panics, "fixture panic");
            });
            await_release(ready).await;
            tokio::time::timeout(DEADLINE, handle.finish())
                .await
                .unwrap();
            await_release(receive).await;
        }
        group.finish().await;
    }

    #[tokio::test]
    async fn owner_drop_cancels_task_even_with_surviving_path_handle() {
        let group = TaskGroup::default();
        let (send, receive) = tokio::sync::oneshot::channel();
        let lease = Lease(Some(send));
        let mut handle = group.spawner().spawn_owned(async move {
            let _lease = lease;
            std::future::pending::<()>().await;
        });
        drop(group);
        await_release(receive).await;
        handle.finish().await;
    }

    #[tokio::test]
    async fn scope_closes_admission_before_dropping_network_guards() {
        struct NetworkGuard {
            spawner: Spawner,
            cleaned: Arc<AtomicBool>,
        }
        impl Drop for NetworkGuard {
            fn drop(&mut self) {
                assert!(!self
                    .spawner
                    .spawn(async { panic!("cleanup saw open admission") }));
                self.cleaned.store(true, Ordering::Release);
            }
        }
        let mut group = TaskGroup::default();
        let spawner = group.spawner();
        let cleaned = Arc::new(AtomicBool::new(false));
        let guard = NetworkGuard {
            spawner: spawner.clone(),
            cleaned: cleaned.clone(),
        };
        let child_released = pending_lease(&group);
        let attempt = spawner.scope(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        drop(attempt);
        assert!(cleaned.load(Ordering::Acquire));
        group.finish().await;
        await_release(child_released).await;
    }
}
