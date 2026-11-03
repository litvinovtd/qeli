//! Ownership and shutdown of one profile generation.

use crate::server_shutdown::Failures;
use std::sync::Arc;
use tokio::task::JoinSet;

/// All nested session/query tasks belonging to one profile generation.
/// Admission closes before cancellation; shutdown waits for task destructors, even when
/// an earlier waiter was cancelled or another owner is already waiting for shutdown.
#[derive(Clone)]
pub(crate) struct ProfileTasks {
    profile: Arc<str>,
    inner: Arc<std::sync::Mutex<ProfileTasksInner>>,
    // JoinSet remembers one join waker. Serialize waiters without holding a blocking mutex
    // across .await, and keep every pending handle in `inner` when a waiter is cancelled.
    shutdown_lock: Arc<tokio::sync::Mutex<()>>,
}

/// A nested worker must not retain its own task registry through a strong reference.
#[derive(Clone)]
pub(crate) struct ProfileSpawner {
    profile: Arc<str>,
    inner: std::sync::Weak<std::sync::Mutex<ProfileTasksInner>>,
}

impl ProfileSpawner {
    pub(crate) fn spawn_abortable(
        &self,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Option<tokio::task::AbortHandle> {
        let inner = self.inner.upgrade()?;
        spawn(&inner, &self.profile, future)
    }
}

struct ProfileTasksInner {
    stopping: bool,
    tasks: JoinSet<()>,
    failures: Failures,
}

fn report_result(
    profile: &str,
    result: Result<(), tokio::task::JoinError>,
    failures: &mut Failures,
) {
    if let Err(error) = result {
        if !error.is_cancelled() {
            log::error!("Profile '{}': child task failed: {}", profile, error);
            failures.record("child task", Err(error.into()));
        }
    }
}

fn spawn(
    shared: &std::sync::Mutex<ProfileTasksInner>,
    profile: &str,
    future: impl std::future::Future<Output = ()> + Send + 'static,
) -> Option<tokio::task::AbortHandle> {
    let mut inner = shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if inner.stopping {
        // A rejected capture may use the same registry from Drop.
        drop(inner);
        return None;
    }
    // Reap completions without scanning live sessions. Admission and actual spawning
    // share the shutdown lock; Tokio never polls this future synchronously here.
    while let Some(result) = inner.tasks.try_join_next() {
        report_result(profile, result, &mut inner.failures);
    }
    Some(inner.tasks.spawn(future))
}

impl ProfileTasks {
    pub(crate) fn new(profile: &str) -> Self {
        Self {
            profile: Arc::from(profile),
            inner: Arc::new(std::sync::Mutex::new(ProfileTasksInner {
                stopping: false,
                tasks: JoinSet::new(),
                failures: Failures::default(),
            })),
            shutdown_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub(crate) fn spawner(&self) -> ProfileSpawner {
        ProfileSpawner {
            profile: self.profile.clone(),
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub(crate) fn spawn<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        spawn(&self.inner, &self.profile, future).is_some()
    }

    pub(crate) fn abort_all(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.stopping = true;
        inner.tasks.abort_all();
    }

    pub(crate) fn is_stopping(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stopping
    }

    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        self.abort_all();
        let _waiter = self.shutdown_lock.lock().await;
        while let Some(result) = std::future::poll_fn(|cx| {
            self.inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .tasks
                .poll_join_next(cx)
        })
        .await
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            report_result(&self.profile, result, &mut inner.failures);
        }
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failures
            .result()
    }
}

/// A UDP listener joins every worker before returning. During owner shutdown a
/// successful worker exit is expected, but completed failures must survive abort.
pub(crate) async fn supervise_udp_workers(
    workers: &mut JoinSet<anyhow::Result<()>>,
    tasks: &ProfileTasks,
) -> anyhow::Result<()> {
    let first = match workers.join_next().await {
        Some(Ok(Err(error))) => Err(anyhow::anyhow!("UDP worker failed: {error}")),
        Some(Ok(Ok(()))) if tasks.is_stopping() => Ok(()),
        Some(Ok(Ok(()))) => Err(anyhow::anyhow!("UDP worker stopped unexpectedly")),
        Some(Err(error)) => Err(anyhow::anyhow!("UDP worker task panicked: {error}")),
        None => Err(anyhow::anyhow!("no UDP workers were started")),
    };
    let mut failures = Failures::default();
    failures.record("UDP listener", first);
    workers.abort_all();
    while let Some(result) = workers.join_next().await {
        failures.record_aborted_task("UDP worker", result);
    }
    failures.result()
}

/// Critical services and ingress listeners remain owned by the outer profile wrapper.
/// Keeping these sets outside startup ensures every `?` joins them before TUN/firewall
/// teardown, just like a normal stop. Dropping a JoinSet only requests cancellation.
#[derive(Default)]
pub(crate) struct ProfileServices {
    pub(crate) services: JoinSet<anyhow::Result<()>>,
    pub(crate) listeners: JoinSet<anyhow::Result<()>>,
    failures: Failures,
}

impl ProfileServices {
    pub(crate) fn request_shutdown(&mut self, tasks: &ProfileTasks) {
        tasks.abort_all();
        self.listeners.abort_all();
        self.services.abort_all();
    }

    pub(crate) async fn shutdown(&mut self, tasks: &ProfileTasks) -> anyhow::Result<()> {
        self.request_shutdown(tasks);
        while let Some(result) = self.listeners.join_next().await {
            self.failures.record_aborted_task("listener", result);
        }
        while let Some(result) = self.services.join_next().await {
            self.failures.record_aborted_task("service", result);
        }
        // A cancelled/repeated waiter must not duplicate stored child failures.
        let children = tasks.shutdown().await;
        let mut result = self.failures.clone();
        result.record("children", children);
        result.result()
    }
}

/// Worker periodic services finish their current cycle before profile resources disappear.
/// Required services are monitored: silently losing quota enforcement is a worker failure.
/// Optional observers (e.g. an unarmed packet trace) may finish normally.
pub(crate) struct WorkerServices {
    tasks: JoinSet<()>,
    names: std::collections::HashMap<tokio::task::Id, (&'static str, bool)>,
    shutdown: tokio::sync::watch::Sender<bool>,
    failures: Failures,
}

impl WorkerServices {
    pub(crate) fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            names: Default::default(),
            shutdown: tokio::sync::watch::channel(false).0,
            failures: Failures::default(),
        }
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub(crate) fn spawn<F>(&mut self, name: &'static str, required: bool, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if *self.shutdown.borrow() {
            return false;
        }
        let handle = self.tasks.spawn(future);
        self.names.insert(handle.id(), (name, required));
        true
    }

    pub(crate) async fn next_failure(&mut self) -> String {
        loop {
            let Some(result) = self.tasks.join_next_with_id().await else {
                return std::future::pending().await;
            };
            let id = match &result {
                Ok((id, ())) => *id,
                Err(error) => error.id(),
            };
            let (name, required) = self.names.remove(&id).expect("owned worker service");
            let failed = result.is_err();
            let reason = match result {
                Ok(_) => format!("worker service '{name}' stopped unexpectedly"),
                Err(error) => format!("worker service '{name}' failed: {error}"),
            };
            if required {
                return reason;
            }
            if failed {
                log::warn!("{reason}");
            }
        }
    }

    pub(crate) fn request_shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    pub(crate) async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.request_shutdown();
        // JoinSet retains pending handles if this waiter is cancelled. Never abort a
        // normal quota sweep halfway through session removal / route / lease cleanup.
        while let Some(result) = self.tasks.join_next_with_id().await {
            let id = match &result {
                Ok((id, ())) => *id,
                Err(error) => error.id(),
            };
            let (name, _) = self.names.remove(&id).expect("owned worker service");
            if let Err(error) = result {
                log::error!("worker service '{name}' failed during shutdown: {error}");
                // Worker services are drained cooperatively, so cancellation is unexpected.
                self.failures.record(name, Err(error.into()));
            }
        }
        self.failures.result()
    }
}

impl Drop for WorkerServices {
    fn drop(&mut self) {
        self.request_shutdown();
        // JoinSet drop is only an emergency abort fallback for outer cancellation.
        // Normal worker teardown must call shutdown() to finish ongoing transactions.
    }
}

pub(crate) async fn worker_tick(
    tick: &mut tokio::time::Interval,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        biased;
        _ = crate::server_supervisor::wait_for_shutdown(shutdown) => false,
        _ = tick.tick() => true,
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn udp_owner_stop_allows_normal_exit_and_drains_pending_workers() {
        let tasks = super::ProfileTasks::new("udp-stop");
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async { Ok(()) });
        workers.spawn(std::future::pending());
        tasks.abort_all();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            super::supervise_udp_workers(&mut workers, &tasks),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(workers.is_empty());
    }

    #[tokio::test]
    async fn udp_worker_normal_exit_in_live_profile_is_fatal() {
        let tasks = super::ProfileTasks::new("udp-live");
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async { Ok(()) });
        let error = super::supervise_udp_workers(&mut workers, &tasks)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("stopped unexpectedly"));
        assert!(workers.is_empty());
    }

    #[tokio::test]
    async fn udp_owner_stop_preserves_completed_worker_errors_and_panics() {
        let tasks = super::ProfileTasks::new("udp-failures");
        let mut workers = tokio::task::JoinSet::new();
        let mut completions = Vec::new();
        for index in 0..3 {
            let (done, completed) = tokio::sync::oneshot::channel();
            completions.push(completed);
            workers.spawn(async move {
                done.send(()).unwrap();
                // No await follows the signal: this poll completes or panics
                // before the single-thread test can request cancellation.
                match index {
                    0 => Ok(()),
                    1 => anyhow::bail!("completed UDP error"),
                    _ => panic!("completed UDP panic"),
                }
            });
        }
        for completed in completions {
            completed.await.unwrap();
        }
        tasks.abort_all();
        let error = super::supervise_udp_workers(&mut workers, &tasks)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("completed UDP error"), "{error}");
        assert!(error.contains("completed UDP panic"), "{error}");
        assert!(workers.is_empty());
    }

    #[tokio::test]
    async fn udp_listener_without_workers_is_fatal_even_during_stop() {
        let tasks = super::ProfileTasks::new("udp-empty");
        let mut workers = tokio::task::JoinSet::new();
        tasks.abort_all();
        let error = super::supervise_udp_workers(&mut workers, &tasks)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no UDP workers"));
    }

    use super::*;
    use std::future::Future;

    #[tokio::test]
    async fn profile_tasks_abort_join_and_close_admission() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let tasks = ProfileTasks::new("test");
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        assert!(tasks.spawn(async move {
            let _signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        }));
        assert!(
            started_rx.await.is_ok(),
            "child task must start before shutdown"
        );

        tasks.shutdown().await.unwrap();

        assert!(
            dropped_rx.await.is_ok(),
            "aborted child future must be dropped"
        );
        assert!(
            !tasks.spawn(async {}),
            "a closed generation must reject late child tasks"
        );
    }

    // Poll without yielding to Tokio: aborted children have not run their destructors yet.
    async fn poll_pending<F: Future>(future: std::pin::Pin<&mut F>) {
        let mut future = future;
        std::future::poll_fn(|cx| {
            assert!(
                future.as_mut().poll(cx).is_pending(),
                "shutdown returned before its children were dropped"
            );
            std::task::Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn concurrent_shutdown_waits_for_same_children() {
        let tasks = ProfileTasks::new("concurrent");
        tasks.spawn(std::future::pending());
        let mut first = Box::pin(tasks.shutdown());
        poll_pending(first.as_mut()).await;
        let mut second = Box::pin(tasks.shutdown());
        poll_pending(second.as_mut()).await;
        let (first, second) = tokio::join!(first, second);
        first.unwrap();
        second.unwrap();
    }

    #[tokio::test]
    async fn cancelled_shutdown_keeps_children_joinable() {
        let tasks = ProfileTasks::new("cancelled");
        tasks.spawn(std::future::pending());
        let mut first = Box::pin(tasks.shutdown());
        poll_pending(first.as_mut()).await;
        drop(first);
        let mut retry = Box::pin(tasks.shutdown());
        poll_pending(retry.as_mut()).await;
        retry.await.unwrap();
        assert!(!tasks.spawn(async {}));
    }
    #[tokio::test]
    async fn shutdown_joins_services_and_children_before_cleanup() {
        let tasks = ProfileTasks::new("setup-failure");
        let mut services = ProfileServices::default();
        let child_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let service_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let child_addr = child_socket.local_addr().unwrap();
        let service_addr = service_socket.local_addr().unwrap();
        let listener_addr = listener_socket.local_addr().unwrap();
        tasks.spawn(async move {
            let _socket = child_socket;
            std::future::pending::<()>().await;
        });
        services.services.spawn(async move {
            let _socket = service_socket;
            std::future::pending().await
        });
        services.listeners.spawn(async move {
            let _socket = listener_socket;
            std::future::pending().await
        });
        // Same cleanup boundary as the outer run_profile wrapper after any startup `?`.
        services.shutdown(&tasks).await.unwrap();
        let _child = tokio::net::UdpSocket::bind(child_addr).await.unwrap();
        let _service = tokio::net::UdpSocket::bind(service_addr).await.unwrap();
        let _listener = tokio::net::TcpListener::bind(listener_addr).await.unwrap();
        assert!(!tasks.spawn(async {}));
    }

    #[tokio::test]
    async fn cancelled_service_shutdown_can_be_resumed() {
        let tasks = ProfileTasks::new("cancelled-services");
        let mut services = ProfileServices::default();
        services.services.spawn(std::future::pending());
        services.listeners.spawn(std::future::pending());
        tasks.spawn(std::future::pending());
        let mut shutdown = Box::pin(services.shutdown(&tasks));
        poll_pending(shutdown.as_mut()).await;
        drop(shutdown);
        services.shutdown(&tasks).await.unwrap();
        assert!(services.services.is_empty());
        assert!(services.listeners.is_empty());
        assert!(tasks.inner.lock().unwrap().tasks.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_spawn_and_shutdown_release_every_future() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Owned(Arc<AtomicUsize>);
        impl Drop for Owned {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let live = Arc::new(AtomicUsize::new(0));
        let tasks = ProfileTasks::new("spawn-race");
        let start = Arc::new(tokio::sync::Barrier::new(9));
        let mut workers = JoinSet::new();
        for _ in 0..8 {
            let tasks = tasks.clone();
            let live = live.clone();
            let start = start.clone();
            workers.spawn(async move {
                start.wait().await;
                for _ in 0..128 {
                    live.fetch_add(1, Ordering::SeqCst);
                    let owned = Owned(live.clone());
                    tasks.spawn(async move {
                        let _owned = owned;
                        std::future::pending::<()>().await;
                    });
                    tokio::task::yield_now().await;
                }
            });
        }
        start.wait().await;
        tokio::task::yield_now().await;
        tasks.shutdown().await.unwrap();
        while let Some(result) = workers.join_next().await {
            result.unwrap();
        }
        tasks.shutdown().await.unwrap();
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert!(!tasks.spawn(async {}));
    }

    #[tokio::test]
    async fn finished_and_panicked_children_are_reaped() {
        let tasks = ProfileTasks::new("reap");
        tasks.spawn(async {});
        tasks.spawn(async {
            panic!("intentional child panic");
        });
        tokio::task::yield_now().await;
        tasks.spawn(std::future::pending());
        assert_eq!(tasks.inner.lock().unwrap().tasks.len(), 1);
        let error = tasks.shutdown().await.unwrap_err();
        assert!(error.to_string().contains("intentional child panic"));
    }

    #[tokio::test]
    async fn worker_required_completion_is_failure() {
        let mut services = WorkerServices::new();
        services.spawn("quota", true, async {});
        let reason =
            tokio::time::timeout(std::time::Duration::from_secs(2), services.next_failure())
                .await
                .unwrap();
        assert!(reason.contains("quota") && reason.contains("stopped unexpectedly"));
        services.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn worker_required_panic_is_failure() {
        let mut services = WorkerServices::new();
        services.spawn("quota", true, async { panic!("fixture failure") });
        let reason =
            tokio::time::timeout(std::time::Duration::from_secs(2), services.next_failure())
                .await
                .unwrap();
        assert!(reason.contains("quota") && reason.contains("fixture failure"));
        services.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn worker_optional_completion_does_not_stop_required_service() {
        let mut services = WorkerServices::new();
        services.spawn("unarmed trace", false, async {});
        let mut shutdown = services.subscribe();
        services.spawn("quota", true, async move {
            crate::server_supervisor::wait_for_shutdown(&mut shutdown).await;
        });
        tokio::task::yield_now().await;
        let mut failure = Box::pin(services.next_failure());
        poll_pending(failure.as_mut()).await;
        drop(failure);
        services.shutdown().await.unwrap();
        assert!(services.tasks.is_empty() && services.names.is_empty());
    }

    #[tokio::test]
    async fn worker_shutdown_finishes_cycle_before_releasing_resources() {
        let mut services = WorkerServices::new();
        let mut shutdown = services.subscribe();
        let cycles = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let shared_cycles = cycles.clone();
        let resource = Arc::new(());
        let weak = Arc::downgrade(&resource);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        services.spawn("quota transaction", true, async move {
            let _resource = resource;
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(1));
            assert!(worker_tick(&mut tick, &mut shutdown).await);
            started_tx.send(()).unwrap();
            finish_rx.await.unwrap();
            shared_cycles.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert!(
                !worker_tick(&mut tick, &mut shutdown).await,
                "no new cycle after stop"
            );
        });
        started_rx.await.unwrap();
        let mut first = Box::pin(services.shutdown());
        poll_pending(first.as_mut()).await;
        assert!(
            weak.upgrade().is_some(),
            "in-flight transaction retains its resources"
        );
        drop(first); // Cancelling a shutdown waiter must keep the service joinable.
        finish_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), services.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cycles.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(weak.upgrade().is_none());
        services.shutdown().await.unwrap(); // idempotent
        assert!(!services.spawn("late admission", true, async {}));
    }

    #[tokio::test]
    async fn worker_tick_stop_wins_over_ready_tick_and_closed_owner() {
        let (tx, mut rx) = tokio::sync::watch::channel(true);
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
        assert!(!worker_tick(&mut tick, &mut rx).await);
        tx.send_replace(false);
        assert!(worker_tick(&mut tick, &mut rx).await);
        drop(tx);
        assert!(!worker_tick(&mut tick, &mut rx).await);
    }

    #[tokio::test]
    async fn dropping_worker_owner_aborts_remaining_services() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let mut services = WorkerServices::new();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        services.spawn("fallback", true, async move {
            let _signal = DropSignal(Some(dropped_tx));
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        drop(services);
        tokio::time::timeout(std::time::Duration::from_secs(2), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn weak_spawner_cannot_keep_its_registry_alive() {
        let tasks = ProfileTasks::new("weak-owner");
        let spawner = tasks.spawner();
        let (send, released) = tokio::sync::oneshot::channel();
        struct Release(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Release {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let guard = Release(Some(send));
        let nested = spawner.clone();
        assert!(spawner
            .spawn_abortable(async move {
                let _guard = guard;
                let _nested = nested;
                std::future::pending::<()>().await;
            })
            .is_some());
        drop(tasks);
        assert!(spawner.inner.upgrade().is_none());
        tokio::time::timeout(std::time::Duration::from_secs(5), released)
            .await
            .unwrap()
            .unwrap();
        assert!(spawner
            .spawn_abortable(async { panic!("owner is gone") })
            .is_none());
    }

    #[tokio::test]
    async fn rejected_nested_capture_can_use_registry_from_drop() {
        struct Reenter(ProfileSpawner, Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Reenter {
            fn drop(&mut self) {
                assert!(self
                    .0
                    .spawn_abortable(async { panic!("closed registry") })
                    .is_none());
                self.1.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        let tasks = ProfileTasks::new("rejected-capture");
        let spawner = tasks.spawner();
        tasks.shutdown().await.unwrap();
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = Reenter(spawner.clone(), released.clone());
        assert!(spawner
            .spawn_abortable(async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            })
            .is_none());
        assert!(released.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn child_panic_is_seen_by_every_shutdown_waiter() {
        let tasks = ProfileTasks::new("panic-waiters");
        tasks.spawn(async {
            panic!("nested fixture panic");
        });
        tokio::task::yield_now().await;
        let (first, second) = tokio::join!(tasks.shutdown(), tasks.shutdown());
        assert!(first
            .unwrap_err()
            .to_string()
            .contains("nested fixture panic"));
        assert!(second
            .unwrap_err()
            .to_string()
            .contains("nested fixture panic"));
        assert!(tasks
            .shutdown()
            .await
            .unwrap_err()
            .to_string()
            .contains("nested fixture panic"));
    }

    #[tokio::test]
    async fn completed_listener_error_survives_cancelled_service_shutdown() {
        let tasks = ProfileTasks::new("partial-drain");
        let mut services = ProfileServices::default();
        services.listeners.spawn(async {
            anyhow::bail!("listener fixture failure");
        });
        services.services.spawn(std::future::pending());
        tokio::task::yield_now().await;
        let mut first = Box::pin(services.shutdown(&tasks));
        poll_pending(first.as_mut()).await;
        drop(first);
        let error = services.shutdown(&tasks).await.unwrap_err().to_string();
        assert!(error.contains("listener fixture failure"), "{error}");
        assert!(services.listeners.is_empty() && services.services.is_empty());
        assert_eq!(
            services.shutdown(&tasks).await.unwrap_err().to_string(),
            error
        );
    }

    #[tokio::test]
    async fn listener_service_and_child_failures_are_all_reported() {
        let tasks = ProfileTasks::new("all-failures");
        let mut services = ProfileServices::default();
        tasks.spawn(async {
            panic!("child fixture panic");
        });
        services.listeners.spawn(async {
            anyhow::bail!("listener fixture failure");
        });
        services.services.spawn(async {
            panic!("service fixture panic");
        });
        tokio::task::yield_now().await;
        let error = services.shutdown(&tasks).await.unwrap_err().to_string();
        for reason in [
            "child fixture panic",
            "listener fixture failure",
            "service fixture panic",
        ] {
            assert!(error.contains(reason), "{error}");
        }
        assert!(services.listeners.is_empty() && services.services.is_empty());
        assert!(tasks.inner.lock().unwrap().tasks.is_empty());
    }

    #[tokio::test]
    async fn worker_service_panic_survives_cancelled_drain_and_keeps_other_service_owned() {
        let mut services = WorkerServices::new();
        services.spawn("failed", true, async {
            panic!("periodic fixture panic");
        });
        let (send, receive) = tokio::sync::oneshot::channel();
        services.spawn("still draining", true, async {
            receive.await.unwrap();
        });
        tokio::task::yield_now().await;
        let mut first = Box::pin(services.shutdown());
        poll_pending(first.as_mut()).await;
        drop(first);
        assert_eq!(services.tasks.len(), 1);
        send.send(()).unwrap();
        let error = services.shutdown().await.unwrap_err().to_string();
        assert!(error.contains("periodic fixture panic"), "{error}");
        assert!(services.tasks.is_empty() && services.names.is_empty());
        assert_eq!(services.shutdown().await.unwrap_err().to_string(), error);
    }
}
