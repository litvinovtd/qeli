//! Bounded, nonblocking notification admission and deadline-limited delivery shutdown.
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};

pub(crate) struct DeliveryQueue {
    inner: Mutex<Inner>,
    active: Arc<Semaphore>,
    capacity: usize,
    grace: Duration,
    shutdown_lock: tokio::sync::Mutex<()>,
}

struct Inner {
    tasks: JoinSet<()>,
    stopping: bool,
    deadline: Option<Instant>,
    rejected: u64,
}

impl DeliveryQueue {
    pub(crate) fn new(capacity: usize, concurrency: usize, grace: Duration) -> Self {
        assert!(concurrency > 0 && capacity >= concurrency);
        Self {
            inner: Mutex::new(Inner {
                tasks: JoinSet::new(),
                stopping: false,
                deadline: None,
                rejected: 0,
            }),
            active: Arc::new(Semaphore::new(concurrency)),
            capacity,
            grace,
            shutdown_lock: tokio::sync::Mutex::new(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn report(result: Result<(), tokio::task::JoinError>) {
        if let Err(error) = result {
            if !error.is_cancelled() {
                log::warn!("notify: delivery task failed: {error}");
            }
        }
    }

    fn spawn<F>(&self, future: F) -> Result<tokio::task::AbortHandle, &'static str>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut inner = self.lock();
        if inner.stopping {
            return Err("notification service is stopping");
        }
        while let Some(result) = inner.tasks.try_join_next() {
            Self::report(result);
        }
        if inner.tasks.len() >= self.capacity {
            inner.rejected = inner.rejected.saturating_add(1);
            // Exponential sampling keeps an overload from becoming a log flood.
            if inner.rejected.is_power_of_two() {
                log::warn!("notify: queue full; rejected {} deliveries", inner.rejected);
            }
            return Err("notification queue is full");
        }
        let active = self.active.clone();
        let handle = inner.tasks.spawn(async move {
            let _permit = active
                .acquire_owned()
                .await
                .expect("delivery semaphore stays open");
            future.await;
        });
        Ok(handle)
    }

    pub(crate) fn try_spawn<F>(&self, future: F) -> Result<(), &'static str>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn(future).map(|_| ())
    }

    /// Interactive probes have one end-to-end deadline, including queue wait. Dropping
    /// their HTTP handler also cancels a queued or active delivery instead of sending late.
    pub(crate) async fn request<F, T>(&self, future: F, timeout: Duration) -> Result<T, String>
    where
        F: Future<Output = Result<T, String>> + Send + 'static,
        T: Send + 'static,
    {
        struct CancelOnDrop(tokio::task::AbortHandle);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cancel = CancelOnDrop(self.spawn(async move {
            let _ = tx.send(future.await);
        })?);
        let result = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("notification delivery cancelled".into()),
            Err(_) => Err("notification delivery timed out (including queue wait)".into()),
        };
        drop(cancel);
        result
    }

    pub(crate) fn abort(&self) {
        let mut inner = self.lock();
        inner.stopping = true;
        inner.tasks.abort_all();
    }

    pub(crate) fn request_shutdown(&self) -> Instant {
        let mut inner = self.lock();
        inner.stopping = true;
        *inner
            .deadline
            .get_or_insert_with(|| Instant::now() + self.grace)
    }

    pub(crate) async fn shutdown(&self) {
        let deadline = self.request_shutdown();
        // Serialize waiters: JoinSet owns one waker. Pending handles and the original
        // deadline stay in self if this future is cancelled and another caller resumes.
        let _waiter = self.shutdown_lock.lock().await;
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => {
                    let mut inner = self.lock();
                    if !inner.tasks.is_empty() {
                        log::warn!("notify: shutdown deadline; cancelling {} deliveries", inner.tasks.len());
                        inner.tasks.abort_all();
                    }
                    break;
                },
                joined = std::future::poll_fn(|cx| self.lock().tasks.poll_join_next(cx)) => {
                    match joined { Some(result) => Self::report(result), None => return }
                },
            }
        }
        // Normal timeout cleanup joins destructors, rather than detaching aborted sends.
        while let Some(result) =
            std::future::poll_fn(|cx| self.lock().tasks.poll_join_next(cx)).await
        {
            Self::report(result);
        }
    }
}

impl Drop for DeliveryQueue {
    fn drop(&mut self) {
        self.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }
    async fn poll_pending<F: Future>(mut f: std::pin::Pin<&mut F>) {
        std::future::poll_fn(|cx| {
            assert!(f.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn burst_bounds_waiting_and_active_work_and_joins_timeout() {
        let queue = DeliveryQueue::new(12, 2, Duration::from_millis(30));
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let live = Arc::new(());
        for _ in 0..12 {
            let tx = started_tx.clone();
            let resource = live.clone();
            queue
                .try_spawn(async move {
                    let _resource = resource;
                    tx.send(()).unwrap();
                    std::future::pending::<()>().await;
                })
                .unwrap();
        }
        assert!(queue
            .try_spawn(async { panic!("rejected job must never execute") })
            .is_err());
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
                .await
                .unwrap()
                .unwrap();
        }
        assert!(
            started_rx.try_recv().is_err(),
            "queued jobs must not start HTTP work"
        );
        assert_eq!(queue.lock().tasks.len(), 12);
        queue.shutdown().await;
        assert_eq!(
            Arc::strong_count(&live),
            1,
            "timeout joins active AND waiting payload drops"
        );
        assert!(queue.lock().tasks.is_empty());
        assert!(queue.try_spawn(async {}).is_err());
    }

    #[tokio::test]
    async fn graceful_shutdown_delivers_all_accepted_jobs() {
        let queue = DeliveryQueue::new(16, 2, Duration::from_secs(2));
        let completed = Arc::new(AtomicUsize::new(0));
        for _ in 0..16 {
            let completed = completed.clone();
            queue
                .try_spawn(async move {
                    completed.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
        }
        queue.shutdown().await;
        assert_eq!(completed.load(Ordering::SeqCst), 16);
        assert_eq!(queue.active.available_permits(), 2);
        queue.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_waiter_keeps_original_deadline_and_join_handles() {
        let queue = DeliveryQueue::new(1, 1, Duration::from_millis(20));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let witness = DropSignal(Some(tx));
        queue
            .try_spawn(async move {
                let _witness = witness;
                std::future::pending::<()>().await;
            })
            .unwrap();
        let mut first = Box::pin(queue.shutdown());
        poll_pending(first.as_mut()).await;
        let deadline = queue.lock().deadline;
        drop(first);
        assert_eq!(queue.lock().tasks.len(), 1);
        tokio::time::sleep(Duration::from_millis(30)).await;
        queue.shutdown().await;
        assert_eq!(queue.lock().deadline, deadline);
        rx.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_shutdown_waiters_join_same_deliveries() {
        let queue = DeliveryQueue::new(2, 1, Duration::from_millis(20));
        queue.try_spawn(std::future::pending()).unwrap();
        let mut first = Box::pin(queue.shutdown());
        poll_pending(first.as_mut()).await;
        let mut second = Box::pin(queue.shutdown());
        poll_pending(second.as_mut()).await;
        tokio::join!(first, second);
        assert!(queue.lock().tasks.is_empty());
    }

    #[tokio::test]
    async fn panicked_delivery_releases_capacity_and_active_permit() {
        let queue = DeliveryQueue::new(2, 1, Duration::from_secs(2));
        let (tx, rx) = tokio::sync::oneshot::channel();
        queue
            .try_spawn(async { panic!("isolated delivery fixture") })
            .unwrap();
        queue
            .try_spawn(async {
                tx.send(()).unwrap();
            })
            .unwrap();
        queue.shutdown().await;
        rx.await.unwrap();
        assert_eq!(queue.active.available_permits(), 1);
    }

    #[tokio::test]
    async fn dropping_owner_cancels_held_payloads() {
        let queue = DeliveryQueue::new(1, 1, Duration::from_secs(2));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let witness = DropSignal(Some(tx));
        queue
            .try_spawn(async move {
                let _witness = witness;
                std::future::pending::<()>().await;
            })
            .unwrap();
        drop(queue);
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn probe_deadline_cancels_and_joins_active_request() {
        let queue = DeliveryQueue::new(2, 1, Duration::from_secs(2));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let witness = DropSignal(Some(tx));
        let result: Result<(), String> = queue
            .request(
                async move {
                    let _witness = witness;
                    std::future::pending().await
                },
                Duration::from_millis(20),
            )
            .await;
        assert!(result.unwrap_err().contains("timed out"));
        queue.shutdown().await;
        rx.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_queued_probe_never_runs_after_capacity_returns() {
        let queue = DeliveryQueue::new(2, 1, Duration::from_secs(2));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        queue
            .try_spawn(async move {
                started_tx.send(()).unwrap();
                rx.await.unwrap();
            })
            .unwrap();
        started_rx.await.unwrap();
        let ran = Arc::new(AtomicUsize::new(0));
        let probe_ran = ran.clone();
        let mut probe = Box::pin(queue.request(
            async move {
                probe_ran.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            Duration::from_secs(2),
        ));
        poll_pending(probe.as_mut()).await;
        drop(probe);
        tx.send(()).unwrap();
        queue.shutdown().await;
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn early_stop_closes_admission_and_does_not_refresh_delivery_deadline() {
        let queue = DeliveryQueue::new(2, 1, Duration::from_millis(20));
        queue.try_spawn(std::future::pending()).unwrap();
        let deadline = queue.request_shutdown();
        assert!(queue.try_spawn(async {}).unwrap_err().contains("stopping"));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(queue.request_shutdown(), deadline);
        tokio::time::timeout(Duration::from_millis(10), queue.shutdown())
            .await
            .unwrap();
        assert!(queue.lock().tasks.is_empty());
    }
}
