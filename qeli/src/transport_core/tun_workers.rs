//! Shared ownership of Unix TUN and Wintun packet threads through async shutdown.
//!
//! The pump must signal stop and close its inbound queue before joining. These workers
//! must terminate without async runtime progress: cancellation joins synchronously in Drop.
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub(crate) struct TunWorkers {
    threads: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

fn join(threads: &Mutex<Vec<JoinHandle<()>>>) {
    // Retain the lock until ALL joins finish. An owner dropped while the helper is already
    // joining must wait for it; if the helper is still queued, Drop can do the joins itself.
    let mut threads = crate::util::lock_or_recover(threads, "tun_workers");
    while let Some(thread) = threads.pop() {
        if thread.join().is_err() {
            log::warn!("TUN packet worker panicked during shutdown");
        }
    }
}

impl TunWorkers {
    pub(crate) fn new(threads: Vec<JoinHandle<()>>) -> Self {
        Self {
            threads: Arc::new(Mutex::new(threads)),
        }
    }

    pub(crate) async fn finish(&mut self) {
        // Share ownership rather than moving raw handles away from the pump. A cancelled
        // waiter still leaves its Drop able to join, without needing the blocking pool to run.
        let threads = self.threads.clone();
        if tokio::task::spawn_blocking(move || join(&threads))
            .await
            .is_err()
        {
            log::warn!("TUN worker join helper failed; completing joins synchronously");
            join(&self.threads);
        }
    }
}

impl Drop for TunWorkers {
    fn drop(&mut self) {
        join(&self.threads);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{poll_fn, Future};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(5);
    const PROBE: Duration = Duration::from_millis(30);
    type Shutdown = Pin<Box<dyn Future<Output = ()> + Send>>;

    struct Lease(Arc<AtomicUsize>);
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }

    fn held_workers(
        count: usize,
    ) -> (
        TunWorkers,
        Vec<std::sync::mpsc::Sender<()>>,
        Arc<AtomicUsize>,
    ) {
        let released = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..count {
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let lease = Lease(released.clone());
            threads.push(std::thread::spawn(move || {
                let _lease = lease;
                let _ = wait.recv_timeout(DEADLINE);
            }));
            releases.push(release);
        }
        (TunWorkers::new(threads), releases, released)
    }

    fn shutdown(mut workers: TunWorkers) -> Shutdown {
        Box::pin(async move {
            workers.finish().await;
        })
    }

    async fn start_pending(future: &mut Shutdown) {
        poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    fn drop_on_thread(
        value: impl Send + 'static,
    ) -> (JoinHandle<()>, tokio::sync::oneshot::Receiver<()>) {
        let (send, done) = tokio::sync::oneshot::channel();
        let dropper = std::thread::spawn(move || {
            drop(value);
            let _ = send.send(());
        });
        (dropper, done)
    }

    #[tokio::test]
    async fn normal_join_waits_for_both_threads_without_blocking_runtime() {
        let (mut workers, release, released) = held_workers(2);
        assert!(tokio::time::timeout(PROBE, workers.finish()).await.is_err());
        assert_eq!(released.load(Ordering::Acquire), 0);
        drop(release);
        tokio::time::timeout(DEADLINE, workers.finish())
            .await
            .unwrap();
        assert_eq!(released.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn cancelling_running_join_waits_before_owner_drop_returns() {
        let (workers, release, released) = held_workers(2);
        let shared = workers.threads.clone();
        let mut finishing = shutdown(workers);
        start_pending(&mut finishing).await;
        tokio::time::timeout(DEADLINE, async {
            while shared.try_lock().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (dropper, mut dropped) = drop_on_thread(finishing);
        assert!(tokio::time::timeout(PROBE, &mut dropped).await.is_err());
        assert_eq!(released.load(Ordering::Acquire), 0);
        drop(release);
        tokio::time::timeout(DEADLINE, dropped)
            .await
            .unwrap()
            .unwrap();
        dropper.join().unwrap();
        assert_eq!(released.load(Ordering::Acquire), 2);
    }

    #[test]
    fn cancelling_queued_join_does_not_wait_for_blocking_pool_capacity() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (started, ready) = tokio::sync::oneshot::channel();
            let (unblock_pool, wait) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                let _ = wait.recv_timeout(DEADLINE);
            });
            ready.await.unwrap();
            let (workers, release, released) = held_workers(2);
            let mut finishing = shutdown(workers);
            start_pending(&mut finishing).await;
            let (dropper, mut dropped) = drop_on_thread(finishing);
            assert!(tokio::time::timeout(PROBE, &mut dropped).await.is_err());
            drop(release);
            tokio::time::timeout(DEADLINE, dropped)
                .await
                .unwrap()
                .unwrap();
            dropper.join().unwrap();
            assert_eq!(released.load(Ordering::Acquire), 2);
            assert!(
                !blocker.is_finished(),
                "owner must not depend on queued join helper"
            );
            drop(unblock_pool);
            blocker.await.unwrap();
        });
    }

    #[tokio::test]
    async fn drop_without_async_shutdown_joins_all_workers() {
        let (workers, release, released) = held_workers(2);
        let (dropper, mut dropped) = drop_on_thread(workers);
        assert!(tokio::time::timeout(PROBE, &mut dropped).await.is_err());
        drop(release);
        tokio::time::timeout(DEADLINE, dropped)
            .await
            .unwrap()
            .unwrap();
        dropper.join().unwrap();
        assert_eq!(released.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn panicked_worker_does_not_skip_remaining_join() {
        let (mut workers, release, released) = held_workers(1);
        let lease = Lease(released.clone());
        let (started, ready) = tokio::sync::oneshot::channel();
        workers
            .threads
            .lock()
            .unwrap()
            .push(std::thread::spawn(move || {
                let _lease = lease;
                started.send(()).unwrap();
                panic!("fixture thread panic");
            }));
        ready.await.unwrap();
        assert!(tokio::time::timeout(PROBE, workers.finish()).await.is_err());
        drop(release);
        tokio::time::timeout(DEADLINE, workers.finish())
            .await
            .unwrap();
        assert_eq!(released.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn empty_and_repeated_shutdown_are_safe() {
        let mut workers = TunWorkers::new(Vec::new());
        workers.finish().await;
        workers.finish().await;
    }
}
