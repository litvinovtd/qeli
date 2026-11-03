use super::*;
use std::time::{Duration, Instant};
const LIMIT: Duration = Duration::from_secs(5);
fn token() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
struct Resource(mpsc::Sender<std::thread::ThreadId>);
impl Drop for Resource {
    fn drop(&mut self) {
        let _ = self.0.send(std::thread::current().id());
    }
}

#[tokio::test]
async fn system_work_does_not_starve_neighboring_async_tasks() {
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let started = Instant::now();
    let job = tokio::spawn(run(token(), move || {
        ready.send(()).unwrap();
        blocked.recv_timeout(LIMIT)?;
        Ok(42)
    }));
    waiting.await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let responsive = started.elapsed() < Duration::from_secs(1);
    release.send(()).unwrap();
    assert_eq!(job.await.unwrap().unwrap(), 42);
    assert!(responsive);
}

#[tokio::test]
async fn cancelled_before_start_never_runs_the_mutation() {
    assert!(
        run(Arc::new(AtomicBool::new(true)), || -> anyhow::Result<()> {
            panic!("cancelled mutation must not start")
        })
        .await
        .is_err()
    );
}

#[tokio::test]
async fn stop_awaits_started_work_and_rolls_back_on_its_original_thread() {
    let cancel = token();
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let (dropped, observed) = mpsc::channel();
    let mut job = tokio::spawn(run(cancel.clone(), move || {
        ready.send(std::thread::current().id()).unwrap();
        blocked.recv_timeout(LIMIT)?;
        Ok(Resource(dropped))
    }));
    let worker = waiting.await.unwrap();
    cancel.store(true, Ordering::Release);
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut job)
        .await
        .is_err());
    release.send(()).unwrap();
    assert!(job.await.unwrap().is_err());
    assert_eq!(observed.recv_timeout(LIMIT).unwrap(), worker);
}

#[test]
fn dropped_waiter_joins_rollback_before_releasing_outer_ownership() {
    let (ready, waiting) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let (dropped, observed) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let owner = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut future = Box::pin(run(token(), move || {
            ready.send(std::thread::current().id()).unwrap();
            blocked.recv_timeout(LIMIT)?;
            Ok(Resource(dropped))
        }));
        runtime.block_on(std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(future.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        }));
        drop(future); // Must join the in-progress transaction and its late result Drop.
        done.send(()).unwrap();
    });
    let worker = waiting.recv_timeout(LIMIT).unwrap();
    let early = finished.recv_timeout(Duration::from_millis(50)).is_ok();
    release.send(()).unwrap();
    finished.recv_timeout(LIMIT).unwrap();
    owner.join().unwrap();
    assert!(
        !early,
        "outer namespace lease could otherwise be released too early"
    );
    assert_eq!(observed.recv_timeout(LIMIT).unwrap(), worker);
}

#[tokio::test]
async fn successful_adoption_transfers_resource_ownership_once() {
    let (dropped, observed) = mpsc::channel();
    let resource = run(token(), move || Ok(Resource(dropped))).await.unwrap();
    assert!(observed.try_recv().is_err());
    drop(resource);
    assert_eq!(
        observed.recv_timeout(LIMIT).unwrap(),
        std::thread::current().id()
    );
    assert!(observed.try_recv().is_err());
}

#[tokio::test]
async fn worker_error_and_panic_are_reported_after_join() {
    assert_eq!(
        run(token(), || -> anyhow::Result<()> {
            anyhow::bail!("fixture error")
        })
        .await
        .unwrap_err()
        .to_string(),
        "fixture error"
    );
    let (dropped, observed) = mpsc::channel();
    let error = run(token(), move || -> anyhow::Result<()> {
        let _resource = Resource(dropped);
        panic!("fixture panic");
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("worker panicked"));
    observed.recv_timeout(LIMIT).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_SYS_ADMIN for private network and mount namespaces"]
fn native_worker_inherits_context_and_rejects_adoption_after_namespace_change() {
    use std::os::unix::fs::MetadataExt;
    fn identity(name: &str) -> (u64, u64) {
        let m = std::fs::metadata(format!("/proc/thread-self/ns/{name}")).unwrap();
        (m.dev(), m.ino())
    }
    let original = (identity("net"), identity("mnt"));
    std::thread::spawn(move || {
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) },
            0
        );
        let expected = (identity("net"), identity("mnt"));
        assert_ne!(expected.0, original.0);
        assert_ne!(expected.1, original.1);
        struct Scoped((u64, u64), (u64, u64), mpsc::Sender<()>);
        impl Drop for Scoped {
            fn drop(&mut self) {
                assert_eq!(identity("net"), self.0);
                assert_eq!(identity("mnt"), self.1);
                self.2.send(()).unwrap();
            }
        }
        let (dropped, observed) = mpsc::channel();
        let (ready, waiting) = mpsc::channel();
        let (work_release, work_wait) = mpsc::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut future = Box::pin(run(token(), move || {
            assert_eq!((identity("net"), identity("mnt")), expected);
            ready.send(()).unwrap();
            work_wait.recv_timeout(LIMIT)?;
            Ok(Scoped(expected.0, expected.1, dropped))
        }));
        runtime.block_on(std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(future.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        }));
        waiting.recv_timeout(LIMIT).unwrap();
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        work_release.send(()).unwrap();
        assert!(runtime.block_on(future).is_err());
        observed.recv_timeout(LIMIT).unwrap();
    })
    .join()
    .unwrap();
}

#[tokio::test]
async fn stop_keeps_executor_responsive_until_result_rollback_finishes() {
    struct SlowDrop(tokio::sync::oneshot::Sender<()>, mpsc::Receiver<()>);
    // Keep the sender optional because Drop cannot move fields out directly.
    struct Guard(Option<SlowDrop>);
    impl Drop for Guard {
        fn drop(&mut self) {
            let SlowDrop(ready, release) = self.0.take().unwrap();
            let _ = ready.send(());
            release.recv_timeout(LIMIT).unwrap();
        }
    }
    let cancel = token();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (work_release, work_wait) = mpsc::channel();
    let (dropping, drop_ready) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let job = tokio::spawn(run(cancel.clone(), move || {
        started.send(()).unwrap();
        work_wait.recv_timeout(LIMIT)?;
        Ok(Guard(Some(SlowDrop(dropping, blocked))))
    }));
    ready.await.unwrap();
    cancel.store(true, Ordering::Release);
    work_release.send(()).unwrap();
    drop_ready.await.unwrap();
    let start = Instant::now();
    tokio::time::sleep(Duration::from_millis(20)).await;
    release.send(()).unwrap();
    assert!(job.await.unwrap().is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
}
