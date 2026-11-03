use super::*;

#[test]
fn report_preserves_drop_failure_and_primary_failure_without_second_cleanup() {
    struct Guard(Report, Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.0
                .record("TUN delete", Err(anyhow::anyhow!("permission denied")));
        }
    }
    let report = Report::default();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    drop(Guard(report.clone(), calls.clone()));
    report.record("generation", Err(anyhow::anyhow!("bind failed")));
    let message = report.result().unwrap_err().to_string();
    assert!(message.contains("permission denied") && message.contains("bind failed"));
    assert_eq!(report.result().unwrap_err().to_string(), message);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn poisoned_report_keeps_existing_evidence() {
    let report = Report::default();
    report.record("TUN", Err(anyhow::anyhow!("earlier failure")));
    let other = report.clone();
    let _ = std::panic::catch_unwind(move || {
        let _guard = other.0.lock().unwrap();
        panic!("fixture");
    });
    report.record("queues", Err(anyhow::anyhow!("later failure")));
    let message = report.result().unwrap_err().to_string();
    assert!(message.contains("earlier failure") && message.contains("later failure"));
}

#[test]
fn empty_threads_complete_without_waiting() {
    let mut wakes = 0;
    stop_threads(Vec::new(), Duration::ZERO, || wakes += 1).unwrap();
    assert_eq!(wakes, 1);
}

#[test]
fn normal_wake_joins_thread_and_releases_its_resource() {
    let resource = Arc::new(());
    let weak = Arc::downgrade(&resource);
    let (send, receive) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let _resource = resource;
        receive.recv().unwrap();
    });
    let mut send = Some(send);
    stop_threads(vec![handle], Duration::from_secs(2), || {
        if let Some(send) = send.take() {
            send.send(()).unwrap();
        }
    })
    .unwrap();
    assert!(weak.upgrade().is_none());
}

#[test]
fn timeout_does_not_block_join_and_still_reports_finished_thread_panic() {
    let panicked = std::thread::Builder::new()
        .name("q-reader".into())
        .spawn(|| panic!("queue fixture panic"))
        .unwrap();
    let ready = Instant::now() + Duration::from_secs(2);
    while !panicked.is_finished() {
        assert!(Instant::now() < ready);
        std::thread::sleep(Duration::from_millis(1));
    }
    let (send, receive) = std::sync::mpsc::channel();
    let (done, completed) = std::sync::mpsc::channel();
    let blocked = std::thread::spawn(move || {
        receive.recv().unwrap();
        done.send(()).unwrap();
    });
    let start = Instant::now();
    let error = stop_threads(vec![blocked, panicked], Duration::ZERO, || {})
        .unwrap_err()
        .to_string();
    send.send(()).unwrap();
    completed.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(
        error.contains("did not stop") && error.contains("queue fixture panic"),
        "{error}"
    );
}

#[test]
fn transient_setup_failure_can_restart_only_after_successful_cleanup() {
    let outcome = Outcome::new(Err(anyhow::anyhow!("port busy")), Ok(()));
    assert!(outcome.can_restart());
    assert!(outcome.result().is_err());
    assert!(outcome
        .into_result()
        .unwrap_err()
        .to_string()
        .contains("port busy"));
}

#[test]
fn old_cleanup_failure_reaches_worker_instead_of_entering_backoff() {
    let outcome = Outcome::new(Ok(()), Err(anyhow::anyhow!("TUN thread retains fd")));
    assert!(!outcome.can_restart());
    assert!(outcome
        .into_result()
        .unwrap_err()
        .to_string()
        .contains("retains fd"));
}

#[test]
fn primary_error_does_not_hide_unsafe_cleanup() {
    let outcome = Outcome::new(
        Err(anyhow::anyhow!("listener failed")),
        Err(anyhow::anyhow!("NAT remains")),
    );
    assert!(!outcome.can_restart());
    let error = outcome.into_result().unwrap_err().to_string();
    assert!(error.contains("listener failed") && error.contains("NAT remains"));
    let healthy = Outcome::new(Ok(()), Ok(()));
    assert!(healthy.can_restart());
    assert!(healthy.into_result().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn blocking_host_cleanup_keeps_executor_responsive() {
    let (started, entered) = tokio::sync::oneshot::channel();
    let (resume, continue_work) = std::sync::mpsc::channel();
    let cleanup = tokio::spawn(blocking("qeli-test-host-work", move || {
        let _ = started.send(());
        continue_work.recv_timeout(Duration::from_secs(5)).unwrap();
    }));
    entered.await.unwrap();
    // This timer must run on the SAME executor that awaits the worker. If setup
    // blocks it, the worker's five-second gate fails before release can be sent.
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        resume.send(()).unwrap();
    })
    .await
    .unwrap();
    cleanup.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_host_cleanup_joins_before_releasing_owned_resource() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let released = Arc::new(AtomicBool::new(false));
    struct Resource(Arc<AtomicBool>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let resource = Resource(released.clone());
    let (started, entered) = tokio::sync::oneshot::channel();
    let (resume, continue_work) = std::sync::mpsc::channel();
    let cleanup = tokio::spawn(blocking("qeli-test-owned-cleanup", move || {
        let _resource = resource;
        let _ = started.send(());
        continue_work.recv_timeout(Duration::from_secs(2)).unwrap();
    }));
    entered.await.unwrap();
    cleanup.abort();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!released.load(Ordering::SeqCst));
    resume.send(()).unwrap();
    assert!(cleanup.await.unwrap_err().is_cancelled());
    assert!(released.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_setup_joins_before_outer_guard_and_drops_unadopted_result() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Outer(Arc<AtomicBool>, Arc<AtomicBool>, Arc<AtomicBool>);
    impl Drop for Outer {
        fn drop(&mut self) {
            if !self.0.load(Ordering::SeqCst) || !self.1.load(Ordering::SeqCst) {
                self.2.store(true, Ordering::SeqCst);
            }
        }
    }
    struct ResultOwner(Arc<AtomicBool>, Arc<AtomicBool>, std::thread::ThreadId);
    impl Drop for ResultOwner {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
            self.1
                .store(std::thread::current().id() == self.2, Ordering::SeqCst);
        }
    }
    let worker_done = Arc::new(AtomicBool::new(false));
    let result_dropped = Arc::new(AtomicBool::new(false));
    let result_dropped_on_worker = Arc::new(AtomicBool::new(false));
    let early_outer_drop = Arc::new(AtomicBool::new(false));
    let (started, entered) = tokio::sync::oneshot::channel();
    let (resume, continue_work) = std::sync::mpsc::channel();
    let worker_done_in = worker_done.clone();
    let result_dropped_in = result_dropped.clone();
    let on_worker_in = result_dropped_on_worker.clone();
    let outer = Outer(
        worker_done.clone(),
        result_dropped.clone(),
        early_outer_drop.clone(),
    );
    let setup = tokio::spawn(async move {
        let _outer = outer;
        let _result = blocking("qeli-test-profile-setup", move || {
            let _ = started.send(());
            continue_work.recv_timeout(Duration::from_secs(2)).unwrap();
            worker_done_in.store(true, Ordering::SeqCst);
            ResultOwner(result_dropped_in, on_worker_in, std::thread::current().id())
        })
        .await
        .unwrap();
    });
    entered.await.unwrap();
    setup.abort();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!worker_done.load(Ordering::SeqCst));
    assert!(!result_dropped.load(Ordering::SeqCst));
    resume.send(()).unwrap();
    assert!(setup.await.unwrap_err().is_cancelled());
    assert!(worker_done.load(Ordering::SeqCst));
    assert!(result_dropped.load(Ordering::SeqCst));
    assert!(result_dropped_on_worker.load(Ordering::SeqCst));
    assert!(!early_outer_drop.load(Ordering::SeqCst));
}

#[test]
fn deferred_entry_keeps_resources_owned_until_taken() {
    struct Resource(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let deferred = Deferred::default();
    deferred.retain(Resource(drops.clone()));
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    let resource = deferred.take().unwrap();
    assert!(deferred.take().is_none());
    drop(resource);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn deferred_owner_drop_quarantines_unjoined_resources() {
    struct Resource(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let deferred = Deferred::default();
    deferred.retain(Resource(drops.clone()));
    drop(deferred);
    assert_eq!(
        drops.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "owner loss must not invoke cleanup before async descendants finish"
    );
}
