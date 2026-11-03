use super::*;
use std::sync::Mutex;
use std::time::{Duration, Instant};
const LIMIT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn slow_teardown_stages_do_not_starve_the_executor() {
    for late in [false, true] {
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let (release, blocked) = mpsc::channel();
        let held = Arc::new(AtomicBool::new(true));
        let middle_held = held.clone();
        let started = Instant::now();
        let work = teardown(
            (Some(ready), Some(blocked)),
            move |resource| {
                if !late {
                    resource.0.take().unwrap().send(()).unwrap();
                    resource.1.take().unwrap().recv_timeout(LIMIT).unwrap();
                }
            },
            async move {
                middle_held.store(false, Ordering::Release);
            },
            move |resource, ()| {
                assert!(!held.load(Ordering::Acquire));
                if late {
                    resource.0.take().unwrap().send(()).unwrap();
                    resource.1.take().unwrap().recv_timeout(LIMIT).unwrap();
                }
            },
        );
        let probe = async move {
            waiting.await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            let responsive = started.elapsed() < Duration::from_secs(1);
            let _ = release.send(());
            responsive
        };
        let (result, responsive) = tokio::join!(work, probe);
        result.unwrap();
        assert!(responsive, "blocked teardown stage: late={late}");
    }
}

#[tokio::test]
async fn resource_stays_on_one_worker_until_after_pump_and_drop() {
    struct Resource(Arc<Mutex<Vec<(&'static str, std::thread::ThreadId)>>>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0
                .lock()
                .unwrap()
                .push(("drop", std::thread::current().id()));
        }
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let pump_events = events.clone();
    let caller = std::thread::current().id();
    let result = teardown(
        Resource(events.clone()),
        |resource| {
            resource
                .0
                .lock()
                .unwrap()
                .push(("dns", std::thread::current().id()));
            42
        },
        async move {
            pump_events
                .lock()
                .unwrap()
                .push(("pump", std::thread::current().id()));
        },
        |resource, value| {
            resource
                .0
                .lock()
                .unwrap()
                .push(("routes", std::thread::current().id()));
            value
        },
    )
    .await
    .unwrap();
    assert_eq!(result, 42);
    let events = events.lock().unwrap();
    assert_eq!(
        events.iter().map(|e| e.0).collect::<Vec<_>>(),
        ["dns", "pump", "routes", "drop"]
    );
    assert_ne!(events[0].1, caller);
    assert_eq!(events[1].1, caller);
    assert_eq!(events[0].1, events[2].1);
    assert_eq!(events[0].1, events[3].1);
}

#[tokio::test]
async fn early_failure_still_runs_pump_and_late_cleanup() {
    let stopped = Arc::new(AtomicBool::new(false));
    let pump = stopped.clone();
    let result = teardown(
        (),
        |_| Err::<(), _>("dns fault"),
        async move {
            pump.store(true, Ordering::Release);
        },
        move |_, result| {
            assert!(stopped.load(Ordering::Acquire));
            assert_eq!(result, Err("dns fault"));
            "route fault"
        },
    )
    .await
    .unwrap();
    assert_eq!(result, "route fault");
}

#[tokio::test]
async fn panics_join_fallback_drop_and_do_not_skip_pump_shutdown() {
    struct Resource(Arc<AtomicBool>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    for early in [true, false] {
        let dropped = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let pump = stopped.clone();
        let result = teardown(
            Resource(dropped.clone()),
            move |_| {
                assert!(!early, "early panic");
            },
            async move {
                pump.store(true, Ordering::Release);
            },
            |_, ()| panic!("late panic"),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("worker panicked"));
        assert!(dropped.load(Ordering::Acquire));
        assert!(stopped.load(Ordering::Acquire));
    }
}

#[test]
fn abandoned_middle_stops_pump_before_joining_fallback_cleanup() {
    struct Pump(Arc<AtomicBool>);
    impl Drop for Pump {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    struct Resource(Arc<AtomicBool>, mpsc::Sender<()>, mpsc::Receiver<()>);
    impl Drop for Resource {
        fn drop(&mut self) {
            assert!(
                self.0.load(Ordering::Acquire),
                "pump must be dropped before network owner"
            );
            self.1.send(()).unwrap();
            self.2.recv_timeout(LIMIT).unwrap();
        }
    }
    let stopped = Arc::new(AtomicBool::new(false));
    let (dropping, observed) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let owner = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let pump = Pump(stopped.clone());
        let mut future = Box::pin(teardown(
            Resource(stopped, dropping, blocked),
            |_| (),
            async move {
                let _pump = pump;
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
            },
            |_, ()| panic!("graceful late cleanup must not run after abandonment"),
        ));
        runtime.block_on(async {
            tokio::select! { _ = &mut future => panic!("teardown finished early"), _ = waiting => {} }
        });
        drop(future);
        done.send(()).unwrap();
    });
    observed.recv_timeout(LIMIT).unwrap();
    let early = finished.recv_timeout(Duration::from_millis(50)).is_ok();
    release.send(()).unwrap();
    owner.join().unwrap();
    finished.recv_timeout(LIMIT).unwrap();
    assert!(!early, "outer ownership released before fallback completed");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_SYS_ADMIN for private network and mount namespaces"]
fn teardown_retains_original_namespaces_across_async_pump_shutdown() {
    use std::os::unix::fs::MetadataExt;
    fn identity() -> [(u64, u64); 2] {
        ["net", "mnt"].map(|name| {
            let m = std::fs::metadata(format!("/proc/thread-self/ns/{name}")).unwrap();
            (m.dev(), m.ino())
        })
    }
    std::thread::spawn(|| {
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) },
            0
        );
        let expected = identity();
        struct Resource([(u64, u64); 2], Arc<AtomicBool>);
        impl Drop for Resource {
            fn drop(&mut self) {
                assert_eq!(identity(), self.0);
                self.1.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(teardown(
                Resource(expected, dropped.clone()),
                |r| assert_eq!(identity(), r.0),
                async {
                    assert_eq!(
                        unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) },
                        0
                    );
                    assert_ne!(identity(), expected);
                },
                |r, ()| assert_eq!(identity(), r.0),
            ))
            .unwrap();
        assert!(dropped.load(Ordering::Acquire));
    })
    .join()
    .unwrap();
}
