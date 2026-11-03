use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const LIMIT: Duration = Duration::from_secs(3);
fn address() -> Vec<SocketAddr> {
    vec!["192.0.2.4:443".parse().unwrap()]
}

#[tokio::test]
async fn literals_and_system_hosts_preserve_ports_and_families() {
    for host in ["127.0.0.1", "::1"] {
        assert_eq!(
            lookup(host, 1234, Instant::now() + LIMIT).await.unwrap(),
            vec![SocketAddr::new(host.parse().unwrap(), 1234)]
        );
    }
    let hosts = lookup("localhost", 1234, Instant::now() + LIMIT)
        .await
        .unwrap();
    assert!(!hosts.is_empty());
    assert!(hosts
        .iter()
        .all(|a| a.ip().is_loopback() && a.port() == 1234));
    assert_eq!(
        lookup("127.0.0.1", 443, Instant::now())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test]
async fn slow_lookup_does_not_block_current_thread_tasks() {
    let slots = Arc::new(Semaphore::new(1));
    let (started, ready) = oneshot::channel();
    let (finish, release) = mpsc::channel();
    let task = tokio::spawn(lookup_with(slots, Instant::now() + LIMIT, move || {
        started.send(()).unwrap();
        release.recv_timeout(LIMIT).unwrap();
        Ok(address())
    }));
    tokio::time::timeout(LIMIT, ready).await.unwrap().unwrap();
    tokio::time::timeout(
        Duration::from_millis(300),
        tokio::time::sleep(Duration::from_millis(20)),
    )
    .await
    .unwrap();
    assert!(!task.is_finished());
    finish.send(()).unwrap();
    assert_eq!(task.await.unwrap().unwrap(), address());
}

#[tokio::test]
async fn cancelled_lookup_keeps_its_slot_until_nss_returns() {
    let slots = Arc::new(Semaphore::new(1));
    let (started, ready) = oneshot::channel();
    let (finish, release) = mpsc::channel();
    let task = tokio::spawn(lookup_with(
        slots.clone(),
        Instant::now() + LIMIT,
        move || {
            started.send(()).unwrap();
            release.recv_timeout(LIMIT).unwrap();
            Ok(address())
        },
    ));
    tokio::time::timeout(LIMIT, ready).await.unwrap().unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(slots.available_permits(), 0);
    let invoked = Arc::new(AtomicBool::new(false));
    let called = invoked.clone();
    assert_eq!(
        lookup_with(
            slots.clone(),
            Instant::now() + Duration::from_millis(30),
            move || {
                called.store(true, Ordering::SeqCst);
                Ok(address())
            }
        )
        .await
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(!invoked.load(Ordering::SeqCst));
    finish.send(()).unwrap();
    let _permit = tokio::time::timeout(LIMIT, slots.acquire())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn timeout_drops_late_answers_without_releasing_live_capacity() {
    let slots = Arc::new(Semaphore::new(1));
    let (finish, release) = mpsc::channel();
    let result = lookup_with(
        slots.clone(),
        Instant::now() + Duration::from_millis(300),
        move || {
            release.recv_timeout(LIMIT).unwrap();
            Ok(address())
        },
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(slots.available_permits(), 0);
    finish.send(()).unwrap();
    let _permit = tokio::time::timeout(LIMIT, slots.acquire())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn expired_admission_and_worker_errors_are_not_success() {
    let slots = Arc::new(Semaphore::new(1));
    assert_eq!(
        lookup_with(slots.clone(), Instant::now(), || panic!("expired work ran"))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        lookup_with(slots.clone(), Instant::now() + LIMIT, || Err(
            io::Error::new(io::ErrorKind::NotFound, "fixture")
        ))
        .await
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotFound
    );
    assert!(
        lookup_with(slots.clone(), Instant::now() + LIMIT, || panic!(
            "resolver fixture"
        ))
        .await
        .is_err()
    );
    let _permit = tokio::time::timeout(LIMIT, slots.acquire())
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn abandoned_nss_cannot_delay_runtime_destruction() {
    let slots = Arc::new(Semaphore::new(1));
    let (finish, release) = mpsc::channel();
    let (done, observed) = mpsc::channel();
    let held = slots.clone();
    let owner = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime
            .block_on(lookup_with(
                held,
                Instant::now() + Duration::from_millis(300),
                move || {
                    release.recv_timeout(LIMIT).unwrap();
                    Ok(address())
                },
            ))
            .unwrap_err();
        drop(runtime);
        done.send(error.kind()).unwrap();
    });
    let result = observed.recv_timeout(Duration::from_millis(1500));
    let still_held = slots.available_permits() == 0;
    let _ = finish.send(());
    owner.join().unwrap();
    assert_eq!(result.unwrap(), io::ErrorKind::TimedOut);
    assert!(still_held);
}

#[tokio::test]
async fn cancelled_consumer_cannot_apply_a_late_answer() {
    let slots = Arc::new(Semaphore::new(1));
    let (started, ready) = oneshot::channel();
    let (finish, release) = mpsc::channel();
    let applied = Arc::new(AtomicBool::new(false));
    let observed = applied.clone();
    let held = slots.clone();
    let task = tokio::spawn(async move {
        let _addresses = lookup_with(held, Instant::now() + LIMIT, move || {
            started.send(()).unwrap();
            release.recv_timeout(LIMIT).unwrap();
            Ok(address())
        })
        .await
        .unwrap();
        applied.store(true, Ordering::SeqCst);
    });
    tokio::time::timeout(LIMIT, ready).await.unwrap().unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    finish.send(()).unwrap();
    let _permit = tokio::time::timeout(LIMIT, slots.acquire())
        .await
        .unwrap()
        .unwrap();
    assert!(!observed.load(Ordering::SeqCst));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_SYS_ADMIN for private network and mount namespaces"]
fn native_resolver_inherits_callers_network_and_mount_namespaces() {
    use std::os::unix::fs::MetadataExt;
    fn identity(name: &str) -> (u64, u64) {
        let m = std::fs::metadata(format!("/proc/thread-self/ns/{name}")).unwrap();
        (m.dev(), m.ino())
    }
    let original = (identity("net"), identity("mnt"));
    std::thread::spawn(move || {
        // A new thread owns the private namespaces; no test runner thread is changed.
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) },
            0
        );
        let caller = (identity("net"), identity("mnt"));
        assert_ne!(caller.0, original.0);
        assert_ne!(caller.1, original.1);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let answer = lookup_with(
                    Arc::new(Semaphore::new(1)),
                    Instant::now() + LIMIT,
                    move || {
                        assert_eq!((identity("net"), identity("mnt")), caller);
                        ("localhost", 4567).to_socket_addrs().map(Iterator::collect)
                    },
                )
                .await
                .unwrap();
                assert!(!answer.is_empty());
                assert!(answer
                    .iter()
                    .all(|a| a.ip().is_loopback() && a.port() == 4567));
            });
    })
    .join()
    .unwrap();
}
