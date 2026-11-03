use super::*;
use std::sync::mpsc;
use std::time::Duration;
const LIMIT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn slow_io_keeps_executor_live_and_coalesces_to_terminal_snapshot() {
    let (started, ready) = tokio::sync::oneshot::channel();
    let mut started = Some(started);
    let (release, blocked) = mpsc::channel();
    let written = Arc::new(Mutex::new(Vec::new()));
    let output = written.clone();
    let (sender, mut writer) = Writer::start(move |value| {
        if let Some(started) = started.take() {
            started.send(()).unwrap();
            blocked.recv_timeout(LIMIT).unwrap();
        }
        output.lock().unwrap().push(value);
    })
    .unwrap();
    assert!(sender.submit(0));
    tokio::time::timeout(LIMIT, ready).await.unwrap().unwrap();
    for value in 1..=10_000 {
        assert!(sender.submit(value));
    }
    // A 10,000-update burst consumes exactly one pending slot while disk I/O is held.
    assert_eq!(writer.shared.queue.lock().unwrap().latest, Some(10_000));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), writer.finish())
            .await
            .is_err()
    );
    assert!(!sender.submit(10_001));
    assert!(written.lock().unwrap().is_empty());
    release.send(()).unwrap();
    tokio::time::timeout(LIMIT, writer.finish())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*written.lock().unwrap(), vec![0, 10_000]);
    writer.finish().await.unwrap();
}

#[tokio::test]
async fn idle_writer_closes_with_live_sender_clones() {
    let (sender, mut writer) = Writer::<u32>::start(|_| panic!("unexpected snapshot")).unwrap();
    let other = sender.clone();
    tokio::time::timeout(LIMIT, writer.finish())
        .await
        .unwrap()
        .unwrap();
    assert!(!other.submit(1));
    assert!(!sender.submit(2));
}

#[tokio::test]
async fn writer_panic_is_joined_and_closes_admission() {
    let (sender, mut writer) = Writer::start(|_: u32| panic!("fixture writer panic")).unwrap();
    sender.submit(1);
    let error = tokio::time::timeout(LIMIT, writer.finish())
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("writer panicked"));
    assert!(!sender.submit(2));
}

#[test]
fn forced_drop_joins_inflight_and_pending_writes() {
    let (started, ready) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let (finished, done) = mpsc::channel();
    let written = Arc::new(Mutex::new(Vec::new()));
    let output = written.clone();
    let owner = std::thread::spawn(move || {
        let mut first = true;
        let (sender, writer) = Writer::start(move |value| {
            if first {
                first = false;
                started.send(()).unwrap();
                blocked.recv_timeout(LIMIT).unwrap();
            }
            output.lock().unwrap().push(value);
        })
        .unwrap();
        sender.submit(1);
        // Await the first write before queuing a second snapshot.
        while writer.shared.queue.lock().unwrap().latest.is_some() {
            std::thread::yield_now();
        }
        sender.submit(2);
        drop(writer);
        assert!(!sender.submit(3));
        finished.send(()).unwrap();
    });
    ready.recv_timeout(LIMIT).unwrap();
    assert!(done.recv_timeout(Duration::from_millis(30)).is_err());
    release.send(()).unwrap();
    done.recv_timeout(LIMIT).unwrap();
    owner.join().unwrap();
    assert_eq!(*written.lock().unwrap(), vec![1, 2]);
}

#[tokio::test]
async fn callback_destruction_is_also_joined() {
    struct HeldDrop(mpsc::Receiver<()>, Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for HeldDrop {
        fn drop(&mut self) {
            self.1.take().unwrap().send(()).unwrap();
            self.0.recv_timeout(LIMIT).unwrap();
        }
    }
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let held = HeldDrop(blocked, Some(entered));
    let (_, mut writer) = Writer::start(move |_: u32| {
        let _ = &held;
    })
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), writer.finish())
            .await
            .is_err()
    );
    tokio::time::timeout(LIMIT, ready).await.unwrap().unwrap();
    release.send(()).unwrap();
    tokio::time::timeout(LIMIT, writer.finish())
        .await
        .unwrap()
        .unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN for isolated mount and network namespaces"]
fn writer_inherits_callers_private_namespaces() {
    use std::os::unix::fs::MetadataExt;
    fn identity(kind: &str) -> (u64, u64) {
        let m = std::fs::metadata(format!("/proc/thread-self/ns/{kind}")).unwrap();
        (m.dev(), m.ino())
    }
    let parent = [identity("mnt"), identity("net")];
    std::thread::spawn(move || {
        // Unshare FS before mount namespace creation in a multithreaded test process.
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_FS | libc::CLONE_NEWNS | libc::CLONE_NEWNET) },
            0
        );
        let expected = [identity("mnt"), identity("net")];
        assert_ne!(parent[0], expected[0]);
        assert_ne!(parent[1], expected[1]);
        let (result, observed) = mpsc::channel();
        let (sender, mut writer) = Writer::start(move |_: ()| {
            result.send([identity("mnt"), identity("net")]).unwrap();
        })
        .unwrap();
        sender.submit(());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(writer.finish()).unwrap();
        assert_eq!(observed.recv_timeout(LIMIT).unwrap(), expected);
    })
    .join()
    .unwrap();
    assert_eq!([identity("mnt"), identity("net")], parent);
}
