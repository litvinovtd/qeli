use super::*;
use std::{
    os::fd::AsRawFd,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn name() -> Vec<u8> {
    format!(
        "qeli-server-lease-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )
    .into_bytes()
}
#[test]
fn live_worker_reservation_excludes_peers_and_drop_releases_it() {
    let name = name();
    let owner = bind(&name).unwrap();
    assert_eq!(bind(&name).unwrap_err().kind(), io::ErrorKind::AddrInUse);
    assert_eq!(bind(&name).unwrap_err().kind(), io::ErrorKind::AddrInUse);
    drop(owner);
    let _next = bind(&name).unwrap();
}
#[test]
fn unrelated_names_can_coexist_without_weakening_exclusion() {
    let a = name();
    let b = name();
    let _a = bind(&a).unwrap();
    let _b = bind(&b).unwrap();
    assert_eq!(bind(&a).unwrap_err().kind(), io::ErrorKind::AddrInUse);
    assert_eq!(bind(&b).unwrap_err().kind(), io::ErrorKind::AddrInUse);
}
#[test]
fn worker_reservation_is_not_inherited_by_exec() {
    let owner = bind(&name()).unwrap();
    // SAFETY: a live borrowed fd and F_GETFD, with no variadic argument.
    let flags = unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
}

#[test]
#[ignore = "child fixture: requires QELI_WORKER_LEASE_TEST_NAME; parent kills this process"]
fn lease_child() {
    let name = std::env::var("QELI_WORKER_LEASE_TEST_NAME").unwrap();
    let _owner = bind(name.as_bytes()).unwrap();
    println!("WORKER_LEASE_READY");
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn sigkill_releases_worker_reservation_without_cleanup() {
    let name = String::from_utf8(name()).unwrap();
    let child_name = format!(
        "{}::lease_child",
        module_path!().split_once("::").unwrap().1
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &child_name, "--ignored", "--nocapture"])
        .env("QELI_WORKER_LEASE_TEST_NAME", &name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // A reader thread is joined after the bounded child is reaped; no hanging fixture.
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        use std::io::BufRead;
        for line in io::BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("WORKER_LEASE_READY") {
                let _ = tx.send(());
                break;
            }
        }
    });
    let ready = rx.recv_timeout(Duration::from_secs(5)).is_ok();
    let blocked =
        ready && bind(name.as_bytes()).is_err_and(|e| e.kind() == io::ErrorKind::AddrInUse);
    child.kill().unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "killed child did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    reader.join().unwrap();
    assert!(
        ready && blocked,
        "child must hold the reservation before SIGKILL"
    );
    let _recovered = bind(name.as_bytes()).unwrap();
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN; disposable thread network namespace only"]
fn native_worker_reservations_are_independent_across_network_namespaces() {
    let name = name();
    let _parent = bind(&name).unwrap();
    let child_name = name.clone();
    std::thread::spawn(move || {
        // SAFETY: fresh disposable thread, no shared runtime/network mutations.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let _child = bind(&child_name).unwrap();
        assert_eq!(
            bind(&child_name).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
    })
    .join()
    .unwrap();
    assert_eq!(bind(&name).unwrap_err().kind(), io::ErrorKind::AddrInUse);
}

#[test]
fn setup_failure_before_network_mutation_releases_reservation() {
    let name = name();
    let lease = reserve(&name).unwrap();
    assert_eq!(bind(&name).unwrap_err().kind(), io::ErrorKind::AddrInUse);
    drop(lease);
    let _replacement = bind(&name).unwrap();
}

#[test]
fn completed_worker_releases_reservation_after_scope_exit() {
    let name = name();
    let mut lease = reserve(&name).unwrap();
    lease.arm();
    lease.mark_complete();
    assert_eq!(bind(&name).unwrap_err().kind(), io::ErrorKind::AddrInUse);
    drop(lease);
    let _replacement = bind(&name).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_worker_keeps_network_reservation_until_process_exit() {
    let name = name();
    let worker_name = name.clone();
    let (ready, entered) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let mut lease = reserve(&worker_name).unwrap();
        let fd = lease.socket.as_ref().unwrap().as_raw_fd();
        lease.arm();
        ready.send(fd).unwrap();
        std::future::pending::<()>().await;
    });
    let fd = entered.await.unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    assert_eq!(bind(&name).unwrap_err().kind(), io::ErrorKind::AddrInUse);
    // A test process must close the intentionally retained descriptor itself.
    assert_eq!(unsafe { libc::close(fd) }, 0);
    let _replacement = bind(&name).unwrap();
}
