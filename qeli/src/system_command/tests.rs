use super::*;
use std::io::{Read, Write};
use tokio::io::AsyncReadExt;
const TEST_DEADLINE: Duration = Duration::from_secs(5);
const CHILD_DEADLINE: Duration = Duration::from_secs(2);

#[test]
fn command_fixture() {
    let Ok(mode) = std::env::var("QELI_SYSTEM_TEST_CHILD") else {
        return;
    };
    let mut witness = std::env::var("QELI_SYSTEM_TEST_WITNESS")
        .ok()
        .map(|address| {
            let mut socket = std::net::TcpStream::connect(address).unwrap();
            socket.write_all(b"ready").unwrap();
            socket
        });
    match mode.as_str() {
        "bytes" => {
            let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
            std::io::stdout().write_all(&data).unwrap();
            std::io::stderr().write_all(&data).unwrap();
        }
        "duplex" => {
            // Fill both output pipes before consuming input. A sequential writer deadlocks.
            std::io::stdout()
                .write_all(&vec![b'o'; 128 * 1024])
                .unwrap();
            std::io::stderr()
                .write_all(&vec![b'e'; 128 * 1024])
                .unwrap();
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            std::io::stdout().write_all(&input).unwrap();
        }
        "slow" => {
            std::thread::sleep(Duration::from_millis(500));
            std::io::stdout().write_all(b"late success").unwrap();
        }
        "fail" => {
            std::io::stderr()
                .write_all(b"expected command failure")
                .unwrap();
            std::process::exit(17);
        }
        "stdin" => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            assert!(input.is_empty());
            std::io::stdout().write_all(b"stdin-eof").unwrap();
        }
        "stdout-flood" | "stderr-flood" => {
            let mut sink: Box<dyn Write> = if mode == "stdout-flood" {
                Box::new(std::io::stdout())
            } else {
                Box::new(std::io::stderr())
            };
            loop {
                sink.write_all(&[42; 8192]).unwrap();
            }
        }
        "hang" => loop {
            std::thread::sleep(Duration::from_millis(20));
        },
        "witness" => {
            let _ = witness.take().unwrap().read(&mut [0]);
        }
        _ => panic!("unknown command fixture"),
    }
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
    std::process::exit(0);
}

pub(super) fn fixture(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "system_command::tests::command_fixture",
        "--nocapture",
    ]);
    command.inner.env("QELI_SYSTEM_TEST_CHILD", mode);
    command
}

#[test]
fn preserves_complete_binary_output_and_reusable_builder_without_runtime() {
    let mut command = fixture("bytes");
    let first = command.output().unwrap();
    let second = command.output().unwrap();
    assert!(first.status.success() && second.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    // libtest prints a header to stdout before entering the subprocess fixture.
    assert!(first.stdout.ends_with(&data));
    assert_eq!(first.stderr, data);
}

#[tokio::test]
async fn works_inside_current_thread_runtime_and_closes_stdin() {
    let output = fixture("stdin").output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.ends_with(b"stdin-eof"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn works_inside_multi_thread_runtime() {
    assert!(fixture("stdin").output().unwrap().status.success());
}

#[test]
fn preserves_nonzero_exit_and_distinguishes_spawn_failure() {
    let output = fixture("fail").output().unwrap();
    assert_eq!(output.status.code(), Some(17));
    assert_eq!(output.stderr, b"expected command failure");
    let missing =
        std::env::temp_dir().join(format!("qeli-missing-command-{}", rand::random::<u64>()));
    assert_eq!(
        Command::new(missing).output().unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn expired_deadline_does_not_spawn() {
    // An attempt to spawn this nonexistent executable would return NotFound instead.
    let missing =
        std::env::temp_dir().join(format!("qeli-expired-command-{}", rand::random::<u64>()));
    assert_eq!(
        Command::new(missing)
            .output_with_limits(Duration::ZERO, 1024)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

async fn ready(listener: &tokio::net::TcpListener) -> tokio::net::TcpStream {
    let (mut peer, _) = tokio::time::timeout(TEST_DEADLINE, listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut bytes = [0; 5];
    tokio::time::timeout(TEST_DEADLINE, peer.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"ready");
    peer
}

async fn closed(mut peer: tokio::net::TcpStream) {
    let read = tokio::time::timeout(TEST_DEADLINE, peer.read(&mut [0]))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0))
            || read.is_err_and(|e| matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ))
    );
}

async fn failure_releases_child(mode: &str, limit: usize, expected: io::ErrorKind) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut command = fixture(mode);
    command.inner.env(
        "QELI_SYSTEM_TEST_WITNESS",
        listener.local_addr().unwrap().to_string(),
    );
    let task =
        tokio::task::spawn_blocking(move || command.output_with_limits(CHILD_DEADLINE, limit));
    let peer = ready(&listener).await;
    let error = tokio::time::timeout(TEST_DEADLINE, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), expected);
    closed(peer).await;
}

#[tokio::test]
async fn timeout_terminates_child_before_sync_return() {
    failure_releases_child("hang", OUTPUT_LIMIT, io::ErrorKind::TimedOut).await;
}

#[tokio::test]
async fn stdout_overflow_fails_without_partial_output_and_releases_child() {
    failure_releases_child("stdout-flood", 32 * 1024, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn stderr_overflow_fails_without_partial_output_and_releases_child() {
    failure_releases_child("stderr-flood", 32 * 1024, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn cancelling_async_collector_releases_owned_child() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut command = fixture("hang");
    command.inner.env(
        "QELI_SYSTEM_TEST_WITNESS",
        listener.local_addr().unwrap().to_string(),
    );
    let task = tokio::spawn(async move {
        crate::hook_process::run_output(
            &mut command.inner,
            tokio::time::Instant::now() + TEST_DEADLINE,
            OUTPUT_LIMIT,
        )
        .await
    });
    let peer = ready(&listener).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    closed(peer).await;
}

#[cfg(target_os = "linux")]
async fn group_timeout(script: &str) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut command = Command::new("/bin/sh");
    command.args([
        std::ffi::OsStr::new("-c"),
        std::ffi::OsStr::new(script),
        std::env::current_exe().unwrap().as_os_str(),
    ]);
    command.inner.env("QELI_SYSTEM_TEST_CHILD", "witness").env(
        "QELI_SYSTEM_TEST_WITNESS",
        listener.local_addr().unwrap().to_string(),
    );
    let task = tokio::task::spawn_blocking(move || {
        command.output_with_limits(CHILD_DEADLINE, OUTPUT_LIMIT)
    });
    let peer = ready(&listener).await;
    assert_eq!(
        tokio::time::timeout(TEST_DEADLINE, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    closed(peer).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn timeout_kills_process_group_and_waiting_shell() {
    group_timeout("\"$0\" --exact system_command::tests::command_fixture --nocapture & wait").await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn exited_leader_retains_group_until_inherited_pipe_closes() {
    group_timeout("\"$0\" --exact system_command::tests::command_fixture --nocapture & exit 0")
        .await;
}

#[test]
fn deadline_errors_even_when_command_would_eventually_succeed() {
    let result = fixture("slow").output_with_limits(Duration::from_millis(100), OUTPUT_LIMIT);
    assert!(
        matches!(result, Err(ref error) if error.kind() == io::ErrorKind::TimedOut),
        "deadline must reject a late success"
    );
}

#[test]
fn finite_oversized_output_is_rejected_instead_of_returned_to_parser() {
    let result = fixture("bytes").output_with_limits(TEST_DEADLINE, 32 * 1024);
    assert!(
        matches!(result, Err(ref error) if error.kind() == io::ErrorKind::InvalidData),
        "oversized output must not reach the parser"
    );
}

#[tokio::test]
async fn generation_stop_joins_timed_out_command_without_late_observation() {
    use crate::transport_core::tasks::TaskGroup;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut command = fixture("hang");
    command.inner.env(
        "QELI_SYSTEM_TEST_WITNESS",
        listener.local_addr().unwrap().to_string(),
    );
    let mut group = TaskGroup::default();
    let sampler = group.spawner();
    let returned = Arc::new(AtomicBool::new(false));
    let published = Arc::new(AtomicBool::new(false));
    let command_returned = returned.clone();
    let observation_published = published.clone();
    group.spawner().spawn(async move {
        let result = sampler
            .blocking(move || {
                let result = command.output_with_limits(CHILD_DEADLINE, OUTPUT_LIMIT);
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
                command_returned.store(true, Ordering::Release);
            })
            .await;
        if result.is_some() {
            observation_published.store(true, Ordering::Release);
        }
    });
    let peer = ready(&listener).await;
    // Closing the group aborts the async collector, but its owned blocking command must
    // finish and reap the child before network cleanup can follow generation teardown.
    tokio::time::timeout(TEST_DEADLINE, group.finish())
        .await
        .unwrap();
    assert!(
        returned.load(Ordering::Acquire),
        "command detached from generation"
    );
    assert!(
        !published.load(Ordering::Acquire),
        "late observation after stop"
    );
    closed(peer).await;
}

#[test]
fn bounded_stdin_drains_both_outputs_without_a_detached_writer() {
    let input = vec![73; 1024 * 1024];
    let output = fixture("duplex")
        .output_bounded(
            Instant::now() + TEST_DEADLINE,
            2 * 1024 * 1024,
            Some(&input),
        )
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.ends_with(&input));
    assert_eq!(output.stderr, vec![b'e'; 128 * 1024]);
}

#[tokio::test]
async fn blocked_stdin_timeout_and_output_overflow_release_the_child() {
    for (mode, limit, kind) in [
        ("witness", OUTPUT_LIMIT, io::ErrorKind::TimedOut),
        ("stdout-flood", 32 * 1024, io::ErrorKind::InvalidData),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = fixture(mode);
        command.inner.env(
            "QELI_SYSTEM_TEST_WITNESS",
            listener.local_addr().unwrap().to_string(),
        );
        let task = tokio::task::spawn_blocking(move || {
            let input = vec![42; 1024 * 1024];
            command.output_bounded(Instant::now() + CHILD_DEADLINE, limit, Some(&input))
        });
        let peer = ready(&listener).await;
        let error = tokio::time::timeout(TEST_DEADLINE, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), kind);
        closed(peer).await;
    }
}

#[tokio::test]
async fn cancellation_with_blocked_stdin_stops_the_owned_child() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut command = fixture("witness");
    command.inner.env(
        "QELI_SYSTEM_TEST_WITNESS",
        listener.local_addr().unwrap().to_string(),
    );
    let task = tokio::spawn(async move {
        let input = vec![42; 1024 * 1024];
        crate::hook_process::run_output_with_input(
            &mut command.inner,
            tokio::time::Instant::now() + TEST_DEADLINE,
            OUTPUT_LIMIT,
            Some(&input),
        )
        .await
    });
    let peer = ready(&listener).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    closed(peer).await;
}

#[test]
fn expired_input_command_never_spawns_or_waits_for_stdin() {
    let missing =
        std::env::temp_dir().join(format!("qeli-expired-input-{}", rand::random::<u64>()));
    assert_eq!(
        Command::new(missing)
            .output_bounded(Instant::now(), 1024, Some(b"archive"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn transaction_deadline_limits_default_and_explicit_command_deadlines() {
    for explicit in [false, true] {
        let _budget =
            crate::operation_budget::Scope::enter(Instant::now() + Duration::from_millis(100));
        let result = if explicit {
            fixture("slow").output_until(Instant::now() + TEST_DEADLINE)
        } else {
            fixture("slow").output()
        };
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        // A new stage cannot reset an expired transaction or even attempt spawn.
        assert_eq!(
            Command::new("qeli-nonexistent-expired-budget-command")
                .output()
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}

#[test]
fn rollback_can_run_after_expired_setup_without_reviving_setup() {
    let _setup = crate::operation_budget::Scope::enter(Instant::now());
    assert_eq!(
        fixture("stdin").output().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    {
        let _cleanup = crate::operation_budget::Scope::enter(Instant::now() + TEST_DEADLINE);
        assert!(fixture("stdin").output().unwrap().status.success());
    }
    assert_eq!(
        fixture("stdin").output().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}
