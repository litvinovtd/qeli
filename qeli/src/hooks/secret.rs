//! Full bounded credential output. Never reuse a hook's truncated/loggable output tail.
use super::OwnedProcess;
use crate::secret_buffer::{SecretBuffer, SecretDataError, MAX_SECRET_BYTES};
use std::{io, process::ExitStatus, process::Stdio, time::Duration};
use tokio::{io::AsyncRead, io::AsyncReadExt, process::Command};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SecretError {
    #[error("auth.password_command could not start: {0}")]
    Spawn(#[source] io::Error),
    #[error("auth.password_command I/O or cleanup failed: {0}")]
    Io(#[source] io::Error),
    #[error("auth.password_command exceeded its execution/output deadline")]
    Timeout,
    #[error("auth.password_command cancelled by client shutdown")]
    Cancelled,
    #[error(
        "auth.password_command stdout exceeds {MAX_SECRET_BYTES} bytes; password was rejected"
    )]
    TooLarge,
    #[error("auth.password_command failed with {0}; command output is not logged")]
    Failed(ExitStatus),
    #[error("auth.password_command stdout is not valid UTF-8; password was rejected")]
    InvalidUtf8,
}

impl From<SecretDataError> for SecretError {
    fn from(error: SecretDataError) -> Self {
        match error {
            SecretDataError::TooLarge => Self::TooLarge,
            SecretDataError::InvalidUtf8 => Self::InvalidUtf8,
        }
    }
}

#[cfg(all(target_os = "linux", feature = "client"))]
pub(crate) async fn password(
    command: &str,
    stop: impl std::future::Future<Output = ()>,
) -> Result<Zeroizing<String>, SecretError> {
    // A fixed executable matches lifecycle hooks and cannot be replaced via PATH.
    let mut shell = Command::new("/bin/sh");
    shell.args(["-c", command]);
    run_until_stopped(shell, Duration::from_secs(30), stop).await
}

async fn read_secret(
    mut reader: impl AsyncRead + Unpin,
    output: &mut SecretBuffer,
) -> Result<(), SecretError> {
    let mut buffer = Zeroizing::new([0u8; 4096]);
    loop {
        let count = reader
            .read(&mut buffer[..])
            .await
            .map_err(SecretError::Io)?;
        if count == 0 {
            return Ok(());
        }
        output.append(&buffer[..count])?;
    }
}

#[cfg(test)]
async fn run(command: Command, deadline: Duration) -> Result<Zeroizing<String>, SecretError> {
    run_until_stopped(command, deadline, std::future::pending()).await
}

async fn run_until_stopped(
    mut command: Command,
    deadline: Duration,
    stop: impl std::future::Future<Output = ()>,
) -> Result<Zeroizing<String>, SecretError> {
    tokio::pin!(stop);
    // Do not even start a supplier when shutdown is already known.
    tokio::select! {
        biased;
        _ = &mut stop => return Err(SecretError::Cancelled),
        _ = std::future::ready(()) => {},
    }
    let until = tokio::time::Instant::now() + deadline;
    // stderr may contain the same secret or the command itself. Discard it at the OS
    // boundary: it cannot fill a pipe, grow retained memory or appear in any error.
    let process =
        OwnedProcess::spawn_with_stderr(&mut command, Stdio::null()).map_err(SecretError::Spawn)?;
    collect_until_stopped(process, until, stop).await
}

#[cfg(test)]
async fn collect(
    process: OwnedProcess,
    until: tokio::time::Instant,
) -> Result<Zeroizing<String>, SecretError> {
    collect_until_stopped(process, until, std::future::pending()).await
}

async fn collect_until_stopped(
    mut process: OwnedProcess,
    until: tokio::time::Instant,
    stop: impl std::future::Future<Output = ()>,
) -> Result<Zeroizing<String>, SecretError> {
    let stdout = process.child.stdout.take().expect("piped command stdout");
    let mut output = SecretBuffer::new();
    let completed = tokio::select! {
        biased;
        _ = stop => Err(SecretError::Cancelled),
        result = tokio::time::timeout_at(until, async {
            read_secret(stdout, &mut output).await?;
            // Keep the group leader unreaped while descendants may hold stdout.
            process.wait().await.map_err(SecretError::Io)
        }) => result.unwrap_or(Err(SecretError::Timeout)),
    };
    let status = match completed {
        Ok(status) => status,
        Err(error) => {
            process.terminate().await.map_err(SecretError::Io)?;
            return Err(error);
        }
    };
    if !status.success() {
        return Err(SecretError::Failed(status));
    }
    output.decode().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_process::tests::{assert_peer_closed, fixture, witness};
    const DEADLINE: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn exact_limit_is_preserved_and_overflow_is_rejected_not_truncated() {
        let source = vec![b'x'; MAX_SECRET_BYTES];
        let mut output = SecretBuffer::new();
        read_secret(&source[..], &mut output).await.unwrap();
        assert_eq!(output.bytes(), &source);
        assert_eq!(output.capacity(), MAX_SECRET_BYTES);
        let mut output = SecretBuffer::new();
        let too_large = vec![b'x'; MAX_SECRET_BYTES + 1];
        assert!(matches!(
            read_secret(&too_large[..], &mut output).await,
            Err(SecretError::TooLarge)
        ));
        assert!(output.bytes().len() <= MAX_SECRET_BYTES);
        assert_eq!(output.capacity(), MAX_SECRET_BYTES);
    }

    #[test]
    fn decoding_is_strict_and_only_trims_outer_whitespace() {
        for (raw, expected) in [
            (" \tпароль with space\r\n", "пароль with space"),
            (" \r\n", ""),
        ] {
            let mut output = SecretBuffer::new();
            output.append(raw.as_bytes()).unwrap();
            assert_eq!(output.decode().unwrap().as_str(), expected);
        }
        let mut output = SecretBuffer::new();
        output.append(b"secret\xff").unwrap();
        assert!(matches!(output.decode(), Err(SecretDataError::InvalidUtf8)));
    }

    #[tokio::test]
    async fn real_command_preserves_full_stdout_and_discards_noisy_stderr() {
        // The fixture is this test executable: libtest adds a preamble to stdout.
        // Compare its complete known-small output, not a hard-coded harness banner.
        let expected = fixture("secret").output().await.unwrap();
        assert!(expected.status.success());
        let expected = std::str::from_utf8(&expected.stdout).unwrap().trim();
        let actual = run(fixture("secret"), DEADLINE).await.unwrap();
        assert_eq!(actual.as_str(), expected);
        assert!(actual.ends_with("fixture-secret-π"));
        assert!(!actual.contains("stderr-fixture-secret"));
    }

    #[tokio::test]
    async fn failure_and_invalid_utf8_never_expose_output_in_display_or_debug() {
        for (mode, failed) in [("secret-fail", true), ("secret-invalid", false)] {
            let error = run(fixture(mode), DEADLINE).await.unwrap_err();
            if failed {
                assert!(matches!(&error, SecretError::Failed(status) if status.code() == Some(17)));
            } else {
                assert!(matches!(&error, SecretError::InvalidUtf8));
            }
            for message in [error.to_string(), format!("{error:?}")] {
                assert!(!message.contains("fixture-secret"));
                assert!(!message.contains("stderr-fixture-secret"));
                assert!(!message.contains("eeeeeeee"));
            }
        }
        let missing =
            std::env::temp_dir().join(format!("qeli-missing-supplier-{}", rand::random::<u64>()));
        assert!(matches!(
            run(Command::new(missing), DEADLINE).await,
            Err(SecretError::Spawn(_))
        ));
    }

    async fn witnessed_process(mode: &str) -> (OwnedProcess, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = fixture(mode);
        command.env(
            "QELI_HOOK_TEST_WITNESS",
            listener.local_addr().unwrap().to_string(),
        );
        let process = OwnedProcess::spawn_with_stderr(&mut command, Stdio::null()).unwrap();
        let peer = witness(&listener).await;
        (process, peer)
    }

    #[tokio::test]
    async fn stdout_overflow_kills_and_reaps_real_supplier() {
        let (process, peer) = witnessed_process("flood-forever").await;
        let result = tokio::time::timeout(
            DEADLINE,
            collect(process, tokio::time::Instant::now() + DEADLINE),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(SecretError::TooLarge)));
        assert_peer_closed(peer).await;
    }

    #[tokio::test]
    async fn deadline_interrupts_hang_and_stderr_flood_without_blocking_runtime() {
        for mode in ["hang", "stderr-forever"] {
            let (process, peer) = witnessed_process(mode).await;
            // Default tokio::test uses one runtime thread. A blocking Command::output
            // would prevent this timer and the deadline from making progress.
            let tick = tokio::time::sleep(Duration::from_millis(20));
            let job = collect(
                process,
                tokio::time::Instant::now() + Duration::from_millis(150),
            );
            tokio::pin!(job);
            tokio::select! {
                _ = tick => {},
                result = &mut job => panic!("supplier returned before responsiveness check: {result:?}"),
            }
            assert!(matches!(
                tokio::time::timeout(DEADLINE, job).await.unwrap(),
                Err(SecretError::Timeout)
            ));
            assert_peer_closed(peer).await;
        }
    }

    #[tokio::test]
    async fn cancellation_closes_real_supplier_witness() {
        let (process, peer) = witnessed_process("hang").await;
        let task = tokio::spawn(collect(
            process,
            tokio::time::Instant::now() + Duration::from_secs(60),
        ));
        // Wait until collect was polled so this tests cancellation of the I/O future.
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_peer_closed(peer).await;
    }

    #[tokio::test]
    async fn cooperative_stop_terminates_supplier_and_pre_cancel_never_spawns() {
        let missing =
            std::env::temp_dir().join(format!("qeli-stopped-supplier-{}", rand::random::<u64>()));
        assert!(matches!(
            run_until_stopped(Command::new(missing), DEADLINE, std::future::ready(())).await,
            Err(SecretError::Cancelled)
        ));
        let (process, peer) = witnessed_process("hang").await;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(collect_until_stopped(
            process,
            tokio::time::Instant::now() + Duration::from_secs(60),
            async {
                let _ = stopped.await;
            },
        ));
        tokio::task::yield_now().await;
        stop.send(()).unwrap();
        assert!(matches!(
            tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap(),
            Err(SecretError::Cancelled)
        ));
        assert_peer_closed(peer).await;
    }

    #[tokio::test]
    async fn output_reader_failure_is_propagated_without_partial_secret() {
        struct Broken;
        impl AsyncRead for Broken {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Err(io::Error::other("fixture read error")))
            }
        }
        let mut output = SecretBuffer::new();
        output.append(b"partial-fixture-secret").unwrap();
        let error = read_secret(Broken, &mut output).await.unwrap_err();
        assert!(matches!(error, SecretError::Io(_)));
        assert!(!format!("{error:?}").contains("partial-fixture-secret"));
    }

    #[cfg(all(target_os = "linux", feature = "client"))]
    #[tokio::test]
    async fn linux_shell_wrapper_preserves_syntax_and_has_no_interactive_stdin() {
        let secret = password(
            "if read -r value; then printf unexpected-input; else printf ' \\tfixture-password\\r\\n'; fi",
            std::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(secret.as_str(), "fixture-password");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn deadline_also_covers_wait_after_stdout_has_closed() {
        use crate::hook_process::tests::shell_fixture;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = shell_fixture(
            r#"exec >/dev/null; exec "$1" --exact hook_process::tests::hook_fixture --nocapture"#,
            listener.local_addr().unwrap(),
        );
        let process = OwnedProcess::spawn_with_stderr(&mut command, Stdio::null()).unwrap();
        let peer = witness(&listener).await;
        let result = tokio::time::timeout(
            DEADLINE,
            collect(
                process,
                tokio::time::Instant::now() + Duration::from_millis(150),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(SecretError::Timeout)));
        assert_peer_closed(peer).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_kills_descendant_holding_stdout_after_shell_exit() {
        use crate::hook_process::tests::{leader_exited_but_not_reaped, shell_fixture};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = shell_fixture(
            r#""$1" --exact hook_process::tests::hook_fixture --nocapture & exit 0"#,
            listener.local_addr().unwrap(),
        );
        let process = OwnedProcess::spawn_with_stderr(&mut command, Stdio::null()).unwrap();
        let leader = process.child.id().unwrap();
        let task = tokio::spawn(collect(
            process,
            tokio::time::Instant::now() + Duration::from_secs(2),
        ));
        let peer = witness(&listener).await;
        leader_exited_but_not_reaped(leader).await;
        assert!(matches!(
            tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap(),
            Err(SecretError::Timeout)
        ));
        assert_peer_closed(peer).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancellation_kills_descendant_holding_stdout_after_shell_exit() {
        use crate::hook_process::tests::{leader_exited_but_not_reaped, shell_fixture};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = shell_fixture(
            r#""$1" --exact hook_process::tests::hook_fixture --nocapture & exit 0"#,
            listener.local_addr().unwrap(),
        );
        let process = OwnedProcess::spawn_with_stderr(&mut command, Stdio::null()).unwrap();
        let leader = process.child.id().unwrap();
        let task = tokio::spawn(collect(
            process,
            tokio::time::Instant::now() + Duration::from_secs(60),
        ));
        let peer = witness(&listener).await;
        leader_exited_but_not_reaped(leader).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_peer_closed(peer).await;
    }
}
