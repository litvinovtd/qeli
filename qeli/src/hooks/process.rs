//! Owned command lifetime for Linux hooks, credential suppliers and network commands.
//! Hooks keep diagnostic tails; credential output is collected separately and never logged.
#[path = "output.rs"]
mod output;
#[cfg(any(test, feature = "client"))]
#[path = "secret.rs"]
pub(crate) mod secret;
#[cfg(any(feature = "server", test))]
pub(crate) use output::run as run_output;
pub(crate) use output::run_with_input as run_output_with_input;

use std::collections::VecDeque;
use std::io;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

const MAX_TAIL_BYTES: usize = 8 * 1024;

#[derive(Debug)]
struct OutputTail {
    bytes: VecDeque<u8>,
    truncated: bool,
}

impl Default for OutputTail {
    fn default() -> Self {
        Self {
            bytes: VecDeque::with_capacity(MAX_TAIL_BYTES),
            truncated: false,
        }
    }
}

impl OutputTail {
    fn push(&mut self, bytes: &[u8]) {
        let overflow = self
            .bytes
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(MAX_TAIL_BYTES);
        self.truncated |= overflow != 0;
        if bytes.len() >= MAX_TAIL_BYTES {
            self.bytes.clear();
            self.bytes.extend(&bytes[bytes.len() - MAX_TAIL_BYTES..]);
        } else {
            self.bytes.drain(..overflow);
            self.bytes.extend(bytes);
        }
    }

    fn text(&self) -> String {
        let bytes: Vec<_> = self.bytes.iter().copied().collect();
        let text = String::from_utf8_lossy(&bytes).trim().to_string();
        if self.truncated {
            format!("[truncated to last {MAX_TAIL_BYTES} bytes] {text}")
        } else {
            text
        }
    }
}

async fn drain(mut reader: impl AsyncRead + Unpin, tail: &mut OutputTail) -> io::Result<()> {
    let mut buffer = [0u8; 4096];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        tail.push(&buffer[..count]);
    }
}

#[derive(Debug)]
pub(crate) struct HookOutput {
    pub(crate) status: ExitStatus,
    pub(crate) timed_out: bool,
    stdout: OutputTail,
    stderr: OutputTail,
}

impl HookOutput {
    pub(crate) fn logged_output(&self) -> String {
        let stdout = self.stdout.text();
        let stderr = self.stderr.text();
        match (stdout.is_empty(), stderr.is_empty()) {
            (true, true) => String::new(),
            (false, true) => format!("stdout: {stdout}"),
            (true, false) => format!("stderr: {stderr}"),
            (false, false) => format!("stdout: {stdout}; stderr: {stderr}"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum RunError {
    Spawn(io::Error),
    Io(io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "hook spawn: {error}"),
            Self::Io(error) => write!(f, "hook I/O or cleanup: {error}"),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct CommandGroups {
    closed: bool,
    groups: std::collections::HashSet<i32>,
}

#[cfg(target_os = "linux")]
fn command_groups() -> &'static std::sync::Mutex<CommandGroups> {
    static GROUPS: std::sync::OnceLock<std::sync::Mutex<CommandGroups>> =
        std::sync::OnceLock::new();
    GROUPS.get_or_init(Default::default)
}

/// Process-budget fallback: prevent new commands and signal only groups whose
/// leaders remain owned/unreaped. Spawn/reap share this lock, preventing PGID reuse.
#[cfg(all(target_os = "linux", feature = "server"))]
pub(crate) fn stop_owned_groups() {
    let mut owned = command_groups()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    owned.closed = true;
    for group in owned.groups.drain() {
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
}

/// The Linux group leader stays unreaped until both output pipes close. Descendants
/// inheriting a pipe can otherwise outlive the leader, whose recycled PID would make
/// a later kill(-pid) unsafe. Never poll wait/try_wait while the drains are pending.
struct OwnedProcess {
    child: Child,
    #[cfg(target_os = "linux")]
    group: Option<i32>,
}

impl OwnedProcess {
    fn spawn(command: &mut Command) -> io::Result<Self> {
        Self::spawn_with_stderr(command, Stdio::piped())
    }

    fn spawn_with_stderr(command: &mut Command, stderr: Stdio) -> io::Result<Self> {
        Self::spawn_with_io(command, Stdio::null(), stderr)
    }

    fn spawn_with_io(command: &mut Command, stdin: Stdio, stderr: Stdio) -> io::Result<Self> {
        command
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(stderr)
            .kill_on_drop(true);
        #[cfg(target_os = "linux")]
        let mut owned = command_groups()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(target_os = "linux")]
        {
            if owned.closed {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "process shutdown budget expired; command admission closed",
                ));
            }
            command.process_group(0);
        }
        let child = command.spawn()?;
        #[cfg(target_os = "linux")]
        if let Some(pid) = child.id() {
            owned.groups.insert(pid as i32);
        }
        Ok(Self {
            #[cfg(target_os = "linux")]
            group: child.id().map(|pid| pid as i32),
            child,
        })
    }

    #[cfg(target_os = "linux")]
    fn kill_group(&mut self) -> io::Result<()> {
        let Some(group) = self.group.take() else {
            return Ok(());
        };
        let mut owned = command_groups()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owned.groups.remove(&group);
        // SAFETY: process_group(0) made this owned, unreaped child the group leader.
        if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    async fn wait(&mut self) -> io::Result<ExitStatus> {
        #[cfg(target_os = "linux")]
        {
            use std::future::Future;
            let waiting = self.child.wait();
            tokio::pin!(waiting);
            let group = &mut self.group;
            std::future::poll_fn(|cx| {
                // The deadline monitor must never observe a leader after this
                // poll reaped it but before its group was disarmed.
                let mut owned = command_groups()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let result = waiting.as_mut().poll(cx);
                if matches!(result, std::task::Poll::Ready(Ok(_))) {
                    if let Some(group) = group.take() {
                        owned.groups.remove(&group);
                    }
                }
                result
            })
            .await
        }
        #[cfg(not(target_os = "linux"))]
        self.child.wait().await
    }

    async fn terminate(&mut self) -> io::Result<ExitStatus> {
        #[cfg(target_os = "linux")]
        if let Err(error) = self.kill_group() {
            log::warn!("command: cannot kill process group: {error}");
        }
        // Group signaling is disarmed now, so reaping cannot expose a recycled
        // PGID. The leader may already have exited before/during the group kill.
        if let Some(status) = self.child.try_wait()? {
            return Ok(status);
        }
        // Also target the owned leader: a hook may have changed its own group.
        if let Err(error) = self.child.start_kill() {
            // A platform may report "already exited" for the race after try_wait.
            return self.child.try_wait()?.ok_or(error);
        }
        self.wait().await
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Err(error) = self.kill_group() {
            log::warn!("command: cannot kill cancelled process group: {error}");
        }
        // Child's kill_on_drop is the leader fallback; Tokio owns eventual reaping
        // on cancellation. Normal timeout/error paths explicitly await it instead.
    }
}

#[cfg(test)]
pub(crate) async fn run(mut command: Command, deadline: Duration) -> Result<HookOutput, RunError> {
    let until = tokio::time::Instant::now() + deadline;
    let process = OwnedProcess::spawn(&mut command).map_err(RunError::Spawn)?;
    collect(process, until).await
}

#[cfg(test)]
async fn collect(
    process: OwnedProcess,
    until: tokio::time::Instant,
) -> Result<HookOutput, RunError> {
    collect_cancellable(process, until, std::future::pending())
        .await
        .map(|output| output.expect("no cancellation"))
}

/// Stop preparation without spawning, or terminate and reap an admitted leader.
/// Used by the joined hook worker so runtime destruction cannot abandon reaping.
pub(crate) async fn run_cancellable(
    mut command: Command,
    deadline: Duration,
    stop: impl std::future::Future<Output = ()>,
) -> Result<Option<HookOutput>, RunError> {
    tokio::pin!(stop);
    tokio::select! {
        biased;
        _ = &mut stop => return Ok(None),
        _ = std::future::ready(()) => {},
    }
    let until = tokio::time::Instant::now() + deadline;
    let process = OwnedProcess::spawn(&mut command).map_err(RunError::Spawn)?;
    collect_cancellable(process, until, stop).await
}

async fn collect_cancellable(
    mut process: OwnedProcess,
    until: tokio::time::Instant,
    stop: impl std::future::Future<Output = ()>,
) -> Result<Option<HookOutput>, RunError> {
    let stdout = process.child.stdout.take().expect("piped hook stdout");
    let stderr = process.child.stderr.take().expect("piped hook stderr");
    let mut out_tail = OutputTail::default();
    let mut err_tail = OutputTail::default();
    let completed = tokio::select! {
        biased;
        _ = stop => None,
        result = tokio::time::timeout_at(until, async {
            tokio::try_join!(drain(stdout, &mut out_tail), drain(stderr, &mut err_tail))?;
            process.wait().await
        }) => Some(result),
    };
    let Some(completed) = completed else {
        process.terminate().await.map_err(RunError::Io)?;
        return Ok(None);
    };
    let (status, timed_out) = match completed {
        Ok(Ok(status)) => (status, false),
        Ok(Err(error)) => {
            // Drains have been dropped; no detached reader task or pipe remains.
            let _ = process.terminate().await;
            return Err(RunError::Io(error));
        }
        Err(_) => (process.terminate().await.map_err(RunError::Io)?, true),
    };
    Ok(Some(HookOutput {
        status,
        timed_out,
        stdout: out_tail,
        stderr: err_tail,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tokio::io::AsyncWriteExt;
    const DEADLINE: Duration = Duration::from_secs(5);

    // Real isolated subprocess, launched only with this exact test name + a per-child
    // environment flag. No host networking changes; optional witness is loopback-only.
    #[test]
    fn hook_fixture() {
        let Ok(mode) = std::env::var("QELI_HOOK_TEST_CHILD") else {
            return;
        };
        let mut witness = std::env::var("QELI_HOOK_TEST_WITNESS").ok().map(|address| {
            let mut socket = std::net::TcpStream::connect(address).unwrap();
            socket.write_all(b"ready").unwrap();
            socket
        });
        match mode.as_str() {
            "flood" | "flood-forever" => {
                let mut stdout = std::io::stdout().lock();
                let mut stderr = std::io::stderr().lock();
                let count = if mode == "flood" { 256 } else { usize::MAX };
                for _ in 0..count {
                    stdout.write_all(&[b'o'; 4096]).unwrap();
                    stderr.write_all(&[b'e'; 4096]).unwrap();
                }
                stdout.write_all(b"OUT-END").unwrap();
                stdout.flush().unwrap();
                stderr.write_all(b"ERR-END").unwrap();
                stderr.flush().unwrap();
                std::process::exit(0);
            }
            "secret" | "secret-fail" | "secret-invalid" => {
                let mut stdout = std::io::stdout().lock();
                stdout
                    .write_all("  fixture-secret-π \r\n".as_bytes())
                    .unwrap();
                if mode == "secret-invalid" {
                    stdout.write_all(&[0xff]).unwrap();
                }
                stdout.flush().unwrap();
                let mut stderr = std::io::stderr().lock();
                for _ in 0..256 {
                    stderr.write_all(&[b'e'; 4096]).unwrap();
                }
                stderr.write_all(b"stderr-fixture-secret").unwrap();
                stderr.flush().unwrap();
                std::process::exit(if mode == "secret-fail" { 17 } else { 0 });
            }
            "stderr-forever" => {
                let mut stderr = std::io::stderr().lock();
                loop {
                    stderr.write_all(&[b'e'; 4096]).unwrap();
                }
            }
            "fail" => {
                eprint!("expected failure");
                std::process::exit(17);
            }
            "witness" => {
                // Owner closing the test socket also cleans up a deliberately surviving
                // background fixture if an assertion fails before explicit release.
                let mut socket = witness.take().unwrap();
                let _ = std::io::Read::read(&mut socket, &mut [0]);
                std::process::exit(0);
            }
            "hang" => loop {
                std::thread::sleep(Duration::from_millis(20));
            },
            _ => panic!("unknown hook fixture"),
        }
    }

    pub(super) fn fixture(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "hook_process::tests::hook_fixture",
                "--nocapture",
            ])
            .env("QELI_HOOK_TEST_CHILD", mode);
        command
    }

    #[tokio::test]
    async fn real_flood_is_drained_with_bounded_tails_on_both_pipes() {
        let output = run(fixture("flood"), DEADLINE).await.unwrap();
        assert!(output.status.success());
        assert!(!output.timed_out);
        for (tail, end) in [(&output.stdout, "OUT-END"), (&output.stderr, "ERR-END")] {
            assert!(
                tail.bytes.len() <= MAX_TAIL_BYTES,
                "hook output retained {} bytes",
                tail.bytes.len()
            );
            assert!(tail.truncated);
            assert!(tail.text().ends_with(end));
        }
        assert!(output.logged_output().contains("stdout:"));
        assert!(output.logged_output().contains("stderr:"));
    }

    #[test]
    fn tail_retains_latest_bytes_across_chunk_boundaries() {
        let mut tail = OutputTail::default();
        let source: Vec<_> = (0..MAX_TAIL_BYTES * 4 + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        for chunk in source.chunks(317) {
            tail.push(chunk);
            assert!(tail.bytes.len() <= MAX_TAIL_BYTES);
            assert!(tail.bytes.capacity() <= MAX_TAIL_BYTES);
        }
        assert_eq!(
            tail.bytes.into_iter().collect::<Vec<_>>(),
            source[source.len() - MAX_TAIL_BYTES..]
        );
        let mut large = OutputTail::default();
        large.push(&source);
        assert_eq!(
            large.bytes.into_iter().collect::<Vec<_>>(),
            source[source.len() - MAX_TAIL_BYTES..]
        );
    }

    #[test]
    fn empty_exact_and_non_utf8_output_are_bounded() {
        let mut tail = OutputTail::default();
        assert_eq!(tail.text(), "");
        tail.push(&[b'a'; MAX_TAIL_BYTES]);
        assert!(!tail.truncated);
        tail.push(&[0xff]);
        assert!(tail.truncated);
        assert!(tail.text().ends_with('\u{fffd}'));
        assert!(tail.text().len() < MAX_TAIL_BYTES * 3 + 100);
    }

    #[tokio::test]
    async fn cooperative_stop_before_admission_does_not_spawn() {
        let missing = std::env::temp_dir().join(format!("missing-hook-{}", rand::random::<u64>()));
        assert!(
            run_cancellable(Command::new(missing), DEADLINE, std::future::ready(()))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn cooperative_stop_terminates_and_reaps_admitted_child() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = fixture("hang");
        command.env(
            "QELI_HOOK_TEST_WITNESS",
            listener.local_addr().unwrap().to_string(),
        );
        let process = OwnedProcess::spawn(&mut command).unwrap();
        #[cfg(target_os = "linux")]
        let pid = process.child.id().unwrap() as libc::pid_t;
        let (mut peer, _) = tokio::time::timeout(DEADLINE, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut ready = [0; 5];
        tokio::time::timeout(DEADLINE, peer.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert!(collect_cancellable(
            process,
            tokio::time::Instant::now() + DEADLINE,
            std::future::ready(())
        )
        .await
        .unwrap()
        .is_none());
        assert_peer_closed(peer).await;
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
    }

    #[tokio::test]
    async fn nonzero_exit_and_spawn_error_remain_distinct() {
        let output = run(fixture("fail"), DEADLINE).await.unwrap();
        assert_eq!(output.status.code(), Some(17));
        assert!(!output.timed_out);
        assert!(output.logged_output().contains("expected failure"));
        let missing =
            std::env::temp_dir().join(format!("qeli-missing-hook-{}", rand::random::<u64>()));
        assert!(matches!(
            run(Command::new(missing), DEADLINE).await,
            Err(RunError::Spawn(_))
        ));
    }

    #[tokio::test]
    async fn timeout_terminates_and_reaps_real_child() {
        let output = run(fixture("hang"), Duration::from_millis(500))
            .await
            .unwrap();
        assert!(output.timed_out);
        assert!(!output.status.success());
    }

    #[tokio::test]
    async fn cancelling_runner_closes_real_child_witness() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = fixture("hang");
        command.env(
            "QELI_HOOK_TEST_WITNESS",
            listener.local_addr().unwrap().to_string(),
        );
        let task = tokio::spawn(run(command, Duration::from_secs(60)));
        let (mut peer, _) = tokio::time::timeout(DEADLINE, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut ready = [0; 5];
        peer.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, b"ready");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_peer_closed(peer).await;
    }

    #[tokio::test]
    async fn drain_keeps_running_after_budget_and_propagates_reader_failure() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let producer = async {
            for _ in 0..32 {
                writer.write_all(&[b'x'; 4096]).await.unwrap();
            }
            writer.write_all(b"last").await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let mut tail = OutputTail::default();
        let (_, result) = tokio::join!(producer, drain(reader, &mut tail));
        result.unwrap();
        assert!(tail.text().ends_with("last"));
        assert!(tail.truncated);
        struct Broken;
        impl AsyncRead for Broken {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Err(io::Error::other("fixture read failure")))
            }
        }
        assert_eq!(
            drain(Broken, &mut tail).await.unwrap_err().to_string(),
            "fixture read failure"
        );
    }

    #[tokio::test]
    async fn continuous_output_cannot_starve_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = fixture("flood-forever");
        command.env(
            "QELI_HOOK_TEST_WITNESS",
            listener.local_addr().unwrap().to_string(),
        );
        let process = OwnedProcess::spawn(&mut command).unwrap();
        let (mut peer, _) = tokio::time::timeout(DEADLINE, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut ready = [0; 5];
        tokio::time::timeout(DEADLINE, peer.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        let output = tokio::time::timeout(
            DEADLINE,
            collect(
                process,
                tokio::time::Instant::now() + Duration::from_millis(150),
            ),
        )
        .await
        .expect("output flood starved timeout")
        .unwrap();
        assert!(output.timed_out);
        assert!(output.stdout.truncated);
        assert!(output.stderr.truncated);
        assert_peer_closed(peer).await;
    }

    #[cfg(target_os = "linux")]
    pub(super) fn shell_fixture(script: &str, witness: std::net::SocketAddr) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script, "qeli-hook-test"])
            .arg(std::env::current_exe().unwrap())
            .env("QELI_HOOK_TEST_CHILD", "witness")
            .env("QELI_HOOK_TEST_WITNESS", witness.to_string());
        command
    }

    pub(super) async fn witness(listener: &tokio::net::TcpListener) -> tokio::net::TcpStream {
        let (mut peer, _) = tokio::time::timeout(DEADLINE, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut ready = [0; 5];
        tokio::time::timeout(DEADLINE, peer.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ready, b"ready");
        peer
    }

    #[cfg(target_os = "linux")]
    pub(super) async fn leader_exited_but_not_reaped(pid: u32) {
        tokio::time::timeout(DEADLINE, async {
            loop {
                // WNOWAIT observes the owned leader without stealing it from the runner.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                assert_eq!(
                    result, 0,
                    "leader was reaped while descendants still hold pipes"
                );
                if unsafe { info.si_pid() } == pid as i32 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    pub(super) async fn assert_peer_closed(mut peer: tokio::net::TcpStream) {
        let mut bytes = Vec::new();
        let result = tokio::time::timeout(DEADLINE, peer.read_to_end(&mut bytes))
            .await
            .expect("hook descendant survived cleanup");
        match result {
            Ok(_) => {}
            // Windows may reset a killed process's TCP socket instead of sending FIN.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            Err(error) => panic!("unexpected witness read error: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    async fn group_timeout(script: &str, exited_leader: bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = shell_fixture(script, listener.local_addr().unwrap());
        let process = OwnedProcess::spawn(&mut command).unwrap();
        let leader = process.child.id().unwrap();
        let task = tokio::spawn(collect(
            process,
            tokio::time::Instant::now() + Duration::from_secs(2),
        ));
        let peer = witness(&listener).await;
        if exited_leader {
            leader_exited_but_not_reaped(leader).await;
        }
        let output = tokio::time::timeout(DEADLINE, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(output.timed_out);
        assert_peer_closed(peer).await;
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    leader,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_kills_shell_and_waited_descendant() {
        group_timeout(
            r#""$1" --exact hook_process::tests::hook_fixture --nocapture & wait"#,
            false,
        )
        .await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_keeps_exited_leader_owned_until_inherited_pipes_close() {
        group_timeout(
            r#""$1" --exact hook_process::tests::hook_fixture --nocapture & exit 0"#,
            true,
        )
        .await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancellation_kills_descendant_after_shell_exit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = shell_fixture(
            r#""$1" --exact hook_process::tests::hook_fixture --nocapture & exit 0"#,
            listener.local_addr().unwrap(),
        );
        let process = OwnedProcess::spawn(&mut command).unwrap();
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn normal_completion_preserves_explicitly_redirected_background_child() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let command = shell_fixture(
            r#""$1" --exact hook_process::tests::hook_fixture --nocapture >/dev/null 2>&1 & exit 0"#,
            listener.local_addr().unwrap(),
        );
        let task = tokio::spawn(run(command, DEADLINE));
        let mut peer = witness(&listener).await;
        let output = tokio::time::timeout(DEADLINE, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(output.status.success());
        assert!(!output.timed_out);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.read(&mut [0]))
                .await
                .is_err(),
            "normal hook killed background service"
        );
        peer.write_all(b"stop fixture").await.unwrap();
        assert_peer_closed(peer).await;
    }
}
