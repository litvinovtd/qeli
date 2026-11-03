//! Complete machine-readable output, using the same process ownership as hooks.
use super::{Command, OwnedProcess};
use std::io;
use std::process::Output;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

async fn read_complete(mut reader: impl AsyncRead + Unpin, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(bytes);
        }
        if count > limit.saturating_sub(bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "system command output limit exceeded; partial output discarded",
            ));
        }
        bytes.try_reserve(count).map_err(io::Error::other)?;
        bytes.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(any(feature = "server", test))]
pub(crate) async fn run(
    command: &mut Command,
    until: tokio::time::Instant,
    limit: usize,
) -> io::Result<Output> {
    run_with_input(command, until, limit, None).await
}

pub(crate) async fn run_with_input(
    command: &mut Command,
    until: tokio::time::Instant,
    limit: usize,
    input: Option<&[u8]>,
) -> io::Result<Output> {
    if tokio::time::Instant::now() >= until {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "system command deadline expired",
        ));
    }
    let stdin = if input.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    };
    let mut process = OwnedProcess::spawn_with_io(command, stdin, std::process::Stdio::piped())?;
    let mut stdin = process.child.stdin.take();
    let stdout = process.child.stdout.take().expect("piped command stdout");
    let stderr = process.child.stderr.take().expect("piped command stderr");
    let completed = tokio::time::timeout_at(until, async {
        // Drain both pipes before reaping: a surviving descendant may retain a pipe.
        // Feed stdin and drain both outputs in the same owned future. A child that
        // stops reading cannot strand a detached writer or bypass the deadline.
        let feed = async {
            if let (Some(mut stdin), Some(input)) = (stdin.take(), input) {
                stdin.write_all(input).await?;
                stdin.shutdown().await?;
            }
            Ok::<_, io::Error>(())
        };
        let (_, stdout, stderr) = tokio::try_join!(
            feed,
            read_complete(stdout, limit),
            read_complete(stderr, limit)
        )?;
        let status = process.wait().await?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    })
    .await;
    let error = match completed {
        Ok(Ok(output)) => return Ok(output),
        Ok(Err(error)) => error,
        Err(_) => io::Error::new(io::ErrorKind::TimedOut, "system command timed out"),
    };
    // Readers are already dropped. Keep ownership until the child is killed and reaped;
    // a timeout alone must never detach a still-running network mutation.
    if let Err(cleanup) = process.terminate().await {
        return Err(io::Error::new(
            error.kind(),
            format!("{error}; process cleanup: {cleanup}"),
        ));
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exact_limit_is_complete_and_overflow_is_an_error() {
        assert_eq!(read_complete(&b"abcd"[..], 4).await.unwrap(), b"abcd");
        assert_eq!(
            read_complete(&b"abcde"[..], 4).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(read_complete(&b""[..], 0).await.unwrap(), b"");
    }

    #[tokio::test]
    async fn output_reader_failure_is_not_a_successful_partial_result() {
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
        assert!(read_complete(Broken, 1024)
            .await
            .unwrap_err()
            .to_string()
            .contains("fixture read failure"));
    }
}
