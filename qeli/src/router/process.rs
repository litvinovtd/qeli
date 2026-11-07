//! Bounded argv-only child processes. Never evaluate policy or endpoint as shell.
use anyhow::{ensure, Context, Result};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

pub async fn output(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    seconds: u64,
) -> Result<Vec<u8>> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("start {program}"))?;
    let stdout = child.stdout.take().context("child stdout")?;
    let stderr = child.stderr.take().context("child stderr")?;
    let mut stdin = child.stdin.take();
    let job = async {
        if let (Some(writer), Some(bytes)) = (stdin.as_mut(), input) {
            writer.write_all(bytes).await?;
            writer.shutdown().await?;
        }
        drop(stdin);
        let (data, error) = tokio::join!(
            async {
                let mut data = Vec::new();
                stdout
                    .take(2 * 1024 * 1024 + 1)
                    .read_to_end(&mut data)
                    .await?;
                Ok::<_, std::io::Error>(data)
            },
            async {
                let mut error = Vec::new();
                stderr.take(16385).read_to_end(&mut error).await?;
                Ok::<_, std::io::Error>(error)
            }
        );
        let data = data?;
        let error = error?;
        ensure!(
            data.len() <= 2 * 1024 * 1024,
            "command output limit exceeded"
        );
        let result = child.wait().await?;
        ensure!(
            result.success(),
            "{program} failed: {}",
            String::from_utf8_lossy(&error)
        );
        Ok(data)
    };
    match tokio::time::timeout(Duration::from_secs(seconds), job).await {
        Ok(result) => result,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            anyhow::bail!("{program} deadline exceeded")
        }
    }
}
pub async fn command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    output(
        program,
        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        None,
        5,
    )
    .await
}
