//! Read-only firewall-tool discovery. Async consumers share bounded probe admission.
use std::io;
use tokio::{sync::Semaphore, time::Instant};

const OUTPUT_LIMIT: usize = 64 * 1024;
static PROBES: Semaphore = Semaphore::const_new(4);

#[derive(Clone, Copy)]
pub(super) enum Tool {
    Ipv4,
    Ipv6,
}
impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::Ipv4 => "iptables",
            Self::Ipv6 => "ip6tables",
        }
    }
    fn paths(self) -> [&'static str; 4] {
        match self {
            Self::Ipv4 => [
                "/usr/sbin/iptables",
                "/sbin/iptables",
                "/usr/bin/iptables",
                "/bin/iptables",
            ],
            Self::Ipv6 => [
                "/usr/sbin/ip6tables",
                "/sbin/ip6tables",
                "/usr/bin/ip6tables",
                "/bin/ip6tables",
            ],
        }
    }
}

pub(super) fn installed(tool: Tool) -> Option<String> {
    tool.paths()
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(str::to_owned)
}

fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "firewall availability probe deadline expired",
    )
}

pub(super) async fn find_async(tool: Tool, until: Instant) -> io::Result<Option<String>> {
    if Instant::now() >= until {
        return Err(expired());
    }
    #[cfg(test)]
    if let Ok(program) = TEST_PROGRAM.try_with(Clone::clone) {
        return probe(&PROBES, &program, until).await;
    }
    if let Some(path) = installed(tool) {
        // Synchronous standard-path metadata lookup is unchanged; never accept it late.
        return if Instant::now() < until {
            Ok(Some(path))
        } else {
            Err(expired())
        };
    }
    probe(&PROBES, tool.name(), until).await
}

async fn probe(slots: &Semaphore, program: &str, until: Instant) -> io::Result<Option<String>> {
    let _permit = tokio::time::timeout_at(until, slots.acquire())
        .await
        .map_err(|_| expired())?
        .map_err(|_| io::Error::other("firewall availability probes are unavailable"))?;
    // timeout_at may poll an immediately-ready permit after the deadline.
    if Instant::now() >= until {
        return Err(expired());
    }
    let output = crate::hook_process::run_output(
        tokio::process::Command::new(program).arg("--version"),
        until,
        OUTPUT_LIMIT,
    )
    .await;
    match output {
        Ok(output) if output.status.success() => Ok(Some(program.to_string())),
        Ok(output) => Err(io::Error::other(format!(
            "firewall tool --version failed with {}",
            output.status,
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

// Task-local injection never changes PATH or another request's discovery behavior.
#[cfg(test)]
tokio::task_local! { static TEST_PROGRAM: String; }
#[cfg(test)]
pub(crate) async fn with_probe<T>(program: String, run: impl std::future::Future<Output = T>) -> T {
    TEST_PROGRAM.scope(program, run).await
}

#[cfg(test)]
mod tests;
