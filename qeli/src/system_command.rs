//! Bounded synchronous commands for Linux network setup and rollback.
//!
//! The caller keeps synchronous ordering (including Drop guards). A scoped thread owns
//! a private runtime so this also works inside a current-thread Tokio runtime or without
//! any runtime. No detached blocking task or output reader survives the call.
use std::ffi::OsStr;
use std::io;
use std::process::Output;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(15);
const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;

pub(crate) struct Command {
    inner: tokio::process::Command,
}

#[cfg(any(test, feature = "server"))]
impl From<std::process::Command> for Command {
    fn from(command: std::process::Command) -> Self {
        Self {
            inner: command.into(),
        }
    }
}

impl Command {
    pub(crate) fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            inner: tokio::process::Command::new(program),
        }
    }

    pub(crate) fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }

    pub(crate) fn output(&mut self) -> io::Result<Output> {
        self.output_until(Instant::now() + DEADLINE)
    }

    pub(crate) fn output_until(&mut self, until: Instant) -> io::Result<Output> {
        let until = crate::operation_budget::limit(until);
        crate::operation_budget::check_until(until)?;
        #[cfg(test)]
        if let Some(action) = test_support::intercept(self.inner.as_std()) {
            return action.run();
        }
        self.output_before(until, OUTPUT_LIMIT, None)
    }

    #[cfg(test)]
    fn output_with_limits(&mut self, deadline: Duration, limit: usize) -> io::Result<Output> {
        self.output_before(Instant::now() + deadline, limit, None)
    }

    #[cfg(any(test, feature = "server"))]
    pub(crate) fn output_bounded(
        &mut self,
        until: Instant,
        limit: usize,
        input: Option<&[u8]>,
    ) -> io::Result<Output> {
        self.output_before(until, limit, input)
    }

    fn output_before(
        &mut self,
        until: Instant,
        limit: usize,
        input: Option<&[u8]>,
    ) -> io::Result<Output> {
        let until = crate::operation_budget::limit(until);
        crate::operation_budget::check_until(until)?;
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("qeli-system-command".to_string())
                .spawn_scoped(scope, || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(crate::hook_process::run_output_with_input(
                        &mut self.inner,
                        tokio::time::Instant::from_std(until),
                        limit,
                        input,
                    ))
                })?
                .join()
                .map_err(|_| io::Error::other("system command worker panicked"))?
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_support;
