//! One deadline for a named server firewall operation, including admission and both families.
use super::discovery::{self, Tool};
use std::{
    io,
    process::Output,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

const LIMIT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy)]
pub(super) struct Budget {
    pub(super) until: Instant,
    operation: &'static str,
}
impl Budget {
    pub(super) fn new() -> Self {
        Self::for_operation("NAT cleanup")
    }
    pub(super) fn for_operation(operation: &'static str) -> Self {
        Self {
            until: Instant::now() + LIMIT,
            operation,
        }
    }
    #[cfg(test)]
    pub(super) fn with_deadline(mut self, until: Instant) -> Self {
        self.until = until;
        self
    }
    fn remaining(self) -> io::Result<Duration> {
        self.until
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{} deadline expired; unresolved ownership retained for retry",
                        self.operation
                    ),
                )
            })
    }
    pub(super) fn check(self) -> io::Result<()> {
        self.remaining().map(|_| ())
    }
    pub(super) fn lock<T>(self, lock: &Mutex<T>) -> io::Result<MutexGuard<'_, T>> {
        loop {
            self.check()?;
            let acquired = match lock.try_lock() {
                Ok(guard) => Some(guard),
                Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(guard) = acquired {
                self.check()?;
                return Ok(guard);
            }
            std::thread::sleep(self.remaining()?.min(Duration::from_millis(10)));
        }
    }
    pub(super) fn checked<T>(self, run: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
        self.check()?;
        let value = run()?;
        self.check()?;
        Ok(value)
    }
    pub(super) fn output(self, command: &mut crate::system_command::Command) -> io::Result<Output> {
        self.check()?;
        let output = command.output_until(self.until);
        self.check()?;
        output
    }
    pub(super) fn ipt(self, path: &str, args: &[&str]) -> io::Result<Output> {
        self.output(
            crate::system_command::Command::new(path)
                .args(["--wait", super::XTABLES_LOCK_WAIT_SECS])
                .args(args),
        )
    }
    pub(super) fn find(self, ipv6: bool) -> io::Result<Option<String>> {
        self.check()?;
        #[cfg(test)]
        if let Some(paths) = PATHS.with(|slot| slot.borrow().clone()) {
            return Ok(paths[usize::from(ipv6)].clone());
        }
        let tool = if ipv6 { Tool::Ipv6 } else { Tool::Ipv4 };
        if let Some(path) = discovery::installed(tool) {
            self.check()?;
            return Ok(Some(path));
        }
        self.probe(if ipv6 { "ip6tables" } else { "iptables" })
    }
    pub(super) fn probe(self, name: &str) -> io::Result<Option<String>> {
        let output = self.output(crate::system_command::Command::new(name).args(["--version"]));
        // Preserve discovery's optional-tool policy, but never hide an exhausted budget.
        self.check()?;
        Ok(output
            .ok()
            .filter(|o| o.status.success())
            .map(|_| name.to_owned()))
    }
}

#[cfg(test)]
thread_local! { static PATHS: std::cell::RefCell<Option<[Option<String>; 2]>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
pub(super) fn with_paths<T>(paths: [Option<String>; 2], run: impl FnOnce() -> T) -> T {
    struct Reset(Option<[Option<String>; 2]>);
    impl Drop for Reset {
        fn drop(&mut self) {
            PATHS.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(PATHS.with(|slot| slot.replace(Some(paths))));
    run()
}
