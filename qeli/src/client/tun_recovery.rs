//! Non-destructive admission before creating or borrowing a Linux TUN/TAP.
use std::{io, time::Duration};
const WAIT_STEPS: usize = 120;
const WAIT_STEP: Duration = Duration::from_millis(50);
trait Host {
    fn index(&mut self, name: &str) -> io::Result<Option<u32>>;
    fn pause(&mut self, duration: Duration);
}

fn inspect(host: &mut impl Host, name: &str) -> anyhow::Result<Option<u32>> {
    host.index(name).map_err(|error| {
        anyhow::anyhow!("cannot inspect interface '{name}' before TUN setup: {error}")
    })
}

fn prepare_with(host: &mut impl Host, name: &str, attach: bool) -> anyhow::Result<()> {
    let observed = inspect(host, name)?;
    if attach {
        if observed.is_none() {
            anyhow::bail!("dev_attach is set but interface '{name}' does not exist yet — waiting for its owner to create it (the reconnect loop will retry)");
        }
        return Ok(());
    }
    let Some(original) = observed else {
        return Ok(());
    };
    // An observed fd held by our PID does not establish exclusive ownership. Procfs
    // can hide other holders, and another component may have lent us the descriptor.
    // There is deliberately no delete, detach or persistence-changing operation here.
    log::warn!("interface '{name}' already exists — waiting for its owner to release it; automatic deletion is disabled");
    for _ in 0..WAIT_STEPS {
        host.pause(WAIT_STEP);
        match inspect(host, name)? {
            None => return Ok(()),
            Some(index) if index == original => {},
            Some(_) => anyhow::bail!("interface '{name}' was replaced while waiting for release — refusing to use the replacement; choose a different dev or explicit dev_attach"),
        }
    }
    anyhow::bail!("interface '{name}' is still present after waiting for release — refusing to delete or attach; stop its owner, choose a different dev, or use explicit dev_attach");
}

#[cfg(all(target_os = "linux", feature = "client"))]
pub(super) fn prepare(name: &str, attach: bool) -> anyhow::Result<()> {
    struct System;
    impl Host for System {
        fn index(&mut self, name: &str) -> io::Result<Option<u32>> {
            crate::tun::open::interface_index(name)
        }
        fn pause(&mut self, duration: Duration) {
            std::thread::sleep(duration);
        }
    }
    prepare_with(&mut System, name, attach)
}

#[cfg(test)]
#[path = "tun_recovery_tests.rs"]
mod tests;
