//! Worker lifetime binding for the durable server firewall journal.
use super::cleanup_budget::Budget;
use crate::{
    nat_firewall_journal::{Backend, Session},
    nat_owned_rules::Rule,
};
use std::sync::{Mutex, OnceLock};

fn session() -> &'static Mutex<Option<Session>> {
    static SESSION: OnceLock<Mutex<Option<Session>>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(None))
}
pub(super) fn initialize(
    budget: Budget,
    mut remove: impl FnMut(&Rule) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut slot = budget.lock(session())?;
    anyhow::ensure!(
        slot.is_none(),
        "server firewall journal already initialized"
    );
    let mut owner = Session::open()?;
    owner.recover(budget.until, |rule, recorded| {
        anyhow::ensure!(current_backend(rule, budget)? == recorded, "iptables backend changed; exact recovery must use the original backend");
        remove(rule)
    }).map_err(|e| anyhow::anyhow!("server firewall recovery incomplete; keep server-firewall.state and retry in its original network namespace/state directory: {e:#}"))?;
    *slot = Some(owner);
    Ok(())
}
fn with_session<T>(
    budget: Budget,
    run: impl FnOnce(Option<&mut Session>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut slot = budget.lock(session())?;
    // Command-budget unit fixtures intentionally do not start a server worker or
    // touch real state. Native Session tests and the subprocess worker regression
    // exercise persistence. Production never permits uninitialized ownership.
    #[cfg(not(test))]
    anyhow::ensure!(slot.is_some(), "server firewall journal is not initialized");
    run(slot.as_mut())
}
pub(super) fn apply<T>(
    rule: &Rule,
    path: &str,
    budget: Budget,
    mutate: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    with_session(budget, |session| match session {
        Some(session) => session.apply(rule, backend(path, budget)?, budget.until, mutate),
        None => mutate(),
    })
}
pub(super) fn remove(
    rule: &Rule,
    budget: Budget,
    remove: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    with_session(budget, |session| match session {
        Some(session) => session.remove(rule, current_backend(rule, budget)?, budget.until, remove),
        None => remove(),
    })
}

fn current_backend(rule: &Rule, budget: Budget) -> anyhow::Result<Backend> {
    let path = budget
        .find(rule.ipv6)?
        .ok_or_else(|| anyhow::anyhow!("firewall tool unavailable; exact ownership retained"))?;
    backend(&path, budget)
}
fn backend(path: &str, budget: Budget) -> anyhow::Result<Backend> {
    let output = budget.output(crate::system_command::Command::new(path).args(["--version"]))?;
    anyhow::ensure!(
        output.status.success(),
        "cannot establish iptables backend identity"
    );
    Backend::parse(&output.stdout)
}
