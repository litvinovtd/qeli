//! Native I/O boundary. The caller holds the worker network reservation and firewall mutex.
use super::{Backend, Store, LIMIT};
use crate::{
    nat_owned_rules::Rule,
    network_namespace::Namespace,
    state_storage::{journal_file::Opened, state_dir::Directory},
};
use std::{path::Path, time::Instant};

pub(crate) struct Session {
    directory: Directory,
    namespace: Namespace,
    boot: String,
    cookie: u64,
    valid: bool,
}
impl Session {
    pub(crate) fn open() -> anyhow::Result<Self> {
        Self::at(&crate::state_storage::default_state_dir())
    }
    fn at(path: &Path) -> anyhow::Result<Self> {
        let namespace = Namespace::capture()?;
        let cookie = crate::network_namespace::cookie()?
            .ok_or_else(|| anyhow::anyhow!("server firewall journal requires SO_NETNS_COOKIE"))?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_string();
        Store::new(&boot).encode()?;
        let mut session = Self {
            directory: Directory::open(path)?,
            namespace,
            boot,
            cookie,
            valid: true,
        };
        session.verify()?;
        Ok(session)
    }
    fn verify(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(self.valid, "server firewall journal context was lost");
        if let Err(error) = self
            .namespace
            .verify()
            .and_then(|()| self.directory.verify())
        {
            self.valid = false;
            return Err(error);
        }
        Ok(())
    }
    fn transaction<T>(
        &mut self,
        until: Instant,
        body: impl FnOnce(&mut Self, &Path, &mut Store) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.verify()?;
        let path = self.directory.journal_path("server-firewall.state")?;
        let left = until
            .checked_duration_since(Instant::now())
            .filter(|x| !x.is_zero())
            .ok_or_else(|| anyhow::anyhow!("server firewall journal deadline expired"))?;
        let _lock =
            crate::util::FileLock::acquire_timeout_owned(&path, left, self.directory.owner())?;
        self.verify()?;
        let mut store = match Opened::open(&path, LIMIT)? {
            Some(file) => Store::decode(&file.read()?, &self.boot)?,
            None => Store::new(&self.boot),
        };
        anyhow::ensure!(
            Instant::now() < until,
            "server firewall journal deadline expired"
        );
        let result = body(self, &path, &mut store);
        self.verify()?;
        anyhow::ensure!(
            Instant::now() < until,
            "server firewall journal deadline expired; exact ownership retained"
        );
        result
    }
    fn persist(&mut self, path: &Path, store: &Store) -> anyhow::Result<()> {
        self.verify()?;
        // Keep the empty envelope: file and parent fsync cover both retention and release.
        // Never unlink the stable .lock sidecar, including when this namespace becomes empty.
        crate::util::write_atomic_private(path, &store.encode()?)?;
        self.verify()
    }
    pub(crate) fn apply<T>(
        &mut self,
        rule: &Rule,
        backend: Backend,
        until: Instant,
        mutate: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.transaction(until, |s, path, store| {
            store.retain(s.cookie, rule.clone(), backend)?;
            s.persist(path, store)?;
            anyhow::ensure!(
                Instant::now() < until,
                "server firewall journal deadline expired before mutation"
            );
            let result = mutate();
            s.verify()?;
            result
        })
    }
    pub(crate) fn remove(
        &mut self,
        rule: &Rule,
        backend: Backend,
        until: Instant,
        remove: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.transaction(until, |s, path, store| {
            anyhow::ensure!(
                store
                    .backend(s.cookie, rule.ipv6)
                    .is_none_or(|b| b == backend),
                "iptables backend changed; exact recovery must use the original backend"
            );
            remove()?;
            s.verify()?;
            store.forget(s.cookie, rule);
            s.persist(path, store)
        })
    }
    pub(crate) fn recover(
        &mut self,
        until: Instant,
        mut remove: impl FnMut(&Rule, Backend) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.transaction(until, |s, path, store| {
            let mut errors = crate::nat_cleanup::Errors::default();
            for rule in store.rules(s.cookie) {
                s.verify()?;
                anyhow::ensure!(
                    Instant::now() < until,
                    "server firewall recovery deadline expired"
                );
                let backend = store
                    .backend(s.cookie, rule.ipv6)
                    .ok_or_else(|| anyhow::anyhow!("missing firewall backend"))?;
                match remove(&rule, backend) {
                    Ok(()) => {
                        s.verify()?;
                        store.forget(s.cookie, &rule);
                        // A later failed rule cannot erase successful siblings or forget a failed one.
                        s.persist(path, store)?;
                    }
                    Err(error) => errors.record("exact server firewall recovery", Err(error)),
                }
            }
            // Also record the current boot when no rules remain to recover.
            s.persist(path, store)?;
            errors.finish()
        })
    }
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
