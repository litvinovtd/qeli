//! All file access is anchored to a trusted directory. A stable lock spans each whole
//! route operation, including checks, borrowing, mutations and rollback across clients.
use super::super::{budget, ownership, route_command_output};
use super::{Change, Store, LIMIT};
use crate::{
    network_namespace::Namespace,
    state_storage::{journal_file::Opened, state_dir::Directory},
};
use std::{
    os::linux::net::SocketAddrExt,
    os::unix::net::{SocketAddr, UnixDatagram},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

pub(crate) struct Session {
    directory: Directory,
    namespace: Namespace,
    boot: String,
    cookie: u64,
    interface: String,
    valid: AtomicBool,
    active: Mutex<Option<Store>>,
    _claim: UnixDatagram,
}
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteSession")
            .field("interface", &self.interface)
            .field("cookie", &self.cookie)
            .finish_non_exhaustive()
    }
}
pub(crate) struct Guard {
    session: Arc<Session>,
    _lock: crate::util::FileLock,
}
impl Drop for Guard {
    fn drop(&mut self) {
        *self
            .session
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }
}
impl Session {
    pub(crate) fn open(interface: &str) -> anyhow::Result<Arc<Self>> {
        Self::at(&crate::state_storage::default_state_dir(), interface)
    }
    pub(crate) fn at(path: &Path, interface: &str) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            super::valid_interface(interface),
            "invalid route journal interface"
        );
        let namespace = Namespace::capture()?;
        let cookie = crate::network_namespace::cookie()?
            .ok_or_else(|| anyhow::anyhow!("client route recovery requires SO_NETNS_COOKIE"))?;
        let name = format!("qeli.client.routes:{interface}");
        let claim = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes())?)
            .map_err(|e| {
                anyhow::anyhow!("client route owner for {interface} is still live: {e}")
            })?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        Store::new(&boot).encode()?;
        let result = Arc::new(Self {
            directory: Directory::open(path)?,
            namespace,
            boot,
            cookie,
            interface: interface.into(),
            valid: AtomicBool::new(true),
            active: Mutex::new(None),
            _claim: claim,
        });
        result.verify()?;
        Ok(result)
    }
    pub(crate) fn verify(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.valid.load(Ordering::Relaxed),
            "client route journal context was lost"
        );
        if let Err(error) = self
            .namespace
            .verify()
            .and_then(|()| self.directory.verify())
        {
            self.valid.store(false, Ordering::Relaxed);
            return Err(error);
        }
        budget::check()?;
        Ok(())
    }
    pub(crate) fn begin(self: &Arc<Self>) -> anyhow::Result<Guard> {
        self.verify()?;
        let path = self.directory.journal_path("client-routes.state")?;
        let left = budget::deadline()
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| anyhow::anyhow!("client route lock deadline expired"))?;
        let lock =
            crate::util::FileLock::acquire_timeout_owned(&path, left, self.directory.owner())?;
        self.verify()?;
        let store = match Opened::open(&path, LIMIT)? {
            Some(file) => Store::decode(&file.read()?, &self.boot)?,
            None => Store::new(&self.boot),
        };
        self.verify()?;
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        anyhow::ensure!(active.is_none(), "nested client route journal operation");
        *active = Some(store);
        Ok(Guard {
            session: self.clone(),
            _lock: lock,
        })
    }
    fn read<T>(&self, body: impl FnOnce(&Store) -> anyhow::Result<T>) -> anyhow::Result<T> {
        self.verify()?;
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let store = active
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("route journal operation not locked"))?;
        let result = body(store);
        self.verify()?;
        result
    }
    fn edit(&self, body: impl FnOnce(&mut Store) -> anyhow::Result<()>) -> anyhow::Result<()> {
        self.verify()?;
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let store = active
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("route journal operation not locked"))?;
        let mut proposed = store.clone();
        body(&mut proposed)?;
        let bytes = proposed.encode()?;
        self.verify()?;
        crate::util::write_atomic_private(
            self.directory.journal_path("client-routes.state")?,
            &bytes,
        )?;
        *store = proposed;
        self.verify()
    }
    pub(crate) fn check_unclaimed(&self, spec: &[String]) -> anyhow::Result<()> {
        self.read(|s| s.check_unclaimed(self.cookie, &self.interface, spec))
    }
    pub(crate) fn change(&self, spec: &[String], change: Change) -> anyhow::Result<()> {
        if super::is_tunnel(spec, &self.interface) {
            return Ok(());
        }
        self.edit(|s| s.change(self.cookie, &self.interface, spec, change))
    }
    pub(crate) fn before_command(&self, args: &[String]) -> anyhow::Result<()> {
        self.verify()?;
        let offset = usize::from(args.first().is_some_and(|s| s == "-6"));
        if args.get(offset).is_some_and(|s| s == "route")
            && args
                .get(offset + 1)
                .is_some_and(|s| matches!(s.as_str(), "add" | "replace"))
        {
            self.change(&ownership::delete_spec(args), Change::Intent)?;
        }
        self.verify()
    }
    pub(crate) fn reconcile(&self) -> anyhow::Result<()> {
        let records = self.read(|s| Ok(s.records(self.cookie, &self.interface, true)))?;
        let mut errors = Vec::new();
        for spec in records {
            match ownership::recorded_route_with(&spec, &|args| {
                self.verify().map_err(std::io::Error::other)?;
                route_command_output(args)
            }) {
                Ok(None) => self.change(&spec, Change::ForgetPending)?,
                Ok(Some(_)) => errors.push(format!(
                    "unresolved physical route intent without delete authority: ip {}",
                    spec.join(" ")
                )),
                Err(error) => errors.push(error.to_string()),
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "client route recovery incomplete: {}",
            errors.join("; ")
        );
        Ok(())
    }
    pub(crate) fn recover(&self) -> anyhow::Result<()> {
        let records = self.read(|s| Ok(s.records(self.cookie, &self.interface, false)))?;
        let pending = self.read(|s| Ok(s.records(self.cookie, &self.interface, true)))?;
        if !records.is_empty() || !pending.is_empty() {
            self.verify_absent_tun()?;
        }
        let mut errors = Vec::new();
        for spec in records {
            match ownership::remove_recorded_route_with(&spec, &|args| {
                self.verify_absent_tun().map_err(std::io::Error::other)?;
                route_command_output(args)
            }) {
                Ok(removed) => {
                    if !removed {
                        log::info!(
                            "recovery preserves changed physical route: ip {}",
                            spec.join(" ")
                        );
                    }
                    self.change(&spec, Change::ForgetOwned)?;
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        if let Err(error) = self.reconcile() {
            errors.push(error.to_string());
        }
        // Retain an empty synced envelope and stable lock, including after a reboot.
        self.edit(|_| Ok(()))?;
        anyhow::ensure!(
            errors.is_empty(),
            "client route recovery incomplete: {}",
            errors.join("; ")
        );
        Ok(())
    }
    fn verify_absent_tun(&self) -> anyhow::Result<()> {
        self.verify()?;
        anyhow::ensure!(crate::tun::open::interface_index(&self.interface)?.is_none(),
            "client route recovery refuses a live or persistent TUN {}; stop its owner and inspect the journal", self.interface);
        Ok(())
    }
}
#[cfg(test)]
#[path = "native/tests.rs"]
mod tests;
