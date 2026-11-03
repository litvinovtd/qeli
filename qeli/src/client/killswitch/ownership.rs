//! A kill switch predates its TUN and survives reconnects. Pin its namespace
//! independently of route/TUN owners, retaining evidence until verified cleanup.
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone)]
enum Namespace {
    #[cfg(target_os = "linux")]
    Live(Arc<crate::network_namespace::Namespace>),
    #[cfg(test)]
    Fixture {
        original: u64,
        current: Arc<std::sync::atomic::AtomicU64>,
    },
}
impl Namespace {
    fn capture() -> anyhow::Result<Self> {
        #[cfg(test)]
        if let Some(current) = test_support::current() {
            return Ok(Self::Fixture {
                original: current.load(Ordering::SeqCst),
                current,
            });
        }
        #[cfg(target_os = "linux")]
        return Ok(Self::Live(Arc::new(
            crate::network_namespace::Namespace::capture()?,
        )));
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("kill-switch requires a Linux namespace or an explicit test fixture")
    }
    fn verify(&self) -> anyhow::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Live(namespace) => namespace.verify(),
            #[cfg(test)]
            Self::Fixture { original, current } => {
                anyhow::ensure!(
                    *original == current.load(Ordering::SeqCst),
                    "kill-switch network namespace changed"
                );
                Ok(())
            }
        }
    }
}
#[derive(Clone)]
pub(super) struct Family {
    pub(super) path: String,
    pub(super) protected: bool,
    pub(super) guard_forward: bool,
}
struct Owner {
    namespace: Namespace,
    failed: AtomicBool,
    // Remember the actual tool before mutation. Cleanup must not silently skip a
    // formerly programmed family because rediscovery now reports it unavailable.
    paths: Mutex<BTreeMap<bool, Family>>,
}
static OWNERS: Mutex<BTreeMap<String, Arc<Owner>>> = Mutex::new(BTreeMap::new());
const MAX_OWNERS: usize = 256;

#[derive(Clone)]
pub(super) struct Context {
    owner: Arc<Owner>,
    cleanup: bool,
    budget: Option<super::Budget>,
}
impl Context {
    // Capture before resolution/operation-lock waits. The caller serializes all
    // subsequent registry admission/mutation with OPERATION.
    pub(super) fn prepare(name: &str) -> anyhow::Result<Self> {
        let previous = OWNERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned();
        let owner = match previous {
            Some(owner) => owner,
            None => Arc::new(Owner {
                namespace: Namespace::capture()?,
                failed: AtomicBool::new(false),
                paths: Mutex::new(BTreeMap::new()),
            }),
        };
        let context = Self {
            owner,
            cleanup: false,
            budget: None,
        };
        context.check()?;
        Ok(context)
    }
    pub(super) fn bind(&self, name: &str) -> anyhow::Result<()> {
        self.check()?;
        let mut owners = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(previous) = owners.get(name) {
            anyhow::ensure!(
                Arc::ptr_eq(previous, &self.owner),
                "kill-switch owner changed while waiting; retry required"
            );
        } else {
            anyhow::ensure!(
                owners.len() < MAX_OWNERS,
                "kill-switch owner registry full; unresolved cleanup retained"
            );
            owners.insert(name.to_owned(), self.owner.clone());
        }
        Ok(())
    }
    pub(super) fn lookup(name: &str, cleanup: bool) -> anyhow::Result<Option<Self>> {
        let owner = OWNERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned();
        owner
            .map(|owner| {
                let context = Self {
                    owner,
                    cleanup,
                    budget: None,
                };
                context.check()?;
                Ok(context)
            })
            .transpose()
    }
    pub(super) fn with_budget(mut self, budget: super::Budget) -> Self {
        self.budget = Some(budget);
        self
    }
    pub(super) fn check_budget(&self) -> std::io::Result<()> {
        if let Some(budget) = self.budget {
            budget.remaining()?;
        }
        Ok(())
    }
    pub(super) fn check(&self) -> anyhow::Result<()> {
        if let Err(error) = self.owner.namespace.verify() {
            self.owner.failed.store(true, Ordering::Release);
            return Err(error
                .context("kill-switch namespace identity lost; protection retained for recovery"));
        }
        anyhow::ensure!(
            self.cleanup || !self.owner.failed.load(Ordering::Acquire),
            "kill-switch namespace identity was lost; cleanup is required before a new engage"
        );
        Ok(())
    }
    pub(super) fn remember(&self, ipv6: bool, path: &str) -> anyhow::Result<()> {
        self.check()?;
        let mut paths = self.owner.paths.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(previous) = paths.get(&ipv6) {
            anyhow::ensure!(
                previous.path == path,
                "kill-switch firewall tool changed before cleanup"
            );
        } else {
            paths.insert(
                ipv6,
                Family {
                    path: path.to_owned(),
                    protected: false,
                    guard_forward: false,
                },
            );
        }
        Ok(())
    }
    pub(super) fn protected(&self, ipv6: bool, protected: bool, guard_forward: bool) {
        if let Some(family) = self
            .owner
            .paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&ipv6)
        {
            family.protected = protected;
            family.guard_forward = guard_forward;
        }
    }
    pub(super) fn paths(&self) -> Vec<(bool, Family)> {
        self.owner
            .paths
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(family, path)| (*family, path.clone()))
            .collect()
    }
    pub(super) fn confirm(&self, name: &str) -> anyhow::Result<()> {
        self.check()?;
        let owners = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
        anyhow::ensure!(
            owners
                .get(name)
                .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner)),
            "kill-switch owner changed while resolving/waiting"
        );
        Ok(())
    }
    pub(super) fn forget(&self, name: &str) -> anyhow::Result<()> {
        self.check()?;
        let mut owners = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
        anyhow::ensure!(
            owners
                .get(name)
                .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner)),
            "kill-switch owner changed before cleanup completed"
        );
        self.check_budget()?;
        owners.remove(name);
        Ok(())
    }
    pub(super) fn ipt(&self, path: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
        self.check().map_err(std::io::Error::other)?;
        self.check_budget()?;
        let result = match self.budget {
            Some(budget) => crate::system_command::Command::new(path)
                .args(args)
                .output_until(budget.until),
            None => super::ipt(path, args),
        };
        self.check().map_err(std::io::Error::other)?;
        self.check_budget()?;
        result
    }
    pub(super) fn present_checked(&self, path: &str, args: &[&str]) -> anyhow::Result<bool> {
        let output = self.ipt(path, args)?;
        super::checked_presence(
            &output,
            super::Query::Rule {
                missing_target: super::expected_qeli_chain(args),
            },
        )
        .map_err(|error| anyhow::anyhow!("{path} {}: {error}", args.join(" ")))
    }
    pub(super) fn present(&self, path: &str, args: &[&str]) -> bool {
        self.ipt(path, args)
            .is_ok_and(|output| output.status.success())
    }
    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self {
            owner: Arc::new(Owner {
                namespace: Namespace::Fixture {
                    original: 1,
                    current: Arc::new(std::sync::atomic::AtomicU64::new(1)),
                },
                failed: AtomicBool::new(false),
                paths: Mutex::new(BTreeMap::new()),
            }),
            cleanup: false,
            budget: None,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::{cell::RefCell, sync::atomic::AtomicU64};
    thread_local! { static CURRENT: RefCell<Option<Arc<AtomicU64>>> = const { RefCell::new(None) }; }
    thread_local! { static PATHS: RefCell<Option<[Option<String>; 2]>> = const { RefCell::new(None) }; }
    pub(crate) fn path(bin: &str) -> Option<Option<String>> {
        PATHS.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|paths| paths[usize::from(bin == "ip6tables")].clone())
        })
    }
    pub(crate) fn with_paths<T>(paths: [Option<String>; 2], action: impl FnOnce() -> T) -> T {
        struct Reset(Option<[Option<String>; 2]>);
        impl Drop for Reset {
            fn drop(&mut self) {
                PATHS.with(|slot| *slot.borrow_mut() = self.0.take());
            }
        }
        let _reset = Reset(PATHS.with(|slot| slot.replace(Some(paths))));
        action()
    }
    pub(super) fn current() -> Option<Arc<AtomicU64>> {
        CURRENT.with(|slot| slot.borrow().clone())
    }
    pub(crate) fn with_namespace<T>(current: Arc<AtomicU64>, action: impl FnOnce() -> T) -> T {
        struct Reset(Option<Arc<AtomicU64>>);
        impl Drop for Reset {
            fn drop(&mut self) {
                CURRENT.with(|slot| *slot.borrow_mut() = self.0.take());
            }
        }
        let _reset = Reset(CURRENT.with(|slot| slot.replace(Some(current))));
        action()
    }
    pub(crate) fn set_namespace(value: u64) {
        current()
            .expect("explicit namespace fixture")
            .store(value, Ordering::SeqCst);
    }
    pub(crate) fn clear() {
        OWNERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, owner| !matches!(&owner.namespace, Namespace::Fixture { .. }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_namespace_is_rechecked_after_wait_before_binding() {
        test_support::with_namespace(Arc::new(std::sync::atomic::AtomicU64::new(1)), || {
            let context = Context::prepare("ks_wait_test").unwrap();
            test_support::set_namespace(2);
            assert!(context.bind("ks_wait_test").is_err());
            assert!(Context::lookup("ks_wait_test", true).unwrap().is_none());
        });
    }
}
