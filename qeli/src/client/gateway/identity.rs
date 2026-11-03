//! Router authority is retained until both firewall and sysctl cleanup succeed.
//! A reservation pins the original namespace, never the TUN descriptor.
use super::Budget;
#[cfg(all(target_os = "linux", feature = "client"))]
use crate::client::route::RouteOwner;
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
use crate::client_route::RouteOwner;
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Clone)]
enum Owner {
    Managed(RouteOwner),
    #[cfg(test)]
    Test(std::sync::Arc<Mutex<test_support::Evidence>>),
}
static OWNERS: Mutex<BTreeMap<String, Owner>> = Mutex::new(BTreeMap::new());

pub(super) fn bind(owner: &RouteOwner) -> anyhow::Result<()> {
    let budget = Budget::new();
    let _operation = super::router_operation(budget)?;
    owner.verify_router_plan()?;
    budget.check()?;
    let mut owners = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(previous) = owners.get(owner.interface()) {
        anyhow::ensure!(
            matches!(previous, Owner::Managed(previous) if previous.same_owner(owner)),
            "router ownership for {} is still reserved by another generation",
            owner.interface()
        );
    } else {
        owners.insert(owner.interface().to_string(), Owner::Managed(owner.clone()));
    }
    Ok(())
}

pub(super) fn matches(owner: &RouteOwner) -> anyhow::Result<bool> {
    let owners = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(previous) = owners.get(owner.interface()) else {
        return Ok(false);
    };
    anyhow::ensure!(
        matches!(previous, Owner::Managed(previous) if previous.same_owner(owner)),
        "refusing router cleanup from a different generation"
    );
    Ok(true)
}

fn lookup(name: &str) -> Option<Owner> {
    #[cfg(test)]
    test_support::admit_fixture(name);
    OWNERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(name)
        .cloned()
}
pub(super) fn forget(name: &str) {
    // Caller holds ROUTER_OPERATION; never drop the route lease under OWNERS.
    let owner = OWNERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(name);
    drop(owner);
}

pub(super) struct Context {
    owner: Owner,
    cleanup: bool,
    budget: Budget,
}
impl Context {
    pub(super) fn forward(name: &str, budget: Budget) -> anyhow::Result<Self> {
        let owner = lookup(name)
            .ok_or_else(|| anyhow::anyhow!("router {name} has no bound NetworkPlan owner"))?;
        let context = Self {
            owner,
            cleanup: false,
            budget,
        };
        context.check(true)?;
        Ok(context)
    }
    pub(super) fn cleanup(name: &str, budget: Budget) -> anyhow::Result<Option<Self>> {
        let Some(owner) = lookup(name) else {
            return Ok(None);
        };
        match &owner {
            Owner::Managed(owner) => owner.stop_admission(),
            #[cfg(test)]
            Owner::Test(evidence) => evidence.lock().unwrap().failed = true,
        }
        let context = Self {
            owner,
            cleanup: true,
            budget,
        };
        context.check(false)?;
        Ok(Some(context))
    }
    fn check(&self, needs_tunnel: bool) -> anyhow::Result<()> {
        self.budget.check()?;
        let result = match &self.owner {
            Owner::Managed(owner) if self.cleanup => owner.verify_cleanup_identity(needs_tunnel),
            Owner::Managed(owner) => owner.verify_router_plan(),
            #[cfg(test)]
            Owner::Test(evidence) => {
                let mut evidence = evidence.lock().unwrap();
                let valid = evidence.namespace && (!needs_tunnel || evidence.tunnel);
                if !self.cleanup && !valid {
                    evidence.failed = true;
                }
                anyhow::ensure!(
                    valid && (self.cleanup || !evidence.failed),
                    "router fixture identity lost"
                );
                Ok(())
            }
        };
        self.budget.check()?;
        result
    }
    pub(super) fn finish(&self) -> anyhow::Result<()> {
        self.check(!self.cleanup)
    }
    fn checked<T>(
        &self,
        needs_tunnel: bool,
        action: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.check(needs_tunnel)?;
        let result = action();
        self.check(needs_tunnel)?;
        result
    }
    pub(super) fn ipt(&self, path: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
        self.checked(!self.cleanup, || {
            crate::system_command::Command::new(path)
                .args(args)
                .output_until(self.budget.until)
                .map_err(Into::into)
        })
        .map_err(std::io::Error::other)
    }
    pub(super) fn present(&self, path: &str, args: &[&str]) -> anyhow::Result<bool> {
        self.checked(!self.cleanup, || {
            let output = self.ipt(path, args)?;
            crate::firewall_check::present(
                &output,
                crate::firewall_check::Query::Rule {
                    missing_target: super::expected_qeli_chain(args),
                },
            )
            .map_err(|error| anyhow::anyhow!("{path} {}: {error}", args.join(" ")))
        })
    }
    pub(super) fn path(&self, binary: &str) -> anyhow::Result<Option<String>> {
        self.checked(!self.cleanup, || {
            Ok(super::ipt_path_with(binary, |path| {
                self.ipt(path, &["--version"])
            }))
        })
    }
    pub(super) fn acquire(&self, path: &str, value: &str, scope: &str) -> bool {
        let result = self.checked(true, || {
            anyhow::ensure!(
                super::host::acquire(path, value, scope),
                "cannot acquire {path}"
            );
            Ok(())
        });
        if let Err(error) = result {
            log::warn!("router sysctl acquisition failed: {error}");
            false
        } else {
            true
        }
    }
    pub(super) fn read(&self, path: &str) -> std::io::Result<String> {
        self.checked(true, || super::host::read(path).map_err(Into::into))
            .map_err(std::io::Error::other)
    }
    pub(super) fn release(&self, scope: &str) -> anyhow::Result<()> {
        // The shared journal also contains per-interface knobs. Without the original
        // TUN, retain the entire scope rather than restoring a replacement by name.
        self.checked(true, || super::host::release(scope))
    }
    pub(super) fn ip(&self, args: &[&str]) -> std::io::Result<std::process::Output> {
        self.checked(true, || {
            crate::system_command::Command::new("ip")
                .args(args)
                .output_until(self.budget.until)
                .map_err(Into::into)
        })
        .map_err(std::io::Error::other)
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;
    use std::{cell::Cell, sync::Arc};
    thread_local! { static FIXTURE: Cell<bool> = const { Cell::new(false) }; }
    pub(in super::super) struct Evidence {
        pub namespace: bool,
        pub tunnel: bool,
        pub failed: bool,
    }
    pub(super) fn admit_fixture(name: &str) {
        if !FIXTURE.with(Cell::get) {
            return;
        }
        OWNERS
            .lock()
            .unwrap()
            .entry(name.into())
            .or_insert_with(|| {
                Owner::Test(Arc::new(Mutex::new(Evidence {
                    namespace: true,
                    tunnel: true,
                    failed: false,
                })))
            });
    }
    pub(in super::super) fn evidence(name: &str) -> Arc<Mutex<Evidence>> {
        admit_fixture(name);
        match OWNERS.lock().unwrap().get(name).unwrap() {
            Owner::Test(evidence) => evidence.clone(),
            _ => panic!("expected fixture evidence"),
        }
    }
    pub(in super::super) fn with_owners<T>(test: impl FnOnce() -> T) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                FIXTURE.with(|flag| flag.set(false));
                OWNERS.lock().unwrap().clear();
            }
        }
        FIXTURE.with(|flag| assert!(!flag.replace(true)));
        let _reset = Reset;
        test()
    }
}
