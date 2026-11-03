//! Cooperative lifetime reservations for Linux clients in one network namespace.
//! The TUN claim applies to every profile; the policy claim additionally excludes
//! incompatible kill-switches. Both survive reconnects and terminal cleanup.
//! Linux abstract AF_UNIX bind provides atomic exclusion and crash release without
//! lockfiles/PID inference. No messages are sent. Sockets are close-on-exec.
//! Old binaries, servers and administrator tools do not participate; kernel TUN
//! admission and firewall inventory checks are still required.
use std::io;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::unix::net::{SocketAddr, UnixDatagram};

// Preserve the existing policy claim across upgrades.
const NAME: &[u8] = b"qeli.client.kill-switch";
const TUN_PREFIX: &str = "qeli.client.tun:";

#[derive(Debug)]
pub(crate) struct Lease<T> {
    _tun: T,
    _kill_switch: Option<T>,
}

#[cfg(target_os = "linux")]
pub(crate) fn acquire(tun: &str, kill_switch: bool) -> anyhow::Result<Lease<UnixDatagram>> {
    claim_with(tun, kill_switch, bind)
}

// Caller supplies the validated configured interface name. Exact bytes are part of
// the claim, so different TUNs remain independent even with the same state directory.
fn claim_with<T>(
    tun: &str,
    kill_switch: bool,
    mut bind: impl FnMut(&[u8]) -> io::Result<T>,
) -> anyhow::Result<Lease<T>> {
    let name = format!("{TUN_PREFIX}{tun}");
    let tun_owner = bind(name.as_bytes()).map_err(|error| {
        anyhow::anyhow!("client: cannot reserve TUN {tun:?} in this network namespace: {error}. Another Qeli client may own it; stop that client or choose a distinct dev")
    })?;
    let policy_owner = if kill_switch {
        Some(bind(NAME).map_err(|error| {
            anyhow::anyhow!("kill-switch: cannot exclusively own this network namespace: {error}. Another protected Qeli client may be active; stop it or use a separate network namespace")
        })?)
    } else {
        None
    };
    // On a failed policy claim, tun_owner drops without releasing anyone else's
    // claim. Neither DNS recovery nor firewall/interface setup has started yet.
    Ok(Lease {
        _tun: tun_owner,
        _kill_switch: policy_owner,
    })
}

#[cfg(target_os = "linux")]
fn bind(name: &[u8]) -> io::Result<UnixDatagram> {
    UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name)?)
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn name() -> Vec<u8> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        format!(
            "qeli-test-lease-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .into_bytes()
    }

    #[test]
    fn live_owner_blocks_reentry_and_drop_allows_recovery() {
        let name = name();
        let owner = bind(&name).unwrap();
        assert_eq!(bind(&name).unwrap_err().kind(), io::ErrorKind::AddrInUse);
        drop(owner);
        let _replacement = bind(&name).unwrap();
    }

    #[test]
    fn independent_names_do_not_block_each_other() {
        let _first = bind(&name()).unwrap();
        let _second = bind(&name()).unwrap();
    }

    #[test]
    fn concurrent_claims_admit_exactly_one_owner() {
        let name = name();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let children: Vec<_> = (0..2)
            .map(|_| {
                let name = name.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    bind(&name)
                })
            })
            .collect();
        // Keep the winner's descriptor live until both attempts have completed.
        let owners: Vec<_> = children
            .into_iter()
            .map(|child| child.join().unwrap())
            .collect();
        assert_eq!(owners.iter().filter(|owner| owner.is_ok()).count(), 1);
        assert_eq!(
            owners
                .iter()
                .filter(|owner| owner
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::AddrInUse))
                .count(),
            1
        );
    }

    #[test]
    fn unwinding_releases_lease_without_network_cleanup() {
        let name = name();
        let failure = std::panic::catch_unwind(|| {
            let _owner = bind(&name).unwrap();
            panic!("simulated client failure");
        });
        assert!(failure.is_err());
        let _replacement = bind(&name).unwrap();
    }

    #[test]
    fn descriptor_is_close_on_exec() {
        use std::os::fd::AsRawFd;
        let owner = bind(&name()).unwrap();
        // SAFETY: the borrowed descriptor is live; F_GETFD has no extra argument.
        let flags = unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    // A child fixture, never an ordinary test (it terminates its own test process).
    #[test]
    #[ignore]
    fn lease_child() {
        let name = std::env::var("QELI_TEST_LEASE_NAME").unwrap();
        let _owner = bind(name.as_bytes());
        std::process::exit(if _owner.is_ok() { 0 } else { 7 });
    }

    fn child(name: &[u8]) -> std::process::ExitStatus {
        let test = format!(
            "{}::lease_child",
            module_path!().split_once("::").unwrap().1
        );
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--ignored", "--nocapture"])
            .env("QELI_TEST_LEASE_NAME", std::str::from_utf8(name).unwrap())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("lease child timed out");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn another_process_is_excluded_and_process_exit_releases_lease() {
        let name = name();
        let owner = bind(&name).unwrap();
        assert_eq!(child(&name).code(), Some(7));
        drop(owner);
        assert_eq!(child(&name).code(), Some(0));
        let _replacement = bind(&name).unwrap();
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

    #[derive(Clone, Default)]
    struct Registry(Rc<RefCell<BTreeSet<Vec<u8>>>>);
    struct Owner {
        name: Vec<u8>,
        registry: Registry,
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            assert!(self.registry.0.borrow_mut().remove(&self.name));
        }
    }
    impl Registry {
        fn bind(&self, name: &[u8]) -> io::Result<Owner> {
            if !self.0.borrow_mut().insert(name.to_vec()) {
                return Err(io::ErrorKind::AddrInUse.into());
            }
            Ok(Owner {
                name: name.into(),
                registry: self.clone(),
            })
        }
        fn claim(&self, tun: &str, protected: bool) -> anyhow::Result<Lease<Owner>> {
            claim_with(tun, protected, |name| self.bind(name))
        }
        fn names(&self) -> BTreeSet<Vec<u8>> {
            self.0.borrow().clone()
        }
    }

    #[test]
    fn duplicate_tun_is_excluded_for_all_protection_combinations() {
        for first in [false, true] {
            for second in [false, true] {
                let registry = Registry::default();
                let owner = registry.claim("vpn0", first).unwrap();
                let before = registry.names();
                assert!(registry.claim("vpn0", second).is_err());
                assert_eq!(registry.names(), before);
                drop(owner);
                let _replacement = registry.claim("vpn0", second).unwrap();
            }
        }
    }
    #[test]
    fn distinct_unprotected_tuns_remain_independent() {
        let registry = Registry::default();
        let first = registry.claim("vpn0", false).unwrap();
        let second = registry.claim("vpn1", false).unwrap();
        assert_eq!(registry.names().len(), 2);
        drop(first);
        assert!(registry.claim("vpn1", false).is_err());
        drop(second);
        assert!(registry.names().is_empty());
    }
    #[test]
    fn a_protected_tun_does_not_exclude_a_distinct_unprotected_tun() {
        let registry = Registry::default();
        let _first = registry.claim("vpn0", true).unwrap();
        let _second = registry.claim("vpn1", false).unwrap();
        assert_eq!(registry.names().len(), 3);
        assert!(registry.names().contains(NAME));
    }
    #[test]
    fn failed_second_policy_claim_releases_only_its_tun_reservation() {
        let registry = Registry::default();
        let _first = registry.claim("vpn0", true).unwrap();
        let before = registry.names();
        assert!(registry.claim("vpn1", true).is_err());
        assert_eq!(registry.names(), before);
        let _second = registry.claim("vpn1", false).unwrap();
        assert!(registry.claim("vpn0", false).is_err());
    }
    #[test]
    fn failed_tun_claim_never_attempts_policy_claim() {
        let mut calls = 0;
        let result = claim_with::<()>("vpn0", true, |_| {
            calls += 1;
            Err(io::ErrorKind::PermissionDenied.into())
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }
    #[test]
    fn failed_policy_io_releases_partial_tun_claim() {
        let registry = Registry::default();
        let result = claim_with("vpn0", true, |name| {
            if name == NAME {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                registry.bind(name)
            }
        });
        assert!(result.is_err());
        assert!(registry.names().is_empty());
        let _replacement = registry.claim("vpn0", true).unwrap();
    }
    #[test]
    fn unwind_releases_both_claims_without_firewall_operations() {
        let registry = Registry::default();
        let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _owner = registry.claim("vpn0", true).unwrap();
            panic!("simulated cancellation");
        }));
        assert!(error.is_err());
        assert!(registry.names().is_empty());
    }
    #[test]
    fn claim_names_are_exact_and_preserve_the_previous_policy_protocol() {
        let registry = Registry::default();
        let _owner = registry.claim("tun.123", true).unwrap();
        assert_eq!(
            registry.names(),
            BTreeSet::from([
                b"qeli.client.tun:tun.123".to_vec(),
                b"qeli.client.kill-switch".to_vec(),
            ])
        );
    }
}
