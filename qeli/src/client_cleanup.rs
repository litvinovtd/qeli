//! Release host egress only after core, network-resource and forwarding cleanup succeed.
use std::sync::{Arc, Mutex};

/// Preconditions for releasing host egress, checked before forwarding cleanup.
pub(crate) struct Checks {
    pub(crate) core: anyhow::Result<()>,
    pub(crate) network: anyhow::Result<()>,
}

impl From<anyhow::Result<()>> for Checks {
    fn from(core: anyhow::Result<()>) -> Self {
        Self {
            core,
            network: Ok(()),
        }
    }
}

impl Checks {
    pub(crate) fn failure_reason(&self) -> Option<(&'static str, &'static str)> {
        if self.core.is_err() {
            Some(("core_stop_failed", "core_stop"))
        } else if self.network.is_err() {
            Some(("network_cleanup_failed", "network_cleanup"))
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Resource {
    Dns,
    Routes,
    Forwarding,
    Transaction,
}

const RESOURCE_NAMES: [&str; 4] = ["DNS", "routes", "forwarding/NAT", "network transaction"];
const ERROR_CHARS: usize = 2048;

/// Sticky, bounded evidence shared by one Linux client and its resource guards.
/// A later successful Drop retry must not erase an already returned cleanup failure.
#[derive(Clone, Default)]
pub(crate) struct Failures(
    Arc<Mutex<[Option<String>; 4]>>,
    Arc<Mutex<Option<std::time::Instant>>>,
);

#[derive(Debug, thiserror::Error)]
#[error("network resource cleanup reported failure: {0}")]
struct NetworkCleanupError(String);

impl Failures {
    /// Only after the previous carrier and resource owners have been joined.
    pub(crate) fn start_attempt(&self) {
        *crate::util::lock_or_recover(&self.1, "client::cleanup_deadline") = None;
    }
    pub(crate) fn cleanup_deadline(&self) -> std::time::Instant {
        *crate::util::lock_or_recover(&self.1, "client::cleanup_deadline")
            .get_or_insert_with(|| std::time::Instant::now() + crate::operation_budget::LIMIT)
    }

    pub(crate) fn observe<T>(
        &self,
        resource: Resource,
        result: anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        if let Err(error) = &result {
            let mut errors = crate::util::lock_or_recover(&self.0, "client::cleanup_failures");
            errors[resource as usize]
                .get_or_insert_with(|| error.to_string().chars().take(ERROR_CHARS).collect());
        }
        result
    }

    pub(crate) fn result(&self) -> anyhow::Result<()> {
        let errors = crate::util::lock_or_recover(&self.0, "client::cleanup_failures");
        let messages: Vec<_> = errors
            .iter()
            .zip(RESOURCE_NAMES)
            .filter_map(|(error, name)| error.as_ref().map(|error| format!("{name}: {error}")))
            .collect();
        if messages.is_empty() {
            Ok(())
        } else {
            Err(NetworkCleanupError(messages.join("; ")).into())
        }
    }
}

pub(crate) fn routing(
    checks: impl Into<Checks>,
    kill_switch: bool,
    remove_forwarding: impl FnOnce() -> anyhow::Result<()>,
    release_kill_switch: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let checks = checks.into();
    let mut incomplete = Vec::new();
    if checks.core.is_err() {
        incomplete.push("transport core teardown");
    }
    let network_failed = checks.network.is_err();
    // Withdraw forwarding permits even when an earlier cleanup stage failed.
    let forwarding = remove_forwarding();
    if forwarding.is_err() {
        incomplete.push("forwarding/NAT cleanup");
    }
    let prerequisites = with_cleanup_error(checks.core, checks.network);
    if let Err(error) = with_cleanup_error(prerequisites, forwarding) {
        let retained = if !kill_switch {
            String::new()
        } else if network_failed {
            "; kill-switch retained because network resource cleanup reported errors".to_string()
        } else {
            format!(
                "; kill-switch retained because {} did not complete",
                incomplete.join(" and ")
            )
        };
        let message = format!("host cleanup failed: {error}{retained}");
        return Err(error.context(message));
    }
    if kill_switch {
        release_kill_switch()
            .map_err(|error| anyhow::anyhow!("host firewall cleanup failed: {error}"))?;
    }
    Ok(())
}

/// Keep both causes visible in ordinary diagnostics, preserving the primary error type.
pub(crate) fn with_cleanup_error(
    result: anyhow::Result<()>,
    cleanup: anyhow::Result<()>,
) -> anyhow::Result<()> {
    match (result, cleanup) {
        (Ok(()), cleanup) => cleanup,
        (result, Ok(())) => result,
        (Err(error), Err(cleanup)) => {
            let message = format!("{error}; teardown also failed: {cleanup}");
            Err(error.context(message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn cleanup_deadline_is_shared_across_guards_and_retry_does_not_extend_it() {
        let failures = Failures::default();
        let expired = std::time::Instant::now();
        *failures.1.lock().unwrap() = Some(expired);
        let guard = failures.clone();
        assert_eq!(guard.cleanup_deadline(), expired);
        assert_eq!(failures.cleanup_deadline(), expired);
        let other = Failures::default();
        assert!(other.cleanup_deadline() > expired);
        let _ = failures.observe::<()>(Resource::Routes, Err(anyhow::anyhow!("retained route")));
        failures.start_attempt();
        assert!(guard.cleanup_deadline() > expired);
        assert!(failures
            .result()
            .unwrap_err()
            .to_string()
            .contains("retained route"));
    }

    #[test]
    fn exhausted_composed_cleanup_preserves_egress_and_sticky_failure() {
        let failures = Failures::default();
        *failures.1.lock().unwrap() = Some(std::time::Instant::now());
        let _scope = crate::operation_budget::Scope::enter(failures.cleanup_deadline());
        let released = Cell::new(false);
        let cleanup = routing(
            Ok(()),
            true,
            || {
                failures.observe(
                    Resource::Forwarding,
                    crate::operation_budget::check().map_err(Into::into),
                )
            },
            || {
                released.set(true);
                Ok(())
            },
        );
        assert!(cleanup
            .unwrap_err()
            .to_string()
            .contains("kill-switch retained"));
        assert!(!released.get());
        assert!(failures.result().is_err());
    }

    #[test]
    fn failed_forwarding_cleanup_keeps_the_egress_barrier() {
        let forwarding_remains = Cell::new(true);
        let barrier_installed = Cell::new(true);
        let error = routing(
            Ok(()),
            true,
            || {
                assert!(forwarding_remains.get());
                anyhow::bail!("IPv6 NAT delete failed")
            },
            || {
                barrier_installed.set(false);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(forwarding_remains.get());
        assert!(
            barrier_installed.get(),
            "cleanup failure must not open host egress"
        );
        assert!(error.to_string().contains("IPv6 NAT delete failed"));
        assert!(error.to_string().contains("kill-switch retained"));
    }

    #[test]
    fn successful_cleanup_removes_forwarding_before_releasing_barrier() {
        let calls = RefCell::new(Vec::new());
        routing(
            Ok(()),
            true,
            || {
                calls.borrow_mut().push("forwarding");
                Ok(())
            },
            || {
                assert_eq!(*calls.borrow(), vec!["forwarding"]);
                calls.borrow_mut().push("kill-switch");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), vec!["forwarding", "kill-switch"]);
    }

    #[test]
    fn barrier_release_failure_is_not_hidden_or_reported_as_retention() {
        let removed = Cell::new(false);
        let error = routing(
            Ok(()),
            true,
            || {
                removed.set(true);
                Ok(())
            },
            || {
                assert!(removed.get());
                anyhow::bail!("OUTPUT jump delete failed")
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("OUTPUT jump delete failed"));
        // Release may have partially succeeded: do not falsely promise protection.
        assert!(!error.to_string().contains("kill-switch retained"));
    }

    #[test]
    fn disabled_kill_switch_is_never_touched_or_claimed_as_retained() {
        for forwarding_ok in [true, false] {
            let result = routing(
                Ok(()),
                false,
                || {
                    if forwarding_ok {
                        Ok(())
                    } else {
                        anyhow::bail!("gateway cleanup failed")
                    }
                },
                || panic!("disabled kill-switch was touched"),
            );
            assert_eq!(result.is_ok(), forwarding_ok);
            if let Err(error) = result {
                assert!(!error.to_string().contains("kill-switch retained"));
            }
        }
    }

    fn busy_core() -> crate::transport_core::ClientCore {
        use crate::transport_core::{ClientCore, CoreOptions};
        let ini = format!(
            "[qeli]\nserver=127.0.0.1:443\nproto=tcp\nuser=test\npass=secret\nkey={}\nmode=fake-tls\n",
            "11".repeat(32)
        );
        let mut core = ClientCore::new(
            &ini,
            CoreOptions {
                event_capacity: 2,
                ..CoreOptions::default()
            },
        )
        .unwrap();
        // Created and Connecting fill a real bounded core queue without private test hooks.
        core.start().unwrap();
        core
    }

    #[test]
    fn core_queue_backpressure_retains_barrier_until_stop_really_completes() {
        use crate::transport_core::{ClientState, CoreError};
        let mut core = busy_core();
        let stop = core.stop().map_err(anyhow::Error::from);
        assert!(matches!(
            stop.as_ref().unwrap_err().downcast_ref(),
            Some(CoreError::EventQueueFull)
        ));
        assert_eq!(core.state(), ClientState::Connecting);
        let forwarded = Cell::new(true);
        let barrier = Cell::new(true);
        let error = routing(
            stop,
            true,
            || {
                forwarded.set(false);
                Ok(())
            },
            || {
                barrier.set(false);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            !forwarded.get(),
            "core error must not skip withdrawal of forwarding permits"
        );
        assert!(
            barrier.get(),
            "an incomplete core stop must not release host egress"
        );
        assert!(matches!(
            error.downcast_ref(),
            Some(CoreError::EventQueueFull)
        ));
        assert!(error
            .to_string()
            .contains("transport core teardown did not complete"));

        // Model explicit recovery; the policy itself must not silently retry a generation.
        while core.poll_event().is_some() {}
        let stop = core.stop().map_err(anyhow::Error::from);
        assert_eq!(core.state(), ClientState::Stopped);
        routing(
            stop,
            true,
            || Ok(()),
            || {
                barrier.set(false);
                Ok(())
            },
        )
        .unwrap();
        assert!(!barrier.get());
    }

    #[test]
    fn core_and_forwarding_failures_are_both_visible_without_releasing_barrier() {
        use crate::transport_core::CoreError;
        let mut core = busy_core();
        let error = routing(
            core.stop().map_err(anyhow::Error::from),
            true,
            || anyhow::bail!("IPv6 NAT delete failed"),
            || panic!("incomplete cleanup must retain the kill-switch"),
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("event queue is full"));
        assert!(text.contains("IPv6 NAT delete failed"));
        assert!(text.contains("core teardown and forwarding/NAT cleanup did not complete"));
        assert!(matches!(
            error.downcast_ref(),
            Some(CoreError::EventQueueFull)
        ));
    }

    #[test]
    fn startup_failure_survives_successful_rollback() {
        use crate::transport_core::CoreError;
        let mut core = busy_core();
        let startup = core.start().map_err(anyhow::Error::from);
        assert!(startup.is_err());
        while core.poll_event().is_some() {}
        let barrier = Cell::new(true);
        let cleanup = routing(
            core.stop().map_err(anyhow::Error::from),
            true,
            || Ok(()),
            || {
                barrier.set(false);
                Ok(())
            },
        );
        let error = with_cleanup_error(startup, cleanup).unwrap_err();
        assert!(
            !barrier.get(),
            "a successfully stopped core can release the barrier"
        );
        assert!(matches!(
            error.downcast_ref(),
            Some(CoreError::InvalidState {
                operation: "start",
                ..
            })
        ));
    }

    #[test]
    fn startup_and_cleanup_failures_keep_both_causes() {
        use crate::transport_core::CoreError;
        let mut core = busy_core();
        let startup = core.start().map_err(anyhow::Error::from);
        let cleanup = routing(
            core.stop().map_err(anyhow::Error::from),
            true,
            || anyhow::bail!("NAT rollback failed"),
            || panic!("failed stop must retain kill-switch"),
        );
        let error = with_cleanup_error(startup, cleanup).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("start"));
        assert!(text.contains("event queue is full"));
        assert!(text.contains("NAT rollback failed"));
        assert!(text.contains("kill-switch retained"));
        assert!(matches!(
            error.downcast_ref(),
            Some(CoreError::InvalidState { .. })
        ));
    }

    #[test]
    fn core_failure_does_not_claim_disabled_barrier_or_report_success() {
        let error = routing(
            Err(anyhow::anyhow!("core stop failed")),
            false,
            || Ok(()),
            || panic!("disabled barrier was touched"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("core stop failed"));
        assert!(!error.to_string().contains("kill-switch retained"));
    }

    #[test]
    fn cleanup_error_combination_preserves_success_and_each_single_error() {
        use crate::transport_core::CoreError;
        with_cleanup_error(Ok(()), Ok(())).unwrap();
        for primary_fails in [true, false] {
            let error = anyhow::Error::new(CoreError::EventQueueFull);
            let result = if primary_fails {
                with_cleanup_error(Err(error), Ok(()))
            } else {
                with_cleanup_error(Ok(()), Err(error))
            };
            assert!(matches!(
                result.unwrap_err().downcast_ref(),
                Some(CoreError::EventQueueFull)
            ));
        }
    }

    #[test]
    fn resource_fault_is_terminal_even_after_core_stop_and_forwarding_succeed() {
        let failures = Failures::default();
        assert!(failures
            .observe::<()>(
                Resource::Dns,
                Err(anyhow::anyhow!("resolver revert failed"))
            )
            .is_err());
        let checks = Checks {
            core: Ok(()),
            network: failures.result(),
        };
        assert_eq!(
            checks.failure_reason(),
            Some(("network_cleanup_failed", "network_cleanup"))
        );
        let forwarded = Cell::new(true);
        let error = routing(
            checks,
            true,
            || {
                forwarded.set(false);
                Ok(())
            },
            || panic!("DNS cleanup failure must not release the kill-switch"),
        )
        .unwrap_err();
        assert!(!forwarded.get());
        assert!(error.to_string().contains("resolver revert failed"));
        assert!(error.to_string().contains("kill-switch retained"));
    }

    #[test]
    fn successful_fallback_does_not_erase_an_observed_failure() {
        let failures = Failures::default();
        let guard = failures.clone();
        let _ = failures.observe::<()>(
            Resource::Routes,
            Err(anyhow::anyhow!("route delete failed")),
        );
        guard.observe(Resource::Routes, Ok(())).unwrap();
        assert!(failures
            .result()
            .unwrap_err()
            .to_string()
            .contains("route delete failed"));
        assert!(
            Failures::default().result().is_ok(),
            "other clients must have isolated records"
        );
    }

    #[test]
    fn late_old_guard_fault_is_not_lost_between_clean_attempts() {
        let failures = Failures::default();
        let old_guard = failures.clone();
        failures.result().unwrap();
        failures.observe(Resource::Dns, Ok(())).unwrap();
        let _ = old_guard.observe::<()>(
            Resource::Routes,
            Err(anyhow::anyhow!("late route cleanup failed")),
        );
        assert!(failures
            .result()
            .unwrap_err()
            .to_string()
            .contains("late route cleanup failed"));
    }

    #[test]
    fn drop_cleanup_fault_survives_original_operation_error_and_unwind() {
        struct FaultyGuard(Failures);
        impl Drop for FaultyGuard {
            fn drop(&mut self) {
                let _ = self
                    .0
                    .observe::<()>(Resource::Routes, Err(anyhow::anyhow!("rollback failed")));
            }
        }
        fn fail(failures: Failures) -> anyhow::Result<()> {
            let _guard = FaultyGuard(failures);
            anyhow::bail!("plan acknowledgement failed")
        }
        let failures = Failures::default();
        let result = fail(failures.clone());
        let error = with_cleanup_error(result, failures.result())
            .unwrap_err()
            .to_string();
        assert!(error.contains("plan acknowledgement failed"));
        assert!(error.contains("rollback failed"));
        let fresh = Failures::default();
        assert!(std::panic::catch_unwind(|| {
            let _guard = FaultyGuard(fresh.clone());
            panic!("simulated callback panic");
        })
        .is_err());
        assert!(fresh.result().is_err());
    }

    #[test]
    fn failure_evidence_is_bounded_and_keeps_first_error_for_each_resource() {
        let failures = Failures::default();
        for resource in [
            Resource::Dns,
            Resource::Routes,
            Resource::Forwarding,
            Resource::Transaction,
        ] {
            let _ = failures.observe::<()>(
                resource,
                Err(anyhow::anyhow!("{}", "é".repeat(ERROR_CHARS * 4))),
            );
            let _ = failures.observe::<()>(resource, Err(anyhow::anyhow!("replacement")));
        }
        let errors = failures.0.lock().unwrap();
        assert_eq!(errors.iter().flatten().count(), RESOURCE_NAMES.len());
        for error in errors.iter().flatten() {
            assert_eq!(error.chars().count(), ERROR_CHARS);
            assert!(!error.contains("replacement"));
        }
    }

    #[test]
    fn concurrent_guards_preserve_each_resource_failure() {
        let failures = Failures::default();
        std::thread::scope(|scope| {
            for (resource, message) in [
                (Resource::Dns, "dns fault"),
                (Resource::Routes, "route fault"),
                (Resource::Forwarding, "nat fault"),
                (Resource::Transaction, "worker fault"),
            ] {
                let copy = failures.clone();
                scope.spawn(move || {
                    let _ = copy.observe::<()>(resource, Err(anyhow::anyhow!(message)));
                });
            }
        });
        let message = failures.result().unwrap_err().to_string();
        for expected in [
            "DNS: dns fault",
            "routes: route fault",
            "forwarding/NAT: nat fault",
            "network transaction: worker fault",
        ] {
            assert!(message.contains(expected), "{message}");
        }
    }

    #[test]
    fn cleanup_reason_priority_and_disabled_barrier_remain_explicit() {
        let failures = Failures::default();
        let _ = failures.observe::<()>(Resource::Dns, Err(anyhow::anyhow!("DNS fault")));
        let checks = Checks {
            core: Err(anyhow::anyhow!("core fault")),
            network: failures.result(),
        };
        assert_eq!(
            checks.failure_reason(),
            Some(("core_stop_failed", "core_stop"))
        );
        let error = routing(
            checks,
            false,
            || Ok(()),
            || panic!("disabled barrier was touched"),
        )
        .unwrap_err();
        assert!(!error.to_string().contains("kill-switch retained"));
        assert!(error.to_string().contains("DNS fault"));
        assert_eq!(Checks::from(Ok(())).failure_reason(), None);
    }
}
