//! Deadlines for synchronous route transactions. The operation mutex is held on this
//! thread for their entire lifetime; this scope is !Send and never crosses an await.
//! A nested rollback intentionally gets a fresh deadline, then restores the parent.
use std::{
    cell::Cell,
    io,
    marker::PhantomData,
    rc::Rc,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};
const LIMIT: Duration = Duration::from_secs(15);
thread_local! { static CURRENT: Cell<Option<Instant>> = const { Cell::new(None) }; }
#[cfg(test)]
thread_local! { static REQUESTED: Cell<Option<Instant>> = const { Cell::new(None) }; }

pub(super) fn deadline() -> Instant {
    crate::operation_budget::limit(
        CURRENT
            .with(Cell::get)
            .unwrap_or_else(|| Instant::now() + LIMIT),
    )
}
fn remaining(until: Instant) -> io::Result<Duration> {
    crate::operation_budget::limit(until)
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "route operation deadline expired; unresolved reservations retained for retry",
            )
        })
}
pub(super) fn check_until(until: Instant) -> io::Result<()> {
    remaining(until).map(|_| ())
}
pub(super) fn check() -> io::Result<()> {
    match CURRENT.with(Cell::get) {
        Some(until) => check_until(until),
        None => Ok(()),
    }
}

pub(super) struct Scope {
    previous: Option<Instant>,
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    fn enter(until: Instant) -> Self {
        Self {
            previous: CURRENT.with(|s| s.replace(Some(until))),
            _thread: PhantomData,
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|s| s.set(self.previous));
    }
}

pub(super) struct Operation {
    _scope: Scope,
    _lock: MutexGuard<'static, ()>,
}
impl Operation {
    pub(super) fn acquire(lock: &'static Mutex<()>) -> io::Result<Self> {
        let until = Instant::now() + LIMIT;
        #[cfg(test)]
        let until = REQUESTED.with(Cell::get).unwrap_or(until);
        let until = CURRENT
            .with(Cell::get)
            .map_or(until, |parent| parent.min(until));
        let scope = Scope::enter(until);
        loop {
            check_until(until)?;
            let acquired = match lock.try_lock() {
                Ok(guard) => Some(guard),
                Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(guard) = acquired {
                check_until(until)?;
                return Ok(Self {
                    _scope: scope,
                    _lock: guard,
                });
            }
            std::thread::sleep(remaining(until)?.min(Duration::from_millis(10)));
        }
    }
}
#[cfg(feature = "experimental-roaming")]
pub(super) fn rollback() -> Scope {
    Scope::enter(Instant::now() + LIMIT)
}
#[cfg(test)]
pub(super) fn with_deadline<T>(until: Instant, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<Instant>);
    impl Drop for Reset {
        fn drop(&mut self) {
            REQUESTED.with(|s| s.set(self.0));
        }
    }
    let _reset = Reset(REQUESTED.with(|s| s.replace(Some(until))));
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_budget_scope_restores_parent_after_panic_and_rollback() {
        assert!(CURRENT.with(Cell::get).is_none());
        let expired = Instant::now();
        let _parent = Scope::enter(expired);
        let result = std::panic::catch_unwind(|| {
            #[cfg(feature = "experimental-roaming")]
            let _child = rollback();
            #[cfg(not(feature = "experimental-roaming"))]
            let _child = Scope::enter(Instant::now() + LIMIT);
            check().unwrap();
            panic!("exercise unwinding");
        });
        assert!(result.is_err());
        assert_eq!(CURRENT.with(Cell::get), Some(expired));
        assert!(check().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_budget_real_child_obeys_operation_deadline() {
        use crate::system_command::Command;
        static LOCK: Mutex<()> = Mutex::new(());
        let started = Instant::now();
        with_deadline(started + Duration::from_millis(120), || {
            let _operation = Operation::acquire(&LOCK).unwrap();
            let error = Command::new("/bin/sh")
                .args(["-c", "sleep 5"])
                .output_until(deadline())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        });
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}

#[cfg(test)]
mod composition_tests {
    use super::*;
    #[test]
    fn exhausted_plan_refuses_route_mutex_and_explicit_cleanup_can_acquire_it() {
        static LOCK: Mutex<()> = Mutex::new(());
        let _setup = crate::operation_budget::Scope::enter(Instant::now());
        assert!(matches!(Operation::acquire(&LOCK), Err(e) if e.kind() == io::ErrorKind::TimedOut));
        {
            let _cleanup = crate::operation_budget::Scope::enter(Instant::now() + LIMIT);
            let _operation = Operation::acquire(&LOCK).unwrap();
            check().unwrap();
        }
        assert!(matches!(Operation::acquire(&LOCK), Err(e) if e.kind() == io::ErrorKind::TimedOut));
    }
}
