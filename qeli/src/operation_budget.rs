//! Caller-thread command budget. Scopes never cross an await or move to a worker.
//! Rollback enters its own scope; component commands/locks can only shorten it.
use std::{
    cell::Cell,
    io,
    marker::PhantomData,
    rc::Rc,
    time::{Duration, Instant},
};
thread_local! { static CURRENT: Cell<Option<Instant>> = const { Cell::new(None) }; }
pub(crate) const LIMIT: Duration = Duration::from_secs(15);
pub(crate) fn limit(until: Instant) -> Instant {
    CURRENT
        .with(Cell::get)
        .map_or(until, |parent| parent.min(until))
}
pub(crate) fn check_until(until: Instant) -> io::Result<()> {
    if limit(until) <= Instant::now() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "network transaction command deadline expired; unresolved ownership retained",
        ))
    } else {
        Ok(())
    }
}
pub(crate) fn check() -> io::Result<()> {
    check_until(Instant::now() + LIMIT)
}
pub(crate) struct Scope {
    previous: Option<Instant>,
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub(crate) fn enter(until: Instant) -> Self {
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_scope_restores_expired_setup_on_unwind() {
        let expired = Instant::now();
        let _setup = Scope::enter(expired);
        assert!(check().is_err());
        let result = std::panic::catch_unwind(|| {
            let _cleanup = Scope::enter(Instant::now() + LIMIT);
            check().unwrap();
            panic!("cleanup unwind");
        });
        assert!(result.is_err());
        assert_eq!(limit(Instant::now() + LIMIT), expired);
    }
    #[test]
    fn component_deadlines_cannot_extend_parent_and_scopes_are_thread_local() {
        let parent = Instant::now() + Duration::from_secs(1);
        let _scope = Scope::enter(parent);
        assert_eq!(limit(parent + LIMIT), parent);
        let earlier = parent - Duration::from_millis(100);
        assert_eq!(limit(earlier), earlier);
        std::thread::spawn(|| assert!(CURRENT.with(Cell::get).is_none()))
            .join()
            .unwrap();
    }
}
