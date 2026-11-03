//! Thread-local command replacement: never changes PATH or the host network.
//! Real finite child probes use the same collector as production with smaller limits.
use super::*;
use std::cell::RefCell;

pub(crate) enum Action {
    Reply(io::Result<Output>),
    Probe { mode: &'static str },
}
impl Action {
    pub(super) fn run(self) -> io::Result<Output> {
        match self {
            Self::Reply(result) => result,
            Self::Probe { mode } => {
                let (deadline, limit) = match mode {
                    "slow" => (Duration::from_millis(100), OUTPUT_LIMIT),
                    "bytes" => (Duration::from_secs(5), 32 * 1024),
                    _ => (Duration::from_secs(5), OUTPUT_LIMIT),
                };
                super::tests::fixture(mode).output_with_limits(deadline, limit)
            }
        }
    }
}

type Interceptor = Box<dyn FnMut(&std::process::Command) -> Action>;
thread_local! {
    static INTERCEPTOR: RefCell<Option<Interceptor>> = RefCell::new(None);
}

pub(super) fn intercept(command: &std::process::Command) -> Option<Action> {
    INTERCEPTOR.with(|slot| slot.borrow_mut().as_mut().map(|run| run(command)))
}

pub(crate) fn with_commands<T>(
    intercept: impl FnMut(&std::process::Command) -> Action + 'static,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            INTERCEPTOR.with(|slot| *slot.borrow_mut() = None);
        }
    }
    INTERCEPTOR.with(|slot| {
        assert!(slot.borrow().is_none(), "nested system command override");
        *slot.borrow_mut() = Some(Box::new(intercept));
    });
    let _reset = Reset;
    run()
}

pub(crate) fn arguments(command: &std::process::Command) -> Vec<String> {
    command
        .get_args()
        .map(|s| s.to_str().unwrap().to_string())
        .collect()
}
