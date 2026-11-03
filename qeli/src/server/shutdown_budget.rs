//! CLI worker shutdown monitor. Never cancels a resource-owning future.
//! Library callers do not install this process-termination policy.
use std::{
    io,
    sync::{Arc, Condvar, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[cfg(all(target_os = "linux", feature = "server"))]
pub(crate) const LIMIT: Duration = Duration::from_secs(45);
pub(crate) const EXIT_CODE: i32 = 124;

enum State {
    Dormant,
    Armed(Instant),
    Finished,
    Expired,
}

pub(crate) struct Budget {
    state: Arc<(Mutex<State>, Condvar)>,
    monitor: Option<JoinHandle<()>>,
    limit: Duration,
}

impl Budget {
    fn new(limit: Duration, alarm: impl FnOnce() + Send + 'static) -> io::Result<Self> {
        let state = Arc::new((Mutex::new(State::Dormant), Condvar::new()));
        let owned = state.clone();
        let monitor = std::thread::Builder::new()
            .name("qeli-shutdown-budget".into())
            .spawn(move || {
                let (lock, wake) = &*owned;
                let mut state = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                loop {
                    match *state {
                        State::Dormant => {
                            state = wake
                                .wait(state)
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                        }
                        State::Armed(deadline) => {
                            let Some(left) = deadline
                                .checked_duration_since(Instant::now())
                                .filter(|left| !left.is_zero())
                            else {
                                *state = State::Expired;
                                drop(state);
                                alarm();
                                return;
                            };
                            state = wake
                                .wait_timeout(state, left)
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .0;
                        }
                        State::Finished | State::Expired => return,
                    }
                }
            })?;
        Ok(Self {
            state,
            monitor: Some(monitor),
            limit,
        })
    }

    #[cfg(all(target_os = "linux", feature = "server"))]
    pub(crate) fn for_worker() -> io::Result<Self> {
        Self::new(LIMIT, || exit_process())
    }

    /// The first observed stop/fatal event sets the deadline. Repeated requests
    /// cannot grant another budget.
    pub(crate) fn arm(&self) {
        let mut state = self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, State::Dormant) {
            *state = State::Armed(Instant::now() + self.limit);
            self.state.1.notify_all();
        }
    }

    /// Late completion cannot win merely because the monitor was scheduled late.
    /// Successful disarming joins the monitor before a normal process exit.
    pub(crate) fn finish(&mut self) -> bool {
        let completed = {
            let mut state = self
                .state
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let completed = match *state {
                State::Expired => false,
                State::Armed(until) => Instant::now() < until,
                State::Dormant | State::Finished => true,
            };
            if completed {
                *state = State::Finished;
            }
            self.state.1.notify_all();
            completed
        };
        if completed {
            if let Some(monitor) = self.monitor.take() {
                let _ = monitor.join();
            }
        }
        completed
    }
}

impl Drop for Budget {
    fn drop(&mut self) {
        // Dropping an armed CLI future must not silently revoke its deadline.
        // The monitor retains only its clock/termination policy until expiry.
        let unarmed = {
            let state = self
                .state
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            matches!(*state, State::Dormant | State::Finished)
        };
        if unarmed {
            self.finish();
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn exit_process() -> ! {
    // Neither logger locks, C atexit callbacks nor Rust destructors may delay this
    // process-only fallback. Kernel exit/reaping itself is not safely preemptible.
    #[cfg(feature = "server")]
    crate::hook_process::stop_owned_groups();
    unsafe { libc::_exit(EXIT_CODE) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_completion_disarms_and_joins_the_monitor() {
        let (alarm, wait) = std::sync::mpsc::channel();
        let mut budget =
            Budget::new(Duration::from_millis(20), move || alarm.send(()).unwrap()).unwrap();
        budget.arm();
        assert!(budget.finish());
        assert!(budget.finish());
        assert!(wait.recv_timeout(Duration::from_millis(30)).is_err());
        assert!(budget.monitor.is_none());
    }

    #[test]
    fn repeated_arm_preserves_the_original_deadline() {
        let mut budget =
            Budget::new(Duration::from_secs(1), || panic!("unexpected expiry")).unwrap();
        budget.arm();
        let before = match *budget.state.0.lock().unwrap() {
            State::Armed(until) => until,
            _ => panic!(),
        };
        std::thread::sleep(Duration::from_millis(5));
        budget.arm();
        let after = match *budget.state.0.lock().unwrap() {
            State::Armed(until) => until,
            _ => panic!(),
        };
        assert_eq!(before, after);
        assert!(budget.finish());
    }

    #[test]
    fn late_completion_cannot_disarm_an_expired_budget() {
        let (alarm, wait) = std::sync::mpsc::channel();
        let mut budget =
            Budget::new(Duration::from_millis(10), move || alarm.send(()).unwrap()).unwrap();
        budget.arm();
        wait.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!budget.finish());
        assert!(!budget.finish());
    }

    #[test]
    fn armed_owner_drop_keeps_the_deadline_but_dormant_drop_cancels_it() {
        let (alarm, wait) = std::sync::mpsc::channel();
        let budget =
            Budget::new(Duration::from_millis(10), move || alarm.send(()).unwrap()).unwrap();
        budget.arm();
        drop(budget);
        wait.recv_timeout(Duration::from_secs(1)).unwrap();
        let (alarm, wait) = std::sync::mpsc::channel();
        drop(Budget::new(Duration::from_millis(10), move || alarm.send(()).unwrap()).unwrap());
        assert!(wait.recv_timeout(Duration::from_millis(30)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_fixture() {
        let Ok(mode) = std::env::var("QELI_AUDIT_PROCESS_BUDGET_FIXTURE") else {
            return;
        };
        let mut budget = Budget::new(Duration::from_millis(50), || exit_process()).unwrap();
        budget.arm();
        match mode.as_str() {
            "drop" => drop(budget),
            "finish" => {
                assert!(budget.finish());
                std::thread::sleep(Duration::from_millis(100));
                return;
            }
            "stall" => {}
            _ => panic!("invalid isolated process fixture"),
        }
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                // Deliberately starve the executor; an async timeout cannot run here.
                std::thread::sleep(Duration::from_secs(5));
            });
        panic!("process budget failed to terminate stalled worker");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_budget_terminates_executor_stall_and_cancelled_owner_but_not_finished_owner() {
        for (mode, expected) in [("stall", EXIT_CODE), ("drop", EXIT_CODE), ("finish", 0)] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "server_shutdown_budget::tests::process_fixture",
                    "--nocapture",
                ])
                .env("QELI_AUDIT_PROCESS_BUDGET_FIXTURE", mode)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert_eq!(status.code(), Some(expected), "{mode}");
                    break;
                }
                if Instant::now() >= until {
                    child.kill().unwrap();
                    let output = child.wait_with_output().unwrap();
                    panic!("fixture {mode} exceeded deadline: {output:?}");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}
