//! Real subprocesses and pinned namespaces; every firewall mutation is a private file.
use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::MutexGuard,
    time::{Duration, Instant},
};
struct Fixture {
    dir: PathBuf,
    name: &'static str,
    _serial: MutexGuard<'static, ()>,
}
const TOOL: &str = r#"
[ "$1" = -t ] && shift 2
case "$1" in
  --version) [ -e "$0.probe-delay" ] && sleep "$(cat "$0.probe-delay")"; printf fixture; exit 0;;
  -S)
    if [ "$#" = 1 ]; then
      [ -e "$0.inventory-delay" ] && sleep "$(cat "$0.inventory-delay")"
      printf '%s\n' '-P INPUT ACCEPT' '-P FORWARD ACCEPT' '-P OUTPUT ACCEPT'
      [ -e "$0.chain" ] && printf '%s\n' "-N $(cat "$0.chain")"
      exit 0
    fi
    [ -e "$0.chain" ] && exit 0
    echo 'iptables: No chain/target/match by that name.' >&2; exit 1;;
  -C)
    case "$2" in
      OUTPUT) [ -e "$0.output" ] && exit 0; exit 1;;
      FORWARD) [ -e "$0.forward" ] && exit 0; exit 1;;
    esac
    [ "$3" = -j ] && [ "$4" = DROP ] && [ -e "$0.fail-drop" ] && exit 1
    [ -e "$0.chain" ] && exit 0; exit 1;;
  -N) printf '%s' "$2" > "$0.chain"; [ -e "$0.setup-delay" ] && sleep "$(cat "$0.setup-delay")"; exit 0;;
  -A) exit 0;;
  -I) case "$2" in OUTPUT) touch "$0.output";; FORWARD) touch "$0.forward";; esac; exit 0;;
  -D) case "$2" in OUTPUT) rm -f "$0.output";; FORWARD) rm -f "$0.forward";; esac; exit 0;;
  -F) [ -e "$0.rollback-delay" ] && sleep "$(cat "$0.rollback-delay")"; exit 0;;
  -X) [ -e "$0.stuck" ] || rm -f "$0.chain"; exit 0;;
  *) exit 17;;
esac
"#;
impl Fixture {
    fn new(name: &'static str) -> Self {
        let serial = BUDGET_TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let _operation = operation();
        let dir = std::env::temp_dir().join(format!(
            "qeli-ks-setup-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        for bin in ["iptables", "ip6tables"] {
            let path = dir.join(bin);
            std::fs::write(
                &path,
                format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$0.calls\"\n{TOOL}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            dir,
            name,
            _serial: serial,
        }
    }
    fn paths(&self) -> [Option<String>; 2] {
        ["iptables", "ip6tables"].map(|bin| Some(self.dir.join(bin).to_str().unwrap().to_owned()))
    }
    fn run(
        &self,
        until: Instant,
        rollback: Duration,
        resolve: impl FnOnce() -> Vec<String>,
    ) -> anyhow::Result<()> {
        ownership::test_support::with_paths(self.paths(), || {
            engage_until(
                Setup {
                    server_addr: "203.0.113.8",
                    tun_if: self.name,
                    allow_ipv4_leak: true,
                    allow_ipv6_leak: true,
                    guard_forward: true,
                },
                until,
                rollback,
                resolve,
            )
        })
    }
    fn setup(&self, duration: Duration, rollback: Duration) -> anyhow::Result<()> {
        self.run(Instant::now() + duration, rollback, || {
            vec!["203.0.113.8".into()]
        })
    }
    fn flag(&self, name: &str, value: &str) {
        std::fs::write(self.dir.join(name), value).unwrap();
    }
    fn calls(&self, bin: &str) -> String {
        std::fs::read_to_string(self.dir.join(format!("{bin}.calls"))).unwrap_or_default()
    }
    fn clean(&self) {
        disengage(self.name).unwrap();
        assert!(Context::lookup(self.name, true).unwrap().is_none());
        for bin in ["iptables", "ip6tables"] {
            for suffix in ["chain", "output", "forward"] {
                assert!(!self.dir.join(format!("{bin}.{suffix}")).exists());
            }
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _operation = operation();
        if let Ok(Some(c)) = Context::lookup(self.name, true) {
            let _ = c.forget(self.name);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn setup_expiry_before_or_during_resolution_does_not_claim_or_program() {
    let f = Fixture::new("ks_setup_dns");
    assert!(f
        .run(Instant::now(), Duration::from_secs(1), || panic!(
            "expired setup resolved"
        ))
        .is_err());
    let until = Instant::now() + Duration::from_millis(30);
    assert!(f
        .run(until, Duration::from_secs(1), || {
            std::thread::sleep(
                until.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
            vec!["203.0.113.8".into()]
        })
        .is_err());
    assert!(f.calls("iptables").is_empty() && f.calls("ip6tables").is_empty());
    assert!(Context::lookup(f.name, true).unwrap().is_none());
}

#[test]
fn setup_busy_mutex_expires_before_firewall_admission() {
    let f = Fixture::new("ks_setup_lock");
    let held = operation();
    assert!(f
        .setup(Duration::from_millis(30), Duration::from_secs(1))
        .is_err());
    assert!(f.calls("iptables").is_empty() && f.calls("ip6tables").is_empty());
    assert!(Context::lookup(f.name, true).unwrap().is_none());
    drop(held);
}

#[test]
fn setup_queue_wait_consumes_inventory_budget_without_binding() {
    let f = Fixture::new("ks_setup_queue");
    f.flag("iptables.inventory-delay", "0.45");
    let held = operation();
    let (sent, received) = std::sync::mpsc::channel();
    let result = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            f.run(
                Instant::now() + Duration::from_millis(650),
                Duration::from_secs(1),
                || {
                    sent.send(()).unwrap();
                    vec!["203.0.113.8".into()]
                },
            )
        });
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
        worker.join().unwrap()
    });
    let error = result.unwrap_err();
    assert!(format!("{error:#}").contains("deadline"), "{error:#}");
    assert_eq!(f.calls("iptables").lines().count(), 1);
    assert!(f.calls("ip6tables").is_empty());
    assert!(Context::lookup(f.name, true).unwrap().is_none());
}

#[test]
fn setup_families_share_deadline_and_rollback_armed_first_family() {
    let f = Fixture::new("ks_setup_both");
    f.flag("iptables.setup-delay", "0.25");
    f.flag("ip6tables.setup-delay", "0.40");
    assert!(f
        .setup(Duration::from_millis(650), Duration::from_secs(2))
        .is_err());
    assert!(
        f.calls("iptables")
            .lines()
            .any(|line| line.starts_with("-I OUTPUT")),
        "fixture never armed first family"
    );
    assert!(f
        .calls("ip6tables")
        .lines()
        .any(|line| line.starts_with("-N ")));
    assert!(!f
        .calls("ip6tables")
        .lines()
        .any(|line| line.starts_with("-A ")));
    assert_eq!(
        Context::lookup(f.name, true)
            .unwrap()
            .unwrap()
            .paths()
            .len(),
        2
    );
    for bin in ["iptables", "ip6tables"] {
        assert!(!f.dir.join(format!("{bin}.chain")).exists());
    }
    f.clean();
}

#[test]
fn expired_setup_has_a_separate_budget_to_rollback_applied_mutation() {
    let f = Fixture::new("ks_setup_roll");
    f.flag("iptables.setup-delay", "1");
    assert!(f
        .setup(Duration::from_millis(350), Duration::from_secs(2))
        .is_err());
    assert!(f
        .calls("iptables")
        .lines()
        .any(|line| line.starts_with("-N ")));
    assert!(
        f.calls("iptables")
            .lines()
            .any(|line| line.starts_with("-X ")),
        "expired setup starved rollback"
    );
    assert!(!f.dir.join("iptables.chain").exists());
    assert!(!f
        .calls("ip6tables")
        .lines()
        .any(|line| line.starts_with("-N ")));
    assert!(Context::lookup(f.name, true).unwrap().is_some());
    f.clean();
}

#[test]
fn rollback_deadline_is_shared_by_inner_and_final_attempts_and_retains_retry() {
    let f = Fixture::new("ks_setup_retry");
    f.flag("iptables.setup-delay", "1");
    f.flag("iptables.rollback-delay", "0.45");
    let error = f
        .setup(Duration::from_millis(350), Duration::from_millis(200))
        .unwrap_err();
    assert!(error.to_string().contains("rollback"));
    assert_eq!(
        f.calls("iptables")
            .lines()
            .filter(|line| line.starts_with("-F "))
            .count(),
        1,
        "final rollback granted a new budget"
    );
    assert!(!f
        .calls("iptables")
        .lines()
        .any(|line| line.starts_with("-X ")));
    assert!(f.dir.join("iptables.chain").exists());
    assert!(Context::lookup(f.name, true).unwrap().is_some());
    std::fs::remove_file(f.dir.join("iptables.rollback-delay")).unwrap();
    f.clean();
}

#[test]
fn incomplete_rollback_cannot_be_accepted_by_leak_escape_hatches() {
    let f = Fixture::new("ks_setup_leak");
    f.flag("iptables.fail-drop", "1");
    f.flag("iptables.stuck", "1");
    let result = f.setup(Duration::from_secs(5), Duration::from_secs(2));
    assert!(result.is_err(), "leak flags accepted incomplete rollback");
    assert!(result.unwrap_err().to_string().contains("rollback"));
    assert!(f.dir.join("iptables.chain").exists());
    assert!(Context::lookup(f.name, true).unwrap().is_some());
    std::fs::remove_file(f.dir.join("iptables.stuck")).unwrap();
    f.clean();
}

#[test]
fn owned_firewall_probe_uses_the_remaining_budget() {
    let f = Fixture::new("ks_setup_probe");
    f.flag("iptables.probe-delay", "0.45");
    let path = f.dir.join("iptables").to_str().unwrap().to_owned();
    let context = Context::fixture().with_budget(Budget {
        until: Instant::now() + Duration::from_millis(100),
        operation: "setup",
    });
    assert!(ipt_path_with("qeli-absent-tool-fixture", |_| context
        .ipt(&path, &["--version"]))
    .is_none());
    assert_eq!(
        context.check_budget().unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
}
