//! Refresh uses real child processes but only private files, never host firewall rules.
use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};

struct Fixture {
    dir: PathBuf,
    name: &'static str,
    _serial: std::sync::MutexGuard<'static, ()>,
}
impl Fixture {
    fn new(name: &'static str, scripts: [&str; 2]) -> Self {
        let serial = BUDGET_TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "qeli-ks-refresh-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let _operation = operation();
        // Real namespace avoids sharing fake owners with tests that clear the model registry.
        let context = Context::prepare(name).unwrap();
        context.bind(name).unwrap();
        for (i, script) in scripts.into_iter().enumerate() {
            let bin = if i == 0 { "iptables" } else { "ip6tables" };
            let path = dir.join(bin);
            std::fs::write(&path, format!("#!/bin/sh\ncd '{}' || exit 17\nprintf '%s\\n' \"$*\" >> \"$0.calls\"\n{script}\n", dir.display())).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            context.remember(i == 1, path.to_str().unwrap()).unwrap();
            context.protected(i == 1, true, false);
        }
        Self {
            dir,
            name,
            _serial: serial,
        }
    }
    fn refresh(&self, until: Instant) -> anyhow::Result<()> {
        refresh_until(self.name, until, || vec!["203.0.113.8".into()])
    }
    fn calls(&self, bin: &str) -> String {
        std::fs::read_to_string(self.dir.join(format!("{bin}.calls"))).unwrap_or_default()
    }
    fn retained(&self) {
        let c = Context::lookup(self.name, true)
            .unwrap()
            .expect("refresh lost ownership");
        assert_eq!(c.paths().len(), 2);
        assert!(c.paths().iter().all(|(_, family)| family.protected));
    }
    fn retry(&self) {
        std::fs::write(self.dir.join("retry"), b"1").unwrap();
        // The public entry must grant a fresh budget to the same retained owner.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(prepare_refresh("203.0.113.8", 443, self.name))
            .unwrap()()
        .unwrap();
        self.retained();
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
fn refresh_expiry_before_or_during_resolution_never_starts_firewall_work() {
    let f = Fixture::new("ks_ref_resolve", ["exit 0", "exit 0"]);
    assert!(refresh_until(f.name, Instant::now(), || panic!(
        "expired attempt resolved a name"
    ))
    .is_err());
    let until = Instant::now() + Duration::from_millis(30);
    assert!(refresh_until(f.name, until, || {
        std::thread::sleep(
            until.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
        );
        vec!["203.0.113.8".into()]
    })
    .is_err());
    assert!(f.calls("iptables").is_empty() && f.calls("ip6tables").is_empty());
    f.retained();
}

#[test]
fn refresh_busy_operation_lock_expires_without_commands() {
    let f = Fixture::new("ks_ref_lock", ["exit 0", "exit 0"]);
    let held = operation();
    assert!(f
        .refresh(Instant::now() + Duration::from_millis(30))
        .is_err());
    assert!(f.calls("iptables").is_empty() && f.calls("ip6tables").is_empty());
    drop(held);
    f.retained();
}

#[test]
fn refresh_queue_wait_consumes_the_first_commands_budget() {
    let script = "[ -e retry ] || sleep 0.45; exit 0";
    let f = Fixture::new("ks_ref_queue", [script, script]);
    let held = operation();
    let (sent, received) = std::sync::mpsc::channel();
    let name = f.name;
    let worker = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_millis(650);
        refresh_until(name, until, || {
            sent.send(()).unwrap();
            vec!["203.0.113.8".into()]
        })
    });
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    drop(held);
    assert!(
        worker.join().unwrap().is_err(),
        "queue wait granted a fresh command budget"
    );
    assert_eq!(f.calls("iptables").lines().count(), 1);
    assert!(f.calls("ip6tables").is_empty());
    f.retry();
}

#[test]
fn refresh_families_share_one_budget_and_keep_retry_authority() {
    let v4 = "[ -e retry ] || sleep 0.06; exit 0";
    let v6 = "[ -e retry ] || sleep 0.55; exit 0";
    let f = Fixture::new("ks_ref_families", [v4, v6]);
    assert!(
        f.refresh(Instant::now() + Duration::from_millis(650))
            .is_err(),
        "families received fresh deadlines"
    );
    assert_eq!(f.calls("iptables").lines().count(), 4);
    assert_eq!(f.calls("ip6tables").lines().count(), 1);
    f.retry();
}

const STATEFUL: &str = r#"
case "$1" in
  -C)
    [ "$2" = OUTPUT ] && exit 0
    [ "$3" = -j ] && [ "$4" = DROP ] && exit 0
    if [ -e unknown ] && [ ! -e retry ]; then echo 'iptables: Permission denied (fixture)' >&2; exit 1; fi
    case "$4" in
      203.0.113.8) [ -e "$0.new" ] && exit 0;;
      203.0.113.7) [ -e "$0.old" ] && exit 0;;
    esac
    exit 1;;
  -I) touch "$0.new"; [ -e slow ] && [ ! -e retry ] && sleep 1; exit 0;;
  -S)
    [ -e "$0.old" ] && printf '%s\n' "-A $2 -d 203.0.113.7/32 -j ACCEPT"
    [ -e "$0.new" ] && printf '%s\n' "-A $2 -d 203.0.113.8/32 -j ACCEPT"
    exit 0;;
  -D) rm -f "$0.old"; exit 0;;
  *) exit 17;;
esac
"#;

#[test]
fn refresh_timeout_after_add_retains_old_allowance_and_drop_for_retry() {
    let f = Fixture::new("ks_ref_partial", [STATEFUL, STATEFUL]);
    std::fs::write(f.dir.join("iptables.old"), b"old").unwrap();
    std::fs::write(f.dir.join("slow"), b"1").unwrap();
    assert!(f
        .refresh(Instant::now() + Duration::from_millis(350))
        .is_err());
    assert!(
        f.dir.join("iptables.new").exists(),
        "fixture did not apply before delaying acknowledgement"
    );
    assert!(
        f.dir.join("iptables.old").exists(),
        "unverified replacement removed the old path"
    );
    assert!(!f
        .calls("iptables")
        .lines()
        .any(|c| c.starts_with("-D ") || c.starts_with("-F ") || c.starts_with("-X ")));
    assert!(f.calls("ip6tables").is_empty());
    f.retry();
    assert!(!f.dir.join("iptables.old").exists());
    assert!(f.dir.join("iptables.new").exists());
}

#[test]
fn refresh_unknown_allowance_does_not_authorize_mutation() {
    let f = Fixture::new("ks_ref_unknown", [STATEFUL, STATEFUL]);
    std::fs::write(f.dir.join("iptables.old"), b"old").unwrap();
    std::fs::write(f.dir.join("unknown"), b"1").unwrap();
    assert!(f.refresh(Instant::now() + Duration::from_secs(5)).is_err());
    assert!(
        !f.dir.join("iptables.new").exists(),
        "unknown query was treated as absence and inserted a rule"
    );
    assert!(f.dir.join("iptables.old").exists());
    assert!(!f
        .calls("iptables")
        .lines()
        .any(|c| c.starts_with("-I ") || c.starts_with("-D ")));
    f.retry();
    assert!(f.dir.join("iptables.new").exists());
    assert!(!f.dir.join("iptables.old").exists());
}
