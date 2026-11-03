//! Exercise production gateway entry points without touching host networking.
use super::*;
#[cfg(all(target_os = "linux", feature = "client"))]
use crate::client::killswitch as kill_switch;
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
use crate::client_killswitch as kill_switch;
use crate::system_command::test_support::{arguments, with_commands, Action};
use host::test_support::{with_sysctls, Operation};
use std::{cell::RefCell, collections::BTreeMap, io, process::Output, rc::Rc, sync::Mutex};

static SERIAL: Mutex<()> = Mutex::new(());
type Rules = BTreeMap<(bool, String, String), Vec<Vec<String>>>;

#[derive(Default)]
struct Kernel {
    rules: Rules,
    lose_after_command: Option<(String, bool)>,
    move_wan_after_command: Option<(String, String)>,
    lose_kill_namespace_after: Option<String>,
    missing_firewall: Option<bool>,
    lose_after_acquire: Option<bool>,
    calls: Vec<Vec<String>>,
    releases: Vec<String>,
    leases: BTreeMap<String, Vec<String>>,
    delay_once: Option<(String, std::time::Duration)>,
    query_fault: Option<&'static str>,
    hook_fault: bool,
    delete_fault: Option<bool>,
    lie_add: bool,
    lie_delete: bool,
    lost_add: bool,
    fail_acquire: bool,
    fail_release: bool,
    wans: [Option<String>; 2],
    fail_mark_delete: bool,
    fail_nat_add: bool,
    fail_ipv6_drop: bool,
    inventory_failure: Option<bool>,
    inventory_override: Option<(bool, Vec<u8>)>,
}
fn output(code: u32, text: &str, error: &str) -> Output {
    #[cfg(unix)]
    let status = {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw((code as i32) << 8)
    };
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code)
    };
    Output {
        status,
        stdout: text.as_bytes().to_vec(),
        stderr: error.as_bytes().to_vec(),
    }
}
impl Kernel {
    fn command(&mut self, cmd: &std::process::Command) -> io::Result<Output> {
        let args = arguments(cmd);
        self.calls.push(args.clone());
        let program = cmd.get_program().to_string_lossy();
        if program == "ip" {
            let wan = &self.wans[usize::from(args.first().is_some_and(|arg| arg == "-6"))];
            let text = wan
                .as_ref()
                .map(|wan| format!("default dev {wan}"))
                .unwrap_or_default();
            return Ok(output(0, &text, ""));
        }
        assert!(
            program.ends_with("iptables") || program.ends_with("ip6tables"),
            "{program}"
        );
        if self.missing_firewall == Some(program.ends_with("ip6tables")) {
            return Err(io::ErrorKind::NotFound.into());
        }
        if args == ["--version"] {
            return Ok(output(0, "", ""));
        }
        let ipv6 = program.ends_with("ip6tables");
        let (table, start) = if args[0] == "-t" {
            (args[1].clone(), 2)
        } else {
            ("filter".into(), 0)
        };
        let op = args[start].as_str();
        for builtin in ["INPUT", "OUTPUT", "FORWARD"] {
            self.rules
                .entry((ipv6, "filter".into(), builtin.into()))
                .or_default();
        }
        if op == "-S" && args.len() == start + 1 {
            if self.inventory_failure == Some(ipv6) {
                return Ok(output(4, "", "iptables: inventory unavailable"));
            }
            if let Some((family, data)) = &self.inventory_override {
                if *family == ipv6 {
                    let mut result = output(0, "", "");
                    result.stdout = data.clone();
                    return Ok(result);
                }
            }
            let mut text = String::new();
            for (family, rule_table, name) in self.rules.keys() {
                if *family != ipv6 || rule_table != &table {
                    continue;
                }
                if ["INPUT", "OUTPUT", "FORWARD"].contains(&name.as_str()) {
                    text.push_str(&format!("-P {name} ACCEPT\n"));
                } else {
                    text.push_str(&format!("-N {name}\n"));
                }
            }
            for ((family, rule_table, name), rules) in &self.rules {
                if *family != ipv6 || rule_table != &table {
                    continue;
                }
                for rule in rules {
                    text.push_str(&format!("-A {name} {}\n", rule.join(" ")));
                }
            }
            return Ok(output(0, &text, ""));
        }
        let chain = args[start + 1].clone();
        let key = (ipv6, table, chain.clone());
        match op {
            "-N" => {
                self.rules.entry(key).or_default();
                return Ok(output(0, "", ""));
            }
            "-F" => {
                self.rules.get_mut(&key).unwrap().clear();
                return Ok(output(0, "", ""));
            }
            "-X" => {
                let referenced = self.rules.iter().any(|((family, rule_table, _), rules)| {
                    *family == ipv6
                        && rule_table == &key.1
                        && rules.iter().any(|rule| {
                            rule.windows(2)
                                .any(|pair| pair[0] == "-j" && pair[1] == chain)
                        })
                });
                if referenced || self.rules.get(&key).is_some_and(|rules| !rules.is_empty()) {
                    return Ok(output(
                        1,
                        "",
                        "iptables: chain is not empty or still referenced",
                    ));
                }
                self.rules.remove(&key);
                return Ok(output(0, "", ""));
            }
            "-S" if !self.rules.contains_key(&key) => {
                return Ok(output(
                    1,
                    "",
                    "iptables: No chain/target/match by that name.",
                ));
            }
            _ => {}
        }
        let rules = self.rules.entry(key).or_default();
        if op == "-S" {
            let mut text = format!("-P {chain} DROP\n");
            for rule in rules {
                text.push_str(&format!("-A {chain} {}\n", rule.join(" ")));
            }
            return Ok(output(0, &text, ""));
        }
        let insertion = op == "-I";
        let body = args[start + if insertion { 3 } else { 2 }..].to_vec();
        if op == "-C" {
            if ipv6 && self.fail_ipv6_drop && body == ["-j", "DROP"] {
                return Ok(output(1, "", ""));
            }
            let hook = body.iter().any(|s| s.starts_with("QELI_KS_"));
            if hook && self.hook_fault {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "hook query deadline",
                ));
            }
            if !hook {
                if let Some(message) = self.query_fault.take() {
                    return Ok(output(4, "", message));
                }
            }
            return Ok(output(u32::from(!rules.contains(&body)), "", ""));
        }
        if op == "-D" {
            if self.delete_fault == Some(ipv6)
                || (self.fail_mark_delete && body.iter().any(|s| s == "MARK"))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "delete blocked",
                ));
            }
            if !self.lie_delete {
                if let Some(index) = rules.iter().position(|rule| rule == &body) {
                    rules.remove(index);
                }
            }
            return Ok(output(0, "", ""));
        }
        assert!(op == "-A" || insertion, "{args:?}");
        if !self.lie_add && !(self.fail_nat_add && body.iter().any(|s| s == "MASQUERADE")) {
            let index = if insertion {
                args[start + 2].parse::<usize>().unwrap() - 1
            } else {
                rules.len()
            };
            rules.insert(index.min(rules.len()), body);
        }
        if self.lost_add {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "completion lost"));
        }
        Ok(output(0, "", ""))
    }
    fn sysctl(&mut self, op: Operation<'_>) -> io::Result<String> {
        assert!(
            ROUTER_OPERATION.try_lock().is_err(),
            "sysctl operation escaped serialization"
        );
        match op {
            Operation::Acquire(path, value, tun) => {
                assert!(path.starts_with("/proc/sys/net/"));
                if let Some(namespace) = self.lose_after_acquire.take() {
                    let evidence = identity::test_support::evidence(tun);
                    let mut evidence = evidence.lock().unwrap();
                    if namespace {
                        evidence.namespace = false;
                    } else {
                        evidence.tunnel = false;
                    }
                }
                if self.fail_acquire {
                    return Err(io::Error::other("acquire failed"));
                }
                self.leases
                    .entry(tun.into())
                    .or_default()
                    .push(format!("{path}={value}"));
            }
            Operation::Read(path) => {
                assert!(path.starts_with("/proc/sys/net/"));
                return Ok("1\n".into());
            }
            Operation::Release(tun) => {
                self.releases.push(tun.into());
                if self.fail_release {
                    return Err(io::Error::other("restore failed"));
                }
                self.leases.remove(tun);
            }
        }
        Ok(String::new())
    }
    fn count(&self, ipv6: bool, tun: &str) -> usize {
        self.rules
            .iter()
            .filter(|((family, _, _), _)| *family == ipv6)
            .flat_map(|(_, rules)| rules)
            .filter(|rule| rule.iter().any(|s| s == tun))
            .count()
    }
    fn mutations(&self) -> usize {
        self.calls
            .iter()
            .filter(|args| {
                args.iter()
                    .any(|s| ["-A", "-I", "-D", "-N", "-F", "-X"].contains(&s.as_str()))
            })
            .count()
    }
}
fn reset_gateway_state() {
    kill_switch::ownership::test_support::clear();
    EXIT_WANS_V4
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    EXIT_WANS_V6
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    GATEWAY_SCOPES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}
fn run(test: impl FnOnce(Rc<RefCell<Kernel>>)) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            reset_gateway_state();
        }
    }
    reset_gateway_state();
    let _reset = Reset;
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    let commands = kernel.clone();
    let knobs = kernel.clone();
    with_commands(
        move |cmd| {
            let result = commands.borrow_mut().command(cmd);
            let args = arguments(cmd);
            let mut kernel = commands.borrow_mut();
            if kernel
                .move_wan_after_command
                .as_ref()
                .is_some_and(|(token, _)| args.contains(token))
            {
                let (_, wan) = kernel.move_wan_after_command.take().unwrap();
                kernel.wans
                    [usize::from(cmd.get_program().to_string_lossy().ends_with("ip6tables"))] =
                    Some(wan);
            }
            if kernel
                .lose_after_command
                .as_ref()
                .is_some_and(|(token, _)| args.contains(token))
            {
                let (_, namespace) = kernel.lose_after_command.take().unwrap();
                let evidence = identity::test_support::evidence("gw_a");
                let mut evidence = evidence.lock().unwrap();
                if namespace {
                    evidence.namespace = false;
                } else {
                    evidence.tunnel = false;
                }
            }
            if kernel
                .lose_kill_namespace_after
                .as_ref()
                .is_some_and(|token| args.contains(token))
            {
                kernel.lose_kill_namespace_after = None;
                kill_switch::ownership::test_support::set_namespace(2);
            }
            if kernel
                .delay_once
                .as_ref()
                .is_some_and(|(token, _)| args.contains(token))
            {
                let (_, delay) = kernel.delay_once.take().unwrap();
                std::thread::sleep(delay);
            }
            Action::Reply(result)
        },
        || {
            kill_switch::ipv6_state::test_support::with_disabled(false, || {
                with_sysctls(
                    move |op| knobs.borrow_mut().sysctl(op),
                    || {
                        identity::test_support::with_owners(|| {
                            kill_switch::ownership::test_support::with_namespace(
                                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
                                || test(kernel),
                            )
                        })
                    },
                );
            });
        },
    );
}
fn engage_family(tun: &str, ipv6: bool) {
    if ipv6 {
        engage_ipv6(tun, "fd20::/64", true).unwrap();
    } else {
        engage(tun, "10.20.0.0/24", true).unwrap();
    }
}
fn cleanup(tun: &str) -> anyhow::Result<()> {
    disengage_plan(tun)
}
fn sibling_cleanup(ipv6: bool) {
    run(|kernel| {
        engage_family("gw_a", ipv6);
        engage_family("gw_b", ipv6);
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(ipv6, "gw_a"), 0);
        assert_eq!(kernel.borrow().count(ipv6, "gw_b"), 4);
        cleanup("gw_b").unwrap();
        assert_eq!(
            kernel.borrow().count(ipv6, "gw_b"),
            0,
            "sibling rules leaked"
        );
    });
}
#[test]
fn regression_ipv4_siblings_both_clean_up() {
    sibling_cleanup(false);
}
#[test]
fn regression_ipv6_siblings_both_clean_up() {
    sibling_cleanup(true);
}

#[test]
fn regression_inactive_tun_cleanup_cannot_clear_another_scope() {
    run(|kernel| {
        engage_family("gw_a", false);
        cleanup("unused").unwrap();
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
    });
}
#[test]
fn regression_changed_lan_subnet_is_removed_from_saved_state() {
    run(|kernel| {
        engage("gw_a", "10.19.0.0/24", true).unwrap();
        engage_family("gw_a", false);
        assert_eq!(kernel.borrow().count(false, "gw_a"), 5);
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
    });
}
#[test]
fn regression_failed_scope_survives_sibling_cleanup_for_retry() {
    run(|kernel| {
        engage_family("gw_a", false);
        engage_family("gw_b", false);
        kernel.borrow_mut().delete_fault = Some(false);
        assert!(cleanup("gw_a").is_err());
        kernel.borrow_mut().delete_fault = None;
        cleanup("gw_b").unwrap();
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
    });
}
#[test]
fn regression_unknown_rule_snapshot_never_authorizes_add() {
    run(|kernel| {
        kernel.borrow_mut().query_fault = Some("iptables: Permission denied");
        assert!(!ensure_rule(
            &Context::forward("gw_a", Budget::new()).unwrap(),
            "iptables",
            "gw_a",
            "nat",
            "POSTROUTING",
            &masq_rule("gw_a", "")
        ));
        assert_eq!(kernel.borrow().mutations(), 0);
    });
}
#[test]
fn regression_unknown_kill_switch_snapshot_never_authorizes_permit() {
    run(|kernel| {
        kernel.borrow_mut().rules.insert(
            (false, "filter".into(), "FORWARD".into()),
            vec![vec!["-j".into(), "QELI_KS_gw_a".into()]],
        );
        kernel.borrow_mut().hook_fault = true;
        assert!(!ensure_rule(
            &Context::forward("gw_a", Budget::new()).unwrap(),
            "iptables",
            "gw_a",
            "filter",
            "FORWARD",
            &fwd_out("gw_a")
        ));
        assert_eq!(
            kernel.borrow().mutations(),
            0,
            "permit inserted ahead of protection"
        );
    });
}

#[test]
fn both_families_are_cleaned_and_sysctls_released() {
    run(|kernel| {
        engage_family("gw_a", false);
        engage_family("gw_a", true);
        cleanup("gw_a").unwrap();
        let k = kernel.borrow();
        assert_eq!(k.count(false, "gw_a") + k.count(true, "gw_a"), 0);
        assert!(k.leases.is_empty());
        assert_eq!(k.releases, ["gw_a"]);
    });
}
#[test]
fn failed_family_does_not_skip_other_family_or_sysctl_restore() {
    run(|kernel| {
        engage_family("gw_a", false);
        engage_family("gw_a", true);
        kernel.borrow_mut().delete_fault = Some(false);
        assert!(cleanup("gw_a").is_err());
        assert_eq!(kernel.borrow().count(true, "gw_a"), 0);
        assert_eq!(kernel.borrow().count(false, "gw_a"), 4);
        assert!(kernel.borrow().leases.is_empty());
        kernel.borrow_mut().delete_fault = None;
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
    });
}
#[test]
fn lying_delete_retains_cleanup_failure_until_absence_is_confirmed() {
    run(|kernel| {
        engage_family("gw_a", false);
        kernel.borrow_mut().lie_delete = true;
        assert!(cleanup("gw_a").is_err());
        assert_eq!(kernel.borrow().count(false, "gw_a"), 4);
        kernel.borrow_mut().lie_delete = false;
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
    });
}
#[test]
fn sysctl_restore_failure_is_reported_and_retryable() {
    run(|kernel| {
        engage_family("gw_a", false);
        kernel.borrow_mut().fail_release = true;
        assert!(cleanup("gw_a").is_err());
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
        assert!(!kernel.borrow().leases.is_empty());
        kernel.borrow_mut().fail_release = false;
        cleanup("gw_a").unwrap();
        assert!(kernel.borrow().leases.is_empty());
    });
}
#[test]
fn failed_forwarding_acquire_rolls_back_without_rule_mutation() {
    run(|kernel| {
        kernel.borrow_mut().fail_acquire = true;
        assert!(engage("gw_a", "", true).is_err());
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().mutations(), 0);
        assert_eq!(kernel.borrow().releases, ["gw_a"]);
    });
}
#[test]
fn lying_add_is_rejected_and_partial_sysctls_are_released() {
    run(|kernel| {
        kernel.borrow_mut().lie_add = true;
        assert!(engage("gw_a", "", true).is_err());
        disengage_plan("gw_a").unwrap();
        assert!(kernel.borrow().leases.is_empty());
    });
}
#[test]
fn permit_remains_after_first_kill_switch_jump() {
    run(|kernel| {
        kernel.borrow_mut().rules.insert(
            (false, "filter".into(), "FORWARD".into()),
            vec![vec!["-j".into(), "QELI_KS_gw_a".into()]],
        );
        assert!(ensure_rule(
            &Context::forward("gw_a", Budget::new()).unwrap(),
            "iptables",
            "gw_a",
            "filter",
            "FORWARD",
            &fwd_out("gw_a")
        ));
        let k = kernel.borrow();
        let rules = &k.rules[&(false, "filter".into(), "FORWARD".into())];
        assert_eq!(rules[0], ["-j", "QELI_KS_gw_a"]);
        assert_eq!(rules[1], fwd_out("gw_a"));
    });
}
#[test]
fn permit_with_absent_kill_switch_is_installed_and_verified() {
    run(|kernel| {
        assert!(ensure_rule(
            &Context::forward("gw_a", Budget::new()).unwrap(),
            "iptables",
            "gw_a",
            "filter",
            "FORWARD",
            &fwd_out("gw_a")
        ));
        assert_eq!(kernel.borrow().count(false, "gw_a"), 1);
    });
}
#[test]
fn misplaced_kill_switch_refuses_new_permit() {
    run(|kernel| {
        kernel.borrow_mut().rules.insert(
            (false, "filter".into(), "FORWARD".into()),
            vec![
                vec!["-j".into(), "DROP".into()],
                vec!["-j".into(), "QELI_KS_gw_a".into()],
            ],
        );
        assert!(!ensure_rule(
            &Context::forward("gw_a", Budget::new()).unwrap(),
            "iptables",
            "gw_a",
            "filter",
            "FORWARD",
            &fwd_out("gw_a")
        ));
        assert_eq!(kernel.borrow().mutations(), 0);
    });
}
#[test]
fn observed_rule_after_lost_add_completion_is_still_cleaned() {
    run(|kernel| {
        kernel.borrow_mut().lost_add = true;
        engage_family("gw_a", false);
        kernel.borrow_mut().lost_add = false;
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
    });
}

#[test]
fn regression_existing_permit_ahead_of_kill_switch_is_not_accepted() {
    run(|kernel| {
        kernel.borrow_mut().rules.insert(
            (false, "filter".into(), "FORWARD".into()),
            vec![
                fwd_out("gw_a").iter().map(|s| s.to_string()).collect(),
                vec!["-j".into(), "QELI_KS_gw_a".into()],
            ],
        );
        assert!(!ensure_rule(
            &Context::forward("gw_a", Budget::new()).unwrap(),
            "iptables",
            "gw_a",
            "filter",
            "FORWARD",
            &fwd_out("gw_a")
        ));
        assert_eq!(kernel.borrow().mutations(), 0);
    });
}

#[test]
fn unchanged_plan_reuses_rules_and_cleanup_is_idempotent() {
    run(|kernel| {
        engage_family("gw_a", false);
        let mutations = kernel.borrow().mutations();
        engage_family("gw_a", false);
        assert_eq!(kernel.borrow().mutations(), mutations);
        cleanup("gw_a").unwrap();
        let calls = kernel.borrow().calls.len();
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().calls.len(), calls);
        assert!(GATEWAY_SCOPES.lock().unwrap().is_empty());
    });
}
#[test]
fn routing_without_nat_is_still_owned_and_removed() {
    run(|kernel| {
        engage("gw_a", "", false).unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 3);
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
    });
}
#[test]
fn cleanup_preserves_untagged_administrator_rule_on_same_tun() {
    run(|kernel| {
        let foreign = vec!["-o".into(), "gw_a".into(), "-j".into(), "ACCEPT".into()];
        kernel.borrow_mut().rules.insert(
            (false, "filter".into(), "FORWARD".into()),
            vec![foreign.clone()],
        );
        engage_family("gw_a", false);
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 1);
        assert_eq!(
            kernel.borrow().rules[&(false, "filter".into(), "FORWARD".into())],
            [foreign]
        );
    });
}
#[test]
fn ipv6_unknown_rule_snapshot_cannot_authorize_nat66() {
    run(|kernel| {
        kernel.borrow_mut().query_fault = Some("ip6tables: backend unavailable");
        assert!(!ensure_rule(
            &Context::forward("gw_a", Budget::new()).unwrap(),
            "ip6tables",
            "gw_a",
            "nat",
            "POSTROUTING",
            &masq_rule("gw_a", "")
        ));
        assert_eq!(kernel.borrow().mutations(), 0);
    });
}
#[test]
fn firewall_and_sysctl_cleanup_errors_are_both_reported() {
    run(|kernel| {
        engage_family("gw_a", false);
        kernel.borrow_mut().delete_fault = Some(false);
        kernel.borrow_mut().fail_release = true;
        let error = cleanup("gw_a").unwrap_err().to_string();
        assert!(error.contains("delete blocked"), "{error}");
        assert!(error.contains("restore failed"), "{error}");
        kernel.borrow_mut().delete_fault = None;
        kernel.borrow_mut().fail_release = false;
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
        assert!(kernel.borrow().leases.is_empty());
    });
}
#[test]
fn rollback_after_later_rule_failure_removes_already_installed_nat() {
    run(|kernel| {
        kernel.borrow_mut().hook_fault = true;
        assert!(engage("gw_a", "10.20.0.0/24", true).is_err());
        assert_eq!(kernel.borrow().count(false, "gw_a"), 2); // NAT + optional MSS
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
        assert!(kernel.borrow().leases.is_empty());
    });
}

#[test]
fn inactive_exit_refresh_does_not_wait_for_another_router_operation() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let operation = router_operation(Budget::new()).unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        send.send(refresh_exit_paths_if_active("ordinary_noexit"))
            .unwrap();
    });
    let result = receive.recv_timeout(std::time::Duration::from_secs(2));
    drop(operation);
    worker.join().unwrap();
    result
        .expect("ordinary path commit blocked behind unrelated router cleanup")
        .unwrap();
}

#[test]
fn ipv6_gateway_rejects_ecmp_before_forwarding_or_ownership() {
    run(|kernel| {
        kernel.borrow_mut().wans[1] =
            Some("wan0\n\tnexthop via 198.51.100.1 dev wan1 weight 1".into());
        let error = engage_ipv6("gw0", "fd20::/64", true).unwrap_err();
        assert!(error.to_string().contains("multiple preferred default WAN"));
        assert_eq!(kernel.borrow().mutations(), 0);
        assert!(!GATEWAY_SCOPES.lock().unwrap().contains_key("gw0"));
    });
}
#[path = "exit_tests.rs"]
mod exit_tests;

#[path = "kill_switch_tests.rs"]
mod kill_switch_tests;

#[path = "identity_tests.rs"]
mod identity_tests;

#[path = "owner_tests.rs"]
mod owner_tests;

#[path = "budget_tests.rs"]
mod budget_tests;
