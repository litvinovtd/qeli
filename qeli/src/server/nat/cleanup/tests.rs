use super::*;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;

fn output(success: bool, stdout: impl Into<Vec<u8>>, stderr: &str) -> Output {
    Output {
        status: std::process::ExitStatus::from_raw(if success { 0 } else { 256 }),
        stdout: stdout.into(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[derive(Clone)]
struct Rule {
    table: &'static str,
    chain: &'static str,
    spec: Vec<String>,
}

impl Rule {
    fn new(table: &'static str, chain: &'static str, comment: &str) -> Self {
        Self {
            table,
            chain,
            spec: ["-m", "comment", "--comment", comment, "-j", "ACCEPT"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }
    fn line(&self) -> String {
        let spec = self
            .spec
            .iter()
            .map(|arg| format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(" ");
        format!("-A {} {spec}\n", self.chain)
    }
}

#[derive(Default)]
struct Firewall {
    rules: Vec<Rule>,
    calls: Vec<Vec<String>>,
    no_op: bool,
}

impl Firewall {
    fn run(&mut self, args: &[&str]) -> std::io::Result<Output> {
        // A broken algorithm fails the fixture instead of hanging the test process.
        assert!(
            self.calls.len() < 4096,
            "cleanup exceeded fixture command budget"
        );
        self.calls
            .push(args.iter().map(|arg| arg.to_string()).collect());
        match args[2] {
            "-S" => {
                let mut listing = format!("-P {} ACCEPT\n", args[3]);
                for rule in self
                    .rules
                    .iter()
                    .filter(|r| r.table == args[1] && r.chain == args[3])
                {
                    listing.push_str(&rule.line());
                }
                Ok(output(true, listing, ""))
            }
            "-D" => {
                let position = self
                    .rules
                    .iter()
                    .position(|r| r.table == args[1] && r.chain == args[3] && r.spec == args[4..])
                    .expect("only rules from the listing may be deleted");
                if !self.no_op {
                    self.rules.remove(position);
                }
                Ok(output(true, "", ""))
            }
            _ => panic!("cleanup must never install or flush rules"),
        }
    }
    fn cleanup(&mut self, needle: &str, exact: bool) -> anyhow::Result<()> {
        cleanup_matching_with(needle, exact, |args| self.run(args))
    }
}

#[test]
fn empty_cleanup_checks_every_chain_once() {
    let mut firewall = Firewall::default();
    firewall.cleanup("qeli-nat:edge", true).unwrap();
    assert_eq!(firewall.calls.len(), 5);
    assert!(firewall.calls.iter().all(|call| call[2] == "-S"));
}

#[test]
fn exact_cleanup_preserves_other_profiles_and_admin_rules_in_every_chain() {
    let mut firewall = Firewall::default();
    for (table, chain) in CHAINS {
        for tag in ["qeli-nat:edge", "qeli-nat:edge2", "admin qeli-nat:edge"] {
            firewall.rules.push(Rule::new(table, chain, tag));
        }
    }
    firewall.cleanup("qeli-nat:edge", true).unwrap();
    assert_eq!(firewall.rules.len(), 10);
    assert!(firewall.rules.iter().all(|r| r.spec[3] != "qeli-nat:edge"));
    let calls = firewall.calls.len();
    firewall.cleanup("qeli-nat:edge", true).unwrap();
    assert_eq!(
        firewall.calls.len() - calls,
        5,
        "idempotent repeated cleanup"
    );
}

#[test]
fn startup_prefix_cleanup_preserves_unowned_comments() {
    let mut firewall = Firewall::default();
    for tag in [
        "qeli-nat:edge",
        "qeli-nat:edge2",
        "admin qeli-nat:edge",
        "qeli-nat",
    ] {
        firewall.rules.push(Rule::new("filter", "INPUT", tag));
    }
    firewall.cleanup("qeli-nat:", false).unwrap();
    assert_eq!(firewall.rules.len(), 2);
    assert_eq!(firewall.rules[0].spec[3], "admin qeli-nat:edge");
    assert_eq!(firewall.rules[1].spec[3], "qeli-nat");
}

#[test]
fn quoted_comment_is_replayed_as_one_argument() {
    let tag = "qeli-nat:edge 'one' \"two\" \\ exit";
    let mut firewall = Firewall::default();
    firewall.rules.push(Rule::new("filter", "FORWARD", tag));
    firewall.cleanup(tag, true).unwrap();
    assert!(firewall.rules.is_empty());
    let deletion = firewall.calls.iter().find(|call| call[2] == "-D").unwrap();
    assert_eq!(deletion[7], tag);
}

#[test]
fn more_than_64_duplicates_are_all_removed_without_repeated_full_scans() {
    let mut firewall = Firewall {
        rules: vec![Rule::new("filter", "FORWARD", "qeli-nat:edge"); 129],
        ..Default::default()
    };
    firewall.cleanup("qeli-nat:edge", true).unwrap();
    assert!(firewall.rules.is_empty());
    assert_eq!(firewall.calls.iter().filter(|c| c[2] == "-D").count(), 129);
    assert_eq!(firewall.calls.iter().filter(|c| c[2] == "-S").count(), 6);
}

#[test]
fn successful_no_op_delete_returns_error_instead_of_looping() {
    let mut firewall = Firewall {
        no_op: true,
        ..Default::default()
    };
    firewall
        .rules
        .push(Rule::new("nat", "POSTROUTING", "qeli-nat:edge"));
    let error = firewall
        .cleanup("qeli-nat:edge", true)
        .unwrap_err()
        .to_string();
    assert!(error.contains("nat/POSTROUTING"), "{error}");
    assert!(error.contains("1 owned rules remain"), "{error}");
    assert_eq!(firewall.calls.len(), 7);
}

#[test]
fn failed_delete_does_not_skip_other_rules_or_chains() {
    let mut firewall = Firewall::default();
    firewall
        .rules
        .push(Rule::new("nat", "POSTROUTING", "qeli-nat:broken"));
    firewall
        .rules
        .push(Rule::new("nat", "POSTROUTING", "qeli-nat:good"));
    firewall
        .rules
        .push(Rule::new("mangle", "FORWARD", "qeli-nat:good"));
    let error = cleanup_matching_with("qeli-nat:", false, |args| {
        if args[2] == "-D" && args.contains(&"qeli-nat:broken") {
            return Ok(output(false, "", "fixture permission failure"));
        }
        firewall.run(args)
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("fixture permission failure"), "{error}");
    assert!(error.contains("1 owned rules remain"), "{error}");
    assert_eq!(firewall.rules.len(), 1);
    // A later retry retains the rule's exact ownership and can succeed.
    firewall.cleanup("qeli-nat:", false).unwrap();
    assert!(firewall.rules.is_empty());
}

#[test]
fn failed_listing_is_reported_and_later_chains_are_still_cleaned() {
    for io_failure in [false, true] {
        let mut firewall = Firewall::default();
        firewall
            .rules
            .push(Rule::new("mangle", "FORWARD", "qeli-nat:edge"));
        let error = cleanup_matching_with("qeli-nat:edge", true, |args| {
            if args[1] == "nat" && args[3] == "POSTROUTING" {
                if io_failure {
                    return Err(std::io::Error::other("fixture spawn failure"));
                }
                return Ok(output(false, "", "fixture listing failure"));
            }
            firewall.run(args)
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("nat/POSTROUTING"), "{error}");
        assert!(
            error.contains(if io_failure {
                "fixture spawn failure"
            } else {
                "fixture listing failure"
            }),
            "{error}"
        );
        assert!(firewall.rules.is_empty());
    }
}

#[test]
fn malformed_listing_never_deletes_a_partial_snapshot() {
    let good = Rule::new("nat", "POSTROUTING", "qeli-nat:edge").line();
    for tail in [
        b"-A POSTROUTING --comment \"unfinished".as_slice(),
        b"\xff",
        b"-A INPUT --comment qeli-nat:edge",
        b"unexpected output",
    ] {
        let mut calls = Vec::new();
        let error = cleanup_matching_with("qeli-nat:edge", true, |args| {
            calls.push(args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            let listing = if args[1] == "nat" && args[3] == "POSTROUTING" {
                [good.as_bytes(), tail].concat()
            } else {
                Vec::new()
            };
            Ok(output(true, listing, ""))
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("nat/POSTROUTING"), "{error}");
        assert_eq!(calls.len(), 5);
        assert!(calls.iter().all(|call| call[2] == "-S"));
    }
}

#[test]
fn failed_verification_is_not_reported_as_success() {
    let mut firewall = Firewall::default();
    firewall
        .rules
        .push(Rule::new("nat", "POSTROUTING", "qeli-nat:edge"));
    let mut reads = 0;
    let error = cleanup_matching_with("qeli-nat:edge", true, |args| {
        if args[2] == "-S" && args[3] == "POSTROUTING" {
            reads += 1;
            if reads == 2 {
                return Ok(output(false, "", "fixture verification failure"));
            }
        }
        firewall.run(args)
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("verify"), "{error}");
    assert!(error.contains("fixture verification failure"), "{error}");
    assert_eq!(firewall.calls.last().unwrap()[1], "mangle");
}

#[test]
fn concurrent_owned_rule_addition_is_reported_without_chasing_it_forever() {
    let mut firewall = Firewall::default();
    firewall
        .rules
        .push(Rule::new("nat", "POSTROUTING", "qeli-nat:edge"));
    let error = cleanup_matching_with("qeli-nat:edge", true, |args| {
        let result = firewall.run(args);
        if args[2] == "-D" {
            firewall
                .rules
                .push(Rule::new("nat", "POSTROUTING", "qeli-nat:edge"));
        }
        result
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("1 owned rules remain"), "{error}");
    assert_eq!(firewall.calls.len(), 7);
}

#[test]
fn errors_keep_multiple_chain_contexts_and_bound_repeated_diagnostics() {
    let error = cleanup_matching_with("qeli-nat:", false, |_| {
        Ok(output(false, "", "fixture unavailable"))
    })
    .unwrap_err()
    .to_string();
    for (table, chain) in CHAINS {
        assert!(error.contains(&format!("{table}/{chain}")), "{error}");
    }
    let mut errors = Errors::default();
    for _ in 0..100 {
        errors.record("delete", Err(anyhow::anyhow!("{}", "e".repeat(4096))));
    }
    let error = errors.finish().unwrap_err().to_string();
    assert!(error.len() < 17000);
    assert!(error.contains("92 additional cleanup errors"));
}

#[test]
fn comment_parser_does_not_confuse_substrings_or_broken_quotes() {
    assert_eq!(
        rule_comment("-A INPUT --comment \"qeli-nat:edge with spaces\" -j ACCEPT").as_deref(),
        Some("qeli-nat:edge with spaces")
    );
    assert_eq!(rule_comment("-A INPUT --comment \"unfinished"), None);
    assert_eq!(rule_comment("-A INPUT --commentary qeli-nat:edge"), None);
}

fn check_output(present: bool) -> Output {
    let mut result = output(true, "", "");
    if !present {
        #[cfg(unix)]
        {
            result.status = std::process::ExitStatus::from_raw(1 << 8);
        }
        #[cfg(windows)]
        {
            result.status = std::process::ExitStatus::from_raw(1);
        }
        result.stderr = b"iptables: Bad rule (does a matching rule exist in that chain?).".to_vec();
    }
    result
}

fn exact_rule() -> Vec<String> {
    [
        "-i",
        "tun0",
        "-s",
        "10.42.0.0/24",
        "-d",
        "10.42.0.1",
        "-p",
        "udp",
        "--dport",
        "53",
        "-m",
        "comment",
        "--comment",
        "qeli-nat:edge",
        "-j",
        "ACCEPT",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[test]
fn exact_cleanup_uses_only_check_and_delete_with_identical_ownership() {
    let rule = exact_rule();
    let mut remaining = 3;
    let mut calls = Vec::new();
    cleanup_exact_rules_with("filter", "INPUT", [("udp", rule.as_slice())], |args| {
        assert_eq!(&args[..2], &["-t", "filter"]);
        assert_eq!(args[3], "INPUT");
        assert_eq!(args[4..], rule);
        calls.push(args[2].to_string());
        match args[2] {
            "-C" => Ok(check_output(remaining != 0)),
            "-D" => {
                remaining -= 1;
                Ok(output(true, "", ""))
            }
            _ => panic!("mixed native nft chains must never require -S"),
        }
    })
    .unwrap();
    assert_eq!(remaining, 0);
    assert_eq!(calls, ["-C", "-D", "-C", "-D", "-C", "-D", "-C"]);
}

#[test]
fn exact_cleanup_absence_is_idempotent_without_deleting() {
    let mut calls = 0;
    cleanup_exact_rules_with(
        "filter",
        "INPUT",
        [("udp", exact_rule().as_slice())],
        |args| {
            calls += 1;
            assert_eq!(args[2], "-C");
            Ok(check_output(false))
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
}

#[test]
fn exact_cleanup_rejects_failed_check_and_never_deletes_on_unknown_state() {
    for io_failure in [false, true] {
        let mut calls = 0;
        let error = cleanup_exact_rules_with(
            "filter",
            "INPUT",
            [("udp", exact_rule().as_slice())],
            |args| {
                calls += 1;
                assert_eq!(args[2], "-C");
                if io_failure {
                    return Err(std::io::Error::other("fixture spawn denied"));
                }
                let mut value = check_output(false);
                value.stderr = b"iptables: Permission denied (you must be root)".to_vec();
                Ok(value)
            },
        )
        .unwrap_err()
        .to_string();
        assert_eq!(calls, 1);
        assert!(
            error.contains(if io_failure {
                "fixture spawn denied"
            } else {
                "Permission denied"
            }),
            "{error}"
        );
        assert!(error.contains("udp"), "{error}");
    }
}

#[test]
fn exact_cleanup_checks_absence_after_exactly_1024_deletions() {
    let mut remaining = MAX_EXACT_RULE_COPIES;
    let mut checks = 0;
    cleanup_exact_rules_with(
        "filter",
        "INPUT",
        [("udp", exact_rule().as_slice())],
        |args| match args[2] {
            "-C" => {
                checks += 1;
                Ok(check_output(remaining > 0))
            }
            "-D" => {
                remaining -= 1;
                Ok(output(true, "", ""))
            }
            _ => panic!("unexpected command"),
        },
    )
    .unwrap();
    assert_eq!(remaining, 0);
    assert_eq!(checks, MAX_EXACT_RULE_COPIES + 1);
}

#[test]
fn exact_cleanup_stops_at_limit_if_rule_still_exists() {
    for no_op in [false, true] {
        let mut remaining = MAX_EXACT_RULE_COPIES + 1;
        let mut deletes = 0;
        let error = cleanup_exact_rules_with(
            "filter",
            "INPUT",
            [("udp", exact_rule().as_slice())],
            |args| match args[2] {
                "-C" => Ok(check_output(remaining > 0)),
                "-D" => {
                    deletes += 1;
                    assert!(deletes <= MAX_EXACT_RULE_COPIES, "cleanup must be finite");
                    if !no_op {
                        remaining -= 1;
                    }
                    Ok(output(true, "", ""))
                }
                _ => panic!("unexpected command"),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("still present after 1024"), "{error}");
        assert_eq!(deletes, MAX_EXACT_RULE_COPIES);
        assert_eq!(remaining, if no_op { MAX_EXACT_RULE_COPIES + 1 } else { 1 });
    }
}

#[test]
fn exact_cleanup_rejects_failed_final_check_after_deletion() {
    let mut checks = 0;
    let error = cleanup_exact_rules_with(
        "filter",
        "INPUT",
        [("udp", exact_rule().as_slice())],
        |args| {
            if args[2] == "-C" {
                checks += 1;
                if checks == 2 {
                    return Err(std::io::Error::other("fixture verification unavailable"));
                }
            }
            Ok(output(true, "", ""))
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("fixture verification unavailable"),
        "{error}"
    );
}

#[test]
fn exact_cleanup_continues_tcp_after_udp_check_or_delete_failure() {
    for fail_check in [true, false] {
        let udp = exact_rule();
        let mut tcp = udp.clone();
        tcp[7] = "tcp".into();
        let mut tcp_present = true;
        let error = cleanup_exact_rules_with(
            "filter",
            "INPUT",
            [("udp", udp.as_slice()), ("tcp", tcp.as_slice())],
            |args| {
                if args.contains(&"udp") {
                    if !fail_check && args[2] == "-C" {
                        return Ok(output(true, "", ""));
                    }
                    return Err(std::io::Error::other("fixture UDP command failure"));
                }
                assert!(args.contains(&"tcp"));
                match args[2] {
                    "-C" => Ok(check_output(tcp_present)),
                    "-D" => {
                        tcp_present = false;
                        Ok(output(true, "", ""))
                    }
                    _ => panic!("unexpected command"),
                }
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("udp"), "{error}");
        assert!(error.contains("fixture UDP command failure"), "{error}");
        assert!(!tcp_present, "UDP failure must not skip TCP cleanup");
    }
}

#[test]
fn exact_cleanup_keeps_both_protocol_errors() {
    let udp = exact_rule();
    let tcp = exact_rule();
    let error = cleanup_exact_rules_with(
        "filter",
        "INPUT",
        [("udp", udp.as_slice()), ("tcp", tcp.as_slice())],
        |_| Ok(output(false, "", "fixture backend error")),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("udp:"), "{error}");
    assert!(error.contains("tcp:"), "{error}");
}

#[test]
fn final_owned_cleanup_attempts_every_sysctl_after_dns_and_profile_errors() {
    let calls = std::cell::RefCell::new(Vec::new());
    let error = super::finish_owned_cleanup_with(
        || {
            calls.borrow_mut().push("dns".to_string());
            anyhow::bail!("DNS denied")
        },
        &["first".into(), "second".into()],
        |profile| {
            calls.borrow_mut().push(profile.to_string());
            if profile == "first" {
                anyhow::bail!("restore denied");
            }
            Ok(())
        },
    )
    .unwrap_err()
    .to_string();
    assert_eq!(*calls.borrow(), ["dns", "first", "second"]);
    assert!(error.contains("DNS denied"), "{error}");
    assert!(
        error.contains("IPv6 sysctls/first: restore denied"),
        "{error}"
    );
}

#[test]
fn final_owned_cleanup_does_not_preserve_a_recovered_attempt_as_failure() {
    let attempts = std::cell::Cell::new(0);
    let mut release = |_: &str| {
        attempts.set(attempts.get() + 1);
        if attempts.get() == 1 {
            anyhow::bail!("transient lock failure");
        }
        Ok(())
    };
    let profiles = ["edge".into()];
    assert!(super::finish_owned_cleanup_with(|| Ok(()), &profiles, &mut release).is_err());
    assert!(super::finish_owned_cleanup_with(|| Ok(()), &profiles, &mut release).is_ok());
    assert_eq!(attempts.get(), 2);
}

#[test]
fn final_owned_cleanup_checks_dns_even_without_sysctl_leases() {
    let calls = std::cell::Cell::new(0);
    assert!(super::finish_owned_cleanup_with(
        || {
            calls.set(calls.get() + 1);
            Ok(())
        },
        &[],
        |_| panic!("no sysctl owners"),
    )
    .is_ok());
    assert_eq!(calls.get(), 1);
}

#[test]
fn final_owned_cleanup_bounds_diagnostics_but_still_attempts_every_profile() {
    let profiles: Vec<_> = (0..20).map(|i| format!("p{i}")).collect();
    let calls = std::cell::Cell::new(0);
    let error = super::finish_owned_cleanup_with(
        || Ok(()),
        &profiles,
        |_| {
            calls.set(calls.get() + 1);
            anyhow::bail!("denied");
        },
    )
    .unwrap_err()
    .to_string();
    assert_eq!(calls.get(), profiles.len());
    assert!(error.contains("12 additional cleanup errors"), "{error}");
}

#[test]
fn dns_ownership_survives_delete_timeout_before_or_after_mutation() {
    use crate::nat_dns_input::{DnsInputRegistry, DnsInputRules};
    for applied_before_timeout in [false, true] {
        let mut registry = DnsInputRegistry::default();
        let owned = DnsInputRules::new("edge", "tun0", "10.42.0.0/24", "10.42.0.1", 53).unwrap();
        let id = registry
            .begin(owned.clone(), |_| panic!("no pending owner"))
            .unwrap();
        let mut present = [true, true];
        let mut deletions = [0, 0];
        let error = registry
            .finish(id, |spec| {
                cleanup_exact_rules_with(
                    "filter",
                    "INPUT",
                    ["udp", "tcp"]
                        .into_iter()
                        .zip(spec.rules.iter().map(Vec::as_slice)),
                    |args| {
                        let proto = usize::from(args.contains(&"tcp"));
                        match args[2] {
                            "-C" => Ok(check_output(present[proto])),
                            "-D" => {
                                deletions[proto] += 1;
                                if proto == 0 {
                                    if applied_before_timeout {
                                        present[proto] = false;
                                    }
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        "system command timed out",
                                    ));
                                }
                                present[proto] = false;
                                Ok(output(true, "", ""))
                            }
                            _ => panic!("exact cleanup must not depend on listings"),
                        }
                    },
                )
            })
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
        assert!(!present[1], "UDP timeout must not skip TCP cleanup");
        assert_eq!(deletions, [1, 1]);
        let mut retried = false;
        registry
            .finish_shutdown(|spec| {
                retried = true;
                assert_eq!(
                    *spec, owned,
                    "timeout must retain exact scope and rule specs"
                );
                cleanup_exact_rules_with(
                    "filter",
                    "INPUT",
                    ["udp", "tcp"]
                        .into_iter()
                        .zip(spec.rules.iter().map(Vec::as_slice)),
                    |args| {
                        let proto = usize::from(args.contains(&"tcp"));
                        match args[2] {
                            "-C" => Ok(check_output(present[proto])),
                            "-D" => {
                                deletions[proto] += 1;
                                present[proto] = false;
                                Ok(output(true, "", ""))
                            }
                            _ => panic!("unexpected command"),
                        }
                    },
                )
            })
            .unwrap();
        assert!(
            retried,
            "failed deletion must remain visible to the final pass"
        );
        assert_eq!(present, [false, false]);
        assert_eq!(deletions, [if applied_before_timeout { 1 } else { 2 }, 1]);
        registry
            .finish_shutdown(|_| panic!("already released"))
            .unwrap();
    }
}
