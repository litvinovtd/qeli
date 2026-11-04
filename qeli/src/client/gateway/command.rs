//! Bounded firewall installation with readback, actionable errors and lock-only retry.
use std::{io, process::Output};

fn lock_busy(output: &Output) -> bool {
    let text = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    output.status.code() == Some(4)
        && text.contains("xtables lock")
        && (text.contains("holding") || text.contains("resource temporarily unavailable"))
        && !text.contains("permission denied")
        && !text.contains("you must be root")
        && !text.contains("couldn't load")
}

fn category(output: &Output) -> &'static str {
    let text = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if text.contains("permission denied") || text.contains("you must be root") {
        "permission-denied"
    } else if lock_busy(output) {
        "xtables-lock-busy"
    } else if text.contains("couldn't load match") || text.contains("couldn't load target") {
        "missing-match-or-target"
    } else if text.contains("unknown option") || text.contains("unrecognized option") {
        "unsupported-option"
    } else {
        "firewall-command-failed"
    }
}

fn excerpt(bytes: &[u8]) -> String {
    let value = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
    let mut text = value.trim().escape_debug().to_string();
    if bytes.len() > 4096 {
        text.push_str(" [truncated]");
    }
    text
}

fn failure(path: &str, args: &[&str], output: &Output) -> String {
    format!(
        "{path} {}: {} ({}); stderr=\"{}\"; stdout=\"{}\"",
        args.join(" "),
        category(output),
        output.status,
        excerpt(&output.stderr),
        excerpt(&output.stdout)
    )
}

fn execute(
    path: &str,
    args: &[&str],
    run: &mut impl FnMut(&[&str]) -> io::Result<Output>,
) -> anyhow::Result<Output> {
    run(args).map_err(|error| {
        anyhow::anyhow!(
            "{path} {}: command execution failed ({:?}): {error}",
            args.join(" "),
            error.kind()
        )
    })
}

pub(super) fn present(
    path: &str,
    args: &[&str],
    mut run: impl FnMut(&[&str]) -> io::Result<Output>,
    mut pause: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<bool> {
    for attempt in 1..=3 {
        let output = execute(path, args, &mut run)?;
        let result = crate::firewall_check::present(
            &output,
            crate::firewall_check::Query::Rule {
                missing_target: super::expected_qeli_chain(args),
            },
        );
        match result {
            Ok(present) => return Ok(present),
            Err(_) => {
                // Keep the bounded, escaped original output; the parser's error
                // repeats raw stderr and must not defeat this diagnostic limit.
                let problem = format!(
                    "inspection could not establish rule presence: {}",
                    failure(path, args, &output)
                );
                if attempt == 3 || !lock_busy(&output) {
                    anyhow::bail!("{problem}");
                }
                log::warn!(
                    "temporary firewall inspection lock contention, attempt {attempt}/3: {problem}"
                );
                pause().map_err(|error| {
                    anyhow::anyhow!("{problem}; retry cancelled or deadline exhausted: {error}")
                })?;
            }
        }
    }
    unreachable!()
}

// Caller already observed absence and established the safe insertion position.
// Never retry an ambiguous spawn/deadline failure: the child may have mutated state.
pub(super) fn install(
    path: &str,
    add: &[&str],
    check: &[&str],
    mut run: impl FnMut(&[&str]) -> io::Result<Output>,
    mut pause: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    for attempt in 1..=3 {
        if attempt > 1 && present(path, check, &mut run, &mut pause)? {
            return Ok(());
        }
        let output = match execute(path, add, &mut run) {
            Ok(output) => output,
            Err(problem) => {
                // Completion can be lost after the kernel accepted the rule. Inspect
                // under the same owner/deadline, but never issue a second mutation.
                return match present(path, check, &mut run, &mut pause) {
                    Ok(true) => {
                        log::warn!("firewall rule verified after lost completion: {problem}");
                        Ok(())
                    }
                    Ok(false) => Err(problem),
                    Err(error) => Err(anyhow::anyhow!("{problem}; readback failed: {error}")),
                };
            }
        };
        let problem = failure(path, add, &output);
        let present = present(path, check, &mut run, &mut pause)
            .map_err(|error| anyhow::anyhow!("{problem}; readback failed: {error}"))?;
        if present {
            if !output.status.success() {
                log::warn!("firewall rule verified despite command failure (possible concurrent installation): {problem}");
            }
            return Ok(());
        }
        if output.status.success() {
            anyhow::bail!(
                "{problem}; command reported success but exact rule is absent on readback"
            );
        }
        // An insertion position is security-sensitive and may change while waiting.
        // Only append rules can reuse this command; do not retry cached -I positions.
        if attempt == 3 || add.contains(&"-I") || !lock_busy(&output) {
            anyhow::bail!("{problem}; exact rule absent; attempt {attempt}/3");
        }
        log::warn!("temporary firewall lock contention, attempt {attempt}/3: {problem}");
        pause().map_err(|error| {
            anyhow::anyhow!("{problem}; retry cancelled or deadline exhausted: {error}")
        })?;
    }
    unreachable!()
}

// Delete one exact owned rule. The caller inventories/removes any duplicates.
// A nonzero status is not silently repeated eight times as if it were success.
pub(super) fn remove_one(
    path: &str,
    delete: &[&str],
    check: &[&str],
    mut run: impl FnMut(&[&str]) -> io::Result<Output>,
    mut pause: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    for attempt in 1..=3 {
        if attempt > 1 && !present(path, check, &mut run, &mut pause)? {
            return Ok(());
        }
        let result = execute(path, delete, &mut run);
        if result.as_ref().is_ok_and(|output| output.status.success()) {
            return Ok(());
        }
        let retry = result.as_ref().is_ok_and(lock_busy);
        let problem = match result {
            Ok(output) => failure(path, delete, &output),
            Err(error) => error.to_string(),
        };
        if !present(path, check, &mut run, &mut pause)
            .map_err(|error| anyhow::anyhow!("{problem}; cleanup readback failed: {error}"))?
        {
            return Ok(());
        }
        if attempt == 3 || !retry {
            anyhow::bail!("{problem}; owned rule still present after deletion attempt {attempt}/3");
        }
        log::warn!("temporary firewall cleanup lock contention, attempt {attempt}/3: {problem}");
        pause().map_err(|error| {
            anyhow::anyhow!("{problem}; cleanup retry cancelled or deadline exhausted: {error}")
        })?;
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    const ADD: &[&str] = &[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-o",
        "vpn0",
        "-j",
        "MASQUERADE",
        "-m",
        "comment",
        "--comment",
        "qeli-gw-nat",
    ];
    const CHECK: &[&str] = &[
        "-t",
        "nat",
        "-C",
        "POSTROUTING",
        "-o",
        "vpn0",
        "-j",
        "MASQUERADE",
        "-m",
        "comment",
        "--comment",
        "qeli-gw-nat",
    ];
    fn output(code: u32, stderr: &str) -> Output {
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
            stderr: stderr.as_bytes().to_vec(),
            stdout: vec![],
        }
    }
    fn miss() -> Output {
        output(1, "iptables: No chain/target/match by that name.")
    }
    fn busy() -> Output {
        output(4, "Another app is currently holding the xtables lock. Perhaps you want to use the -w option?")
    }
    #[test]
    fn inspection_retries_only_explicit_temporary_lock_not_absence_or_permissions() {
        let mut replies = VecDeque::from([busy(), miss()]);
        let mut waits = 0;
        assert!(!present(
            "/opt/sbin/iptables",
            CHECK,
            |_| Ok(replies.pop_front().unwrap()),
            || {
                waits += 1;
                Ok(())
            }
        )
        .unwrap());
        assert!(replies.is_empty());
        assert_eq!(waits, 1);
        let error = present(
            "iptables",
            CHECK,
            |_| {
                Ok(output(
                    4,
                    "Permission denied while inspecting xtables lock held by another app",
                ))
            },
            || panic!("permission error is not transient"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("permission-denied"));
        assert!(!present(
            "iptables",
            CHECK,
            |_| Ok(miss()),
            || panic!("absence needs no retry")
        )
        .unwrap());
    }
    fn fixture(values: Vec<Output>) -> (anyhow::Result<()>, Vec<Vec<String>>, usize) {
        let mut replies: VecDeque<_> = values.into();
        let mut calls = Vec::new();
        let mut waits = 0;
        let result = install(
            "/opt/sbin/iptables",
            ADD,
            CHECK,
            |args| {
                calls.push(args.iter().map(|s| s.to_string()).collect());
                Ok(replies.pop_front().expect("unexpected command"))
            },
            || {
                waits += 1;
                Ok(())
            },
        );
        assert!(replies.is_empty());
        (result, calls, waits)
    }
    #[test]
    fn missing_comment_and_permissions_keep_original_error_and_do_not_retry() {
        for (code, message, kind) in [
            (
                2,
                "iptables v1.4.21: Couldn't load match `comment':No such file or directory",
                "missing-match-or-target",
            ),
            (
                2,
                "iptables: Couldn't load target `MASQUERADE':No such file or directory",
                "missing-match-or-target",
            ),
            (
                1,
                "iptables: Permission denied (you must be root)",
                "permission-denied",
            ),
            (
                2,
                "iptables: unknown option --comment",
                "unsupported-option",
            ),
            (
                4,
                "iptables: kernel backend unavailable",
                "firewall-command-failed",
            ),
        ] {
            let (result, calls, waits) = fixture(vec![output(code, message), miss()]);
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("/opt/sbin/iptables -t nat -A POSTROUTING"),
                "{error}"
            );
            assert!(
                error.contains(kind) && error.contains("MASQUERADE"),
                "{error}"
            );
            assert!(error.contains(&excerpt(message.as_bytes())), "{error}");
            assert_eq!((calls.len(), waits), (2, 0));
        }
    }
    #[test]
    fn temporary_lock_retries_with_readback_and_exact_same_tagged_rule() {
        let (result, calls, waits) =
            fixture(vec![busy(), miss(), miss(), output(0, ""), output(0, "")]);
        result.unwrap();
        assert_eq!(waits, 1);
        assert_eq!(calls[0], calls[3]);
        assert_eq!(calls[1], calls[2]);
        assert!(calls
            .iter()
            .all(|args| args.iter().any(|s| s == "qeli-gw-nat")));
    }
    #[test]
    fn lock_retries_are_limited() {
        let (result, _, waits) = fixture(vec![
            busy(),
            miss(),
            miss(),
            busy(),
            miss(),
            miss(),
            busy(),
            miss(),
        ]);
        assert!(result.unwrap_err().to_string().contains("attempt 3/3"));
        assert_eq!(waits, 2);
    }
    #[test]
    fn concurrent_installation_is_not_duplicated() {
        let (result, calls, waits) = fixture(vec![busy(), miss(), output(0, "")]);
        result.unwrap();
        assert_eq!((calls.len(), waits), (3, 1));
        fixture(vec![output(1, "concurrent insertion"), output(0, "")])
            .0
            .unwrap();
    }
    #[test]
    fn success_requires_readback_and_preserves_add_error_on_inspection_failure() {
        let error = fixture(vec![output(0, ""), miss()])
            .0
            .unwrap_err()
            .to_string();
        assert!(error.contains("reported success but exact rule is absent"));
        let error = fixture(vec![
            output(2, "missing extension"),
            output(1, "Permission denied"),
        ])
        .0
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("missing extension")
                && error.contains("Permission denied")
                && error.contains("readback failed")
        );
    }
    #[test]
    fn spawn_timeout_or_owner_loss_never_retries_a_mutation() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Interrupted,
        ] {
            let mut calls = 0;
            let error = install(
                "/opt/sbin/iptables",
                ADD,
                CHECK,
                |_| {
                    calls += 1;
                    Err(io::Error::new(kind, "fixture owner/deadline failure"))
                },
                || panic!("must not retry"),
            )
            .unwrap_err()
            .to_string();
            assert_eq!(calls, 2); // one mutation attempt, one read-only verification
            assert!(
                error.contains("command execution failed") && error.contains("/opt/sbin/iptables")
            );
        }
    }
    #[test]
    fn lost_completion_is_accepted_only_after_successful_readback() {
        let mut calls = 0;
        install(
            "iptables",
            ADD,
            CHECK,
            |args| {
                calls += 1;
                if args == ADD {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "completion lost"))
                } else {
                    Ok(output(0, ""))
                }
            },
            || panic!("must not retry"),
        )
        .unwrap();
        assert_eq!(calls, 2);
    }
    #[test]
    fn security_sensitive_insert_position_is_not_reused_after_lock_contention() {
        let mut replies = VecDeque::from([busy(), miss()]);
        let error = install(
            "iptables",
            &["-t", "filter", "-I", "FORWARD", "2", "-j", "ACCEPT"],
            CHECK,
            |_| Ok(replies.pop_front().unwrap()),
            || panic!("must not retry cached insertion position"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("xtables-lock-busy") && replies.is_empty());
    }
    #[test]
    fn cancellation_or_deadline_during_lock_wait_stops_before_next_add() {
        let mut replies = VecDeque::from([busy(), miss()]);
        let error = install(
            "iptables",
            ADD,
            CHECK,
            |_| Ok(replies.pop_front().unwrap()),
            || anyhow::bail!("router deadline expired"),
        )
        .unwrap_err()
        .to_string();
        assert!(replies.is_empty());
        assert!(error.contains("xtables-lock-busy") && error.contains("router deadline expired"));
    }
    #[test]
    fn diagnostics_are_bounded_and_control_characters_are_escaped() {
        let error = failure(
            "iptables",
            ADD,
            &output(2, &format!("bad\n\r\x1b{}", "x".repeat(9000))),
        );
        assert!(error.len() < 5000 && error.contains("[truncated]"));
        assert!(!error.contains(['\n', '\r', '\x1b']));
    }
    #[test]
    fn cleanup_keeps_delete_stderr_and_does_not_repeat_permanent_failure() {
        let mut replies = VecDeque::from([
            output(1, "iptables: Permission denied deleting owned rule"),
            output(0, ""),
        ]);
        let error = remove_one(
            "/opt/sbin/iptables",
            &["-t", "nat", "-D", "POSTROUTING"],
            CHECK,
            |_| Ok(replies.pop_front().unwrap()),
            || panic!("permanent error is not retryable"),
        )
        .unwrap_err()
        .to_string();
        assert!(replies.is_empty());
        assert!(
            error.contains("-D POSTROUTING")
                && error.contains("permission-denied")
                && error.contains("Permission denied deleting owned rule")
        );
    }
    #[test]
    fn cleanup_retries_lock_but_does_not_delete_again_after_lost_completion() {
        let mut replies = VecDeque::from([busy(), output(0, ""), output(0, ""), output(0, "")]);
        let mut waits = 0;
        remove_one(
            "iptables",
            &["-D", "POSTROUTING"],
            CHECK,
            |_| Ok(replies.pop_front().unwrap()),
            || {
                waits += 1;
                Ok(())
            },
        )
        .unwrap();
        assert!(replies.is_empty());
        assert_eq!(waits, 1);
        let mut calls = 0;
        remove_one(
            "iptables",
            &["-D", "POSTROUTING"],
            CHECK,
            |args| {
                calls += 1;
                if args == CHECK {
                    Ok(miss())
                } else {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "completion lost"))
                }
            },
            || panic!("must not delete again"),
        )
        .unwrap();
        assert_eq!(calls, 2);
    }
    #[test]
    fn inspection_error_output_is_bounded_even_when_parser_repeats_it() {
        let error = present(
            "iptables",
            CHECK,
            |_| {
                Ok(output(
                    1,
                    &format!("Permission denied\n{}", "x".repeat(100000)),
                ))
            },
            || panic!("must not retry"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.len() < 6000 && error.contains("truncated") && !error.contains('\n'));
    }
}
