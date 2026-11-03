//! Interpret firewall inspection results consistently for server NAT and client teardown.
//! Exit 1 alone is not absence: iptables also uses it for backend/permission failures.
use std::process::Output;

#[derive(Clone, Copy)]
pub(crate) enum Query<'a> {
    Rule {
        missing_target: Option<&'a str>,
    },
    #[cfg(any(test, feature = "client"))]
    Chain(&'a str),
}

fn missing_named_chain(message: &str, expected: &str) -> bool {
    // Parse the diagnostic prefix before quotes: "Couldn't" itself has an apostrophe.
    // Chain names are case-sensitive, and `edge` must never match `edge2`.
    let lower = message.to_ascii_lowercase();
    for prefix in ["chain ", "couldn't load target "] {
        if !lower.starts_with(prefix) {
            continue;
        }
        let rest = &message[prefix.len()..];
        let Some(rest) = rest.strip_prefix(['\'', '`']) else {
            return false;
        };
        let Some((name, suffix)) = rest.split_once('\'') else {
            return false;
        };
        if name != expected {
            return false;
        }
        let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        return if prefix == "chain " {
            suffix == "does not exist"
        } else {
            suffix.trim_start_matches(':').trim() == "no such file or directory"
        };
    }
    false
}

fn diagnostic(stderr: &str) -> Option<&str> {
    let mut lines = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        // nft reports coexistence with legacy tables even for a valid absence
        // diagnostic. These exact advisory lines do not invalidate its own query;
        // they alone still cannot establish absence or mask another failure.
        .filter(|line| {
            !matches!(
            *line,
            "# Warning: iptables-legacy tables present, use iptables-legacy to see them"
                | "# Warning: ip6tables-legacy tables present, use ip6tables-legacy to see them"
        )
        });
    let line = lines.next()?;
    // xtables parameter errors can append this standard help line. Any other
    // warning/error is unknown, even if one line also mentions a missing rule.
    if lines.any(|line| {
        !matches!(
            line,
            "Try `iptables -h' or 'iptables --help' for more information."
                | "Try `ip6tables -h' or 'ip6tables --help' for more information."
        )
    }) {
        return None;
    }
    // Strip the tool/version prefix, not arbitrary text inside the diagnostic.
    let message = if line.starts_with("iptables:") || line.starts_with("ip6tables:") {
        line.split_once(':')?.1
    } else if line.starts_with("iptables v") || line.starts_with("ip6tables v") {
        line.split_once(": ")?.1
    } else {
        line
    };
    Some(message.trim().trim_end_matches('.'))
}

pub(crate) fn present(output: &Output, query: Query<'_>) -> anyhow::Result<bool> {
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let rule_query = matches!(query, Query::Rule { .. });
    let expected = match query {
        Query::Rule { missing_target } => missing_target,
        #[cfg(any(test, feature = "client"))]
        Query::Chain(chain) => Some(chain),
    };
    if output.status.code() == Some(1) {
        // Preserve silent -C misses used by existing legacy/wrapper integrations.
        // A failed -S listing without diagnostic text does not establish absence.
        if rule_query && stderr.trim().is_empty() {
            return Ok(false);
        }
        if let Some(message) = diagnostic(&stderr) {
            let message = message.to_ascii_lowercase();
            if message == "no chain/target/match by that name"
                || (rule_query
                    && matches!(
                        message.as_str(),
                        "bad rule (does a matching rule exist in that chain?)"
                            | "rule does not exist"
                    ))
            {
                return Ok(false);
            }
        }
    }
    if matches!(output.status.code(), Some(1 | 2))
        && expected.is_some_and(|chain| {
            diagnostic(&stderr).is_some_and(|message| missing_named_chain(message, chain))
        })
    {
        return Ok(false);
    }
    anyhow::bail!(
        "firewall inspection failed with {}: {}",
        output.status,
        stderr.trim()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;

    fn output(code: u32, stderr: &str) -> Output {
        #[cfg(unix)]
        let status = std::process::ExitStatus::from_raw((code as i32) << 8);
        #[cfg(windows)]
        let status = std::process::ExitStatus::from_raw(code);
        Output {
            status,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }
    const RULE: Query<'static> = Query::Rule {
        missing_target: None,
    };

    #[test]
    fn success_is_present_for_rule_and_chain() {
        for query in [RULE, Query::Chain("QELI_KS_edge")] {
            assert!(present(&output(0, ""), query).unwrap());
        }
    }
    #[test]
    fn silent_rule_miss_is_absent_but_silent_failed_listing_is_unknown() {
        assert!(!present(&output(1, ""), RULE).unwrap());
        assert!(present(&output(1, ""), Query::Chain("QELI_KS_edge")).is_err());
    }
    #[test]
    fn legacy_and_nft_rule_misses_are_recognized() {
        for stderr in [
            "iptables: Bad rule (does a matching rule exist in that chain?).",
            "ip6tables v1.8.11 (nf_tables): Bad rule (does a matching rule exist in that chain?).",
            "iptables: No chain/target/match by that name.",
            "iptables: Rule does not exist.",
        ] {
            assert!(!present(&output(1, stderr), RULE).unwrap(), "{stderr}");
        }
    }
    #[test]
    fn exact_legacy_coexistence_advice_preserves_explicit_absence() {
        for tool in ["iptables", "ip6tables"] {
            let warning =
                format!("# Warning: {tool}-legacy tables present, use {tool}-legacy to see them");
            for diagnostic in [
                format!("{tool}: No chain/target/match by that name."),
                format!("{tool} v1.8.11 (nf_tables): Chain 'QELI_KS_edge' does not exist"),
            ] {
                for stderr in [
                    format!("{warning}\n{diagnostic}"),
                    format!("{diagnostic}\n{warning}"),
                ] {
                    for query in [RULE, Query::Chain("QELI_KS_edge")] {
                        // Named diagnostics require an expected target.
                        if matches!(query, Query::Rule { .. }) && diagnostic.contains("Chain '") {
                            assert!(present(&output(1, &stderr), query).is_err());
                        } else {
                            assert!(!present(&output(1, &stderr), query).unwrap());
                        }
                    }
                }
            }
            let missing = format!("{tool}: Bad rule (does a matching rule exist in that chain?).");
            assert!(!present(&output(1, &format!("{warning}\n{missing}")), RULE).unwrap());
        }
    }
    #[test]
    fn coexistence_advice_never_masks_unknown_failed_inspection() {
        let warning = "# Warning: iptables-legacy tables present, use iptables-legacy to see them";
        let missing = "iptables: No chain/target/match by that name.";
        for stderr in [
            warning.to_owned(),
            format!("{warning}\niptables: Permission denied"),
            format!("{warning}\n{missing}\nError: meta sreg is not an immediate"),
            format!(
                "{warning}\n{missing}\niptables v1.8.11 (nf_tables): Parsing nftables rule failed"
            ),
            format!("{warning} (unrecognized suffix)\n{missing}"),
            format!("# Warning: unknown tables present\n{missing}"),
        ] {
            for query in [RULE, Query::Chain("QELI_KS_edge")] {
                assert!(present(&output(1, &stderr), query).is_err(), "{stderr}");
            }
        }
        for code in [2, 3, 4, 111, 137, 255] {
            assert!(present(&output(code, &format!("{warning}\n{missing}")), RULE).is_err());
        }
    }
    #[test]
    fn general_status_one_errors_are_not_absence() {
        for stderr in [
            "iptables: Permission denied (you must be root)",
            "iptables: Table does not exist",
            "iptables: backend unavailable",
            "iptables: Resource temporarily unavailable",
        ] {
            for query in [RULE, Query::Chain("QELI_KS_edge")] {
                let error = present(&output(1, stderr), query).unwrap_err().to_string();
                assert!(error.contains(stderr), "{error}");
            }
        }
    }
    #[test]
    fn error_codes_cannot_be_masked_by_absence_text() {
        for code in [2, 3, 4, 111, 137, 255] {
            assert!(present(
                &output(code, "iptables: No chain/target/match by that name."),
                RULE
            )
            .is_err());
        }
    }
    #[test]
    fn exact_qeli_target_diagnostics_survive_parameter_error_status() {
        for code in [1, 2] {
            for stderr in [
                "iptables v1.8.9 (legacy): Couldn't load target 'QELI_KS_edge':No such file or directory",
                "iptables v1.8.9 (legacy): Couldn't load target `QELI_KS_edge':No such file or directory\n\nTry `iptables -h' or 'iptables --help' for more information.\n",
                "ip6tables v1.8.11 (nf_tables): Chain 'QELI_KS_edge' does not exist",
            ] {
                for query in [Query::Rule { missing_target: Some("QELI_KS_edge") }, Query::Chain("QELI_KS_edge")] {
                    assert!(!present(&output(code, stderr), query).unwrap());
                }
                assert!(present(&output(code, stderr), RULE).is_err());
            }
        }
    }
    #[test]
    fn target_name_match_is_exact_and_case_sensitive() {
        for target in ["QELI_KS_edge2", "QELI_KS_Edge", "QELI_KS_other"] {
            let stderr = format!("iptables v1.8.11 (nf_tables): Chain '{target}' does not exist");
            assert!(present(
                &output(2, &stderr),
                Query::Rule {
                    missing_target: Some("QELI_KS_edge")
                }
            )
            .is_err());
        }
    }
    #[test]
    fn unrelated_target_failure_and_extra_diagnostics_remain_errors() {
        for stderr in [
            "iptables v1.8.9 (legacy): Couldn't load target 'MARK':No such file or directory",
            "iptables: Permission denied\niptables: No chain/target/match by that name.",
            "iptables: No chain/target/match by that name.\nbackend failed",
            "iptables: No chain/target/match by that name. Permission denied",
            "iptables v1.8.11 (nf_tables): Chain 'QELI_KS_edge' does not exist; backend failed",
        ] {
            assert!(present(
                &output(1, stderr),
                Query::Rule {
                    missing_target: Some("QELI_KS_edge")
                }
            )
            .is_err());
        }
    }
    #[test]
    fn invalid_diagnostic_bytes_do_not_confirm_absence() {
        let mut value = output(1, "iptables: No chain/target/match by that name.");
        value.stderr.push(0xff);
        assert!(present(&value, RULE).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn signal_termination_is_unknown_even_with_an_absence_message() {
        let mut value = output(0, "iptables: No chain/target/match by that name.");
        value.status = std::process::ExitStatus::from_raw(9);
        assert!(present(&value, RULE).is_err());
    }
}
