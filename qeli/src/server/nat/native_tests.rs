//! Run explicitly in an isolated Linux lab; no mutation precedes CLONE_NEWNET.
use super::*;

fn present(path: &str, rule: &Rule) -> anyhow::Result<bool> {
    let mut args = vec!["-t", rule.table, "-C", rule.chain];
    args.extend(rule.args.iter().map(String::as_str));
    crate::firewall_check::present(
        &ipt(path, &args)?,
        crate::firewall_check::Query::Rule {
            missing_target: None,
        },
    )
    .map_err(|error| anyhow::anyhow!("native rule check failed: {error}"))
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and iptables/ip6tables; isolated netns"]
fn native_exact_cleanup_removes_duplicates_both_families_and_preserves_sibling(
) -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        // SAFETY: only this new disposable thread changes namespace.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let v4 = iptables_path().ok_or_else(|| anyhow::anyhow!("iptables unavailable"))?;
        let v6 = ip6tables_path().ok_or_else(|| anyhow::anyhow!("ip6tables unavailable"))?;
        let make_rule =
            |profile: &str, table: &'static str, chain: &'static str, target: &str| Rule {
                table,
                chain,
                essential: true,
                args: vec![
                    "-m".into(),
                    "comment".into(),
                    "--comment".into(),
                    tag(profile),
                    "-j".into(),
                    target.into(),
                ],
            };
        let parent = make_rule("audit-owned", "filter", "FORWARD", "ACCEPT");
        let sibling = make_rule("audit-owned2", "filter", "FORWARD", "DROP");
        let nat = make_rule("audit-owned", "nat", "POSTROUTING", "MASQUERADE");
        {
            let _guard = firewall_program_lock().lock().unwrap();
            for (ipv6, path) in [(false, &v4), (true, &v6)] {
                for (profile, rule) in [
                    ("audit-owned", &parent),
                    ("audit-owned", &parent),
                    ("audit-owned2", &sibling),
                    ("audit-owned", &nat),
                ] {
                    anyhow::ensure!(
                        install_rule(
                            profile,
                            ipv6,
                            path,
                            rule,
                            Budget::for_operation("native setup")
                        )?,
                        "rule not installed"
                    );
                }
            }
            // Test the exact path itself, without a preceding successful -S tag sweep.
            retry_owned_rules(Some("audit-owned"), Budget::new())?;
            for path in [&v4, &v6] {
                anyhow::ensure!(!present(path, &parent)?);
                anyhow::ensure!(!present(path, &nat)?);
                anyhow::ensure!(present(path, &sibling)?);
            }
        }
        // Public cleanup must select the sibling exactly and remain idempotent.
        cleanup("audit-owned2")?;
        cleanup("audit-owned2")?;
        for path in [&v4, &v6] {
            anyhow::ensure!(!present(path, &sibling)?);
        }
        Ok(())
    })
    .join()
    .expect("native firewall test panicked")
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and iptables/ip6tables; isolated netns"]
fn native_dns_leases_install_and_remove_both_transports_without_foreign_deletion(
) -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        // SAFETY: only this disposable thread changes its network namespace.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        for (ipv6, pool, listen) in [
            (false, "192.0.2.0/24", "192.0.2.1"),
            (true, "2001:db8::/64", "2001:db8::1"),
        ] {
            let path = if ipv6 {
                ip6tables_path()
            } else {
                iptables_path()
            }
            .ok_or_else(|| anyhow::anyhow!("firewall tool unavailable"))?;
            let foreign = [
                "-m",
                "comment",
                "--comment",
                "audit-dns-foreign",
                "-j",
                "DROP",
            ];
            anyhow::ensure!(ipt(&path, &["-P", "INPUT", "DROP"])?.status.success());
            let mut insert = vec!["-A", "INPUT"];
            insert.extend(foreign);
            anyhow::ensure!(ipt(&path, &insert)?.status.success());
            let owned = DnsInputRules::new("audit-dns-deadline", "vpn0", pool, listen, 5353)?;
            let mut lease = enable_dns_input("audit-dns-deadline", "vpn0", pool, listen, 5353)?;
            for rule in &owned.rules {
                anyhow::ensure!(rule_present(&path, "filter", "INPUT", rule));
            }
            lease.cleanup()?;
            for rule in &owned.rules {
                let mut check = vec!["-t", "filter", "-C", "INPUT"];
                check.extend(rule.iter().map(String::as_str));
                anyhow::ensure!(!crate::firewall_check::present(
                    &ipt(&path, &check)?,
                    crate::firewall_check::Query::Rule {
                        missing_target: None
                    }
                )
                .map_err(anyhow::Error::msg)?);
            }
            let mut check = vec!["-C", "INPUT"];
            check.extend(foreign);
            anyhow::ensure!(ipt(&path, &check)?.status.success());
        }
        Ok(())
    })
    .join()
    .expect("native DNS test panicked")
}
