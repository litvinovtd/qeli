//! A separate scoped guard survives VPN/reconciler restarts. On OpenWrt it is
//! also installed before network startup. It never changes INPUT/admin access.
use super::*;
use process::{command, output};
const TAG: &str = "qeli-router-guard-v1";
const TABLE: &str = "qeli_router_guard";
fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}
fn locals(p: &Policy) -> impl Iterator<Item = &String> {
    p.local_subnets
        .iter()
        .chain(p.networks.iter().flat_map(|n| n.subnets.iter()))
}
fn nft_rules(p: &Policy, authenticated: bool, usable: bool) -> String {
    let mut text=format!("table inet {TABLE} {{\n comment \"{TAG}\"\n chain protect {{\n type filter hook forward priority -20; policy accept;\n");
    for n in &p.networks {
        if n.policy == NetworkPolicy::Direct {
            continue;
        }
        // Reply direction only: DNAT admission remains with the platform. This
        // cannot exempt a new WAN connection initiated by a VPN-only client.
        text.push_str(&format!(
            " iifname \"{}\" ct direction reply return\n",
            n.device
        ));
        for prefix in locals(p) {
            text.push_str(&format!(
                " iifname \"{}\" {} daddr {} return\n",
                n.device,
                if prefix.contains(':') { "ip6" } else { "ip" },
                prefix
            ));
        }
        if n.policy == NetworkPolicy::VpnOnly {
            text.push_str(&if usable {
                format!(
                    " iifname \"{}\" oifname != \"{}\" counter drop\n",
                    n.device, p.device
                )
            } else {
                format!(" iifname \"{}\" counter drop\n", n.device)
            });
        } else {
            text.push_str(&if usable {
                format!(
                    " iifname \"{}\" meta nfproto ipv6 oifname != \"{}\" counter drop\n",
                    n.device, p.device
                )
            } else {
                format!(" iifname \"{}\" meta nfproto ipv6 counter drop\n", n.device)
            });
        }
    }
    text.push_str(" }\n");
    if p.router_policy == Some(NetworkPolicy::VpnOnly) {
        text.push_str(" chain router_guard {\n type filter hook output priority -20; policy accept;\n oifname \"lo\" return\n ct direction reply return\n");
        text.push_str(control::nft());
        for u in &p.uplinks {
            for ip in &u.probes {
                text.push_str(&format!(
                    " oifname \"{}\" {} daddr {} {} type echo-request return\n",
                    u.device,
                    if ip.is_ipv6() { "ip6" } else { "ip" },
                    ip,
                    if ip.is_ipv6() { "icmpv6" } else { "icmp" }
                ));
            }
        }
        for ip in &p.server_addresses {
            text.push_str(&format!(
                " {} daddr {} return\n",
                if ip.is_ipv6() { "ip6" } else { "ip" },
                ip
            ));
        }
        for prefix in locals(p) {
            text.push_str(&format!(
                " {} daddr {} return\n",
                if prefix.contains(':') { "ip6" } else { "ip" },
                prefix
            ));
        }
        if authenticated {
            text.push_str(&format!(" oifname \"{}\" return\n", p.device));
        }
        text.push_str(" counter drop\n }\n");
    }
    text.push_str(" chain translate {\n type nat hook postrouting priority 99; policy accept;\n");
    for n in &p.networks {
        if n.policy == NetworkPolicy::Direct {
            continue;
        }
        for prefix in &n.subnets {
            text.push_str(&format!(
                " {} saddr {} oifname \"{}\" masquerade\n",
                if prefix.contains(':') { "ip6" } else { "ip" },
                prefix,
                p.device
            ));
        }
    }
    text.push_str(" }\n}\n");
    text
}
fn iptables_rules(p: &Policy, authenticated: bool, usable: bool, v6: bool) -> String {
    let mut text = String::from(
        "*filter\n:QELI_G_FWD - [0:0]\n:QELI_G_OUT - [0:0]\n-F QELI_G_FWD\n-F QELI_G_OUT\n",
    );
    let tag = format!("-m comment --comment {TAG}");
    for n in &p.networks {
        if n.policy == NetworkPolicy::Direct {
            continue;
        }
        text.push_str(&format!(
            "-A QELI_G_FWD -i {} -m conntrack --ctdir REPLY {tag} -j RETURN\n",
            n.device
        ));
        for prefix in locals(p).filter(|s| s.contains(':') == v6) {
            text.push_str(&format!(
                "-A QELI_G_FWD -i {} -d {} {tag} -j RETURN\n",
                n.device, prefix
            ));
        }
        if n.policy == NetworkPolicy::VpnOnly || v6 {
            text.push_str(&if usable {
                format!(
                    "-A QELI_G_FWD -i {} ! -o {} {tag} -j DROP\n",
                    n.device, p.device
                )
            } else {
                format!("-A QELI_G_FWD -i {} {tag} -j DROP\n", n.device)
            });
        }
    }
    if p.router_policy == Some(NetworkPolicy::VpnOnly) {
        text.push_str(&format!("-A QELI_G_OUT -o lo {tag} -j RETURN\n-A QELI_G_OUT -m conntrack --ctdir REPLY {tag} -j RETURN\n"));
        text.push_str(&control::iptables("QELI_G_OUT", v6, &tag));
        for u in &p.uplinks {
            for ip in u.probes.iter().filter(|ip| ip.is_ipv6() == v6) {
                text.push_str(&format!(
                    "-A QELI_G_OUT -o {} -d {} -p {} {} echo-request {tag} -j RETURN\n",
                    u.device,
                    ip,
                    if v6 { "ipv6-icmp" } else { "icmp" },
                    if v6 { "--icmpv6-type" } else { "--icmp-type" }
                ));
            }
        }
        for ip in p.server_addresses.iter().filter(|ip| ip.is_ipv6() == v6) {
            text.push_str(&format!("-A QELI_G_OUT -d {ip} {tag} -j RETURN\n"));
        }
        for prefix in locals(p).filter(|s| s.contains(':') == v6) {
            text.push_str(&format!("-A QELI_G_OUT -d {prefix} {tag} -j RETURN\n"));
        }
        if authenticated {
            text.push_str(&format!("-A QELI_G_OUT -o {} {tag} -j RETURN\n", p.device));
        }
        text.push_str(&format!("-A QELI_G_OUT {tag} -j DROP\n"));
    }
    text.push_str(&format!("-A QELI_G_FWD {tag} -j RETURN\n-A QELI_G_OUT {tag} -j RETURN\nCOMMIT\n*nat\n:QELI_G_NAT - [0:0]\n-F QELI_G_NAT\n"));
    for n in &p.networks {
        if n.policy == NetworkPolicy::Direct {
            continue;
        }
        for prefix in n.subnets.iter().filter(|s| s.contains(':') == v6) {
            text.push_str(&format!(
                "-A QELI_G_NAT -s {prefix} -o {} {tag} -j MASQUERADE\n",
                p.device
            ));
        }
    }
    text.push_str(&format!("-A QELI_G_NAT {tag} -j RETURN\nCOMMIT\n"));
    text
}
async fn owned_nft() -> Result<Option<Vec<u8>>> {
    let json = match command("nft", &["-j", "list", "table", "inet", TABLE]).await {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let value: Value = serde_json::from_slice(&json)?;
    ensure!(
        value["nftables"]
            .as_array()
            .context("nft table inventory")?
            .iter()
            .any(|v| v["table"]["name"] == TABLE && v["table"]["comment"] == TAG),
        "foreign scoped-guard table; refusing to replace/delete it"
    );
    Ok(Some(
        command("nft", &["-s", "list", "table", "inet", TABLE]).await?,
    ))
}
async fn owned_chain(tool: &str, table: &str, chain: &str) -> Result<bool> {
    let text = match command(tool, &["-w", "2", "-t", table, "-S", chain]).await {
        Ok(v) => String::from_utf8(v)?,
        Err(_) => return Ok(false),
    };
    let rules = text
        .lines()
        .filter(|l| l.starts_with("-A "))
        .collect::<Vec<_>>();
    ensure!(
        !rules.is_empty()
            && rules.iter().all(|line| line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|v| v[0] == "--comment" && v[1].trim_matches('"') == TAG)),
        "foreign/empty rule in a Qeli scoped-guard chain"
    );
    Ok(true)
}
pub(super) async fn preflight(p: &Policy) -> Result<()> {
    if p.components.firewall != Owner::Client {
        return Ok(());
    }
    if p.backend == "nft" {
        let existing = owned_nft().await?.is_some();
        let rules = nft_rules(p, false, false);
        let rules = if existing {
            format!("delete table inet {TABLE}\n{rules}")
        } else {
            rules
        };
        output(
            "nft",
            &args(&["--check", "-f", "-"]),
            Some(rules.as_bytes()),
            5,
        )
        .await?;
    } else {
        for (tool, restore, v6) in [
            ("iptables", "iptables-restore", false),
            ("ip6tables", "ip6tables-restore", true),
        ] {
            for (table, chain) in [
                ("filter", "QELI_G_FWD"),
                ("filter", "QELI_G_OUT"),
                ("nat", "QELI_G_NAT"),
            ] {
                owned_chain(tool, table, chain).await?;
            }
            output(
                restore,
                &args(&["--test", "--noflush"]),
                Some(iptables_rules(p, false, false, v6).as_bytes()),
                5,
            )
            .await?;
        }
    }
    Ok(())
}
pub(super) async fn remove(p: &Policy) -> Result<()> {
    if p.backend == "nft" {
        if owned_nft().await?.is_some() {
            command("nft", &["delete", "table", "inet", TABLE]).await?;
        }
    } else {
        for tool in ["iptables", "ip6tables"] {
            for (table, base, chain) in [
                ("filter", "FORWARD", "QELI_G_FWD"),
                ("filter", "OUTPUT", "QELI_G_OUT"),
                ("nat", "POSTROUTING", "QELI_G_NAT"),
            ] {
                if !owned_chain(tool, table, chain).await? {
                    continue;
                }
                let hook = [
                    "-w",
                    "2",
                    "-t",
                    table,
                    "-C",
                    base,
                    "-m",
                    "comment",
                    "--comment",
                    TAG,
                    "-j",
                    chain,
                ];
                if command(tool, &hook).await.is_ok() {
                    let mut remove = hook;
                    remove[4] = "-D";
                    command(tool, &remove).await?;
                }
                command(tool, &["-w", "2", "-t", table, "-F", chain]).await?;
                command(tool, &["-w", "2", "-t", table, "-X", chain]).await?;
            }
        }
    }
    Ok(())
}
#[derive(Default)]
pub(super) struct Guard {
    key: Option<String>,
    actual: Option<Vec<u8>>,
}
impl Guard {
    pub(super) async fn sync(
        &mut self,
        p: &Policy,
        authenticated: bool,
        usable: bool,
    ) -> Result<()> {
        if p.components.firewall == Owner::External {
            remove(p).await?;
            self.key = None;
            self.actual = None;
            return Ok(());
        }
        let key = serde_json::to_string(&(p, authenticated, usable))?;
        if p.backend == "nft" {
            let actual = owned_nft().await?;
            if self.key.as_ref() == Some(&key) && actual == self.actual {
                return Ok(());
            }
            let rules = nft_rules(p, authenticated, usable);
            let rules = if actual.is_some() {
                format!("delete table inet {TABLE}\n{rules}")
            } else {
                rules
            };
            output(
                "nft",
                &args(&["--check", "-f", "-"]),
                Some(rules.as_bytes()),
                5,
            )
            .await?;
            output("nft", &args(&["-f", "-"]), Some(rules.as_bytes()), 5).await?;
            self.actual = owned_nft().await?;
        } else {
            for (tool, restore, v6) in [
                ("iptables", "iptables-restore", false),
                ("ip6tables", "ip6tables-restore", true),
            ] {
                for (table, chain) in [
                    ("filter", "QELI_G_FWD"),
                    ("filter", "QELI_G_OUT"),
                    ("nat", "QELI_G_NAT"),
                ] {
                    owned_chain(tool, table, chain).await?;
                }
                let rules = iptables_rules(p, authenticated, usable, v6);
                output(
                    restore,
                    &args(&["--test", "--noflush"]),
                    Some(rules.as_bytes()),
                    5,
                )
                .await?;
                output(restore, &args(&["--noflush"]), Some(rules.as_bytes()), 5).await?;
                for (table, base, chain) in [
                    ("filter", "FORWARD", "QELI_G_FWD"),
                    ("filter", "OUTPUT", "QELI_G_OUT"),
                    ("nat", "POSTROUTING", "QELI_G_NAT"),
                ] {
                    if command(
                        tool,
                        &[
                            "-w",
                            "2",
                            "-t",
                            table,
                            "-C",
                            base,
                            "-m",
                            "comment",
                            "--comment",
                            TAG,
                            "-j",
                            chain,
                        ],
                    )
                    .await
                    .is_err()
                    {
                        command(
                            tool,
                            &[
                                "-w",
                                "2",
                                "-t",
                                table,
                                "-I",
                                base,
                                "1",
                                "-m",
                                "comment",
                                "--comment",
                                TAG,
                                "-j",
                                chain,
                            ],
                        )
                        .await?;
                    }
                }
            }
        }
        self.key = Some(key);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cold_guard_never_opens_input_and_blocks_without_status() {
        let mut p = Policy::default();
        p.networks.push(Network {
            device: "br-vpn".into(),
            subnets: vec!["10.80.0.0/24".into()],
            policy: NetworkPolicy::VpnOnly,
        });
        let rules = nft_rules(&p, false, false);
        assert!(!rules.contains("hook input"));
        assert!(rules.contains("iifname \"br-vpn\" counter drop"));
        assert!(!rules.contains("ct state established accept"));
        let rules = nft_rules(&p, true, true);
        assert!(rules.contains("oifname != \"qeli0\" counter drop"));
    }
}
