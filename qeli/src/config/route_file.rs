//! Portable route-file grammar. Reading paths and applying routes remain OS operations.
use crate::transport_core::network::NumericCidr;
use std::{collections::HashSet, net::Ipv4Addr};

pub fn parse_lines(lines: &[String], source: &str, offset: u64) -> anyhow::Result<Vec<String>> {
    let mut result = vec![];
    let mut seen = HashSet::new();
    for (index, raw) in lines.iter().enumerate() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parsed = (|| -> anyhow::Result<String> {
            let fields: Vec<_> = line.split_whitespace().collect();
            let kind = fields[0].to_ascii_lowercase();
            // route_file is an inclusion list. Ignoring this OpenVPN gateway
            // would reverse the operator's intent and send bypass traffic into VPN.
            if matches!(kind.as_str(), "route" | "route-ipv6") {
                anyhow::ensure!(
                    !fields.iter().skip(2).any(|f| f.trim_matches(['\'', '"']).eq_ignore_ascii_case("net_gateway")),
                    "net_gateway routes bypass the VPN and cannot be imported into route_file; move this network to [qeli] exclude instead"
                );
            }
            let candidate = if kind == "route" {
                anyhow::ensure!(fields.len() >= 2, "route has no network");
                if fields[1].contains('/') {
                    fields[1].to_string()
                } else if fields.len() >= 3 {
                    let mask = u32::from(
                        fields[2]
                            .parse::<Ipv4Addr>()
                            .map_err(|_| anyhow::anyhow!("invalid IPv4 netmask"))?,
                    );
                    let bits = mask.leading_ones();
                    anyhow::ensure!(
                        mask == if bits == 0 {
                            0
                        } else {
                            u32::MAX << (32 - bits)
                        },
                        "invalid IPv4 netmask"
                    );
                    let address = fields[1].parse::<Ipv4Addr>()?;
                    format!("{address}/{bits}")
                } else {
                    format!("{}/32", fields[1].parse::<Ipv4Addr>()?)
                }
            } else if kind == "route-ipv6" {
                anyhow::ensure!(fields.len() >= 2, "route-ipv6 has no CIDR");
                fields[1].to_string()
            } else {
                fields[0].to_string()
            };
            Ok(NumericCidr::parse(&candidate)?.render())
        })()
        .map_err(|e| {
            anyhow::anyhow!(
                "{source}:{}: {e}",
                offset.saturating_add(index as u64).saturating_add(1)
            )
        })?;
        if seen.insert(parsed.clone()) {
            result.push(parsed);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bypass_for_both_families_with_source_and_batch_line() {
        for route in [
            "route 192.0.2.0 255.255.255.0 net_gateway",
            "route 192.0.2.0/24 NET_GATEWAY 5",
            "route 192.0.2.0 255.255.255.0 \"net_gateway\"",
            "route-ipv6 2001:db8::/32 'net_gateway'",
            "route-ipv6 2001:db8::/32 net_gateway",
        ] {
            let error = parse_lines(&["# comment".into(), route.into()], "corp.txt", 512)
                .unwrap_err()
                .to_string();
            assert!(error.starts_with("corp.txt:514:"), "{error}");
            assert!(error.contains("exclude"), "{error}");
        }
    }

    #[test]
    fn accepts_inclusions_and_ignores_gateway_words_inside_comments() {
        let lines = [
            "route 192.0.2.0 255.255.255.0 vpn_gateway 5",
            "192.0.2.0/24 # net_gateway",
            "route-ipv6 2001:db8::/32 ; net_gateway",
        ]
        .map(str::to_string);
        assert_eq!(
            parse_lines(&lines, "routes", 0).unwrap(),
            ["192.0.2.0/24", "2001:db8::/32"]
        );
    }

    #[test]
    fn desktop_policy_boundary_returns_no_partial_inclusion_set() {
        let request = serde_json::json!({"operation":"route_file", "data": {
            "source":"corp.txt", "offset":512,
            "lines":["192.0.2.0/24", "route 198.51.100.0 255.255.255.0 net_gateway"]
        }});
        let error = crate::config::policy::execute(&request)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("corp.txt:514:"));
        assert!(error.contains("exclude"));
    }
}
