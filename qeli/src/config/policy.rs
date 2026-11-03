//! Portable policy calculations. Platform adapters supply facts and apply the result.
use crate::transport_core::network::{cidr_minus_excludes, NumericCidr};
use serde_json::{json, Value};
fn text<'a>(v: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing policy string"))
}
fn strings(v: &Value, key: &str) -> anyhow::Result<Vec<String>> {
    let a = v[key]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing policy list"))?;
    anyhow::ensure!(a.len() <= 4096, "too many policy inputs");
    a.iter()
        .map(|x| {
            x.as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow::anyhow!("invalid policy list element"))
        })
        .collect()
}
fn prefix(s: &str) -> anyhow::Result<NumericCidr> {
    if s.contains('/') {
        NumericCidr::parse(s)
    } else {
        let ip = s.parse::<std::net::IpAddr>()?;
        NumericCidr::parse(&format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
    }
}
fn subtract(s: &str, excludes: &[String]) -> anyhow::Result<Vec<String>> {
    let base = prefix(s)?;
    let e = excludes
        .iter()
        .map(|v| prefix(v))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(cidr_minus_excludes(&base.render(), &e)?
        .iter()
        .map(|p| p.render())
        .collect())
}
fn normalize_version(s: &str) -> String {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let s = s.split(['-', '+']).next().unwrap_or("");
    if s.is_empty() {
        "0".into()
    } else {
        s.to_string()
    }
}
fn compare_versions(a: &str, b: &str) -> i32 {
    let a = normalize_version(a);
    let b = normalize_version(b);
    let a: Vec<_> = a
        .split('.')
        .map(|n| n.parse::<i32>().unwrap_or(0))
        .collect();
    let b: Vec<_> = b
        .split('.')
        .map(|n| n.parse::<i32>().unwrap_or(0))
        .collect();
    for i in 0..a.len().max(b.len()) {
        match a.get(i).unwrap_or(&0).cmp(b.get(i).unwrap_or(&0)) {
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Greater => return 1,
            _ => {}
        }
    }
    0
}
pub fn execute(req: &Value) -> anyhow::Result<Value> {
    let d = &req["data"];
    let result = match req["operation"].as_str().unwrap_or("") {
        "version_normalize" => json!(normalize_version(text(d, "value")?)),
        "version_compare" => json!(compare_versions(text(d, "a")?, text(d, "b")?)),
        "backoff" => json!(reconnect_backoff(
            d["attempt"].as_i64().unwrap_or(0),
            d["base"].as_i64().unwrap_or(1000),
            d["cap"].as_i64().unwrap_or(60000)
        )),
        "jitter" => json!(reconnect_jitter(
            d["scheduled"].as_i64().unwrap_or(0),
            d["reduction"].as_i64()
        )),
        "lan_prefixes" => json!(LAN_BYPASS_PREFIXES
            .iter()
            .filter(|p| match d["family"].as_u64() {
                Some(4) => !p.contains(':'),
                Some(6) => p.contains(':'),
                _ => true,
            })
            .collect::<Vec<_>>()),
        "next_attempt" => json!(reconnect_next_attempt(
            d["attempt"].as_i64().unwrap_or(0),
            d["established"] == true,
            d["forced"] == true,
            d["connected_ms"].as_i64().unwrap_or(0),
        )),
        "retry_decision" => {
            let attempt = d["attempt"].as_i64().unwrap_or(0).max(0);
            let reason = reconnect_stop_reason(
                d["enabled"].as_bool().unwrap_or(true),
                d["max_retries"].as_i64().unwrap_or(-1),
                attempt,
            );
            let delay = if reason.is_some() {
                0
            } else {
                reconnect_delay(
                    attempt,
                    d["base"].as_i64().unwrap_or(1000),
                    d["cap"].as_i64().unwrap_or(60000),
                    d["elapsed_ms"].as_i64().unwrap_or(0),
                    if d["carrier_restored"] == true {
                        Some(0)
                    } else {
                        d["settling_cap"].as_i64()
                    },
                    d["reduction"].as_i64(),
                )
            };
            json!({"reason": reason, "attempt": attempt, "delay_ms": delay})
        }
        "full_tunnel" => json!(full_tunnel(
            d["gateway"] == true,
            d["mode"].as_str().unwrap_or("")
        )),
        "roaming_allowed" => json!(
            matches!(
                d["mode"]
                    .as_str()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str(),
                "auto" | "required"
            ) && d["local"].as_str().unwrap_or("").trim().is_empty()
                && d["port"]
                    .as_str()
                    .unwrap_or("0")
                    .trim()
                    .parse::<u16>()
                    .unwrap_or(u16::MAX)
                    == 0
        ),
        "private_update" => json!(
            d["full"] == true
                && d["captured"] == true
                && !["leak4", "leak6", "lan", "global_lan", "excluded"]
                    .iter()
                    .any(|k| d[*k] == true)
        ),
        "route_file" => json!(super::route_file::parse_lines(
            &strings(d, "lines")?,
            d["source"].as_str().unwrap_or("route_file"),
            d["offset"].as_u64().unwrap_or(0)
        )?),
        "host_prefix" => json!(
            if text(d, "value")?.parse::<std::net::IpAddr>()?.is_ipv4() {
                32
            } else {
                128
            }
        ),
        "sink" => json!(d["full"] == true && d["address"] == false && d["leak"] == false),
        "mtu" => {
            let n = d["value"].as_i64().unwrap_or(-1);
            json!(n == 0 || super::server::mtu_in_range(n))
        }
        "ip" => json!(text(d, "value")?.parse::<std::net::IpAddr>().is_ok()),
        "cidr" => json!(text(d, "value")?.parse::<ipnet::IpNet>().is_ok()),
        "subtract" => json!(subtract(text(d, "cidr")?, &strings(d, "excludes")?)?),
        "overlaps" => json!(prefix(text(d, "a")?)?.overlaps(prefix(text(d, "b")?)?)),
        "on_link" => {
            let a = prefix(text(d, "cidr")?)?;
            let b = prefix(text(d, "gateway")?)?;
            let n = d["prefix"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("missing prefix"))?;
            anyhow::ensure!(n <= b.bits as u64, "invalid on-link prefix");
            // Protect the gateway host itself, not every address in its on-link subnet.
            json!(a.bits == b.bits && a.prefix as u64 >= n && a.overlaps(b))
        }
        "installed" => {
            let installed = strings(d, "installed")?;
            let protected = strings(d, "protected")?;
            let excludes = strings(d, "excludes")?;
            let mut count = 0;
            for original in strings(d, "originals")? {
                let required = if protected.contains(&original) {
                    vec![original]
                } else {
                    subtract(&original, &excludes)?
                };
                if !required.is_empty() && required.iter().all(|x| installed.contains(x)) {
                    count += 1;
                }
            }
            json!(count)
        }
        "effective_excludes" => {
            let mut e = strings(d, "excludes")?;
            if d["full"].as_bool() == Some(true) && d["lan"].as_bool() == Some(true) {
                e.extend(LAN_BYPASS_PREFIXES.iter().map(|s| s.to_string()));
            }
            json!(e)
        }
        "private_prefixes" | "capture_prefixes" => {
            let roots =
                ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].map(|s| prefix(s).unwrap());
            let excludes = if d["excludes"].is_array() {
                strings(d, "excludes")?
                    .iter()
                    .map(|s| prefix(s))
                    .collect::<anyhow::Result<Vec<_>>>()?
            } else {
                vec![]
            };
            let mut result = vec![];
            for s in strings(d, "prefixes")? {
                let Ok(p) = prefix(&s) else { continue };
                if !roots.iter().any(|r| r.prefix <= p.prefix && r.overlaps(p)) {
                    continue;
                }
                if req["operation"] == "private_prefixes" {
                    result.push(p);
                } else if let Some(children) = p.children() {
                    result.extend(children.into_iter().filter(|c| {
                        !excludes
                            .iter()
                            .any(|e| e.prefix <= c.prefix && e.overlaps(*c))
                    }));
                }
            }
            result.sort_by_key(|p| (p.start, p.prefix));
            result.dedup();
            anyhow::ensure!(
                result.len() <= crate::transport_core::MAX_ROUTES,
                "too many capture routes"
            );
            json!(result.iter().map(|p| p.render()).collect::<Vec<_>>())
        }
        _ => anyhow::bail!("unknown policy operation"),
    };
    Ok(json!({"value":result}))
}

/// Local/private scopes used by every allow_lan adapter.
pub const LAN_BYPASS_PREFIXES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/24",
    "239.255.255.250/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];
/// Count consecutive unstable attempts. Only time spent connected can establish stability;
/// handshake, DNS, teardown and offline waiting are deliberately excluded by the adapters.
pub fn reconnect_next_attempt(
    previous: i64,
    established: bool,
    forced: bool,
    connected_ms: i64,
) -> i64 {
    let previous = previous.clamp(0, i64::from(i32::MAX) + 1);
    if established && (forced || connected_ms >= 30_000) {
        0
    } else if forced {
        previous
    } else {
        previous.saturating_add(1).min(i64::from(i32::MAX) + 1)
    }
}

/// Called after an attempt, including a stable session (attempt zero).
/// N permits N retries after an initial unstable attempt; -1 is unlimited.
pub fn reconnect_stop_reason(enabled: bool, maximum: i64, attempt: i64) -> Option<&'static str> {
    if !enabled {
        Some("disabled")
    } else if maximum >= 0 && attempt.max(0) > maximum {
        Some("retry_limit")
    } else {
        None
    }
}

/// A settling window limits the delay exponent, never the finite retry budget.
/// The 1.5 s start-to-start floor also bounds deliberate cycles with zero backoff.
pub fn reconnect_delay(
    attempt: i64,
    base: i64,
    cap: i64,
    elapsed_ms: i64,
    settling_cap: Option<i64>,
    reduction: Option<i64>,
) -> i64 {
    let delay_attempt = settling_cap.map_or(attempt, |cap| attempt.min(cap.max(0)));
    reconnect_jitter(reconnect_backoff(delay_attempt, base, cap), reduction)
        .max(1500i64.saturating_sub(elapsed_ms.max(0)).max(0))
}

/// Milliseconds. Attempt zero is the initial connection; the first retry is one.
pub fn reconnect_backoff(attempt: i64, base: i64, cap: i64) -> i64 {
    if attempt <= 0 {
        return 0;
    }
    base.max(0)
        .saturating_mul((1i64 << ((attempt - 1).min(7) as u32)).min(100))
        .min(cap.max(1000))
        .max(1000)
}
pub fn reconnect_jitter(scheduled: i64, reduction: Option<i64>) -> i64 {
    let scheduled = scheduled.max(0);
    let spread = scheduled / 5;
    let reduction = reduction.map(|n| n.clamp(0, spread)).unwrap_or_else(|| {
        use rand::RngExt;
        rand::rng().random_range(0..=spread)
    });
    scheduled - reduction
}

pub fn full_tunnel(gateway: bool, mode: &str) -> bool {
    gateway || matches!(mode.to_ascii_lowercase().as_str(), "full-tunnel" | "all")
}
