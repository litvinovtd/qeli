//! Durable exact server firewall specifications. This is internal recovery state, not configuration.
use crate::nat_owned_rules::Rule;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const LIMIT: u64 = 8 * 1024 * 1024;
const MAX_RULES: usize = 32768;
const MAX_NAMESPACES: usize = 64;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Store {
    version: u8,
    boot: String,
    namespaces: BTreeMap<u64, Group>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    backends: [Option<Backend>; 2],
    rules: BTreeSet<Rule>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Backend {
    Nft,
    Legacy,
}
impl Backend {
    pub(crate) fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(bytes.len() <= 256, "invalid iptables backend identity");
        let text = std::str::from_utf8(bytes)?.trim();
        let fields: Vec<_> = text.split_whitespace().collect();
        anyhow::ensure!(
            fields.len() >= 2
                && fields.len() <= 3
                && matches!(fields[0], "iptables" | "ip6tables")
                && fields[1].strip_prefix('v').is_some_and(
                    |v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                ),
            "unrecognized iptables backend identity"
        );
        match fields.get(2).copied() {
            Some("(nf_tables)") => Ok(Self::Nft),
            Some("(legacy)") | None => Ok(Self::Legacy),
            _ => anyhow::bail!("unrecognized iptables backend identity"),
        }
    }
}
impl Store {
    pub(crate) fn new(boot: &str) -> Self {
        Self {
            version: 1,
            boot: boot.into(),
            namespaces: BTreeMap::new(),
        }
    }
    pub(crate) fn decode(bytes: &[u8], boot: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() as u64 <= LIMIT,
            "server firewall journal exceeds its size limit"
        );
        let store: Self = serde_json::from_slice(bytes)?;
        store.validate()?;
        // Firewall state cannot survive a host reboot. Never apply another boot's specifications.
        Ok(if store.boot == boot {
            store
        } else {
            Self::new(boot)
        })
    }
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == 1
                && !self.boot.is_empty()
                && self.boot.len() <= 128
                && !self.boot.chars().any(char::is_control),
            "invalid server firewall journal header"
        );
        anyhow::ensure!(
            self.namespaces.len() <= MAX_NAMESPACES
                && self
                    .namespaces
                    .values()
                    .map(|g| g.rules.len())
                    .sum::<usize>()
                    <= MAX_RULES,
            "server firewall journal capacity exceeded"
        );
        for (&cookie, group) in &self.namespaces {
            anyhow::ensure!(cookie != 0, "invalid server firewall namespace generation");
            for rule in &group.rules {
                anyhow::ensure!(
                    group.backends[usize::from(rule.ipv6)].is_some(),
                    "missing firewall backend"
                );
                validate_rule(rule)?;
            }
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        anyhow::ensure!(
            bytes.len() as u64 <= LIMIT,
            "server firewall journal exceeds its size limit"
        );
        Ok(bytes)
    }
    pub(crate) fn rules(&self, cookie: u64) -> Vec<Rule> {
        self.namespaces
            .get(&cookie)
            .map(|group| group.rules.iter().cloned().collect())
            .unwrap_or_default()
    }
    pub(crate) fn retain(
        &mut self,
        cookie: u64,
        rule: Rule,
        backend: Backend,
    ) -> anyhow::Result<()> {
        validate_rule(&rule)?;
        let group = self.namespaces.entry(cookie).or_insert_with(|| Group {
            backends: [None; 2],
            rules: BTreeSet::new(),
        });
        let previous = &mut group.backends[usize::from(rule.ipv6)];
        anyhow::ensure!(
            previous.is_none_or(|b| b == backend),
            "iptables backend changed; exact recovery must use the original backend"
        );
        *previous = Some(backend);
        group.rules.insert(rule);
        self.validate()
    }
    pub(crate) fn backend(&self, cookie: u64, ipv6: bool) -> Option<Backend> {
        self.namespaces
            .get(&cookie)
            .and_then(|g| g.backends[usize::from(ipv6)])
    }
    pub(crate) fn forget(&mut self, cookie: u64, rule: &Rule) {
        if let Some(group) = self.namespaces.get_mut(&cookie) {
            group.rules.remove(rule);
            if !group.rules.iter().any(|r| r.ipv6 == rule.ipv6) {
                group.backends[usize::from(rule.ipv6)] = None;
            }
            if group.rules.is_empty() {
                self.namespaces.remove(&cookie);
            }
        }
    }
}

// Recovery never accepts a command, table switch or arbitrary extension from the journal.
// These are the exact argument forms emitted by server NAT, IPv6 isolation and DNS.
fn validate_rule(rule: &Rule) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            (rule.table.as_str(), rule.chain.as_str()),
            ("nat", "POSTROUTING" | "PREROUTING")
                | ("filter", "FORWARD" | "INPUT")
                | ("mangle", "FORWARD")
        ),
        "invalid server firewall table/chain"
    );
    anyhow::ensure!(
        !rule.args.is_empty()
            && rule.args.len() <= 64
            && rule.args.iter().all(|arg| !arg.is_empty()
                && arg.len() <= 512
                && !arg.chars().any(char::is_control)),
        "invalid server firewall arguments"
    );
    // The NAT44 off-WAN guard uses repeated iprange matches. Recovery must
    // accept only the exact form emitted by rules(), not arbitrary extension
    // arguments supplied through a damaged or foreign journal.
    if rule
        .args
        .windows(2)
        .any(|pair| pair[0] == "-m" && pair[1] == "iprange")
    {
        let a = rule.args.as_slice();
        anyhow::ensure!(
            !rule.ipv6
                && rule.table == "filter"
                && rule.chain == "FORWARD"
                && a.len() == 26
                && a[0] == "-i"
                && !a[1].starts_with('-')
                && a[1] != "!"
                && a[2] == "!"
                && a[3] == "-o"
                && !a[4].starts_with('-')
                && a[4] != "!"
                && a[5] == "-m"
                && a[6] == "iprange"
                && a[7] == "!"
                && a[8] == "--dst-range"
                && a[9] == "10.0.0.0-10.255.255.255"
                && a[10] == "-m"
                && a[11] == "iprange"
                && a[12] == "!"
                && a[13] == "--dst-range"
                && a[14] == "172.16.0.0-172.31.255.255"
                && a[15] == "-m"
                && a[16] == "iprange"
                && a[17] == "!"
                && a[18] == "--dst-range"
                && a[19] == "192.168.0.0-192.168.255.255"
                && a[20] == "-j"
                && a[21] == "DROP"
                && a[22] == "-m"
                && a[23] == "comment"
                && a[24] == "--comment"
                && a[25]
                    .strip_prefix("qeli-nat:")
                    .is_some_and(crate::util::is_valid_profile_name),
            "invalid NAT44 off-WAN firewall guard"
        );
        return Ok(());
    }
    let mut i = 0;
    let (mut comments, mut targets) = (0, 0);
    while i < rule.args.len() {
        let option = rule.args[i].as_str();
        let n = match option {
            "!" => {
                anyhow::ensure!(
                    rule.args
                        .get(i + 1)
                        .is_some_and(|x| matches!(x.as_str(), "-i" | "-o")),
                    "invalid firewall negation"
                );
                i += 1;
                continue;
            }
            "--tcp-flags" => 2,
            "-i" | "-o" | "-s" | "-d" | "-p" | "-m" | "--comment" | "-j" | "--state"
            | "--set-mss" | "--dport" | "--to-ports" => 1,
            _ => anyhow::bail!("unsupported server firewall argument {option}"),
        };
        anyhow::ensure!(
            i + n < rule.args.len()
                && rule.args[i + 1..=i + n]
                    .iter()
                    .all(|v| !v.starts_with('-') && v != "!"),
            "invalid firewall option value"
        );
        let value = &rule.args[i + 1];
        if option == "--comment" {
            comments += 1;
            anyhow::ensure!(
                value
                    .strip_prefix("qeli-nat:")
                    .is_some_and(crate::util::is_valid_profile_name),
                "foreign server firewall comment"
            );
        }
        if option == "-m" {
            anyhow::ensure!(
                matches!(value.as_str(), "comment" | "state"),
                "unsupported firewall module"
            );
        }
        if option == "-j" {
            targets += 1;
            anyhow::ensure!(
                matches!(
                    (rule.table.as_str(), value.as_str()),
                    ("nat", "MASQUERADE" | "REDIRECT")
                        | ("filter", "ACCEPT" | "DROP")
                        | ("mangle", "TCPMSS")
                ),
                "unsupported firewall target"
            );
        }
        i += n + 1;
    }
    anyhow::ensure!(
        comments == 1 && targets == 1,
        "ambiguous server firewall ownership/target"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[path = "firewall_journal/native.rs"]
mod native;
#[cfg(all(target_os = "linux", feature = "server"))]
pub(crate) use native::Session;

#[cfg(test)]
#[path = "firewall_journal/tests.rs"]
mod tests;
