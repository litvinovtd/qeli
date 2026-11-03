//! Durable physical route ownership. INI configuration is unrelated to this internal state.
use super::ownership::same_route_key;
use std::collections::{BTreeMap, BTreeSet};
pub(super) const LIMIT: u64 = 8 * 1024 * 1024;
const MAX_GROUPS: usize = 128;
const MAX_RECORDS: usize = 8192;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    version: u8,
    boot: String,
    groups: Vec<Group>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    cookie: u64,
    interface: String,
    owned: Vec<Vec<String>>,
    pending: Vec<Vec<String>>,
}
#[derive(Clone, Copy)]
pub(super) enum Change {
    Intent,
    Confirm,
    ForgetOwned,
    ForgetPending,
}
impl Store {
    fn new(boot: &str) -> Self {
        Self {
            version: 1,
            boot: boot.into(),
            groups: Vec::new(),
        }
    }
    fn decode(bytes: &[u8], boot: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() as u64 <= LIMIT,
            "client route journal size limit"
        );
        let store: Self = serde_json::from_slice(bytes)?;
        store.validate()?;
        Ok(if store.boot == boot {
            store
        } else {
            Self::new(boot)
        })
    }
    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        anyhow::ensure!(
            bytes.len() as u64 <= LIMIT,
            "client route journal size limit"
        );
        Ok(bytes)
    }
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == 1
                && !self.boot.is_empty()
                && self.boot.len() <= 128
                && !self.boot.chars().any(char::is_control),
            "invalid client route journal header"
        );
        anyhow::ensure!(
            self.groups.len() <= MAX_GROUPS
                && self
                    .groups
                    .iter()
                    .map(|g| g.owned.len() + g.pending.len())
                    .sum::<usize>()
                    <= MAX_RECORDS,
            "client route journal capacity exceeded"
        );
        let mut identities = BTreeSet::new();
        for group in &self.groups {
            anyhow::ensure!(
                group.cookie != 0
                    && valid_interface(&group.interface)
                    && identities.insert((group.cookie, &group.interface)),
                "invalid route journal owner"
            );
            for records in [&group.owned, &group.pending] {
                let mut destinations = BTreeSet::new();
                for spec in records {
                    validate_spec(spec)?;
                    anyhow::ensure!(
                        !is_tunnel(spec, &group.interface),
                        "TUN routes are not physical recovery records"
                    );
                    let key = super::ownership::route_key(spec);
                    let prefix = key.last().expect("validated destination");
                    let canonical = match prefix.parse::<ipnet::IpNet>() {
                        Ok(net) => (net.network(), net.prefix_len()),
                        Err(_) => {
                            let ip = prefix.parse::<std::net::IpAddr>()?;
                            (ip, if ip.is_ipv4() { 32 } else { 128 })
                        }
                    };
                    anyhow::ensure!(
                        destinations.insert((
                            spec[0] == "-6",
                            key.iter().any(|s| s == "blackhole"),
                            canonical
                        )),
                        "duplicate route journal destination"
                    );
                }
            }
        }
        Ok(())
    }
    fn records(&self, cookie: u64, interface: &str, pending: bool) -> Vec<Vec<String>> {
        self.groups
            .iter()
            .find(|g| g.cookie == cookie && g.interface == interface)
            .map(|g| {
                if pending {
                    g.pending.clone()
                } else {
                    g.owned.clone()
                }
            })
            .unwrap_or_default()
    }
    fn check_unclaimed(&self, cookie: u64, interface: &str, spec: &[String]) -> anyhow::Result<()> {
        validate_key(spec)?;
        for group in &self.groups {
            if group.cookie == cookie
                && group.interface != interface
                && group
                    .owned
                    .iter()
                    .chain(&group.pending)
                    .any(|r| same_route_key(r, spec))
            {
                anyhow::bail!("route destination is reserved by Qeli client {}; shared borrowing is unsupported", group.interface);
            }
        }
        Ok(())
    }
    fn change(
        &mut self,
        cookie: u64,
        interface: &str,
        spec: &[String],
        change: Change,
    ) -> anyhow::Result<()> {
        if matches!(change, Change::ForgetOwned | Change::ForgetPending) {
            validate_key(spec)?;
        } else {
            validate_spec(spec)?;
        }
        self.check_unclaimed(cookie, interface, spec)?;
        let index = match self
            .groups
            .iter()
            .position(|g| g.cookie == cookie && g.interface == interface)
        {
            Some(index) => index,
            None if matches!(change, Change::ForgetOwned | Change::ForgetPending) => return Ok(()),
            None => {
                self.groups.push(Group {
                    cookie,
                    interface: interface.into(),
                    owned: Vec::new(),
                    pending: Vec::new(),
                });
                self.groups.len() - 1
            }
        };
        let group = &mut self.groups[index];
        match change {
            Change::Intent => {
                group.pending.retain(|r| !same_route_key(r, spec));
                group.pending.push(spec.to_vec());
            }
            Change::Confirm => {
                group.pending.retain(|r| !same_route_key(r, spec));
                group.owned.retain(|r| !same_route_key(r, spec));
                group.owned.push(spec.to_vec());
            }
            Change::ForgetOwned => group.owned.retain(|r| !same_route_key(r, spec)),
            Change::ForgetPending => group.pending.retain(|r| !same_route_key(r, spec)),
        }
        self.groups
            .retain(|g| !g.owned.is_empty() || !g.pending.is_empty());
        self.validate()
    }
}
fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\'))
}
pub(super) fn is_tunnel(spec: &[String], interface: &str) -> bool {
    spec.windows(2).any(|p| p[0] == "dev" && p[1] == interface)
}
// Never replay arbitrary ip arguments from disk. The permitted grammar is exactly a
// main-table unicast/blackhole delete emitted by the physical route adapter.
fn validate_key(spec: &[String]) -> anyhow::Result<()> {
    let offset = usize::from(spec.first().is_some_and(|s| s == "-6"));
    anyhow::ensure!(
        spec.get(offset).is_some_and(|s| s == "route")
            && spec.get(offset + 1).is_some_and(|s| s == "del"),
        "invalid route reservation key"
    );
    let index = offset + 2 + usize::from(spec.get(offset + 2).is_some_and(|s| s == "blackhole"));
    let destination = spec
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("missing route reservation destination"))?;
    let address = destination
        .parse::<ipnet::IpNet>()
        .map(|n| n.addr())
        .or_else(|_| destination.parse::<std::net::IpAddr>())?;
    anyhow::ensure!(
        address.is_ipv6() == (offset == 1),
        "route reservation family mismatch"
    );
    Ok(())
}
fn validate_spec(spec: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        spec.len() >= 3
            && spec.len() <= 24
            && spec.iter().all(|s| !s.is_empty()
                && s.len() <= 128
                && !s.chars().any(|c| c.is_control() || c.is_whitespace())),
        "invalid recovery route arguments"
    );
    let offset = usize::from(spec[0] == "-6");
    anyhow::ensure!(
        spec.get(offset).is_some_and(|s| s == "route")
            && spec.get(offset + 1).is_some_and(|s| s == "del"),
        "invalid recovery route command"
    );
    let blackhole = spec.get(offset + 2).is_some_and(|s| s == "blackhole");
    let destination = offset + 2 + usize::from(blackhole);
    let prefix = spec
        .get(destination)
        .ok_or_else(|| anyhow::anyhow!("missing recovery destination"))?;
    let address = prefix
        .parse::<ipnet::IpNet>()
        .map(|n| n.addr())
        .or_else(|_| prefix.parse::<std::net::IpAddr>())?;
    anyhow::ensure!(
        address.is_ipv6() == (offset == 1),
        "recovery route family mismatch"
    );
    let mut attrs = BTreeMap::new();
    let mut fields = spec[destination + 1..].iter();
    while let Some(field) = fields.next() {
        if field == "linkdown" {
            continue;
        }
        let value = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("incomplete recovery route field"))?;
        anyhow::ensure!(
            attrs.insert(field.as_str(), value.as_str()).is_none(),
            "duplicate recovery route field"
        );
        match field.as_str() {
            "dev" => anyhow::ensure!(valid_interface(value), "invalid recovery device"),
            "via" | "src" => anyhow::ensure!(
                value.parse::<std::net::IpAddr>()?.is_ipv6() == (offset == 1),
                "recovery address family mismatch"
            ),
            "metric" => {
                value.parse::<u32>()?;
            }
            "proto" => anyhow::ensure!(
                matches!(value.as_str(), "boot" | "3"),
                "foreign recovery route protocol"
            ),
            "scope" => anyhow::ensure!(
                matches!(value.as_str(), "link" | "global" | "universe" | "0" | "253"),
                "invalid recovery scope"
            ),
            "pref" => anyhow::ensure!(
                offset == 1 && value == "medium",
                "invalid recovery preference"
            ),
            _ => anyhow::bail!("unsupported recovery route field {field}"),
        }
    }
    anyhow::ensure!(
        blackhole || attrs.contains_key("dev"),
        "recovery route has no physical device"
    );
    anyhow::ensure!(
        !blackhole || (!attrs.contains_key("via") && !attrs.contains_key("src")),
        "invalid blackhole recovery selector"
    );
    Ok(())
}
#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
#[path = "persistent/native.rs"]
pub(super) mod native;
#[cfg(test)]
#[path = "persistent/tests.rs"]
mod tests;
