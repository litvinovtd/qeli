//! Process-local ownership for exact DNS INPUT permits, including failed retirement.
//! The caller serializes this registry with firewall mutations; callbacks must not re-lock it.
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const MAX_TRACKED_RULESETS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DnsInputRules {
    pub(crate) profile: String,
    pub(crate) ipv6: bool,
    pub(crate) rules: [Vec<String>; 2],
}

impl DnsInputRules {
    pub(crate) fn new(
        profile: &str,
        tun: &str,
        pool: &str,
        listen: &str,
        port: u16,
    ) -> anyhow::Result<Self> {
        let address: std::net::IpAddr = listen.parse()?;
        Ok(Self {
            profile: profile.to_string(),
            ipv6: address.is_ipv6(),
            rules: ["udp", "tcp"]
                .map(|proto| dns_input_rule(profile, tun, pool, listen, port, proto)),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DnsInputId(u64);

/// Dropping this token publishes retirement without waiting for the firewall or registry.
/// It owns no cleanup I/O; the registry retains the exact rules until verified absent.
#[derive(Debug)]
pub(crate) struct DnsInputOwner {
    id: DnsInputId,
    retired: Arc<AtomicBool>,
}
impl DnsInputOwner {
    pub(crate) fn id(&self) -> DnsInputId {
        self.id
    }
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }
}
impl Drop for DnsInputOwner {
    fn drop(&mut self) {
        self.retire();
    }
}

#[derive(Debug)]
struct Entry {
    rules: DnsInputRules,
    retired: Arc<AtomicBool>,
}

#[derive(Default, Debug)]
pub(crate) struct DnsInputRegistry {
    entries: BTreeMap<DnsInputId, Entry>,
    last_id: u64,
}

impl DnsInputRegistry {
    pub(crate) fn begin_owned(
        &mut self,
        rules: DnsInputRules,
        cleanup: impl FnMut(&DnsInputRules) -> anyhow::Result<()>,
    ) -> anyhow::Result<DnsInputOwner> {
        let id = self.begin(rules, cleanup)?;
        Ok(DnsInputOwner {
            id,
            retired: self.entries[&id].retired.clone(),
        })
    }

    /// Reserve ownership BEFORE the first insertion. Old failed retirement for this
    /// profile must complete before a new generation may install DNS permits.
    pub(crate) fn begin(
        &mut self,
        rules: DnsInputRules,
        cleanup: impl FnMut(&DnsInputRules) -> anyhow::Result<()>,
    ) -> anyhow::Result<DnsInputId> {
        self.retry(Some(&rules.profile), cleanup)?;
        // Retirement can arrive while an earlier cleanup callback is running.
        // Do not reserve a new generation over newly observed pending evidence.
        if self.entries.values().any(|entry| {
            entry.rules.profile == rules.profile && entry.retired.load(Ordering::Acquire)
        }) {
            anyhow::bail!("DNS INPUT cleanup still pending for '{}'", rules.profile);
        }
        if self.entries.values().any(|entry| entry.rules == rules) {
            anyhow::bail!(
                "DNS INPUT rules for '{}' already have a live owner",
                rules.profile
            );
        }
        if self.entries.len() >= MAX_TRACKED_RULESETS {
            anyhow::bail!("DNS INPUT ownership limit reached ({MAX_TRACKED_RULESETS}); finish pending cleanup before installing more rules");
        }
        let next = self
            .last_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("DNS INPUT ownership ids exhausted"))?;
        self.last_id = next;
        let id = DnsInputId(next);
        self.entries.insert(
            id,
            Entry {
                rules,
                retired: Arc::new(AtomicBool::new(false)),
            },
        );
        Ok(id)
    }

    /// Mark retired before attempting I/O. Failure (or unwind) leaves exact evidence
    /// available to retry. An old token can never retire a replacement generation.
    pub(crate) fn finish(
        &mut self,
        id: DnsInputId,
        mut cleanup: impl FnMut(&DnsInputRules) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let Some(entry) = self.entries.get_mut(&id) else {
            return Ok(());
        };
        entry.retired.store(true, Ordering::Release);
        cleanup(&entry.rules)?;
        self.entries.remove(&id);
        Ok(())
    }

    /// At worker shutdown every lease should have retired. Retry pending exact rules,
    /// but report a still-active owner instead of deleting its permits or claiming success.
    pub(crate) fn finish_shutdown(
        &mut self,
        cleanup: impl FnMut(&DnsInputRules) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let mut errors = crate::nat_cleanup::Errors::default();
        errors.record("pending DNS INPUT", self.retry(None, cleanup));
        // A token may retire after retry's snapshot. Every remaining entry is unresolved,
        // including newly retired ones; checking only active entries would miss that race.
        for entry in self.entries.values() {
            errors.record(
                &entry.rules.profile,
                Err(anyhow::anyhow!(if entry.retired.load(Ordering::Acquire) {
                    "DNS INPUT cleanup still pending at worker shutdown"
                } else {
                    "DNS INPUT lease still active at worker shutdown"
                })),
            );
        }
        errors.finish()
    }

    /// Only retired entries are eligible. A profile retry must never touch active
    /// permits or another profile; retry(None) handles every retired owner.
    pub(crate) fn retry(
        &mut self,
        profile: Option<&str>,
        mut cleanup: impl FnMut(&DnsInputRules) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let ids: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                (entry.retired.load(Ordering::Acquire)
                    && profile.is_none_or(|profile| profile == entry.rules.profile))
                .then_some(*id)
            })
            .collect();
        let mut errors = crate::nat_cleanup::Errors::default();
        for id in ids {
            let label = self.entries[&id].rules.profile.clone();
            errors.record(&label, self.finish(id, &mut cleanup));
        }
        errors.finish()
    }
}

pub(crate) fn dns_input_rule(
    profile: &str,
    tun: &str,
    pool_cidr: &str,
    listen: &str,
    port: u16,
    proto: &str,
) -> Vec<String> {
    vec![
        "-i".into(),
        tun.into(),
        "-s".into(),
        pool_cidr.into(),
        "-p".into(),
        proto.into(),
        "-d".into(),
        listen.into(),
        "--dport".into(),
        port.to_string(),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        format!("qeli-nat:{profile}"),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

#[cfg(test)]
#[path = "dns_input/tests.rs"]
mod tests;
