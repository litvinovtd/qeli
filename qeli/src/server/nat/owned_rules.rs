//! Exact firewall specifications retained before a mutation can reach the kernel.
//! Tag sweeps remain useful after a crash, but are not cleanup evidence for a live worker.
use std::collections::{BTreeMap, BTreeSet};

const MAX_RULES: usize = 32768;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub(crate) ipv6: bool,
    pub(crate) table: String,
    pub(crate) chain: String,
    pub(crate) args: Vec<String>,
}

#[derive(Default)]
pub(crate) struct Registry {
    profiles: BTreeMap<String, BTreeSet<Rule>>,
    count: usize,
}

impl Registry {
    /// Reserve BEFORE invoking -A/-I: failure/timeout does not prove no mutation occurred.
    pub(crate) fn retain(&mut self, profile: &str, rule: Rule) -> anyhow::Result<()> {
        self.retain_with_limit(profile, rule, MAX_RULES)
    }

    fn retain_with_limit(&mut self, profile: &str, rule: Rule, limit: usize) -> anyhow::Result<()> {
        if self
            .profiles
            .get(profile)
            .is_some_and(|rules| rules.contains(&rule))
        {
            return Ok(());
        }
        if self.count >= limit {
            anyhow::bail!(
                "exact firewall ownership capacity exhausted; refusing untracked mutation"
            );
        }
        self.profiles
            .entry(profile.into())
            .or_default()
            .insert(rule);
        self.count += 1;
        Ok(())
    }

    /// Attempt every selected specification. Only verified absence releases a record.
    pub(crate) fn cleanup(
        &mut self,
        profile: Option<&str>,
        mut remove: impl FnMut(&Rule) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let mut errors = crate::nat_cleanup::Errors::default();
        for (name, rules) in &mut self.profiles {
            if profile.is_some_and(|profile| profile != name) {
                continue;
            }
            rules.retain(|rule| {
                let result = remove(rule);
                let pending = result.is_err();
                errors.record(&format!("{name}/{}/{}", rule.table, rule.chain), result);
                if !pending {
                    self.count -= 1;
                }
                pending
            });
        }
        self.profiles.retain(|_, rules| !rules.is_empty());
        errors.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(ipv6: bool, chain: &str) -> Rule {
        Rule {
            ipv6,
            table: "filter".into(),
            chain: chain.into(),
            args: vec![
                "--comment".into(),
                "qeli-nat:web".into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        }
    }

    #[test]
    fn failed_mutation_keeps_exact_specification_until_verified_absent() {
        let mut registry = Registry::default();
        registry.retain("web", rule(false, "FORWARD")).unwrap();
        // The caller's mutation times out after applying; no success callback is necessary.
        assert!(registry
            .cleanup(None, |_| anyhow::bail!("tool missing"))
            .is_err());
        assert_eq!(registry.count, 1);
        let mut calls = 0;
        registry
            .cleanup(None, |saved| {
                calls += 1;
                assert_eq!(saved, &rule(false, "FORWARD"));
                Ok(())
            })
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(registry.count, 0);
        registry.cleanup(None, |_| panic!("already clean")).unwrap();
    }

    #[test]
    fn failure_does_not_skip_other_rules_families_or_profiles() {
        let mut registry = Registry::default();
        registry.retain("web", rule(false, "FORWARD")).unwrap();
        registry.retain("web", rule(true, "FORWARD")).unwrap();
        registry.retain("web2", rule(false, "INPUT")).unwrap();
        let mut calls = 0;
        assert!(registry
            .cleanup(None, |saved| {
                calls += 1;
                if saved.ipv6 {
                    anyhow::bail!("denied")
                }
                Ok(())
            })
            .is_err());
        assert_eq!(calls, 3);
        assert_eq!(registry.count, 1);
        registry
            .cleanup(None, |saved| {
                assert!(saved.ipv6);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn exact_profile_selection_preserves_sibling_ownership() {
        let mut registry = Registry::default();
        registry.retain("web", rule(false, "FORWARD")).unwrap();
        registry.retain("web2", rule(true, "INPUT")).unwrap();
        registry
            .cleanup(Some("web"), |saved| {
                assert!(!saved.ipv6);
                Ok(())
            })
            .unwrap();
        assert_eq!(registry.count, 1);
        registry
            .cleanup(Some("web"), |_| panic!("wrong profile"))
            .unwrap();
        registry
            .cleanup(Some("web2"), |saved| {
                assert!(saved.ipv6);
                Ok(())
            })
            .unwrap();
        assert_eq!(registry.count, 0);
    }

    #[test]
    fn capacity_refuses_new_mutations_without_discarding_retry_evidence() {
        let mut registry = Registry::default();
        registry
            .retain_with_limit("web", rule(false, "FORWARD"), 1)
            .unwrap();
        registry
            .retain_with_limit("web", rule(false, "FORWARD"), 1)
            .unwrap();
        assert!(registry
            .retain_with_limit("web", rule(true, "FORWARD"), 1)
            .is_err());
        assert_eq!(registry.count, 1);
        registry.cleanup(None, |_| Ok(())).unwrap();
        registry
            .retain_with_limit("web", rule(true, "FORWARD"), 1)
            .unwrap();
        assert_eq!(registry.count, 1);
    }
}
