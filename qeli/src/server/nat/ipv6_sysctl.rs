//! Profile ownership for IPv6 sysctl acquisition, rollback and final retry.
//! Journal operations are injected so partial writes can be tested without a Linux host.
use std::collections::HashMap;

const IPV6_FORWARDING_SYSCTL: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Lease {
    wan: Option<String>,
    scope: String,
}

#[derive(Default)]
pub(crate) struct Registry {
    leases: HashMap<String, Lease>,
}

impl Registry {
    pub(crate) fn profiles(&self) -> Vec<String> {
        let mut profiles: Vec<_> = self.leases.keys().cloned().collect();
        profiles.sort();
        profiles
    }

    pub(crate) fn acquire(
        &mut self,
        profile: &str,
        wan: Option<&str>,
        tun: &str,
        mut acquire: impl FnMut(&str, &str, &str) -> anyhow::Result<()>,
        release: impl FnOnce(&str) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let ra_path = wan.map(accept_ra_sysctl).transpose()?;
        let scope = server_sysctl_scope(tun);
        if let Some(existing) = self.leases.get(profile) {
            if existing.wan.as_deref() != wan || existing.scope != scope {
                anyhow::bail!(
                    "profile '{profile}' already owns IPv6 router settings for interface '{}'",
                    existing.wan.as_deref().unwrap_or("<none>")
                );
            }
            // Re-acquire both settings: a failed release may have restored only one knob.
        }
        // An acquire may change the kernel and then fail verification or journal I/O.
        // Retain the scope BEFORE either call so even a first-call failure can be retried.
        self.leases.insert(
            profile.to_string(),
            Lease {
                wan: wan.map(str::to_string),
                scope: scope.clone(),
            },
        );
        let result = (|| {
            // Keep WAN router advertisements while enabling global forwarding.
            if let Some(path) = ra_path.as_deref() {
                acquire(path, "2", &scope)?;
            }
            acquire(IPV6_FORWARDING_SYSCTL, "1", &scope)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => match self.release(profile, release) {
                Ok(()) => Err(error),
                Err(rollback) => Err(anyhow::anyhow!(
                    "IPv6 sysctl acquisition failed: {error}; rollback incomplete: {rollback}"
                )),
            },
        }
    }

    pub(crate) fn release(
        &mut self,
        profile: &str,
        release: impl FnOnce(&str) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let Some(lease) = self.leases.get(profile) else {
            return Ok(());
        };
        // A failed release retains ownership for profile cleanup and the worker's final pass.
        release(&lease.scope)?;
        self.leases.remove(profile);
        Ok(())
    }
}

fn server_sysctl_scope(tun: &str) -> String {
    // Encode the kernel interface name instead of using it verbatim. Linux permits a few
    // punctuation characters that are deliberately forbidden in the journal's owner grammar.
    let mut scope = String::with_capacity(2 + tun.len() * 2);
    scope.push_str("s-");
    for byte in tun.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut scope, "{byte:02x}").expect("writing to String cannot fail");
    }
    scope
}

fn accept_ra_sysctl(wan: &str) -> anyhow::Result<String> {
    // Interface names originate in a trusted config or `ip route`, but they are still used as
    // one filesystem component below. Reject separators/dot components here so a malformed
    // command response or config can never turn this into an arbitrary /proc write.
    if wan.is_empty()
        || wan.len() > 15
        || wan == "."
        || wan == ".."
        || wan.contains('/')
        || wan.contains('\\')
        || wan.contains('\0')
        || wan
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        anyhow::bail!("invalid IPv6 uplink interface name '{wan}'");
    }
    Ok(format!("/proc/sys/net/ipv6/conf/{wan}/accept_ra"))
}

#[cfg(test)]
#[path = "ipv6_sysctl/tests.rs"]
mod tests;
