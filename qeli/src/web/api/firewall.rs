//! Shared NAT availability diagnostic for status and transport health.
use crate::config::server::ServerConfig;

pub(super) struct Warning {
    pub severity: &'static str,
    pub message: String,
}

pub(super) async fn nat_warning(config: &ServerConfig) -> Option<Warning> {
    if !config.profiles.iter().any(|p| p.routing.nat.enabled) {
        return None;
    }
    let until = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    warning(crate::server::nat::iptables_path_async(until).await)
}

fn warning(result: std::io::Result<Option<String>>) -> Option<Warning> {
    match result {
        Ok(Some(_)) => None,
        Ok(None) => Some(Warning {
            severity: "critical",
            message: "NAT masquerade is enabled on a profile, but `iptables` is not installed — full-tunnel internet egress will NOT work. Install it: apt install iptables.".into(),
        }),
        Err(error) => Some(Warning {
            severity: "warning",
            message: format!("Could not verify iptables availability: {error}. Check the host's firewall tools and retry diagnostics."),
        }),
    }
}

#[cfg(test)]
mod tests;
