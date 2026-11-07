//! Public routing admission data. No credentials, hooks or key material.
use super::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub device: String,
    pub server_host: String,
    pub server_port: u16,
    pub protocol: String,
    pub gateway: bool,
    pub kill_switch: bool,
    pub core_gateway: bool,
    pub route_local: bool,
    pub resolver_external: bool,
    pub local_address_bound: bool,
    pub pull_routes: bool,
}
impl Metadata {
    pub(super) fn validate(&self, p: &Policy) -> Result<()> {
        ensure!(
            self.device == p.device,
            "router policy TUN differs from the client config"
        );
        if p.components.routing != Owner::Client {
            return Ok(());
        }
        ensure!(!self.gateway && !self.kill_switch && !self.core_gateway,"managed routing requires gateway=false, kill_switch=false and core gateway NAT/forward/exit disabled");
        ensure!(
            !self.route_local && !self.pull_routes,
            "managed routing requires route_local=false and pull_routes=false"
        );
        ensure!(
            self.resolver_external,
            "managed routing requires dns=off/system; DNS remains externally owned"
        );
        ensure!(
            p.router_policy.is_none(),
            "router-originated policies currently remain externally owned; omit router_policy"
        );
        if let Ok(ip) = self.server_host.parse::<IpAddr>() {
            ensure!(
                p.server_addresses.contains(&ip),
                "literal endpoint missing from server_addresses"
            );
        }
        ensure!(
            p.uplinks.len() == 1 || !self.local_address_bound,
            "multi-WAN cannot use a client address pinned to one WAN"
        );
        Ok(())
    }
    pub(super) fn load(p: &Policy) -> Result<Self> {
        if let Some(meta) = &p.client_metadata {
            return Ok(meta.clone());
        }
        let (snapshot, _) = crate::config_source::load_client(&p.client_config)?;
        let (contents, _) = snapshot.into_parts();
        let c = crate::config::parse_client_config_strict(&contents)?;
        Ok(Self {
            device: c.tun.name.clone(),
            server_host: c.server.address.clone(),
            server_port: c.server.port,
            protocol: c.server.protocol.clone(),
            gateway: c.routing.add_default_gateway,
            kill_switch: c.routing.kill_switch,
            core_gateway: c.routing.gateway_nat || c.routing.forward || c.routing.exit_node,
            route_local: c.routing.route_local_networks,
            resolver_external: c.leaves_resolver_alone(),
            local_address_bound: c.server.local_address.is_some(),
            pull_routes: c.routing.pull_routes,
        })
    }
}
async fn value(key: &str, default: &str) -> Result<String> {
    let option = format!("qeli.main.{key}");
    match process::command("uci", &["-q", "get", &option]).await {
        Ok(bytes) => {
            let text = std::str::from_utf8(&bytes)?.trim_end_matches('\n');
            ensure!(
                text.len() <= 4096 && !text.bytes().any(|b| b < 32 || b == 127),
                "invalid public UCI routing option"
            );
            Ok(text.into())
        }
        Err(_) => Ok(default.into()),
    }
}
async fn boolean(key: &str, default: &str) -> Result<bool> {
    match value(key, default).await?.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" | "enabled" => Ok(true),
        "0" | "false" | "off" | "no" | "disabled" | "" => Ok(false),
        _ => bail!("invalid public UCI boolean"),
    }
}
pub(super) async fn openwrt(routing: Owner) -> Result<(Metadata, bool)> {
    ensure!(
        std::str::from_utf8(&process::command("uci", &["-q", "get", "qeli.main"]).await?)?.trim()
            == "qeli",
        "missing OpenWrt qeli.main section"
    );
    let device = value("dev", "qeli0").await?;
    interface(&device)?;
    ensure!(
        device.starts_with("qeli"),
        "OpenWrt TUN must use the package qeli namespace"
    );
    let endpoint = value("server", "vpn.example.com:443").await?;
    let (server_host, server_port) =
        crate::config::share::supported_public_endpoint(&endpoint, 443)
            .map_err(|_| anyhow::anyhow!("invalid public Qeli server endpoint"))?;
    let protocol = value("proto", "tcp").await?;
    ensure!(
        matches!(protocol.as_str(), "tcp" | "udp"),
        "invalid public Qeli protocol"
    );
    let dns = value("dns", "off").await?;
    Ok((
        Metadata {
            device,
            server_host,
            server_port,
            protocol,
            gateway: boolean("gateway", "0").await?,
            kill_switch: boolean("kill_switch", "0").await?,
            core_gateway: false,
            route_local: boolean("route_local", "0").await?,
            resolver_external: matches!(dns.as_str(), "off" | "system"),
            local_address_bound: false,
            pull_routes: routing != Owner::Client,
        },
        boolean("enabled", "0").await?,
    ))
}
