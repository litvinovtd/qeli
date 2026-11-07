//! Optional router integration. External ownership is the compatibility default.
//! This module never runs as part of the transport until explicitly requested.
use anyhow::{bail, ensure, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs,
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

mod control;
mod guard;
mod metadata;
mod policy;
mod process;
mod status;
mod transaction;

#[derive(Args)]
pub struct RouterArgs {
    #[command(subcommand)]
    command: RouterCommand,
}
#[derive(Subcommand)]
enum RouterCommand {
    /// Print a safe, external-by-default policy template.
    Example {
        #[arg(long, value_enum, default_value = "openwrt")]
        platform: Platform,
    },
    /// Print component ownership without reading credentials or changing routes.
    Ownership {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Inspect Linux devices, routes and policy-routing managers; no writes.
    Discover,
    /// Validate and print the proposed router policy; no network writes.
    Check {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        client_config: Option<PathBuf>,
    },
    /// Reconcile only explicitly enabled components (supervise independently of the VPN).
    Run {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Start the optional Entware policy worker, independently from VPN restarts.
    Start {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Stop only the verified policy worker; retained fail-closed rules remain.
    Stop {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Return to manual ownership, cleaning only this integration's own objects.
    Disable {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Install the scoped firewall before network startup; does not create routes/TUN.
    Guard {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Render non-secret router JSON from stdin, validating ownership and paths.
    Render {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        routing: Owner,
        #[arg(long, value_enum)]
        firewall: Owner,
        #[arg(long)]
        client_config: PathBuf,
        #[arg(long)]
        runtime: PathBuf,
        #[arg(long)]
        openwrt: bool,
        /// Early boot validates static intent before Linux devices exist.
        #[arg(long)]
        bootstrap: bool,
    },
    /// Confirm the current managed policy after checking access from a new session.
    Confirm {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Internal independent rollback watchdog (also works if the reconciler exits).
    #[command(hide = true)]
    Watchdog {
        #[arg(long)]
        pending: PathBuf,
    },
    /// Validate the live report against boot, process generation and TUN identity.
    Status {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        pid_file: PathBuf,
        #[arg(long)]
        device: String,
    },
    /// Atomically store one line read from stdin; never pass a secret in argv.
    StoreSecret {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: SecretName,
    },
    /// Delete a secret without following a directory/file symlink.
    ForgetSecret {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        name: SecretName,
    },
    /// Copy a retained secret into a private per-boot directory.
    RestoreSecrets {
        #[arg(long)]
        persistent: PathBuf,
        #[arg(long)]
        runtime: PathBuf,
    },
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum SecretName {
    Pass,
    ObfsKey,
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum Platform {
    Openwrt,
    Keenetic,
}
impl SecretName {
    fn file(self) -> &'static str {
        match self {
            Self::Pass => "password",
            Self::ObfsKey => "obfs-key",
        }
    }
}

#[derive(Default, Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    #[default]
    External,
    Client,
}
#[derive(Default, Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    #[default]
    Direct,
    VpnOnly,
    VpnFallback,
}
#[derive(Default, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Components {
    pub routing: Owner,
    pub firewall: Owner,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub device: String,
    pub subnets: Vec<String>,
    pub policy: NetworkPolicy,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Uplink {
    pub device: String,
    /// Literal, public test destinations, reached using this interface's own table.
    pub probes: Vec<IpAddr>,
    /// Optional existing platform routing table when automatic discovery is ambiguous.
    #[serde(default)]
    pub routing_table: Option<u32>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Health {
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub down: u32,
    pub up: u32,
    pub tunnel_probes: Vec<IpAddr>,
}
impl Default for Health {
    fn default() -> Self {
        Self {
            interval_secs: 3,
            timeout_secs: 1,
            down: 3,
            up: 2,
            tunnel_probes: vec![],
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub schema: u32,
    pub components: Components,
    pub device: String,
    pub status_file: PathBuf,
    pub pid_file: Option<PathBuf>,
    pub client_config: PathBuf,
    pub state_directory: PathBuf,
    pub uplinks: Vec<Uplink>,
    pub networks: Vec<Network>,
    pub local_subnets: Vec<String>,
    /// Router-originated traffic is separate: null retains its existing manager.
    pub router_policy: Option<NetworkPolicy>,
    pub health: Health,
    /// Confirmed server IPs or bootstrap addresses. Resolve the hostname externally
    /// when using external DNS; no attempt is made to change resolv.conf.
    pub server_addresses: Vec<IpAddr>,
    /// Firewall backend must match the platform; iptables uses Entware's tools.
    pub backend: String,
    /// Explicit acknowledgement after disabling platform forwarding acceleration.
    /// Packet-policy managers cannot protect traffic bypassing the kernel hooks.
    pub offload_disabled: bool,
    /// A firmware-persistent guard already protects selected VPN-only networks.
    pub persistent_guard: bool,
    /// Set by the OpenWrt renderer; qeli-guard must be enabled before networking.
    pub managed_boot: bool,
    pub client_disabled: bool,
    pub client_metadata: Option<metadata::Metadata>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            schema: 1,
            components: Components::default(),
            device: "qeli0".into(),
            status_file: "/var/run/qeli/status.json".into(),
            pid_file: None,
            client_config: "/var/run/qeli/client.conf".into(),
            state_directory: "/var/run/qeli/router".into(),
            uplinks: vec![],
            networks: vec![],
            local_subnets: vec![],
            router_policy: None,
            health: Health::default(),
            server_addresses: vec![],
            backend: "nft".into(),
            offload_disabled: false,
            persistent_guard: false,
            managed_boot: false,
            client_disabled: false,
            client_metadata: None,
        }
    }
}
fn interface(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 15
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
        "invalid Linux interface name"
    );
    ensure!(
        !matches!(value, "lo" | "." | "..") && !value.starts_with('-'),
        "invalid router policy interface"
    );
    Ok(())
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == 1, "unsupported router policy schema");
        interface(&self.device)?;
        ensure!(
            matches!(self.backend.as_str(), "nft" | "iptables"),
            "backend must be nft or iptables"
        );
        ensure!(
            (1..=60).contains(&self.health.interval_secs)
                && (1..=5).contains(&self.health.timeout_secs),
            "invalid health interval/deadline"
        );
        ensure!(
            (1..=10).contains(&self.health.down) && (1..=10).contains(&self.health.up),
            "invalid health thresholds"
        );
        ensure!(
            self.uplinks.len() <= 8 && self.networks.len() <= 32,
            "too many router interfaces"
        );
        ensure!(
            self.server_addresses.len() <= 64
                && self.local_subnets.len() <= 64
                && self.health.tunnel_probes.len() <= 4,
            "router policy list limit exceeded"
        );
        for path in [
            &self.status_file,
            &self.client_config,
            &self.state_directory,
        ]
        .into_iter()
        .chain(self.pid_file.iter())
        {
            ensure!(
                path.is_absolute()
                    && !path
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir)),
                "router paths must be absolute without parent traversal"
            );
        }
        let mut devices = std::collections::HashSet::new();
        devices.insert(self.device.as_str());
        for uplink in &self.uplinks {
            interface(&uplink.device)?;
            ensure!(devices.insert(&uplink.device), "duplicate router device");
            ensure!(
                !uplink.probes.is_empty() && uplink.probes.len() <= 4,
                "each WAN needs 1..4 literal probes"
            );
        }
        let mut subnets = vec![];
        for network in &self.networks {
            interface(&network.device)?;
            ensure!(devices.insert(&network.device), "duplicate router device");
            ensure!(
                !network.subnets.is_empty() && network.subnets.len() <= 8,
                "each network needs explicit source subnets"
            );
            for subnet in &network.subnets {
                let net: ipnet::IpNet = subnet.parse().context("invalid client subnet")?;
                ensure!(
                    net.prefix_len() > 0 && net.addr() == net.network(),
                    "client subnet must be a canonical, non-default prefix"
                );
                ensure!(
                    !subnets
                        .iter()
                        .any(|n: &ipnet::IpNet| n.contains(&net.addr()) || net.contains(&n.addr())),
                    "overlapping client subnets"
                );
                subnets.push(net);
            }
        }
        for subnet in &self.local_subnets {
            let n: ipnet::IpNet = subnet.parse().context("invalid local subnet")?;
            ensure!(
                n.prefix_len() > 0 && n.addr() == n.network(),
                "local bypass prefixes must be canonical and cannot be a default route"
            );
        }
        if self.components.routing == Owner::Client {
            ensure!(self.offload_disabled,"disable forwarding offload in firmware and acknowledge offload_disabled before managed mode");
            ensure!(
                !self.uplinks.is_empty(),
                "managed routing requires selected WAN interfaces"
            );
            ensure!(!self.server_addresses.is_empty(), "managed routing requires literal server addresses (include all current A/AAAA answers)");
            ensure!(
                !self.health.tunnel_probes.is_empty(),
                "managed routing requires explicit tunnel-bound health destinations"
            );
        }
        if self.components.firewall == Owner::Client {
            ensure!(
                self.offload_disabled,
                "managed firewall requires forwarding offload to be disabled"
            );
        }
        if self.components.firewall == Owner::Client
            && (self.router_policy == Some(NetworkPolicy::VpnOnly)
                || self
                    .networks
                    .iter()
                    .any(|n| n.policy == NetworkPolicy::VpnOnly))
        {
            ensure!(self.persistent_guard || self.managed_boot,"VPN-only requires a persistent firmware guard or the OpenWrt early-boot guard service");
        }
        if self.components.routing == Owner::Client
            && (self.router_policy == Some(NetworkPolicy::VpnOnly)
                || self
                    .networks
                    .iter()
                    .any(|n| n.policy == NetworkPolicy::VpnOnly))
        {
            ensure!(
                self.components.firewall == Owner::Client,
                "VPN-only policies require managed firewall or keep routing external"
            );
        }
        Ok(())
    }
}

fn private_dir(path: &Path, create: bool) -> Result<()> {
    if create && !path.exists() {
        fs::create_dir(path).context("create private directory (parent must exist)")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    // Check every path component, not only the final leaf. /var -> /tmp is a
    // platform alias: callers must provide its already-resolved physical path.
    let mut part = PathBuf::from("/");
    for component in path.components().skip(1) {
        part.push(component);
        let m = fs::symlink_metadata(&part)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.uid() == 0
                && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0),
            "untrusted router directory"
        );
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.mode() & 0o077 == 0,
        "router directory must be private (0700)"
    );
    Ok(())
}
fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o077 == 0 && m.nlink() == 1 && m.len() <= limit,
        "private regular root-owned file required"
    );
    let mut data = Vec::new();
    f.take(limit + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= limit, "router file exceeds limit");
    Ok(data)
}
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("file needs parent")?;
    private_dir(parent, false)?;
    if read_private(path, data.len() as u64).ok().as_deref() == Some(data) {
        return Ok(());
    }
    if let Ok(m) = fs::symlink_metadata(path) {
        ensure!(
            m.is_file() && m.uid() == 0 && m.nlink() == 1,
            "unsafe publication target"
        );
    }
    let temp = parent.join(format!(".qeli-{:016x}.tmp", rand::random::<u64>()));
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}
fn secret_input() -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut value = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().take(4098).read_to_end(&mut value)?;
    if value.ends_with(b"\n") {
        value.pop();
    }
    ensure!(
        !value.is_empty() && value.len() <= 4096 && !value.iter().any(|b| *b < 32 || *b == 127),
        "expected one non-empty secret line (at most 4096 bytes)"
    );
    std::str::from_utf8(&value).context("secret must be UTF-8")?;
    Ok(value)
}
pub async fn run(args: RouterArgs) -> Result<()> {
    match args.command {
        RouterCommand::Example { platform } => {
            let mut p = Policy::default();
            if matches!(platform, Platform::Keenetic) {
                p.backend = "iptables".into();
                p.device = "vpn0".into();
                p.client_config = "/opt/etc/qeli/client.conf".into();
                p.status_file = "/tmp/qeli-status/status.json".into();
                p.pid_file = Some("/opt/var/run/qeli-client.pid".into());
                p.state_directory = "/tmp/qeli-router".into();
            }
            println!("{}", serde_json::to_string_pretty(&p)?);
        }
        RouterCommand::Ownership { policy } => {
            let p: Policy = serde_json::from_slice(&read_private(&policy, 65536)?)?;
            p.validate()?;
            println!(
                "{}",
                if p.components.routing == Owner::Client || p.components.firewall == Owner::Client {
                    "client"
                } else {
                    "external"
                }
            );
        }
        RouterCommand::Discover => println!(
            "{}",
            serde_json::to_string_pretty(&policy::discover().await?)?
        ),
        RouterCommand::Check {
            policy,
            client_config,
        } => {
            let mut p: Policy = serde_json::from_slice(&read_private(&policy, 65536)?)?;
            if let Some(client_config) = client_config {
                p.client_config = client_config;
                p.client_metadata = None;
            }
            p.validate()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&policy::check(&p).await?)?
            );
        }
        RouterCommand::Run { policy } => policy::run(&policy).await?,
        RouterCommand::Start { policy } => transaction::start(&policy).await?,
        RouterCommand::Stop { policy } => transaction::stop(&policy).await?,
        RouterCommand::Disable { policy } => transaction::disable(&policy).await?,
        RouterCommand::Guard { policy } => {
            let _namespace = policy::namespace_lock()?;
            let p: Policy = serde_json::from_slice(&read_private(&policy, 65536)?)?;
            p.validate()?;
            guard::Guard::default().sync(&p, false, false).await?;
        }
        RouterCommand::Render {
            output,
            routing,
            firewall,
            client_config,
            runtime,
            openwrt,
            bootstrap,
        } => {
            let mut bytes = Vec::new();
            std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 65536, "router policy exceeds limit");
            let mut p: Policy = serde_json::from_slice(&bytes)?;
            let runtime = fs::canonicalize(runtime)?;
            private_dir(&runtime, false)?;
            p.components = Components { routing, firewall };
            p.client_config = client_config;
            p.managed_boot = true;
            p.state_directory = runtime.join("router");
            p.status_file = runtime.join("status.json");
            p.pid_file = None;
            if openwrt {
                let (meta, enabled) = metadata::openwrt(routing).await?;
                if let Ok(ip) = meta.server_host.parse::<IpAddr>() {
                    if !p.server_addresses.contains(&ip) {
                        p.server_addresses.push(ip);
                    }
                }
                p.device = meta.device.clone();
                p.client_metadata = Some(meta);
                p.client_disabled = !enabled;
            }
            p.validate()?;
            if routing == Owner::Client || firewall == Owner::Client {
                metadata::Metadata::load(&p)?.validate(&p)?;
            }
            transaction::admit_render(&output, &p)?;
            if !bootstrap {
                policy::check(&p).await?;
            }
            let owner = output.with_extension("owner");
            if fs::symlink_metadata(&output).is_ok() {
                ensure!(
                    read_private(&owner, 64)?.as_slice() == b"qeli-openwrt-router-v1",
                    "refusing to adopt an existing non-owned router policy"
                );
            } else if fs::symlink_metadata(&owner).is_ok() {
                ensure!(
                    read_private(&owner, 64)?.as_slice() == b"qeli-openwrt-router-v1",
                    "router ownership marker conflicts"
                );
            }
            write_private(&owner, b"qeli-openwrt-router-v1")?;
            write_private(&output, &serde_json::to_vec_pretty(&p)?)?;
        }
        RouterCommand::Confirm { policy } => transaction::confirm(&policy).await?,
        RouterCommand::Watchdog { pending } => transaction::watchdog(&pending).await?,
        RouterCommand::Status {
            file,
            pid_file,
            device,
        } => println!("{}", status::read(&file, Some(&pid_file), &device)),
        RouterCommand::StoreSecret { directory, name } => {
            private_dir(&directory, true)?;
            write_private(&directory.join(name.file()), &secret_input()?)?;
        }
        RouterCommand::ForgetSecret { directory, name } => {
            private_dir(&directory, false)?;
            let path = directory.join(name.file());
            if path.exists() {
                read_private(&path, 4096)?;
                fs::remove_file(path)?;
            }
        }
        RouterCommand::RestoreSecrets {
            persistent,
            runtime,
        } => {
            private_dir(&persistent, false)?;
            private_dir(&runtime, true)?;
            for name in [SecretName::Pass, SecretName::ObfsKey] {
                let source = persistent.join(name.file());
                if match fs::symlink_metadata(&source) {
                    Ok(_) => true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(e) => return Err(e.into()),
                } {
                    let bytes = zeroize::Zeroizing::new(read_private(&source, 4096)?);
                    ensure!(
                        !bytes.is_empty() && !bytes.iter().any(|b| *b < 32 || *b == 127),
                        "invalid retained secret"
                    );
                    std::str::from_utf8(&bytes).context("retained secret must be UTF-8")?;
                    write_private(&runtime.join(name.file()), &bytes)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
