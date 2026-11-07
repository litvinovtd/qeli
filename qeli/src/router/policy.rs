//! Linux policy adapter shared by OpenWrt and Entware. Own only a reserved mark
//! field, private tables, named chains and a receipt. Never flush system rules.
use super::*;
use process::{command, output};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Allocation {
    table: u32,
    preference: u32,
    shift: u32,
}
impl Allocation {
    fn mask(&self) -> u32 {
        15u32 << self.shift
    }
    fn mark(&self, index: usize) -> u32 {
        (index as u32 + 1) << self.shift
    }
    fn table(&self, index: usize) -> String {
        (self.table + index as u32).to_string()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Receipt {
    boot: String,
    allocation: Allocation,
    backend: String,
    firewall: bool,
    count: usize,
    layout: Vec<String>,
}
fn layout(p: &Policy) -> Vec<String> {
    std::iter::once(p.device.clone())
        .chain(p.uplinks.iter().map(|u| u.device.clone()))
        .collect()
}
#[derive(Clone, Debug)]
struct Route {
    device: String,
    gateway: Option<String>,
    source: Option<String>,
}
#[derive(Default)]
struct HealthState {
    good: bool,
    successes: u32,
    failures: u32,
}
impl HealthState {
    fn update(&mut self, success: bool, h: &Health) -> bool {
        if success {
            self.failures = 0;
            self.successes = self.successes.saturating_add(1);
            if self.successes >= h.up {
                self.good = true;
            }
        } else {
            self.successes = 0;
            self.failures = self.failures.saturating_add(1);
            if self.failures >= h.down {
                self.good = false;
            }
        }
        self.good
    }
}
async fn json_command(program: &str, args: &[&str]) -> Result<Value> {
    let numeric = if program == "ip" {
        std::iter::once("-N")
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
    } else {
        args.to_vec()
    };
    Ok(serde_json::from_slice(&command(program, &numeric).await?)?)
}
pub(super) async fn discover() -> Result<Value> {
    let devices = json_command("ip", &["-j", "address", "show"]).await?;
    let routes4 = json_command("ip", &["-j", "-4", "route", "show", "table", "all"]).await?;
    let routes6 = json_command("ip", &["-j", "-6", "route", "show", "table", "all"]).await?;
    let rules4 = json_command("ip", &["-j", "-4", "rule", "show"]).await?;
    let rules6 = json_command("ip", &["-j", "-6", "rule", "show"]).await?;
    Ok(
        json!({"devices":devices,"routes4":routes4,"routes6":routes6,"rules4":rules4,"rules6":rules6,
        "mwan3":Path::new("/etc/config/mwan3").exists(),"pbr":Path::new("/etc/config/pbr").exists(),
        "keenetic":Path::new("/opt/etc/ndm").exists()}),
    )
}
fn number(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok()).or_else(|| {
        v.as_str().and_then(|s| {
            if let Some(x) = s.strip_prefix("0x") {
                u32::from_str_radix(x, 16).ok()
            } else {
                s.parse().ok()
            }
        })
    })
}
fn address_family(value: &str) -> bool {
    value.contains(':')
}
fn selected(policy: NetworkPolicy, vpn: bool, wan: Option<usize>, tun: usize) -> Option<usize> {
    match policy {
        NetworkPolicy::Direct => wan,
        NetworkPolicy::VpnOnly => Some(tun),
        NetworkPolicy::VpnFallback => {
            if vpn {
                Some(tun)
            } else {
                wan
            }
        }
    }
}
fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
pub(super) fn namespace_lock() -> Result<fs::File> {
    use std::os::fd::AsRawFd;
    let runtime = fs::canonicalize("/var/run")?;
    let directory = runtime.join("qeli-policy-locks");
    private_dir(&directory, true)?;
    let scope = fs::metadata("/proc/thread-self/ns/net")?;
    let path = directory.join(format!("{}-{}.lock", scope.dev(), scope.ino()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0,
        "unsafe namespace lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another Qeli policy controller owns this network namespace"
    );
    Ok(file)
}
async fn route(uplink: &Uplink, v6: bool, owned: &Receipt) -> Result<Option<Route>> {
    let device = &uplink.device;
    let family = if v6 { "-6" } else { "-4" };
    let table = uplink
        .routing_table
        .map(|t| t.to_string())
        .unwrap_or_else(|| "all".into());
    let routes = json_command(
        "ip",
        &[
            "-j", family, "route", "show", "table", &table, "default", "dev", device,
        ],
    )
    .await?;
    let mut routes = routes
        .as_array()
        .context("WAN route inventory")?
        .iter()
        .filter(|r| {
            let table = r.get("table").and_then(number).unwrap_or(254);
            table < owned.allocation.table || table >= owned.allocation.table + owned.count as u32
        })
        .collect::<Vec<_>>();
    routes.sort_by_key(|r| {
        (
            r.get("table").and_then(number).unwrap_or(254) != 254,
            r["metric"].as_u64().unwrap_or(0),
        )
    });
    if let Some(first) = routes.first() {
        if uplink.routing_table.is_none()
            && first.get("table").and_then(number).unwrap_or(254) != 254
        {
            ensure!(
                routes.iter().all(|r| r["gateway"] == first["gateway"]),
                "ambiguous WAN gateways; select the platform's routing_table explicitly"
            );
        }
    }
    Ok(routes.first().map(|r| Route {
        device: device.clone(),
        gateway: r["gateway"].as_str().map(str::to_string),
        source: r["prefsrc"].as_str().map(str::to_string),
    }))
}
async fn reserved_marks() -> Result<u32> {
    let mut used = 0u32;
    for family in ["-4", "-6"] {
        let rules = json_command("ip", &["-j", family, "rule", "show"]).await?;
        for rule in rules.as_array().context("ip rule JSON array")? {
            if rule.get("fwmark").is_some() {
                used |= rule.get("fwmask").and_then(number).unwrap_or(u32::MAX);
            }
        }
    }
    // A manager with an unmasked MARK/CONNMARK operation owns all bits. Refuse
    // managed mode instead of silently fighting it. nft native marks are also read.
    for tool in ["iptables-save", "ip6tables-save"] {
        let text = String::from_utf8(command(tool, &["-t", "mangle"]).await?)?;
        for line in text
            .lines()
            .filter(|l| l.contains("-j MARK") || l.contains("-j CONNMARK"))
        {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let mut found = false;
            for pair in fields.windows(2) {
                if matches!(pair[0], "--nfmask" | "--ctmask") {
                    used |= number(&json!(pair[1])).context("unrecognized mark mask")?;
                    found = true;
                } else if matches!(pair[0], "--set-xmark" | "--set-mark") {
                    let mask = pair[1]
                        .split_once('/')
                        .map(|(_, m)| m)
                        .unwrap_or("0xffffffff");
                    used |= number(&json!(mask)).context("unrecognized mark mask")?;
                    found = true;
                }
            }
            if !found {
                used = u32::MAX;
            }
        }
    }
    // iptables-nft JSON rules are included in this inventory too. Unknown native
    // mark expressions fail conservatively; they are not assumed collision-free.
    if let Ok(rules) = command("nft", &["-j", "list", "ruleset"]).await {
        let rules: Value = serde_json::from_slice(&rules)?;
        fn scan(v: &Value, used: &mut u32) {
            match v {
                Value::Object(m) => {
                    if m.get("match").is_some() || m.get("mangle").is_some() {
                        let text = v.to_string();
                        if text.contains("\"mark\"") {
                            fn masks(v: &Value, found: &mut bool, used: &mut u32) {
                                if let Value::Object(m) = v {
                                    if let Some(Value::Array(a)) = m.get("&") {
                                        if let Some(n) = a.get(1).and_then(number) {
                                            *used |= n;
                                            *found = true;
                                        }
                                    }
                                    for child in m.values() {
                                        masks(child, found, used);
                                    }
                                } else if let Value::Array(a) = v {
                                    for child in a {
                                        masks(child, found, used);
                                    }
                                }
                            }
                            let mut found = false;
                            masks(v, &mut found, used);
                            if !found {
                                *used = u32::MAX;
                            }
                        }
                    } else {
                        for child in m.values() {
                            scan(child, used);
                        }
                    }
                }
                Value::Array(a) => {
                    for child in a {
                        scan(child, used);
                    }
                }
                _ => {}
            }
        }
        scan(&rules, &mut used);
    }
    Ok(used)
}
async fn allocate(count: usize) -> Result<Allocation> {
    let inventory = discover().await?;
    let mut tables = BTreeSet::new();
    let mut preferences = BTreeSet::new();
    for key in ["routes4", "routes6", "rules4", "rules6"] {
        for item in inventory[key].as_array().context("routing inventory")? {
            if let Some(n) = item.get("table").and_then(number) {
                tables.insert(n);
            }
            if let Some(n) = item.get("priority").and_then(number) {
                preferences.insert(n);
            }
        }
    }
    let table = (20000..60000)
        .step_by(16)
        .find(|base| (0..count as u32).all(|i| !tables.contains(&(base + i))))
        .context("no free router routing tables")?;
    let first = preferences
        .iter()
        .copied()
        .filter(|n| *n > 0)
        .min()
        .unwrap_or(32766);
    let preference = (1..first)
        .find(|base| base + 2 * (count as u32) < first)
        .context("no free rule priorities ahead of other policy managers")?;
    let used = reserved_marks().await?;
    let shift = [28, 24, 20, 16, 12, 8, 4, 0]
        .into_iter()
        .find(|shift| used & (15 << shift) == 0)
        .context(
            "routing marks conflict: retain external mode or migrate existing unmasked rules",
        )?;
    Ok(Allocation {
        table,
        preference,
        shift,
    })
}
pub(super) async fn check(p: &Policy) -> Result<Value> {
    p.validate()?;
    if p.components.routing == Owner::External && p.components.firewall == Owner::External {
        return Ok(json!({"valid":true,"routing":"external","firewall":"external","mutations":[]}));
    }
    metadata::Metadata::load(p)?.validate(p)?;
    if p.components.routing == Owner::External && p.state_directory.join("receipt.json").exists() {
        bail!("disable the current managed routing before selecting external routing with managed firewall");
    }
    if p.components.firewall == Owner::Client && p.managed_boot && !p.persistent_guard {
        ensure!(
            Path::new("/etc/rc.d/S17qeli-guard").exists(),
            "enable the OpenWrt qeli-guard service before enabling VPN-only integration"
        );
    }
    guard::preflight(p).await?;
    if p.backend == "nft" {
        let rules = String::from_utf8(command("nft", &["list", "ruleset"]).await?)?;
        ensure!(
            !rules.contains("flowtable "),
            "disable forwarding offload before enabling managed routing/firewall"
        );
    }
    let inventory = discover().await?;
    let devices = inventory["devices"]
        .as_array()
        .context("device inventory")?;
    for device in p
        .uplinks
        .iter()
        .map(|u| u.device.as_str())
        .chain(p.networks.iter().map(|n| n.device.as_str()))
    {
        ensure!(
            devices.iter().any(|d| d["ifname"] == device),
            "selected Linux device does not exist: {device}"
        );
    }
    if p.components.routing == Owner::External {
        return Ok(
            json!({"valid":true,"components":p.components,"routing":"external","firewall":"client","mutations":"scoped guard/NAT only; existing routing and administrative INPUT are preserved"}),
        );
    }
    // High-preference source/iif policy rules can bypass or supersede a new
    // manager. Do not infer that two managers agree just because marks differ.
    for key in ["rules4", "rules6"] {
        for r in inventory[key].as_array().context("rule inventory")? {
            let interfaces = p
                .networks
                .iter()
                .map(|n| n.device.as_str())
                .collect::<Vec<_>>();
            let source_conflict = r["src"]
                .as_str()
                .filter(|s| *s != "all")
                .and_then(|s| s.parse::<ipnet::IpNet>().ok())
                .is_some_and(|source| {
                    p.networks
                        .iter()
                        .flat_map(|n| n.subnets.iter())
                        .filter_map(|s| s.parse::<ipnet::IpNet>().ok())
                        .any(|n| n.contains(&source.addr()) || source.contains(&n.addr()))
                });
            let device_conflict = r["iif"].as_str().is_some_and(|d| interfaces.contains(&d))
                || r["oif"].as_str().is_some_and(|d| interfaces.contains(&d));
            ensure!(!source_conflict && !device_conflict, "an existing source/device policy already owns a selected client network; retain external mode or migrate it explicitly");
        }
    }
    let owned = p.state_directory.join("receipt.json");
    let existing = if owned.exists() {
        Some(serde_json::from_slice::<Receipt>(&read_private(
            &owned, 8192,
        )?)?)
    } else {
        None
    };
    if let Some(r) = &existing {
        ensure!(
            r.boot == boot()?
                && r.backend == p.backend
                && r.count == p.uplinks.len() + 1
                && r.layout == layout(p)
                && r.firewall == (p.components.firewall == Owner::Client),
            "stale/incompatible resource layout; disable managed policy before changing its layout"
        );
    }
    if p.backend == "nft" {
        let rules = String::from_utf8(command("nft", &["list", "ruleset"]).await?)?;
        ensure!(
            !rules.contains("flowtable "),
            "disable software/hardware flow offload before enabling managed router policy"
        );
        ensure!(existing.is_some() || !rules.contains("table inet qeli_router {"),"Qeli table exists without ownership receipt; review existing setup before enabling managed mode");
        // fw4 is allowed to continue owning permission to forward packets. This
        // adapter enforces scoped drop/NAT rules; admission must already exist.
    } else {
        for tool in ["iptables-save", "ip6tables-save"] {
            let rules = String::from_utf8(command(tool, &[]).await?)?;
            ensure!(
                existing.is_some() || !rules.contains("QELI_R_"),
                "Qeli chains exist without ownership receipt; explicit migration required"
            );
        }
    }
    let allocation = if let Some(r) = existing {
        r.allocation
    } else {
        allocate(p.uplinks.len() + 1).await?
    };
    Ok(
        json!({"valid":true,"components":p.components,"allocation":allocation,
        "forwarding_admission":"platform firewall must allow selected client networks to selected WAN/TUN; Qeli does not widen administrative access",
        "server_addresses":p.server_addresses,"networks":p.networks,"router_policy":p.router_policy}),
    )
}
async fn ip(args: Vec<String>) -> Result<()> {
    output("ip", &args, None, 5).await?;
    Ok(())
}
fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}
async fn rules(receipt: &Receipt, add: bool) -> Result<()> {
    for family in ["-4", "-6"] {
        let current = if add {
            Some(json_command("ip", &["-j", family, "rule", "show"]).await?)
        } else {
            None
        };
        for index in 0..receipt.count {
            let a = &receipt.allocation;
            let v = vec![
                family.into(),
                "rule".into(),
                if add { "add".into() } else { "del".into() },
                "pref".into(),
                (a.preference + index as u32).to_string(),
                "fwmark".into(),
                format!("0x{:x}/0x{:x}", a.mark(index), a.mask()),
                "lookup".into(),
                a.table(index),
            ];
            // The terminal rule prevents lookup fall-through while a TUN/table
            // disappears or a route is being reconciled. A missing default may
            // NEVER silently turn a VPN-only packet into main-table WAN traffic.
            let terminal = vec![
                family.into(),
                "rule".into(),
                if add { "add".into() } else { "del".into() },
                "pref".into(),
                (a.preference + receipt.count as u32 + index as u32).to_string(),
                "fwmark".into(),
                format!("0x{:x}/0x{:x}", a.mark(index), a.mask()),
                "prohibit".into(),
            ];
            if add {
                let records = current
                    .as_ref()
                    .and_then(Value::as_array)
                    .context("rule inventory")?;
                for (command, preference, terminal_rule) in [
                    (
                        terminal,
                        a.preference + receipt.count as u32 + index as u32,
                        true,
                    ),
                    (v, a.preference + index as u32, false),
                ] {
                    let at = records
                        .iter()
                        .filter(|r| r["priority"].as_u64() == Some(preference as u64))
                        .collect::<Vec<_>>();
                    ensure!(
                        at.len() <= 1,
                        "duplicate rule priority in Qeli's reserved range"
                    );
                    if let Some(rule) = at.first() {
                        let action = rule["action"].as_str().or_else(|| rule["type"].as_str());
                        ensure!(
                            rule.get("fwmark").and_then(number) == Some(a.mark(index))
                                && rule.get("fwmask").and_then(number) == Some(a.mask())
                                && if terminal_rule {
                                    matches!(action, Some("prohibit" | "8"))
                                        || rule.get("action").and_then(number) == Some(8)
                                        || rule.get("type").and_then(number) == Some(8)
                                } else {
                                    rule.get("table").and_then(number)
                                        == Some(a.table + index as u32)
                                },
                            "foreign policy collided with Qeli's reserved rule priority"
                        );
                    } else {
                        ip(command).await?;
                    }
                }
            } else {
                // Crash recovery is idempotent but never deletes by priority only.
                let _ = ip(v).await;
                let _ = ip(terminal).await;
            }
        }
    }
    Ok(())
}
async fn tables(
    p: &Policy,
    r: &Receipt,
    wan_routes: &[(Option<Route>, Option<Route>)],
    vpn: bool,
) -> Result<()> {
    for (v6, family) in [(false, "-4"), (true, "-6")] {
        for index in 0..r.count {
            let table = r.allocation.table(index);
            // A never-populated FIB returns ENOENT when queried by table ID.
            // Enumerating the kernel's tables also represents an empty one safely.
            let all = json_command("ip", &["-j", family, "route", "show", "table", "all"]).await?;
            let old = all
                .as_array()
                .context("owned routes inventory")?
                .iter()
                .filter(|route| {
                    route.get("table").and_then(number) == Some(r.allocation.table + index as u32)
                })
                .collect::<Vec<_>>();
            let mut desired = BTreeSet::new();
            desired.insert("default".to_string());
            // Connected routes (not main defaults or Qeli's server host bypasses)
            // retain local access even while a strict VPN table is unreachable.
            let connected =
                json_command("ip", &["-j", family, "route", "show", "table", "main"]).await?;
            let mut connected = connected
                .as_array()
                .context("connected routes")?
                .iter()
                .collect::<Vec<_>>();
            connected.sort_by_key(|c| {
                c["dev"].as_str().is_some_and(|d| {
                    if let Some(u) = p.uplinks.get(index) {
                        u.device == d
                    } else {
                        p.networks.iter().any(|n| n.device == d)
                    }
                })
            });
            for c in connected {
                let link = c["scope"] == "link"
                    || number(&c["scope"]) == Some(253)
                    || (v6
                        && (c["protocol"] == "kernel" || number(&c["protocol"]) == Some(2))
                        && c.get("gateway").is_none());
                if !link || c["dst"] == "default" || c["dev"] == p.device {
                    continue;
                }
                let (Some(dst), Some(dev)) = (c["dst"].as_str(), c["dev"].as_str()) else {
                    continue;
                };
                if interface(dev).is_err() {
                    continue;
                }
                desired.insert(dst.to_string());
                let mut v = args(&[
                    family, "route", "replace", "table", &table, dst, "dev", dev, "scope", "link",
                ]);
                if let Some(src) = c["prefsrc"].as_str() {
                    v.extend(args(&["src", src]));
                }
                ip(v).await?;
            }
            for subnet in p.local_subnets.iter().filter(|s| address_family(s) == v6) {
                desired.insert(subnet.to_string());
                ip(args(&[
                    family, "route", "replace", "table", &table, "throw", subnet,
                ]))
                .await?;
            }
            let mut v = args(&[family, "route", "replace", "table", &table]);
            if index == p.uplinks.len()
                && vpn
                && Path::new(&format!("/sys/class/net/{}", p.device)).exists()
            {
                // No gateway is invented: the authenticated NetworkPlan owns TUN
                // addresses; a point-to-point TUN route needs only the device.
                v.extend(args(&["default", "dev", &p.device]));
            } else if let Some(route) =
                wan_routes
                    .get(index)
                    .and_then(|pair| if v6 { pair.1.as_ref() } else { pair.0.as_ref() })
            {
                v.push("default".into());
                if let Some(gateway) = &route.gateway {
                    v.extend(args(&["via", gateway]));
                }
                v.extend(args(&["dev", &route.device]));
                if let Some(source) = &route.source {
                    v.extend(args(&["src", source]));
                }
            } else {
                v.extend(args(&["unreachable", "default"]));
            }
            v.extend(args(&["metric", "1000"]));
            ip(v).await?;
            // Replace first, then retire stale owned prefixes. Never flush an
            // active table during failback: healthy connmarked flows retain a
            // valid default throughout the update.
            for old_route in old {
                let Some(dst) = old_route["dst"].as_str() else {
                    continue;
                };
                if desired.contains(dst) {
                    continue;
                }
                let mut remove = args(&[family, "route", "del", "table", &table]);
                if let Some(kind) = old_route["type"].as_str() {
                    match kind {
                        "unicast" | "1" => {}
                        "9" => remove.push("throw".into()),
                        other => remove.push(other.into()),
                    }
                }
                remove.push(dst.into());
                if let Some(dev) = old_route["dev"].as_str() {
                    remove.extend(args(&["dev", dev]));
                }
                if let Some(gateway) = old_route["gateway"].as_str() {
                    remove.extend(args(&["via", gateway]));
                }
                ip(remove).await?;
            }
        }
    }
    Ok(())
}
fn nft_mark(a: &Allocation, index: usize) -> String {
    format!(
        "meta mark set (meta mark & 0x{:08x}) | 0x{:08x}",
        !a.mask(),
        a.mark(index)
    )
}
fn nft_restore(a: &Allocation, count: usize) -> String {
    // Enumerate the small owned mark field. Combining two variable registers
    // with bitwise OR is unsupported by older router kernels/nft versions.
    let mut text = String::new();
    for i in 0..count {
        text.push_str(&format!(
            " ct mark & 0x{:08x} == 0x{:08x} {}\n",
            a.mask(),
            a.mark(i),
            nft_mark(a, i)
        ));
    }
    text
}
fn nft_save(a: &Allocation, count: usize) -> String {
    let mut text = String::new();
    for i in 0..count {
        text.push_str(&format!(
            " meta mark & 0x{:08x} == 0x{:08x} ct mark set (ct mark & 0x{:08x}) | 0x{:08x}\n",
            a.mask(),
            a.mark(i),
            !a.mask(),
            a.mark(i)
        ));
    }
    text
}
fn nft_rules(p: &Policy, r: &Receipt, healthy: &[bool], vpn: bool) -> String {
    let a = &r.allocation;
    let tun = p.uplinks.len();
    let wan = healthy.iter().position(|h| *h);

    let mut out=String::from("table inet qeli_router {\n comment \"qeli-router-v1\"\n chain preroute {\n type filter hook prerouting priority -155; policy accept;\n");
    out.push_str(&nft_restore(a, r.count));
    out.push_str(&format!(" meta mark & 0x{:08x} != 0 return\n", a.mask()));
    for (i, u) in p.uplinks.iter().enumerate() {
        out.push_str(&format!(" iifname \"{}\" {}\n", u.device, nft_mark(a, i)));
    }
    out.push_str(&format!(" iifname \"{}\" {}\n", p.device, nft_mark(a, tun)));
    for n in &p.networks {
        if let Some(index) = selected(n.policy, vpn, wan, tun) {
            for subnet in &n.subnets {
                out.push_str(&format!(
                    " iifname \"{}\" {} saddr {} {}\n",
                    n.device,
                    if address_family(subnet) { "ip6" } else { "ip" },
                    subnet,
                    nft_mark(a, index)
                ));
            }
        }
    }
    out.push_str(&nft_save(a, r.count));
    out.push_str(" }\n");
    out.push_str(" chain output_mark {\n type route hook output priority -155; policy accept;\n");
    out.push_str(control::nft());
    out.push_str(" ip6 daddr fe80::/10 return\n");
    out.push_str(&nft_restore(a, r.count));
    out.push_str(&format!(" meta mark & 0x{:08x} != 0 return\n", a.mask()));
    for server in &p.server_addresses {
        // Preserve the transport's underlay route/SO_BINDTODEVICE. Re-marking a
        // first SYN here changes its route after source-address selection and can
        // break roaming candidates or IPv6. Inbound reply CT restoration precedes this.
        out.push_str(&format!(
            " {} daddr {} return\n",
            if server.is_ipv6() { "ip6" } else { "ip" },
            server
        ));
    }
    if let Some(policy) = p.router_policy {
        if let Some(index) = selected(policy, vpn, wan, tun) {
            out.push_str(&format!(
                " meta mark & 0x{:08x} == 0 {}\n",
                a.mask(),
                nft_mark(a, index)
            ));
        }
    }
    out.push_str(&nft_save(a, r.count));
    out.push_str(" }\n");
    if p.components.firewall == Owner::Client {
        out.push_str(" chain guard {\n type filter hook forward priority -5; policy accept;\n");
        for n in &p.networks {
            if n.policy != NetworkPolicy::Direct {
                out.push_str(&format!(
                    " iifname \"{}\" ct direction reply return\n",
                    n.device
                ));
            }
            if n.policy == NetworkPolicy::VpnOnly {
                // Local destinations stay reachable; connected links still need
                // the platform's normal inter-segment permission.
                for subnet in p
                    .local_subnets
                    .iter()
                    .chain(p.networks.iter().flat_map(|n| n.subnets.iter()))
                {
                    out.push_str(&format!(
                        " iifname \"{}\" {} daddr {} return\n",
                        n.device,
                        if address_family(subnet) { "ip6" } else { "ip" },
                        subnet
                    ));
                }
                out.push_str(&format!(
                    " iifname \"{}\" oifname != \"{}\" counter drop\n",
                    n.device, p.device
                ));
            }
            if n.policy != NetworkPolicy::Direct {
                // Inner IPv6 support is not inferred from the TUN's mere existence.
                // Until the adapter can prove an IPv6 NetworkPlan, block its bypass.
                out.push_str(&format!(
                    " iifname \"{}\" meta nfproto ipv6 oifname != \"{}\" counter drop\n",
                    n.device, p.device
                ));
            }
        }
        out.push_str(
            " }\n chain nat {\n type nat hook postrouting priority srcnat; policy accept;\n",
        );
        for n in &p.networks {
            if n.policy == NetworkPolicy::Direct {
                continue;
            }
            for subnet in &n.subnets {
                out.push_str(&format!(
                    " {} saddr {} oifname \"{}\" masquerade\n",
                    if address_family(subnet) { "ip6" } else { "ip" },
                    subnet,
                    p.device
                ));
            }
        }
        out.push_str(" }\n");
    }
    out.push_str("}\n");
    out
}
async fn own_main_nft() -> Result<bool> {
    let raw = match command("nft", &["-j", "list", "table", "inet", "qeli_router"]).await {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let value: Value = serde_json::from_slice(&raw)?;
    ensure!(
        value["nftables"]
            .as_array()
            .context("main table inventory")?
            .iter()
            .any(|v| v["table"]["name"] == "qeli_router"
                && v["table"]["comment"] == "qeli-router-v1"),
        "foreign Qeli routing table; refusing replacement/cleanup"
    );
    Ok(true)
}
async fn own_main_chain(tool: &str, table: &str, chain: &str) -> Result<()> {
    let text = match command(tool, &["-w", "2", "-t", table, "-S", chain]).await {
        Ok(v) => String::from_utf8(v)?,
        Err(_) => return Ok(()),
    };
    let rules = text
        .lines()
        .filter(|line| line.starts_with("-A "))
        .collect::<Vec<_>>();
    ensure!(
        !rules.is_empty()
            && rules.iter().all(|line| line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|v| v[0] == "--comment" && v[1].trim_matches('"') == "qeli-router-v1")),
        "foreign/empty chain in Qeli routing namespace"
    );
    Ok(())
}
async fn nft(p: &Policy, r: &Receipt, healthy: &[bool], vpn: bool, exists: bool) -> Result<()> {
    ensure!(
        own_main_nft().await? == exists,
        "routing table changed during admission"
    );
    let generated = nft_rules(p, r, healthy, vpn);
    let text = if exists {
        format!("delete table inet qeli_router\n{generated}")
    } else {
        generated
    };
    output(
        "nft",
        &args(&["--check", "-f", "-"]),
        Some(text.as_bytes()),
        5,
    )
    .await?;
    output("nft", &args(&["-f", "-"]), Some(text.as_bytes()), 5).await?;
    Ok(())
}
fn ipt_mark(a: &Allocation, i: usize) -> String {
    format!("MARK --set-xmark 0x{:x}/0x{:x}", a.mark(i), a.mask())
}
fn iptables_rules(p: &Policy, r: &Receipt, healthy: &[bool], vpn: bool, v6: bool) -> String {
    let a = &r.allocation;
    let tun = p.uplinks.len();
    let wan = healthy.iter().position(|h| *h);

    let restore = format!(
        "CONNMARK --restore-mark --nfmask 0x{:x} --ctmask 0x{:x}",
        a.mask(),
        a.mask()
    );
    let save = format!(
        "CONNMARK --save-mark --nfmask 0x{:x} --ctmask 0x{:x}",
        a.mask(),
        a.mask()
    );
    let notzero = format!("-m mark ! --mark 0/0x{:x} -j RETURN", a.mask());
    let mut text = format!(
        "*mangle\n:QELI_R_PRE - [0:0]\n:QELI_R_OUT - [0:0]\n-F QELI_R_PRE\n-F QELI_R_OUT\n{}",
        control::iptables("QELI_R_OUT", v6, "")
    );
    if v6 {
        text.push_str("-A QELI_R_OUT -d fe80::/10 -j RETURN\n");
    }
    text.push_str(&format!(
        "-A QELI_R_PRE -m connmark ! --mark 0/0x{:x} -j {restore}\n-A QELI_R_PRE {notzero}\n",
        a.mask()
    ));
    for (i, u) in p.uplinks.iter().enumerate() {
        text.push_str(&format!(
            "-A QELI_R_PRE -i {} -j {}\n",
            u.device,
            ipt_mark(a, i)
        ));
    }
    text.push_str(&format!(
        "-A QELI_R_PRE -i {} -j {}\n",
        p.device,
        ipt_mark(a, tun)
    ));
    for n in &p.networks {
        if let Some(index) = selected(n.policy, vpn, wan, tun) {
            for subnet in n.subnets.iter().filter(|s| address_family(s) == v6) {
                text.push_str(&format!(
                    "-A QELI_R_PRE -i {} -s {} -j {}\n",
                    n.device,
                    subnet,
                    ipt_mark(a, index)
                ));
            }
        }
    }
    text.push_str(&format!("-A QELI_R_PRE -j {save}\n-A QELI_R_OUT -m connmark ! --mark 0/0x{:x} -j {restore}\n-A QELI_R_OUT {notzero}\n",a.mask()));
    for server in p.server_addresses.iter().filter(|s| s.is_ipv6() == v6) {
        text.push_str(&format!("-A QELI_R_OUT -d {server} -j RETURN\n"));
    }
    if let Some(policy) = p.router_policy {
        if let Some(index) = selected(policy, vpn, wan, tun) {
            text.push_str(&format!(
                "-A QELI_R_OUT -m mark --mark 0/0x{:x} -j {}\n",
                a.mask(),
                ipt_mark(a, index)
            ));
        }
    }
    text.push_str(&format!("-A QELI_R_OUT -j {save}\nCOMMIT\n"));
    if p.components.firewall == Owner::Client {
        text.push_str("*filter\n:QELI_R_GUARD - [0:0]\n-F QELI_R_GUARD\n");
        for n in &p.networks {
            if n.policy != NetworkPolicy::Direct {
                text.push_str(&format!(
                    "-A QELI_R_GUARD -i {} -m conntrack --ctdir REPLY -j RETURN\n",
                    n.device
                ));
            }
            if n.policy == NetworkPolicy::VpnOnly {
                for subnet in p
                    .local_subnets
                    .iter()
                    .chain(p.networks.iter().flat_map(|n| n.subnets.iter()))
                    .filter(|s| address_family(s) == v6)
                {
                    text.push_str(&format!(
                        "-A QELI_R_GUARD -i {} -d {} -j RETURN\n",
                        n.device, subnet
                    ));
                }
                text.push_str(&format!(
                    "-A QELI_R_GUARD -i {} ! -o {} -j DROP\n",
                    n.device, p.device
                ));
            }
            if v6 && n.policy != NetworkPolicy::Direct {
                text.push_str(&format!(
                    "-A QELI_R_GUARD -i {} ! -o {} -j DROP\n",
                    n.device, p.device
                ));
            }
        }
        text.push_str(
            "-A QELI_R_GUARD -j RETURN\nCOMMIT\n*nat\n:QELI_R_NAT - [0:0]\n-F QELI_R_NAT\n",
        );
        for n in &p.networks {
            if n.policy == NetworkPolicy::Direct {
                continue;
            }
            for subnet in n.subnets.iter().filter(|s| address_family(s) == v6) {
                text.push_str(&format!(
                    "-A QELI_R_NAT -s {} -o {} -j MASQUERADE\n",
                    subnet, p.device
                ));
            }
        }
        // A family with no selected source prefix still needs an ownership
        // sentinel; an empty chain is intentionally never adopted as ours.
        text.push_str("-A QELI_R_NAT -j RETURN\nCOMMIT\n");
    }
    text.lines()
        .map(|line| {
            if line.starts_with("-A ") {
                format!("{line} -m comment --comment qeli-router-v1\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect()
}
async fn iptables(p: &Policy, r: &Receipt, healthy: &[bool], vpn: bool) -> Result<()> {
    for (tool, restore, v6) in [
        ("iptables", "iptables-restore", false),
        ("ip6tables", "ip6tables-restore", true),
    ] {
        for (table, chain) in [("mangle", "QELI_R_PRE"), ("mangle", "QELI_R_OUT")] {
            own_main_chain(tool, table, chain).await?;
        }
        if p.components.firewall == Owner::Client {
            for (table, chain) in [("filter", "QELI_R_GUARD"), ("nat", "QELI_R_NAT")] {
                own_main_chain(tool, table, chain).await?;
            }
        }
        let text = iptables_rules(p, r, healthy, vpn, v6);
        output(
            restore,
            &args(&["--test", "--noflush"]),
            Some(text.as_bytes()),
            5,
        )
        .await?;
        output(restore, &args(&["--noflush"]), Some(text.as_bytes()), 5).await?;
        let mut hooks = vec![
            ("mangle", "PREROUTING", "QELI_R_PRE"),
            ("mangle", "OUTPUT", "QELI_R_OUT"),
        ];
        if p.components.firewall == Owner::Client {
            hooks.extend([
                ("filter", "FORWARD", "QELI_R_GUARD"),
                ("nat", "POSTROUTING", "QELI_R_NAT"),
            ]);
        }
        for (table, chain, target) in hooks {
            if command(
                tool,
                &[
                    "-w",
                    "2",
                    "-t",
                    table,
                    "-C",
                    chain,
                    "-m",
                    "comment",
                    "--comment",
                    "qeli-router-v1",
                    "-j",
                    target,
                ],
            )
            .await
            .is_err()
            {
                command(
                    tool,
                    &[
                        "-w",
                        "2",
                        "-t",
                        table,
                        "-I",
                        chain,
                        "1",
                        "-m",
                        "comment",
                        "--comment",
                        "qeli-router-v1",
                        "-j",
                        target,
                    ],
                )
                .await?;
            }
        }
    }
    Ok(())
}
pub(super) async fn cleanup(r: &Receipt) -> Result<()> {
    ensure!(
        r.boot == boot()?,
        "stale boot receipt requires manual review"
    );
    // First remove routing marks/hooks; remove rules/tables only after that succeeds.
    if r.backend == "nft" {
        if own_main_nft().await? {
            command("nft", &["delete", "table", "inet", "qeli_router"]).await?;
        }
    } else {
        for tool in ["iptables", "ip6tables"] {
            let mut hooks = vec![
                ("mangle", "PREROUTING", "QELI_R_PRE"),
                ("mangle", "OUTPUT", "QELI_R_OUT"),
            ];
            if r.firewall {
                hooks.extend([
                    ("filter", "FORWARD", "QELI_R_GUARD"),
                    ("nat", "POSTROUTING", "QELI_R_NAT"),
                ]);
            }
            for (table, chain, target) in hooks {
                own_main_chain(tool, table, target).await?;
                if command(
                    tool,
                    &[
                        "-w",
                        "2",
                        "-t",
                        table,
                        "-C",
                        chain,
                        "-m",
                        "comment",
                        "--comment",
                        "qeli-router-v1",
                        "-j",
                        target,
                    ],
                )
                .await
                .is_ok()
                {
                    command(
                        tool,
                        &[
                            "-w",
                            "2",
                            "-t",
                            table,
                            "-D",
                            chain,
                            "-m",
                            "comment",
                            "--comment",
                            "qeli-router-v1",
                            "-j",
                            target,
                        ],
                    )
                    .await?;
                }
                if command(tool, &["-w", "2", "-t", table, "-S", target])
                    .await
                    .is_ok()
                {
                    command(tool, &["-w", "2", "-t", table, "-F", target]).await?;
                    command(tool, &["-w", "2", "-t", table, "-X", target]).await?;
                }
            }
        }
    }
    rules(r, false).await?;
    for family in ["-4", "-6"] {
        let routes = json_command("ip", &["-j", family, "route", "show", "table", "all"]).await?;
        for i in 0..r.count {
            if routes
                .as_array()
                .context("cleanup route inventory")?
                .iter()
                .any(|route| {
                    route.get("table").and_then(number) == Some(r.allocation.table + i as u32)
                })
            {
                ip(args(&[
                    family,
                    "route",
                    "flush",
                    "table",
                    &r.allocation.table(i),
                ]))
                .await?;
            }
        }
    }
    Ok(())
}
pub(super) async fn restore_rollback(p: &Policy, r: &Receipt) -> Result<()> {
    p.validate()?;
    ensure!(
        r.boot == boot()?
            && r.backend == p.backend
            && r.count == p.uplinks.len() + 1
            && r.layout == layout(p),
        "rollback resource layout mismatch"
    );
    // Reinstall the previously accepted guard immediately even if the VPN INI
    // is temporarily absent. A subsequent worker may refine reachability; no
    // route/guard gap is introduced for the previously VPN-only networks.
    let mut routes = Vec::new();
    for u in &p.uplinks {
        routes.push((route(u, false, r).await?, route(u, true, r).await?));
    }
    let native = status::read(&p.status_file, p.pid_file.as_deref(), &p.device);
    let live = !p.client_disabled && native["available"] == true && native["state"] == "connected";
    rules(r, true).await?;
    tables(p, r, &routes, live).await?;
    let unknown = vec![false; p.uplinks.len()];
    if p.backend == "nft" {
        let exists = command("nft", &["list", "table", "inet", "qeli_router"])
            .await
            .is_ok();
        nft(p, r, &unknown, false, exists).await?;
    } else {
        iptables(p, r, &unknown, false).await?;
    }
    Ok(())
}
async fn probe(device: &str, targets: &[IpAddr], mark: u32, timeout: u64) -> bool {
    let mut pending = tokio::task::JoinSet::new();
    for target in targets {
        let family = if target.is_ipv6() { "-6" } else { "-4" };
        let command_args = args(&[
            family,
            "-n",
            "-c",
            "1",
            "-W",
            &timeout.to_string(),
            "-I",
            device,
            "-m",
            &mark.to_string(),
            &target.to_string(),
        ]);
        pending.spawn(async move {
            output("ping", &command_args, None, timeout + 1)
                .await
                .is_ok()
        });
    }
    let mut good = false;
    while let Some(result) = pending.join_next().await {
        good |= result.unwrap_or(false);
    }
    good
}
pub(super) async fn run(path: &Path) -> Result<()> {
    let _namespace = namespace_lock()?;
    let bytes = read_private(path, 65536)?;
    let p: Policy = serde_json::from_slice(&bytes)?;
    p.validate()?;
    private_dir(&p.state_directory, true)?;
    // flock dies with the worker; the independent transport never shares it.
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p.state_directory.join("lock"))?;
    use std::os::fd::AsRawFd;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another router reconciler is active"
    );
    let mutation = transaction::mutation_lock(&p.state_directory)?;
    transaction::publish_worker(&p.state_directory, &bytes)?;
    let receipt_path = p.state_directory.join("receipt.json");
    let mut previous = if receipt_path.exists() {
        Some(serde_json::from_slice::<Receipt>(&read_private(
            &receipt_path,
            8192,
        )?)?)
    } else {
        None
    };
    if previous
        .as_ref()
        .is_some_and(|r| Some(&r.boot) != boot().ok().as_ref())
    {
        // Kernel routes/rules do not survive reboot; never execute a stale boot's
        // cleanup against an unrelated new kernel allocation.
        fs::remove_file(&receipt_path)?;
        previous = None;
    }
    let mut firewall = guard::Guard::default();
    if p.components.routing == Owner::External {
        if p.components.firewall == Owner::Client {
            check(&p).await?;
            transaction::arm(path, &p, &bytes).await?;
        } else {
            transaction::accept_external(path, &p, &bytes)?;
        }
        if let Some(receipt) = previous {
            cleanup(&receipt).await?;
            fs::remove_file(&receipt_path)?;
        }
        firewall.sync(&p, false, false).await?;
        // A supervised external-mode worker is idle instead of exiting into an
        // unlimited procd respawn loop after migration/automatic rollback.
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        transaction::publish_ready(&p.state_directory)?;
        drop(mutation);
        loop {
            tokio::select! {_=terminate.recv()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
            if read_private(path, 65536)? != bytes {
                break;
            }
            let _mutation = transaction::mutation_lock(&p.state_directory)?;
            let state = status::read(&p.status_file, p.pid_file.as_deref(), &p.device);
            let live =
                !p.client_disabled && state["available"] == true && state["state"] == "connected";
            tokio::time::timeout(Duration::from_secs(30), firewall.sync(&p, live, live))
                .await
                .context("scoped firewall cycle deadline")??;
        }
        return Ok(());
    }
    let checked = check(&p).await?;
    transaction::arm(path, &p, &bytes).await?;
    firewall.sync(&p, false, false).await?;
    let r = if let Some(receipt) = previous {
        ensure!(
            receipt.boot == boot()?
                && receipt.backend == p.backend
                && receipt.firewall == (p.components.firewall == Owner::Client)
                && receipt.count == p.uplinks.len() + 1
                && receipt.layout == layout(&p),
            "owned resource layout changed: first disable managed policy to clean it up"
        );
        receipt
    } else {
        let allocation = serde_json::from_value(checked["allocation"].clone())?;
        let receipt = Receipt {
            boot: boot()?,
            allocation,
            backend: p.backend.clone(),
            firewall: p.components.firewall == Owner::Client,
            count: p.uplinks.len() + 1,
            layout: layout(&p),
        };
        // Record intent before any mutation: never forget partially-created resources.
        write_private(&receipt_path, &serde_json::to_vec(&receipt)?)?;
        // Scoped guard goes in before table/rule changes. No INPUT rules are
        // changed: administrative access is outside this component's authority.
        rules(&receipt, true).await?;
        if p.backend == "nft" {
            nft(&p, &receipt, &vec![false; p.uplinks.len()], false, false).await?;
        } else {
            iptables(&p, &receipt, &vec![false; p.uplinks.len()], false).await?;
        }
        receipt
    };
    transaction::publish_ready(&p.state_directory)?;
    drop(mutation);
    let mut health: HashMap<String, HealthState> = HashMap::new();
    let mut applied = None;
    let mut route_signature = None;
    let mut live_rules = None;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        // Bound the whole mutation batch, not only individual child commands:
        // the independent watchdog must always be able to acquire its lock.
        let cycle = async {
            let mutation = transaction::mutation_lock(&p.state_directory)?;
            ensure!(
                read_private(path, 65536)? == bytes,
                "router policy changed; restart/review reconciler"
            );
            rules(&r, true).await?;
            let mut routes = Vec::new();
            let mut good = Vec::new();
            // WAN probes and TUN probes have explicit device AND routing mark; an
            // answer obtained over a fallback path cannot produce a false green.
            for u in &p.uplinks {
                routes.push((route(u, false, &r).await?, route(u, true, &r).await?));
            }
            let native = status::read(&p.status_file, p.pid_file.as_deref(), &p.device);
            let live =
                !p.client_disabled && native["available"] == true && native["state"] == "connected";
            let prior_usable = health.get(&p.device).is_some_and(|h| h.good) && live;
            firewall.sync(&p, live, prior_usable).await?;
            let connected4 = command("ip", &["-4", "route", "show", "table", "main"]).await?;
            let connected6 = command("ip", &["-6", "route", "show", "table", "main"]).await?;
            let current_routes = format!("{routes:?}:{live}:{connected4:?}:{connected6:?}");
            if route_signature.as_ref() != Some(&current_routes) {
                tables(&p, &r, &routes, live).await?;
                route_signature = Some(current_routes);
            }
            let mut probes = tokio::task::JoinSet::new();
            for (i, u) in p.uplinks.iter().enumerate() {
                let device = u.device.clone();
                let targets = u
                    .probes
                    .iter()
                    .copied()
                    .filter(|ip| {
                        if ip.is_ipv6() {
                            routes[i].1.is_some()
                        } else {
                            routes[i].0.is_some()
                        }
                    })
                    .collect::<Vec<_>>();
                let mark = r.allocation.mark(i);
                let deadline = p.health.timeout_secs;
                probes.spawn(async move { (i, probe(&device, &targets, mark, deadline).await) });
            }
            let mut results = vec![false; p.uplinks.len()];
            while let Some(result) = probes.join_next().await {
                let (i, result) = result?;
                results[i] = result;
            }
            for (i, u) in p.uplinks.iter().enumerate() {
                let success = results[i];
                good.push(
                    health
                        .entry(u.device.clone())
                        .or_default()
                        .update(success, &p.health),
                );
            }
            let probe_ok = if live && !p.health.tunnel_probes.is_empty() {
                probe(
                    &p.device,
                    &p.health.tunnel_probes,
                    r.allocation.mark(p.uplinks.len()),
                    p.health.timeout_secs,
                )
                .await
            } else {
                live
            };
            let vpn = health
                .entry(p.device.clone())
                .or_default()
                .update(probe_ok, &p.health)
                && live;
            firewall.sync(&p, live, vpn).await?;
            let signature = serde_json::to_string(&(
                routes.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>(),
                &good,
                vpn,
            ))?;
            let actual = if p.backend == "nft" {
                command("nft", &["-s", "list", "table", "inet", "qeli_router"])
                    .await
                    .ok()
            } else {
                None
            };
            let exists = actual.is_some();
            if applied.as_ref() != Some(&signature)
                || actual != live_rules
                || p.backend == "iptables"
            {
                if p.backend == "nft" {
                    nft(&p, &r, &good, vpn, exists).await?;
                } else {
                    iptables(&p, &r, &good, vpn).await?;
                }
                applied = Some(signature);
                if p.backend == "nft" {
                    live_rules = Some(
                        command("nft", &["-s", "list", "table", "inet", "qeli_router"]).await?,
                    );
                }
            }
            write_private(
                &p.state_directory.join("health.json"),
                &serde_json::to_vec(
                    &json!({"schema":1,"vpn":vpn,"native":native,"uplinks":p.uplinks.iter().zip(&good).map(|(u,g)|json!({"device":u.device,"internet":g})).collect::<Vec<_>>(),"server_path":"outer underlay remains transport/platform-owned; authenticated native status plus bound TUN internet probe"}),
                )?,
            )?;
            drop(mutation);
            Ok::<_, anyhow::Error>(())
        };
        tokio::time::timeout(Duration::from_secs(30), cycle)
            .await
            .context("router reconciliation cycle deadline")??;
        tokio::select! {
            _=tokio::time::sleep(Duration::from_secs(p.health.interval_secs))=>{},
            _=interrupt.recv()=>{break;},
            _=tokio::signal::ctrl_c()=>{break;},
        }
        // A reload is performed by the platform supervisor. Never half-apply a
        // concurrent on-disk policy without fresh preflight/rollback admission.
        ensure!(
            read_private(path, 65536)? == bytes,
            "router policy changed; restart/review reconciler"
        );
    }
    // Stop deliberately retains a fail-closed guard. Disabling the integration
    // explicitly (external mode) owns cleanup; killing the VPN cannot remove it.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Policy, Receipt) {
        let mut p = Policy::default();
        p.components = Components {
            routing: Owner::Client,
            firewall: Owner::Client,
        };
        p.uplinks = vec![
            Uplink {
                device: "eth3".into(),
                probes: vec!["1.1.1.1".parse().unwrap()],
                routing_table: None,
            },
            Uplink {
                device: "eth4".into(),
                probes: vec!["8.8.8.8".parse().unwrap()],
                routing_table: None,
            },
        ];
        p.networks = vec![Network {
            device: "br-vpn".into(),
            subnets: vec!["192.168.17.0/24".into()],
            policy: NetworkPolicy::VpnOnly,
        }];
        p.server_addresses = vec!["203.0.113.10".parse().unwrap()];
        let r = Receipt {
            boot: "fixture".into(),
            allocation: Allocation {
                table: 21000,
                preference: 1200,
                shift: 24,
            },
            backend: "nft".into(),
            firewall: true,
            count: 3,
            layout: layout(&p),
        };
        (p, r)
    }
    #[test]
    fn restores_only_owned_mark_field_before_selecting_new_paths() {
        let (p, r) = fixture();
        let s = nft_rules(&p, &r, &[true, true], true);
        assert!(s.contains("meta mark & 0xf0ffffff"));
        assert!(
            s.find("meta mark & 0x0f000000 != 0 return").unwrap()
                < s.find("iifname \"eth3\"").unwrap()
        );
        assert!(!s.contains("flush ruleset"));
        assert!(!s.contains("hook input"));
        assert!(s.contains("iifname \"br-vpn\" oifname != \"qeli0\" counter drop"));
    }
    #[test]
    fn vpn_fallback_moves_new_connections_only() {
        let (mut p, r) = fixture();
        p.networks[0].policy = NetworkPolicy::VpnFallback;
        let off = nft_rules(&p, &r, &[false, true], false);
        let on = nft_rules(&p, &r, &[true, true], true);
        assert!(off
            .contains("saddr 192.168.17.0/24 meta mark set (meta mark & 0xf0ffffff) | 0x02000000"));
        assert!(on
            .contains("saddr 192.168.17.0/24 meta mark set (meta mark & 0xf0ffffff) | 0x03000000"));
    }
    #[test]
    fn iptables_ipv6_has_no_ipv4_addresses_and_does_not_flush_base_chains() {
        let (p, r) = fixture();
        let s = iptables_rules(&p, &r, &[true, true], true, true);
        assert!(!s.contains("192.168."));
        assert!(!s.contains("-F FORWARD"));
        assert!(!s.contains("*raw"));
        assert!(s.contains("--nfmask 0xf000000 --ctmask 0xf000000"));
        assert!(s.contains("-A QELI_R_NAT -j RETURN -m comment --comment qeli-router-v1"));
        assert!(s.contains("-A QELI_R_GUARD -i br-vpn ! -o qeli0 -j DROP"));
    }
    #[test]
    fn hysteresis_does_not_flap_on_single_failure() {
        let mut s = HealthState::default();
        let h = Health::default();
        assert!(!s.update(true, &h));
        assert!(s.update(true, &h));
        assert!(s.update(false, &h));
        assert!(s.update(false, &h));
        assert!(!s.update(false, &h));
        assert!(!s.update(true, &h));
        assert!(s.update(true, &h));
    }
    #[test]
    fn outer_endpoint_keeps_transport_underlay_binding() {
        let (mut p, r) = fixture();
        p.router_policy = Some(NetworkPolicy::VpnOnly);
        let s = nft_rules(&p, &r, &[false, false], false);
        assert!(s.contains("ip daddr 203.0.113.10 return"));
        let s = iptables_rules(&p, &r, &[false, false], false, false);
        assert!(s.contains("-A QELI_R_OUT -d 203.0.113.10 -j RETURN"));
    }
    #[test]
    fn nft_transfer_uses_constant_masks_supported_by_router_kernels() {
        let (p, r) = fixture();
        let s = nft_rules(&p, &r, &[true, true], true);
        assert!(!s.contains("| (ct mark"));
        assert!(!s.contains("| (meta mark"));
        assert!(!s.contains("chain mark {"));
        let s = iptables_rules(&p, &r, &[true, true], true, false);
        assert!(
            s.contains("-A QELI_R_OUT -m connmark ! --mark 0/0xf000000 -j CONNMARK --restore-mark")
        );
    }
}
