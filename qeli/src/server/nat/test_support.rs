//! Real child processes model rules in private files; no host firewall/sysctl writes.
use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::MutexGuard,
    time::{Duration, Instant},
};

static SERIAL: Mutex<()> = Mutex::new(());
pub(super) struct Fixture {
    pub(super) dir: PathBuf,
    pub(super) profile: String,
    ids: Mutex<Vec<DnsInputId>>,
    _serial: MutexGuard<'static, ()>,
}
const TOOL: &str = r#"
printf '%s\n' "$*" >> "$0.calls"
[ "$1" = --wait ] && shift 2
if [ "$1" = --version ]; then
  [ -e "$0.probe-delay" ] && sleep "$(cat "$0.probe-delay")"
  printf fixture; exit 0
fi
[ "$1" = -t ] && shift 2
op=$1; chain=$2; shift 2
proto=udp
while [ "$#" -gt 0 ]; do
  if [ "$1" = -p ]; then proto=$2; shift; fi
  shift
done
case "$op" in
  -S) [ -e "$0.inventory-delay" ] && sleep "$(cat "$0.inventory-delay")"; printf '%s\n' "-P $chain ACCEPT"; exit 0;;
  -C) [ -e "$0.$chain.$proto" ] && exit 0; exit 1;;
  -I|-A) touch "$0.$chain.$proto"; [ -e "$0.insert-$proto-delay" ] && sleep "$(cat "$0.insert-$proto-delay")"; exit 0;;
  -D)
    [ -e "$0.deny-$proto" ] && exit 4
    rm -f "$0.$chain.$proto"
    [ -e "$0.$proto-delay" ] && sleep "$(cat "$0.$proto-delay")"
    exit 0;;
  *) exit 17;;
esac
"#;
impl Fixture {
    pub(super) fn new() -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let profile = format!("budget-{}", rand::random::<u64>());
        let dir = std::env::temp_dir().join(format!("qeli-nat-{}-{profile}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        for bin in ["iptables", "ip6tables"] {
            let path = dir.join(bin);
            std::fs::write(&path, format!("#!/bin/sh\n{TOOL}")).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            dir,
            profile,
            ids: Mutex::new(Vec::new()),
            _serial: serial,
        }
    }
    pub(super) fn run<T>(&self, run: impl FnOnce() -> T) -> T {
        cleanup_budget::with_paths(
            ["iptables", "ip6tables"]
                .map(|bin| Some(self.dir.join(bin).to_str().unwrap().to_owned())),
            run,
        )
    }
    pub(super) fn flag(&self, name: &str, value: &str) {
        std::fs::write(self.dir.join(name), value).unwrap();
    }
    pub(super) fn calls(&self, bin: &str) -> String {
        std::fs::read_to_string(self.dir.join(format!("{bin}.calls"))).unwrap_or_default()
    }
    pub(super) fn retain(&self, ipv6: bool, proto: &str) {
        let _guard = firewall_program_lock().lock().unwrap();
        owned_rules()
            .lock()
            .unwrap()
            .retain(
                &self.profile,
                crate::nat_owned_rules::Rule {
                    ipv6,
                    table: "filter".into(),
                    chain: "FORWARD".into(),
                    args: vec![
                        "-p".into(),
                        proto.into(),
                        "-m".into(),
                        "comment".into(),
                        "--comment".into(),
                        tag(&self.profile),
                        "-j".into(),
                        "ACCEPT".into(),
                    ],
                },
            )
            .unwrap();
        self.flag(
            &format!(
                "{}.FORWARD.{}",
                if ipv6 { "ip6tables" } else { "iptables" },
                proto
            ),
            "present",
        );
    }
    pub(super) fn retained(&self) -> Vec<bool> {
        let _guard = firewall_program_lock().lock().unwrap();
        let mut families = Vec::new();
        let _ = owned_rules()
            .lock()
            .unwrap()
            .cleanup(Some(&self.profile), |rule| {
                families.push(rule.ipv6);
                anyhow::bail!("inspection only")
            });
        families
    }
    pub(super) fn retire_dns(&self) -> DnsInputRules {
        let _guard = firewall_program_lock().lock().unwrap();
        let owned =
            DnsInputRules::new(&self.profile, "vpn0", "192.0.2.0/24", "192.0.2.1", 53).unwrap();
        let mut registry = dns_input_registry().lock().unwrap();
        let id = registry
            .begin(owned.clone(), |_| panic!("unexpected previous owner"))
            .unwrap();
        self.ids.lock().unwrap().push(id);
        assert!(registry
            .finish(id, |_| anyhow::bail!("defer fixture cleanup"))
            .is_err());
        self.flag("iptables.INPUT.udp", "present");
        self.flag("iptables.INPUT.tcp", "present");
        owned
    }
    pub(super) fn dns_lease(&self) -> DnsInputLease {
        let _guard = firewall_program_lock().lock().unwrap();
        let owner = dns_input_registry()
            .lock()
            .unwrap()
            .begin_owned(
                DnsInputRules::new(&self.profile, "vpn0", "192.0.2.0/24", "192.0.2.1", 53).unwrap(),
                |_| panic!("unexpected pending generation"),
            )
            .unwrap();
        self.ids.lock().unwrap().push(owner.id());
        self.flag("iptables.INPUT.udp", "present");
        self.flag("iptables.INPUT.tcp", "present");
        DnsInputLease {
            owner: Some(owner),
            profile: self.profile.clone(),
        }
    }
    pub(super) fn cleanup(&self) {
        self.run(|| cleanup_until(&self.profile, budget(3000)))
            .unwrap();
        assert!(self.retained().is_empty());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _guard = firewall_program_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = owned_rules()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cleanup(Some(&self.profile), |_| Ok(()));
        let mut registry = dns_input_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for id in self.ids.get_mut().unwrap() {
            let _ = registry.finish(*id, |_| Ok(()));
        }
        let _ = registry.retry(Some(&self.profile), |_| Ok(()));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
pub(super) fn budget(ms: u64) -> Budget {
    Budget::new().with_deadline(Instant::now() + Duration::from_millis(ms))
}
pub(super) fn deadline(result: anyhow::Result<()>) {
    let error = result.unwrap_err();
    assert!(format!("{error:#}").contains("deadline"), "{error:#}");
}
