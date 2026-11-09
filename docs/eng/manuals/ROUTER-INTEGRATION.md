# OpenWrt and Keenetic: manual and client-managed policies

[Русский](../../ru/manuals/ROUTER-INTEGRATION.md) · English

Experimental integration entered `dev` in commit `33805e96`. Install matching
**client binary and package/templates**. A `0.8.5` version string alone does not
prove support: check `qeli-client router --help`. The 0.8.5 OpenWrt feed pin/hash
includes this integration and the UDP fixes; the SDK source export was verified,
not an IPK build. A server upgrade does not add these local client commands.

Base installation: [OpenWrt](OPENWRT-INSTALL.md), [Keenetic](KEENETIC-DEPLOY.md),
[OpkgTun registration](../../../release/keenetic/opkgtun/README.md).
This guide configures **existing** networks and WANs. Wi-Fi, DHCP, provider
connections and forwarding admission in fw4/KeeneticOS must already be configured.

## 1. Choose ownership and network policy

There are three independent choices:

1. **Route/firewall owner:** existing scripts/firmware or the separate Qeli
   controller. External ownership remains the default.
2. **Client network path:** `direct`, `vpn_only` or `vpn_fallback`.
3. **TUN owner:** the ordinary client or KeeneticOS/NDM with OpkgTun. Choosing
   OpkgTun does not automatically enable Qeli's policy controller.

| Route owner `routing` | Restriction owner `firewall` | Use case |
|---|---|---|
| `external` | `external` | Existing scripts, mwan3/PBR or KeeneticOS policies |
| `client` | `client` | Built-in policies for existing networks, path checks and scoped firewall/NAT |
| `client` | `external` | Qeli selects routes; the administrator supplies firewall rules; `vpn_only` is rejected |
| `external` | `client` | Firmware/scripts retain routes; Qeli supplies scoped restrictions and TUN NAT |

External mode still connects the VPN and publishes status. It does not configure
routes, DNS or WAN leak protection for you. Existing full-tunnel `gateway=true`
is a separate core feature, not a synonym for `components.routing=client`;
disable it before using the new route controller.

With `routing=external`, selecting `vpn_fallback` in JSON does not create route
failover: the external owner must provide it. Without managed routing the guard
uses native tunnel state, not the controller's WAN/TUN ICMP probes.

Do not enable two owners for the same network. Selecting `client` does not delete
custom rules. Migrate only rules for the selected networks; globally stopping
mwan3/PBR can affect other networks and management connectivity.

### Network policies with `routing=client`

| `networks[].policy` | VPN available | VPN unavailable |
|---|---|---|
| `direct` | Selected physical WAN | Physical WAN |
| `vpn_only` | TUN | WAN egress blocked; permitted local access retained |
| `vpn_fallback` | New connections prefer TUN | New connections select an available WAN |

`uplinks` order determines preference: the first healthy WAN is used for new
connections. Healthy TCP/UDP sessions on WAN2 retain their path when WAN1 returns.
Existing WAN sessions also need not move immediately into a recovered VPN.
A failed ordinary TCP session cannot migrate between different public IPs;
the application may need to reconnect.

`local_subnets` lists permitted local destinations. The controller does not open
administrative INPUT/SSH/web ports. Replies to platform-admitted inbound
connections and DNAT return through the incoming WAN/TUN; conntrack reply
direction is not a new WAN connection initiated by a VPN-only client.

## 2. Requirements for managed mode

- Run as root with `ip-full` and the selected firewall backend. OpenWrt nftables
  needs `nftables-json` and `kmod-nft-nat`.
- Disable software/hardware forwarding offload in firmware, then acknowledge
  `offload_disabled: true`. The flag does not disable acceleration itself.
- The controller and native status validator require procfs network namespace
  interfaces, including `/proc/thread-self/ns/net` and `/proc/<PID>/ns/net`.
  The base client's compatibility path for kernels without `CONFIG_NET_NS`
  does **not** automatically extend to these new features; keep external mode
  on those systems.
- Managed routing requires `gateway=false`, `kill_switch=false`,
  `route_local=false`, `pull_routes=false`, `dns=off/system`, and disabled
  `gateway_nat`, `forward`, `exit_node`. OpenWrt's renderer adds
  `pull_routes=false` when `router_routing=client`.
- Keenetic VPN-only requires an actual permanent firmware WAN block before
  Entware starts. `persistent_guard=true` only acknowledges that protection.
  Entware cannot protect the earlier boot period before `/opt` mounts.
  OpenWrt uses the early `qeli-guard` service for this purpose.

For a remote transition from full-tunnel, first verify an alternative management
path. Changing the VPN profile can restart the VPN itself. The 120-second policy
watchdog does not restore profiles, credentials, arbitrary UCI networks, custom
scripts or administrative settings.

## 3. OpenWrt: configure through LuCI

1. Open **Services → qeli VPN → Router integration**. If absent, update the client,
   init files and LuCI together from a compatible bundle.
2. For manual operation leave **Routing owner = External / manual scripts** and
   **Scoped firewall owner = External / manual scripts**. Continue below only
   when enabling managed policies.
3. Discover existing Linux network/WAN devices:

   ```sh
   qeli-client router discover
   ubus call network.interface.wan status
   ip -br address
   ```

   A UCI interface `wan2` may use Linux device `lan1` or `pppoe-wan2`. JSON needs
   the **Linux device**, not the SSID label or logical UCI name. Configure the
   backup provider's DHCP/PPPoE in OpenWrt separately.
4. Disable offload, full-tunnel, core kill-switch and `route_local`; keep
   `dns=off/system`. Select `client` / `client` ownership.
5. Paste the example below into **Advanced router policy (JSON)**, replacing
   devices, prefixes and server IPs. **Save & Apply** validates the candidate
   before publishing; the controller then applies it with rollback protection.
6. Enable the independent policy service at boot. Verify a **new** SSH/web
   management connection and egress from a device in **each selected network**.
   Within 120 seconds press **Confirm router policy**. A ping from the router
   alone does not test a client Wi-Fi network's policy.

   ```sh
   /etc/init.d/qeli-router enable
   ```

   After verification, confirm separately:

   ```sh
   /etc/init.d/qeli-router confirm_policy
   ```

### JSON for two WANs and two client networks

`192.0.2.10` is a documentation address. Replace it with your server's IP and
include every A/AAAA address actually used. Automatic DNS-set refresh is not
implemented. This example permits WAN fallback; change that network's `policy`
to `vpn_only` for strict operation.

```json
{
  "offload_disabled": true,
  "uplinks": [
    {"device": "wan", "probes": ["1.1.1.1", "8.8.8.8"]},
    {"device": "lan1", "probes": ["1.1.1.1", "8.8.8.8"]}
  ],
  "networks": [
    {"device": "br-vpn", "subnets": ["192.168.77.0/24"], "policy": "vpn_fallback"},
    {"device": "br-lan", "subnets": ["192.168.1.0/24"], "policy": "direct"}
  ],
  "local_subnets": ["192.168.1.0/24"],
  "server_addresses": ["192.0.2.10"],
  "health": {
    "tunnel_probes": ["1.0.0.1"],
    "interval_secs": 3,
    "timeout_secs": 1,
    "up": 2,
    "down": 3
  }
}
```

`br-vpn` must already exist with its address/DHCP service. This JSON creates no
SSID, VLAN or forwarding-admission zone. `subnets` contains canonical source
prefixes; default `/0` and overlapping client prefixes are rejected.

### The same settings through UCI

Save the adapted JSON as `/tmp/qeli-router-policy.json`, mode 0600. UCI option
`router_policy` contains the **whole document**. The identically named JSON field
`router_policy` concerns router-originated traffic; leave it `null` or omitted.

```sh
uci set qeli.main.gateway='0'
uci set qeli.main.kill_switch='0'
uci set qeli.main.route_local='0'
uci set qeli.main.dns='off'
uci set qeli.main.router_routing='client'
uci set qeli.main.router_firewall='client'
uci set qeli.main.router_policy="$(cat /tmp/qeli-router-policy.json)"
uci commit qeli
/etc/init.d/qeli-router enable
/etc/init.d/qeli reload
```

After verifying a fresh management connection and every selected network,
run confirmation as a separate action:

```sh
/etc/init.d/qeli-router confirm_policy
```

Server settings, credentials and VPN enabled intent must already be configured
using the [installation guide](OPENWRT-INSTALL.md). Confirmation is a separate
action after successful checks, not an unconditional installer command.

For mixed ownership, set the relevant UCI owner to `external`. With
`routing=client, firewall=external` use only `direct`/`vpn_fallback` and configure
the external firewall yourself. LuCI uses these same options.

### Services, files and returning to scripts

| Object | Purpose |
|---|---|
| `/etc/config/qeli` | UCI intent, JSON and owners |
| `/etc/qeli/router.json` | Generated effective policy; do not edit manually |
| `/etc/init.d/qeli-guard` | START=17: scoped restrictions before networking |
| `/etc/init.d/qeli-router` | START=18: independent procd policy controller |
| `/etc/init.d/qeli` | VPN process and its profile |
| `/var/run/qeli/router/health.json` | WAN/TUN probe results |

Selecting managed firewall enables `qeli-guard`. Packaged ifup/ifupdate hotplug
retries application. Policy-only reload can retain the VPN process when
INI/credentials are unchanged. Stopping the VPN or `qeli-router stop` retains
the guard; it does not restore manual ownership.

```sh
# Clean only the new controller's resources and persist external/external UCI:
/etc/init.d/qeli-router disable_policy
```

Then activate the prepared external rules for these networks. Do not substitute
deleting JSON or killing a process for `disable_policy`. If the controller has
never been enabled, simply select both external owners; there is nothing to clean.

Manual installation of the new features also needs matching `qeli.router.init` →
`/etc/init.d/qeli-router`, `qeli.guard.init` → `/etc/init.d/qeli-guard`,
`98-qeli-policy` → `/etc/hotplug.d/iface/98-qeli-policy`, and `qeli.sysupgrade` →
`/lib/upgrade/keep.d/qeli`. Init/hotplug scripts must be executable; a compatible
package installs them. Do not overwrite your `/etc/config/qeli` with the empty
repository example during an upgrade.

## 4. Keenetic: ordinary TUN and OpkgTun

Choose interface ownership independently from route/firewall ownership:

| Variant | Template | INI | Address/link owner |
|---|---|---|---|
| Ordinary Entware TUN | `release/keenetic/S99qeli` | `dev=vpn0`, `dev_attach=false` | Qeli |
| OpkgTun | `release/keenetic/opkgtun/S99qeli` and wan.d hook | `dev=opkgtun0`, `dev_attach=true` | KeeneticOS/NDM |

Example device names must match the installed template's `TUN`/`OPKGTUN`.
Complete [OpkgTun registration](../../../release/keenetic/opkgtun/README.md)
first. The new controller neither registers OpkgTun nor assigns NDM's addresses.

### Manual routes or KeeneticOS policies

Keep external `components` and do not run `policy-start`. Merely creating
`/opt/etc/qeli/router.json` does not activate it: a private `router.enabled`
marker is required. If the controller was active, restore external ownership:

```sh
/opt/etc/init.d/S99qeli policy-disable
```

For fully external NAT/routes set `GATEWAY=no` in S99qeli and disable core
`gateway_nat`/`forward`/`exit_node`. This differs from the older whole-LAN gateway
setup, which intentionally enables core or legacy NAT. OpkgTun can retain NDM
routes/NAT. Do not mark the same networks with Qeli and an active NDM policy.

### Enable the built-in controller

1. Check `/opt/bin/qeli-client router --help`, existing Linux devices with
   `router discover`, offload and procfs namespace support.
2. Prepare a working split-tunnel profile. **Replace**, rather than duplicate,
   these keys in the existing `[qeli]` section:

   ```ini
   gateway = false
   gateway_nat = false
   forward = false
   exit_node = false
   kill_switch = false
   route_local = false
   pull_routes = false
   dns = off
   ```

   Retain server, credentials and masking. Ordinary TUN uses `dev=vpn0`,
   `dev_attach=false`; OpkgTun uses `dev=opkgtun0`, `dev_attach=true`.
   Set `GATEWAY=no` in S99qeli for this scenario. Applying INI edits requires
   a separate VPN stop/start; `policy-start` does not update a running VPN's INI.
3. Generate a **candidate**, preserving the active policy:

   ```sh
   umask 077
   /opt/bin/qeli-client router example --platform keenetic > /opt/etc/qeli/router.candidate.json
   vi /opt/etc/qeli/router.candidate.json
   ```

   Set `"components": {"routing": "client", "firewall": "client"}`, retain
   `backend: "iptables"`, and set
   real `uplinks`, `networks`, `local_subnets`, `server_addresses`,
   `health.tunnel_probes` as in the OpenWrt example. Set `offload_disabled: true`,
   `router_policy: null`. The example already supplies Keenetic paths:
   `/tmp/qeli-status/status.json`, `/opt/var/run/qeli-client.pid`,
   `/tmp/qeli-router`. Change `device` to `opkgtun0` for OpkgTun. Do not copy
   OpenWrt's `managed_boot` or `client_metadata`.
4. For `vpn_only`, configure permanent firmware protection first, then set
   `persistent_guard: true`. For permitted `vpn_fallback` keep its default `false`.
5. Check and publish the candidate. `/opt/etc/qeli` must be root-owned 0700 and
   JSON 0600. Back up the previous JSON if it exists.

   ```sh
   /opt/bin/qeli-client router check --policy /opt/etc/qeli/router.candidate.json &&
       mv /opt/etc/qeli/router.candidate.json /opt/etc/qeli/router.json &&
       /opt/etc/init.d/S99qeli policy-start
   ```

   Verify new management access and each network, then confirm separately
   before the 120-second deadline:

   ```sh
   /opt/etc/init.d/S99qeli policy-confirm
   ```

`policy-start` creates `router.enabled`, launches a separate process and enables
subsequent S99qeli starts to pick it up. Repeating it after JSON edits replaces
only the controller. It does not register an NDM service. If admission failed
because an interface/route was not yet present, resolve that condition and retry;
a complete native NDM late-start adapter is not implemented.

| S99qeli command | Effect |
|---|---|
| `start` / `stop` / `restart` | VPN process lifecycle; the separate guard remains |
| `policy-start` | Start/update the selected policy controller |
| `policy-stop` | Stop only the controller; retain the guard |
| `policy-confirm` | Confirm the current 120-second transaction |
| `policy-disable` | Remove owned resources/activation marker; persist external owners |
| `status` | Process status plus separately validated tunnel status |

## 5. Parameters and path checks

| JSON field | Meaning |
|---|---|
| `uplinks` | Physical WANs in preference order, already configured by firmware |
| `uplinks[].routing_table` | Optional existing platform table when gateway discovery is ambiguous |
| `uplinks[].probes` | 1–4 literal ICMP targets; one successful target is sufficient per cycle |
| `networks` | Linux device, source prefixes and policy |
| `local_subnets` | Explicit local bypass prefixes; never `/0` |
| `server_addresses` | All server IPs actually used; maintained by the administrator |
| `health.tunnel_probes` | Literal targets for Internet checks through the TUN |
| `health.interval_secs` | Pause between cycles, default 3 s; not total failover time |
| `health.timeout_secs` | Probe timeout, default 1 s |
| `health.up` / `health.down` | Consecutive successes/failures, default 2/3 |
| `backend` | OpenWrt defaults to `nft`; Keenetic example uses `iptables` |
| `router_policy` | Keep `null`: router-originated routing remains externally owned |

Qeli allocates its own table IDs, priorities and mark bits. Do not copy table 100
or another script's mask. Changes to backend, WAN ordering, TUN name or slot count
require explicitly disabling the old controller and preparing an external policy
for the transition.

IPv6 WAN bypass is blocked for VPN networks, including `vpn_fallback`: direct
IPv6 fallback is not provided; TUN IPv6 depends on the server plan. Client-network
policy does not automatically select the path of a router-hosted DNS resolver's
own traffic. DoH/DoT and DNS interception remain externally configured.

## 6. Status and troubleshooting

OpenWrt:

```sh
ubus call luci.qeli service_status '{}'
qeli-client router check --policy /etc/qeli/router.json
cat /var/run/qeli/router/health.json
logread -e qeli
```

Keenetic:

```sh
/opt/etc/init.d/S99qeli status
/opt/bin/qeli-client router check --policy /opt/etc/qeli/router.json
cat /tmp/qeli-router/health.json
tail -n 100 /opt/var/log/qeli-client.log
```

`router check` validates without applying routes. On OpenWrt pass the effective
`/etc/qeli/router.json`, not raw UCI JSON lacking rendered owners, paths and
metadata. `health.json` is produced by managed routing; its absence in manual
mode is expected.

Process, tunnel and Internet availability are separate. Successful init status
or S99qeli status exit 0 does not prove Connected. Native states are `connecting`,
`connected`, `reconnecting`, `stopped`, `error`. Missing, stale or foreign reports
yield `available:false` / “Tunnel status unavailable”. Validation checks boot,
PID generation, namespace, ifindex, UP and assigned plan addresses. OpkgTun stays
Connecting until NDM assigns its address. Idle sessions are not failures.
Connected describes the authenticated Qeli session; `health.json.vpn` also
accounts for the TUN Internet probe.

| Error/symptom | Check |
|---|---|
| `unrecognized subcommand router` | Update the client binary and matching templates |
| gateway/kill-switch/pull_routes conflict | Compatible split-tunnel options and the applied INI |
| `existing source/device policy` / mark conflict | Existing rules for the same network; retain external ownership or explicitly migrate them |
| `selected Linux device does not exist` | Actual device name, DHCP/PPPoE startup and bridge creation by firmware |
| `persistent_guard` / `offload_disabled` | Configure real protection/disable acceleration before acknowledging |
| Policy reverted | Missing confirmation within 120 s; inspect restored policy and logs |
| `this policy was rolled back` | Correct rejected intent; automatic reapplication of identical JSON is blocked |
| Process alive, status unavailable | Matching binary/template, procfs namespaces, process generation, TUN address and freshness |

Rollback retains the last confirmed policy and rejected-intent record. Editing
UCI alone does not fix the rejection. Do not blindly remove protective rules or
state files, particularly when VPN provides the only management path.

## 7. Credentials and upgrades

**OpenWrt.** `retain_secrets=0` retains RAM-only behavior. For reboot persistence,
enable **Retain credentials across reboot** and apply the choice before entering
a new password/obfs-key. UCI equivalent:

```sh
uci set qeli.main.retain_secrets='1'
uci commit qeli
# Enter through LuCI or stdin from an already prepared private file:
/etc/init.d/qeli set_secret pass < /root/qeli-password
```

The source file must be root-only and contain one newline-terminated line.
Do not place a real secret in shell history/arguments. Retained copies are
`/etc/qeli/secrets/{password,obfs-key}`, mode 0600 inside 0700. First explicit
opt-in can also retain existing RAM values at startup; stored values are then
restored before launch. Disabling retention or **Clear volatile secret** does
not erase retained files. Use **Delete retained credentials** or:

```sh
/etc/init.d/qeli forget_retained_secrets
```

**Keenetic.** Replace inline `pass` with
`password_file=/tmp/qeli-status/password` in `[qeli]`. Choose storage:

```sh
# Persistent: S99qeli restores it into RAM at the next start.
umask 077
/opt/bin/qeli-client router store-secret --directory /opt/etc/qeli/secrets --name pass < /opt/etc/qeli/password.input
# Alternatively RAM-only: enter again after reboot.
/opt/bin/qeli-client router store-secret --directory /tmp/qeli-status --name pass < /opt/etc/qeli/password.input
```

Native secret storage requires physical root-owned directories without symlink
components; check the firmware's /opt path before choosing this method.
These commands are **alternatives**. Delete a retained copy with
`router forget-secret --directory /opt/etc/qeli/secrets --name pass`.
Keep the input file root-only and separately decide whether to retain it after
import. S99qeli restores any existing persistent copy at startup: explicitly
delete it when switching to RAM-only. No new Keenetic obfs-key-file INI field is
provided. Updating a file does not reauthenticate an existing session without restart.

OpenWrt sysupgrade preserves `/etc/config/qeli` and `/etc/qeli/`: opted-in
credentials, identity, pins, policies and confirmation records. Ordinary
sysupgrade does not guarantee binary package retention; include Qeli in the
image or reinstall a compatible bundle. Runtime/tables/rules regenerate when
the relevant services are enabled. Keenetic `/opt` persistence depends on the
Entware storage being mounted before S99qeli starts.

## 8. Implementation and qualification limits

SSID/DHCP provisioning wizard, separate encrypted DNS groups, automatic server
DNS refresh, per-WAN authenticated Qeli checks, backup VPN profiles and native
NDM policy creation are not implemented. Outer sockets retain transport/platform
underlay routing; a WAN ICMP Internet probe does not prove that Qeli's server
is reachable through that WAN. Unknown JSON fields are rejected.

Linux amd64 checks covered nftables/iptables, VPN-only/fallback, WAN failover/
failback, symmetric service/DNAT replies, healthy TCP/UDP retention, independent
watchdog and secrets. Real fake-TLS clients were tested with ordinary TUN and
`dev_attach` using an external fixture address owner. Fixtures:
`scripts/router_policy_netns_fixture.py`, `scripts/router_status_netns_fixture.py`.
These are not throughput, firmware boot, physical router or all-architecture
musl release qualifications.


Explicit `local_subnets` exceptions copy the longest matching non-default route from
the main table into each owned table, including its gateway and device. Both connected
and routed IPv4/IPv6 networks are supported. If that local route disappears, the
exception becomes unreachable until it returns; a WAN default is never substituted.
The terminal prohibit rule still protects other VPN-only destinations when TUN is absent.
