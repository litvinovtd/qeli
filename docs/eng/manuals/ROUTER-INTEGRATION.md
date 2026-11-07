# Optional router integration

Experimental source implementation on `dev`; use a matching `qeli-client` and
package/templates. The public OpenWrt source pin/hash still identifies the older
source tree and must be updated separately during release preparation.
No production router was changed during development.

## Ownership and compatibility

`components.routing` and `components.firewall` independently accept `external`
(default) or `client`. Existing scripts, mwan3/PBR and KeeneticOS policies remain
the default. Managed routing with VPN-only requires managed firewall; managed
firewall can also guard externally managed routes. Disable forwarding offload
before selecting managed components and acknowledge `offload_disabled: true`.
Do not run two managers for the same component/network.

The Linux controller manages explicitly selected existing devices/source prefixes:
`direct`, `vpn_only`, `vpn_fallback`. It allocates free tables, priorities and a
masked conntrack-mark field; refuses conflicts; retains healthy WAN2 connections
when WAN1 returns; and restores missing owned rules. A TCP connection cannot
survive a failed ISP by moving to a different public IP. Connected prefixes and
explicit local bypasses remain accessible, subject to the platform firewall.
No administrative INPUT rules, TUN devices or addresses are changed. Forwarding
admission stays with fw4/NDM. IPv6 WAN bypass for VPN networks is blocked;
IPv6 fallback is not provided by this implementation.

The tunnel process and policy controller have independent lifecycles. Native
status is validated against boot, process generation, namespace, interface index,
UP and assigned plan addresses. OpkgTun remains Connecting until KeeneticOS/NDM
assigns its addresses. A missing/stale report never means Connected. WAN probes
and TUN Internet probes are bound to the device and owned routing table, with
configurable thresholds. Endpoint underlay routing remains transport/platform
owned, preserving bound roaming candidates.

## OpenWrt

LuCI → Qeli → Router integration selects owners and accepts advanced non-secret
JSON. It is not a provisioning wizard. Obtain actual Linux device names using
`qeli-client router discover`; UCI WAN names may differ from Linux devices.
For managed routing use `gateway=0`, `kill_switch=0`, `route_local=0`,
`dns=off/system`; the package renders `pull_routes=false`.

Example `router_policy` (replace devices, prefixes and the documentation server IP):

```json
{
  "offload_disabled": true,
  "uplinks": [{"device":"wan","probes":["1.1.1.1","8.8.8.8"]}],
  "networks": [{"device":"br-vpn","subnets":["192.168.77.0/24"],"policy":"vpn_only"}],
  "local_subnets": ["192.168.1.0/24"],
  "server_addresses": ["192.0.2.10"],
  "health": {"tunnel_probes":["1.0.0.1"]}
}
```

Include all actual server A/AAAA addresses. An uplink can specify `routing_table`
when platform gateway discovery is ambiguous. Keep `router_policy: null` (the
default): router-originated routing remains externally managed.

`qeli-guard` (START=17) installs the scoped VPN-only guard before networking;
`qeli-router` (START=18) supervises policies independently from `qeli`.
Enable `qeli-router`; selecting client firewall also enables `qeli-guard`.
Packaged ifup/ifupdate integration retries late interface startup. Unchanged
INI/password contents let procd retain the VPN process on policy-only reloads.

```sh
/etc/init.d/qeli-router enable
/etc/init.d/qeli reload
# Verify a NEW management connection and selected network paths, then:
/etc/init.d/qeli-router confirm_policy
```

An independent watchdog restores the last confirmed policy after 120 seconds
unless confirmed. It rolls back route/guard policy, not arbitrary UCI networks,
VPN profiles, credentials or administrative configuration. Rejected intent is
not automatically reapplied on a stale UCI reload. Changing backend, WAN slot
ordering or TUN name requires explicitly disabling the old controller first:
`/etc/init.d/qeli-router disable_policy`.

## Keenetic TUN and KeeneticOS 5.x OpkgTun

Both `S99qeli` templates publish safe native tunnel status separately from process
status. Existing manual gateway/NAT behavior remains for old configurations.
Explicitly selecting the new controller suppresses duplicate legacy rules.

```sh
umask 077
/opt/bin/qeli-client router example --platform keenetic > /opt/etc/qeli/router.json
# Edit owners, devices, prefixes, probes and server IPs.
/opt/bin/qeli-client router check --policy /opt/etc/qeli/router.json
/opt/etc/init.d/S99qeli policy-start
# Verify a fresh management connection, then:
/opt/etc/init.d/S99qeli policy-confirm
```

INI must use `gateway=false`, `kill_switch=false`, `route_local=false`,
`pull_routes=false`, `dns=off` for managed routing. Device names must match INI,
the template and policy. `policy-start` explicitly creates a private activation
marker; an unrelated JSON file is never adopted automatically. Repeating it
after policy edits restarts only the controller. VPN stop/restart retains the
guard. `policy-stop` keeps protection; `policy-disable` removes owned resources.

Keenetic VPN-only admission requires an **actual persistent native firmware WAN
block**, acknowledged with `persistent_guard=true`: Entware starts after network
services and `/opt` may not be mounted. The flag alone provides no boot protection.
Disable hardware forwarding acceleration. Polling repair after NDM resets does
not replace firmware protection. A native NDM adapter is not implemented, and
no specific Keenetic hardware/firmware has been qualified.

## Credentials and upgrades

OpenWrt `retain_secrets=0` keeps RAM-only behavior. Opting into `1` stores password
and obfs-key under `/etc/qeli/secrets`, root-owned 0600 inside 0700, restoring them
before launch. Clearing RAM does not erase retained files; use the LuCI deletion
button or `/etc/init.d/qeli forget_retained_secrets`.

Keenetic can use `password_file=/tmp/qeli-status/password`. Native `router
store-secret --directory /opt/etc/qeli/secrets --name pass` reads stdin; S99
restores it before launch. Store directly in `/tmp/qeli-status` for RAM-only use.
This change does not add a Keenetic INI obfs-key-file field. Never pass secrets
as command-line arguments.

OpenWrt sysupgrade preserves `/etc/config/qeli` and `/etc/qeli/`, including opted-in
secrets, identity, pins and confirmed policy. Binary packages are not guaranteed
to survive ordinary sysupgrade: include Qeli in the image or reinstall a matching
package. Kernel tables/rules and temporary state are regenerated.

## Remaining scope and verification

Encrypted per-network DNS groups, DHCP/SSID provisioning wizard, automatic server
DNS-set refresh, per-WAN authenticated Qeli reachability, backup VPN profiles and
native KeeneticOS policy creation remain externally managed. This implementation
does not complete the full router provisioning requirements.

`scripts/router_policy_netns_fixture.py` requires private mount/net/PID namespaces
and PID=1. It tests fake ISP/LAN/TUN paths, fail-closed/fallback, assigned-address
readiness, WAN failover/failback, healthy TCP/UDP retention, rollback and secrets.
It is not a VPN throughput test or hardware/firmware qualification.
