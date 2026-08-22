# IPv6 in qeli: configuration, operation, and troubleshooting

**Русская версия → [../ru/IPV6.md](../ru/IPV6.md)**

This is the user and operator guide to complete IPv6 support. [CONFIG.md](CONFIG.md)
remains the reference for every individual key; implementation details and release gates
live in [IPV6-IMPLEMENTATION-PLAN.md](IPV6-IMPLEMENTATION-PLAN.md).

## 1. Two independent IPv6 layers

qeli separates:

1. The **outer carrier** — the TCP/UDP connection from client to server, selected by server
   `bind.address`/`listen` and the client `server` endpoint. The carrier can use IPv4 or IPv6.
2. The **inner traffic** — IP packets carried inside the encrypted tunnel, selected by
   `tun.ip_mode`, the IPv4/IPv6 pools, and authenticated capability negotiation.

The layers are independent. An IPv4 carrier can transport inner IPv6 and an IPv6 carrier can
transport inner IPv4. An outer IPv6 listener does not by itself assign an inner IPv6 address.

An IPv6 literal in client INI needs brackets:

```ini
[qeli]
server = [2001:db8::10]:443
```

A domain needs no brackets. qeli considers usable A and AAAA carrier addresses and keeps the
actual `carrier_address` outside full-tunnel routes.

## 2. Server profile modes

| `tun.ip_mode` | Client assignment | Intended use |
|---|---|---|
| `ipv4` | IPv4 only | compatibility and IPv4-only infrastructure |
| `dual` | IPv4 and IPv6 | recommended for the ordinary Internet |
| `ipv6` | IPv6 only | IPv6-only networks; IPv4 needs a separate NAT64 |

With an L3 TUN the client receives host prefixes `/32` and `/128`; `NetworkPlan v2`
separately carries the allocation/on-link prefixes and gateways. This prevents ARP/NDP on a
point-to-point TUN while retaining correct connected routes.

A minimal dual-stack field set is:

```ini
[profile:dual]
tun.ip_mode = dual
tun.name = vpn0
tun.address = 10.19.0.1
tun.ipv6_address = fd71:e1:19::1
tun.mtu = 1400
tun.device_type = tun

pool.cidr = 10.19.0.0/24
pool.ipv6.cidr = fd71:e1:19::/64

routing.nat.enabled = true
routing.ipv6.mode = nat66

dns.enabled = true
dns.listen = 10.19.0.1
dns.listen_ipv6 = fd71:e1:19::1
dns.push_servers = 10.19.0.1, fd71:e1:19::1
```

The complete runtime-validated source example is
[`qeli/config/server-ipv6.conf`](../../qeli/config/server-ipv6.conf). Both the DEB package
and `install-qeli-server.sh` install it as `/etc/qeli/server-ipv6.conf.example`; copy or
adapt that example into the active `/etc/qeli/server.conf`. Do not copy one ULA prefix to
independent sites: give each site a unique RFC4193 `/48` and each profile its own `/64`.

## 3. Client `ipv6` policy

```ini
[qeli]
ipv6 = auto
```

| Value | Behaviour |
|---|---|
| `auto` | accepts IPv4/dual/IPv6 plans; a dual profile can safely downgrade to IPv4 if the adapter lacks the complete IPv6 contract |
| `required` | requires inner IPv6 and fails on a legacy server, an IPv4-only profile, MTU below 1280, or incomplete platform capabilities |
| `off` | requests only IPv4 from a dual profile and rejects an IPv6-only profile |

`auto` is the default. Use `required` for release validation and networks where IPv6 is
mandatory: it prevents a hidden downgrade.

The policy is part of the authenticated handshake. The server produces one NetworkPlan and
the platform must atomically apply every address, route, DNS server and MTU in that generation
or reject it before packet flow starts.

## 4. IPv6 egress from the server

`routing.ipv6.mode` has three values.

### `nat66`

qeli enables verified forwarding and MASQUERADE through `ip6tables`. It is the portable
choice for a ULA pool on a normal VPS where the provider does not route a dedicated GUA
prefix to VPN clients. The WAN needs a public IPv6 address and an IPv6 default route.

```ini
routing.ipv6.mode = nat66
routing.ipv6.interface =
```

An empty interface means automatic IPv6 uplink detection. Set, for example,
`routing.ipv6.interface = ens18` if detection is ambiguous.

### `route`

This preserves the client's source IPv6. Use it with a routed GUA prefix or for
site-to-site/LAN routing. The upstream router must have a return route for `pool.ipv6.cidr`
through the qeli server.

```ini
tun.ipv6_address = 2001:db8:1200:10::1
pool.ipv6.cidr = 2001:db8:1200:10::/64
routing.ipv6.mode = route
routing.ipv6.interface =
```

`2001:db8::/32` is documentation space; replace it with a real delegated prefix. An empty
interface is valid for a LAN-only route deployment: qeli follows kernel routes and does not
require a public default uplink.

### `off`

Clients can still receive inner IPv6, but qeli fail-closed blocks forwarding outside the
profile. This is an intentional isolated IPv6 segment, not “do not configure anything”.
qeli verifies the `ip6tables` boundary and refuses to start if isolation cannot be guaranteed.

qeli manages `net.ipv6.conf.all.forwarding` and, on an RA-dependent WAN, first leases
`accept_ra=2` so enabling forwarding does not remove the SLAAC address/default route. Original
values are restored after the last cleanly stopped owner.

## 5. IPv6-only profile

```ini
[profile:v6-only]
enabled = true
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp

tun.ip_mode = ipv6
tun.name = vpn0
tun.ipv6_address = fd71:e1:20::1
tun.mtu = 1400
pool.ipv6.cidr = fd71:e1:20::/64

routing.nat.enabled = false
routing.forward_private = false
routing.ipv6.mode = nat66

dns.enabled = true
dns.listen_ipv6 = fd71:e1:20::1
dns.upstream = 2606:4700:4700::1111
```

Use a strict client for validation:

```ini
ipv6 = required
gateway = true
```

qeli does not implement NAT64/DNS64. An IPv6-only tunnel does not make IPv4-only services
reachable. Use `dual` when both families are required, or operate a separate controlled NAT64.

## 6. Full tunnel and missing-family protection

In a full tunnel both IP families must either use qeli or be blocked. If the server supplies
only IPv4, native client IPv6 is captured/blocked by default. An IPv6-only plan symmetrically
blocks native IPv4.

Explicit escape hatches exist for exceptional deployments:

```ini
allow_ipv4_leak = false
allow_ipv6_leak = false
```

`true` permits that **missing** family outside the full tunnel. It does not enable IPv6 and is
not needed by a dual-stack plan. Both defaults are `false`; enable one only after evaluating
the resulting leak. In a split tunnel, destinations outside selected routes naturally remain
on the physical network.

## 7. DNS

Each built-in DNS listener must match the gateway for its family:

```ini
dns.enabled = true
dns.listen = 10.19.0.1
dns.listen_ipv6 = fd71:e1:19::1
dns.push_servers = 10.19.0.1, fd71:e1:19::1
dns.upstream = 1.1.1.1, 2606:4700:4700::1111
```

The client filters DNS servers against the actually negotiated inner families. It never
invents a public fallback resolver. `dns = off`/`system` keeps the system resolver and is
independent from `ipv6 = off`.

## 8. Static addresses and reservations

A profile reservation:

```ini
pool.reservation.alice = 10.19.0.100
pool.ipv6.reservation.alice = fd71:e1:19::100
```

Or in the user database:

```ini
[user:alice]
static_ip = 10.19.0.100
static_ipv6 = fd71:e1:19::100
```

The address must be a usable host in its pool, distinct from the gateway, exclude list and
every other permitted user's address. `check-config`, CLI and the panel reject conflicts
before write/start; runtime never silently replaces an invalid fixed address with a dynamic one.

## 9. Web-panel Quick Start

Quick Start offers `auto`, `ipv4`, `dual`, and `ipv6`.

- `auto` chooses `dual` only when a public GUA is observed on an IPv6 default-route
  interface and `ip6tables` is available; otherwise it stores a usable `ipv4` profile.
- explicit `dual`/`ipv6` fails closed without public IPv6, the firewall backend, or when
  `tun.mtu < 1280`;
- IPv6 setup generates a collision-checked RFC4193 `/64`, the `::1` gateway, an IPv6 DNS
  listener, and `routing.ipv6.mode = nat66`;
- `dual` keeps NAT44 and adds NAT66; `ipv6` disables irrelevant NAT44 and IPv4 forwarding;
- `auto` is resolved once. Relaunching an existing profile preserves its concrete mode and
  manual settings; an explicit mode selection intentionally switches and normalizes the
  complete egress contract.

Quick Start promises Internet IPv6. Use Config/Raw INI and manual infrastructure for routed
GUA or an isolated `off` deployment.

## 10. Host prerequisites and preflight

```bash
ip -6 addr show scope global
ip -6 route show default
command -v ip6tables
sudo ip6tables -S
```

NAT66 needs a usable public IPv6 on the interface carrying the default route. A ULA or
link-local address alone is not proof of Internet egress. The host firewall and cloud security
group must allow the selected outer TCP/UDP listener; inner IPv6 does not require a separate
public listener.

Validate before starting:

```bash
sudo qeli check-config --config /etc/qeli/server.conf
qeli check-config --config ~/qeli-client.conf --client
```

IPv6 requires `tun.mtu >= 1280`. A value of 1400 is a safe starting point for ordinary
encapsulation; the effective PMTU still depends on the outer transport and path.

## 11. Verification after connect

On the Linux server:

```bash
ip -4 addr show dev vpn0
ip -6 addr show dev vpn0
ip -4 route show dev vpn0
ip -6 route show dev vpn0
sudo tcpdump -ni vpn0 'ip or ip6'
```

On the client, verify in this order:

1. status contains every NetworkPlan address (`IPv4/32` and/or `IPv6/128`);
2. each tunnel gateway is reachable;
3. a public destination is reachable;
4. DNS returns A and AAAA records appropriate to the mode;
5. a full tunnel leaves no missing family on the physical path.

Example:

```bash
ping -6 fd71:e1:19::1
ping -6 2606:4700:4700::1111
curl -4 https://ifconfig.co
curl -6 https://ifconfig.co
```

On Windows use `Get-NetIPAddress` and `Get-NetRoute -AddressFamily IPv6`; on macOS use
`ifconfig utunN` and `netstat -rn -f inet6`. Android/iOS expose negotiated addresses in
connection details while their system VPN APIs own interfaces and routes.

## 12. TAP and IPv6

A complete client `device_type = tap` is Linux-only. A Linux server TAP accepts local
IPv4/IPv6 Ethernet frames, ARP and NDP, but the qeli wire remains L3: arbitrary EtherTypes,
VLAN/STP/LLDP and a transparent L2 bridge are not transported. Windows, macOS, Android and
iOS preserve the portable key but reject TAP at connect time.

## 13. Platform matrix

Windows and macOS expose `ipv6 = auto|required|off` and both missing-family leak exceptions
as structured, localized controls. Android and iOS intentionally use a complete raw INI
editor instead of maintaining a second partial form schema; their new-profile templates show
`ipv6 = auto` and the two commented leak exceptions. All four applications parse and validate
the same keys before connect. A value pasted into raw INI therefore has the same meaning as a
desktop form selection; `allow_ipv4_leak` and `allow_ipv6_leak` remain advanced full-tunnel
exceptions, not general connectivity switches.

| Platform | IPv6 TUN/routes/DNS | Full-tunnel protection | Notes |
|---|---:|---:|---|
| Linux CLI | yes | iptables/ip6tables | TUN and client TAP |
| Windows | yes | Windows Firewall/WinDivert | editor exposes IPv6 policy/leak controls |
| macOS | yes | pf/Network Extension | system utun |
| Android | yes | VpnService + verified lockdown | Always-on VPN is a system setting |
| iOS | yes | system On Demand policy | `kill_switch` is not emulated inside PacketTunnel |
| OpenWrt/Keenetic | yes | platform firewall/hooks | router and site-to-site scenarios |

## 14. Common failures

| Symptom | Likely cause | Check |
|---|---|---|
| Quick Start `auto` created IPv4 | no public GUA/default route or no `ip6tables` | `ip -6 addr`, `ip -6 route`, `command -v ip6tables` |
| explicit dual/IPv6 was refused | Quick Start cannot promise Internet IPv6 | preflight message; repair WAN/firewall or configure `route/off` manually |
| `ipv6=required` cannot connect | IPv4-only profile, legacy server, MTU <1280, or incomplete adapter | versions, capability log, MTU |
| address exists but Internet does not | missing NAT66 or return route | `routing.ipv6.mode`, WAN interface, upstream route |
| routed mode works one way | upstream lacks the VPN `/64` route | add a return route for `pool.ipv6.cidr` |
| AAAA resolves but connection fails | route/MTU/firewall, not DNS | gateway ping, public IPv6, tcpdump, ICMPv6 PTB |
| full tunnel “broke” the other family | it is absent from the plan and intentionally blocked | use dual or explicitly permit the relevant leak |
| outer IPv6 endpoint is unreachable | carrier listener/firewall is absent | `listen = [::]:port`, listening socket, security group |
| TAP IPv6 is silent | a transparent L2 bridge was expected | test IP/ARP/NDP; qeli does not carry arbitrary Ethernet |

## 15. Migration and rollback

1. Upgrade server and clients to builds that support NetworkPlan v2.
2. Add a unique IPv6 `/64`, gateway, DNS listener and `routing.ipv6.mode`.
3. Validate the server with `check-config`.
4. Connect one test client with `ipv6=required`.
5. Verify assignments, both gateways, DNS, PMTU and leak behaviour.
6. Then migrate ordinary clients with `auto`.

To roll back, set server `tun.ip_mode = ipv4`, clear the IPv6 pool/listener, and set
`routing.ipv6.mode = off`; explicit IPv4 in Quick Start performs that normalization
automatically. Return clients to `ipv6 = auto` or `off`. Restart the profile/service after a
server data-plane change.
