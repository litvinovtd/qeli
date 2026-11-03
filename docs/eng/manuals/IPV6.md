# IPv6 in qeli: configuration, operation, and troubleshooting

**Русская версия → [../ru/IPV6.md](../../ru/manuals/IPV6.md)**

This is the user and operator guide to complete IPv6 support. [CONFIG.md](CONFIG.md)
remains the reference for every individual key; implementation details and release gates
live in [IPV6-IMPLEMENTATION-PLAN.md](../plans/IPV6-IMPLEMENTATION-PLAN.md).

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
tun.ipv6_address = fd71:e1:8000:102::1
tun.mtu = 1400
tun.device_type = tun

pool.cidr = 10.19.0.0/24
pool.ipv6.cidr = fd71:e1:8000:102::/64

routing.nat.enabled = true
routing.ipv6.mode = nat66

dns.enabled = true
dns.listen = 10.19.0.1
dns.listen_ipv6 = fd71:e1:8000:102::1
dns.push_servers = 10.19.0.1, fd71:e1:8000:102::1
```

The complete runtime-validated source example is
[`qeli/config/server-ipv6.conf`](../../../qeli/config/server-ipv6.conf). Both the DEB package
and `install-qeli-server.sh` install it as `/etc/qeli/server-ipv6.conf.example`; copy or
adapt that example into the active `/etc/qeli/server.conf`. Do not copy one ULA prefix to
independent sites: give each site a unique RFC4193 `/48` and each profile its own `/64`.

Use the locally assigned half of ULA, `fd00::/8` (inside RFC4193 `fc00::/7`), for tunnel
addresses. Do **not** use `fe80::/10`: link-local addresses are interface-scoped, are not
routed through the tunnel, and qeli rejects them for profile-wide TUN/pool fields. The static
files contain a conspicuous example site prefix only; Quick Start and the one-shot installer
replace it with 40 random Global-ID bits.

On a normal VPS, NAT66 is IPv6 MASQUERADE: qeli sends the ULA pool through the interface
selected by the IPv6 default route, and the kernel chooses that interface's current public GUA
as the translated source. The installer keeps dual-stack only when that route, a public
`2000::/3` source address, and the `ip6tables` NAT table all exist. Otherwise it writes a safe
IPv4-only active profile. On Debian/Ubuntu, both `iptables` and `ip6tables` are installed by the
single `iptables` package.

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

`routing.ipv6.mode` has four values.

| Mode | Qeli responsibility | `routing.ipv6.ndp_proxy` |
|---|---|---|
| `off` | Blocks IPv6 transit between the profile TUN and other interfaces in both directions | `off` only |
| `manual` | Leaves external routing, firewall and forwarding to the administrator; still manages the tunnel and client routes | `off`, `auto`, `required` |
| `route` | Configures forwarding while preserving clients' source IPv6 addresses | `off`, `auto`, `required` |
| `nat66` | Configures forwarding and NAT66 (MASQUERADE) through the IPv6 uplink | `off` only |

`manual` was added in the **0.8.2** development tree; **0.8.1** binaries do not recognize
this value. Omitting the key defaults to `off`; templates and Quick Start may explicitly
select `nat66`. An IPv4-only profile requires `off` for both keys.

### `nat66`

qeli enables verified forwarding and MASQUERADE through `ip6tables`. It is the portable
choice for a ULA pool on a normal VPS where the provider does not route a dedicated GUA
prefix to VPN clients. The WAN needs a public IPv6 address and an IPv6 default route.
Qeli blocks TUN transit through every other interface before host permits: with a
`FORWARD ACCEPT` policy, the client's address would otherwise leave without MASQUERADE.
Use `route` or `manual` for LAN and site-to-site routing.

```ini
routing.ipv6.mode = nat66
routing.ipv6.interface =
```

An empty interface means automatic IPv6 uplink detection. Set, for example,
`routing.ipv6.interface = ens18` if detection is ambiguous. For managed `route` and
`nat66`, the selected uplink must exist in the worker network namespace at setup.
Auto selection rejects a best default route spread over different WANs (ECMP).
`nat66` also refuses an unreadable or unusable complete default-route listing:
one `route get` answer cannot prove a unique WAN. Set an explicit interface only
when the administrator controls that routing.
In `nat66`, a route change to another interface blocks packets but may interrupt
connectivity. The administrator must still control active WAN deletion and name reuse.

### `manual`

Use this mode when firewalld, native nftables, or another administrator-managed setup
owns IPv6 routing and firewall policy. Qeli creates the tunnel, configures its addresses
and connected/authenticated client routes, and can run the NDP responder. It does not
install IPv6 FORWARD, NAT66, MSS, DNS INPUT or DNS REDIRECT rules, and does not acquire
forwarding/`accept_ra` sysctl leases. `ip6tables` is not required for this IPv6 mode.
IPv4 NAT, routing and DNS settings remain independent in a dual-stack profile.

Fragment of an existing `[profile:<name>]` with `tun.ip_mode = dual` or `ipv6`, and
`tun.ipv6_address` and `pool.ipv6.cidr` already configured:

```ini
routing.ipv6.mode = manual
routing.ipv6.interface = ens3
routing.ipv6.ndp_proxy = required
routing.ipv6.ndp_proxy_interface = ens3
```

The administrator must provide IPv6 forwarding, the return path, firewall policy
(including profile isolation and ICMPv6), and any RA settings required by the uplink.
For the built-in DNS resolver, permit UDP and TCP INPUT to its tunnel address. With
`dns.port != 53`, also arrange IPv6 port-53 redirection yourself, or use port 53.
Existing address/MTU/collision checks and authenticated session restrictions still apply.

A restart removes rules tagged for the previous Qeli profile and releases its old sysctl
leases before starting `manual`; administrator rules are not removed. Configure host
sysctls independently rather than relying on another managed profile to keep forwarding
on. NDP `required` still refuses startup if the responder cannot bind; it does not verify
that the administrator's routing/firewall setup can deliver packets. A routed prefix
that needs no Neighbor Discovery can use `ndp_proxy = off` with `manual` too.
A required-NDP failure rejects this profile: the worker stays alive and retries it
while other profiles continue running. Forwarding and RA belong to the network
namespace; a sibling `route`/`nat66` may change them for its own operation, while
`manual` acquires no IPv6 sysctl lease.

#### Switching to administrator-managed IPv6

1. Check `qeli --version`: use a 0.8.2 build that supports `manual`.
2. Prepare persistent IPv6 forwarding, return routes, firewall, ICMPv6 and DNS policy in
   the host's configuration manager. Preserve uplink RA reception when using RA/SLAAC.
3. Change the profile's INI `routing.ipv6.mode` to `manual`. If the upstream uses NDP for
   client addresses, set `ndp_proxy = required` and its interface; for an ordinary routed
   prefix, leave `ndp_proxy = off`.
4. Run `qeli check-config --config /etc/qeli/server.conf`, then apply the configuration
   with a restart. In the panel, use `Apply & Restart`.
5. After restart, check host forwarding/RA settings, client access to the intended IPv6
   networks and DNS over UDP/TCP. For NDP, verify an uplink response for a connected
   client's address; a successfully bound responder alone does not prove packet delivery.

Switching `route` ↔ `manual` preserves NDP settings. Selecting `off` or `nat66` in the
form disables NDP and clears its interface. When editing INI, set
`routing.ipv6.ndp_proxy = off` yourself: incompatible combinations are rejected.

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

#### On-link prefix and NDP proxy (0.8.1)

The normal and preferred design has the provider route the client prefix through the server's
WAN address. Keep `routing.ipv6.ndp_proxy = off` in that case: the upstream does not perform
NDP for every VPN address.

Some VPS providers instead treat the delegated prefix as directly connected to the L2 segment
and issue a Neighbor Solicitation for every address. Enable the built-in responder for that
topology:

```ini
routing.ipv6.mode = route
routing.ipv6.interface = ens3
routing.ipv6.ndp_proxy = required
routing.ipv6.ndp_proxy_interface = ens3
```

| Mode | Behaviour |
|---|---|
| `off` | responder disabled; the default and the correct choice for a normal routed prefix |
| `auto` | try to open the responder; warn and continue without it when the interface, Ethernet, or `CAP_NET_RAW` is unavailable |
| `required` | refuse profile startup until the responder is attached to the selected interface |

An empty `routing.ipv6.ndp_proxy_interface` reuses the effective uplink from
`routing.ipv6.interface`/the IPv6 default route. The link must be Ethernet-compatible and the
Linux server normally already runs as root. NDP proxy is valid only with source-preserving
`route` or administrator-managed `manual`, not with `off` or NAT66. While active, the responder joins `PACKET_MR_ALLMULTI` on
its packet socket so that the NIC accepts solicited-node multicast for client `/128`s which are
not assigned to the WAN interface. This does not set persistent `IFF_ALLMULTI` on the interface
or relay multicast into the VPN.

This responder is not a broad multicast relay. It validates each NS and advertises the server's
MAC only when the target currently belongs to a live session:

- an exact IPv6 lease from `pool.ipv6.cidr`, including `static_ipv6`;
- an address inside a non-default IPv6 `client_subnet` registered by a connected router or
  site-to-site client.

After registry removal on revoke/disconnect, the proxy no longer authorizes new answers.
An already kernel-queued answer may still leave the socket; 0.8.3 rechecks owner generation after readiness before submitting a new frame. `/0`, link-local,
multicast, invalid checksum/hop-limit, and unrelated targets are ignored. DAD with source `::`
requires the target solicited-node multicast destination; a unicast DAD is discarded.

Responses are limited to 256 per source MAC and 4096 globally per one-second window.
An unowned target does not consume these response budgets. Rate-limit warnings appear
at most once per window; responses resume in the next window.

To expose a network behind one client:

```ini
[user:branch-router]
static_ipv6 = 2001:db8:1200:10::10
client_subnet = 2001:db8:1200:20::/64
```

The `client_subnet` may be a separate delegated network; its Linux route exists only while the
session is active. Do not assign `pool.ipv6.cidr` to the server WAN or add a competing connected
route there: the profile TUN must remain the only owner of that route, while only the upstream
side performs NDP.

##### Complete scenario: a public on-link `/64` for clients

Assume the provider gave the server a normal WAN address and a separate client prefix, but
treats the second prefix as on-link:

```text
qeli WAN interface:                ens3
qeli WAN address:                  2001:db8:100::10/64
Separate on-link client prefix:    2001:db8:1200:10::/64
Profile TUN:                       vpn-public
In-VPN IPv6 gateway:               2001:db8:1200:10::1
Pinned alice address:              2001:db8:1200:10::100
```

`2001:db8::/32` is documentation space throughout this example. Substitute the addresses
assigned by the provider.

1. **Confirm the topology before enabling the responder.** Stop the profile or server and
   inspect host addressing and routes:

   ```bash
   sudo systemctl stop qeli-server
   ip -6 addr show dev ens3
   ip -6 route show table all
   ```

   `2001:db8:1200:10::/64` must not be assigned to `ens3` and must not have a connected route
   through `ens3`. Otherwise the WAN and TUN become competing owners of one prefix, and qeli
   correctly rejects the configuration.

   Capture traffic on the server while an independent external IPv6 host tries the future
   client address:

   ```bash
   sudo tcpdump -ni ens3 'icmp6 && ip6[40] == 135'
   # On the external host:
   ping -6 2001:db8:1200:10::100
   ```

   An incoming `Neighbor Solicitation, who has 2001:db8:1200:10::100` proves that the
   upstream resolves the address through NDP and that this placement needs a proxy. When the
   provider sends the prefix over a normal L3 route through the server WAN address, no NS for
   the client address arrives and `ndp_proxy = off` remains correct. No observed NS does not
   by itself prove a routed setup: first exclude an incorrect prefix, provider filtering, and
   capture on the wrong interface.

2. **Add the IPv6 settings to the existing profile.** Transport, bind, authentication, and
   obfuscation stay unchanged; this is only the IPv6-related fragment:

   ```ini
   [profile:public-v6-onlink]
   tun.ip_mode = ipv6
   tun.name = vpn-public
   tun.ipv6_address = 2001:db8:1200:10::1
   tun.mtu = 1280
   pool.ipv6.cidr = 2001:db8:1200:10::/64

   # Preserve the public client source address; no IPv6 MASQUERADE is created.
   routing.ipv6.mode = route
   routing.ipv6.interface = ens3

   # Use required in production: the profile cannot look healthy without its responder.
   routing.ipv6.ndp_proxy = required
   routing.ipv6.ndp_proxy_interface = ens3
   ```

   For dual stack, use `tun.ip_mode = dual` and retain the existing IPv4 `tun.address`,
   `pool.cidr`, and `routing.nat.*`. The NDP proxy affects IPv6 only and does not replace IPv4
   NAT.

   Pin an address to an existing user in `users.conf` for a stable inbound test:

   ```ini
   [user:alice]
   # Keep the existing password_hash, enabled flag, limits, and groups.
   static_ipv6 = 2001:db8:1200:10::100
   ```

   The panel exposes the same fields under **Configuration → profile → Routing**: select IPv6
   mode `route`, NDP proxy `required`, and interface `ens3`. Set Static IPv6 on the user card.
   `auto` is useful for trial deployment, but in production it may continue after a warning
   without a working responder; `required` prevents that false-positive status.

3. **Validate the configuration and start the server.**

   ```bash
   sudo qeli check-config --config /etc/qeli/server.conf
   sudo systemctl restart qeli-server
   sudo journalctl -u qeli-server -n 100 --no-pager | grep -F 'IPv6 NDP proxy'
   ip -6 route show 2001:db8:1200:10::/64
   ```

   With `required`, the journal must contain
   `session-aware IPv6 NDP proxy active on 'ens3'`. The client `/64` route must point to
   `vpn-public`, not `ens3`. Failure to open the raw packet socket, missing `CAP_NET_RAW`, or
   a nonexistent/non-Ethernet interface prevents this profile from starting instead of
   silently running without NDP.

4. **Verify the complete lifecycle.** Keep an NS/NA capture running on the WAN:

   ```bash
   sudo tcpdump -ni ens3 'icmp6 && (ip6[40] == 135 || ip6[40] == 136)'
   ```

   - While `alice` is disconnected, a fresh NS for `2001:db8:1200:10::100` must receive no NA.
   - After successful authentication, the server registers alice's `/128`, replies with an NA
     carrying its own MAC, and an external `ping -6 2001:db8:1200:10::100` must reach the
     client. If the client OS blocks inbound ICMPv6, allow Echo Request or test a TCP/UDP
     service which is already listening.
   - Server registry removal, revoke, or session replacement removes ownership immediately.
     Stopping a client process, especially UDP, may first leave its session alive until
     idle/liveness timeout and the next cleanup pass; roaming may also retain a grace
     period. Before checking for absent NAs, confirm that the server no longer lists
     this session. Flush the entry
     on an accessible upstream router or wait for its neighbor cache to expire, then retry: a
     new NS receives no proxy NA and traffic without a live session is dropped. A stale upstream
     entry may continue to show the server MAC for a while; that is upstream caching, not
     continuing qeli ownership.
   - Reconnecting registers ownership and restores NDP responses.

   With `client_subnet = 2001:db8:1200:20::/64`, the lifecycle is identical but the connected
   site-to-site client owns the complete prefix: the responder answers for any target inside it
   while that session is active. The client router must forward IPv6 to its LAN, route replies
   through qeli, and permit the required traffic in its firewall. `/0` never becomes NDP
   ownership.

| Symptom | Check |
|---|---|
| A profile with `required` does not start | uplink name, Ethernet link type, root or `CAP_NET_RAW`, and the journal message |
| `tcpdump` shows no NS | correct WAN interface/address, provider route/security group; the prefix may already be routed and need no proxy |
| NS arrives but no NA while the client is online | actual `static_ipv6`, profile name, session state, and whether the target is in `pool.ipv6.cidr` or an active `client_subnet` |
| NA is visible but packets do not arrive | `/64` must route to the TUN; inspect `ip6tables`/cloud firewall, forwarding, and the client firewall |
| The upstream still shows the server MAC after disconnect | flush or wait for neighbor cache; new NS must receive no NA and data without a session is dropped |
| `auto` starts but NDP does not work | find `NDP proxy auto mode is unavailable`, fix the cause, and switch to `required` |

#### Public client IPv6 addresses without NAT66

`route` can assign a real global unicast IPv6 address (GUA) to every client, preserve that
address on egress, and accept connections initiated from the Internet. The provider must
either route a **separate prefix** to the qeli server's WAN address or treat it as on-link and
use the built-in NDP proxy described above. A typical routed layout is:

```text
qeli server WAN:                  2001:db8:100::10/64
Prefix routed to the server:     2001:db8:1200:10::/64
Provider route:                  2001:db8:1200:10::/64 via 2001:db8:100::10
Server TUN address:              2001:db8:1200:10::1
Client alice address:            2001:db8:1200:10::100
```

The `2001:db8::/32` addresses above are documentation-only. Use the real GUA space assigned
by the provider. When a `/56` or `/48` is delegated, allocate a separate `/64` to each
profile.

Add the routed prefix to the server profile:

```ini
[profile:public-v6]
tun.ip_mode = dual
tun.name = vpn-public
tun.ipv6_address = 2001:db8:1200:10::1
pool.ipv6.cidr = 2001:db8:1200:10::/64

# Preserve the client's IPv6 source; do not create MASQUERADE.
routing.ipv6.mode = route
routing.ipv6.interface = ens3
```

In a dual-stack profile, `routing.nat.enabled = true` may independently keep NAT44 enabled
for IPv4. That key does not enable NAT66 or alter routed IPv6.

Dynamic addresses are allocated from the complete `pool.ipv6.cidr`. Assign a fixed address
for stable public reachability, DNS records, or inbound services in `users.conf`:

```ini
[user:alice]
static_ipv6 = 2001:db8:1200:10::100
```

The same value can be set under **Users / Static IPv6**, with
`qeli add-client --static-ipv6 2001:db8:1200:10::100`, or through
`pool.ipv6.reservation.alice`. It must be a unique address inside `pool.ipv6.cidr`. A fixed
address is effectively single-session: a new session for that user evicts the previous
holder.

For a strict IPv6 full tunnel on the client:

```ini
ipv6 = required
gateway = true
```

Verify the server and upstream before connecting a client:

```bash
# The provider/upstream must have a return route through the server WAN.
ip -6 route show default

# After startup the profile creates a connected route to the pool through its TUN.
ip -6 route show 2001:db8:1200:10::/64

# route must not create IPv6 MASQUERADE for this pool.
ip6tables -t nat -S POSTROUTING

# qeli enables forwarding and installs verified bidirectional FORWARD rules.
sysctl net.ipv6.conf.all.forwarding
ip6tables -S FORWARD
```

Then verify the client's egress address and inbound reachability of its fixed GUA from an
external IPv6 host. A capture such as
`tcpdump -ni ens3 'ip6 and host 2001:db8:1200:10::100'` must show the unchanged client
source address.

A normal WAN `/64` directly connected to `ens3` cannot also be used as `pool.ipv6.cidr`: the
TUN and WAN would acquire competing connected routes, so preflight rejects a pool that overlaps
an existing host address or route. Request a separate routed `/64` (or `/56`/`/48`), or a
separate on-link client prefix which is not assigned to the WAN interface; enable the built-in
NDP proxy for the latter. If the provider cannot supply a separate prefix, use `nat66`.

A routed GUA makes the client directly addressable from the Internet. qeli permits
bidirectional forwarding in `route` mode, so the cloud security group, server firewall, and
client firewall must explicitly define which inbound protocols and ports are allowed.

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
dns.listen_ipv6 = fd71:e1:8000:102::1
dns.push_servers = 10.19.0.1, fd71:e1:8000:102::1
dns.upstream = 1.1.1.1, 2606:4700:4700::1111
```

The client filters DNS servers against the actually negotiated inner families. It never
invents a public fallback resolver. `dns = off`/`system` keeps the system resolver and is
independent from `ipv6 = off`.

## 8. Static addresses and reservations

A profile reservation:

```ini
pool.reservation.alice = 10.19.0.100
pool.ipv6.reservation.alice = fd71:e1:8000:102::100
```

Or in the user database:

```ini
[user:alice]
static_ip = 10.19.0.100
static_ipv6 = fd71:e1:8000:102::100
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

Quick Start creates Internet IPv6 through `nat66`. Configure `route`, `manual` or isolated
`off` through Config (Form or INI), and prepare the corresponding infrastructure. Select
`manual` in Config, not in Quick Start.

## 10. Host prerequisites and preflight

```bash
ip -6 addr show scope global
ip -6 route show default
# Managed off/route/nat66 only; manual uses the administrator-managed firewall.
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
ping -6 fd71:e1:8000:102::1
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
| explicit dual/IPv6 was refused | Quick Start cannot promise Internet IPv6 | preflight message; repair WAN/firewall or configure `route/manual/off` manually |
| `manual` is not recognized | installed binary does not support the new mode | `qeli --version`; use a 0.8.2 build that supports `manual` |
| NDP responds in `manual`, but traffic fails | manual routing or firewall is incomplete | forwarding/RA, return routes, FORWARD and ICMPv6; `required` checks responder startup |
| DNS works on a custom port in `manual`, but clients get no answer | clients query port 53 | UDP/TCP INPUT and administrator-provided 53-to-`dns.port` redirection, or `dns.port = 53` |
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


#### NDP responder changes in 0.8.3

The NA source is a usable IPv6 address assigned to the uplink, preferably
link-local, otherwise another usable assigned unicast address. Target remains the client's address.
Tentative, optimistic, deprecated and DAD-failed addresses are excluded in the
worker network namespace. `required` now also requires a usable source;
`auto` reports startup failure and continues without proxying. Runtime address
loss pauses advertisements; source changes are refreshed once per second.
A replaced interface index or MAC stops the responder instead of using stale
link identity.

Ownership includes completed admission: kernel routes and primary AuthOK must
commit before an address is eligible. Exact leases precede non-default delegated
prefixes; revoked, closing, removed or superseded owners cannot authorize new NA.
After writable readiness, the exact owner generation is checked again immediately
before nonblocking send. A frame already accepted by the kernel cannot be recalled.

Known concrete leases join their solicited-node IPv6 multicast groups on a
socket-owned membership, so MLD can inform a snooping network. Groups are refreshed
once per second, bounded to 1024 concrete targets, and released on close.
PACKET_MR_ALLMULTI still covers the local NIC receive filter. Neither mechanism
guarantees delivery through arbitrary upstream multicast policy. A delegated
prefix is never enumerated: NS for unknown addresses in it still requires the
upstream network to deliver that multicast to the server (for example, an
appropriate router/switch multicast policy).

One unsolicited all-nodes NA is attempted for a newly admitted known address or
changed owner/source binding: at most 16 per second per profile, sharing the
4096/s response budget. Pending work is bounded by the target limit. There is
no periodic reannouncement option. Solicited proxy replies use S=1,O=0; DAD and
appearance announcements use S=0,O=0. R=0 describes the advertised client-host
role, rather than blindly advertising the proxy host as a router. Arbitrary
R/S/O overrides are not exposed. Unsolicited NA is an optimization, not a
reachability guarantee or replacement for normal Neighbor Discovery.
See [RFC 4861 §4.4](https://www.rfc-editor.org/rfc/rfc4861.html#section-4.4) and
[§7.2.8](https://www.rfc-editor.org/rfc/rfc4861.html#section-7.2.8).
The `manual` mode still leaves routing, firewall and forwarding to the administrator.
