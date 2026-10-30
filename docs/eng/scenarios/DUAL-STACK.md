# IPv4 and IPv6 through one VPN

Route a device's Internet traffic through a VPS over both IPv4 and IPv6. An
application may choose either address family for a site, but both must use the VPN.
The main example uses IPv4 NAT and IPv6 NAT66 on the VPS.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/DUAL-STACK.md)

These settings apply to published 0.8.3 and current dev 0.8.4. First establish an
ordinary working connection following [FULL-TUNNEL](FULL-TUNNEL.md). The changes
below affect an existing profile's networking, not installation, transport/auth or keys.

## What dual stack means

The client has two inner addresses, such as `10.9.0.2` and
`fd71:e1:8000:102::2`. IPv4 and IPv6 packets travel inside one VPN, not two parallel
VPNs. This is neither TCP/UDP redundancy nor automatic server switching.

The outer server connection is independent of the inner traffic:

| Outer Qeli connection | Traffic inside the tunnel |
| --- | --- |
| IPv4 TCP/UDP | Can carry IPv4 and IPv6 simultaneously |
| IPv6 TCP/UDP | Can also carry IPv4 and IPv6 |
| Either, but server `tun.ip_mode=ipv4` | Does not itself provide inner IPv6 |

The client's ISP may supply IPv4 only: inner IPv6 can still work over an available
IPv4 carrier. However, the **egress node** needs usable IPv6 Internet access of its
own. Here that node is the VPS; a home exit has different requirements, see
[EXIT-NODE](EXIT-NODE.md).

## Address plan

| Setting | Example |
| --- | --- |
| Server profile and TUN | `main`, `vpn0` |
| IPv4 pool and server address | `10.9.0.0/24`, `10.9.0.1` |
| IPv6 pool and server address | `fd71:e1:8000:102::/64`, `fd71:e1:8000:102::1` |
| VPS IPv4 and IPv6 WANs | Example `ens3`; these may be different interfaces |
| Outer connection endpoint | An already-working `vpn.example.com:443` |

Use your own non-overlapping ULA prefix, not the shared example `fd71:e1:8000::/48`.
The installer may already have generated a unique prefix; retain it. Each profile
needs a separate `/64`. Do not change the IPv4 pool unnecessarily: preserve
reservations, `pool.exclude` and static user addresses within the active pools.

ULA addresses are internal, not public IPv6 Internet addresses. In the main example,
NAT66 substitutes the VPS WAN's public IPv6. Client L3 TUN addresses may have `/32`
and `/128` prefixes; that does not contradict `/24` and `/64` allocation pools.

## Prepare VPS IPv6 egress

Before changing Qeli, check the host's addresses and routes. Substitute actual
interfaces if they differ from `ens3`:

```sh
ip -4 address show dev ens3
ip -6 address show dev ens3
ip -4 route show default
ip -6 route show default
sudo iptables -t nat -S
sudo ip6tables -t nat -S
```

NAT66 needs a public WAN IPv6 address, working IPv6 default route and an available
`ip6tables` NAT table in the server worker's namespace. A `fe80::` or ULA WAN address
alone is insufficient. For a default route learned through RA, account for
`accept_ra` and forwarding following [IPV6](../manuals/IPV6.md); do not bulk-change
sysctls over Qeli's ownership.

Test **the VPS itself** over each family:

```sh
curl -4 -fsS --max-time 10 --noproxy '*' https://api64.ipify.org
curl -6 -fsS --max-time 10 --noproxy '*' https://api64.ipify.org
```

Each command should succeed with an address from its selected family. These
commands contact a public service and disclose the source IP to it; substitute
your own test endpoint if needed. Endpoint families are described in the
[ipify documentation](https://www.ipify.org/). A failed VPS IPv6 test first needs
an ISP/WAN fix, not an additional address in the VPN pool.

## Configure the server profile

Back up following the [common procedure](README.md). Merge the networking fields
below into the existing section, substituting your profile name, interfaces and
addresses. Do not create a second `[profile:main]` or replace working `bind.*`,
obfuscation, identity, `[auth]`, `[web]` or user database settings just for IPv6.

```ini
[profile:main]
tun.ip_mode = dual
tun.name = vpn0
tun.device_type = tun
tun.address = 10.9.0.1
tun.ipv6_address = fd71:e1:8000:102::1
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.ipv6.cidr = fd71:e1:8000:102::/64

routing.nat.enabled = true
routing.nat.interface = ens3
routing.ipv6.mode = nat66
routing.ipv6.interface = ens3
routing.ipv6.ndp_proxy = off

dns.enabled = true
dns.listen = 10.9.0.1
dns.listen_ipv6 = fd71:e1:8000:102::1
dns.port = 53
dns.push_servers = 10.9.0.1, fd71:e1:8000:102::1
dns.upstream = 1.1.1.1, 2606:4700:4700::1111
```

Here `dns.upstream` is an explicit administrator choice, not a hidden fallback.
If your DNS policy differs, substitute your reachable resolvers. DNS listens on
TUN addresses, not the public WAN. NAT66 needs no NDP proxy; keep it `off`.
`1400` is an example inner MTU; IPv6 needs at least `1280`, but actual data
transfers must still verify path suitability.

Do not install a second manual set of NAT rules: Qeli owns managed NAT44/NAT66
and cleanup. Preserve administrator rules, allow necessary ICMPv6/PMTU and check
the provider firewall. An outer IPv6 listener is not required for inner IPv6;
the working connection to the VPS over IPv4 is sufficient.

The user must be allowed on `main`. If a new user is needed:

```sh
sudo -u qeli qeli add-client laptop-dual --profiles main --config /etc/qeli/server.conf
sudo -u qeli qeli share-link laptop-dual --profile main --host vpn.example.com:443 --config /etc/qeli/server.conf
```

Do not recreate an existing identity. Check personal and group `allowed_networks`:
a nonempty IPv4-only ACL will not permit IPv6. Permit actual destinations and
tunnel DNS addresses for both families. Adding `0.0.0.0/0` and `::/0` also permits
private/ULA addresses, not just the public Internet; for restricted roles follow
[ACCESS-PROFILES](ACCESS-PROFILES.md).

## Configure the client

Keep `server`, the key, password and transport settings in the imported working
profile. For mandatory dual stack, set:

```ini
[qeli]
gateway = true
ipv6 = required
dns = tunnel
kill_switch = true
mtu = 0
apps_mode = all
```

`required` requires inner IPv6 in the negotiated plan and adapter capabilities.
It **does not test Internet availability beyond the IPv6 WAN**; use a real request
for that. `auto` is acceptable when IPv4 downgrade is allowed, but such a downgrade
is not a successful dual-stack test. Remove unintended direct `exclude` entries
and inspect remaining LAN exceptions; per-app and split policies need separate tests.

On Linux, perform the [tunnel DNS checks](README.md#tunnel-dns-on-linux).
On Android, enable OS Always-on/lockdown to block traffic without VPN; one INI key
does not replace OS policy. iOS and other adapter restrictions are covered in the
[client matrix](../reference/CLIENT-CONFIG-MATRIX.md).

## Startup and checks for both families

Validate complete configs as their actual owners. Stop and fix any error before
restarting. After successful checks, restart the server in a maintenance window
and connect the client:

```sh
sudo -u qeli qeli check-config --config /etc/qeli/server.conf
sudo qeli check-config --client --config /etc/qeli/client.conf
```

The second path is for a Linux client; validate GUI profiles with the normal
editor. Only after successful checks, run on the server:

```sh
sudo systemctl restart qeli
```

Restarting affects every profile in that service.

On a connected Linux client, replace `vpn0` with its actual TUN name:

```sh
ip -4 address show dev vpn0
ip -6 address show dev vpn0
ip -4 route get 1.1.1.1
ip -6 route get 2606:4700:4700::1111
curl -4 -fsS --max-time 10 --noproxy '*' https://api64.ipify.org
curl -6 -fsS --max-time 10 --noproxy '*' https://api64.ipify.org
```

Expect addresses of both families and tunnel paths to both destinations. In NAT
mode, external addresses should correspond to VPS egress, not the client's home
or mobile ISP. On Windows, use `curl.exe` to avoid a PowerShell alias; test both
`-4`/`-6` commands and inspect routes with `Get-NetRoute`. On macOS, inspect system
routes and use `curl`; on Android, test real application traffic and diagnostics.

For DNS, separately check A and AAAA, for example `nslookup -type=A example.com`
and `nslookup -type=AAAA example.com`. DNS over IPv4 can return AAAA; IPv6 transport
to the resolver is not required for that. An AAAA answer does not prove IPv6 packet
delivery. On Linux inspect `resolvectl status`; check browser DoH separately.

On the VPS, correlate traffic with NAT counters:

```sh
sudo iptables -t nat -nvL POSTROUTING
sudo ip6tables -t nat -nvL POSTROUTING
```

Then test TCP downloads, uploads and UDP for both families, sleep/wake and reconnect.
One successful IPv4 speed test or IPv6 ping does not establish the whole scenario.

## Failure tests

Using a test profile in a controlled environment, check two distinct events:

1. Loss of the VPS connection: when fail-closed is required, neither IPv4 nor IPv6
   should silently return to the client's physical network. Account for documented
   kill-switch service exceptions; this does not promise to block every system packet.
2. Loss of only the VPS IPv6 WAN while the IPv4 carrier remains alive: Qeli may
   remain connected, but the IPv6 request must fail rather than use the client's
   ISP directly. Working IPv4 does not establish working IPv6.

After restoration, repeat both-family and DNS checks, then reboot in a maintenance
window and verify restoration of addresses, routes and NAT. Do not delete journals
or bypass protection with another launch when stop/recovery fails.

## When IPv6 without NAT is appropriate

If the provider routes a separate public IPv6 prefix to the VPS, use
`routing.ipv6.mode=route`, IPv6 TUN/pool addresses from that prefix and agreed
upstream return routing. Update IPv6 DNS addresses, reservations and ACLs too.
Simply changing `nat66` to `route` while retaining a ULA pool cannot provide
public Internet access.

In that setup the client's external IPv6 is its assigned address, not the VPS
WAN address. An on-link client prefix may need an NDP proxy; a prefix routed through
an ordinary L3 route does not. Follow [IPV6](../manuals/IPV6.md) for configuration
and topology checks. Do not put the same connected prefix on the WAN when the TUN
already owns it.

For a [home exit node](EXIT-NODE.md), do not enable VPS NAT66 from this example:
both families must exit at home, with VPS bypass transit prohibited.

## Troubleshooting and rollback

| Symptom | What to check |
| --- | --- |
| `ipv6=required` is rejected | Both endpoint versions, `tun.ip_mode`, adapter contract and MTU of at least 1280 |
| The VPS has no IPv6 Internet | Public WAN address, default route, RA and provider restrictions |
| TUN IPv6 exists but Internet fails | ACLs, NAT66/route, IPv6 uplink, firewall and return routing |
| A works but AAAA is missing | DNS policy and the domain's actual record; this is not an IPv6 transit check |
| Small packets work but downloads stall | MTU, outer UDP path, PMTU/ICMPv6; do not disable IPv6 protection as a workaround |
| External IPv6 still belongs to the ISP | Direct exceptions, routes, selected process/per-app and VPN plan application |

To roll back, disconnect the client cleanly and restore complete server/client
config backups with their former owners and permissions. Validate and restart only
the intended service. Do not flush the firewall or delete recovery journals:
Qeli manages its own profile rules.

When returning to IPv4-only operation, separately verify blocking of unwanted
physical IPv6. `ipv6=off` alone is insufficient: it controls Qeli negotiation,
not IPv6 throughout the OS. Without safe IPv6 egress, do not call the connection dual stack.
