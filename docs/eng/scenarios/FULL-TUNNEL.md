# Full tunnel through a VPS

Send a device's Internet traffic through a public Linux server. Applications do
not need a SOCKS/HTTP proxy: the client creates an IP tunnel and the server performs NAT.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/FULL-TUNNEL.md)

## Topology and requirements

`Device → Qeli on VPS → VPS WAN → Internet`.

Start with a working profile, a reachable TCP/UDP port, TUN and server `iptables`.
This example uses pool `10.9.0.0/24`, server tunnel address `10.9.0.1` and WAN `ens3`.
Find the actual WAN with `ip route get 1.1.1.1`; do not assume the interface name.
Check the cloud provider's firewall as well.

## Server

Merge networking fields into the existing profile, retaining transport, identity and REALITY settings:

```ini
[profile:main]
routing.nat.enabled = true
routing.nat.interface = ens3
routing.forward_private = true
dns.enabled = true
dns.listen = 10.9.0.1
dns.upstream = 1.1.1.1
```

Here `dns.upstream` is an explicit administrator choice. Replace it if your policy
does not permit Cloudflare. Do not expose this resolver on the WAN: clients use
`10.9.0.1` inside the tunnel.

Create an individual user and generate a link for this profile:

```sh
sudo -u qeli qeli add-client laptop --profiles main --config /etc/qeli/server.conf
sudo -u qeli qeli share-link laptop --profile main --host vpn.example.com:443 --config /etc/qeli/server.conf
```

If `allowed_networks` restricts this user, permit the required Internet and DNS
destinations. An empty ACL means unrestricted access, not deny-all.

## Client

Import the link containing the pinned key, then select local routing policy:

```ini
[qeli]
gateway = true
kill_switch = true
dns = tunnel
mtu = 0
```

`gateway=true` opts into full tunnel locally; server NAT alone does not do that.
On Android, also enable the OS Always-on VPN and Block connections without VPN.
On iOS, `kill_switch` does not implement system-wide blocking; on-demand alone
does not prove leak protection. See the platform conditions in
[CONFIG](../manuals/CONFIG.md).

On Linux, first perform the [tunnel DNS checks](README.md#tunnel-dns-on-linux):
the system must use `systemd-resolved`. Do not blindly replace a resolver setup
failure with `dns=off`; that changes the promised DNS policy.

## IPv4, IPv6 and dual stack

**Dual stack means IPv4 and IPv6 inside the same VPN simultaneously.** An application
may reach a site over IPv4 or AAAA/IPv6, and both families need the intended VPN
routes, permissions and working egress. This is neither two VPNs nor switching
between primary and backup transports.

The outer TCP/UDP connection to Qeli is independent of the inner traffic: a
connection to a VPS IPv4 address can carry both IPv4 and IPv6. Conversely, connecting
to an IPv6 server address does not itself assign IPv6 inside the tunnel.

For dual stack, the server profile specifies `tun.ip_mode=dual`, its IPv4 address/pool
and `tun.ipv6_address`/`pool.ipv6.cidr`. A client with `ipv6=auto` accepts the negotiated
plan, but an incomplete IPv6 contract can downgrade to IPv4. When IPv6 is mandatory,
test with `ipv6=required`: missing support should fail rather than count as successful
dual stack. A TUN IPv6 address alone does not prove Internet connectivity.

Choose an explicit policy. IPv6 Internet egress requires a usable server IPv6 WAN,
a TUN IPv6 address, a distinct pool and `routing.ipv6.mode=route` or `nat66`
following [IPV6](../manuals/IPV6.md). A ULA pool is not Internet-routable by itself.
`route` requires a routed prefix and return routing; `nat66` masquerades IPv6
through an IPv6 WAN. NAT66 does not translate IPv6 into IPv4 or replace NAT64.
IPv4 NAT and IPv6 egress are configured separately, as are routes, ACLs and loss protection.
If no IPv6 egress is provided, verify that the client captures or blocks IPv6
rather than sending it directly. An IPv4-only check cannot establish full-tunnel protection.
`ipv6=off` restricts Qeli negotiation, not IPv6 throughout the OS, and does not
itself prove physical IPv6 is blocked.

In a split/LAN scenario, dual stack means separate permitted IPv4 and IPv6 networks,
not necessarily two Internet gateways. Check the destination service, route and DNS
for each family; for full tunnel, also check external IP and behavior on VPN loss.

For the address plan, server/client fragments and step-by-step checks, see
[IPv4 and IPv6 through one VPN](DUAL-STACK.md).

## Startup and verification

1. Validate complete configs using the [common procedure](README.md), restart
   the server in a maintenance window, then connect the client.
2. The client's external IPv4 must match the VPS. Test IPv6 separately.
3. Check DNS in the actual application. Browser DoH need not use the system
   resolver even when its connection travels through the VPN.
4. On Linux, inspect `ip route get 1.1.1.1`, `ip address` and logs; server NAT
   counters should increase during a transfer.
5. Test server loss using a disposable connection. When fail-closed is required,
   normal Internet access must not silently fall back to the physical network.

## Rollback and common failures

Disconnect, restore the previous profile and follow [common rollback](README.md).
For Connected-without-Internet, inspect WAN/NAT, ACLs, forwarding, DNS and MTU;
do not disable identity protection or flush the firewall as a diagnostic shortcut.

Related: [LAN only](HOME-LAN.md), [split routing](SPLIT-ROUTING.md),
[home exit node](EXIT-NODE.md).
