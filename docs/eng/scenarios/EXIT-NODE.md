# Internet through a home exit node

Use a public server as a rendezvous point and a home Linux client as Internet
egress. The home node initiates its own VPS connection and needs no inbound port forwarding.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/EXIT-NODE.md)

## Topology and constraints

`Consumer → Qeli VPS → home exit client → home WAN → Internet`.

`exit_node` is a Linux role, not a Windows/Android/iOS role. The home node needs
a usable physical WAN with an unambiguous default route, TUN and network
capabilities/iptables. Its own Internet traffic must not enter this VPN.
Do not combine `exit_node` with `gateway_nat`, `forward` or external `dev_attach`.

## Prepare the server

Create a dedicated profile or deliberately adapt an existing one:

```ini
[profile:main]
routing.client_to_client = true
routing.forward_private = true
routing.nat.enabled = false
```

Create `home-exit` and `traveller` through CLI/the panel, retaining their real
credential fields. For IPv4, extend `users.conf`:

```ini
[user:home-exit]
profiles = main
client_subnet = 0.0.0.0/0

[user:traveller]
profiles = main
route = 0.0.0.0/0
```

The first `/0` registers Internet destinations behind the exit client. The second
authorizes this consumer to use that exit; it does not push a default route.
Both users' actual ACLs must permit required destinations, including DNS. Do not
share one exit identity between multiple exit nodes.

For an **exit-only** policy, also block direct forwarding of this profile's VPN
pool into the VPS WAN using your firewall. Neither disabled NAT nor a user `/0`
marker alone proves that prohibition, especially if another profile/rule already
masquerades the same source range.

### Block egress through the VPS WAN

For the strict variant, use a **dedicated profile and TUN**. Below, `main` is its
name and `vpn0` its actual `tun.name`; substitute both from your configuration.
Stop consumers and disable their autostart during setup. Back up firewall rules
and retain SSH access outside the VPN. An administrator runs these commands
**in the same network namespace as the server worker's TUN**.

Example for a host with `iptables`/`ip6tables` and an available `mangle` table:

```sh
sudo iptables -w 5 -t mangle -C FORWARD -i vpn0 -m comment --comment qeli-exit-only-main -j DROP 2>/dev/null || sudo iptables -w 5 -t mangle -I FORWARD 1 -i vpn0 -m comment --comment qeli-exit-only-main -j DROP
sudo ip6tables -w 5 -t mangle -C FORWARD -i vpn0 -m comment --comment qeli-exit-only-main -j DROP 2>/dev/null || sudo ip6tables -w 5 -t mangle -I FORWARD 1 -i vpn0 -m comment --comment qeli-exit-only-main -j DROP
```

This blocks **all kernel transit out of that TUN**, not just traffic through the
current WAN name. It survives an uplink change and does not depend on NAT being
present. `mangle FORWARD` runs before `filter FORWARD` permits. The working consumer
→ exit-client path goes directly between Qeli sessions, bypassing VPS kernel FORWARD.
Without a suitable exit session, kernel fallback is blocked. This TUN therefore
cannot also serve ordinary VPS egress or transit into its LAN.

Verify both rules; do not start consumers if either check fails:

```sh
sudo iptables -w 5 -t mangle -C FORWARD -i vpn0 -m comment --comment qeli-exit-only-main -j DROP
sudo ip6tables -w 5 -t mangle -C FORWARD -i vpn0 -m comment --comment qeli-exit-only-main -j DROP
sudo iptables -w 5 -t mangle -nvL FORWARD --line-numbers
sudo ip6tables -w 5 -t mangle -nvL FORWARD --line-numbers
```

**Persistence is mandatory:** add equivalent restrictions to your firewall's managed
persistent configuration, applied **before Qeli/consumers start**, in the intended
namespace. Verify after reboot and firewall reload. If UFW/firewalld/another manager
owns the firewall, configure the policy there: these manual commands do not create
persistent configuration. Until that is done, this is a manual test only; do not
enable consumer autostart. Do not blindly save the whole live Qeli ruleset with
`iptables-save`: that could persist temporary NAT/recovery rules. Do not rely only
on `routing.post_up`: a hook failure alone does not guarantee profile startup refusal.
Independent protection checks are required.

These rules neither restrict `INPUT` to VPS-local services nor its `OUTPUT`,
including DNS-proxy upstream queries. Those need separate ACLs and host policy.
Do not remove the restriction while consumers can still use the profile.

## Home Linux client

Retain its working transport/authentication fields:

```ini
[qeli]
gateway = false
exit_node = true
gateway_nat = false
forward = false
dns = system
```

Qeli forwards incoming tunnel traffic through the selected physical WAN and
masquerades it. Do not set a default route through this client's own TUN. Do not
rename its WAN while running; stop the profile and confirm cleanup first.

## Consumer

```ini
[qeli]
gateway = true
kill_switch = true
dns = tunnel
dns_servers = 1.1.1.1
```

This explicitly selects a public resolver whose queries must also use the home
exit. Using the VPS DNS proxy may instead send its upstream requests with the
VPS address. Select a resolver appropriate for your policy and verify its route.
Kill-switch applicability depends on the consumer OS.

For a Linux consumer, first perform the [tunnel DNS checks](README.md#tunnel-dns-on-linux).

### When dual stack is required

Here this means **both families inside the VPN, exiting at home**, not an IPv6
connection to the VPS itself. Retain the IPv4 entries and add `client_subnet=::/0`
for the exit user and `route=::/0` for the consumer. The VPS needs `tun.ip_mode=dual`,
an IPv6 TUN/pool and ACL permissions for required IPv6 destinations. Do not copy
`nat66` from an ordinary VPS full-tunnel setup: exit-only IPv6 egress belongs at
home, not on the VPS. `routing.ipv6.mode=off` on the VPS blocks its kernel transit,
not the direct path between Qeli sessions; retain the independent restrictions
above for both families as well.

The home exit client needs a working IPv6 WAN/default route and `ip6tables` NAT66
support: Qeli masquerades IPv6 there. Home IPv4 Internet access alone cannot provide
IPv6 egress. For mandatory verification, set `ipv6=required` on both exit and
consumer, and separately test external IPv4/IPv6 and loss of each family. Follow
[IPV6](../manuals/IPV6.md) for pools, prefixes and MTU, and
[FULL-TUNNEL](FULL-TUNNEL.md) for outer versus inner IP.

Otherwise prevent unintended direct IPv6 on the consumer; `ipv6=off` does not disable
IPv6 throughout the OS.

## Startup and verification

1. Validate complete configs and persistent VPS kernel-transit restrictions. Start
   the VPS, recheck both rules, then start the home exit and the consumer.
2. Check consumer external IPv4/IPv6: expect the home WAN, not the VPS.
3. On the exit, inspect `Exit-node engaged`, the selected WAN and increasing
   counters for the relevant `qeli-exit-node` rules; do not delete them manually.
4. Test DNS and TCP/UDP. Stop the exit node: in an exit-only setup, consumer
   Internet must stop rather than switch to the VPS WAN or physical network.
5. Restore the exit and repeat after reconnect/reboot. Before enabling consumer
   autostart, confirm restoration of the restrictions, DNS and both families.

## Rollback

Stop the consumer, then the exit cleanly. Remove only your `/0` markers, settings
and extra firewall restriction, and restore the former policy. For the manual
example, after confirming these are your exact rules:

```sh
sudo iptables -w 5 -t mangle -D FORWARD -i vpn0 -m comment --comment qeli-exit-only-main -j DROP
sudo ip6tables -w 5 -t mangle -D FORWARD -i vpn0 -m comment --comment qeli-exit-only-main -j DROP
```

Remove only the corresponding persistent firewall entries too, or they will return
on reload/reboot. Do not flush whole tables. Resolve Qeli cleanup
errors using [OPERATIONS](../manuals/OPERATIONS.md), not journal deletion.
This differs from a [two-server chain](CHAINED-SERVERS.md).
