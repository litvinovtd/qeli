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

For dual stack, register `client_subnet=::/0` for the exit and `route=::/0` for the
consumer, configure IPv6 TUN/pool and a usable home IPv6 WAN following
[CONFIG](../manuals/CONFIG.md). Otherwise prevent unintended direct IPv6 on the
consumer; `ipv6=off` does not disable IPv6 throughout the OS.

## Startup and verification

1. Validate complete configs. Start the VPS, then the home exit, then the consumer.
2. Check consumer external IPv4/IPv6: expect the home WAN, not the VPS.
3. On the exit, inspect `Exit-node engaged`, the selected WAN and increasing
   counters for the relevant `qeli-exit-node` rules; do not delete them manually.
4. Test DNS and TCP/UDP. Stop the exit node: in an exit-only setup, consumer
   Internet must stop rather than switch to the VPS WAN or physical network.
5. Restore the exit and repeat after reconnect/reboot.

## Rollback

Stop the consumer, then the exit cleanly. Remove only your `/0` markers, settings
and extra firewall restriction, and restore the former policy. Resolve cleanup
errors using [OPERATIONS](../manuals/OPERATIONS.md), not journal deletion.
This differs from a [two-server chain](CHAINED-SERVERS.md).
