# Two local networks through a central server

Connect two site LANs through Qeli on a VPS without NAT. A Linux client acts as a
router at each site; ordinary Internet access retains each site's local gateway.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/SITE-TO-SITE.md)

## Address plan

`LAN A → Linux A → Qeli VPS → Linux B → LAN B`.

| Node | LAN | VPN address |
| --- | --- | --- |
| Site A | `192.168.50.0/24`, Linux A: `192.168.50.2` | `10.9.0.2` |
| Site B | `192.168.60.0/24`, Linux B: `192.168.60.2` | `10.9.0.3` |
| Server | Pool `10.9.0.0/24` | `10.9.0.1` |

All networks must be distinct. Outbound site-to-VPS connections are sufficient,
so Linux A/B may be behind NAT. This is an IPv4 example; IPv6 requires distinct
prefixes and equivalent routes/ACLs following [IPV6](../manuals/IPV6.md).

## Server and users

In the existing server profile:

```ini
[profile:main]
routing.client_to_client = true
routing.forward_private = true
routing.nat.enabled = false
```

Create `branch-a` and `branch-b` through CLI/the panel. Then extend their
**existing** `users.conf` sections, retaining the generated password hashes:

```ini
[user:branch-a]
profiles = main
static_ip = 10.9.0.2
client_subnet = 192.168.50.0/24
route = 192.168.60.0/24 gateway=10.9.0.1
allowed_networks = 192.168.60.0/24, 10.9.0.0/24

[user:branch-b]
profiles = main
static_ip = 10.9.0.3
client_subnet = 192.168.60.0/24
route = 192.168.50.0/24 gateway=10.9.0.1
allowed_networks = 192.168.50.0/24, 10.9.0.0/24
```

`client_subnet` registers a LAN **behind** a client; `route` tells it how to reach
the other LAN; `allowed_networks` permits destinations. Use a separate identity
for each gateway: reconnecting with the same `static_ip` can replace the previous
session. Do not NAT between LANs when original source addresses are required.

## Linux gateways and LAN routers

Use these settings in both working client profiles, with their own credentials:

```ini
[qeli]
gateway = false
pull_routes = true
forward = true
gateway_nat = false
dns = system
```

`forward=true` routes the client's LAN without masquerading. On ordinary Linux,
Qeli manages required sysctls with ownership tracking; do not replace that with
blanket sysctl changes. Also permit required traffic in gateway and endpoint firewalls.

If the Linux gateways are not their LANs' default gateways, add and persist routes
on the main LAN routers:

```sh
# Router A, after checking for conflicting existing routes
sudo ip route add 192.168.60.0/24 via 192.168.50.2
# Router B
sudo ip route add 192.168.50.0/24 via 192.168.60.2
```

These commands illustrate Linux routers. Use your hardware's own persistent
configuration mechanism. Start the server, then Linux A and B; enable normal
client-service startup and check private INI permissions.

## Verification and rollback

Test a TCP service from LAN A to LAN B and the reverse direction. Receiving hosts
must see the other LAN's actual source address, not the VPS address. Both sites'
Internet IPs must remain unchanged. After each gateway reboot, check route
restoration and absence of unexpected NAT rules.

For one-way connectivity, check return routes, ACLs, endpoint firewalls,
overlapping subnets and `client_subnet` registration. Broadcast discovery is not
an L3 connectivity test: names/discovery may need separate DNS or application settings.

To roll back, stop clients, restore user/server settings, remove only the LAN-router
routes you added and restore previous autostart. Retain Qeli recovery journals.
For sequential Internet egress through another server, use
[CHAINED-SERVERS](CHAINED-SERVERS.md).
