# Home LAN access only

Reach a NAS, cameras or home services from a remote device without replacing its
normal Internet connection. The primary design routes without NAT, preserving client VPN addresses.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/HOME-LAN.md)

## Address plan

| Node or network | Example |
| --- | --- |
| Home LAN | `192.168.50.0/24` |
| Home router | `192.168.50.1` |
| Qeli server LAN address | `192.168.50.2` |
| VPN pool and server address | `10.9.0.0/24`, `10.9.0.1` |
| NAS | `192.168.50.10` |

Reserve the server's LAN address. Its VPN port must be externally reachable:
home-router NAT requires port forwarding; CGNAT may prevent inbound forwarding.
In that case, consider [site-to-site through a VPS](SITE-TO-SITE.md).
The remote client's LAN must not overlap `192.168.50.0/24`.

## Server and user

Merge into the existing profile:

```ini
[profile:main]
routing.nat.enabled = false
routing.forward_private = true
route = 192.168.50.0/24 gateway=10.9.0.1 metric=100
```

Create a user through the panel or `add-client`, then extend its `users.conf`
section while retaining the real hash and other credential fields:

```ini
[user:home-laptop]
profiles = main
allowed_networks = 192.168.50.0/24
```

`route` selects the client path; `allowed_networks` permits the destination on the
server. An ACL does not create a route. Permit required services from the VPN pool
in server and LAN-host firewalls, rather than allowing everything just to pass ping.

## Client and return route

In the working client profile:

```ini
[qeli]
gateway = false
pull_routes = true
dns = system
```

Internet and system DNS remain local. Names such as `nas.home` do not start
resolving automatically: separately configure a reachable home resolver and its
ACL permission, or test the service by IP.

Persist a route on the home router: `10.9.0.0/24` via `192.168.50.2`.
For a Linux router, a temporary test is:

```sh
sudo ip route add 10.9.0.0/24 via 192.168.50.2
```

First check for an existing route to that pool. Persist the route through the
router/OS's own configuration mechanism. The Qeli server's LAN route must use its
physical LAN interface, not point back into the VPN.

## Verification

1. Validate configs and connect using the [common procedure](README.md).
2. Open a real NAS service, not just ping. On a Linux client,
   `ip route get 192.168.50.10` must select the tunnel.
3. The client's external IP must remain unchanged. Check physical DNS as well.
4. A LAN host should see a source in `10.9.0.0/24`; replies must return through
   `192.168.50.2`.
5. Confirm that destinations outside the user's ACL remain inaccessible.

## If a return route cannot be added

As a compromise, enable `routing.nat.enabled=true` and set
`routing.nat.interface` to the Qeli server's **LAN interface**. Keep
`gateway=false` on the client. LAN hosts then see the server address instead of
individual VPN users, reducing the precision of LAN rules and logs.
This is an alternative design, not a substitute for the return route in the routed example.

## Rollback

Disconnect and restore the original settings and ACL. Remove only your own added
return route and its persistent router entry; do not replace someone else's routes.
For a LAN behind a remote client, use [SITE-TO-SITE](SITE-TO-SITE.md).
