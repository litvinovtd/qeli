# Personal, home and guest access

Separate destinations and credentials for a family or team. A profile defines
the entry point, a user defines identity/permissions, and a group supplies default
limits/ACLs. One shared password does not provide individual access revocation.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/ACCESS-PROFILES.md)

## Define roles

| Role | Profile | Allowed destination | Local client policy |
| --- | --- | --- | --- |
| Personal laptop | `personal` | Internet under owner policy | Full tunnel, tunnel DNS |
| Home device | `home` | `192.168.50.0/24` | Split tunnel, system DNS |
| Guest | `guest` | Service host `192.168.50.30/32` only | Split tunnel, system DNS |

Prepare three complete server profiles using [MULTI-PROFILE](MULTI-PROFILE.md),
with distinct TUNs/pools/ports. Use [FULL-TUNNEL](FULL-TUNNEL.md) for personal access
and [HOME-LAN](HOME-LAN.md) for home/guest access, including return routes for all
their pools. Do not enable client-to-client traffic where it is unnecessary.

## Create individual accounts

```sh
sudo -u qeli qeli add-client alice-laptop --profiles personal --config /etc/qeli/server.conf
sudo -u qeli qeli add-client family-tablet --profiles home --config /etc/qeli/server.conf
sudo -u qeli qeli add-client guest-phone --profiles guest --config /etc/qeli/server.conf
```

Keep generated secrets private and distribute each link only to its owner.
Extend existing `users.conf` sections without replacing password hashes:

```ini
[group:home]
allowed_networks = 192.168.50.0/24
max_sessions = 2

[group:guests]
allowed_networks = 192.168.50.30/32
max_sessions = 1
bandwidth_limit_mbps = 5

[user:alice-laptop]
profiles = personal
max_sessions = 1

[user:family-tablet]
profiles = home
group = home
route = 192.168.50.0/24

[user:guest-phone]
profiles = guest
group = guests
route = 192.168.50.30/32
```

Group limits apply to **each** member, not as a shared group quota. Positive
personal limits and nonempty personal ACLs can override the group; remove stale
overrides when changing roles. Set `profiles` explicitly per user. An empty/
unrestricted value does not mean all entry points are prohibited.

`allowed_networks` is an IP/CIDR allowlist, not a port filter. The guest can reach
the allowed host, not automatically just HTTPS. Restrict ports, management
services, VPS metadata endpoints and LAN isolation through firewall policy.
`0.0.0.0/0` includes private IPv4 destinations; it is not a safe synonym for
public-Internet-only access. Configure IPv6 ACLs separately.

## Clients and verification

Use `gateway=true`, `dns=tunnel` for personal access, and `gateway=false`,
`pull_routes=true`, `dns=system` for home/guest access. If tunnel DNS is required,
permit those resolver addresses explicitly.

Validate the complete config, apply settings and test **each** role: the permitted
profile works, other profiles reject access, the desired service works, and the
guest cannot reach adjacent LAN hosts or management ports. Also test IPv6 and
device limits. `max_sessions` limits devices of one user; a new device can evict
the oldest session rather than always being rejected.

## Revocation and rollback

Disable the intended user through the panel/INI and terminate its active sessions
using normal management; verify that reconnection is refused. Do not rotate a
shared password for all devices instead. To roll back, restore prior fields/
groups and permissions, retaining database ownership and avoiding wider guest
profile access. References: [CONFIG](../manuals/CONFIG.md), [PANEL](../manuals/PANEL.md).
