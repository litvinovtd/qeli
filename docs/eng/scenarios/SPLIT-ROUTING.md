# Split routing by destination

Choose destinations that use Qeli and those that go directly. Geographic selection
requires your own maintained IP/CIDR list; these settings have no built-in country
database or domain-name routing engine.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/SPLIT-ROUTING.md)

## Select a model

| Model | Client settings | Result |
| --- | --- | --- |
| Listed networks through VPN | `gateway=false`, `include` | Other destinations use normal routing |
| Everything through VPN except exclusions | `gateway=true`, `exclude` | Exclusions intentionally bypass the VPN |
| Server-managed routes | Repeatable server `route` | Accepted when the client has `pull_routes=true` |

The `203.0.113.0/24` and `198.51.100.7` examples are documentation addresses, not
working destinations. Replace them with a verified list. CDN, anycast and changing
IP assignments make country-based classification approximate.

## Selected IPs through VPN

Merge into an existing client profile:

```ini
[qeli]
gateway = false
include = 203.0.113.0/24, 198.51.100.7/32
pull_routes = false
dns = system
```

Here `pull_routes=false` declines additional server routes. It does not disable
local `include`, the carrier connection or independent full-tunnel policy.
Restore `pull_routes=true` if administrator routes are also needed. Public IP
egress needs suitable server NAT or a routed uplink; private LAN access needs
a [return route](HOME-LAN.md).

On Windows/macOS, a long list can live in a separate file:

```ini
[qeli]
gateway = false
route_file = C:\Qeli\selected-cidrs.txt
```

```text
# selected-cidrs.txt: one IP or CIDR per line
203.0.113.0/24
198.51.100.7
```

On macOS, substitute a path such as `/Users/alice/.config/qeli/selected-cidrs.txt`.
This `route_file` behavior is a desktop feature. Use `include`/`exclude` or server
push on Linux CLI/mobile clients. Avoid conflicting simultaneous lists.

## Full tunnel with direct exclusions

```ini
[qeli]
gateway = true
exclude = 203.0.113.0/24, 198.51.100.7/32
dns = tunnel
```

These addresses intentionally bypass the VPN. `exclude` is neither a server ACL
nor a guarantee of compatibility with every platform's kill-switch implementation.
Test the combination on your OS without disabling protection for the entire profile.

## Server routes and DNS

Instead of a local list, add routes at profile or user scope:

```ini
[profile:main]
route = 203.0.113.0/24 gateway=10.9.0.1 metric=100
route = 198.51.100.7/32 gateway=10.9.0.1 metric=100
```

`allowed_networks` must permit destinations but creates no routes itself.
IPv6 needs its own policy: IPv4 lists do not cover a domain's AAAA addresses.
`dns=system` preserves local DNS; `dns=tunnel` uses permitted tunnel resolvers.
Neither turns an IP list into a domain routing engine.

## Verification and rollback

Validate the full config and reconnect. Compare a listed and an unlisted
destination using Linux `ip route get`, Windows `Get-NetRoute` or macOS
`route -n get`. Test a real TCP/UDP service, DNS, IPv6 and behavior after reconnect.
Restore previous fields/files and reconnect cleanly to roll back; do not flush
the system routing table.

Reference: [CONFIG](../manuals/CONFIG.md). For process-based selection, use
[PER-APP](PER-APP.md).
