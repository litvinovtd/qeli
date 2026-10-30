# Use cases

Practical Qeli deployments: goals, required inputs, complete configs, startup order,
verification and recovery after reboot.

[Documentation map](../index.md) · [Русский](../../ru/scenarios/README.md)

| Use case | Goal | Version and qualification |
| --- | --- | --- |
| [Full tunnel through a VPS](FULL-TUNNEL.md) | Device Internet egress through the VPS, NAT and tunnel DNS | 0.8.3 settings; verify IPv6 and blocking without VPN separately |
| [Home LAN access only](HOME-LAN.md) | Reach a NAS, cameras and LAN without replacing the Internet gateway | Routed access without NAT requires a return route |
| [Multiple server profiles](MULTI-PROFILE.md) | Separate TCP/UDP listeners, ports, TUNs and pools | Complete profile template and independent identity keys |
| [Primary and backup transport](PRIMARY-BACKUP.md) | Reality TLS and UDP QUIC on one server | Manual profile selection; roaming does not switch profiles |
| [Split routing by destination](SPLIT-ROUTING.md) | Choose IP/CIDR destinations through Qeli or directly | include/exclude, server push and desktop route_file scope |
| [Mobile and unstable networks](MOBILE-ROAMING.md) | Wi-Fi/LTE changes, sleep, reconnect and MTU | Roaming auto; platform limitations still apply |
| [Two local networks](SITE-TO-SITE.md) | Connect sites through a central server | Linux gateways, client_subnet, forwarding and ACLs without NAT |
| [Internet through a home exit node](EXIT-NODE.md) | Other clients use the WAN of a Linux client behind NAT | Linux exit_node; exit authorization is per IP family |
| [Selected applications only](PER-APP.md) | Select VPN traffic by application | Windows/Android; macOS needs signed extensions, iOS needs MDM |
| [External TUN or TAP](EXTERNAL-TUN.md) | Delegate network policy to an external interface owner | Linux dev_attach; the owner creates, routes and removes the interface |
| [Personal, home and guest access](ACCESS-PROFILES.md) | Separate identities, permissions and limits | profiles and allowed_networks; individual device credentials |
| [Client → A → B → Internet](CHAINED-SERVERS.md) | Accept clients on A and send their traffic through B, retaining the servers' own routes; built-in client, INI hooks and autostart | Planned 0.8.4 reconnect fix passed candidate testing; root qualified, User=qeli not independently qualified |

To install Qeli itself, start with [GETTING-STARTED](../manuals/GETTING-STARTED.md).
Full parameters are in [CONFIG](../manuals/CONFIG.md); this section describes complete
deployments rather than duplicating the reference.

## Before configuration

These guides cover the tasks in the [website catalog](https://qeli.ru/docs/scenarios/)
as individual procedures. The published example baseline is **0.8.3 Beta**;
**0.8.4 is development**, not the default downloadable package. The chain guide
separately identifies the `post_up` change requiring 0.8.4. A guide is not a claim
of a fresh runtime qualification on every OS and topology.

Install both ends using [GETTING-STARTED](../manuals/GETTING-STARTED.md) and establish
a normal connection first. Retain working transport/authentication fields:
`server`, `proto`, `mode`, `key`, `sni` and `reality_sid` must match the profile.
Obtain the key and `qeli://` link over a trusted channel; do not disable
`bind_static` to make an example connect.

In networking snippets, `[profile:main]` means an **existing** profile. Substitute
its actual name and merge fields into that section; do not add a second listener
on an occupied address/port. Snippets do not replace a complete server config.
Edit existing `[qeli]` and `[user:*]` sections rather than duplicating them.
The `10.9.0.0/24`, `192.168.50.0/24`, `192.168.60.0/24` networks and interface names
are examples; choose ranges that do not overlap your networks. `203.0.113.0/24`
and `198.51.100.0/24` are documentation ranges, not geographic destination lists.

Run user/identity management as the service/configuration owner, usually
`sudo -u qeli qeli ...` with the packaged service. Do not switch the service to
root for these guides. Linux routing, firewall and TUN operations need separate
network privileges; retain the unit's required capabilities and restrictions.

Before editing, privately back up configs, `users.conf`, ownership/permissions,
routes and service drop-ins. Keep an SSH or console path outside the VPN.
Create credentials through `add-client` or the panel; do not expose real passwords
in `--password`, shell history or public reports.

## Common verification and rollback

Validate both **complete** configurations before restarting:

```sh
sudo -u qeli qeli check-config --config /etc/qeli/server.conf
sudo qeli check-config --client --config /etc/qeli/client.conf
```

Use the actual Linux client UID/path for the second command; use the normal
profile editor for GUI clients. Restarting `qeli.service` disconnects all profiles
in that service; plan a maintenance window and verify your service name.

After startup, check logs, the route to a target IP, DNS, permitted and prohibited
destinations, both IP families and connection-loss behavior. A Connected label or
a successful ping does not verify the whole deployment. For example, check egress
with `curl -4 https://api.ipify.org` and, when IPv6 is available,
`curl -6 https://api64.ipify.org`. These are third-party services; a controlled
endpoint of your own is an alternative.

To roll back, stop affected connections cleanly, restore saved configuration and
permissions, and remove **only your own** added routes/rules. Start the previous
setup and verify it again. Do not flush the entire firewall or delete DNS/sysctl/
route recovery journals to bypass an error; follow
[recovery procedures](../manuals/OPERATIONS.md).

## Chain qualification results

- [0.8.4 candidate: repeated post_up, autostart and A/B reboot](../reports/CHAINED-SERVERS-084-2026-10-30.md).
- [Historical 0.8.3 INI-hook and cleanup checks](../reports/CHAINED-SERVERS-HOOKS-2026-10-30.md).
- [Original C → A → B qualification](../reports/CHAINED-SERVERS-2026-10-30.md).

Add new use cases as separate files here with matching RU/EN paths. Include version/
privilege requirements, verification steps and qualification limits, then link them
from this catalog. Test reports and raw locations remain in reports/;
the lab raw files themselves are not moved here.

[The previous guide address](../manuals/CHAINED-SERVERS.md) remains for old links;
the maintained document is in this section.
