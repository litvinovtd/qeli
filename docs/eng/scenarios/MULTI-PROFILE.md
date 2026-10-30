# Multiple profiles on one server

Run independent entry points in one Qeli service, such as TCP `reality-tls` and
UDP `udp-quic`. Profiles have separate transports, TUNs, address pools and identities;
users share a database with explicit profile permissions.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/MULTI-PROFILE.md)

## Profile plan

| Profile | Listener | TUN | IPv4 pool |
| --- | --- | --- | --- |
| `reality-tls` | TCP `443` | `vpn0` | `10.9.0.0/24` |
| `udp-quic` | UDP `8449` | `vpn7` | `10.9.7.0/24` |

Interface names and pools must be unique in their network context. For IPv6,
assign distinct `/64` pools from your own ULA or routed prefix. TCP and UDP have
separate port namespaces, but different numbers make this example easier to diagnose.

## Prepare complete profiles

Start from [server-multiprofile.conf](../../../qeli/config/server-multiprofile.conf),
retain the required profile sections and merge them into the working config.
Do not replace existing `[auth]`, `[web]`, `[logging]` or `users_file` with demo
values. This is only the structure, not a complete REALITY configuration:

```ini
[profile:reality-tls]
bind.transport = tcp
bind.port = 443
tun.name = vpn0
tun.address = 10.9.0.1
pool.cidr = 10.9.0.0/24
obf.mode = reality-tls

[profile:udp-quic]
bind.transport = udp
bind.port = 8449
tun.name = vpn7
tun.address = 10.9.7.1
pool.cidr = 10.9.7.0/24
obf.mode = fake-tls
obf.quic.enabled = true
```

For REALITY, retain the full `obf.tls.reality_proxy.*` settings, matching target/SNI,
`real_tls=true` and your own random `short_ids`; a public sample short ID is not a
production secret. Each profile has its own identity: do not reuse the first
profile's pinned key in the second client's configuration.

Configure NAT/DNS independently for each full-tunnel profile using
[FULL-TUNNEL](FULL-TUNNEL.md), including the DNS address in its own pool.
For split/LAN access, follow [HOME-LAN](HOME-LAN.md) instead of enabling general NAT.

## Grant access and generate links

```sh
sudo -u qeli qeli add-client laptop --profiles reality-tls,udp-quic --config /etc/qeli/server.conf
sudo -u qeli qeli share-link laptop --profile reality-tls --host vpn.example.com:443 --config /etc/qeli/server.conf
sudo -u qeli qeli share-link laptop --profile udp-quic --host vpn.example.com:8449 --config /etc/qeli/server.conf
```

For an existing user, edit `profiles` in its existing section instead of creating
a duplicate identity. Omitting a profile restriction allows all profiles, not
none. Open TCP `443` and UDP `8449` separately on the host and in cloud firewall
rules. A reachable TCP port says nothing about UDP.

## Startup and verification

1. Validate the complete server config and restart in a maintenance window.
2. Inspect listeners (`ss -lntup`), TUNs and addresses (`ip address`).
3. Import both links as separate client profiles. Test connection, egress IP,
   DNS and MTU for each in turn.
4. Test a user allowed on only one profile: the other must reject authentication
   even with the correct password.
5. Two saved profiles do not imply two simultaneously active VPNs on a phone.

## Rollback

Disconnect clients of the removed profile, restore server settings and user
restrictions, and confirm clean TUN/DNS/firewall release. Do not delete existing
recovery journals. For a backup transport, continue with
[PRIMARY-BACKUP](PRIMARY-BACKUP.md).
