# Primary and backup transport

Keep two ways to reach one server: TCP Reality TLS as the primary and UDP QUIC as
the backup. The user selects the backup profile; roaming does not do that.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/PRIMARY-BACKUP.md)

## Prepare independent entry points

Follow [MULTI-PROFILE](MULTI-PROFILE.md), for example TCP `443` and UDP `8449`,
with distinct TUNs, pools and correct identity keys. Give both the same purpose:
VPS Internet egress or access to the same LAN. Different ACLs/routes make the backup
an intentionally different service rather than an equivalent replacement.

Permit both profiles in the user's existing `users.conf` section:

```ini
[user:laptop]
profiles = reality-tls, udp-quic
```

Generate separate links:

```sh
sudo -u qeli qeli share-link laptop --profile reality-tls --host vpn.example.com:443 --config /etc/qeli/server.conf
sudo -u qeli qeli share-link laptop --profile udp-quic --host vpn.example.com:8449 --config /etc/qeli/server.conf
```

Import them as Primary TCP and Backup UDP. Do not merely edit `proto` or a port
in the old profile: transport, camouflage and identity must match the selected
server entry point. Configure local routing, DNS and per-app policy in both
profiles; `qeli://` does not carry arbitrary local settings.

## Enable recovery within a profile

```ini
[qeli]
roaming = auto
reconnect = true
reconnect_retries = -1
mtu = 0
```

Roaming transfers a session of the **same** profile between physical networks;
reconnect dials that profile again. Neither turns Reality TLS into UDP QUIC or
selects another server. A profile availability result also does not establish
successful authentication, DNS or payload delivery.

## Switching and verification

1. Before travelling, connect the primary and check required resources, DNS and IPv4/IPv6.
2. Disconnect cleanly, connect the backup and repeat the same checks.
3. If TCP becomes unavailable, finish the primary connection and select UDP.
   Resolve an incomplete stop/recovery before switching; do not bypass protection.
4. Check uploads/downloads, not just a small ping. UDP can be filtered, lose large
   datagrams or behave differently after a network change.
5. Return to TCP manually once available and check that previous routes/DNS are gone.

Two transports on one VPS do not protect against VPS failure. Independent backup
requires another server, its own link and equivalent access policy. UDP is not
universally faster, and no mode guarantees bypassing every DPI implementation.

## Rollback

Disconnect the backup and return to the tested primary. To remove a server entry
point, revoke its user permissions first and plan the service stop.
See [MOBILE-ROAMING](MOBILE-ROAMING.md) for physical network changes.
