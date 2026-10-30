# Attaching to an external TUN or TAP

Attach the Qeli Linux client to an interface created and maintained by another
controller. Qeli carries packets; the external owner configures L3 and network
policy. Keenetic OpkgTun is a typical integration.

[Catalog and preparation](README.md) · [Русский](../../ru/scenarios/EXTERNAL-TUN.md)

## Ownership boundaries

| Operation | Owner |
| --- | --- |
| Create/delete TUN/TAP | External controller |
| Link up, MTU, addresses and prefixes | External controller |
| Routes, DNS, NAT and firewall | External controller |
| AUTH, encryption and packet transport | Qeli |
| Publish assigned IPv4 | Qeli through `QELI_TUNIP_FILE` |

The client and owner must use the same network namespace, compatible TUN/TAP
type and suitable `/dev/net/tun` permissions. `IFF_NO_PI`, absence of
`IFF_VNET_HDR` and queue mode must be compatible with attach. Do not replace the
interface while the client still owns an open descriptor to it.

## External preparation

For example `ext0` and the packaged `qeli` account, only if the interface does not exist:

```sh
sudo ip tuntap add dev ext0 mode tun user qeli
sudo ip link set dev ext0 mtu 1400 up
sudo install -d -o qeli -g qeli -m 0700 /run/qeli-ext
```

Do not run this over an interface owned by router firmware; use its normal
controller. `1400` is an example: coordinate MTU with the server and path.
IPv6 inner MTU must not be below `1280`. Supporting a smaller outer UDP path does
not mean the external owner can assign that same smaller MTU to the interface.

## Client configuration

Retain a complete working connection profile and add:

```ini
[qeli]
dev = ext0
device_type = tun
dev_attach = true
gateway = false
dns = off
```

For an actual external TAP, use `device_type=tap` and let the same owner prepare
a compatible TAP. **Omit `tun.tx_queue_len`**: the external owner controls its
queue; an explicit value with attach is rejected, even `1000`.
`exit_node=true` is incompatible with attach.

Set the environment in the Linux client process or its existing unit:

```ini
[Service]
Environment=QELI_TUNIP_FILE=/run/qeli-ext/ext0.ip
```

This is a **client-service** drop-in, not a replacement for server `qeli.service`.
`QELI_TUNIP_FILE` is an environment variable, not an INI field. Named attach is
different from the internal platform contract `QELI_PLATFORM_TUN_FD`.

## Address and routes after AUTH

Start the interface owner before Qeli. After AUTH, the file contains only the
assigned IPv4 address **without a prefix length**. The controller must establish
freshness, validate the expected pool and use the negotiated/configured prefix.
Do not apply an old session's file or assume every pool is `/24`.

For example, only if the server actually assigned `10.9.0.2` from `/24`, the owner
can manually assign:

```sh
sudo ip address add 10.9.0.2/24 dev ext0
```

The owner then installs required routes/firewall policy, retaining a physical
carrier route outside the tunnel. `gateway=false` alone creates no split routes
in attach mode. The IPv4 file does not convey IPv6 configuration; that needs a
separate coordinated mechanism in the owner.

## Verification and shutdown

Inspect `ip -details link show dev ext0`, `ip address show dev ext0`, carrier and
destination routes, attach logs and actual traffic. Stop Qeli cleanly first,
then remove **your own** owner policy/interface if you created it. Qeli does not
delete the borrowed interface itself.

## Rollback

To return to ordinary operation, remove `dev_attach`, address-file environment
and external-owner settings. Do not create a normal TUN over a still-busy `ext0`.
The external manager sees packets before encryption and belongs to the trusted base.

Integration and firmware requirements:
[Keenetic OpkgTun](../../../release/keenetic/opkgtun/README.md),
[KEENETIC-DEPLOY](../manuals/KEENETIC-DEPLOY.md), [CONFIG](../manuals/CONFIG.md).
