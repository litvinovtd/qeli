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
| Publish IPv4/IPv6 addresses, prefixes, MTU and generation | Qeli through `QELI_TUNIP_FILE` |

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
forward = false
gateway_nat = false
exit_node = false
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

Start the interface owner before Qeli. In 0.8.3 and current dev, the file is published
after successful application steps for the authenticated NetworkPlan. It contains
**multiple lines**, not one IPv4 address. Example dual-stack plan:

```text
10.9.0.2
ipv4=10.9.0.2/32
ipv6=fd71:e1:8000:102::2/128
mtu=1400
generation=7
```

The first line is the primary address without a prefix for compatibility; it is
IPv6 in an IPv6-only plan. `ipv4`/`ipv6` lines appear only for assigned families.
Named fields contain TUN addresses **with their prefixes**, not allocation-pool
sizes. In particular, `/32` and `/128` are valid on an L3 TUN: do not substitute
`/24` or `/64`.

The controller reads one file snapshot and parses data, never shell code
(`source`/`eval` are forbidden). Validate addresses against expected pools, prefix
lengths and MTU, required families and the current process lifecycle. `generation`
distinguishes repeated AUTH within an adapter, including the same address, but can
reset when the adapter is recreated. It is neither a global ID nor a heartbeat:
the file's existence does not prove the old session is still alive.

For automatic apply/reconnect, coordinate the owner with the writer as described
in [Keenetic OpkgTun](../../../release/keenetic/opkgtun/README.md), including the
publication lock for current dev. Reading the file alone cannot exclude a plan
change during application. Never remove a lock with an unknown/live owner.

For example, only if the fresh plan actually contains `ipv4=10.9.0.2/32`, the owner
can manually assign:

```sh
sudo ip address add 10.9.0.2/32 dev ext0
```

The owner then installs required routes/firewall policy, retaining a physical
carrier route outside the tunnel. `gateway=false` alone creates no split routes
in attach mode. An `ipv6` field supplies an address/prefix, but the owner still
applies it and the IPv6 policy. The file does not enumerate routes, DNS or firewall
rules; addresses and MTU alone cannot reconstruct them.

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
