# qeli-client on Keenetic — step-by-step deployment

Deploying the qeli VPN client on a Keenetic router (Entware) as a gateway for the whole
LAN. The architecture and rationale of the port — [KEENETIC-PORT.md](KEENETIC-PORT.md).
The bundle files — in `release/keenetic/`.

> ⚠️ The bundle scripts are **templates**, not tested on a live Keenetic. The commands
> below are universal; the interface names and the interaction with the KeeneticOS
> firewall depend on the model and firmware version — check on site.

---

## Prerequisites

- **Entware** is installed on the router (the `opkg` package manager, the `/opt`
  directory).
- **SSH** is enabled and you have shell access to the router.
- The **VPN** component is enabled in KeeneticOS (any of WireGuard/OpenVPN/IPsec) — it
  ensures `/dev/net/tun` is present. Added in the web UI: *Management → General settings →
  Change the component set*.
- There's a working **qeli server** with a profile and a client provisioned for the
  router.

---

## Step 0. Router reconnaissance (over SSH to the router)

```sh
opkg print-architecture | grep -E 'aarch64|mipsel|mips'   # the package arch
cat /proc/cpuinfo | grep -E 'cpu model|FPU|system type'   # CPU/FPU
ls -l /dev/net/tun                                         # must exist
df -h /opt                                                 # space (need ~5-10 MB)
```

- `mipsel-…` → the binary `qeli-client-mipsel` (MT7621/7628, etc.).
- `aarch64-…` → the binary `qeli-client-aarch64` (new ARM models).
- No `/dev/net/tun` → go back to the prerequisites and enable the VPN component.

---

## Step 1. Build the binaries (on the dev/lab, not on the router)

```sh
python scripts/build_keenetic.py
# → release/keenetic/qeli-client-aarch64   (static ARM aarch64)
# → release/keenetic/qeli-client-mipsel    (static-pie MIPS32r2)
```

You can build only the needed arch: `python scripts/build_keenetic.py mipsel`.

---

## Step 2. Get the client credentials from the server (on the qeli server)

```sh
# Provision a client and get a qeli:// link right away (and the password — printed ONCE):
qeli add-client router1 --link --host <server_public_address>

# The server public key for pinning (anti-MITM):
qeli show-identity
```

From the link/output you'll need: `server` (host:port), `proto` (tcp/udp), `user`, `pass`,
`key` (the server pubkey), `mode` (fake-tls/obfs/plain/…), `sni`.

---

## Step 3. Copy the bundle to the router (from the dev)

```sh
scp -r release/keenetic <user>@<router-ip>:/opt/tmp/keenetic
# <user> — the router account with access to /opt (usually admin/root). An alternative is USB.
```

---

## Step 4. Installation (on the router)

```sh
cd /opt/tmp/keenetic
sh install-keenetic.sh
```

The script: detects the arch → places the right binary in `/opt/bin/qeli-client`; installs
`ip-full` and `iptables` (Keenetic's busybox `ip` is stripped — no `tuntap`); checks
`/dev/net/tun`; lays out `S99qeli` and a config stub.

---

## Step 5. Fill in the config (on the router)

```sh
vi /opt/etc/qeli/client.conf
```

Substitute the values from Step 2. For a gateway router two keys matter:

```ini
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = router1
pass   = <password>
key    = <server pubkey from show-identity>
mode   = fake-tls           # MIPS: fake-tls | obfs | plain (ChaCha20). reality-tls
sni    = www.cloudflare.com #       on mipsel is very slow — for ARM only
gateway = true              # all LAN traffic into the tunnel (full-tunnel)
dns     = off               # DON'T touch the router's resolver (the firmware owns it)

[logging]
level = info
file  = /opt/var/log/qeli-client.log
```

---

## Step 6. Check the interfaces for NAT (on the router)

```sh
ip a            # find the LAN bridge (usually br0) and confirm the tun will be vpn0
```

If the LAN bridge isn't `br0` or the tun isn't `vpn0` — fix the variables at the top of
`S99qeli`:

```sh
vi /opt/etc/init.d/S99qeli      # TUN=…, LAN_IF=…, GATEWAY=yes
```

---

## Step 7. Start

```sh
/opt/etc/init.d/S99qeli start
tail -f /opt/var/log/qeli-client.log
```

Wait for the line `Auth OK, assigned IP: 10.x.x.x` — that's a successful connection to the
server. Entware starts an init script with the `S` prefix **automatically when the router
boots**.

---

## Step 8. Check the tunnel

On the router:

```sh
ip a show vpn0                                  # the tun has an address 10.x.x.x
ip route | grep -E 'default|vpn0'               # with gateway=true — default via vpn0
iptables -t nat -L POSTROUTING -n | grep MASQUERADE   # NAT on vpn0 is set
curl -s https://ifconfig.me ; echo             # the external IP = the VPN server address
```

From any LAN client (a phone/PC behind the router):

```sh
# the external IP should become the VPN server address; DNS and sites open
curl -s https://ifconfig.me ; echo
```

---

## Selective mode (only part of the traffic via the VPN)

Instead of full-tunnel (`gateway=true`) you can route only the needed addresses:
`gateway = false` in the config + `ipset` + `iptables` + DNS overrides on the router's
dnsmasq (an approach like the `kvas` / `antizapret` projects for Keenetic). This is more
flexible and doesn't cut the speed on non-VPN traffic, but the setup is manual and outside
this bundle.

---

## Diagnostics

| Symptom | Cause / what to do |
|---|---|
| `no /dev/net/tun` at start | Enable the VPN component in KeeneticOS (prerequisites) |
| `ip: ... tuntap` doesn't work | `opkg install ip-full` (busybox `ip` is stripped) |
| No `Auth OK`, `SERVER KEY MISMATCH` | A wrong `key` — check against `qeli show-identity` on the server |
| No `Auth OK`, `auth failed` | Wrong `user`/`pass`, or `mode`/`sni` don't match the server profile |
| LAN without internet, the router with internet | Check `ip_forward`, `MASQUERADE`, the correct `LAN_IF` name in `S99qeli` |
| After a reboot the server sees a "new device" | `QELI_DEVICE_ID_FILE` must be on `/opt` (in `S99qeli` it already is; `/var` is tmpfs) |
| Very slow (mipsel) | The CPU ceiling without AES-NI; set `mode = obfs`/`plain`, not `reality-tls` |
| The tunnel breaks | Auto-reconnect is on; check `/opt/var/log/qeli-client.log` |

---

## Update / removal

```sh
# update the binary: stop, replace, start
/opt/etc/init.d/S99qeli stop
install -m755 qeli-client-<arch> /opt/bin/qeli-client
/opt/etc/init.d/S99qeli start

# remove completely
/opt/etc/init.d/S99qeli stop
rm -f /opt/etc/init.d/S99qeli /opt/bin/qeli-client
rm -rf /opt/etc/qeli /opt/var/log/qeli-client.log
```
