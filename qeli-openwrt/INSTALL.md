# Installing the qeli client on OpenWrt

> **Experimental — published in v0.7.5 as a preview.** Not yet tested on real OpenWrt
> hardware; the integration paths are by-design and pending a real-device run. Use at
> your own risk.

Two ways to install: **A) prebuilt binary** (fastest — hand-install + opkg deps) or
**B) from source** (proper feed package + `.ipk`). Both end with the same UCI/LuCI
config and a procd service.

---

## 0. Prerequisites (on the router)

```sh
opkg update
opkg install kmod-tun ip-full iptables ip6tables ca-bundle
ls -l /dev/net/tun        # must exist (kmod-tun provides it)
```

- **Disk space:** the client binary is ~2.5–8 MB depending on arch. On 8/16 MB-flash
  devices use **extroot** or install to a USB/`/opt` overlay.
- **Wire mode by CPU:** low-end **mipsel** (MT7621/7628) → `fake-tls` / `obfs` / `plain`
  (ChaCha20). `reality-tls` (double AEAD) is sane only on **aarch64** routers.

---

## A. Prebuilt binary (quick)

1. Pick your arch (`opkg print-architecture` / `uname -m`) and download the matching
   prebuilt `qeli-client-openwrt-<arch>` binary from **GitHub Releases** (aarch64 /
   x86_64 / mipsel / armv7, static musl), then copy it to the router:

   > `build/build_openwrt.py` is a **maintainer-internal** helper (it cross-builds on a
   > private lab host over SSH) — don't run it yourself; use the release binary here, or
   > build from source via the SDK (section B).

   ```sh
   # from your PC:
   scp qeli-openwrt/dist/qeli-client-openwrt-aarch64 root@192.168.1.1:/usr/bin/qeli-client
   # and the integration files:
   scp qeli-openwrt/files/qeli.init   root@192.168.1.1:/etc/init.d/qeli
   scp qeli-openwrt/files/qeli.config root@192.168.1.1:/etc/config/qeli
   scp qeli-openwrt/files/qeli.firewall.uci-defaults root@192.168.1.1:/etc/uci-defaults/99-qeli-firewall
   ```

2. On the router, fix perms and run the firewall-zone defaults once:

   ```sh
   chmod 755 /usr/bin/qeli-client /etc/init.d/qeli /etc/uci-defaults/99-qeli-firewall
   chmod 600 /etc/config/qeli
   sh /etc/uci-defaults/99-qeli-firewall      # creates the `qeli` fw zone (or runs on next boot)
   ```

3. Go to **§3 Configure**.

---

## B. From source (feed package + .ipk)

On a build host with the **OpenWrt SDK** for your target (23.05 recommended):

```sh
# 1. Add the rust + luci feeds (rust is needed to compile the client).
./scripts/feeds update -a && ./scripts/feeds install -a

# 2. Drop the package into the tree (symlink or copy this dir).
cp -r /path/to/qeli-openwrt            package/qeli
cp -r /path/to/qeli-openwrt/luci-app-qeli package/luci-app-qeli

# 3. Select and build.
make menuconfig        # Network → VPN → <*> qeli ;  LuCI → Applications → luci-app-qeli
make package/qeli/compile V=s
make package/luci-app-qeli/compile V=s

# 4. The .ipk lands in bin/packages/<arch>/…  — install on the router:
opkg install ./qeli_<ver>-1_<arch>.ipk ./luci-app-qeli_<ver>-1_all.ipk
```

> **Where's the Rust crate / Cargo.toml?** You don't place it — the package fetches it.
> `package/qeli/Makefile` clones the whole repo (`PKG_SOURCE_PROTO:=git`) and the Cargo
> project lives in the repo's `qeli/` subdir (`qeli/Cargo.toml`); the build cd's into it
> automatically. So `package/qeli/` only needs the `Makefile` + `files/` — the crate comes
> from the git source, not from your local copy. (To build a LOCAL/modified crate instead,
> point `PKG_SOURCE_URL`/`PKG_SOURCE_VERSION` at your fork, or use `PKG_SOURCE_PROTO` with a
> local mirror.)

`opkg install` pulls `kmod-tun`/`ip-full`/`iptables` automatically and runs the
firewall-zone uci-default.

---

## 3. Configure

Get the connection bits from the server's link and the key from the server:

```sh
# on the SERVER:
qeli add-client router1 --link --host vpn.example.com   # prints a qeli:// link
qeli show-identity                                       # prints the public key to pin
```

Set it via **UCI** (or LuCI → Services → qeli VPN):

```sh
uci set qeli.main.server='vpn.example.com:443'
uci set qeli.main.user='router1'
uci set qeli.main.pass='<password>'
uci set qeli.main.key='<64-hex server identity>'   # zero/empty = TOFU
uci set qeli.main.bind_static='1'                  # keep on with a real key (drop to 0 for TOFU)
uci set qeli.main.mode='fake-tls'
uci set qeli.main.sni='www.cloudflare.com'
uci set qeli.main.gateway='1'                      # 1 = route the WHOLE LAN through the tunnel
uci set qeli.main.dns='off'                        # leave the router's resolver alone
uci set qeli.main.enabled='1'
uci commit qeli
```

`gateway = 1` turns the router into a **full-tunnel gateway**: the firewall zone `qeli`
NATs the LAN out the tunnel. `gateway = 0` is split-tunnel (only the tunnel subnet +
pushed routes).

---

## 4. Run

```sh
/etc/init.d/qeli enable        # start on boot
/etc/init.d/qeli start
/etc/init.d/qeli status

logread -e qeli                # watch for "Auth OK"
ip addr show qeli0             # the tun should have an address
ip route                       # full-tunnel: 0.0.0.0/1 + 128.0.0.0/1 via qeli0
```

Verify egress from a LAN client (full-tunnel): its public IP should now be the server's.

```sh
# from a LAN PC:
curl -s https://api.ipify.org ; echo      # == server IP when gateway=1
```

---

## 5. Troubleshooting

| Symptom | Check |
|---|---|
| `/dev/net/tun missing` | `opkg install kmod-tun` |
| Stuck handshake on **LTE/4G WAN** | already mitigated (0.7.4 UDP fragmentation); confirm `proto`/`mode` match the server |
| `Auth` fails | `user`/`pass`/`key` mismatch; check `qeli show-identity` on the server |
| LAN has tunnel but no internet | firewall zone — `uci show firewall | grep qeli` should show `name 'qeli'`, `masq '1'`, and a `lan → qeli` forwarding; `fw4 reload` |
| Reconnect loops | check time sync (`ntpd`); the server log for the disconnect reason |
| Router DNS broken | set `dns='off'` so the client doesn't touch `resolv.conf` (dnsmasq owns it) |

Logs: `logread -e qeli`. Raise detail with `uci set qeli.main.log_level='debug'; /etc/init.d/qeli restart`.

`log_time_format` controls the timestamp the client itself prints (`none` |
`datetime` | `rfc3339` | `time` | `epoch`). It ships as `none` on purpose: procd
sends stderr to syslog, which already stamps each line, so any other value gives
you two timestamps per line in `logread`. Set `rfc3339` only if you forward these
logs off the router and need UTC that lines up with the server's.
