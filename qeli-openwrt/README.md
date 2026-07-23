# qeli for OpenWrt (client)

> **Status: experimental preview (since v0.7.5).** Prebuilt per-arch binaries are
> attached to the GitHub Release; the package source lives here in the repo. Not yet
> tested on real OpenWrt hardware — use at your own risk.

A native **OpenWrt** package for the qeli **client**, so an OpenWrt router can dial
out to a qeli server and route its LAN through the tunnel — managed the OpenWrt way
(procd + UCI + firewall + LuCI), not by hand-editing files.

## Design — what's new and what's reused

The client logic is **not reimplemented**. OpenWrt runs the exact same
`qeli client` binary the Linux/Keenetic clients use, so it **inherits every
core-side fix automatically**:

| Fix (release) | Why it matters on a router |
|---|---|
| Kill-switch on **iptables**+ip6tables, verified with `-C` (0.7.3) | OpenWrt firewall is nft-backed; the binary's `-C`-verified path already tolerates the iptables-nft wrapper. |
| **UDP handshake fragmentation** (0.7.4) | Routers on an **LTE / 4G / CGNAT WAN** drop IP fragments — the big PQ handshake now app-fragments to ≤1200 B and connects. |
| UDP idle/download **liveness** (0.7.4) | No false reconnects on an idle or download-only router tunnel. |
| `gateway` / `dns` INI keys, `bind_static`/H-1, persistent **device-id** + TOFU `known_hosts` | Router runs headless; these are exactly the keys the init script writes. |

So this package = **integration only**: packaging, a procd service, a UCI schema, a
firewall zone, and a LuCI page. The GUI-only fixes (Android IPv4-fallback at
`establish()`, the C# INI parity, low-res layout) are desktop/phone concerns and do
not apply to the headless router client.

## Layout

```
qeli-openwrt/
├── Makefile                         # OpenWrt feed package "qeli" (binary + service + UCI + fw)
├── files/
│   ├── qeli.init                    # /etc/init.d/qeli — procd service (UCI → INI → qeli client)
│   ├── qeli.config                  # /etc/config/qeli — UCI defaults
│   └── qeli.firewall.uci-defaults   # first-install: create the `qeli` firewall zone (fw4-native)
├── luci-app-qeli/                   # LuCI web UI (modern client-side JS)
│   ├── Makefile
│   ├── root/usr/share/luci/menu.d/luci-app-qeli.json
│   ├── root/usr/share/rpcd/acl.d/luci-app-qeli.json
│   └── htdocs/luci-static/resources/view/qeli/config.js
└── build/build_openwrt.py           # cross-compile the client-only binary per arch (zig), for the .ipk
```

## How it runs

1. **Binary**: the client-only target `qeli-client` (`--no-default-features --features
   client-bin`, no `ring` → works on mips), installed to `/usr/bin/qeli-client` and run
   directly as `qeli-client --config <file>` (no subcommand; the default `qeli` bin with
   subcommands needs the server+client features).
2. **Config**: the operator edits **UCI** (`/etc/config/qeli`) or LuCI — never the INI.
   On start, `qeli.init` renders UCI → a 0600 flat-INI in **tmpfs** (`/var/run/qeli/client.conf`,
   so the *rendered* config never lands on flash) and runs `qeli client --config …` under **procd**
   (respawn + logs to `logread`). Note: the UCI source `/etc/config/qeli` still stores the
   password (and `obfs_key`) in **plaintext on flash** — keep it `chmod 600`; tmpfs only avoids
   a second on-flash copy, it doesn't make the secret disappear.
3. **Persistence**: `QELI_DEVICE_ID_FILE` + `QELI_KNOWN_HOSTS` live in `/etc/qeli/`
   (persistent overlay; `/tmp` and `/var` are tmpfs and reset on reboot) so the server
   doesn't see a "new device" every boot and the TOFU pin survives.
4. **Gateway (full-tunnel for the LAN)**: handled by an **OpenWrt firewall zone**
   (`config zone … name 'qeli' … masq '1'` + a `lan → qeli` forwarding), created once by
   `qeli.firewall.uci-defaults`. This is fw4-native and survives `/etc/init.d/firewall reload`
   — unlike raw iptables, which fw4 would flush. The qeli kill-switch (client-side) is a
   separate, independent layer.

## Quick start (on the router)

```sh
opkg install qeli luci-app-qeli      # from the feed, or `opkg install ./qeli_*.ipk`
uci set qeli.main.server='vpn.example.com:443'
uci set qeli.main.user='router1'; uci set qeli.main.pass='…'
uci set qeli.main.key='<server identity hex from: qeli show-identity>'
# H-1 MUST match the server, and the server default is ON. The shipped UCI default is
# '0' because the shipped key is the all-zero TOFU placeholder — the moment you set a
# real key above, flip this too, or the handshake completes and then every record fails
# to decrypt ("Connection error: decryption failed"), because the two sides derive keys
# from different salts. Nothing is negotiated on the wire.
uci set qeli.main.bind_static='1'
uci set qeli.main.mode='fake-tls'; uci set qeli.main.sni='www.cloudflare.com'
uci set qeli.main.gateway='1'       # route the whole LAN through the tunnel
uci set qeli.main.enabled='1'; uci commit qeli
/etc/init.d/qeli enable; /etc/init.d/qeli start
logread -e qeli                      # look for "Auth OK"
```

Or just use **LuCI → Services → qeli VPN**.

## Notes / open items

- Wire mode by CPU: on low-end **mipsel** prefer `fake-tls` / `obfs` / `plain` (ChaCha20);
  `reality-tls` (double AEAD) is sane only on ARM (aarch64) routers.
- `dns`: default `off` (leave the router's dnsmasq/resolver alone). `tunnel` to push
  the server's resolver; or a comma list of resolvers.
- The `.ipk` ships per-arch; `build/build_openwrt.py` cross-builds the binary (zig), the
  OpenWrt `Makefile` also builds it from source via the SDK rust feed.
- TODO before marking stable: test on a real OpenWrt 23.05 device; confirm fw4 zone
  naming; add a status/connect toggle to the LuCI view.
