# qeli configuration

> **These docs describe 0.7.11** — the current released version.
> Features marked "**since 0.7.12**" are already in the source tree but **not
> released yet**: they are absent from a 0.7.11 `.deb` install.

## Format: flat-INI (the only one; TOML/JSON have been dropped)

Configs are **text flat-INI**. Structure:

- Global sections `[auth]`, `[web]`, `[logging]`.
- One `[profile:<name>]` per interface; nested struct fields are **dotted keys**:
  `bind.port`, `tun.address`, `obf.tls.reality_proxy.enabled`, `perf.connection.max_clients`.
- Users/groups are `[user:<name>]` / `[group:<name>]` sections (inline in the
  server config, or in a separate `auth.users_file` file).
- Repeatable keys: `route = <cidr> gateway=<ip> metric=<n>`, `pool.exclude`,
  `pool.reservation.<user> = <ip>`.
- The client config is a single `[qeli]` section; the same thing is expanded from
  a `qeli://` link (QR import). INI keys ↔ qeli:// query parameters:
  `server`(host:port), `proto`(tcp|udp), `user`, `pass`, `key`(pinning, hex),
  `mode`(plain|fake-tls|obfs|reality-tls; the **aliases** `udp-quic` =
  `proto=udp`+`mode=fake-tls`+`quic=1` and `udp-obfs` = `proto=udp`+`mode=obfs` are also
  accepted — a convenient "transport+obfuscation" shorthand in one key), `sni`,
  `obfs_key`(=`obfs` in the link),
  `reality_sid`(=`rsid` in the link — REALITY short_id for `reality-tls`),
  `front`(websocket|none — anti-FET fronting for obfs, default websocket),
  `quic`(=`quic=1`/`true` — QUIC masking for UDP; puts the client into udp-quic. The server
  **mirrors the client's choice per-connection** — it sniffs QUIC from the first packet's
  signature, so udp-quic works even when the server profile's `obf.quic.enabled` is off; the
  server flag only controls whether the server stamps `quic=1` into links it generates),
  `awg`(=`awg=1`/`true` — AmneziaWG-style junk before the handshake, OFF by default; works
  on **TCP `obfs` and every UDP mode** — on TCP both ends must agree on `jc`, on UDP `jc` is
  sender-only) with `jc`/`jmin`/`jmax` (junk packet count and its min/max size); pairs with
  the server's `obf.awg.*` (see the obfuscation section),
  `dev`(the TUN interface name on the client, default `vpn0` — a **file/INI key** (also settable in
  the web panel's client-profile form, and in the panel's **TUN device** field), **not** carried in
  the qeli:// link; set your own if `vpn0` is taken by another application or you need to bring up
  several clients on one host. When the panel creates a client tunnel it auto-assigns a free
  `vpnN` not already used by another profile **or live on the host** — so it never clashes with a
  server profile's `vpn0`/`vpn1` — unless you set the name yourself).
  On the **C# desktop clients (Windows/macOS)** `dev` is **not applied**: Windows auto-names the
  Wintun adapter (`Qeli-<hash>`, derived from the server address) and macOS takes a kernel `utunN`.
  A manual interface name works only on the **Rust/Linux/router client and the panel client-manager**.
  *Note:* `quic`/`front` are parsed by all three clients (Android, Windows, Rust CLI) and emitted by
  the server-side link generators (`qeli add-client`, web `/api/share`).

**Keepalive (all clients).** The client always sends a periodic keepalive (an empty encrypted
packet) to the server while the tunnel is up — even when the server's heartbeat is off. Otherwise the
server reaps the session after `perf.connection.idle_timeout_secs` (default 300s) of client→server
silence and FINs it every ~5 minutes on an idle tunnel. Interval = the server's heartbeat interval
(30s fallback).

**OpenVPN parity + reconnect behaviour (C# desktop clients Windows/macOS, `[qeli]` keys):**
- `persist_tun` (`true`/`false`, default `false`) — keep the TUN adapter + routes UP across
  reconnects until the user disconnects (no adapter flicker / route gap; fail-closed during the
  reconnect window). If the assigned IP changes, the adapter is rebuilt.
- `local = <ip>` — bind the carrier socket to a specific local address (egress selection on a
  multi-homed host). **Important when the client and server are on the same LAN.** When `local`
  is set the client does **not** pin the /32 route to the server via the physical gateway (the
  carrier follows the bound interface's routing). If the server is on-link (same subnet as the
  client), pinning it via the gateway creates an asymmetric path and the tunnel dies right after
  the handshake (reconnect loop) — set `local` to this host's LAN IP so the server is reached
  directly. See TROUBLESHOOTING §6.8.
- `lport = <port>` — bind the carrier socket to a fixed local source port (for firewall rules).
- `dev_node = <name>` — name the Wintun adapter manually (Windows; otherwise auto `Qeli-<hash>`).
- `metric = <n>` — TUN interface routing metric (Windows; lower = higher priority). Applied to
  **both IPv4 and IPv6** via the WinAPI `SetIpInterfaceEntry` (no `netsh`; falls back to `netsh` on failure).
- `route_file = <path>` — **Windows/macOS clients only** (the Rust CLI does not read this key
  and silently ignores it): extra split-tunnel routes from a file of CIDRs (one per line,
  `#`/`;` comments), in addition to the profile's routes. On the Rust CLI use `include`/
  `exclude` directly in the config for the same effect.
- `keepalive = <secs>` (default `60`) — TCP keepalive probe interval (seconds) on the carrier
  socket (`SO_KEEPALIVE` / `TCP_KEEPIDLE`). Emitted only when non-default.
- `tcp_nodelay = <true|false>` (default `true`) — disable Nagle's algorithm on the carrier socket
  (send small packets immediately, lower latency). Set `false` to re-enable Nagle. Emitted only
  when non-default.

Example client profile using the new keys (Windows/macOS desktop, split-tunnel):

```ini
[qeli]
server = 203.0.113.10:8443
proto  = tcp
mode   = fake-tls
user   = alice
pass   = secret
# split-tunnel (else full-tunnel by default)
gateway = false
# keep TUN + routes up across reconnects
persist_tun = true
# fixed local source port
lport = 51820
# egress via a specific local address
local = 192.168.1.50
# TUN interface priority (Windows; lower = higher)
metric = 10
# Wintun adapter name (Windows)
dev_node = QeliWork
# extra CIDR routes from a file
route_file = C:\qeli\routes.txt
# these subnets bypass the tunnel (go direct)
exclude = 192.168.50.0/24, 10.20.0.0/16
```

`route_file` format — one CIDR per line (blank lines and `#`/`;` comments are ignored):

```
10.20.0.0/16      # office LAN
192.0.2.0/24
```

Keepalive, graceful FIN on disconnect, the amber connecting indicator, ISO-8601 log timestamps and
the per-profile Wintun adapter name work **automatically** — no configuration needed.

> **⚠️ Comments — on a separate line only** (a leading `#`). An inline comment
> after a value (`port = 443  # https`) is NOT stripped and will end up in the value.

Fully documented examples — [server.conf](../../qeli/config/server.conf),
[client.conf](../../qeli/config/client.conf), [users.conf](../../qeli/config/users.conf),
[server-maxobf.conf](../../qeli/config/server-maxobf.conf). Default paths:
`/etc/qeli/server.conf`, `/etc/qeli/client.conf`, `/etc/qeli/users.conf`.
Structural saving via the Web UI / control CLI (`PUT /api/config`) rewrites the
config from the serde structs — comments are lost in the process. To preserve
them, use the **raw editor**: `GET /api/config/raw` returns the file verbatim, and
`PUT /api/config/raw` validates via `parse_server_config` and writes the text **as
is** (comments intact); in the Web UI this is the "Raw INI" tab. The exact key map
is `qeli/src/config/server_ini.rs` (the serializer) and the serde structs in
`config/`.



## Profile defaults (the INI applies them per-field — the footgun is gone)

In the INI loader each profile is built from `baseline_profile()` (a skeleton with
applied per-field serde defaults), on top of which the specified keys are layered.
Therefore **omitting whole subsections is safe** — missing keys get their real
defaults (`keepalive_secs=60`, `max_clients=128`, etc.), not zeros.

Historical note (this was relevant for the old TOML/JSON, where omitting an *entire
nested object* yielded `Default::default()` = zeros): omitting `performance` led to —

| Omitted | Effect |
|---|---|
| `performance.tcp.keepalive_secs` → 0 | `setsockopt(TCP_KEEPIDLE, 0)` → **EINVAL**, every TCP connection breaks at setup |
| `performance.connection.handshake_timeout_secs` → 0 | handshake timeout = 0 → instant timeout, no client can connect |
| `performance.connection.max_clients` → 0 | "max clients (0) reached" → everyone refused |

The values depend on the deployment (channel, number of clients, latency), so
**they are not hardcoded** — set them in the config. A minimal working profile:

```ini
[auth]
users_file = /etc/qeli/users.conf

[logging]
level = info
file = /var/log/qeli/server.log

[profile:tcp]
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.9.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.exclude = 10.9.0.1
routing.nat.enabled = true
routing.forward_private = true
dns.enabled = false
obf.mode = fake-tls
obf.padding.enabled = true
obf.padding.min_bytes = 32
obf.padding.max_bytes = 256
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
obf.heartbeat.jitter_ms = 20
perf.tcp.nodelay = true
perf.tcp.keepalive_secs = 60
perf.tun.read_buffer_size = 65535
perf.connection.max_clients = 128
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 300
```

(A full, exhaustively commented example — [server.conf](../../qeli/config/server.conf).)

## Server multi-core (`tun.queues`)

By default the data plane uses **all cores**: per-connection encryption/decryption
is already spread across cores, while **`tun.queues`** (per-profile) sets the number
of TUN queues (Linux `IFF_MULTI_QUEUE`) — how many parallel reader/writer tasks pump
the interface, so that the TUN pump itself (and per-queue encrypt) runs on several
cores rather than through a single funnel.

```ini
[profile:tcp]
# 0 = auto (= number of cores, the default); N = that many queues; 1 = legacy single-threaded pump
tun.queues = 0
```

- `0`/auto = `nproc` (recommended). Capped at 256 (the Linux kernel TUN-queue
  ceiling, `MAX_TAP_QUEUES`) — auto=nproc is not clamped on real servers.
- `1` = the old behavior (a single pump) — for rollback.
- Non-breaking, **server only**: nothing changes on the wire, clients need no
  rebuild (TUN is a local OS-kernel interface). Both **TCP** (N TUN queues) **and
  UDP** (N workers on `SO_REUSEPORT` sockets — the kernel distributes datagrams by
  flow, a client is bound to a single worker) are parallelized. TUN readers are
  blocking (0% CPU when idle).
- The effect grows with the number of cores and clients: a single tunnel is bound
  by its decrypt task (~1 core) regardless of queues — the gain comes from MANY
  connections / a large server. On a 2-core lab it measured **+18% aggregate**
  (2 tunnels: 607→718 Mbps at `queues=1`→`2`; a single tunnel unchanged, 458≈455),
  and that is a lower bound — the host hit saturation (the `iperf3` sink on the same
  server); on larger servers it's more. A detailed A/B with a table —
  [BENCHMARK.md](BENCHMARK.md).

## Tunnel MTU (`tun.mtu`) and the push to the client

The server sets the MTU of its TUN via `tun.mtu` (per-profile, default 1400) **and
pushes this value to the client** at auth. Priority on the client:

1. **an explicit client MTU** (`mtu` in `[qeli]` INI / `qeli://` link / `tun.mtu` in JSON, `> 0`) — wins;
2. otherwise (auto, `mtu = 0`) — the **discovered / pushed** MTU, see below;
3. otherwise (an old server pushing nothing and no probe result) — a fallback of **1400**.

**`mtu = 0` on the client = "auto" (this is the default).** What auto does depends on
the transport:
- **UDP transports** (obfs-UDP / fake-tls-UDP / QUIC): the client **actively probes the
  real path MTU** before bringing the tunnel up. It sends DF-marked probe datagrams from
  the server-pushed ceiling downward (the server echoes them) and sets the tunnel MTU to
  the largest size that traverses the path **without IP-fragmenting** — so a narrow
  LTE/CGNAT/PPPoE path is measured, not guessed. If every probe is dropped (a network that
  blocks them), it falls back to the pushed MTU (unchanged behaviour). Turn it off with
  **`mtu_probe = false`** in `[qeli]` (a kill switch; then auto = "just adopt the pushed
  MTU"). Probing is **Linux/Windows/macOS/Android** (best-effort on Android).

  The probe has three limits worth knowing before you treat MTU as a solved problem:
  - **It only measures client → server.** The probe datagram is full size but the
    acknowledgement is tiny. An asymmetric path (wide up, narrow down) passes the probe,
    and a download-direction black hole goes undetected.
  - **It never probes below 1280** (the bottom rung of the ladder). With qeli's record
    overhead plus IP/UDP headers, that rung is about **1356 bytes of real path MTU** — a
    path narrower than that fails **every** rung and the probe returns "no result".
  - **"No result" means the pushed MTU is adopted**, which on such a path is certainly
    too large. Connectivity does not break (DF is cleared and packets fragment), but at
    that point you are back to guessing rather than measuring.

  Practically: auto-probing handles **most** LTE/CGNAT/PPPoE cases, not all. If downloads
  stall while small packets flow, set `mtu` by hand (1200–1280) and retest; §12 of
  GETTING-STARTED and TROUBLESHOOTING §6 cover the diagnosis.
- **TCP transports** (reality-tls / fake-tls / obfs / plain): auto = adopt the pushed MTU;
  the **kernel** discovers the path MTU there (`tcp_mtu_probing` + MSS clamping), so no
  app-level probe is needed.

So the MTU is usually set **once in the server profile** (the ceiling), UDP clients refine
it per-path, and nothing in the client configs/links needs changing (generated `qeli://`
links come with `mtu=0`/without it = auto). An explicit `mtu` on the client is needed only
to forcibly override — it also disables probing.

```ini
# server: centrally sets the MTU for all clients of this profile
[profile:reality-tls]
tun.mtu = 1380
```
```ini
# client: override manually (rarely needed); 0/absence = auto/push
[qeli]
mtu = 1280
```

> Note on reality-tls/fake-tls (TCP transport): inner-MTU has little effect on
> throughput (the bottleneck is the outer TCP segment and path), but a correct MTU
> matters against fragmentation and for UDP modes. See the MTU discussion in
> [BENCHMARK.md](BENCHMARK.md).

## Push to clients — what the server hands over on connect

After a successful authentication the server sends the client a JSON (`OK:{…}`) that carries
the client's whole runtime configuration. **The `qeli://` link does NOT carry any of it** — the
link is only about *how to connect*; everything else arrives via the push, which is why it can
be changed on the server **without re-issuing links** (see "What is NOT pushed" below).

### The complete push payload

| field | source in the server config | what the client does with it |
|---|---|---|
| `client_ip` | allocated from `pool.cidr` (or `pool.reservation.<user>` / the user's `static_ip`) | the TUN address |
| `server_ip` | the profile's `tun.address` | the tunnel gateway; **the default next hop for pushed routes** |
| `prefix` | the prefix length of `pool.cidr` | the on-link netmask (otherwise the client would assume `/24`) |
| `mtu` | the profile's `tun.mtu` | a client on `mtu = 0` (default, auto) **adopts** it; a client with its own `mtu > 0` keeps it |
| `dns` | `dns.push_servers[0]` → else `dns.listen` (only if `dns.enabled = true`) → else empty | sets the resolver — **only if the client is on `dns = tunnel`** (default); ignored on `dns = off` |
| `dns_port` | `dns.port` | the resolver port |
| `routes` | the user's **personal** routes, otherwise the profile's `route =` | installs the routes (since 0.7.12 — **always**) |
| `obfuscation` | `obf.padding.*`, `obf.heartbeat.*`, `obf.traffic_normalization.*`, `obf.traffic_shaping.*` | applies the obfuscation parameters live |
| `session_token` | generated per session | the bonding join token |
| `max_streams` | `obf.multipath.max_streams` (when `obf.multipath.enabled`) | how many parallel connections to open |
| `multipath_adaptive` | `obf.multipath.adaptive` | auto-ramp the stream count |

An empty `dns` = the client keeps its own resolvers. The default `dns.listen` (`10.0.0.1`) is
pushed **only** when the in-tunnel proxy actually runs — otherwise it resolves nowhere and would
black-hole the client's DNS.

### Routes (`route`) in detail

**Where to put it.** Inside `[profile:<name>]`. The key is **repeatable** (several lines = several routes):

```ini
[profile:tcp]
tun.address = 10.0.0.1
route = 172.16.20.0/24
route = 10.20.0.0/16 gateway=10.0.0.1 metric=100
```

**Format:** `route = <cidr> [gateway=<next-hop-ip>] [metric=<n>]`

| part | required | rule |
|---|---|---|
| `<cidr>` | **yes** | **first and bare** (or explicitly `cidr=<…>`). E.g. `172.16.20.0/24` |
| `gateway=` | no | the **next-hop IP, NOT a subnet**. Defaults to the profile's `tun.address` |
| `metric=` | no | defaults to `100` |

> ⚠️ **Keys that do NOT exist in the INI:** `advertised_routes`, `push_routes`,
> `routing.advertised_routes`, `routing.routes`. `push_routes` is a serde **alias** — it only
> works for JSON/TOML, while the real INI is parsed by a separate hand-written parser. An
> unknown key is **silently ignored**, so the route simply never exists.

**Personal routes OVERRIDE the profile's — they do not merge.** The server's logic is
`find_user(username).filter(|u| !u.routes.is_empty())` →

- the user has **≥1** own route → the client gets **only those**; the profile's `route =` lines
  are ignored **entirely**;
- the user has **0** own routes (or an empty list) → the profile's routes are used.

Personal routes live in `[user:<name>]` (`users.conf`) or in the user's card in the panel.

### When the push works — and when it doesn't

| situation | result |
|---|---|
| a correct `route = <cidr>`, client **≥ 0.7.12** | ✅ installed; **no client-side flag needed** |
| a correct `route`, client **before 0.7.12** with `route_local = false` (default) | ❌ **silently ignored, not a single log line** — the historical trap |
| a correct `route`, client before 0.7.12 with `route_local = true` | ✅ installed (but it also pulls in **all** of RFC1918) |
| CIDR empty / without a prefix / garbage | ❌ **rejected at config load** with a warning; never pushed |
| the subnet typed into `gateway=` (CIDR left empty) | ❌ same. The panel writes `route = " gateway=… "` when the CIDR field is empty — that's this case |
| the user has personal routes | the profile's routes **will not be sent** (override, see above) |
| Android / Windows / macOS client | ✅ same as the Rust CLI (since 0.7.12) |
| the route was added via the panel | ✅ the panel writes a correct `route = <cidr> …` and **rejects** malformed input with an error |

### How to check

- **Server:** `qeli show-routes`; a malformed line logs `WARN config: ignoring route …`.
- **Client (Rust/CLI):** the log shows `Pushed route applied: <cidr> via <gw> dev <if> metric <n>`;
  in the system — `ip route show | grep <cidr>`.
- **Client (Windows / macOS / Android):** the log shows `pushed route: <cidr>`.
- No such line at all → the server sent an empty array (a config key/format problem, or an
  override by personal routes). The line is there but the route isn't in the table → the problem
  is already in the OS.

### What is NOT pushed

These are **client-side file-only** keys — they are in neither the push nor the `qeli://` link, and
are set in the client's own file (or in the panel's **Client manager** tab, which edits those files):
`dev`, `gateway` (full-tunnel), `route_local`, `kill_switch`, `include`/`exclude`,
`dns` (the client's resolver-management **mode**), `persist_tun`, `local`/`lport`, `metric`,
`gateway_nat`/`lan_subnet`, `post_up`/`post_down`, `autostart`.

The `qeli://` link carries exactly: `host:port`, `user`, `pass`, `proto`, `mode`, `key`, `sni`,
`reality_sid`, `obfs_key`, `front`, `quic`, `mtu=0`, `awg`/`jc`/`jmin`/`jmax` and a label — i.e.
**only what the client cannot learn any other way**. Routes and DNS are not in it by design. The
links from the panel (`POST /api/share`) and from the CLI
(`qeli add-client <user> --link --host <host>`) are built from the same struct and carry the same set.

## Server OS tuning (sysctl + iptables) — MANDATORY for production

These are **server operating-system settings**, not the qeli config. Without them,
TCP modes (reality-tls/fake-tls/obfs-tcp) on real (especially mobile) clients
**break the connection under load and choke the speed**. Apply on every VPN server.

### 1. MSS clamping (CRITICAL — otherwise downloads break)

Traffic from the internet arrives at the client via NAT with an MSS for a 1500-byte
path, but it doesn't fit inside the tunnel (`tun.mtu`, e.g. 1280); if the
"fragmentation needed" ICMP is lost, you get a **PMTU black hole**: large packets
are silently dropped, small ones pass → the download hangs, the client drops on
timeout. The cure is clamping the forwarded TCP's MSS to the tunnel MTU
(`tun.mtu − 40`).

> **If the profile has `routing.nat.enabled` (or `routing.forward_private`) — you do
> NOT need these rules: qeli installs them itself.** On profile start it enables
> `ip_forward`, adds MASQUERADE, two `FORWARD … ACCEPT` rules and **two `TCPMSS` clamps
> with that same `tun.mtu − 40`** (floored at 536), tags them `qeli-nat:<profile>` and
> removes them on a clean stop. The manual rules below would duplicate them, would not
> carry the tag — so qeli cannot clean them up — and, once saved into `rules.v4`, go
> stale the first time you change `tun.mtu`.
>
> The rules below are needed **only** when NAT is off (`nat.enabled = false` and
> `forward_private = false`) and you wire up forwarding yourself.

```bash
# MSS = tun.mtu(1280) − 40 = 1240; vpn+ = all profile tun interfaces (vpn0, vpn1, …)
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o vpn+ -j TCPMSS --set-mss 1240
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i vpn+ -j TCPMSS --set-mss 1240
iptables-save > /etc/iptables/rules.v4      # save (netfilter-persistent)
```
> If you change `tun.mtu` — recompute the MSS (`tun.mtu − 40`).

**The outer handshake (reality-tls/fake-tls on LTE) — a separate clamp.** The rule above
is for traffic INSIDE the tunnel (`vpn+`). But reality-tls with `real_tls=true` sends a
**real Chrome ClientHello carrying the post-quantum share (X25519MLKEM768) ~1700 B** over
the **outer** TCP to `:443` — and on that connection the MSS is **not clamped** (the server
advertises ~1460 from the 1500 WAN MTU). On LTE/CGNAT (path MTU ~1400) a 1460-byte segment
doesn't fit, mobile networks drop the ICMP "frag needed" → the same **PMTU black hole**, but
now on the **handshake** itself: works on wired, hangs on LTE. The cure is clamping the MSS
the server advertises on its **outer TCP ports** (reality / fake-tls / obfs):

```bash
# OUTPUT: the server's SYN-ACK on its TCP ports carries the advertised MSS. set-mss 1340 →
# an LTE client sends ≤1340-byte segments (≈1380-byte IP) → fits; harmless on wired. If some
# carriers' path MTU is even lower (~1358), drop to 1300.
for p in 443 8443 8444 8445; do
  iptables -t mangle -A OUTPUT -p tcp --sport $p --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340
done
iptables-save > /etc/iptables/rules.v4
```
> The ports are the `bind.port` of your **TCP** profiles. `tcp_mtu_probing=1` (below) does
> NOT help here: it recovers the *server's* sends, but what hangs is the *client's* send (the
> big ClientHello), whose segment size is governed by the MSS the **server** advertises.

### 2. sysctl: BBR + buffers + MTU probing

cubic (the default) on mobile loss halves the window → speed collapse. **BBR**
holds the bandwidth via a channel model (Google introduced it precisely for slow
TCP over lossy links) — the main win for reality-tls on a phone. Plus large buffers
for the high mobile RTT and MTU probing against residual PMTU black holes.

```ini
# /etc/sysctl.d/99-qeli-perf.conf  (apply: sysctl --system; module: modprobe tcp_bbr)
net.core.default_qdisc=fq
# the main fix for mobile TCP
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_mtu_probing=1
```
```bash
modprobe tcp_bbr && echo tcp_bbr > /etc/modules-load.d/qeli-bbr.conf   # load the module at boot
sysctl --system                                                       # apply
sysctl -n net.ipv4.tcp_congestion_control                             # check: should be bbr
```

### 3. padding for reality-tls — better turned off

`obf.padding` (40–400 B per packet) is useless for reality-tls (the traffic is
already inside real TLS — padding isn't visible from outside) but eats bandwidth.
In a reality-tls profile: `obf.padding.enabled = false`.

> Verified in production: BBR/buffers/mtu_probing + `vpn+` MSS-clamp 1240 +
> `tun.mtu 1280` + padding off (2026-06-08), and the **outer TCP-port MSS** (443/8443/8444/8445)
> **1340** — the reality/fake-tls LTE-handshake fix (2026-06-28). Script: `scripts/prod_tcp_tune.py`.
> Rollback: remove `/etc/sysctl.d/99-qeli-perf.conf` + `/etc/modules-load.d/qeli-bbr.conf`
> (`sysctl --system`), remove the mangle rules, restore `tun.mtu`/padding.

## Stream bonding — multipath (`obf.multipath.*`)

A single TCP connection (reality-tls/fake-tls/obfs) on a mobile network hits the
"TCP over TCP" ceiling (~6 Mbps in production, while UDP/WireGuard does tens).
Multipath opens **several parallel connections to the same :443 port**, and the
server aggregates them into **ONE tunnel** (one tun-IP); outgoing IP packets are
spread round-robin. DPI-clean — a browser also opens 6+ parallel TLS to an HTTPS
host; a single long-lived TCP with a continuous flow is actually more suspicious.

**Settings — per-profile** (like `tun.mtu`/`padding`), the server pushes them to
the client:

```ini
[profile:reality-tls]
# enable bonding on this profile
obf.multipath.enabled = true
# HARD ceiling of streams per session (the server enforces it)
obf.multipath.max_streams = 4
# false = open EXACTLY max_streams; true = auto-tune
obf.multipath.adaptive = false
```

- **`enabled`** (default `false`) — turn bonding on/off for the profile.
- **`max_streams`** (default `4`) — a **hard ceiling** of parallel connections per
  session; the server rejects extras. `max_clients × max_streams` = the server's
  connection budget.
- **`adaptive`** (default `false`):
  - `false` — the client opens **exactly `max_streams`** connections (fixed);
  - `true` — the client **auto-tunes** the count from 1 to `max_streams` by the
    measured speed (starts at 1, adds a stream under load while throughput grows,
    stops at a plateau). In this mode `max_streams` works only as a **ceiling**, not
    a target.

The client may open **fewer** than the ceiling, but **there is no client `[qeli]`
INI key** for this — the stream count is server-controlled: the client uses the
server-pushed `max_streams` (and in `adaptive` mode auto-tunes the count itself).

> **TCP modes only** (reality-tls/fake-tls/obfs/plain) — they have head-of-line
> blocking. UDP profiles (udp-*) don't need bonding (no "TCP over TCP") — leave
> `enabled = false`.
>
> **The profile name is irrelevant** — the behavior is determined by the
> `bind.transport = tcp`, `obf.mode`, and `obf.multipath.enabled` fields, not the
> section name. Any TCP profile with `multipath` enabled bonds (whether
> `[profile:reality-tls]` or `[profile:my-tcp]`), as long as the client is
> configured for its `mode`/port/key.
>
> **Compatible/rollback-safe:** an old client ignores the push and works in 1
> stream; an old server sends no `max_streams` → the client uses 1 stream. Each
> connection does its own key exchange → independent crypto per stream (no
> nonce-reuse).

**Measured (lab, `tc netem`, download, 8 parallel flows).** On a clean link bonding
is at parity (the TUN pump is the ceiling); on a lossy/latent link it scales:

| link | 1 stream | 4 streams | gain |
|---|---:|---:|---:|
| clean | ~725–846 | ~805–815 | parity |
| RTT 40 ms, 0.05% loss | ~225–420 | ~692–704 | ~1.6–3× |
| RTT 80 ms, 0.1% loss | ~50–65 | ~260–305 | **~5×** |

Note the distribution is **per-flow** — each inner flow is pinned to one connection
by a flow hash (`flow_hash % streams`) to avoid reordering (which only hurts the
inner TCP). So only traffic with **several concurrent connections** (like a browser's
6+ TLS) speeds up; a single lone flow won't.

## Flow shaping — cover traffic (`obf.traffic_shaping.*`)

Closes DPI tells **6.1** (flow shape = "download", not "browsing") and **6.2**
(periodic heartbeat beacon). While the tunnel is **idle**, the server emits cover
packets at gaps sampled **exponentially** (a Poisson process) instead of a fixed
heartbeat — no dead air, no metronome. A cover packet is an encrypted record with
an **empty payload**; the peer drops it (like a heartbeat) → **not wire-breaking**,
old clients stay compatible. Real packets are **never delayed** (Phase 1 = zero
added latency); only idle is filled, within a byte budget. When shaping is on it
**replaces** the heartbeat (which is disabled, so there is no double beacon).

```ini
# on (default false)
obf.traffic_shaping.enabled = true
# mean idle gap between cover packets (exponential)
obf.traffic_shaping.idle_gap_mean_ms = 700
# gap floor
obf.traffic_shaping.idle_gap_min_ms = 40
# gap cap (don't go dead on a long tail)
obf.traffic_shaping.idle_gap_max_ms = 6000
# cover-traffic ceiling, B/s (0 = none)
obf.traffic_shaping.budget_bytes_per_sec = 16384
# cover packet size range
obf.traffic_shaping.min_size = 64
obf.traffic_shaping.max_size = 1024
# STEALTH (Phase 2): trade throughput for DPI passability.
obf.traffic_shaping.stealth = false
# data-plane rate cap under stealth (Mbps)
obf.traffic_shaping.stealth_rate_mbps = 2
```

- **Cost (without stealth)** — only cover-traffic bandwidth while idle (capped by
  `budget_bytes_per_sec`); no effect on real throughput.
- **When to enable** — on profiles facing heavy DPI / an ML classifier; overkill for
  home use. Parameters are pushed to the client (like padding/heartbeat).

### `stealth` (Phase 2, opt-in — speed for passability)

Closes the under-load **"download" tell** (baseline: 100% full-MTU packets at line
rate). With `stealth = true` (requires `enabled = true`):
1. **Rate-cap** the data plane to `stealth_rate_mbps` (both directions) → the flow
   stops looking like a line-rate bulk download.
2. **Cover under load** — the rate-cap gaps are filled with jittered small cover
   packets → breaks the "100% full-MTU" size signature and makes the timing bursty
   (not a metronome).

**What it buys** (measured with `scripts/shaping_profile.py`, server→client under bulk):

| Feature | Without stealth | With stealth |
|---|---|---|
| Throughput | ~600 Mbps (line rate) | ≈ `stealth_rate_mbps` |
| Packet sizes | **100% full-MTU** | **~81% full-MTU + ~19% small/medium** (a mix) |
| Timing (inter-packet CV) | low/flat (constant stream) | **bursty (CV≈1.0)** — bursts + gaps, not a metronome |

Net: the flow no longer reads as a high-rate bulk download. This is **not**
"indistinguishable from browsing" (that would need seconds-scale buffering, making
the tunnel unusable) — it is "no longer a file download."

#### Why it cuts speed so much — this is the mechanism, not a bug

The strongest, most robust tunnel signal for DPI/ML is **the sustained high rate
itself**: hundreds of Mbps of continuous full-MTU traffic at a ~constant pace looks
like no "normal" traffic (web, chat). So stealth **hard-caps the data plane to
`stealth_rate_mbps`** — that is not a side effect, it is the point: **you cannot both
push 600 Mbps and not look like a 600 Mbps download.** Browsing / normal activity is
a few Mbps in bursts, not a constant line-rate. So throughput under stealth ≈
`stealth_rate_mbps` (measured: tcp-plain/faketls/obfs/reality-tls 442–602 Mbps →
~10/10 at cap=10).

`stealth_rate_mbps` is the **direct speed↔stealth knob**: higher = faster but closer
to the bulk signature; lower = slower but stealthier. On top of the cap, the gaps are
filled with small cover (extra bandwidth, but the *real data* is what the rate-cap
throttles). It does NOT change the *data* packets' own size (still full-MTU, just
rarer + interleaved with cover) — that needs fragmentation+reassembly (wire-breaking,
not implemented). Per-mode speeds: `scripts/bench_stealth.py`.

**When to enable:** only under aggressive DPI/ML that blocks high-rate tunnels. For
normal use it is overkill (needlessly slow). **Not wire-breaking** (cover = the same
empty records peers already drop). The server shapes the downlink for ALL clients;
every client (Rust, Windows/macOS, Android) shapes its own uplink (TCP only).

> **TCP wire modes only** (plain/fake-tls/obfs/reality-tls). On UDP, stealth was
> measured to crater throughput (lock contention under load → ~0), so it is
> **ignored on UDP profiles** — they keep Phase-1 idle cover. The main "download"
> case (reality-tls/fake-tls/obfs) is TCP anyway.

## Wire obfuscation modes (`obfuscation.mode`)

`mode` selects how a connection looks "on the wire"; it is set **identically on the
server (in the profile) and on the client**. The modes
`plain`/`obfs`/`reality`/`reality-tls` are **TCP only** (stream-based); on UDP the
wire mode is `fake-tls` (+ optional QUIC masking), the rest are rejected on UDP at
startup.

| `mode` | Behavior | Against what | Notes |
|---|---|---|---|
| `"plain"` | No obfuscation: a raw X25519 key exchange and bare `[len][nonce][ct]` records (no TLS mimicry). An ordinary encrypted VPN tunnel | Nothing — on the wire a high-entropy flow with no recognizable protocol (which is itself a signal for entropy-based DPI) | The cheapest, speed ≈ fake-tls. **TCP only.** For trusted networks where DPI doesn't matter |
| `"fake-tls"` (default) | A pseudo-TLS-1.3 handshake (ClientHello with GREASE and a random extension order → JA3 changes), then the data plane in TLS-Application-Data records | Passive signature-based DPI | Cheaper on CPU; "looks like TLS" |
| `"obfs"` | The entire flow is XOR'd with a ChaCha20 stream key; the start of the connection is by default masked as a WebSocket Upgrade handshake (see `obfs_fronting`), then pseudo-random bytes | DPI that signatures *known* protocols (incl. fake-TLS/JA3) + entropy-based "fully encrypted" detection (GFW/TSPU) | Requires `obfs_key` (PSK) shared by server and client. ~11% overhead (double encryption) |
| `"reality-tls"` | The client sends a **real** browser TLS 1.3 ClientHello (Chrome JA4) with a REALITY token in `session_id`; the server terminates real TLS (rustls) and carries the tunnel inside. "Foreign" connections are proxied to a real site | Active probing + JA3/JA4 + entropy-based DPI (real TLS on the wire) | The client needs `key`(pin) + `reality_sid`; the server needs `reality_proxy.real_tls=true` + `short_ids`. ↓ Lower speed (nested TLS). **TCP only.** See the REALITY section below |

> **How to choose a mode (positioning).** The `fake-tls` default targets
> **passive** DPI (D1/D2) and is cheap on CPU. If your threat model includes
> **active probing** (D3 — the censor reaches the server itself: GFW, a number of
> ISPs) — enable **`reality-tls`** explicitly (it is not the default, since it costs
> more CPU and is slower due to the nested TLS, but it is the only mode
> indistinguishable from real HTTPS and serving the prober a real site). `obfs` —
> against entropy-based "fully-encrypted" detection (without mimicking a specific
> protocol). `plain` — trusted networks only (the most visible on the wire). A
> detailed detectability model — [DPI-AUDIT.md](DPI-AUDIT.md).

### `obfs_fronting` (anti-FET, only for `mode = obfs`)

The key `obf.obfs_fronting` (server) / `front` in the qeli:// link and the `[qeli]`
section (client). **Must match on server and client.**

| Value | Behavior |
|---|---|
| `"websocket"` (default) | Before the nonce exchange the client sends `GET … Upgrade: websocket`, the server sends `101 Switching Protocols` (with a correct `Sec-WebSocket-Accept`). The first packet is printable HTTP text → it passes the GFW/TSPU "fully encrypted traffic" entropy heuristics. The request is randomized (path/Host/key) — no static signature. **After the upgrade the stream is wrapped in real WebSocket binary frames** (opcode `0x2`, per-frame client mask), so the whole connection is well-formed WebSocket on the wire, not just the opening handshake |
| `"none"` | Legacy: an immediate random nonce prologue. "Looks like nothing" — blocked by entropy-based DPI. For rollback only |

An `obfs` example (fragments):

```ini
# server.conf — in the [profile:obfs] profile:
obf.mode = obfs
obf.obfs_key = SHARED-SECRET
obf.obfs_fronting = websocket
```
```ini
# client.conf — the [qeli] section:
mode = obfs
obfs_key = SHARED-SECRET
front = websocket
```

`obfs` limitation: the IETF-ChaCha20 keystream = 256 GiB per direction per session.
On exceeding it the connection ends with an error and reconnects with a fresh nonce
(fail-safe, no keystream reuse). For very high-volume long-lived links this means a
reconnect roughly every 256 GiB.

UDP obfuscation is a separate mechanism (`obfuscation.quic`, masking as QUIC);
`mode: "obfs"` applies only to TCP profiles.

### REALITY (`mode = reality-tls`, keys `obf.tls.reality_proxy.*`)

"REALITY" in qeli has two layers, both in the server profile:

| key (server) | value |
|---|---|
| `obf.tls.reality_proxy.enabled` | enable REALITY handling of incoming connections |
| `obf.tls.reality_proxy.target` / `target_port` | the real site to which "non-ours"/probing connections are transparently proxied (e.g. `www.microsoft.com:443`) |
| `obf.tls.reality_proxy.short_ids` | allow-list of 8-byte (16 hex) "our" IDs — the cryptographic discriminator (a token in `session_id`). **Required when `reality_proxy.enabled`**: with an empty list the server refuses to start. (An empty list used to fall back to a legacy "no ALPN" heuristic; it is trivially defeated by an active prober, so it is now rejected at startup.) |
| `obf.tls.reality_proxy.real_tls` | `true` → the server terminates **real** TLS 1.3, the tunnel inside (client mode `reality-tls`); `false` → fake-TLS on the wire, REALITY only the bridge/token |
| `obf.tls.reality_proxy.handrolled` | `true` → the hand-rolled TLS terminator: **borrows the target's real cert chain** (cert-borrowing — at profile start a probe captures the real cert, e.g. microsoft; **auto-refresh every 12h**, target certs rotate) + mirrors its JA3S/ServerHello. `false` → rustls: a **self-signed** cert + its own JA3S (weaker camouflage). **The default is `true`** — you get Xray-REALITY parity out of the box, nothing to enable; set `false` only to fall back to rustls. Requires `real_tls = true` |

- **proxy-bridge (`real_tls=false`):** the client sends `mode=fake-tls`; fake-TLS on
  the wire, but "foreign" handshakes go to `target` (an active prober sees the real
  site). Speed ≈ `plain`.
- **`reality-tls` (`real_tls=true`):** the client sends `mode=reality-tls` + a
  **mandatory** `key` (the pin of the profile's static key, from `show-identity`) +
  `reality_sid` (one of `short_ids`). On the wire — real Chrome TLS 1.3, the tunnel
  inside; it closes tells 1.1–1.6 ([DPI-AUDIT.md](DPI-AUDIT.md)). ↓ Lower speed
  (nested TLS — see [BENCHMARK.md](BENCHMARK.md)). Distributed via a QR link (`rsid=`
  carries the short_id). Config templates — [release/reality-tls/](../../release/reality-tls/).
- **Client and server clocks must agree within ±120 seconds** (when `short_ids` is
  set): the REALITY token in `session_id` carries a timestamp (anti-replay,
  `REALITY_WINDOW_SECS = 120`), and a larger skew makes the server **silently**
  bridge the client to `target` — like any "foreign" connection. Symptom: the
  connection never establishes with no error in the client log, while `curl` against
  the server shows the real site. Fix: enable automatic time sync (NTP) — most often
  the clock drifts on Android without auto-time and in VMs after suspend.

## Server identity (per-profile)

**Each profile has its own** long-term static key (X25519) — it is bound to the
profile's interface. The private keys live in `/etc/qeli/identity/<profile>.key`
(permissions `0600`, directory `0700`); the path can be overridden with the profile
field `identity_key`. The public key is derived from the private one, and the
client pins it.

On the profile's first start the key is generated automatically (if the file is
absent) and saved. Logged:
`Profile '<name>': server identity public key (pin on client): <hex>`.

CLI for key management (without starting the server, root required):

```bash
# show the public keys of all profiles (creates missing ones)
qeli show-identity --config /etc/qeli/server.conf
# PROFILE   BIND                 SERVER PUBLIC KEY (pin on client)
# tcp       tcp://0.0.0.0:443    33f399e6…d532450
# udp       udp://0.0.0.0:4443   35d12dd2…7d764e04
# obfs      tcp://0.0.0.0:8443   26c45f81…9dbca952

# rotate one profile's key (then restart qeli)
qeli rotate-identity udp --config /etc/qeli/server.conf
```

### How to deliver the key to the client (pinning)
The profile's public key (hex from `show-identity`) is entered into the **client**
config:

```ini
# client.conf — a client connecting to the tcp profile; the [qeli] section:
user = alice
pass = secret
key = 33f399e6…d532450
```

Delivery is **out-of-band** (copy the hex: the `show-identity` output, a secure
channel, a QR, etc.). The client checks the key received from the server against the
pinned one; on a mismatch — a `SERVER KEY MISMATCH` error (anti-MITM). If the field
is unset — TOFU: the client connects and prints the candidate key to the log
(without protection against substitution). The client pins the key **of the
profile** it connects to (by port).

> **`allow_unpinned_tofu` (client `[qeli]`, default `false`) — the fail-closed TOFU
> escape hatch.** By default a client with no pinned `key` **refuses to connect**
> (fail-closed: no silent MITM-exposed TOFU). To knowingly connect without a pin —
> first contact to learn the key, or a lab — set `allow_unpinned_tofu = true`; the
> client then falls back to TOFU (connect + log the candidate key). Once you have the
> hex, pin it with `key` and drop the flag. Ignored when `key` is set (a pinned client
> is already protected).

After `rotate-identity` the public key changes → all clients of that profile must
receive the new hex (otherwise `SERVER KEY MISMATCH`).

### Mandatory pinning — `auth.require_client_key_proof`
By default a client without a pin (`key` in `[qeli]`) connects in TOFU mode (without
MITM protection). To **forbid** connections from clients that have not pinned the
key:
```ini
# server.conf — the [auth] section:
require_client_key_proof = true
```
Then the client must prove knowledge of the server static key: it computes a proof
from the **pinned** key (`key` in `[qeli]`), and the server verifies it with its
private key. A client without the key (or with a wrong one) is rejected
(`AUTH DENIED … server key not pinned by client`). Works on TCP and UDP.

The order (by design, safe): the client first **authenticates the server** (checks
the static key against the pinned one) and only then sends the login/password —
otherwise a MITM could intercept the credentials. So "sending the key after
authorization" is not possible. The static key itself is public; its "leak" to a
scanner gives only a fingerprint.

### H-1 — binding keys to the server identity (`auth.bind_static_to_session`)
**On by default since 0.7.1.** A Noise-IK-style hardening: the session-key KDF also
folds in `es = X25519(client_eph, server_static)`, so a failed ephemeral RNG alone is
no longer enough to expose the tunnel — the attacker also needs the server's private
static key.
```ini
# server.conf — the [auth] section (default true):
bind_static_to_session = true
# client — the [qeli] section (default true; requires a real pinned `key`):
bind_static = true
```
**WIRE-BREAKING**: a server with H-1 only admits clients that also run H-1 and have
pinned the key — enable it in lockstep on the server and all clients. The client
**must** pin the key (`key`); an unpinned / TOFU client (all-zero `key`) must set
`bind_static = false` explicitly, otherwise the connection fails with a clear error.
To interoperate with a legacy 0.7.0 fleet during a staged upgrade, set `false` on both
sides. A separate HKDF salt rules out silent bound↔unbound interop: a flag mismatch
yields different keys and an honest failure, not a silent downgrade. Details —
[AUDIT-2026-06-12.md](AUDIT-2026-06-12.md).

## Per-profile user authorization (interface isolation)

In `users.conf` (or an inline `[user:<name>]` section in server.conf) a user has a
`profiles` key — a list of profiles (interfaces) they are allowed to connect to:

```ini
[user:alice]
password_hash = $argon2id$...
profiles = tcp
```

- **empty** (key absent) → **all** profiles allowed (backward compatibility);
- **non-empty** → only those listed (comma-separated). A user with `profiles = tcp`
  connecting to `udp` is refused with `AUTH DENIED … not permitted on profile 'udp'`
  even with the correct password. This isolates interfaces: access to one does not
  grant access to another.

The check runs after password verification, on both TCP and UDP.

## Connection limits (`max_clients` vs `max_sessions`)

Two independent limits — do NOT confuse them:

| Key | Where | Counts | What it does on reaching it |
|---|---|---|---|
| `perf.connection.max_clients` | `[profile:<name>]` | **all** profile sessions (all users together) | a new AUTH is rejected (`max clients … reached`) |
| `max_sessions` | `[user:<name>]` / `[group:<name>]` | **one user's devices** | the user's oldest device is evicted (newest wins) |

### `max_sessions` — a per-user device limit

Each client carries a stable **device-id** (random 16 bytes, stored on the device;
see multi-device in [ROADMAP](ROADMAP.md)), and the server keys sessions/IP pool by
`username:hex(device_id)`. Therefore:

- **Several devices on one login coexist**, each with its own tun-IP — but no more
  than `max_sessions`.
- **A reconnect of the same device does NOT spend a slot**: it evicts its own
  previous session (the same device-id), the counter doesn't grow. A Wi-Fi↔LTE
  network switch is a reconnect of the same device, the limit is untouched.
- **On reaching the limit, a new device evicts the oldest** device of that user (by
  connection time) — "newest wins", a new device always connects.

**Value resolution** (`effective_max_sessions`): the value in `[user:]` (if `> 0`) →
otherwise from its `[group:]` → otherwise **`0` = no limit**. Enforced identically
on TCP and UDP.

```ini
# users.conf (or inline in server.conf)
[user:alice]
password_hash = $argon2id$...
# alice: at most 2 devices at once
max_sessions = 2

[user:bob]
password_hash = $argon2id$...
# bob takes the limit from the group (max_sessions unset = 0)
group = premium

[group:premium]
# default for group members without their own max_sessions
max_sessions = 5
```

It can be set by editing `users.conf` (then restart/reload) or via the web UI
(Users page → "Max simultaneous sessions", `0` = from the group). Old clients
without a device-id (if any exist) count as one key = username → one "device" per
login.

> Backward compatibility: `max_sessions = 0` (default) = unlimited = the previous
> behavior. The profile's `max_clients` always applies on top — a user cannot exceed
> the profile capacity even if their `max_sessions` is larger.

> **`static_ip` (a user's fixed tun IP).** Set in `[user:<name>]` (`static_ip = 10.0.0.50`,
> must be inside the profile's `pool.cidr`) or via `qeli add-client --static-ip` / the web UI.
> The address **always wins**: a new connection/device takes it, **evicting** whoever holds
> it — so a `static_ip` user has effectively **one** active session, and a reconnect from a
> new source IP always lands on the same tunnel address (effectively `max_sessions = 1`). An
> invalid / out-of-pool address → fall back to a dynamic address + a log warning. Profile
> `pool.reservation.<user>` entries behave the same. Read from the LIVE user db at auth time,
> so a panel edit + reload applies at once.

## Users & groups (`[user:*]` / `[group:*]`)

Users live in the standalone `auth.users_file` (default `/etc/qeli/users.conf`) or inline as
`[user:<name>]` sections in `server.conf`; groups are `[group:<name>]` sections in the same file.
The file is flat-INI, written atomically by `add-client` and the web panel. Full annotated example
— [users.conf](../../qeli/config/users.conf).

**`[user:<name>]` keys:**

| Key | Default | Purpose |
|---|---|---|
| `password_hash` | — | Argon2id hash of the password (`$argon2id$...`). Set by `add-client` / the panel. Never returned over the API |
| `password_enc` | — | reversibly-encrypted (ChaCha20-Poly1305 under the panel key, base64) copy of the plaintext, so the panel can re-issue a `qeli://` link/QR without knowing the password. Absent for legacy hash-only users. Never returned over the API |
| `enabled` | `true` | whether the account may log in. `false` = disabled (rejected at auth) without deleting it |
| `static_ip` | — | fixed tun IP (must be inside the profile's `pool.cidr`); the address always wins and evicts whoever holds it (see the `static_ip` note above) |
| `max_sessions` | `0` | per-user simultaneous-device cap (`0` = from the group, else unlimited); see "`max_sessions`" above |
| `profiles` | `[]` (all) | comma-separated list of profiles the user may connect to; empty = all (interface isolation, see above) |
| `group` | — | name of a `[group:<name>]` to inherit `bandwidth`/`max_sessions`/`allowed_networks` from |
| `route` | — | repeatable per-user route pushed to the client, `<cidr> [gateway=<ip>] [metric=<n>]`; **overrides** the profile's global `route`/`advertised_routes` when present |
| `client_subnet` | `[]` | repeatable (or comma-separated) subnet/address **behind** this client that the server routes INBOUND into this client's tunnel (OpenVPN `iroute`); server-side inbound registration only — see §"Routing networks behind nodes WITHOUT NAT" |
| `allowed_networks` | `[]` (any) | destination ACL — CIDRs/IPs the user is allowed to reach; empty = anywhere |
| `bandwidth.limit_mbps` | `0` | per-user rate cap in Mbit/s (`0` = unlimited or from the group) |
| `bandwidth.burst_mbps` | `0` | per-user burst allowance in Mbit/s above the sustained limit |
| `data_limit_gb` | `0` | lifetime data cap in GB (`0` = unlimited), counted on **download only** (server→client, `used_down`); upload is tracked separately (`used_up`) but does NOT count against the cap. Enforced at auth and by the usage sweep (over-quota live sessions are disconnected). Consumption is tracked in the `usage.json` sidecar |
| `expire_at` | — | account expiry as a Unix timestamp (seconds); absent = never expires. Past it the user is rejected at auth and disconnected by the sweep |
| `metadata.<key>` | — | free-form string annotations (repeatable, one per `<key>`); stored as-is, not interpreted by the server |

**`[group:<name>]` keys** — a template inherited by members via the user's `group` key (a user's own value always wins when set):

| Key | Default | Purpose |
|---|---|---|
| `bandwidth_limit_mbps` | — | default rate cap in Mbit/s for members without their own `bandwidth.limit_mbps` |
| `max_sessions` | — | default per-user device cap for members without their own `max_sessions` |
| `allowed_networks` | — | default destination ACL (CIDRs/IPs) for members |

```ini
# users.conf (or inline in server.conf)
[user:bob]
password_hash = $argon2id$v=19$m=...$...
enabled = true
profiles = tcp
allowed_networks = 10.0.0.0/24, 192.168.1.0/24
bandwidth.limit_mbps = 50
bandwidth.burst_mbps = 100
data_limit_gb = 100
expire_at = 1767225600
route = 10.20.0.0/16 gateway=10.0.0.1 metric=100
group = premium
metadata.note = contractor

[group:premium]
bandwidth_limit_mbps = 100
max_sessions = 5
allowed_networks = 0.0.0.0/0
```

## Client: credentials, routing, reconnect

**Client credentials** — in the `[qeli]` section:
```ini
# client.conf
user = alice
pass = secret
```
The password can be supplied three ways in the `[qeli]` section (precedence high → low):
- `pass = <secret>` — inline plaintext (wins if present and non-empty).
- `password_file = <path>` — read the password from a file (its content is trimmed). Used only
  when `pass` is absent. Good for headless clients that keep the secret out of the config.
- `password_command = <cmd>` — obtain the password by running a command via `sh -c` (its stdout is
  trimmed). Used only when both `pass` and `password_file` are absent. **Runs as the client
  process (typically root)**, so it is honored ONLY from a trusted (not group/world-writable)
  config file — otherwise the client refuses to start (fail-closed), same rule as `post_up`. The
  panel never persists this key.

On the **server**, users can be kept inline — as
`[user:<name>]` sections right in server.conf (with Argon2 hashes) — or in the
standalone `auth.users_file`:
```ini
# server.conf:
[user:alice]
password_hash = $argon2id$...
profiles = tcp
```

> **Inline + file precedence.** The server loads the **union** of the users file
> and any inline `[user:*]`, and the **users file wins** for a duplicate username.
> This matters because the web panel and `add-client` write to the *file*: with the
> old "inline replaces the file" rule, a config that carried inline users made every
> panel edit a silent no-op. Now a panel/`add-client` change always applies (the file
> copy shadows the inline one; the shadowing is logged). Pure-inline and pure-file
> setups are unchanged. To manage users dynamically, prefer the file (or the panel);
> keep inline `[user:*]` only for fully static, hand-edited deployments.

**Routing is predominantly server-side.** The flat-INI client (`[qeli]`) is
deliberately minimal: routes/DNS/MTU come from the server at the handshake. The
server distributes routes with the repeatable `route` key in the profile (or
individually per user — the same `route` key in `[user:<name>]`, which overrides the
global ones); the client applies them to the tun automatically:
```ini
# server.conf, in the [profile:tcp] profile:
route = 192.168.50.0/24 gateway=10.0.0.1 metric=50
```
Verified: the client gets `192.168.50.0/24 via <tun_gw> dev <tun>` in the table.

Client-side routing keys in flat-INI (`[qeli]`, file-only — not carried in a
`qeli://` link; the booleans default `false`, `dns` defaults to `tunnel`):

| Key | Purpose |
|---|---|
| `route_local` | pull the **broad RFC1918 ranges** (10/8, 172.16/12, 192.168/16) into the tunnel. Default `false` — it would otherwise hijack the client's own LAN. **Routes the server explicitly advertises (`route = …`) are applied ALWAYS and do not depend on this flag** (since 0.7.12; before that they sat behind it and were silently dropped) |
| `gateway` | full-tunnel: all client traffic into the VPN (default route via tun) |
| `exclude` | comma-separated CIDRs to **exclude** from the tunnel — they go directly via the real gateway, not the VPN. Works **even under full-tunnel**: each subnet gets a more-specific route **via the physical gateway** (beats the `0.0.0.0/1`+`128.0.0.0/1` halves by longest-prefix match). Rust/Windows/macOS install that bypass route (torn down on disconnect); Android uses `VpnService.excludeRoute` (API 33+). CIDRs are strictly validated before being spliced into route commands. Example: `exclude = 192.168.50.0/24, 10.20.0.0/16` |
| `include` | comma-separated CIDRs to route **into** the tunnel (split-tunnel — relevant when `gateway` is not set) |
| `allow_lan` (Android, default `false`) | shortcut over `exclude`: carve **all** private ranges out of the tunnel (RFC1918 + link-local `169.254/16` + local-multicast `224.0.0.0/24` for mDNS/SSDP) so home Wi-Fi/LAN devices stay reachable without disconnecting. Also exposed as an "Allow local network access" toggle in the app Settings. Android 13+ uses `excludeRoute`; older uses route-splitting (the RFC1918 complement of `0.0.0.0/0`) |
| `allow_ipv6_leak` (default `false`) | kill-switch escape hatch: by default, on a host with global IPv6 but no `ip6tables`, the kill-switch **refuses** to engage (fail-closed, so IPv6 can't leak). `true` = connect anyway, accepting the IPv6 leak |
| `kill_switch` | firewall kill-switch (Linux/iptables, full-tunnel only): while the tunnel is down, block all egress except loopback/tun/DHCP/server IP, so a drop can't leak onto the physical interface |
| `gateway_nat` | router mode (Linux/iptables): the client programs `ip_forward` + `MASQUERADE` out the tun (+FORWARD +MSS-clamp) so a LAN **behind** it reaches the internet through the tunnel — no manual iptables. Idempotent, kept across reconnects, removed on a clean stop (a crash leaves it, like the kill-switch) |
| `lan_subnet` | restrict `gateway_nat` to one source CIDR (`-s <CIDR>`); empty = masquerade everything leaving the tun |
| `post_up` / `post_down` | command run at start / clean stop (Linux, root) for custom routing/firewall. **SECURITY:** honoured ONLY from a trusted file (root-owned, not group/world-writable); the panel/API never write them (else RCE). Env: `QELI_TUN`, `QELI_SERVER`, `QELI_SERVER_PORT`, `QELI_LAN_SUBNET` |
| `dns` | client DNS mode. `tunnel` (default) = route DNS through the tunnel: the client **rewrites `/etc/resolv.conf`** (Linux) to the tunnel resolver to prevent DNS leaks. `off` = **leave the system resolver untouched**, use the host's DNS as-is (for routers and any Linux host that already has DNS configured and shouldn't have `resolv.conf` touched). File-only; emitted to INI only when `!= tunnel` |
| `autostart` | auto-connect this profile when the supervisor/panel starts (accepts `true`/`1`/`yes`/`on`). Read by the **panel client-manager**; ignored by the client runtime itself. Emitted to INI only when `true` |

**Auto-reconnect** is on by default (there are no separate keys in flat-INI `[qeli]`
— the defaults apply: exponential backoff, cap 60s, infinite retries). A client left
on while the server is unreachable (even a day+) keeps retrying and **reconnects as
soon as the server returns**.

A dead server on an idle tunnel is detected via **RX-liveness**: if no data arrives
from the server for longer than `rx_dead = max(3 × heartbeat_interval, 30s)`, the
client drops the link and reconnects (log: `no data from server for >Ns — reconnecting`).
The threshold is **not a separate key** — it is derived from `obf.heartbeat.interval_ms`
(pushed by the server; default 15s → `max(45s, 30s)` = **45s**, hence the `>45s` in the
log). The 30s floor suppresses false trips from UDP loss, and the 3× multiplier rides
out a couple of dropped heartbeats. To change it, edit `obf.heartbeat.interval_ms` in
the server profile.

> Detection is active only while heartbeat (or traffic-shaping cover) is on: the code
> guards on `heartbeat_enabled || shaping_on`. With `obf.heartbeat.enabled = false`
> there is nothing to refresh `last_rx`, so a dead server on an idle link is **not**
> detected — which is why heartbeat is best left on for UDP.

## Router mode: automatic NAT (`gateway_nat`, `lan_subnet`)

> ⚠️ **Binary-only.** `gateway_nat`, `lan_subnet`, `post_up`/`post_down` (and the
> server's `routing.post_up`/`routing.post_down`) work **only** when running the
> **`qeli` / `qeli-client`** binary on Linux (router / headless / server). The GUI
> apps (Android, Windows, macOS) **ignore** these keys — they have no root `sh`/
> `iptables`, and router mode doesn't apply (an endpoint device, not a gateway).

When the client runs **on a router** (a Mikrotik container, Keenetic, OpenWrt, any
Linux gateway) and must carry the LAN **behind** it into the tunnel, it needs a
source-NAT out of the tun: otherwise the server sees traffic from a private address
outside its pool and can't return the reply. This used to be set by hand
(`iptables -t nat -A POSTROUTING -o vpn0 -j MASQUERADE`) and the rules dropped on a
reconnect / container restart.

`gateway_nat = true` does it itself, idempotently:
- `net.ipv4.ip_forward = 1` (+ relaxes `rp_filter` for the asymmetric LAN↔tun path);
- `MASQUERADE` out the tun (everything, or just `lan_subnet`);
- a `FORWARD` accept both ways;
- a TCP **MSS-clamp** (without it pings pass but sites hang — the tunnel MTU is < 1500).

All rules carry a `qeli-gw-nat` comment, are verified with `iptables -C`, persist
across reconnects, and are removed on a **clean** stop. A crash leaves them (fail-safe;
clear them like the kill-switch).

**Example — a Mikrotik container as the gateway for `192.168.254.0/24`:**

```ini
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = router1
pass   = <password>
key    = <server pubkey>
mode   = fake-tls
sni    = www.cloudflare.com
dev    = vpn0
gateway_nat = true
# empty = masquerade everything leaving the tun
lan_subnet  = 192.168.254.0/24
# leave /etc/resolv.conf alone, use the host DNS
dns    = off
[logging]
level = info
```

`chmod 600 client.conf` — and the client keeps `ip_forward` + `MASQUERADE -s
192.168.254.0/24 -o vpn0` consistent across every reconnect and container restart. No
manual wiring or watchdog entrypoint needed.

> On `iptables-nft` hosts the `filter` table's `FORWARD` chain can be legacy-
> incompatible (same as `server/nat.rs`) — then it's installed best-effort and
> forwarding works thanks to the `FORWARD` policy being `ACCEPT` (a warning is logged).
> `MASQUERADE` and the MSS-clamp are mandatory.

## Routing networks behind nodes WITHOUT NAT (`client_subnet`, `forward`, `forward_private`)

Since 0.7.11 qeli does site-to-site L3 routing — traffic to any networks through the server or a
client, **without NAT** (real source IPs preserved; NAT is only for internet egress = `gateway_nat`).

### 1. `client_subnet` (per-user, server) — a subnet BEHIND a client (OpenVPN `iroute`)

By default the server routes to a client ONLY by its assigned pool IP (`by_ip`) — a packet to any
other of its addresses is dropped. `client_subnet` registers an extra address/subnet as an **inbound**
route into that client's tunnel (and adds `ip route … dev <tun>` on the server). Set per user (panel
→ user card → "Client subnets", or the users file):

```ini
[user:branch1]
password_hash = ...
; the LAN behind client branch1
client_subnet = 192.168.50.0/24
; several lines or a comma-separated list
client_subnet = 10.20.0.7/32
```

Guards reject a default route, a subnet covering the tunnel gateway, or one already claimed by another client.

### 2. `routing.forward` (client) — forward a LAN behind the client WITHOUT NAT

When the client is a gateway for a LAN behind it, it needs `ip_forward`. Unlike `gateway_nat`
(ip_forward + **MASQUERADE**, for internet egress), `forward` enables only `ip_forward` +
`FORWARD ACCEPT` (both directions) + MSS-clamp, **without MASQUERADE** — real source IPs preserved:

```ini
[qeli]
server  = vpn.example.com:443
user    = branch1
pass    = ...
key     = <server-pubkey>
; ip_forward without NAT for the LAN behind this client
forward = true
```

Rust/OpenWrt — full support; Windows — `netsh … forwarding=enabled` (LAN→tunnel may also need
forwarding on the LAN NIC / `IPEnableRouter`); macOS — `sysctl net.inet.ip.forwarding=1`;
Android — VpnService can't do this (the key is ignored).

### 3. `routing.forward_private` (server, default `true`) — forward on the server WITHOUT NAT

Previously the server raised `ip_forward`+`FORWARD` only inside `routing.nat`. Now, with NAT **off**
and `forward_private = true`, the server enables `ip_forward` + `FORWARD ACCEPT` tun↔networks
**without MASQUERADE** — for transit of third-party hosts to subnets behind clients. A packet the
server itself originates to a `client_subnet` needs no forwarding — the route from step 1 suffices.

### Site-to-site example (server LAN ↔ LAN behind branch1), no NAT

Server: `[user:branch1] client_subnet = 192.168.50.0/24`, on the profile `routing.forward_private = true`,
`routing.nat.enabled = false`; the client gets the return route to the server LAN via
`routing.advertised_routes` (push). Client branch1: `forward = true`. Result: a host on the server LAN
pings `192.168.50.x` behind branch1 and back — no NAT, real addresses.

## Multiple listeners per profile (`listen`)

A profile listens on ONE socket by default. To reach the SAME profile (one TUN / pool / identity /
users) on more ports/addresses, add `listen` (repeatable) instead of cloning the profile:

```ini
[profile:main]
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
; fallback port
listen = 0.0.0.0:8443
; another address on a multi-homed host
listen = 203.0.113.5:443
```

Each `listen` is a bare `addr:port` on the SAME transport as the profile (`bind.transport`). A
profile is ONE transport — use a separate profile for the other (a per-listener transport is not
supported; a `addr:port udp` suffix is ignored as malformed). Panel: profile → "Extra listeners". A
malformed spec is ignored (logged); a busy port logs "address already in use" and the others keep
running.

## Lifecycle hooks: `post_up` / `post_down`

> ⚠️ **Binary-only** (see the note above) and **Linux-only**. The GUI apps ignore them.

An arbitrary command (`/bin/sh -c …`) qeli runs at a tunnel lifecycle point — for rules
`gateway_nat` doesn't cover: policy routing, mangle marks, site-to-site, custom
firewall. The analogue of `wg-quick`'s `PostUp`/`PostDown`.

**Client** (`[qeli]`, file-only — NOT included in the `qeli://` link):
- `post_up` — once at start, **after** the kill-switch/gateway-NAT, **before** the connect loop;
- `post_down` — only on a **clean** stop (SIGINT/SIGTERM, `reconnect.enabled=false`,
  `max_retries` exhausted);
- hook env: `QELI_TUN`, `QELI_SERVER`, `QELI_SERVER_PORT`, `QELI_LAN_SUBNET`.

```ini
[qeli]
# … + policy routing for one subnet only (not full-tunnel for the whole router):
post_up   = ip rule add from 192.168.254.0/24 table 100; ip route add default dev vpn0 table 100
post_down = ip rule del from 192.168.254.0/24 table 100; ip route flush table 100
```

**Server** (`[profile:*]`, per-profile):
- `routing.post_up` — after this profile's TUN + NAT are up;
- `routing.post_down` — on a clean server stop;
- hook env: `QELI_PROFILE`, `QELI_TUN`, `QELI_POOL`, `QELI_WAN`, `QELI_BIND_PORT`.

The server hook closes **site-to-site** (reaching a LAN behind a client) with no manual
steps — the reverse route + NAT for the client's subnet:

```ini
[profile:tcp]
# … the client needs a STATIC tun IP (pool.static_reservations / qeli add-client --static-ip 10.0.0.2)
routing.post_up   = ip route add 192.168.254.0/24 via 10.0.0.2; iptables -t nat -A POSTROUTING -s 192.168.254.0/24 -o eth0 -j MASQUERADE
routing.post_down = ip route del 192.168.254.0/24 via 10.0.0.2; iptables -t nat -D POSTROUTING -s 192.168.254.0/24 -o eth0 -j MASQUERADE
```

### External script
A hook is `/bin/sh -c …`, so instead of an inline command you can point it at a
**script path** (arguments / pipes / `;` work too):

```ini
[qeli]
post_up   = /etc/qeli/hooks/up.sh
post_down = /etc/qeli/hooks/down.sh
```

`/etc/qeli/hooks/up.sh` (the env context is available to the script):

```sh
#!/bin/sh
set -e
iptables -t nat -A POSTROUTING -s 192.168.254.0/24 -o "$QELI_TUN" -j MASQUERADE
ip rule add from 192.168.254.0/24 table 100
ip route add default dev "$QELI_TUN" table 100
```

> ⚠️ qeli checks the permissions of **the config file only**, not of the script it
> calls. Protect the script the same way, or a world-writable script can be swapped to
> bypass the file-only guard:
> ```sh
> chown root:root /etc/qeli/hooks/*.sh && chmod 700 /etc/qeli/hooks/*.sh
> ```
> This is the standard model (like `systemd ExecStart=`, `cron`, `wg-quick PostUp` — the
> called script's permissions are the operator's responsibility).

### Hook security (important)
A hook runs **as root** (qeli usually runs as root). To keep that from becoming RCE —
**two barriers**:

1. **File-permission check.** If the config is **group/world-writable**
   (`mode & 0o022 ≠ 0`), hooks **are not run** — the log says `Ignoring
   post_up/post_down — …`. Rationale: only the owner should be able to edit the file.
   Fix with `chmod 600`.
2. **The panel/API never write hooks.** The structured `PUT /api/config` restores
   `post_up`/`post_down` from the on-disk file (discarding what the panel sent); the
   raw `PUT /api/config/raw` rejects a config that changes hooks. Hooks can be set or
   changed **only by editing the file** on the server (like `systemd ExecStartPost`),
   never over the network.

### Semantics
- **A crash (SIGKILL/panic) does NOT run `post_down`** — only a clean stop (fail-safe).
- **A 30 s timeout** per hook (`kill_on_drop`) — a hung hook can't wedge start/stop.
- A hook failure **does not abort the tunnel** — it's logged (`hook[post_up]: exited …`).

## Authentication: tokens and anti-brute-force (`[auth]`)

Beyond pinning / H-1 (above), the `[auth]` section carries:

| Key | Default | Purpose |
|---|---|---|
| `users_file` | `/etc/qeli/users.conf` | path to the standalone user database (when there are no inline `[user:*]`) |
| `password_hash` | `argon2id` | password hashing scheme (only argon2id is supported) |
| `token_ttl_secs` | `86400` | auth/session token lifetime (seconds) |
| `brute_force.enabled` | `true` | master switch for **VPN-auth** rate-limiting; `false` = off entirely |
| `brute_force.max_attempts` | `5` | failed-attempt threshold before lockout (per source IP) |
| `brute_force.window_secs` | `300` | window for counting failures (seconds) |
| `brute_force.lockout_secs` | `900` | lockout duration after the threshold is exceeded (seconds) |

This `[auth] brute_force` policy governs **VPN authentication only**. The **web-panel
login** has its own, independent policy — `[web] brute_force` (see [Web panel](#web-panel-web)
below) — with its own switch, attempt count, window and lockout, so the tunnel and the
panel can be tuned (or disabled) separately. Since 0.7.7 the two are separate journals.

The lockout is **per source IP**; a username under attack gets an adaptive tarpit
(slowdown) instead of a hard lock, so a correct password always passes and a
username cannot be locked by guessing it ([L1](AUDIT-2026-06-11.md)). Setting
`brute_force.enabled = false` makes the tracker inert (no lockout, no tarpit, no
tracking) — use it only behind an external limiter or on a trusted network.

> **Editable in the panel** (Config → Authentication → "Brute-force protection — VPN
> authentication"), not only in the file. They apply on **Apply & Restart** or on a
> `SIGHUP` reload — the server rebuilds the tracker with the new values (in-flight lockout
> counters reset at that moment). The tarpit's internal delays (200 ms … 3 s) are not
> configurable. Blocked addresses — the **"Blocked IPs"** tab (split into a VPN-auth and a
> panel-login journal) / `qeli list-blocked` (see [PANEL.md](PANEL.md),
> [GETTING-STARTED.md](GETTING-STARTED.md) §10).
>
> The *Blocked IPs* tab also carries a live editor for **both** policies (VPN + panel) — the
> same thresholds, applied without a restart.

## Obfuscation: handshake shaping and anti-fingerprinting

Fine-tuning of how a profile looks **on the wire**, on top of the chosen `obf.mode`.
All keys are per-profile; the defaults below are the serde defaults (in the example
[server.conf](../../qeli/config/server.conf) some are shown with illustrative,
**non-default** values — rely on the tables here).

> **How the client chooses its SNI.** Priority: a configured/link `sni` wins; else,
> when dialing a bare IP, a random decoy from the built-in pool (per connection); else
> the connect hostname. So **fake-tls** SNI rotation is a *client* setting — leave `sni`
> empty and connect by IP to rotate. Adding more `server_names` on the *server* does
> nothing on the wire. For **reality / reality-tls** the client SNI must equal the one
> mimicked `reality_proxy.target`; to offer several front domains, run several
> reality-tls profiles, each with its own target and matching client links.
>
> **Hiding/omitting SNI (fake-tls/obfs only).** Special `sni` values: `!` = don't send the
> SNI extension at all (like a browser dialing a bare IP); `~` = send an empty extension;
> `@` = empty `server_name_list`. Useful where a pinned SNI gets the flow blocked but a
> no-SNI hello passes. Not applied to **reality / reality-tls** — there SNI is required.

**AEAD and the fake-TLS ClientHello:**

| Key | Default | Purpose |
|---|---|---|
| `obf.tls.server_name` | `www.cloudflare.com` | SNI baked into a generated share link. **fake-tls:** cosmetic (the server ignores the client's SNI). **reality / reality-tls:** must equal `reality_proxy.target`. |

**Padding / Fragmentation / Heartbeat** (all three **enabled** by default):

| Key | Default | Purpose |
|---|---|---|
| `obf.padding.enabled` | `true` | pad packets with random bytes |
| `obf.padding.min_bytes` / `max_bytes` | `32` / `512` | padding range |
| `obf.padding.randomize` | `true` | random length within the range |
| `obf.padding.probability` | `1.0` | fraction of packets padded (0.0–1.0) |
| `obf.fragmentation.enabled` | `true` | split the **handshake record** (ServerHello) across several TCP segments — see the note below the table |
| `obf.fragmentation.min_chunk_size` / `max_chunk_size` | `256` / `1024` | chunk size (bytes), random within the range |
| `obf.fragmentation.max_fragments_per_packet` | `4` | cap on the number of chunks |
| `obf.heartbeat.enabled` | `true` | background cover traffic (keepalive) |
| `obf.heartbeat.interval_ms` | `15000` | interval |
| `obf.heartbeat.data_size_bytes` | `16` | payload size |
| `obf.heartbeat.jitter_ms` | `20` | interval jitter |

> **Fragmentation applies to the handshake only, not to traffic.** It splits one
> record — the ServerHello — once per connection. It never touches the data stream, so
> it **costs no throughput**: the price is roughly 600 bytes (each chunk leaves as its
> own TCP segment, with its own header) and a few tens of milliseconds on a handshake
> that already takes about that long.
>
> The point is that the ServerHello must **not arrive in one segment**, where a DPI
> signature matcher can read it whole. The point is NOT to shred it: many tiny segments
> defeat the matcher but become an anomaly themselves — no real TLS server writes like
> that, so you would trade one tell for another. The defaults give 2-4 plausibly sized
> chunks, indistinguishable from ordinary TCP segmentation. Lower them only against a
> specific DPI you know more about than we do.

> For `reality-tls` padding is pointless (traffic is already inside real TLS) —
> turn it off (`obf.padding.enabled = false`), see the "Server OS tuning" section.

**Extra masking (disabled by default):**

| Key | Default | Purpose |
|---|---|---|
| `obf.traffic_normalization.enabled` | `false` | pad records up to fixed "round" sizes (flattens the length histogram) |
| `obf.traffic_normalization.round_sizes` | `64,128,256,512,1024,1500` | target sizes |
| `obf.anti_fingerprinting.enabled` | `false` | cipher rotation + handshake jitter|
| `obf.anti_fingerprinting.add_jitter_to_handshake` | `true` | handshake jitter|
| `obf.quic.enabled` | `false` | QUIC masking (**udp profiles only**); the server accepts inbound udp-quic even without the flag (mirrors the client per-connection) — the flag only stamps `quic=1` into generated links |
| `obf.awg.enabled` | `false` | AmneziaWG-style junk pre-handshake: send `jc` random "junk" packets before the real handshake so the first bytes on the wire carry no fixed signature. **Works on any profile** — TCP `obfs` and every UDP mode (obfs / fake-tls / QUIC). On **TCP obfs** both ends must use the same `jc` (the receiver skips exactly that many records; a mismatch breaks the handshake). On **UDP** `jc` is *sender-only*: the server drops the junk datagrams cheaply — before its rate limiter — so a lost / reordered / mismatched junk count is harmless (the client just prepends `jc` decoy datagrams before its ClientHello). Client side: `awg`/`jc`/`jmin`/`jmax` in `[qeli]` / `qeli://` |
| `obf.awg.jc` | `0` | number of junk packets sent before the handshake (`0` = none; capped at `128`) |
| `obf.awg.jmin` / `jmax` | `40` / `300` | junk-packet size range in bytes (`jmin ≤ jmax ≤ 1400`; on UDP each junk datagram is additionally capped at 1200 so it never IP-fragments) |

## Built-in DNS resolver (`dns.*`)

An optional in-tunnel DNS proxy: the server hands clients its own resolver and
(optionally) filters domains. Disabled (default) — clients keep their own resolvers
and the server pushes no DNS. Per-profile.

| Key | Default | Purpose |
|---|---|---|
| `dns.enabled` | `false` | enable the in-tunnel DNS proxy |
| `dns.listen` | `10.0.0.1` | listen address (usually the tun IP) |
| `dns.port` | `53` | port |
| `dns.upstream` | `1.1.1.1, 8.8.8.8` | upstream resolvers (comma-separated) |
| `dns.upstream_protocol` | `udp` | `udp` \| `tcp` \| `tls` (DoT) — ⚠️ **not implemented**: the value is parsed and stored, but changes nothing |
| `dns.cache_size` | `1000` | record cache size |
| `dns.timeout_secs` | `5` | upstream timeout (seconds) |
| `dns.blocklist` | `[]` | domains answered with `0.0.0.0` (ad/tracker blocking) |
| `dns.push_servers` | `[]` | hand clients this resolver (first IP in the list) **without** running the proxy — e.g. a LAN / AdGuard / NextDNS box. Empty = as before (the proxy's listen IP when `dns.enabled`, else nothing is pushed). The client applies it in `dns = tunnel` mode; the value is strict-IP-validated before it touches resolv.conf |

## DHCP server (`dhcp.*`)

An optional DHCP server on the profile's interface (for TAP/L2 setups; most
deployments don't need it — IPs are handed out in AUTH). Disabled by default.
Per-profile.

| Key | Default | Purpose |
|---|---|---|
| `dhcp.enabled` | `false` | enable the DHCP server |
| `dhcp.listen` | `0.0.0.0:67` | listen address:port |
| `dhcp.pool_start` / `pool_end` | (none) | lease range (optional; else from `pool.cidr`) |
| `dhcp.lease_time_secs` | `86400` | lease time |
| `dhcp.domain_name` | `vpn` | domain name advertised to clients |

## Performance tuning (`perf.*`, `tun.tx_queue_len`)

All per-profile. Values depend on the link/load — see the general note in "Profile
defaults".

| Key | Default | Purpose |
|---|---|---|
| `tun.tx_queue_len` | `1000` | TX queue length of the TUN device |
| `perf.tcp.nodelay` | `true` | `TCP_NODELAY` (disable Nagle) |
| `perf.tcp.keepalive_secs` | `60` | TCP keepalive |
| `perf.tcp.send_buffer_size` / `recv_buffer_size` | `262144` | socket buffer sizes|
| `perf.tun.read_buffer_size` / `write_buffer_size` | `65535` | TUN-pump buffers |
| `perf.connection.max_clients` | `128` | total sessions per profile (all users; see "Connection limits") |
| `perf.connection.handshake_timeout_secs` | `10` | handshake timeout |
| `perf.connection.idle_timeout_secs` | `300` | idle timeout (`0` = never idle-drop) |
| `perf.connection.new_session_rate_max` | `10` | max new sessions from one source IP per window |
| `perf.connection.new_session_rate_window_secs` | `60` | window for `new_session_rate_max` (seconds) |

## Routing and other per-profile keys

Server-side routing for the profile (client-side routing keys are in the "Client" section):

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `true` | whether this profile is active. `true` = bound and served; `false` = kept in the config but **skipped at startup** (turn an interface off without deleting it). Omitting the key keeps the profile enabled |
| `routing.client_to_client` | `false` | allow client↔client traffic within the tunnel subnet. **Enforced** server-side: when `false` (the default) a packet whose source IP is one client and whose destination is another client is dropped — clients are isolated. Internet traffic (external source) is unaffected |
| `routing.forward_private` | `true` | forward private (RFC1918) networks behind the server to clients |
| `routing.nat.enabled` | `false` | MASQUERADE client traffic to the internet (full-tunnel gateway) |
| `routing.nat.interface` | `eth0` | NAT egress interface (auto-detected when left at default) |
| `route` | — | repeatable: a route advertised to clients, `<cidr> [gateway=<ip>] [metric=<n>]` |
| `routing.post_up` | — | command run after this profile's TUN+NAT are up (Linux, root). **File-only** (panel/API never write it — RCE guard). Env: `QELI_PROFILE`/`QELI_TUN`/`QELI_POOL`/`QELI_WAN`/`QELI_BIND_PORT` |
| `routing.post_down` | — | command run on a clean profile/server stop (mirrors `routing.post_up`; a crash doesn't run it) |
| `tun.device_type` | `tun` | interface type: `tun` (L3) \| `tap` (L2) |
| `obf.tls.reality_proxy.peek_timeout_ms` | `1500` | how many ms to peek the ClientHello before classifying peer as client vs probe |

## Web panel (`[web]`)

The built-in admin UI (profiles, users, clients, identity, link/QR issuance).
Full install & usage guide — [PANEL.md](PANEL.md). Section keys:

```ini
[web]
# enable the panel
enabled = true
# address (public IP, or 127.0.0.1 behind an SSH tunnel)
bind = 0.0.0.0
port = 8080
username = admin
# argon2id hash (NOT the plaintext)
password_hash = $argon2id$...
# native HTTPS (rustls); empty cert/key = self-signed auto
tls = true
tls_cert =                    # (opt.) your PEM cert; empty = self-signed
tls_key =                     # (opt.) your PEM key
# (opt.) source-IP/CIDR allowlist; empty = any
allowed_ips = 203.0.113.4, 10.0.0.0/8
# (opt.) default host for share links
public_host = vpn.example.com
# (opt.) extra CSRF origins (domain / reverse proxy)
allowed_origins = panel.example.com
# Secure on the cookie (auto=true under tls; manual behind a TLS proxy)
secure_cookie = false
# keep panel logins across a process restart; emitted only when false
persist_session_key = true
base_path =                   # (opt.) reverse-proxy sub-path, e.g. /qeli; empty = served at root
# CSRF protection (default true); false = ONLY on a loopback bind
csrf = true
trusted_proxies =             # (opt.) reverse-proxy IPs/CIDRs whose X-Forwarded-For is trusted; empty = none
# (opt.) panel login-session lifetime (seconds); emitted only when != 86400
session_ttl_secs = 86400
# PANEL-LOGIN lockout switch (independent of [auth] brute_force)
brute_force.enabled = true
# failed panel logins before lockout (per source IP)
brute_force.max_attempts = 5
# window for counting failures (seconds)
brute_force.window_secs = 300
# lockout duration after the threshold (seconds)
brute_force.lockout_secs = 900
```

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `false` | enable the web panel |
| `bind` | `127.0.0.1` | listen interface (a public IP for public access) |
| `port` | `8080` | panel HTTP/HTTPS port |
| `username` | `admin` | admin login |
| `password_hash` | `""` | argon2id password hash. **Required on a non-loopback bind** (fail-closed) |
| `tls` | `false` | serve HTTPS directly (rustls/`ring`). Auto `Secure` cookie |
| `tls_cert` / `tls_key` | `""` | PEM cert/key; empty = self-signed (`/etc/qeli/web-tls-*.pem`, SAN=bind+localhost) |
| `allowed_ips` | `[]` | source-IP/CIDR allowlist; empty = no restriction |
| `public_host` | `""` | default public host for `qeli://` links (editable in the Share dialog); also accepted as a CSRF origin |
| `allowed_origins` | `[]` | extra browser origins (`host[:port]`) accepted by the CSRF check when the panel is reached via a domain / reverse proxy; otherwise a public panel loads but every save returns 403 |
| `secure_cookie` | `false` | add `Secure` to the session cookie |
| `persist_session_key` | `true` | persist the panel session-signing secret to a `0600` file (in `$STATE_DIRECTORY`, else `/etc/qeli/.session_key`) so panel logins **survive a full process restart**. Emitted only when `false`. Set `false` for a per-process-random key (stricter, H-4) — a full restart then logs everyone out. The key lives in a separate `0600` file (not the config, not backups), so a config-only leak still can't forge a token |
| `base_path` | `""` | reverse-proxy sub-path (e.g. `/qeli`); empty = served at root. An `X-Forwarded-Prefix` header overrides it per-request. See "Reverse-proxy sub-path" below |
| `csrf` | `true` | CSRF same-origin protection for mutating requests. **Keep `true`.** `false` disables the Origin/Referer check entirely (with a startup warning) — only acceptable on a loopback-only bind (accessed via an SSH forward); dangerous on a public/LAN bind (any site you open could drive your logged-in panel). Loopback origins are already trusted on any port |
| `trusted_proxies` | `[]` | reverse-proxy source IPs/CIDRs whose `X-Forwarded-For` is trusted (for the allowlist + rate-limiting); empty = trust no proxy header. Always emitted |
| `session_ttl_secs` | `86400` | panel login-session lifetime (cookie `Max-Age` + token expiry), seconds. Emitted only when non-default (`≠ 86400`) |
| `update_check` | `false` | let the panel query GitHub Releases and show an "update available" banner (opt-in, notify-only). Emitted only when `true` |
| `brute_force.enabled` | `true` | master switch for **panel-login** rate-limiting (independent of `[auth] brute_force`); `false` = off entirely |
| `brute_force.max_attempts` | `5` | failed panel logins before lockout (per source IP) |
| `brute_force.window_secs` | `300` | window for counting failures (seconds) |
| `brute_force.lockout_secs` | `900` | lockout duration after the threshold is exceeded (seconds) |

**Panel-login brute-force (`[web] brute_force`).** A policy fully independent of the
VPN-auth one in `[auth]`: the panel keeps its **own** lockout journal, so failed admin
logins never touch the VPN counters and vice-versa. Same per-source-IP lockout + admin-name
tarpit semantics. Set `brute_force.enabled = false` to disable panel-login rate-limiting
entirely (only safe on a trusted / loopback bind). Editable live on the **Blocked IPs** tab
(the "Panel login" side of the policy editor) or in Config → Web UI.

**Reverse-proxy sub-path (`base_path`).** To serve the panel under a prefix (e.g.
`https://host/qeli/`) instead of the domain root, set `base_path` and proxy **without
stripping** the prefix:

```nginx
location /qeli/ {
    proxy_pass https://127.0.0.1:8080;      # no trailing "/" → /qeli/ passes through as-is
    proxy_ssl_verify off;                    # the panel serves self-signed TLS
    proxy_set_header X-Forwarded-Prefix /qeli;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

```ini
[web]
base_path = /qeli
# the reverse-proxy domain (for CSRF)
allowed_origins = host
# panel behind an HTTPS proxy
secure_cookie = true
```

Prefix precedence: `X-Forwarded-Prefix` (if the proxy sends it) → else `base_path` → else
root. No-config alternative: leave `base_path` empty and have nginx **strip** the prefix
(`proxy_pass https://127.0.0.1:8080/;` with a trailing "/") while sending
`X-Forwarded-Prefix /qeli` — the prefix then comes only from the header. `qeli://` links
and QR codes stay absolute in either mode.

- **Update check (`update_check`, default OFF):** when `true`, the panel shows a
  dismissible banner if a newer qeli release exists on GitHub. Privacy-first: the check
  is performed **by the operator's browser** (like the marketing site does), not by the
  qeli server process — there is **no server-side beacon and no telemetry**. It is a
  single unauthenticated GET of public release metadata (`/repos/litvinovtd/qeli/releases`,
  cached ~6 h), sends nothing that identifies the host, and is **notification-only** —
  it never downloads or installs anything. Leave it OFF to make no outbound request at all.
  (Desktop/mobile clients have their own opt-in toggle in Settings; the CLI offers
  `qeli version --check`.)
- **Fail-closed:** with a non-loopback `bind` and an empty `password_hash` the
  panel **refuses to start** (the VPN is unaffected). Set a password (Config → Web
  → Set admin password, the `argon2` CLI, or `/api/hash-password`).
- **Self-signed TLS** is generated on first start and persists across restarts;
  browsers warn once. For a clean cert set `tls_cert`/`tls_key`.
- **User password storage:** besides the argon2 hash the panel keeps a reversibly-
  encrypted copy (`password_enc`, key `/etc/qeli/panel-secret.key`) so a config can
  be re-issued without typing the password. Never returned over the API. Details &
  trade-off — [PANEL.md](PANEL.md#3-password-storage-model--trade-off).

## Logging

The `[logging]` section (in server.conf and client.conf):

```ini
[logging]
# error | warn | info | debug | trace  (RUST_LOG overrides)
level = info
# if set — logs are written to a file (the directory is created);
# if omitted — stderr (under systemd this goes to journald)
file = /var/log/qeli/server.log
# plain | json — log line format (default plain)
format = plain
```

At the `info` level the log records all key events: profile and listener
start/stop, connection establishment (`New TCP connection`,
`Client … connected … IP …`), authentication (`AUTH attempt/OK/FAIL/BLOCKED`,
including brute-force lockouts), connection teardown (`Client … disconnected`),
administrative commands via the control socket (`CONTROL action=… user=…` —
kick/disable/enable/set-bandwidth), SIGHUP reload. Data-plane-side teardown reasons
are written at the `debug` level.

For diagnostics, `level: "info"` with a set `file` is the minimum sufficient.
```
