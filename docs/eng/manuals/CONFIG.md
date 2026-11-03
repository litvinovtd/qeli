# qeli configuration

> **Documentation status:** current development tree **0.8.3**; planned full-IPv6 release **0.8.3**;
> package version covered by this guide **0.8.3**.
> `qeli --version` reports the version of the binary actually installed.
> See [GitHub Releases](https://github.com/litvinovtd/qeli/releases) for package availability and publication status.
> Links to this version's files work after its publication.

## Format: flat-INI (the only one; TOML/JSON have been dropped)

Configs are **text flat-INI**. Structure:

- Global sections `[auth]`, `[web]`, `[logging]`.
- One `[profile:<name>]` per interface; nested struct fields are **dotted keys**:
  `bind.port`, `tun.address`, `obf.tls.reality_proxy.enabled`, `perf.connection.max_clients`.
- Users/groups are `[user:<name>]` / `[group:<name>]` sections (inline in the
  server config, or in a separate `auth.users_file` file).
- Repeatable keys: `route = <cidr> gateway=<ip> metric=<n>` and `listen`.
  Lists (`pool.exclude`, `dns.upstream`, and others) accept comma-separated values
  or repeated lines of the same key, preserving their order.
- `pool.reservation.<user>`, `pool.ipv6.reservation.<user>`, and `metadata.<key>` are
  maps: a suffix is required and each full key may occur only once.
- The client config is a single `[qeli]` section (plus an optional `[logging]`); the same
  thing is expanded from a `qeli://` link on QR import. The full client key reference and the
  "which client supports what" matrix live in
  [Client: credentials, routing, reconnect](#client-credentials-routing-reconnect).

The client INI is limited to **256 KiB**, including logging inspection before
startup and `qeli check-config --client`. On Linux, both `qeli client` and the
standalone `qeli-client` accept regular files only; FIFOs and directories are
rejected without waiting. `[logging]` uses the same strict parser as the rest of
the profile. An invalid profile sends diagnostics to stderr. To use
`logging.file`, the config must be a regular file without a symlink, owned by root
or the process user, with no group/other write permission; use
`chmod 600 client.ini`. An untrusted config cannot open a log file; its other
valid logging settings remain effective.
A file sink must be a regular file: FIFOs, devices and directories are rejected,
and messages fall back to stderr. Leave `file` empty for journald/logread.

The panel provides a **form and an INI editor**; there is no configuration JSON editor.
JSON in the internal HTTP API carries form data and status, not a configuration file format.
The server INI is limited to **16 MiB**: `check-config`, startup, SIGHUP and panel
reads refuse a larger file before parsing. The form, INI editor, Quick Start and
snapshot restore cannot write a config above this limit.
A panel save writes the server INI with mode `0600`, even when the previous
file had more permissive access.
A failed load blocks saving; edits made during a pending save remain marked unsaved.
Panel address/port/TLS/base_path changes require a full process restart, not just a worker restart.
Changed panel-login thresholds apply immediately when live reload succeeds; existing IP
lockouts remain when thresholds are unchanged. Save responses include
`web_settings_applied`: when `false`, the INI was written but the previous panel
settings remain active; inspect the file and server log before restarting.

Repeated `[profile:<name>]`, `[user:<name>]`, and `[group:<name>]` sections in one file
are rejected before applying changes. Profile names cannot contain commas, `/`,
or `\`: commas separate entries in a user's `profiles` list, and the name is also part of the default identity key
path. Rename affected profiles and their references before upgrading; there is
no automatic rename. To keep an existing key after renaming, explicitly set
`identity_key` to its old absolute path. The same username may still appear in both inline config and the external users_file; the external entry wins.
In the INI editor, `<unchanged>` preserves a secret. If the original value cannot be found,
saving fails and a new value must be entered explicitly.


Global `[auth]`, `[web]`, and `[logging]` sections may occur at most once and must
not have a `:<name>` suffix. Unknown sections are rejected, including empty ones.
Duplicate scalar keys, unknown keys, and malformed values are rejected at startup,
on reload, and when saving through the panel/CLI. A rejected reload keeps the running
configuration; rewriting must not silently remove an invalid entry.
Known retired keys remain exempt only within their documented section scopes. Legacy profile `tun.netmask` is read only to warn and is ignored; `pool.cidr` defines the subnet prefix.

A `route` requires a valid CIDR; `gateway` must be an IP of the same address family,
and `metric` an integer in `0..=4294967295`. Unknown or duplicate options and malformed
numbers are errors. For profile routes, the final `desc=` option consumes the remaining
description text; user routes do not support `desc`. Invalid members of the numeric
`obf.traffic_normalization.round_sizes` list are also rejected instead of being dropped.
INI comments occupy a separate line starting with `#` or `;`; comments after a value
are not supported.

For list keys, omission keeps the baseline list; an explicit empty value (`key =` or `key = ""`) replaces it with an empty list. Repeated lines append comma-separated entries in source order; blank members are discarded, without generic deduplication. Consumers can reject duplicates (for example DNS upstreams and IPv6 pool exclusions). Quotes apply to the whole INI value, not separately to each comma-separated member. `listen` and `route` use one complete specification per line, rather than comma splitting.

Numeric `parse_or` fields use their baseline when empty (for example `max_sessions =` means zero/inheritance). Optional numeric fields such as user `expire_at` and group `max_sessions` reject an empty value; remove the key to express absence. Empty boolean values are invalid. These parsing rules still apply when a profile, account or panel is disabled.

Control characters in INI are rejected with a line number instead of being removed on save.
LF/CRLF line endings, tabs between record components and tabs inside values are supported;
tabs inside key/section names are rejected. Double quotes preserve significant whitespace
and tabs at the edges of a value. `logging.level` under `[qeli]` is an unknown key: use
`level` under `[logging]`.

Legacy client `dns = <IP list>` is migrated only when the DNS fields are unambiguous and
free of errors. Duplicate `dns` or malformed `dns_servers` remains invalid after opening
and saving a form. A BOM before client INI or `qeli://` is accepted; it never relaxes link
validation. Unsupported controls in `qeli://`, including percent-encoded ones, are rejected
before INI conversion: an endpoint, transport or server key cannot change through character
removal. This also applies to panel imports.

### What a `qeli://` link carries

Links with duplicate known parameters are rejected: a second `key=` cannot clear
the first pin. `quic`/`awg` accept case-insensitive `true`, `false`, `1`, `0`.
Malformed numbers and type overflow are errors, not requests to use defaults.
Percent encoding and UTF-8 must be valid; encode a literal `%` as `%25`, while `+`
remains a plus. Unknown parameters remain ignored for forward compatibility.
AWG defaults to `jmin=40`, `jmax=300`; `jc` is capped at 128, sizes at 1400, and
`jmin > jmax` becomes `jmin = jmax` on every client. The existing fallback from a
numeric MTU outside the supported range to auto is preserved.

A link carries the address, credentials, handshake parameters, and an explicitly selected
portable session-roaming policy. Routes, DNS, and other local settings are deliberately absent;
they are either pushed by the server on connect or set in the client's file. Format:

```
qeli://<user>:<pass>@<host>:<port>?<parameters>#<label>
```

Server endpoints may use IPv4, IPv6, or a hostname with A and/or AAAA records. A literal IPv6
address is bracketed in both INI and links: `server = [2001:db8::10]:443` and
`qeli://user:pass@[2001:db8::10]:443?...`. Bare IPv6 plus a port is rejected as ambiguous.
INI and URI use one host check: whitespace, URL delimiters and empty DNS labels are
invalid. Internationalized domains use ASCII/Punycode; `localhost`, local names containing
`_` and a trailing DNS root dot are retained. A malformed endpoint can remain in an INI
draft but cannot activate or export to a link. Editing another field never repairs its
port automatically. The panel uses the same client contract for saves and automatic
`dev` assignment: BOM and `[QELI]`/`DEV` case variants are supported, and original INI
comments are retained. Panel restrictions on shell commands and unsafe paths remain separate.

| In the link | INI key | When it appears | Meaning |
|---|---|---|---|
| authority | `server` | always | `host:port` |
| userinfo | `user` / `pass` | when non-empty | credentials (percent-encoded) |
| `proto` | `proto` | when non-empty | `tcp` / `udp` |
| `mode` | `mode` | when non-empty | `plain` / `fake-tls` / `obfs` / `reality-tls` |
| `key` | `key` | when pinning is set | server public key (hex) |
| `sni` | `sni` | when set | SNI for fake-tls / reality-tls |
| `rsid` | `reality_sid` | when set | REALITY short_id |
| `obfs` | `obfs_key` | when set | PSK for `obfs` mode |
| `front` | `front` | only when it differs from the default | `websocket` / `none` |
| `quic=1` | `quic` | only when enabled | QUIC masking for UDP |
| `awg=1` + `jc` + `jmin` + `jmax` | `awg` `jc` `jmin` `jmax` | only when `awg` is enabled | AmneziaWG junk preamble |
| `mtu` | `mtu` | only for an explicit value `> 0` | tunnel MTU; absent = auto (adopt the push) |
| `roaming` | `roaming` | only for non-default `off` / `required` | policy for preserving the logical session across network changes |
| `#` fragment | `name` | when set | profile display name in the UI |

Optional parameters at their default value are **omitted**, which is why an ordinary link
stays short and byte-identical to what earlier versions produced.
Consequently `roaming=auto` is absent from a link; links generated by the server CLI and panel
use that default. When a user exports a profile with explicit `off` or `required`, the policy
survives import into Rust, Android, Windows, macOS, and iOS. An unknown value is rejected at
the import boundary instead of silently becoming `auto`.

**`mode` aliases.** Two "transport + obfuscation" shorthands are accepted:
`udp-quic` = `proto=udp` + `mode=fake-tls` + `quic=1`; `udp-obfs` = `proto=udp` + `mode=obfs`.
They are expanded by the **Rust CLI, the desktop (C#) clients and iOS**, and by **Android
from 0.7.13 on**. In 0.7.12 Android keeps the alias as the literal `mode` value: such a
profile imports without an error and then never connects, so hand Android users on 0.7.12
links with `proto` and `mode` spelled out separately.

> **The table is exhaustive.** Five clients use the same Rust INI/URI implementation
> through ABI 1.16; C#, Kotlin and Swift retain generated data projections.
> `config/share.rs` and `conformance/qeli-links.json` define the shared URI contract.
>
> **`bind_static` and `mtu_probe` are deliberately NOT in the link.** They are local device
> policy rather than a property of the server, and the link by definition carries only what
> the client cannot learn any other way; on top of that, `bind_static=0` inside a
> forwardable QR hands out a weakened security setting. Set both in the client's own file
> (see the `[qeli]` key reference below). Before 0.7.13 Android put them in the link while
> the other three dropped them as unknown params, so an Android link arrived elsewhere with
> `bind_static` silently back to `true` — which demands a pinned `key`. From 0.7.13 Android
> no longer emits them, but still **parses** them so links it issued earlier import as
> intended.
>
> **`apps_mode` and `apps` are also file-only.** Application identifiers are
> platform-owned (Windows executable paths, Apple signing identifiers, Android package
> names), so forwarding them in a portable QR can silently change scope on another device.
> All clients preserve and apply their local flat-INI policy; qeli:// serializers omit it and
> importers ignore legacy `apps*` query parameters.

**Password when sharing.** Exporting a local profile to `qeli://` requires a nonempty inline `pass` in the INI. `password_file` and `password_command` work only on the source device and cannot be carried in a link; without `pass`, export now fails while the local INI remains usable. Add `pass` only when you intend to give the link recipient that secret.

**About `quic`.** The server **mirrors the client's choice per-connection** — it validates
the complete qeli QUIC envelope on the first datagram (including its declared Length), so
`udp-quic` works even when the server profile's
`obf.quic.enabled` is off; that flag only controls whether the server stamps `quic=1` into
the links it generates.

**About `awg`.** OFF by default. Works on **TCP `obfs` and every UDP mode**: on TCP both ends
must agree on `jc`, on UDP `jc` is sender-only. Pairs with the server's `obf.awg.*` (see the
obfuscation section).

**About `dev` (the TUN interface name).** A **file/INI key** — it is not carried in the link.
Default `vpn0`; set your own if `vpn0` is taken by another application or you need several
clients on one host. When the web panel creates a client tunnel (the **TUN device** field) it
auto-assigns a free `vpnN` not already used by another profile **or live on the host**, so it
never clashes with a server profile's `vpn0`/`vpn1`. On the **C# desktop clients
(Windows/macOS)** `dev` is **not applied**: Windows auto-names the Wintun adapter
(`Qeli-<hash>`, derived from the server address) and macOS takes a kernel `utunN`. A manual
interface name works only on the Rust/Linux/router client and the panel's client manager.

Links from the panel (`POST /api/share`) and from the CLI
(`qeli add-client <user> --link --host <host>`) are built from the same struct and are
identical in content.

### Client keys: keepalive and OpenVPN parity

**Keepalive.** The authenticated server heartbeat setting is applied by the shared Rust core,
except that current TCP `reality-tls` forcibly disables the qeli heartbeat: H2/TCP supplies
transport liveness and a periodic application beacon is classifiable. Other modes send the
configured encrypted keepalive; traffic shaping replaces it with randomized cover. If both are
disabled there is no invented 30-second fallback or RX-liveness reap. UDP profiles must retain
heartbeat, shaping or a finite idle timeout so vanished clients release their lease and slot.

**OpenVPN parity + reconnect behaviour (`persist_tun` and the platform route keys are C#
desktop-only; carrier source binding also applies to the Linux CLI):**
- `persist_tun` (`true`/`false`, default `false`) — keep the TUN adapter + routes UP across
  reconnects until the user disconnects (no adapter flicker / route gap; fail-closed during the
  reconnect window). If the assigned IP or physical gateway/DNS topology changes, the adapter and
  its routes/resolver state are rebuilt.
- `local = <ip>` — bind the carrier socket to a specific local address on Linux/Windows/macOS
  (egress selection on a
  multi-homed host). **Important when the client and server are on the same LAN.** When `local`
  is set the client does **not** pin the /32 route to the server via the physical gateway (the
  carrier follows the bound interface's routing). If the server is on-link (same subnet as the
  client), pinning it via the gateway creates an asymmetric path and the tunnel dies right after
  the handshake (reconnect loop) — set `local` to this host's LAN IP so the server is reached
  directly. See TROUBLESHOOTING §6.8.
- `lport = <port>` — bind the primary carrier socket to a fixed local source port (for firewall
  rules). Bonded TCP members keep `local`, but use ephemeral ports because simultaneous streams
  to the same server cannot share one TCP four-tuple.
  An omitted value or explicit `lport = 0` selects the normal OS-assigned ephemeral port.
  <!-- normative-sync: udp-source-tuple-reuse-q36-v1 -->
  For UDP, reconnecting from the same external address and source port may wait for
  removal of the previous authenticated server session. A new unauthenticated ClientHello
  does not replace a live session. Removal follows the server idle timeout and negotiated
  liveness checks; it is not necessarily controlled by the client's `timeout`.
  For this timeout, use a different source port or wait for the old session to be removed.
  `lport = 0` lets the OS choose a port but does not guarantee that the previous port will
  never be assigned again; NAT also determines the external port.
- `dev_node = <name>` — name the Wintun adapter manually (Windows; otherwise auto `Qeli-<hash>`).
- `metric = <n>` — TUN interface routing metric (Windows; lower = higher priority). Applied to
  **both IPv4 and IPv6** via the WinAPI `SetIpInterfaceEntry` (no `netsh`; falls back to `netsh` on failure).
- `route_file = <path>` — **Windows/macOS clients only** (the Rust CLI does not read this key
  and silently ignores it): extra split-tunnel routes from a file of CIDRs (one per line,
  `#`/`;` comments), in addition to the profile's routes. On the Rust CLI use `include`/
  `exclude` directly in the config for the same effect.
  The key may be repeated; all files are loaded in declaration order and duplicate networks are
  removed. A source may contain either plain CIDRs or OpenVPN `route <network> <netmask>` /
  `route-ipv6 <CIDR>` lines. Invalid or unreadable input aborts the connection instead of
  silently omitting requested routes. On Windows, only the authenticated tunnel-pool prefix is
  on-link; imported networks use the authenticated tunnel gateway, so they do not create a
  broadcast `/32` for every imported subnet.
The next two keys are **not** C#-only: the Rust CLI parses them too (there's a round-trip
test), unlike the rest of this block.
- `keepalive = <secs>` (default `60`) — TCP keepalive probe interval (seconds) on the carrier
  socket (`SO_KEEPALIVE` / `TCP_KEEPIDLE`). Emitted only when non-default.
- `tcp_nodelay = <true|false>` (default `true`) — disable Nagle's algorithm on the carrier socket
  (send small packets immediately, lower latency). Set `false` to re-enable Nagle. Emitted only
  when non-default.
- `recv_buffer_size = <bytes>` — `SO_RCVBUF` on the **UDP socket** (`proto = udp`). When
  the key is absent, the core starts at `4194304` (4 MiB) and grows, only on measured local
  pressure, through 8 to 16 MiB. Growth uses the exact per-socket Linux/Android kernel-overflow
  counter when `/proc` is accessible, plus the traffic volume required to survive the measured
  scheduler stall; wire sequence gaps alone never trigger it. A live buffer is never shrunk. Any explicit value,
  including `4194304`, fixes the size; `0` leaves the OS setting alone. Explicit values are
  limited to 64 MiB per socket.

  On the server this per-socket controller is also bounded by a **process-wide memory budget**.
  Before save/start qeli counts every enabled UDP profile, extra listener and SO_REUSEPORT
  worker, reserves explicit send/receive requests (including Linux's doubled kernel accounting),
  and limits the automatic maximum to a fair share of 12.5% of currently available RAM. A
  configuration whose fixed requests exceed that budget, or whose queue count leaves less than
  256 KiB per automatic socket, is rejected. Thus `4 → 8 → 16 MiB` remains the ceiling for a
  normal host, not a promise to allocate it independently 256 times.
- `send_buffer_size = <bytes>` (default `0` — leave the kernel alone) — `SO_SNDBUF` on the UDP
  socket. The default differs on purpose: an undersized send buffer does **not** lose data
  (`sendto` just applies backpressure), so raising it rarely helps — while pinning an explicit
  value would *lower* the buffer on a host whose `net.core.wmem_default` was raised for this very
  workload.

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
# extra routes from any number of files
route_file = C:\qeli\routes.txt
route_file = C:\qeli\openvpn-routes.txt
# these subnets bypass the tunnel (go direct)
exclude = 192.168.50.0/24, 10.20.0.0/16
```

#### How to attach and populate `route_file`

`route_file` sends the listed networks **into the tunnel**. It is not a bypass list; use
`exclude` for destinations that must stay outside. The normal setup is Windows/macOS in
split-tunnel mode:

1. Open the profile's manual INI editor.
2. Set `gateway = false`.
3. Add one `route_file = <path>` line per file. The key is repeatable; files are read in
   declaration order and duplicate networks are installed once.
4. Save and connect. An unreadable file or invalid line aborts the connection fail-closed so
   traffic cannot escape merely because a requested route was omitted.

Use an absolute path where possible. Windows backslashes are literal and the whole value after
`=` is the path, so even a path containing spaces is written **without quotes**:

```ini
[qeli]
gateway = false
route_file = C:\Users\Alice\Qeli routes\corp-cidrs.txt
route_file = C:\Users\Alice\Qeli routes\openvpn-routes.txt
```

Each route file accepts these forms:

| Form | Example | Result |
|---|---|---|
| IPv4/IPv6 CIDR | `10.20.0.0/16` | network is sent into the tunnel |
| OpenVPN IPv4 + netmask | `route 172.16.9.7 255.255.0.0` | canonicalized to `172.16.0.0/16` |
| OpenVPN CIDR | `route 192.0.2.0/24` | `192.0.2.0/24` |
| OpenVPN host route | `route 192.0.2.7` | `192.0.2.7/32` |
| OpenVPN IPv6 | `route-ipv6 2001:db8:42::/48` | `2001:db8:42::/48` |

Exported OpenVPN `[gateway] [metric]` fields may follow an IPv4 netmask, for example
`route 172.16.0.0 255.255.0.0 vpn_gateway 10`. They are accepted for compatibility but do not
select the next hop: the client always uses the authenticated tunnel gateway.

<!-- normative-sync: route-file-net-gateway-issue69-v2 -->

`net_gateway` in `route`/`route-ipv6` lines is rejected by the shared parser with
its filename and line number (case-insensitive). In OpenVPN this means bypassing
VPN through the ordinary gateway; importing it as a tunnel inclusion would reverse
its meaning. Remove, for example, `route 192.0.2.0 255.255.255.0 net_gateway` from
the route file and, if bypass is intended, explicitly set `exclude = 192.0.2.0/24`
under `[qeli]`. For IPv6 use, for example, `exclude = 2001:db8::/32`. Import never
creates exclusions automatically: on failure the entire route-file set is not
applied and connection fails. `net_gateway` inside a comment has no effect.

Blank lines and full-line or inline `#`/`;` comments are ignored:

```text
# Office networks
10.20.0.0/16      # office LAN
192.0.2.0/24      ; test segment
route 172.16.0.0 255.255.0.0 vpn_gateway
route-ipv6 2001:db8:42::/48
```

Addresses with host bits are canonicalized and duplicates across all files are removed. IPv4
netmasks must be contiguous; arbitrary text, a bare IP without `route`, a malformed mask, or
more than 250,000 total routes is an error.

<!-- normative-sync: route-file-bounded-reader-q26-v1 -->

Windows/macOS limit each line to 65,536 .NET characters (UTF-16 code units), including
comments. Batches sent to the shared parser contain at most 512 lines and 131,072 characters;
long Unicode comments cannot overflow the service request. Reading checks cancellation
between 4096-character chunks, including before a long line ends.
Reading and installation can be interrupted with Disconnect. In full-tunnel mode `route_file` is unnecessary and is not applied (except desktop
per-app mode).

#### OpenVPN `net_gateway`: moving VPN bypasses to `exclude`

VPN bypasses use the existing `exclude` setting. A `route_file` contains tunnel
inclusions; the shared import check applies to Windows/macOS. For example, an
original OpenVPN `routes.txt` contains:

```text
route 10.20.0.0 255.255.0.0 vpn_gateway
route 192.0.2.0 255.255.255.0 net_gateway
route-ipv6 2001:db8:ffff::/48 net_gateway
```

Connecting stops the import at line two:

```text
routes.txt:2: net_gateway routes bypass the VPN and cannot be imported into route_file; move this network to [qeli] exclude instead
```

Line numbers start at the beginning of the corresponding file, including comments
and blank lines. The check also recognizes `NET_GATEWAY`, `"net_gateway"`, and
`'net_gateway'`. Even valid lines from this file set are not partially installed;
the connection fails.

To migrate, keep only the first line in `routes.txt`. Add exclusions to the
existing client profile, preserving its other connection settings:

```ini
[qeli]
gateway = false
route_file = C:\qeli\routes.txt
exclude = 192.0.2.0/24, 2001:db8:ffff::/48
```

Save and reconnect: `10.20.0.0/16` goes through VPN, while excluded networks use
the physical path of the corresponding IP family. Those networks must already be
reachable through the physical network; `exclude` does not create external
connectivity. Append to an existing `exclude` list using commas.

Full-tunnel (`gateway = true`) uses the same exclusions; `route_file` is normally
not read (except desktop per-app mode). With desktop `kill_switch` enabled in
system full-tunnel mode, excluded traffic is blocked rather than permitted outside
VPN. Import never changes the kill switch or creates exclusions automatically.

#### Distinguishing service routes from `route_file`

An L3 TUN deliberately assigns the client address as a host prefix (`/32` for IPv4 and `/128`
for IPv6), while the pool from `on_link_prefix_len` is installed as a separate connected route.
For a `10.8.0.2` client, `10.8.0.1` gateway/DNS and `10.8.0.0/24` pool, Windows may therefore show:

- `10.8.0.2/32` — the local client address;
- `10.8.0.0/24` — the VPN pool's only on-link network;
- a system pool host/broadcast route such as `10.8.0.255/32`, which Windows may synthesize;
- `10.8.0.1/32` — a protected NetworkPlan DNS route, not a `route_file` result.

An imported `1.0.0.0/24` line must produce exactly `1.0.0.0/24` through the authenticated
tunnel gateway. An extra `1.0.0.255/32` or another network/broadcast host route for that imported
network is a bug. When inspecting the table, keep VPN-pool service routes, protected DNS routes,
and file-imported routes separate.

Keepalive, graceful FIN on disconnect, the amber connecting indicator, ISO-8601 log timestamps and
the per-profile Wintun adapter name work **automatically** — no configuration needed.

### Comments, ready-made examples and saving the file

> **⚠️ Comments — on a separate line only** (a leading `#`). An inline comment
> after a value (`port = 443  # https`) is NOT stripped and will end up in the value.

Fully documented examples — [server.conf](../../../qeli/config/server.conf),
[client.conf](../../../qeli/config/client.conf), [users.conf](../../../qeli/config/users.conf),
[server-maxobf.conf](../../../qeli/config/server-maxobf.conf). Default paths:
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

These settings are optional: baseline defaults live in `ProfileConfig::baseline()`,
are used by the INI loader, and are exposed to the panel by `/api/config/defaults`.
Explicit zeroes for `perf.connection.handshake_timeout_secs` and
`perf.connection.max_clients` do not mean "use the default" and are rejected. Manual
tuning uses only flat `perf.*` keys inside `[profile:<name>]`. Example profile:

| Key | Default | Purpose |
|---|---|---|
| `bind.address` | `0.0.0.0` | carrier listen address |
| `bind.port` | `443` | carrier listen port; `1..65535`, zero is rejected |
| `bind.transport` | `tcp` | outer transport |
| `tun.name` | `vpn0` | server interface name |
| `tun.mtu` | `1400` | server ceiling; client auto MTU adopts the authenticated push |
| `tun.queues` | `0` | `0` selects the available CPU count at startup |
| `obf.mode` | `fake-tls` | wire mode before authenticated negotiation |
| `obf.obfs_key` | — | shared secret required for obfs |
| `obf.obfs_fronting` | `websocket` | obfs fronting; must match the client |
| `identity_key` | — | optional identity-key path; omitted = generated per-profile path |
| `listen` | `[]` | extra address:port listeners, one per repeated line; the primary bind is separate |
| `pool.exclude` | `[]` | extra IPv4 addresses excluded from allocation; the server address is always reserved |
| `pool.reservation.<user>` | `{}` | fixed IPv4 leases; one unique full key per user |

```ini
[auth]
users_file = /etc/qeli/users.conf

[logging]
level = info
file = /var/log/qeli/server.log
# timestamp: datetime (default) | rfc3339 | time | epoch | none
time_format = datetime

[profile:tcp]
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.9.0.1
tun.ip_mode = dual
tun.ipv6_address = fd71:e1:8000:100::1
tun.mtu = 1400
# Single source for the server/client prefix, allocation pool, and DHCP subnet.
pool.cidr = 10.9.0.0/24
pool.ipv6.cidr = fd71:e1:8000:100::/64
routing.nat.enabled = true
routing.ipv6.mode = nat66
routing.ipv6.interface =
routing.forward_private = true
dns.enabled = true
dns.listen = 10.9.0.1
dns.listen_ipv6 = fd71:e1:8000:100::1
dns.upstream = 1.1.1.1, 2606:4700:4700::1111
obf.mode = fake-tls
obf.recordizer.policy = prefer
obf.recordizer.batch.delay_min_ms = 2
obf.recordizer.batch.delay_max_ms = 8
obf.recordizer.batch.max_packets = 16
obf.recordizer.batch.max_queue_bytes = 262144
obf.recordizer.record.max_payload_bytes = 0
obf.recordizer.record.small_min_ratio = 0.25
obf.recordizer.record.small_max_ratio = 0.875
obf.recordizer.record.full_probability = 0.72
obf.recordizer.fragment.enabled = true
obf.recordizer.fragment.reassembly_timeout_ms = 3000
obf.recordizer.fragment.max_inflight_packets = 64
obf.recordizer.fragment.max_reassembly_bytes = 4194304
obf.recordizer.fragment.max_fragments_per_packet = 64
obf.padding.enabled = true
obf.padding.min_bytes = 32
obf.padding.max_bytes = 256
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
obf.heartbeat.jitter_ms = 5000
perf.tcp.nodelay = true
perf.tcp.keepalive_secs = 60
perf.tun.read_buffer_size = 65535
perf.connection.max_clients = 128
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 300
```

(A full, exhaustively commented example — [server.conf](../../../qeli/config/server.conf); a
runnable dual-stack deployment — [server-ipv6.conf](../../../qeli/config/server-ipv6.conf)).

## Server network-rule cleanup

One profile-cleanup attempt, startup worker cleanup or final verification receives
15 seconds for lock admission and firewall commands. IPv4/IPv6 and retired DNS UDP/TCP
share the deadline; a late deletion acknowledgement is not success. Unverified exact
rules remain in worker memory for retry. After process exit, inspect leftovers separately;
historical tag sweeps do not guarantee removal of unlistable mixed nft rules. This is
not a whole-shutdown bound: profiles use separate calls, and synchronous sysctl/I/O
may return after the deadline. NAT44, IPv4 forwarding and managed IPv6 routing each receive 15 seconds for setup,
including queue time and commands. An error starts exact rollback with a separate shared
15 seconds; incomplete rollback retains records and returns an error. DNS INPUT and
REDIRECT share 15 seconds for setup; their cleanup operations have separate deadlines.
[Limits and validation](../reports/audit-0.8.2/AUDIT-Q14-NAT-SETUP-BUDGET.md).
[Description and validation](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP-BUDGET.md).

Setup of one DNS INPUT ruleset receives 15 seconds including admission and cleanup of
previous retired generations. UDP/TCP share this deadline. Lease Drop/cleanup receives
a separate 15 seconds including locks and both transports; this is also the rollback
budget after partial setup. Retirement is published before waiting for a mutex, so a
timeout cannot strand an active entry without its lease. Unverified rules remain for
explicit retry in the same worker. These budgets do not guarantee whole-DNS-setup or
shutdown time. [Description and limits](../reports/audit-0.8.2/AUDIT-Q14-DNS-INPUT-BUDGET.md).

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
- Explicit values: `1..=256`; a larger value is rejected during config validation
  rather than silently clamped.
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
  [BENCHMARK.md](../reports/BENCHMARK.md).

## Tunnel MTU (`tun.mtu`) and the push to the client

The server sets the MTU of its TUN via `tun.mtu` (per-profile, default 1400) **and
pushes this value to the client** at auth.

> **The accepted range is `576..=16602`, and it is hard.** 576 is the IPv4
> minimum reassembly buffer (RFC 791). The ceiling is **derived from the PacketCodec record
> format**, not chosen: each complete inner IP packet must first fit one encrypted record
> (nonce + counter + payload + padding + tag) inside `MAX_RECORD_SIZE`. Negotiated
> `UDP_DATA_FRAG_V1` can split that already-encrypted record into authenticated UDP envelopes,
> but it cannot make an over-format inner packet valid. The old flat 9000 ceiling
> ("conventional jumbo") was an Ethernet convention that rejected otherwise workable setups;
> a 10G NIC using 16348-byte frames can carry a much larger tunnel. Mind the units:
> `tun.mtu` is the **inner** interface MTU, not the outer UDP-datagram budget.
>
> A value outside the range is no longer **silently discarded with a fallback to the
> default**: the server refuses to start the profile (`profile '<name>': tun.mtu <N> is out of
> range — expected 576..=16602`) and the client rejects the link/config (`invalid mtu <N> —
> expected 0 (auto) or 576..=16602`). A peer without `UDP_DATA_FRAG_V1` still has to send one
> complete record in one UDP datagram, which is another reason to keep the explicit bound.
> On the client `0` still means "auto" and need not be in range.

Priority on the client:

1. **an explicit client MTU** (`mtu` in the `[qeli]` INI or the `qeli://` link, `> 0`) — wins;
2. otherwise (auto, `mtu = 0`) — the authenticated **server-pushed inner MTU**;
3. otherwise (an old server pushing nothing) — a fallback inner MTU of **1400**.

**`mtu = 0` on the client = "auto" (this is the default).** On a negotiated modern UDP
session, the inner MTU and the outer datagram size are deliberately independent:

- **UDP transports** (obfs-UDP / fake-tls-UDP / QUIC) actively probe the real path before
  bringing the tunnel up. The client sends DF-marked probe datagrams from the selected inner MTU
  down (the server echoes them) and records the largest complete **outer UDP payload** that
  traverses client → server without IP fragmentation. Probing also runs with an explicit
  `mtu > 0`: this selects the inner TUN MTU rather than disabling outer-path discovery.
  With `UDP_DATA_FRAG_V1`, the inner TUN keeps the explicit/pushed MTU and an encrypted record that exceeds this outer budget is split
  into separately authenticated DATA_FRAG envelopes and exactly reassembled by the peer.
- A legacy peer cannot reassemble DATA_FRAG. With automatic MTU a successful probe
  lowers an IPv4 inner MTU to the certified record size. An explicit inner MTU is preserved;
  outer IP fragmentation remains enabled for legacy compatibility. IPv6/dual-stack keeps IPv6's mandatory
  1280-byte interface floor and restores outer fragmentation rather than failing every
  1280-byte IPv6 packet with `EMSGSIZE`.
- **`mtu_probe = false`** disables startup and live active probing for any `mtu` setting.
  The inner TUN retains the explicit value or adopts the authenticated push; a DATA_FRAG session uses the conservative outer UDP-payload floor (548 bytes
  over IPv4 or 1232 over IPv6) until a wider budget has actually been certified. Probing is
  implemented on **Linux/Windows/macOS/Android/iOS**. Linux/Android use `IP_MTU_DISCOVER`,
  Windows uses `IP_DONTFRAGMENT`, and Apple platforms use `IP_DONTFRAG`. If DF control is
  unavailable, the same conservative/fallback behaviour applies.
- **TCP transports** (reality-tls / fake-tls / obfs / plain): auto adopts the pushed inner MTU.
  The **kernel** discovers the outer path MTU there (`tcp_mtu_probing` + MSS clamping), so no
  application-level UDP probe or DATA_FRAG budget is involved.

The probe has four limits worth knowing before you treat MTU as a solved problem:

- **The two directions are certified separately.** The client's full-size DF ladder certifies
  client → server. Its authenticated UDP-budget report is only a ceiling for the opposite
  direction: the server starts at the family-safe 548/1232-byte floor, sends its own full-size
  DF probe server → client, and widens downlink only after the client echoes the exact tiny ACK.
  A genuinely asymmetric path therefore cannot borrow the uplink result for downlink. A lost
  report/probe is retried; an old peer or a peer that never answers remains at the safe floor.
  A local `EMSGSIZE` after a path change atomically drops the server back to that floor and
  retries the complete encrypted record with a new DATA_FRAG record id. The separate
  authenticated inner-MTU report remains in place for PMTU/ICMP handling. Older peers ignore
  the additive control type.
- **A DATA_FRAG session with `mtu_probe = true` re-probes a wider path every 10 minutes**,
  including when the inner MTU is explicit. The state machine
  uses the existing socket receive loop (there is no competing reader), tries only rungs above
  the currently certified uplink budget and requires three independently random exact
  challenge/ACK confirmations before widening it. A success atomically updates the record,
  fragmentation and control-padding budgets and re-sends the authenticated budget report so
  the server can run its own reverse-direction probe. If every larger rung times out, the
  current certified budget and DF state remain unchanged. Legacy peers are not live-widened
  because changing their carrier budget would require rebuilding the inner interface.
- **The bottom rung reaches exactly 1280 bytes of real path MTU** (the IPv6 minimum). The rung
  value describes the inner-shaped probe payload while the floor is computed as `1280 − outer
  overhead` (qeli probe framing + obfs seal + QUIC header + UDP/IP), so the narrowest probe is
  exactly 1280 bytes on the wire. It does not probe below that path size: an IPv6 path narrower
  than 1280 is outside the supported Internet minimum.
- **"No result" no longer makes a negotiated DATA_FRAG session guess an outer size.** Its inner
  TUN still adopts the explicit/pushed MTU, but outer records use the conservative family
  budget. A legacy session restores OS IP fragmentation because it has no record-layer split.

Practically: auto-probing handles **effectively all** LTE/CGNAT/PPPoE cases — a path narrower
than 1280 violates the IPv6 minimum. If downloads still stall while small packets flow, set
`mtu` by hand (1200–1280) and retest; §12 of GETTING-STARTED and TROUBLESHOOTING §6 cover the
diagnosis.

So the inner MTU is usually set **once in the server profile** (the ceiling), while UDP clients
refine the outer datagram budget per path. Nothing in client configs/links needs changing (`qeli://`
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
> [BENCHMARK.md](../reports/BENCHMARK.md).

## Push to clients — what the server hands over on connect

After successful authentication the server sends encrypted JSON `OK:{…}`. Capable peers receive
NetworkPlan v2 while the same object retains a legacy projection for old IPv4 clients.
**The `qeli://` link does NOT carry any of it** — the
link is only about *how to connect*; everything else arrives via the push, which is why it can
be changed on the server **without re-issuing links** (see "What is NOT pushed" below).

### The complete push payload

| field | source in the server config | what the client does with it |
|---|---|---|
| `family_mode` | negotiated `ipv4` / `dual` / `ipv6` | selects the families applied atomically |
| `addresses` | IPv4/IPv6 allocation, reservations and `static_ip`/`static_ipv6` | typed addresses with assigned prefix, on-link prefix and gateway; L3 TUN uses `/32`/`/128`, TAP keeps the pool prefix |
| `client_ip` / `server_ip` / `prefix` | projection of IPv4, or the sole IPv6 address in an IPv6-only plan | backward-compatible fields; a v2 client verifies that they agree with `addresses` |
| `mtu` | the profile's `tun.mtu` | a client on `mtu = 0` (default, auto) **adopts** it; a client with its own `mtu > 0` keeps it |
| `dns_servers` | `dns.push_servers` or the active IPv4/IPv6 proxy listeners | typed resolver list, restricted to negotiated families and applied only with `dns = tunnel` |
| `dns` | first compatible resolver | legacy resolver projection Linux checks actual `nameserver` entries in `/etc/resolv.conf`: only stub `127.0.0.53`/`127.0.0.54`, without external fallback; symlink names/comments do not prove this path. Regular file, up to 64 KiB. [Contract](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONFIG.md). |
| `dns_port` | always **53** | no client platform can express another port (neither `VpnService.Builder` nor `NEDNSSettings` takes one), so 53 is pushed unconditionally; when the proxy listens elsewhere the tunnel redirects 53 → `dns.port` with an iptables rule |
| `routes` | the user's **personal** routes, otherwise the profile's `route =` | installs the routes (since 0.7.12 — **always**) |
| `obfuscation` | `obf.padding.*`, `obf.heartbeat.*`, `obf.traffic_normalization.*`, `obf.traffic_shaping.*` | applies the obfuscation parameters live |
| `session_token` | generated per session | the bonding join token |
| `max_streams` | `obf.multipath.max_streams` (when `obf.multipath.enabled`) | how many parallel connections to open |
| `multipath_adaptive` | `obf.multipath.adaptive` | auto-ramp the stream count |

An empty `dns` = the client keeps its own resolvers. The default `dns.listen` (`10.9.0.1`) is
pushed **only** when the in-tunnel proxy actually runs — otherwise it resolves nowhere and would
black-hole the client's DNS.

> **Clients never invent public DNS resolvers.** With `dns = tunnel`, the shared plan
> selects the profile's `dns_servers`, then the server push. Without a resolver, a split
> tunnel leaves system DNS unchanged, while a full tunnel refuses to connect. Configure
> `dns_servers`, enable server DNS push, or use `dns = off` / `system` when the platform
> deliberately manages DNS itself.

Legacy IPv4 push (`dns`/`dns_port`) and the v2 `dns_servers` array use the same validation.
A selected resolver must be an IP address in an active tunnel family; up to eight resolvers
and nonzero ports are accepted. A malformed selected push fails connection setup instead
of silently falling back to host DNS. Explicit client `dns_servers` override the push;
`dns = off` / `system` disables its application.

The shared plan adds a tunnel `/32` or `/128` route for every resolver, including split
mode and DNS outside the VPN subnet. Broad route exclusions preserve that DNS host route;
an exact DNS host exclusion is rejected as contradictory. In Linux `dev_attach` mode,
the external interface owner is responsible for routes, including DNS reachability.

CIDR exclusions are subtracted as a union, independently of order and duplicates. The
256-route limit applies to the final set; temporary fragmentation caused by an early
narrow exclusion must not reject a plan when a later exclusion removes those pieces.

### Routes (`route`) in detail

> ⚠️ **`gateway` and `metric` do not reach every client.** All of them apply the CIDR, but
> the optional fields differ. The **Rust client** honours both the next hop and the metric.
> **Android** reads them. The **desktop (C#)** clients read them but cannot apply them —
> their routes are scoped to the tunnel interface — and they say so in the log
> (`next-hop/metric not settable here`); traffic still enters the tunnel and the server
> forwards it. **iOS** takes only `cidr` from the push and drops both fields **silently**.
> Practical consequence: do not rely on a pushed next hop or metric as a route-priority
> mechanism — on some clients it simply is not there.

**Where to put it.** Inside `[profile:<name>]`. The key is **repeatable** (several lines = several routes):

```ini
[profile:tcp]
tun.address = 10.9.0.1
route = 172.16.20.0/24
route = 10.20.0.0/16 gateway=10.9.0.1 metric=100
```

**Format:** `route = <cidr> [gateway=<next-hop-ip>] [metric=<n>]`

| part | required | rule |
|---|---|---|
| `<cidr>` | **yes** | **first and bare** (or explicitly `cidr=<…>`). E.g. `172.16.20.0/24` |
| `gateway=` | no | the **next-hop IP, NOT a subnet**. Defaults to the active gateway of the same family: `tun.address` for IPv4 or `tun.ipv6_address` for IPv6 |
| `metric=` | no | defaults to `100` |

> ⚠️ **Keys that do NOT exist in the INI:** `advertised_routes`, `push_routes`,
> `routing.advertised_routes`, `routing.routes`. `push_routes` is an internal serde **alias**, not
> part of the supported flat-INI runtime surface. The real INI is parsed separately. An
> unknown key is **silently ignored**, so the route simply never exists.

**Personal routes OVERRIDE the profile's — they do not merge.** The server's logic is
`find_user(username).filter(|u| !u.routes.is_empty())` →

- the user has **≥1** own route → the client gets **only those**; the profile's `route =` lines
  are ignored **entirely**;
- the user has **0** own routes (or an empty list) → the profile's routes are used.

Personal routes live in `[user:<name>]` (`users.conf`) or in the user's card in the panel.

`0.0.0.0/0` and `::/0` are the deliberate exception: they are exit-node authorization
markers, not ordinary pushed routes. The server does not put them in AuthOK and therefore
cannot silently force a client into full tunnel; the consumer opts in with local
`gateway = true`. See [Exit node](#exit-node-exit_node).

### When the push works — and when it doesn't

| situation | result |
|---|---|
| a correct non-default `route = <cidr>`, client **≥ 0.7.12** | ✅ installed; **no client-side flag needed** |
| `route = 0.0.0.0/0` / `::/0` | server-side exit authorization only; consumer needs local `gateway = true` |
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
`gateway_nat`/`lan_subnet`, `post_up`/`post_down`, `autostart`, `apps_mode`/`apps`.

Exactly what a `qeli://` link carries — parameter by parameter — is in
[What a `qeli://` link carries](#what-a-qeli-link-carries). In short: the address, the
credentials and the handshake parameters, i.e. **only what the client cannot learn any other
way**. Routes and DNS are not in it by design.

## Server OS tuning (sysctl + iptables) — MANDATORY for production

These are **server operating-system settings**, not the qeli config. Without them,
TCP modes (reality-tls/fake-tls/obfs-tcp) on real (especially mobile) clients
**break the connection under load and choke the speed**. Apply on every VPN server.

### 1. MSS clamping (CRITICAL — otherwise downloads break)

Traffic from the internet arrives at the client via NAT with an MSS for a 1500-byte
path, but it doesn't fit inside the tunnel (`tun.mtu`, e.g. 1280); if the
"fragmentation needed" ICMP is lost, you get a **PMTU black hole**: large packets
are silently dropped, small ones pass → the download hangs, the client drops on
timeout. The cure is clamping forwarded TCP to the tunnel MTU: `tun.mtu−40` for
IPv4 and `tun.mtu−60` for IPv6.

> **If the profile has `routing.nat.enabled` (or `routing.forward_private`) — you do
> NOT need these rules: qeli installs them itself.** On profile start it enables
> `ip_forward`, adds MASQUERADE, `FORWARD … ACCEPT` rules and **two `TCPMSS` clamps per
> active family** (`tun.mtu−40` for IPv4, floored at 536; `tun.mtu−60` for IPv6, floored
> at 1220), tags them `qeli-nat:<profile>` and
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
tmp=$(mktemp /etc/iptables/rules.v4.qeli.XXXXXX) && iptables-save >"$tmp" && \
  test -s "$tmp" && iptables-restore --test <"$tmp" && chmod 600 "$tmp" && \
  mv -f "$tmp" /etc/iptables/rules.v4

# IPv6 inner TCP: MSS = tun.mtu(1280) − IPv6(40) − TCP(20) = 1220.
ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o vpn+ -j TCPMSS --set-mss 1220
ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i vpn+ -j TCPMSS --set-mss 1220
tmp=$(mktemp /etc/iptables/rules.v6.qeli.XXXXXX) && ip6tables-save >"$tmp" && \
  test -s "$tmp" && ip6tables-restore --test <"$tmp" && chmod 600 "$tmp" && \
  mv -f "$tmp" /etc/iptables/rules.v6
```
> If you change `tun.mtu`, recompute IPv4 MSS as `MTU−40` and IPv6 MSS as `MTU−60`.
> The persistence commands in this section atomically replace `rules.v4`/`rules.v6`; run them
> only when those files are your managed snapshots. Otherwise use your firewall manager.

**The outer handshake (reality-tls/fake-tls on LTE) — a separate clamp.** The rule above
is for traffic INSIDE the tunnel (`vpn+`). But reality-tls with `real_tls=true` sends a
**real Chrome ClientHello carrying the post-quantum share (X25519MLKEM768) ~1700 B** over
the **outer** TCP to `:443` — and on that connection the MSS is **not clamped** (the server
advertises ~1460 from the 1500 WAN MTU). On LTE/CGNAT (path MTU ~1400) a 1460-byte segment
doesn't fit, mobile networks drop the ICMP "frag needed" → the same **PMTU black hole**, but
now on the **handshake** itself: works on wired, hangs on LTE. The cure is clamping the MSS
advertised by both peers on the server's **outer TCP ports** (reality / fake-tls / obfs):

```bash
# PREROUTING clamps the client's SYN (therefore server→client ServerHello segments);
# OUTPUT clamps the server's SYN-ACK (therefore client→server ClientHello segments).
# MSS 1240 means ≤1280-byte IPv4 packets and survives the conservative mobile/CGNAT
# baseline; it is harmless on wired. If the measured path is below 1280, use path-MTU − 40.
for p in 443 8443 8444 8445; do
  iptables -t mangle -A PREROUTING -p tcp --dport $p --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
  iptables -t mangle -A OUTPUT -p tcp --sport $p --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
done
tmp=$(mktemp /etc/iptables/rules.v4.qeli.XXXXXX) && iptables-save >"$tmp" && \
  test -s "$tmp" && iptables-restore --test <"$tmp" && chmod 600 "$tmp" && \
  mv -f "$tmp" /etc/iptables/rules.v4

# If those ports also listen on IPv6: 1280 − IPv6(40) − TCP(20) = MSS 1220.
for p in 443 8443 8444 8445; do
  ip6tables -t mangle -A PREROUTING -p tcp --dport $p --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
  ip6tables -t mangle -A OUTPUT -p tcp --sport $p --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
done
tmp=$(mktemp /etc/iptables/rules.v6.qeli.XXXXXX) && ip6tables-save >"$tmp" && \
  test -s "$tmp" && ip6tables-restore --test <"$tmp" && chmod 600 "$tmp" && \
  mv -f "$tmp" /etc/iptables/rules.v6
```
> The ports are the `bind.port` of your **TCP** profiles. `tcp_mtu_probing=1` (below) does
> not replace these clamps: it can recover later *server* sends, but cannot resize the
> client's first large ClientHello, whose segment size follows the MSS the server advertised.

### 2. sysctl: BBR + buffers + MTU probing

BBR uses a bandwidth/RTT model; results depend on the path and kernel version.
High-RTT TCP also needs sufficient buffer limits and enabled autotuning. This is
a system-wide Linux server tuning profile, not a throughput or loss-free guarantee.
Size limits separately for low-memory routers.

```ini
# /etc/sysctl.d/99-qeli-perf.conf  (apply: sysctl --system; module: modprobe tcp_bbr)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_moderate_rcvbuf=1
net.ipv4.tcp_mtu_probing=1
# UDP has no OS receive autotuning. In automatic mode qeli requests 4 MiB
# and may grow to 16 MiB, so rmem_max must
# allow the whole auto range; these defaults also protect older builds and other UDP
# sockets. qeli exposes the effective size and overflow counters in logs/stats.
net.core.rmem_default=4194304
net.core.wmem_default=4194304
net.core.netdev_max_backlog=4000
```
```bash
modprobe tcp_bbr && echo tcp_bbr > /etc/modules-load.d/qeli-bbr.conf   # load the module at boot
sysctl --system                                                       # apply
sysctl -n net.ipv4.tcp_congestion_control                             # check: should be bbr
systemctl restart qeli.service                                        # UDP sockets take the buffer size at creation
ss -ulnm | grep -A1 ':8449' | grep -o 'rb[0-9]*'                      # Linux usually reports twice the SO_RCVBUF request
```

A UDP buffer can overflow during scheduling stalls or consumer overload. Datagram
loss can trigger inner TCP retransmissions; larger buffers cannot fix sustained
overload. Check `netstat -su`, the `d<N>` field in `ss -ulnm` and Qeli metrics.
Linux usually reports twice the requested `SO_RCVBUF` in `rb`: a 4 MiB request
typically gives `rb8388608`, and 16 MiB gives `rb33554432`, unless the kernel clamps
the request. Compare with Qeli logs rather than `rmem_default`. Current Qeli
requests its UDP buffer explicitly; `rmem_default=4 MiB` is not a prerequisite
for its autotuning. `rmem_max`, its RAM budget and manual keys matter instead.

For TCP check `sysctl net.ipv4.tcp_moderate_rcvbuf net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_mem`.
`tcp_moderate_rcvbuf` must be `1`. `tcp_rmem`/`tcp_wmem` are min/default/max byte
triples; 16 MiB here limits growth of an individual buffer, not preallocated memory.
The global `tcp_mem` budget is in pages and is left unchanged by the installer.
Also set server `perf.tcp.send_buffer_size = 0` and `perf.tcp.recv_buffer_size = 0`
in the intended `[profile:...]`; a nonzero value disables autotuning for that
buffer. Inspect actual buffers on active connections with `ss -tinmp`.

### 3. padding for reality-tls — better turned off

`obf.padding` (40–400 B per packet) is useless for reality-tls (the traffic is
already inside real TLS — padding isn't visible from outside) but eats bandwidth.
In a reality-tls profile: `obf.padding.enabled = false`.

> Verified in production: BBR/buffers/mtu_probing + IPv4 `vpn+` MSS-clamp 1240
> (and IPv6 1220 when enabled) +
> `tun.mtu 1280` + padding off (2026-06-08), and the **outer TCP-port MSS** (443/8443/8444/8445)
> **1240** — the conservative reality/fake-tls outer-handshake baseline for a 1280-byte
> IPv4 path. Script: `scripts/prod_tcp_tune.py`.
> The UDP buffers (`rmem_default`/`wmem_default`) were added 2026-08-02: the 06-08 change
> raised only `rmem_max`, so the UDP profiles silently stayed at 208 KB.
> Installer rollback: inspect the matching run receipt under
> `/etc/qeli/client-links/kernel-tuning-*/restore.txt`; restore prior persistent files
> and saved runtime values. Deleting a sysctl file and running `sysctl --system` alone
> does not restore the previous state. Without a receipt, use your own baseline/backup.
> Remove only installer-added mangle rules; restore `tun.mtu`/padding separately.
> A loaded BBR module is not automatically unloaded. [Install and rollback details](GETTING-STARTED.md).

### 4. UDP profiles: inner MTU and the outer datagram budget

The no-split threshold for one complete UDP record is:

```
tun.mtu + 48 (qeli record/probe margin)
        + 13 (UDP obfs seal, when keyed)
        + 9  (QUIC, when enabled)
        + 8  (UDP)
        + 20 (outer IPv4) or 40 (outer IPv6)  ≤  PMTU
```

With negotiated `UDP_DATA_FRAG_V1`, crossing this threshold no longer asks IP to fragment the
oversized datagram. Qeli first encrypts the complete inner packet, then splits the opaque record
into authenticated envelopes (44-byte DATA_FRAG header per datagram), each constrained by the
probed outer UDP-payload budget, and reassembles the exact record before PacketCodec decryption.
This preserves inner IPv4/IPv6 packets and avoids outer IP fragmentation; the cost is more
datagrams, per-fragment authentication and reassembly work. The server starts at 548 bytes of
UDP payload for an IPv4 carrier or 1232 for IPv6 and widens only after an authenticated report
of a successful larger client probe. A peer without DATA_FRAG retains the one-record/one-datagram
behaviour, so the formula above remains a hard deployment constraint for mixed-version pairs.

**Padding is not a separate term.** It is clamped so that payload plus padding remains inside
the current record budget in both directions. `obf.padding.max_bytes` decides how much of that
budget padding may occupy, never how far past it a datagram may grow. Before this clamp, padding
really was added on top and could fragment every full-size packet. Adding `padding.max_bytes` to
the formula now double-counts it.

For example, without a keyed UDP obfs seal, `tun.mtu = 1380` plus QUIC occupies about 1465 bytes
on an outer IPv4 path or 1485 on IPv6; a keyed seal adds 13 bytes. If that is over the discovered
budget, DATA_FRAG splits the record. If you want padding to remain visible even on full inner
packets, leave room for it — `tun.mtu = 1240` with `obf.padding.max_bytes = 80` is a comfortable
udp-quic pair. `netstat -s | grep -i 'fragments created'` should not climb under load on modern
negotiated peers; DATA_FRAG is record-layer splitting and is not counted as kernel IP fragmentation.

> In production, removing the fragmentation alone took udp-quic from 22 to 30 Mbit; together
> with the server and client buffers it reached **40+ down and 55 up**.

## Stream bonding — multipath (`obf.multipath.*`)

Multipath opens several TCP connections to one server address and port; they
serve one session and one tunnel address. A hash pins each inner flow to one
connection instead of striping it across all connections. A single large download
therefore need not become faster; the result depends on the number of inner
flows and network conditions. Bonding alone does not guarantee DPI evasion.

With negotiated authenticated TCP resume, healthy logical slots remain stable
when another carrier disappears or returns. Legacy bearer-JOIN preserves
`hash % live stream count`: membership changes may remap other flows. Losing
the selected carrier can require inner TCP retransmission. A full pinned queue
drops the packet without spilling it onto another carrier or blocking other flows.

**Settings — per-profile** (like `tun.mtu`/`padding`), the server pushes them to
the client:

| Key | Default | Purpose |
|---|---|---|
| `obf.multipath.enabled` | `false` | enable negotiated stream bonding |
| `obf.multipath.max_streams` | `4` | per-session stream ceiling |
| `obf.multipath.adaptive` | `false` | grow the stream count adaptively |

```ini
[profile:reality-tls]
# enable bonding on this profile
obf.multipath.enabled = true
# server-enforced ceiling of ordinary active streams per session
obf.multipath.max_streams = 4
# false = target max_streams; true = auto-tune
obf.multipath.adaptive = false
```

- **`enabled`** (default `false`) — turn bonding on/off for the profile.
- **`max_streams`** (default `4`) — valid values are **1–16** when bonding is
  enabled; the server rejects values outside that range. This caps ordinary
  streams of one session. A prepared authenticated resume permits one temporary
  carrier above the cap; commit drains the replaced carrier, abort frees the candidate.
  `max_clients × max_streams` describes ordinary streams. Capacity planning must
  also include temporary candidates, handshakes and each connection's TCP/TLS buffers.
- **`adaptive`** (default `false`):
  - `false` — `max_streams` is the target. A failed secondary JOIN leaves fewer
    streams; the background maintainer retries without another AUTH.
  - `true` — starts at one stream and samples combined upload + download every
    3 seconds. Under load above 250,000 B/s it adds streams while throughput
    improves by more than 10%; after one extra observation window it stops at
    a plateau or the ceiling. There is no automatic downscaling; the maintainer
    restores the learned width after a carrier fails.

All session streams share the bandwidth limit **independently in each direction**:
8 Mbps permits up to 8 Mbps upload and 8 Mbps download, rather than 8 per stream.
The cover/stealth budget is shared too. Download quota uses aggregate session
counters; a secondary JOIN creates no new quota or session accounting entry.
Shared packet pools are bounded independently of stream count; per-carrier crypto
state, descriptor queues and socket/TLS buffers still consume additional memory.

Bonded uplink uses one additional snapshot pool of at most 4 MiB per session:
the native TUN/ring packet is released before its snapshot is queued. Each queue
receives a limited share so one blocked carrier cannot consume the whole pool.
Exhaustion drops the packet instead of allocating extra memory.


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

**Historical measurements before Q24** (lab, `tc netem`, download, 8 parallel
flows). These numbers have no recorded execution date or artifact SHA here and
were not rerun for Q24; they do not qualify the current build's peak throughput:

| link | 1 stream, Mbps | 4 streams, Mbps | gain |
|---|---:|---:|---:|
| clean | ~725–846 | ~805–815 | parity |
| RTT 40 ms, 0.05% loss | ~225–420 | ~692–704 | ~1.6–3× |
| RTT 80 ms, 0.1% loss | ~50–65 | ~260–305 | **~5×** |

Distribution is **per-flow** in the shared Rust core used by the CLI, desktop,
Android and iOS clients. With negotiated authenticated resume, the flow hash selects
one stable logical slot; otherwise legacy scheduling uses `flow_hash % live_streams`,
so a membership change can remap flows. One inner flow is never striped across
carriers. The core clamps the pushed ordinary stream limit to 16; the server also
enforces its profile limit. An authenticated prepared resume may temporarily add
one candidate socket. Traffic with several concurrent connections can benefit;
one lone flow stays on one carrier and does not automatically become faster.

## Flow shaping — cover traffic (`obf.traffic_shaping.*`)

Closes DPI tells **6.1** (flow shape = "download", not "browsing") and **6.2**
(periodic heartbeat beacon). While the tunnel is **idle**, the server emits cover
packets at gaps sampled **exponentially** (a Poisson process) instead of a fixed
heartbeat — no dead air, no metronome. A cover packet is an encrypted record with
an **empty payload**; the peer drops it (like a heartbeat) → **not wire-breaking**,
old clients stay compatible. Real packets are **never delayed** (Phase 1 = zero
added latency); only idle is filled, within a byte budget. When shaping is on it
**replaces** the heartbeat (which is disabled, so there is no double beacon).

| Key | Default | Purpose |
|---|---|---|
| `obf.traffic_shaping.enabled` | `false` | enable cover traffic |
| `obf.traffic_shaping.idle_gap_mean_ms` | `700` | mean idle gap, milliseconds |
| `obf.traffic_shaping.idle_gap_min_ms` | `40` | minimum idle gap, milliseconds |
| `obf.traffic_shaping.idle_gap_max_ms` | `6000` | maximum idle gap, milliseconds |
| `obf.traffic_shaping.budget_bytes_per_sec` | `16384` | cover budget; when enabled, at least max_size |
| `obf.traffic_shaping.min_size` | `64` | minimum cover-record size, bytes |
| `obf.traffic_shaping.max_size` | `1024` | maximum cover-record size, bytes |
| `obf.traffic_shaping.stealth` | `false` | enable the stealth rate limit |
| `obf.traffic_shaping.stealth_rate_mbps` | `2` | rate limit under stealth, Mbps |

```ini
# on (default false)
obf.traffic_shaping.enabled = true
# mean idle gap between cover packets (exponential)
obf.traffic_shaping.idle_gap_mean_ms = 700
# gap floor
obf.traffic_shaping.idle_gap_min_ms = 40
# gap cap (don't go dead on a long tail)
obf.traffic_shaping.idle_gap_max_ms = 6000
# cover-traffic ceiling, B/s; when enabled, must be at least max_size
obf.traffic_shaping.budget_bytes_per_sec = 16384
# cover packet size range
obf.traffic_shaping.min_size = 64
obf.traffic_shaping.max_size = 1024
# STEALTH (Phase 2): trade throughput for DPI passability.
obf.traffic_shaping.stealth = false
# data-plane rate cap under stealth (Mbps)
obf.traffic_shaping.stealth_rate_mbps = 2
```

- When shaping is enabled, `budget_bytes_per_sec` must be at least `max_size`.
  The server rejects a smaller budget because even one scheduled cover record could
  never acquire enough tokens; that would silently disable cover and liveness.
- `stealth_rate_mbps` must be positive only while `stealth = true`; its dormant value is retained
  when stealth mode is off.
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
throttles). The shaper does not deliberately change inner data-packet sizes. Independently,
negotiated UDP DATA_FRAG may split an encrypted record to satisfy the measured PMTU, but it is
not a configurable DPI packet-size shaper; TCP data remains full-sized. Per-mode speeds:
`scripts/bench_stealth.py`.

**When to enable:** only under aggressive DPI/ML that blocks high-rate tunnels. For
normal use it is overkill (needlessly slow). **Not wire-breaking** (cover = the same
empty records peers already drop). The server shapes the downlink for ALL clients;
every client (Rust, Windows/macOS, Android) shapes its own uplink (TCP only).

> **TCP wire modes only** (plain/fake-tls/obfs/reality-tls). On UDP, stealth was
> measured to crater throughput (lock contention under load → ~0), so it is
> **ignored on UDP profiles** — they keep Phase-1 idle cover. The main "download"
> case (reality-tls/fake-tls/obfs) is TCP anyway.

## Wire obfuscation modes (`obfuscation.mode`)

`mode` selects the wire carrier. New server profiles and clients use the canonical
`reality-tls` spelling. During migration a new server also accepts the legacy server label
`fake-tls` when `reality_proxy.enabled=true` and `real_tls=true`; a new client still sends
`mode=reality-tls`. `plain`/`obfs`/`reality`/`reality-tls` are TCP-only. UDP accepts the
supported UDP aliases/underlying `fake-tls` or `obfs` modes; Reality/H2 is unavailable on UDP.
| `mode` | Behavior | Against what | Notes |
|---|---|---|---|
| `"plain"` | No obfuscation: a raw X25519 key exchange and bare `[len][nonce][ct]` records (no TLS mimicry). An ordinary encrypted VPN tunnel | Nothing — on the wire a high-entropy flow with no recognizable protocol (which is itself a signal for entropy-based DPI) | The cheapest, speed ≈ fake-tls. **TCP only.** For trusted networks where DPI doesn't matter |
| `"fake-tls"` (default) | A pseudo-TLS-1.3 handshake (ClientHello with GREASE and a random extension order → JA3 changes), then the data plane in TLS-Application-Data records | Passive signature-based DPI | Cheaper on CPU; "looks like TLS" |
| `"obfs"` | The entire flow is XOR'd with a ChaCha20 stream key; the start of the connection is by default masked as a WebSocket Upgrade handshake (see `obfs_fronting`), then pseudo-random bytes | DPI that signatures *known* protocols (incl. fake-TLS/JA3) + entropy-based "fully encrypted" detection (GFW/TSPU) | Requires `obfs_key` (PSK) shared by server and client. ~11% overhead (double encryption) |
| `"reality-tls"` | REALITY TLS 1.3 negotiates ALPN `h2`; one long-lived bidirectional HTTP/2 POST carries the private qeli stream with randomized batching. Foreign connections are bridged to the target | Reduces known active-probe, TLS-fingerprint and record-boundary tells | Needs client `key` + `reality_sid` + matching `sni`; server `real_tls=true` + `short_ids`. Outer TLS AEAD plus inner qeli AEAD remains. **TCP only.** |

> **How to choose.** Use `reality-tls` for the strongest current TCP camouflage: genuine
> TLS 1.3 + H2 and target bridging for unauthenticated probes. This reduces the known tells in
> [DPI-AUDIT.md](../reports/DPI-AUDIT.md), but does not guarantee indistinguishability. `fake-tls` is
> cheaper and intended for passive/signature DPI; `obfs` targets fully-encrypted-flow heuristics;
> `plain` is for trusted networks. The installer and shipped stealth templates select
> `reality-tls`, while the generic schema baseline remains compatibility-oriented.

### Ready-made profile presets

The repo ships [`server-multiprofile.conf`](../../../qeli/config/server-multiprofile.conf)
with **ten** pre-built profiles (each on its own port) — you can run several wire modes on
one server and hand different users different entry points. Copy the `[profile:*]` section
you want into your config:

| Profile | Transport:port | `obf.mode` | When to use |
|---|---|---|---|
| `reality-tls` | tcp :443 | reality-tls | strongest current TCP masking: REALITY TLS 1.3 + genuine H2; unauthenticated probes are bridged to target |
| `reality` | tcp :8443 | fake-tls (+reality-proxy) | fake-tls that proxies "foreign" connections to a real site |
| `fake-tls` | tcp :8444 | fake-tls | the default balance against passive DPI |
| `obfs-ws` | tcp :8445 | obfs | ChaCha obfuscation under WebSocket fronting (needs `obfs_key`) |
| `obfs-none` | tcp :8446 | obfs | bare obfs, no fronting (legacy/fallback) |
| `plain` | tcp :8447 | plain | trusted networks, maximum speed |
| `udp-fake-tls` | udp :8448 | fake-tls | UDP transport with TLS mimicry |
| `udp-quic` | udp :8449 | fake-tls (+QUIC-shape) | shallow QUIC-shaped compatibility mode; not real QUIC/HTTP3 |
| `udp-obfs` | udp :8450 | obfs | UDP with ChaCha obfuscation |
| `obfs-awg` | tcp :8451 | obfs | obfs + AmneziaWG masking (junk preamble) |

> Except for the documented legacy Reality server label, the client uses the same `mode`
> (and `obfs_key`/`front`/`sni`, where applicable) as the selected profile. The complete
> working sections and every required key are in `server-multiprofile.conf`.

### `obfs_fronting` (anti-FET, only for `mode = obfs`)

The key `obf.obfs_fronting` (server) / `front` in the qeli:// link and the `[qeli]`
section (client). **Must match on server and client.** On a non-`obfs` server profile the
field is dormant, preserved without validation, and checked again if the profile is switched
to `obfs`.

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

`mode = obfs` is supported on both TCP and UDP and requires the same `obfs_key` on both
peers. TCP may additionally use `obfs_fronting`; fronting is not part of the UDP carrier.
`obfuscation.quic` is an independent optional UDP packet-shape wrapper and is not the
implementation of `udp-obfs`.

### REALITY (`mode = reality-tls`, keys `obf.tls.reality_proxy.*`)

"REALITY" in qeli has two layers, both in the server profile:

| Key | Default | Purpose |
|---|---|---|
| `obf.tls.reality_proxy.enabled` | `false` | enable REALITY handling of incoming connections |
| `obf.tls.reality_proxy.target` / `target_port` | `www.cloudflare.com` / `443` | the real site to which "non-ours"/probing connections are transparently proxied (e.g. `www.microsoft.com:443`) |
| `obf.tls.reality_proxy.short_ids` | `[]` | allow-list of "our" IDs decoded into 8 bytes; use 16 hex digits with a nonzero decoded value (shorter values are zero-padded, `:`/`-`/spaces are accepted) — the cryptographic discriminator (a token in `session_id`). **Required when `reality_proxy.enabled`**: with an empty list the server refuses to start. (An empty list used to fall back to a legacy "no ALPN" heuristic; it is trivially defeated by an active prober, so it is now rejected at startup.) |
| `obf.tls.reality_proxy.real_tls` | `false` | `true` → terminate real TLS 1.3 and run the automatic genuine H2 carrier (client `mode=reality-tls`); `false` → legacy fake-TLS wire with only the REALITY bridge/token |
| `obf.tls.reality_proxy.handrolled` | `true` | `true` → the hand-rolled TLS terminator: **borrows the target's real cert chain** (cert-borrowing — captured at profile start; **auto-refresh every 12h**) and mirrors its JA3S/ServerHello shape. `false` → rustls: a **self-signed** cert + its own JA3S (weaker camouflage). The default is `true`; this matches those certificate/ServerHello dimensions only, not complete browser/Xray/H2 behaviour. Requires `real_tls = true` |

- **proxy-bridge (`real_tls=false`):** the client sends `mode=fake-tls`; fake-TLS on
  the wire, but "foreign" handshakes go to `target` (an active prober sees the real
  site). Speed ≈ `plain`.
- **`reality-tls` (`real_tls=true`):** the client sends `mode=reality-tls`, a mandatory pinned
  `key`, matching `reality_sid`/`sni`, then negotiates ALPN `h2`. One long-lived HTTP/2 POST
  carries raw private qeli records with randomized batching; there is no second fake-TLS
  handshake and no H2 config key. Outer TLS AEAD plus the inner qeli AEAD remains. Templates —
  [release/reality-tls/](../../../release/reality-tls). Upgrade the server before clients: a new
  server accepts the legacy Reality carrier, while a new client does not downgrade to an old server.
- **Client and server clocks must agree within ±120 seconds** (when `short_ids` is
  set): the REALITY token in `session_id` carries a timestamp (anti-replay,
  `REALITY_WINDOW_SECS = 120`), and a larger skew makes the server **silently**
  bridge the client to `target` — like any "foreign" connection. Symptom: the
  connection never establishes with no error in the client log, while `curl` against
  the server shows the real site. Fix: enable automatic time sync (NTP) — most often
  the clock drifts on Android without auto-time and in VMs after suspend.

Client-side REALITY ClientHello controls (flat `[qeli]` keys, TCP `reality-tls` only):

| key | default | meaning |
|---|---|---|
| `reality_compact` | `false` | emit a compact X25519-only outer TLS ClientHello so it stays below one TCP MSS on paths that drop a segmented ClientHello; the authenticated Qeli handshake remains unchanged |
| `reality_split` | `none` | split the ClientHello across writes: `sni`, `record`, or `first`; `none`/empty disables the split |
| `reality_split_delay` | `100` ms | delay between split writes, valid range `0..5000`; used only when `reality_split` is active |

These are transport-core settings. All native profile editors accept and preserve them even
when the UI does not expose a dedicated control.

## Server identity (per-profile)

**Each profile has its own** long-term static key (X25519) — it is bound to the
profile's interface. The private keys live in `/etc/qeli/identity/<profile>.key`
(permissions `0600`, directory `0700`); the path can be overridden with the profile
field `identity_key`. Profile names with path separators `/` or `\` are
rejected so a name cannot move the key outside the default directory. The
public key is derived from the private one, and the client pins it.

An explicit `identity_key` can direct the key write to another directory.
Therefore `check-config`, server startup, the panel and key creation/rotation commands
require a trusted `server.conf` when this field is set: a regular non-symlink
file owned by root or the process's effective UID, with no group/world write.
Trust applies to the same opened file snapshot that supplied the path. A
rejected config cannot start a key write.

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
is unset, TOFU stores the first key after the server's cryptographic key proof and verifies
it on later connections (the first contact is still not protected against substitution).
The client pins the key **of the profile** it connects to (by port).

> **`allow_unpinned_tofu` (client `[qeli]`, default `false`) is an escape hatch only
> for a TOFU-pin persistence failure.** With no explicit `key`, the client accepts the
> server-proven key on first contact and **must persist** it in `known_hosts`; later
> connections verify that pin. If the new pin cannot be persisted, the default `false` aborts
> fail-closed. `true` permits continuing unpinned only in that failure case. It never
> permits a mismatch with an existing `known_hosts` entry or explicit `key`. H-1 and
> mandatory pinning still require `key`; ordinary TOFU requires `bind_static = false`.

On Linux, the TOFU store must be a regular UTF-8 file of at most 1 MiB. Read errors,
malformed target records or conflicting duplicates reject connection with either value
of `allow_unpinned_tofu`. A missing file permits first trust; new pins are published
atomically. This bounds the local Linux store, not INI configuration.
[Details](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-FILES.md).

Linux bounds TOFU waiting by `timeout` for TCP and UDP. An admitted write completes
before reconnect/exit, so this is not an overall shutdown deadline.
[Cancellation and retained errors](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md).

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

The device cap is counted separately on each profile. After accepted reload, lowering
the effective user/group `max_sessions` immediately retains the newest sessions
within the cap and disconnects older ones. `0` without a group cap remains unlimited.
Changing effective `allowed_networks`, `client_subnets` or exit-default permission
ends sessions carrying the old packet permissions; reconnect to use the new policy.
Reordering or duplicating the same ACL rules does not disconnect clients. A user ACL
continues to override its group ACL.


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
[auth]
bind_static_to_session = true
```

```ini
# client — the [qeli] section (default true; requires a real pinned `key`):
[qeli]
bind_static = true
```
**WIRE-BREAKING**: a server with H-1 only admits clients that also run H-1 and have
pinned the key — enable it in lockstep on the server and all clients. The client
**must** pin the key (`key`); an unpinned / TOFU client (empty `key` or exactly 64 zeros) must set
`bind_static = false` explicitly, otherwise the connection fails with a clear error.
To interoperate with a legacy 0.7.0 fleet during a staged upgrade, set `false` on both
sides. A separate HKDF salt rules out silent bound↔unbound interop: a flag mismatch
yields different keys and an honest failure, not a silent downgrade. Details —
[AUDIT-2026-06-12.md](../archive/audits/AUDIT-2026-06-12.md).

`key` contains exactly 64 hex characters. The only nonempty TOFU placeholder is
64 zeros; `0`, 63 or 65 zeros are errors, not a request to disable pinning.
The rule is identical for INI and `qeli://`.

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

## Session roaming (`roaming.*`)

Roaming is enabled separately for each server profile. Every standard 0.8.0 server,
standalone-client and FFI build includes the implementation; every shipped server template,
new installation, panel-created profile and Quick Start profile explicitly sets
`roaming.enabled = true`. If the key is absent from an older sparse config, it remains
`false`: installing a new binary does not silently enable a new wire capability.

```ini
[profile:mobile-udp]
roaming.enabled = true
roaming.grace_secs = 30
roaming.max_orphaned = 256
roaming.max_orphan_bytes = 67108864
```

| Key | Default | Valid range | Purpose |
|---|---:|---:|---|
| `roaming.enabled` | `false` when omitted; `true` in new templates | boolean | advertise and accept authenticated TCP/UDP roaming for this profile |
| `roaming.grace_secs` | `30` | `1..3600` | how long an unexpectedly detached TCP session may wait for authenticated resume |
| `roaming.max_orphaned` | `256` | `1..65536` | profile-wide cap on detached TCP sessions retained for resume |
| `roaming.max_orphan_bytes` | `67108864` | `4194304..1073741824` | profile-wide memory cap for retained TCP sessions; the 4 MiB minimum matches one fixed encrypted-record pool |

With `roaming.enabled = false`, the server masks every roaming capability for that
profile while retaining unrelated authenticated-extension and UDP-fragmentation bits;
legacy reconnect behavior is unchanged. Setting it to `true` on a binary without the
build feature is rejected by `check-config` instead of being silently ignored.

A live session migrates only when the client policy is `auto` or `required`, client and server
negotiate the transport-specific capability, and the platform adapter supplies the complete
transactional `ROAMING_PATH` contract. Explicit client `local` or non-zero `lport` values pin
the carrier socket: `auto` uses a normal reconnect while `required` is rejected during config
validation. Before `COMMIT_PATH` is issued, prepare/bind/proof failures roll back the exact
candidate. After it is issued, only an explicit platform rejection is safely reversible: an ACK
timeout, cancellation, closed channel, or late/failed ACK is an ambiguous result and terminates
the current generation for an immediate full reconnect. Once the platform ACK succeeds, a later
`JOINCOMMIT` or final-ACK failure follows the same terminal path rather than issuing a stale abort.
On Android, a failure after `setUnderlyingNetworks()` succeeds, including a JNI ACK exception,
also stops the generation immediately. `required` fails closed instead of silently
continuing on an unverified path.

On Linux, `dev_attach=true` leaves routes to the external manager, so the adapter does
not advertise `ROAMING_PATH`: `roaming=auto` uses reconnect and `required` lacks the necessary
platform contract. A Qeli-managed interface's routes belong to a particular connection;
late commits after cleanup are rejected.
[Owner diagnostics](TROUBLESHOOTING.md#641-linux-route-owner-stopped-expired-or-still-reserved).

During IPv4 make-before-break, the old `/32` server route stays in place until COMMIT.
Strict Linux `rp_filter` can otherwise discard replies arriving on the new interface.
Qeli temporarily sets `rp_filter=2` (loose) on the candidate interface alone through
its managed sysctl journal and restores the original value on COMMIT or ABORT.
If it cannot acquire that ownership safely, candidate preparation is rejected.
Roaming does not change the global `rp_filter` setting.

The grace and orphan limits govern TCP hard-resume. UDP uses the same profile opt-in and
authenticated capability negotiation for every UDP camouflage mode, but keeps its own
short-lived candidate and anti-amplification bounds. `perf.connection.max_clients` and
per-user `max_sessions` continue to apply on top.

All four numeric values are validated even while the profile switch is off, so a typo
cannot become active later during a rollout. Low-level proof, path-validation, PMTU and
CID-rotation rules are protocol invariants and are intentionally not configurable.

## Connection limits (`max_clients` vs `max_sessions`)

Two independent limits — do NOT confuse them:

| Key | Where | Counts | What it does on reaching it |
|---|---|---|---|
| `perf.connection.max_clients` | `[profile:<name>]` | **all** profile sessions (all users together) | a new AUTH is rejected (`max clients … reached`) |
| `max_sessions` | `[user:<name>]` / `[group:<name>]` | **one user's devices** | the user's oldest device is evicted (newest wins) |

### `max_sessions` — a per-user device limit

Each client carries a stable **device-id** (random 16 bytes, stored on the device;
see multi-device in [ROADMAP](../plans/ROADMAP.md)), and the server keys sessions/IP pool by
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

> `max_sessions = 0` (default) inherits the group cap; without a group cap the number of devices is unlimited. The profile's `max_clients` always applies on top — a user cannot exceed
> the profile capacity even if their `max_sessions` is larger.

When replacing the same device, a fixed-address holder or an older device at the
session cap, the server sends management-capable clients `session_superseded`.
Automatic reconnect stops so the evicted client cannot take the connection back.
Connect manually to return. One delivery budget of up to four seconds covers the
whole eviction batch; revocation and address transfer complete even without ACK.
Clients without management support receive transport closure and may retry.
The server device cap still applies to them.

> **`static_ip` (a user's fixed tun IP).** Set in `[user:<name>]` (`static_ip = 10.9.0.50`,
> or via `qeli add-client --static-ip` / the web UI. It must be a usable host inside the
> profile's `pool.cidr`, must not equal `tun.address` / `pool.exclude`, and must be unique
> among enabled users allowed on that profile. `static_ipv6` has the same contract relative to
> `pool.ipv6.cidr`, `tun.ipv6_address`, and `pool.ipv6.exclude`. `check-config`, the panel and
> `add-client` reject violations before startup/write; runtime never substitutes a dynamic
> lease for an invalid fixed address. A valid address **always wins**: a new connection/device
> takes it, **evicting** whoever holds it — so a fixed-address user effectively has **one**
> active session, and a reconnect from a new source IP lands on the same tunnel address
> (effectively `max_sessions = 1`). Profile `pool.reservation.<user>` and
> `pool.ipv6.reservation.<user>` entries use the same strict contract. Values are read from
> the LIVE user database at authentication time,
> so a panel edit + reload applies at once.

## Users & groups (`[user:*]` / `[group:*]`)

Users live in the standalone `auth.users_file` (default `/etc/qeli/users.conf`) or inline as
`[user:<name>]` sections in `server.conf`; groups are `[group:<name>]` sections in the same file.
The file is flat-INI, written atomically by `add-client` and the web panel. Full annotated example
— [users.conf](../../../qeli/config/users.conf).

**`[user:<name>]` keys:**

| Key | Default | Purpose |
|---|---|---|
| `password_hash` | — | Argon2id hash of the password (`$argon2id$...`). Set by `add-client` / the panel. Never returned over the API |
| `password_enc` | — | reversibly-encrypted (ChaCha20-Poly1305 under the panel key, base64) copy of the plaintext, so the panel can re-issue a `qeli://` link/QR without knowing the password. Absent for legacy hash-only users. Never returned over the API |
| `enabled` | `true` | whether the account may log in. `false` = disabled (rejected at auth) without deleting it |
| `static_ip` | — | strict fixed tun IPv4: usable host inside `pool.cidr`, not `tun.address` / `pool.exclude`, unique among enabled users on the profile; invalid values are rejected without dynamic fallback |
| `static_ipv6` | — | strict fixed IPv6 lease inside `pool.ipv6.cidr`, not `tun.ipv6_address` / `pool.ipv6.exclude`, unique among enabled users on the profile; no dynamic fallback |
| `max_sessions` | `0` | per-user simultaneous-device cap (`0` = from the group, else unlimited); see "`max_sessions`" above |
| `profiles` | `[]` (all) | comma-separated list of profiles the user may connect to; empty = all (interface isolation, see above) |
| `group` | — | name of a `[group:<name>]` to inherit `bandwidth`/`max_sessions`/`allowed_networks` from |
| `route` | — | repeatable per-user route pushed to the client, `<cidr> [gateway=<ip>] [metric=<n>]`; **overrides** the profile's global `route`/`advertised_routes` when present; maximum 256 |
| `client_subnet` | `[]` | repeatable (or comma-separated) subnet/address **behind** this client that the server routes INBOUND into this client's tunnel (OpenVPN `iroute`); server-side inbound registration only — see §"Routing networks behind nodes WITHOUT NAT" |
| `allowed_networks` | `[]` | destination ACL — a nonempty list overrides the group; empty inherits its ACL, or allows any destination when the group has no ACL |
| `bandwidth.limit_mbps` | `0` | per-user rate cap in Mbit/s (`0` = unlimited or from the group), applied independently to concurrent upload and download; multipath streams share their direction's cap |
| `bandwidth.burst_mbps` | `0` | legacy compatibility field: stored in INI; no separate burst limit is enforced |
| `data_limit_gb` | `0` | lifetime data cap in GB (`0` = unlimited), counted on **download only** (server→client, `used_down`); upload is tracked separately (`used_up`) but does NOT count against the cap. Enforced at auth and by the usage sweep (over-quota live sessions are disconnected). Consumption is tracked in the `usage.json` sidecar |
| `expire_at` | — | account expiry as a Unix timestamp (seconds); absent = never expires. Past it the user is rejected at auth and disconnected by the sweep |
| `metadata.<key>` | — | free-form string annotations (repeatable, one per `<key>`); stored as-is, not interpreted by the server |

Traffic counters are collected and persisted every ten seconds. Completed TCP/UDP
sessions remain accounted for even when they start and end between sweeps; shutdown
collects their final bytes after profile tasks stop. Resetting a user's usage also
advances active-session baselines, so earlier unswept traffic is not charged again.
The quota applies to download and is enforced periodically, so it may be exceeded
between checks. A crash/SIGKILL can lose changes since the last successful write.
`usage.json` is internal accounting state, not a configuration format; configuration
files remain INI. See [worker/accounting audit](../reports/audit-0.8.2/AUDIT-Q14-Q15-WORKER-USAGE.md).

**`[group:<name>]` keys** — a template inherited by members via the user's `group` key (positive user limits and a nonempty user ACL override the group):

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
allowed_networks = 10.9.0.0/24, 192.168.1.0/24
bandwidth.limit_mbps = 50
bandwidth.burst_mbps = 100
data_limit_gb = 100
expire_at = 1767225600
route = 10.20.0.0/16 gateway=10.9.0.1 metric=100
group = premium
metadata.note = contractor

[group:premium]
bandwidth_limit_mbps = 100
max_sessions = 5
allowed_networks = 0.0.0.0/0
```

## Client: credentials, routing, reconnect

### Full `[qeli]` key reference and client matrix

A client config is a single `[qeli]` section (plus an optional `[logging]`). All five clients
recognize the same **81-key contract**, while the set of keys they can actually apply differs:
the platform dictates what is possible (a phone has no iptables, the Rust CLI has no Wintun
adapter, and so on). The complete per-key **0.7.14 → 0.7.15** history is in
[CLIENT-CONFIG-MATRIX.md](../reference/CLIENT-CONFIG-MATRIX.md).

An unknown key is **rejected, not ignored.** Every client refuses a config carrying a name
no qeli client understands, because being ignored is what made a misspelling invisible:
`gatway = true` left the tunnel split with nothing said anywhere. "Unknown" means unknown to
*all* of them — a key this client ignores but another one acts on (`post_up`, `exit_node`,
the whole `—` column below) is carried through untouched, and every GUI client also writes it
back out unchanged, so opening a CLI profile and saving it does not strip its hooks, its
routing policy or its per-app selection.

Clients: **CLI** — Rust `qeli client` / `qeli-client` (Linux, routers, headless);
**Win** — Windows desktop (C#); **mac** — macOS desktop (C#); **And** — Android (Kotlin);
**iOS** — iPhone (Swift).
Legend: **✓** read and applied, **—** recognized and preserved when a GUI saves the profile
but not applied on this platform, **✓\*** with a caveat (footnote).

> The **iOS** column states what is **implemented in code**, not what was verified on a
> device — that client has never been run on hardware (see
> [qeli-ios/README.md](../../../qeli-ios/README.md)).

**Connection & transport**

| Key | Default | CLI | Win | mac | And | iOS | Purpose |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `server` | — | ✓ | ✓ | ✓ | ✓ | ✓ | server address `host:port` (**required**) |
| `proto` | `tcp` | ✓ | ✓ | ✓ | ✓ | ✓ | transport: `tcp` / `udp` |
| `roaming` | `auto` | ✓\* | ✓\* | ✓\* | ✓\* | ✓\* | `off` = normal reconnect; `auto` = negotiated roam with reconnect fallback; `required` = fail closed without the complete safe roaming contract |
| `keepalive` | `60` | ✓ | ✓ | ✓ | ✓ | ✓ | TCP keepalive probe interval; applied by the shared Rust core |
| `tcp_nodelay` | `true` | ✓ | ✓ | ✓ | ✓ | ✓ | disable Nagle's algorithm on the TCP carrier |
| `recv_buffer_size` | auto: `4194304` → 8/16 MiB | ✓\* | ✓\* | ✓\* | ✓\* | ✓\* | absent key enables bounded UDP receive-buffer auto-grow; an explicit value is fixed, `0` leaves the OS setting alone, maximum 64 MiB. TCP keeps OS autotuning. Granted bytes, kernel/internal drops and grow count are exposed in stats/logs |
| `send_buffer_size` | `0` | ✓\* | ✓\* | ✓\* | ✓\* | ✓\* | best-effort `SO_SNDBUF` request on UDP carrier sockets; `0` = leave alone, maximum 64 MiB. TCP keeps OS autotuning; refusal is logged but does not abort the tunnel |

`roaming` has identical semantics for ordinary TCP and every UDP camouflage mode; there is no
separate UDP/QUIC switch. It activates only when the feature core, platform, and server profile
negotiate the complete transport-specific contract. Under `auto`, an old core/peer or unsupported
platform uses normal reconnect; under `required`, connection stops before credentials/full AUTH
are sent. An explicit `local` or non-zero `lport` prevents cross-interface migration:
`required` with such a pin fails validation, while `auto` retains reconnect fallback.
`reconnect = false` does not prevent a successful roam, but disables full reconnect after a
failed roam.

**Authentication**

| Key | Default | CLI | Win | mac | And | iOS | Purpose |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `user` | `client` | ✓ | ✓ | ✓ | ✓ | ✓ | username |
| `pass` | — | ✓ | ✓ | ✓ | ✓ | ✓ | password (inline) |
| `password_file` | — | ✓ | — | — | — | — | read the password from a file (headless) |
| `password_command` | — | ✓ | — | — | — | — | password from an `sh -c` command (trusted config only) |
| `key` | — | ✓ | ✓ | ✓ | ✓ | ✓ | pin the server's public key (hex) |
| `bind_static` | `true` | ✓ | ✓ | ✓ | ✓ | ✓ | H-1: bind the session to the static identity (requires `key`) |
| `allow_unpinned_tofu` | `false` | ✓\* | ✓\* | ✓\* | ✓\* | ✓\* | continue after a proven first-seen-key persistence failure; **never** permits a mismatch with an existing pin |

**Obfuscation** (must match the server profile)

| Key | Default | CLI | Win | mac | And | iOS | Purpose |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `mode` | `fake-tls` | ✓ | ✓ | ✓ | ✓ | ✓ | wire mode: `fake-tls`/`obfs`/`reality-tls`/`plain` |
| `sni` | — | ✓ | ✓ | ✓ | ✓ | ✓ | SNI for fake-tls / reality-tls |
| `obfs_key` | — | ✓ | ✓ | ✓ | ✓ | ✓ | PSK for `mode = obfs` |
| `front` | `websocket` | ✓ | ✓ | ✓ | ✓ | ✓ | anti-FET fronting for obfs: `websocket`/`none` |
| `reality_sid` | — | ✓ | ✓ | ✓ | ✓ | ✓ | REALITY short_id for `reality-tls` |
| `reality_compact` | `false` | ✓ | ✓ | ✓ | ✓ | ✓ | compact outer ClientHello for REALITY |
| `reality_split` | — | ✓ | ✓ | ✓ | ✓ | ✓ | explicit REALITY ClientHello TCP split plan |
| `reality_split_delay` | `100` | ✓ | ✓ | ✓ | ✓ | ✓ | delay between REALITY split writes, milliseconds |
| `quic` | `false` | ✓ | ✓ | ✓ | ✓\* | ✓ | QUIC masking for UDP: `proto=udp`, `mode=fake-tls`, `quic=true`; `mode=udp-quic` remains an import alias |
| `awg` `jc` `jmin` `jmax` | `false` / `0` / `40` / `300` | ✓ | ✓ | ✓ | ✓ | ✓ | AmneziaWG junk preamble (`jc` must match the server on TCP; sender-only on UDP) |

**TUN & routing**

| Key | Default | CLI | Win | mac | And | iOS | Purpose |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `dev` | CLI: `vpn0`; Win: generated interface name | ✓ | ✓ | — | — | — | explicit interface name; Linux reserves it for the entire client session, including `dev_attach`; Windows gives `dev_node` precedence and uses a unique `Qeli-…` name when omitted; mac/iOS/Android use system names |
| `device_type` | `tun` | ✓ | — | — | — | — | Linux interface kind: `tun` (L3) or `tap` (local L2 emulation); non-Linux clients preserve the key but reject TAP at connect time |
| `dev_attach` | `false` | ✓ | — | — | — | — | attach to a pre-existing interface (don't create one) |
| `tun.tx_queue_len` | `1000` | ✓ | — | — | — | — | Owned Linux TUN/TAP TX queue, in packets (`1..32767`); local `[qeli]` setting, not server-pushed or exported in `qeli://`. No adaptive mode. Set `500` for the previous size. Leave unset with `dev_attach=true`: the external owner controls the queue; an explicit combination is rejected. Other OSes preserve but do not apply it |
| `mtu` | `0`=auto | ✓ | ✓ | ✓ | ✓ | ✓ | tunnel MTU; `0` = adopt the server push |
| `mtu_probe` | `true` | ✓\* | ✓\* | ✓\* | ✓\* | ✓\* | active outer UDP path probe with manual or automatic MTU; preserves an explicit inner MTU |
| `gateway` | `true` | ✓ | ✓ | ✓ | ✓ | ✓ | full tunnel; common CLI/GUI default `true`; `gateway=false` explicitly selects split tunnel |
| `pull_routes` | `true` | ✓ | ✓ | ✓ | ✓ | ✓ | Accept server-pushed routes; false preserves local routes, gateway and protected tunnel DNS routes; carried in qeli:// |
| `windows_disable_sharing` | `false` | — | ✓ | — | — | — | Disable ms_msclient/ms_server only on the owned Wintun, with GUID/LUID and readback checks; not used by WinDivert |
| `route_local` | `false` | ✓ | ✓ | ✓ | ✓ | ✓ | pull IPv4 RFC1918 into the tunnel; does not alter IPv6 policy |
| `include` | — | ✓ | ✓ | ✓ | ✓\* | ✓ | CIDR list forced **into** the tunnel (Android — split-tunnel only) |
| `exclude` | — | ✓ | ✓ | ✓ | ✓\* | ✓ | CIDR list carved **out** of the tunnel (Android: API 33+ uses `excludeRoute`; earlier versions subtract CIDRs) |
| `route_file` | — | — | ✓ | ✓ | — | — | split routes from a file (on the CLI use `include`/`exclude`) |
| `dns` | `tunnel` | ✓ | ✓ | ✓ | ✓ | ✓ | DNS mode: `tunnel` / `off` / `system`. `system` is an accepted spelling of `off`: both mean “leave the device resolver alone”. Android/iOS still import legacy `dns = 1.1.1.1, 8.8.8.8`, but save it canonically as `dns_servers` |
| `dns_servers` | — | ✓ | ✓ | ✓ | ✓ | ✓ | comma-separated IPv4/IPv6 resolvers under `dns = tunnel`. **Override the server push**. Each address must be reachable in the negotiated inner family. At most 8 resolvers, each with a protected tunnel host route. With no resolver, split mode keeps host DNS; full mode refuses connection |
| `kill_switch` | `false` | ✓ | ✓ | ✓ | ✓\* | —\* | fail-closed firewall (iptables / WFP / pf; Android — verified system Always-on VPN lockdown) |
| `ipv6` | `auto` | ✓ | ✓ | ✓ | ✓ | ✓ | inner IPv6 policy: `auto` negotiates it, `required` refuses downgrade, `off` requests IPv4 only |
| `allow_ipv6_leak` / `allow_ipv4_leak` | `false` | ✓ | ✓ | ✓ | ✓ | ✓ | explicit escape hatches for the family absent from an IPv4-only/IPv6-only full tunnel |
| `gateway_nat` | `false` | ✓ | — | — | — | — | router NAT (`MASQUERADE`) out the tun (Linux) |
| `forward` | `false` | ✓ | ✓ | ✓ | — | — | site-to-site forwarding **without** NAT (iptables / netsh / sysctl); desktop per-app mode is rejected because transit packets have no app identity |
| `lan_subnet` / `lan_subnet_ipv6` | — | ✓ | — | — | — | — | restrict router NAT/forwarding to one source subnet per family |
| `exit_node` | `false` | ✓ | — | — | — | — | mirror of `gateway_nat`: this client is an internet **exit** for other tunnel clients (`MASQUERADE` out the physical WAN) |
| `post_up` / `post_down` | — | ✓ | — | — | — | — | commands at start / clean stop (root, trusted config) |
| `allow_lan` | `false` | — | — | — | ✓ | ✓ | carve local IPv4/IPv6 ranges out of the full tunnel — reach the home LAN (Android/iOS) |

**OpenVPN parity — desktop only** (no UI form; set via the manual INI editor)

| Key | Default | CLI | Win | mac | And | iOS | Purpose |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `persist_tun` | `false` | — | ✓ | ✓ | — | — | keep the TUN + routes across reconnects (fail-closed in the window) |
| `local` | — | ✓ | ✓ | ✓ | — | — | bind the carrier socket's source address (matters when the server is on-link) |
| `lport` | `0` | ✓ | ✓ | ✓ | — | — | fixed local source port on the primary carrier |
| `dev_node` | — | — | ✓ | —\* | — | — | Wintun adapter name (**Windows**; mac parses but never applies) |
| `metric` | `0` | — | ✓ | —\* | — | — | interface metric (**Windows**; mac parses but never applies) |

**Misc & platform-specific**

| Key | Default | CLI | Win | mac | And | iOS | Purpose |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `name` | — | — | ✓ | ✓ | —\* | —\* | desktop profile name; mobile preserves the INI field but uses its own profile metadata. A `qeli://` fragment supplies an import label |
| `autostart` | `false` | ✓\* | — | — | — | — | auto-connect when the supervisor/panel starts (GUIs use their own OS autostart) |
| `apps_mode` / `apps` | `all` / — | — | ✓ | ✓ | ✓ | —\* | per-app split tunnel. `include` tunnels only listed apps; `exclude` tunnels everything except them. Windows entries are full `.exe` paths, macOS entries are code-signing identifiers (normally bundle IDs), Android entries are package names. iOS preserves but cannot apply them without MDM `NEAppRule` |
| `reconnect` · `reconnect_retries` · `reconnect_base_delay` · `reconnect_max_delay` | `true` / `-1` / `1` / `60` | ✓ | ✓ | ✓ | ✓ | ✓ | shared retry-loop settings; delays are seconds, `-1` is unlimited; the core checks the retry budget and calculates delays; OS events stay in the client |
| `timeout` | `30` | ✓ | ✓ | ✓ | ✓ | ✓ | one connection-attempt timeout; after transport migration the shared Rust core parses and applies it |


<!-- normative-sync: android-perapp-lockdown-q29-v1 -->

**Android per-app and lockdown.** With “Block connections without VPN” disabled,
apps omitted from `include` or listed in `exclude` use the ordinary network.
With Android lockdown enabled those UIDs are blocked: excluding an app from VPN
does not permit bypassing system blocking. API34 coverage includes IPv4/IPv6 TCP/UDP
and DNS, stop, manual recovery and policy removal.
[Results and limits](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-APP-POLICY.md).

**Desktop per-app details.** With `apps_mode = all`, Windows keeps its native Wintun
zero-copy path and macOS keeps its ordinary global utun routes/DNS. `include` or `exclude`
changes only platform packet/flow ownership: the selected TCP, UDP and DNS traffic still enters
the same ABI 1.16 Rust transport (compatibility floor 1.16) and uses the same server push, crypto and reconnect logic.
On Windows, a configured/pushed tunnel resolver is intentionally tunnel-wide in per-app mode:
DNS commonly belongs to the shared system resolver process rather than the originating app, so
trying to classify it by that process leaks selected applications' queries. IPv4 DNS can use an
IPv6 tunnel resolver and vice versa; the adapter translates the packet family and reverse-NATs
the reply. Non-DNS traffic remains governed by `apps_mode`.
Windows captures/classifies with the bundled WinDivert driver. macOS uses a signed system
extension containing both `NETransparentProxyProvider` and `NEDNSProxyProvider`; an ad-hoc or
cross-built macOS archive therefore rejects an app-filtered profile until a Developer-ID build
with the required Network Extension entitlements is installed and approved. The underlying
APIs exist on macOS 13+, but the 0.8.3 .NET 10 application requires macOS 15 or newer.
Public distribution also requires Apple notarization and stapling; `qeli-mac/build_app.sh`
performs it when `QELI_MAC_NOTARY_PROFILE` is supplied.

Per-app ICMP is not available through the macOS flow API and is not promised by this setting.
For an app-filtered profile, host-global `kill_switch` is ignored because it would also block the
applications explicitly bypassed by `exclude`; selected TCP/UDP/DNS is instead held fail-closed
by the classifier while qeli reconnects. Unknown process identity is fail-closed for `include`.
In macOS split mode, ordinary destinations outside `include`/server-pushed routes bypass the
tunnel; an explicit route always requires its negotiated address family and is dropped rather
than leaked when that family is absent. Hostnames are resolved through the tunnel DNS with both
A and AAAA queries, and the relay tries policy-compatible candidates instead of treating the
first A record as authoritative for an IPv6-only profile.

**Data plane — local values and server push**

| Key | Default | CLI | Win | mac | And | iOS | Purpose |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `padding` · `padding_min` · `padding_max` | on / `0` / `255` | ✓ | ✓ | ✓ | ✓ | ✓ | record padding; the maximum is strictly bounded by the wire format |
| `heartbeat` · `heartbeat_interval` · `heartbeat_size` · `heartbeat_jitter` | on / `15000` / `16` / `2000` | ✓ | ✓ | ✓ | ✓ | ✓ | cover heartbeat and its interval/size/jitter |
| `shaping` · `shaping_gap_mean` · `shaping_gap_min` · `shaping_gap_max` · `shaping_budget` | `false` / `700` / `40` / `6000` / `16384` | ✓ | ✓ | ✓ | ✓ | ✓ | shaping enablement and timing/budget envelope |
| `shaping_min_size` · `shaping_max_size` · `shaping_stealth` · `shaping_stealth_mbps` | `64` / `1024` / `false` / `2` | ✓ | ✓ | ✓ | ✓ | ✓ | cover-record sizes and stealth rate |

Local values apply when the server did not push the corresponding setting. An authenticated
server push still wins and is reported in every client's complete `NetworkPlan` log.

**The `[logging]` section** (`level`, `file`, `time_format`) is recognized by the shared
parser and preserved by every editor. The CLI applies all three fields. Windows/macOS use
`level` for service/daemon profiles; the GUI can supply its application log preference.
Desktop preserves `file` and `time_format` without applying them. Android/iOS preserve
the section while their own application preferences control logging.

| Key | Default | CLI | Win | mac | And | iOS | Purpose |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| `logging.level` | `info` | ✓ | ✓* | ✓* | — | — | `level` in `[logging]`; desktop service/daemon can use app settings |
| `logging.file` | — | ✓ | — | — | — | — | `file` in `[logging]`; empty uses stderr |
| `logging.time_format` | `datetime` | ✓ | — | — | — | — | `time_format` in `[logging]`; timestamp format |

Qualified names identify schema fields; write the unqualified key under `[logging]`.

**Footnotes.** `mtu_probe` applies only to UDP, independently of a manual or automatic inner MTU. `gateway` defaults to `true` on all clients; use `false` for split tunnel. On Android: `include` is honored only
in split tunnel; `exclude` works before API 33 through CIDR subtraction and on API 33+
through `excludeRoute`. QUIC masking uses `proto=udp`, `mode=fake-tls`, `quic=true`;
`mode=udp-quic` remains a legacy import spelling. `dev_node`/`metric` are parsed and round-tripped by mac but **not applied**
(Wintun/Windows-specific). `autostart` is read by the panel/supervisor; the `qeli client`
runtime ignores it.

**Android kill-switch footnote.** `kill_switch = true` applies to full-tunnel only. On
Android 10+ the client requires Qeli to be selected as **Always-on VPN** with **Block
connections without VPN** enabled; otherwise it refuses the connection fail-closed and names
the system setting that is missing. Before creating the TUN, Qeli verifies that it is the
currently prepared VPN provider and that Android's readable `Settings.Secure` lockdown policy
is armed. Immediately after `Builder.establish()` it requires the authoritative
`isAlwaysOn()` and `isLockdownEnabled()` owner checks before giving the TUN to Rust or ACKing
the plan. Android 9 is refused because those live owner checks are not available there. The OS
owns this switch and the app cannot enable it.

**iOS footnotes.** `kill_switch` is not supported: on iOS the fail-closed role belongs to
the system's **VPN On Demand** (rules set in the app or via MDM), not to a config key. The
key is still preserved when a profile moves to another platform. iOS does not apply `[qeli]`
`name`, but 0.7.15 preserves it through a round trip; iOS keeps its own profile label in a
leading comment line (`# Name`). A `qeli://` link carries the label correctly either way.
`mtu_probe` is parsed and stored and, as everywhere
else, only takes effect on UDP; an explicit `mtu` does not disable probing.

<a id="client-tun-tx-queue"></a>

### Linux client TUN queue size (`tun.tx_queue_len`)

In development 0.8.2 builds that support this key, set it **locally in the client
INI's `[qeli]` section**, for example in `/etc/qeli/client.conf`:

```ini
[qeli]
tun.tx_queue_len = 1000
```

This is a client config fragment, not a new `[tun]` section or a CLI flag.
In the panel, edit the client connection's INI, not a server profile.
`qeli client --config <file>` and standalone `qeli-client --config <file>` use the
same key. It is neither carried in `qeli://`/QR nor supplied by server push.

- The unit is **packets**, not bytes. With the key absent Qeli sets `1000`;
  explicit `500` restores the previous size observed in the lab.
- Accepted values are integers `1..32767`. `0`, `auto`, negative/fractional and
  out-of-range values are rejected. There is no automatic adjustment mode.
- The policy applies only to a **Linux TUN/TAP created by the client**, before
  bringing the interface up, across supported transports and both IPv4/IPv6 on
  that device. A queue-setting failure aborts connection setup rather than
  reporting success after a kernel refusal. Other OSes preserve but do not apply it.
- With `dev_attach = true`, **remove** the key instead of setting it to `1000`:
  the external owner, such as Keenetic `ndm`, controls the interface and its queue.
  Omission leaves the external queue untouched; an explicit value is incompatible
  with Linux attach mode and is rejected.

After saving the file, stop/start the client itself (or its client service/panel
connection) so it reads the new config. This is not hot reload: a server-profile
reload or reconnect using the old in-memory config does not apply the file edit.
Updating only the server cannot change an installed client binary either.
Older builds, even with the same version number, may not recognize this key;
install a client containing this change before adding it.
When editing through the Client tab, the Qeli binary serving the **local panel**
must also recognize the key because it validates the INI with its own parser.
This does not require updating a remote VPN server to change a standalone client queue.

On Linux this is the **kernel → Qeli TUN reader** queue (`TX` on the device).
It also carries outgoing TCP ACKs during downloads; it is not an upload-only rate limiter.
It is not the multiqueue descriptor count `tun.queues`, socket buffers, Qeli/
Recordizer internal queues or the H2 flow-control window. The same-named server
key under `[profile:<name>]` controls a different TUN and does not set the client queue.

After connecting, check the following in the client's network namespace,
replacing `vpn0` with the actual `dev`:

```sh
ip link show dev vpn0
ip -s -s link show dev vpn0
tc -s qdisc show dev vpn0
```

The first output should contain `qlen 1000` or the configured value; the log says
`Client TUN TX queue length: 1000 packets`. A larger queue may absorb bursts, but
does not guarantee zero loss or higher throughput and may increase latency/memory
use. Compare drop/retransmission deltas and RTT under the same load; do not grow
buffers indefinitely instead of investigating a slow reader.
[Diagnostics and counter boundaries](OPERATIONS.md#client-tun-tx-queue).

#### Increasing and decreasing the queue

The queue size limits room for an **already arriving burst**, not the TUN reader's
processing rate. If the reader is consistently slower than the source, a larger
queue only postpones overflow; it does not remove CPU limits or processing pauses.
On an idle interface, increasing the limit need not change RTT.

| Change | Possible benefit | Tradeoff under load |
|---|---|---|
| Decrease, for example `1000 → 500 → 250` | Fewer packets can accumulate before the reader, reducing potential queued memory and delay | Bursts hit the limit earlier; packet loss can reduce TCP cwnd and useful throughput. Loss-recovery delays may outweigh the benefit of a shorter queue |
| Keep `1000` | Baseline for an updated Linux client, not auto or a measured optimum for every link | Drops remain possible; the result depends on transport, load and device |
| Increase, for example `1000 → 2000` | More room for short bursts; potentially fewer drops/retransmissions | More packets can wait when the queue fills; RTT and memory use may rise without additional throughput |

`1..32767` is the accepted input range, **not a recommended operating range**.
The upper bound accounts for Linux's current `S16_MAX` cap on `tx_queue_len`;
the lab rejected `65535` during interface setup.
[Linux change](https://kernel.googlesource.com/pub/scm/linux/kernel/git/netdev/net/+/66ab4c59b74db7ab53a1c9083feaaede393a96a0).
Do not select its upper bound merely because the config accepts it. Compare
several values on the same binary with otherwise identical settings: throughput,
TUN TX drops separately from qdisc, retransmissions, cwnd and loaded RTT.
Keep the server queue constant and check IPv4/IPv6, upload/download and the
transports you actually use separately. Select the smallest queue that preserves
the required throughput with acceptable loss/latency, not the largest queue.
[VM300/301 report for queue sizes 250/500/1000/2000](../reports/TUN-QUEUE-SIZE-2026-10-16.md)
and [queue-size recommendations](../reports/TUN-QUEUE-SIZE-2026-10-16.md#choosing-a-size).
For the identified 0.8.2 artifact SHA `1d94d4c4…`, see the separate
[TCP/UDP tables, queue settings and lab parameters](../reports/LINUX-LAB-0.8.2-2026-10-17.md).
[Remaining drops at 1000 and reader-localization limits](../reports/TUN-READER-0.8.2-2026-10-18.md)
do not imply that a deeper queue will remove the bottleneck.

The [19 October N04 follow-up](../reports/TUN-N04-0.8.2-2026-10-19.md)
confirmed `FULL_RING` and tested raw TUN reads on the Linux UDP client's transport
runtime. Queues 1000/2000 were checked separately; the default remains 1000.
Zero TUN drops in three QUIC windows at 2000 do not establish zero UDP loss or
optimal latency. The report identifies a separate test ELF; its measurements
must not be automatically reassigned to packaged distribution files.

### Precedence: which source wins

A client has three sources of values — its `[qeli]` file, what the server pushes on connect,
and the built-in default — and different fields resolve differently. There are **no override
flags**: `qeli client` takes only `--config <file>`, so "CLI vs file" never arises.

| Setting | Winner | Rule |
|---|---|---|
| `tun.tx_queue_len` | local client | explicit `[qeli]` value → else `1000` for an owned Linux TUN/TAP; not push or link. With `dev_attach=true` the external owner retains the queue and an explicit key is rejected |
| `mtu` | client | an explicit `mtu > 0` in `[qeli]` → else the server push (its profile's `tun.mtu`) → else `1400`. The outer UDP budget is governed separately by `mtu_probe`; probing lowers the inner MTU only with automatic MTU and a legacy peer |
| DNS resolver | client | the push applies only if this client manages the resolver at all. With `dns = off` the pushed DNS is **ignored** (a `warn` line says so and names the fix) |
| routes (`route`) | server | pushed CIDRs are **always** applied; local `route_local` / `include` / `exclude` add to them rather than cancelling them |
| padding · heartbeat · normalization · shaping | **server** | the push unconditionally overwrites these fields of the client's obfuscation section — otherwise the two ends disagree on the data-plane format |
| `mode` · `sni` · `obfs_key` · `front` · `awg.*` | client | handshake parameters are never pushed: they must be known **before** connecting, so the only source is the file or the link |
| password | `pass` | `pass` → `password_file` → `password_command`: the first one that is set and non-empty |
| log level | `RUST_LOG` | the environment variable overrides `[logging] level` |

What the server actually sent, and what the client did with it, is in the log: every pushed
item gets its own line marked `APPLIED` or `IGNORED` **with the reason**, plus one summary line:

```
server push: ip=10.9.0.2/24 gw=10.9.0.1 mtu=1280 dns=10.9.0.1:53 routes=2 obf=yes streams=1
server push: mtu 1280 IGNORED — this client sets mtu = 1400 in its config (wins); using 1400
```

That answers "did the server not send it, or did the client drop it?" — from the outside both
look identical: the setting is simply missing.

Below is the same behaviour in more detail, by group.

**Client credentials** — in the `[qeli]` section:
```ini
# client.conf
user = alice
pass = secret
```
The password can be supplied three ways in the `[qeli]` section (precedence high → low):
- `pass = <secret>` — inline plaintext (wins if present and non-empty).
- `password_file = <path>` — read the password from a regular file; a symlink to a regular
  file is supported. Used only when `pass` is absent. Raw input is limited to **16 KiB**,
  decoded as strict UTF-8 and trimmed at the edges, using the same zeroizing buffer as
  `password_command`. Oversized input and detected changes while reading reject the
  password; it is never truncated. FIFO, device and directory sources are rejected.
  Reading runs outside the async runtime workers, with at most one queued/active file
  job per process. Its **30-second budget** includes admission wait. Stop/deadline signals
  cancel queued work and request cancellation between filesystem calls; an already-running
  syscall cannot be force-cancelled, so ordinary stop/timeout waits for that job to finish.
  A stalled filesystem can therefore exceed 30 seconds. Forced future cancellation leaves
  that job holding its slot and zeroizing buffers until I/O returns, preventing accumulated
  reads. These are file-reading rules; the config-command ownership policy does not apply
  to a password file. The operator remains responsible for its access permissions.
- `password_command = <cmd>` — obtain the password by running a command via `sh -c` (its stdout is
  trimmed). Used only when both `pass` and `password_file` are absent. **Runs as the client
  process (typically root)**, so it requires a regular non-symlink config owned by root or
  the process's effective UID, with no group/world write bits. Trust is checked on the same
  opened file that supplies the parsed bytes; otherwise the client refuses to start
  (fail-closed). After fixing permissions, start the client again. The panel never persists
  this key. See the [hook security rules](#security) for the shared file policy.
  The Linux client uses `/bin/sh -c`, with stdin closed and stderr discarded. Execution,
  stdout reading and exit wait share a **30-second deadline**; stdout may contain at most
  **16 KiB before whitespace trimming**. Overflow, invalid UTF-8 or a nonzero exit reject
  the password, never truncate or replace it. The existing AUTH credential-size limit
  still applies after trimming. Errors report the cause/status without the command or
  its output. SIGINT/SIGTERM during this step cancel startup and terminate the supplier;
  timeout, overflow and cancellation also target its Linux process group. Normal error/
  stop paths await the shell; forced future cancellation uses eventual Tokio reaping.
  Descendants that deliberately leave the group and uninterruptible kernel waits remain
  outside this cleanup guarantee. Successful commands may retain explicitly redirected
  background services, as with hooks. Raw retained output and the returned password use
  zeroizing buffers. File reading follows the separate cancellation rules described above.

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
route = 192.168.50.0/24 gateway=10.9.0.1 metric=50
```
Verified: the client gets `192.168.50.0/24 via <tun_gw> dev <tun>` in the table.

Client-side routing keys in flat-INI (`[qeli]`, file-only — not carried in a
`qeli://` link; `gateway` defaults to `true`, the other booleans below to `false`, and `dns` to `tunnel`):

| Key | Purpose |
|---|---|
| `route_local` | pull the **IPv4 RFC1918 ranges** (10/8, 172.16/12, 192.168/16) into the tunnel. On desktop system-TUN clients, `true` also installs more-specific overrides for directly connected RFC1918 prefixes, so a physical `/24` cannot win over the broad tunnel route; desktop per-app mode applies the same decision policy. Explicit `exclude` CIDRs still win. This flag does not affect IPv6 ULA or multicast. Default `false` avoids hijacking a directly connected LAN; remote RFC1918 destinations still follow the ordinary full/split-tunnel policy. **Routes the server explicitly advertises (`route = …`) are applied ALWAYS and do not depend on this flag** (since 0.7.12; before that they sat behind it and were silently dropped) |
| `gateway` | full-tunnel: all client traffic into the VPN (default route via tun) |
| `exclude` | comma-separated strict IPv4/IPv6 CIDRs to **exclude** from the tunnel — they go directly via the physical path of the same address family. Windows/macOS resolve that path before capture routes, iOS uses `NEIPv4Route`/`NEIPv6Route`, and Android uses `VpnService.excludeRoute` on API 33+ (a computed complement on older versions). Use `/32` for one IPv4 host or `/128` for one IPv6 host. Example: `exclude = 192.168.50.0/24, 2001:db8::7/128` |
| `include` | comma-separated IPv4/IPv6 CIDRs to route **into** the tunnel (split-tunnel — relevant when `gateway=false`). A route is accepted only when that family was negotiated in the authenticated NetworkPlan |
| `allow_lan` (Android/iOS, default `false`) | full-tunnel-only shortcut over `exclude`: carve **all** private ranges out of the default capture (RFC1918 + link-local `169.254/16` + link-local multicast `224.0.0.0/24` + SSDP `239.255.255.250/32`) so home Wi-Fi/LAN devices stay reachable without disconnecting. It never subtracts authenticated pushed/include routes in split-tunnel mode. Also exposed as an "Allow local network access" toggle in app Settings. Android 13+ uses `excludeRoute`; older versions compute the exact complement of the same exclusions against `0.0.0.0/0`; iOS applies equivalent Network Extension exclusions |
| `ipv6` (default `auto`) | authenticated inner-family policy. `auto` uses IPv6 only when server, Rust core and platform adapter all advertise the complete capability set; `required` refuses an IPv4 downgrade; `off` requests the IPv4 side of a dual profile and refuses IPv6-only |
| `allow_ipv6_leak` / `allow_ipv4_leak` (default `false`) | symmetric full-tunnel escape hatches. When the negotiated plan lacks one family, qeli blocks that family's native egress by default; the matching `true` deliberately lets it bypass the VPN. `allow_ipv4_leak` and `allow_ipv6_leak` also permit an unavailable Linux kill-switch leg when the matching leak is explicitly accepted |
| `kill_switch` | firewall kill-switch (Linux/iptables, full-tunnel only): while the tunnel is down, block all egress except loopback/tun/DHCP/server IP, so a drop can't leak onto the physical interface |
| `gateway_nat` | router mode (Linux/iptables): the client programs `ip_forward` + `MASQUERADE` out the tun (+FORWARD +MSS-clamp) so a LAN **behind** it reaches the internet through the tunnel — no manual iptables. Idempotent within a generation; removed before releasing the original TUN and reinstalled on full reconnect. A crash may leave rules |
| `lan_subnet` / `lan_subnet_ipv6` | restrict `gateway_nat`/`forward` to one source CIDR per family; empty = apply to all traffic of that family leaving the tun |
| `forward` (default `false`) | site-to-site **without NAT**: forward traffic between the tun and the LAN behind the client while preserving the original source IP (unlike `gateway_nat`, which masquerades it). Use it when a routed network sits behind the client and its addresses must stay visible on the server. See "Routing networks behind nodes WITHOUT NAT" below |
| `exit_node` (default `false`) | **mirror of `gateway_nat`.** `gateway_nat` masquerades a LAN behind the client INTO the tunnel; `exit_node` masquerades traffic that arrived FROM the tunnel out the physical WAN — so other clients reach the internet under THIS host's IP (e.g. behind a grey/NAT'd line). See "Exit node (`exit_node`)" below. Linux/router-only |
| `dev = <name>` + `dev_attach = true` | **attach to a pre-existing** interface instead of creating one. `dev` is literal: qeli does not rename TAP devices. The existing kind must match `device_type`, it must use `IFF_NO_PI` without `IFF_VNET_HDR`, and qeli detects its single/multi-queue mode automatically while preserving supported features. qeli only opens it for packet IO: it does **not** create, address, route, or delete it — an external manager (router firmware, your own script) owns all of that. The assigned tunnel IP is written to `$QELI_TUNIP_FILE` (if set in the environment) so the external script can bring up the address/routes itself |
| `post_up` / `post_down` | standalone Linux client lifecycle commands. A committed NetworkPlan supplies `$1=ifname`, `$2=gateway`, the full versioned `QELI_*` environment and temporary JSON (`QELI_CONTEXT_FILE`); `post_down` gets the stop reason and latest plan. **SECURITY:** trusted file-only config; panel/API never write them |
| `dns` | client DNS mode. On Linux, `tunnel` applies per-interface DNS through `systemd-resolved`; it does not overwrite `/etc/resolv.conf`. Installing a requested resolver fails if resolved is not the active system resolver. Deleting the tunnel interface removes its DNS; clean shutdown also explicitly reverts it. `off` / `system` leaves DNS to the platform. File-only; emitted to INI only when `!= tunnel` |
| `autostart` | auto-connect this profile when the supervisor/panel starts (accepts `true`/`1`/`yes`/`on`). Read by the **panel client-manager**; ignored by the client runtime itself. Emitted to INI only when `true` |

On Linux, the nonempty `QELI_TUNIP_FILE` environment variable selects the committed
NetworkPlan state file. Atomic rename publishes it: the first line is the tunnel
address for legacy scripts, followed by `ipv4=<CIDR>` and `ipv6=<CIDR>` for present
families, `mtu=<number>` and `generation=<number>` (development0.8.2).
Generation comes from the authenticated core plan and distinguishes repeated
application of identical addresses within one adapter; resetting the adapter may
restart the counter. This is a runtime file, not an INI parameter or a new
configuration format. Atomic rename does not make external route/ndm setup atomic.

<!-- normative-sync: plan-publication-lock-v1 -->

On Linux, publication also acquires the sibling directory
`$QELI_TUNIP_FILE.publish-lock` with atomic `mkdir`. The matching Keenetic hook
holds the same lock from its final plan snapshot through NDM apply/save and receipt
publication. The client waits within the existing shared NetworkPlan budget
(maximum 15 seconds); a busy hook returns an error for a later event to retry.
The lock is separate from `/var/run/qeli.lifecycle.lock`: the hook creates the
attach device and waits for the first address without holding the publication lock.
It releases the lock before a later core publication can proceed; the core releases
it before any post-up hook. A newly published plan still needs a later wan.d event.

Update the binary, `lifecycle.sh` and hook together. Older binaries/hooks and
administrator writes do not participate. NDM commands remain sequential and may
partially succeed; pending/applied records retain address ownership for retry.
Normal return, Rust unwind and handled shell signals release the lock. SIGKILL or
power loss, including a standalone release panic with `panic=abort`, can leave a
directory: do not remove an active or unknown owner's lock.
After independently verifying that the client and hook have stopped, review the
saved/pending addresses, then remove only the empty stale publication directory
with `rmdir`. Never discard the plan or recovery receipts to bypass this check.


On Linux, `dev_attach=false` only waits approximately six seconds for an occupied
name to be released; Qeli does not delete a device based on its observed PID holders.
Query errors and changed ifindex stop setup. TUN/TAP creation and the first multiqueue
open are exclusive: a device appearing after the check is not borrowed. Later queues
use the first queue's actual name. The server immediately refuses an occupied
`tun.name`. No new parameters are introduced; diagnostics and `dev_attach` limits:
[TROUBLESHOOTING.md §6.47](TROUBLESHOOTING.md).

`dev_attach` and additional multiqueue descriptors require permitted `TUNSETIFINDEX`
to prevent creation if the original device disappears. An ioctl refusal has no
unguarded fallback. The external owner must keep the device and framing stable
during opening, and sysfs must match the current network namespace. Qeli rejects a
detected `ifindex` mismatch, but equal indexes across namespaces do not prove that
the sysfs mount belongs to the current namespace.
See [diagnostics §6.48](TROUBLESHOOTING.md).

Qeli retains original TUN descriptors through cleanup, then closes them; disconnect,
rollback and server teardown do not delete a device by name or clear persistence.
External holders can keep it alive. DNS/route commands still require stable device
identity during cleanup; see [diagnostics §6.49](TROUBLESHOOTING.md).

Linux per-link DNS is owned by a generation lease with a nonblocking lock and a
namespace/index recovery record. Disabled/empty DNS plans perform no per-link cleanup.
Managed DNS requires `TUNGETIFF`/`TUNGETDEVNETNS` and readable namespace/boot metadata;
old name-only markers and orphaned persistent-link state may require explicit recovery.
See [DNS ownership and upgrade recovery §6.50](TROUBLESHOOTING.md).

Managed Linux routes also require these TUN ioctls and usable `/proc/thread-self/ns/net`,
including with `dns=off`. Setup requires the actual name to match `dev`; name templates or
truncation are not silently accepted. Cleanup checks the original fd, name, index and held
namespace before each command. External rename/delete refuses TUN route cleanup and retains
reservations; physical bypass cleanup remains independent when namespace is proven.
`dev_attach=true` still leaves routing to its external owner.
See [route ownership recovery §6.51](TROUBLESHOOTING.md).

Original TUN/namespace checks also apply before setup/roaming route commands and managed
MAC/address/up. Identity loss prevents continuing the same generation even when physical
rollback succeeds. RouteOwner holds Weak evidence and does not retain the TUN after the
session ends. See [setup/roaming errors §6.52](TROUBLESHOOTING.md).

Gateway/exit-node bind the same generation, including router features with `dev_attach=true`.
They check the original TUN/namespace inside firewall and WAN operations; sysctl checks
surround the shared journal API. Gateway/exit rules and the sysctl scope are cleaned before
TUN release; full reconnect reinstalls them. Losing the TUN still permits recorded rule
cleanup in the original namespace, but defers the entire sysctl scope, including shared
forwarding/rp_filter. Failed cleanup retains the generation reservation. Kill-switch has
its separate lifetime across reconnect. Sysctl internals, crash recovery and races after
the final observation remain limitations.
See [gateway ownership and recovery §6.53](TROUBLESHOOTING.md).

On Android and iOS, `allow_lan` also excludes IPv6 ULA, link-local and multicast
(`fc00::/7`, `fe80::/10`, `ff00::/8`). A site's local IPv6 GUA prefix cannot be inferred
safely; add that exact prefix to `exclude`. Android 13+ uses `excludeRoute`; older versions
build complete route complements for both IPv4 and IPv6.

**Auto-reconnect** defaults on and is controlled by `[qeli]` on every client:
`reconnect=true`, `reconnect_retries=-1`, `reconnect_base_delay=1`,
`reconnect_max_delay=60`. Delays are seconds. Rust owns the retry budget and delay policy;
clients supply connection state and OS events.

- `reconnect=false` prevents every automatic restart, including after a stable session.
- `reconnect_retries=-1` permits unlimited retries. `N >= 0` permits N retries after an
  initial unstable attempt: with `N=2`, three consecutive failures stop the loop.
- The counter resets after **30 seconds actually connected** or a deliberate restart of
  an established session for a network change. DNS, handshake, teardown and offline waiting
  do not establish stability. A short connected session still consumes the failure budget.
- `reconnect_retries=0` refuses a retry after an unstable attempt; it still permits recovery
  after a stable session or a deliberate network-change cycle. Use `reconnect=false` to
  prohibit all automatic recovery.
- Backoff uses `base × min(2^(attempt−1), 100)`, bounded by the configured maximum
  (at least 1 second), with 80–100% jitter. All clients also maintain a **1.5 second minimum
  between attempt starts**, including deliberate cycles.

During the desktop's 30-second network-settling window, or without a physical address,
the delay exponent is capped at attempt 3 (up to 4 seconds at the default base). This
**does not cap the failure counter**: a finite retry limit remains effective. Mobile
clients park while no usable carrier exists; waiting does not consume attempts. Carrier
restoration skips the stale backoff but retains the accumulated failures and the minimum
start-to-start interval. Disabled or exhausted loops stop before waiting for a carrier.
With the default unlimited budget, a client left running retries until the server returns.

A dead server on an idle tunnel is detected via **authenticated RX-liveness**. Raw UDP
datagrams do not refresh the timer: only a record that passed framing, length and AEAD
authentication counts. The deadline is derived from the active server-pushed cadence:

- heartbeat: `rx_dead = max(3 × (interval + jitter), 30s)`;
- traffic shaping: `rx_dead = max(3 × (idle_gap_max + 1s), 30s)`.

The client then reconnects with `no authenticated data from server for >Ns — reconnecting`.
The 30-second floor and 3× multiplier tolerate at least two lost scheduled records. The
threshold is not a separate key: change the heartbeat or shaping cadence in the server
profile. When heartbeat and shaping are both disabled there is no RX watchdog. In
particular, UDP uplink without downlink is valid and is no longer treated as a dead session
after an arbitrary eight seconds; suspend/network callbacks and an explicit non-zero idle
policy remain available.

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

For negotiated IPv6 the client gateway preserves `accept_ra` on the external
WAN before enabling forwarding. If the preferred IPv6 default route is
ambiguous across interfaces, setup stops before changing sysctl/firewall.
A LAN-only host without an IPv6 default route remains supported.
[ECMP verification](../reports/audit-0.8.2/AUDIT-Q25-WAN-ECMP.md).

All rules carry a `qeli-gw-nat` comment and are verified with `iptables -C`.
Within the running process, Qeli records attempted rules by TUN, IP family and LAN
subnet; cleanup removes saved subnet variants even after configuration changes.
A successful cleanup of one TUN/family does not clear another's retry state.
Failures are reported, both families are attempted, and sysctl ownership is released
through the shared journal without releasing another profile's lease.
The rule registry is in memory: after a crash, inspect leftover tagged rules before
manual recovery; cleanup of an old subnet across process restarts is not guaranteed.

New and reused FORWARD permits check the order of the detected Qeli kill-switch.
An inspection failure cannot authorize insertion ahead of it. MSS-clamp remains
best-effort: failure logs a warning and requires working Path-MTU Discovery.
[Validation and remaining limits](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md).

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
192.168.254.0/24 -o vpn0` configured for the current generation, cleaning up before TUN
release and reinstalling on full reconnect. After a crash or forced stop,
check for leftover rules before reusing the interface.

> On `iptables-nft` hosts the `filter` table's `FORWARD` chain can be legacy-
> incompatible (same as `server/nat.rs`) — then it's installed best-effort and
> forwarding may continue only when qeli verifies an otherwise empty `FORWARD` chain whose
> built-in policy is `ACCEPT` (a warning is logged). Any explicit rule/jump or an unreadable
> chain fails router-mode setup instead of risking a silent black hole.
> `MASQUERADE` is required in NAT mode; an unverified MSS-clamp produces a warning.

## Kill-switch (`kill_switch`)

Linux kill-switch reads `/run/systemd/resolve/resolv.conf` and `/etc/resolv.conf` in
advance, using one snapshot for IPv4/IPv6. Reading shares the four DNS/NSS slots and
the setup deadline; this wait still applies with a numeric server address. Files must
be regular and at most 64 KiB; the list is limited to 64 distinct entries. Invalid or
unreadable files grant no DNS allowances; exceeding the merged list limit aborts setup.
The `nameserver` token must be separate, with whitespace before a trailing comment.
Scoped IPv6 with `%interface`/`%index` grants no unrestricted interface-independent
allowance and does not discard other valid entries. Later DNS changes do not refresh
firewall rules automatically. [Resolver-file reads](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-FILES.md).

System name resolution for kill-switch, connections and UDP diagnostics uses one core
module: at most four unfinished DNS/NSS calls or resolver-file reads per core instance in a process, with queue
time included in the request deadline. Cancellation does not release a live call's slot.
Numeric IPs bypass admission; addresses supplied by platform adapters remain authoritative.
There are no new INI parameters.
[DNS waiting and shutdown](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-RESOLVER.md).

Kill-switch setup (`engage`) receives a shared 15-second deadline: resolver time,
operation-mutex admission, tool discovery, policy admission and IPv4/IPv6 commands.
Partial-setup rollback gets a separate 15 seconds from its first recovery operation,
shared by all inner and final attempts across both families. Unverified cleanup rejects
setup even with `allow_ipv4_leak`/`allow_ipv6_leak`: those flags accept an unprotected family,
but cannot accept incomplete rollback as success. Ownership and tool paths remain for
verified cleanup in the same process; after process exit, inspect exact remaining chains.
Some rules may already be gone, so incomplete rollback does not establish intact protection.
DNS/NSS waiting is deadline-bound and cancelled on stop; the underlying system call
may continue in a separate capacity-limited thread. Other synchronous boundaries cannot
be interrupted by the timer: this is not a promise to finish within 30 seconds.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-SETUP.md).

Linux `disengage` shares 15 seconds across operation-mutex admission and IPv4/IPv6
cleanup. Expired attempts start no new commands and retain ownership for retry in the
same process. Some rules may already be gone: timeout establishes neither complete
removal nor intact protection. Resolve the firewall delay and retry cleanup; after
process exit inspect leftovers in the original namespace using the recovery instructions.
This is not a whole-client shutdown bound.
[Details and validation](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-BUDGET.md).

Server-IP refresh before reconnect also shares 15 seconds across resolver, queue and
both families' commands. Expiry or stop cancels DNS/NSS waiting; late answers are
discarded without firewall work. Unknown inspection of an allowance does not authorize insertion. Refresh failure
stops reconnect while retaining protection; an unverified replacement does not remove
the previous address. This is not a hard whole-connection time bound.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REFRESH.md).

On Linux, successful transport-core teardown and gateway/exit-node forwarding cleanup,
with no recorded DNS/route/TUN cleanup failures, are required before releasing an enabled
kill-switch. If these conditions are not met, Qeli reports `kill-switch retained` and
keeps the egress barrier. Resolve the reported cleanup failure before retrying cleanup
or performing administrator recovery. A failed stop is not a successful network reset.

A fail-closed firewall on the client, **full-tunnel only**: while the tunnel is down, all
egress except loopback / tun / DHCP / the server IP is blocked, so a drop can't leak onto
the physical interface. Enabled with `kill_switch = true` in `[qeli]`.

With `kill_switch = true`, full-tunnel `exclude` entries remain fail-closed: the firewall
blocks non-tunnel egress, so those networks are **unreachable/blackholed**, not routed directly
over the physical interface. Clients log an explicit warning. Disable `kill_switch` if direct
access to an excluded network is required.

The implementation is **different on every OS** — not one cross-platform layer but three
independent mechanisms plus the system one on mobile. Summary:

| Platform | Mechanism | Scope | Manual teardown |
|---|---|---|---|
| Linux | `iptables`/`ip6tables`, own `QELI_KS_<tun>` chain | network namespace policy; cleanup per interface | §13.2 in GETTING-STARTED |
| Windows | WinDivert kernel DROP gate + crash-persistent WFP/`NetSecurity` default-block and `qeli_ks` allow group | whole host (all profiles) | `Remove-NetFirewallRule -Group qeli_ks` + restore the default |
| macOS | `pf`, anchor `qeli` (or `com.apple/qeli`) | whole host | flush the anchor (**not** `pfctl -f /etc/pf.conf`) |
| Android | system "Always-on VPN + Block connections without VPN" | whole host | in Android settings |
| iOS | none of its own — the system on-demand plays that role | — | — |

**The common rule is fail-closed before the connect loop and protection across reconnects.**
Desktop clients raise their own rules before the first attempt; Android verifies that the
system lockdown is already armed. If the guarantee cannot be confirmed, the connection does
not start. Desktop rules are lifted only on a **clean** stop and survive a crash; Android's
policy also survives a clean stop and remains until the user or MDM disables it in Settings.

> ⚠️ A bug in this subsystem blocks the machine's outbound traffic entirely. On Windows and
> macOS the scope is the **whole host**, not a single interface. Exercise it on a machine
> you can afford to lock out.

### Linux (`iptables`)

Every Linux client reserves its configured TUN/TAP name before DNS recovery and network
setup, including gateway/exit and `dev_attach` without a kill-switch.
One `dev` in one network namespace can belong to only one client session. Distinct names
remain independent; a kill-switch additionally requires the sole namespace policy claim.
Reservations span reconnect and are released after terminal cleanup; they require AF_UNIX.
Qeli servers, external interface owners and old clients do not participate: this does not
replace existing-device checks or authorize deletion of another owner's TUN.


Reinstalling a Linux kill-switch over prior protection uses temporary DROP rules `qeli-ks-rebuild:<tun>`. Failure or SIGKILL retains them; successful retry retires them after both required families are ready. Guards may block DNS/loopback until replacement is ready; `allow_ipv*_leak` cannot bypass recovery failure. For manual removal after stopping the owner, inspect guards separately from `QELI_KS_<tun>`. [Procedure §6.79](TROUBLESHOOTING.md#679-linux-kill-switch-rebuild-guard-remains-after-failure).

How it works (matters for manual teardown and for several instances on one host):

- Rules use a **separate chain per interface**, `QELI_KS_<tun_if>` (for example
  `QELI_KS_vpn0`), keyed by `dev = …` to scope cleanup. OUTPUT/FORWARD policy covers
  the entire network namespace: independent terminal-DROP chains do not compose.
  Before any changes, Qeli inspects both available families and refuses another
  `QELI_KS_<tun>` or legacy `QELI_KS`, including unhooked chains. Unknown/incomplete
  inventory also refuses; `allow_ipv4_leak`/`allow_ipv6_leak` do not bypass ownership
  conflicts. Before DNS recovery and firewall setup, the client atomically claims
  kill-switch ownership for its entire session in this network namespace.
  A second process using the same or another TUN is refused before changes; the lease
  spans reconnects and terminal cleanup. Once the owner exits, the same TUN may recover
  its remaining chain. Old binaries and external firewall tools do not participate.
  Use separate network namespaces for independently protected tunnels. Failure to obtain
  the lease also refuses startup; leak overrides do not bypass it.
- **DNS is scoped to the system resolvers** — the same as Windows and macOS. The rule used to
  be `--dport 53` to any destination, so while the tunnel was down **every** application's DNS
  queries egressed in cleartext on the physical interface, to a resolver of the querier's
  choosing. The resolvers are read before the tunnel overrides DNS: first
  `/run/systemd/resolve/resolv.conf` (the real upstreams when systemd-resolved is in use),
  then `/etc/resolv.conf`; loopback entries are skipped, as the stub is already covered by the
  `lo` rule. **Fail-closed:** with no resolver readable, no port-53 rule is installed at all
  and reconnects run off the allow-listed server IPs. The residual leak is an application
  querying those same resolvers; to avoid even that, give the server as an IP rather than a
  hostname.
- The chain holds ACCEPTs for loopback/tun/DHCP/server-IP and a terminal DROP, and is
  hooked in via a jump from **OUTPUT**. Every rule is verified with `iptables -C` (the
  iptables-nft wrapper can report success while doing nothing), and if a rule is missing
  the client **refuses to arm** and tears the half-built chain down — rather than raising a
  leaky kill-switch.
- In **router mode** (`gateway_nat`) the chain is also hooked from **FORWARD** — routed
  LAN traffic behind the client never traverses OUTPUT, so without the FORWARD hook it
  would be unprotected during a reconnect.
- The IPv4 kill switch needs working `iptables` even when there is currently no
  default route: DHCP or an administrator can add one during the session. If the firewall
  is unavailable, startup requires explicit `allow_ipv4_leak = true`; an empty
  `ip -4 route show default` snapshot no longer authorizes skipping protection.
- With positively verified `/sys/module/ipv6/parameters/disable = 1`, Qeli skips
  IPv6 firewall and address inspection during startup, refresh and cleanup. This disables
  module functionality (`ipv6.disable=1`), unlike `net.ipv6.conf.*.disable_ipv6`.
  A missing/unreadable file, any other content or an empty address list does not authorize
  bypassing failed firewall ownership inspection. IPv4 checks remain in force.
- IPv6 is programmed symmetrically (`ip6tables`). If the tool is unavailable or installation
  fails, the kill switch refuses even when the current global IPv6 address list is empty:
  an address may arrive during the session. The exceptions are verified global disabling
  of the IPv6 module or explicit `allow_ipv6_leak = true`. Refusal rolls back an already
  installed IPv4 leg and reports rollback failures. An IPv4-only host with the IPv6 module
  enabled now also needs working `ip6tables` or an explicit leak override.
  See also the `::/1`+`8000::/1` blackhole in the client routing-keys table.

It is removed automatically on a **clean** stop (Ctrl+C / SIGTERM); a crash leaves the
chain in place (fail-safe). **Never drop it with `iptables -F`** — that flushes the entire
`filter` table. The surgical manual teardown (OUTPUT + FORWARD + ip6tables) is in
[GETTING-STARTED.md](GETTING-STARTED.md) §13.2.

### Windows (WFP)

Requires **administrator** — the VPN already does (Wintun). Two layers are armed. A
WinDivert `WINDIVERT_FLAG_DROP` filter discards physical-interface egress in the kernel
unless it targets the server, the configured physical DNS resolvers or DHCP; packets routed
to the Wintun interface do not match. This is the strict allow-list layer: pre-existing WFP
Allow rules cannot override it, and matching packets are not copied through userspace, so it
does not enter the VPN throughput path. In parallel, `NetSecurity` flips the per-profile
`DefaultOutboundAction` to `Block` and installs the small `qeli_ks` allow group. That second
layer persists after an application crash; the WinDivert handle is process-bound and is
removed by Windows when the process exits.

The ordering is deliberate: the state file recording the previous per-profile
`DefaultOutboundAction` is written first, the kernel drop gate is opened, then the allow
rules are added, and **only then** is the default flipped to `Block`. The whole script runs as a single PowerShell invocation
with `$ErrorActionPreference='Stop'`, so a failing rule aborts it **before** the default
flips.

**DNS is deliberately narrowed** to the resolvers actually configured on the system, never
"port 53 to anywhere": a broad rule would let every application's DNS query egress in
cleartext on the physical NIC exactly while the tunnel is down — the metadata leak the
kill-switch exists to stop. The resolvers are needed so the server hostname can be
re-resolved on reconnect. With no resolvers, no rule is created at all and the reconnect
uses the cached server IP. Residual risk accepted: an application querying those same
resolvers still leaks its own query.

The state file is stamped with the process pid and start time, so the startup `Sweep` can
tell a genuine crash (owner gone) from a live tunnel owned by another instance — a second
launch must **not** sweep away an active kill-switch. With no saved state, `Disengage`
restores the neutral `NotConfigured` rather than an explicit `Allow`, which would weaken a
pre-existing firewall policy we have no record of.

Manual teardown (after a crash, if `Sweep` somehow did not run):
```powershell
Remove-NetFirewallRule -Group qeli_ks
Set-NetFirewallProfile -All -DefaultOutboundAction Allow
```

### macOS (`pf`)

<!-- normative-sync: mac-pf-ownership-q28-v1 -->

Qeli requires an already loaded unconditional anchor reference for qeli or com.apple/*.
Check the active configuration with sudo pfctl -sr. With no reference, connection with
a kill-switch refuses; a firewall administrator must add the reference through the host's
existing policy manager. Qeli does not load /etc/pf.conf automatically: empty filter output
does not prove absence of nat/rdr/scrub. Existing quick/pass rules and anchor ordering must
also be assessed by that administrator; host traffic protection is not qualified by the
managed selftest. Cleanup preserves global pf enabled state and foreign rules/references.
Only the recorded owner or a stale owner's recovery may remove Qeli protection. Manual
flush below is an explicit override and should follow stopping all Qeli clients/daemons.


Requires **root** — the tunnel already does. A `block out all` ruleset is loaded that passes
only loopback, the utun interface(s), the server IP(s), DNS and DHCP.

The rules live in **their own anchor** (`qeli`), so arming and clearing never touch another
tool's pf rules. If the host's main ruleset carries the stock `anchor "com.apple/*"`
reference, the child anchor `com.apple/qeli` is used instead — it is already evaluated by
that existing reference, so the main ruleset need not be touched at all. The reason for this
design: `pfctl -f /etc/pf.conf` reloads the **file**, not whatever the host actually had
loaded, so "restoring" through it discarded other tools' dynamic rules. The system-TUN path
reserves the real utun device before loading pf and permits only that exact interface. During
an atomic persisted-plan replacement, the old and replacement utun names are allowed together
only until the swap completes.

Manual teardown — flush the anchor, **not** `pfctl -f /etc/pf.conf`:
```bash
sudo pfctl -a com.apple/qeli -F rules
sudo pfctl -a qeli -F rules
```

### Android and iOS

On Android the app does **not** raise a firewall of its own: the real kill-switch here is
the system one. The app reads, preserves and passes `kill_switch = true` to the shared Rust
core, but it starts a full tunnel only after `VpnService` has verified both system flags:
Settings → Network → VPN → Qeli → **Always-on VPN** + **Block connections without VPN**.
If either flag is off, the Android adapter refuses the unprotected connection instead of
acknowledging the `NetworkPlan`. The pre-connect proof combines Qeli's prepared-provider state
with Android's read-only-to-apps secure lockdown policy. After TUN creation, the adapter also
requires the live owner-scoped `isAlwaysOn()` and `isLockdownEnabled()` results immediately
before ACK, so disabling lockdown during the handshake cannot produce a false Connected state.

A normal VPN app cannot enable those switches programmatically; that decision belongs to the
user (or a device owner/MDM). Once armed, the OS policy is stronger than a process-local
firewall because it remains in force if the app crashes, stops, or reconnects. The observable
API exists on Android 10+, so Android 9 refuses a profile that requests `kill_switch = true`.
As on desktop, split-tunnel does not engage this key and the client logs that fact explicitly.

<!-- normative-sync: android-platform-restart-q29-v1 -->

System blocking and automatic VPN restart are separate properties. On the tested
Android14/API34 image,external SIGKILL prevented automatic restart even for a
minimal Java VpnService without Qeli core;negative IPv4 UDP probes remained
blocked under lockdown. This is a boundary of that fixture,not established behavior
for every device. Details and exact fingerprint:
[Android system lifecycle audit](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md).

On iOS `kill_switch` is **not supported**; the system on-demand plays the fail-closed role
(see the iOS footnotes in the client-keys table above).

## Exit node (`exit_node`)

Topology: `Win client → server (public IP) → exit client (grey IP behind NAT) → internet`.
Some clients' traffic exits under **another** client's IP — e.g. a home/NAT'd line. It is the
mirror of `gateway_nat`: that pushes a LAN behind the client INTO the tunnel; `exit_node`
lets traffic that arrived FROM the tunnel out the client's own physical WAN.

### What to set where (three nodes)

**Exit client** (Linux; server/router/RPi), split-tunnel:
```ini
[qeli]
server    = <public-IP-of-server>:443
user      = exit
pass      = ...
# keep this host's own internet on the WAN — it is the exit
gateway   = false
# use auto/off for an IPv4-only exit
ipv6      = required
exit_node = true
```

**Server** — register the exit behind the exit user, allow client-to-client, and grant the
exit families to the consumers entitled to use them:
```ini
[profile:tcp]
# without this the server won't move a packet session-to-session
routing.client_to_client = true

# The node traffic exits THROUGH
[user:exit]
password_hash = $argon2id$...
# "the whole internet is behind this client" (inbound iroute)
client_subnet = 0.0.0.0/0
# IPv6 internet is behind the same exit
client_subnet = ::/0

# A consumer of the exit — /0 is the server-side exit authorization marker
[user:alice]
password_hash = $argon2id$...
# CIDR FIRST; see "Routes (route) — in detail"
route = 0.0.0.0/0
# authorize IPv6 exit use for this consumer too
route = ::/0

# A plain user without that line does NOT use the exit — it egresses via the server
[user:bob]
password_hash = $argon2id$...
```

**Consumer** (Win/any client) — explicitly opts into full-tunnel capture locally:
```ini
[qeli]
server  = <public-IP-of-server>:443
user    = alice
pass    = ...
gateway = true
ipv6    = required
```

Who may use the exit is decided **on the server**, independently per family, by the
`route = 0.0.0.0/0` / `route = ::/0` lines in the relevant `[user:*]`. These two defaults are
authorization markers: qeli removes them from AuthOK rather than allowing a server to force
full-tunnel capture. The consumer explicitly consents with local `gateway = true`; once that
traffic reaches the server, only an authorized source session may take the internal `/0` next
hop. In the example `bob` still egresses through the server itself (`routing.nat.enabled`),
while `alice` goes out through the exit node.

**Checking that it came up.** From the consumer, the public IP should become the exit node's,
not the server's:
```bash
curl -s https://api.ipify.org ; echo      # expect the exit node's WAN IP
curl -6s https://api64.ipify.org ; echo   # expect its IPv6 WAN address
```
On the exit node the startup log carries `Exit-node engaged` with the WAN it picked, and the
forward counters are visible there too:
```bash
sudo iptables -t nat -L POSTROUTING -v -n | grep MASQUERADE   # packets should climb
sudo ip6tables -t nat -L POSTROUTING -v -n | grep MASQUERADE  # IPv6/NAT66 counter
```

Exit NAT rules have an exact `qeli-exit-node:<tun>` comment, for example
`qeli-exit-node:vpn0`. Multiple TUNs on one WAN get distinct equivalent MASQUERADE
rules: stopping one does not delete another's rule. MARK/FORWARD/MSS keep the
`qeli-exit-node` comment and are distinguished by interfaces. Bits selected by
`0x51/0x51` are reserved for Qeli exit traffic and must not be reused by other marking.
An exit-TUN packet without that mark is dropped in FORWARD: if policy routing
sends it to a WAN Qeli has not selected, the client's original address cannot
egress. After a confirmed roaming update or the next default-route check
(every 5 seconds), Qeli adds rules for the new WAN; packets remain blocked
until installation succeeds.
If the default route points back to the exit TUN, the exit node rejects setup
or refresh of that path: it needs a separate external WAN.
For ECMP across different interfaces or equal best metrics on different WANs,
the exit node rejects automatic selection; give one external WAN a lower
metric. [Verification](../reports/audit-0.8.2/AUDIT-Q25-WAN-ECMP.md).
[Monitor verification](../reports/audit-0.8.2/AUDIT-Q25-EXIT-WAN-MONITOR.md). `exit_node = true` cannot be combined
with `gateway_nat = true` or `forward = true` on the same TUN: those modes
require different handling of unmarked traffic arriving from the tunnel.

Qeli brings its owned exit-TUN up only after installing the guard;
`dev_attach = true` is rejected for exit nodes because an external TUN may
already forward packets. Do not rename, remove, or replace the selected
physical WAN while an exit node is active: old firewall rules match its name
and will apply to a new device reusing that name even without refresh.
Stop the profile, verify successful rule cleanup, change the WAN, and then
start it again. [Rename/reuse evidence](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md).

Cleanup uses only WANs remembered during installation, including previous uplinks;
without ownership records, the current default route cannot authorize deletion.
An old MASQUERADE with an unsuffixed comment is preserved. After confirming its old
owners have stopped, inspect and recover it explicitly. WAN records are in memory:
successful cleanup in a new process does not prove recovery of pre-crash rules.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md).

### How it works and what the flag programs

Trace a packet Win→8.8.8.8: Win sends its default into the tunnel → the server forwards it to
the exit client's session via `client_to_client` (the exit registered `0.0.0.0/0`) → the exit
client forwards it out its WAN and **masquerades** it; the reply returns the same way. **The
internet sees the exit node's IP** — that is the point.

The server keeps `0.0.0.0/0` and `::/0` in qeli's internal longest-prefix table. It does
**not** install either as the Linux host's default route: doing that would capture the
server's own WAN and control connection. Packets move directly into the normal downlink
pipeline, where client isolation, MTU/fragmentation, rate limits and encryption still apply.

`exit_node = true` installs generation-owned rules (idempotent within that generation;
cleaned before releasing the original TUN and reinstalled on full reconnect):
- `net.ipv4.ip_forward = 1` + relaxed `rp_filter` on the tun and WAN (asymmetric path);
- for negotiated IPv6, `net.ipv6.conf.all.forwarding = 1`, `accept_ra = 2` on an
  RA-based IPv6 WAN, and a separately verified `ip6tables` NAT66 path;
- a mark on `tun→WAN` packets and a `MASQUERADE` of **only those** out the WAN (scoped by
  packet mark, not source subnet: the pool is unknown until after auth, and locally-generated
  host traffic is never marked, so it is never masqueraded);
- a `FORWARD … ACCEPT` both ways and a `TCPMSS` clamp (without it ping works but TCP/HTTPS stalls);
- the WAN is selected from **`ip route show default`** using the lowest metric
  among usable routes. If the preferred routes use different interfaces (ECMP
  or tied priority), Qeli refuses to select just one WAN. Only when there is no
  usable default route does it fall back to `ip route get 1.1.1.1`; that fallback
  does not prove every policy route is suitable. IPv6 selects its uplink
  separately through `ip -6 route` and may use a different interface.
  [Route metrics](../reports/audit-0.8.2/AUDIT-Q25-WAN-METRIC.md) and
  [ECMP](../reports/audit-0.8.2/AUDIT-Q25-WAN-ECMP.md).

The rules are removed on a **clean** stop; **a crash leaves them in place** — like the
kill-switch this is fail-safe, not forgetfulness. Manual cleanup after a crash is in
[GETTING-STARTED.md](GETTING-STARTED.md) §13.2.

The host-wide forwarding, `rp_filter`, and IPv6 `accept_ra` values use a locked persistent
owner journal shared by server profiles and standalone client processes. Ownership is
registered even when the kernel already has the requested value. A clean stop restores
the original after the last `PID + process-start-time + TUN` owner, provided the original
object remains verified. Administrator changes are not overwritten. The next operation
prunes confirmed dead owners; valid state from another boot is discarded without
replaying previous values.

Unreadable or malformed `/proc/<pid>/stat` does not prove that an owner died. If its
state cannot be confirmed, the entry remains and new acquisition or startup recovery
reports `cannot verify host sysctl owner(s)`. Releasing a verified scope continues
independent cleanup and reports remaining failures. Failed sysctl reads/writes retain
the original value for recovery.

Internal `sysctls.state` version 4 separates entries by network namespace. Each group
also records PID and exposed time namespace identity; mismatch stops the operation
before checking owners or changing settings. Foreign network groups remain intact and
their PIDs are not probed. Participants in one network must share a state directory
and PID/time context; separate directories do not replace coordination. Procfs must
match the current PID namespace and expose `NStgid` and namespace metadata.

For named-interface `rp_filter`/`accept_ra`, Qeli retains the open sysctl fd and its
namespace until the entry is released. Another process can join only with a matching
object and a confirmed live owner. Restoration never reopens the setting by name:
rename/delete/recreate, even with the same ifindex, does not authorize writing an old
value into a new interface. `ENOENT` does not authorize forgetting the original either.
After all live descriptors are lost, including SIGKILL, the entry remains for manual
recovery and startup recovery returns an error. Exception: if `original == managed`,
Qeli changed nothing and can release the entry without accessing the interface. Global
settings and `all`/`default` additionally require matching `network_cookie`
and boot-id. Reused dev/inode with a different cookie never authorizes replay. Managed
sysctls require `SO_NETNS_COOKIE`: unsupported kernels allow empty recovery but refuse
acquire before mutation. Cookie does not replace the original named-interface fd.

Nonempty v1/v2/v3 journals from the current boot are not migrated automatically. Version 2
reports `legacy v2 host sysctl journal lacks live descriptor ownership`; v1 retains
`legacy host sysctl journal has no namespace identity`. Before upgrading, stop old
participants and complete recovery in the original namespaces while the original
interfaces remain verified. Do not blindly run old recovery after an interface was
replaced. Alternatively, use a planned host reboot. Empty v1/v2/v3 or valid previous-boot
state allows transition; old values are not replayed after reboot. Do not manually
change version/boot-id or remove the journal to force startup. Mixed journal versions
are unsupported. User configs remain INI; no new keys were added.
V3 reports `legacy v3 host sysctl journal lacks durable namespace generation`.
[V4 contract, migration and limits](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-GENERATION.md).

On Unix shared atomic writes and removal of the final sysctl journal sync the
parent directory. `published ... persistence is uncertain` means the file was
already replaced, but crash durability was not confirmed; reread state before
retrying. [Troubleshooting](TROUBLESHOOTING.md#661-published--persistence-is-uncertain).

Sysctl requires a real absolute state directory: `STATE_DIRECTORY` or `/var/lib/qeli`.
Symlinks/`..` in the path and group/world write are rejected; operations stay bound
to one open directory. Root and the service-directory owner retain shared access.
[Access policy](../reports/audit-0.8.2/AUDIT-Q25-STATE-DIRECTORY.md).

### Caveats

- **Linux only** (`iptables` and, when IPv6 is negotiated, `ip6tables`), like
  `gateway_nat`/`forward`. An exit node is a server/router/RPi;
  the flag does nothing on Windows/macOS/Android. The consumer must opt into full tunnel
  locally with `gateway = true` and have the matching server-side `/0` authorization marker.
- **Split-tunnel only.** With `gateway = true` the host's own default flips into the tunnel
  and there is no WAN to forward out of; validation rejects that combination.
- Not needed on the server: the server is already an exit via `routing.nat.enabled` (it
  masquerades clients out its public IP). `exit_node` is about exiting through *another* client.
- **Liability.** All traffic leaves under the exit owner's IP.
- **Double hop.** Traffic transits server + exit — the cost of the scheme.

## Routing networks behind nodes WITHOUT NAT (`client_subnet`, `forward`, `forward_private`)

Since 0.7.11 qeli does site-to-site L3 routing — traffic to any networks through the server or a
client, **without NAT** (real source IPs preserved; NAT is only for internet egress = `gateway_nat`).

### 1. `client_subnet` (per-user, server) — a subnet BEHIND a client (OpenVPN `iroute`)

By default the server routes to a client ONLY by its assigned pool IP (`by_ip`) — a packet to any
other of its addresses is dropped. `client_subnet` registers an extra address/subnet as an **inbound**
route into that client's tunnel (and adds `ip route … dev <tun>` on the server for non-default
prefixes; exit-node `/0` routes remain internal). Set per user (panel
→ user card → "Client subnets", or the users file):

```ini
[user:branch1]
password_hash = ...
; the LAN behind client branch1
client_subnet = 192.168.50.0/24
; several lines or a comma-separated list
client_subnet = 10.20.0.7/32
```

`0.0.0.0/0` and `::/0` are accepted only as internal exit-node next hops and are never
installed as Linux host defaults. Registration skips a non-default subnet covering the tunnel gateway.
If the same canonical prefix is already claimed, the first owner remains; the second
client authenticates without that conflicting route.

Outbound packets must pass allowed_networks and current source ownership: exact pool leases
take precedence over longest-prefix client_subnet. A broader prefix or /0 cannot impersonate
another client. An exit /0 permits external reply sources. A skipped conflicting route is
not inherited when its owner disconnects; a new connection must register it. The rule is
shared by TCP/UDP/QUIC and IPv4/IPv6. Server tunnel addresses remain local destinations
even with an exit /0; clients cannot use those reserved addresses as sources.
Authentication also fails rather than
replacing or adopting a pre-existing exact host route that lacks Qeli's TUN+metric (`42760`) ownership
marker. A marked route left by an earlier Qeli process is recovered safely; any unmarked route
must be removed or reconciled explicitly before connecting. At most 16 `client_subnet` entries
are accepted per user, bounding kernel-route work during authentication.

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
This mode requires `iptables`: qeli verifies the permits after insertion and starts without explicit
rules only when the built-in `FORWARD` chain is otherwise empty and its policy is read back as exactly
`ACCEPT`. A `DROP`, any explicit rule/jump, or an unreadable chain fails profile startup instead of
acknowledging a route that would black-hole transit traffic.

### Site-to-site example (server LAN ↔ LAN behind branch1), no NAT

Server: `[user:branch1] client_subnet = 192.168.50.0/24`, on the profile `routing.forward_private = true`,
`routing.nat.enabled = false`; the client gets the return route to the server LAN via
`routing.advertised_routes` (push). Client branch1: `forward = true`. Result: a host on the server LAN
pings `192.168.50.x` behind branch1 and back — no NAT, real addresses.
For the IPv6 equivalent, use an IPv6 `client_subnet`, set the profile's
`routing.ipv6.mode = route`, advertise the server-LAN return prefix, and keep `forward = true`
on branch1. Route mode permits both server-originated OUTPUT and third-party LAN FORWARD along
the authenticated dynamic route without NAT66.

## Multiple listeners per profile (`listen`)

A profile listens on ONE socket by default. To reach the SAME profile (one TUN / pool / identity /
users) on more ports/addresses, add `listen` (repeatable) instead of cloning the profile:

```ini
[profile:main]
; specific primary address; a wildcard would overlap the extra listener
bind.address = 203.0.113.4
bind.port = 443
bind.transport = tcp
; fallback port
listen = 0.0.0.0:8443
; another address on a multi-homed host
listen = 203.0.113.5:443
```

Each `listen` is a bare `addr:port` on the SAME transport as the profile (`bind.transport`). A
profile is ONE transport — use a separate profile for the other (a per-listener transport is not
supported; an `addr:port udp` suffix is rejected as malformed). Panel: profile → "Extra listeners". A
malformed spec is rejected at admission. A profile is ready only after **every** listener binds,
including every UDP `SO_REUSEPORT` socket. An occupied primary or extra port stops that
generation; after successful rollback the server retries, while other profiles continue.
Setup until readiness has one 120-second budget; that timer does not limit a ready profile.

For a newly created Quick Start profile, the backend adds the V6ONLY `[::]:port` outer listener
only when its host snapshot reports an IPv6 interface/default route. This keeps IPv4 Quick Start
launchable on kernels with IPv6 disabled. Re-launching an existing profile never removes or
rewrites its manually configured listener set.

## Lifecycle hooks: `post_up` / `post_down`

> ⚠️ Client hooks are executed only by the standalone **Linux** binary, including
> OpenWrt/Keenetic. Windows, macOS, Android and iOS preserve the keys when a profile is moved,
> but never run the commands. These keys are **file-only**: they are excluded from `qeli://`
> links and the panel/API cannot set them remotely.

A lifecycle hook is a local command for actions not covered by qeli's built-in routing: policy
routing, extra firewall/mangle rules, integration with another network manager, local logging or
notifications. It runs through `/bin/sh -c` with the same privileges as the qeli process.

### When client hooks run

- `post_up` runs once after authentication and successful application of the first
  `NetworkPlan`: TUN/TAP exists and addresses, routes, DNS and gateway/exit firewall state are
  already applied. Packet forwarding starts immediately after the hook returns. Authentication
  failures and rejected plans do not run it.
- A normal reconnect creates a new network generation but does not run `post_up` again. Its
  context snapshot is refreshed, so the eventual `post_down` receives the latest successfully
  applied plan.
- `post_down` runs once on a handled terminal exit: SIGINT/SIGTERM, reconnect disabled, a terminal
  server kick, exhausted `reconnect_retries`, or core startup/teardown failure after kill-switch
  setup. A hook invocation does not mean that cleanup succeeded. Core teardown failure takes
  precedence over a simultaneous stop signal and prevents reconnect; Qeli attempts forwarding
  cleanup and retains an enabled kill-switch. If core startup fails but subsequent teardown and
  forwarding cleanup succeed, the barrier can be removed while the startup error remains fatal.
- A reported DNS, route, TUN or setup-rollback cleanup failure terminates the client with
  `network_cleanup_failed` / `network_cleanup`. It takes precedence over signal-success and
  reconnect. Core teardown failure still has higher reason priority. An enabled kill-switch
  remains installed even if a later guard retry succeeds; that retry does not erase the
  previously reported failure. The record belongs to this client run and is not reset between
  attempts. Inspect the log and current network state before administrator recovery.
- Normal TCP shutdown closes background-task admission and joins readers/writers, the
  pipeline and connection-maintenance tasks before DNS restoration and TUN cleanup.
  Management-event errors follow the same path. The Linux TCP/UDP path monitor also waits
  for its running blocking jobs. This does not bound system commands or guarantee async
  joining on forced cancellation of the entire future; see [validation limits](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md).
- UDP uses the same task owner: active/candidate/draining receive, candidate connection
  and the Linux monitor finish before platform-path inspection/rollback, followed by DNS/TUN
  cleanup. Management-event errors follow this sequence too. Cancelling a candidate stops
  its receiver while the active path keeps running; see [details and validation limits](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md).
- Cancelling an already-started Unix TUN/Wintun shutdown retains worker ownership and
  waits for worker termination during pump destruction. This wait can be synchronous;
  it does not confirm completion of other tasks or network recovery when cancelling
  the whole client. See [the contract and validation](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).
- For `reality-tls`, the client group also owns internal HTTP/2 drivers/bridges from the
  connection stage. Normal TCP teardown joins them before DNS/TUN cleanup; the native runner
  joins the TCP group before finish_generation after attempt cancellation. This does not
  validate early platform rollback or UDP cleanup; see [limits](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).
- If no plan was ever applied, `post_down` may still run. `QELI_PLAN_AVAILABLE=false`,
  plan-dependent values are empty, and JSON `network_plan` is `null`.
- SIGKILL, process crashes and power loss cannot run `post_down`. A script must be idempotent and
  able to repair its own stale state on the next start.
- Current-generation network resources may already be gone by `post_down`. Use its snapshot to
  remove state created by the hook; do not assume the interface still exists.
- Each invocation has a 30-second execution/output deadline. Hook failures are logged
  without rejecting the tunnel; process cleanup details are described below.

Minimal configuration:

```ini
[qeli]
post_up   = /etc/qeli/hooks/client-route.sh "$@"
post_down = /etc/qeli/hooks/client-route.sh "$@"
```

The effective invocation is:

```sh
/bin/sh -c '<post_up/post_down value>' qeli-hook '<ifname>' '<gateway>'
```

Inside the shell command, `$1 = ifname` and `$2 = primary tunnel gateway` (IPv4 first, then IPv6;
empty when no plan exists). Add `"$@"` after an external script path, as above, to forward those
positional parameters into that script. New scripts should prefer named `QELI_*` variables: they
are order-independent and expose the complete dual-stack context.

### Complete client variable reference

Every boolean is the string `true` or `false`. Every variable is defined; a fact that is not yet
known or not applicable is an empty string. Array indices begin at zero and end at `COUNT - 1`.

#### Lifecycle and identity

| Variable | Meaning |
|---|---|
| `QELI_HOOK_API` | Environment/JSON contract version; currently `1`. Scripts should check it before depending on newer fields. |
| `QELI_EVENT` | `post_up` or `post_down`, allowing one script to handle both events. |
| `QELI_PROFILE`, `QELI_PROFILE_NAME` | Profile name derived from the config filename without its extension. The latter is an explicit alias. |
| `QELI_CONFIG_PATH` | Canonical client INI path when canonicalization succeeds, otherwise the path supplied at launch. |
| `QELI_PID` | PID of the qeli process invoking the hook. |
| `QELI_PLAN_AVAILABLE` | `true` after at least one authenticated `NetworkPlan` was committed. |
| `QELI_PLAN_GENERATION` | Generation number of the latest committed plan. |
| `QELI_SESSION_DURATION_SECONDS` | Seconds since this process committed its first plan; `0` before that. Reconnect time between generations is included. |
| `QELI_REASON`, `QELI_STOP_REASON` | Event reason. `post_up`: `connected`; `post_down`: `shutdown_signal`, `reconnect_disabled`, `server_kick`, `max_retries`, `core_start_failed`, `core_stop_failed`, `network_cleanup_failed` or `kill_switch_failed`. `QELI_REASON` is the generic alias. |
| `QELI_ERROR_CODE` | Stable terminal category: empty, `shutdown`, `transport_error`, `server_kick`, `max_retries`, `core_start`, `core_stop` or `network_cleanup`. |
| `QELI_ERROR_MESSAGE` | Human-readable final error with no secrets. It is not a stable machine-parsing API. |
| `QELI_CONTEXT_FILE`, `QELI_NETWORK_PLAN_FILE` | Two names for the same temporary full-context JSON file. It is mode `0600` and removed as soon as the hook exits. Both values are empty if file creation failed. |

#### TUN/TAP and addresses

| Variable | Meaning |
|---|---|
| `QELI_TUN`, `QELI_IFNAME` | Actual interface name. `QELI_TUN` is the compatibility alias; prefer `QELI_IFNAME`. |
| `QELI_IFINDEX` | Numeric Linux interface index captured when the latest plan was applied; empty if it has not been determined yet. |
| `QELI_DEVICE_TYPE`, `QELI_TUN_MODE` | `tun` or `tap`; equivalent names. |
| `QELI_TUN_REUSED` | `true` for `dev_attach=true`, meaning an external owner created/manages the interface. It does not mean reconnect. |
| `QELI_MTU` | Effective negotiated MTU. |
| `QELI_FAMILY_MODE` | `ipv4`, `ipv6` or `dual`. |
| `QELI_TUNNEL_ADDRESS` | Legacy primary-address projection from `NetworkPlan`. Use the family-specific values below for exact dual-stack logic. |
| `QELI_PREFIX_LEN` | Prefix length of the legacy projection. |
| `QELI_TUNNEL_GATEWAY` | Legacy gateway projection from the plan. |
| `QELI_GATEWAY` | Primary gateway also supplied as `$2`: IPv4 when present, otherwise IPv6. |
| `QELI_IPV4_ADDRESS`, `QELI_IPV6_ADDRESS` | Assigned interface address without a prefix. |
| `QELI_IPV4_PREFIX`, `QELI_IPV6_PREFIX` | Assigned address prefix-length aliases for `*_PREFIX_LEN`. |
| `QELI_IPV4_PREFIX_LEN`, `QELI_IPV6_PREFIX_LEN` | Prefix applied to the interface address; normally `/32` and `/128` on an L3 TUN. |
| `QELI_IPV4_ON_LINK_PREFIX_LEN`, `QELI_IPV6_ON_LINK_PREFIX_LEN` | Pool/on-link prefix, distinct from the host prefix. |
| `QELI_IPV4_CIDR`, `QELI_IPV6_CIDR` | Interface address with its applied prefix, for example `10.9.0.2/32`. |
| `QELI_IPV4_SUBNET`, `QELI_IPV6_SUBNET` | Calculated on-link network, for example `10.9.0.0/24`. |
| `QELI_IPV4_GATEWAY`, `QELI_IPV6_GATEWAY` | Inner gateway for that address family. |

Every address is also exported as an indexed group:

- `QELI_ADDRESS_COUNT`;
- `QELI_ADDRESS_N_FAMILY` (`ipv4`/`ipv6`);
- `QELI_ADDRESS_N_ADDRESS`;
- `QELI_ADDRESS_N_PREFIX_LEN`;
- `QELI_ADDRESS_N_ON_LINK_PREFIX_LEN`;
- `QELI_ADDRESS_N_GATEWAY`;
- `QELI_ADDRESS_N_CIDR`;
- `QELI_ADDRESS_N_SUBNET`.

#### Server and physical carrier

| Variable | Meaning |
|---|---|
| `QELI_SERVER`, `QELI_SERVER_HOST` | Host from `server = ...`, possibly a DNS name. `QELI_SERVER` is the compatibility alias. |
| `QELI_SERVER_PORT` | Profile port. |
| `QELI_SERVER_ENDPOINT` | Correctly formatted `host:port`, including brackets around an IPv6 literal. |
| `QELI_CARRIER_ADDRESS` | Actual socket peer selected after DNS; this is the address whose physical bypass is pinned. |
| `QELI_CARRIER_ENDPOINT` | Actual `IP:port`. |
| `QELI_CARRIER_LOCAL_ADDRESS` | Source selected by `ip route get`, or the configured `local`; empty when unavailable. |
| `QELI_CARRIER_IFNAME`, `QELI_CARRIER_IFINDEX` | Physical uplink and its ifindex, never the TUN. |
| `QELI_CARRIER_GATEWAY` | Physical next hop to the carrier; empty for an on-link peer. |
| `QELI_PROTOCOL` | Outer transport: `tcp` or `udp`. |
| `QELI_WIRE_MODE` | `plain`, `fake-tls`, `obfs` or `reality-tls`. |
| `QELI_FRONTING` | Configured fronting mode (`websocket`/`none`). |

Do not resolve `QELI_SERVER_HOST` again when current-carrier identity matters: round-robin DNS may
return another address. Use `QELI_CARRIER_ADDRESS` for bypass rules.

#### Routing and client mode

| Variable | Meaning |
|---|---|
| `QELI_ROUTING_MODE` | Effective `full` or `split` mode. |
| `QELI_FULL_TUNNEL` | Whether all client traffic is captured into the tunnel. |
| `QELI_KILL_SWITCH` | Whether the committed plan includes a kill switch. |
| `QELI_ROUTE_LOCAL` | Configured `route_local`. |
| `QELI_GATEWAY_NAT` | Configured `gateway_nat`. |
| `QELI_FORWARD` | Pure L3 forwarding is enabled. |
| `QELI_EXIT_NODE` | This client is an exit node for other peers. |
| `QELI_ALLOW_IPV4_LEAK`, `QELI_ALLOW_IPV6_LEAK` | Explicit fail-closed escape hatches for a missing family. |
| `QELI_LAN_SUBNET`, `QELI_LAN_SUBNET_IPV6` | Configured IPv4/IPv6 router-mode source networks. |

Lists:

- `QELI_ROUTE_COUNT`, then `QELI_ROUTE_N_CIDR`, `QELI_ROUTE_N_GATEWAY`,
  `QELI_ROUTE_N_METRIC`: final plan routes;
- `QELI_PUSHED_ROUTE_COUNT`, then `QELI_PUSHED_ROUTE_N`: original validated server-pushed routes;
- `QELI_INCLUDE_COUNT`, then `QELI_INCLUDE_N`: local `include` entries;
- `QELI_EXCLUDE_COUNT`, then `QELI_EXCLUDE_N`: local `exclude` entries.

#### DNS and negotiated data-plane facts

| Variable | Meaning |
|---|---|
| `QELI_DNS_COUNT` | Number of applied resolver endpoints. |
| `QELI_DNS_N` | Correctly formatted `address:port`, including IPv6 brackets. |
| `QELI_DNS_N_ADDRESS`, `QELI_DNS_N_PORT` | Resolver address and port separately. |
| `QELI_MAX_STREAMS` | Negotiated bonded-stream limit. |
| `QELI_ADAPTIVE` | Whether adaptive stream-count control is enabled. |
| `QELI_ROAMING_POLICY` | Client policy: `off`, `auto` or `required`. |
| `QELI_ROAMING_MODE` | Negotiated `reconnect`, `udp_roam_v1`, `tcp_resume_v2` or `tcp_handover_v2`. |
| `QELI_RECORDIZER_MODE` | `packet_mux_v1` or `legacy_packet_per_record`. |
| `QELI_RECORDIZER_POLICY` | Negotiated Recordizer policy; empty for legacy mode. |
| `QELI_PADDING_ENABLED`, `QELI_PADDING_MIN`, `QELI_PADDING_MAX` | Effective padding and byte range. |
| `QELI_NORMALIZATION_MAX` | Largest negotiated normalization target, or `0` when disabled. |
| `QELI_HEARTBEAT_ENABLED`, `QELI_HEARTBEAT_INTERVAL_MS` | Effective heartbeat and interval. |
| `QELI_SHAPING_ENABLED` | Whether traffic shaping is enabled. |

### JSON context and list processing

Use `QELI_CONTEXT_FILE` for complex logic. Indexed environment variables are convenient for
small shell commands; JSON preserves types, arrays and the complete canonical `NetworkPlan`
without indirect `eval`.

Top-level schema:

```json
{
  "hook_api": 1,
  "event": "post_up",
  "profile": "office",
  "config_path": "/etc/qeli/clients/office.conf",
  "process_id": 1234,
  "interface": { "name": "vpn0", "index": "17", "device_type": "tun", "reused": false },
  "server": { "configured_host": "vpn.example.com", "port": 443, "endpoint": "vpn.example.com:443", "protocol": "tcp", "wire_mode": "reality-tls", "fronting": "none" },
  "carrier": { "address": "203.0.113.10", "interface": "eth0", "interface_index": "2", "local_address": "192.0.2.20", "gateway": "192.0.2.1" },
  "routing": { "route_local": false, "gateway_nat": false, "forward": false, "exit_node": false, "allow_ipv4_leak": false, "allow_ipv6_leak": false, "lan_subnet": "", "lan_subnet_ipv6": "", "include": [], "exclude": [] },
  "lifecycle": { "reason": "connected", "error_code": "", "error_message": "", "session_duration_seconds": 0 },
  "network_plan": { "generation": 1, "family_mode": "dual", "addresses": [], "routes": [], "pushed_routes": [], "dns_servers": [] }
}
```

Examples:

```sh
# Every final route
jq -r '.network_plan.routes[] | "\(.cidr) via \(.gateway) metric \(.metric)"' "$QELI_CONTEXT_FILE"

# First IPv4 gateway without assuming address order
jq -r '.network_plan.addresses[] | select(.family == "ipv4") | .gateway // empty' "$QELI_CONTEXT_FILE" | head -n1
```

The file exists only until the command returns. A background process that needs the snapshot must
copy it to a protected location inside the hook. JSON and `QELI_*` deliberately exclude the
password, `password_command`, obfs/reality secrets, private/public identity keys, session token and
data-plane key material.

### One idempotent script for both events

```sh
#!/bin/sh
set -eu

IFNAME=${QELI_IFNAME:?QELI_IFNAME is required}
LAN=192.168.50.0/24
TABLE=100

case "$QELI_EVENT" in
  post_up)
    GATEWAY=${QELI_IPV4_GATEWAY:?IPv4 gateway is required}
    ip rule add from "$LAN" table "$TABLE" 2>/dev/null || true
    ip route replace default via "$GATEWAY" dev "$IFNAME" table "$TABLE"
    ;;
  post_down)
    ip rule del from "$LAN" table "$TABLE" 2>/dev/null || true
    ip route flush table "$TABLE" 2>/dev/null || true
    ;;
  *)
    echo "unsupported QELI_EVENT=$QELI_EVENT" >&2
    exit 2
    ;;
esac
```

Install and validate it:

```sh
sudo install -o root -g root -m 0700 client-route.sh /etc/qeli/hooks/client-route.sh
sudo chown root:root /etc/qeli/clients/office.conf
sudo chmod 0600 /etc/qeli/clients/office.conf
sudo qeli check-config --client /etc/qeli/clients/office.conf
```

A temporary diagnostic hook can inspect the contract without changing networking:

```sh
#!/bin/sh
set -eu
{
  echo "event=$QELI_EVENT if=$QELI_IFNAME gateway=$QELI_GATEWAY reason=$QELI_REASON"
  env | grep '^QELI_' | sort
  [ -n "${QELI_CONTEXT_FILE:-}" ] && jq . "$QELI_CONTEXT_FILE"
} >> /var/log/qeli-client-hooks.log
```

### Security

1. A config containing hooks must be a regular non-symlink file, owned by root or the process's
   effective UID, and have no group/world write bits (`mode & 0022 == 0`). Otherwise both hooks
   are ignored and the reason is logged. `0600` is the usual mode. Ownership, permissions
   and contents come from one opened file descriptor; detected changes during reading
   reject the load. Non-regular sources, including FIFO, are rejected before reading.
   A symlink to a regular config remains readable for operation without file commands.
   The resulting command permission belongs to those startup bytes. Changing permissions
   or replacing the file later cannot authorize old commands: restart the client or server
   worker to load them again. Profile retry and SIGHUP do not refresh hook authorization.
   Likewise, a previously authorized server `post_down` keeps the command and environment
   of its ready generation even if the config is removed/replaced before cleanup; changing
   the file is not a way to revoke that already-armed cleanup.
2. The panel/API deliberately cannot create or change `post_up`, `post_down` or
   `password_command`: remote shell-command editing would turn the panel into an RCE path.
3. Protect the called script and everything it reads. Qeli warns about a world-writable executable
   file, but the operator owns the complete trust chain.
4. The value is a shell command. Never concatenate untrusted data into it; use the separately
   supplied and quoted variables, for example `"$QELI_IFNAME"`.
5. A hook runs as the qeli process user. The packaged `.deb` service normally runs as `qeli` with
   networking capabilities: these cover many `ip`/firewall operations but not arbitrary writes to
   `/etc`. A manual root launch or root container also runs hooks as root.

### Process execution and output

These rules apply to both client and server hooks:

- Command execution and output reading share a 30-second deadline. Stdout and stderr are
  drained concurrently; memory retains only the last **8 KiB of each stream**, rather than
  all output. Truncation is marked in the log. Reading continues after the retention limit,
  so a full pipe cannot block the command. Timeout diagnostics retain the collected tails.
- Each Linux hook gets an isolated process group. Timeout, read failure or cancellation
  sends `SIGKILL` to that group, with a direct shell fallback. The owning thread awaits
  and reaps the shell on timeout, error and cancellation. Context-file preparation/removal
  also runs there. Forced Drop joins that thread; stuck filesystem/kernel calls cannot be
  preempted. The 30 seconds bound command/output work, not file preparation or whole shutdown.
  CLI server workers separately enforce a 45-second cleanup budget with forced exit 124.
  [Details](OPERATIONS.md#hook-and-backup-file-operations).
- Normal shell completion with closed stdout/stderr preserves intentionally launched
  background services. Redirect both streams, for example to the service's own log, and
  arrange its shutdown through your `post_down` or a service manager. A descendant keeping
  an output pipe open holds the hook invocation until EOF or timeout, even after shell exit.
- A process group is not a sandbox: descendants deliberately escaping through `setsid` or
  a group change have no group-termination guarantee. Qeli does not manage such a service.
  Do not rely on the temporary `QELI_CONTEXT_FILE` after the hook returns.

### Linux TUN and DNS system commands

Built-in TUN setup/removal commands (`ip` in the interface adapter) and client `busctl`
calls have a 15-second execution deadline and a 16 MiB limit for each stdout/stderr stream.
Timeout or output overflow returns an error after attempting to terminate and wait for the
process. Partial output is not used. The DNS marker remains until confirmed revert; timeout
does not mean that the command made no changes.

DNS bus/service context checks and `SetLinkDNS[Ex]` / `SetLinkDomains` share one 15-second
budget starting at DNS setup entry, including time spent in preliminary checks. The
second command receives only the remaining time; no new command starts after expiry.
Partial failure preserves the generation lease; its later `revert` has a separate
15-second deadline, so setup expiry does not prevent owned rollback. This budget does
not give synchronous file I/O, spawn or kill/reap a hard upper bound.
[DNS shared deadline validation](../reports/audit-0.8.2/AUDIT-Q25-DNS-BUDGET.md).

`dns = tunnel` requires `busctl` and an already running systemd-resolved in the same network namespace; the D-Bus broker must share the caller PID namespace. Commands target a specific unique owner on a bus with a pinned AUTH GUID. Replacing the service/bus aborts the operation and retains the lease. There is no autoactivation or networkd fallback; `LinkBusy` requires adjusting TUN ownership or selecting `dns = off`/`system`. Nonstandard NetworkPlan ports require `SetLinkDNSEx`; port 53 uses `SetLinkDNS`. [Context and validation](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONTEXT.md).

Managed DNS on Linux also requires `SO_NETNS_COOKIE` and a trusted state directory without symlinks or group/world write: `$STATE_DIRECTORY`, otherwise `/var/lib/qeli`. Routes, DNS, sysctls and server firewall journals use the same root. Stop the old client cleanly before upgrading; retained v1 markers require administrator recovery when they match the new link. [V2 format and recovery](TROUBLESHOOTING.md#650-linux-dns-lease-ownership-and-recovery-markers).

Legacy global `dns-backup.json`/`dns-holders` are not restored automatically: startup preserves them and requires administrator recovery even with `dns = off`/`system`. Stop the old client cleanly before upgrading. [Procedure §6.20](TROUBLESHOOTING.md#620-linux-legacy-resolver-recovery-failed-backup-kept).

The managed Linux client persists physical bypass/exclude and blackhole routes in `$STATE_DIRECTORY/client-routes.state` (default `/var/lib/qeli/client-routes.state`). Therefore `SO_NETNS_COOKIE` and trusted writable state storage are required even with `dns = off`/`system`; clients sharing a network must see the same journal and lock. Do not switch physical roots while recovery is pending. No new INI key is added. [Recovery and limits](OPERATIONS.md#client-physical-route-recovery).

These are internal bounds, with no new INI key. User-hook deadlines are unchanged. 15 seconds
does not define total shutdown time. Current route/firewall sequence coverage and remaining
limits are tracked in the [debt register](../plans/AUDIT-DEBT.md). IPv4/IPv6 preflight shares
one 15-second budget across four probes; the panel runs them asynchronously before the
config lock. [Panel transactions](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md).

### Server hooks

Normal shutdown of a `reality-tls` profile joins internal H2 drivers/bridges and rejection
flush tasks before releasing profile resources. A rejected H2 connection retains its
pre-auth slot until its I/O is released; the flush still has a one-second limit. Successful
H2 accept hands admission to inner authentication, which releases it after AUTH.
This does not set an overall shutdown deadline; [details and limits](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).

Server hooks remain a separate per-profile contract:

- `routing.post_up`: after the profile TUN and NAT/routed state are up;
- `routing.post_down`: once when a generation that reached TUN + NAT/routed + NDP
  setup ends, including a later startup failure;
- env: `QELI_PROFILE`, `QELI_TUN`, `QELI_POOL`, `QELI_POOL_IPV4`, `QELI_POOL_IPV6`,
  `QELI_WAN`, `QELI_WAN_IPV4`, `QELI_WAN_IPV6`, `QELI_BIND_PORT`.

The extended client `QELI_ADDRESS_N_*`, carrier and JSON values do not apply to server hooks. The
server retains one snapshot of the actual WAN interfaces selected for a generation and supplies
that same snapshot to `routing.post_down`. Disabled profiles and failures before this point
never run `post_down`. The snapshot is armed before `post_up`: failure or interruption of
`post_up` still needs subsequent cleanup; an empty `post_up` is valid too. Each restarted
generation has its own snapshot. SIGKILL and process crashes cannot guarantee a hook.

```ini
[profile:tcp]
# The client needs a static tunnel IP.
routing.post_up   = ip route add 192.168.254.0/24 via 10.9.0.2
routing.post_down = ip route del 192.168.254.0/24 via 10.9.0.2
```

## Authentication: tokens and anti-brute-force (`[auth]`)

Beyond pinning / H-1 (above), the `[auth]` section carries:

| Key | Default | Purpose |
|---|---|---|
| `require_client_key_proof` | `false` | require a pinned-key proof; templates can opt in |
| `bind_static_to_session` | `true` | bind session keys to the static server identity |
| `users_file` | `/etc/qeli/users.conf` | standalone user database; merged with inline `[user:*]` and wins duplicate names |
| `brute_force.enabled` | `true` | master switch for **VPN-auth** rate-limiting; `false` = off entirely |
| `brute_force.max_attempts` | `5` | failed-attempt threshold before lockout (per source IP); allowed `1..=10000` |
| `brute_force.window_secs` | `300` | window for counting failures (seconds); allowed `1..=86400` (24h) |
| `brute_force.lockout_secs` | `900` | lockout duration after the threshold is exceeded (seconds); allowed `1..=2592000` (30d) |

If the external `users_file` is genuinely absent and the server INI has no inline users or groups, first startup and `qeli check-config` use an empty database. A malformed or unreadable existing file remains an error. If inline entries exist, they are used without the external file. A non-default `auth.users_file` is accepted only from a trusted server INI (regular file, owned by root or the effective UID, with no group/world write and no symlink). This is checked by `check-config`, worker/supervisor startup, panel user operations, and CLI operations that write users. Use `chmod 600 server.conf` after choosing a custom path. Changing `auth.users_file` requires a full supervisor restart: SIGHUP and a worker-only restart retain the startup path.

In the VPN worker, `SIGHUP` applies the users database and `auth.brute_force.*` policy without a full restart. Changes to `auth.require_client_key_proof`, `auth.bind_static_to_session`, `logging.level`, `logging.file`, `logging.time_format`, `logging.format`, and enabled-profile settings require a restart; the server logs them. Edits to profiles that remain disabled do not produce a warning about live profiles.

> **Removed from here: `password_hash` and `token_ttl_secs`.** Both are listed in `RETIRED_KEYS`
> (`config/mod.rs`) and are not honoured; `qeli check-config` names them as stale (rather than
> as typos), and an ordinary server start simply ignores them. The hashing
> scheme is not configurable (always argon2id) and the token lifetime is set in code. The docs
> described them as live, so a config written from this table earned a warning about keys that
> no longer exist. Not to be confused with `password_hash` under `[web]` and `[user:*]`, which
> are real and documented in their own sections. (Audit 2026-08-01, §12.)

> **The bounds are hard, and are checked even when `enabled = false` (since 0.7.13).** An
> out-of-range config is **rejected at load** instead of being accepted silently. Zeros were
> not harmless but dangerous in opposite directions: `max_attempts = 0` locked a source out on
> the **very first** failed attempt (a self-inflicted denial of service), while
> `window_secs = 0` cleared the failure history before every attempt, so the lockout **never
> triggered** — it looked enabled while protecting against nothing. The check runs with the
> switch off too, so turning it on later cannot activate a policy nobody validated.

This `[auth] brute_force` policy governs **VPN authentication only**. The **web-panel
login** has its own, independent policy — `[web] brute_force` (see [Web panel](#web-panel-web)
below) — with its own switch, attempt count, window and lockout, so the tunnel and the
panel can be tuned (or disabled) separately. Since 0.7.7 the two are separate journals.

The lockout is **per source IP**; a username under attack gets an adaptive tarpit
(slowdown) instead of a hard lock, so a correct password always passes and a
username cannot be locked by guessing it ([L1](../archive/audits/AUDIT-2026-06-11.md)). Setting
`brute_force.enabled = false` makes the tracker inert (no lockout, no tarpit, no
tracking) — use it only behind an external limiter or on a trusted network.

> **Editable in the panel** (Config → Authentication → "Brute-force protection — VPN
> authentication"), not only in the file. They apply on **Apply & Restart** or on a
> `SIGHUP` reload — if the new INI and users database validate, the server rebuilds
> the tracker with the new values (in-flight lockout counters reset at that moment).
> If either source is invalid, both live users and thresholds remain unchanged. The tarpit's internal delays (200 ms … 3 s) are not
> configurable. Blocked addresses — the **"Blocked IPs"** tab (split into a VPN-auth and a
> panel-login journal) / `qeli list-blocked` (see [PANEL.md](PANEL.md),
> [GETTING-STARTED.md](GETTING-STARTED.md) §10).
>
> The *Blocked IPs* tab also carries a live editor for **both** policies (VPN + panel) — the
> same thresholds, applied without a restart.

## Obfuscation: handshake shaping and anti-fingerprinting

Fine-tuning of how a profile looks **on the wire**, on top of the chosen `obf.mode`.
All keys are per-profile; the defaults below are the serde defaults (in the example
[server.conf](../../../qeli/config/server.conf) some are shown with illustrative,
**non-default** values — rely on the tables here).

> **How the client chooses SNI/Host.** An explicit `sni` wins. Otherwise the connect
> hostname is used as SNI/Host; for a bare IP `fake-tls` omits SNI and WebSocket obfs
> uses the actual IP in `Host`. Unrelated CDN names are no longer rotated. A
> `reality-tls` IP endpoint requires an explicit DNS `sni` matching
> `reality_proxy.target`; invalid names and control characters fail before connect.
>
> **Hiding/omitting SNI (fake-tls only).** Special `sni` values: `!` = omit the SNI
> extension, `~` = send an empty extension, `@` = an empty `server_name_list`. For
> obfs this field is the HTTP `Host`; reality-tls requires an ordinary DNS name.

**AEAD and the fake-TLS ClientHello:**

| Key | Default | Purpose |
|---|---|---|
| `obf.tls.server_name` | `www.cloudflare.com` | SNI for generated non-REALITY share links. **fake-tls:** cosmetic (the server ignores client SNI). With REALITY enabled, generated links take SNI from `reality_proxy.target`; manually configured clients must also match the target. |

**Schema baseline: Padding / Fragmentation / Heartbeat** (enabled unless a shipped profile overrides them; Reality/H2 templates disable padding and heartbeat):

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
| `obf.heartbeat.jitter_ms` | `5000` | one-shot interval jitter; re-rolled after activity/send |

> **The `obf.fragmentation.*` setting applies to the handshake only.** It splits one
> record — the ServerHello — once per connection. It never touches the data stream, so
> it **costs no data-plane throughput**: the price is roughly 600 bytes (each chunk leaves as
> its own TCP segment, with its own header) and a few tens of milliseconds on a handshake
> that already takes about that long.
>
> This is separate from automatically negotiated UDP `DATA_FRAG_V1`, which splits oversized
> encrypted data records to the path budget and is not controlled by `obf.fragmentation.*`.
>
> The point is that the ServerHello must **not arrive in one segment**, where a DPI
> signature matcher can read it whole. The point is NOT to shred it: many tiny segments
> defeat the matcher but become an anomaly themselves — no real TLS server writes like
> that, so you would trade one tell for another. The defaults give 2-4 plausibly sized
> chunks, indistinguishable from ordinary TCP segmentation. Lower them only against a
> specific DPI you know more about than we do.

**Transport-independent data-plane morphology (`PACKET_MUX_V1`):**

For the complete layer order, compatibility matrix, recommended profiles and migration procedure,
see [Obfuscation and PACKET_MUX recordizer](OBFUSCATION.md).

After successful authentication the server can enable one common recordizer for every carrier:
TCP `plain`, `fake-tls`, `reality-tls`, `obfs`/WebSocket/AWG and UDP `fake-tls`, QUIC-shape,
`obfs`/AWG. This is not a new transport mode: it coalesces IP packets, changes encrypted-record
boundaries, and can split one IP packet across several inner records.

| Key | Default | Purpose |
|---|---|---|
| `obf.recordizer.policy` | `off` | `off` — legacy data plane; `prefer` — enable with a `PACKET_MUX_V1` client, otherwise legacy; `required` — reject an incompatible client before allocating an address |
| `obf.recordizer.batch.delay_min_ms` / `delay_max_ms` | `2` / `8` | randomized maximum wait for the first queued item before flushing a batch |
| `obf.recordizer.batch.max_packets` | `16` | maximum source IP packets queued in one batch |
| `obf.recordizer.batch.max_queue_bytes` | `262144` | hard per-direction queue-memory limit (`64..=4194304`) |
| `obf.recordizer.record.max_payload_bytes` | `0` | `0` selects the safe carrier/path payload automatically; otherwise `64..=tun MTU ceiling` |
| `obf.recordizer.record.small_min_ratio` / `small_max_ratio` | `0.25` / `0.875` | randomized partial target range relative to the safe maximum (`0 < min ≤ max ≤ 1`) |
| `obf.recordizer.record.full_probability` | `0.72` | probability of choosing the full safe target instead of a random partial target (`0..=1`) |
| `obf.recordizer.fragment.enabled` | `true` | allow one IP packet to cross inner record boundaries |
| `obf.recordizer.fragment.reassembly_timeout_ms` | `3000` | incomplete-reassembly timeout |
| `obf.recordizer.fragment.max_inflight_packets` | `64` | maximum packets being reassembled per direction |
| `obf.recordizer.fragment.max_reassembly_bytes` | `4194304` | total hard reassembly-memory limit per direction |
| `obf.recordizer.fragment.max_fragments_per_packet` | `64` | maximum fragments for one IP packet |

Only the server owns these values and pushes them inside authenticated `AUTH OK`; no client-side
recordizer keys are required. The sparse schema baseline remains `off` for existing configs that
omit the key, while shipped templates, Quick Start and profiles newly added in the panel use
`prefer` so current clients get the new shape without breaking legacy clients. After the whole fleet
is upgraded an operator may switch to `required`. Negotiation is per-session, so a config
change requires reconnecting sessions, not merely editing the file.
When `policy = off`, the nested `batch`, `record` and `fragment` values are dormant: they are
preserved without blocking an unrelated panel save and are validated again when policy changes to
`prefer` or `required`. This makes disabling and later restoring a tuned profile lossless.

The recordizer removes the “one IP packet = one qeli record” relation from every mode, but it does
not make their carriers identical: TLS/REALITY/H2, WebSocket, QUIC-shape, endpoints and outer timing
remain visible and need their own coherent camouflage. This reduces one class of statistical tells;
it is not a promise of universal unclassifiability.

> For `reality-tls` padding is redundant because genuine H2 batching already decouples qeli packets from outer record boundaries —
> turn it off (`obf.padding.enabled = false`), see the "Server OS tuning" section.

**Extra masking (schema baseline off; shipped Reality/max-obfuscation profiles explicitly enable traffic shaping):**

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

## Inner IPv4/IPv6 addressing

Step-by-step dual-stack, IPv6-only, NAT66, routed GUA, `manual`, NDP proxy, Quick Start and verification
workflows are collected in the separate [IPv6 guide](IPV6.md).

The outer listener family and inner tunnel family are independent. A profile reached over
IPv4 may carry dual-stack traffic, and an IPv6 carrier may serve an IPv4-only profile.

| Key | Default | Purpose |
|---|---|---|
| `tun.ip_mode` | `ipv4` | `ipv4`, `dual`, or `ipv6` inside the tunnel |
| `tun.address` | `10.9.0.1` | server IPv4 TUN address; used in `ipv4`/`dual` |
| `tun.ipv6_address` | — | server IPv6 TUN address; required in `dual`/`ipv6` |
| `pool.cidr` | `10.9.0.0/24` | IPv4 allocation/on-link prefix |
| `pool.ipv6.cidr` | — | IPv6 allocation/on-link prefix; required in `dual`/`ipv6` (normally `/64`) |
| `pool.ipv6.exclude` | — | comma-separated IPv6 addresses never allocated |
| `pool.ipv6.reservation.<user>` | — | fixed IPv6 lease for one user |

For an L3 TUN, clients receive host routes (`/32` and `/128`) while the NetworkPlan carries
the separate pool/on-link prefix. This avoids IPv6 neighbor discovery on a point-to-point TUN.
TAP keeps the pool prefix because Ethernet ARP/NDP/RA is available locally. The qeli wire
transport is still **L3**: it removes the Ethernet header and carries only an IPv4/IPv6 packet.
It is not a transparent Ethernet bridge; VLAN, STP, LLDP, unknown EtherTypes, and arbitrary L2
broadcast/multicast are not distributed between qeli sessions. IPv6 requires `tun.mtu >= 1280`;
`dhcp.*` remains DHCPv4 and must be disabled in an IPv6-only profile.
In `tun.ip_mode = ipv6`, the legacy IPv4 shadow fields `tun.address`, `pool.cidr`, and
`dns.listen` are not parsed or used. `routing.nat.enabled` is NAT44 and is rejected in this
mode; `routing.forward_private` is also IPv4-only. Configure IPv6 egress explicitly through
`routing.ipv6.mode = route` or `nat66`, or use `manual` for administrator-managed IPv6.
Conversely, an IPv4-only profile preserves dormant `tun.ipv6_address` and `pool.ipv6.*` values
without validating them. They become active and are checked after switching to `dual`/`ipv6`.
`routing.ipv6.mode` and `routing.ipv6.ndp_proxy` are operational switches rather than dormant
address fields, so they must remain `off` in an IPv4-only profile.

Managed IPv6 modes (`off`, `route`, `nat66`) require `ip6tables`.
`manual` leaves IPv6 firewall, forwarding and RA settings to the administrator, including
DNS INPUT access and any port-53 redirect; it does not require `ip6tables`. Tunnel addresses
and authenticated client routes remain managed by Qeli.
Forwarding and RA belong to the network namespace: a sibling `route` or `nat66`
profile may enable them for its own operation. `manual` does not acquire its own
IPv6 sysctl lease or isolate these values from sibling profiles.
In `off`, qeli installs a verified per-profile drop for packets
entering or leaving that TUN through any other interface, so an isolated profile cannot
inherit host-wide forwarding enabled by a sibling profile in either direction. `route` permits
source-preserving forwarding between the TUN and networks selected by the profile's kernel
routes (WAN, server LAN, its pool and authenticated dynamic IPv6 `client_subnet` routes);
`nat66` adds MASQUERADE, blocks TUN egress through any interface other than the
selected WAN, and accepts only related/established return traffic from that WAN.
`route` does not require a public/default IPv6 uplink: on a LAN-only/site-to-site router an
empty `routing.ipv6.interface` enables forwarding without `accept_ra`; when an uplink is found
or explicitly configured, qeli also leases `accept_ra=2` so enabling forwarding preserves SLAAC.
`nat66` always requires a detected or explicit uplink.
For an on-link prefix that the upstream resolves through Neighbor Discovery, `route` and `manual` can enable
the session-aware NDP proxy. It answers only for exact live-session IPv6 leases and their
non-default IPv6 `client_subnet` ownership, without relaying multicast to clients. `auto`
allows startup without the responder after a warning, while `required` fails closed. See
[IPV6.md](IPV6.md#on-link-prefix-and-ndp-proxy-081) for the topology, link requirements, and
configuration example.

## Built-in DNS resolver (`dns.*`)

An optional in-tunnel DNS proxy: the server hands clients its own resolver and
(optionally) filters domains. Disabled (default) — clients keep their own resolvers
and the server pushes no DNS. Per-profile.

Enabling the proxy requires `iptables` for IPv4 and `ip6tables` for each managed IPv6
listener. With `routing.ipv6.mode = manual`, IPv6 INPUT and any port-53 redirect are
administrator-managed and do not require `ip6tables`. For other listeners, qeli inserts narrow `INPUT` permits for the exact TUN, client pool, address and
port, verifies them, and falls back only when the built-in `INPUT` chain is otherwise empty
and its policy is exactly `ACCEPT`; missing tooling, `DROP`, any explicit rule/jump, or an
unreadable chain fails profile startup.

| Key | Default | Purpose |
|---|---|---|
| `dns.enabled` | `false` | enable the in-tunnel DNS proxy (requires the firewall CLI except for IPv6 listeners in `manual`) |
| `dns.listen` | `10.9.0.1` | listen address (usually the tun IP) |
| `dns.listen_ipv6` | — | IPv6 listener; required with `dns.enabled` in `dual`/`ipv6` and must equal `tun.ipv6_address` |
| `dns.port` | `53` | the port the **server-side proxy** listens on. Clients are still told 53, and qeli redirects 53 to this port; a non-53 port requires `iptables` for IPv4 and `ip6tables` for managed IPv6; in `manual`, the administrator provides IPv6 redirection |
| `dns.upstream` | `1.1.1.1, 8.8.8.8` | unique IP-literal upstream resolvers (comma-separated), maximum 16 |
| `dns.upstream_protocol` | `udp` | `udp` \| `tcp`. `tcp` really does force TCP to the upstream, and a UDP answer that comes back TRUNCATED is retried over TCP either way. ⚠️ **`tls` (DoT) is REJECTED at config load** — the server refuses to start rather than silently sending plaintext UDP while the config says DoT |
| `dns.cache_size` | `1000` | maximum cached exchanges; `0` disables caching, at most 10000 entries and 16 MiB of retained query/response bytes per profile |
| `dns.timeout_secs` | `5` | one total deadline across all upstream attempts, 1–300 seconds |
| `dns.blocklist` | `[]` | ASCII/punycode domains answered with `NXDOMAIN` (the name and all subdomains); no `*` wildcard, maximum 10000 unique names |
| `dns.push_servers` | `[]` | hand clients IPv4/IPv6 resolvers **without** running the proxy. Empty = the active proxy listeners when `dns.enabled`, else nothing. Every address is strict-IP-validated and must belong to an active inner family |

The cache stores response DNS records together, without the control OPT record.
Its lifetime cannot exceed the smallest TTL across ANSWER, AUTHORITY and ADDITIONAL;
a TTL with the high bit set is treated as zero and prevents caching.
NXDOMAIN and NODATA, including a CNAME chain,
are bounded by the negative SOA lifetime and alias TTL; without a suitable SOA,
a negative response is not cached. Cached record TTLs are reduced by entry age.
Truncated responses (TC) are not cached. If TCP retry also returns TC, the proxy
tries the next upstream within the total `dns.timeout_secs` deadline; that response
is retained only as a last resort when no complete answer is available.

The byte limit is independent of `dns.cache_size` and shared by IPv4/IPv6 and
UDP/TCP listeners within one profile. Under pressure expired entries are removed
first, then a batch of entries is evicted. The 16 MiB limit covers retained packet
payloads, not map metadata, in-flight buffers or the process's total memory.

TSIG and SIG(0) exchanges bypass the cache. Allowed signed requests and their upstream
replies are relayed unchanged; Qeli does not validate keys or generate signatures.
An oversized signed UDP reply is dropped because Qeli cannot sign a shortened
replacement: use TCP or advertise enough space with EDNS. A signed reply to an
unsigned request is rejected and another upstream is tried; ordinary requests
continue to use random upstream IDs. DNSSEC RRSIG records are distinct from
transaction signatures; this is not DNSSEC validation. Blocklist decisions still
apply, and locally generated errors/NXDOMAIN are unsigned.

The proxy handles opcode QUERY. Other opcodes (including UPDATE/NOTIFY) receive
NOTIMP. Incoming responses are ignored. QUERY with more than one question receives
FORMERR without client questions/records, with a fresh OPT for valid EDNS;
zero-question exchanges such as DNS COOKIE remain allowed.

EDNS(0) is supported. Duplicate OPT, a non-root owner, OPT outside ADDITIONAL
and malformed option lengths receive FORMERR; other EDNS versions receive BADVERS.
Malformed upstream replies are rejected and the next resolver is tried.
A shortened ordinary UDP reply retains the extended error code and EDNS fields,
but omits option payloads: TC instructs the client to fetch the full reply over TCP.

An exchange carrying nonempty EDNS options in its query or response, including
COOKIE, ECS, NSID and PADDING, bypasses caching. Unknown options are relayed without
interpretation when their lengths are valid. Ordinary queries with an empty OPT
can cache DNS records: a terminal empty response OPT is removed before storage
and rebuilt on a cache hit. Responses with OPT in the middle of ADDITIONAL or
without matching EDNS negotiation are forwarded without caching; an unsolicited
OPT in a reply to a non-EDNS request is rejected.

RDATA size and structure are checked for common records: IN A/AAAA,
NS/CNAME/PTR/DNAME, MX, IN SRV, SOA and TXT. Unknown formats remain opaque bytes.
These checks do not establish RRset semantic correctness or DNSSEC authenticity.

Each UDP listener allows up to 512 concurrent queries; each TCP listener allows
up to 512 connections, including idle connections. IPv4 and IPv6 have independent
limits: a dual profile has four separate bounds. At capacity, UDP queries are
dropped and excess TCP connections are closed. For TCP, `dns.timeout_secs` bounds
each length-prefix read, body read and response write; an active persistent
connection can remain open longer than that duration.

On an ordinary stop or startup error, the profile closes child-task admission,
aborts and joins DNS/other services, listeners and queries, then removes its
network resources. An occupied additional DNS bind also cleans up services
already started for that profile. Other profiles continue serving.

When `dns.enabled = false`, proxy-only fields (`listen`, `listen_ipv6`, `port`, `upstream`,
`upstream_protocol`, cache, timeout and blocklist) are dormant and preserved without validation;
they are validated again when the proxy is enabled. `dns.push_servers` is intentionally independent:
it remains active and is always validated because it can distribute resolvers even when the local
proxy is off.

## DHCP server (`dhcp.*`)

An optional DHCP server on the profile's interface (for TAP/L2 setups; most
deployments don't need it — IPs are handed out in AUTH). Disabled by default.
Per-profile.
On Linux the socket receives standard broadcast `DISCOVER`/`REQUEST` traffic on
`0.0.0.0:67`, but is restricted to the profile's **actual TUN/TAP interface** with
`SO_BINDTODEVICE`; the unauthenticated service is not exposed on WAN.

| Key | Default | Purpose |
|---|---|---|
| `dhcp.enabled` | `false` | enable the DHCP server |
| `dhcp.listen` | empty (`tun.address:67`) | logical DHCP address and port; empty is recommended. Explicit `0.0.0.0` is rejected as unsafe |
| `dhcp.pool_start` / `pool_end` | — | lease range (optional; else from `pool.cidr`) |
| `dhcp.lease_time_secs` | `86400` | lease time |
| `dhcp.domain_name` | `vpn` | domain name advertised to clients |

With the built-in DNS proxy enabled, DHCP advertises the profile address. With the
proxy disabled, it advertises IPv4 addresses from `dns.push_servers`; an empty list
omits the DNS option. There is no hidden fallback to public `1.1.1.1`/`8.8.8.8`.

> **`pool.cidr` is the subnet source of truth (since 0.7.15).** Its prefix configures the
> server TUN, is pushed to every client, and defines the DHCP subnet (`/16` means
> `255.255.0.0`). `tun.address` may be **any** usable host inside it and is always reserved
> from dynamic AUTH and DHCP allocation automatically; it does not have to be `.1` and
> should not be duplicated in `pool.exclude`. An automatic DHCP range selects the larger
> contiguous side of that server address; an explicit range that contains it is rejected.
> The legacy `tun.netmask`
> key is accepted only while reading old INI files, ignored with a warning, and is never
> written back. The config is **rejected at load** if `pool_start` /
> `pool_end` fall outside its usable range (`dhcp.<field> (<IP>) is outside the tunnel
> subnet's usable range …`) or if `pool_end` is below `pool_start`. Such a pool used to be
> accepted silently, handing clients addresses that **cannot route on that interface** — a
> failure that presented as "it connects but no traffic flows". The values must also be plain
> IPv4 addresses, with no CIDR prefix.


<!-- normative-sync: dhcp-wire-boundaries-q20-v1 -->

DHCPv4 identifies Ethernet clients by the complete six-byte `chaddr`. Invalid
BOOTREQUEST hardware fields, truncated options, missing END and duplicate or
incorrectly sized message-type/requested-address/server-ID options are rejected
before address allocation. Option 52 can select `file`/`sname` option fields;
those fields undergo the same complete validation. An OFFER reserves an address
for 30 seconds; REQUEST promotes it to `dhcp.lease_time_secs`. RELEASE requires
the owning MAC and address, and DECLINE quarantines that address for 600 seconds.
The shared pool prevents DHCP from taking an active VPN session's address.
Leases are process-local and are not persisted across profile restart.

With `dhcp.enabled = true` and `dns.enabled = false`, at most **63 IPv4 entries**
in `dns.push_servers` fit the supported single DNS option. A larger list is
rejected by `check-config`, not silently truncated. When the DNS proxy is enabled,
DHCP advertises the profile's IPv4 gateway instead. This restriction does not
apply to DHCP-disabled profiles. Lease timers use T1=1/2 and T2=3/4 of the lease,
including large `u32` lifetimes. This DHCP service is separate from the address
assigned to an authenticated VPN session; enabling it does not replace AUTH.

## Performance tuning (`perf.*`, `tun.tx_queue_len`)

The following table contains **server** parameters under `[profile:<name>]`, all
per-profile. Values depend on the link/load — see the general note in "Profile defaults".
The same-named client `tun.tx_queue_len` under `[qeli]` is independent and is not
server-pushed: [Linux client queue](#client-tun-tx-queue).

| Key | Default | Purpose |
|---|---|---|
| `tun.tx_queue_len` | `1000` | **Server** TUN TX queue length in packets; neither the client queue setting nor `tun.queues` |
| `perf.tcp.nodelay` | `true` | `TCP_NODELAY` (disable Nagle) |
| `perf.tcp.keepalive_secs` | `60` | TCP keepalive |
| `perf.tcp.send_buffer_size` / `recv_buffer_size` | `0` | `SO_SNDBUF`/`SO_RCVBUF`; explicit `0` preserves OS autotuning |
| `perf.udp.recv_buffer_size` | auto: `4194304` → 8/16 MiB | With the key absent, each UDP worker starts at 4 MiB and bounded auto-grow requests 8/16 MiB only after local overflow or measured rate/stall pressure; it never shrinks. An explicit value disables auto, `0` leaves the OS alone, maximum 64 MiB per socket. Granted bytes and counters are logged/exposed; OS limits remain best-effort |
| `perf.udp.send_buffer_size` | `0` | `SO_SNDBUF` on the UDP listener. `0` = leave alone; maximum 64 MiB per socket. A full send buffer applies backpressure rather than losing data, so there is no send-buffer auto-grow |
| `perf.tun.read_buffer_size` | `65535` | TUN read-buffer size, **per queue**. Must be at least `tun.mtu` (plus 14 bytes of Ethernet header for TAP) and at most 1 MiB; out-of-range values are **rejected at load**. `0` is not "auto" — it makes the read return EOF immediately and stops the data plane |
| `perf.connection.max_clients` | `128` | total sessions per profile (all users; see "Connection limits") |
| `perf.connection.handshake_timeout_secs` | `10` | 10 seconds: TCP key exchange, proof, first AUTH/JOIN, AUTH verification and AUTH OK sending share one inner-handshake deadline; UDP AUTH verification, admission waiting and AuthOK/negotiation-error sending share the deadline measured from handshake creation. Resource rollback may finish after that deadline |
| `perf.connection.idle_timeout_secs` | `300` | idle timeout (`0` = never idle-drop) |
| `perf.connection.new_session_rate_max` | `10` | max new sessions from one source IP per window |
| `perf.connection.new_session_rate_window_secs` | `60` | window for `new_session_rate_max` (seconds) |


On Linux these server TCP keys request `SO_SNDBUF` and `SO_RCVBUF`. Since 0.8.3 an absent key uses **0** (OS management); 0.8.2 used 262144 bytes. Explicit operator values are preserved. Explicit `0` skips the corresponding socket option, preserving kernel autotuning; a nonzero value disables it for that buffer. OS limits can constrain the grant; Linux includes bookkeeping memory, so readback is usually twice the request. Check `ss -tinmp`, `skmem` fields `tb`/`rb`.

These are server TCP settings. Client `send_buffer_size`/`recv_buffer_size` apply to UDP; client TCP retains OS settings. Smaller buffers can move backpressure and reduce throughput. [Linux6.12 semantics](https://www.kernel.org/doc/html/v6.12/networking/ip-sysctl.html).

### Internal UDP receive queue and wait metrics

Since 0.8.3, the client and each server UDP worker measure depth and wait time of
the internal receive handoff queue. Its working limit is always **128 UDP datagrams**,
with automatic, explicit or zero receive-buffer settings alike. It neither shrinks
after idle nor grows under load. A full queue backpressures the producer; resizing
never discards packets because the queue does not resize.

This queue does not change `tun.tx_queue_len`, the number of `tun.queues` or `SO_RCVBUF`.
Existing automatic `SO_RCVBUF` growth and the server aggregate RAM budget remain
in force. The recycler retains the previous limit of 129 buffers of 65535 bytes per
receive pump. A fixed queue cannot guarantee loss-free operation under sustained
CPU/link overload. Existing manual TUN and socket-buffer settings are preserved.

Metrics are available in the Linux CLI status file (`QELI_CLIENT_STATUS`), under
`stats.udp_receive_queue`; on the server, through the local control command
`queue-stats` and authenticated `GET /api/transport/health`, in
`profiles[].udp_receive_queue`. Unsupported workers return `null` through that API,
not zero counters. The fixed C/JNI statistics ABI is unchanged.

`queued_packets`/`queued_bytes` report current depth, `peak_*` report lifetime peaks,
and `limit_packets` sums the current limits of all receive pumps in the profile.
`grow_events`/`shrink_events` are zero for this fixed queue; they do not count kernel
UDP receive-buffer growth. `delivered_packets` count batches
handed to the consumer in packets, and `cancelled_packets` count queued packets
cancelled before that handoff. Cancellation is not a network-loss counter.
Here a packet means an outer UDP datagram, not an individual inner Recordizer packet.
Wait time runs from completion of a batch receive until the consumer dequeues it,
including admission wait. It excludes subsequent batch processing, decryption,
TUN delivery and network RTT.

`wait_mean_us`, `wait_max_us` and `wait_p50_upper_us`/`wait_p95_upper_us`/`wait_p99_upper_us`
are cumulative. Percentiles are upper bounds from a packet-weighted histogram.
For a measurement window, subtract the boundary values of `wait_total_us`,
`delivered_packets` and `wait_histogram_packets`; `wait_bucket_upper_us` contains
the histogram bounds. Counters live until their client/profile counter object is
recreated; ordinary client reconnect does not reset them. Concurrent updates can make
an individual snapshot momentarily inconsistent.

Since 0.8.3 the recommended TCP default leaves buffers to the OS. To enable
autotuning for an existing profile with explicit sizes, set both server keys to `0`:

```ini
perf.tcp.send_buffer_size = 0
perf.tcp.recv_buffer_size = 0
```

This permits Linux buffer management without changing sysctl: also check
`tcp_moderate_rcvbuf=1` and sufficient `tcp_rmem`/`tcp_wmem` limits (see the sysctl
section above). Explicit old sizes are not rewritten.
An omitted key now uses `0`; set `262144` explicitly to retain the old behavior. Before applying, run `qeli check-config --config /etc/qeli/server.conf`, then
`systemctl restart qeli.service` and reconnect clients: buffer options apply to
new sockets. This interrupts active sessions. Do not use the installer with
`QELI_FORCE_RECONFIG=1` just to change these keys: it regenerates configuration
and can change identity/connection links. Results depend on RTT, available memory and load. Compare receiver goodput, retransmissions and actual
`skmem` buffer sizes on your own connection.

The TCP default is supported by [1/8 independent-client measurements and memory checks](../../data/benchmarks/queue-tuning-20261021.json)
on Linux with 40/100 ms added RTT. The record also includes UDP/TUN diagnostics
at 900 Mbit/s and manual `tun.tx_queue_len = 1000/2000`. Generator bursts, consumer
backpressure and scheduler delays can fill the finite TUN queue. A larger manual
queue allows more burst headroom and kernel memory/latency; it does not increase
processing capacity or change Qeli's internal RAM limits. Automatic TUN queue resizing
is not enabled; its default remains 1000. These windows do not guarantee zero drops
on every connection or client count.

The server local control command `tun-stats` returns cumulative profile counters:
TUN packets/bytes, the fixed pool size, queue peaks and timing histograms for pool
wait, consumer dispatch and UDP batch send. `between_reads` measures userspace time
between completion of one read and start of the next, including pool/queue wait and
scheduling stalls. `kernel_read` includes normal waiting for new packets; a large
value alone does not prove overload. Histogram bounds are in `bucket_upper_us`;
use counter differences for an individual window. `dispatch_wait` measures the entire handoff call,
including its fast path, rather than only parking on a full queue. The TUN reader
first uses non-blocking `try_send`; a full queue retains the previous blocking
wait for space. `udp_send` covers the normal Recordizer batch-send path, including
socket wait; it does not measure legacy sends, the separate MTU-fallback fragmentation
path, encryption or rate-limit pacing. Zero samples means no measured calls, rather
than zero latency for all UDP sends. These metrics do not enlarge pools or TUN queues.

## Routing and other per-profile keys

Server-side routing for the profile (client-side routing keys are in the "Client" section):

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `true` | whether this profile is active. `true` = bound and served; `false` = kept in the config but **skipped at startup** (turn an interface off without deleting it). Omitting the key keeps the profile enabled. At least one profile must remain enabled; `check-config`, server startup and panel saves reject an INI with every profile disabled |
| `routing.client_to_client` | `false` | allow client↔client traffic within the tunnel subnet. **Enforced** server-side: when `false` (the default) a packet whose source IP is one client and whose destination is another client is dropped — clients are isolated. Internet traffic (external source) is unaffected |
| `routing.forward_private` | `true` | with NAT44 disabled, enable source-preserving IPv4 transit through the server; with `routing.nat.enabled = true`, this key adds no separate LAN permits; inactive in IPv6-only mode |
| `routing.nat.enabled` | `false` | IPv4 NAT44/MASQUERADE for client Internet traffic; rejected in IPv6-only mode. TUN traffic to destinations outside RFC1918 through any interface other than the selected WAN is dropped even with `FORWARD ACCEPT`; RFC1918 destinations (`10/8`, `172.16/12`, `192.168/16`) retain the administrator firewall policy and can leave another interface without NAT. For LANs using other address ranges, use source-preserving routing without NAT or the selected WAN |
| `routing.nat.interface` | `eth0` | IPv4 NAT WAN; empty and the historical `eth0` default mean auto. Auto requires a readable, unambiguous default-route listing: ECMP, equal-best metrics, command failure and no usable listing are refused without a `route get` fallback. A different explicit name must exist in the worker network namespace; its routing is administrator-managed. WAN is selected for the profile generation; changing the default route does not automatically move NAT44 — see [operations](OPERATIONS.md). |
| `routing.ipv6.mode` | `off` | `off` — block IPv6 transit; `manual` — administrator-owned external routing/firewall/forwarding (0.8.2); `route` — forward with client addresses; `nat66` — forward with MASQUERADE. All modes except `manual` require `ip6tables`; [details](IPV6.md#manual) |
| `routing.ipv6.interface` | — | IPv6 uplink; empty = IPv6 default route when present. Required by `nat66`, optional for LAN-only `route`. In `manual`, supplies the default NDP uplink and hook metadata without configuring routing/firewall. In managed `route`/`nat66`, the selected device must exist during rule setup. Empty auto selection rejects ECMP/equal-priority different WANs; `nat66` also refuses a failed/unusable default-route listing without a `route get` fallback. LAN-only `route` without a default route remains valid. In nat66, selection lasts until profile reinstallation; routing through another interface is blocked by the off-WAN guard. In route, current kernel routes determine egress. |
| `routing.ipv6.ndp_proxy` | `off` | Upstream NDP responder: `off`, best-effort `auto`, or mandatory `required`; enabled only with `routing.ipv6.mode = route` or `manual`. Egress `off`/`nat66` requires `ndp_proxy = off`; `required` does not verify packet delivery |
| `routing.ipv6.ndp_proxy_interface` | — | Ethernet uplink for NDP; empty = reuse the effective/configured IPv6 interface or discover the IPv6 uplink, including in `manual` |
| `route` | — | repeatable: a route advertised to clients, `<cidr> [gateway=<ip>] [metric=<n>]`; maximum 256 |
| `routing.post_up` | — | command run after this profile's TUN+NAT are up (Linux, root). **File-only** (panel/API never write it — RCE guard). Env includes `QELI_PROFILE`, `QELI_TUN`, explicit `QELI_POOL_IPV4`/`QELI_POOL_IPV6`, actual `QELI_WAN_IPV4`/`QELI_WAN_IPV6`, `QELI_BIND_PORT`; legacy `QELI_POOL`/`QELI_WAN` select the profile's primary family |
| `routing.post_down` | — | once-per-generation cleanup after completed network setup; disabled/early failure does not run it; SIGKILL cannot guarantee it |
| `tun.device_type` | `tun` | interface type: `tun` (L3) \| `tap` (L2) |
| `obf.tls.reality_proxy.peek_timeout_ms` | `1500` | how many ms to peek the ClientHello before classifying peer as client vs probe; minimum `300` while Reality is enabled |

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
# (opt.) your PEM cert; empty = self-signed
tls_cert =
# (opt.) your PEM key
tls_key =
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
# (opt.) reverse-proxy sub-path, e.g. /qeli; empty = served at root
base_path =
# CSRF protection (default true); false = ONLY on a loopback bind
csrf = true
# (opt.) reverse-proxy IPs/CIDRs whose X-Forwarded-For is trusted; empty = none
trusted_proxies =
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

> **Restart scope.** `enabled`, `bind`, `port`, `tls`, `tls_cert`, `tls_key` and `base_path`
> are consumed when the **process** starts, so changing any of them needs a FULL restart.
> The panel's **Apply & Restart** button performs exactly that (it saves, then runs
> `systemctl restart <unit>`); from a shell it is `systemctl restart qeli`. Your panel login
> survives it while `persist_session_key` is on (the default). A worker-only respawn still
> exists (`POST /api/server/restart`) and is used as an automatic fallback where systemd is
> unavailable (e.g. a container). Everything else in `[web]` (password, `allowed_ips`,
> `allowed_origins`, `csrf`, `public_host`, …) reloads live, with no restart.
>
> **With `tls = true` the panel speaks HTTPS** — open `https://<bind>:<port>`, not `http://`.
> With an empty `tls_cert`/`tls_key` the certificate is self-signed, so the browser warns once.

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `false` | enable the web panel. While disabled, dormant operational values are preserved; INI syntax, key names, duplicates and scalar types are still checked. Operational validation applies when enabled |
| `bind` | `127.0.0.1` | bare IPv4/IPv6 listen address or `localhost` (a public IP for public access); configure the port separately |
| `port` | `8080` | panel HTTP/HTTPS port, `1..=65535` while enabled |
| `username` | `admin` | admin login |
| `password_hash` | `""` | argon2id password hash. **Required — the panel refuses to start without one on ANY bind, loopback included** (since 0.7.12; it used to be required only off-loopback). Set it with `qeli set-web-password`, or opt out deliberately with `insecure_no_auth` below. The panel rejects saving an enabled `[web]` without either condition, including history restore. `check-config` and startup reject a missing password without explicit `insecure_no_auth = true`, as well as a malformed nonempty Argon2 PHC hash; live reload keeps the previous working authentication on failure |
| `tls` | `false` | serve HTTPS directly (rustls/`ring`). Auto `Secure` cookie |
| `tls_cert` / `tls_key` | `""` | PEM cert/key; both empty = self-signed (`/etc/qeli/web-tls-*.pem`, SAN=bind+localhost), otherwise both paths must be set. Each PEM is a regular file up to 4 MiB; symlinks to regular files work. If one auto file survives, restore its partner or remove both to rotate. Explicit paths require a trusted server INI |
| `allowed_ips` | `[]` | strict source-IP/CIDR allowlist. Omitted, empty (`allowed_ips =`) or `""` all mean **no restriction** — surrounding quotes are stripped, so `""` is just an explicit "empty". A blocked source gets a **bare 403 on every route**, so a 403 when merely opening the panel is this filter, never CSRF (which exempts `GET`). **Duplicate lines are folded into one list** (not last-one-wins), so a stray earlier `allowed_ips` keeps the filter active; startup logs `Web panel source-IP allowlist active (N entries)` when non-empty |
| `public_host` | `""` | default public host for `qeli://` links (editable in the Share dialog); also accepted as a CSRF origin |
| `allowed_origins` | `[]` | extra browser origins as `host[:port]` or full `http(s)://host[:port][/path]`, strictly validated and accepted by CSRF when the panel is reached via a domain / reverse proxy; otherwise a public panel loads but every save returns 403 |
| `secure_cookie` | `false` | add `Secure` to the session cookie |
| `insecure_no_auth` | `false` | **since 0.7.12** — serve the panel with NO authentication. An empty `password_hash` no longer opens the panel by itself: without a password it refuses to start anywhere (it used to open on loopback, which handed full admin to every local process and to any SSRF on the host). Set a password with `qeli set-web-password`; this key is only for deliberately wanting an open panel. A warning is logged at startup |
| `persist_session_key` | `true` | persist the panel session-signing secret to a `0600` file (in `$STATE_DIRECTORY`, else `/etc/qeli/.session_key`) so panel logins **survive a full process restart**. Emitted only when `false`. Set `false` for a per-process-random key (stricter, H-4) — a full restart then logs everyone out. The key is not in the config or the panel-generated `/etc/qeli` archive under systemd; a full manual backup that includes `/var/lib/qeli` does contain it and must be protected accordingly |
| `base_path` | `""` | plain reverse-proxy URL path (e.g. `/qeli`, max 128 characters); empty = served at root. An `X-Forwarded-Prefix` header overrides it per-request. See "Reverse-proxy sub-path" below |
| `csrf` | `true` | CSRF same-origin protection for mutating requests. **Keep `true`.** `false` disables the Origin/Referer check entirely (with a startup warning) — only acceptable on a loopback-only bind (accessed via an SSH forward); dangerous on a public/LAN bind (any site you open could drive your logged-in panel). Loopback origins are accepted by default only on the panel's port; add an SSH forward's different local port to `allowed_origins` |
| `trusted_proxies` | `[]` | strictly validated reverse-proxy source IPs/CIDRs whose `X-Forwarded-For` is trusted (for the allowlist + rate-limiting); empty = trust no proxy header. Always emitted |
| `session_ttl_secs` | `86400` | panel login-session lifetime (cookie `Max-Age` + token expiry), seconds; active configuration accepts `60..=2592000` (30 days). Emitted only when non-default (`≠ 86400`) |
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
  encrypted copy (`password_enc`, key `/var/lib/qeli/panel-secret.key`) so a config can
  be re-issued without typing the password. Never returned over the API. The key is
  deliberately excluded from the panel-generated `/etc/qeli` backup; the legacy key in
  `/etc/qeli` is migrated automatically on upgrade. See
  [PANEL.md](PANEL.md#3-password-storage-model--trade-off) for recovery consequences and
  the security trade-off.

## Logging

<!-- normative-sync: logging-rotation-format-issue69-v1 -->

The `[logging]` section: `level`, `file`, `time_format` apply to Linux server/client;
`format` below applies only to the server (`server` and `_worker`).

```ini
[logging]
# error | warn | info | debug | trace  (RUST_LOG overrides)
level = info
# if set — logs are written to a file (the directory is created);
# if omitted — stderr (under systemd this goes to journald)
file = /var/log/qeli/server.log
# shape of the timestamp prefix (default datetime)
time_format = datetime
# server.conf: plain | json — log line format; configuration remains INI
format = plain
```

If `[logging] file` comes from an untrusted config, the early logger does
not create the directory or file; it reports the refusal on stderr and logs
there instead. Level and timestamp settings remain readable without a file
write. This applies to Linux server/worker/client before main validation.

Changing `level`, `file`, `time_format`, or `format` on a running server requires a full
process restart: restarting only the VPN worker does not reconfigure supervisor logging.

| Key | Default | Purpose |
|---|---|---|
| `level` | `info` | `error` \| `warn` \| `info` \| `debug` \| `trace`. The `RUST_LOG` env var takes priority |
| `file` | — (stderr) | log file path; the directory is created. Without it, stderr — i.e. journald under systemd. rotates at 10 MiB with three archives `.1`–`.3` |
| `time_format` | `datetime` | shape of the timestamp: `datetime` \| `rfc3339`/`iso8601` \| `time` \| `epoch`/`unix` \| `none`/`off`. Examples in the table below |
| `format` | `plain` | `plain` — text; `json` — one JSON object per server log line |

### `time_format` — the timestamp prefix

In `plain`, a log line is `<timestamp> LEVEL target: message`; this key controls only
the shape of the timestamp. It applies to both the server (`qeli`) and the
router client (`qeli-client`).

| Value | Example | When to use |
|---|---|---|
| `datetime` (default) | `2026-07-18 18:10:03.259` | local time, logs read by a human |
| `rfc3339` / `iso8601` | `2026-07-18T18:10:03.259Z` | UTC — correlating hosts, shipping to Loki/ELK |
| `time` | `18:10:03.259` | no date — short lines, embedded devices |
| `epoch` / `unix` | `1782000603.259` | machine parsing, computing deltas |
| `none` / `off` | *(no prefix)* | under systemd/journald or procd — they stamp the line already |

An unknown value silently falls back to `datetime`, so a typo in the config
can't stop startup. Local time follows the host TZ (`localtime_r`); `rfc3339`
and `epoch` are always UTC.

The same five variants are available in the apps — Settings → Log timestamp
(Windows, macOS, Android) and the `log_time_format` UCI/LuCI option on OpenWrt.
The apps store their own choice, not this file; the key here drives the `qeli`
and `qeli-client` logs. The defaults differ on purpose: `datetime` on the server
and desktop, `time` on Android (narrow screen), `none` on OpenWrt (syslog stamps
the line already).

Server `format = json` emits `level`, `target`, `message`, `pid`, and `timestamp`
(omitted with `time_format = none/off`). Quotes and newlines inside messages are
escaped; the panel filters severity using the `level` field. Unknown formats warn
on stderr and fall back to `plain`. Client applications retain their own logging
preferences; client INI does not gain a `format` key.

Linux server/client file output rotates before exceeding 10 MiB: the active file
becomes `.1`, and older archives shift up to `.3`. Supervisor and worker share a
`.lock` file and reopen the active path for every write. Do not delete `.lock`
while running. Size and archive count have no separate configuration keys.
New files occupy at most 40 MiB in total; a pre-existing oversized file is kept
intact on first rotation and expires after three more rotations. The directory
must allow file creation and renames. Symlinks, FIFOs, and files with multiple
hard links are rejected for log/lock/archive paths; write or rotation failures
send affected records to stderr. A single record larger than 10 MiB also goes to
stderr. The panel displays the active file; archives must be read separately.
System policy controls stderr/journald rotation; Qeli does not change it.

At the `info` level the log records all key events: profile and listener
start/stop, connection establishment (`New TCP connection`,
`Client … connected … IP …`), authentication (`AUTH attempt/OK/FAIL/BLOCKED`,
including brute-force lockouts), connection teardown (`Client … disconnected`),
administrative commands via the control socket (`CONTROL action=… user=…` —
kick/disable/enable/set-bandwidth), SIGHUP reload. Data-plane-side teardown reasons
are written at the `debug` level.

For diagnostics, `level = info` with a set `file` is the minimum sufficient.

> **`QELI_TRACE` — a packet-shape timeline (obfuscation diagnostics).** Not an INI key but
> an environment variable: `QELI_TRACE=<file> qeli client …` enables opt-in recording of
> packet sizes and timings (never payload) into a ring buffer; it dumps on `SIGUSR1`.
> It shows processing events inside the application; it does not confirm network delivery.
> Capture-point boundaries and clock comparison rules are in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
> Dumps use atomic replacement and mode `0600`; shutdown does not dump automatically.
> Parent directories must already exist. The guide lists capture coverage and panel log limits.

## Shared client profile processing (ABI 1.16)

INI, links, validation and defaults now have one Rust owner across clients. Draft export
preserves errors for repair; connection and URI export require valid profiles. Common
defaults are `gateway=true`, padding `0..255`, `heartbeat_jitter=2000` ms. Set
`gateway=false` explicitly to retain an older CLI split tunnel. Files remain INI.
See [shared client configuration](../plans/CLIENT-CONFIG-CORE.md) for migration, platform
constraints and build instructions.

Gateway/exit-node setup, refresh and cleanup each share 15 seconds across router mutex admission, discovery, WAN and firewall commands. Cleanup includes both families; partial records remain for a fresh attempt. Inside NetworkPlan/cleanup the remaining shared command budget also applies; internal I/O is not preempted. [Details](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-BUDGET.md).

Client route setup/prepare/COMMIT/cleanup each share 15 seconds across the operation mutex and commands of both families. COMMIT rollback receives a separate shared 15 seconds; unknown changes remain reserved for verified retry. Inside NetworkPlan/cleanup this limit is capped by the remaining shared command budget. [Contract](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-BUDGET.md).

Linux NetworkPlan commands share 15 seconds; rollback/cleanup receives separate shared 15 seconds, including subsequent stages and automatic Drop. [Contract and limits](OPERATIONS.md#shared-networkplan-and-cleanup-command-deadline).

### Client profile writes and active sessions

Profile configuration is INI. Edit/import it through the app; the internal encrypted store is not a configuration editor. Desktop instances coordinate through the shared sidecar lock and revision; Android windows check an encrypted version within the shared process. On iOS the app writes profiles and the tunnel extension only reads. A missing archive or encryption key refuses connection/read without the extension creating a profile or key. Recover a missing key by restoring a backup through the app.

Saving INI does not replace the configuration of an existing session. Reconnect explicitly when the app requests it. Direct external-process store writes bypassing app coordination are unsupported; finish every writer before maintenance. A revision detects conflicts but cannot make arbitrary writes ignoring the lock atomic.

[D08 checks and boundaries](../plans/AUDIT-DEBT.md).

### Service reload and root-owned configuration

`systemctl reload qeli` sends SIGHUP to the supervisor, which validates and reloads users/authentication and asks the worker to reload without replacing either process. Invalid INI/users are rejected without publishing new authentication state. Profile/listener/TUN and panel startup settings still need a full service restart. SIGHUP preserves the panel login lockout tracker. [Systemd audit](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).

Root mode can read qeli-owned private state, but panel config publication still requires a trusted file owned by root or the running user, without group/other write permissions and without a symlink. Root will therefore refuse a panel save of a qeli-owned INI. Review the configuration as administrator, then use `sudo chown root:root /etc/qeli/server.conf` and `sudo chmod 600 /etc/qeli/server.conf` if root is the intended service account. Do not change ownership of password receipts to qeli. To refresh an older root drop-in, rerun `sudo qeli set-service-user root` with the current binary and restart the service. This grants three filesystem capabilities, not an unrestricted capability set. [Systemd audit](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).

In 0.8.3 `sni` supplies TLS SNI for fake-tls/reality-tls and the HTTP Host
for TCP obfs with `front=websocket`. UDP obfs, TCP obfs with `front=none`,
and plain do not use it: legacy values survive INI editing but are omitted
from newly generated qeli:// links. All modes enforce a 253-byte limit and
reject controls and surrounding whitespace. fake-tls accepts `!`, `~`, `@`;
REALITY requires a DNS hostname.


### Client additions in 0.8.3: routes, UDP and Windows

In `[qeli]`, `pull_routes = true` accepts server routes by default.
`pull_routes = false` excludes only those routes from the shared NetworkPlan.
Local `include`, `exclude`, `route_local`, the default route selected by
`gateway = true`, tunnel addresses and transport negotiation remain active.
Required `/32` and `/128` tunnel DNS routes are independent of this switch;
an exact exclusion of a tunnel DNS address is still rejected. This does **not**
disable the whole server push. Also set `gateway = false` for split tunneling;
Rust INI serialization now preserves explicit `false`.

Linux/routers, Android, iOS, Windows and macOS share this policy. It survives
INI/model/backup round trips and new qeli:// links (`pull_routes=0` when off).
Older versions do not implement it; do not rely on them honoring a link's
`pull_routes=false`. Desktop forms expose “Accept routes from server”; mobile
clients expose the parameter through the INI editor.

Inner `mtu` and the outer UDP payload budget remain separate. Client path diagnostics describe the uplink budget; server reverse-probe logs describe downlink certification. Manual MTU does
not disable `mtu_probe=true`. With `mtu_probe=false`, the client emits neither
its initial nor repeated probes; the safe initial budget is 548 bytes for an
IPv4 carrier and 1232 for IPv6. Unconfirmed probing and path changes also use
fallback. Diagnostics expose `estimate=probe|fallback` and `fallback_reason`
(`probe_disabled`, `probe_unconfirmed`, `path_changed`, or `null` after success),
plus `inner_mtu`, `udp_payload_budget`, `data_frag`, `fragmented_records` and
`fragments_created`. CLI status JSON places this under
`stats.udp_data_fragmentation`; logs use `UDP path diagnostics`. Startup is
info-level; changed counters are debug-level, at most once per 10 seconds.
Server `queue-stats` adds per-profile `data_fragmentation`, preserving its
existing `profiles` queue object.

Counters mean **encrypted-record split attempts** and DATA_FRAG fragments
created, including retries and control records. They do not count loss or inner
IP packets, and do not confirm delivery. Recordizer changes packet-to-record
mapping. Distinguish inner IP fragmentation, DATA_FRAG, outer IP fragmentation
and probe/cover datagrams in captures. The fixed C/JNI stats layout is unchanged.
Client probes and the separate server reverse-probe have their own DF policy;
this is not a DF setting for all traffic on the shared server socket. IPv6 has
no IPv4 DF bit; the inner IPv6 MTU remains at least 1280. This stage adds neither
fit-path mode nor a one-IP-packet/one-datagram guarantee.

Windows displays IPv4/IPv6 separately from the committed NetworkPlan. Copy
buttons and tooltips preserve complete addresses; disconnected or stale service
observations clear them. The graph uses existing counters, keeps at most 120
samples in memory, resets on session/counter changes, and treats missing data as
a gap. Hidden windows skip graph work; history is not persisted. Form, INI and
import dialog dimensions are stored separately in app settings and clamped to
the current monitor/DPI. Window placement is not a VPN configuration parameter.

Windows-only `windows_disable_sharing = false` preserves OS behavior by default.
When true, “Disable Microsoft Client / File Sharing on Qeli adapter” disables
only `ms_msclient` and `ms_server` on the Wintun created by Qeli. The creator
handle and exact LUID/GUID establish ownership; CIM associations select that
adapter's binding instances without alias wildcards. The operation has a
5-second deadline and verifies readback and unchanged IP bindings. Failure
rejects setup and invokes normal cleanup. Physical/foreign adapters are not
selected. Service mode uses the same profile setting; WinDivert/per-app does
not apply it. Other clients preserve it as inactive platform policy. False does
not force previously disabled bindings on. This local policy is not exported in qeli:// links. `persist_tun` still covers reconnect;
a permanent adapter surviving Disconnect is not implemented in this stage.
