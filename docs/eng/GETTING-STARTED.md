# Qeli — installation & getting started (step by step)

A complete from-scratch guide: from standing up the server to creating users with
routes and connecting your first client — **both via the CLI and via the web panel**.

Targets a clean **Linux server** (Debian/Ubuntu) with root access. All server commands
run as root (or via `sudo`).

> References this guide builds on:
> [CONFIG.md](CONFIG.md) — every config key · [PANEL.md](PANEL.md) — web panel ·
> example configs: [`server.conf`](../../qeli/config/server.conf) ·
> [`users.conf`](../../qeli/config/users.conf) · [`client.conf`](../../qeli/config/client.conf).

## Contents
1. [What you need](#1-what-you-need)
2. [Install the server](#2-install-the-server)
3. [Initial server setup (CLI)](#3-initial-server-setup-cli)
4. [Start & verify](#4-start--verify)
5. [Full-tunnel: NAT & forwarding at the OS level](#5-full-tunnel-nat--forwarding-at-the-os-level)
6. [Creating users (CLI)](#6-creating-users-cli)
7. [Routes: split/full-tunnel, pushed routes, ACL, static IP](#7-routes)
8. [Connecting a client](#8-connecting-a-client)
9. [The same via the web panel](#9-the-same-via-the-web-panel)
10. [Live management & diagnostics](#10-live-management--diagnostics)
11. [Wire modes — which to pick](#11-wire-modes--which-to-pick)
12. [Common problems](#12-common-problems)

---

## 1. What you need

- A **Linux x86-64 server** (Debian 11+/Ubuntu 20.04+), root, a public IP.
- An **open port** for the VPN (TCP `443` by default) and, if you enable the panel,
  its port (`8080` by default). Open them in your cloud firewall / security group.
- A kernel with **TUN** support (`/dev/net/tun` — present almost everywhere; some VPS
  enable it in the provider panel).
- `iproute2`, `iptables` packages (pulled in as .deb dependencies).
- A **client**: phone (Android), desktop (Windows/macOS), or Linux CLI.

A single `qeli` binary plays both roles: `qeli server` and `qeli client`.

---

## 2. Install the server

> ⚡ **Fastest path (one command).** The repo root ships a ready installer
> [`install-reality-server.sh`](../../install-reality-server.sh): it installs the
> dependencies and the latest `.deb`, **asks which profile** (reality-tls by default, or
> fake-tls) **and which port** (default :443), brings it up with full-tunnel NAT, and
> creates **5 users** with ready `qeli://` connection strings under
> `/etc/qeli/client-links/`. Run as root: `./install-reality-server.sh <public-ip-or-host>`
> (or `sudo ./install-reality-server.sh …` if you have sudo — it is not required and is
> never installed). For a non-interactive run (or `curl … | bash`) set the choice up
> front: `QELI_PROFILE=fake-tls QELI_PORT=8443 ./install-reality-server.sh <IP>`. After
> that you just paste a connection string into the app. Manual steps below.

### Option A — .deb package (recommended)

```bash
# from the GitHub Releases tab or your own build (see below)
sudo apt install ./qeli_0.7.10_amd64.deb
```

The package:
- installs the binary to `/usr/bin/qeli` and grants it `cap_net_admin` (runs without root under systemd);
- creates the system user `qeli` and the dirs `/etc/qeli`, `/var/log/qeli`, `/var/lib/qeli`;
- ships **examples** `/etc/qeli/{server,users,client}.conf.example` (you create the real configs yourself — step 3);
- installs the systemd unit `qeli.service` (`ExecStart=/usr/bin/qeli server --config /etc/qeli/server.conf`).

### Option B — build from source

Requires Rust (stable). From the repo root:

```bash
cd qeli
cargo build --release          # binary → qeli/target/release/qeli

# (optional) build your own .deb from the fresh binary:
make -C debian deb             # → qeli/debian/qeli_0.7.10_amd64.deb
```

Without the package you can run the binary directly (see step 4), but then you create
the systemd unit, the user and the directories yourself.

### Option C — Docker

A **multi-arch** image (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) carries **both
roles** (`qeli server` and `qeli client`) with every runtime dependency bundled
(`iproute2`, `iptables`, CA certs) — it runs on any Linux host and on router container
runtimes (MikroTik RouterOS v7, OpenWrt). The container needs `NET_ADMIN` +
`/dev/net/tun`; a ready `docker-compose.yml` (server + optional gateway client) is
included. Build/run instructions, compose example and caveats:

> 🐳 **[release/docker/README.md](../../release/docker/README.md)**

With Docker you can skip the rest of this guide's install/systemd steps; profile and
user management below (CLI or web panel) still apply inside the container.

---

## 3. Initial server setup (CLI)

### 3.1. Create a real config from the example

```bash
sudo cp /etc/qeli/server.conf.example /etc/qeli/server.conf
sudo nano /etc/qeli/server.conf
```

The format is **flat-INI**. The example file is **exhaustive**: every key is listed
with its default value and a note; any deleted key falls back to its default. To get
started you only need to check a few fields in the `[profile:tcp]` section.

### 3.2. The minimal profile fields

```ini
[profile:tcp]
enabled = true

# what to listen on (the port must be open in your firewall)
bind.address = 0.0.0.0
bind.port    = 443
bind.transport = tcp            # tcp | udp

# the tunnel's virtual network
tun.address  = 10.0.0.1         # the server's address inside the tunnel (gateway)
tun.netmask  = 255.255.255.0
tun.mtu      = 1400             # pushed to clients; for production TCP see §12 and CONFIG.md

# pool of addresses handed out to clients
pool.cidr    = 10.0.0.0/24
pool.exclude = 10.0.0.1         # never hand out the gateway

# on-the-wire masking mode (see §11)
obf.mode = fake-tls
```

Everything else (DNS proxy, padding, heartbeat, limits) already has sensible defaults
in the example. Full description of every key — [CONFIG.md](CONFIG.md).

> **Multiple profiles.** You can run a second interface side by side, e.g. UDP on
> `:1443` — add a `[profile:udp]` section (its own `tun.name`/`tun.address`/`pool.cidr`/
> `bind.port`/`bind.transport = udp`). Each profile has its own identity key and pool.
> A ready template with **all 9 modes at once** (reality-tls on :443, the rest on
> 8443–8450) ships as `/etc/qeli/server-multiprofile.conf.example` (installed by the
> .deb; in the source — [`config/server-multiprofile.conf`](../../qeli/config/server-multiprofile.conf)):
> copy it to `server.conf`, keep the profiles you want, replace the `CHANGEME` keys.

### 3.3. Users: where they live

By default users live in a **separate file** — `auth.users_file` (default
`/etc/qeli/users.conf`). The example configs ship **without** inline users; add users
with `qeli add-client` (step 6), which appends them to that file. Nothing else to do.

> You *can* instead define users inline in `server.conf` as `[user:*]` sections, but
> then `auth.users_file` is **ignored entirely** (inline takes precedence) — so don't
> set both, or the server warns and the file is silently dropped. The separate file is
> the recommended default; keep `[user:*]` out of `server.conf`.

---

## 4. Start & verify

```bash
sudo systemctl enable --now qeli         # start + autostart at boot
systemctl status qeli                    # should be active (running)
journalctl -u qeli -f                     # live log (Ctrl-C to exit)
```

On startup the log should show `Profile 'tcp': TUN vpn0 is up`,
`listening on 0.0.0.0:443`, and a line with the profile's public key.

### Get the server identity key (to pin on the client)

```bash
sudo qeli show-identity --config /etc/qeli/server.conf
```

```
PROFILE   BIND                SERVER PUBLIC KEY (pin on client)
tcp       tcp://0.0.0.0:443   33f399e6d9b8a31a41e5ffa8b1e1ce457f10d8bbf07c145377fcb7917d532450
```

The client **pins** this hex key (`key = …`). The command creates the profile keys if
they don't exist yet (`/etc/qeli/identity/<profile>.key`).

> **Why pinning is mandatory.** **H-1** is on by default
> (`auth.bind_static_to_session = true`): session keys are bound to the server's static
> identity, so the client **must** pin the real key (otherwise the server rejects it).
> The `qeli://` link produced by `add-client --link` (step 6) already embeds this key —
> the user doesn't type anything by hand.

After changing the config, apply it: `sudo systemctl restart qeli`.

---

## 5. Full-tunnel: NAT (set up automatically)

Only needed if you want to route the client's **entire internet traffic** through the
server (full-tunnel / "exit node"). For split-tunnel (access only to the tunnel subnet
and resources behind the server) — skip this.

Flip one toggle in the profile — the server itself, via `iptables`, enables IP
forwarding and installs MASQUERADE + FORWARD + MSS-clamp, and removes the rules again
when it stops:

```ini
# in [profile:tcp]
routing.nat.enabled  = true
# WAN egress interface. Leave empty/default to auto-detect (ip route get 1.1.1.1),
# or set it explicitly, e.g. ens3.
routing.nat.interface =
```

```bash
sudo systemctl restart qeli      # the server applies NAT when the profile starts
journalctl -u qeli | grep NAT    # "NAT masquerade active via iptables (10.0.0.0/24 -> ens3)"
sudo iptables-save | grep qeli-nat   # see the installed rules
```

What the server installs (each rule is tagged with the comment `qeli-nat:<profile>` so
it can remove exactly those on disable/stop): `net.ipv4.ip_forward=1`; `-t nat
POSTROUTING -s <pool.cidr> -o <wan> -j MASQUERADE`; two `FORWARD … ACCEPT` (tun↔wan);
two `-t mangle FORWARD … TCPMSS --set-mss (tun.mtu−40)` (PMTU-black-hole guard).

> ⚠️ **Requires `iptables`** (the `iptables` package). The .deb depends on it, so a
> package install already has it. If `iptables` is **missing**, NAT can't be applied:
> the server log shows `ERROR … NAT requested but NOT applied`, and the **web panel**
> (Dashboard) shows a yellow banner. Install it: `sudo apt install iptables`. Only the
> classic `iptables` CLI is used (never `nft`/`ufw`).

> Production tuning (BBR, buffers, MTU probing — noticeably speeds up TCP on mobile) is
> in [CONFIG.md → "Server OS tuning"](CONFIG.md). Strongly recommended for full-tunnel.
> To keep NAT across a reboot without the qeli service you may also persist the rules
> (`apt install iptables-persistent`), but qeli normally re-installs them on start.

---

## 6. Creating users (CLI)

### 6.1. A simple user

```bash
sudo qeli add-client alice --password 's3cret'
sudo systemctl restart qeli            # re-read users
```

The command Argon2id-hashes the password and appends a `[user:alice]` section to the
users file. Without `--password` it generates a random one and **prints it once**.

### 6.2. With options

```bash
sudo qeli add-client bob \
  --password 'pass123' \
  --static-ip 10.0.0.50 \          # fixed tunnel IP
  --max-sessions 3 \               # how many devices at once (0 = unlimited)
  --profiles tcp                   # access only to the tcp profile (interface isolation)
```

| Option | Purpose |
|---|---|
| `--password <P>` | password (else random, printed once) |
| `--static-ip <IP>` | permanent tunnel address (else from the pool) |
| `--max-sessions <N>` | concurrent **device** cap (0 = inherit group/unlimited) |
| `--profiles a,b` | allowed profiles (empty = all) |
| `--link --host <H[:port]>` | also print a `qeli://` link + QR (see below) |
| `--link-profile <P>` | which profile to build the link for (default: first) |

### 6.3. Issue a `qeli://` link / QR right away

```bash
sudo qeli add-client carol --password 'pw' --link --host vpn.example.com:443 --link-profile tcp
```

Prints a ready `qeli://…` link (with the **server key**, mode and SNI already embedded)
and a QR code in the terminal — the user scans it in the mobile client and connects in
one tap. Nothing to type by hand.

### 6.4. Manual fine-tuning (optional)

Any field can be added straight into the `[user:*]` section (see the comments in
[`users.conf`](../../qeli/config/users.conf)):

```ini
[user:bob]
password_hash = $argon2id$v=19$m=...$...   # set by add-client
enabled = true
static_ip = 10.0.0.50
max_sessions = 3
profiles = tcp
allowed_networks = 10.0.0.0/24, 192.168.1.0/24   # ACL: where this user may go (empty = anywhere)
bandwidth.limit_mbps = 50                         # rate cap (0 = unlimited)
bandwidth.burst_mbps = 100
route = 10.20.0.0/16 gateway=10.0.0.1 metric=100  # per-user pushed route (repeatable)
group = premium                                    # inherit from [group:premium]
```

Groups are templates for repeated settings:

```ini
[group:premium]
bandwidth_limit_mbps = 100
max_sessions = 5
allowed_networks = 0.0.0.0/0
```

After editing the users file — `sudo systemctl restart qeli` (or apply it live, §10,
without a restart).

---

## 7. Routes

### 7.1. Split-tunnel (default)

By default the client routes only the **tunnel subnet** (`pool.cidr`) through the VPN.
Everything else bypasses the VPN. No server-side setup needed.

### 7.2. Full-tunnel (all traffic through the server)

Enabled **on the client** (`gateway = true` in `client.conf` / a toggle in the app),
and on the server it requires the NAT+forwarding from **§5**. Then all of the client's
internet egresses with the server's IP.

### 7.3. Pushed routes at the profile level (to all clients of the profile)

To give clients access to a network **behind the server** (e.g. an office
`192.168.50.0/24`), the server "pushes" a route — the client adds it to its table on
connect:

```ini
# in [profile:tcp] — repeatable
route = 192.168.50.0/24 gateway=10.0.0.1 metric=100
```

`gateway` is the server's tunnel address (`tun.address`). `metric` sets priority
(optional). Additionally `routing.forward_private = true` forwards RFC1918 networks
behind the server.

### 7.4. Per-user routes (to one specific user)

Same syntax, but in a `[user:*]` section — pushed only to that user:

```ini
[user:bob]
route = 10.20.0.0/16 gateway=10.0.0.1 metric=100
```

### 7.5. Destination ACL (`allowed_networks`)

Restricts **where** a user may go through the tunnel (a whitelist of dst CIDRs).
Empty/absent = unrestricted:

```ini
[user:bob]
allowed_networks = 10.0.0.0/24, 192.168.1.0/24
```

### 7.6. Client-to-client and static addresses

```ini
# in [profile:tcp]
routing.client_to_client = true      # let clients see each other inside the tunnel
pool.reservation.alice = 10.0.0.100  # pin an IP to a user (alternative to user.static_ip)
```

### 7.7. DNS over the tunnel

By default the server runs a DNS proxy on `tun.address:53` and pushes it to clients:

```ini
# in [profile:tcp]
dns.enabled  = true
dns.upstream = 1.1.1.1, 8.8.8.8
# dns.blocklist = ads.example.com, track.example.com   # answer with 0.0.0.0 (ad blocking)
```

With `dns.enabled = false` the server pushes no DNS — the client keeps its own resolvers.

---

## 8. Connecting a client

### 8.1. Mobile (Android) and desktop (Windows/macOS)

1. On the server, issue a link: `qeli add-client <user> --link --host <public-host:port>`
   (§6.3) — you get `qeli://…` + a QR.
2. In the app: **Add profile → Scan QR** (or **Paste qeli:// link**) → the profile
   appears with all parameters and the **server key pinned**.
3. Tap the connect ring. Done.

Full-tunnel and "route local networks" are toggles in the app.

> ⚠️ **macOS — first launch.** The app is **ad-hoc** signed (not notarized by Apple), so
> Gatekeeper blocks it and it **won't open** on a double-click. Clear the quarantine once
> in Terminal:
> ```bash
> xattr -cr /Applications/Qeli.app
> ```
> (see [qeli-mac/README.md](../../qeli-mac/README.md)).

### 8.2. Linux CLI client

```bash
sudo cp /etc/qeli/client.conf.example /etc/qeli/client.conf
sudo nano /etc/qeli/client.conf
```

Minimum (see [`client.conf`](../../qeli/config/client.conf) — every key documented):

```ini
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = alice
pass   = s3cret
key    = 33f399e6…d532450     # from `qeli show-identity` (REQUIRED under H-1)
mode   = fake-tls             # must match the profile's obf.mode
sni    = www.cloudflare.com

# local routing (NOT carried in a qeli:// link — file only):
gateway     = false           # true = full-tunnel (all traffic through the VPN)
route_local = false           # also route private networks + server-pushed ones
kill_switch = false           # block leaks while the tunnel is down (full-tunnel)
dns         = tunnel          # tunnel = manage /etc/resolv.conf; off = don't touch it
```

```bash
sudo qeli client --config /etc/qeli/client.conf
```

> Under H-1 (the default) `key` is required and must be **real** (not all-zero). If the
> server has `bind_static_to_session = false`, you may use TOFU (an all-zero `key`).

---

## 9. The same via the web panel

Full guide — [PANEL.md](PANEL.md). Quick start:

### 9.1. Enable the panel

```bash
# set the admin password (generates/hashes it, writes it into [web], enables the panel)
sudo qeli set-web-password                    # random password, printed once
# or your own:  sudo qeli set-web-password --password 'PANELPASS'
```

Fill in the `[web]` section for access over a public IP and restart:

```ini
[web]
enabled = true
bind = 0.0.0.0            # or 127.0.0.1 for SSH-tunnel-only access
port = 8080
tls  = true              # native HTTPS (self-signed auto; the browser warns once)
# allowed_ips = 203.0.113.4        # (recommended) put your own IP on the allowlist
# public_host = vpn.example.com    # default host for share links
```

```bash
sudo systemctl restart qeli
```

> **Fail-closed:** on a non-loopback `bind` with an empty `password_hash` the panel
> won't start (the VPN `:443` still works — it's a separate process). Open port `8080`
> in your firewall.

### 9.2. Using it

Open `https://<bind>:8080`, log in as `admin`.

- **Dashboard → "Quick start"** — mode tiles (REALITY / HTTPS-fake-tls / Obfuscated /
  QUIC): one click creates a ready profile (TUN/NAT/DNS/pool/obfuscation), applies it
  and restarts the server.
- **Config** — every profile field on one page (Bind/TUN/Pool/Routing/DNS/Obfuscation/
  Performance), incl. pushed routes and NAT; the **Global** tab — identity keys (view +
  **Rotate**), Web UI, H-1. Save with **Save to Disk** or **Apply & Restart**.
- **Users** — create a user (password in **plaintext** — hashed by the server), set
  bandwidth/static-IP/group/max-sessions/**allowed profiles**/allowed-networks/
  **per-user routes**. Groups are templates.
- **Share / QR** on a user — issues a `qeli://` link + QR **without typing the password**
  (the server keeps a reversibly-encrypted copy; the password is unchanged).

### 9.3. Connecting TO other servers (the Client tab)

The panel can not only **serve** a VPN but also **dial OUT** to other qeli servers (this box
becomes a client — a relay, or just a managed client). The **Client** tab:

- **Add a profile** — three ways:
  - **Import qeli:// link** — paste the `qeli://` string your server admin gave you;
  - **Add manually** — a form (server/user/pass/key/mode/sni/rsid/obfs_key, QUIC for UDP,
    split/full-tunnel);
  - **Paste INI config** / the **Raw INI** toggle — a full client INI (any key:
    `dev`/`mtu`/`dns`/`kill_switch`/`bind_static`/`[logging]`…).
- **Each profile is controlled INDEPENDENTLY.** Adding a profile does NOT connect it — it
  sits *Disconnected*. Each has its own **Connect** / **Disconnect** button; you start only
  the ones you want. Status (connected + log tail) refreshes itself.
- **Multiple connections at once** — bring up as many as you like: each profile is
  **auto-assigned its own TUN device** (`vpn0`/`vpn1`/…, shown in the list), so the tunnels
  don't clash. For the same server, create several profiles (one tunnel per profile). Any
  wire mode, not just reality-tls.
- ⚠️ **Full-tunnel + multiple tunnels.** A host has a single default route, so **multiple
  simultaneous full-tunnels conflict** — for a multi-relay use split-tunnel (and distinct
  pool subnets on the servers), or keep one full-tunnel at a time. Full-tunnel on a server
  box can cut off the panel/SSH itself — enable it deliberately.
- **Storage:** profiles live in `/etc/qeli/clients/<name>.conf` (the same flat-INI). So you
  can do the same with **files**: drop configs there and run
  `qeli client --config /etc/qeli/clients/<name>.conf` (for several, a distinct `dev` per
  file). Ready examples — [`client-reality.conf`](../../qeli/config/client-reality.conf) and
  [`client.conf`](../../qeli/config/client.conf) (all modes and keys).
- **Auto-start at boot.** Each profile has an **autostart** flag: flagged profiles are
  brought up by `qeli` (supervisor + panel) when the service starts — after a
  `reboot`/`systemctl restart qeli` the chosen tunnels come up with no manual Connect. Set it
  **two equivalent ways**:
  - in the panel — the **“Auto-connect this profile when the server/panel starts”** checkbox
    in the profile form (flagged profiles show an `↻ autostart` marker in the list);
  - in the file — the line `autostart = true` in the `[qeli]` section of
    `/etc/qeli/clients/<name>.conf` (hand-edit it — same effect as the checkbox).

  The flag is **per-profile and independent** — only flagged profiles auto-connect; the rest
  stay *Disconnected* until you Connect them. To turn it off, clear the checkbox (or remove
  the line from the file).

---

## 10. Live management & diagnostics

Commands via the control socket — **without restarting** the server
(`--socket`, default `/var/run/qeli/control.sock`):

```bash
sudo qeli list-clients               # who's connected now
sudo qeli kick alice                 # drop a user's sessions
sudo qeli disable-user bob           # block (kick + forbid reconnect)
sudo qeli enable-user bob            # allow again
sudo qeli set-bandwidth alice 50     # cap Mbit/s (0 = unlimited)
sudo qeli show-routes alice          # the user's routes
sudo qeli rotate-identity tcp        # rotate the profile key (clients then update key=)
sudo qeli list-blocked               # IPs locked by brute-force protection (wrong password)
sudo qeli unblock 1.2.3.4            # release one address (or --all for every one)
```

Diagnostics:

```bash
journalctl -u qeli -f                          # server log
sudo qeli list-clients                          # active sessions + assigned IPs
ping 10.0.0.2                                   # ping a client from the tunnel (on the server)
ss -tulnp | grep qeli                           # is it listening on :443 / :8080
```

On the client, check that a `vpn0` interface and routes appeared (`ip a`, `ip route`).

---

## 11. Wire modes — which to pick

Set by `obf.mode` on the server and `mode` on the client (they must match):

| Mode | When |
|---|---|
| `fake-tls` | **default.** TLS-1.3 mimicry, against passive/signature DPI. A good balance. |
| `reality-tls` | maximum masking: the tunnel runs **inside a genuine TLS 1.3** session borrowing a real site's cert (Xray-REALITY parity). Defeats active probing too. Needs `key` + `reality_sid` + `sni`; slightly slower. |
| `obfs` | ChaCha20 stream obfuscation of the whole flow + WS fronting. Needs a shared `obfs_key`. TCP-only. |
| `plain` | no masking — a bare encrypted tunnel (max speed, TCP-only). For trusted networks. |
| QUIC masking | for **UDP** profiles (`obf.quic.enabled = true`), masks as QUIC. |

A detailed comparison, REALITY setup (short_ids, handrolled), multipath bonding — in
[CONFIG.md](CONFIG.md). Benchmarks of all modes — [BENCHMARK.md](BENCHMARK.md).

---

## 12. Common problems

- **Client passes "identity verified" but drops immediately / `AUTH FAIL … not found`.**
  The user isn't where the server looks: `server.conf` has inline `[user:*]`, so
  `users_file` is ignored (see §3.3). Keep users in one place.
- **Connects, but no internet (full-tunnel).** Check that the profile has
  `routing.nat.enabled = true` and that **`iptables`** is installed on the server (`apt
  install iptables`) — without it the server can't add MASQUERADE (log: `NAT requested
  but NOT applied`, panel: a yellow banner). Verify: `iptables-save | grep qeli-nat`
  should list the rules; `journalctl -u qeli | grep NAT` shows "NAT masquerade active".
  If the WAN interface was auto-detected wrong, set `routing.nat.interface` explicitly.
- **Downloads hang / drop under load (TCP).** No MSS clamp to the tunnel MTU (a PMTU
  black hole) — the `TCPMSS` rule from §5; for production also BBR (CONFIG.md).
- **Server rejects the client with no clear reason.** H-1 is on (default) but the
  client doesn't pin the key. Set the real `key` (from `qeli show-identity`) — easiest
  is to issue the profile via `add-client --link` (§6.3).
- **Locked out after a few wrong passwords.** The per-source-IP anti-brute-force
  (`auth.brute_force.*`) tripped. Wait out the lockout window or restart the server
  (`systemctl restart qeli` clears the in-memory counters).
- **The web panel won't start.** Fail-closed: a public `bind` with an empty
  `password_hash` — set `qeli set-web-password` (§9.1). The VPN `:443` is unaffected.
- **403 on every save in the panel behind a domain/proxy.** Add the domain to
  `web.allowed_origins` (same-origin CSRF); add your IP to `web.allowed_ips`, or you'll
  lock yourself out.

---

> Found an inaccuracy or have a setup question — open an issue/discussion in the
> repository. Full documentation map — in the [README](README.md).
