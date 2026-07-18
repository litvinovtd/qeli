# Qeli — operations: compatibility, upgrades, rollback, backup

> **These docs describe 0.7.11** — the current released version.
> Features marked "**since 0.7.12**" are already in the source tree but **not
> released yet**: they are absent from a 0.7.11 `.deb` install.

Installation is covered in [GETTING-STARTED.md](GETTING-STARTED.md), config keys in
[CONFIG.md](CONFIG.md), error decoding in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
This file covers what you need **after** the first start: why a client won't meet the
server, how to upgrade and roll back, what you must back up, and what to open in the
firewall.

## Contents
1. [What must match between client and server](#1-what-must-match-between-client-and-server)
2. [Checking a config before you start](#2-checking-a-config-before-you-start)
3. [Upgrades and rollback](#3-upgrades-and-rollback)
4. [What to back up](#4-what-to-back-up)
5. [Firewall: what to open](#5-firewall-what-to-open)
6. [Silent configuration traps](#6-silent-configuration-traps)

---

## 1. What must match between client and server

Almost none of this is **negotiated on the wire** — both sides read the values from
their own configs independently. So a mismatch rarely looks like a clean "parameters
disagree" error; it looks like the connection dying halfway.

The nastiest one is **`bind_static` (H-1)**: what diverges is not a check but the KDF
salts, so the handshake formally succeeds and then the very first encrypted record
fails to decrypt.

| What | Server side | Client side | Symptom on mismatch |
|---|---|---|---|
| **`bind_static` (H-1)** | `auth.bind_static_to_session` (**default `true`**) | `bind_static` (default `true`) | The KDF salts diverge, so the two sides derive **different keys**. There is no explicit "parameters disagree" error: the server logs `handshake failed for <addr>`, the client dies right after `Handshake complete` (`decryption failed`). The least obvious failure of all |
| **Server key (pinning)** | `qeli show-identity` | `key` / `auth.server_public_key` | `SERVER KEY MISMATCH … possible MITM attack!` — with a hint about what to do after a deliberate rotation |
| **`bind_static` + zero key** | — | `key = 0000…` (TOFU placeholder) with `bind_static = true` | Fatal before any traffic: `bind_static_to_session is on but server_public_key is the all-zero TOFU sentinel` |
| **Transport** | `bind.transport` (`tcp`/`udp`) | `proto` | The connection simply never establishes: a TCP client knocking on a UDP port and vice versa |
| **Wire mode** | `obf.mode` | `mode` | The server doesn't recognise the stream: handshake timeout, `handshake timeout` in the debug log |
| **`obfs_key` (for `mode = obfs`)** | `obf.obfs_key` | `obfs_key` | The stream decrypts to garbage → the handshake won't parse |
| **REALITY `short_id`** | `obf.tls.reality_proxy.short_ids` | `reality_sid` | The server **silently** treats you as a stranger and bridges you to the target: "won't connect, no errors", while `curl` to the server shows the real site |
| **AmneziaWG junk** | `obf.awg.jc` / `jmin` / `jmax` | `awg` / `jc` / `jmin` / `jmax` | Handshake fails: the server expects a different junk-packet count. Enable on **both** ends with the same `jc` |
| **Clocks (for REALITY)** | — | — | The token carries a timestamp with a **±120 s** window. Drifted clocks give the same symptom as a wrong `short_id`: silently bridged to the target. Run NTP |
| **Which profile you pin** | **every** profile has its own `identity/<profile>.key` | `key` | Profile A's pin against profile B's port → `SERVER KEY MISMATCH`. The key is per-profile, not per-server |
| **`require_client_key_proof`** | `auth.require_client_key_proof` | whether a pin is set | The reverse direction: the server rejects an **unpinned** client — `AUTH DENIED … server key not pinned` — and the attempt counts against that IP's brute-force budget |
| **`obf.fronting`** | `obf.obfs_fronting` (default `websocket`) | `front` | For `mode = obfs`: a mismatch gives `obfs ws: server did not switch protocols` |

**In practice.** Don't hand-write client configs — import a `qeli://` link
(`qeli add-client <user> --link --host <host>`, or the button in the panel). It carries
`host:port`, `user`, `pass`, `proto`, `mode`, `key`, `sni`, `reality_sid`, `obfs_key`,
`awg`/`jc`/`jmin`/`jmax` — i.e. **every** row above except `bind_static` (on by default
on both sides) and the clock.

Routers deserve a note: the OpenWrt template (`qeli-openwrt/files/qeli.config`) ships the
all-zero TOFU key with `bind_static` set to `'0'` to match it. The moment you fill in a
**real** key, set `bind_static` to `'1'` as well, or you get row 1 of the table.

---

## 2. Checking a config before you start

```bash
qeli check-config --config /etc/qeli/server.conf
qeli check-config --client --config /etc/qeli/client.conf
```

The command starts nothing — no listeners, no TUN, no service — and separates three kinds
of problem that a normal startup cannot tell apart:

1. **Syntax** — the broken line, with its number.
2. **Schema** — the same checks the data-plane worker runs at startup (unknown
   `bind.transport`, a typo in `obf.mode`, `plain` on UDP, a zeroed
   `[profiles.performance]`, and so on), so its verdict matches a real start.
3. **Keys nothing reads** — i.e. typos.

The third one matters more than it sounds. **An unknown key is not an error**: it is simply
never requested, so the setting silently keeps its default, with no warning at any log
level. That is exactly how `exclude_routes` instead of `exclude` looked like a working
setting while split-tunnel was never applied at all. Now it shows up:

```
/etc/qeli/client.conf: 1 key(s) that nothing reads — check the spelling:
  [qeli] exclude_routes
An unknown key is not an error: it is simply ignored, and the setting keeps its default.
```

Exit code: `0` clean, `1` problems found. Suitable for CI and as a pre-flight before
`systemctl restart`.

> The command validates **the config file itself**, not the environment around it. It does
> not read `users_file`, check that the identity key exists, that the ports are free, or
> that permissions are right — those only surface on a real start. "OK" means "this config
> is valid", not "the server will definitely come up".

> On older versions without this command you can validate by running in the foreground
> (`systemctl stop qeli && qeli server --config …`), but you must interrupt it yourself:
> the supervisor respawns a dead worker in a loop with a growing backoff and will not
> exit on its own even on a hopelessly broken config.

---

## 3. Upgrades and rollback

### 3.1. The `.deb` install (the usual path)

The repo root ships [`update-qeli-server.sh`](../../update-qeli-server.sh), which does
the right things by itself:

```bash
sudo ./update-qeli-server.sh
```

What it actually does:
1. Detects the current version and the latest GitHub release (`QELI_REPO` overrides the repo).
2. Downloads the `.deb` **and `SHA256SUMS`** and **verifies the checksum** — refusing to install on a mismatch.
3. **Copies the current binary** to a backup beside it.
4. Installs the package and restarts `qeli`.
5. If the service **fails to come up**, it **restores the old binary** and restarts again;
   if that also fails it says plainly that the service is down and points you at the journal.

So rollback-on-failure is built in; nothing extra to do. `QELI_FORCE=1` reinstalls even
the current version.

Three caveats:

- **The rollback covers the binary only.** The script does not back up your config, users
  or identity key, and it does not roll back dpkg's metadata (the package registers as new
  while the old binary sits on disk). Take a backup before a major upgrade — see
  [§4](#4-what-to-back-up).
- **`QELI_DEB=/path/to.deb` disables checksum verification** — there is nothing to compare
  against. Use it deliberately, for your own builds.
- **There are no signatures**, only the SHA256 from the same release. That guarantees
  integrity, not provenance.

The manual equivalent, if you'd rather not use the script:

```bash
sudo cp -a "$(command -v qeli)" /root/qeli.bak      # 1. back up the binary
sudo apt install ./qeli_<version>_amd64.deb         # 2. install
sudo systemctl restart qeli && systemctl status qeli
# roll back if it didn't come up:
sudo systemctl stop qeli && sudo cp -a /root/qeli.bak "$(command -v qeli)" && sudo systemctl start qeli
```

> **The package does not touch your configs.** The `.deb` only installs `*.conf.example`;
> your `/etc/qeli/server.conf`, `users.conf` and the identity key are not in the package
> at all, so there is nothing to overwrite them with. An "upgrade" replaces the binary,
> not your configuration.

Three things worth knowing up front:

- **Don't edit `*.conf.example` in place.** They are dpkg conffiles, so an upgrade will
  ask you "keep your version or take the new one". Copy them (`cp server.conf.example
  server.conf`) and edit the copy — then upgrades stay silent.
- **`postinst` runs `chown -R qeli:qeli /etc/qeli` on every install.** Contents are
  untouched, ownership is not. If you deliberately set different permissions, re-check
  them after an upgrade.
- **`apt remove` also runs `systemctl disable`.** After reinstalling you must re-enable
  autostart: `systemctl enable --now qeli`. And `apt purge` **leaves `/etc/qeli` behind**
  (the package has no `postrm`) — keys and password hashes stay on disk; remove them by
  hand if you don't want that.

### 3.2. Docker

The image is not upgraded in place — you change the tag and recreate the container. State
lives in the `/etc/qeli` volume, so configs, users and the key survive recreation:

```bash
docker compose -f release/docker/docker-compose.yml pull
docker compose -f release/docker/docker-compose.yml up -d
```

To roll back, put the previous image tag back in `docker-compose.yml` and `up -d` again.

> **`update-qeli-server.sh` is not for Docker.** It looks for a container named exactly
> `qeli`, while compose creates `qeli-server` — so on a compose deployment its Docker
> branch never fires at all. And even when it does fire it runs `docker restart` on the
> **existing** container, which keeps running the old image. Upgrade with
> `docker compose pull && up -d`.

> **The client role in Docker needs `dns = off`.** `/etc/resolv.conf` is a bind mount in
> the container, so the default `dns = tunnel` fails with EBUSY and reconnect-loops. The
> entrypoint warns about this at startup.
Details and caveats — [release/docker/README.md](../../release/docker/README.md).

### 3.3. Version compatibility across an upgrade

There is **no version negotiation** between client and server — no minimum supported
version, no refusal by version number. Compatibility is decided purely by the parameters
in [§1](#1-what-must-match-between-client-and-server). Practical consequence: upgrade the
**server first**, clients as you can; what breaks you is never the version number but a
changed default (as happened with `bind_static` in 0.7.1, and with `handrolled` later).

Before upgrading, read your version's section in [CHANGELOG.md](../../CHANGELOG.md) — a
changed default is always called out there explicitly.

---

## 4. What to back up

You can take a backup from the panel (**Backup** → download the archive) or by hand. The
minimum set, **without which recovery is impossible**:

| What | Default path | In the panel archive | Why it matters |
|---|---|---|---|
| **Profile identity key** | `/etc/qeli/identity/<profile>.key` (0600, created on first start) | yes | **Not recoverable.** Lose it and the server silently generates a new one at startup — **every** pinning client then gets `SERVER KEY MISMATCH`. The key is **per profile** |
| Server config | `/etc/qeli/server.conf` | yes | Profiles, ports, modes, REALITY `short_ids`, the panel's `password_hash` |
| Users | `/etc/qeli/users.conf` | yes | Logins, argon2 hashes, limits, ACLs, static IPs |
| Panel TLS cert and key | `/etc/qeli/web-tls-{cert,key}.pem` | yes | Otherwise browsers start complaining about a self-signed cert again |
| Client links | `/etc/qeli/client-links/` | yes | Ready `qeli://` strings and **plaintext passwords** — treat as a secret |
| **Panel session key** | `/var/lib/qeli/.session_key` | **NO** | Under systemd (`StateDirectory=qeli`) it lives **outside** `/etc/qeli`. Losing it is not fatal — it just logs everyone out — but the panel archive does not contain it |
| **Client TOFU pins** | `/var/lib/qeli/known_hosts` | **NO** | Only on machines where qeli runs as a client |

> **The panel archive covers `/etc/qeli` only.** Nothing under `/var/lib/qeli` is included.
> Taking a backup by hand? Take both directories.

```bash
sudo systemctl stop qeli
sudo tar czf qeli-backup-$(date +%F).tar.gz -C / etc/qeli var/lib/qeli
sudo systemctl start qeli
```

Two implementation details worth knowing:

- The panel **refuses** to hand you an archive if the identity keys turned out to be
  unreadable (the panel runs as the `qeli` user, and `tar --ignore-failed-read` would
  silently skip them). Instead of a broken archive you get an error telling you to fix the
  permissions (`chown -R qeli:qeli /etc/qeli/identity`) or take the backup as root. This is
  exactly the "we had backups but couldn't restore" case, closed.
- **Restore snapshots the current state first** to `/etc/qeli/.pre-restore-<ts>.tgz` (0600,
  newest 5 kept), so a bad restore is reversible. Those snapshots are excluded from new
  archives. A restore needs a **manual restart** to take effect.

> The archive contains **the key, the password hashes, and client passwords in plaintext**.
> Treat it as a secret: not in shared cloud storage, not in a repository.

**Test the restore before you need it**, not during an outage: unpack the archive on a
spare machine, start the server, connect with a pinning client. Only that proves the
identity key was really saved.

---

## 5. Firewall: what to open

The minimum is **the port of each enabled profile** (`bind.port`, with the right protocol)
and, if you need the panel from outside, its port.

| What | Default port | Protocol | Open it |
|---|---|---|---|
| VPN profile | `443` | per `bind.transport` — **TCP or UDP** | always |
| Extra profiles | 8443–8450 in the multiprofile template | TCP/UDP per profile | if enabled |
| Web panel | `8080` | TCP | **only if** you need it from outside |

Caveats that actually bite:

- **A UDP profile needs a UDP rule.** An open TCP/443 will not pass `udp-quic` on 443 —
  those are different rules in a cloud security group.
- **You do not need to open DNS.** The qeli resolver runs **inside** the tunnel.
- **Prefer not to publish the panel.** Safer to leave `bind = 127.0.0.1` and reach it over
  an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 root@server`. If you do publish it,
  `password_hash` is mandatory (a public bind refuses to start without one) and
  `allowed_ips` is strongly advised. Note that `install-reality-server.sh` **enables the
  panel on `0.0.0.0:8080` for you** — see §2 of GETTING-STARTED.
- **qeli installs the tunnel's own rules** when the profile has `routing.nat.enabled`:
  `ip_forward`, MASQUERADE, `FORWARD … ACCEPT` and the MSS clamp, tagged
  `qeli-nat:<profile>` and removed on a clean stop. Don't duplicate them by hand — details
  and the one exception are in [CONFIG.md](CONFIG.md), "Server OS tuning".
- **iptables-nft vs legacy.** qeli drives the `iptables` CLI **only** (never `nft`, never
  `ufw`) and verifies each rule by re-reading it (`-C`) instead of trusting the exit code —
  which lies under the nft wrapper. Rules are split into essential (MASQUERADE and the two
  MSS clamps: on failure the partial set is rolled back and the profile refuses to start)
  and best-effort (`FORWARD … ACCEPT`: on failure, a warning only). If you see
  `FORWARD ACCEPT rules could not be applied (host has a mixed legacy/nft filter table)`,
  egress still works while the FORWARD policy is `ACCEPT`; with `DROP` you must permit the
  forwarding yourself.
- **OpenWrt** has its own firewall (fw4/nftables): the package creates a `qeli` zone and a
  `lan → qeli` forwarding rule **once, at install time**. That is deliberate — fw4 flushes
  raw iptables rules on `/etc/init.d/firewall reload`. The side effect: the zone is bound
  to the device name as it was at install, so **changing `qeli.main.dev` later leaves the
  zone pointing at the old name**. See [qeli-openwrt/README.md](../../qeli-openwrt/README.md).

To see what qeli installed:

```bash
sudo iptables-save | grep qeli-nat
```

---

## 6. Silent configuration traps

These settings raise no error — they just don't do what you expect. The server warns about
them in the log **at startup**, so read the first lines of `journalctl -u qeli` after
editing a config.

| Setting | When it does nothing | What the log says |
|---|---|---|
| `obf.awg.*` (junk) | on a TCP `fake-tls` / `reality-tls` profile | `obf.awg.enabled has no effect on a TCP '<mode>' profile` — junk is only sent on TCP `obfs` and on any UDP mode |
| `obf.multipath.*` | on a UDP transport | `has no effect on a UDP transport` — stream bonding is TCP-only; a UDP session is capped at one stream |
| `web.secure_cookie` | on a plain-HTTP panel | A `Secure` cookie is never sent over HTTP — you simply cannot log in |
| `web.allowed_origins` unset | panel behind a proxy / on a domain | The page loads, but every POST returns 403 (Origin-based CSRF) |
| `[profiles.performance]` section deleted | always | Serde fills an absent section with **zeros**, not per-field defaults: `handshake_timeout = 0` and `max_clients = 0` reject everyone. This one is caught at startup with an explicit message |

Separately: **a misspelled key name is not logged at all** — see
[§2](#2-checking-a-config-before-you-start).
