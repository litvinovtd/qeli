# Qeli — operations: compatibility, upgrades, rollback, backup

> **Documentation status:** current development tree **0.8.3**; planned full-IPv6 release **0.8.3**;
> package version covered by this guide **0.8.3**.
> `qeli --version` reports the version of the binary actually installed.
> See [GitHub Releases](https://github.com/litvinovtd/qeli/releases) for package availability and publication status.
> Links to this version's files work after its publication.

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
| **Wire mode** | `obf.mode` | `mode` | Normally they match. Current Reality uses `reality-tls` on both sides; a new server temporarily accepts the legacy server spelling/carrier for migration. Other mismatches end in handshake timeout |
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
   an explicit zero in `perf.connection.*`, and so on), so its verdict matches a real start.
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

The repo root ships [`update-qeli-server.sh`](../../../update-qeli-server.sh), which does
the right things by itself:

```bash
sudo ./update-qeli-server.sh
```

The updater holds a transaction lock in root-owned0700 `/run/qeli-updater`. A second updater refuses while the first is running. It selects the host architecture's release package, checks SHA256SUMS, validates Package/Version/Architecture and installs it. A restart failure, missing/zero MainPID or changed MainPID during the2+3-second observation enters rollback; an active stable supervisor does not establish VPN readiness.

It saves the old binary and uses the previous package from root-owned0700 `/var/cache/qeli` for rollback, matching the installed Debian version including revision. A package downgrade must report the expected configured dpkg identity and pass the same health check. If no usable old package exists or downgrade fails, binary-only restoration is the last resort: it warns that dpkg may still record the newer version. Recovery returns nonzero because the update failed. Reinstall the previous package to reconcile metadata; do not treat a restored binary as a complete downgrade.

`QELI_FORCE=1` reinstalls even the current version. For an offline package:

```bash
sudo env QELI_DEB=/path/qeli.deb ./update-qeli-server.sh
```

The local path must exist; a typo refuses instead of downloading. Local input skips release checksum/attestation lookup and needs neither curl nor jq; use a trusted package. Updater-owned downloads are cleaned on normal exit/failure/INT/TERM; the supplied local file stays. The service-owned legacy `/var/lib/qeli/packages` is preserved and ignored, never imported into the root rollback cache.

SHA256SUMS from the same release establish integrity against its metadata, not independent provenance. Set `QELI_VERIFY_ATTESTATION=1` to require `gh attestation verify` for a remote package; missing gh or failed verification aborts. Keep separate backups of configs/users/identity/client links before major upgrades: the updater preserves them but does not back them up. See [§4](#4-what-to-back-up) and [the scoped updater audit](../reports/audit-0.8.2/AUDIT-Q33-SERVER-UPDATER.md).

To verify a downloaded amd64 package before manual installation, use GitHub CLI against this repository. The filename below refers to the version covered by this guide; availability depends on publication. Failed verification means the package has not passed this provenance check.

```bash
gh attestation verify qeli_0.8.3_amd64.deb --repo litvinovtd/qeli
```

The 0.8.3 prerelease preserves its qualified candidate package without a new
release-build attestation. The command above is therefore expected to refuse
that package unless a matching attestation is separately published. Its
`SHA256SUMS` describes the integrity of the downloads. The source-side
[release certification](../../../release/certification/0.8.3.json) and
[native build provenance](../../../native-libs/PROVENANCE) record their respective
qualification scopes; they do not replace a GitHub build attestation.
Separate `PROVENANCE.json` and `QUALIFICATION.json` downloads are not included in
the final 0.8.3 asset set.
An installation requiring `QELI_VERIFY_ATTESTATION=1` must remain blocked when
the required attestation is unavailable.

For manual package rollback, keep a trusted old .deb and install it with `apt-get install --allow-downgrades`, then restart/check the service and inspect dpkg's installed version. Binary restoration alone is emergency recovery, with the metadata limitation above.

> **The package does not touch your configs.** The `.deb` only installs `*.conf.example`;
> your `/etc/qeli/server.conf`, `users.conf` and the identity key are not in the package
> at all, so there is nothing to overwrite them with. An "upgrade" replaces the binary,
> not your configuration.

Three things worth knowing up front:

- **Don't edit `*.conf.example` in place.** They are dpkg conffiles, so an upgrade will
  ask you "keep your version or take the new one". Copy them (`cp server.conf.example
  server.conf`) and edit the copy — then upgrades stay silent.
- **`postinst` repairs daemon-state ownership on every install, excluding `client-links` and `*.bak-*`.** Contents are
  untouched; the installer receipts directory stays root0700. If you deliberately set different permissions, re-check
  them after an upgrade.
- **`apt remove` also runs `systemctl disable`.** After reinstalling you must re-enable
  autostart: `systemctl enable --now qeli`. And `apt purge` **leaves `/etc/qeli` behind**
  (the package has no `postrm`) — keys and password hashes stay on disk; remove them by
  hand if you don't want that.

The package now rejects linked/non-directory state roots and linked/nonregular default users.conf before unpack; it leaves those paths for the administrator to repair. A new users.conf is empty0600; existing regular files retain their content and mode. On a booted systemd host, failure to apply the selected service user leaves the package half-configured; fix the reported cause and retry `sudo dpkg --configure qeli`. In a nonbooted chroot/container, an unconfirmed user change is warned and must be retried after boot. Removal refuses if the service cannot be stopped on a booted host; purge removes packaged examples but retains unmanaged config/users/identity. [Executed scope and limitations](../reports/audit-0.8.2/AUDIT-Q33-DEBIAN-LIFECYCLE.md).

With QELI_BIN, an explicit QELI_SRC must contain all eight examples, qeli.service and49-qeli.rules; missing files refuse rather than falling back to GitHub. These files are admitted in private staging before replacing the binary. Without QELI_SRC, the requested release payload is selected by host architecture and verified; QELI_VERIFY_ATTESTATION=1 also requires successful gh verification. Linked/nonregular state paths refuse; INT/TERM stop installation after cleanup. Subsequent publication is sequential, so final installation errors are not an automatic rollback. The dependency phase now skips apt when prerequisites are available; a local payload alone does not qualify the entire first installation as disconnected. [Executed scope](../reports/audit-0.8.2/AUDIT-Q33-BINARY-INSTALLER.md).

Installer dependency setup invokes apt only for missing prerequisites, then verifies commands/CA availability. For QELI_BIN+complete QELI_SRC or a local QELI_DEB, provide PUBLIC_HOST and preinstall OS/package dependencies to avoid dependency downloads; this stage check does not qualify the entire disconnected install. QELI_DEB is an absolute local .deb path, not a URL. Package=qeli, host architecture/all and exact installed status/version/architecture are required before config generation. QELI_VERIFY_ATTESTATION=1 requires successful gh verification for the Debian install path, including a local package. Failed install/repair is fatal, with no automatic package rollback. [Executed admission scope](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-ADMISSION.md).

Installer-generated links, summary and backups are private0600 and published through temporary files; existing kept links retain their bytes through a private copy. Linked/nonregular generated names refuse before dependency changes. Backups have a random suffix after the timestamp to avoid collisions. The web helper replaces its config atomically, preserving ownership and setting0600. This does not make the entire forced reconfiguration transactional.

If user/link creation fails, the old CONNECTION-STRINGS.txt remains and a root0600 `/etc/qeli/client-links/INSTALL-PENDING-<timestamp>-<suffix>` journal retains generated passwords, recorded before add-client. Read it as root, compare its users with users.conf, and use the recovered passwords/links for the affected client configurations; a pending entry may not have created an account. Do not blindly repeat add-client for an existing user. Accounts/individual links may already change; there is no automatic rollback. After successful summary publication the current journal is removed; journals from earlier failures remain until you verify recovery and remove them. These are plaintext secrets; include them in protected backups and remove obsolete copies after recovery. Power-loss durability is not qualified. [Audit scope](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-SECRETS.md).

Installer validates explicit endpoint/panel options and nonempty boolean opt-ins (0/1) before dependency/payload changes. Auto-host is checked before config/identity, but dependencies/binary may already change. Complete INI is prepared privately beside server.conf; CLI/web/final check-config use that stage. After validation and the selected service-user helper, the old live config is backed up and replaced by rename, then restarted. Before-publication errors retain the old config; fresh failed installation publishes no partial config. Users/identity/links/tuning/dependencies/binary/drop-in can already change; use the password recovery journal if present. Restart/health failure after publication does not restore the old config automatically. The installer explicitly applies QELI_RUN_AS, including the default qeli choice, after validation; qeli removes a previous root override while preserving installer receipts/backups. [Audit and limits](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CONFIG.md).

Version-number discovery in installer/updater uses `qeli --version`, also supported by older installations. Current `qeli version --check` remains an opt-in update query. Actual CLI writers create a sibling lock for the temporary INI; installer removes that unique stage lock after writers finish, while keeping the live config/users locks. Three profile installation flows have passed with real CLI parsing/keys/Argon2/links; service startup/kernel/VPN remained outside that earlier qualification; the default-unit ownership/drop-in transition is covered by the [subsequent service-user audit](../reports/audit-0.8.2/AUDIT-Q33-SERVICE-USER.md). [Evidence and limits](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CLI.md).

### Service reload and root-owned configuration

`systemctl reload qeli` sends SIGHUP to the supervisor, which validates and reloads users/authentication and asks the worker to reload without replacing either process. Invalid INI/users are rejected without publishing new authentication state. Profile/listener/TUN and panel startup settings still need a full service restart. SIGHUP preserves the panel login lockout tracker. [Systemd audit](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).

Root mode can read qeli-owned private state, but panel config publication still requires a trusted file owned by root or the running user, without group/other write permissions and without a symlink. Root will therefore refuse a panel save of a qeli-owned INI. Review the configuration as administrator, then use `sudo chown root:root /etc/qeli/server.conf` and `sudo chmod 600 /etc/qeli/server.conf` if root is the intended service account. Do not change ownership of password receipts to qeli. To refresh an older root drop-in, rerun `sudo qeli set-service-user root` with the current binary and restart the service. This grants three filesystem capabilities, not an unrestricted capability set. [Systemd audit](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).


### 3.2. Docker

The image is not upgraded in place — you change the tag and recreate the container. State
lives in the `/etc/qeli` volume, so configs, users and the key survive recreation:

**Check which image your `docker-compose.yml` references first** — it decides the command.
The bundled compose uses `image: qeli:latest`, which is **built locally**, not pulled from a
registry. For it `docker compose pull` is useless (and would go asking Docker Hub for an
unrelated image); rebuild instead:

```bash
docker buildx build -f release/docker/Dockerfile -t qeli:latest --load .
docker compose -f release/docker/docker-compose.yml up -d
```

If you switched `image:` to the published `ghcr.io/litvinovtd/qeli:latest`, the usual path
works:

```bash
docker compose -f release/docker/docker-compose.yml pull
docker compose -f release/docker/docker-compose.yml up -d
```

To roll back, put the previous image tag back in `docker-compose.yml` and `up -d` again.

For 0.8.3 Beta, select `ghcr.io/litvinovtd/qeli:0.8.3` only after the Docker image
has been published successfully. Publishing the GitHub Release files does not mean
the multi-arch image build has finished. Automatic `latest` promotion is reserved
for a published stable release, not a Beta; updating a client does not require a
manual `latest` promotion. Select the container tag in `image:`; it is not inferred
from the version of an installed `.deb` or APK.
See [release/docker/README.md](../../../release/docker/README.md) for details.

> **`update-qeli-server.sh` does handle Docker — with one caveat.** It finds the container
> under either name, `qeli` or `qeli-server` (the latter is what the bundled compose
> creates), pulls **the image the container actually runs**, and recreates it with
> `docker compose up -d` — a plain `docker restart` would keep the old image. But when that
> image is local (`qeli:latest`, no registry) there is nothing to pull, so the script
> **stops with an explanation** instead of reporting an update that never happened. Rebuild
> with the command above in that case.

> **The client role in Docker needs `dns = off`.** `/etc/resolv.conf` is a bind mount in
> the container, so the default `dns = tunnel` fails with EBUSY and reconnect-loops. The
> entrypoint warns about this at startup.
Details and caveats — [release/docker/README.md](../../../release/docker/README.md).

### 3.3. Version compatibility across an upgrade

There is **no version negotiation** between client and server — no minimum supported
version, no refusal by version number. Compatibility is decided purely by the parameters
in [§1](#1-what-must-match-between-client-and-server). Practical consequence: upgrade the
**server first**, clients as you can; what breaks you is never the version number but a
changed default (as happened with `bind_static` in 0.7.1, and with `handrolled` later).

For the 0.8.0 Reality/H2 transition this order is mandatory: the new server accepts both the
legacy Reality carrier and H2, but the new client is H2-only and does not downgrade. An
intermediate reverse proxy/load balancer must use transparent TCP pass-through; terminating TLS,
converting H2 or routing HTTP before qeli breaks the discriminator and carrier.

Before upgrading, read your version's section in [CHANGELOG.md](../../../CHANGELOG.md) — a
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
| **`password_enc` decryption key** | `/var/lib/qeli/panel-secret.key` | **NO** | Deliberately separated from the encrypted passwords in `users.conf`. Without it Argon2 authentication still works, but existing passwords cannot be re-issued in a link/QR without a reset |
| Panel TLS cert and key | `/etc/qeli/web-tls-{cert,key}.pem` | yes | Otherwise browsers start complaining about a self-signed cert again |
| Client links | `/etc/qeli/client-links/` | yes | Ready `qeli://` strings and **plaintext passwords** — treat as a secret |
| **Panel session key** | `/var/lib/qeli/session.key` | **NO** | Under systemd (`StateDirectory=qeli`) it lives **outside** `/etc/qeli`. Losing it is not fatal — it just logs everyone out — but the panel archive does not contain it. Without `StateDirectory`, `/etc/qeli/.session_key` is used |
| **Client TOFU pins** | `/var/lib/qeli/known_hosts` | **NO** | Only on machines where qeli runs as a client |

> **The panel archive covers `/etc/qeli` only.** Nothing under `/var/lib/qeli` is included.
> In particular, it contains `password_enc` from `users.conf` but deliberately excludes
> `/var/lib/qeli/panel-secret.key`, which decrypts those values. For a complete manual
> backup, take both directories.

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

Restore refuses introduced or changed `routing.post_up/post_down` commands and replacement of files referenced by existing hooks. The check accounts for `..`, quotes, spaces and symlinks, including outside aliases into `/etc/qeli`. A literal `/etc/qeli/$SCRIPT` or `/etc/qeli/*.sh` cannot identify the top-level entry: restore is refused before publication. A pattern inside known `/etc/qeli/scripts/` protects the entire `scripts/` entry.

Overlay restore may remove a command or profile from INI; the ready generation retains its original state. Protection also includes commands retained from startup and later worker generations until supervisor exit. Clearing a hook from INI through restore does not allow a second archive to replace its script. Exact restore refuses deleting these files/directories before publication. Releasing old references requires a full supervisor restart after correcting configuration on the server; a worker-only restart does not reset the set.

Keep executable hooks and their dependencies outside `/etc/qeli`, for example under `/opt/site/`, and update them on the server separately from panel archives. Static inspection does not execute the shell and cannot discover paths built entirely from variables, runtime `cd`, or inside an external script. It is not a sandbox for arbitrary hook commands. Files without executable bits are protected too: `sh file.txt` can execute their contents.

> The panel archive contains private identity/TLS keys, password hashes, `password_enc`,
> and client links with plaintext passwords. A complete manual archive additionally contains
> `panel-secret.key` and the remaining state under `/var/lib/qeli`. Treat both forms as
> secrets: encrypted storage, not a shared cloud drive and not a repository.

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
| Extra profiles | 8443–8451 in the multiprofile template | TCP/UDP per profile | if enabled |
| Web panel | `8080` | TCP | **only if** you need it from outside |

Caveats that actually bite:

- **A UDP profile needs a UDP rule.** An open TCP/443 will not pass `udp-quic` on 443 —
  those are different rules in a cloud security group.
- **You do not need to open DNS.** The qeli resolver runs **inside** the tunnel.
- **Prefer not to publish the panel.** Safer to leave `bind = 127.0.0.1` and reach it over
  an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 root@server`. If you do publish it,
  `password_hash` is mandatory (a public bind refuses to start without one) and
  `allowed_ips` is strongly advised. `install-qeli-server.sh` leaves the panel **on
  loopback** and publishes it only when `QELI_PANEL_PUBLIC=1` is given together with
  `QELI_PANEL_ALLOWED_IPS`; a public bind without a source allowlist is refused — see §2
  of GETTING-STARTED.
- **qeli installs the tunnel's own rules** when the profile has `routing.nat.enabled`:
  `ip_forward`, MASQUERADE, `FORWARD … ACCEPT` and the MSS clamp, tagged
  `qeli-nat:<profile>` and removed on a clean stop. Don't duplicate them by hand — details
  and the one exception are in [CONFIG.md](CONFIG.md), "Server OS tuning".
- **iptables-nft vs legacy.** qeli drives the `iptables` CLI **only** (never `nft`, never
  `ufw`) and verifies each rule by re-reading it (`-C`) instead of trusting the exit code —
  which lies under the nft wrapper. Rules are split into essential (MASQUERADE and the two
  MSS clamps: on failure the partial set is rolled back and the profile refuses to start)
  and conditional (`FORWARD … ACCEPT`: omission is safe only for an otherwise empty chain
  whose built-in policy is `ACCEPT`). If you see
  `FORWARD ACCEPT rules could not be applied (host has a mixed legacy/nft filter table)`,
  egress continues only after qeli verifies that empty/`ACCEPT` state; `DROP`, any explicit
  rule/jump, or an unreadable chain fails profile startup.
- **OpenWrt** has its own firewall (fw4/nftables): the package creates a `qeli` zone and a
  `lan → qeli` forwarding rule **once, at install time**. That is deliberate — fw4 flushes
  raw iptables rules on `/etc/init.d/firewall reload`. The side effect: the zone is bound
  to the device name as it was at install, so **changing `qeli.main.dev` later leaves the
  zone pointing at the old name**. See [qeli-openwrt/README.md](../../../qeli-openwrt/README.md).

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
| `perf.connection.handshake_timeout_secs = 0` or `perf.connection.max_clients = 0` | always | An explicit zero has no valid timeout/limit semantics and is rejected during validation. Remove the key to use its baseline default, or set a positive value |

Separately: **a misspelled key name is not logged at all** — see
[§2](#2-checking-a-config-before-you-start).

## Local control socket

The worker listens on `/var/run/qeli/control.sock`. `QELI_CONTROL_SOCKET` selects another
server path and the CLI default; an explicit `--socket` selects the command's path.
This is an administrative API protected by OS permissions. Its JSON envelopes are not
a configuration format: Qeli configuration remains INI.

One network namespace admits one server worker with all its profiles. Before
preflight, accounting or firewall recovery it holds the `qeli.server.worker` kernel
lease (an abstract Unix socket); different control/state directories or mount/PID
namespaces cannot bypass it. It remains held during `post_down`. An early error
before the first network mutation releases it; after work begins, forced cancellation
or incomplete cleanup retains the reservation until process exit, preventing another
worker from overlapping unfinished tasks. A successful ordinary stop releases it
after the other resources. SIGKILL releases the kernel socket; the next start runs
normal recovery. Multiple workers require separate network namespaces and
config/state/control paths; additional profiles within one worker do not. The normal
supervisor + worker pair is supported. Old binaries do not participate: stop the
previous worker before upgrading.
[Ownership](../reports/audit-0.8.2/AUDIT-Q14-WORKER-NETWORK-LEASE.md) ·
[forced cancellation](../reports/audit-0.8.2/AUDIT-Q25-SERVER-FORCED-DROP-LEASE.md).

The socket directory must belong to the worker user, have mode `0700`, and not be a
symlink. Qeli creates new directories privately and never chmods existing directories.
Do not place the socket directly in shared `/tmp`: use, for example,
`/tmp/qeli-<uid>/control.sock`. Ancestors must belong to root/the worker user and deny
other users write access; shared sticky `/tmp` is allowed. The standard `/var/run` →
`/run` symlink is supported. The packaged systemd unit sets `RuntimeDirectoryMode=0700`;
a custom unit must provide the same mode and owner. When updating only the binary,
check the runtime directory settings in the existing unit.

The socket itself is `0600`. A neighboring `control.sock.lock` holds an interprocess
lease until the worker's control handlers and profiles finish. Do not delete a live
process's lock file. A second worker refuses an occupied path; regular files and
symlinks are preserved. Crash leftovers are reclaimed only after ownership checks
and `ECONNREFUSED` from a nonblocking connect. Normal shutdown removes only this
worker's socket inode; the lock file remains for subsequent starts.

The protocol is one JSON line per connection, up to 64 KiB per request and 8 MiB per
response excluding LF/CRLF. Overflow is an error, never a truncated message. Request
reads, CLI connect, and writes have a 5 s deadline; CLI response reads have 15 s.
At most 16 connections are handled concurrently. Shutdown closes admission and drains
accepted handlers before profile teardown. CLI workers use one 45 s cleanup budget;
the supervisor retains its 60 s grace. Forced termination does not confirm command
or hook completion; see the shutdown section below.


## Server firewall recovery

`server-firewall.state` in `STATE_DIRECTORY` (default `/var/lib/qeli`) saves exact
NAT/FORWARD/MSS/DNS INPUT/REDIRECT rules before invoking commands. It is internal
recovery state; user configuration remains INI. `SO_NETNS_COOKIE` support and trusted
state storage are required: no symlinks, foreign write access or unsafe owners.

After SIGKILL, restart with the original state directory, network namespace and
iptables backend. Deleted INI profiles are also cleaned up. Rules recorded by this
version recover without `-S`, through exact `-C` checks and `-D` deletion. Incomplete
cleanup aborts startup and retains unresolved entries. Fix the cause and retry;
do not delete the journal or `.lock`. An empty journal and stable `.lock` after a
clean stop are expected.

For `iptables backend changed`, restore the original nft/legacy choice for that
family. Recovery never switches the backend automatically or treats absence in a
different backend as cleanup success. Corruption, unsupported versions and namespace
context loss require investigation; deleting the journal discards rule evidence.
Changing `STATE_DIRECTORY` does not migrate state.

Limits are 8 MiB, 32768 rules and 64 namespace groups. Foreign groups remain untouched;
valid records from a previous boot no longer supply commands. Historical rules from
older binaries without journals still depend on tagged sweeps and available listing.
Stop the old worker before upgrading.
[Checks and limits](../reports/audit-0.8.2/AUDIT-Q14-FIREWALL-JOURNAL.md).

## Client DNS recovery

Managed DNS on Linux also requires `SO_NETNS_COOKIE` and a trusted state directory without symlinks or group/world write: `$STATE_DIRECTORY`, otherwise `/var/lib/qeli`. DNS lease markers share this root with route, sysctl and server firewall journals. Selecting another path does not automatically copy or recover existing state. Stop the old client cleanly before upgrading; retained v1 markers require administrator recovery when they match the new link. [V2 format and recovery](TROUBLESHOOTING.md#650-linux-dns-lease-ownership-and-recovery-markers).

Legacy global `dns-backup.json`/`dns-holders` are not restored automatically: startup preserves them and requires administrator recovery even with `dns = off`/`system`. Stop the old client cleanly before upgrading. [Procedure §6.20](TROUBLESHOOTING.md#620-linux-legacy-resolver-recovery-failed-backup-kept).

## Client kill-switch recovery

Reinstalling a Linux kill-switch over prior protection uses temporary DROP rules `qeli-ks-rebuild:<tun>`. Failure or SIGKILL retains them; successful retry retires them after both required families are ready. Guards may block DNS/loopback until replacement is ready; `allow_ipv*_leak` cannot bypass recovery failure. For manual removal after stopping the owner, inspect guards separately from `QELI_KS_<tun>`. [Procedure §6.79](TROUBLESHOOTING.md#679-linux-kill-switch-rebuild-guard-remains-after-failure).

## Linux: physical routes changed by an administrator

The client removes its physical bypass or blackhole only while the observed entry
matches its parameters and implicit defaults. A replacement with `proto static`, a
different metric/source/scope or additional attributes is preserved at stop. The log
`owned route changed; preserving replacement` means Qeli relinquished its previous
ownership. Inspect that remaining entry in the original network namespace; it now
requires an administrator decision. A suitable route present before connection is
borrowed without destination delete authority.

The owned managed TUN still has its interface routes flushed during teardown. The
check is not atomic with the next command and cannot distinguish another root's
identical route. Confirmed physical entries are persisted for the next start after
SIGKILL; uncertain intents require manual investigation. Do not flush the entire route
table; verify the origin of an exact entry before removing it manually.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-ATTRIBUTES.md).

## Client physical route recovery

The Linux managed-TUN client persists physical bypass/exclude and blackhole routes in
`$STATE_DIRECTORY/client-routes.state` (default `/var/lib/qeli/client-routes.state`). This requires `SO_NETNS_COOKIE` and a trusted
state directory writable by the process owner, without symlinks or group/world write.
This also applies with `dns = off`/`system`. DNS, sysctl and firewall journals share this root.
All clients sharing a network must see the same directory and `client-routes.state.lock`.
Configuration remains INI; the journal is internal recovery state.

OpenWrt and both Keenetic launchers resolve the firmware-owned `/var` alias before
appending `/lib/qeli` (`/tmp/lib/qeli` when `/var -> /tmp`). Only this system alias is
resolved; the core still rejects links and unsafe owners/modes inside the resulting
path. The physical directory is unchanged, so pending journals remain visible.
For a manual router launch, resolve successfully before exporting the path:

```sh
var_root="$(readlink -f /var)" || exit 1
export STATE_DIRECTORY="${var_root%/}/lib/qeli"
```

Do not move to an unrelated empty state directory to bypass recovery. Before changing
a custom root, stop all clients/server workers and complete recovery using the old root.
No journal import, deletion or permission repair is performed automatically.

Stop the old client cleanly before upgrading. After SIGKILL, restart with the original
`dev`, network namespace and state directory. Recovery precedes DNS resolution/handshake.
Only confirmed entries with unchanged attributes are removed; operator replacements
remain. Foreign namespace/TUN groups are not cleaned. A live/persistent TUN blocks
recovery; Qeli does not delete it by name.

An uncertain intent gives no permission to delete a matching route. Incomplete recovery
aborts startup and retains records. Repair the cause and retry; follow
[§6.81](TROUBLESHOOTING.md#681-linux-physical-route-journal-recovery) for manual investigation.
Do not delete the journal or lock to bypass refusal. Empty state and a stable lock after
clean stop are normal. The journal does not adopt leftovers of older unjournaled versions.
Limits are 8 MiB, 128 groups and 8192 records. Attach does not manage these routes.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-JOURNAL.md).

## Persistent TUN/TAP after a client crash

Qeli does not delete or adopt a surviving device by matching its name. Stop its owners,
verify the orphan's origin, retain evidence, manually remove only that device if
appropriate, and restart in the original context. Retain the kill-switch and journals
until recovery completes. Procedure and limits:
[§6.82](TROUBLESHOOTING.md#682-linux-persistent-tuntap-survives-client-termination).

## Coexistence with nftables and firewalld

Preserve each family's original backend during crash recovery. Native rules can
prevent confirmation of absence even after successful deletion; Qeli retains those
records until inspection is repaired. A firewalld reload does not replace Qeli journal
recovery. Rule preservation and actual traffic through zones/policies are separate
validation steps.
[Troubleshooting §6.83](TROUBLESHOOTING.md#683-linux-mixed-nftlegacyfirewalld-recovery).

A Qeli iptables/ip6tables permit does not override DROP in another nftables/firewalld
chain. The administrator configures zones/policies for WAN/TUN, the VPN listener,
forwarding and DNS. In `manual`, they also provide IPv6 forwarding, INPUT and
port-53 DNS delivery when the DNS proxy is enabled. Qeli preserves foreign
restrictions on stop/restart; change a restriction through its owner. Four mixed
backend pairs with four IPv6 profiles and a public policy passed reload/restart
and real permitted/denied IPv4/IPv6 control-port probes; this does not guarantee
traffic through every administrator policy.
[Validation scope](../plans/AUDIT-DEBT.md).

Keep both families' original backend until client recovery/stop finishes. Exact legacy-table
advice is permitted alongside a recognized missing-rule/chain diagnostic; unknown errors
are not ignored. Do not flush operator tables to silence that advice.
[Client diagnostics §6.84](TROUBLESHOOTING.md#684-linux-client-rejects-a-legacy-table-warning).

## Stopping during DNS delays

The shared client resolver bounds waiting and the number of DNS/NSS calls. SIGTERM/SIGINT
interrupt Linux waiting during kill-switch setup/refresh and initial connection; network
cleanup remains a verified operation. Four stuck system calls occupy all slots until they
finish; late answers do not initiate network setup.
[Troubleshooting §6.85](TROUBLESHOOTING.md#685-client-dns-delay-and-shutdown).

## Resolver files before installing protection

Linux kill-switch reads `/run/systemd/resolve/resolv.conf` and `/etc/resolv.conf` in
advance, using one snapshot for IPv4/IPv6. Reading shares the four DNS/NSS slots and
the setup deadline; this wait still applies with a numeric server address. Files must
be regular and at most 64 KiB; the list is limited to 64 distinct entries. Invalid or
unreadable files grant no DNS allowances; exceeding the merged list limit aborts setup.
The `nameserver` token must be separate, with whitespace before a trailing comment.
Scoped IPv6 with `%interface`/`%index` grants no unrestricted interface-independent
allowance and does not discard other valid entries. Later DNS changes do not refresh
firewall rules automatically. [Resolver-file reads](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-FILES.md).

[§6.86](TROUBLESHOOTING.md#686-linux-resolver-files-and-kill-switch-dns-allowances).

## Stopping while NetworkPlan is being applied

Linux applies NetworkPlan on a separate thread and retains TUN/routes/DNS ownership
until the operation and any rollback finish. Ordinary SIGTERM/SIGINT is processed
while waiting. Started system work is not interrupted: the client waits for completion
and rolls back an unadopted result. State stays `awaiting_network` until successful ACK;
cancellation before ACK does not run `post_up`. Cleanup failure prevents a successful restart.

Sending a signal alone does not make a TUN ready for reuse. Wait for process exit and
verify cleanup. Forcibly dropping a future may synchronously wait for the worker join;
there is no single hard shutdown deadline yet.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-TASK.md).

## Stopping an established Linux tunnel

TCP and UDP share this order: stop connection tasks → restore DNS → stop and join TUN
packet workers → clean owned routes and forwarding → close the original TUN descriptor.
DNS/routes/forwarding run on a separate thread; the client waits for completion.
Failure of one stage does not skip the remaining cleanup attempts.

On `network resource cleanup reported failure`, automatic reconnect is prohibited and
an enabled kill-switch is retained. A successful guard retry does not turn the initial
failure into successful exit. Retain logs and investigate before a new explicit start.
Forced Drop may synchronously await completion; there is still no single hard shutdown
deadline. [Design and checks](../reports/audit-0.8.2/AUDIT-Q25-TUN-TEARDOWN.md).

## Stopping during kill-switch setup, refresh or removal

Before firewall mutation, stop can cancel DNS/read-only preparation. Once admitted,
the client awaits the operation's actual result. Success after stop takes setup/refresh
to ordinary cleanup without a new connection; an error remains an error requiring investigation.
Forced future destruction also joins the worker but can block the calling thread.

`firewall unhook failed; chain retained` means removal of all hooks into the named chain
has not been confirmed. Qeli preserves its contents, including DROP, and returns an error.
Do not manually flush that chain before inspecting its hooks. Another firewall family
may already have been removed; one retained chain does not establish host-wide protection.
After resolving the cause, a new explicit start performs ordinary recovery.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-FIREWALL-TASK.md).

## UDP servers with multiple local addresses

With wildcard `bind.address = 0.0.0.0` or `::`, replies use the local address that received
the client packet. This covers handshake, data and control messages without a new INI
option. Clients using different addresses cannot change each other's source. If the OS
does not provide valid pktinfo, the server does not substitute another address.
[Checks and limits](../reports/audit-0.8.2/AUDIT-Q15-UDP-LOCAL-ADDRESS.md).

## Stopping during Linux client startup recovery

Before connecting, Qeli reserves its network lease, recovers owned physical routes and
checks DNS markers on a separate joined thread. SIGTERM/SIGINT does not interrupt
admitted recovery: the client retains the lease and awaits the result. Success after
stop exits without a new connection; errors retain `failed`. `dev_attach = true` skips
physical-route recovery but still checks DNS. Startup does not change a live resolver
solely from a stored marker.

Wait for client exit and inspect the final error before restarting. The 15-second route
operation budget is not a single hard shutdown deadline; forced Drop may synchronously
join the worker. [Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-STARTUP-RECOVERY-TASK.md).

## Linux TUN packet-worker startup failure

`TUN packet pump startup failed` means packet handling could not start after applying
the network plan. Qeli waits for partially started threads and owned-resource cleanup
on a joined worker, keeping neighboring async tasks responsive. A cleanup error retains
the kill-switch; inspect logs before another explicit start. Stop does not hide that
cleanup failure.

Successful `post_up` confirms NetworkPlan application, not completed pump startup.
Failure to create a cleanup worker or forced Drop can still cause synchronous fallback
waiting. [Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-PUMP-START.md).

## Linux client diagnostics on slow storage

With `QELI_CLIENT_STATUS` set, one dedicated thread writes status. While a write is
busy, only the latest pending snapshot is retained; intermediate states may never
appear in the file. Schema 1 and `0600` permissions are unchanged.

Ordinary exit awaits terminal publication after stopping the sampler. Slow fsync keeps
neighboring async tasks responsive but can delay process exit; there is no hard overall
deadline. Diagnostics failures do not change the VPN result. If a write fails, the file
may be stale: inspect exit status and logs. [Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md).

## TCP client queue drops

The `stats.tcp_uplink_drops` object in the `QELI_CLIENT_STATUS` diagnostic file
records losses while handing TUN packets to the TCP carrier. `pool_exhausted`
means refusal by the bounded pool, `queue_full` a full selected carrier queue,
`oversize` a packet larger than its slot, and `no_carrier` no live carrier after
closed queues are removed. `total` is derived from that snapshot's reason values.
Successful retry from a closed carrier to a live one is not a packet drop; a full
live queue preserves flow pinning and records one loss.

These counters live in the common TCP data plane and are published here through
Linux status schema 1. The C ABI layout and GUI statistics are not extended.
Check `updated_at_ms` freshness and `generation`: the sampler runs every two
seconds, and slow storage can delay publication. These counters cover the hand-off
before encryption, not confirmed peer delivery. On this path, tx_packets/tx_bytes
count valid TUN packets observed before enqueue.

Zero values do not exclude TCP downlink-to-TUN losses, device write errors,
retransmissions or network loss. Server dropped and UDP RcvbufErrors measure
other locations. [Validation and limits](../reports/BENCHMARK.md).
<!-- normative-sync: manual-tcp-uplink-drops-v1 -->

## TCP losses at TUN handoff

Linux status `stats.tcp_downlink_drops` counts handoff failures after TCP record
receive/decryption: `pool_exhausted` is pool refusal for a reassembled mux packet,
`queue_full` is a full TUN queue, `disconnected` is a closed queue. `total` is
derived from the reasons in one snapshot. Full counts one packet and permits
continued processing; Disconnected counts the packet and stops the receive task.
Raw mode retains the received pooled buffer, with no separate slot acquisition
in this function. Mux counts reached handoff attempts per reassembled packet,
not an entire record. After Disconnected, remaining packets in the record are
no longer processed and are outside this counter. Empty, management, unsupported
packets and decode errors are also outside the handoff measurement.

After buffer acquisition, rx_packets/rx_bytes increase before enqueue; growth
does not establish device delivery. Mux pool refusal does not increase them.
Uplink/downlink counters are independent and reset with a fresh runtime generation;
check generation and updated_at_ms freshness, with a two-second sampler period.
C ABI layout and GUI stats are unchanged. These are not ACK/retransmission or
total network loss counters. Later OS write drops use the existing shared writer
counter udp_drops_tun_write; its historical name also covers TCP TUN writes.
[Validation and limits](../reports/BENCHMARK.md).
<!-- normative-sync: manual-tcp-downlink-drops-v1 -->

<a id="client-tun-tx-queue"></a>

## Client TUN queue size: applying and verifying

In a build supporting this setting, put `tun.tx_queue_len` under `[qeli]` in
the client INI (`1000` packets by default; `1..32767`, no auto mode), then
stop/start the client to reread the file. Do not restart the server for this local
setting. With `dev_attach=true`, remove the key: an external system owns the
queue and Qeli does not apply even its default `1000` to that interface.
[Syntax, compatibility and limits](CONFIG.md#client-tun-tx-queue).

In the client's namespace, inspect `ip link show dev vpn0` (`qlen`) and the log
`Client TUN TX queue length: <N> packets`; use the actual `dev` name.
Compare `ip -s -s link show dev vpn0` and `tc -s qdisc show dev vpn0` before/after
one window. TX here means kernel → Qeli reader, not physical NIC TX.
Compare the same ifindex: restarting an owned TUN recreates the interface and its
counters; an attached interface remains with its external owner.

These kernel drops are not `stats.tcp_uplink_drops`/`tcp_downlink_drops`:
the latter cover internal application handoff queues. Neither increasing TX drops
nor an empty queue at the end of a window proves `FULL_RING`, ACK delays or H2
window exhaustion by itself. A causal conclusion requires matched observations.
Do not confuse `tun.tx_queue_len` with the `tun.queues` count,
`perf.tun.read_buffer_size` or socket UDP auto-grow. A larger queue may reduce burst
loss while increasing RTT and memory; assess throughput, retransmissions and latency together.
[Report: queue sizes, IPv6 and three transports](../reports/TUN-QUEUE-SIZE-2026-10-16.md).
[Queue-size recommendations and the throughput/latency trade-off](../reports/TUN-QUEUE-SIZE-2026-10-16.md#choosing-a-size).

## Linux client identity files

`/var/lib/qeli/device-id` (`QELI_DEVICE_ID_FILE`) is loaded once before connecting.
The existing first 16 bytes are retained unless all are zero. If storage is unavailable,
one temporary ID survives every reconnect until client exit; it may change after restart.
Lock contention is limited to 15 seconds. Stop awaits admitted work and then starts no connection.

TOFU store `/var/lib/qeli/known_hosts` (`QELI_KNOWN_HOSTS`) must be a regular UTF-8 file
of at most 1 MiB. `allow_unpinned_tofu` cannot bypass read errors, malformed target pins
or conflicting duplicates. Preserve the original file and verify the server key before
repairing it. New pins use atomic publication with `0600`. TOFU file I/O runs on a
separate joined worker. Stop/timeout stop handshake waiting; an admitted write completes
before reconnect or exit. A late error preserves `failed`; successful persistence may
finish after cancellation. The 15-second flock bound is not an overall shutdown limit.
[Worker and cancellation](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md).
[Design and validation](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-FILES.md).

## Reading INI during Linux client startup

SIGTERM/SIGINT handlers are installed before opening the config. Reading, initial
capability checks and hook-path resolution run on a joined thread. Client INI is capped
at 256 KiB: a regular file's size is checked before reading its contents. The password
readability warning uses permissions from the same opened snapshot.

Stop during an admitted read waits for completion. Success exits without running
password_command, loading device-id, connecting or configuring the network; a late read
error remains an exit error. This is not a hard filesystem timeout: a stuck system call
may delay exit, but normal waiting does not block async tasks. This change sets no server
config size limit.

## Shared NetworkPlan and cleanup command deadline

Linux NetworkPlan setup shares **15 seconds** across TUN, gateway, route and DNS
commands. A component may shorten the remaining time but cannot restart its own
15 seconds. Expiry prevents new commands and successful NetworkPlan acknowledgement.

Cleanup receives separate **15 seconds** from the first resource cleanup in the current
attempt. DNS, pump waiting, routes, gateway and subsequent kill-switch removal share
that deadline. Automatic Drop retries retain the same remainder. The next connection
attempt receives a new deadline only after previous owners complete; sticky cleanup
failures are not cleared and still prohibit ordinary reconnect. Resource cleanup failure
prevents entering kill-switch removal. A failure inside firewall removal may occur after
some rules were deleted: intact protection is not guaranteed in that case.

This bounds commands and their admission, not process exit: kernel/filesystem I/O,
packet-worker joins, TOFU/status writers and user hooks are not aborted by this timer.
Their waiting consumes an already-started cleanup budget. On timeout inspect the log
and leftovers in the original namespace; do not delete retained ownership evidence to
bypass the error. [Validation and remaining audit work](../plans/AUDIT-DEBT.md).

After a gateway timeout and process exit, restarting may reach `lost live per-interface sysctl evidence`: the original TUN is closed, so its saved value cannot be replayed onto a new same-name interface. Follow [manual recovery §6.64](TROUBLESHOOTING.md); a restart loop does not resolve it.


## One Linux client per process

The public `run_client` admits one active invocation per process, including INI loading,
connection, cleanup and final diagnostics. A simultaneous second call returns
`a Linux client is already running in this process` before reading config or registering
signal handlers. Carrier addresses and the cycle flag reset only after successful
admission. Independent Linux clients require separate processes; existing shared
namespace/TUN/kill-switch restrictions still apply.

After `run_client` returns success or error, another invocation is allowed; leftover
network-resource checks still apply. For graceful stop, send SIGTERM/SIGINT and await
return. Forcibly destroying an already-started future, for example through
`JoinHandle::abort`, an outer timeout or panic, makes subsequent calls return
`previous Linux client was cancelled before cleanup completed; restart the process`.
Nested tasks receive cancellation requests, but Drop cannot guarantee their async join;
a new generation must not overlap tasks still finishing. An unpolled future does not
acquire admission. This rule applies to the Linux `run_client` runtime, not to every
shared transport-core instance on other platforms.


## Hook and backup file operations

Linux hooks perform script metadata checks, private context-file creation, command
execution and file removal on one joined thread with its own async runtime. Normal
waiting does not block the client/server executor. Cancellation during preparation
allows admitted file I/O to finish, removes the file and skips command startup.
Cancellation of a running command terminates its group and reaps the shell before
file removal. Forced Drop joins synchronously and may wait on the filesystem for more
than 30 seconds. The command/output deadline remains 30 seconds after preparation.
A background service deliberately detached by a hook with closed pipes retains its
existing contract.

Panel backup reads and checks the active config on a blocking worker that holds the
config write lease until work ends, even if the HTTP request is cancelled. Reading uses
the shared stable regular-file loader: FIFO is rejected without waiting for a writer.
Preparation spends the same 60-second budget as archive creation/verification; late
results neither start tar nor publish a backup. This timer cannot safely interrupt a
stuck syscall. INI format, hook authorization, archive contents and restore policy are
unchanged. [Validation and remaining audit work](../plans/AUDIT-DEBT.md).


<!-- normative-sync: panel-client-stop-v2 -->

## Stopping panel client tunnels

When the supervisor handles SIGTERM/SIGINT, it immediately closes Connect/autostart.
Worker and running clients are asked to stop concurrently: waiting for the worker
does not postpone client shutdown or add a new grace period afterwards.
Clients share one five-second grace from the stop request; repeated waits do not extend it. A client that exceeds the grace receives SIGKILL
and is reaped before its process handle is released. Forced kill or unsuccessful
exit produces a supervisor shutdown error: DNS, route and firewall restoration
has not been confirmed. The next start uses the ordinary recovery mechanisms
for Qeli-owned resources.

Cancelling a Disconnect HTTP request does not lose the process or admit its replacement
before cleanup ends. Status checks for other clients remain available. This grace
is not a total server shutdown deadline and cannot interrupt a stuck kernel syscall.

<!-- normative-sync: server-profile-cancel-v2 -->

## Forced cancellation of a server profile

When a profile future is cancelled, Qeli closes descendant-task admission and retains
their JoinSets together with TUN and DNS/NAT resources. The worker joins descendants
before deleting resources; terminal NAT cleanup and hooks follow this step.
Cancelling cleanup waiting requeues the generation and preserves the failure:
a successful later join does not turn forced cancellation into an ordinary stop.

Use SIGTERM and await process exit. Destroying the worker future itself does not
guarantee completed cleanup: unfinished resources and network-namespace admission
remain retained until process exit. Do not launch a new generation in that process.
The next process uses the ordinary recovery of Qeli-owned rules. The CLI process
boundary is described below; library `run_worker` does not install that timer.
[Checks](../plans/AUDIT-DEBT.md).


<!-- normative-sync: server-stop-budget-v1 -->

## Total server shutdown budget

The CLI worker (`_worker`, including supervisor children) starts one **45-second**
budget on the first observed stop or fatal event, before stop logging. It covers
control handlers, service/profile tasks, deferred joins, NAT/sysctl cleanup,
hooks, accounting persistence and control-socket removal. Repeated waits do not
extend the deadline. A dedicated OS thread monitors the clock independently of
Tokio execution. The limit is below the supervisor’s sixty-second grace, allowing
the worker to report failure before the parent forcibly kills it. Normal exit
reports the final cleanup result; failure is nonzero.

On expiry, the worker closes command admission, sends SIGKILL to tracked groups
of owned commands whose leaders have not been reaped, and exits with **code 124**.
The supervisor reports `worker exceeded its total shutdown budget`: this is a
failure with cleanup unconfirmed. Ownership journals remain for ordinary recovery
on the next start; do not delete them to conceal the failure. Services deliberately
detached by a hook with closed pipes retain their existing contract; descendants
that escape the process group are outside Qeli's management.

The supervisor stops its worker, panel clients and notification queue concurrently:
worker grace remains **60 seconds**, client grace **5 seconds**, and notification
grace **10 seconds** from the first stop request. Worker notifications also drain
concurrently with cleanup; they do not add a separate ten seconds afterwards.
Accepted messages may be lost on timeout or forced exit.

The 45 seconds apply to CLI cleanup, not OS signal delivery, preparation before
shutdown, or library `run_worker`. Library cancellation retains resources and
rejects another in-process worker as described above. Arbitrarily stuck kernel
syscalls, kernel exit/reaping and synchronous spawn under the command-registry
lock cannot safely be interrupted by this timer; there is no absolute wall-clock
guarantee during kernel failure. A stalled filesystem worker is verified with
forced process exit and subsequent recovery.

## Linux client system context

Use separate processes for independent CLI clients. One `run_client` holds process
admission through normal cleanup; forced Drop requires a process restart. For
`dns = tunnel`, client and resolver must share the supported network/PID context;
a changed D-Bus owner does not authorize Qeli to mutate the new service. With
`dev_attach = true`, the external manager keeps the device and packet features
stable during attach and sysfs matches the calling network namespace. Index
checks reject observed replacement, but equal numeric indices in separate
namespaces do not prove identity.

A late IPv4 default route or global IPv6 does not remove an installed kill-switch:
checked on four nft/legacy pairs. Do not delete/replace a selected WAN while
retaining its name during an active profile; stop the profile and confirm cleanup
first. The default-WAN name monitor does not remove this limitation.
[Checks and remaining D06 scope](../plans/AUDIT-DEBT.md).

## Server routes with an active profile

A server NAT44/NAT66 WAN is selected when installing the profile. A default-route
change does not automatically move its NAT/permits to another interface. If a route
or policy rule sends client traffic through another WAN, NAT66 blocks that egress;
NAT44 blocks non-RFC1918 destinations. Returning the route to the selected WAN
restores traffic without reconnecting clients. To change the selected WAN itself,
restart the profile with the desired configuration and confirm old-generation
cleanup. Client `exit_node` has a separate default-WAN monitor; that behavior does
not apply to server profiles.

In IPv6 `route`, kernel routes select WAN/LAN egress and preserve the source address.
NAT44 toward RFC1918 networks on another interface also preserves client addresses
and administrator policy: with `FORWARD DROP`, Qeli does not open that LAN. CGNAT
`100.64.0.0/10` and public address space outside RFC1918 do not qualify for this NAT44
exception. The checked scenario changes routes while retaining devices; it does not
protect replacing a WAN with a different device under the same name.
[Packet checks and remaining D06 scope](../plans/AUDIT-DEBT.md).

### Retained WAN identity limitation

For managed NAT44/NAT66 and client `exit_node`, the selected WAN name remains the
firewall selector. Startup device-presence checks and the client monitor do not
protect against a new device reusing that name. Stop the profile and verify cleanup
before WAN rename/delete/recreate; then change the interface and restart the profile.

On 3 October 2026 production BPF protection was excluded by user decision; current
Qeli requires no additional CAP_BPF or bpffs.
[Known P2 and disposition](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md).

DEB update qualification: package downgrade restored the configured DB and service after two faults in an isolated fixture. Remove/purge preserved operator data. This does not guarantee every profile is healthy: updater checks supervisor PID stability; verify a client connection and logs after updating. Details and limits: [Q33 DEB/update](../reports/audit-0.8.2/AUDIT-Q33-PACKAGE-MANAGER.md).

Additional release package qualification confirms VPN traffic through systemd after install, upgrade and both rollbacks with a pinned server key. Each stage uses a new client connection; uninterrupted sessions during restart are not guaranteed. IPv4/IPv6, TCP/UDP, DNS and MTU matrix also passed. [Scope and evidence](../reports/audit-0.8.2/AUDIT-Q33-PACKAGE-MANAGER.md).
