# Qeli — installation & getting started (step by step)

> **Documentation status:** current development tree **0.8.3**; planned full-IPv6 release **0.8.3**;
> package version covered by this guide **0.8.3**.
> `qeli --version` reports the version of the binary actually installed.
> See [GitHub Releases](https://github.com/litvinovtd/qeli/releases) for package availability and publication status.
> Links to this version's files work after its publication.

A complete from-scratch guide: from standing up the server to creating users with
routes and connecting your first client — **both via the CLI and via the web panel**.

Targets a clean **Linux server** (Debian/Ubuntu) with root access. All server commands
run as root (or via `sudo`).

> References this guide builds on:
> [CONFIG.md](CONFIG.md) — every config key · [PANEL.md](PANEL.md) — web panel ·
> [IPV6.md](IPV6.md) — IPv4/IPv6/dual-stack, `off/manual/route/nat66`, NDP proxy and troubleshooting ·
> example configs: [`server.conf`](../../../qeli/config/server.conf) ·
> [`server-ipv6.conf`](../../../qeli/config/server-ipv6.conf) ·
> [`users.conf`](../../../qeli/config/users.conf) · [`client.conf`](../../../qeli/config/client.conf).

## Contents
1. [What you need](#1-what-you-need)
2. [Install the server](#2-install-the-server)
3. [Initial server setup (CLI)](#3-initial-server-setup-cli)
4. [Start & verify](#4-start--verify)
5. [Full-tunnel: NAT (set up automatically)](#5-full-tunnel-nat-set-up-automatically)
6. [Creating users (CLI)](#6-creating-users-cli)
7. [Routes: split/full-tunnel, pushed routes, ACL, static IP](#7-routes)
8. [Connecting a client](#8-connecting-a-client)
9. [The same via the web panel](#9-the-same-via-the-web-panel)
10. [CLI reference & diagnostics](#10-cli-reference--diagnostics)
11. [Wire modes — which to pick](#11-wire-modes--which-to-pick)
12. [Common problems](#12-common-problems)
13. [Full removal of qeli](#13-full-removal-of-qeli)

---

## 1. What you need

- A **Linux x86-64 server** (**Debian 11+ / Ubuntu 20.04+**), root, a public IP.
  The `.deb` is a portable build (`make deb-portable`, guarded by `check-abi`); the
  package depends on `libc6 >= 2.28`, `libgcc-s1`, `iptables`, `iproute2` and
  `libcap2-bin`. It installs out of the box on Debian 11/12 and Ubuntu
  20.04/22.04/24.04. **Debian 10 (Buster) does not work**: it ships `libgcc1`, and
  `libgcc-s1` only arrived in Debian 11, so `apt` refuses on the dependency. For Buster
  and for systems with glibc < 2.28, use option B (build from source on the machine
  itself) or option C (Docker — the runtime is inside the image).
- An **open port** for the VPN (TCP `443` by default) and, if you enable the panel,
  its port (`8080` by default). Open them in your cloud firewall / security group.
- A kernel with **TUN** support (`/dev/net/tun` — present almost everywhere; some VPS
  enable it in the provider panel).
- `iproute2`, `iptables`, `libcap2-bin` packages (pulled in as .deb dependencies).
- A **client**: phone (Android), desktop (Windows/macOS), or Linux CLI.

A single `qeli` binary plays both roles: `qeli server` and `qeli client`.

---

## 2. Install the server

> ⚡ **Fastest path (one command).** The repo root ships a ready installer
> [`install-qeli-server.sh`](../../../install-qeli-server.sh): it installs qeli and its
> dependencies, **asks which profile** — `reality-tls` (the default; real TLS 1.3 + H2 on
> TCP:443, bridges unauthorised probes to the target), `fake-tls` (cheaper on CPU, enough against passive
> DPI), or **`udp-quic`** (a UDP path with QUIC-shaped datagrams — pick it where TCP:443 is
> throttled, reset, or otherwise degraded) —
> **and which port** (default :443), brings it up with full-tunnel NAT, and creates
> **5 users** with ready `qeli://` connection strings under `/etc/qeli/client-links/`.
> Run as root: `./install-qeli-server.sh <public-ip-or-host>` (or `sudo …` if you have
> sudo — it is not required and is never installed). Download the script and run it as a
> second step — we do not use `curl … | bash`: the script runs as root and is worth reading
> first, and `curl -fsSL` stays silent on an HTTP error while `bash` with empty stdin exits
> 0 (a failed download then looks like a successful install).
> For a non-interactive run (automation) set the choice up front:
> `QELI_PROFILE=udp-quic QELI_PORT=443 ./install-qeli-server.sh <IP>`. After that you just
> paste a connection string into the app. Manual steps below.
>
> **What it does, in order:** ① installs dependencies (`curl`, `jq`, `iptables`,
> `iproute2`, `openssl`) → ② gets qeli onto the box **and sets up exactly what the `.deb`
> does** (the `qeli` system user, `/etc/qeli` + state dirs, the `*.conf.example` files,
> the systemd unit, the polkit rule) → ③ writes `/etc/qeli/server.conf` with the chosen
> profile on the chosen port + full-tunnel NAT (a fresh REALITY `short_id` for reality-tls)
> → ④ generates the per-profile server identity key → ⑤ creates the 5 users and saves their
> `qeli://` links → ⑥ applies mobile/LTE OS tuning (BBR + PMTU probing, plus outer IPv4
> and, when listening on IPv6, IPv6 MSS clamps on the TCP profiles) → ⑦ enables the HTTPS
> web panel with a generated password →
> ⑧ `systemctl enable --now qeli`.
>
> **Which user the service runs as** — `QELI_RUN_AS=qeli` (default, unprivileged) or
> `QELI_RUN_AS=root`. The installer applies it with `qeli set-service-user` (§10.4) just
> before the first start, so the service comes up as the chosen user:
> ```bash
> sudo QELI_RUN_AS=root ./install-qeli-server.sh <IP>    # no privilege separation — see §10.4
> ```
> Keep the default unless you have a specific reason; the warning in §10.4 applies.
>
> **Two install branches (step ②) — both end in an identical system:**
> - **Default — download the `.deb`** from GitHub Releases, verify its SHA256, and
>   `apt install` it. This is the normal path; nothing extra to pass.
> - **From a prebuilt binary — `QELI_BIN=<path>`:** instead of downloading, install that
>   binary and **reproduce the .deb layout itself** (user, dirs, `*.conf.example` files,
>   `qeli.service`, the `49-qeli.rules` polkit rule). Use it for a **build-from-source** or
>   **air-gapped** install. Add `QELI_SRC=<repo checkout>` to copy the unit and examples
>   straight from source (Qeli payload only); missing OS dependencies are installed through apt.
>   Without QELI_SRC, payload is fetched from GitHub. Example:
>   ```bash
>   sudo QELI_BIN=qeli/target/release/qeli QELI_SRC=. ./install-qeli-server.sh <IP>
>   ```
>
> **What else it changes on the host** (not incidental details — know them up front):
> - **System-wide network tuning**: writes requests to `/etc/sysctl.d/99-qeli-perf.conf` and tries to switch
>   congestion control to **BBR** — this affects **all** TCP on the host, not just qeli.
>   Enables TCP receive autotuning (`tcp_moderate_rcvbuf=1`), sets `tcp_rmem`/`tcp_wmem`
>   growth limits to 16 MiB, and leaves the global `tcp_mem` budget unchanged.
>   New TCP profile examples explicitly set `perf.tcp.send_buffer_size = 0` and
>   `perf.tcp.recv_buffer_size = 0` for OS management. Normal upgrades preserve
>   existing explicit nonzero profile values.
>   It also raises system-wide `rmem_max`/`wmem_max` to 16 MiB and
>   `rmem_default`/`wmem_default` to 4 MiB. Current Qeli explicitly requests UDP
>   buffers and may grow the receive buffer within its RAM budget; growth depends
>   on `rmem_max`, not the system default buffer size.
> - **Requests loading `tcp_bbr` at boot** via `/etc/modules-load.d/qeli-bbr.conf`.
>   Kernel/module restrictions can prevent application. The installer reads each value
>   back and reports verified success or `kernel tuning incomplete`, with effective
>   value/write-failure counts and a diagnostic log. VPN installation can still succeed.
>   Before changing tuning it saves readable runtime values and prior persistent files
>   in a root-only `/etc/qeli/client-links/kernel-tuning-<stamp>-<suffix>/` receipt.
>   `restore.txt` contains commands to restore prior files (or remove newly created ones),
>   then apply `runtime.before`. Review the receipt before using it, especially after
>   later administrator changes. A key without a readable baseline is not changed at
>   runtime. Forced reconfiguration creates a separate receipt. Deleting a sysctl file
>   and running `sysctl --system` alone does not restore previous runtime values.
> - **Adds MSS rules** (TCP profiles only — udp-quic skips them) in `mangle/OUTPUT`:
>   IPv4 always, and IPv6 when the installer enables its independent V6ONLY listener.
>   The matching `mangle/PREROUTING` rules clamp the client's incoming SYN too, so both the
>   client→server ClientHello and server→client ServerHello directions are bounded.
>   It then tries to **persist the firewall** by creating only missing
>   `/etc/iptables/rules.v4` and `rules.v6` snapshots. It never overwrites an existing
>   administrator-managed file and deliberately does not invoke `netfilter-persistent save`,
>   which would replace those files from live state. Each new snapshot still contains that
>   family's **entire** current ruleset, not just qeli's rule.
>   **Persisting is best-effort, not a guarantee.** A failure is reported but does not abort
>   the installation. And `/etc/iptables/rules.v4`/`rules.v6` restore nothing by themselves:
>   those files are read at boot by the `iptables-persistent` (`netfilter-persistent`)
>   package, and **without it the MSS rules are gone after a reboot**. Check after reboot:
>   `iptables -t mangle -S OUTPUT | grep TCPMSS`; also check
>   `ip6tables -t mangle -S OUTPUT | grep TCPMSS` when IPv6 is enabled. If a required rule
>   is missing, install `iptables-persistent` or reinstate it from your own unit. The symptom of a
>   missing clamp is downloads that stall dead for mobile clients.
> - **Enables the HTTPS web panel on `127.0.0.1:8080` (loopback only)**, generating a
>   password and printing it **once** at the end. That is the only time you see it — save it
>   right away. Reach it over an SSH forward:
>   `ssh -L 8080:127.0.0.1:8080 root@<server>`, then open `https://127.0.0.1:8080`.
>   Publishing it is a deliberate act and needs BOTH `QELI_PANEL_PUBLIC=1` and
>   `QELI_PANEL_ALLOWED_IPS=<ip[,ip…]>`; a public bind without a source allowlist is
>   REFUSED by the installer. If you don't want the panel at all, disable it afterwards
>   (`[web] enabled = false`).
> - Writes `/etc/qeli/client-links/CONNECTION-STRINGS.txt` containing the **plaintext
>   passwords of all five users** (directory `0700`, files `0600`).
> - If you don't pass a public address, it discovers one by calling external services
>   (`api.ipify.org`, `ifconfig.me`, `icanhazip.com`).
>
> All of it is reversible — see §13 "Full removal".

For an existing server, do not force reinstall just to enable autotuning.
Back up the config, sysctl file and previous runtime values. In the intended
`[profile:...]`, set both `perf.tcp.*_buffer_size` keys to `0`; add
`net.ipv4.tcp_moderate_rcvbuf=1` to the existing
`/etc/sysctl.d/99-qeli-perf.conf`, preserving other settings. Run
`sysctl -p /etc/sysctl.d/99-qeli-perf.conf` and check readback, then
`qeli check-config --config /etc/qeli/server.conf` and `systemctl restart qeli.service`.
Reconnect clients to create new TCP sockets; this interrupts current sessions.
Normal `update-qeli-server.sh` upgrades do not migrate configs or sysctl.
For memory limits and socket checks, see [CONFIG — network tuning](CONFIG.md).

### Option A — .deb package (recommended)

#### A.1. Download the package **into `/tmp`**

Fetch the `.deb` into `/tmp` (or any world-readable directory) — **not** into `/root` or a
home directory:

```bash
cd /tmp
curl -fLO https://github.com/litvinovtd/qeli/releases/download/v0.8.3/qeli_0.8.3_amd64.deb
# or copy it from your workstation:  scp qeli_0.8.3_amd64.deb root@server:/tmp/
```

> **Why `/tmp`.** `apt` downloads and unpacks as the unprivileged `_apt` user, which cannot
> read `/root` or home directories. Installing from `/root` still works, but prints:
> ```
> N: Download is performed unsandboxed as root as file '/root/qeli_0.8.3_amd64.deb'
>    couldn't be accessed by user '_apt'. - pkgAcquire::Run (13: Permission denied)
> ```
> It is only a warning (apt falls back to running as root), but from `/tmp` it never appears.

#### A.2. Install

```bash
sudo apt install /tmp/qeli_0.8.3_amd64.deb     # installs and pulls dependencies
```

Give a **full path** (or `./name.deb`) — without a slash apt looks for a repository package
of that name instead. If apt is unavailable:

```bash
sudo dpkg -i /tmp/qeli_0.8.3_amd64.deb
sudo apt-get -f install -y          # pull the dependencies (iproute2, iptables, libcap2-bin)
```

What the package does:
- installs the binary to `/usr/bin/qeli` (`0755 root:root`, **without** file capabilities —
  since 0.7.12 `setcap` is deliberately stripped: the systemd unit grants
  `CAP_NET_ADMIN`/`CAP_NET_RAW`/`CAP_NET_BIND_SERVICE` via `AmbientCapabilities`, and with
  `NoNewPrivileges=true` the kernel ignores file caps anyway);
- creates the system user **`qeli`** plus `/etc/qeli`, `/var/log/qeli`, `/var/lib/qeli`, then
  ownership repair on daemon state, excluding installer receipts/backups;
- creates an empty `/etc/qeli/users.conf` (the sample file with a KNOWN hash is never seeded);
- ships **examples** `/etc/qeli/{server,server-multiprofile,server-ipv6,server-maxobf,users,client,client-reality,client-maxobf}.conf.example`
  (you create the real configs yourself — step 3);
- installs the systemd unit `qeli.service` (`ExecStart=/usr/bin/qeli server --config /etc/qeli/server.conf`)
  and the polkit rule `/etc/polkit-1/rules.d/49-qeli.rules`;
- **asks which OS user the service should run as** (debconf question `qeli/run-as`:
  `qeli` — the default, unprivileged — or `root`) and applies the answer via
  `qeli set-service-user`. Answer non-interactively (automation / preseed) with:
  ```bash
  echo "qeli qeli/run-as select root" | sudo debconf-set-selections
  sudo apt install /tmp/qeli_0.8.3_amd64.deb
  ```
  Changeable at any time afterwards — `sudo qeli set-service-user root|qeli` (§10.4),
  where the trade-offs of `root` are spelled out.

#### A.3. Fix ownership of `/etc/qeli` — a required step after configuring

**This is the most common cause of "installed it and nothing works".** The service runs as
`User=qeli` (see `qeli.service`) and **writes inside `/etc/qeli`**: per-profile identity keys
(`/etc/qeli/identity/<profile>.key`) are generated there on first start, `add-client` and the
web panel persist users there, and `usage.json` lives there too. That is exactly why the unit
carries `ReadWritePaths=/etc/qeli`.

`postinst` sets ownership **at install time**, but anything you **create** afterwards as root
stays root-owned:

```bash
sudo cp /etc/qeli/server-multiprofile.conf.example /etc/qeli/server.conf   # → root:root
sudo qeli show-identity --config /etc/qeli/server.conf                      # creates identity/ as root
```

> **What changed in 0.7.13.** **Replacing an existing** file used to fall into the same trap:
> an atomic write ends in `rename`, which swaps in a new inode owned by the writer — so a
> single `sudo qeli add-client` flipped an already-correct `users.conf` from `qeli:qeli` to
> `root:root`, and the panel broke next (the lock file is created with the owner of the file
> it guards). Writes now preserve the owner of the file they replace, so that path is closed.
> **Creating new files and directories as root is still a trap** — everything below still
> applies.

After that the `qeli` service cannot write those files. So **once the config is in place and
you have run any root CLI command**, fix the ownership:

```bash
sudo qeli set-service-user qeli
sudo chmod 755 /etc/qeli
sudo chmod 640 /etc/qeli/server.conf /etc/qeli/users.conf   # they hold password hashes and keys
[ -d /etc/qeli/identity ] && sudo chmod 700 /etc/qeli/identity && sudo chmod 600 /etc/qeli/identity/*.key
sudo systemctl restart qeli
```

> **How to avoid this entirely** — run the CLI as the `qeli` user from the start:
> ```bash
> sudo -u qeli qeli add-client alice --config /etc/qeli/server.conf
> ```
> Everything is then created with the right owner and no `chown` is needed.

`/var/lib/qeli`, `/var/log/qeli` and `/run/qeli` (the control socket) are created and chowned
by systemd itself via `StateDirectory`/`LogsDirectory`/`RuntimeDirectory` — leave them alone.

**Symptoms of wrong ownership** (check `journalctl -u qeli -n 50 --no-pager`):
- `Permission denied` / `EROFS` while generating the identity — the profile fails to bind on a
  fresh install;
- `add-client` succeeded but the user is gone after a restart — the write never persisted;
- the panel saves settings without an error, yet they revert after a restart;
- the service enters a restart loop (`systemctl status qeli` → `NRestarts` climbing).

#### A.4. Verify the install

```bash
qeli --version
systemctl status qeli --no-pager
ls -la /etc/qeli                      # everything owned by qeli:qeli
journalctl -u qeli -n 30 --no-pager   # no permission errors
```

### Option B — build from source

Use Rust 1.97.0 for the server build, matching the main CI jobs. From the repo root:

```bash
rustup toolchain install 1.97.0 --profile minimal
cd qeli
cargo +1.97.0 build --locked --release --features jemalloc   # binary → qeli/target/release/qeli
# --features jemalloc is required for the SERVER binary: without it the worker's
# RSS plateaus around ~180 MB under handshake churn (glibc keeps freed arenas)
# instead of ~40–60 MB with jemalloc. A client build does not need it.

# (optional) build your own .deb from the fresh binary (the Makefile enables jemalloc):
RUSTUP_TOOLCHAIN=1.97.0 make -C debian deb  # → qeli/debian/qeli_<version>_amd64.deb
```

Without the package you can run the binary directly (see step 4), but then you create the
systemd unit, the user and the directories yourself — **or let the installer do it for
you** from the freshly built binary, reproducing the exact `.deb` layout (the `qeli` user,
`/etc/qeli` + state dirs, the `*.conf.example` files, `qeli.service`, the polkit rule) with
no download. From the repo root:

```bash
sudo QELI_BIN=qeli/target/release/qeli QELI_SRC=. ./install-qeli-server.sh <public-ip>
```

Installer validates explicit endpoint/panel options and nonempty boolean opt-ins (0/1) before dependency/payload changes. Auto-host is checked before config/identity, but dependencies/binary may already change. Complete INI is prepared privately beside server.conf; CLI/web/final check-config use that stage. After validation and the selected service-user helper, the old live config is backed up and replaced by rename, then restarted. Before-publication errors retain the old config; fresh failed installation publishes no partial config. Users/identity/links/tuning/dependencies/binary/drop-in can already change; use the password recovery journal if present. Restart/health failure after publication does not restore the old config automatically. The installer explicitly applies QELI_RUN_AS, including the default qeli choice, after validation; qeli removes a previous root override while preserving installer receipts/backups. [Audit and limits](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CONFIG.md).

Version-number discovery in installer/updater uses `qeli --version`, also supported by older installations. Current `qeli version --check` remains an opt-in update query. Actual CLI writers create a sibling lock for the temporary INI; installer removes that unique stage lock after writers finish, while keeping the live config/users locks. Three profile installation flows have passed with real CLI parsing/keys/Argon2/links; service startup/kernel/VPN remained outside that earlier qualification; the default-unit ownership/drop-in transition is covered by the [subsequent service-user audit](../reports/audit-0.8.2/AUDIT-Q33-SERVICE-USER.md). [Evidence and limits](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CLI.md).

`QELI_BIN` selects the from-binary branch; `QELI_SRC=.` copies the unit and examples
straight from this checkout; the OS dependency phase uses apt only for missing prerequisites. See §2's **"Two install branches"**. This also
installs the polkit rule, so the panel's `Apply & Restart` works without the extra step below.

Installer-generated links, summary and backups are private0600 and published through temporary files; existing kept links retain their bytes through a private copy. Linked/nonregular generated names refuse before dependency changes. Backups have a random suffix after the timestamp to avoid collisions. The web helper replaces its config atomically, preserving ownership and setting0600. This does not make the entire forced reconfiguration transactional.

If user/link creation fails, the old CONNECTION-STRINGS.txt remains and a root0600 `/etc/qeli/client-links/INSTALL-PENDING-<timestamp>-<suffix>` journal retains generated passwords, recorded before add-client. Read it as root, compare its users with users.conf, and use the recovered passwords/links for the affected client configurations; a pending entry may not have created an account. Do not blindly repeat add-client for an existing user. Accounts/individual links may already change; there is no automatic rollback. After successful summary publication the current journal is removed; journals from earlier failures remain until you verify recovery and remove them. These are plaintext secrets; include them in protected backups and remove obsolete copies after recovery. Power-loss durability is not qualified. [Audit scope](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-SECRETS.md).

Installer dependency setup invokes apt only for missing prerequisites, then verifies commands/CA availability. For QELI_BIN+complete QELI_SRC or a local QELI_DEB, provide PUBLIC_HOST and preinstall OS/package dependencies to avoid dependency downloads; this stage check does not qualify the entire disconnected install. QELI_DEB is an absolute local .deb path, not a URL. Package=qeli, host architecture/all and exact installed status/version/architecture are required before config generation. QELI_VERIFY_ATTESTATION=1 requires successful gh verification for the Debian install path, including a local package. Failed install/repair is fatal, with no automatic package rollback. [Executed admission scope](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-ADMISSION.md).

With QELI_BIN, an explicit QELI_SRC must contain all eight examples, qeli.service and49-qeli.rules; missing files refuse rather than falling back to GitHub. These files are admitted in private staging before replacing the binary. Without QELI_SRC, the requested release payload is selected by host architecture and verified; QELI_VERIFY_ATTESTATION=1 also requires successful gh verification. Linked/nonregular state paths refuse; INT/TERM stop installation after cleanup. Subsequent publication is sequential, so final installation errors are not an automatic rollback. The dependency phase now skips apt when prerequisites are available; a local payload alone does not qualify the entire first installation as disconnected. [Executed scope](../reports/audit-0.8.2/AUDIT-Q33-BINARY-INSTALLER.md).

> ⚠️ **Non-.deb install + web panel:** the panel's **`Apply & Restart`** button runs
> `systemctl restart` on the service. A **non-root** `User=qeli` service is only allowed
> to do that with a polkit rule. The `.deb` (Option A) installs it; on a manual/binary
> install you must add it once, as root:
> ```bash
> sudo qeli install-polkit          # → /etc/polkit-1/rules.d/49-qeli.rules (see §10.4)
> ```
> Skip this and `Apply & Restart` will report that the rule is missing (it no longer
> fails silently). In a **container** systemctl is unavailable entirely — the panel
> applies profile changes via the in-process worker restart, and panel-socket changes
> (`web.bind`/`port`/`tls`) need the container recreated (`docker restart`).

### Option C — Docker

A **multi-arch** image (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) carries **both
roles** (`qeli server` and `qeli client`) with every runtime dependency bundled
(`iproute2`, `iptables`, CA certs) — it runs on any Linux host and on router container
runtimes (MikroTik RouterOS v7, OpenWrt). The container needs `/dev/net/tun` and three
capabilities — `NET_ADMIN` (TUN, routes, iptables), `NET_RAW` and `NET_BIND_SERVICE`
(binding ports below 1024); a ready `docker-compose.yml` (server + optional gateway client) is
included. Build/run instructions, compose example and caveats:

> 🐳 **[release/docker/README.md](../../../release/docker/README.md)**

For upgrades preserve both volumes: `/etc/qeli` (INI, users and identity) and `/var/lib/qeli` (client state). Before replacement record the running container image ID, retain the previous image and back up data. After recreation check logs, client connection and tunnel traffic; Running alone does not establish VPN readiness. On failure restore the saved image with the same volumes. Current compose provides no automatic rollback/HEALTHCHECK. Manual branch publication uses a SHA tag; `latest` is reserved for stable release tags.

With Docker you can skip the rest of this guide's install/systemd steps; profile and
user management below (CLI or web panel) still apply inside the container.

> **Permissions work differently in a container — and §A.3 does not apply to it.** The image
> carries no `USER` directive and the entrypoint drops no privileges, so **the process inside
> the container runs as root**. Three consequences:
> - The privilege separation that the `qeli` user provides on a host is **absent** here:
>   compromising the daemon means root inside the container (not on the host, but with
>   `NET_ADMIN`/`NET_RAW` granted the boundary is thinner than it looks). Do not expose the
>   panel without a password and `web.allowed_ips`.
> - The `/etc/qeli` ownership trap **cannot occur** — everything inside is written as root
>   anyway. But files in a mounted volume appear on the host owned by uid 0; if that same
>   directory is later handed to a host service running as `User=qeli`, the ownership has to
>   be fixed by hand.
> - `post_up`/`post_down` hooks in a container really do run **as root** (unlike a `.deb`
>   install, where they run as `qeli`).
>
> Restarting the service from the panel does **not** work in a container, and does not try:
> there is no systemd inside. Profiles/users/DNS/NAT are applied by an automatic worker
> restart, while panel-socket changes (`web.bind`/`web.port`/`web.tls*`/`web.enabled`) need
> the container recreated from outside — see §6.11 in
> [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

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
# tcp | udp
bind.transport = tcp

# the tunnel's virtual network
# the server's address inside the tunnel (gateway)
tun.address  = 10.9.0.1
tun.ip_mode = dual
tun.ipv6_address = fd71:e1:8000:100::1
# pushed to clients; for production TCP see §12 and CONFIG.md
tun.mtu      = 1400

# VPN subnet and pool; its prefix also configures the server and clients
pool.cidr    = 10.9.0.0/24
# example only: use one random RFC4193 /48 per site and one /64 per profile
pool.ipv6.cidr = fd71:e1:8000:100::/64

# full-tunnel egress for both families
routing.nat.enabled = true
routing.ipv6.mode = nat66
routing.ipv6.interface =

# in-tunnel resolver on both gateway addresses
dns.enabled = true
dns.listen = 10.9.0.1
dns.listen_ipv6 = fd71:e1:8000:100::1

# on-the-wire masking mode (see §11)
obf.mode = fake-tls

# transport-independent packet/record boundary masking
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
```

Everything else (padding, heartbeat, limits) already has sensible defaults
in the example. Full description of every key — [CONFIG.md](CONFIG.md).

> **Multiple profiles.** You can run a second interface side by side, e.g. UDP on
> `:1443` — add a `[profile:udp]` section (its own `tun.name`/`tun.address`/`tun.ipv6_address`/`pool.cidr`/`pool.ipv6.cidr`/
> `bind.port`/`bind.transport = udp`). Each profile has its own identity key and pool.
> A ready template with **all 10 modes at once** (reality-tls on :443, the rest on
> 8443–8451) ships as `/etc/qeli/server-multiprofile.conf.example` (installed by the
> .deb; in the source — [`config/server-multiprofile.conf`](../../../qeli/config/server-multiprofile.conf)):
> copy it to `server.conf`, keep the profiles you want, replace the `CHANGEME` keys.

### 3.3. Users: where they live

By default users live in a **separate file** — `auth.users_file` (default
`/etc/qeli/users.conf`). The example configs ship **without** inline users; add users
with `qeli add-client` (step 6), which appends them to that file. Nothing else to do.

> You can instead define users inline in `server.conf` as `[user:*]` sections. If both
> sources are configured, the server loads their **union**, and `auth.users_file` wins
> duplicate names. Panel edits preserve the configured file path. Prefer the separate
> file for dynamically managed users.

---

## 4. Start & verify

**Validate the config first** — this catches misspelled keys (which §3.1 and §12 warn
about: a wrong key silently keeps its default) and keys retired in 0.7.12:

```bash
sudo qeli check-config --config /etc/qeli/server.conf     # server (rc≠0 = don't start)
qeli check-config --config ~/qeli-client.conf --client     # a client config
```

Then start it:

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
when it stops. IPv4 traffic outside RFC1918 is blocked on another interface,
while access to RFC1918 LANs follows the administrator firewall policy:

```ini
# in [profile:tcp]
routing.nat.enabled  = true
# WAN egress interface. Leave empty/default to detect one unambiguous default route,
# or set it explicitly, e.g. ens3.
routing.nat.interface =
# IPv6 ULA egress: MASQUERADE through the public IPv6 default-route interface
routing.ipv6.mode = nat66
routing.ipv6.interface =
```

```bash
sudo systemctl restart qeli      # the server applies NAT when the profile starts
journalctl -u qeli | grep NAT    # "NAT masquerade active via iptables (10.9.0.0/24 -> ens3)"
sudo iptables-save | grep qeli-nat   # see the installed rules
```

What the server installs (each rule is tagged with the comment `qeli-nat:<profile>` so
it can remove exactly those on disable/stop): `net.ipv4.ip_forward=1`; `-t nat
POSTROUTING -s <pool.cidr> -o <wan> -j MASQUERADE`; two `FORWARD … ACCEPT` (tun↔wan);
two per-family `-t mangle FORWARD … TCPMSS` rules (`tun.mtu−40` for IPv4,
`tun.mtu−60` for IPv6; PMTU-black-hole guard).

> ⚠️ **Requires `iptables` and `ip6tables`** (both commands come from the Debian/Ubuntu `iptables` package). The .deb depends on it, so a
> package install already has it. If `iptables` is **missing**, NAT can't be applied:
> the server log shows `ERROR … routing.nat.enabled is set but NAT was NOT applied`, and the **web panel**
> (Dashboard) shows a yellow banner. Install it: `sudo apt install iptables`. Only the
> classic `iptables`/`ip6tables` CLIs are used (never direct `nft`/`ufw` rules).
>
> The one-shot installer detects the real IPv6 default-route interface and a public
> `2000::/3` source address, verifies the `ip6tables` NAT table, then generates a random
> RFC4193 `/48`. If any prerequisite is absent, only the generated active profile is
> normalized to IPv4; the shipped examples remain dual-stack templates.

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
  --static-ip 10.9.0.50 \          # fixed tunnel IP
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
[`users.conf`](../../../qeli/config/users.conf)):

```ini
[user:bob]
# set by add-client
password_hash = $argon2id$v=19$m=...$...
enabled = true
static_ip = 10.9.0.50
max_sessions = 3
profiles = tcp
# ACL: where this user may go (empty = anywhere)
allowed_networks = 10.9.0.0/24, 192.168.1.0/24
# rate cap (0 = unlimited)
bandwidth.limit_mbps = 50
bandwidth.burst_mbps = 100
# per-user pushed route (repeatable)
route = 10.20.0.0/16 gateway=10.9.0.1 metric=100
# inherit from [group:premium]
group = premium
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
route = 192.168.50.0/24 gateway=10.9.0.1 metric=100
```

`gateway` is the server's tunnel address (`tun.address`). `metric` sets priority
(optional). Forwarding of RFC1918 networks behind the server (`routing.forward_private`)
is **on by default**; set it `false` to disable.

### 7.4. Per-user routes (to one specific user)

Same syntax, but in a `[user:*]` section — pushed only to that user:

```ini
[user:bob]
route = 10.20.0.0/16 gateway=10.9.0.1 metric=100
```

### 7.5. Destination ACL (`allowed_networks`)

Restricts **where** a user may go through the tunnel (a whitelist of dst CIDRs).
Empty/absent = unrestricted:

```ini
[user:bob]
allowed_networks = 10.9.0.0/24, 192.168.1.0/24
```

### 7.6. Client-to-client and static addresses

```ini
# in [profile:tcp]
# let clients see each other inside the tunnel
routing.client_to_client = true
# pin an IP to a user (alternative to user.static_ip)
pool.reservation.alice = 10.9.0.100
```

### 7.7. DNS over the tunnel

It matters to keep **two separate mechanisms** apart — this is a common source of confusion:

1. **The in-tunnel DNS proxy** (`dns.enabled` / `dns.listen` / `dns.upstream`) — the
   server runs a resolver on `tun.address:53` (cache, blocklist) and forwards to upstream.
2. **Which DNS is handed to clients** (`dns.push_servers`) — the address(es) the client
   writes into its own resolver config. This is a **separate** key.

What the server actually pushes (`server/handler.rs`):

| `dns.push_servers` | `dns.enabled` | Client receives | Effect |
|---|---|---|---|
| set (e.g. `1.1.1.1`) | — | the list for negotiated families; the legacy field carries the first address | client queries it **directly**, bypassing the proxy (no cache/blocklist) |
| negotiated-family list empty | `true` | `dns.listen` and/or `dns.listen_ipv6` for negotiated families | client → proxy on the server → upstream. The example explicitly enables the proxy; `dns.enabled` defaults to `false`. |
| negotiated-family list empty | `false` | nothing | subsequent behavior follows client DNS policy, see below |
Client `dns_servers` overrides the push in `dns = tunnel` mode. If filtering by negotiated
families leaves no pushed resolvers, an enabled proxy supplies its active listeners.
Without a push, configured/platform fallback resolvers are considered; a full tunnel
with `dns = tunnel` and no available resolver is refused rather than silently retaining
host DNS. `dns = off`/`system` leaves device resolvers unchanged. [DNS contract](CONFIG.md).


```ini
# in [profile:tcp] — "clients go through my proxy" (recommended)
dns.enabled  = true
dns.upstream = 1.1.1.1, 8.8.8.8
# dns.blocklist = ads.example.com, track.example.com   # answer with 0.0.0.0 (ad blocking)
# empty → clients get the proxy address (dns.listen)
dns.push_servers = ""

# ...or "hand clients a ready resolver directly" (LAN / AdGuard / NextDNS):
# dns.push_servers = 192.168.50.10        # the proxy need not even be enabled
```

> If the panel's "Push DNS to clients" field shows a non-empty value but the client still
> receives `tun.address`, check that the edit was **saved and applied** (service restart):
> the pushed DNS comes from the on-disk config, not from an unsaved form.

---

## 8. Connecting a client

### 8.1. Mobile (Android) and desktop (Windows/macOS)

1. On the server, issue a link: `qeli add-client <user> --link --host <public-host:port>`
   (§6.3) — you get `qeli://…` + a QR.
2. In the app: **Add profile → Scan QR** (or **Paste qeli:// link**) → the profile
   appears with all parameters and the **server key pinned**.
3. Tap the connect ring. Done.

Full-tunnel and "route local networks" are toggles in the app.

The timestamp shape in the log pane is **Settings → Log timestamp** (the same five
variants as the server's `[logging] time_format`: date and time / RFC 3339 in UTC / time
only / Unix / none). If you plan to compare the app log against the server's, set
`RFC 3339` on both sides. It applies immediately; already-written lines keep their stamp.

> **iOS.** The iPhone/iPad client lives in [`qeli-ios/`](../../../qeli-ios/README.md) and
> mirrors Android feature for feature: the same profiles, `qeli://` links and QR codes, the
> same wire modes, an English/Russian UI, a widget and a Control Center toggle. It is
> **built from source on macOS** (Xcode 16+, see its README) — there is no prebuilt binary
> in the releases, and it has not yet been exercised on a physical device. The
> platform-imposed differences: per-app routing is MDM-only, and VPN On Demand stands in
> for boot auto-connect — see [`qeli-ios/PARITY.md`](../../../qeli-ios/PARITY.md).

> **macOS 0.8.3:** choose `Qeli-macos-arm64.tar.gz` for Apple Silicon or
> `Qeli-macos-x86_64.tar.gz` for Intel. Each archive contains a self-contained
> `Qeli.app`; do not combine their contents. macOS 15 or newer is required.
>
> ⚠️ **macOS — first launch.** The app is **ad-hoc** signed (not notarized by Apple), so
> Gatekeeper blocks it and it **won't open** on a double-click. Clear the quarantine once
> in Terminal:
> ```bash
> xattr -cr /Applications/Qeli.app
> ```
> (see [qeli-mac/README.md](../../../qeli-mac/README.md)).

### 8.2. Linux CLI client

Updated development 0.8.2 clients set their owned Linux TUN queue to `1000`
packets without extra configuration. To select a value, add `tun.tx_queue_len = 1000`
(or `500` for the previous lab size) to `[qeli]` in the client file itself.
Stop/start that client after editing; a server reload does not apply it.
Omit the key with `dev_attach=true`. Older binaries need an update first;
there is no auto mode. [Contract and verification](CONFIG.md#client-tun-tx-queue).
[Lab report](../reports/TUN-QUEUE-SIZE-2026-10-16.md)
and [queue-size recommendations](../reports/TUN-QUEUE-SIZE-2026-10-16.md#choosing-a-size).

```bash
sudo cp /etc/qeli/client.conf.example /etc/qeli/client.conf
sudo nano /etc/qeli/client.conf
```

Minimum (see [`client.conf`](../../../qeli/config/client.conf) — every key documented):

```ini
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = alice
pass   = s3cret
# from `qeli show-identity` (REQUIRED under H-1)
key    = 33f399e6…d532450
# must match the profile's obf.mode
mode   = fake-tls
sni    = www.cloudflare.com

# local routing (NOT carried in a qeli:// link — file only):
# true = full-tunnel (all traffic through the VPN)
gateway     = false
# also route private networks + server-pushed ones
route_local = false
# block leaks while the tunnel is down (full-tunnel)
kill_switch = false
# tunnel = per-link DNS through systemd-resolved; off = platform-managed DNS
dns         = tunnel
```

On Linux, `dns = tunnel` requires `busctl`, active systemd-resolved and its stub in `/etc/resolv.conf`. Client and resolved must share a network namespace, and client and D-Bus broker a PID namespace. For platform-managed DNS, use `dns = off`/`system`. [Exact contract](CONFIG.md#linux-tun-and-dns-system-commands).

Managed DNS on Linux also requires `SO_NETNS_COOKIE` and a trusted state directory without symlinks or group/world write: `$STATE_DIRECTORY`, otherwise `/var/lib/qeli`. Routes, DNS, sysctls and server firewall journals share this root. Stop the old client cleanly before upgrading; retained v1 markers require administrator recovery when they match the new link. [V2 format and recovery](TROUBLESHOOTING.md#650-linux-dns-lease-ownership-and-recovery-markers).

Legacy global `dns-backup.json`/`dns-holders` are not restored automatically: startup preserves them and requires administrator recovery even with `dns = off`/`system`. Stop the old client cleanly before upgrading. [Procedure §6.20](TROUBLESHOOTING.md#620-linux-legacy-resolver-recovery-failed-backup-kept).

The managed Linux client also requires `SO_NETNS_COOKIE` and trusted writable `/var/lib/qeli` for its durable route journal, even with `dns = off`/`system`. Preserve this directory across restarts; all clients sharing a network must see the same journal. [Route recovery](OPERATIONS.md#client-physical-route-recovery).

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

Fill in the `[web]` section and restart. **Start with loopback** — this is the default and
needs nothing opened in any firewall:

```ini
[web]
enabled = true
bind = 127.0.0.1
port = 8080
# native HTTPS (self-signed auto; the browser warns once)
tls  = true
# default host for share links
# public_host = vpn.example.com
```

Reach it from your own machine over an SSH forward:

```bash
ssh -L 8080:127.0.0.1:8080 root@<server>   # then open https://127.0.0.1:8080
```

Only if you genuinely need the panel on a public address, publish it **with an allowlist —
not without one**. `allowed_ips` is the only thing besides the password standing between the
open internet and an interface that manages users, rewrites the config, rotates identity
keys and restores backups:

```ini
[web]
enabled = true
bind = 0.0.0.0
port = 8080
tls  = true
# REQUIRED here — your own address(es)
allowed_ips = 203.0.113.4
# public_host = vpn.example.com
```

`install-qeli-server.sh` refuses to create the public variant without an allowlist; do not
hand-write what the installer declines to produce.

```bash
sudo systemctl restart qeli
```

> **Fail-closed:** with an empty `password_hash` the panel won't start on ANY bind,
> loopback included (since 0.7.12 — a loopback bind used to be exempt and served an open
> panel). The VPN `:443` still works — it's a separate process. `qeli set-web-password`
> sets the hash; `web.insecure_no_auth = true` is the deliberate opt-out. Open port
> `8080` in your firewall.

### 9.2. Using it

Open `https://<bind>:8080`, log in as `admin`.

- **Quick start** — its **own item in the left nav** (not a Dashboard tab). A table of all
  **10** masking modes: `reality-tls`, `reality`, `fake-tls`, `obfs-ws`, `obfs-none`,
  `plain`, `udp-fake-tls`, `udp-quic`, `udp-obfs`, `obfs-awg`. The row's **Launch** button
  builds a ready profile (TUN/NAT/DNS/pool/obfuscation), saves it and restarts the server.
- **Config** — every profile field on one page (Bind/TUN/Pool/Routing/DNS/Obfuscation/
  Performance), incl. pushed routes and NAT; the **Global** tab — identity keys (view +
  **Rotate**), Web UI, H-1. Buttons: **Save** writes the config to disk; **Apply & Restart**
  saves and does a full `systemctl restart` (applies everything, panel socket included);
  **Reload** re-reads the file from disk, discarding unsaved edits.
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
  file). Ready examples — [`client-reality.conf`](../../../qeli/config/client-reality.conf) and
  [`client.conf`](../../../qeli/config/client.conf) (all modes and keys).
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

## 10. CLI reference & diagnostics

`qeli` is a single binary with subcommands; there is also a thin client binary
`qeli-client`. Commands split by **how** they talk to the server: they either edit the
on-disk config (needs a restart) or go over the control socket (applied live). `qeli
--help` and `qeli <command> --help` print the same.

### 10.1. Run modes (`-c/--config`)

```bash
qeli server        [-c /etc/qeli/server.conf]   # server (supervisor + data-plane worker)
qeli client        [-c /etc/qeli/client.conf]   # client
qeli check-config  [-c <path>] [--client]        # validate a config and exit (see §4); --client = a [qeli] file
qeli-client        [-c /opt/etc/qeli/client.conf] # thin client for routers/headless (Entware), --config only
```
> The hidden `qeli _worker` is the internal data-plane child spawned by `server`. Do not run it by hand.

### 10.2. Users & identity

These edit the **on-disk config/keys** (`-c/--config`, default `/etc/qeli/server.conf`),
**not** the socket — where they change the config or a key, restart the service:

```bash
# add a user (Argon2-hashed password) to the users file:
sudo qeli add-client alice \
     -p 'secret' \            # --password; omit to generate + print it ONCE
     --profiles tcp,reality \ # restrict to profiles (empty = all)
     --static-ip 10.9.0.100 \ # pin a tunnel IP (optional)
     --max-sessions 2 \       # 0 = group default
     --link --host vpn.example.com:443 --link-profile reality   # print a qeli:// link (+QR)

# RE-ISSUE the link for an EXISTING user (no password to retype):
sudo qeli share-link alice \
     --host vpn.example.com:443 \  # omit to use web.public_host
     --profile reality \           # defaults to the first profile
     --label 'My VPN'              # defaults to <profile>-<port>

sudo qeli set-web-password --username admin [-p 'password'] [--no-enable]  # panel login (Argon2id); §9.1
sudo qeli show-identity                     # each profile's pubkey (clients pin key=); creates keys if absent
sudo qeli rotate-identity reality           # regenerate a profile key → clients update key=, restart to apply
```

#### 10.2.1. `share-link` — re-send an existing user their config

Answers "the client lost their settings / got a new phone — how do I hand out the config
again". `add-client` cannot: it **creates** a user and errors out on an existing name.

```
qeli share-link <username> [--host <addr[:port]>] [--profile <name>]
                           [--label <text>] [--reset] [-c <config>]
```

| Flag | Default | What it does |
|---|---|---|
| `<username>` | — | **required**: an existing user from the users file |
| `--host` | `web.public_host` from the config | the server's public address for the link; `host:port` overrides the profile's port |
| `--profile` | first profile in the config | which profile to build for (each has its own port, mode, key) |
| `--label` | `<profile>-<port>` | profile caption shown in the client app |
| `--reset` | off | generate a NEW password when the old one cannot be recovered (**destructive**, see below) |
| `-c`, `--config` | `/etc/qeli/server.conf` | path to the server config |

**How it works.** No password to type — and none can be recovered from the hash, which is
one-way. So when a user is created, a reversibly-encrypted copy of the password is stored
next to the Argon2 hash; `share-link` decrypts that copy and puts it in the link. Everything
else comes from the profile automatically: port, transport, wire mode, SNI, obfs key, reality
short_id, awg parameters and the pinned server public key (`show-identity`). Same mechanism
and same code as the panel's share/QR button — links from the CLI and the panel match.

```bash
# typical case: the address is already set in web.public_host
sudo qeli share-link alice

# explicit address and a specific profile
sudo qeli share-link alice --host vpn.example.com:443 --profile reality --label 'My VPN'
```

The output is a `qeli://…` line: send it to the client, show it as a QR, or paste it into
the app.

**When there is no stored copy** (user created before this existed, or the encryption key
changed) the command **refuses** and points at `--reset`:

```bash
sudo qeli share-link alice --reset      # prints the NEW password once
sudo systemctl reload qeli              # required: otherwise the server checks the old one
```

> ⚠️ `--reset` is **destructive**: the config that user is on right now stops working and
> they need the new link. And unlike the panel, the CLI has no channel to the running
> worker, so users must be re-read manually (`reload`) — the command says so in its output.

### 10.3. Live management (control socket, NO restart)

Run one worker with multiple profiles per network namespace. Independent workers need separate network namespaces; changing `QELI_CONTROL_SOCKET` alone does not isolate the network. [Details](OPERATIONS.md#local-control-socket).

Over `--socket` (default `/var/run/qeli/control.sock`) — applied immediately:

```bash
sudo qeli list-clients               # who's connected now + assigned IPs
sudo qeli kick alice                 # drop a user's sessions
sudo qeli disable-user bob           # block (kick + forbid reconnect)
sudo qeli enable-user bob            # allow again
sudo qeli set-bandwidth alice 50     # cap Mbit/s (0 = unlimited)
sudo qeli show-routes alice          # the user's routes
sudo qeli list-blocked               # IPs locked by brute-force protection (wrong password)
sudo qeli unblock 1.2.3.4            # release one address (--all for every one)
```

### 10.4. Misc

```bash
qeli version           # version
qeli version --check   # ask GitHub Releases whether a newer one exists (opt-in, notify only, downloads nothing)

# Let the non-root service user restart its own unit from the panel's "Apply & Restart".
# ONLY needed for a NON-.deb install (the .deb ships the rule) — the panel tells you when
# it is missing. Writes /etc/polkit-1/rules.d/49-qeli.rules; must run as root.
sudo qeli install-polkit                                        # defaults: user=qeli, unit=qeli.service
sudo qeli install-polkit --unit qeli-server.service --user vpn  # non-standard unit/user
sudo qeli install-polkit --dry-run                             # print the rule, write nothing

# Choose the OS user the SERVICE runs as: `qeli` (default, unprivileged) or `root`.
sudo qeli set-service-user root      # switch to root (see the warning below)
sudo qeli set-service-user qeli      # switch back to the unprivileged default
sudo qeli set-service-user root --dry-run          # show what would change
sudo qeli set-service-user root --unit qeli-server.service   # non-standard unit
sudo systemctl restart qeli          # required for either to take effect
```

`systemctl reload qeli` sends SIGHUP to the supervisor, which validates and reloads users/authentication and asks the worker to reload without replacing either process. Invalid INI/users are rejected without publishing new authentication state. Profile/listener/TUN and panel startup settings still need a full service restart. SIGHUP preserves the panel login lockout tracker. [Systemd audit](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).

**What `set-service-user` actually does.** It never edits the packaged unit file
(`/lib/systemd/system/qeli.service`) — dpkg overwrites that on every upgrade and your
change would silently vanish. Instead it manages a **systemd drop-in override**:

| argument | effect |
|---|---|
| `root` | writes `/etc/systemd/system/qeli.service.d/run-as.conf` containing `[Service] User=root / Group=root`, adding `CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER` to the bounded network capabilities and clearing root ambient capabilities; it takes precedence over the packaged `User=qeli`. Lives in `/etc`, so it survives package upgrades. |
| `qeli` | repairs daemon-state ownership under `/etc/qeli` before removing that drop-in (the packaged unit already says `User=qeli`). It preserves `client-links` and `*.bak-*` administrator data, protecting the receipts directory as root0700. A repair failure keeps an existing root override; restart is a separate step. |

Both then run `systemctl daemon-reload`; you restart the service to apply. The command is
idempotent (safe to re-run), requires root, and rejects anything other than `qeli`/`root`.
The unit's hardening — `ProtectSystem=full`, `NoNewPrivileges=true`, the bounded
`CapabilityBoundingSet` — **stays in force either way**. Root adds three filesystem capabilities to read and update private state owned by qeli; the network capability set remains bounded. Switching back removes the drop-in and restores the packaged qeli capability settings.

> ⚠️ **When to run as root — and why you normally should not.**
> The default `qeli` user exists for privilege separation: if the daemon is ever
> compromised, the attacker gets an account that owns nothing but `/etc/qeli` — **not the
> machine**. Running as root removes that account boundary and permits access to other owners’ files.
> The packaged filesystem sandbox and capability bounds still apply, but UID 0 is a much broader privilege. The daemon is reachable from the internet, so this is not a
> theoretical distinction.
>
> Legitimate reasons to pick `root`:
> - a kernel or container that does not honour `AmbientCapabilities`, so the unprivileged
>   service cannot create the TUN device or bind :443 at all (symptom: the profile fails to
>   bind with `Operation not permitted` even though the unit grants the caps);
> - a restricted environment where you cannot install the polkit rule, and you still want
>   the panel's `Apply & Restart` to work (root manages its own unit directly);
> - you keep tripping over the `/etc/qeli` ownership trap (§A.3) and accept the trade-off.
>
> If you do run as root, compensate elsewhere: keep the panel off the public internet
> (`web.allowed_ips`, or a loopback bind + SSH tunnel), and switch back with
> `sudo qeli set-service-user qeli` as soon as the reason is gone.

### 10.5. Diagnostics

```bash
journalctl -u qeli -f                          # server log
sudo qeli list-clients                          # active sessions + assigned IPs
ping 10.9.0.2                                   # ping a client from the tunnel (on the server)
ss -tulnp | grep qeli                           # is it listening on :443 / :8080
```

On the client, check that a `vpn0` interface and routes appeared (`ip a`, `ip route`).

> **Deep obfuscation diagnostics.** For a timeline of packet processing inside the application,
> enable `QELI_TRACE=<file> qeli client …`. Tracing does not confirm network delivery
> (opt-in; records sizes/timing only, never payload; dumps on SIGUSR1). Details
> and a walkthrough in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## 11. Wire modes — which to pick

New profiles use `obf.mode = reality-tls` on the server and `mode = reality-tls` on the client. A new server temporarily accepts the legacy `fake-tls + real_tls=true` server spelling during server-first migration.

| Mode | When |
|---|---|
| `fake-tls` | **default.** TLS-1.3 mimicry, against passive/signature DPI. A good balance. |
| `reality-tls` | strongest current TCP masking: REALITY TLS 1.3 + a genuine H2 carrier and target bridging for unauthenticated probes. Needs `key` + `reality_sid` + matching `sni`; update the server before clients. |
| `obfs` | ChaCha20 stream obfuscation of the whole flow; WebSocket fronting is optional (`front = websocket` / `none`). Needs a shared `obfs_key`. Works over both TCP and UDP. |
| `plain` | no masking — a bare encrypted tunnel (max speed). For trusted networks. |
| QUIC shaping | for **UDP** profiles (`obf.quic.enabled = true`); shallow compatibility masking, not real QUIC/HTTP3. |

A detailed comparison, REALITY setup (short_ids, handrolled), multipath bonding — in
[CONFIG.md](CONFIG.md). Benchmarks of all modes — [BENCHMARK.md](../reports/BENCHMARK.md).

---

## 12. Common problems

- **The server refuses to start: "pool.cidr … contains this host's DEFAULT GATEWAY" /
  "overlaps the existing route …".** That is the pre-flight check, and it just saved your
  access to the box. The tunnel subnet overlaps a network this host already uses. The worst
  case is a `tun.address` equal to the gateway: bringing the TUN up makes the gateway a
  local address, every outbound packet dies in the tunnel, and the server drops off the
  network entirely — SSH and ping included — leaving the provider's console as the only way
  back. Fix by moving the tunnel to a free range (`tun.address = 10.9.0.1`, `pool.cidr =
  10.9.0.0/24`). Inspect your own networks with `ip route` and
  `ip -4 addr`, and verify a config **before** starting with `qeli check-config --config
  /etc/qeli/server.conf` — it runs the same check against the current host.
- **Installed the .deb and "nothing works": the profile won't bind, users and panel
  settings don't persist, the service restart-loops.** Almost always ownership: the service
  runs as `User=qeli` and writes into `/etc/qeli` (identity keys, users file, panel saves),
  while the config and any files you created as root **after** the install stayed root-owned.
  Fix with `sudo qeli set-service-user qeli` + restart — full symptom list and modes in
  §2, "A.3. Fix ownership of `/etc/qeli`".
- **Client passes "identity verified" but drops immediately / `AUTH FAIL … not found`.**
  Check the merged inline `[user:*]` plus `auth.users_file` view (see §3.3): a
  same-named entry from the file takes precedence and can shadow the inline user.
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
- **Locked out after a few wrong passwords.** A per-source-IP anti-brute-force tripped.
  There are **two independent policies**: `[auth] brute_force` guards **VPN logins** (clear
  it with `qeli unblock <ip>` / `--all`), `[web] brute_force` guards the **panel login**
  (clear it only from the panel's **Blocked IPs** page — the CLI cannot reach it: the control
  socket lives in the worker, the panel in the supervisor). Both default to 5 attempts /
  300 s window / 900 s lockout. Wait out the lockout window or restart the server
  (`systemctl restart qeli` clears the in-memory counters).
- **The web panel won't start.** Fail-closed: an empty `password_hash` stops the panel on
  **ANY `bind`, loopback included** — set one with `qeli set-web-password` (§9.1). The VPN
  `:443` is unaffected (separate process).
- **403 on every save in the panel behind a domain/proxy.** Add the domain to
  `web.allowed_origins` (same-origin CSRF); add your IP to `web.allowed_ips`, or you'll
  lock yourself out.

---

## 13. Full removal of qeli

By role — remove only what you installed. `<PORT>` below = your profile's port (e.g. `443`).

### 13.1. Server (Linux)

```bash
# 1. Stop and disable the service
sudo systemctl disable --now qeli

# 2a. Installed from .deb -> remove the package (drops the service, /usr/bin/qeli, the
#     polkit rule). purge also removes the conffiles (example configs):
sudo apt purge qeli

# 2b. Installed manually / by binary -> remove by hand:
sudo rm -f /usr/bin/qeli /usr/local/bin/qeli
sudo rm -f /etc/systemd/system/qeli.service /lib/systemd/system/qeli.service && sudo systemctl daemon-reload

# 3. First inspect/save kernel-tuning-*/restore.txt and restore the required tuning
#    BEFORE deleting /etc/qeli. Then remove configs, identity keys, users, issued links.
#    WARNING: the identity key is gone -> clients that pin it (reality-tls / H-1) will
#    need REISSUED configs. To keep it: sudo cp -a /etc/qeli /root/qeli-backup
sudo rm -rf /etc/qeli

# 4. State, logs, runtime
sudo rm -rf /var/lib/qeli /var/log/qeli /run/qeli

# 5. The service's system user
sudo deluser --system qeli 2>/dev/null; sudo delgroup qeli 2>/dev/null; true
```

Additionally — **if you installed via `install-qeli-server.sh`** (it touches the OS):

```bash
# Before removing /etc/qeli, inspect/save the exact run receipt and follow its
# restore.txt commands for prior persistent files and runtime.before values.
# Deleting tuning files alone does not undo runtime changes. If an old installation
# has no receipt, recover the previous values/files from your own backup or policy.
# Do not unload a tcp_bbr module that may be used by other host connections.

# iptables: qeli removes ITS OWN NAT/MASQUERADE rules on a clean stop (step 1). The
# installer additionally adds MSS clamps in BOTH handshake directions. Inspect leftovers first:
sudo iptables-save | grep -iE 'qeli-nat|MASQUERADE|TCPMSS'
sudo ip6tables-save | grep -iE 'qeli-ipv6|MASQUERADE|TCPMSS'
sudo iptables -t mangle -D PREROUTING -p tcp --dport <PORT> --tcp-flags SYN,RST SYN \
     -j TCPMSS --set-mss 1240 2>/dev/null; true
sudo iptables -t mangle -D OUTPUT -p tcp --sport <PORT> --tcp-flags SYN,RST SYN \
     -j TCPMSS --set-mss 1240 2>/dev/null; true
sudo ip6tables -t mangle -D PREROUTING -p tcp --dport <PORT> --tcp-flags SYN,RST SYN \
     -j TCPMSS --set-mss 1220 2>/dev/null; true
sudo ip6tables -t mangle -D OUTPUT -p tcp --sport <PORT> --tcp-flags SYN,RST SYN \
     -j TCPMSS --set-mss 1220 2>/dev/null; true

# Re-persist only AFTER the delete — otherwise save cements the very rule you just tried
# to remove. Check that the grep above no longer finds anything.
sudo netfilter-persistent save 2>/dev/null; true
```

> **Direction matters.** The installer uses `PREROUTING --dport` for the incoming SYN and
> `OUTPUT --sport` for the outgoing SYN-ACK. Swapping those selectors matches nothing and a
> subsequent `netfilter-persistent save` would preserve the rule you meant to remove.

> If the installer created a previously missing `/etc/iptables/rules.v4` or, for an IPv6
> listener, `rules.v6`, each snapshot is the
> host's **entire** current ruleset for that family, not just qeli's rule. Review either
> existing file before changing or deleting it.

> If the rules were NOT saved to `netfilter-persistent` / `/etc/iptables/rules.v4`, they
> vanish on their own after a reboot.

### 13.2. Client — Linux (Rust CLI)

On restart, the client does not automatically delete an occupied TUN: it waits for
the name to be released. A non-persistent device disappears after its last fd closes.
Before manual deletion, establish that it belongs to the configuration being retired;
`dev_attach=true` leaves it to the external owner. See
[TROUBLESHOOTING.md §6.47](TROUBLESHOOTING.md).

`sysctls.state` may hold recovery entries for several network namespaces. Restore
settings in their original network/PID/time context and preserve the shared state directory
while any client or server still needs it. When upgrading with nonempty v1 state, keep
the journal; see the migration procedure in
[TROUBLESHOOTING.md §6.33](TROUBLESHOOTING.md).
The state removal below applies only when uninstalling every component using it.

A clean stop (Ctrl+C) reverts only its owned per-link DNS, cleans NAT/routes and closes
its TUN descriptors. The kill-switch is released only after successful cleanup. New
sessions leave `/etc/resolv.conf` intact; legacy file backups require manual recovery (§6.20).
For DNS ownership and stale markers see [§6.50](TROUBLESHOOTING.md). After a crash:

Reinstalling a Linux kill-switch over prior protection uses temporary DROP rules `qeli-ks-rebuild:<tun>`. Failure or SIGKILL retains them; successful retry retires them after both required families are ready. Guards may block DNS/loopback until replacement is ready; `allow_ipv*_leak` cannot bypass recovery failure. For manual removal after stopping the owner, inspect guards separately from `QELI_KS_<tun>`. [Procedure §6.79](TROUBLESHOOTING.md#679-linux-kill-switch-rebuild-guard-remains-after-failure).

```bash
sudo pkill -f 'qeli client'                    # kill if it's stuck
# DNS: inspect per-link state and ownership markers first (TROUBLESHOOTING §6.50).
# /var/lib/qeli/dns-backup.json is a legacy resolver-file snapshot, not new-session DNS state.

# Kill-switch (if kill_switch = true). The rules live in a DEDICATED
# QELI_KS_<interface> chain — the name follows `dev = …` so several client instances
# cannot wipe each other's rules. Remove it surgically: drop the OUTPUT jump first
# (a referenced chain can't be deleted), then flush and delete the chain itself. In
# gateway mode a FORWARD jump is added too. Repeat for IPv6 — engage() programs both
# families, and without the ip6tables half v6 egress stays blocked.
#
# The exact chain name is printed to the log when the kill-switch engages; below is the
# example for `dev = vpn0`.
CH=QELI_KS_vpn0
sudo iptables  -D OUTPUT  -j $CH 2>/dev/null; true
sudo iptables  -D FORWARD -j $CH 2>/dev/null; true
sudo iptables  -F $CH            2>/dev/null; true
sudo iptables  -X $CH            2>/dev/null; true
sudo ip6tables -D OUTPUT  -j $CH 2>/dev/null; true
sudo ip6tables -D FORWARD -j $CH 2>/dev/null; true
sudo ip6tables -F $CH            2>/dev/null; true
sudo ip6tables -X $CH            2>/dev/null; true

# Exit node / gateway (if exit_node = true or gateway_nat = true was set). These rules are
# also lifted only on a CLEAN stop, and a crash leaves them — the host then keeps
# masquerading and forwarding long after the tunnel died. Every rule carries a comment:
# qeli-exit-node[:<tun>] (exit_node) or qeli-gw-nat (gateway_nat).
# New exit MASQUERADE rules include the :<tun> suffix.
# Do not remove another live profile's rules or old shared NAT without checking all owners.
sudo iptables -t mangle -S | grep -e qeli-exit-node -e qeli-gw-nat
sudo iptables -t nat    -S | grep -e qeli-exit-node -e qeli-gw-nat
sudo iptables           -S | grep -e qeli-exit-node -e qeli-gw-nat
# Delete them line by line: take a printed line, swap -A for -D and run it as-is, e.g.
#   sudo iptables -t nat -D POSTROUTING -o eth0 -m mark --mark 0x51/0x51 -j MASQUERADE \
#        -m comment --comment qeli-exit-node:vpn0
# ip_forward and rp_filter were changed on the fly — restore them if they had been off:
#   sudo sysctl -w net.ipv4.ip_forward=0
#   sudo sysctl -w net.ipv4.conf.eth0.rp_filter=1        # eth0 = your WAN

sudo ip link del vpn0 2>/dev/null; true        # tun — name from `dev = …`
# Remove the binary, config, state:
sudo rm -f /usr/local/bin/qeli
rm -f ~/qeli-client.conf                        # your client config path
# Complete route recovery (§6.81) first and confirm no server shares this state.
sudo rm -rf /var/lib/qeli                       # only after verified cleanup
```

Before manual recovery, establish that the owning client has stopped. The TUN name
is now reserved even without a kill-switch, including `dev_attach`; independent client
sessions must use distinct `dev` names in one network namespace.
The TUN lease rejects another startup with the same name until the owner exits;
kill-switch additionally restricts conflicting sessions with other TUNs. Releasing
a lease after a crash does not remove the remaining firewall.
[Ownership and IPv6 troubleshooting](TROUBLESHOOTING.md).

> **Never drop the kill-switch with `iptables -F`.** Without a chain name that command
> flushes the **entire** `filter` table — your SSH rules, ufw/fail2ban, Docker, everything
> the administrator configured. qeli keeps its rules in its own `QELI_KS_<interface>` chain
> precisely so it can be removed surgically. On engage the client logs the **OUTPUT**
> removal; in gateway mode also remove the **FORWARD** jump and the ip6tables copies — as
> in the example above.

> On a **combined** host (server + client side by side) `/var/lib/qeli` is shared — don't
> remove it until you've removed the server.

### 13.3. Desktop — Windows / macOS (GUI)

- **Windows:** close the app -> remove `QeliWin` (the portable folder, or via Apps &
  features). The Wintun adapter is ephemeral — created and removed per session, nothing is
  left after Disconnect; routes/DNS are restored there too. Data (profiles / settings /
  device-id) — delete the folders:
  `%AppData%\QeliWin`, `%LocalAppData%\qeli`, `%ProgramData%\QeliWin`.
- **macOS:** close -> delete `QeliMac.app`. `utun` is kernel-managed — gone on disconnect.
  Data — delete `~/.local/share/qeli`; if you enabled autostart, remove the LaunchAgent
  from `~/Library/LaunchAgents` (the file with `qeli` in its name).

### 13.4. Android

Settings → Apps → **qeli** → Uninstall. This removes everything: profiles (in encrypted
storage), device-id, the widget, the QS tile, boot-autoconnect. For a full wipe — revoke
the VPN consent and turn off Always-on VPN (if you enabled it): Settings → Network → VPN → qeli.

### 13.5. Routers

**OpenWrt:**
```sh
/etc/init.d/qeli stop; /etc/init.d/qeli disable
opkg remove luci-app-qeli qeli
rm -f /etc/config/qeli /etc/init.d/qeli /usr/bin/qeli-client
# remove the qeli firewall zone the uci-default created on install:
sec=$(uci show firewall | awk -F. "/\.name='qeli'/{print \$2; exit}")
[ -n "$sec" ] && uci delete firewall.$sec && uci commit firewall && /etc/init.d/firewall restart
```

**Keenetic:** stop and remove the init script, binary and config — reverse the install
steps (see `docs/*/manuals/KEENETIC-DEPLOY.md`).

### 13.6. Docker

```bash
docker compose -f release/docker/docker-compose.yml down      # stop and remove the container
# (-v is pointless here: the compose declares no named volumes, only the ./data bind
#  mounts — the data is removed by the rm -rf ./data below)
docker rmi qeli:latest                                        # image
rm -rf ./data                                                 # the mounted /etc/qeli (configs + keys)
```

---

> Found an inaccuracy or have a setup question — open an issue/discussion in the
> repository. Full documentation map — in the [README](../README.md).

Linux server workers require `SO_NETNS_COOKIE` and a trusted `STATE_DIRECTORY` (normally `/var/lib/qeli`). Preserve that directory across restarts: `server-firewall.state` supports exact cleanup after SIGKILL, including deleted INI profiles. Stop the previous worker before upgrading. [Firewall recovery](OPERATIONS.md#server-firewall-recovery).
