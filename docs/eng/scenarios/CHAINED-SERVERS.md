# Qeli chain: client → A → B → Internet

[← Use cases](README.md)

The client connects to **A** and reaches the Internet through **B**.
A uses Qeli's built-in client in the **Client** tab to connect to B.
Both servers retain their own existing routes and DNS.
Complete configs follow, including firewall, NAT and routing-table commands inside INI.

## Supported version

Run `qeli --version` first:

- **0.8.3:** post_up runs once per process. A route installed by the hook will not restore
  itself after full reconnect; the automatic recovery recipe below does not apply to this version.
- **Planned 0.8.4:** post_up will repeat after successful TUN recreation. This has passed
  candidate testing, but the release is not published yet. The instructions below target this version.

## Contents

[Variant 1: root](#variant-1-root) · [Variant 2: User=qeli](#variant-2-userqeli)

[Prerequisites](#prerequisites)

1. [Server B config](#1-server-b-config)
2. [Server A config](#2-server-a-config)
3. [A's connection to B](#3-as-connection-to-b)
4. [Start and check](#4-start-and-check)

[Startup and recovery](#startup-and-recovery)

[Reverting root execution](#reverting-root-execution) · [Minimum checklist](#minimum-checklist)

## Choose service privileges

Qeli is already [installed](../manuals/GETTING-STARTED.md) on A/B. Administrative commands run
in a root shell, but the service can use another account. Check on A/B:

```sh
systemctl show qeli -p User -p Group -p AmbientCapabilities -p CapabilityBoundingSet -p NoNewPrivileges
```

Choose **for each server separately**:
[variant 1 — root](#variant-1-root) or [variant 2 — User=qeli](#variant-2-userqeli).
If unsure about the non-root unit, use the described root variant only after considering
the risks below. Non-root requires unit verification; autostart itself does not require root.

Back up configs, ownership/permissions and service drop-ins. Perform initial setup
without VPN clients: `systemctl stop qeli` on A/B. Keep SSH sessions open.

### Variant 1: root

The tested network hooks ran **as root**. Packaged services usually run as user qeli.

This increases the impact of Qeli mistakes/compromise: hooks execute shell commands
with the process's privileges. **Do not change the service user just for autostart**;
the flag does not require it. Root here concerns the privileged network-hook recipe.
First back up configs with ownership/permissions and existing service drop-ins;
do not overwrite an existing chain.conf. Changing User alone does not guarantee key/
directory access under a restrictive unit/sandbox; package UID migration was not separately tested.

If the service already runs as root, its User/Group need not change. For an explicit
switch to root, create this file on the relevant server:
`/etc/systemd/system/qeli.service.d/chain.conf`:

```ini
[Service]
User=root
Group=root
```

Create the parent directory with `install -d /etc/systemd/system/qeli.service.d`.
This changes the existing service user, not the number of server services.
Only an administrator should edit INI commands.
After saving the step 1–3 configs, only for the root variant on A/B:
`chown root:qeli /etc/qeli/server.conf; chmod 640 /etc/qeli/server.conf`.
On A: `chown root:root /etc/qeli/clients/upstream.conf; chmod 600 /etc/qeli/clients/upstream.conf`.

Continue to [prerequisites](#prerequisites); you can skip variant 2.

### Variant 2: User=qeli

Retain `User=qeli` / `Group=qeli`; do not apply variant 1's root override.
This variant requires unit/permission verification, not simply replacing User=root.
The stock package unit already supplies network capabilities. Hooks and the built-in
client inherit service privileges, not automatic root access.

1. **Run CLI as the service user.** For example, step 1 on B:

   ```sh
   sudo -u qeli qeli add-client upstream --profiles chain --static-ip 10.80.2.2 --config /etc/qeli/server.conf
   sudo -u qeli qeli show-identity --config /etc/qeli/server.conf
   ```

   Apply the same prefix to A's add-client, show-identity, set-web-password and check-config.
   Here sudo switches user rather than elevating privileges: your shell is already root.
   A plain `sudo -u qeli` does not reproduce the running systemd unit's capabilities,
   so it is not a valid network-hook test.
2. **File permissions.** Before the first CLI call, qeli needs access to the server
   config, users_file, identity key and their directories. New configs for this variant
   should be owned by qeli:qeli with mode 0600. For step 3 use
   `install -d -o qeli -g qeli -m 700 /etc/qeli/clients`; upstream.conf must also be
   readable by qeli and trusted for hooks. Systemd manages /run/qeli and package state/log
   directories. Preserve existing keys; adjust only the specific necessary files,
   not a recursive chown of all /etc/qeli.
3. **Network privileges.** CAP_NET_ADMIN is needed for TUN, ip rule/route and firewall;
   the package unit also grants CAP_NET_RAW and CAP_NET_BIND_SERVICE. Retain them in
   AmbientCapabilities and CapabilityBoundingSet. With a custom unit, also inspect its
   sandbox and /dev/net/tun access. Capabilities do not bypass file permissions; for
   example, denied /run/xtables.lock access needs a separate administrator decision.
4. **Verification.** After normal step 4 startup, check hook logs and actual rules/routes.
   Do not proceed past Permission denied or Operation not permitted until file/unit
   restrictions are fixed. Do not put sudo in INI: the package's NoNewPrivileges=true
   prevents privilege elevation this way. Do not use chmod 777, blanket NOPASSWD sudoers
   or setcap on shell/ip/iptables.

For another service UID, substitute its account/group for qeli in these examples.
**Qualification limit:** this chain was tested as root. The User=qeli instructions above
describe requirements/setup, not an independently qualified lab run. Do not attribute
the root series' results to it.

## Prerequisites

Follow only the variant selected above. Common-step `qeli ...` commands illustrate root;
with variant 2 add `sudo -u qeli` and retain qeli ownership/permissions.

Replace these values. VPN user passwords are not the web-panel password.

| Variable | Where to obtain it | Where it is used |
| --- | --- | --- |
| `A_IP` | A's external IPv4 | End client C: `server = A_IP:4553` |
| `B_IP` | B's external IPv4 | Built-in A → B client: `server = B_IP:4553` |
| `B_WAN` | On B: interface after `dev` in `ip route get 1.1.1.1` | Every B_WAN in B's post_up **and** post_down |
| `PASSWORD` | Password from `add-client upstream` on B, step 1 | A → B client's `pass` |
| `B_PUBLIC_KEY` | Chain profile's public key from `show-identity` on B | A → B client's `key` |
| `C_PASSWORD` | Password from `add-client c` on A, step 2 | End client C's `pass` |
| `A_PUBLIC_KEY` | Chain profile's public key from `show-identity` on A | End client C's `key` |

TCP/4553 must be reachable on A/B through existing INPUT/provider firewalls;
their general policies are not changed here. Do not transfer private identity keys.
Replacing B_WAN only in post_up leaves post_down unable to remove NAT on shutdown.
Check both lines.

Networks `10.80.1.0/24` (A's clients) and `10.80.2.0/24` (A → B) must not overlap
existing networks. Table **208**, priority **20800**, and names `qeli-in/qeli-out/qeli-b`
must be unused or exclusively owned by this recipe. Inspect
`ip -4 rule show` and `ip -4 route show table 208`; a missing table is normal.
Do not remove foreign entries.

These examples are for a dedicated setup: inner IPv4, TCP FakeTLS and Recordizer required.
On an existing server, retain global/auth sections and the users file;
copy only the complete new `[profile:chain]` section.
Needs `ip`, `iptables`, `ip6tables`, `grep`. No `nft` commands are used.

**The web panel is optional.** In the complete examples, `[web] enabled=false`
deliberately disables only the HTTP interface. The client manager inside the main Qeli
still reads `autostart=true` and starts A → B. If your panel is already configured,
retain its existing `[web]` section instead of replacing it with the example.

## 1. Server B config

**Purpose:** B accepts A and performs NAT for A's client subnet.
Complete `/etc/qeli/server.conf` on B:

```ini
[auth]
users_file = /etc/qeli/users.conf
require_client_key_proof = true

[web]
enabled = false

[logging]
level = info

[profile:chain]
enabled = true
identity_key = /etc/qeli/identity/chain.key
bind.address = 0.0.0.0
bind.port = 4553
bind.transport = tcp
tun.name = qeli-b
tun.address = 10.80.2.1
tun.mtu = 1400
pool.cidr = 10.80.2.0/24
pool.exclude = 10.80.2.1
routing.nat.enabled = false
routing.forward_private = true
routing.ipv6.mode = off
routing.post_up = set -e; iptables -w 5 -t nat -C POSTROUTING -s 10.80.1.0/24 -o B_WAN -m comment --comment qeli-chain -j MASQUERADE 2>/dev/null || iptables -w 5 -t nat -A POSTROUTING -s 10.80.1.0/24 -o B_WAN -m comment --comment qeli-chain -j MASQUERADE
routing.post_down = set -e; if iptables -w 5 -t nat -C POSTROUTING -s 10.80.1.0/24 -o B_WAN -m comment --comment qeli-chain -j MASQUERADE 2>/dev/null; then iptables -w 5 -t nat -D POSTROUTING -s 10.80.1.0/24 -o B_WAN -m comment --comment qeli-chain -j MASQUERADE; fi
dns.enabled = false
obf.mode = fake-tls
obf.recordizer.policy = required
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 1000
obf.heartbeat.jitter_ms = 100
```

Create A's user and obtain B's public identity:

```sh
qeli add-client upstream --profiles chain --static-ip 10.80.2.2 --config /etc/qeli/server.conf
qeli show-identity --config /etc/qeli/server.conf
```

Save the password and chain profile's public key. In `/etc/qeli/users.conf`, add
`client_subnet` to the **existing** `[user:upstream]` section.
Only the relevant fragment is shown below; retain every other line in the section.
`EXISTING_HASH` denotes the generated hash: **do not paste this word over your hash**.

Before:

```ini
[user:upstream]
password_hash = EXISTING_HASH
```

After:

```ini
[user:upstream]
password_hash = EXISTING_HASH
client_subnet = 10.80.1.0/24
```

This tells B that 10.80.1.0/24 is behind A.
Retain the hash and other fields; do not create a second `[user:upstream]` section.
If this subnet is already present, do not duplicate it; retain other client_subnet entries.

## 2. Server A config

**Purpose:** A accepts end clients; separate table 208 sends their packets to qeli-out.
Complete `/etc/qeli/server.conf` on A:

```ini
[auth]
users_file = /etc/qeli/users.conf
require_client_key_proof = true

[web]
enabled = false

[logging]
level = info

[profile:chain]
enabled = true
identity_key = /etc/qeli/identity/chain.key
bind.address = 0.0.0.0
bind.port = 4553
bind.transport = tcp
tun.name = qeli-in
tun.address = 10.80.1.1
tun.mtu = 1400
pool.cidr = 10.80.1.0/24
pool.exclude = 10.80.1.1
routing.nat.enabled = false
routing.forward_private = true
routing.ipv6.mode = off
routing.post_up = set -e; iptables -w 5 -t mangle -C FORWARD -i qeli-in ! -o qeli-out -j DROP 2>/dev/null || iptables -w 5 -t mangle -I FORWARD 1 -i qeli-in ! -o qeli-out -j DROP; ip6tables -w 5 -t mangle -C FORWARD -i qeli-in -j DROP 2>/dev/null || ip6tables -w 5 -t mangle -I FORWARD 1 -i qeli-in -j DROP; ip -4 route replace blackhole default metric 32767 table 208; ip -4 rule show | grep -q '^20800:' || ip -4 rule add priority 20800 iif qeli-in lookup 208
routing.post_down = set -e; if iptables -w 5 -t mangle -C FORWARD -i qeli-in ! -o qeli-out -j DROP 2>/dev/null; then iptables -w 5 -t mangle -D FORWARD -i qeli-in ! -o qeli-out -j DROP; fi; if ip6tables -w 5 -t mangle -C FORWARD -i qeli-in -j DROP 2>/dev/null; then ip6tables -w 5 -t mangle -D FORWARD -i qeli-in -j DROP; fi; if ip -4 rule show | grep -q '^20800:.*iif qeli-in.*lookup 208'; then ip -4 rule del priority 20800 iif qeli-in lookup 208; fi; if ip -4 route show table 208 2>/dev/null | grep -q '^blackhole default.*metric 32767'; then ip -4 route del blackhole default metric 32767 table 208; fi
dns.enabled = false
obf.mode = fake-tls
obf.recordizer.policy = required
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 1000
obf.heartbeat.jitter_ms = 100
```

A has its own identity; do not copy B's private key. Create an end user:

```sh
qeli add-client c --profiles chain --static-ip 10.80.1.10 --config /etc/qeli/server.conf
qeli show-identity --config /etc/qeli/server.conf
```

**Only if A's web interface is wanted but not configured yet:** run
`qeli set-web-password --config /etc/qeli/server.conf`. This **modifies that file**:
it stores the panel password hash and sets `[web] enabled=true`. The resulting file
on disk is the final config; do not overwrite it with the enabled=false example again.
Step 4 startup applies the change. The panel binds localhost by default; use your existing
SSH tunnel or HTTPS proxy. If no web interface is needed, skip this command:
client autostart still works.

## 3. A's connection to B

**Purpose:** configure the connection to B using Qeli's existing built-in client on A.
It creates qeli-out and installs its working route.

If the connection to B already exists in the **Client** tab, reuse that profile:
apply the settings below to its file, retaining its name. **Do not create a second profile.**
Edit hooks locally in the file, not through the panel form.

`/etc/qeli/clients/upstream.conf` below is an example filename **on A**. If your profile
has another name, use it in subsequent config/log paths too.
Qeli already uses `/etc/qeli/clients`; only if it is missing, run
`install -d -m 700 /etc/qeli/clients`. No additional client installation is needed.

Complete connection config:

```ini
[qeli]
autostart = true
server = B_IP:4553
proto = tcp
mode = fake-tls
user = upstream
pass = PASSWORD
key = B_PUBLIC_KEY
dev = qeli-out
gateway = false
pull_routes = false
forward = true
gateway_nat = false
kill_switch = false
ipv6 = off
allow_ipv6_leak = false
dns = off
reconnect = true
timeout = 3
post_up = ip -4 route replace default dev qeli-out metric 10 table 208
post_down = if ip -4 route show table 208 2>/dev/null | grep -q '^default dev qeli-out.*metric 10'; then ip -4 route del default dev qeli-out metric 10 table 208; fi
```

`gateway=false`, `pull_routes=false` and `dns=off` preserve A's own egress and DNS.
Do not enable NAT on A. `autostart=true` starts this client with the main Qeli;
`reconnect=true` keeps retrying when B is temporarily unavailable.

All network actions are already configured:

- `routing.forward_private=true`: Qeli enables IPv4 forwarding and its own FORWARD
  allowances on A/B. These need not be added manually.
- Server `routing.post_up/post_down`: additional firewall/table 208 entries on A
  and tagged NAT on B.
- Client `post_up/post_down`: only the working default through qeli-out in table 208.

**Copying hooks:** each post_up/post_down must occupy one physical INI line, from
the parameter name to the final command character. Browser line wrapping is fine;
do not insert Enter, line-continuation backslashes or ellipses. Edit the host file,
not the panel. After saving, run both step 4 check-config commands; they do not replace
runtime route checks.

After pasting, check **the `[profile:chain]` section** has exactly one
`routing.post_up = ...` line and one `routing.post_down = ...` line; the client's
`[qeli]` section needs one post_up and one post_down. Other server profiles may have
hooks of their own; do not count them. Compare the entire commands too: the right
line count does not prove that a command was copied without truncation.

`-C ... || -I/-A` and `route replace` avoid duplicates;
post_down checks that an entry exists before deleting it.
The client does not delete server rules; A's server does not delete the client's working route.
There is no `iptables -F` or whole-table flush; foreign rules are left alone.
The rule check assumes exclusive ownership of priority 20800.

`post_down` runs on clean shutdown; execution is not guaranteed after SIGKILL or power loss.
Therefore post_up tolerates retained entries.
Qeli removes its standard FORWARD rules itself; the server's own default route is not replaced.

## 4. Start and check

**Purpose:** validate configs, establish A → B and check client egress through B.

Run on A/B (with User=qeli, prefix qeli commands with `sudo -u qeli`):

```sh
qeli check-config --config /etc/qeli/server.conf
systemctl daemon-reload
```

Also run `qeli check-config --client --config /etc/qeli/clients/upstream.conf` on A.
Fix any config errors before proceeding.
Run `systemctl start qeli` on B, then on A.

The main Qeli on A finds profile `upstream` and starts the client itself.
If the web panel is enabled, the **Client** tab shows its autostart marker and connection
status. Without the panel, use the checks below and the client log.
Do not start a second `qeli client` manually. After connection:

- On A: `ip -4 rule show` has one 20800 entry with `iif qeli-in lookup 208`;
  `ip -4 route show table 208` has default via qeli-out metric 10 and blackhole metric 32767.
- On B: `ip route get 10.80.1.10` shows qeli-b.
- End client: connect to `A_IP:4553`, using user c and **A's** public identity.

For end client C, use a separate file (password and key belong to **A**, not B):

```ini
[qeli]
server = A_IP:4553
proto = tcp
mode = fake-tls
user = c
pass = C_PASSWORD
key = A_PUBLIC_KEY
dev = qeli-c
gateway = true
forward = false
kill_switch = true
ipv6 = off
allow_ipv6_leak = false
dns = tunnel
dns_servers = 1.1.1.1
reconnect = true
```

This client needs no custom network hooks: Qeli manages its routes and DNS.
Replace 1.1.1.1 with your external resolver if needed. Do not use A's DNS proxy.
Linux `dns=tunnel` needs working systemd-resolved; see [CONFIG](../manuals/CONFIG.md).

Check separately on A, B and the end client:

```sh
curl -4 -fsS --max-time 10 --noproxy '*' https://api.ipify.org
```

A should retain IP A, B should retain IP B, and the client should show IP B.

## Startup and recovery

A → B uses **Qeli's built-in client manager**, the same one controlled by the panel,
not a separate client service. HTTP-panel availability is not required for autostart.
On A and B enable the existing main Qeli service:

```sh
systemctl enable qeli
```

At A's boot, Qeli's manager reads `/etc/qeli/clients/*.conf` and starts profiles
with `autostart=true`. This is the same flag as the panel's auto-connect checkbox.
The main Qeli manages both the server and the outbound A → B client child.

**For hook-bearing configs:** set `post_up/post_down` and `autostart=true` locally
in the step 3 file. Panel/API saves intentionally reject shell commands.
The panel can display/connect/disconnect this profile; do not resave it through
the form that prohibits hooks.

After successful TUN recreation, `route replace` restores the working route in table 208.
Repeated processing of the same generation and carrier recovery preserving the TUN
do not rerun the hook. Post_down remains terminal cleanup, not a paired command on
every reconnect. Post_up must be idempotent.

If A boots before B, `reconnect=true` keeps retrying; the connection and route recover
once B becomes available with the behavior specified in the
[version block](#supported-version).
This client does not replace the servers' own routes or DNS.

The autostart checkbox is not a watchdog for an abruptly exited process.
Use **Connect** in the panel in that case; the main Qeli starts it again after reboot.
For an administratively deleted route on a live TUN, use **Disconnect → Connect**.
For deleted B NAT, use `systemctl restart qeli` on B (restarts its profiles).

Check the **Client** tab, client log `/var/log/qeli/client-upstream.log`, and
server log `journalctl -u qeli -n 100 --no-pager`.
Repeat step 4 checks after recovery.

### Reverting root execution

On A first stop the A → B profile and disable its autostart. Then, on each changed server,
run `systemctl stop qeli` (stops all its profiles). Remove the added hooks or restore
the original configs. If chain.conf existed before setup, restore its backup.
If you created it solely for this recipe, disable **only that file**, retaining a copy:

```sh
mv -n -- /etc/systemd/system/qeli.service.d/chain.conf /etc/systemd/system/qeli.service.d/chain.conf.disabled
systemctl daemon-reload
systemctl show qeli -p User -p Group
```

Do not use `systemctl revert qeli`: it may remove other administrators' overrides.
If chain.conf.disabled already exists, `mv -n` replaces nothing; inspect both files first.
Confirm User/Group have returned to their original values (qeli/qeli in the stock package).
Restore original ownership/permissions of changed configs, keys and directories from
your backup; changing User alone is insufficient. Validate the original config, run
`systemctl start qeli` and inspect `journalctl -u qeli -n 100 --no-pager`.

## Minimum checklist

- [ ] A/B `qeli --version` matches the [conditions at the start](#supported-version); a privilege variant is selected.
- [ ] All table values are substituted; B_WAN is replaced in post_up and post_down, and hook lines are not split.
- [ ] On B, `qeli check-config --config /etc/qeli/server.conf` passes.
- [ ] On A, server check-config and `qeli check-config --client --config /etc/qeli/clients/upstream.conf` pass (with User=qeli, prefix qeli commands on both servers with `sudo -u qeli`).
- [ ] Run `systemctl start qeli` on B before A; enable OS startup with `systemctl enable qeli`.
- [ ] A has one rule 20800 and a working qeli-out default in table 208; B routes 10.80.1.10 through qeli-b.
- [ ] Run step 4's `curl` on A/B/C: A retains IP A, B retains IP B, C shows IP B.

[Candidate qualification report](../reports/CHAINED-SERVERS-084-2026-10-30.md) ·
[Earlier checks](../reports/CHAINED-SERVERS-HOOKS-2026-10-30.md) ·
[Version conditions](#supported-version).
