# qeli web panel — installation & usage

> **These docs describe 0.7.12** — the latest released version. `qeli --version` tells you
> what you actually have.

The daemon's built-in admin UI: profiles, users/groups, live clients, identity
keys and `qeli://` link/QR issuance. It runs **inside** `qeli server` (the
supervisor process) and manages everything through the same config / users file
and the control socket.

- **Self-contained:** CSS/JS/fonts are embedded in the binary and served from
  `/assets/*` — **no runtime CDN**, so the panel works on an air-gapped server.
- **Stack:** `axum` + `alpine.js`; REST `/api/*`; the session is a stateless HMAC
  cookie (key = the admin password hash).
- **Languages:** RU/EN dropdown at the bottom of the sidebar (default English;
  the choice is remembered in the browser).

> Full `[web]` key reference — [CONFIG.md](CONFIG.md#web-panel-web). This page is
> how to bring it up and how to use it.

---

## 1. Install / enable

The panel is configured by the server config's `[web]` section. Minimum for safe
access **over a public IP**:

```ini
[web]
enabled = true
# or a specific public IP (an IP is better for the self-signed SAN)
bind = 0.0.0.0
port = 8080
username = admin
# REQUIRED on EVERY bind, loopback included — empty = the panel refuses to start
password_hash = $argon2id$v=19$m=...$...
# native HTTPS (rustls); self-signed cert auto-generated. Then open https://, not http://
tls = true
# (optional) source allowlist. Omitted, empty, or "" = any source.
# allowed_ips = 203.0.113.4, 10.0.0.0/8
# (optional) share-link host; also an allowed CSRF origin
public_host = vpn.example.com
# (optional) extra browser origins for LAN/domain/proxy access without it the panel loads but POST (login/saves) 403s
# allowed_origins = 192.168.88.8:8080
```

After a server restart the panel is at **`https://<bind>:<port>`**.

### Admin password (required)

The server stores only the **argon2id hash** (`web.password_hash`), never the
plaintext. **Fail-closed:** with an empty `password_hash` the panel **refuses to
start on ANY bind, loopback included** (logs an error; the VPN `:443` keeps
running — it's a separate process). Before 0.7.12 a loopback bind was exempt and
served an OPEN panel, which meant full admin for every local process and for any
SSRF on the host; if that is genuinely wanted it now has to be asked for by name
with `web.insecure_no_auth = true`, and the server warns at startup. Ways to set
the hash:

- **`qeli set-web-password` CLI (easiest — for a fresh install with no panel
  access yet):** generates/hashes the password, writes `web.username`/`password_hash`
  straight into the config (preserving comments) and enables the panel:
  ```bash
  qeli set-web-password                    # random password, printed once
  qeli set-web-password --password 'PASS'  # your own password
  qeli set-web-password --username admin --password 'PASS' --no-enable   # creds only
  qeli set-web-password --config /etc/qeli/server.conf                   # default path
  ```
  Then `systemctl restart qeli` (the password is shown only at generation time).
- **In the panel:** Config → Web → "Set admin password" (type a password → it's
  hashed into the field → Save) — once you already have access and want to rotate it.
  A panel save of the `[web]` settings (admin password/username, IP allowlist, CSRF
  origins) takes effect **immediately, without a restart** — a password change also
  invalidates the current session on the spot. Only socket-bound fields (`bind`/`port`/
  `tls`) still need a restart. (The `set-web-password` CLI above is a separate process,
  so it does need the restart.)
- **`argon2` CLI (manual):** `printf '%s' 'YOUR_PASSWORD' | argon2 "$(head -c12 /dev/urandom|base64)" -id -t 3 -m 15 -p 1 -e`
- **Via API** (only when the panel is already reachable — i.e. a password is already
  set, or `web.insecure_no_auth = true`; on a fresh install with no password the panel
  is not running, so use `qeli set-web-password` above instead):
  `curl -s localhost:8080/api/hash-password -H 'Content-Type: application/json' -d '{"password":"..."}'`

### TLS (`tls = true`)

The panel terminates HTTPS itself (rustls, `ring` provider) — no reverse proxy
needed.

- **Self-signed (default):** with empty `tls_cert`/`tls_key` a cert is generated
  at startup and persisted to `/etc/qeli/web-tls-cert.pem` +
  `/etc/qeli/web-tls-key.pem` (key `0600`); the SAN covers the `bind`
  address/IP, `localhost`, `127.0.0.1`. Browsers warn once (traffic is still
  encrypted) — accept/pin it.
- **Your own cert** (no warning, needs a domain):
  ```ini
  tls = true
  tls_cert = /etc/letsencrypt/live/vpn.example.com/fullchain.pem
  tls_key  = /etc/letsencrypt/live/vpn.example.com/privkey.pem
  ```
- With `tls = true` the session cookie automatically gets `Secure`.

> Alternative to publishing: keep `bind = 127.0.0.1`, `tls = false` and reach the
> panel **over an SSH tunnel** (`ssh -L 8080:127.0.0.1:8080 root@server`). Then
> TLS isn't needed — SSH encrypts the transport.

### IP allowlist (`allowed_ips`)

The strongest barrier for a public bind: a list of CIDRs / bare IPs allowed to
reach the panel; everyone else gets `403`. Edit it in Config → Web → "Source-IP
allowlist". **Include your own current IP**, or you'll 403 yourself.

**Allowing any source.** All three of these are equivalent — surrounding quotes are
stripped by the config parser, so `""` is simply an explicit way to write "empty":

```ini
# allowed_ips = …    ; key omitted entirely
allowed_ips =        ; present but empty
allowed_ips = ""     ; identical to the line above
```

With no entries there is no IP filter and security rests on TLS + password + rate-limit.

> **A bare `403` when merely OPENING the panel is always this allowlist.** It is applied
> to every route (pages, assets, API) and returns a 403 with an EMPTY body. CSRF cannot
> cause it: that check exempts `GET`/`HEAD`/`OPTIONS`, and its 403 carries a text body
> naming the rejected origin.
>
> **Gotcha — duplicate keys are folded.** Every `allowed_ips` line in `[web]` is merged
> into ONE list (not "last one wins"). A leftover `allowed_ips = 1.2.3.4` earlier in the
> section keeps the filter active even though the line you are editing looks empty. When a
> 403 makes no sense, `grep -n allowed_ips /etc/qeli/server.conf` and confirm with the
> startup log: `Web panel source-IP allowlist active (N entries)` — no such line = no filter.
> A rejected request is logged as `panel: blocked request from <ip> (not in web.allowed_ips)`.

### Accessing over a LAN IP, domain or reverse proxy (CSRF origins)

To stop a malicious page from making a logged-in admin submit a request, the panel
accepts **mutating** requests (the login POST and every save) only when the browser
`Origin`/`Referer` matches an allowed host. **Allowed by default:** the `bind` address
and loopback (`127.0.0.1` / `localhost` / `[::1]`).

So if you open the panel on a **LAN IP, a domain, or behind a reverse proxy** (anything
other than loopback), the page loads (`GET /login` → `200`) but `POST /login` and every
save return **`403`**. The 403 body now names the rejected origin and tells you exactly what
to add; the log also shows `CSRF: rejected POST … (origin/referer=…)`.

Fix — add that address to the allowed origins in `[web]`, then `systemctl restart qeli`:

```ini
[web]
# your LAN IP / domain — host or host:port
allowed_origins = 192.168.88.8:8080
# public_host is also accepted as an origin; a host with no port also matches the bind port
```

Or, without editing the config, reach the panel over an SSH tunnel to loopback (always
allowed): `ssh -L 8080:127.0.0.1:8080 root@<server>` → open `http://127.0.0.1:8080`.

**Behind a reverse proxy at a sub-path** (e.g. `https://host/qeli/` instead of the domain
root): set `base_path = /qeli` in `[web]` and proxy the prefix through **without** stripping
it. The panel then re-roots all its assets, API calls and redirects under the prefix and
honors `X-Forwarded-Prefix`. Full nginx example — see "Reverse-proxy sub-path" in
[CONFIG.md](CONFIG.md).

### What else is enforced (automatically)

- **Security headers** on every response: HSTS (when `tls`), `X-Frame-Options:
  DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, CSP (same-origin).
- **CSRF** — mutating requests (the login POST and every `/api/*` save) are checked
  against `Origin`/`Referer`; only the `bind`, loopback and configured origins are
  accepted (see "Accessing over a LAN IP, domain or reverse proxy" above).
- **Anti-brute-force** — hard lockout per source IP + per-username tarpit (you
  can't lock someone else's account by guessing their name).
- **Session** — `HttpOnly; SameSite=Strict; Path=/` cookie (+`Secure` under TLS),
  HMAC-signed with the password hash (changing the password invalidates sessions).

---

## 2. Usage

### Login
`https://<bind>:<port>` → user `admin` + password. A **language dropdown** (RU/EN)
sits at the bottom of the sidebar (and in the corner of the login page).

### Dashboard
- **Quick start** — mode tiles (REALITY / HTTPS-fake-tls / Obfuscated / QUIC):
  one click builds a ready profile (TUN/NAT/DNS/pool/obfuscation), applies it and
  restarts the server. Presets ship the curated **stealth posture** — Poisson
  flow-shaping instead of the ~15s heartbeat beacon, MTU 1400, and stream bonding
  on the TCP modes.
  **Mobile / LTE:** the large post-quantum handshake can black-hole behind a
  sub-1500 path MTU; on the server apply the OS tuning (outer-port MSS clamp + BBR /
  PMTU probing) — see [CONFIG.md](CONFIG.md) → "sysctl + iptables". The
  `install-reality-server.sh` installer does this automatically.
- **Live clients** — who's connected (profile, IP, uptime, traffic, limit), with
  **Kick** and **Set bandwidth**. Per-profile filter, 10s auto-refresh.

### Host & tunnel metrics on the Dashboard
The two cards at the top of the page refresh **every 2 s** (polling pauses while the
browser tab is hidden and catches up when it comes back). The numbers come from the
supervisor's sampler, which reads cheap `/proc` counters and the worker's aggregate byte
totals **once a second** and keeps a 300-point ring buffer (= 5 minutes). The endpoints
are `/api/system` (latest snapshot) and `/api/metrics` (the history the chart draws) —
nothing parses `/proc` per request.

- **Host load** — CPU % (and the core count), RAM % plus absolute used / total, load
  average (1/5/15), used-space percentage of `/`, a **qeli proc** line (the data-plane
  worker's pid, its CPU % and RSS), **WAN net** — ↓/↑ Mbps across the host's physical
  interfaces (`lo`, `vpn*`, `tun*` are skipped so the tunnel isn't counted twice), and
  **conns · uptime** — established TCP sockets, UDP sockets and host uptime. If the
  sampler is unreachable the heading shows "· unavailable".
- **Tunnel throughput** — the aggregate rate across all live sessions (↓ server→client,
  ↑ client→server) and a 5-minute chart labelled with the peak. The **load** button
  overlays host CPU % (dashed) and the client count (dotted).

Below them are the *Connected clients / Active profiles / Total sent / Total received*
tiles, the per-profile cards and the live-client table (10 s refresh).

### Per-client actions (Kick, Set bandwidth)
Each row of the live-client table carries two operations; both go to the data plane over
the control socket and take effect immediately.

- **Kick** (`POST /api/clients/{username}/kick`) — after a confirmation, drops every
  session that user has on that profile. If they aren't connected the panel answers
  "user … not connected".
- **Set bandwidth** (`POST /api/clients/{username}/bandwidth`) — a limit in Mbps, whole
  number, `0` = unlimited. The value is applied to the live sessions **and written to the
  users file**, so it survives a restart; if that write fails the panel says plainly that
  the limit only applies to the live session and will be lost on restart. A fractional,
  negative or oversized value is rejected with an error instead of silently becoming
  "unlimited".

### Backup / Restore
The **⤓ Backup** and **⤒ Restore** buttons in the header of the *Host load* card.

- **Backup** (`GET /api/backup`) — the browser downloads
  `qeli-backup-<unixtime>.tar.gz`: a `tar czf` of the whole **`/etc/qeli`** directory —
  the server config, the users file, the **per-profile identity keys**,
  `panel-secret.key`, `usage.json`, `notify.json`, the client profiles and the panel's
  TLS cert. Leftovers from earlier restores (`.pre-restore-*`, `.restore-*`) are
  excluded so an archive can't nest inside the next one. The file lands **off the box**,
  on your machine. If any critical file (identity, `server.conf`, `panel-secret.key`, the
  users database) turned out to be unreadable, the download is **refused** with an
  explanation rather than handing you an archive that only looks complete.
  > **The archive holds secrets.** Private identity keys, argon2 password hashes, the
  > reversibly-encrypted user passwords, the panel's session-signing key and client
  > profiles with a plaintext password in them. Treat it as key material — encrypted
  > storage, not a shared drive and not a repository.
- **Restore** (`POST /api/restore`) — pick a `.tar.gz`; the panel warns that the current
  config, users and identity keys will be **overwritten** and uploads the file as the
  request body. The **request-body ceiling is 16 MiB** (`DefaultBodyLimit` in
  `qeli/src/web/api/mod.rs`); anything larger is rejected. Before extracting, the archive
  is vetted: the expanded size must stay under 64 MiB and 5000 entries (decompression-bomb
  guard), every path must sit strictly under `qeli/` (no leading `/`, no `..`), and only
  regular files and directories are accepted — symlinks, hardlinks and special entries are
  refused.
- **A restore is reversible.** Before publishing anything the server snapshots the
  current state to `/etc/qeli/.pre-restore-<tag>.tgz` (`0600`, the newest 5 are kept). If
  the snapshot can't be taken the restore is **refused** — otherwise the change would be
  irreversible. To roll back: `tar xzf /etc/qeli/.pre-restore-<tag>.tgz -C /etc` and
  restart.
- Extraction goes into a staging directory, never straight into `/etc/qeli`: the content
  is vetted again (no executable files; `post_up`/`post_down` and `password_command`
  **cannot be introduced or changed** by a restore — the same rule the config editor
  enforces; a restored server config must pass the same profile validation the worker
  runs at startup). Only then are the files moved across with atomic renames.
- Two restores never run at once — the second is refused with "another restore is already
  in progress". After a successful restore you **must restart** to apply it, and a
  *Config restored* notification fires.

### Quick start page
Its own sidebar page: a table of ten masking modes, each launchable with **Launch** —
`reality-tls` (TCP 443, badged "flagship"), `reality` (8443), `fake-tls` (8444),
`obfs-ws` (8445), `obfs-none` (8446), `plain` (8447), `udp-fake-tls` (UDP 8448),
`udp-quic` (8449), `udp-obfs` (8450), `obfs-awg` (TCP 8451). Each row shows the
transport, the port and one line on what the mode does.

What **Launch** does:
1. reads the current config and **checks the port**: if that port+transport is already
   taken by a DIFFERENT profile you get a "Port already in use" popup with a link to
   Config (re-launching the SAME mode just replaces its own profile, which is allowed);
2. asks for confirmation, then builds a profile on top of the server's canonical defaults
   (`/api/config/defaults`): bind `0.0.0.0:<port>`, its own TUN `vpn<N>`, its own
   `10.9.<N>.0/24` subnet and pool, in-tunnel DNS, NAT egress and the obfuscation stack
   for that mode;
3. saves the config (`PUT /api/config`) and restarts the server.

When it's done a modal shows the profile name and endpoint plus, for the modes that need
them, the generated **REALITY short_id** and **obfs pre-shared key** with a Copy button —
these have to go into every client. The same modal reminds you that clients also need the
server's pinned public key (`qeli show-identity`, or Config → Global → Server identity
keys), and for the TCP modes it repeats the mobile/LTE path-MTU warning.

The modes are independent — each gets its own interface, subnet and port — so running
several at once is the recommended production layout (a client connects on whichever port
gets through its network).

### Config
- **Top tabs** — `Global` + one per profile (+ add). A profile's settings are
  **all on one page** (no inner tabs); a **sticky jump nav** (Bind / TUN / Pool /
  Routing / DNS / DHCP / Obfuscation / Performance) is pinned under the header.
- **Profile** — an `enabled` toggle and sections with **every** field: transport/
  bind/identity path, TUN (incl. multi-queue `queues`), IP pool + reservations,
  routing + NAT + pushed routes, DNS + blocklist, DHCP (TAP only — see below),
  obfuscation (mode/cipher/fronting, TLS masking + SNI pool, REALITY +
  `handrolled`/`peek`, padding, heartbeat, fragmentation, http2, traffic-norm,
  anti-fingerprint, QUIC, **multipath**), performance (limits, rate-limit/
  new-session, TCP/TUN buffers).
- **Global** — Authentication (incl. `bind_static_to_session` H-1), Web UI (TLS,
  allowlist, public_host, admin password), Logging, **Server identity keys**
  (show each profile's pinned key + **Rotate**).
- **Saving:** `Save to Disk` (writes the config, applied on next restart) or
  `Apply & Restart` (save + restart now). `Form` / `JSON` / `Raw INI` views (raw
  saves verbatim — comments preserved).

> **`Apply & Restart` needs permission to restart the service.** It runs
> `systemctl restart <unit>`. A **root** service can do this directly; the hardened
> **non-root** `User=qeli` service needs a polkit rule. The **.deb installs it**
> (`/etc/polkit-1/rules.d/49-qeli.rules`) — nothing to do. If you installed some
> **other way** (binary drop-in, tarball), the panel detects the missing rule and
> tells you to run it once on the server:
> ```
> sudo qeli install-polkit                 # defaults: user=qeli unit=qeli.service
> sudo qeli install-polkit --unit qeli-server.service --user vpn   # custom
> ```
> Then `Apply & Restart` works. **Inside a container** systemctl is not available:
> profile/data-plane changes are applied automatically via the in-process worker
> restart; a change to the **panel socket** (`web.bind`/`port`/`tls`/`enabled`)
> needs the container recreated (`docker restart <name>`). The panel now reports the
> exact reason instead of silently doing nothing.

> **DHCP — a common confusion.** In normal **TUN** mode client IPs are assigned by
> the built-in **pool** (Pool section → CIDR/reservations), **not** DHCP. The DHCP
> server is only for **TAP/bridged** setups. With DHCP off, TUN still assigns IPs.

### Restarting the server: worker vs full restart
The panel has two different restarts and the difference matters.

- **Worker restart** (`POST /api/server/restart`) — the supervisor, and with it the panel
  itself, keep running; only the data-plane process is respawned, so the VPN profiles
  (TUN, listeners, DNS, DHCP) are torn down as the old worker exits and rebuilt by a
  fresh one. The panel never goes down — its JS just polls `/api/status` until clients
  reappear. This is what **Launch** on the Quick start page runs.
- **Full restart** (`POST /api/server/full-restart`) — `systemctl restart <unit>` (the
  unit is detected from the process's own cgroup, falling back to `qeli.service`). The
  whole process is replaced, panel socket included. This is what the **Apply & Restart**
  button on the Config page runs.

**A full restart is REQUIRED** for the fields the panel listens on: `web.enabled`,
`web.bind`, `web.port`, `web.tls`, `web.tls_cert`, `web.tls_key` (and `web.base_path`) —
they are bound when the supervisor starts and a worker restart does not reapply them. A
save that touched any of them says so: apply it with a FULL restart.

- **The panel session survives a full restart** as long as `web.persist_session_key` is
  on (the default: the session-signing key is kept in a `0600` file). Turn it off and
  every restart logs everyone out.
- **Permissions.** The restart is pre-flighted so it fails *loudly* rather than silently:
  no systemd (a container or a hand-run process), no `systemctl` binary, or a non-root
  service with no polkit rule at `/etc/polkit-1/rules.d/49-qeli.rules` — in that last case
  the reply tells you to run `sudo qeli install-polkit` (the `.deb` ships the rule
  already). The HTTP reply is sent first and `systemctl restart` runs ~0.8 s later, so the
  browser gets the answer before the process is replaced.
- **Inside a container** systemctl is unavailable; if the change does NOT touch the panel
  socket the panel falls back to the worker restart on its own and says so.

### Raw INI config editor
The third view on the Config page (`GET`/`PUT /api/config/raw`) shows the config **file
verbatim** and writes back exactly the text you submit — **comments and formatting are
preserved**. The `Form` and `JSON` views go through parse-and-reserialize, so
hand-written comments in the file are lost on save; edit a comment-heavy config in Raw
INI (or directly on the server).

Raw saves are guarded exactly like structured ones: the text must parse; `logging.file`
must be inside `/var/log/qeli`; `auth.users_file`, `identity_key` and
`web.tls_cert`/`tls_key` inside `/etc/qeli`; `web.password_hash` must be a valid argon2
hash (the hand editor is the easiest place to lock yourself out with a typo);
`routing.post_up`/`post_down` can neither be introduced nor changed through the panel;
and the config must pass the same profile validation the server runs at startup. Panel
settings apply live, profile/bind/tun changes need a restart.

### Server identity: show & rotate
**Config → Global → Server identity keys** (`GET /api/identity`) lists each profile with
its bind string and its **pinned public key** (hex) — the panel equivalent of
`qeli show-identity`; the key file is created on first read if it doesn't exist yet.

**Rotate** (`POST /api/identity/{profile}/rotate`) generates a new key for that profile.
**The running worker keeps using the OLD key until a restart**, and after the restart
**every client of that profile must be given the new `auth.server_public_key`** — the key
they pinned before will no longer match. In other words rotating means re-issuing the
config/link to all of that profile's clients, so don't do it "just in case".

### Users & groups
- **Create/edit:** enter the password in **plaintext** — the server hashes it
  (argon2id) and stores a reversibly-encrypted copy (for config re-issue, below).
  Fields: bandwidth/burst, static IP, group, max sessions, **allowed profiles**
  (interface isolation), allowed networks, **per-user routes**.
- **Groups** (`/api/groups`) — named templates kept in the same users file next to the
  users (a `[group:<name>]` section) carrying three fields: `bandwidth_limit_mbps`,
  `max_sessions`, `allowed_networks`. A member inherits whichever field it does not set
  itself — **the user's own value always wins**, and when neither sets it there is no
  limit. Groups can be created, updated and deleted; the worker re-reads the users file
  after a change.
- **Data cap & expiry** (the ⚙ button on a user): a lifetime **download** cap (GB, `0` =
  unlimited) and an account **expiry** — set it as *Expire in (days)* or pick a concrete
  **calendar date** (*Or until date*, the two fields stay in sync). On/after the expiry
  the user can no longer connect and any live session is dropped, and a *Quota breach*
  notification fires. The ↺ button resets the lifetime usage counter.
  - **The cap counts DOWNLOAD only** (server→client). Uploads are unmetered, so a user
    can't be locked out by sending. The usage column shows the two directions separately —
    `↓` download (the metered one, drawn against the cap) and `↑` upload — and the bar
    tracks download vs the cap.
- Actions: Enable/Disable (kicks sessions), Delete.

### Usage & quotas
The **Data usage** column of the users table (`GET /api/usage`) shows the lifetime
counters: a "download vs cap" bar, `↓` download (the metered direction), `↑` upload, the
lifetime connection count (`· N×`) and the expiry. The ⚙ (cap & expiry) and ↺ (reset)
buttons are described under Users above.

- **Where it lives.** A separate sidecar file, **`/etc/qeli/usage.json`** — not the users
  file (which holds password hashes and is rewritten on every CRUD), so accounting never
  risks it. The worker writes it atomically; the panel re-reads it on every `/api/usage`
  request and marks who is currently online.
- **How it accrues.** The worker's usage sweep runs **every 10 s**, reads each live
  session's byte counters and folds only the delta since the last pass into the lifetime
  total (idempotent per `session_id`) — so no per-packet work is added to the hot path.
- **The cap counts DOWNLOAD only** — `used_down` (server→client); 1 GB =
  1,000,000,000 bytes, `0` = unlimited. Upload (`used_up`) is tracked and displayed but
  **never capped**, so a user cannot be locked out by sending.
- **What happens over quota.** A new login is refused at authentication
  (`AUTH DENIED … download quota exhausted`), and **the same sweep drops the live
  session**: it is disconnected, its pool IP is released, the log records
  `usage: disconnected … over quota / expired`, and a *Quota breach* notification fires
  (throttled to once an hour per user so a reconnect loop can't spam). A reached expiry
  is handled identically.
- **Setting and resetting** (`POST /api/usage/{username}/limit` and `…/reset`) go through
  the worker over the control socket, so the authoritative users DB is edited and the file
  saved. An invalid number is rejected with an error instead of quietly becoming
  "unlimited" / "never expires". A reset zeroes **both** directions and leaves the cap and
  expiry alone.

### Issuing a config (Share / QR) — no password needed
The **Share/QR** button on a user. Give only the public host (pre-filled from
`web.public_host`, else the last-used one) → **Generate**. **No password entry** —
the server decrypts the stored copy and builds the `qeli://` link + QR. The
password is **not changed**.

- **Legacy users** (created before this feature — no stored copy): the panel shows
  "no stored password" and a **"Reset password & issue config"** button — it
  resets the password once (shows the new one), after which re-issue always works.
  (Reset is the only path: the old plaintext is unrecoverable.)

### Client manager (Client tab) — outbound tunnels
Its own sidebar page, where the panel acts as a **client**: this box dials OUT to OTHER
qeli servers (a client role alongside the server role — e.g. to send its own egress
through a remote server, or to link sites). It has nothing to do with the VPN clients
connecting *to* this machine.

**Adding a profile** — three buttons:
- **Import qeli:// link** — paste a
  `qeli://user:pass@host:443?mode=…&key=…&sni=…&rsid=…` string and, optionally, a profile
  name; without one it is derived from the link's label or its host. An imported profile
  is always **split-tunnel** — a link never carries the full-tunnel flag.
- **Paste INI config** — paste a whole client INI (`[qeli]` + `[logging]`); it is stored
  verbatim, so every client key is available.
- **Add manually** — a form: server `host:port`, tcp/udp protocol, wire mode (`fake-tls` /
  `reality-tls` / `obfs` / `plain`), user and password, TUN device (blank = auto), SNI,
  the **pinned server key** (hex; required for `reality-tls`), REALITY short_id, obfs key
  and fronting, AmneziaWG junk (jc/jmin/jmax), QUIC masking (UDP only), auto-connect on
  start, `route_local` and full-tunnel. The **Raw INI ↦** toggle in the same dialog gives
  the full config, and keys the form doesn't manage survive a round-trip through it.

**Where things live.**
- Profiles: `/etc/qeli/clients/<name>.conf`, mode `0600` (they contain the password in
  plaintext). Names are `[A-Za-z0-9._-]` only, up to 64 characters.
- The TUN device, unless you set one, is auto-assigned: the lowest free `vpnN` that is
  claimed neither by another client profile nor by an interface that already exists on the
  host (including a server profile's TUN).
- Each tunnel's log: `/var/log/qeli/client-<name>.log`, truncated on every Connect.

**Connect / Disconnect.** Connect spawns `qeli client -c <file>` as a child of the
supervisor (inheriting its privileges, so it can bring up its TUN and routes). Disconnect
sends SIGTERM — the client restores DNS and routes and exits; if it hasn't left after 5 s
it is SIGKILLed. **Delete** disconnects first, then removes the profile and its log. A
profile with `autostart = true` is connected when the supervisor starts.

**The status is honest, not "is the process alive".** The list refreshes every 5 s and the
state is derived from the log tail: **● Connected**, **◌ Connecting…**, **⚠ Error —
retrying** (the process is alive but the tunnel is looping on reconnect — e.g.
`reality-tls` with no short_id) or **○ Disconnected**. Next to it are the assigned
internal tunnel IP and the last few log lines.

> **Full-tunnel is dangerous on a server.** The "Full-tunnel (route ALL traffic)" checkbox
> reroutes ALL of this box's traffic through the remote server and can cut off this very
> panel and your SSH — which is why it is off by default and flagged with a warning.
>
> **Hooks are refused.** A panel-managed profile may not carry `post_up`/`post_down` or
> `password_command` (they run through a shell), and `password_file` must live inside
> `/etc/qeli`. If you need hooks, edit the profile file on the host.

### Logs tab
Shows the **tail of the file** named by `logging.file` (`GET /api/logs`).

- If `logging.file` isn't set, the page says plainly that logs go to stderr/journald and
  suggests `journalctl -u qeli -n 200 --no-pager` — the panel cannot read the systemd
  journal itself.
- The path must resolve inside **`/var/log/qeli`**, otherwise you get "log path rejected"
  (so editing the config can't turn into reading an arbitrary file such as `/etc/shadow`).
- The server reads only the last ~4 MiB of the file and returns at most the requested
  number of lines: the selector offers **100 / 200 / 500 / 1000**, the default is 200 and
  the API's hard ceiling is 2000.
- **Filtering:** a level dropdown (All / ERROR / WARN / INFO / DEBUG) and a search box
  (case-insensitive). A search with no level selected is sent to the server and applied to
  the window it read; the level and the search then filter the already-loaded lines in the
  browser — so filtering works within that recent tail, not across the whole log archive.
- **Auto-refresh** (a toggle) re-reads every 5 s and scrolls to the bottom; **Refresh**
  and **Bottom** do the same by hand. The stats bar shows the file path, "showing N / M
  lines" and per-level counts; lines are colour-coded by level.

### Blocked IPs
A dedicated sidebar tab. Lists source IPs **locked by brute-force protection** (repeated
wrong passwords), split into **two independent journals**: **VPN authentication** and
**Panel login**. Each entry shows the address, the failure count, and how long until it
auto-unblocks. **The tab auto-refreshes every 5 s** (background polling, no spinner flicker)
and the "until unblock" value **ticks down each second** — expired rows disappear on their
own, so an active block is visible in real time (previously the list loaded once on open and
a transient lock was easy to miss). The **Unblock** button releases one address, **Clear
all** releases every one — per journal, so releasing a panel lock never touches the VPN
journal. A lock also clears itself after that surface's timeout (`brute_force.lockout_secs`,
default 900 s).
Same from the CLI for the VPN journal: `qeli list-blocked` / `qeli unblock <ip>` (see
GETTING-STARTED §10).

**Lockout policy — two independent policies, edited live on this tab.** Since 0.7.7 the
*Lockout policy* editor carries **two** side-by-side policies:
- **VPN authentication** → `[auth] brute_force`,
- **Panel login** → `[web] brute_force`.

Each has its own **on/off switch**, *Max attempts*, *Window* and *Lockout*, so the tunnel
and the panel are limited (or disabled) separately. **Save policy** applies both live with
no restart and no dropped sessions (it resets that surface's failure counters). Turn a
switch off to disable rate-limiting for that surface entirely (only safe for panel login on
a trusted / loopback bind). The same policies are also editable in **Config → Authentication**
(VPN) and **Config → Web UI** (panel).

> Frequent `New TCP connection from …` from one IP on `reality-tls` in the logs are
> **scanners/probes**, not password guessing: they're transparently bridged to the
> upstream and carry no user. Real attempts show as `AUTH FAIL … user=X — wrong password`.

### Notifications
Outbound alerts on key server events via **Telegram** and a **generic webhook** — two
independent channels, each with its own switch, credentials, event toggles and **Send
test** button. Config lives in `/etc/qeli/notify.json` (editable from the panel or the
file); sends are best-effort and never block the data plane, and outbound TLS certs are
verified. OFF by default (no `notify.json` → no-op).
- **Server name** — a label prefixed to every message (`[name] …`) and put in the
  webhook JSON `server` field, so several servers reporting into one chat / hook are
  distinguishable. Empty = no prefix.
- **Events** (each toggled per channel): *Server start / restart*, *Quota breach* (a
  user hit their data cap or their expiry), *Panel login lockout* (an IP locked after
  too many failed **panel** logins), **VPN auth IP lockout** (an IP locked by
  brute-force protection after repeated wrong **VPN** login/password), *Config
  restored*. Recurring conditions are throttled (≤ once/hour per user or IP).
- The Telegram token is **write-only** (masked after saving); **Send test** delivers a
  probe to one channel using the current (even unsaved) settings.

### Update banner (opt-in)
When `[web] update_check = true`, the panel shows a dismissible **"Update available"**
banner if a newer qeli release exists on GitHub. The check runs in the **operator's
browser** (like the marketing site) — not the server process — so there is no
server-side beacon; it sends nothing identifying and never downloads anything. The
banner offers a **copy-paste update command** matched to the install type (`.deb`:
download → verify SHA256 → `dpkg -i` → restart; Docker: `docker pull`) — you run it.
Default OFF. (Desktop/mobile clients have their own opt-in check in Settings; the CLI
has `qeli version --check`.) See "Update check" in [CONFIG.md](CONFIG.md).

---

## 3. Password storage (model & trade-off)

Authentication uses the **argon2id hash** (irreversible). To allow **re-issuing**
a config for an existing user without knowing the password, a **reversibly-
encrypted** copy of the password is also kept:

- Cipher: ChaCha20-Poly1305, panel key `/etc/qeli/panel-secret.key` (`0600`,
  auto-generated). Stored as `password_enc` (base64) in the users file; **never
  returned over the API**.
- **Trade-off (deliberate):** a server compromise (key + users file) can recover
  these passwords. They're VPN-only credentials; this is how most VPN panels work.
  For a hash-only model with no re-issue, don't set passwords via the panel/CLI
  (Share will then require a reset for each user).

---

## 4. `[web]` cheat-sheet

| Key | Purpose |
|---|---|
| `enabled` | enable the panel |
| `bind` / `port` | address and port (public IP, or `127.0.0.1` for an SSH tunnel) |
| `username` / `password_hash` | admin login and argon2id hash (hash **required on every bind, loopback included** — empty = fail-closed, the panel does not start) |
| `tls` | native HTTPS (rustls) |
| `tls_cert` / `tls_key` | your PEM cert/key; empty = auto self-signed |
| `allowed_ips` | source-IP/CIDR allowlist. Omitted, empty, or `""` = any source. Duplicate lines are folded into one list; a blocked source gets a bare 403 on every route |
| `public_host` | default host for share links (overridable in the dialog); also an allowed CSRF origin |
| `allowed_origins` | extra browser origins (host or `host:port`) accepted for mutating requests — needed for LAN-IP / domain / reverse-proxy access, else login & saves `403` |
| `base_path` | serve the panel under a reverse-proxy sub-path (e.g. `/qeli`); empty = root. See "Reverse-proxy sub-path" in CONFIG.md |
| `csrf` | CSRF same-origin protection (default `true`); `false` disables it — only on a loopback-only bind, else any website you open could drive the panel |
| `update_check` | opt-in "update available" banner (default `false`); the panel checks GitHub in the operator's browser and shows a copy-paste update command. See "Update check" in CONFIG.md |
| `session_ttl_secs` | panel session lifetime (cookie Max-Age + token expiry; default `86400`) |
| `trusted_proxies` | source IP/CIDR of reverse proxies whose `X-Forwarded-For` to trust (for the allow-list and rate-limiting); empty = XFF not trusted |
| `secure_cookie` | `Secure` on the cookie (auto under `tls`; manual behind a TLS proxy) |

All the `[web]` keys above (including `base_path`, `csrf`, `session_ttl_secs`,
`trusted_proxies`, `update_check`) are editable directly in **Config → Web UI** — they
previously required hand-editing the INI.

Server identity, key pinning, H-1, per-profile authorization, limits, wire
modes/REALITY — see [CONFIG.md](CONFIG.md).
