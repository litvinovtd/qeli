# qeli web panel — installation & usage

> **Documentation status:** current development tree **0.8.3**; planned full-IPv6 release **0.8.3**;
> package version covered by this guide **0.8.3**.
> `qeli --version` reports the version of the binary actually installed.
> See [GitHub Releases](https://github.com/litvinovtd/qeli/releases) for package availability and publication status.
> Links to this version's files work after its publication.

The daemon's built-in admin UI: profiles, users/groups, live clients, identity
keys and `qeli://` link/QR issuance. It runs **inside** `qeli server` (the
supervisor process) and manages everything through the same config / users file
and the control socket.

- **Self-contained:** CSS/JS/fonts are embedded in the binary and served from
  `/assets/*` — **no runtime CDN**, so the panel works on an air-gapped server.
- **Stack:** `axum` + `alpine.js`; REST `/api/*`; the session is a stateless HMAC
  cookie. Its signing key is derived with HKDF from a separate random secret,
  the admin password hash and the session-revocation generation.
- **Languages:** RU/EN dropdown at the bottom of the sidebar (default English;
  the choice is remembered in the browser).

The Tailwind 4 stylesheet targets Safari 16.4+, Chrome/Chromium 111+
and Firefox 128+. These are upstream minimum requirements, not evidence that
every browser/version has been tested. See the
[upstream compatibility guide](https://tailwindcss.com/docs/upgrade-guide).

> Full `[web]` key reference — [CONFIG.md](CONFIG.md#web-panel-web). This page is
> how to bring it up and how to use it.


Failed background reads double the polling interval up to 60 seconds; a successful
read restores the normal interval. Hidden tabs do not poll; manual refresh remains
immediate. API reads have a 15-second timeout.

Share/QR profile selectors label disabled profiles. The first enabled profile is
preferred; a disabled one remains selectable for preparing configuration, but it
will accept connections only after being enabled and the server restarted.

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
  origins) takes effect **immediately, without a restart** when the response reports
  `web_settings_applied: true` — a password change also invalidates the current session.
  If false, the INI is saved but the previous panel settings remain active; the response
  warns about it. Socket-bound fields (`bind`/`port`/`tls`) still need a full restart. (The `set-web-password` CLI above is a separate process,
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
- Each PEM must be a regular file no larger than 4 MiB. Symlinks to regular
  files, including Let's Encrypt's, remain supported. FIFOs and other special
  files are rejected without waiting. If only one auto-generated file remains,
  the panel refuses HTTPS and preserves it: restore the other file from backup,
  or remove **both** files to deliberately generate a new pair.
  `qeli check-config` validates an existing pair with the same TLS loader. When
  the auto-generated pair does not yet exist, it permits first startup without
  creating files. An explicit TLS path requires a trusted server INI: a regular
  file owned by root or the effective UID, with no group/world write or symlink.
  With TLS files outside `/etc/qeli`, panel Backup returns HTTP 409; back up
  the external pair separately.
- With `tls = true` the session cookie automatically gets `Secure`.

> Alternative to publishing: keep `bind = 127.0.0.1`, `tls = false` and reach the
> panel **over an SSH tunnel** (`ssh -L 8080:127.0.0.1:8080 root@server`). Then
> TLS isn't needed — SSH encrypts the transport.

### IP allowlist (`allowed_ips`)

The strongest barrier for a public bind: a list of CIDRs / bare IPs allowed to
reach the panel; everyone else gets `403`. Edit it in Config → Web → "Source-IP
allowlist". **Include your own current IP**, or you'll 403 yourself.

**How to allow access from everywhere.** Choose one of the three alternatives below. They are equivalent — surrounding quotes are
stripped by the config parser, so `""` is simply an explicit way to write "empty":

```ini
# allowed_ips = …    ; key omitted entirely
# present but empty
allowed_ips =
# identical to the line above
allowed_ips = ""
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
allowed): `ssh -L 8080:127.0.0.1:8080 root@<server>` → open `https://127.0.0.1:8080` and
accept the expected hostname warning for the installer-generated certificate. Use `http://`
only when `web.tls = false` was explicitly configured.

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
  HMAC-signed with a key derived from a separate signing secret, the password
  hash and the revocation generation. Changing the password or revoking all
  sessions invalidates existing tokens. With `web.persist_session_key = true`
  (the default), the secret is stored in a file with mode `0600`; with it disabled,
  or if the file cannot be used, a process-local secret ends sessions on restart.

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
  `install-qeli-server.sh` installer does this automatically.
- **Live clients** — who's connected (profile, IP, peer, client build, uptime, traffic,
  limit), with **Kick** and **Set bandwidth**. Per-profile filter, 10s auto-refresh.
  The **Client** column shows the version and platform each session reports over the
  tunnel (e.g. `0.7.14 android`) — the quick answer to "who still has to update". A dash
  means the client does not report one: every build that predates the feature, and the
  GUI clients until they ship the frame. The value is **self-reported and not verified** — any
  authenticated peer can claim any string, so read it as a label, never as proof of what
  is actually running.

### Host & tunnel metrics on the Dashboard
The two cards at the top of the page refresh **every 2 s** (polling pauses while the
browser tab is hidden and catches up when it comes back). The numbers come from the
supervisor's sampler, which reads cheap `/proc` counters and the worker's aggregate byte
totals **once a second** and keeps a 300-point ring buffer (= 5 minutes). The endpoints
are `/api/system` (latest snapshot) and `/api/metrics` (the history the chart draws) —
nothing parses `/proc` per request.

- **Host load** — CPU % (and the core count), RAM % plus absolute used / total, load
  average (1/5/15), used-space percentage of `/`, a **qeli proc** line (the data-plane
  worker's pid, its top-style CPU %, where 100% is one fully busy core, and RSS), **WAN net**
  — ↓/↑ Mbps across the host's physical interfaces (`lo`, `vpn*`, `tun*` are skipped so the
  tunnel isn't counted twice), and **conns · uptime** — established TCP sockets and UDP
  sockets owned by that worker, plus host uptime. Unrelated services in the same network
  namespace are not counted. If the sampler is unreachable the heading shows "· unavailable".
- **Tunnel throughput** — the aggregate rate across all live sessions (↓ server→client,
  ↑ client→server) and a 5-minute chart labelled with the peak. The **load** button
  overlays host CPU % (dashed) and the client count (dotted).

Below them are the *Connected clients / Active profiles / Total sent / Total received*
tiles, the per-profile cards and the live-client table (10 s refresh).

### Transport Health
The **Transport health** sidebar page joins the worker's live sessions with a deliberately
secret-free projection of the configuration currently on disk. Every profile card shows its
listener, state, sessions, bonded streams, traffic and server backpressure drops. Expanding it
shows TUN address/pool/MTU/queues, routing/NAT, DNS, masking/heartbeat/shaping/multipath,
socket/TUN buffers and connection limits. Alerts call out an unavailable worker, missing
`iptables` for requested NAT, observed drops and liveness combinations that could retain a dead
peer. The page refreshes every 5 s and pauses background polling in a hidden browser tab.

Status and Transport health share asynchronous iptables discovery. If the tool is
not found in standard system directories, its PATH `--version` probe has 15 seconds
including waiting for a slot. At most four such async iptables/ip6tables probes run
at once, including Quick Start IPv6 discovery. These two pages skip the probe when
no profile requests NAT. `Could not verify iptables availability` reports a failed
check, such as timeout or denied access; Transport health presents it as a warning.
Confirmed tool absence remains critical. Finding the tool does not verify NAT rules.
[Responsiveness checks and limitations](../reports/audit-0.8.2/AUDIT-Q05-HEALTH-PROBES.md).

The projection selects safe fields individually: obfs/reality credentials, passwords, identity
private keys and session keys are never returned by `/api/transport/health`.

### Per-client actions (Kick, Set bandwidth)
Each row of the live-client table carries two operations; both go to the data plane over
the control socket and take effect immediately.

- **Kick** (`POST /api/clients/{username}/kick`) — after a confirmation, drops every
  session that user has on that profile. If they aren't connected the panel answers
  "user … not connected".
- **Set bandwidth** (`POST /api/clients/{username}/bandwidth`) — a limit in Mbps, whole
  number, `0` = unlimited. The same cap is applied **independently and concurrently** to
  upload and download: for example, `50` means up to 50 Mbps in each direction (up to
  100 Mbps aggregate at full duplex). All multipath streams of a session share their
  direction's allowance; TCP and UDP behave the same. The value is applied to the live
  sessions **and written to the
  users file**, so it survives a restart; if that write fails the panel says plainly that
  the limit only applies to the live session and will be lost on restart. A fractional,
  negative or oversized value is rejected with an error instead of silently becoming
  "unlimited".

### Backup / Restore
The **⤓ Backup** and **⤒ Restore** buttons in the header of the *Host load* card.

- **Backup** (`GET /api/backup`) — the browser downloads
  `qeli-backup-<unixtime>.tar.gz`: a `tar czf` of the whole **`/etc/qeli`** directory —
  the server config, the users file, the **per-profile identity keys**,
  `usage.json`, `notify.ini`, the client profiles and the panel's TLS cert. Leftovers
  from earlier restores (`.pre-restore-*`, `.restore-*`) are
  excluded so an archive can't nest inside the next one; local editor rollback history
  (`.config-history`) is excluded as well, so superseded credentials do not accumulate in
  portable backups. The file lands **off the box**,
  on your machine. If any critical file (identity, `server.conf`, the users database)
  turned out to be unreadable, the download is **refused** with an
  explanation rather than handing you an archive that only looks complete.
  The active config, external users database, per-profile identity keys and explicit TLS
  files of an **enabled HTTPS panel** must all use normal absolute paths below
  `/etc/qeli`. Custom filenames and subdirectories there are supported. If any active path is relative or outside that managed
  root, both panel backup and restore are refused with HTTP 409 instead of silently producing
  or applying a partial archive; use a manual backup that includes every external path.
  > **The archive holds secrets.** Private identity keys, argon2 password hashes, the
  > reversibly-encrypted `password_enc` values and client profiles with a plaintext
  > password in them. Treat it as key material — encrypted storage, not a shared drive and
  > not a repository.
  >
  > **What the archive does NOT contain: the key that decrypts `password_enc`.**
  > `/var/lib/qeli/panel-secret.key` deliberately lives outside `/etc/qeli`, so an
  > unencrypted panel archive never carries both ciphertext and its key.
  > After restoring only a panel archive onto another machine, the Argon2 hashes still
  > authenticate users, but the old passwords cannot be decrypted and re-issued in a
  > `qeli://` link/QR; reset the password to do that. A complete manual disaster-recovery
  > backup must also preserve `/var/lib/qeli`, and the resulting archive must be protected
  > as containing the decryption key. On upgrade the legacy
  > `/etc/qeli/panel-secret.key` is migrated automatically.
  >
  > **The panel's session-signing key is not in the ordinary archive either.** It is a
  > separate file, easy to confuse with `panel-secret.key` because both are "panel keys".
  > The session key lives at `$STATE_DIRECTORY/session.key` — under systemd that is
  > `/var/lib/qeli/session.key`, outside the `/etc/qeli` tree the archive captures; the
  > fallback without `StateDirectory` is `/etc/qeli/.session_key`, and only then is it
  > included. In practice: after restoring onto a different machine, every panel login has
  > to be done again. Not data loss, but not something to discover mid-incident either.
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
- Panel saves, `qeli set-web-password`, and restore share a server-INI sidecar
  lock. Exact restore preserves `.lock` files, and old archived lock files are
  not published over active ones. A manual SSH editor does not take this lock:
  do not edit the INI concurrently with a panel or CLI save.

The restored active INI requires all profile identities: managed paths below
`/etc/qeli` must be supplied as regular 32-byte files, including overlay mode.
Missing keys are never replaced by newly generated identities. Enabled HTTPS
requires a complete readable matching PEM pair; managed paths are checked in
staging, external paths against existing server files. Missing or corrupt
dependencies are rejected before publication. Archive UID/GID values are ignored:
extraction creates files as the server user. Nested `.lock` files retain their
inodes and do not prevent `exact` restore.

Backup/Restore preparation shares 60 seconds across config-lock admission, all tar
commands and preflight. Portable gzip is limited to 16 MiB, pre-restore gzip to 64 MiB;
timeout/overflow never yields a partial archive. An unreadable file makes the rollback
snapshot fail and prevents publication. Once publication starts, filesystem operations
finish under the lock; no hard filesystem I/O deadline is promised. Cancelling a request
does not cancel a running restore. A duplicate restore immediately receives HTTP 409,
including while the first awaits the config lock. [Troubleshooting](TROUBLESHOOTING.md#659-backuprestore-timeout-archive-limit-and-incomplete-snapshot).


### Failure during archive restoration

Restore publishes files through individual atomic renames; the whole tree is not
one atomic transaction. A rename or exact-cleanup failure returns HTTP 500 with
`ok: false`, `publication_started: true`, and `rollback_snapshot` naming the private
snapshot. Some files may already have changed. Inspect the tree and recover from
that snapshot before restarting. A process crash disconnects HTTP; locate the
latest created `/etc/qeli/.pre-restore-*.tgz`, inspect it and recover the old tree.

`tar xzf <snapshot> -C /etc` restores snapshot members but does not remove new files
introduced by a failed restore. For a complete recovery, compare the tree with
the snapshot and remove only confirmed newly introduced files. Preserve the
snapshot and active `.lock` files; coordinate recovery with other writers. Check
config, users, identity and TLS before restarting. Automatic rollback and power-loss
guarantees are not provided.

The snapshot is created after staging validation and acquisition of FileLocks for
the active config and managed users/identity paths from both old and new configs.
Each additional lock waits up to 5 seconds within the shared preparation budget.
A busy lock returns HTTP 409 before publication. Invalid archives do not rotate
previous snapshots. Successful restores retain the five newest by mtime and always
preserve the current recovery snapshot. Publication failures do not rotate snapshots.

Uploaded archives cannot contain `.config-history`, `.pre-restore-*`,
`.restore-upload-*` or `.restore-staging-*` at any level: these are local operational
state. A full pre-restore snapshot is for manual recovery, not API upload. File-only
command checks cover both `.ini` and legacy `.conf`; notify.ini uses its own parser.
Exact retains nested `.lock` files even in a directory absent from the archive,
while removing that directory's ordinary files.

`exact` accepts `true/1/yes/on` and `false/0/no/off`, case-insensitively, trimming
surrounding spaces. An absent parameter means overlay. Empty or unknown values
return HTTP 400 before restore starts.


Filesystem failures opening/checking locks and tar extraction failures return
HTTP 500; actual external FileLock contention timeout returns HTTP 409. Structurally
invalid uploads still return HTTP 400. Pre-publication failure reports
`publication_started: false` and `rollback_snapshot: null`.
If storage becomes read-only after extraction, staging cannot be removed either:
a private `.restore-staging-*` directory remains with modes 0700/0600. Once storage
is writable and restore has finished, inspect and remove that temporary directory.
Subsequent restores do not use it; portable backups and rollback snapshots exclude
operational staging/upload paths.

Fresh restoration with mixed inline/external users requires the external users INI
in the archive even when inline accounts exist. The external file wins duplicate
user/group names; group references are validated on the union. Restart applies
the restored credentials and restrictions. `/var/lib/qeli/panel-secret.key` remains
machine-local state excluded from portable archives. On the same server the preserved
key allows reissuing the old link. On a new server without that key, old password_hash
values still authenticate, but reissuing password_enc needs recovery of a separate
state backup or an explicitly authorized password reset. Decryption failure itself
does not change passwords.

### Quick start page
Its own sidebar page: a table of ten masking modes, each launchable with **Launch** —
`reality-tls` (TCP 443, badged "flagship"), `reality` (8443), `fake-tls` (8444),
`obfs-ws` (8445), `obfs-none` (8446), `plain` (8447), `udp-fake-tls` (UDP 8448),
`udp-quic` (8449), `udp-obfs` (8450), `obfs-awg` (TCP 8451). Each row shows the
transport, the port and one line on what the mode does.

What **Launch** does:
1. reads the current config and **checks the port**: if that port+transport is already
   taken by a DIFFERENT profile you get a "Port already in use" popup with a link to
   Config (re-launching the SAME mode is allowed);
2. asks for confirmation and the IP mode **inside** the tunnel: `auto`, `ipv4`, `dual`, or
   `ipv6`. The first launch builds from canonical defaults (`/api/config/defaults`) and
   assigns `0.0.0.0:<port>`, its own `vpn<N>` TUN, collision-free addressing, DNS/NAT,
   and the selected obfuscation stack.
   - `auto` chooses `dual` only when a public GUA is observed on an IPv6 default-route
     interface and `ip6tables` is available; otherwise it stores a fully usable `ipv4`;
   - explicit `dual`/`ipv6` refuses to launch without those prerequisites or with MTU <1280;
   - IPv6 receives a unique RFC4193 `/64`, the `::1` gateway, an IPv6 DNS listener and
     NAT66; `dual` retains NAT44 while `ipv6` disables IPv4 NAT/forwarding;
   - `auto` resolves once. Re-launching an existing profile preserves its concrete IP mode,
     credentials and manual settings. Explicitly choosing another mode intentionally
     switches and normalizes the complete egress contract without rotating credentials.
   Existing client links therefore keep working; use explicit Config actions for rotation
   or reset;
3. sends the expected config revision to `POST /api/config/quickstart/{mode}`. The server holds
   the config writer lock while it re-reads, builds, validates, snapshots and atomically writes
   the profile; a concurrent panel/SSH edit produces a conflict instead of being overwritten.
   Only after that successful operation does the page restart the server.

When it's done a modal shows the profile name and endpoint plus, for the modes that need
them, the newly generated (first launch) or preserved (repeat launch) **REALITY short_id**
and **obfs pre-shared key** with a Copy button — these have to go into every client. The
same modal reminds you that clients also need the
server's pinned public key (`qeli show-identity`, or Config → Global → Server identity
keys), and for the TCP modes it repeats the mobile/LTE path-MTU warning.

The modes are independent — each gets its own interface, subnet and port — so running
several at once is the recommended production layout (a client connects on whichever port
gets through its network).

The complete selection rules, routed GUA, `off/manual/route/nat66`, NDP proxy, client `ipv6=auto|required|off`, and
leak verification are documented in the [IPv6 guide](IPV6.md).

### Config

- **Top tabs** — `Global` + one per profile (+ add). A profile's settings are
  **all on one page** (no inner tabs); a **sticky jump nav** (Bind / TUN / Pool /
  Routing / DNS / DHCP / Obfuscation / Performance) is pinned under the header.
- **Profile** — an `enabled` toggle and sections with **every** field: transport/
  bind/identity path, TUN (including `ip_mode`, IPv4/IPv6 gateways, MTU and multi-queue
  `queues`), separate IPv4/IPv6 pools, exclusions and reservations, routing with NAT44 +
  `off|manual|route|nat66` + pushed routes, dual-family DNS + blocklist,
  DHCP (TAP only — see below),
  obfuscation (mode/cipher/fronting, TLS masking + SNI pool, REALITY +
  `handrolled`/`peek`, padding, heartbeat, fragmentation, the automatic Reality/H2 carrier (no user switch), traffic-norm,
  anti-fingerprint, QUIC, **multipath**), performance (limits, rate-limit/
  new-session, TCP/TUN buffers).
- **Global** — Authentication (incl. `bind_static_to_session` H-1), Web UI (TLS,
  allowlist, public_host, admin password), Logging, **Server identity keys**
  (show each profile's pinned key + **Rotate**).
- **Administrator-managed IPv6 (0.8.2):** in Config, select a profile with `tun.ip_mode = dual`
  or `ipv6`, then Routing → `IPv6 forwarding / NAT66` → `manual`.
  `Upstream IPv6 NDP proxy` offers `off`, `auto`, `required`; for an on-link prefix,
  specify the upstream Ethernet interface. Switching `route` ↔ `manual` preserves NDP;
  choosing `off` or `nat66` disables NDP and clears its interface. Prepare host firewall,
  forwarding, RA and DNS, then use `Apply & Restart`. `Save to Disk` only saves the
  configuration for the next restart. See the [manual section](IPV6.md#manual) for
  responsibilities and an INI example.
- **Saving:** `Save to Disk` (writes the config, applied on next restart) or
  `Apply & Restart` (save + restart now). `Form` / `INI` views (raw
  saves verbatim — comments preserved).
- **Safe editing:** all views share a revision of the exact INI bytes (comments included).
  A save refuses to overwrite a newer panel-tab or hand edit, and switching raw/structured,
  Reload or leaving the page warns before discarding unsaved work. Before confirmation the
  panel lists changed field paths or raw line numbers. Every changing panel write creates a
  private rollback snapshot in `/etc/qeli/.config-history` (`0700` directory, `0600` files;
  newest ten retained); **History** validates and restores one while first preserving the
  current file as another snapshot. A restart is still required for data-plane changes.

Save/restart network preflight runs asynchronously before acquiring the write lock.
Probes share 15 seconds; after observation, five seconds remain for config-lock admission
and candidate preparation. Busy or expired preflight asks for a retry; revision and users
are re-read under the lock. [Details](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md).

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
save that touched any of them says so: apply it with a FULL restart. A full restart
is also required after changing `auth.users_file`, `web.persist_session_key`, or the
active logging settings `logging.level`, `logging.file`, and `logging.time_format`.
Before a full restart, the panel also checks for an enabled profile, admission
for an enabled panel, and a readable certificate/key pair when TLS files exist.
If this fails, the running process stays up; correct the configuration and retry.

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


<!-- normative-sync: panel-editor-state-v1 -->

### Config editor operation and confirmation

Save reviews the current draft and writes it with the revision that draft was
loaded from. Repeated clicks cannot start another action while a confirmation,
write or restart is pending. Edits made after the review opens remain unsaved
if they differ from the submitted draft. Apply & Restart stops if saving is
cancelled, fails or leaves newer edits unsaved. An unconfirmed full restart
keeps the indication that panel socket changes still need a full restart.

Reload and Form/INI switching request confirmation before discarding a dirty
draft. Leaving the page uses the browser's unsaved-changes warning. Failed
reads show an error and require a successful reload before saving; they do not
make initial defaults eligible for a write. If new-profile defaults alone are
unavailable, the loaded configuration stays editable, while Add remains disabled.

Identity and History show read failures with Reload. A failed refresh retains
the previous snapshot. A late reply cannot replace a newer opened history window
or update a destroyed editor. Restoring history uses the current config revision;
it reloads the restored configuration and does not restart automatically.

The shared confirmation dialog initially focuses Cancel, keeps Tab and Shift+Tab
inside the dialog, supports Escape and returns focus to the initiating control
when that control remains available. Closing a nested restore confirmation leaves
History open.

### Raw INI config editor

The `INI` view on the Config page (`GET`/`PUT /api/config/raw`) shows the config **file
verbatim** and writes back the submitted text — **comments and formatting are preserved**.
`Form` parses the configuration and serializes it back to INI, so hand-written comments
are lost on that save; edit a comment-heavy config in the `INI` view or directly on the
server. Both views save configuration only as INI.

> **Secrets are masked in this view (since 0.7.13).** The values of `password_hash`,
> `password_enc` and `password` are served as `<unchanged>` — the editor used to show them
> verbatim, handing the admin password hash and every user secret to whoever opened the page.
> The placeholder **can be left alone**: submitted back unchanged it means "keep what is on
> disk". To change a value, type the new one over the placeholder. The rest of the file
> (comments, ordering, spacing) is still preserved verbatim.

Raw saves are guarded exactly like structured ones: the text must parse; `logging.file`
must be inside `/var/log/qeli`; `auth.users_file` and `identity_key` inside
`/etc/qeli`; `web.tls_cert`/`tls_key` inside `/etc/qeli` or `/etc/letsencrypt`;
`web.password_hash` must be a valid argon2 hash (the hand editor is the easiest
place to lock yourself out with a typo);
`routing.post_up`/`post_down` can neither be introduced nor changed through the panel;
and the config must pass the same profile validation the server runs at startup. Panel
settings apply live when the save response reports `web_settings_applied: true`;
when false, the previous panel settings remain active. Changing `auth.users_file`
or `web.persist_session_key`,
`logging.level`, `logging.file`, or `logging.time_format` requires a full supervisor
restart through `Apply & Restart` (or `systemctl restart qeli`). Profile/bind/tun
changes also need a restart.

When writing server INI through the API (Quick Start, form, INI editor or history
restore), send `expected_revision` from the latest config GET. A missing or stale
revision rejects the write; reload the config and retry.

### Server identity: show & rotate
**Config → Global → Server identity keys** (`GET /api/identity`) lists each profile with
its bind string and its **persisted public key** (hex) — the panel equivalent of
`qeli show-identity`; the key file is created on first read if it doesn't exist yet.
The panel reads a bounded snapshot of the current INI and refuses identity listing,
rotation, and Share when an explicit `identity_key` comes from an untrusted file.
It also refuses a custom `auth.users_file` from that snapshot for user operations.

**Rotate** (`POST /api/identity/{profile}/rotate`) generates a new key for that profile.
**The running worker keeps using the OLD key until a restart**, and after the restart
**every client of that profile must be given the new `auth.server_public_key`** — the key
they pinned before will no longer match. In other words rotating means re-issuing the
config/link to all of that profile's clients, so don't do it "just in case".

The Identity list reads the persisted key. After rotation it shows the new key even
while the running worker still holds the old one; coordinate client pin updates with
the explicit worker restart.

### Users & groups
- **Create/edit:** enter the password in **plaintext** — the server hashes it
  (argon2id) and stores a reversibly-encrypted copy (for config re-issue, below).
  Fields: bandwidth limit and read-only legacy burst, optional static IPv4 and IPv6 addresses, group, max sessions,
  **allowed profiles** (interface isolation), allowed networks and **per-user routes**.
  Clearing either static-address field or the group really removes the stored value; the API
  distinguishes an omitted field (leave unchanged) from `null`/blank (clear it).
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
  - **The data quota counts DOWNLOAD only** (server→client). Upload does not count toward
    that quota, so a user cannot be locked out by sending. This is separate from the
    `bandwidth.limit_mbps` rate cap, which limits both directions. The usage column shows
    the two directions separately —
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

Set the Linux client TUN queue size here through **Raw INI**:
`tun.tx_queue_len = 1000` under `[qeli]` (default `1000` packets, range `1..32767`,
no auto mode). There is no dedicated form control; the key is local, absent from
links/QR and not configured in a server profile. It requires a client containing
the development 0.8.2 change. Omit it with `dev_attach=true`, where an external
system owns the queue. Save, then Disconnect and Connect; do not reload the server.
The binary serving this panel must also support the key: an old editor can reject
the INI before starting a new client. This concerns the local panel host, not a
mandatory remote VPN-server upgrade for a standalone client.
[Full contract](CONFIG.md#client-tun-tx-queue).

Creating or importing requires an unused name; an existing client profile is never
silently replaced. The editor saves with the exact INI revision it loaded. If another
tab or a manual edit changes the file, the save is rejected: reopen the profile,
review the newer contents, and save again. INI reads use the client runtime's
256 KiB limit. Saving a connected profile writes the INI but does not change the
running client process. Use Disconnect, then Connect to apply it; the process's
internal reconnect loop does not reload the file.

**Where things live.**
- Profiles: `/etc/qeli/clients/<name>.conf`, mode `0600` (they contain the password in
  plaintext). Names are `[A-Za-z0-9._-]` only, up to 64 characters.
- The TUN device, unless you set one, is auto-assigned: the lowest free `vpnN` that is
  claimed neither by another client profile nor by an interface that already exists on the
  host (including a server profile's TUN).
- Each tunnel's log: `/var/log/qeli/client-<name>.log`, appended across reconnects/connects and
  trimmed from the oldest half after 4 MiB.
- Structured diagnostics: beside the control socket, `client-<name>.status.json` (`0600`). It
  contains only state/retry, negotiated `NetworkPlan` and TX/RX/UDP counters — never credentials.

**Connect / Disconnect.** Connect spawns `qeli client -c <file>` as a child of the
supervisor (inheriting its privileges, so it can bring up its TUN and routes). Disconnect
sends SIGTERM — the client restores DNS and routes and exits; if it hasn't left after 5 s
it is SIGKILLed. **Delete** checks the INI revision before disconnecting, then
removes the profile and its log. A stale page leaves the tunnel running and the
file intact; refresh the list. Direct Delete API calls require the
X-Qeli-Revision header from the profile list. A
profile with `autostart = true` is connected when the supervisor starts. Autostart
reads only a stable client INI up to 256 KiB; a file that changes during reading
or exceeds the limit is skipped.

**The status is honest, not "is the process alive".** The list refreshes every 5 s and reads
the Rust client's structured status: **● Connected**, **◌ Connecting…**, **⚠ Error —
retrying** (the process is alive but the tunnel is looping on reconnect — e.g.
`reality-tls` with no short_id) or **○ Disconnected**. **Details** shows carrier/tunnel
addresses, MTU, DNS, effective routes, full-tunnel/kill-switch/multipath decisions and
TX/RX/UDP buffer/drop counters. The short log tail remains a human audit trail and a
compatibility fallback for a client process started by an older binary. A
structured status file over 64 KiB or changed during reading is ignored,
leaving the log fallback.

### Panel source and visual checks
`python3 scripts/check_panel.py` is a dependency-free CI gate for shared control styling,
keyboard-operable custom switches, duplicate RU keys and missing translations in controls or
`qeliT`/`qeliTf` calls. A seeded lab can run `scripts/panel_visual_regression.py` to capture or
compare all panel pages in the 72-case RU/EN × dark/light × desktop/mobile matrix; the script is
opt-in because it needs a running authenticated panel and reviewed baselines.

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
and the panel are limited (or disabled) separately. **Save policy** validates the complete
resulting INI before writing it and applies the panel policy through a live settings reload; it requests a VPN
worker SIGHUP without dropping sessions. Applying changed thresholds resets that surface's
failure counters. If the worker is unavailable, the tab reports that the saved VPN policy
will apply at its next start. If the panel reload fails, the INI remains saved while the active policy stays unchanged; the tab flags the saved/live mismatch and asks the operator to check the INI and logs before restarting. A failed INI read is shown as an error rather than defaults.
Turn a
switch off to disable rate-limiting for that surface entirely (only safe for panel login on
a trusted / loopback bind). The same policies are also editable in **Config → Authentication**
(VPN) and **Config → Web UI** (panel).

> Frequent `New TCP connection from …` from one IP on `reality-tls` in the logs are
> **scanners/probes**, not password guessing: they're transparently bridged to the
> upstream and carry no user. Real attempts show as `AUTH FAIL … user=X — wrong password`.

### Notifications
Outbound alerts on key server events via **Telegram** and a **generic webhook** — two
independent channels, each with its own switch, credentials, event toggles and **Send
test** button. Config lives in `/etc/qeli/notify.ini` (editable from the panel or the
file); sends are best-effort and never block the data plane, and outbound TLS certs are
verified. Channels are OFF by default when no saved notification settings exist.

The file uses the shared INI parser with `[notify]`, `[telegram]`, and `[webhook]`
sections. Event keys belong to their channel section; unknown keys, duplicates and
invalid booleans are rejected. Example:

```ini
[notify]
server_name = edge-eu

[telegram]
enabled = false
token = ""
chat_id = ""
on_server_start = true
on_quota_breach = true
on_login_lockout = true
on_auth_lockout = true
on_restore = true
on_client_connect = false
on_client_disconnect = false

[webhook]
enabled = false
url = ""
on_restore = true
```

Notification settings are read only from INI (up to 64 KiB); an oversized or
invalid file is rejected without falling back to defaults. If an old
`notify.json` remains without `notify.ini`, loading fails: transfer its
settings to INI and remove the old file. Panel backups omit `notify.json`,
and archive restore rejects it. JSON remains only in the internal API and
webhook messages.

On save, the panel checks a revision of the exact notify.ini bytes. If another
tab or a manual editor has changed the file, the write is rejected; reload
the page and review the new values before saving again.

- **Server name** — a label prefixed to every message (`[name] …`) and put in the
  webhook JSON `server` field, so several servers reporting into one chat / hook are
  distinguishable. Empty = no prefix.
- **Events** (each toggled per channel): *Server start / restart*, *Quota breach* (a
  user hit their data cap or their expiry), *Panel login lockout* (an IP locked after
  too many failed **panel** logins), **VPN auth IP lockout** (an IP locked by
  brute-force protection after repeated wrong **VPN** login/password), *Config
  restored*. Quota/VPN-auth alerts have a one-hour per-key cooldown; panel lockouts use ten minutes.
  Opt-in connect/disconnect alerts use ten seconds per user and event type.
- The Telegram token is **write-only** (masked after saving); **Send test** delivers a
  probe to one channel using the current (even unsaved) settings.

Delivery limits apply separately to worker and supervisor: **128 accepted requests
including active ones**, **8 active sends**, shared by Telegram, webhook and **Send test**.
An event sent to both channels uses two slots. A full queue drops new automatic sends;
`notify: queue full` reports the cumulative rejection count at exponentially spaced
intervals. A panel probe gets an explicit error instead. Its **10-second total timeout
includes queue wait**; timeout or handler cancellation cancels unsent work. Each automatic
HTTP send also has a ten-second timeout after admission to the active group.

Event details and the displayed server name are clipped at UTF-8 boundaries to 2048 and
256 bytes respectively. Webhook bodies are capped at 32 KiB. URL/token/chat id longer
than 4096/512/128 bytes are rejected, not shortened; saved configuration is unchanged.
Graceful stop closes admission, drains for at most ten seconds, then cancels and joins
remaining deliveries. There is no durable retry; full queues, shutdown or network errors
can lose notifications. The grace starts at the first worker/supervisor stop request;
the queue drains concurrently with cleanup and does not add ten seconds afterwards.
HTTP responses outside 2xx are logged with the channel name.

<!-- normative-sync: notify-delivery-trust-v1 -->

On Unix the sidecar must be a regular file owned by root or the running user,
without group/other write permission. Symlinks are refused; `0600` is recommended.
An untrusted file disables automatic channels and produces a panel error. A panel
save never repairs its permissions or authorizes its contents: repair the file as
an administrator, then reload it. Successful saves invalidate the process cache;
the next event loads the current stable INI snapshot, including a later manual edit.

Webhook URLs preserve query parameters and omit fragments (`#...`) from requests.
Encode spaces in the URL. Delivery accepts only HTTP/1.0 or HTTP/1.1 final status
lines of at most 4 KiB; interim 1xx responses are unsupported. Only 2xx is success.
3xx is a failure and redirects are not followed. Malformed remote response text
is never copied into panel errors or the journal.

Destinations must pass the conservative public-address policy before connection,
each candidate is checked before use; only a validated address is selected and pinned.
Loopback, private/link-local, documentation, benchmark and reserved destinations,
IPv6 translation/tunnelling prefixes and special protocol assignments are refused.
This also excludes some globally reachable special-purpose addresses; it is not an
exact IANA reachability classifier. Internal webhooks and NAT64 destinations are
unsupported. HTTPS verifies certificates and names against the bundled root store.

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

- Cipher: ChaCha20-Poly1305, panel key `/var/lib/qeli/panel-secret.key` (`0600`,
  auto-generated). Stored as `password_enc` (base64) in the users file; **never
  returned over the API**. The key is deliberately excluded from the panel-generated
  `/etc/qeli` backup; the legacy `/etc/qeli/panel-secret.key` is migrated automatically
  on upgrade.
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

<!-- normative-sync: server-config-writers-v1 -->
<a id="server-config-writers-v1"></a>

### External server INI writers and revision boundaries

The form, INI editor, Quick Start, history, writing CLI commands and Backup/Restore
share one sidecar lock `<canonical config path>.lock`. It protects the complete
read, validation and atomic publication transaction. Never delete or replace a live
process's lock file; exact restore preserves its inode.

An external script or editor must hold an exclusive `flock` on that same canonical
sidecar from reading through completion of writing/rename. If the editor cannot
follow this protocol, stop Qeli and finish concurrent panel/CLI operations first,
edit the INI, run `qeli check-config`, then start the service. `expected_revision`
detects changes to the previously read file; a second read also detects changes
during save preparation. This detects conflicts rather than blocking arbitrary
root writers: a write without the sidecar lock between the final check and rename
is not protected.

Saving a profile does not change active bind/TUN/DNS parameters. Apply it through
an explicit worker restart; startup-only panel fields require a full process
restart. An invalid restart candidate is refused before stopping the active worker.
History applies eligible web fields live; archive restoration requires an explicit
restart. These boundaries are checked by the shared
[runtime scenario](../../../scripts/audit_panel_config_lifecycle.py) and recorded
in the [D07 register](../plans/AUDIT-DEBT.md).

## API authentication and attempt limits

<!-- normative-sync: panel-web-auth-v1 -->

Panel pages use the `qeli_session` cookie. HTTP Basic is supported for `/api/*`;
its scheme is case-insensitive (`Basic`, `basic`, `bAsIc`). The username is compared
exactly; password spaces and colons are preserved. Service JSON API payloads do not
change INI as the sole configuration-file format.

`[web] brute_force.*` governs admin login and API Basic independently of the VPN
policy under `[auth] brute_force.*`. Hard lockout applies to the client IP; behind
a configured trusted proxy the validated X-Forwarded-For chain supplies that IP.
Ordinary probes without credentials or with an invalid/expired cookie do not count
as password attempts. The admin username never receives a global hard lockout.

Password verification shares an Argon2 semaphore (2–8 jobs based on available
CPU count). After queueing, the IP is checked again: a locked source receives 429
before hashing. Already admitted jobs may complete; their results are recorded
before permit return even when the HTTP client cancels its request.

CSRF applies to mutating API requests, including login and Basic. Origin takes
precedence over Referer; allowed host/port are compared. CLI calls without either
header are supported. `trusted_proxies` also controls trust in forwarded HTTPS
and prefixes; a direct caller cannot impersonate a proxy.

Logout revokes all previously issued admin sessions through persistent session
generation and clears the browser cookie. Persistence failure returns an explicit
500: browser cookie removal does not prove successful token revocation. With
healthy persistent key/generation files, revocation survives restart. An authenticated
login page redirects directly to the canonical panel root. Web-panel TOTP is not
implemented; VPN TOTP is a separate mechanism.

### Save failures and restart confirmation

<!-- normative-sync: panel-transaction-outcomes-v1 -->

Form/INI/Quick Start/history require a fresh `expected_revision`. Save publishes a
private rollback snapshot before replacing INI; it does not restart the worker.
An error containing `published ... persistence is uncertain` may follow publication:
read the new revision and inspect INI before retrying; an error does not prove rollback.
New password/allowlist settings apply live; password changes revoke previous cookies.
Bind/port/base_path/TLS require full restart; startup values remain active until then.

`worker restarting` confirms command dispatch; use status to check readiness. Full
restart also responds before replacing the supervisor. Rejection/uncertainty appears
in status warnings; inspect unit/journal before retrying. A successful full restart
applies new listener settings and retains sessions with healthy persistent keys.


### Damaged key files

<!-- normative-sync: panel-key-storage-v1 -->

Identity, panel-secret and session keys are read as regular files of exactly 32 bytes. FIFOs, directories and dangling links are not missing keys and are never replaced automatically. Links to existing regular files remain supported; reading does not change their owner/mode. Verify ownership/permissions manually: generated files are private (0600), and the standard identity directory is 0700.

Legacy panel-secret migration holds the same lock as key creation: an already-published modern key takes precedence. A damaged or inaccessible legacy file requires recovering the original key; do not delete it to generate a new key when existing `password_enc` must remain decryptable. Key errors can disable reversible storage of a new password; its Argon2 hash remains a separate authentication mechanism. An unavailable session key is preserved without replacement; the panel uses its existing per-process-key fallback and logs a warning, so those cookies do not survive restart.

### Users API and live access

<!-- normative-sync: panel-user-mutations-v6 -->

User/group/limit mutation bodies must be objects; wrong types cannot become Unlimited or a successful no-op. `enabled` is boolean, `bandwidth` an object, password/hash strings, route gateway string/null. Configurations are saved only as INI.

A file entry overrides its namesake inline definition. Deleting this override is refused: it would restore inline access or previous group limits. Use Disable or remove the inline definition in server.conf.

After successful Users reload in the worker, removed/disabled users and entries forbidding the current profile lose open TCP/UDP sessions. Effective bandwidth, including group inheritance, applies to live sessions. API success confirms persistence and queued reload; new authentication readiness may follow later. Periodic sweep rechecks rights, quota and expiry. `burst_mbps` remains a stored legacy field; there is no separate burst enforcement.

After accepted SIGHUP, enable-user, disable-user, set-limit and set-bandwidth use
current inline users/groups. Removed inline accounts cannot return from the startup
snapshot; accounts added by reload can be managed without restarting the worker.
Rejected reload preserves the previous accepted auth configuration.

Changing effective user/group ACL, `client_subnets` or exit-default permission also
ends open sessions carrying old permissions. Reconnect to receive the new policy.
Rule order and duplicates do not affect sessions; a user ACL overrides its group.
Lowering `max_sessions` retains the newest devices on each profile and disconnects
older excess sessions. Bandwidth changes apply without disconnecting. `burst_mbps`
is a stored compatibility field with no separate data-plane burst control.

Waiting for the users-file lock is bounded to five seconds. Failure before `rename`
preserves old bytes. If rename has published INI but directory fsync fails, the API
returns an error with `published=true` and uncertain durability, reads back users
and attempts to queue worker reload. `reload_requested` reports queue success,
not application acknowledgement. Inspect saved INI and live client state before
retrying. Control commands also read back published users and never promise rollback.

Users displays effective bandwidth: a positive own cap, otherwise the group cap,
otherwise Unlimited. A zero own cap restores inheritance. Legacy burst is read-only
in the form and remains stored when editing other fields; it does not raise the
permitted rate.

Replacing a device, a fixed-IP holder or an older session at a full cap ends the
previous connection with `session_superseded`. Management-capable clients stop
retrying automatically; connect manually to return. Caps apply separately on each
profile. Narrowing allowed profiles disconnects only forbidden connections;
account deletion removes all its sessions.

Password reset during link issuance uses the same published-write recovery.
If fsync fails after rename, inspect `published`/`reload_requested` and reissue the
link without another reset: the persisted password can be recovered from the database.
