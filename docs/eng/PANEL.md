# qeli web panel — installation & usage

> **These docs describe 0.7.12.** Features marked "**since 0.7.12**" are in the source
> tree and running on the reference server, but **no package has been published yet** —
> the latest released version is still 0.7.11. They are absent from a `.deb` install;
> `qeli --version` tells you what you actually have.

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
# REQUIRED on a non-loopback bind (see below)
password_hash = $argon2id$v=19$m=...$...
# native HTTPS (rustls); self-signed cert auto-generated
tls = true
# (optional) source allowlist
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
reach the panel; everyone else gets `403`. Empty = any source (security then
rests on TLS + password + rate-limit). Edit it in Config → Web → "Source-IP
allowlist". **Include your own current IP**, or you'll 403 yourself.

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
  flow-shaping instead of the ~15s heartbeat beacon, MTU 1280, and stream bonding
  on the TCP modes.
  **Mobile / LTE:** the large post-quantum handshake can black-hole behind a
  sub-1500 path MTU; on the server apply the OS tuning (outer-port MSS clamp + BBR /
  PMTU probing) — see [CONFIG.md](CONFIG.md) → "sysctl + iptables". The
  `install-reality-server.sh` installer does this automatically.
- **Live clients** — who's connected (profile, IP, uptime, traffic, limit), with
  **Kick** and **Set bandwidth**. Per-profile filter, 10s auto-refresh.

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

> **DHCP — a common confusion.** In normal **TUN** mode client IPs are assigned by
> the built-in **pool** (Pool section → CIDR/reservations), **not** DHCP. The DHCP
> server is only for **TAP/bridged** setups. With DHCP off, TUN still assigns IPs.

### Users & groups
- **Create/edit:** enter the password in **plaintext** — the server hashes it
  (argon2id) and stores a reversibly-encrypted copy (for config re-issue, below).
  Fields: bandwidth/burst, static IP, group, max sessions, **allowed profiles**
  (interface isolation), allowed networks, **per-user routes**.
- **Groups** — templates (bandwidth/max-sessions/networks) a user inherits unless
  it overrides them.
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

### Issuing a config (Share / QR) — no password needed
The **Share/QR** button on a user. Give only the public host (pre-filled from
`web.public_host`, else the last-used one) → **Generate**. **No password entry** —
the server decrypts the stored copy and builds the `qeli://` link + QR. The
password is **not changed**.

- **Legacy users** (created before this feature — no stored copy): the panel shows
  "no stored password" and a **"Reset password & issue config"** button — it
  resets the password once (shows the new one), after which re-issue always works.
  (Reset is the only path: the old plaintext is unrecoverable.)

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
| `username` / `password_hash` | admin login and argon2id hash (hash **required** on non-loopback) |
| `tls` | native HTTPS (rustls) |
| `tls_cert` / `tls_key` | your PEM cert/key; empty = auto self-signed |
| `allowed_ips` | source-IP/CIDR allowlist (empty = any) |
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
