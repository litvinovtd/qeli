# qeli web panel — installation & usage

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
bind = 0.0.0.0            # or a specific public IP (an IP is better for the self-signed SAN)
port = 8080
username = admin
password_hash = $argon2id$v=19$m=...$...   # REQUIRED on a non-loopback bind (see below)
tls = true               # native HTTPS (rustls); self-signed cert auto-generated
# allowed_ips = 203.0.113.4, 10.0.0.0/8    # (optional) source allowlist
public_host = vpn.example.com              # (optional) share-link host; also an allowed CSRF origin
# allowed_origins = 192.168.88.8:8080      # (optional) extra browser origins for LAN/domain/proxy access
#                                          #   without it the panel loads but POST (login/saves) 403s
```

After a server restart the panel is at **`https://<bind>:<port>`**.

### Admin password (required on a public bind)

The server stores only the **argon2id hash** (`web.password_hash`), never the
plaintext. **Fail-closed:** on a non-loopback `bind` with an empty
`password_hash` the panel **refuses to start** (logs an error; the VPN `:443`
keeps running — it's a separate process). Ways to set the hash:

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
- **`argon2` CLI (manual):** `printf '%s' 'YOUR_PASSWORD' | argon2 "$(head -c12 /dev/urandom|base64)" -id -t 3 -m 15 -p 1 -e`
- **Via API** (if the panel is already open without a password on loopback):
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
save return **`403`**, and the log shows `CSRF: rejected POST … (origin/referer=…)`.

Fix — add that address to the allowed origins in `[web]`, then `systemctl restart qeli`:

```ini
[web]
allowed_origins = 192.168.88.8:8080   # your LAN IP / domain — host or host:port
# public_host is also accepted as an origin; a host with no port also matches the bind port
```

Or, without editing the config, reach the panel over an SSH tunnel to loopback (always
allowed): `ssh -L 8080:127.0.0.1:8080 root@<server>` → open `http://127.0.0.1:8080`.

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
  restarts the server.
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
| `secure_cookie` | `Secure` on the cookie (auto under `tls`; manual behind a TLS proxy) |

Server identity, key pinning, H-1, per-profile authorization, limits, wire
modes/REALITY — see [CONFIG.md](CONFIG.md).
