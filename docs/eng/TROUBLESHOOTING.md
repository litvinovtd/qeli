# Qeli — connection diagnostics and error reference

> **These docs describe 0.7.15** — the latest released version. `qeli --version` tells you
> what you actually have.

A detailed, practical guide: how to enable debug logging, how to read the log by
connection stage, what every server and client (Windows / macOS / Android) error
means, and how to fix it. All strings are verbatim as they appear in the log.

> Error strings in the code are **in English** (that's how they print). Each one
> below has an explanation and a fix. If a line from your log isn't here, search by
> keyword — the sections are grouped by subsystem.

**Contents**
1. [Enabling debug logs](#1-enabling-debug-logs)
2. [Architecture and the connection lifecycle](#2-architecture-and-the-connection-lifecycle)
3. [Step-by-step diagnostics](#3-step-by-step-diagnostics)
4. [Error catalog — server](#4-error-catalog--server)
5. [Error catalog — clients (Windows / macOS / Android)](#5-error-catalog--clients)
6. [Common scenarios (symptom → cause → fix)](#6-common-scenarios)
7. [Reference: statuses, indicator colors, log prefixes](#7-reference)
8. [Command checklists](#8-command-checklists)

---

## 1. Enabling debug logs

### 1.1 Server

The default level is **`info`**. Most reasons a connection is refused (handshake/
crypto/MTU problems **before** authentication) are logged at **`debug`** — invisible
at `info`. So the first step in any "client won't connect, and the server is silent
after `New TCP connection`" investigation is to enable debug.

Two ways (**`RUST_LOG` takes priority over `[logging] level` in the config** — set in
`main.rs::init_logging`):

**A. Via a systemd drop-in (nothing changed in the config):**
```bash
mkdir -p /etc/systemd/system/qeli.service.d
printf '[Service]\nEnvironment=RUST_LOG=debug\n' > /etc/systemd/system/qeli.service.d/zz-debug.conf
systemctl daemon-reload && systemctl restart qeli
journalctl -u qeli -f
# revert: rm /etc/systemd/system/qeli.service.d/zz-debug.conf && systemctl daemon-reload && systemctl restart qeli
```

**B. Via the config** — set `level = debug` in the `[logging]` section, then
`systemctl restart qeli`. Section keys: `level` (`error`/`warn`/`info`/`debug`/`trace`),
`file` (log-file path; default is stderr → journald), `time_format`, `format`.

**The timestamp — `time_format`.** A log line is always
`<timestamp> LEVEL target: message`; this key sets the shape of the timestamp:
`datetime` (default, local time) / `rfc3339` (UTC) / `time` (no date) / `epoch` / `none`.
Two cases where it matters:

- **correlating client and server logs** (or several servers) — set `rfc3339` on both
  sides: UTC removes the timezone skew and the lines sort correctly;
- **logging to journald/syslog** — `none`: systemd and procd stamp the line themselves,
  otherwise `journalctl` shows two timestamps in a row.

The full table of variants is in [CONFIG.md](CONFIG.md#time_format--the-timestamp-prefix).
The same choice exists in the apps: Settings → Log timestamp (Windows, macOS, Android)
and `log_time_format` in UCI/LuCI on OpenWrt.

> ⚠️ **`format = json` is a stub.** Not to be confused with `time_format` above: `format`
> controls the shape of the line itself. It is parsed and shown in the panel, but
> `init_logging` **never reads it** — the log is always flat. Don't rely on JSON logs.

Targeted filtering (less noise): `RUST_LOG=qeli::server::handler=debug,qeli::server::udp_handler=debug,info`.

**One-off foreground run** (quick look, no unit edit):
```bash
systemctl stop qeli
RUST_LOG=debug /usr/bin/qeli server --config /etc/qeli/server.conf   # the .deb installs to /usr/bin
```

### 1.2 Clients (Windows / macOS)

There is no separate "debug mode" — **the client logs everything already** into the
**Log** tab in the app window. By default a line starts with the local date and time:
`2026-07-18 18:10:03.259  …`. **Since 0.7.12** the shape is configurable — Settings →
Log timestamp, with the same variants as the server's `[logging] time_format` (date and
time / RFC 3339 in UTC / time only / Unix / none); to compare the app log against the
server's, set `RFC 3339` on both sides. **Copy log** / **Clear log** buttons are in the log header.
A line's "severity" is set by its prefix: `ERR:`, `WARN:`, `NOTE:`, `[SECURITY]`, and
nested causes appear as `  <- …` lines.

### 1.3 Android client

Also logs everything into the **in-app Log tab** (index 3), with Clear / Copy /
Autoscroll buttons, a 500-line buffer, and a `[HH:mm:ss.SSS]` prefix. **Since 0.7.12**
the shape is configurable in Settings → Log timestamp (the same five variants; on Android
the default is time-only, because a full date eats the screen width). Plus via `adb`:
```bash
adb logcat -s VpnSvc VpnMain
```
`VpnSvc` — the VPN service (matches the Log tab), `VpnMain` — the activity. Pure
`Log.e` crash lines go **only** to logcat (they are not broadcast to the panel).

### 1.4 Packet trace (`QELI_TRACE`, Rust server and Rust client)

For when the logs are too coarse and you need a timeline — "did the packet leave, and when
did the other end see it". Armed by an environment variable, off otherwise:

```bash
# client
QELI_TRACE=/tmp/qeli-client.csv qeli client -c /etc/qeli/client.conf

# server (systemd): a drop-in, then restart
systemctl edit qeli
#   [Service]
#   Environment=QELI_TRACE=/tmp/qeli-server.csv
```

Dump on a signal, at any time (the process keeps running):

```bash
kill -USR1 $(pgrep -f 'qeli client')      # client
kill -USR1 $(pgrep -f 'qeli _worker')     # server: the worker, not the supervisor
```

The log gets a `packet trace: wrote N events` line, and the file holds CSV:

```
# qeli packet trace — shapes only, no payloads, no addresses
# overwritten=0 contended=0
t_us,dir,site,size,seq
479384,tx,client.tcp,40,0
```

- `t_us` — microseconds since process start, `dir` — `tx` (TUN → tunnel) / `rx`
  (tunnel → TUN), `site` — the capture point, `size` — bytes, `seq` — stream index.
- Only packet **shapes** are written: no payloads, no addresses — a trace can be attached
  to an issue without exposing anyone's traffic.
- The buffer is a 65,536-event ring. The header's `overwritten=` says how many events were
  overwritten (the trace outran the buffer) and `contended=` how many were lost to lock
  contention: a trace is **never silently partial**.
- Both ends write their own file. There is no shared packet id, so correlate client and
  server by time and size.

With tracing off the cost is one atomic load per packet, so the variable can safely be left
unset in production.

---

## 2. Architecture and the connection lifecycle

### 2.1 Server: supervisor + worker

The `qeli server` process is the **supervisor**: it holds the web panel and spawns a
child **data-plane worker** (`qeli _worker`). Two important consequences:

- **"Apply & Restart" in the panel does a FULL `systemctl restart`** — everything is
  applied, the panel socket included (`web.bind`/`port`/`tls`/`base_path`). A worker-only
  respawn (`POST /api/server/restart`) remains as the automatic fallback where systemd is
  unavailable (a container). Share links in the panel read the config
  **fresh from disk** (fix #69), so an SNI change shows up in the link without a restart.
- Startup looks like this in the log:
  ```
  Starting server (supervisor) with config: /etc/qeli/server.conf
  Web UI (HTTPS) listening on https://0.0.0.0:8080
  supervisor: data-plane worker started (pid NNNN)
  Starting data-plane worker with config: /etc/qeli/server.conf
  Starting profile 'fake-tls' (tcp://0.0.0.0:443)
  Profile 'fake-tls': server identity public key (pin on client): 320a4700…
  Profile 'fake-tls' listening on 0.0.0.0:443 (TCP)
  ```
  If the worker dies at startup (config validation), the supervisor logs
  `supervisor: worker exited after Ns — respawning in Ns` and respawns with backoff.

### 2.2 The stages of one connection (by log)

Localize the failure by the last successful line:

| # | Stage | Client line | Server line |
|---|---|---|---|
| 1 | TCP/UDP connect | `Connecting TCP/UDP <ip>:<port> as user '<u>'…` → `TCP connected` / `Bound carrier socket…` | `New TCP connection from …` / `UDP handshake started for …` |
| 2 | Send ClientHello | `ClientHello sent (NNNN B, hybrid X25519+ML-KEM)` | `Received ClientHello: N bytes` *(debug)* |
| 3 | Verify server identity | `Server identity verified [OK]` | `Sent server auth proof…` *(debug)* |
| 4 | Authentication | *(parse `OK:` from the reply)* | `AUTH attempt … user=…` → `AUTH OK …` |
| 5 | Pushed params applied | `Applied server-pushed obfuscation params` | — |
| 6 | IP assigned | `Auth OK, IP 10.x.x.x` | `Client … connected …, IP: 10.x.x.x` |
| 7 | TUN bring-up | `Wintun adapter …` / `utun …` → `TUN MTU …` → routes → DNS | — |
| 8 | Tunnel active (🟢) | `TUN ready, entering tunnel loop` → **status Connected** | — |

> **🟢 "Connected" = TUN is up, NOT "Auth OK".** Between `Auth OK, IP …` and
> `Connected` the status stays **yellow** (Connecting) while `SetupTun` runs (on
> Windows, opening Wintun takes up to ~10 s). This is deliberate (issue #69):
> previously green lit at Auth OK, and a TUN-setup failure reset the backoff → a tight
> reconnect storm.

---

## 3. Step-by-step diagnostics

1. **Is the server alive and listening?**
   ```bash
   systemctl is-active qeli
   ss -ltnp | grep -E ':443|:8443|:8444'      # TCP profiles
   ss -lunp | grep -E ':8448|:8449|:8450'     # UDP profiles
   journalctl -u qeli --since '5 min ago' -p warning --no-pager
   ```
2. **Is the port open in the cloud firewall / Security Group?** (a common reason
   "TCP connected" never appears at all).
3. **Client log: how far did it get?** (table §2.2). The last successful line points
   at the subsystem.
4. **Did it reach the server?** On the server look for `New TCP connection` / `UDP
   handshake started` with the client's IP. If that line is missing, traffic isn't
   arriving (firewall/route/wrong IP:port).
5. **It reached, but "silence" after accept?** Enable **debug** (§1.1), reconnect,
   and look for **exactly one** decisive line:
   - `handshake timeout for <addr>` → the client didn't finish sending the ClientHello
     (or the reply never arrived) = a **network MTU black-hole** (see §6.1);
   - `Client <addr> disconnected on profile '…': <reason>` → look up `<reason>` in §4.2;
   - `AUTH FAIL/DENIED/BLOCKED …` (visible at `info` already) → credentials/ban/rights (§4.3).
6. **Verify the key and mode.** The server's public key is in the startup log
   (`server identity public key (pin on client): …`) and via `qeli show-identity`.
   The client's `key=`/`reality_sid=`/`mode=` must match (see §6.4).

---

## 4. Error catalog — server

### 4.1 Config validation — worker won't start (`bail!`, fatal)

These errors **abort worker startup**; the supervisor logs the crash and respawns in
a loop with backoff. All at ERROR level.

| Message | Cause | Fix |
|---|---|---|
| `no profiles defined in server config` | no `[profile:*]` at all | add a profile |
| `all profiles are disabled (enabled = false) — enable at least one` | every profile `enabled = false` | enable a profile |
| `duplicate profile name: '<n>'` | two profiles share a name | rename |
| `profile '<n>': unknown bind.transport '<t>' — expected 'tcp' or 'udp'` | transport typo | `bind.transport = tcp` or `udp` |
| `profile '<n>': unknown obf.mode '<m>' — expected 'fake-tls', 'obfs', 'plain' or 'reality-tls'` | wire-mode typo | fix `obf.mode` |
| `profile '<n>': performance.connection.handshake_timeout_secs and max_clients must be > 0. The [profiles.performance] section is likely missing…` | **the classic footgun**: the profile's `[performance]` section is missing → serde zeros → instant timeouts / reject-everyone | add the `performance` section (or copy from the example) |
| `profile '<n>': plain (raw) wire mode is TCP-only — set bind.transport = tcp` | `obf.mode=plain` on UDP | switch transport to tcp |
| `profile '<n>': obfs wire mode requires a non-empty obfuscation.obfs_key…` | empty `obfs_key` (publicly derivable → no DPI resistance) | set `obf.obfs_key` |
| `profile '<n>': reality_proxy.enabled requires at least one non-empty obf.tls.reality_proxy.short_ids entry…` | REALITY without a short_id | set `obf.tls.reality_proxy.short_ids` |

| `profile has an empty name` | a `[profile:]` section with no name | name the profile |
| `profile '<n>': obf.heartbeat.interval_ms must be > 0 when the heartbeat is enabled` | heartbeat on with a zero interval | set `obf.heartbeat.interval_ms` |
| `profile '<n>': obf.heartbeat.jitter_ms (<j>) must be smaller than …` | jitter ≥ interval makes the schedule meaningless | lower `obf.heartbeat.jitter_ms` |
| `profile '<n>': obf.heartbeat.data_size_bytes (<b>) must be <= <max>` | heartbeat packet exceeds the max record size | lower `obf.heartbeat.data_size_bytes` |
| `profile '<n>': pool.cidr '<c>': <error>` | the pool does not parse as a CIDR (no prefix, junk, too narrow) | write it as `10.9.0.0/24` |
| `profile '<n>': invalid tun.address '<a>': … — expected a plain IPv4 address (e.g. 10.9.0.1)` | address carries a prefix/mask, or a typo | use a bare IPv4 |
| `profile '<n>': tun.address <a> is not a usable host inside pool.cidr <c>` | gateway is outside the VPN subnet, or is its network/broadcast address | choose a usable address inside `pool.cidr`; its prefix is the only mask setting |

Non-fatal (profile still starts), WARN level — they just warn about a
meaningless/weak setting: `obf.multipath.enabled has no effect on a UDP transport…`,
`obf.awg.enabled has no effect on a TCP … profile…`, `reality_proxy.target '<t>' is a
bare IP…`, `wire mode 'fake-tls' has LOW DPI resistance…` (on a UDP profile that last
one recommends `obfs` only — reality-tls runs over TCP and is unavailable on UDP).

### 4.1.1 Pre-flight checks — the service does not start at all (supervisor)

A separate class: these run in the **supervisor, before** the panel binds, the worker
spawns or any TUN comes up. So this is not a worker restart loop but a refusal of the
whole service — deliberately: a config caught by these checks would, on start, **cut you
off the machine itself**.

What is checked is the tunnel addressing against what the host already uses. The worst
case is a `tun.address` equal to the gateway: bringing the TUN up makes the gateway a
local address, every outbound packet dies in the tunnel, and the server drops off the
network along with SSH and ping — while the log looks like a perfectly successful start.

| Message | Cause | Fix |
|---|---|---|
| `profile '<n>': tun.address <a> is this host's DEFAULT GATEWAY…` | tunnel address = host gateway | move the tunnel to a free range (`10.9.0.1` / `10.9.0.0/24`) |
| `profile '<n>': tun.address <a> is already assigned to interface '<if>'` | address already held by a host interface | pick an address outside the host's own networks |
| `profile '<n>': pool.cidr <c> contains this host's DEFAULT GATEWAY <gw>…` | the pool swallows the gateway | change the pool |
| `profile '<n>': pool.cidr <c> contains <a>, the address of interface '<if>'…` | the pool swallows the host's own address | change the pool |
| `profile '<n>': pool.cidr <c> overlaps the existing route <r> on interface '<if>'…` | pool overlaps an already-routed network (LAN, provider subnet) | change the pool |
| `profile '<n>': pool.cidr <c> overlaps profile '<other>' pool <o>…` | two profiles share a range | separate them (`10.9.0.0/24`, `10.9.1.0/24`, …) |

Inspect your own networks with `ip route` and `ip -4 addr`. To check a config **before**
starting: `qeli check-config --config /etc/qeli/server.conf` — it runs the same check
against the current host and prints `would NOT start on this host — <reason>`.

One WARN of its own: `pre-flight: could not read the host's network state (ip missing or
unreadable) — skipping the subnet-collision check`. The host state could not be read, the
check was skipped and startup continues (fail-open — this guards against an operator
mistake, it is not a security boundary). Verify by hand that `tun.address` and `pool.cidr`
do not overlap the host's addresses, gateway or routes.

### 4.2 Handshake — before authentication (mostly DEBUG)

> **Key point:** these errors are returned from `handle_client` and logged in the
> accept loop as **`Client <addr> disconnected on profile '<name>': <reason>`** at
> **DEBUG** level. At `info` — silence. Enable debug (§1.1).

| `<reason>` in the disconnected line / a separate line | Meaning | Fix |
|---|---|---|
| `handshake timeout for <addr>` | the client didn't finish the ClientHello within `handshake_timeout_secs` (there's no inner read timeout — only this outer one). Almost always = a **PMTU black-hole** of the large PQ ClientHello | see §6.1 (MSS-clamp / MTU) |
| `failed to read ClientHello: <e>` | the TLS record didn't read (drop/junk) | network/MTU; check the client is fake-tls and the profile is fake-tls |
| `failed to parse ClientHello` | `FakeTlsHandshake::parse_client_hello` returned None (malformed TLS record) | client↔server wire-mode mismatch |
| `ClientHello missing the X25519MLKEM768 key_share` | client without ML-KEM (old/classic) — the PQ hybrid is mandatory in every non-plain mode | update the client |
| `ML-KEM encapsulation failed (malformed ek)` | a bad ML-KEM key in the ClientHello | version skew/corruption; update both sides |
| `rejected low-order client public key` | small-subgroup guard (low-order X25519 point) | client bug/attack; update the client |
| `invalid client public key length` | key_share ≠ 32 bytes | version skew |
| `auth packet too short` / `invalid auth format` | first packet < 32 bytes / creds without a `:` | version skew/corruption |

### 4.3 Authentication — visible at `info` already (WARN)

If the log has `AUTH attempt … user=…`, the handshake succeeded and it's a
credentials/rights problem. All lines are **WARN** (visible without debug).

| Message | Meaning | Fix |
|---|---|---|
| `AUTH DENIED … — server key not pinned (require_client_key_proof)` | `auth.require_client_key_proof=true`, and the client doesn't pin the server key (no/wrong `key=`) | set the client's `key=<server pubkey>` (see `qeli show-identity`) |
| `AUTH BLOCKED … — source IP locked for Ns…` | IP is locked by brute-force protection | wait out `lockout_secs`, or `qeli unblock <ip>`; investigate the flood |
| `AUTH FAIL … — not found or disabled` | user not in DB or disabled | check `users.conf` / `qeli add-client` |
| `AUTH FAIL … — wrong password` | wrong password (Argon2 mismatch) | reissue the link (`qeli add-client … --link`) |
| `invalid password hash: <e>` | broken PHC password hash for the user | recreate the user |
| `AUTH DENIED … not permitted on profile '<n>'` | valid creds but the user isn't allowed on this profile | add the profile to the user's `profiles = …` |
| `AUTH DENIED … — account expired` | `expire_at` passed (Tier-2) | extend the account |
| `AUTH DENIED … — download quota exhausted (…GB down)` | download quota reached | reset/raise `data_limit_gb` |

Notes: a username is **never** hard-locked (anti-DoS) — only IP addresses are; an
unknown user still spends a dummy Argon2 (anti-enumeration).

### 4.4 Accepting connections / rate limit

| Message | Level | Meaning |
|---|---|---|
| `New TCP connection from <addr> on profile '<n>'` | INFO | accepted (passed rate-limit), dispatched to the handler |
| `Rate limit exceeded for <ip> on profile '<n>'` | WARN | the **new-connection** limit for the IP was exceeded (`new_session_rate_max` per `new_session_rate_window_secs`) — the connection is dropped **before** the handshake. Common cause: a client reconnect storm or a probe flood |
| `Accept error on profile '<n>': <e> — backing off 100ms` | ERROR | `accept()` failed (e.g. EMFILE — fd exhaustion); a 100ms pause avoids a hot spin |
| `obfs accept failed for <addr> …` | DEBUG | the obfs/websocket-nonce exchange failed before the qeli handshake (`obfs_key`/`fronting` mismatch) |

### 4.5 UDP-specific

| Message | Level | Meaning / fix |
|---|---|---|
| `UDP handshake started for <addr> … (fragmented, QUIC-masked)` | INFO | ClientHello accepted, ServerHello sent |
| `UDP handshake failed for <addr> …: <e>` | DEBUG | reason below |
| `UDP initial too small (NB < 1200B) — anti-amplification guard` | DEBUG | the first datagram is smaller than 1200 B — reflector/amplification defense. A normal client pads to ≥1200; if you see this, it's an old/broken client |
| `UDP drop … no handshake permit (pre-auth crypto saturated)` | DEBUG | the pre-auth PQ-crypto semaphore is exhausted (spoofed-source flood defense). Harmless under real load; under a flood it works as intended |
| `UDP drop … QUIC unwrap failed (<e>)` | DEBUG | the datagram claimed QUIC masking but didn't unwrap — `quic` mismatch client↔server |
| `AUTH attempt UDP … user=…` → `UDP client … authenticated …, IP: …` | INFO | the normal success path; auth uses the same WARN lines from §4.3 |
| `UDP writer for <addr> kicked on profile '<n>'` | INFO | the session writer got a kick: supersede (same device reconnect) / session-cap / static-IP steal / reaper / over-quota. **Not an error by itself** — see §6.3 |

### 4.6 REALITY (`reality-tls` / reality-proxy)

REALITY crypto is silent: an invalid client is **transparently proxied to `target`**
(active-probe defense), usually with no log or a DEBUG
`REALITY: bridging non-Qeli connection … to <target>`.

| Message | Level | Meaning |
|---|---|---|
| `REALITY: Qeli client detected from <addr> …` | INFO | the client passed the short_id discriminator + anti-replay |
| `REALITY: Qeli client <addr> … failed after the handshake discriminator (likely config/version/core mismatch): <e>` | WARN | the short_id matched, but the **inner** qeli handshake failed — almost always a config/version/core mismatch (not a probe). Check `key`, `reality_sid`, versions |
| `REALITY: replayed session_id … — bridging as probe` | WARN | a session_id repeated within the window (captured-ClientHello replay) — bridged as a probe |
| `REALITY: failed to connect to backend <target>: <e>` | WARN | the server couldn't reach the decoy site |

Conditions under which a client is treated as "not qeli" and bridged (silently): the
ClientHello didn't parse; key_share ≠ 32 B; the AEAD session_id didn't open **or** the
timestamp is outside ±120 s (check the clock!); **short_id not in the allow-list**
(`short_ids`). The last is the most common "reality won't let me in" cause: the
client's `reality_sid` must be in the server's `obf.tls.reality_proxy.short_ids`.

### 4.7 Web panel

| Message | Level | Meaning / fix |
|---|---|---|
| `Web panel NOT started: bind <addr> has NO admin password…` | ERROR | **fail-closed**: a public bind without `web.password_hash` → the panel does NOT start (the VPN keeps running!). Set a password: `qeli set-web-password`, enable `web.tls = true` |
| `Web panel on non-loopback <addr> WITHOUT TLS…` | WARN | a public bind without TLS — credentials travel in the clear. Enable `web.tls` |
| `Web panel CSRF protection is DISABLED (web.csrf=false)…` | WARN | `web.csrf=false` (dangerous on a public bind) |
| `panel: REFUSING live web-settings reload — … NO admin password…` | ERROR | the panel live-reload is fail-closed too |
| `Web UI (HTTPS) listening on https://<addr>` / `Web UI listening on http://<addr>` | INFO | the panel came up |

---

## 5. Error catalog — clients

The strings are identical on **Windows and macOS** (the shared `VpnTunnelBase`
data-plane) and nearly identical on **Android** (its Kotlin port has the same
messages). Below they're combined; platform differences are marked.

### 5.1 Connection / handshake

| Line | Meaning | Fix |
|---|---|---|
| `Service started: TCP/fake-tls` (`+QUIC` for UDP+quic) | first line of a connect | — |
| `Connecting TCP/UDP <ip>:<port> as user '<u>'…` | resolve+connect to the server | if `TCP connected` doesn't follow — port closed/firewall/wrong IP |
| `TCP connected` / `Bound carrier socket to …` | the carrier socket is up | — |
| `ClientHello sent (NNNN B, hybrid X25519+ML-KEM)` | the PQ ClientHello was sent | if silence follows → **PMTU** (§6.1) or the server silently dropped it (mode/key) |
| `Server identity verified [OK]` | the server identity matched | — |
| `Auth failed: <server text>` | the server replied not-`OK:` — **wrong credentials/ban** | check user/password; on the server look at WARN `AUTH FAIL` (§4.3) |
| `Failed to parse ServerHello` / `Failed to parse hybrid ServerHello` | the server reply didn't parse as a ServerHello | version skew **or** a UDP reconnect with foreign packets / a broken QUIC frame (see §6.2) |
| `Auth OK, IP 10.x.x.x` | session established, IP assigned | — |
| `Applied server-pushed obfuscation params` | pushed obfs settings applied | — |

**Crypto/pinning (Windows/macOS throw a `SecurityException` → a terminal stop with no
retries; Android — `[SECURITY]` + stop):**

| Line | Meaning | Fix |
|---|---|---|
| `[SECURITY] Server identity changed — possible MITM…` / `SERVER KEY MISMATCH - possible MITM` | the pinned key ≠ the server key | if the server key **deliberately** rotated — clear the pin/old TOFU entry and reconnect; otherwise it's a MITM |
| `SERVER KEY MISMATCH for <id> … Pinned <a>, got <b>. If you deliberately rotated the key, remove its line from <known_hosts>…` | the TOFU entry is stale | remove the server's line from known_hosts (desktop) / clear the saved key (Android) |
| `server sent proof-only but no server_public_key pinned` / `server auth proof INVALID` | the identity proof didn't match | check `key=` against `qeli show-identity` |
| `Pinned server key for <id> on first use (TOFU)…` | first connect — the key was remembered (not an error) | for explicit pinning, set `key=` |

**Config guards at connect time (thrown, not in the parser):**

| Line | Meaning / fix |
|---|---|
| `obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)` | obfs mode without `obfs_key` — set the key |
| `reality-tls requires a pinned server key (auth.server_public_key)` / `server key must be 32 bytes (64 hex chars)` / `reality-tls requires reality_sid` | reality-tls without `key=`/`reality_sid=` — add them |
| `bind_static_to_session is on but no server key is pinned…` / `… all-zero TOFU sentinel…` | `bind_static` requires a pinned key — set `key=` or `bind_static = false` |

### 5.2 TUN / adapter / routes

| Line | Platform | Meaning / fix |
|---|---|---|
| `Wintun prewarm failed (<e>); will open in SetupTun` | Win | the background (handshake-parallel) adapter create failed — it opens synchronously (slower) |
| `NOTE: a Wintun driver (X.Y) is already loaded by another app…` | Win | another VPN (OpenVPN/WireGuard/Tailscale) holds the shared Wintun driver at a different version — possible conflicts; a matching 0.14.x is needed |
| `WintunCreateAdapter failed (err …; fresh name/GUID retries also failed)` | Win | can't create the adapter (no admin rights / corrupted driver). Run as administrator |
| `WintunStartSession failed` / `WintunReceivePacket failed` | Win | a Wintun session failure |
| `utun: socket(PF_SYSTEM) failed (errno …) — are you root?` | mac | not root — run via `sudo` or enable the launchd daemon |
| `utun: connect failed / getsockopt(IFNAME) failed …` | mac | can't open utun |
| `Failed to establish VPN interface` | Android | `VpnService.Builder.establish()` returned null |
| `TUN establish with IPv6 failed (<e>); retrying IPv4-only` | Android | the ROM rejected the TUN IPv6 address — auto-fallback to IPv4 (not an error) |
| `WARN: could not determine physical gateway; full-tunnel may loop` | all | no physical gateway found — full-tunnel may loop; check network/routes |
| `local = <addr>: not pinning the server route — carrier follows the bound interface's routing` | Win/mac | with `local`/`lport` set, the server bypass route isn't pinned (deliberate) |
| `Default route now via tunnel (0.0.0.0/1 + 128.0.0.0/1)` | all | full-tunnel is up |
| `IPv6 captured into tunnel (…)` | all | the dual-stack IPv6 leak is closed (`allow_ipv6_leak=true` disables this) |
| `Pinned server route <ip> via <gw>` | Win/mac | the carrier route to the server via the physical gateway |
| `exclude routes need Android 13+ (API 33); ignoring N` | Android | `exclude`/precise LAN-bypass needs Android 13+ |
| `split: app not installed: <pkg>` | Android | a package in the per-app list isn't installed (skipped) |
| `bad dns <ip>: <msg>` / `bad route <cidr>: <msg>` | all | the server pushed / the config has a broken resolver/route — skipped |
| `<exe> <args> -> exit <code>: …` (`InvalidOperationException`) | Win/mac | a mandatory `netsh`/`route`/`ifconfig` command returned non-zero — see stdout/stderr in the line |
| `full tunnel: could not install route 0.0.0.0/1 …` / `… is not in the routing table … after being added` | Linux | **fatal since 0.7.12.** This used to be a `warn` the client carried on from — half of IPv4 left the tunnel while the indicator stayed green. The connection is now refused. Read the `ip` text in the line: usually missing privileges (not root) or a clash with an existing route |
| `full tunnel: could not pin the server bypass route …` | Linux | fatal: without the bypass the encrypted path to the server would be routed into the tunnel being built |
| `could not route included subnet <cidr> … refusing to run` | Linux | fatal: a subnet listed in `include` would have left unencrypted |
| `full tunnel: IPv6 blackholed (…)` | Linux | expected since 0.7.12: qeli tunnels IPv4 only, so IPv6 is blocked. Need IPv6 direct? Set `allow_ipv6_leak = true` |
| `full tunnel: IPv6 is NOT fully blocked …` | Linux | the blackhole did not install (no `ip -6`?) — IPv6 may bypass the tunnel |
| `kill-switch: could not install N allow rule(s) in QELI_KS_<if> …` | Linux | **since 0.7.12** the chain refuses to arm when an allow rule did not land (otherwise it would cut the host off from the very tunnel it protects). See the listed rules |
| `interface '<dev>' already exists …` | Linux | see §6 — our own orphaned interface is reclaimed automatically; a refusal means it is held by **another** process, or is not a tuntap device |

### 5.3 Liveness / reconnect (why it drops and reconnects)

The RX watchdog counts only records that pass framing, length and AEAD authentication.
For heartbeat its deadline is `max(3×(interval+jitter), 30s)`; for shaping it is
`max(3×(idle_gap_max+1s), 30s)`. On an authenticated-downlink loss the client tears the
link down and reconnects. With both mechanisms disabled there is no RX watchdog. Backoff
is exponential (cap 60s), retries are infinite by default.

| Line | Meaning |
|---|---|
| `no authenticated data from server for >Ns` | no valid heartbeat, cover or data record arrived before the derived `rxDead` deadline. Raw/forged UDP does not keep the session alive |
| `resumed after ~Ns suspend — reconnecting` | the host slept (the wall clock jumped ≫ monotonic) — immediate reconnect. L1 |
| `Network changed — reconnecting` / `<reason> — reconnecting` | the physical network changed (Wi-Fi↔Ethernet/LTE) — a proactive `ForceReconnect`. The accompanying socket error (`recvfrom EBADF` / EBADF) is **deliberately suppressed** and not logged as an `ERR:` |
| `Reconnect attempt N in Xs` | a normal backoff retry |
| `Max retries reached, giving up` | the configured retry cap was hit (infinite by default) |
| `Reconnect disabled, giving up` | `reconnect = false` in the config |
| `Connection closed cleanly` | the server closed the connection cleanly |
| `ERR: [<Class>] <msg>` + `  <- <cause>` | a generic loop error (socket/handshake) — read the nested `<-` causes |

**Android specifics:** `PacketTooLarge` / oversized-record under load and EMSGSIZE on
UDP historically dropped the loop into a reconnect storm — in current builds the
padding is capped to the MTU and a UDP send error drops the packet (non-fatal). If you
see a storm on an old APK — update the client.

### 5.4 Config parsing

**Android** (`Config.kt`) — throws exceptions (in the UI: toast `Invalid config: …`):
`config: missing [qeli] section`, `[qeli] missing required key 'server' (host:port)`,
`'server' must be host:port, got '…'`, `'server' has empty host`, `'server' has
invalid port: '…'`; for links: `not a qeli:// link`, `qeli:// authority missing
:port`, `invalid port in qeli:// link`, `empty host in qeli:// link`,
`qeli:// authority malformed IPv6 [host]:port`.

**Windows/macOS** (`VpnConfig.cs`) — the INI parser is **lenient, not throwing**: a
config without `[qeli]` yields defaults; **an invalid port silently falls back to 443**;
the empty-`obfs_key` guard is not in the parser but at connect time (§5.1). Only
`FromQeliUri` throws (the same `FormatException`s as above). The profile editor
validates fields separately: `Enter the server address.`, `Invalid port (1–65535).`,
`Enter the username.`.

---

## 6. Common scenarios

### 6.1 "accept → silence on both sides" = a PMTU black-hole

**Symptom:** the client `ClientHello sent (…B)` and hangs; the server `New TCP
connection` / `UDP handshake started` and then silence; at debug — `handshake timeout
for <addr>`.

**Cause:** the PQ ClientHello is large (~1.4–1.5 KB, and with TLS/TCP/IP already >1500).
If any link on the path has MTU < 1500 (PPPoE 1492, LTE/CGNAT, VPN-over-VPN) and the
ICMP "fragmentation needed" is filtered, the big segment silently vanishes. The TCP
handshake completed (`New TCP connection` is present) but the app-level ClientHello/
ServerHello doesn't arrive.

**Fix (server, both clamp directions):**
```bash
# server→client (ServerHello): clamp the incoming SYN
iptables -t mangle -A PREROUTING -p tcp --dport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
# client→server (ClientHello): clamp the outgoing SYN-ACK (the installer usually sets this)
iptables -t mangle -A OUTPUT     -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -L OUTPUT -n -v | grep TCPMSS   # verify it applied
```
`--set-mss 1240` = MTU 1280 (survives LTE/CGNAT/the IPv6 minimum). Confirmation:
connect **from a different network** (wired Ethernet 1500). If it works there, MTU is a
**likely** cause but not the only one: DPI, NAT hairpinning (see §6.8), UDP blocking and
firewall rules all produce the same symptom. The tell is easy: with MTU, large packets
are silently lost while small ones pass — the handshake completes and the download
stalls. If the connection never establishes at all, MTU is not your problem. On the
client you can lower `mtu` in the profile.

### 6.2 `Failed to parse ServerHello` on a UDP reconnect

**Symptom:** the first connect succeeds, then a watchdog/network event triggers a
reconnect → `Failed to parse ServerHello` several times; on the server you see re-auth
from a **new** source port and `UDP writer … kicked`.

**Cause:** a UDP reconnect from a new source port (NAT remap, especially
VPN-over-VPN) plus a possible QUIC-framing/fragmentation mismatch of the ServerHello.
Current builds (0.7.11) reworked UDP sessions (kick_all, fragmented ServerHello,
writer-leak fix). **Fix:** update the server to 0.7.11 or newer and retest; check that
`quic` matches client↔server (`quic = true`/`quic=1`).

### 6.3 Reconnect storm / hosting ban

**Symptom:** a tight `Connecting… → Auth OK → closed/reconnect` loop, on the server
`Rate limit exceeded for <ip>` and/or an AUTH flood.

**Causes (all documented in code, issue #69):** premature "Connected" before the TUN
was up reset the backoff; an EMSGSIZE loop on udp-quic; a short (<5 B) UDP record
crashed the loop; a fast Wi-Fi↔LTE flap without a retry floor. **Fix:** update the
client (0.7.9+ added a reconnect floor, "Connected only after TUN", a UDP drain). On
the server — don't lower `new_session_rate_max` too aggressively.

### 6.4 "The client isn't the one the server expects" (key/mode)

**Symptom:** on the server (info) `AUTH DENIED … server key not pinned`, or reality
`Qeli client … failed after the handshake discriminator`, or a client crypto error.

**Fix:** check the public key against `qeli show-identity --config <cfg>`; the client's
`key=`, `mode=`, `reality_sid=` must match the server. Reissue the link:
```bash
qeli add-client <user> --password '<pw>' --link --host <public-ip>:<port> \
  --link-profile <profile> --config /etc/qeli/server.conf
```

### 6.5 A grey profile indicator ≠ "not connected"

The grey dot on a profile card is a **server reachability probe** (Unknown/grey = not
probed yet), **not** the tunnel status. The tunnel status is a separate indicator
(Disconnected/Connecting/Connected/Error). Tap "Ping" / wait for the auto-poll. Green
for the connected active profile is set directly (probing through the live full-tunnel
is unreliable).

### 6.6 `protect() failed …` (Android) = a conflict with an always-on VPN

`WARN: protect() failed for <label> after retries — the socket may not bypass the
tunnel (another active/always-on VPN, or VpnService not ready)` — almost always
**another always-on VPN** is installed. Disable it / clear "Always-on VPN" in Android
settings.

### 6.7 The panel :8080 won't come up, but the VPN works

`Web panel NOT started: non-loopback bind … NO admin password` (fail-closed). The VPN
is alive, only the panel doesn't start. Set a password (`qeli set-web-password`) +
`web.tls = true`, then restart. Don't confuse this with a VPN failure.

### 6.8 Client and server on the same LAN → reconnect loop

**Symptom:** the client and the server are on the **same subnet** (e.g. both on
`192.168.50.0/24`). The handshake completes fully — `Server identity verified`,
`Auth OK`, `TUN ready` — but no traffic flows: the authenticated RX watchdog fires (when
heartbeat/shaping is enabled), or the server tears down the idle session after ~20 s
(client sees the connection reset;
the server reaps the inactive session) → an endless reconnect loop. **The same profile
works from a different network (the Internet / another subnet)** — that contrast is the
key tell.

**Cause (routing, not a client/server bug):** the desktop client pins a /32 route to the
server **via the physical gateway** (`Pinned server route <srv> via <gw>`) so the carrier
traffic never loops back into the tunnel. When the server is **on-link** (same subnet as
the client) this makes the path asymmetric: outbound goes `client → gateway → server`
while replies come `server → client` directly (same subnet). The gateway lets the handful
of handshake packets through but breaks the sustained data plane. From another network the
server is genuinely behind the gateway → the path is symmetric → it works.

**Fix:** set `local` to this host's LAN IP in the client profile:
```ini
local = 192.168.50.50
```
With `local` set the client binds the carrier socket to that interface and does **not** pin
the server via the gateway → the server is reached on-link directly → symmetric path, and
the tunnel works on the same LAN. A quick way to confirm the cause is to connect from a
different network (wired Ethernet / mobile data): if it works there but not on the LAN,
this is it.

Server-side check (while the client is connected but stalled): the session counters show
`SENT`/`RECV` = 0 and only grow on real exchange — with this problem both stay zero even
under load, because the asymmetric carrier flow never gets through.
```bash
qeli list-clients                      # session SENT/RECV (0/0 = data plane not flowing)
```

### 6.9 The panel cannot issue a QR / link — "no permission on `/etc/qeli`"

**Symptom:** the install went fine and the VPN works, but the panel will not issue a link
or a QR code; the log shows a permission denial on `/etc/qeli/users.conf.lock` (or on
`users.conf` itself).

**Cause.** The service and the panel run as the `qeli` user, but the CLI is normally run
under `sudo`. An atomic write — write a temp file, then `rename` — swapped in a **new inode
owned by the writer**, so a single `sudo qeli add-client` flipped `/etc/qeli/users.conf`
from `qeli:qeli` to `root:root`. The lock file is created with the owner of the file it
guards, so it went root-owned too — and the panel, running as `qeli`, could no longer take
it. The `chown -R` in postinst does not help here: it runs at install time, **before** those
writes.

**Fixed** in 0.7.13: an atomic write now preserves the owner of the file it replaces
(regression test `atomic_write_preserves_owner`, run as root). On an **already broken**
install the ownership has to be restored by hand, once:
```bash
sudo chown -R qeli:qeli /etc/qeli
sudo systemctl restart qeli
```
Check (everything should belong to `qeli`):
```bash
ls -la /etc/qeli/
```

### 6.10 Client refuses to change DNS: systemd-resolved is not the resolver

**Symptom:** a connection using `dns = tunnel` stops with
`refusing to replace /etc/resolv.conf with tunnel DNS`.

**Cause.** The client picks its DNS path not by whether the binary exists, but by what
actually **resolves** on this machine: whether `/etc/resolv.conf` points at the
systemd-resolved stub. If the service is installed but not enabled, or `resolv.conf` was
left as a plain file (the usual state after removing `resolvconf` on Ubuntu), then
`resolvectl dns` is a silent no-op.

Starting with 0.7.15 qeli deliberately **does not replace persistent `/etc/resolv.conf`**:
after `SIGKILL`, power loss or client removal it could retain the vanished tunnel resolver
and break DNS for the whole host. Legacy backups are still recovered at startup, but new
ones are not created. Enable the lifecycle-safe per-link path:
```bash
sudo systemctl enable --now systemd-resolved
sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```
Check (it should be a symlink to the stub):
```bash
ls -l /etc/resolv.conf
```
If NetworkManager, dnsmasq or the OpenWrt platform already owns DNS, leave it there and set
`dns = off` in the qeli profile.

### 6.11 After saving settings in the panel the service still needs a manual restart

**Symptom:** "Apply & Restart" reports no visible error, but the service keeps running the
old configuration.

**Cause.** The panel does not run as root, and what lets an unprivileged user call
`systemctl restart` is a polkit rule. The `.deb` ships one; a script or manual install does
not. The panel asks polkit about the effective service user and unit before restarting and
returns `polkit_missing` when that action is denied. It does not inspect the rule file:
on Ubuntu `/etc/polkit-1/rules.d` may be inaccessible to `qeli` even though polkitd has
loaded the rule successfully.
Install it once:
```bash
sudo qeli install-polkit
sudo systemctl restart qeli
```
Check the effective permission (this is more reliable than reading the rule directory):
```bash
sudo -u qeli systemctl restart qeli.service
```

**In a container** the rule will not help: `systemctl` there does not manage the host, so
"Apply & Restart" cannot restart the service — the panel reports that separately
(`kind: container`). Restart from outside:
```bash
docker restart <container-name>
```

### 6.12 Clients: slow recovery after sleep or phone unlock

**Symptom:** after waking from sleep the tunnel takes about a minute to come back;
sometimes it disappears entirely during that window and traffic goes outside the VPN.

**Cause.** The exponential reconnect backoff exists so we do not hammer a server that is
down, but it also counted attempts that failed into a **network that was not up yet** (Wi-Fi
reassociating, DHCP pending). At the default base delay of 1 s the delay doubles every
attempt, so the handful of attempts burned while the network came up left the client asleep
for 16–32 s **after** it became usable. With a finite `max_retries` those same attempts
could exhaust it, and giving up tears down the TUN and routes — hence traffic leaving
outside the tunnel.

**This took two passes, both within 0.7.13.** The first capped the pauses **between**
attempts (retry at least every ~4 s for 30 s after a resume). Correct in itself, but it
missed the dominant term: the time was going **inside a single attempt**, so 0.7.13 builds
predating the second pass still showed the original delay.

**What the second pass closed.** Name resolution used a blocking call with **no timeout at
all**, and `ConnectionTimeoutSecs` — default **30 s** — was charged to the connect and again
to the handshake reads. One badly-timed attempt therefore outlasted the whole settling window
by itself. The entire pre-data-plane phase (resolve + connect + handshake) is now capped at
5 s while the network settles, and resolution is time-bounded always. On top of that the
window was not being armed at all in the most common case: it sat behind a "tunnel still
connected" guard, and after a suspend the tunnel is already dead by the time the Resume event
lands. No action is required beyond running a current 0.7.13 build.

**Mobile and headless closure in 0.7.15.** Keeping the Android CPU awake does not keep the
Wi-Fi association or NAT mapping alive, and the same Android `Network` object can survive a
DHCP/link change. The service now compares that network's capabilities, link addresses, routes
and DNS, and after screen-on waits briefly for a usable physical IPv4 path before replacing the
native transport generation while retaining the TUN. iOS now replaces an established generation
after `PacketTunnelProvider.wake()` instead of only logging the event. Windows Service and the
macOS launch daemon poll the filtered physical-network signature themselves, because the GUI's
network callbacks do not own the headless tunnel. Blocking Android/iOS resolver calls are limited
to one outstanding request, so repeated reconnects cannot accumulate resolver threads.

Manual disconnect is also an asynchronous boundary in 0.7.15. Android displays
`Disconnecting` until the Rust runner has exited and every duplicated TUN descriptor is closed;
only then does it publish `Disconnected` and permit another connection. This matters for DNS:
starting a new generation while the old TUN still owned Android's routes could leave the device
resolver selected on a descriptor that no longer had a data plane. If DNS fails after a manual
disconnect, capture the log from `Disconnecting` through the next `Connected`; a teardown warning
longer than 5 seconds identifies a native descriptor owner that did not stop promptly.

To confirm from the log (**Log** tab → **Copy log**): a resume should now produce
`Network settling — short attempt budget 5s for the next 30s`. If that line is present and
recovery is still slow, the time is going somewhere else — send the whole log covering
wake → `Connected`. On mobile 0.7.15 the same interval should contain `Device woke` / `Device
wake: replacing...` (iOS) or `Device woke after ... screen-off — reconnecting` (Android).

### 6.13 Panel behind a reverse proxy: 404, or thrown to the site root

**The symptom pair is the diagnosis:** with `base_path` set the panel returns **404**; without
it the panel loads but throws you to the root of the site.

> ⚠️ **First check that the `base_path` line carries no comment.** In flat-INI, `#` and `;`
> begin a comment **only at the start of a line**, so `base_path =    # keep empty` sets the
> value to the literal `# keep empty`. The panel then mounts under a prefix nobody requests
> and **every** route, `/login` included, returns 404. From this version on the server rejects
> such a value, logs `web.base_path = "…" is not a plain URL path`, and serves the panel at
> the root instead. An empty value is written simply as `base_path =`, with nothing after it.

**Cause.** The prefix has two independent consumers, configured by different things:

| What | Comes from | Applied |
|---|---|---|
| Where routes are mounted | **only** `web.base_path` | at process start |
| `<base href>` and redirects | `X-Forwarded-Prefix`, else `web.base_path` | per request |

Hence two working configurations, and they are mutually exclusive:

| | `web.base_path` | Proxy |
|---|---|---|
| A | empty | strips the prefix, sends `X-Forwarded-Prefix` |
| B | `/qeli` | does **not** strip the prefix |

**A 404 with `base_path` set means your proxy strips the prefix** — so you need variant A, not
B. In nginx that is decided by the trailing slash on `proxy_pass`: without it the original URI
is passed through whole (variant B), with it the location prefix is stripped (variant A).

**Being thrown to the root is `trusted_proxies`.** Pages load, because relative links resolve
against the request URL. But every page without a session issues `Redirect::to("/login")`, and
the login page issues `Redirect::to("/")` — and the prefix is prepended to those redirects
**only when it is non-empty**. `X-Forwarded-Prefix` is honored only from an address listed in
`web.trusted_proxies`; with an empty list the header is dropped, the prefix becomes empty, and
the redirect lands on the site root.

> This is why the symptom looks intermittent: with a live session there is no redirect and
> everything works; after a service restart or session expiry the panel starts "throwing you
> to the root".

The full variant A:

```ini
[web]
bind = 127.0.0.1
base_path =
trusted_proxies = 127.0.0.1
public_host = your-domain.com
```

```nginx
location /qeli/ {
    proxy_pass http://127.0.0.1:1444/;          # trailing slash — strips /qeli
    proxy_set_header X-Forwarded-Prefix /qeli;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

`base_path` applies only on a **full** process restart; `trusted_proxies` reloads live.

Check:
```bash
curl -s https://your-domain.com/qeli/login | grep -o '<base href="[^"]*"'
```
Expect `<base href="/qeli/">`. If it is `/`, look in the server log for
`panel: ignoring X-Forwarded-Prefix from … not covered by web.trusted_proxies` — it names the
exact address to add.

### 6.14 macOS: DNS `10.9.0.1` remains after removing Qeli

macOS generates `/etc/resolv.conf`; do not repair it directly. Inspect the recovery journal
first — `previousServers` may contain custom resolvers that should be restored instead of
`empty`:

```bash
sudo cat "/Library/Application Support/Qeli/dns-override.json" 2>/dev/null
sudo launchctl bootout system/ru.qeli.app.daemon 2>/dev/null || true
sudo launchctl bootout system/ru.autocash.qeli.daemon 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/ru.qeli.app.daemon.plist
sudo rm -f /Library/LaunchDaemons/ru.autocash.qeli.daemon.plist
networksetup -listallnetworkservices
sudo networksetup -setdnsservers "Wi-Fi" empty
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
networksetup -getdnsservers "Wi-Fi"
scutil --dns
```

Replace `Wi-Fi` with the exact active service name. If `previousServers` lists addresses,
pass those to `-setdnsservers` instead of `empty`. Remove the old journal only after the
checks succeed:

```bash
sudo rm -f "/Library/Application Support/Qeli/dns-override.json"
```

In 0.7.15 the daemon stores Connect intent separately from installation, verifies the actual
`launchctl bootout`, and does not confirm Disconnect until the original DNS is restored.

---

## 7. Reference

### 7.1 Tunnel statuses (clients)
`Disconnected` (grey) · `Connecting` (yellow, including reconnect and "TUN not up
yet") · `Connected` (green, **only after the TUN is up**) · `Error` (red, the error
text — from the server's `EXTRA_ERROR` / the last cause).

### 7.2 Reachability dot colors (profile card)
Reachable → green (`N ms`) · Unreachable → red (`offline`) · Checking → yellow (`…`) ·
Unknown → **grey** (not probed yet).

Android `reach` sentinels: `-1` = unreachable (red), `-2` = checking (yellow), `≥0` =
ms (green), `null` = grey.

### 7.3 Log line prefixes (clients)
`ERR:` — a loop error · `WARN:` — a warning (non-fatal) · `NOTE:` — an informational
note · `[SECURITY]` — crypto/MITM (**terminal**, no retries) · `  <- …` — a nested
exception cause.

### 7.4 Server log levels
`info` (default) — startup, `New TCP connection`, `AUTH OK`, all `AUTH FAIL/DENIED/
BLOCKED` (WARN). `debug` — reasons for refusal **before** authentication (`handshake
timeout`, `Client … disconnected: …`, `UDP handshake failed`, REALITY bridging).
`RUST_LOG` overrides `[logging] level`.

---

## 8. Command checklists

### 8.1 Server
```bash
# status, version, listeners
systemctl is-active qeli
/usr/bin/qeli --version
ss -ltnp | grep qeli ; ss -lunp | grep qeli

# log: problems only / real time
journalctl -u qeli --since '10 min ago' -p warning --no-pager
journalctl -u qeli -f

# enable debug and watch the decisive line
mkdir -p /etc/systemd/system/qeli.service.d
printf '[Service]\nEnvironment=RUST_LOG=debug\n' > /etc/systemd/system/qeli.service.d/zz-debug.conf
systemctl daemon-reload && systemctl restart qeli && journalctl -u qeli -f

# server identity (public key to pin)
qeli show-identity --config /etc/qeli/server.conf

# brute-force locks
qeli list-blocked ; qeli unblock <ip>

# reissue a client link
qeli add-client <user> --password '<pw>' --link --host <ip>:<port> --link-profile <profile> --config /etc/qeli/server.conf

# the server's REALITY cert from outside (masking)
echo | openssl s_client -connect 127.0.0.1:443 -servername www.microsoft.com 2>/dev/null | openssl x509 -noout -subject

# PMTU fix (both directions)
iptables -t mangle -A PREROUTING -p tcp --dport <port> --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
iptables -t mangle -A OUTPUT     -p tcp --sport <port> --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
```

### 8.2 Android client
```bash
adb logcat -s VpnSvc VpnMain            # service + activity log
# reset profiles / VPN consent when stuck:
adb shell pm clear com.qeli
adb shell appops set com.qeli ACTIVATE_VPN allow   # if supported
```

### 8.3 Desktop (Windows/macOS)
- **Log** tab → **Copy log** — attach it when troubleshooting.
- Windows requires **administrator** (manifest `requireAdministrator`); macOS —
  **root** (`sudo`) or the launchd daemon enabled.
- Kill-switch left over after a crash? Windows:
  `Remove-NetFirewallRule -Group qeli_ks; Set-NetFirewallProfile -All -DefaultOutboundAction Allow`;
  macOS: restart / `pfctl -d` (the "Found a stale kill-switch…" line self-heals on the next start).
- `kill-switch is owned by another live Qeli process` means a second Windows tunnel tried
  to take over the same machine-wide firewall state. Stop the other client/service first.
- `[SECURITY] kill-switch disengage failed; egress remains blocked` is fail-closed: the
  recovery state and ownership remain armed so the same process (or the next startup) can
  retry a complete three-profile firewall restore. Do not delete the recovery state by hand.

---

*This document is based on the current code (`qeli/src/**`, `qeli-shared`, `qeli-win`,
`qeli-mac`, `qeli-android`) on the `dev` branch. Error strings are checked against the
sources; if behavior diverges, trust the code and update this file.*
