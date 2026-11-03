# Qeli — connection diagnostics and error reference

> **Documentation status:** current development tree **0.8.3**; planned full-IPv6 release **0.8.3**;
> package version covered by this guide **0.8.3**.
> `qeli --version` reports the version of the binary actually installed.
> See [GitHub Releases](https://github.com/litvinovtd/qeli/releases) for package availability and publication status.
> Links to this version's files work after its publication.

A detailed, practical guide: how to enable debug logging, how to read the log by
connection stage, what every server and client (Windows / macOS / Android) error
means, and how to fix it. All strings are verbatim as they appear in the log.

> For the dedicated inner/outer IPv6, `off/manual/route/nat66`, NDP proxy, PMTU, DNS and leak checklist, see the
> [IPv6 guide](IPV6.md).

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

> **Server log format:** `[logging] format = plain|json` selects text or one JSON object
> per record. `time_format` controls timestamps separately. Changing either setting
> requires a full server restart; a worker restart does not reconfigure the supervisor's
> logger. Configuration files remain INI. See [logging](CONFIG.md).

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

The VPN service keeps a private persistent journal even while the Activity is closed or its
process UI is recreated. The newest 1,000 events are retained, capped at 512 KiB, and restored
into the **in-app Log tab** (index 3) when Qeli opens. The file is held in Android's private
no-backup directory and never contains the password, private keys, or the complete profile.

<!-- normative-sync: android-disconnect-log-settings-v1 -->

**Settings → Clear log after disconnect** is **enabled by default**, including after an
upgrade when no choice has been saved. Once VPN shutdown completes, the service removes
the saved journal and clears the visible tab, even if the app was backgrounded or closed.
A connection ending with an error also clears the journal; the error remains on the main screen.

For diagnostics, turn this option off beforehand and tap **Save**: history survives disconnect
and is restored when the app opens again; **Copy log** includes events emitted while the
screen was off. The setting applies to the next disconnect without requiring a reconnect;
saving it does not erase existing entries immediately. Cancel does not change the choice.
Automatic reconnects, network changes, active connection reconfiguration and trusted-Wi-Fi
pauses do not clear the journal. The manual **Clear** button remains available independently.

The default Info level records session boundaries, stop reasons, network loss/reconnect,
Android service redelivery/revoke and battery-optimization warnings. Debug/Trace additionally
records screen-off/screen-on timing and detailed adapter events. Timestamps remain configurable
in Settings → Log timestamp; restored entries keep their original event time. The default is
time-only because a full date consumes phone width.

An active user-requested VPN returns `START_REDELIVER_INTENT`; Android can therefore redeliver
the exact connect request after killing the service process. Explicit Disconnect first clears
the durable desired-state bit and is never restarted. OEM force-stop/background policies can
still prevent any service restart, so exclude Qeli from battery optimization when diagnosing.
The same process-level output is available via `adb`:
```bash
adb logcat -s VpnSvc VpnMain
```
`VpnSvc` is the VPN service and `VpnMain` is the Activity. Uncaught Android runtime crash lines
can still exist only in logcat; Qeli's own service diagnostics are written to the durable tab.

### iOS client log

<!-- normative-sync: ios-disconnect-log-settings-v1 -->

**Settings → Appearance → Clear log after disconnect** is **on by default**, including
after upgrades. Unlike Android's Save button, iOS applies this switch immediately to the
next stop of the current session; changing it does not erase the journal right away.
Disable it before reproducing a problem to keep the shared App Group history across
disconnects and app launches. The log retains at most 500 entries, 4 KiB per message and
1 MiB of encoded history.

The VPN extension clears history after a terminal stop or start failure, even while the
app UI is closed; the error status remains available. Reconnects inside the running
extension and settings reloads do not clear it. Stops reported by iOS as network loss,
network change, sleep or app update retain history, as do unspecified On Demand stops
while the desired connection remains armed (including trusted-Wi-Fi waiting).
Late callbacks from a completed session cannot refill the journal. Manual **Clear**
remains independent. A forced process kill may prevent the extension from cleaning up.

### 1.4 Packet trace (`QELI_TRACE`, Rust server and Rust client)

When logs are too coarse, tracing shows packet timing and sizes at processing points
inside the application. Enabled by an environment variable, off otherwise:

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

- `t_us` — microseconds since tracing initialized in this process, `dir` — `tx` (TUN → tunnel) / `rx`
  (tunnel → TUN), `site` — the capture point, `size` — bytes, `seq` — stream index.
- Only packet **shapes** are written: no payloads, no addresses — a trace can be attached
  to an issue without exposing anyone's traffic.
- The buffer is a 65,536-event ring. The header's `overwritten=` says how many events were
  overwritten (the trace outran the buffer) and `contended=` how many were lost to lock
  contention: a trace is **never silently partial**.
- Both ends write their own file with a separate time origin. `seq` is a stream index,
  not a packet identifier or TCP sequence number.

<!-- normative-sync: q36-trace-correlation-v1 -->

Comparing client and server traces first requires an external alignment of their time
axes. Matching time and size after alignment is only a hypothesis: multiple packets
can have the same size. The CSV cannot prove delivery of a particular ACK or measure
its exact delay between peers.

An event means the packet reached `site`, not that network transmission completed.
For example, `server.stream` records after dequeue, before rate limiting, encryption
and socket writes; receive-side `client.tcp` records before the TUN queue accepts
the packet. An event can exist even if a later enqueue or send fails. The size at
that point may also differ from the encrypted record and network packet sizes.
To verify delivery and latency, use separate captures on the relevant interfaces
with packet identification and verified clock alignment. Account for ring-buffer
incompleteness and the diagnostic capture's effect on load.

<!-- normative-sync: q32-log-trace-io-v1 -->

Dump files are published by atomic replacement with Unix mode `0600`. A symlink
or FIFO at the destination is replaced; its target is not written. The parent
directory must exist. Failed publication preserves the previous dump; an error
syncing the directory after rename means publication occurred with uncertain
durability. Dump I/O runs outside Tokio workers, with one admitted dump per process.
A stalled filesystem syscall can retain that slot even after the watcher stops.
`SIGUSR1` is required: shutdown does not dump automatically. Separate processes
should use separate destinations; a shared destination retains the last publication.
Current capture sites cover Rust client TCP/UDP and server TCP. Server UDP,
core-owned transport paths and standalone `qeli-client` tracing are not qualified
by this mechanism. Missing records do not prove packet loss.

The panel Logs page polls `/api/logs`; it does not use SSE. Authentication applies.
Reading is limited to the recent 4 MiB, at most 2000 lines and four concurrent
blocking readers per process. A busy reader returns `ok=false`; retry the request.
An API `filter` is limited to 1024 UTF-8 bytes and searches only that recent window.
Only regular files inside `/var/log/qeli` are accepted. A path swapped to a
symlink or FIFO after validation is rejected; rotation cannot redirect an already
opened descriptor. The no-file response explains journald instead of streaming it.
These limits bound read jobs, not all outstanding HTTP responses or disk latency.

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
  `supervisor: worker stopped unexpectedly — respawning in Ns` and respawns with backoff.

Repeated spawn failures and unexpected exits use delays of 1, 2, 4, 8, 16 and then
at most 30 seconds. A generation that ran for at least 30 seconds resets the delay.
SIGINT/SIGTERM remain active during retry. Exit status is logged separately, and
the worker PID metric is cleared while no new process exists.

For an **internal** worker restart (`POST /api/server/restart`), the new process
reads configuration after the old one exits, without crash backoff. Restart wakes
a pending retry; old queued commands coalesce. ReloadUsers preserves connections
in an active worker; while it is absent or terminating, the next generation reads
the updated users instead.

A worker gets 60 seconds to stop gracefully, then the supervisor requests SIGKILL
and waits for exit. Repeated Restart does not extend this deadline. The message
`worker did not stop within 60s — killing and reaping it` means forced termination:
post_down may not have run and complete firewall rollback is not guaranteed.
The next worker clears stale NAT rules during startup. The 60 seconds bounds the
grace period, not an uninterruptible kernel wait after SIGKILL.

`worker service 'usage sweep' failed: ...` (or `stopped unexpectedly`) means the
required accounting/quota task has failed. The same rule applies to `UDP loss report`:
the worker starts cleanup instead of silently continuing without that service. An
unarmed packet trace is optional and may return normally. Graceful stop finishes the
current periodic cycle before stopping profiles, then collects and persists final
traffic while retaining exclusive worker ownership. `usage: shutdown flush failed`
means the final write failed; inspect disk space, permissions and the preceding error.
The worker reports failure, and unpersisted statistics are not guaranteed to survive.

Notification warnings: `notify: queue full` means new events exceeded the per-process
128-delivery budget; they are dropped, not retried indefinitely. `notify: shutdown deadline`
means ten seconds of drain elapsed and remaining deliveries were cancelled. Check the
channel-specific transport/HTTP warnings for a slow or rejecting destination. **Send test**
shares the same budget and reports queue, cancellation or timeout errors directly.
See [notification limits](PANEL.md#notifications).

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
| `profile '<n>': perf.connection.handshake_timeout_secs and perf.connection.max_clients must be > 0…` | one of the flat-INI keys is explicitly zero | remove the zero-valued key to use its baseline default, or set a positive value |
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
| `REALITY: Qeli client <addr> … failed after the handshake discriminator (likely config/version/core mismatch): <e>` | WARN | the short_id matched, but the authenticated carrier or subsequent qeli exchange failed — usually a config/version/core mismatch (not a probe). Check `key`, `reality_sid`, versions and upgrade order |
| `REALITY: genuine HTTP/2 carrier established with <addr>` | DEBUG | the current H2 carrier is established; normal qeli auth follows |
| `REALITY HTTP/2 carrier timed out/failed for <addr>: <e>` | WARN/error context | Reality discrimination succeeded but H2 did not. Check server-first upgrade order and remove any upstream TLS termination/H2 conversion |
| `REALITY: replayed session_id … — bridging as probe` | WARN | a session_id repeated within the window (captured-ClientHello replay) — bridged as a probe |
| `REALITY: failed to connect to backend <target>: <e>` | WARN | the server couldn't reach the decoy site |

Conditions under which a client is treated as "not qeli" and bridged (silently): the
ClientHello didn't parse; key_share ≠ 32 B; the AEAD session_id didn't open **or** the
timestamp is outside ±120 s (check the clock!); **short_id not in the allow-list**
(`short_ids`). The last is the most common "reality won't let me in" cause: the
client's `reality_sid` must be in the server's `obf.tls.reality_proxy.short_ids`.

For the current path the client also logs `REALITY-TLS carrier: genuine HTTP/2 stream` at INFO.
Upgrade the server first: the new server accepts H2 and the legacy Reality carrier, while the
new client is H2-only. A reverse proxy/LB in front of qeli must use transparent TCP pass-through.

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

Windows, macOS and Android use the shared Rust transport; C#/Kotlin adapters
add system-API, service and UI messages. Common core errors are collected below;
platform differences are marked. Wording and prefixes can depend on adapter and version.

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
| `TUN establish with IPv6 failed (<e>); retrying IPv4-only` | Android | the ROM rejected only the synthetic IPv6 leak-block address of an IPv4 plan. A real negotiated IPv6 address never downgrades: that failure is fatal |
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
| `could not install blackhole <half>` | Linux | the negotiated full-tunnel plan lacks that address family and qeli could not enforce its fail-closed block. Fix `ip route`/privileges, use a dual profile, or deliberately set the matching `allow_ipv4_leak`/`allow_ipv6_leak` |
| `kill-switch: could not install N allow rule(s) in QELI_KS_<if> …` | Linux | **since 0.7.12** the chain refuses to arm when an allow rule did not land (otherwise it would cut the host off from the very tunnel it protects). See the listed rules |
| `interface '<dev>' already exists …` | Linux | the client only waits for release; the server refuses immediately. Automatic recovery deletion is disabled; see §6.47 |

### 5.3 Liveness / reconnect (why it drops and reconnects)

The RX watchdog counts only records that pass framing, length and AEAD authentication.
Reality/H2 forces qeli heartbeat off even when an old local/pushed config enables it; its liveness
comes from the carrier and normal authenticated traffic. In other modes, for heartbeat the deadline
is `max(3×(interval+jitter), 30s)`; for shaping it is
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
| `WARN: could not prepare a safe reconnect: …; retrying recovery N/5 in Xs` | Windows/macOS is retrying restoration of the previous network state **before** another connection. The configured retry policy and cancellation still apply; one successful recovery resets the consecutive-failure counter |
| `[SECURITY] could not prepare a safe reconnect: …; recovery stopped …` / `recovery retry policy exhausted` | recovery reached its consecutive-failure limit or retry policy, or a classifier/firewall safety operation was refused. The client stops reconnecting and reports Error |
| `platform cleanup failed; egress remains fail-closed` | Windows/macOS could not finish cleanup. The kill-switch/replacement guard and resource ownership remain available for a retry; retry Disconnect after resolving the reported platform failure |
| `ERR: reconnect loop faulted: …` | an unexpected lifecycle error reached the outer handler. Terminal cleanup is attempted and Error is published; a cleanup failure does not release the protective block |
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
# If the listener is also on IPv6, use its 40-byte IP header: 1280−40−20 = 1220.
ip6tables -t mangle -A PREROUTING -p tcp --dport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
ip6tables -t mangle -A OUTPUT     -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
```
IPv4 `--set-mss 1240` and IPv6 `--set-mss 1220` both fit a 1280-byte path. Confirmation:
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
(Disconnected/Connecting/Connected/Error). Tap "Ping" to check it manually; automatic polling is opt-in and disabled by default.
Green for the connected active profile is set directly (probing through the live full-tunnel
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
it. The ownership repair in postinst does not help here: it runs at install time, **before** those
writes.

**Fixed** in 0.7.13: an atomic write now preserves the owner of the file it replaces
(regression test `atomic_write_preserves_owner`, run as root). On an **already broken**
install the ownership has to be restored by hand, once:
```bash
sudo qeli set-service-user qeli
sudo systemctl restart qeli
```
Check: daemon configs/identity/users and their locks should belong to `qeli`; `client-links` remains root0700 and reserved `*.bak-*` backups retain their owner.
```bash
ls -la /etc/qeli/
```

### 6.10 Client refuses to change DNS: systemd-resolved is not the resolver

**Symptom:** a connection using `dns = tunnel` stops with
`refusing to replace /etc/resolv.conf with tunnel DNS`.

**Cause.** Actual `nameserver` entries in `/etc/resolv.conf` must contain only
`127.0.0.53`/`127.0.0.54`; a regular file is supported and a symlink name proves nothing.
The systemd-resolved/D-Bus availability and context are checked separately. Installing
the service without starting it is insufficient; Qeli does not autoactivate it. See §6.76.

Starting with 0.7.15 qeli deliberately **does not replace persistent `/etc/resolv.conf`**:
after `SIGKILL`, power loss or client removal it could retain the vanished tunnel resolver
and break DNS for the whole host. New backups are not created; old ones require manual
recovery under §6.20. Startup no longer changes the global resolver. Enable the
lifecycle-safe per-link path:
```bash
sudo systemctl enable --now systemd-resolved
sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```
Check (the usual recommended stub symlink):
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

Starting with 0.8.3, a confirmed clean daemon stop remains `Disconnected` without a
running heartbeat. This receipt is invalidated before another connection or launchd
startup, so a failed restart cannot reuse it. Stop also checks DNS, Qeli firewall and
forwarding recovery and requires the daemon to have reported `Disconnected`; a cleanup
error or missing/unsettled terminal status is not reported as success. Keep recovery
journals and inspect `service.log` when recovery remains incomplete; do not delete
state files merely to clear the UI error. On Apple Silicon, 0.8.3 also fixes lock-file
creation permissions and safely repairs affected root-owned, single-link regular locks.

---

### 6.15 Linux: hooks ignored or password_command refused after chmod

Messages containing `ignoring post_up`, `ignoring post_down` or
`refusing to run auth.password_command` include the reason for command refusal.
Use a regular config rather than a symlink, owned by root or the service's effective UID,
and remove group/world write bits (normally `chmod 600 /path/to/config`). Keep the file
readable by the actual service user. Check scripts and their dependencies too.

Then restart the client or server worker. Permission repair alone, a profile retry or
SIGHUP cannot grant commands permission for a configuration already loaded as untrusted.
Authorized cleanup from the old running generation can still execute its saved
`post_down` after the path changes; a new config applies on the next worker startup.

`configuration changed while reading; retry with a stable file` means the loader detected
changed content or metadata. Finish writing the file and retry; prefer atomic replacement
when saving. `configuration must be a regular file` rejects directories/devices/FIFOs.
See [configuration security](CONFIG.md#security).

---

### 6.16 Linux: password supplier timeout, oversized output or hidden stderr

`auth.password_command exceeded its execution/output deadline` means the command,
stdout EOF or shell exit did not finish within 30 seconds. Use a noninteractive
supplier: stdin is closed. A background child holding stdout open also consumes this
deadline; redirect its streams if it is intentionally persistent.

`stdout exceeds 16384 bytes` rejects all output, including a small password surrounded
by too much whitespace. `stdout is not valid UTF-8` rejects malformed bytes. Return
only the password on stdout; the smaller AUTH wire-size check still applies after trim.
`failed with ...; command output is not logged` preserves the exit status while keeping
stderr out of Qeli logs. Inspect the supplier in a protected operator session when
needed; do not paste secrets into tickets or enable secret-bearing diagnostic output.
SIGINT/SIGTERM while waiting for the supplier cancel startup and clean up its process group.

---

### 6.17 Linux: password_file rejected or stop waits for file I/O

`auth.password_file must resolve to a regular file` rejects a FIFO, device or directory.
Use a regular secret file; symlinks used by secret stores remain supported. `exceeds 16384
bytes`, `is not valid UTF-8` and `changed while reading` reject the whole credential.
Remove unwanted output, correct encoding, or finish/atomically replace the secret file
before retrying. Error messages do not include the password.

`auth.password_file exceeded its read deadline` uses a 30-second admission/read budget.
A queued read can be cancelled; an already-running filesystem syscall must return before
ordinary stop/timeout finishes. Check filesystem/mount health if shutdown is still waiting.
Repeated caller cancellation cannot launch more simultaneous reads: the running job keeps
its sole per-process slot. It releases buffers when the syscall returns and it can exit.

The final client status is written after the sampler and signal watchers are aborted and
joined. This prevents an older sampler write from replacing `stopped`/`failed`; a blocked
synchronous diagnostic write can also delay that final publication. This is not a guarantee
of a terminal status after SIGKILL or forced cancellation of the entire client future.

---

### 6.18 Linux: kill-switch retained after cleanup failure

`kill-switch retained because forwarding/NAT cleanup did not complete` means the earlier
error prevented reliable gateway/exit-node cleanup. Qeli deliberately keeps the enabled
kill-switch. Fix the reported firewall/tool failure and retry normal cleanup or controlled
administrator recovery; network access can remain restricted until then. The message does
not appear when kill_switch is disabled. An error while removing the kill-switch itself
has a different meaning: removal may have partially succeeded, so retention is not claimed.

---

### 6.19 Linux: transport core startup or teardown failed

After kill-switch setup, a core lifecycle error terminates the client with a failure status;
it is not retried as an ordinary carrier failure. `post_down` receives `core_start_failed` /
`core_start`, or `core_stop_failed` / `core_stop` (reason / error code). If both phases fail,
`core_stop_failed` takes precedence and the message keeps the startup and cleanup causes.
A concurrent SIGINT/SIGTERM cannot turn the teardown failure into a successful stop.

`kill-switch retained because transport core teardown did not complete` means Qeli could
not confirm core teardown. Forwarding cleanup is still attempted. A combined message names
both failures when forwarding cleanup also fails. Preserve the error log and verify process,
firewall and route state before administrator recovery; do not interpret a hook invocation
as proof of a clean network reset. User hook scripts can make their own firewall changes.

---

### 6.20 Linux: legacy resolver recovery failed; backup kept

`legacy global DNS state ... administrator recovery required` means that an old client's
`/var/lib/qeli/dns-backup.json` or `dns-holders` remains. The current version preserves
it and refuses startup, including with `dns = off`/`system`. These records lack ownership
of the current resolver and its original namespace. Neither a valid snapshot nor absent
PIDs authorizes automatic `/etc/resolv.conf` replacement.

1. Establish the original host, network/mount view and stop all old DNS owners. Prefer
   a clean stop of the old client before upgrading. A saved PID may belong to another
   boot/PID namespace; do not terminate a process based only on its number.
2. Preserve legacy evidence and current resolver state. Before reading a snapshot,
   check its type, size, owner and path. A FIFO, directory or unknown symlink needs
   investigation; Qeli does not open its contents.
3. Restore DNS through its responsible network manager or a verified original. `file`
   needs verified content/permissions; `symlink` needs a verified target. `absent` does
   not authorize removing a resolver now needed by another owner. `managed-no-original`
   means the original is unknown: the administrator selects DNS, without a public fallback.
4. Verify DNS and absence of old owners. Only then archive the resolved
   `dns-backup.json`/`dns-holders` outside their active names and restart. Do not delete
   live locks or all of `/var/lib/qeli`. A stable `dns-holders.lock` alone does not
   prevent startup.

On older binaries, `failed to restore /etc/resolv.conf ... (backup kept at ...)` meant
an unsuccessful automatic attempt. Upgrading does not repeat that attempt. New
connections use per-link systemd-resolved; old global resolver snapshots are not adopted.
[Report](../reports/audit-0.8.2/AUDIT-Q25-LEGACY-DNS.md).

---

### 6.21 Linux: network resource cleanup reported errors

`kill-switch retained because network resource cleanup reported errors` means that DNS,
route or forwarding/NetworkPlan rollback cleanup failed during this client run. The client attempts
forwarding cleanup, reports terminal failure and does not reconnect. `post_down` receives
`network_cleanup_failed` / `network_cleanup`, unless core teardown also failed (then
`core_stop_failed` / `core_stop` has priority). A simultaneous stop signal does not hide the
cleanup failure. If the server also sent a terminal kick, its cause remains in the error.

<!-- normative-sync: manual-terminal-policy-v1 -->

A received authenticated `KICK` with `reconnect_allowed=false` prevents automatic
reconnect even if the TCP stream closes simultaneously or the platform cannot accept
the event. Ordinary EOF without KICK follows reconnect settings. If an old client
reconnects after being superseded, update its native core: [Q09-F010/F011](../reports/audit-0.8.2/AUDIT-Q09-FINAL.md).
An unread or lost packet is not treated as received by this rule.


A fallback guard may retry cleanup, but its later success does not erase the original fault
or automatically release the kill-switch. Review the first error for each resource and verify
current DNS, route and interface state before administrator recovery. The retained record is
limited to three resource categories with the first 2048 characters each; it is not a complete
history of every retry. User hook scripts may still change firewall state independently.

---

<!-- normative-sync: manual-management-receipts-v1 -->

A management ACK requires a complete valid payload. Repeating an unfinished fragment, malformed KICK or conflicting contents under an old ID receives no receipt. An exact repeat of an accepted message is ACKed again; it must use a newly authenticated PacketCodec record, because the replay window rejects repeated ciphertext. [Q10 validation](../reports/audit-0.8.2/AUDIT-Q10-CODEC-CONTROL.md).

<!-- normative-sync: manual-realtls-policy-v1 -->

REALITY-TLS uses common strict ServerHello decoding and post-handshake policy in async/sans-IO. Validated application bytes precede a later record fatal error; the failed session accepts/sends no new records. Fragmented NewSessionTicket is accumulated within bounds and ignored; unsupported KeyUpdate requires reconnection. Legacy `qeli_realtls_open` returns earlier plaintext with `0`, then terminal `-1` on the next call; close_notify uses that terminal code because the ABI has no separate EOF result. [Q11](../reports/audit-0.8.2/AUDIT-Q11-REALITY-TLS-H2.md).

### 6.22 TCP: shutdown waits for background work

Normal shutdown closes TCP-task admission and joins readers/writers, the decrypt pipeline
and connection-maintenance tasks before network cleanup. Management-event errors follow
the same sequence. The Linux TCP and UDP path monitor also waits for running route reads
or path updates. Individual route, firewall, TUN and busctl commands have
[bounds](#627-linux-system-command-timed-out-or-output-limit-exceeded); total stop time
also depends on command count, verification queries and waiting for process exit.

If shutdown is delayed, inspect logs and child ip/iptables/busctl processes. A stop
request alone does not prove network cleanup is complete. Forcing process termination cannot
guarantee joining, network restoration or post_down. See [the report and validation limits](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md).

---

### 6.23 UDP: candidate and old-path termination

Connection shutdown waits for receive tasks, candidate connection and the Linux monitor
before platform-path rollback and DNS/TUN cleanup. Candidate rejection or expiry finishes
its receive pump while the active path keeps receiving. After commit the old receiver
continues only for the designated drain window, then its task finishes.

Termination must not depend on another packet arriving at an idle socket or free queue
capacity. A delayed system blocking operation still needs separate investigation. Forced
cancellation of the whole client does not confirm rollback or async joining.
See [the report and tested scenarios](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md).

---

### 6.24 TUN/Wintun worker termination when shutdown is cancelled

Even if the shutdown waiter is cancelled, pump destruction waits for its reader/writer.
Cancellation can make this synchronous. A saturated blocking pool does not prevent Drop
from joining itself; a join already running is awaited until both threads have terminated.

Stop and closing the inbound queue release packet waits and blocking_send. Bounded loop
waits do not guarantee a finite deadline for driver/OS calls. If shutdown stalls, distinguish
TUN workers, system commands and platform ACK waits using logs/thread dumps. A stop request
or UI state does not prove all network cleanup is complete. See [tested scenarios and
limits](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md).

---

### 6.25 HTTP/2: stopping with a delayed response or full window

For `reality-tls`, the client tracks internal H2 drivers/bridges with TCP tasks from connect
onward. Normal group shutdown waits for their release before DNS/TUN cleanup. Cancelling
a native TCP attempt also joins the group before generation-completion bookkeeping.

A zero peer window or full bridge must not require another network event for cancellation.
Half-close remains supported: a reply can follow completion of outbound traffic. This is
not an overall shutdown deadline, validation of early rollback or a guarantee of joining
when the entire runtime is destroyed. See [the report and scenarios](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md).

---

### 6.26 Server HTTP/2: profile shutdown and rejected requests

A `reality-tls` profile tracks its H2 driver, bridge and bounded rejection flush alongside
session tasks. Normal teardown waits for their release; cancelling a shutdown wait preserves
the ability to join again. A zero peer window must not block cancellation.

An invalid H2 request still receives its HTTP status. Its pre-auth slot remains occupied
while the connection sends the rejection; the flush has a one-second limit. H2 200 does not
mean inner AUTH has succeeded. This does not guarantee an overall shutdown deadline or
joining when the runtime is destroyed. Linux runtime validation remains open;
[report and reproducers](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md).

---

### 6.27 Linux: system command timed out or output limit exceeded

For client route, kill-switch/gateway, TUN-interface and `busctl` commands, these
errors mean exceeding 15 seconds
or 16 MiB on one output stream. Spawn errors and nonzero exit codes remain distinct. Qeli
attempts to terminate the child and, on Linux, its group, then waits for exit; partial output
is never accepted as a command result.

DNS application (`dns` + `domain`) shares 15 seconds from setup entry.
`DNS setup command budget exhausted` means the shared deadline expired before the
next step; the second command can time out before its own 15 seconds. The generation
retains its lease for separate rollback. [Validation](../reports/audit-0.8.2/AUDIT-Q25-DNS-BUDGET.md).

Timeout does not prove that nothing changed. A failed D-Bus `RevertLink` retains its marker
for the owning guard's retry. Startup does not revert live links from a marker alone (see §6.50).
Generation rollback failures appear in the log; an attempted rollback
does not mean successful revert. Check the affected interface and systemd-resolved state.
Total shutdown time still depends on other work: commands and verification queries are
sequential, and kill/reap can wait on the kernel.
[Original runner and tests](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md),
[routes and firewall](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md).

---

### 6.28 Server: NAT cleanup ... incomplete

This warning means rule cleanup is unconfirmed: a listing, deletion or verification
command failed, or owned rules remained after a successful deletion response. The log
identifies the table/chain and cause. Qeli makes a finite pass over the discovered rules
and continues other chains after failures.

Inspect the named chain through the same backend (`iptables` or `ip6tables`), tool
availability and process permissions. Mixed native nft chains may reject `-S` even when
exact DNS cleanup works. The warning alone does not prove a rule remains: listing may
have failed. Similarly, successful server exit does not yet establish firewall recovery.
Do not flush an administrator's entire table to clean one profile.
[Scope and open findings](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md).

---

### 6.29 Linux: firewall inspection failed / DNS INPUT cleanup failed

Inspection failure is now distinct from confirmed rule absence. Check the tool path,
backend, permissions and specific stderr cause. A permission error with code 1 does not
mean the rule was deleted. Unknown or additional diagnostic text also leaves state
unconfirmed; include the complete log when reporting it.

Server DNS permit cleanup attempts both UDP and TCP even if one fails. Exactly 1024
identical rules are supported; `still present after 1024 deletion attempts` means the
last check still found the rule. Accumulated copies, concurrent additions or a backend's
successful no-op may explain this. Final retry of known DNS leases now affects worker
exit status; see §6.31. This does not verify all server resources.
[Firewall checks report](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md).

---

### 6.30 Server: exact DNS INPUT ownership retained for retry

DNS permit removal is unconfirmed, but the worker retained the complete specification
for retry. Inspect the preceding cause: `iptables`/`ip6tables` availability, permissions,
backend and exact check/delete results. Later profile cleanup and new DNS installation
attempts retry pending cleanup first. New DNS permits for that profile are not installed
until its pending cleanup succeeds.

`DNS INPUT ownership limit reached (4096)` means the registry is full of active and
pending rule sets. Each resolver occupies one UDP+TCP set; IPv4/IPv6 use separate sets.
Resolve cleanup failures first; successful retirement releases capacity without
automatically evicting existing records.

The evidence lives only in the current worker's memory. Do not assume retries survive
crashes or process restarts; there is no separate persistent journal yet. Final worker
verification is described in §6.31; it does not verify all server resources.
[Report and limits](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md).

---

### 6.31 Server: Server shutdown failed — owned network cleanup

After profiles stop, the worker retries retained DNS INPUT rules and remaining IPv6
sysctl leases. If cleanup cannot be confirmed, signal-driven worker shutdown exits 1
and logs `Server shutdown failed: owned network cleanup: ...`. Concurrent failures add
`worker`, `profile/worker task cleanup` and/or `usage shutdown flush` to the same message.
Accounting is flushed even
after network cleanup failure.

`DNS INPUT lease still active at worker shutdown` means active ownership remains;
this check does not delete its rules. For ordinary cleanup failure, inspect the named
firewall tool, sysctl access and earlier profile errors. If final retry confirms cleanup,
an earlier transient failure alone does not change a successful exit status.

The outer supervisor returns final worker stop failure to its calling CLI and logs
`Supervisor shutdown failed: ...`. A nonzero exit or forced kill after the grace deadline
does not count as a successful stop. Successful worker exit returns success.
Explicit Restart and unexpected exit without a stop request still respawn the worker;
termination failure is logged.

This check covers only DNS/IPv6 sysctl leases known to the worker. A successful exit
does not prove the absence of generic NAT rules or resources from earlier generations.
Profile task and TUN teardown error reporting is described in §6.32.
DNS ownership is lost when the process exits; automatic exact-rule recovery after
restart is not yet guaranteed.
[Report and open boundaries](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md).

---

### 6.32 Server: profile/worker task cleanup and teardown incomplete

`Server shutdown failed: profile/worker task cleanup: ...` reports a task or current
profile-generation failure. Nested details distinguish listener/service/child panics,
profile supervisor errors and TUN queue timeout/panic.
A profile may also log `teardown incomplete: ...`.

A failed profile does not skip draining the others, final known DNS/IPv6 sysctl lease
cleanup or accounting flush. Signal-driven worker shutdown exits 1, and the outer
supervisor propagates the failure to its calling CLI. Ordinary child-task cancellation
during shutdown is expected. Cancelling a waiter or repeating shutdown does not erase
already collected task diagnostics.

`queue thread(s) did not stop` means a thread exceeded the three-second grace and may
retain the device. Inspect earlier profile errors and the named TUN; this mechanism
releases its owned descriptors without deleting a device by name (see §6.49). `teardown attempted` reports an attempt,
not proof that all NAT rules or old devices are absent. Earlier-generation errors after
retry/replacement still require separate accounting.
[Validation and limitations](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md).

---

### 6.33 Server: could not restore stale host sysctl value(s)

At worker startup, sysctl journal recovery found settings with no live owner that could
not be restored. Startup returns an error listing their paths. Check service access to
the named sysctls and preceding `host networking` messages. Keep `sysctls.state`: its
original values are needed for retry. After resolving the cause, starting again retries
restoration.

One failure does not skip other journal entries. Values with live owners and external
administrator changes are preserved. Failed repeated lease acquisition now retains the
previous owner, preventing recovery from restoring the original value beneath an active
component. Supervisor restart policy is unchanged.
[Report and validation boundaries](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md).

`cannot verify host sysctl owner(s)` means that a recorded owner's state cannot be
verified. Check service access to `/proc/<pid>/stat`, procfs restrictions and PID/network
namespace consistency with journal owners. Denied access, malformed contents and hidden
existing processes retain the owner; new acquisition and startup recovery return an
error. During release, independent cleanup may finish, but unknown co-owners remain
and are included in the resulting error.

Missing sysctls and malformed/empty values retain their entries for recovery.
Disappearance of the previous interface name no longer permits forgetting the original:
the object may have been renamed or replaced. Restarting cannot recreate evidence from
a lost live sysctl descriptor. Do not remove the journal to bypass the check.
[Current contract](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md).

Version 4 separates groups by network namespace. `host sysctl PID namespace mismatch`
or `host sysctl time namespace mismatch` means the same network is being accessed from
a different process-observation context; recover in the original PID/time namespace.
`procfs PID namespace mismatch or unavailable NStgid` requires procfs for the current
PID namespace and a kernel exposing the required data. Missing/unreadable net/pid
namespace metadata also stops the operation. Minimal kernels without these interfaces
have not been qualified.

`legacy host sysctl journal has no namespace identity` retains nonempty v1 state from
the current boot; `legacy v2 host sysctl journal lacks live descriptor ownership` retains
nonempty v2. Before upgrading, stop old participants and complete recovery in the original
context while the original interfaces remain verified. Renamed/replaced interfaces require
manual inspection, rather than blindly running previous recovery. Alternatively, use a
planned host reboot; restarting Qeli alone does not change boot-id. Do not change
version/boot-id or remove the journal to bypass checks. Mixed versions sharing a journal
are unsupported. Foreign network groups remain, so success in one network does not prove
cleanup of the others. [Migration and limits](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md).

---

### 6.34 Server: IPv6 sysctl acquisition failed — rollback incomplete

A route/nat66 setup error may include both the original acquisition failure and
`rollback incomplete`: sysctl restoration after the failure could not be confirmed.
This can happen even on the first accept_ra call because writing may precede failed
verification. The profile scope is retained for cleanup retry.

Ordinary profile cleanup and final worker shutdown retry scope release. If it still
fails, the final outcome includes `owned network cleanup` with `IPv6 sysctls/<profile>`.
Check service access to the named sysctls and journal; keep `sysctls.state` for retry.
Successful final retry clears this network failure; the current generation's original
failure may separately remain under `profile/worker task cleanup`.

Until the old scope is released, another WAN/TUN for the same profile cannot replace it.
The accept_ra → forwarding order and `off`/`manual` modes are preserved; no new INI keys.
[Report and validation](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md).

---

### 6.35 Server: system command timed out / output limit exceeded in NAT cleanup

Server NAT commands, including iptables/ip6tables, PATH version probes and WAN route
lookup, use a 15-second deadline and separate 16 MiB stdout/stderr limits. `--wait 5`
remains the xtables lock wait within that attempt. On timeout, the shared runner requests
process termination; oversized output is never passed partially to the parser.

`system command timed out` does not mean the firewall is unchanged. Inspect backend/xtables
delays and earlier profile messages. Exact DNS rule specifications remain available for
cleanup retry in the current worker; a failed check is not proof of rule absence.
Generic NAT sweeps retain their previous best-effort policy and log failures.

This limits an individual command: the full cleanup sequence and process termination
can take longer. Preflight is covered separately in §6.36; client firewall/route
commands remain outside this change.
There are no new INI keys.
[Scope and validation](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md).

### 6.36 Server: preflight delay or unavailable network state

The four `ip` queries for IPv4/IPv6 addresses/routes share one 15-second budget,
with separate 16 MiB stdout/stderr limits per command. Oversized output is never
parsed partially.

The warning `pre-flight: could not read the host's network state` means the IPv4
snapshot is unavailable: causes include missing `ip`, nonzero exit, read errors,
timeouts or output overflow. Existing policy permits startup; this does not establish
absence of network collisions. Inspect the host's addresses and routes.

An IPv6 address or route query failure preserves IPv4 and the available IPv6 part;
there is still no separate warning for this partial failure. Observed collisions
continue to block application. Successful empty output is valid.

The panel runs preflight asynchronously before the config lock; later steps receive
only the remaining budget. The full transaction, file I/O and final kill/reap can
take longer than 15 seconds. There are no new INI keys.
[Current contract](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md).


### 6.37 Linux client: path observation failure or delayed stop

The debug message `Linux roaming path sample failed` means the monitor could not obtain
a usable route/address observation. Its three read-only `ip` queries now each have
a 15-second deadline and separate 16 MiB stdout/stderr limits. Timeout or output overflow
returns an error; partial data is not published as a new path. Internal iproute2 output
does not change the INI format of user profiles.

During orderly stop, the generation owner waits for an already running command even
when the async monitor is cancelled. This is not an overall stop deadline: queries are
sequential and process waiting may extend the call. Route-mutating commands are also
bounded individually. Check iproute2 availability and earlier debug logs when troubleshooting.
[Validation and boundaries](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md).


### 6.38 Linux gateway/exit-node: WAN detection and cleanup

WAN is selected independently for IPv4 and IPv6. Qeli reads the default route first,
then falls back to a local route-get lookup for `1.1.1.1` or `2606:4700:4700::1111`.
Each query has a 15-second deadline and separate 16 MiB stdout/stderr limits.
A failed first query can still succeed through fallback; failure of both leaves the
WAN unavailable. Check iproute2 availability and the relevant family's routing table.

Exit-node cleanup uses all WANs remembered for that TUN, including previous uplinks,
without querying current routes for a family with known targets. Failed family cleanup
keeps its targets for retry. If ownership is empty, discovery remains best-effort;
this does not reconstruct ownership lost in a crash.

The limit is per read-only query. Sequential fallback and process waiting can take
longer, and gateway/kill-switch firewall commands still need separate bounds.
There are no new INI parameters.
[Validation and boundaries](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-WAN.md).

### 6.39 Linux roaming: route mutation left platform state unknown

A failed `ip route add/replace/del` can have changed the route before returning an error.
For a failed add/replace, Qeli checks the destination after rolling back earlier steps:
ordinary rejection retaining the previous path requires confirmation of the previous state.
Deletion and restoration use the subsequent snapshot regardless of command status:
confirmed absence completes retirement, and an exact previous snapshot confirms restoration
(see 6.42). Failure to confirm the previous state when rejecting a transaction returns
`PlatformStateUnknown` through the controller and requires stopping the current connection
generation.

The messages `failed route mutation ... did not preserve the previous route` and
`ambiguous route snapshot` explain failed verification. Inspect the affected
IPv4/IPv6 destination and earlier command errors. Multiple nonempty snapshot lines
are rejected; multipath snapshot reconstruction is not implemented.

This is not a guarantee that every uncertain route was removed. An unsuccessful add
does not prove ownership; such a route may remain for inspection. Unknown roaming
operations retain separate pending reservations without delete authority (see 6.43).
Durable crash recovery and command deadlines remain separate work. No new INI fields are required.
[Evidence and limits](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md).

### 6.40 Linux: changed route ownership or cleanup retry

Physical-route cleanup compares the recorded gateway/device and other supplied identity
fields with the current exact route. `owned route changed; preserving replacement`
means a different observed route was left in place and the stale journal record dropped.
An already absent route also requires no delete.

`command succeeded but route remains` means the matching route survived the command.
Unreadable, malformed or ambiguous snapshots likewise fail cleanup; the specification
is retained for retry. A lost command result can still complete cleanup if a subsequent
query confirms absence. Roaming updates cleanup parameters after a successful route change.

The journal remains in memory, with records now separated by connection owner (see 6.41).
Crash recovery, atomic protection against other processes and command deadlines remain open.
No new INI parameters. [Selector checks](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md).

### 6.41 Linux: route owner stopped, expired or still reserved

`route owner is stopped/has expired` means an old prepare/commit cannot mutate routes
after cleanup starts or its owner is released. A new plan needs its own owner; repeating
a generation number does not revive the old one.

`still live or has pending cleanup` means a live guard or unconfirmed cleanup reserves
the interface name. A live guard retries only its own cleanup. Once the final guard
has been released with leftovers, a new connection may release the reservation only
after read-only confirmation of absence and the conditions in 6.43. There is no automatic
adoption/deletion of an unconfirmed route. Inspect the original error and affected routes
first; restarting the process alone does not prove that those routes were removed.

`belongs to another Qeli owner` reports a carrier/exclude/blackhole conflict with another
connection in this process. Shared ownership of that route is unsupported.
`dev_attach=true` leaves routes to the external manager: Linux does not advertise
`ROAMING_PATH`; `roaming=auto` uses reconnect and `required` is unavailable.
[Regressions and limits](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md).

### 6.42 Linux roaming: deletion or restoration was not confirmed

`carrier route ... remains after retirement` means a route survived delete even if the
command reported success or already absent. `changed before retirement` means the saved
snapshot changed before deletion: Qeli does not delete the observed replacement or
recreate a route that disappeared before that step.

`could not restore carrier route ... snapshot differs` means the subsequent snapshot
did not match the saved one; `could not verify restored carrier route` means the
post-restoration check failed. Successful exit status alone is insufficient. A confirmed
previous snapshot completes restoration even after a lost command result. Likewise,
confirmed absence completes deletion.

After a failure, Qeli verifies rollback of the completed steps. If the previous path's
state cannot be established, the generation must stop instead of continuing on an assumed
restoration. Inspect the affected destination, current snapshot and preceding errors;
pending tracking and release of absent orphans are described in 6.43. Full semantic
comparison of every attribute and atomic protection against external changes remain
unsupported. There are no new INI parameters.
[Regressions and limits](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md).

### 6.43 Linux: pending reservation after an unknown outcome

`unresolved route mutation; destination remains reserved without delete authority`
means command completion did not establish ownership and the destination is still
present. Qeli retains the operation record and cleanup error but does not delete the
route on the authority of pending alone. Matching plan parameters do not prove who
installed it. `could not verify pending route` means no valid snapshot was obtained.

An unknown commit result immediately closes new route operations for that owner,
including gateway refresh. A live guard can retry cleanup; pending clears only after
confirmed destination absence. Successful cleanup leaves the old owner stopped;
a new one becomes possible after the final guard is released.

After guard release, a new connection in the same process performs a read-only orphan
check only after the previous IPv4/IPv6 interface-flush results were confirmed.
This requires empty state, not just successful command status (see 6.44). All
recorded destinations must be absent and both families' interface routes empty.
`orphan route reservation ... is still present` and
`could not confirm empty interface routes` mean release is blocked.
Other query errors also retain the reservation; routes are not overwritten.

Inspect the destinations, interface and original error. Pending grants no route-delete authority.
Independent cleanup of a Qeli-owned interface is described in 6.46. Without previous cleanup, after unconfirmed interface flush or
with a live guard, automatic release is unavailable. This mechanism operates within the
process and does not restore the journal after crash/restart. Pending also covers initial
carrier/exclude/blackhole and TUN/TAP setup with possible leftovers (see 6.44–6.46). No INI parameters were added.
[Report and limits](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md).

### 6.44 Linux: verifying initial setup and interface-route cleanup

Before installing carrier/exclude/blackhole and TUN/TAP routes, Qeli checks the exact destination
snapshot. A matching existing route is used without a claim. `initial route conflicts
with an existing route` reports a conflict before writing. Query failure also prevents add.

`route is absent after initial add` means the command did not create a verifiable route.
`initial add outcome is not proven; destination remains reserved` and
`could not verify initial route` report a possible unconfirmed leftover.
Setup fails; pending does not authorize deletion. Even `File exists` after initial
absence does not make a newly appearing route safe to borrow.

After each IP-family flush, Qeli verifies that no interface routes remain.
`interface routes remain` reports a leftover regardless of command status.
`could not confirm empty interface routes` means empty state was not established.
Lost flush completion permits success if absence is confirmed. Failure in one family
does not skip cleanup of the other.

If a route query returns negative status after TUN deletion, Qeli confirms the exact
name is absent through a separate `ip -o link show`. `Cannot find device` alone is
insufficient. `invalid link snapshot`, execution failure, non-UTF-8 output or a present
interface retains cleanup failure. A route-query I/O error requires verification retry.

Inspect the address, interface and preceding log errors; a live guard can retry cleanup.
This does not certify crash recovery, arbitrary policy tables/VRFs or completed TUN
workers. No INI parameters were added.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md).

### 6.45 Linux: route/firewall timeout and an unknown IPv4 path

Client routing `ip` commands and kill-switch/gateway `iptables/ip6tables` commands
share a 15-second per-call deadline and separate 16 MiB stdout/stderr limits. Exceeding
a bound returns an error without partial output. This is not a 15-second limit for
the entire setup, cleanup or reconnect: verification and process exit also take time.

If a command could have changed the network, timeout does not undo that change.
An unconfirmed add remains pending without deletion authority from that record.
Flush requires verification that routes are absent; failed verification requires retry.
An unreadable firewall chain is not considered absent either. Inspect preceding errors,
iproute2/iptables availability and the affected interface; child exit alone does not
establish successful cleanup.

`IPv4 can become active` means the IPv4 firewall leg is unavailable. No current
default route does not guarantee the absence of an IPv4 path for the whole session: a route
may appear later. Fix `iptables` or deliberately set `allow_ipv4_leak = true`.
That option permits an IPv4 leak; it does not restore the firewall.

No configuration keys were added. Linux runtime, complete gateway rollback and an
overall transaction deadline remain separate checks.
[Report and evidence](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md).

### 6.46 Linux: unconfirmed TUN/TAP route or malformed route_local inventory

Connected pools, full-tunnel capture, pushed/include/DNS routes and local-network
overrides use one installer. `initial route conflicts with an existing route` means
the exact prefix already has another interface, gateway or metric. Direct L3 TUN routes
do not borrow a gateway route. Successful exit status is insufficient: add is followed
by an actual snapshot check. Unknown outcomes fail setup and close route admission
for that owner.

Compare the current entry with the expected plan. Do not delete a conflicting route
solely because its prefix matches: another configuration or Qeli owner may own it.
IPv4 metric zero may be omitted from output; IPv6 metric zero has the effective value
1024. Qeli handles these forms and checks other explicitly requested metrics.

During cleanup, pending does not authorize a separate `route del`. The Qeli-owned
TUN/TAP is independently flushed by interface, including routes on it that were
previously borrowed. After flush, Qeli checks pending destinations for absence.
A leftover removed this way releases its reservation; a route on another interface
or an unreadable snapshot retains failure. This does not authorize taking over an
interface opened with `dev_attach`.

`invalid connected IPv4 address snapshot for route_local` means malformed output from
`ip -4 -o address show up scope global`. Qeli refuses to treat it as an empty inventory
and stops setup before route mutations. Inspect iproute2 availability and output.
A valid empty response is permitted; addresses on the owned TUN and non-RFC1918
networks do not produce overrides.

User configuration remains INI; no keys were added.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md).

### 6.47 Linux: occupied TUN/TAP name and creation refusal

In normal creation mode, the Linux client waits approximately six seconds for an
occupied `dev` to disappear (120 pauses of 50 ms plus query time). It does not
delete the existing interface based on PID discovery or change its persistence.
A non-persistent TUN disappears when its owner closes the last descriptor.

- `still present after waiting for release` means the name remains occupied.
  Stop the previous owner or choose another `dev`; for an externally managed
  TUN/TAP, deliberately configure `dev_attach=true` and matching `device_type`.
- `cannot inspect interface` means the kernel query failed. Resolve the reported
  cause; an error is not treated as absence.
- `was replaced while waiting for release` means another ifindex was observed
  under the same name; the current attempt stops.
- `Device or resource busy` during creation may mean a device appeared after
  the check. Exclusive creation does not automatically attach to it.

The server immediately refuses an occupied `tun.name`. The first client/server
queue is created exclusively; later queues use the name returned by the kernel.
`dev_attach` requires a pre-created compatible interface; §6.48 describes preventing
creation after it disappears. An already-existing replacement and identity during
later cleanup remain separate audit items. [Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md).

### 6.48 Linux: attach prevents creation and checks packet framing

`cannot prohibit TUN creation while attaching` means installing the guard failed
before attachment. Check kernel support and sandbox permission for `TUNSETIFINDEX`;
Qeli does not continue without it. Additional server multiqueue descriptors have the
same requirement; the first exclusive creation does not. If the name disappears,
the subsequent ioctl refuses instead of creating a new TUN.

`uses IFF_VNET_HDR` means the external device uses virtio headers that Qeli cannot
process. Provide a separate TUN/TAP without VNET_HDR, with NO_PI and matching
`device_type`. Do not change the framing of another application's device.
`unsupported tun_flags` refuses unknown features rather than silently resetting them.

Supported ONE_QUEUE/NAPI/NAPI_FRAGS and queue mode are preserved; persistence is unchanged.
The external manager must retain the device and stable framing during opening.
Sysfs must describe the current network namespace. `refusing foreign tun_flags`
means the current namespace's `ifindex` differs from `/sys/class/net/<name>/ifindex`;
correct the sysfs mount rather than changing the foreign device's flags. Equal
indexes across namespaces are possible, so the guard does not prove the identity
of a same-name replacement. Descriptor-based release is described in §6.49;
DNS/route identity during external replacement remains open.
[Report, Linux tests and limits](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md).

---

### 6.49 Linux: TUN release follows descriptor ownership

Client disconnect/rollback and server profile teardown no longer run `ip tuntap del`.
The client guard keeps the original descriptor until DNS/routes cleanup finishes;
the server guard retains one original after worker-fd duplication through host cleanup
and worker stop. A non-persistent device disappears after all attached descriptors close.
Attach mode closes
only the borrowed descriptor; it does not clear the external device's persistence.

If a device remains, inspect its actual owner and earlier queue-stop errors. External
holders, changed persistence or a timed-out server worker can retain it. Qeli does not
force deletion of the name. DNS and route cleanup additionally verify the original fd
and namespace (see §6.50–6.51). Privileged external changes between check and command
remain a limitation.
[Tests and precise boundaries](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md).

---

### 6.50 Linux: DNS lease ownership and recovery markers

Only a connection that acquired a DNS lease may revert its per-link DNS. `dns=off/system`,
a plan without resolvers and a failed ownership acquisition perform no per-link cleanup.
An active lease is retained through setup rollback and disconnect; DNS errors remain terminal.

`DNS link already has an active owner` means another generation holds this link's lock.
`unrecovered DNS ownership marker` means a prior record remains; it is not overwritten.
New state uses `dns-link-v2-<boot>-<netns-device>-<netns-inode>-<cookie>-<ifindex>.state` plus `.lock`
in `$STATE_DIRECTORY` (default `/var/lib/qeli`), shared with route/sysctl/firewall state. The cookie comes
from `SO_NETNS_COOKIE`; missing support refuses managed DNS. The directory must have no
symlinks, untrusted owners or group/world write. New files use 0600; unsafe existing modes
or ownership fail without automatic repair. Do not bypass these checks by deleting evidence;
resolve the cause and inspect the actual DNS state first.
Startup skips active/foreign owners, retains live indices and retires confirmed absent ones
without a resolver command. A saved name/index alone never triggers revert of a live link.

`Legacy DNS v1 marker ... lacks namespace generation` means a retained `dns-link-v1-*` file.
It is not migrated automatically: the old inode cannot prove namespace generation. Matching
boot/device/inode/ifindex block a new lease until administrator recovery.
`legacy DNS marker ... needs administrator recovery` refers to old `dns-resolvectl-*`.
Stop the old client cleanly before upgrading so it retires its own marker.
Stop the affected owner, identify the actual interface, inspect `resolvectl status`, and
restore DNS through the responsible network manager or revert a verified Qeli-owned link.
Only then archive/remove the exact orphaned marker. Do not delete live `.lock` sidecars,
remove all state files, or mix old/new DNS owners of the same interface. Recovery of a
persistent external link after a crash may require this procedure.

Managed DNS requires permitted `TUNGETIFF`/`TUNGETDEVNETNS`, CAP_NET_ADMIN for the namespace
ioctl and usable namespace/boot procfs metadata. `cannot verify TUN namespace`,
`DNS cleanup namespace changed`, `DNS link identity changed` or a changed marker refuse
mutation and preserve evidence. DNS commands use the captured numeric index after checking
the original fd; ordinary rename is supported and a detached original never authorizes
revert on its replacement. The resolved service must manage the same network namespace.
External mutation after the last check and external DNS writers remain limitations.
[Lease contract](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md) ·
[Storage checks and the v2 transition](../reports/audit-0.8.2/AUDIT-Q25-DNS-MARKER-STORAGE.md).

---

### 6.51 Linux: original TUN ... was renamed, detached or changed

`route owner network namespace changed; refusing route commands` means the current
thread is outside the saved route namespace. `original TUN ... was renamed, detached
or changed; preserving route reservations` means the original name/index or device
attachment is lost. Metadata/ioctl errors also refuse cleanup. Qeli does not delete
routes using a name that may already belong to a replacement device.

Checks cover TCP/UDP disconnect, error-path Drop and partial setup rollback. Independent
physical bypass/blackhole records can still be deleted when namespace is proven;
borrowed physical routes survive. A namespace mismatch blocks even queries that could
incorrectly release reservations. Existing cleanup policy still applies: an attempted
cleanup alone does not authorize releasing a retained kill-switch.

Do not rename or move a Qeli-managed TUN during a session. Inspect names/indices with
`ip -o link show`, both families with `ip route show` and `ip -6 route show`, and namespace
with `/proc/<pid>/task/<tid>/ns/net`; inspect the thread performing the operation. First
stop the external manager changing this interface and end the affected session. Remove
only leftovers whose ownership is verified; a broad flush of the saved name is unsafe.
Creating a new device with the same name does not restore an externally deleted original.

A live original guard can retry when its identity is proven again. Once that guard is
lost, an unconfirmed flush keeps the name in the process registry until process exit.
After inspecting/recovering routes and remaining protective rules, restarting the affected
Qeli process may be necessary. End its other active sessions first when using the daemon;
restart alone is not proof that network state was recovered.

`actual TUN name ... differs from route owner ...; refusing setup` requires an exact
supported `dev`. Managed routes need CAP_NET_ADMIN, permitted `TUNGETIFF`/`TUNGETDEVNETNS`
and procfs namespace metadata even with `dns=off`. Attach does not install/clean managed
routes. DNS rename support does not imply rename support for the whole network plan.
Observations and iproute2 are not atomic; physical uplinks and other setup/gateway/firewall
operations still need a separate pass.
[Findings and verification](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md).

---

### 6.52 Linux: route owner identity lost during path commit

`route owner identity lost before path commit`, `route owner identity lost during path
commit`, and `route owner previously lost identity; refusing further setup` refuse further
setup in the current generation. Read the nested cause: original TUN renamed/deleted,
its owning object expired, namespace mismatch, or failed metadata/ioctl observation.
This is not an ordinary transient failure of a candidate roaming route.

Qeli checks the original TUN before setup/prepare/commit route commands, before/after
the platform callback and before acknowledging a successful plan. Managed MAC/address/up
also checks before each call. These checks do not establish the safety of arbitrary
gateway/firewall/sysctl work inside a callback.

When only TUN evidence is lost, the client independently attempts to roll back proven
physical routes in the original namespace. Namespace loss blocks that rollback and
retains journal evidence. Even successful rollback cannot resume a generation with lost
identity. Restoring the name/namespace does not revive it. Uncertain installation outcomes
remain pending and do not grant deletion authority.

Resolve the conflict with the external interface manager and inspect routes/namespace as
in §6.51. End the affected session; start a new generation after verified recovery. A new
interface with the old name does not replace the original fd. A retained process reservation
may require process shutdown as described in §6.51. Do not remove shared routes or protective
rules merely to bypass this diagnostic.

`route owner has no original TUN identity` means managed TUN binding was not established;
`original TUN descriptor owner has expired` means its original object was released. Prepared
paths and route journals do not prolong its life: they use Weak, not another queue.
The final-check/command race, physical uplink identity and other gateway/firewall operations
remain limitations.
[Findings and verification](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md).

---

### 6.53 Linux: gateway ownership or router cleanup is unconfirmed

`router ... has no bound NetworkPlan owner` means gateway was called without its original
owner. `route owner is stopped; refusing router setup` rejects a stopped generation.
`router ownership ... still reserved by another generation` means previous ownership has
not been cleaned. Inspect the nested cause of `router-plan cleanup failed`: command failure,
loss of original TUN/namespace, or unavailable ioctl/metadata.

On full reconnect, Qeli now removes gateway/exit rules and releases their sysctl scope
before closing the original TUN. The next generation reinstalls them. Roaming within a
generation retains old WAN rules until that generation ends. Kill-switch continues across
reconnect under its separate contract.

A lost TUN still permits deletion of confirmed tagged rules in the original namespace.
The entire sysctl scope is deferred: even shared forwarding/rp_filter may remain enabled,
since the scope also contains original interface settings. With an unconfirmed namespace,
gateway executes no rule queries/deletes or sysctl journal calls. Remaining state and the
reservation are retained; cleanup errors prevent automatic reconnect.

Establish the cause of rename/delete/namespace changes and the actual interface's owner.
Cleanup retries need original identity; a new interface with the old name is no substitute.
If the original fd is lost, inspect remaining rules and host settings before process exit
and manual recovery. Do not flush the firewall, remove other owners' rules or delete
sysctls.state to bypass a reservation. A crash does not grant ownership to a new process.

Checks are not atomic with external commands. Shared sysctl checks currently surround its
API: internal lock/prune/read/write, stale recovery and physical WAN identity need separate
review. Independent kill-switch operations are also outside the gateway context.
[Report and tests](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md).

---


### 6.54 Server: a generation does not restart after cleanup failure

If a profile leaves unverified NAT/DNS/sysctl resources or a TUN queue fails to stop,
the worker reports a shutdown error and stops. Another generation within that worker
is refused. Check the original firewall/sysctl/TUN error in the log; a successful
accounting flush does not prove that network resources were released.

Exact NAT/FORWARD/MSS/DNS REDIRECT rules remain in memory until verified absent.
Cleanup can retry while the worker is alive; a missing firewall tool is not evidence
that rules are absent. SIGKILL loses this registry, and historical sweeps cannot
guarantee recovery for unlistable mixed nft chains.

A clean full-worker stop also releases its IPv4 forwarding lease. The original value
is restored only when no other owners remain and the current value is still managed.
Stopping one profile does not release this global lease. No INI setting is required.
[Report](../reports/audit-0.8.2/AUDIT-Q14-RETAINED-CLEANUP.md).


### 6.55 Linux: sysctl journal read or lock wait refused

`sysctls.state` must be a regular file without extra hardlinks, group/world write
permission or content exceeding 128 KiB. Symlinks/FIFOs, growth, truncation or changed
snapshots are refused before restoring kernel sysctls. Saved original values are
preserved. Inspect the state file and directory owner; do not replace the journal
with an empty file just to allow startup.

`timed out waiting for ... host sysctl journal lock` / `timed out waiting for lock`
means the shared 15-second mutex/flock contention budget expired. Find the holder and
finish its operation/process normally. Deleting an active `.lock` creates a different
inode and breaks mutual exclusion; it does not release the held lock. A namespace
change during the wait also stops recovery before sysctl writes. This budget is not
a deadline for complete network setup or file I/O.
[Report](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-JOURNAL-IO.md).


### 6.56 Linux: kill-switch identity or reconnect verification failed

`kill-switch namespace identity lost` stops commands in the current namespace and
retains the original owner/rules. Do not start cleanup against an unrelated same-name
chain. Return to the original namespace and retry verified cleanup, or establish the
exact stale owner and use the recovery procedure in [Getting started](GETTING-STARTED.md).
An identity failure cannot be overridden with `allow_ipv4_leak` / `allow_ipv6_leak`.

`kill-switch verification/address refresh failed` stops reconnect before the next dial.
Inspect the reported OUTPUT/FORWARD/DROP rule or unavailable firewall tool. Remaining
protection is retained; post_down receives reason `kill_switch_failed` and error code
`kill_switch`. Failed installation of a new server allowance keeps the old allowance.
Restore the required tool/access and recover the exact rules before restarting. Do not
flush the whole filter table. A clean IPv6-only lifecycle does not require an IPv4 tool
that was never used. Cleanup without a live in-process owner does not claim crash recovery.
[Report and boundaries](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-IDENTITY.md).


### 6.57 Linux: interface exists but NDP/TAP inspection failed

NDP proxy, TAP MAC discovery, hook ifindex, sysctl interface-presence checks and automatic
panel TUN selection now query the calling network namespace through a kernel socket.
An inherited `/sys/class/net` view no longer supplies these observations. For
`cannot inspect NDP interface`, check the interface inside Qeli's own namespace, its
Ethernet type/unicast MAC and access to control/packet sockets. `required` still refuses
startup on an inspection/bind error; `auto` still reports the failure and continues.

This does not change `off`, `manual`, `route` or `nat66` responsibilities. In particular,
`manual` with required NDP can initialize without remounting sysfs, while the administrator
still owns forwarding/routing/firewall. TUN/TAP `dev_attach` flag inspection remains dependent
on a matching sysfs mount. A snapshot does not authorize restoring a replaced link by name.
[Report and remaining scope](../reports/audit-0.8.2/AUDIT-Q25-LINK-OBSERVATION.md).


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
ip6tables -t mangle -A PREROUTING -p tcp --dport <port> --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
ip6tables -t mangle -A OUTPUT     -p tcp --sport <port> --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220
```

### 8.2 Android client
```bash
adb logcat -s VpnSvc VpnMain            # service + activity log
# reset profiles / VPN consent when stuck:
adb shell pm clear com.qeli
adb shell appops set com.qeli ACTIVATE_VPN allow   # if supported
```

### 8.3 Desktop (Windows/macOS)

- `Refusing untrusted service storage` / `refusing default DLL search` is a security
  refusal, not a reason to place DLLs beside the executable. Since 0.8.2 Windows checks
  owners, all write grants and reparse points; the service profile is private to
  SYSTEM/Administrators. Unsafe legacy files are not adopted automatically.
  Stop the VPN/service and finish DNS/route/firewall recovery first. Preserve a backup
  for diagnosis, recreate protected storage from the elevated GUI and re-save a profile
  from a trusted source. Do not delete active recovery journals or merely tighten
  ACLs over files whose origin has not been verified.
- `Legacy or untrusted Qeli storage requires migration` in development **0.8.3**:
  manual elevated GUI startup offers an explicit legacy-storage
  preparation dialog. Disconnect normally, finish network recovery, stop `QeliWinSvc`
  and close other clients first. Do not migrate after
  `previous tunnel task did not stop within 8s`: let the task finish and retry Disconnect;
  that error does not confirm recovery. The service and autostart never silently move
  legacy data. The old directory is retained inside a unique private backup; reselect
  a trusted service profile afterwards. DLLs use
  `%ProgramData%\QeliWin\native\<bundle-SHA256>`, private service data uses
  `%ProgramData%\QeliWin\service`; `%APPDATA%\QeliWin` and recovery journals stay put.
  Checks conservatively block on any Wintun adapter, including another VPN's adapter;
  do not remove unrelated adapters/firewall rules or bypass the refusal. The user must
  also confirm completed DNS/route recovery; these checks do not prove it automatically.
- `Tunnel cleanup remains incomplete` means cleanup has not finished: the service
  keeps Error instead of Disconnected. Retry stopping and inspect the log.
- `TLS traffic key budget exhausted; reconnect required` is a protective
  REALITY-TLS termination after 2^24 records or 64 GiB of ciphertext per key/direction.
  The client's usual reconnect policy applies; KeyUpdate is not implemented yet.

- **Log** tab → **Copy log** — attach it when troubleshooting.
- Windows requires **administrator** (manifest `requireAdministrator`); macOS —
  **root** (`sudo`) or the launchd daemon enabled.
- Kill-switch left over after a crash? Windows:
  `Remove-NetFirewallRule -Group qeli_ks; Set-NetFirewallProfile -All -DefaultOutboundAction Allow`;
  macOS: restart Qeli as root for checked stale-owner recovery. For an explicit manual override, stop every Qeli instance and flush only its qeli/com.apple/qeli anchors; preserve global pf and foreign policies. See [macOS kill-switch](CONFIG.md#macos-pf).
- `kill-switch is owned by another live Qeli process` means a second Windows tunnel tried
  to take over the same machine-wide firewall state. Stop the other client/service first.
- `[SECURITY] kill-switch disengage failed; egress remains blocked` is fail-closed: the
  recovery state and ownership remain armed so the same process (or the next startup) can
  retry a complete three-profile firewall restore. Do not delete the recovery state by hand.

---

*This document is based on the current code (`qeli/src/**`, `qeli-shared`, `qeli-win`,
`qeli-mac`, `qeli-android`) on the `dev` branch. Error strings are checked against the
sources; if behavior diverges, trust the code and update this file.*

### Gateway cleanup or kill-switch order errors

`gateway cleanup failed` retains failed TUN/family records for retry in the running
process. Inspect the reported firewall error; successful cleanup of another profile
does not prove this one is clean. A sysctl restore error is reported alongside rule
errors. Do not lift a retained kill-switch merely because forwarding was restored.

`cannot inspect router kill-switch protection` or a jump-order error prevents the
permit from being inserted or reused without verified protection. Check access to
iptables/ip6tables and the actual FORWARD chain order. After a process crash the
in-memory rule registry is gone; review leftover `qeli-gw-nat` rules for the affected
interface/subnet before manual recovery.
[Evidence and limitations](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md).

### Exit-node NAT or kill-switch conflict

If policy routing sends forwarded exit-TUN packets through a WAN other than
Qeli's selected one, the `qeli-exit-node` guard drops them rather than
letting the client's original address egress. Inspect `ip rule`,
`ip route get <destination> from <client-address> iif <tun>`, and the WAN
logged by Qeli. After a cleanup failure `qeli-exit-node:lockdown` keeps
blocking the TUN until retry succeeds; do not remove it separately from
remaining MARK/NAT rules. `exit_node` cannot share a profile with
`gateway_nat`, `forward`, or `dev_attach`.

If the physical WAN was renamed or replaced while exit-node ran, stop the
profile and verify `qeli-exit-node` cleanup before restarting: a new device
with the old name can inherit admission from the old rules.
[Evidence and boundary](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md).

If a separate exit WAN changes while the VPN-server path stays the same,
the exit node checks the default route every 5 seconds and installs rules
for the new WAN. The guard blocks traffic until installation succeeds. If
logs show `exit-node WAN refresh failed`, inspect the default route,
`iptables`, and selected WAN. With multiple defaults Qeli selects the lowest
metric; an individual policy route can select another WAN and remain blocked
by the guard. [Monitor and limits](../reports/audit-0.8.2/AUDIT-Q25-EXIT-WAN-MONITOR.md).
`no unique default WAN` means there is no unambiguous external interface:
inspect `ip route show default` and `ip -6 route show default`. For ECMP
or equal lowest metrics on different WANs, give one WAN priority; `route get`
for one address does not represent every client flow.
[ECMP verification](../reports/audit-0.8.2/AUDIT-Q25-WAN-ECMP.md).

For a shared WAN, inspect the exact `qeli-exit-node:<tun>` NAT comments in each family.
The unsuffixed legacy MASQUERADE is preserved during cleanup; do not delete it while
an older exit process may still rely on it. No remembered WAN means no automatic
firewall deletion, not proof that a previous process left nothing behind.

`kill-switch conflict` means another per-TUN or legacy Qeli chain was found before
installation. Stop its live owner cleanly, or establish that it is stale and recover
the exact chain using the procedure in [Getting started](GETTING-STARTED.md).
Do not flush the whole filter table. Incomplete/unreadable inventory also blocks
admission. Leak overrides do not resolve policy conflicts.
[Audit evidence and limits](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md).

### Linux: kill-switch ownership unavailable or IPv6 state unknown

`cannot exclusively own this network namespace` means the kill-switch claim failed.
For `Address already in use`, stop the other protected client in this network namespace,
including one using the same `dev`. For other errors, inspect AF_UNIX/sandbox restrictions
and process resources. Before this refusal the new client does not recover DNS or change
the firewall. Leak overrides do not bypass it.

The lease is released when the client closes, but does not itself remove firewall rules
after a crash. Establish ownership of remaining chains before the precise recovery in
[GETTING-STARTED.md](GETTING-STARTED.md). There is no lease lock file to delete.
Old versions and manual firewall changes need separate coordination during upgrades.

`IPv6 can become active` after IPv6 setup failure means that starting without
`ip6tables` could leak if an address appears later. Install/fix `ip6tables` or disable
IPv6 globally; `allow_ipv6_leak = true` explicitly accepts leakage. If IPv4 rollback also failed,
do not assume the remaining firewall was cleaned up.
[Checks and limits](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV6.md).

### Linux: TUN name already reserved

`cannot reserve TUN` with `Address already in use` means another updated Linux client
already uses this `dev` in the same network namespace, even during a reconnect gap
when the interface is absent. Stop its owner or choose another name. This applies with
`kill_switch = false` and `dev_attach = true`: a shared multi-queue interface is not
for two independent Qeli sessions. AF_UNIX/sandbox/resource failures also refuse startup,
before DNS recovery or network changes. A failed kill-switch claim releases the failed
startup's temporary TUN reservation.

If IPv6 was disabled with `ipv6.disable=1`, a readable exact `1` in
`/sys/module/ipv6/parameters/disable` permits skipping IPv6 firewall access.
An unreadable file or an unloaded module is not evidence that IPv6 is disabled.
Do not substitute sysfs contents or disable IPv6 to evade checks; restore diagnostic
access and investigate the original error.
[Report and limitations](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md).


### 6.58. Panel: busy config, expired preflight and cancelled restore

`network preflight is busy`, `config is busy` or `network preflight expired` means
this save/restart attempt did not reach writing/dispatch. Let the preceding operation
finish, refresh the panel config and retry. Network probes share 15 seconds; after
observation, five seconds cover config-lock admission and candidate preparation.
This is not a deadline for all filesystem operations.

Closing the tab or cancelling a request may leave an already started restore running.
Its blocking worker retains the config lease until completion. Inspect actual files
and snapshots before another restore. Cancellation does not mean rollback.

`could not confirm systemctl restart` means the outcome is unknown. Inspect
`systemctl status <unit>` and the journal: systemd may have accepted the request.
Do not automatically repeat restart based on a timeout alone. A busy worker restart
queue returns an immediate error; retry after the queue becomes available.

[Analysis](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md).


### 6.59. Backup/restore: timeout, archive limit and incomplete snapshot

Download/restore preparation shares 60 seconds across config-lock admission,
archiving, validation and extraction. `archive operation timed out before publication`
means this restore did not begin replacing live files. Once publication starts,
the lock remains held until filesystem operations finish; this is not a hard I/O limit.

Portable gzip is limited to 16 MiB, matching panel upload; pre-restore snapshots to
64 MiB. `system command output limit exceeded` rejects partial output. Check for
unrelated large files in `/etc/qeli`. If a complete set exceeds the limit, take a
complete manual backup before maintenance.

`could not take the pre-restore snapshot` caused by an unreadable file stops restore.
Check access as the actual service user. Do not proceed with replacement until a
complete backup exists. If publication already started and failed, use the retained
`.pre-restore-*.tgz`; automatic whole-tree rollback is not promised.

[Analysis and verification](../reports/audit-0.8.2/AUDIT-Q05-ARCHIVE-BUDGET.md).


HTTP 409 means actual contention or a FileLock wait timeout. Read-only lock-open errors, upload/extraction ENOSPC and snapshot failures return HTTP 500; malformed archives return HTTP 400. Before publication, the response reports `publication_started=false`, `rollback_snapshot=null`. If storage becomes read-only after extraction, private `.restore-staging-*` may remain: inspect and remove it manually once writes are restored and restore has ended. These operational paths are excluded from backups and never reused by the next restore. [Q07 checks](../reports/audit-0.8.2/AUDIT-Q07-BACKUP-RESTORE.md).

### 6.60. Sysctl: namespace changed during a transaction

`host sysctl namespace changed during the journal transaction` or `transaction lost
its namespace context` prevents that transaction from writing further. Keep
`sysctls.state`; do not delete the journal to bypass the error. Return to the original
network, PID/time namespaces and matching procfs, then retry cleanup as a separate
operation. An error after writing does not mean the sysctl remained unchanged: the
journal retains the original value for verification/recovery. Returning to the original
context does not revive a failed transaction. [Analysis](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-CONTEXT-IO.md).

### 6.61. `published ... persistence is uncertain`

New bytes are already published, but directory synchronization failed. This is
not a rollback: reread the file and its revision before retrying a save. Check
filesystem health, free space and I/O errors. After the equivalent removal error
the name may already be absent; retry still performs fsync. Do not delete
`sysctls.state` to bypass the error. Errors before rename preserve the previous
file and remove the incomplete temporary file when the filesystem permits it.
[Analysis and guarantee limits](../reports/audit-0.8.2/AUDIT-Q25-ATOMIC-STATE.md).

### 6.62. Unsafe sysctl state directory or replaced lock

`unsafe sysctl state directory` refuses the operation before journal loading/recovery.
Use an absolute real `STATE_DIRECTORY` without symlinks or `..`; do not grant the
directory or journal group/world write. The standard `/var/lib/qeli` may belong to
the service account; root CLI cooperation is preserved. Root does not adopt a foreign
directory directly beneath shared sticky `/tmp`. Do not use `chmod 777`.

`lock changed while waiting` means the lock pathname no longer matches the waiting
process's descriptor. Keep the journal, inspect external directory operations and
retry once the conflicting operation has ended. Do not remove a lock to “unlock” it:
that creates an independent flock domain.
[Analysis and supported policy](../reports/audit-0.8.2/AUDIT-Q25-STATE-DIRECTORY.md).

### 6.63. Sysctl: namespace pins require available file descriptors

A transaction now opens and retains network, PID and available time namespaces
until journal work completes, starting before lock waits. An open failure such
as `Too many open files` or `Permission denied` does not permit recovery without
verified identity. Check fd limits and access to the service's own procfs view;
do not remove the journal to bypass the failure. This does not reserve a namespace
persistently after the process exits.
[Guarantees and limitations](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-PIN.md).

### 6.64. Original interface sysctl evidence was lost

`lost live per-interface sysctl evidence/witness`, `per-interface sysctl object changed`
or `cannot inspect saved sysctl ... No such file` means automatic restoration of the
original `rp_filter`/`accept_ra` cannot safely continue. Even the same name and ifindex
do not prove it is the original object. Rename may also make an old fd return ENOENT.
Qeli retains the original, continues independent cleanup and reports the failure.

Stop automatic restarts and participants using this journal. Preserve a private copy
of `sysctls.state` and logs. Use administrative network history to establish which
original interface owned the setting; manually restore only a verified original object.
The journal alone does not prove the identity of the current interface. If identity
cannot be established, use a planned host reboot: the next start recognizes valid state
from the previous boot and does not replay it. There is no automatic command that safely
guesses the mapping and clears such an entry. An ordinary restart, renaming back or
removing the journal does not replace verification.

The limit of 256 retained per-interface objects is per process. Each holds a sysctl fd
and references to namespace fds; this is not a total limit of 256 descriptors. On
`per-interface sysctl descriptor limit reached`, finish verified cleanup and inspect
fds and remaining entries. Do not raise limits instead of identifying the cause.
[Analysis, v2 → v3 migration and tests](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md).

### 6.65. Panel: iptables availability could not be verified

`Could not verify iptables availability` appears in Status/Transport health when the
PATH probe fails: timeout, execution permissions, nonzero exit or excessive output.
Check the installed tool and service-account access, then retry diagnostics. This is
a warning; confirmed absence of iptables receives a separate critical diagnostic.

Async `iptables/ip6tables --version` probes share four slots and a 15-second per-request
budget including queue time. Each stdout/stderr stream is limited to 64 KiB. Request
cancellation stops its owned process group; ordinary timeout waits for child completion.
Kill/reap and synchronous file checks have no hard upper bound here, so this is not
a whole-HTTP-request latency promise. Finding the tool also does not verify firewall
correctness. [Analysis](../reports/audit-0.8.2/AUDIT-Q05-HEALTH-PROBES.md).

### 6.66. Linux: shared kill-switch cleanup deadline expired

`kill-switch cleanup deadline expired; ownership retained for retry` means the attempt's
15 seconds were consumed by lock admission or commands across both families. Inspect
stalled backends, competing firewall operations and their logs. Once resolved, cleanup
retry in the same process receives a fresh budget and checks the remaining resources.
Some jumps/chains may already have been removed; neither intact protection nor successful
shutdown is established by timeout. After process exit the in-memory owner is lost:
inspect exact `QELI_KS_<tun>` chains in the original namespace and perform verified
recovery. Preserve unrelated chains. [Analysis](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-BUDGET.md).

### 6.67. Linux: kill-switch refresh stopped reconnect

`kill-switch server-address refresh deadline expired; ownership retained for retry`
means resolver, queue or firewall-command time exhausted the shared 15-second budget.
Check DNS/NSS, competing firewall operations and iptables/ip6tables replies. DNS waiting
is deadline-bound; a late system-call result is discarded.
`firewall inspection failed` while checking an IP allowance cannot authorize insertion.
The connect loop stops reconnect and retains protection. Do not remove DROP to bypass
the error: resolve its cause, then perform controlled recovery/restart. A partially added
new address may remain alongside the previous one. A separate refresh call in the same
process gets a new deadline, but no automatic retry was added here.
[Analysis](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REFRESH.md).

### 6.68. Linux: kill-switch setup or rollback failed

`kill-switch setup deadline expired` means resolver, queue or commands exhausted the
shared 15-second setup deadline. Check DNS/NSS, competing operations and firewall replies.
A late result cannot start new setup commands; changes already started require rollback,
which receives a separate shared 15-second budget.

`kill-switch setup rollback incomplete; ownership retained` means cleanup of recorded
families was not verified. `allow_ipv4_leak`/`allow_ipv6_leak` cannot bypass this refusal.
Do not assume successful setup, intact protection or complete removal: some rules may
already be gone. Resolve the cause and perform verified cleanup. In the live process it
uses the original namespace and remembered tool paths; after process exit, inspect exact
`QELI_KS_<tun>` chains and jumps in the original namespace before manual recovery,
preserving unrelated rules. A deadline before ownership binding does not itself mean new
rules were installed. This is not a hard connection deadline or automatic crash recovery.
[Analysis](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-SETUP.md).

### 6.69. Server: NAT cleanup deadline expired

`NAT cleanup deadline expired; unresolved ownership retained for retry` means one
cleanup attempt spent its 15 seconds on admission or command sequences. Inspect
iptables/ip6tables delays, competing firewall changes and the number of rules. A
separate attempt in the same worker gets a new deadline and checks remaining state.
An applied but late-acknowledged deletion remains pending; that does not prove the
rule still exists. A profile/worker cleanup failure is not successful shutdown.

After worker exit, its exact in-memory registries are gone: before recovery inspect
rules with the exact `qeli-nat:<profile>` comment, DNS INPUT and the sysctl journal in
the original namespace. Preserve unrelated rules; do not substitute a broad firewall
flush or journal deletion for verification. The deadline does not interrupt sysctl/I/O
already started or guarantee whole-shutdown time.
[Analysis](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP-BUDGET.md).

### 6.70. Server: DNS INPUT setup/cleanup deadline expired

`DNS firewall setup deadline expired` covers one ruleset's 15 seconds: queue time,
old pending records, UDP/TCP and INPUT verification. Failure after partial installation
starts rollback with a separate 15-second deadline.

`DNS INPUT cleanup deadline expired` retains the entry as pending before lock admission.
Once the delay is resolved, profile/setup/final cleanup can retry verification. Drop
logs its failure; subsequent verified cleanup determines the shutdown result.
`DNS INPUT cleanup still pending` prevents successful final cleanup, and during setup
refuses reservation over an observed pending generation. Inspect competing operations
and iptables/ip6tables replies; preserve unrelated INPUT rules. After worker exit,
inspect leftovers separately: in-memory retirement is not a crash journal. Port-53
DNS REDIRECT setup has a separate, still-open operation-budget boundary.
[Analysis](../reports/audit-0.8.2/AUDIT-Q14-DNS-INPUT-BUDGET.md).

### 6.71. Server: NAT setup / rollback deadline

`NAT setup`, `IPv4 routing setup` and `IPv6 routing setup deadline expired` include
firewall/registry admission and the complete command sequence for one setup. Rollback
has a separate shared deadline. `NAT rollback incomplete` retains exact records and
prevents successful setup. Once the delay is resolved, lifecycle cleanup verifies the
remaining rules again. Preserve unrelated rules; timeout does not prove no mutation.
[Analysis](../reports/audit-0.8.2/AUDIT-Q14-NAT-SETUP-BUDGET.md).

### 6.72. Sysctl: namespace generation or legacy v3

`host sysctl network namespace generation mismatch` retains the journal and refuses
before owner probes and sysctl I/O. Matching inode alone is insufficient; never assign
the current cookie to old state. `SO_NETNS_COOKIE is required` needs kernel support
for this socket option to manage sysctls. `legacy v3 host sysctl journal lacks durable
namespace generation` requires verified cleanup in the original network before upgrading
or a planned reboot. Preserve state; never edit cookie/version/boot-id to bypass refusal.
[Details](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-GENERATION.md).

### 6.73. Router operation deadline expired

Gateway/exit-node did not complete commands or router mutex admission within its deadline. Remaining rules and sysctl ownership are retained for verified cleanup with a fresh deadline. Check firewall tool availability; do not delete rules by a broad prefix. Internal I/O may return after the deadline. [Contract](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-BUDGET.md).

### 6.74. Route operation deadline expired

Route queries/mutations or mutex admission exceeded the shared deadline. Timeout does not prove that nothing changed. The retained owner permits verified cleanup; unknown rollback stops COMMIT. Preserve foreign routes and do not discard pending reservations without verification. [Details](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-BUDGET.md).

### 6.75. DNS: systemd-resolved is not the active system resolver

For `dns = tunnel`, Qeli checks `/etc/resolv.conf` contents, including the symlink target. An upstream file, commented stub address or mixed DNS list is insufficient. Use an operating stub or `dns = off`/`system` for platform-managed DNS. Qeli does not rewrite the file automatically. [Validation and boundaries](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONFIG.md).

### 6.76. DNS: bus/service context changed or different network namespace

The client refuses numeric ifindex mutations in a foreign network or through a replaced
service/bus instance. Check that resolved serves the client network, the broker shares
its PID namespace, `busctl` is installed, `/proc` is accessible, and
`DBUS_SYSTEM_BUS_ADDRESS` selects one local Unix bus. Do not expose the host bus to a
separate-network container for DNS management. Delegate external management through
`dns = off`/`system`.

A retained lease is not automatically transferred to a replacement service. Inspect
the interface and `resolvectl status`; preserve evidence before manual recovery (§6.50).
`LinkBusy` means another manager controls the link; there is no implicit networkd
fallback. A `SetLinkDNSEx` error with a custom port requires resolved supporting this
API: Qeli does not silently change the port to 53.
[Analysis and checks](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONTEXT.md).

### 6.77. Server worker network namespace already owned

Another worker or process holds `qeli.server.worker` in this network. Changing
control sockets, state directories or mount/PID namespaces does not resolve the
conflict. Use the existing worker with multiple profiles, or allocate another
network namespace and separate file paths. If the old worker is still executing
`post_down`, wait for exit. After actual SIGKILL the kernel lease disappears;
there is no lease file to delete. Do not remove a live process's control lock.

Unknown holders are not bypassed automatically; a local process can also occupy
the abstract name. Reservation unavailable may indicate another bind error,
identified in the message. [Checks and limits](../reports/audit-0.8.2/AUDIT-Q14-WORKER-NETWORK-LEASE.md).

### 6.78. Server firewall recovery incomplete

The worker does not launch profiles when exact rules in `server-firewall.state` cannot be removed or verified. Keep the journal and `.lock`, use the original state/network namespace/backend, fix the iptables or permission failure and retry. `iptables backend changed` requires restoring the original nft/legacy backend; `server firewall journal requires SO_NETNS_COOKIE` requires kernel support for that option. Corrupt or unsupported state cannot be automatically reset. An empty journal after success is normal. [Recovery procedure](OPERATIONS.md#server-firewall-recovery).

### 6.79. Linux: kill-switch rebuild guard remains after failure

Rules `-m comment --comment qeli-ks-rebuild:<tun> -j DROP` close OUTPUT and, when needed,
FORWARD while replacing prior kill-switch protection. A same-`dev` restart in the same
namespace/backend verifies guards, then rebuilds ordinary chains. Guards retire only
after every required family is ready. Setup failure or another SIGKILL retains protection;
`allow_ipv*_leak` cannot bypass recovery failure. Guard retirement errors do not remove
completed replacement chains.

Temporary guards are stricter than the normal allow-list: before the new chain is ready,
they may block DNS and loopback. A retained guard can prevent hostname-based startup
from passing resolution; use a verified server IP or administrator recovery. Resolve
the original firewall error first and retry the same client. For manual removal, stop
the owner, inspect exact OUTPUT/FORWARD rules in both families in the original namespace,
and deliberately choose to restore direct egress. After clearing the ordinary
`QELI_KS_<tun>` chain, remove only verified surviving guards:

```bash
# Example for dev = vpn0; run only for verified remaining rules.
sudo iptables  -D OUTPUT  -m comment --comment qeli-ks-rebuild:vpn0 -j DROP
sudo iptables  -D FORWARD -m comment --comment qeli-ks-rebuild:vpn0 -j DROP
sudo ip6tables -D OUTPUT  -m comment --comment qeli-ks-rebuild:vpn0 -j DROP
sudo ip6tables -D FORWARD -m comment --comment qeli-ks-rebuild:vpn0 -j DROP
```

Never flush the whole table or remove another TUN's guards. This comment prefix is
reserved for Qeli. `kill-switch conflict` can refer to another client's guard even
without its ordinary chain. First installation without prior protection creates no
guards: this contract covers replacement of an existing barrier.
[Leak reproduction and validation](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REBUILD.md).

### 6.80. Linux: owned route changed; preserving replacement

Qeli detected a changed physical bypass or blackhole and left it to the administrator.
Even with the same destination/gateway/device, changes to `proto`, metric, source or
additional attributes relinquish the previous ownership. This can explain a route left
after orderly stop. Inspect the original namespace; an address match alone is not
permission to remove every matching entry. After SIGKILL the durable journal recovers
confirmed physical entries on the next start; unresolved intents require §6.81.
[Operations](OPERATIONS.md#linux-physical-routes-changed-by-an-administrator).

### 6.81. Linux: physical route journal recovery

`client route recovery incomplete` means verified cleanup did not finish.
`unresolved physical route intent without delete authority` means a command may have
changed the route without confirming ownership. Matching destination is not permission
to remove it.

1. Stop the owner and verify the original network namespace, boot ID and `dev`. Save
   the journal and `ip -4 route show table main` / `ip -6 route show table main`
   snapshots. Do not move the journal to another network.
2. Repair unavailable `ip`, permissions or state I/O, then retry. Do not weaken
   directory permissions or remove the stable lock.
3. For pending state, establish the exact entry's origin. Delete only an exact route
   confirmed by the administrator as a Qeli crash leftover. Once it is absent,
   restart retires the reservation. If another owner needs it, preserve it and reconcile
   the network plan; pending state is never adopted automatically.
4. `refuses a live or persistent TUN` requires stopping its owner and inspecting the
   existing device. Do not delete a foreign TUN based on its name. `still live` means
   an occupied kernel lease; another state path cannot bypass it.

Malformed/unknown format, capacity overflow, unsafe owner/symlink or `context was lost`
stops operations. Do not edit boot/cookie/version to bypass checks. A new boot resets
only valid old state. The journal is required in managed mode even with DNS disabled;
`SO_NETNS_COOKIE` and trusted writable `/var/lib/qeli` are required. Empty state and
`.lock` after clean shutdown are normal.
[Recovery contract](OPERATIONS.md#client-physical-route-recovery).

### 6.82. Linux: persistent TUN/TAP survives client termination

`client route recovery refuses a live or persistent TUN` means the device with the
previous `dev` still exists. Closing the last queue fd deletes an ordinary nonpersistent
TUN; persistence keeps it after SIGKILL. A matching name and ifindex do not prove that
the new process may delete it. Qeli preserves the journal and refuses this recovery.
Per-link DNS for a live index is not reverted from a retained marker alone either.

1. Stop the previous client and automatic restarts. In the original network namespace,
   establish who created the device and who holds its queues; stopping one PID alone
   does not prove that no other owner remains.
2. Save the journal, DNS markers, `ip -d link show dev vpn0`, addresses, IPv4/IPv6
   routes and firewall rules. Inspect `ip tuntap show dev vpn0`, `resolvectl status`
   and the current ifindex. `vpn0` is an example; use your actual `dev`.
3. Preserve the device and investigate if another process needs it or its origin is
   unknown. Do not delete the journal or change cookie/boot ID to force startup.
   `dev_attach = true` is not a crash-recovery command.
4. Only for a confirmed orphan that is no longer needed, remove **that exact device
   in its original network**: `ip tuntap del dev vpn0 mode tun`; use `mode tap` for a
   verified TAP. Recheck the device and owners immediately before the command.
   This is an explicit administrator decision, not an automatic Qeli operation.
5. Confirm that the device is absent, then start the original INI with the same `dev`,
   namespace and state directory. Qeli recovers confirmed physical routes and retires
   the DNS marker for the absent link; uncertain intents require separate investigation
   (§6.81). Verify the new interface, connectivity and DNS.

Removing the interface does not remove a retained kill-switch. Keep the barrier until
the new connection is ready; use §6.79 when deliberately returning to direct access.
Do not flush shared firewall/route tables. Automatically adopting a persistent device
or another owner's DNS configuration is not supported.
[SIGKILL and manual recovery validation](../reports/audit-0.8.2/AUDIT-Q25-PERSISTENT-TUN.md).

### 6.83. Linux: mixed nft/legacy/firewalld recovery

The backend is selected independently for `iptables` and `ip6tables`. For server firewall journal recovery, if it changes
after a crash, Qeli preserves the affected family's records and aborts startup;
independent confirmed deletions in the other family may already have completed.
Restore each family's original backend. A whole-table flush is unnecessary.

A native nft expression in a shared chain can prevent both `-S` listing and `-C`
inspection of an absent rule. In the tested case, successful `-D` is followed by
`Parsing nftables rule failed` and exit 3. The kernel rule may already be absent,
but the journal correctly remains: a parse failure does not establish absence.
Repeated startup will refuse while inspection remains ambiguous.

Stop automatic restarts and save the journal plus `nft -a list ruleset` in the
original namespace. The owner of the native nft rules must restore chain compatibility
while preserving required filtering; for example, move its expression to a separate
native table after checking hook/priority and rule ordering. Remove only explicitly
verified unwanted rules, never the whole FORWARD chain. Once inspection works, restart
Qeli to finish exact checks and retire the corresponding journal records. Do not
reinterpret exit 3 as absence or delete state to bypass refusal.

Successful firewall recovery does not complete every subsystem. WAN `accept_ra`
reporting `lost live per-interface sysctl evidence` follows §6.64: the original
interface and value require separate administrator confirmation.

Reloading firewalld with its nftables backend is checked separately from Qeli recovery.
Preservation of Qeli rules does not prove that firewalld zones and policies permit VPN
traffic; that depends on administrator configuration.
[Matrix and limits](../reports/audit-0.8.2/AUDIT-Q14-MIXED-FIREWALL.md).

### 6.84. Linux: client rejects a legacy-table warning

`# Warning: iptables-legacy tables present, use iptables-legacy to see them`
(or its `ip6tables-legacy` counterpart) reports tables belonging to the other backend.
It does not by itself mean that the selected backend is broken. Previously, this line
before `No chain/target/match by that name` caused a false failure when inspecting an
absent `QELI_KS_<dev>` chain. Q25-F102 permits only these exact advisory lines alongside
a recognized absence diagnostic and appropriate exit. Update to a binary containing
this fix; do not delete operator legacy rules merely to silence the warning.

Permission/backend errors, unknown extra messages and nft parse errors still require
investigation. Exit 1 alone does not establish absence. For `Parsing nftables rule failed`,
follow §6.83 without erasing journals/chains. Keep **each family's** original backend
across client startup, crash recovery and stop: automatic nft/legacy migration is not
certified. Firewalld reload does not replace checks of traffic, DNS and retained kill-switch.
[Cause, tests and boundaries](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-MIXED-FIREWALL.md).

### 6.85. Client: DNS delay and shutdown

`system DNS resolver queue expired` means the request could not acquire a free slot;
`system DNS resolution timed out` / `deadline expired` means DNS/NSS waiting expired.
Kill-switch includes this wait in its 15-second budget; connections and UDP diagnostics
use their own deadlines. Linux setup/refresh and initial connection respond to
SIGTERM/SIGINT during DNS waiting. Ordinary network cleanup still runs, and cleanup
failure still requires recovery.

Check name resolution in the same network and mount namespace, `/etc/hosts`,
`/etc/nsswitch.conf`, and the system resolver. Four stuck calls can occupy all slots;
retries wait in the shared queue, while numeric IPs bypass it. The system call cannot
be safely interrupted: it retains its thread/slot until completion, but does not delay
Tokio runtime destruction and has no authority to change firewall, routes or TUN.
This is not a hard whole-network-operation shutdown deadline.
[Validation and limits](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-RESOLVER.md).

### 6.86. Linux: resolver files and kill-switch DNS allowances

If DNS fails while protection is active, inspect both resolver files from the same
mount/network namespace. Ordinary symlinks are allowed; a FIFO, directory, file over
64 KiB, NUL/invalid UTF-8 or malformed `nameserver` directive grants no allowances
from that file. Write `nameserver 192.0.2.53 # comment`, with whitespace separators.
Scoped IPv6 (`%wan0`/`%2`) receives no address-only rule that would lose its scope;
other valid entries remain usable. Do not broaden the rule to arbitrary `--dport 53`.

Reading before setup uses the shared queue in §6.85, even with a numeric server.
If waiting expires, new installation does not begin; existing protection still needs
ordinary recovery/cleanup. SIGTERM cancels waiting for the read-only worker; synchronous
network mutations retain their previous boundaries. Changed system DNS needs a new
installation cycle: refreshing VPN server addresses does not reread DNS allowances.
[Causes and lab validation](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-FILES.md).

### 6.87. Linux: stopping in awaiting_network

When stopped during TUN/address/route/DNS setup, the client continues processing signals
and neighboring async tasks but waits for started system work. Unadopted settings are
then rolled back in their original context. If a command or kernel call is stuck, do not
start a competing profile with the same `dev`: the outer lease must remain held until
cleanup finishes. A signal log entry does not establish completed rollback.

`network transaction ... namespace changed` rejects result adoption from a changed
NET/mount context; `worker panicked` reports worker failure, not successful setup.
Retain journals when cleanup is unverified. Established-tunnel teardown and kill-switch
still have their previous synchronous-section limitations.
[Operation and tests](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-TASK.md).

### 6.88. Linux: cleanup error after an established connection

During graceful DNS/route/forwarding teardown, neighboring async tasks keep running,
but the TUN and network lease remain owned until cleanup finishes. A stop signal does
not confirm that the interface is ready for reuse.

A `network transaction` cleanup error means worker creation/context failure or panic.
Hook reason `network_cleanup_failed` and code `network_cleanup` remain unchanged.
Do not assume an enabled kill-switch was removed after this exit, or automatically
remove it merely because the client window closed. Early errors and forced Drop may
still run fallback synchronously. [Details](../reports/audit-0.8.2/AUDIT-Q25-TUN-TEARDOWN.md).

### 6.89. Linux: stop during a firewall command or chain retained

DNS waits can be cancelled before mutation. Once iptables/ip6tables work starts, the
client retains its namespace/TUN lease and awaits the result even after receiving stop.
Neighboring async tasks keep running. There is still no single hard shutdown deadline.

For `firewall unhook failed; chain retained`, inspect the OUTPUT/FORWARD error and
exact IPv4/IPv6 family. A chain with unconfirmed hook removal is not automatically
flushed. Retain logs and resolve the command failure before a new start; `failed`
alone proves neither absence nor complete retention of protection.
[Cancellation and recovery scenarios](../reports/audit-0.8.2/AUDIT-Q25-FIREWALL-TASK.md).

### 6.90. UDP: no ServerHello through the server's secondary IP

Older wildcard listeners could reply from the primary IP instead of the destination.
Compare request/reply IPs in a capture: an open UDP port alone does not confirm the right
source. The fix retains each packet's local destination. An older build can explicitly
set `bind.address` to the required address; this does not fix wildcard mode.
`UDP destination packet info missing`/`truncated UDP packet info` indicates that address
context could not be obtained; retain logs and OS/socket details.
[Reproduction and fix](../reports/audit-0.8.2/AUDIT-Q15-UDP-LOCAL-ADDRESS.md).

### 6.91. Linux: stop waits for startup recovery or the journal lock

While another process holds `client-routes.state.lock`, admitted recovery retains the
TUN/namespace lease. Heartbeat and stop handling continue, but exit awaits the result.
Lock timeout, a malformed journal or legacy global DNS retain `failed` even after stop.
Keep the evidence and resolve the lock/error cause; do not delete a live owner's lockfile.

A stopped client starts no handshake after successful recovery. `dev_attach = true`
does not bypass DNS checks. [Scenarios](../reports/audit-0.8.2/AUDIT-Q25-STARTUP-RECOVERY-TASK.md).

### 6.92. Linux: TUN packet pump startup failed

Retain the full error chain: fcntl can fail on a descriptor and packet-thread creation
can fail because of OS resources. An already started reader is joined before releasing
the original TUN. A route/DNS/forwarding cleanup failure retains `failed` and kill-switch
even after SIGTERM. Resolve the cause and start explicitly; `post_up` alone does not
prove a working data plane. [fcntl/thread-failure reproduction](../reports/audit-0.8.2/AUDIT-Q25-PUMP-START.md).

### 6.93. Linux: panel status is delayed or unchanged after exit

Check `cannot publish client diagnostics`, storage availability and permissions on the
`QELI_CLIENT_STATUS` directory. `cannot start client diagnostics writer` means its
thread could not be created; the VPN can continue without updating the file. Failure
to publish terminal status does not change the VPN exit code and may retain old state.

On slow fsync, ordinary exit awaits the writer; forced owner destruction also joins it.
A displayed `running` does not prove the process is alive, and missing an intermediate
state does not prove a lost connection: the queue coalesces snapshots.
[Design and validation](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md).

### 6.94. Linux: corrupt known_hosts or temporary device-id

`cannot read known_hosts store`, `known_hosts exceeds 1 MiB`, `invalid known_hosts pin`
and `SERVER KEY MISMATCH` require inspecting the existing file and server key.
`allow_unpinned_tofu = true` does not disable these checks. Preserve a copy and repair
the specific record after verifying its key instead of deleting the whole trust store.

`device id will be per-run` indicates a read/lock error; `device id could not be persisted`
indicates write failure. This run uses one temporary ID, which may not survive restart.
Check file type, permissions and lock ownership; do not delete a live process's lock.
[Details](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-FILES.md).

### 6.95. Linux: TOFU timeout and late persistence failure

`server identity verification timed out` means the handshake stopped waiting. The client
still awaits admitted file work before reconnect/exit; this is not a total shutdown
deadline. `unobserved identity verification failure` reports an error arriving after
handshake cancellation: the run fails even on SIGTERM. Inspect storage and the I/O cause;
do not remove a live process's lock. [Details](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md).

### 6.96. Server: profile setup exceeded 120 seconds

`setup exceeded its 120 second budget before all listeners bound` means the
generation did not become ready on time. Inspect earlier TUN/NAT/NDP,
`post_up`, DNS and each `listen` bind message. `listener bind failed` identifies
a specific port failure; free the address/port and let rollback finish before
retry. `post_up` alone does not prove that the listeners are bound.

This budget covers setup only. Cancellation may still await admitted worker
work or cleanup beyond 120 seconds; do not start a second generation with the
same TUN/network rules in parallel. [Validation](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-BUDGET.md).

<!-- normative-sync: manual-ws-write-v1 -->

With fronting=websocket,the shared core flushes each protocol record,including handshake/ACK/heartbeat. Under backpressure,unsent bytes remain in the bounded writer and survive cancellation of a later operation. A fault after partial emission terminates that stream;do not resume it with the old cipher state—establish a new connection. [Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md).

<!-- normative-sync: manual-ws-read-v1 -->

If WebSocket Upgrade fails,check that the intermediate HTTP endpoint preserves GET/HTTP/1.1,Host,Sec-WebSocket-Version13 and does not duplicate key/accept. Body,Transfer-Encoding,unoffered extensions/subprotocols and heads exceeding4096 bytes are unsupported. UnexpectedEof may indicate an unfinished frame or fragmented message. A later-frame failure follows already received payloads and requires a new connection. Configuration settings are unchanged;format remains INI. [Q12 report](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md).

<!-- normative-sync: manual-ws-control-v1 -->

With front=websocket,Ping is handled without application data. Valid Close ends the connection after echo;later data is refused. A Close payload error indicates invalid length,status or UTF-8 reason. Terminal errors require a new carrier. `reality` is a Quick Start name:INI uses fake-tls with REALITY proxy;mode=reality-tls means real TLS. AWG jc must match for TCP obfs;on UDP it means junk datagrams. Configs remain INI. [Q12](../reports/audit-0.8.2/AUDIT-Q12-TRANSPORTS.md).

<!-- normative-sync: manual-macos-forwarding-v1 -->

### macOS: forwarding owner or cleanup error

Ordinary utun profiles with forward=true allow one Qeli forwarding owner per Mac.
For Another live Qeli forwarding owner exists, stop the current profile before starting
another. Initially enabled forwarding also requires a lease. No new INI settings.
Root startup recovers dead-owner journals and preserves live owners.

Forwarding cleanup remains pending or Owned forwarding journal disappeared means
cleanup was not confirmed. Retry ordinary stop after resolving sysctl or protected
/Library/Application Support/Qeli access errors. Corrupt/replaced forwarding-state.json
requires administrator inspection; do not blindly delete it. Restore failure refuses TUN
closure. The journal is an internal JSON DTO; user configs remain INI. It does not provide
full network crash recovery or coordination with independent tools changing sysctl.
[Checks and limits](../reports/audit-0.8.2/AUDIT-Q28-MACOS-FORWARDING.md).

<!-- normative-sync: manual-macos-guardian-v1 -->

### macOS per-app: guardian readiness and bundle upgrade

Internal per-app schema is v5. Upgrade host/helper/extension as one signed bundle after
stopping old profiles and joining guardians. Version 4 does not prove ownership and is not
automatically taken over. If old state blocks claim, confirm old Qeli managers/guardians
stopped, preserve a copy of per-app-state.json and remove only that stale file in the Qeli
app-group container. Do not blindly remove active/unknown-owner state.

Readiness failure means no exact token acknowledgement after claim within 5 seconds,
child exit or invalid ack. A live PID alone is insufficient; finish cleanup before retry.
A join error after confirmed stop retries join only and blocks reconfiguration until it
finishes. Foreign live owners are preserved. Completed owner state remains as a tombstone;
a new token may claim after confirmed stop. Configs remain INI; JSON state is internal DTO.
[Checks and limits](../reports/audit-0.8.2/AUDIT-Q28-MACOS-GUARDIAN.md).

<!-- normative-sync: manual-macos-relay-budget-v1 -->

### macOS per-app: relay timeout and socket stop

TCP connect shares a 10-second budget across DNS and all candidates; a first blackhole
can consume it before fallback. TCP send and the entire UDP batch have 5-second budgets,
DNS queries 2 seconds within the caller's budget. Framework-write's 10-second watchdog
closes its current relay; partial TCP transmission requires a fresh connection.
Stop first refuses new I/O, then queued cleanup/cancel handlers release fd;
returning from stop does not prove completed kernel release. Empty UDP datagrams
are not EOF. No new INI settings. These changes were reviewed by source;
Swift/macOS runtime is user-excluded and managed tests do not replace it.
[Checks and limits](../reports/audit-0.8.2/AUDIT-Q28-MACOS-SOCKETS.md).


<!-- normative-sync: q28-macos-identity-halfclose-v1 -->

### macOS: legacy DNS/PF journals and TCP EOF

New DNS journals use schema2/UTC; PF stamps use clock=utc. A live legacy PID is not
stale solely because local ticks mismatch. Stop old profiles/guardians before upgrade.
If another process occupies a legacy PID, inspect ownership manually; never blindly
remove journals. Downgrade with active new state is unsupported. TCP EOF ends only
its direction: app FIN preserves server response; remote FIN preserves app-to-server.
Both EOF or error/cancel/write timeout retire the relay.
[Criteria, checks and exclusions](../reports/audit-0.8.2/AUDIT-Q28-MACOS-INTEGRATION.md).


<!-- normative-sync: q29-android-legacy-backup-v1 -->

### Android: unreadable legacy profiles and recovery

Failed legacy migration is not an empty default store and cannot authorize ordinary writes.
The encrypted recovery copy survives. Restart the app process after a transient failure;
use a previously exported backup and explicit UI restore confirmation after Keystore key loss.
Stale restore refuses; app data is not automatically deleted. Explicit cloud/device-transfer
rules exclude app state; profile transfer uses user backup export/import. No backup means
no recovery of a lost key.
[Q29 checks and limits](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md).


<!-- normative-sync: android-private-dns-q29-v1 -->

### Android: excluded app blocked / DNS lookup fails

“Block connections without VPN” also blocks apps excluded by per-app settings.
If they need direct access, deliberately disable system lockdown; a profile with
`kill_switch=true` then cannot confirm its required protection.

For lookup failures check Android Settings → Network & internet → Private DNS.
On the tested API34 image an invalid strict-provider name broke system DNS even
with VPN active, with no clear-DNS fallback. Ensure the provider is reachable
outside and inside the VPN. `Automatic` permits ordinary DNS; a successful raw
UDP probe does not prove that Private DNS/DoT works.
[Matrix, exact artifacts and limits](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-APP-POLICY.md).
Trusted CA, invalid CA/SAN rejection and recovery were checked on API34
for TCP/UDP/QUIC: [strict DoT](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-DOT.md).

### Service reload and root-owned configuration

`systemctl reload qeli` sends SIGHUP to the supervisor, which validates and reloads users/authentication and asks the worker to reload without replacing either process. Invalid INI/users are rejected without publishing new authentication state. Profile/listener/TUN and panel startup settings still need a full service restart. SIGHUP preserves the panel login lockout tracker. [Systemd audit](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).

Root mode can read qeli-owned private state, but panel config publication still requires a trusted file owned by root or the running user, without group/other write permissions and without a symlink. Root will therefore refuse a panel save of a qeli-owned INI. Review the configuration as administrator, then use `sudo chown root:root /etc/qeli/server.conf` and `sudo chmod 600 /etc/qeli/server.conf` if root is the intended service account. Do not change ownership of password receipts to qeli. To refresh an older root drop-in, rerun `sudo qeli set-service-user root` with the current binary and restart the service. This grants three filesystem capabilities, not an unrestricted capability set. [Systemd audit](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md).

### Linux: TCP works but simultaneous upload/download reduces throughput

<!-- normative-sync: q36-tun-counter-boundary-v1 -->

Zero client tcp_uplink_drops/tcp_downlink_drops and server dropped do not exclude
kernel TUN losses: these are Qeli application counters. Capture before/after
`ip -s -s link show dev vpn0` and `tc -s qdisc show dev vpn0` over the same interval
on server/client. Replace vpn0 with the actual TUN name; run commands in the
process namespace. Compare RX/TX errors/dropped deltas for the same ifindex,
and qdisc drops separately. With mq, do not sum root/children: root aggregates
them already. Zero backlog after a test does not show peak queueing during load.
Increasing TUN tx_dropped with zero qdisc drops identifies TUN device loss,
without establishing the driver drop reason or the lost TCP flow. Compare
latency before increasing queues: larger buffers may increase delay.
[Scoped experiment and evidence limits](../reports/BENCHMARK.md).

The internal TUN ring may overflow before Qeli reads a packet; native handoff counters do not cover this stage. Aggregate TX dropped cannot identify the cause of an arbitrary failure on another system. Development laboratory numbers are not published.


<!-- normative-sync: q29-process-death-troubleshooting-v2 -->

### Android: VPN did not return after process death

After process death,Always-on VPN depends on Android restarting services. Corrected ordinary R8 Qeli on tested Android14/API34 automatically restored authenticated connectivity after SIGKILL in2.985s with one new generation through guarded sticky recovery; previous refusal remains an older-control result. This is a specific lab result, not a guarantee across OEMs. Force stop,VPN revoke and explicit Disconnect intentionally did not resurrect connectivity in30s controls. If automatic start is absent,check active profile/Always-on and retain ActivityManager/Vpn/VpnSvc logcat and dumpsys activity services; manual Qeli start remains available. Generic/null DNS is a separate open item. [Qualified recovery and limits](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md).

[Audit details](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-SYSTEM.md).


<!-- normative-sync: q29-publication-troubleshooting-v1 -->

### Android: APPLIED / CONNECTED

During Android connection, `Native NetworkPlan APPLIED` means plan application and TUN handoff to the core; system VPN publication may still be pending. Wait for Connected / `Android VPN CONNECTED` before checking traffic. With Block connections without VPN enabled, early sockets during connection may be refused. If a fresh request started after CONNECTED fails, retain its start time and VpnSvc/ConnectivityService logcat: investigate it as a separate failure rather than disabling blocking. Lab samples qualified delivery after CONNECTED, without guaranteeing zero delay for every socket on every device.

[Audit](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).


### Android: recovery after process death

Qeli SIGKILL recovery qualified on the ordinary production R8 APK; disconnect/revoke prevent service resurrection in 30-second windows. Generic/null DnsResolver ENONET on the tested API34 image is accepted as an unfixed limitation; Q29 is closed within the agreed scope. [Details](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md).


<!-- normative-sync: q29-dns-compatibility-troubleshooting-v1 -->

### Android: ENONET in one application

If VPN is already Connected and ordinary DNS works, but one application reports
`DnsResolver` / `resNetworkQuery failed: ENONET`, retain the Android version,
query time and that application's error. On tested Android14/API34, automatic
address-family selection without an explicit network failed before DNS was
sent; a minimal VPN without Qeli reproduced it. This is an observation of one
image, not a general tunnel DNS failure.

To repair that call, the application's developer can pass the VPN Network
explicitly to DnsResolver.query or use A/AAAA queries. These variants and
ordinary DNS have separate positive evidence on the measured image. The
network parameter belongs to the caller application — see the
[Android API contract](https://developer.android.com/reference/android/net/DnsResolver).
Keep system Always-on VPN and Block connections without VPN enabled. Qeli
has no separate mode permitting VPN bypass.

[Facts, reproduction and limits](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).

### Linux: client TUN queue size was not applied

Set `tun.tx_queue_len` in `[qeli]` in the client file, not a new `[tun]` section
or only on the server. A build containing this change uses `1000` packets when
the key is absent for an owned Linux TUN/TAP. Save the INI, stop/start the client
itself and inspect `qlen` using `ip link show dev vpn0` in its namespace.
Use the actual `dev` name; the confirming log line is
`Client TUN TX queue length: <N> packets`. Reloading the server does not change the client queue.

If the key is unknown, check the installed **client binary**: earlier builds
with the same 0.8.2 version number need not contain this change. Updating only
the server does not help. If saving through the panel fails, also check whether
its local editor supports the key. Accepted values are integers `1..32767`;
`0` and `auto` do not enable automatic adjustment. With `dev_attach=true`, remove
the key completely and configure the queue through the external interface owner.

`failed to set client TUN TX queue length` means the kernel setup was refused:
connection setup aborts without silently falling back to the old length. Check
the `ip` tool, process permissions, interface name/ownership and namespace;
do not bypass the error by weakening config validation. A larger queue does not
fix every asymmetry: compare kernel TX drops separately from qdisc/application
drops, along with retransmissions and RTT.
[Full contract](CONFIG.md#client-tun-tx-queue),
[operational verification](OPERATIONS.md#client-tun-tx-queue).
[Report with loss, retransmission and latency measurements](../reports/TUN-QUEUE-SIZE-2026-10-16.md)
and [queue-size recommendations](../reports/TUN-QUEUE-SIZE-2026-10-16.md#choosing-a-size).
