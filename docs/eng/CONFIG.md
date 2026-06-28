# qeli configuration

## Format: flat-INI (the only one; TOML/JSON have been dropped)

Configs are **text flat-INI**. Structure:

- Global sections `[auth]`, `[web]`, `[logging]`.
- One `[profile:<name>]` per interface; nested struct fields are **dotted keys**:
  `bind.port`, `tun.address`, `obf.tls.reality_proxy.enabled`, `perf.connection.max_clients`.
- Users/groups are `[user:<name>]` / `[group:<name>]` sections (inline in the
  server config, or in a separate `auth.users_file` file).
- Repeatable keys: `route = <cidr> gateway=<ip> metric=<n>`, `pool.exclude`,
  `pool.reservation.<user> = <ip>`.
- The client config is a single `[qeli]` section; the same thing is expanded from
  a `qeli://` link (QR import). INI keys ↔ qeli:// query parameters:
  `server`(host:port), `proto`(tcp|udp), `user`, `pass`, `key`(pinning, hex),
  `mode`(plain|fake-tls|obfs|reality-tls), `sni`, `obfs_key`(=`obfs` in the link),
  `reality_sid`(=`rsid` in the link — REALITY short_id for `reality-tls`),
  `front`(websocket|none — anti-FET fronting for obfs, default websocket),
  `quic`(=`quic=1`/`true` — QUIC masking for UDP; **required for a udpquic profile**,
  otherwise the client sends non-QUIC and a server with `obf.quic.enabled` stays silent),
  `dev`(the TUN interface name on the client, default `vpn0` — **only in the INI**, not in the link;
  set your own if `vpn0` is taken by another application or you need to bring up several clients
  on one host; otherwise the client "steals" the existing `vpn0` at start).
  *Note:* `quic`/`front` are parsed by all three clients (Android, Windows, Rust CLI) and emitted by
  the server-side link generators (`qeli add-client`, web `/api/share`).

> **⚠️ Comments — on a separate line only** (a leading `#`). An inline comment
> after a value (`port = 443  # https`) is NOT stripped and will end up in the value.

Fully documented examples — [server.conf](../../qeli/config/server.conf),
[client.conf](../../qeli/config/client.conf), [users.conf](../../qeli/config/users.conf),
[server-maxobf.conf](../../qeli/config/server-maxobf.conf). Default paths:
`/etc/qeli/server.conf`, `/etc/qeli/client.conf`, `/etc/qeli/users.conf`.
Structural saving via the Web UI / control CLI (`PUT /api/config`) rewrites the
config from the serde structs — comments are lost in the process. To preserve
them, use the **raw editor**: `GET /api/config/raw` returns the file verbatim, and
`PUT /api/config/raw` validates via `parse_server_config` and writes the text **as
is** (comments intact); in the Web UI this is the "Raw INI" tab. The exact key map
is `qeli/src/config/server_ini.rs` (the serializer) and the serde structs in
`config/`.



## Profile defaults (the INI applies them per-field — the footgun is gone)

In the INI loader each profile is built from `baseline_profile()` (a skeleton with
applied per-field serde defaults), on top of which the specified keys are layered.
Therefore **omitting whole subsections is safe** — missing keys get their real
defaults (`keepalive_secs=30`, `max_clients=64`, etc.), not zeros.

Historical note (this was relevant for the old TOML/JSON, where omitting an *entire
nested object* yielded `Default::default()` = zeros): omitting `performance` led to —

| Omitted | Effect |
|---|---|
| `performance.tcp.keepalive_secs` → 0 | `setsockopt(TCP_KEEPIDLE, 0)` → **EINVAL**, every TCP connection breaks at setup |
| `performance.connection.handshake_timeout_secs` → 0 | handshake timeout = 0 → instant timeout, no client can connect |
| `performance.connection.max_clients` → 0 | "max clients (0) reached" → everyone refused |

The values depend on the deployment (channel, number of clients, latency), so
**they are not hardcoded** — set them in the config. A minimal working profile:

```ini
[auth]
users_file = /etc/qeli/users.conf

[logging]
level = info
file = /var/log/qeli/server.log

[profile:tcp]
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = vpn0
tun.address = 10.9.0.1
tun.netmask = 255.255.255.0
tun.mtu = 1400
pool.cidr = 10.9.0.0/24
pool.exclude = 10.9.0.1
routing.nat.enabled = true
routing.forward_private = true
dns.enabled = false
obf.mode = fake-tls
obf.padding.enabled = true
obf.padding.min_bytes = 32
obf.padding.max_bytes = 256
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 15000
obf.heartbeat.jitter_ms = 2000
perf.tcp.nodelay = true
perf.tcp.keepalive_secs = 60
perf.tun.read_buffer_size = 65535
perf.connection.max_clients = 128
perf.connection.handshake_timeout_secs = 10
perf.connection.idle_timeout_secs = 300
```

(A full, exhaustively commented example — [server.conf](../../qeli/config/server.conf).)

## Server multi-core (`tun.queues`)

By default the data plane uses **all cores**: per-connection encryption/decryption
is already spread across cores, while **`tun.queues`** (per-profile) sets the number
of TUN queues (Linux `IFF_MULTI_QUEUE`) — how many parallel reader/writer tasks pump
the interface, so that the TUN pump itself (and per-queue encrypt) runs on several
cores rather than through a single funnel.

```ini
[profile:tcp]
tun.queues = 0     # 0 = auto (= number of cores, the default); N = that many queues; 1 = legacy single-threaded pump
```

- `0`/auto = `nproc` (recommended). Capped at 256 (the Linux kernel TUN-queue
  ceiling, `MAX_TAP_QUEUES`) — auto=nproc is not clamped on real servers.
- `1` = the old behavior (a single pump) — for rollback.
- Non-breaking, **server only**: nothing changes on the wire, clients need no
  rebuild (TUN is a local OS-kernel interface). Both **TCP** (N TUN queues) **and
  UDP** (N workers on `SO_REUSEPORT` sockets — the kernel distributes datagrams by
  flow, a client is bound to a single worker) are parallelized. TUN readers are
  blocking (0% CPU when idle).
- The effect grows with the number of cores and clients: a single tunnel is bound
  by its decrypt task (~1 core) regardless of queues — the gain comes from MANY
  connections / a large server. On a 2-core lab it measured **+18% aggregate**
  (2 tunnels: 607→718 Mbps at `queues=1`→`2`; a single tunnel unchanged, 458≈455),
  and that is a lower bound — the host hit saturation (the `iperf3` sink on the same
  server); on larger servers it's more. A detailed A/B with a table —
  [BENCHMARK.md](BENCHMARK.md).

## Tunnel MTU (`tun.mtu`) and the push to the client

The server sets the MTU of its TUN via `tun.mtu` (per-profile, default 1400) **and
pushes this value to the client** at auth. Priority on the client:

1. **an explicit client MTU** (`mtu` in `[qeli]` INI / `qeli://` link / `tun.mtu` in JSON, `> 0`) — wins;
2. otherwise — the **MTU pushed by the server** (its profile's `tun.mtu` value);
3. otherwise (an old server pushing nothing) — a fallback of **1400**.

**`mtu = 0` on the client = "auto" (this is the default)** — the client takes the
server's. So the MTU is usually set **once in the server profile**, and all clients
pick it up themselves — nothing in the client configs/links needs changing
(generated `qeli://` links come with `mtu=0`/without it = auto). An explicit `mtu`
on the client is needed only to forcibly override the server value.

```ini
# server: centrally sets the MTU for all clients of this profile
[profile:reality-tls]
tun.mtu = 1380
```
```ini
# client: override manually (rarely needed); 0/absence = auto/push
[qeli]
mtu = 1280
```

> Note on reality-tls/fake-tls (TCP transport): inner-MTU has little effect on
> throughput (the bottleneck is the outer TCP segment and path), but a correct MTU
> matters against fragmentation and for UDP modes. See the MTU discussion in
> [BENCHMARK.md](BENCHMARK.md).

## Server OS tuning (sysctl + iptables) — MANDATORY for production

These are **server operating-system settings**, not the qeli config. Without them,
TCP modes (reality-tls/fake-tls/obfs-tcp) on real (especially mobile) clients
**break the connection under load and choke the speed**. Apply on every VPN server.

### 1. MSS clamping (CRITICAL — otherwise downloads break)

Traffic from the internet arrives at the client via NAT with an MSS for a 1500-byte
path, but it doesn't fit inside the tunnel (`tun.mtu`, e.g. 1280); if the
"fragmentation needed" ICMP is lost, you get a **PMTU black hole**: large packets
are silently dropped, small ones pass → the download hangs, the client drops on
timeout. The cure is clamping the forwarded TCP's MSS to the tunnel MTU
(`tun.mtu − 40`). Every VPN does this; qeli has no config knob for it — it is set at
the firewall level:

```bash
# MSS = tun.mtu(1280) − 40 = 1240; vpn+ = all profile tun interfaces (vpn0, vpn1, …)
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o vpn+ -j TCPMSS --set-mss 1240
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i vpn+ -j TCPMSS --set-mss 1240
iptables-save > /etc/iptables/rules.v4      # save (netfilter-persistent)
```
> If you change `tun.mtu` — recompute the MSS (`tun.mtu − 40`).

**The outer handshake (reality-tls/fake-tls on LTE) — a separate clamp.** The rule above
is for traffic INSIDE the tunnel (`vpn+`). But reality-tls with `real_tls=true` sends a
**real Chrome ClientHello carrying the post-quantum share (X25519MLKEM768) ~1700 B** over
the **outer** TCP to `:443` — and on that connection the MSS is **not clamped** (the server
advertises ~1460 from the 1500 WAN MTU). On LTE/CGNAT (path MTU ~1400) a 1460-byte segment
doesn't fit, mobile networks drop the ICMP "frag needed" → the same **PMTU black hole**, but
now on the **handshake** itself: works on wired, hangs on LTE. The cure is clamping the MSS
the server advertises on its **outer TCP ports** (reality / fake-tls / obfs):

```bash
# OUTPUT: the server's SYN-ACK on its TCP ports carries the advertised MSS. set-mss 1340 →
# an LTE client sends ≤1340-byte segments (≈1380-byte IP) → fits; harmless on wired. If some
# carriers' path MTU is even lower (~1358), drop to 1300.
for p in 443 8443 8444 8445; do
  iptables -t mangle -A OUTPUT -p tcp --sport $p --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340
done
iptables-save > /etc/iptables/rules.v4
```
> The ports are the `bind.port` of your **TCP** profiles. `tcp_mtu_probing=1` (below) does
> NOT help here: it recovers the *server's* sends, but what hangs is the *client's* send (the
> big ClientHello), whose segment size is governed by the MSS the **server** advertises.

### 2. sysctl: BBR + buffers + MTU probing

cubic (the default) on mobile loss halves the window → speed collapse. **BBR**
holds the bandwidth via a channel model (Google introduced it precisely for slow
TCP over lossy links) — the main win for reality-tls on a phone. Plus large buffers
for the high mobile RTT and MTU probing against residual PMTU black holes.

```ini
# /etc/sysctl.d/99-qeli-perf.conf  (apply: sysctl --system; module: modprobe tcp_bbr)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr     # the main fix for mobile TCP
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 131072 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_mtu_probing=1
```
```bash
modprobe tcp_bbr && echo tcp_bbr > /etc/modules-load.d/qeli-bbr.conf   # load the module at boot
sysctl --system                                                       # apply
sysctl -n net.ipv4.tcp_congestion_control                             # check: should be bbr
```

### 3. padding for reality-tls — better turned off

`obf.padding` (40–400 B per packet) is useless for reality-tls (the traffic is
already inside real TLS — padding isn't visible from outside) but eats bandwidth.
In a reality-tls profile: `obf.padding.enabled = false`.

> Applied in production on YOUR_PROD_HOST: BBR/buffers/mtu_probing + `vpn+` MSS-clamp 1240 +
> `tun.mtu 1280` + padding off (2026-06-08), and the **outer TCP-port MSS** (443/8443/8444/8445)
> **1340** — the reality/fake-tls LTE-handshake fix (2026-06-28). Script: `scripts/prod_tcp_tune.py`.
> Rollback: remove `/etc/sysctl.d/99-qeli-perf.conf` + `/etc/modules-load.d/qeli-bbr.conf`
> (`sysctl --system`), remove the mangle rules, restore `tun.mtu`/padding.

## Stream bonding — multipath (`obf.multipath.*`)

A single TCP connection (reality-tls/fake-tls/obfs) on a mobile network hits the
"TCP over TCP" ceiling (~6 Mbps in production, while UDP/WireGuard does tens).
Multipath opens **several parallel connections to the same :443 port**, and the
server aggregates them into **ONE tunnel** (one tun-IP); outgoing IP packets are
spread round-robin. DPI-clean — a browser also opens 6+ parallel TLS to an HTTPS
host; a single long-lived TCP with a continuous flow is actually more suspicious.

**Settings — per-profile** (like `tun.mtu`/`padding`), the server pushes them to
the client:

```ini
[profile:reality-tls]
obf.multipath.enabled = true       # enable bonding on this profile
obf.multipath.max_streams = 4      # HARD ceiling of streams per session (the server enforces it)
obf.multipath.adaptive = false     # false = open EXACTLY max_streams; true = auto-tune
```

- **`enabled`** (default `false`) — turn bonding on/off for the profile.
- **`max_streams`** (default `4`) — a **hard ceiling** of parallel connections per
  session; the server rejects extras. `max_clients × max_streams` = the server's
  connection budget.
- **`adaptive`** (default `false`):
  - `false` — the client opens **exactly `max_streams`** connections (fixed);
  - `true` — the client **auto-tunes** the count from 1 to `max_streams` by the
    measured speed (starts at 1, adds a stream under load while throughput grows,
    stops at a plateau). In this mode `max_streams` works only as a **ceiling**, not
    a target.

The client may open **fewer** than the ceiling: `streams = N` in `[qeli]`
(0/absence = auto = the server's `max_streams`; in `adaptive` mode it is ignored as
a target).

> **TCP modes only** (reality-tls/fake-tls/obfs/plain) — they have head-of-line
> blocking. UDP profiles (udp-*) don't need bonding (no "TCP over TCP") — leave
> `enabled = false`.
>
> **The profile name is irrelevant** — the behavior is determined by the
> `bind.transport = tcp`, `obf.mode`, and `obf.multipath.enabled` fields, not the
> section name. Any TCP profile with `multipath` enabled bonds (whether
> `[profile:reality-tls]` or `[profile:my-tcp]`), as long as the client is
> configured for its `mode`/port/key.
>
> **Compatible/rollback-safe:** an old client ignores the push and works in 1
> stream; an old server sends no `max_streams` → the client uses 1 stream. Each
> connection does its own key exchange → independent crypto per stream (no
> nonce-reuse).

**Measured (lab, `tc netem`, download, 8 parallel flows).** On a clean link bonding
is at parity (the TUN pump is the ceiling); on a lossy/latent link it scales:

| link | 1 stream | 4 streams | gain |
|---|---:|---:|---:|
| clean | ~725–846 | ~805–815 | parity |
| RTT 40 ms, 0.05% loss | ~225–420 | ~692–704 | ~1.6–3× |
| RTT 80 ms, 0.1% loss | ~50–65 | ~260–305 | **~5×** |

Note the distribution is **per-flow** — each inner flow is pinned to one connection
by a flow hash (`flow_hash % streams`) to avoid reordering (which only hurts the
inner TCP). So only traffic with **several concurrent connections** (like a browser's
6+ TLS) speeds up; a single lone flow won't.

## Flow shaping — cover traffic (`obf.traffic_shaping.*`)

Closes DPI tells **6.1** (flow shape = "download", not "browsing") and **6.2**
(periodic heartbeat beacon). While the tunnel is **idle**, the server emits cover
packets at gaps sampled **exponentially** (a Poisson process) instead of a fixed
heartbeat — no dead air, no metronome. A cover packet is an encrypted record with
an **empty payload**; the peer drops it (like a heartbeat) → **not wire-breaking**,
old clients stay compatible. Real packets are **never delayed** (Phase 1 = zero
added latency); only idle is filled, within a byte budget. When shaping is on it
**replaces** the heartbeat (which is disabled, so there is no double beacon).

```ini
obf.traffic_shaping.enabled = true            # on (default false)
obf.traffic_shaping.idle_gap_mean_ms = 700    # mean idle gap between cover packets (exponential)
obf.traffic_shaping.idle_gap_min_ms = 40      # gap floor
obf.traffic_shaping.idle_gap_max_ms = 6000    # gap cap (don't go dead on a long tail)
obf.traffic_shaping.budget_bytes_per_sec = 16384  # cover-traffic ceiling, B/s (0 = none)
obf.traffic_shaping.min_size = 64             # cover packet size range
obf.traffic_shaping.max_size = 1024
# STEALTH (Phase 2): trade throughput for DPI passability.
obf.traffic_shaping.stealth = false
obf.traffic_shaping.stealth_rate_mbps = 2     # data-plane rate cap under stealth (Mbps)
```

- **Cost (without stealth)** — only cover-traffic bandwidth while idle (capped by
  `budget_bytes_per_sec`); no effect on real throughput.
- **When to enable** — on profiles facing heavy DPI / an ML classifier; overkill for
  home use. Parameters are pushed to the client (like padding/heartbeat).

### `stealth` (Phase 2, opt-in — speed for passability)

Closes the under-load **"download" tell** (baseline: 100% full-MTU packets at line
rate). With `stealth = true` (requires `enabled = true`):
1. **Rate-cap** the data plane to `stealth_rate_mbps` (both directions) → the flow
   stops looking like a line-rate bulk download.
2. **Cover under load** — the rate-cap gaps are filled with jittered small cover
   packets → breaks the "100% full-MTU" size signature and makes the timing bursty
   (not a metronome).

**What it buys** (measured with `scripts/shaping_profile.py`, server→client under bulk):

| Feature | Without stealth | With stealth |
|---|---|---|
| Throughput | ~600 Mbps (line rate) | ≈ `stealth_rate_mbps` |
| Packet sizes | **100% full-MTU** | **~81% full-MTU + ~19% small/medium** (a mix) |
| Timing (inter-packet CV) | low/flat (constant stream) | **bursty (CV≈1.0)** — bursts + gaps, not a metronome |

Net: the flow no longer reads as a high-rate bulk download. This is **not**
"indistinguishable from browsing" (that would need seconds-scale buffering, making
the tunnel unusable) — it is "no longer a file download."

#### Why it cuts speed so much — this is the mechanism, not a bug

The strongest, most robust tunnel signal for DPI/ML is **the sustained high rate
itself**: hundreds of Mbps of continuous full-MTU traffic at a ~constant pace looks
like no "normal" traffic (web, chat). So stealth **hard-caps the data plane to
`stealth_rate_mbps`** — that is not a side effect, it is the point: **you cannot both
push 600 Mbps and not look like a 600 Mbps download.** Browsing / normal activity is
a few Mbps in bursts, not a constant line-rate. So throughput under stealth ≈
`stealth_rate_mbps` (measured: tcp-plain/faketls/obfs/reality-tls 442–602 Mbps →
~10/10 at cap=10).

`stealth_rate_mbps` is the **direct speed↔stealth knob**: higher = faster but closer
to the bulk signature; lower = slower but stealthier. On top of the cap, the gaps are
filled with small cover (extra bandwidth, but the *real data* is what the rate-cap
throttles). It does NOT change the *data* packets' own size (still full-MTU, just
rarer + interleaved with cover) — that needs fragmentation+reassembly (wire-breaking,
not implemented). Per-mode speeds: `scripts/bench_stealth.py`.

**When to enable:** only under aggressive DPI/ML that blocks high-rate tunnels. For
normal use it is overkill (needlessly slow). **Not wire-breaking** (cover = the same
empty records peers already drop). The server shapes the downlink for ALL clients;
every client (Rust, Windows/macOS, Android) shapes its own uplink (TCP only).

> **TCP wire modes only** (plain/fake-tls/obfs/reality-tls). On UDP, stealth was
> measured to crater throughput (lock contention under load → ~0), so it is
> **ignored on UDP profiles** — they keep Phase-1 idle cover. The main "download"
> case (reality-tls/fake-tls/obfs) is TCP anyway.

## Wire obfuscation modes (`obfuscation.mode`)

`mode` selects how a connection looks "on the wire"; it is set **identically on the
server (in the profile) and on the client**. The modes
`plain`/`obfs`/`reality`/`reality-tls` are **TCP only** (stream-based); on UDP the
wire mode is `fake-tls` (+ optional QUIC masking), the rest are rejected on UDP at
startup.

| `mode` | Behavior | Against what | Notes |
|---|---|---|---|
| `"plain"` | No obfuscation: a raw X25519 key exchange and bare `[len][nonce][ct]` records (no TLS mimicry). An ordinary encrypted VPN tunnel | Nothing — on the wire a high-entropy flow with no recognizable protocol (which is itself a signal for entropy-based DPI) | The cheapest, speed ≈ fake-tls. **TCP only.** For trusted networks where DPI doesn't matter |
| `"fake-tls"` (default) | A pseudo-TLS-1.3 handshake (ClientHello with GREASE and a random extension order → JA3 changes), then the data plane in TLS-Application-Data records | Passive signature-based DPI | Cheaper on CPU; "looks like TLS" |
| `"obfs"` | The entire flow is XOR'd with a ChaCha20 stream key; the start of the connection is by default masked as a WebSocket Upgrade handshake (see `obfs_fronting`), then pseudo-random bytes | DPI that signatures *known* protocols (incl. fake-TLS/JA3) + entropy-based "fully encrypted" detection (GFW/TSPU) | Requires `obfs_key` (PSK) shared by server and client. ~11% overhead (double encryption) |
| `"reality-tls"` | The client sends a **real** browser TLS 1.3 ClientHello (Chrome JA4) with a REALITY token in `session_id`; the server terminates real TLS (rustls) and carries the tunnel inside. "Foreign" connections are proxied to a real site | Active probing + JA3/JA4 + entropy-based DPI (real TLS on the wire) | The client needs `key`(pin) + `reality_sid`; the server needs `reality_proxy.real_tls=true` + `short_ids`. ↓ Lower speed (nested TLS). **TCP only.** See the REALITY section below |

> **How to choose a mode (positioning).** The `fake-tls` default targets
> **passive** DPI (D1/D2) and is cheap on CPU. If your threat model includes
> **active probing** (D3 — the censor reaches the server itself: GFW, a number of
> ISPs) — enable **`reality-tls`** explicitly (it is not the default, since it costs
> more CPU and is slower due to the nested TLS, but it is the only mode
> indistinguishable from real HTTPS and serving the prober a real site). `obfs` —
> against entropy-based "fully-encrypted" detection (without mimicking a specific
> protocol). `plain` — trusted networks only (the most visible on the wire). A
> detailed detectability model — [DPI-AUDIT.md](DPI-AUDIT.md).

### `obfs_fronting` (anti-FET, only for `mode = obfs`)

The key `obf.obfs_fronting` (server) / `front` in the qeli:// link and the `[qeli]`
section (client). **Must match on server and client.**

| Value | Behavior |
|---|---|
| `"websocket"` (default) | Before the nonce exchange the client sends `GET … Upgrade: websocket`, the server sends `101 Switching Protocols` (with a correct `Sec-WebSocket-Accept`). The first packet is printable HTTP text → it passes the GFW/TSPU "fully encrypted traffic" entropy heuristics. The request is randomized (path/Host/key) — no static signature |
| `"none"` | Legacy: an immediate random nonce prologue. "Looks like nothing" — blocked by entropy-based DPI. For rollback only |

An `obfs` example (fragments):

```ini
# server.conf — in the [profile:obfs] profile:
obf.mode = obfs
obf.obfs_key = SHARED-SECRET
obf.obfs_fronting = websocket
```
```ini
# client.conf — the [qeli] section:
mode = obfs
obfs_key = SHARED-SECRET
front = websocket
```

`obfs` limitation: the IETF-ChaCha20 keystream = 256 GiB per direction per session.
On exceeding it the connection ends with an error and reconnects with a fresh nonce
(fail-safe, no keystream reuse). For very high-volume long-lived links this means a
reconnect roughly every 256 GiB.

UDP obfuscation is a separate mechanism (`obfuscation.quic`, masking as QUIC);
`mode: "obfs"` applies only to TCP profiles.

### REALITY (`mode = reality-tls`, keys `obf.tls.reality_proxy.*`)

"REALITY" in qeli has two layers, both in the server profile:

| key (server) | value |
|---|---|
| `obf.tls.reality_proxy.enabled` | enable REALITY handling of incoming connections |
| `obf.tls.reality_proxy.target` / `target_port` | the real site to which "non-ours"/probing connections are transparently proxied (e.g. `www.microsoft.com:443`) |
| `obf.tls.reality_proxy.short_ids` | allow-list of 8-byte (16 hex) "our" IDs — the cryptographic discriminator (a token in `session_id`). **Required when `reality_proxy.enabled`**: with an empty list the server refuses to start. (An empty list used to fall back to a legacy "no ALPN" heuristic; it is trivially defeated by an active prober, so it is now rejected at startup.) |
| `obf.tls.reality_proxy.real_tls` | `true` → the server terminates **real** TLS 1.3, the tunnel inside (client mode `reality-tls`); `false` → fake-TLS on the wire, REALITY only the bridge/token |
| `obf.tls.reality_proxy.handrolled` | `true` → the hand-rolled TLS terminator: **borrows the target's real cert chain** (cert-borrowing — at profile start a probe captures the real cert, e.g. microsoft; **auto-refresh every 12h**, target certs rotate) + mirrors its JA3S/ServerHello. `false` (default) → rustls: a **self-signed** cert + its own JA3S. **Parity with Xray-REALITY needs `true`** (requires `real_tls=true`) |

- **proxy-bridge (`real_tls=false`):** the client sends `mode=fake-tls`; fake-TLS on
  the wire, but "foreign" handshakes go to `target` (an active prober sees the real
  site). Speed ≈ `plain`.
- **`reality-tls` (`real_tls=true`):** the client sends `mode=reality-tls` + a
  **mandatory** `key` (the pin of the profile's static key, from `show-identity`) +
  `reality_sid` (one of `short_ids`). On the wire — real Chrome TLS 1.3, the tunnel
  inside; it closes tells 1.1–1.6 ([DPI-AUDIT.md](DPI-AUDIT.md)). ↓ Lower speed
  (nested TLS — see [BENCHMARK.md](BENCHMARK.md)). Distributed via a QR link (`rsid=`
  carries the short_id). Config templates — [release/reality-tls/](../../release/reality-tls/).
- **Client and server clocks must agree within ±120 seconds** (when `short_ids` is
  set): the REALITY token in `session_id` carries a timestamp (anti-replay,
  `REALITY_WINDOW_SECS = 120`), and a larger skew makes the server **silently**
  bridge the client to `target` — like any "foreign" connection. Symptom: the
  connection never establishes with no error in the client log, while `curl` against
  the server shows the real site. Fix: enable automatic time sync (NTP) — most often
  the clock drifts on Android without auto-time and in VMs after suspend.

## Server identity (per-profile)

**Each profile has its own** long-term static key (X25519) — it is bound to the
profile's interface. The private keys live in `/etc/qeli/identity/<profile>.key`
(permissions `0600`, directory `0700`); the path can be overridden with the profile
field `identity_key`. The public key is derived from the private one, and the
client pins it.

On the profile's first start the key is generated automatically (if the file is
absent) and saved. Logged:
`Profile '<name>': server identity public key (pin on client): <hex>`.

CLI for key management (without starting the server, root required):

```bash
# show the public keys of all profiles (creates missing ones)
qeli show-identity --config /etc/qeli/server.conf
# PROFILE   BIND                 SERVER PUBLIC KEY (pin on client)
# tcp       tcp://0.0.0.0:443    33f399e6…d532450
# udp       udp://0.0.0.0:4443   35d12dd2…7d764e04
# obfs      tcp://0.0.0.0:8443   26c45f81…9dbca952

# rotate one profile's key (then restart qeli)
qeli rotate-identity udp --config /etc/qeli/server.conf
```

### How to deliver the key to the client (pinning)
The profile's public key (hex from `show-identity`) is entered into the **client**
config:

```ini
# client.conf — a client connecting to the tcp profile; the [qeli] section:
user = alice
pass = secret
key = 33f399e6…d532450
```

Delivery is **out-of-band** (copy the hex: the `show-identity` output, a secure
channel, a QR, etc.). The client checks the key received from the server against the
pinned one; on a mismatch — a `SERVER KEY MISMATCH` error (anti-MITM). If the field
is unset — TOFU: the client connects and prints the candidate key to the log
(without protection against substitution). The client pins the key **of the
profile** it connects to (by port).

After `rotate-identity` the public key changes → all clients of that profile must
receive the new hex (otherwise `SERVER KEY MISMATCH`).

### Mandatory pinning — `auth.require_client_key_proof`
By default a client without a pin (`key` in `[qeli]`) connects in TOFU mode (without
MITM protection). To **forbid** connections from clients that have not pinned the
key:
```ini
# server.conf — the [auth] section:
require_client_key_proof = true
```
Then the client must prove knowledge of the server static key: it computes a proof
from the **pinned** key (`key` in `[qeli]`), and the server verifies it with its
private key. A client without the key (or with a wrong one) is rejected
(`AUTH DENIED … server key not pinned by client`). Works on TCP and UDP.

The order (by design, safe): the client first **authenticates the server** (checks
the static key against the pinned one) and only then sends the login/password —
otherwise a MITM could intercept the credentials. So "sending the key after
authorization" is not possible. The static key itself is public; its "leak" to a
scanner gives only a fingerprint.

### H-1 — binding keys to the server identity (`auth.bind_static_to_session`)
**On by default since 0.7.1.** A Noise-IK-style hardening: the session-key KDF also
folds in `es = X25519(client_eph, server_static)`, so a failed ephemeral RNG alone is
no longer enough to expose the tunnel — the attacker also needs the server's private
static key.
```ini
# server.conf — the [auth] section (default true):
bind_static_to_session = true
# client — the [qeli] section (default true; requires a real pinned `key`):
bind_static = true
```
**WIRE-BREAKING**: a server with H-1 only admits clients that also run H-1 and have
pinned the key — enable it in lockstep on the server and all clients. The client
**must** pin the key (`key`); an unpinned / TOFU client (all-zero `key`) must set
`bind_static = false` explicitly, otherwise the connection fails with a clear error.
To interoperate with a legacy 0.7.0 fleet during a staged upgrade, set `false` on both
sides. A separate HKDF salt rules out silent bound↔unbound interop: a flag mismatch
yields different keys and an honest failure, not a silent downgrade. Details —
[AUDIT-2026-06-12.md](AUDIT-2026-06-12.md).

## Per-profile user authorization (interface isolation)

In `users.conf` (or an inline `[user:<name>]` section in server.conf) a user has a
`profiles` key — a list of profiles (interfaces) they are allowed to connect to:

```ini
[user:alice]
password_hash = $argon2id$...
profiles = tcp
```

- **empty** (key absent) → **all** profiles allowed (backward compatibility);
- **non-empty** → only those listed (comma-separated). A user with `profiles = tcp`
  connecting to `udp` is refused with `AUTH DENIED … not permitted on profile 'udp'`
  even with the correct password. This isolates interfaces: access to one does not
  grant access to another.

The check runs after password verification, on both TCP and UDP.

## Connection limits (`max_clients` vs `max_sessions`)

Two independent limits — do NOT confuse them:

| Key | Where | Counts | What it does on reaching it |
|---|---|---|---|
| `perf.connection.max_clients` | `[profile:<name>]` | **all** profile sessions (all users together) | a new AUTH is rejected (`max clients … reached`) |
| `max_sessions` | `[user:<name>]` / `[group:<name>]` | **one user's devices** | the user's oldest device is evicted (newest wins) |

### `max_sessions` — a per-user device limit

Each client carries a stable **device-id** (random 16 bytes, stored on the device;
see multi-device in [ROADMAP](ROADMAP.md)), and the server keys sessions/IP pool by
`username:hex(device_id)`. Therefore:

- **Several devices on one login coexist**, each with its own tun-IP — but no more
  than `max_sessions`.
- **A reconnect of the same device does NOT spend a slot**: it evicts its own
  previous session (the same device-id), the counter doesn't grow. A Wi-Fi↔LTE
  network switch is a reconnect of the same device, the limit is untouched.
- **On reaching the limit, a new device evicts the oldest** device of that user (by
  connection time) — "newest wins", a new device always connects.

**Value resolution** (`effective_max_sessions`): the value in `[user:]` (if `> 0`) →
otherwise from its `[group:]` → otherwise **`0` = no limit**. Enforced identically
on TCP and UDP.

```ini
# users.conf (or inline in server.conf)
[user:alice]
password_hash = $argon2id$...
max_sessions = 2          # alice: at most 2 devices at once

[user:bob]
password_hash = $argon2id$...
group = premium           # bob takes the limit from the group (max_sessions unset = 0)

[group:premium]
max_sessions = 5          # default for group members without their own max_sessions
```

It can be set by editing `users.conf` (then restart/reload) or via the web UI
(Users page → "Max simultaneous sessions", `0` = from the group). Old clients
without a device-id (if any exist) count as one key = username → one "device" per
login.

> Backward compatibility: `max_sessions = 0` (default) = unlimited = the previous
> behavior. The profile's `max_clients` always applies on top — a user cannot exceed
> the profile capacity even if their `max_sessions` is larger.

## Client: credentials, routing, reconnect

**Client credentials** — in the `[qeli]` section:
```ini
# client.conf
user = alice
pass = secret
```
In flat-INI the password is set only with the `pass` key (the INI client has no
password_file/command variants). On the **server**, users can be kept inline — as
`[user:<name>]` sections right in server.conf (with Argon2 hashes); if present, they
are used instead of `auth.users_file`:
```ini
# server.conf:
[user:alice]
password_hash = $argon2id$...
profiles = tcp
```

**Routing is predominantly server-side.** The flat-INI client (`[qeli]`) is
deliberately minimal: routes/DNS/MTU come from the server at the handshake. The
server distributes routes with the repeatable `route` key in the profile (or
individually per user — the same `route` key in `[user:<name>]`, which overrides the
global ones); the client applies them to the tun automatically:
```ini
# server.conf, in the [profile:tcp] profile:
route = 192.168.50.0/24 gateway=10.0.0.1 metric=50
```
Verified: the client gets `192.168.50.0/24 via <tun_gw> dev <tun>` in the table.

Client-side routing keys in flat-INI (`[qeli]`, file-only — not carried in a
`qeli://` link; all default `false`):

| Key | Purpose |
|---|---|
| `route_local` | route RFC1918 + the server-distributed local subnets into the tunnel |
| `gateway` | full-tunnel: all client traffic into the VPN (default route via tun) |
| `kill_switch` | firewall kill-switch (Linux/iptables, full-tunnel only): while the tunnel is down, block all egress except loopback/tun/DHCP/server IP, so a drop can't leak onto the physical interface |

**Auto-reconnect** is on by default (there are no separate keys in flat-INI `[qeli]`
— the defaults apply: exponential backoff, cap 60s, infinite retries). A client left
on while the server is unreachable (even a day+) keeps retrying and **reconnects as
soon as the server returns**.

A dead server on an idle tunnel is detected via **RX-liveness**: if no data arrives
from the server for longer than `rx_dead = max(3 × heartbeat_interval, 30s)`, the
client drops the link and reconnects (log: `no data from server for >Ns — reconnecting`).
The threshold is **not a separate key** — it is derived from `obf.heartbeat.interval_ms`
(pushed by the server; default 15s → `max(45s, 30s)` = **45s**, hence the `>45s` in the
log). The 30s floor suppresses false trips from UDP loss, and the 3× multiplier rides
out a couple of dropped heartbeats. To change it, edit `obf.heartbeat.interval_ms` in
the server profile.

> Detection is active only while heartbeat (or traffic-shaping cover) is on: the code
> guards on `heartbeat_enabled || shaping_on`. With `obf.heartbeat.enabled = false`
> there is nothing to refresh `last_rx`, so a dead server on an idle link is **not**
> detected — which is why heartbeat is best left on for UDP.

## Authentication: tokens and anti-brute-force (`[auth]`)

Beyond pinning / H-1 (above), the `[auth]` section carries:

| Key | Default | Purpose |
|---|---|---|
| `users_file` | `/etc/qeli/users.conf` | path to the standalone user database (when there are no inline `[user:*]`) |
| `password_hash` | `argon2id` | password hashing scheme (only argon2id is supported) |
| `token_ttl_secs` | `86400` | auth/session token lifetime (seconds) |
| `brute_force.max_attempts` | `5` | failed-attempt threshold before lockout (per source IP) |
| `brute_force.window_secs` | `300` | window for counting failures (seconds) |
| `brute_force.lockout_secs` | `900` | lockout duration after the threshold is exceeded (seconds) |

The lockout is **per source IP**; a username under attack gets an adaptive tarpit
(slowdown) instead of a hard lock, so a correct password always passes and a
username cannot be locked by guessing it ([L1](AUDIT-2026-06-11.md)).

## Obfuscation: handshake shaping and anti-fingerprinting

Fine-tuning of how a profile looks **on the wire**, on top of the chosen `obf.mode`.
All keys are per-profile; the defaults below are the serde defaults (in the example
[server.conf](../../qeli/config/server.conf) some are shown with illustrative,
**non-default** values — rely on the tables here).

> **How the client chooses its SNI.** Priority: a configured/link `sni` wins; else,
> when dialing a bare IP, a random decoy from the built-in pool (per connection); else
> the connect hostname. So **fake-tls** SNI rotation is a *client* setting — leave `sni`
> empty and connect by IP to rotate. Adding more `server_names` on the *server* does
> nothing on the wire. For **reality / reality-tls** the client SNI must equal the one
> mimicked `reality_proxy.target`; to offer several front domains, run several
> reality-tls profiles, each with its own target and matching client links.

**AEAD and the fake-TLS ClientHello:**

| Key | Default | Purpose |
|---|---|---|
| `obf.cipher` | `chacha20-poly1305` | data-plane cipher: `chacha20-poly1305` \| `aes-256-gcm` \| `aes-128-gcm` |
| `obf.tls.server_name` | `www.cloudflare.com` | SNI baked into a generated share link. **fake-tls:** cosmetic (the server ignores the client's SNI). **reality / reality-tls:** must equal `reality_proxy.target`. |
| `obf.tls.server_names` | cloudflare/google/microsoft/apple/amazon | the client's built-in decoy pool (used when its `sni` is empty *and* it dials a bare IP). Server-side this list is **not** validated on the inbound qeli path and **not** pushed to clients. |
| `obf.tls.session_id` | `true` | put a (REALITY) token in the `session_id` |
| `obf.tls.supported_groups` | `x25519, secp256r1` | named groups in the ClientHello (fingerprint shaping) |
| `obf.tls.key_share_entropy_bytes` | `32` | key_share entropy size |

**Padding / Fragmentation / Heartbeat** (all three **enabled** by default):

| Key | Default | Purpose |
|---|---|---|
| `obf.padding.enabled` | `true` | pad packets with random bytes |
| `obf.padding.min_bytes` / `max_bytes` | `32` / `512` | padding range |
| `obf.padding.randomize` | `true` | random length within the range |
| `obf.padding.probability` | `1.0` | fraction of packets padded (0.0–1.0) |
| `obf.fragmentation.enabled` | `true` | split records into chunks |
| `obf.fragmentation.min_chunk_size` / `max_chunk_size` | `64` / `512` | chunk size |
| `obf.fragmentation.max_fragments_per_packet` | `16` | max fragments per packet |
| `obf.heartbeat.enabled` | `true` | background cover traffic (keepalive) |
| `obf.heartbeat.interval_ms` | `15000` | interval |
| `obf.heartbeat.data_size_bytes` | `16` | payload size |
| `obf.heartbeat.jitter_ms` | `20` | interval jitter |

> For `reality-tls` padding is pointless (traffic is already inside real TLS) —
> turn it off (`obf.padding.enabled = false`), see the "Server OS tuning" section.

**Extra masking (disabled by default):**

| Key | Default | Purpose |
|---|---|---|
| `obf.http2_masking.enabled` / `.ratio` | `false` / `0.1` | mix in HTTP/2 frames; ratio |
| `obf.traffic_normalization.enabled` | `false` | pad records up to fixed "round" sizes (flattens the length histogram) |
| `obf.traffic_normalization.round_sizes` | `64,128,256,512,1024,1500` | target sizes |
| `obf.traffic_normalization.randomize_sequence` | `false` | randomize the order |
| `obf.anti_fingerprinting.enabled` | `false` | cipher rotation + handshake jitter |
| `obf.anti_fingerprinting.rotate_ciphers_every` | `300` | rotation period (seconds) |
| `obf.anti_fingerprinting.add_jitter_to_handshake` | `true` | handshake jitter |
| `obf.quic.enabled` | `false` | QUIC masking (**udp profiles only**) |
| `obf.quic.cid_length` | `4` | QUIC connection-id length |
| `obf.quic.version` | `1` | QUIC version |

## Built-in DNS resolver (`dns.*`)

An optional in-tunnel DNS proxy: the server hands clients its own resolver and
(optionally) filters domains. Disabled (default) — clients keep their own resolvers
and the server pushes no DNS. Per-profile.

| Key | Default | Purpose |
|---|---|---|
| `dns.enabled` | `false` | enable the in-tunnel DNS proxy |
| `dns.listen` | `10.0.0.1` | listen address (usually the tun IP) |
| `dns.port` | `53` | port |
| `dns.upstream` | `1.1.1.1, 8.8.8.8` | upstream resolvers (comma-separated) |
| `dns.upstream_protocol` | `udp` | `udp` \| `tcp` \| `tls` (DoT) |
| `dns.cache_size` | `1000` | record cache size |
| `dns.timeout_secs` | `5` | upstream timeout (seconds) |
| `dns.blocklist` | `[]` | domains answered with `0.0.0.0` (ad/tracker blocking) |

## DHCP server (`dhcp.*`)

An optional DHCP server on the profile's interface (for TAP/L2 setups; most
deployments don't need it — IPs are handed out in AUTH). Disabled by default.
Per-profile.

| Key | Default | Purpose |
|---|---|---|
| `dhcp.enabled` | `false` | enable the DHCP server |
| `dhcp.listen` | `0.0.0.0:67` | listen address:port |
| `dhcp.pool_start` / `pool_end` | (none) | lease range (optional; else from `pool.cidr`) |
| `dhcp.lease_time_secs` | `86400` | lease time |
| `dhcp.domain_name` | `vpn` | domain name advertised to clients |

## Performance tuning (`perf.*`, `tun.tx_queue_len`)

All per-profile. Values depend on the link/load — see the general note in "Profile
defaults".

| Key | Default | Purpose |
|---|---|---|
| `tun.tx_queue_len` | `1000` | TX queue length of the TUN device |
| `perf.tcp.nodelay` | `true` | `TCP_NODELAY` (disable Nagle) |
| `perf.tcp.keepalive_secs` | `60` | TCP keepalive |
| `perf.tcp.send_buffer_size` / `recv_buffer_size` | `262144` | socket buffer sizes |
| `perf.tun.read_buffer_size` / `write_buffer_size` | `65535` | TUN-pump buffers |
| `perf.tun.read_timeout_ms` | `10` | TUN read timeout |
| `perf.tun.max_pending_packets` | `256` | packet-queue ceiling |
| `perf.connection.max_clients` | `128` | total sessions per profile (all users; see "Connection limits") |
| `perf.connection.handshake_timeout_secs` | `10` | handshake timeout |
| `perf.connection.idle_timeout_secs` | `300` | idle timeout (`0` = never idle-drop) |
| `perf.connection.rate_limit_packets_per_sec` | `10000` | packets/sec ceiling per connection |
| `perf.connection.new_session_rate_max` | `10` | max new sessions from one source IP per window |
| `perf.connection.new_session_rate_window_secs` | `60` | window for `new_session_rate_max` (seconds) |

## Routing and other per-profile keys

Server-side routing for the profile (client-side routing keys are in the "Client" section):

| Key | Default | Purpose |
|---|---|---|
| `routing.client_to_client` | `false` | allow client↔client traffic within the tunnel subnet |
| `routing.forward_private` | `true` | forward private (RFC1918) networks behind the server to clients |
| `routing.nat.enabled` | `false` | MASQUERADE client traffic to the internet (full-tunnel gateway) |
| `routing.nat.interface` | `eth0` | NAT egress interface (auto-detected when left at default) |
| `route` | — | repeatable: a route advertised to clients, `<cidr> [gateway=<ip>] [metric=<n>]` |
| `tun.device_type` | `tun` | interface type: `tun` (L3) \| `tap` (L2) |
| `pool.lease_time_secs` | `3600` | IP-pool lease time (seconds) |
| `obf.tls.reality_proxy.peek_timeout_ms` | `1500` | how many ms to peek the ClientHello before classifying peer as client vs probe |

## Web panel (`[web]`)

The built-in admin UI (profiles, users, clients, identity, link/QR issuance).
Full install & usage guide — [PANEL.md](PANEL.md). Section keys:

```ini
[web]
enabled = true                # enable the panel
bind = 0.0.0.0                # address (public IP, or 127.0.0.1 behind an SSH tunnel)
port = 8080
username = admin
password_hash = $argon2id$... # argon2id hash (NOT the plaintext)
tls = true                    # native HTTPS (rustls); empty cert/key = self-signed auto
tls_cert =                    # (opt.) your PEM cert; empty = self-signed
tls_key =                     # (opt.) your PEM key
allowed_ips = 203.0.113.4, 10.0.0.0/8   # (opt.) source-IP/CIDR allowlist; empty = any
public_host = vpn.example.com           # (opt.) default host for share links
allowed_origins = panel.example.com     # (opt.) extra CSRF origins (domain / reverse proxy)
secure_cookie = false         # Secure on the cookie (auto=true under tls; manual behind a TLS proxy)
```

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `false` | enable the web panel |
| `bind` | `127.0.0.1` | listen interface (a public IP for public access) |
| `port` | `8080` | panel HTTP/HTTPS port |
| `username` | `admin` | admin login |
| `password_hash` | `""` | argon2id password hash. **Required on a non-loopback bind** (fail-closed) |
| `tls` | `false` | serve HTTPS directly (rustls/`ring`). Auto `Secure` cookie |
| `tls_cert` / `tls_key` | `""` | PEM cert/key; empty = self-signed (`/etc/qeli/web-tls-*.pem`, SAN=bind+localhost) |
| `allowed_ips` | `[]` | source-IP/CIDR allowlist; empty = no restriction |
| `public_host` | `""` | default public host for `qeli://` links (editable in the Share dialog); also accepted as a CSRF origin |
| `allowed_origins` | `[]` | extra browser origins (`host[:port]`) accepted by the CSRF check when the panel is reached via a domain / reverse proxy; otherwise a public panel loads but every save returns 403 |
| `secure_cookie` | `false` | add `Secure` to the session cookie |

- **Fail-closed:** with a non-loopback `bind` and an empty `password_hash` the
  panel **refuses to start** (the VPN is unaffected). Set a password (Config → Web
  → Set admin password, the `argon2` CLI, or `/api/hash-password`).
- **Self-signed TLS** is generated on first start and persists across restarts;
  browsers warn once. For a clean cert set `tls_cert`/`tls_key`.
- **User password storage:** besides the argon2 hash the panel keeps a reversibly-
  encrypted copy (`password_enc`, key `/etc/qeli/panel-secret.key`) so a config can
  be re-issued without typing the password. Never returned over the API. Details &
  trade-off — [PANEL.md](PANEL.md#3-password-storage-model--trade-off).

## Logging

The `[logging]` section (in server.conf and client.conf):

```ini
[logging]
# error | warn | info | debug | trace  (RUST_LOG overrides)
level = info
# if set — logs are written to a file (the directory is created);
# if omitted — stderr (under systemd this goes to journald)
file = /var/log/qeli/server.log
# plain | json — log line format (default plain)
format = plain
```

At the `info` level the log records all key events: profile and listener
start/stop, connection establishment (`New TCP connection`,
`Client … connected … IP …`), authentication (`AUTH attempt/OK/FAIL/BLOCKED`,
including brute-force lockouts), connection teardown (`Client … disconnected`),
administrative commands via the control socket (`CONTROL action=… user=…` —
kick/disable/enable/set-bandwidth), SIGHUP reload. Data-plane-side teardown reasons
are written at the `debug` level.

For diagnostics, `level: "info"` with a set `file` is the minimum sufficient.
```
