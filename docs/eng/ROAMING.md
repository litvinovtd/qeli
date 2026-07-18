# Client roaming (seamless network change) — implementation plan

Status: **PLANNED for 0.8.0. Not started.** This is a working design; line numbers
point at 0.7.2 code.

Goal: when the client's IP/interface changes (Wi-Fi↔LTE, cell handover, new DHCP
lease) the **user's connections do not drop**. The real traffic rides on the tun-IP,
which is preserved, so the inner flows are insulated from the outer-path change — the
job is to keep the **outer** tunnel alive (or rebuild it instantly) without losing
the session or paying Argon2 again.

## 0. Seamlessness per transport

| Transport | Achievable | How |
|---|---|---|
| **UDP + QUIC masking** | Fully seamless (connection migration) | The CID is already on the wire; the server migrates the peer-addr on an authenticated packet |
| **TCP** (reality-tls / fake-tls / obfs / plain) | Seamless with make-before-break; otherwise a short gap | Multipath JOIN over the new network *before* the old dies; fallback — grace + JOIN-resume |
| **UDP plain** (no quic) | Out of scope | No on-wire identifier → roaming requires `quic=1` |

**Non-goals:** zero byte loss on a hard handover where only one network is alive at
the moment of transition (inner-TCP retransmit covers it); MPTCP; buffering +
re-encrypting un-flown downstream packets (not worth the complexity).

## 1. Current behavior (0.7.2)

A network change today = **fast reconnect, not roaming**: the client detects the
change (Android — `registerDefaultNetworkCallback` → `forceReconnect`), does a **full
new handshake** (ephemeral X25519+ML-KEM + a fresh Argon2 login); the server
supersedes its own previous session by **device-id** and hands back the same tun-IP
(the pool is sticky by `device_key`) and routes. Result — a ~(RTT + Argon2 time) dip
and packet loss in the window. Roaming removes that hiccup.

## 2. Protocol / wire design

### 2.1 UDP connection-id (CID) — demux by packet content

Today: the client picks **its own stable 4-byte CID** once
([client/mod.rs:1678](../../qeli/src/client/mod.rs#L1678)) and puts it on every upstream
packet; the server **extracts and discards** that CID (`_connection_id`,
[udp_handler.rs:328](../../qeli/src/server/udp_handler.rs#L328)) and demuxes sessions by the
source `SocketAddr` ([:117](../../qeli/src/server/udp_handler.rs#L117) /
[:342](../../qeli/src/server/udp_handler.rs#L342)). An address change → map miss → treated as a
new client → full handshake.

Change: the server **records the client CID** at handshake and can find the session by
CID when the source address is unknown. The CID lives in the QUIC short header **in the
clear** (it must — the server has to identify the session **before** decrypting, to
pick the key).

### 2.2 CID rotation (unlinkability) — mandatory

A constant cleartext CID that survives a network change is a **correlation tell**: a
passive observer links your Wi-Fi to your LTE. So the CID **rotates**, as in QUIC.
Adopted design — **deterministic rotation (Design B):**

```
roam_cid(n) = HKDF-Expand(session_secret, "qeli-roam-cid" ‖ LE32(n))[..8]
```

- `session_secret` — derived from the same ECDH secrets as the data keys (via a
  separate HKDF label), known only to the endpoints.
- `n` — the path epoch, incremented on each migration. On the original path `n=0`.
- On migration the client switches to `roam_cid(n+1)`; the server keeps a **sliding
  window** of precomputed future CIDs (`roam_cid(n+1 … n+K)`, K≈4) → session. A packet
  from an unknown address whose CID falls in the window **and** passes AEAD+replay →
  migrate, advance `n`, recompute the window.

Properties: the on-wire CID differs per path (anti-link), the derivation is
deterministic (no CID-pool exchange), the server precompute is bounded by the window.
**8 bytes wide** (vs today's 4) — for collision safety; this is a wire change to the
masking header ([protocol/quic.rs](../../qeli/src/protocol/quic.rs),
`wrap_quic_short`/`unwrap_quic`), acceptable in 0.8.0 (real QUIC CIDs run up to 20
bytes).

> Alternative (Design A, QUIC-style "CID pool"): the server hands the client a set of
> future CIDs in advance (encrypted, post-auth). More flexible, but more state and
> protocol. Rejected in favor of deterministic rotation as simpler and stateless.

### 2.3 Migration trigger & validation (anti-hijack)

The server updates a session's stored peer-addr **only** if a packet: (1) matched a
known/expected CID, (2) **passed AEAD authentication**, (3) **passed the replay
window**. This is WireGuard's model: possession of the key proves identity; the replay
window stops capture-replay from a foreign address. An attacker without the key can't
steer the address (their packet won't decrypt → no migration).

Optional (Phase 2, belt-and-suspenders) — **QUIC-style path validation**: after
migrating, send a random challenge to the new address and await an authenticated echo
before fully switching downstream.

### 2.4 TCP: JOIN-resume + grace period

The outer TCP socket can't migrate — but there's a ready primitive, the **JOIN token**
(stream bonding): a new TCP connection from the new IP does its own handshake and sends
`JOIN(session_token)` instead of AUTH → the server attaches it to the live session
(same tun-IP, routes, **no second Argon2**). What's missing:

1. **Grace period.** Today, when the last stream detaches the session is torn down
   **immediately** ([handler.rs:766](../../qeli/src/server/handler.rs#L766)): `by_ip`/`by_token`
   cleared, IP returned to the pool. Needed: on last-stream detach, mark the session
   `orphaned_at = now` and **keep** it for `roaming.grace_secs`; a JOIN in that window
   revives it (for `max_streams=1` the check passes: 0 < 1,
   [handler.rs:411](../../qeli/src/server/handler.rs#L411)).
2. **JOIN hardening (Phase 2).** Today the token is a bearer (16 bytes,
   [protocol/mod.rs](../../qeli/src/protocol/mod.rs) `JOIN_TOKEN_LEN`), sent only inside the
   authenticated tunnel. Bind the JOIN to a proof over session material —
   `join_proof = HKDF(session_resume_secret, transcript_hash)` — so a single leaked
   token isn't enough.
3. **Anti-DoS caps.** Orphaned sessions **still count** against `max_clients` and the
   per-user limit during grace; cap `roaming.max_orphaned`. Otherwise connect→drop
   churn accumulates dangling sessions and exhausts the IP pool/slots (directly against
   the anti-ghost-session work already done).

### 2.5 TCP make-before-break (the seamless path)

When the new network appears **before** the old dies (typical Wi-Fi→LTE, both briefly
up), the client **proactively** opens a JOIN stream **over the new network**; the
scheduler ([server/mod.rs](../../qeli/src/server/mod.rs) `pick_stream`/`flow_hash`) shifts
flows onto it; the old stream dies — no gap. The server needs **nothing new** beyond
the existing multipath + grace (for the case where the old dies slightly first). The
requirement is **per-interface socket binding** on the client (see 4.4).

## 3. Server implementation (Rust)

### 3.1 UDP demux ([udp_handler.rs](../../qeli/src/server/udp_handler.rs))
- A secondary index `cid_index: HashMap<[u8;8], SocketAddr>` next to the primary
  `HashMap<SocketAddr, UdpClient>`. The primary stays the fast path (most packets come
  from a known address), with no per-packet cost change.
- `handle_udp_datagram`: (1) lookup by address — as today; (2) miss + `quic_enabled` →
  unwrap → CID → lookup in `cid_index` (incl. the expected roam-CID window) → candidate
  session → trial-decrypt with its `rx_codec` → if Ok and replay-ok → **MIGRATE**.
- MIGRATE (under the `sessions` write lock): move the `UdpClient` from the old
  addr-key to the new, update `cid_index`, update the **live** writer-addr, advance the
  roam-CID epoch + recompute the window, log.
- `writer_addr` is currently captured by value
  ([udp_handler.rs:671](../../qeli/src/server/udp_handler.rs#L671)) — make it
  `Arc<Mutex<SocketAddr>>` (or a packed `AtomicU64` for v4+port; v6 — a small struct
  under a Mutex), read on each `send_to`.
- **Crypto state is preserved** (codec, counter, replay window) — that's the whole
  point of seamlessness.

### 3.2 TCP grace + JOIN-resume ([handler.rs](../../qeli/src/server/handler.rs))
- In `run_stream` (teardown, `was_last`): instead of immediate removal, mark
  `orphaned_at = Some(now)`, keep it in the maps.
- A reaper (extend the existing cleanup tick) removes orphaned sessions older than
  `grace_secs` (then release IP/token).
- The JOIN path on attach: clear `orphaned_at` (session revived).
- New field on `SessionShared`: `orphaned_at: Mutex<Option<Instant>>`.

### 3.3 Config ([config/server.rs](../../qeli/src/config/server.rs) + INI + panel)
A new `[roaming]` section:
```ini
[roaming]
# enable roaming (UDP migration + TCP grace/JOIN-resume)
enabled = true
# how long a TCP session lives with 0 streams for JOIN-resume
grace_secs = 30
# rotate the UDP roam-CID (anti-linkability) — don't disable lightly
cid_rotation = true
# cap on simultaneously orphaned sessions per profile (anti-DoS)
max_orphaned = 256
# (Phase 2) QUIC-style challenge of the new address
path_validation = false
```
Parse/serialize like the other sections
([config/server_ini.rs](../../qeli/src/config/server_ini.rs)), a field in the panel form near
perf/obfs.

### 3.4 MTU after roaming (Phase 2)
A new path (LTE) may have a smaller MTU → blackhole of large packets. Phase 1 relies on
a conservative default `tun.mtu=1400`; Phase 2 — PMTUD re-probe or a re-push of the MTU
on migration.

## 4. Client implementation (all 4 clients)

Rust ([client/mod.rs](../../qeli/src/client/mod.rs)), Android (Kotlin), Windows (C#), macOS (C#).

### 4.1 Network-change detection
- **Rust** (Linux/router): netlink `RTM_NEWADDR`/route monitor, or poll the default route.
- **Android**: `registerDefaultNetworkCallback` (already used for `forceReconnect`) —
  repurpose for the soft-rebind.
- **Windows**: `NetworkChange.NetworkAddressChanged` / `NotifyAddrChange`.
- **macOS**: `nw_path_monitor` / `SCNetworkReachability`.

### 4.2 UDP soft-rebind (the seamless path)
On a network change: create a **new** UDP socket on the new interface, **keeping** the
existing `PacketCodec`/counter/CID state; advance the roam-CID epoch; resume sending.
**Critical: do NOT recreate the codec** — that's nonce reuse (catastrophic for AEAD).
Architecturally — a single session-state object that survives socket replacement.

### 4.3 TCP make-before-break
- "New network available" (both up): open a JOIN stream bound to the new interface;
  after the ack, mark the old stream draining; the old dying → no gap.
- "Only the new network" (hard handover): the old stream is already dead → JOIN-resume
  over the new within the grace window; grace expired → full reconnect (today's path).

### 4.4 Per-interface socket binding
Android `Network.bindSocket`; Linux `SO_BINDTODEVICE` (the client is root for TUN
anyway); Windows `IP_UNICAST_IF` (or bind to the interface address); macOS
`IP_BOUND_IF`.

## 5. Security (summary)
- **Anti-hijack:** migrate only after AEAD+replay; optional path validation.
- **Anti-linkability:** CID rotation (UDP). The TCP token is in-tunnel, no wire tell —
  but the **server** sees both IPs under one session (as it already does via device-id),
  and a global observer correlates by timing/volume — **add to THREAT-MODEL.md**.
- **Anti-DoS:** grace/orphaned caps; orphaned counts against limits; UDP migration is
  O(1) lookups; the roam-CID window is bounded.
- **Nonce reuse (the #1 footgun):** the client must carry the codec **verbatim** across
  the rebind — assertion + test.
- **MTU blackhole:** re-probe / conservative default.

## 6. Testing & lab
- **Unit:** roam-CID derivation/rotation KATs; migration accept/reject (a valid packet
  migrates, a spoofed/replayed one doesn't); grace timer; JOIN-resume attach at
  `max_streams=1`.
- **Fuzz:** extend [qeli/fuzz](../../qeli/fuzz) along the CID/migration path.
- **e2e on the lab (.10/.11):** a script flips the client's src-addr mid-flow
  (netns/iptables SNAT) and asserts: UDP+QUIC → 0 reconnects, the flow continues; TCP →
  make-before-break 0-gap with two live networks, JOIN-resume <grace on a hard
  handover; measure gap/loss/"Argon2 skipped".
- **Regression:** throughput unchanged (the CID lookup runs only on an address miss,
  not per packet).

## 7. Phasing

- **Phase 1 → 0.8.0:** UDP+QUIC seamless roaming (server CID demux + migration + live
  writer-addr; client soft-rebind) **with CID rotation from the start**; TCP
  break-before-make (grace + JOIN-resume, token-only). The `[roaming]` section. Tests +
  lab.
- **Phase 2 → 0.8.x:** TCP make-before-break (per-interface binding + handover on
  multipath), `join_proof` hardening, path validation, MTU re-probe.
- **Phase 3 (later):** a CID for plain-UDP (if demanded); a CID pool (Design A) if
  deterministic rotation proves insufficient.

## 8. Compatibility / rollout
Wire changes (8-byte rotating CID, JOIN-resume semantics) → 0.8.0 as the **lockstep**
upgrade point for the server and all clients. For non-roaming peers the default
behavior is unchanged (roaming under the `[roaming].enabled` flag); old clients keep
working as "fast reconnect".

## 9. Effort estimate (rough)

| Component | Size | Risk |
|---|---|---|
| Server UDP demux + migration + roam-CID | Medium | Medium (data-plane) |
| Server TCP grace + JOIN-resume | Small-medium | Low |
| Config `[roaming]` + panel | Small | Low |
| Client: net detection + UDP soft-rebind ×4 | Medium | Medium (nonce reuse) |
| Client: TCP make-before-break + per-iface bind ×4 (Phase 2) | Large | Medium |
| Tests + lab address-change scenarios | Medium | — |

The main risks are changes in the security-critical data plane and **nonce reuse on a
botched rebind**; mitigated by the `[roaming].enabled` flag (can default off at first),
the grace/orphaned caps, and a mandatory codec-carry test.
