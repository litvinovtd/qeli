# Client roaming (seamless network change) — implementation plan
<!-- normative-sync: roaming-v12-udp-client-wire-dialer -->

> **Status: design complete; Phases 0–2A and the shared Phase 2B TCP handover are
> implemented behind `experimental-roaming`. The Linux in-process and Android feature TCP adapters
> advertise complete `ROAMING_PATH` only when the core implements it; default builds and UDP retain
> normal reconnect behavior. Linux passed isolated two-path live e2e 15/15, hard resume, and explicit
> close. An Android API 34 emulator passed Wi-Fi → cellular (198/200 probes), cellular → Wi-Fi
> (200/200), and sleep/wake on the unchanged path (160/160): PID, TUN, and NetworkPlan survived,
> full AUTH ran once, the underlying Network changed atomically, and DNS still resolved after the
> transitions. A repeated hard-loss/make-before-break race gate admitted exactly one authenticated
> JOIN per change (76/80 and 80/80 probes). The Phase 3A–3E
> bounded UDP registry, cross-worker dispatch, atomic data/auxiliary egress, negotiated bootstrap,
> authenticated ingress/control boundary, guarded PATH_RESPONSE/PATH_COMMIT transaction, and
> post-commit UDP DATA/DATA_FRAG ingress plus shared client validation, wire framing and the
> exact-bound candidate-socket dialer are source-complete; live UDP actor socket publication,
> UDP capability activation, and live
> acceptance remain. Windows/macOS/iOS adapters and remaining Phase 3–6 work remain. Current lab
> gates pass 940 feature library tests with three ignored, strict feature Clippy, base Linux netns
> 26/26, roaming netns 15/15,
> an Android x86_64 NDK release with `-D warnings`, and Gradle unit/assemble.
> The full platform/race/soak matrix is still a release gate. Target: 0.8.x.**
>
> Rechecked against the current unified Rust-core architecture. This document defines
> mandatory implementation invariants and intentionally avoids fragile source-line anchors.

Goal: when the client's IP/interface changes (Wi-Fi↔LTE, cell handover, new DHCP
lease) the **user's connections do not drop**. The real traffic rides on the tun-IP,
which is preserved, so the inner flows are insulated from the outer-path change — the
job is to keep the **outer** tunnel alive (or rebuild it instantly) without losing
the session or paying Argon2 again.

## 0. Seamlessness per transport

| Transport | Achievable | How |
|---|---|---|
| **UDP + QUIC masking** | Fully seamless (connection migration) | A new authenticated path becomes a candidate; PATH_CHALLENGE/PATH_RESPONSE validation commits the peer address |
| **TCP** (reality-tls / fake-tls / obfs / plain) | Seamless with make-before-break; otherwise a short gap | Multipath JOIN over the new network *before* the old dies; fallback — grace + JOIN-resume |
| **UDP plain** (no quic) | Out of scope | No on-wire identifier → roaming requires `quic=1` |

**Non-goals:** zero byte loss on a hard handover where only one network is alive at
the moment of transition (inner-TCP retransmit covers it); MPTCP; buffering +
re-encrypting un-flown downstream packets (not worth the complexity).

## 1. Current pre-roaming behavior

Without `experimental-roaming`, a network change still means **fast reconnect, not roaming**:
the client detects the change, performs a **full new handshake** (ephemeral X25519+ML-KEM plus a
fresh Argon2 login); the server supersedes its previous session by **device-id** and hands back the
same tun-IP (the pool is sticky by `device_key`) and routes. The Android feature TCP adapter instead
turns the physical callback into a bounded PathUpdate and uses full reconnect only as fallback.
The default result remains a ~(RTT + Argon2 time) dip and packet loss in the window.
Roaming removes that hiccup.

## 2. Protocol / wire design

### 2.1 UDP connection-id (CID) — demux by packet content

Today: the client picks **its own stable 4-byte CID** once
([client/mod.rs](../../../qeli/src/client/mod.rs)) and puts it on every upstream
packet; the server **extracts and discards** that CID (`_connection_id`,
[udp_handler.rs](../../../qeli/src/server/udp_handler.rs)) and demuxes sessions by the
source `SocketAddr` ([udp_handler.rs](../../../qeli/src/server/udp_handler.rs) /
[udp_handler.rs](../../../qeli/src/server/udp_handler.rs)). An address change → map miss → treated as a
new client → full handshake.

Change: the server **records the client CID** at handshake and can find the session by
CID when the source address is unknown. The rotating eight-byte CID lives in the QUIC
short header **in the clear** (it must — the server has to identify the session **before**
decrypting, to pick the key). The negotiated form keeps the ordinary QUIC short flags and
widens the legacy four-byte DCID to eight bytes; it adds no fixed qeli-specific marker. On an
address miss the server attempts the eight-byte registry lookup, while a known legacy path
continues to use its recorded four-byte form.

### 2.2 CID rotation (unlinkability) — mandatory

A constant cleartext CID that survives a network change is a **correlation tell**: a
passive observer links your Wi-Fi to your LTE. So the CID **rotates**, as in QUIC.
Adopted design — **deterministic rotation (Design B):**

```
roam_cid(n) = HKDF-Expand(session_secret, "qeli-roam-cid" ‖ LE64(n))[..8]
```

- `session_secret` — derived from the same ECDH secrets as the data keys (via a
  separate HKDF label), known only to the endpoints.
- `n` — the path epoch, incremented on each migration. On the original path `n=0`.
- For a candidate path the client selects `roam_cid(n+1)`; the server keeps a **sliding
  window** of bounded current/previous/future CID aliases. A packet from an unknown
  address whose CID is expected and passes AEAD+replay creates only a bounded candidate.
  The active CID and monotonic path epoch advance only after return-path validation and
  atomic PATH_COMMIT.

Properties: the on-wire CID differs per path (anti-link), the derivation is
deterministic (no CID-pool exchange), the server precompute is bounded by the window.
**8 bytes wide** (vs today's 4) — for collision safety; this is a wire change to the
masking header ([protocol/quic.rs](../../../qeli/src/protocol/quic.rs),
`wrap_quic_short`/`unwrap_quic`), scheduled for the roaming-capable 0.8.x protocol
revision after the full-IPv6 0.8.0 release (real QUIC CIDs run up to 20 bytes).

> Alternative (Design A, QUIC-style "CID pool"): the server hands the client a set of
> future CIDs in advance (encrypted, post-auth). More flexible, but more state and
> protocol. Rejected in favor of deterministic rotation as simpler and stateless.

### 2.3 Migration trigger & validation (anti-hijack)

The server **does not update** the active peer address merely because a packet matched an
expected CID and passed AEAD plus replay checks. Those checks authenticate the session
and permit creation of one bounded candidate path; they do not prove that the sender owns
the return path. An attacker without the key cannot create a candidate, and an
authenticated but unusable/spoofed return path cannot become active without the
challenge/response transaction below.

**QUIC-style path validation is mandatory in the first production version.** A packet
with an authenticated next CID creates only a bounded candidate path. The server sends
PATH_CHALLENGE within a 3× anti-amplification budget, waits for PATH_RESPONSE, and only
then atomically commits downstream to the candidate. Stale epochs, duplicate challenges,
parallel candidates, and late responses from an old path must not roll back the active
path. AEAD plus replay protection authenticates the session; challenge/response proves
that the peer also owns the return path.

### 2.4 TCP: JOIN-resume + grace period

The outer TCP socket can't migrate — but there's a ready primitive, the **JOIN token**
(stream bonding): a new TCP connection from the new IP does its own handshake and sends
`JOIN(session_token)` instead of AUTH → the server attaches it to the live session
(same tun-IP, routes, **no second Argon2**). What's missing:

1. **Grace period.** Today, when the last stream detaches the session is torn down
   **immediately** ([handler.rs](../../../qeli/src/server/handler.rs)): `by_ip`/`by_token`
   cleared, IP returned to the pool. Needed: on last-stream detach, mark the session
   `orphaned_at = now` and **keep** it for `roaming.grace_secs`; a JOIN in that window
   revives it (for `max_streams=1` the check passes: 0 < 1,
   [handler.rs](../../../qeli/src/server/handler.rs)).
2. **Authenticated JOIN is mandatory from the first production version.** The existing
   token is only a session locator and never a bearer credential. A new key exchange
   creates fresh AEAD keys, while a proof binds the resume secret, transcript hash,
   session locator, wide resume epoch, logical slot id, and handover flag. A repeated
   proof, a proof for another slot/epoch, or a modified transcript is rejected. A leaked
   locator alone is therefore insufficient to resume a session.
3. **Anti-DoS caps.** Orphaned sessions **still count** against `max_clients` and the
   per-user limit during grace; cap `roaming.max_orphaned`. Otherwise connect→drop
   churn accumulates dangling sessions and exhausts the IP pool/slots (directly against
   the anti-ghost-session work already done).

### 2.5 TCP make-before-break (the seamless path)

When the new network appears **before** the old dies (typical Wi-Fi→LTE, both briefly
up), the client **proactively** opens a JOIN stream **over the new network**; the
scheduler ([server/mod.rs](../../../qeli/src/server/mod.rs) `pick_stream`/`flow_hash`) shifts
flows only after the new logical slot is ready, then drains the old stream. Existing
multipath is a foundation, not a complete implementation: the server and shared core
still need authenticated JOIN proof, stable logical slots, the generation-scoped path
transaction, bounded queues, and race-safe JOIN/reaper/kick ownership. The client also
needs exact per-interface socket binding (see 4.4).

## 3. Server implementation (Rust)

### 3.1 UDP demux ([udp_handler.rs](../../../qeli/src/server/udp_handler.rs))
- A secondary index `cid_index: HashMap<[u8;8], SocketAddr>` next to the primary
  `HashMap<SocketAddr, UdpClient>`. The primary stays the fast path (most packets come
  from a known address), with no per-packet cost change.
- `handle_udp_datagram`: (1) lookup by address — as today; (2) miss + `quic_enabled` →
  unwrap → CID → lookup in `cid_index` (incl. the expected roam-CID window) → candidate
  session → trial-decrypt with its `rx_codec` → if Ok and replay-ok, enqueue PATH_INIT
  for the per-session actor and create at most one bounded **CANDIDATE**.
- The actor sends PATH_CHALLENGE under the 3× anti-amplification budget. Only a valid,
  epoch-bound PATH_RESPONSE may perform atomic PATH_COMMIT: switch the active address,
  receiving/egress socket and outer family, rotate bounded CID aliases, reset PMTU, then
  drain the old receive path. An abort removes only resources owned by that candidate
  generation.
- Replace the writer's captured address/socket with actor-owned `ActiveUdpPath`; every
  egress send reads the committed path. This must represent IPv4 and IPv6 without a
  packed-IPv4 shortcut.
- **Crypto state is preserved** (codec, counter, replay window) — that's the whole
  point of seamlessness.

### 3.2 TCP grace + JOIN-resume ([handler.rs](../../../qeli/src/server/handler.rs))
- In `run_stream` (teardown, `was_last`): instead of immediate removal, mark
  `orphaned_at = Some(now)`, keep it in the maps.
- A reaper (extend the existing cleanup tick) removes orphaned sessions older than
  `grace_secs` (then release IP/token).
- The JOIN path on attach: clear `orphaned_at` (session revived).
- New field on `SessionShared`: `orphaned_at: Mutex<Option<Instant>>`.

### 3.3 Flat-INI config and panel
User-facing server settings are profile-scoped:
```ini
[profile:mobile-udp]
roaming.enabled = true
roaming.grace_secs = 30
roaming.max_orphaned = 256
roaming.max_orphan_bytes = 67108864
```

Client policy is part of `[qeli]`:
```ini
[qeli]
roaming = auto
```

Allowed values are `off` (always reconnect), `auto` (roam when safely negotiated,
otherwise reconnect), and `required` (fail if safe roaming is unavailable).
Low-level cryptography, path validation, anti-amplification, PMTU reset,
and CID rotation are protocol invariants, not operator switches.

### 3.4 PMTU and DATA_FRAG after roaming
A new path can have a smaller outer MTU and otherwise black-hole large records. The first
production version resets the outer payload budget to the safe minimum for the new family
after PATH_COMMIT and starts a bidirectional live PMTU probe bound to path epoch, source,
and egress socket. Old-path measurements and late ACKs cannot raise the new budget.
DATA_FRAG_V1 keeps the existing inner TUN/TAP MTU and NetworkPlan unchanged.

## 4. Client implementation (all five applications)

Rust (Linux/OpenWrt), Android (Kotlin), Windows and macOS (shared C# layer), and iOS
(Swift platform adapter) all use the same Rust session supervisor and path transaction.

### 4.1 Network-change detection
- **Rust** (Linux/router): netlink `RTM_NEWADDR`/route monitor, or poll the default route.
- **Android**: best-matching non-VPN Network callback (full reconnect fallback) —
  repurpose for the soft-rebind.
- **Windows**: `NetworkChange.NetworkAddressChanged` / `NotifyAddrChange`.
- **macOS**: `nw_path_monitor` / `SCNetworkReachability`.

The Android feature TCP adapter now submits bounded, generation-scoped PathUpdates, resolves through
the exact `Network`, binds and protects the candidate socket, and publishes `setUnderlyingNetworks`
only after COMMIT. Stale generations and superseded Networks cannot mutate platform state. Same-network
NAT rebinding/dead-mapping detection remains.

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
- **Anti-hijack:** AEAD+replay may create a candidate; mandatory return-path validation
  and atomic PATH_COMMIT are required before downstream or the active address changes.
- **Anti-linkability:** CID rotation (UDP). The TCP token is in-tunnel, no wire tell —
  but the **server** sees both IPs under one session (as it already does via device-id),
  and a global observer correlates by timing/volume — **add to THREAT-MODEL.md**.
- **Anti-DoS:** grace/orphaned caps; orphaned counts against limits; UDP migration is
  O(1) lookups; CID aliases, candidates, and anti-amplification are bounded.
- **Nonce reuse (the #1 footgun):** the client must carry the codec **verbatim** across
  the rebind — assertion + test.
- **MTU blackhole:** re-probe / conservative default.

## 6. Testing & lab
- **Unit:** roam-CID derivation/rotation KATs; migration accept/reject (a valid packet
  migrates, a spoofed/replayed one doesn't); grace timer; JOIN-resume attach at
  `max_streams=1`.
- **Fuzz:** extend [qeli/fuzz](../../../qeli/fuzz) along the CID/migration path.
- **e2e on the lab (.10/.11):** a script flips the client's src-addr mid-flow
  (netns/iptables SNAT) and asserts: UDP+QUIC → 0 reconnects, the flow continues; TCP →
  make-before-break 0-gap with two live networks, JOIN-resume <grace on a hard
  handover; measure gap/loss/"Argon2 skipped".
- **Regression:** throughput unchanged (the CID lookup runs only on an address miss,
  not per packet).

## 7. Phasing

No production stage may expose roaming without authenticated JOIN proof, path validation,
anti-amplification, PMTU reset, and bounded DATA_FRAG/reassembly.

- **Phase 0 — ✅ source complete:** capabilities, CONTROL_V2, KDF labels, proofs, wire
  limits, and KATs are frozen behind the default-off feature gate.
- **Phase 1 — ✅ source complete:** ABI 1.12 provides bounded generation-scoped
  PathUpdate plus PREPARE/BIND/COMMIT/ABORT, V3 roaming telemetry, strict correlation,
  lifecycle cleanup, and mock fault injection. The Linux in-process TCP feature adapter now
  advertises the path contract and passed live e2e; the Android feature TCP adapter now does the same.
  The default data plane and remaining native adapters remain unchanged.
- **Phase 2A — ✅ lifecycle source complete:** the default-off shared core owns the
  Active/Orphaned/Resuming/Closing/Revoked state machine, dual orphan session/byte limits,
  generation-tagged reaper ownership, monotonic resume-epoch consumption, stable logical
  slots, atomic JOIN reservation, and make-before-break draining. Unit tests cover stale
  proof/transcript/epoch/locator rejection, JOIN-vs-reaper, revoke-vs-JOIN, exact-once
  release, cap exhaustion, abort, and late drain acknowledgements.
- **Phase 2B — 🟡 shared TCP resume/handover complete; Linux and Android feature live accepted:** the Linux handler
  and shared client supervisor derive and zeroize the original-session resume secret, strictly
  parse authenticated resume JOIN, reserve before JOINOK, and use a fresh KE plus fresh
  per-carrier data keys on every attach. The feature client core can advertise `CONTROL_V2`,
  `TCP_RESUME_V1`, and `TCP_HANDOVER_V1`, but negotiation requires the complete platform contract.
  Linux advertises it only for feature TCP without a fixed source; Android advertises it only for
  TCP when the loaded feature core reports the path-transaction ABI.
  Loss of the last carrier preserves the same TUN and NetworkPlan for a 30-second grace and
  retries the same stable logical slot once per second; sibling reader/writer tasks share a
  persistent stop signal. The server permits one bounded authenticated candidate above the
  stream cap so a hard resume can atomically replace a stale carrier before server-side EOF/RST
  detection, then drains and closes the obsolete transport. Orphan session/byte limits and the
  generation-scoped reaper remain the fallback when every server-side carrier has detached.
  Legacy JOIN/scheduling remain unchanged for non-negotiated sessions.

  Intentional client stop now sends a strict empty single-part `CLOSE_SESSION` inside the
  authenticated PacketCodec/`PACKET_MUX_V1` path. The client forces a pending recordizer batch
  to flush and waits at most 750 ms for socket write completion; the server atomically blocks new
  JOIN/resume admission, closes every bonded stream, releases the lease immediately, and never
  enters orphan grace. Linux SIGINT/SIGTERM uses this cooperative cancel path instead of
  bypassing data-plane destructors with `process::exit`.

  The make-before-break foundation now binds the authenticated resume proof to an explicit
  handover bit and reference-counts overlapping carriers for each stable logical slot. Draining
  the old carrier therefore cannot make the replacement appear absent. Server negotiation also
  requires the authenticated client to advertise both TCP handover core bits and the complete
  platform `ROAMING_PATH` contract (`PATH_TRANSACTIONS + PATH_SOCKET_BINDING`); claiming the core
  bit alone cannot authorize replacement of a live transport.

  The shared supervisor now consumes one ACK-confirmed PREPARE candidate at a time, creates a
  separate unbound socket, requires exact platform `BIND_SOCKET` before connect, and dials only
  the A/AAAA addresses supplied by that PathUpdate. A fresh-KE authenticated handover JOIN is
  validated before `COMMIT_PATH`; only after its ACK does the new carrier replace stable slot 0.
  Overlapping carriers retain the slot by refcount, and the committed address set becomes the
  repair source for the remaining bonded slots. BIND/COMMIT/ABORT have correlated oneshot results,
  a 45-second bound, and cancellation on supersede/stop.

  An unsupported peer is rolled back with an ACK-confirmed ABORT before the normal full-reconnect
  fallback. Candidate connect/JOIN failures also abort temporary platform state. A COMMIT rejection
  is fail-closed: because the server has already authenticated and switched the carrier, the client
  recovers through the existing authenticated hard-resume path instead of publishing an uncommitted
  local path. Android enables application platform bits only for feature TCP after emulator acceptance;
  Windows/macOS/iOS keep them disabled until their Phase 4 device/race acceptance.

  Lab `.10` passes the final default/feature suites (865/910 library tests, 4 CLI,
  7 integration; one privileged test ignored in each configuration) and strict all-target
  Clippy for both builds. An isolated Linux netns e2e with an asymmetric TCP RST passes 13/13:
  resume completes in 2 seconds, the outer carrier changes, TUN ifindex/address survive,
  traffic recovers, and password AUTH occurs exactly once. A separate `.11 → .10` live test with
  required `PACKET_MUX_V1` passes 3/3 tunnel pings, observes both close markers, leaves zero
  established carriers and no client TUN, and confirms that the server did not enter resume
  grace. Those `.10/.11` results cover hard resume and explicit close. The two-path Linux
  feature e2e now also passes 15/15: path B completes authenticated JOIN/COMMIT, path A can be
  removed, the same PID/TUN survive, and 150/150 probes pass without a top-level reconnect.
  Android API 34 emulator acceptance covers both directions: Wi-Fi hard loss selects an already
  available cellular Network and retains 198/200 probes; cellular-to-Wi-Fi make-before-break retains
  200/200. The same process, VPN Network, `tun0`, and `NetworkPlan 1` survive, with exactly one
  `Auth OK`. Sleep/wake on the unchanged Network retains 160/160 probes without an unnecessary
  handover, and system DNS still resolves after both transitions and sleep.

  The shared TCP supervisor now always yields generic slot repair to an already-prepared exact-path
  candidate and, after the last carrier disappears, gives a handover-enabled platform a bounded
  one-second PathUpdate preparation window. If no candidate materializes by then, ordinary hard-resume
  proceeds; recovery is never deferred indefinitely. This removes the observed Android sequence in
  which generic hard-resume and exact-path handover replaced slot 0 back-to-back. A repeated API 34
  race gate recorded exactly one authenticated JOIN for Wi-Fi-to-cellular hard loss and one for the
  reverse make-before-break transition, retained 76/80 and 80/80 probes respectively, kept the same
  PID/VPN Network/`NetworkPlan 1`, ran AUTH once, and still resolved DNS names. The full Rust library
  suite passed 931 tests with three ignored; strict all-target Clippy and Android release `-D warnings` passed.

  Real devices, same-network NAT rebinding, Windows/macOS/iOS, and the broader
  transport/family/race/soak matrix remain.
- **Phase 3 — 🟡 registry/migration, server egress, and client validation foundations source-complete:** a default-off,
  profile-wide bounded table now owns generation-tagged sessions, up to three deterministic CID
  aliases, directional zeroized secrets, one authenticated candidate, exact path challenge/response,
  3× anti-amplification accounting, atomic collision-safe CID rotation, generation-tagged PMTU reset,
  stale-probe rejection, and exact cleanup. A generic bounded cross-worker fabric keeps immutable
  home-worker ownership of each session codec, avoids a global decrypt lock, uses no channel hop for
  local ingress, and uses fail-closed `try_send` for other `SO_REUSEPORT` workers. Unknown CID,
  invalid worker, full and closed mailbox outcomes are distinct, and rejected payloads retain exact
  ownership without `Debug`.

  The authenticated server UDP writer now snapshots the exact socket, peer, framing, path epoch,
  and matching PMTU budget once per complete encrypted record. An experimental guarded commit can
  atomically publish the next IPv4/IPv6 path and eight-byte CID without replacing the PacketCodec,
  replay window, rate buckets, or TUN ownership. A stale commit cannot roll the path back; a late
  old-path `EMSGSIZE` cannot overwrite the new family's safe budget; and DATA_FRAG subtracts the
  actual legacy or roaming header length. The legacy four-byte-CID wire path remains byte-identical.
  Thirteen focused unit tests cover sequential rotations, stale/collision/anti-amplification,
  local/cross-worker/full/closed routing, and atomic writer publication.
  Heartbeat and shaping-cover records now take the same per-record active-egress snapshot, so a
  committed path supplies their exact socket, peer, and CID. A record already snapshotted may finish
  on the draining path, but subsequent records observe the commit. A reverse PMTU probe is built for
  the active framing, sent from the active socket to the active peer, and bound to the exact path
  epoch and address. Its pending marker is shared with the timeout task, so changing the session's
  address-map key cannot strand the retry gate. ACK certification checks epoch and peer while the
  active-path read guard is held; an old-path ACK therefore cannot widen the new path's budget.

  The UDP bootstrap contract is now fail-closed and additive. Entry requires explicit authenticated
  opt-in from both peers to `CONTROL_V2 + UDP_ROAM_V1 + UDP_DATA_FRAG_V1`; a client cannot activate
  a reserved capability that the server did not advertise. For a negotiated QUIC session, encrypted
  AuthOK carries `udp_roaming_session` as a non-zero `u64` encoded by exactly 16 hexadecimal
  characters. The client rejects a missing or malformed identifier once negotiation succeeds, while
  the legacy AuthOK builder omits the field byte-for-byte. Three focused tests cover negotiation,
  canonical emission/legacy omission, and strict parsing.

  Feature UDP handshakes now use the shared `SessionKeyMaterial`: existing data keys remain
  identical, while directional C2S/S2C CID secrets come from the same hybrid or static-bound KDF
  and remain zeroizing. Before AuthOK can advertise a fully negotiated session, the server records
  its exact initial worker/path, epoch-zero CIDs, and family-safe payload budget in one profile-wide
  registry; the client independently derives the matching directional CIDs from the session id.
  A non-cloneable generation-scoped registration guard owns cleanup, so late teardown of an old
  session cannot remove a replacement's aliases. Worker ids are now unique across every
  `bind.listen` of the profile, preparing unambiguous cross-listener and cross-family delivery.
  Two focused lifecycle tests pin the stale-owner/replacement and shared-fabric races.

  The server hot path now creates one bounded fabric across every profile worker/listener and gives
  each worker one non-cloneable mailbox. It checks an eight-byte short-header CID before new-session
  rate limiting, but enters the roaming path only after the full CID resolves. The shared first byte
  is not treated as a discriminator, so an unknown CID from a known address retains legacy handling
  and a repeated AUTH can still recover a lost AuthOK. The pooled datagram moves without copying
  together with the exact receiving socket to the immutable home worker. A generation-safe
  `session_id → address` index is published only after AUTH and removed transactionally with the
  address map; stale teardown cannot delete a replacement generation.

  The owner boundary now feeds the encrypted record through the session's existing PacketCodec,
  replay window, and bounded DATA_FRAG reassembler. Only a single-part, flag-free client
  `PATH_INIT` or `PATH_RESPONSE` can cross the strict CONTROL_V2 decoder. Replays, malformed or
  fragmented control, server-direction messages, ordinary data, and unauthenticated bytes are
  rejected before the TUN and before any path state can change. Candidate liveness advances only
  after successful AEAD verification. Two focused tests pin the direction/shape gates and shared
  replay-window behaviour.

  An authenticated `PATH_INIT` now validates the next epoch, future C2S CID, expected S2C CID,
  and new socket/peer under one profile-registry operation. It creates or idempotently finds the
  session's sole candidate with a non-zero 128-bit token. `PATH_CHALLENGE` uses the shared TX
  PacketCodec and verified eight-byte destination CID, then leaves through the exact receiving
  socket. Its cumulative budget is reserved before send and includes the roaming header plus obfs
  overhead; it cannot exceed 3× the conservatively counted authenticated candidate ingress. The
  generation-scoped ticket remains in the session actor for the following PATH_RESPONSE slice.

  The guarded commit state transaction now prepares the complete next CID/PMTU outcome before
  changing registry state and calls a synchronous external socket/address publisher while holding
  the profile-registry lock. CID aliases, active epoch, PMTU generation, and candidate ownership
  change only after publication succeeds. A publisher failure leaves the candidate retryable, and
  an invalid challenge no longer increases the anti-amplification budget. A focused regression test
  pins this rollback. The last successful commit is retained as one bounded exact
  ticket/path/epoch/token outcome per session. A freshly encrypted retry of that PATH_RESPONSE
  returns the same PATH_COMMIT decision without invoking the publisher, rotating CIDs, or resetting
  an already refined PMTU; a mismatching token or path still fails closed. A second focused test
  pins the idempotent replay.

  The live server handler now authenticates PATH_RESPONSE against the retained candidate, validates
  the old epoch and peer, and synchronously places PATH_COMMIT on the candidate socket before it
  exposes the new socket, peer, CID, epoch, or family-safe PMTU. `WouldBlock` and any other socket
  publication failure leave both registry and writer state unchanged and the candidate retryable.
  After success, the address map and generation-safe owner index move together under the directory
  lock. Session-limit, supersede, and teardown cleanup resolve the current owner by session id rather
  than the connect-time address. An exact fresh-encrypted PATH_RESPONSE retry sends PATH_COMMIT again
  without rotating CIDs or resetting PMTU; a different token, path, old peer, occupied destination,
  or stale epoch fails closed.

  Post-commit DATA and DATA_FRAG now enter the existing authenticated UDP uplink path. Before AEAD,
  the owner classifies the routed CID against the writer snapshot under the directory lock: a
  previous or farther-future epoch is rejected without consuming replay state, the current epoch
  requires the exact committed socket and peer, and only the next epoch may reach candidate control.
  After one session-wide decrypt, ordinary records use the existing bounded DATA_FRAG reassembler,
  recordizer, source guard, destination ACL, bandwidth pacing, accounting, MTU/client-info control,
  and TUN forwarder. Candidate DATA is rejected; only authenticated path control may use that path.
  Commit, teardown, and DATA therefore cannot observe a partially moved directory/egress state.

  A fully negotiated epoch-zero session now publishes its initial server-to-client CID directly in
  `UdpActiveEgress`, so writer PMTU/recordizer budgets are computed for the 13-byte roaming header
  from the first post-auth record. AuthOK and its cached retransmit deliberately retain the legacy
  four-byte QUIC framing: the client must receive AuthOK before it knows the session id from which
  both directional CIDs are derived. The ingress owner rejects every routed CID until all AuthOK
  fragments have been sent and `auth_ok_sent` is published, preventing an early candidate from
  committing over the epoch-zero bootstrap. Default and non-negotiated wire output remains unchanged.

  Candidate validation is now independently bounded per profile. A candidate has a fixed ten-second
  lifetime, the profile retains at most `min(max_clients, 1024)` candidates, and a sliding one-second
  admission window permits at most 64 new candidates. An idempotent retransmit of the same
  authenticated PATH_INIT adds only its bounded ingress accounting: it neither refreshes lifetime nor
  consumes another rate slot. Expired tickets fail before egress/commit, while the existing server
  maintenance tick reaps silent candidates. Commit, abort, CID collision, session teardown, and
  expiry update the exact shared count.

  A cross-listener IPv4-to-IPv6 regression now routes the future CID from a foreign receiving
  worker to the immutable codec owner, commits that exact candidate socket/family and PMTU
  generation, then verifies that post-commit ingress still returns to the original owner.

  The shared client state machine now owns directional CID derivation/rotation, the next epoch,
  platform-candidate and CONTROL_V2 message correlation, and the complete `PATH_INIT →
  PATH_CHALLENGE → PATH_RESPONSE → PATH_COMMIT/PATH_ABORT` validation sequence. A zero challenge,
  wrong CID/epoch/direction, parallel candidate, or stale platform completion fails closed. An exact
  duplicate challenge idempotently resends the response. Retransmission is capped at four datagrams
  at 500 ms intervals inside the same fixed ten-second lifetime as the server candidate. A received
  wire commit is only a proposal: active epoch/CIDs do not change until the platform has acknowledged
  `COMMIT_PATH`, so a late completion after ABORT cannot publish an old path. Eight focused tests pin
  these invariants; strict feature Clippy and the full feature library suite (940 passed, three
  ignored) pass.

  The shared client wire layer now produces the complete `CONTROL_V2 → PacketCodec → eight-byte
  CID` envelope and parses authenticated packets with the session's one replay window. It treats
  ordinary data as data while requiring each marked `PATH_*` control to be flag-free, complete and
  single-part. Android, Apple and desktop adapters therefore cannot grow different CID/control
  grammars. Round-trip, data/control separation, fragmented-control rejection and replay tests cover
  that boundary.

  The transport-facing platform contract is now the protocol-neutral `PathController`. A shared Unix
  UDP candidate dialer creates one unbound socket, waits for the exact candidate's `BIND_SOCKET` ACK,
  and only then connects to the first family-compatible address resolved by that PathUpdate. The
  Linux test exercises the same bind-before-connect contract for both TCP and UDP.

  `UDP_ROAM_V1` remains absent from implemented server and client advertisements, so bootstrap and
  eight-byte CID framing still cannot activate in production. Live UDP actor/candidate-socket
  receive/egress publication remains before capability activation. The Phase 4 Linux/OpenWrt adapter now consumes
  the shared ordered family-compatible candidate projection: a physical path must have
  at least one local/resolved family match, and an unusable leading AAAA/A answer cannot hide a later
  usable address. Native Android/Windows/macOS/iOS runtimes now delegate prepared-candidate lookup,
  BIND/COMMIT/ABORT requests, correlated ACK completion and cancellation to one shared Rust
  `CorePathController`. The Linux in-process adapter now uses that controller and the shared bounded
  `ClientCore`: it executes PathCommands outside the core lock, correlates ACKs, immediately drains a
  mandatory ABORT after rejection, and leaves unrelated lifecycle events queued. Its source-complete
  read-only PREPARE route projection requires each carrier to resolve through the exact
  `from <source> oif <interface>` pair and the FIB must return that physical interface. An isolated
  netns regression proves that source binding plus `SO_BINDTODEVICE` selects the candidate default
  route despite active tunnel `/1` routes and an old carrier `/32`; no temporary route/policy rule
  is therefore needed before authenticated proof. The exact candidate-socket primitive then applies
  `SO_BINDTODEVICE` for the validated interface index and binds a same-family local address (including
  the IPv6 link-local scope). The COMMIT route primitive now preflights the complete address set before
  mutation: matching operator routes remain unclaimed, conflicting operator routes reject the commit,
  and only qeli-journalled routes may be replaced. Every add/replace is verified by an ordinary
  source-aware FIB lookup; a later IPv4/IPv6 failure restores earlier routes in reverse order and
  reconciles the ownership journal. Every TCP wire mode (`reality-tls`, `obfs`, `fake-tls`, `plain`)
  now creates a separate unbound candidate socket, receives BIND acknowledgement before connect, and
  uses only the first compatible address from that PathUpdate. After authenticated JOIN, COMMIT applies
  routes first and only then publishes the new pinned carrier-address set for later bonded streams. An
  unprivileged regression proves that the dialer ignores an intentionally unreachable configured address,
  connects to the candidate address, and binds before connect. Linux observation, capability activation,
  and initial live acceptance are complete. Android TCP exact-Network DNS/bind/protect,
  PREPARE/BIND/COMMIT/ABORT, stale/supersede guards, and Wi-Fi↔cellular plus sleep/wake emulator
  acceptance are complete. Real-device PMTU/race/soak/NAT-rebinding, the remaining native adapters,
  and exit-node acceptance remain.
- **Phase 4 — 🟡:** Linux/OpenWrt and Android TCP feature adapters are complete at initial live-acceptance level; Windows, macOS, iOS, real-device soak, NAT rebinding, and exit-node acceptance remain.
- **Phase 5:** flat-INI, app editors, panel/API, metrics, examples, and RU/EN docs.
- **Phase 6:** full lab matrix, soak, canary profiles, staged rollout, and legacy fallback.

## 8. Compatibility / rollout
Each roaming feature is negotiated through the existing authenticated capability trailer.
A feature-enabled server advertises only implemented server bits, and a session enters the TCP
roaming lifecycle only after the authenticated client extension opts in. Legacy peers keep the
normal full-reconnect path, so rollout does not require a lockstep server/client upgrade.
The initial server default is off and client policy is auto. Any failed or unsupported
transaction rolls back candidate resources and falls back to a full reconnect.

## 9. Effort estimate (rough)

Full delivery across the server, shared core, five client applications, panel,
documentation, and lab is approximately **20–30 engineering weeks**.

| Component | Size | Risk |
|---|---|---|
| CONTROL_V2, capabilities, KDF/proofs | Medium | High (protocol/security) |
| Server UDP registry/actor + PMTU/DATA_FRAG | Large | High (data plane) |
| Server TCP lifecycle + authenticated handover | Medium-large | High (races) |
| Shared-core supervisor and path transaction | Large | High |
| Five platform adapters, apps, panel, and config | Large | Medium-high |
| Lab matrix, soak, rollback, and rollout | Large | High |

Primary risks are cross-worker UDP state, TCP orphan/JOIN/reaper races, nonce reuse,
platform binding rollback, outer-family PMTU changes, iOS behavior, and interactions
