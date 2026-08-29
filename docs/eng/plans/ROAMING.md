# Client roaming (seamless network change) — implementation plan
<!-- normative-sync: roaming-v35-ios-path-executor -->

> **Status: design complete; Phases 0–2A and the shared Phase 2B TCP handover are
> implemented behind `experimental-roaming`. The Linux in-process and Android feature adapters
> advertise complete `ROAMING_PATH` for TCP and every supported UDP camouflage mode when the core
> implements it; default builds and unsupported platforms retain normal reconnect. Linux TCP passed
> live e2e 15/15, hard resume, and explicit
> close. An Android API 34 emulator passed Wi-Fi → cellular (198/200 probes), cellular → Wi-Fi
> (200/200), and sleep/wake on the unchanged path (160/160): PID, TUN, and NetworkPlan survived,
> full AUTH ran once, the underlying Network changed atomically, and DNS still resolved after the
> transitions. A repeated hard-loss/make-before-break race gate admitted exactly one authenticated
> JOIN per change (76/80 and 80/80 probes). The Phase 3A–3E
> bounded UDP registry, cross-worker dispatch, atomic data/auxiliary egress, negotiated bootstrap,
> authenticated ingress/control boundary, guarded PATH_RESPONSE/PATH_COMMIT transaction, and
> post-commit UDP DATA/DATA_FRAG ingress plus shared client validation, wire framing and the
> exact-bound candidate-socket dialer are source-complete. The live client actor now switches every
> epoch-zero post-auth data/control/PMTU path to directional CID framing, validates a separate
> candidate socket, handles PATH_INIT/CHALLENGE/RESPONSE/COMMIT/ABORT, waits for the exact platform
> COMMIT acknowledgement, and atomically replaces the socket, receive pump, CID framing, and
> conservative PMTU budget. A failure after peer PATH_COMMIT triggers a fail-closed reconnect.
> A feature-enabled Linux UDP session now advertises and negotiates `UDP_ROAM_V1` for fake-TLS,
> QUIC masking, obfs, and AWG only with a complete platform `ROAMING_PATH` and authenticated
> `DATA_FRAG_V1`; fixed-source and default builds do not.
> An isolated two-path UDP netns live e2e passed 17/17: PATH_INIT/CHALLENGE/RESPONSE/COMMIT moved the
> authenticated session, carrier `/32`, socket, and receive pump before the old interface was disabled,
> preserving PID, TUN, and the absence of top-level reconnect. A separate rollback scenario passed
> 20/20: path B alone was blackholed, bounded PATH_INIT retries expired, and the exact platform ABORT
> removed the prepared candidate while retaining the active carrier `/32` on path A; the tunnel kept
> the same PID/TUN without entering top-level reconnect. A three-path supersede scenario passed 24/24:
> blackholed B emitted PATH_INIT, then the platform executed `ABORT(B) → PREPARE(C)`, the actor
> discarded the old socket before retry expiry, and the server saw challenge/commit only on C with
> exactly one published commit. PID/TUN and traffic survived without reconnect. The Windows/macOS
> C# and iOS Swift path executors are now source-complete; their device/race acceptance and Phases
> 4–6 remain. The iOS Rust slice passes strict `aarch64-apple-ios` cross-target Clippy, while Xcode
> and physical-device NetworkExtension acceptance remain. A deterministic commit-race scenario passed
> 24/24: after server
> PATH_COMMIT(B), local COMMIT(B) route mutation was delayed while the detector observed C, but the
> serialized executor prevented C from cancelling or overtaking B. B's exact ACK/publication completed
> before PREPARE(C), after which C committed exactly once; PID/TUN and traffic survived without reconnect.
> A deterministic control-loss scenario passed 18/18: firewall counters proved that the first
> PATH_CHALLENGE and first PATH_COMMIT were dropped, fresh PATH_INIT/PATH_RESPONSE flights recovered
> both losses, and the server replayed PATH_COMMIT without a second path publication or reconnect.
> The Linux IPv4 roaming PMTU slices passed 19/19 each. Bare probes and ACKs are routed after exact
> committed CID/epoch/socket/peer classification instead of being discarded as failed AEAD records.
> A symmetric move from MTU 1500 to 1280 independently re-certified both directions from 1461 to
> 1161 bytes, retained the inner TUN MTU 1400, and carried a 1350-byte payload through DATA_FRAG.
> An asymmetric C2S 1500 / S2C 1280 gate kept uplink at 1461 while the server descended the shared
> PMTU ladder and certified downlink at 1161; reverse DATA_FRAG, PID/TUN, and the session survived.
> A deterministic Linux IPv4 receive-drain gate passed 26/26. Both directions on old path A used
> MTU 1280 with a three-second delay and gap reordering; path B committed while each 1350-byte
> DATA_FRAG record was incomplete. The exact previous epoch/peer/socket/CID remained receive-only
> for one reassembly timeout, completed both records, and then expired; old control and PMTU stayed
> rejected. Duplicate DATA_FRAG on active path B remained idempotent without replacing PID/TUN or
> reconnecting.
> A dual-listener Linux outer-family gate passed 32/32. One authenticated session moved
> IPv4 → IPv6 → IPv4 through distinct receiving workers without another AUTH or reconnect, while
> retaining its codec owner, PID, and TUN. Each direction independently re-certified PMTU
> 1461 → 1341 → 1461, a DATA_FRAG-sized packet crossed the IPv6 leg, and each commit left exactly
> one active qeli-owned `/32` or `/128`. Generation-scoped A/AAAA discovery now survives exact
> active-peer pinning only for a future authenticated PathUpdate; the bypass and bonded carriers
> remain restricted to the committed peer.
> A deliberate bidirectional DATA_FRAG-loss Linux gate passed 25/25. With both paths at outer MTU
> 1280, the firewall dropped exactly the first full-size fragment of each 1350-byte record while
> admitting its tail; neither incomplete record reached the TUN. Path B committed without another
> AUTH, PID/TUN replacement, or reconnect. After the five-second reassembly timeout and removal of
> old path A, later fragmented records completed in both directions. A focused unit regression pins
> expiry of the stale record before allocating and completing its replacement.
> A deterministic same-network NAT dead-mapping Linux gate passed 21/21. Stateless translation moved
> the server-observed peer from `10.41.3.1` to `10.41.3.254` while the client interface, local address,
> default/carrier routes, endpoint, PID, and TUN remained unchanged. Authenticated RX silence requested
> one bounded `SameNetworkNatFailure` PathUpdate for the active epoch; the observer retained sole
> ownership of path observation and update IDs, and the candidate committed exactly once without a
> second AUTH or reconnect. The one-attempt/grace/fallback policy now lives in the shared Rust core;
> platform controllers only expose a bounded request for a fresh same-path snapshot. ABI 1.13 now
> carries that request to Android as a no-payload, generation-scoped `PATH_REFRESH` event. Kotlin
> returns a `SameNetworkNatFailure` snapshot of the unchanged `Network` and owns no retry timer;
> the shared Rust policy still owns the one attempt, 15-second grace and reconnect fallback.
> Source/JVM regressions and the complete API 34 feature-APK UDP emulator NAT-rebinding matrix are
> complete. For fake-TLS, QUIC, obfs and obfs-AWG, a bidirectionally dead old 5-tuple produced
> `PATH_REFRESH`, `PATH_CHALLENGE` and `PATH_COMMIT` on a new source port without a second AUTH,
> NetworkPlan, process/TUN replacement or reconnect. The Android `Network` handle remained
> unchanged and tunnel ping passed 5/5 before and after migration in every mode. Real-device
> NAT-rebinding remains a separate gate.
> The shared feature core is Windows socket-handle ready: `PATH_COMMAND` carries a borrowed signed
> 64-bit Unix descriptor or Windows `SOCKET`, while native TCP candidate dialing and the common UDP
> migration actor both compile on Windows. The shared C# adapter implements the optional ABI
> 1.12/1.13 path-update/result bindings and a strict bounded JSON contract for correlated
> PREPARE/BIND/COMMIT/ABORT and no-payload PATH_REFRESH events. Conformance tests reject unknown
> fields, stale generations and incompatible address families, and preserve Windows socket values
> wider than `Int32`.
> The Windows C# adapter now executes the serialized path transaction. PREPARE installs only
> exact-interface, exact-source `/32` or `/128` candidate routes and expands the kill switch and
> WinDivert carrier allow-set to old+new. BIND applies `IP_UNICAST_IF`/`IPV6_UNICAST_IF` to the
> borrowed 64-bit `SOCKET` and binds the selected local address before the Rust core connects it.
> COMMIT transfers the candidate routes into session cleanup, removes only stale Qeli-owned carrier
> rows, and narrows policy to the new path; ABORT removes candidate state and restores the old path.
> Ordinary TCP and every supported UDP camouflage profile share this executor. Explicit `local` or
> `lport`, a default/old core, or an unsupported peer retain the existing reconnect fallback.
> Shared and Windows desktop builds and managed route/socket/policy self-tests pass without warnings.
> Windows real-device, race, kill-switch and soak acceptance remains required before rollout.
> The macOS C# adapter now executes the same serialized path transaction for ordinary TCP and every
> supported UDP camouflage profile. PREPARE validates an exact live physical interface/source and
> creates only exact Darwin `RTF_IFSCOPE` carrier routes while preserving operator-owned routes.
> BIND applies `IP_BOUND_IF` or `IPV6_BOUND_IF` and the selected source address to the borrowed fd
> before Rust connects it. COMMIT retains the scoped route for the migrated socket, transactionally
> switches Qeli's ordinary host route for later bonded TCP repair, and narrows PF from old+new to the
> new carrier set; ABORT removes only candidate-owned state and restores the old PF set. Disconnect
> retries candidate cleanup and restores both committed Qeli routes and any pre-existing operator
> route. Explicit `local`/`lport`, a default/old core, or an unsupported peer retain reconnect.
> The cross-platform Release build and macOS route/socket/capability self-tests pass without
> warnings. Live macOS route-command, PF, per-app, device/race and sleep/soak acceptance is still
> required before rollout; no live macOS result is claimed by this source-only gate.
> The shared Linux exit-node roaming gate passed TCP 35/35 and a 4/4 UDP matrix: `quic`, `fake-tls`,
> `obfs`, and `obfs-awg` each passed 35/35. A real full-tunnel consumer sent
> traffic through server → exit → WAN A, then the exit's authenticated carrier and physical default
> moved to WAN B without a repeated full AUTH, PID/TUN replacement, or top-level reconnect. The
> exactly two initial full AUTHs belong to the exit and consumer; that count did not change after
> handover. Exact
> MARK/MASQUERADE/FORWARD rules and NAT counters were verified on both WANs; the previous generation
> remained available for fail-safe drain. After the exit process completed SIGTERM cleanup, rules
> for both generations were absent and the original `ip_forward`/`rp_filter` values were restored.
> Exit WAN ownership is now keyed by TUN, so an ordinary sibling profile in the same daemon cannot
> acquire exit rules. IPv4 and IPv6 refresh their actual default uplinks independently instead of
> assuming that either matches the qeli carrier interface. The gate isolates its identity, TOFU,
> device-id, and control socket state inside its work directory; TCP and all UDP camouflage modes
> exercise the same exit-node COMMIT path.
> Current lab gates pass 972 feature library tests with three ignored,
> 881 default tests with one ignored, strict default/feature Clippy, base Linux netns 26/26,
> exit-node TCP 35/35 and four UDP modes at 35/35 each, and a six-mode TCP matrix with
> `reality-tls` at 19/19 and the other five modes at 15/15 each,
> UDP roaming success 17/17, rollback 20/20, supersede 24/24, commit-race 24/24,
> control-loss/replay 18/18, symmetric IPv4 PMTU 19/19, asymmetric IPv4 PMTU 19/19, and
> receive-drain/reorder/duplicate 26/26, outer-family round-trip 32/32, DATA_FRAG-loss 25/25, and
> same-network NAT dead-mapping 21/21, an Android x86_64 NDK
> release with `-D warnings`, and Gradle unit/assemble. The full platform/race/soak matrix is still a release gate. Target: 0.8.x.**
> The TCP matrix covers `fake-tls`, `reality-tls`, `plain`, `obfs-ws`, `obfs-none`, and `obfs-awg`
> through one runner. The REALITY slice uses a genuine local TLS target and verifies the borrowed
> TLS shape/certificate chain, transparent decoy bridge, exact pinned identity, and genuine HTTP/2
> carrier before exercising the same make-before-break handover.
> A dedicated `roaming_wire` fuzz target now exercises arbitrary UDP CID headers, TCP resume
> JOIN/proofs, and PATH control bodies plus canonical round trips and a tampered-proof path. It is
> part of both the blocking CI smoke loop and the persisted-corpus nightly matrix. A lab
> ASan/libFuzzer smoke completed 1,324,437 runs in 31 seconds at coverage 515, corpus 22, and
> 371 MiB peak RSS without a crash or sanitizer finding.
> Every live Linux TCP/UDP netns profile explicitly enables the server rollout and uses client
> `required`, so reconnect fallback cannot produce a green migration gate. Split UDP case helpers
> are loaded fail-closed; a missing helper is a verified `rc=2`, never a false `0 failed` result.
> Client `off|auto|required` policy, transport-specific capability negotiation, and flat-INI/
> `qeli://` round-trip are now source-complete in Rust, Kotlin, C#, and Swift. `off` cannot enter
> TCP resume/handover, every UDP camouflage mode uses the same policy gate, and `required` fails
> closed before credentials/full AUTH. All four client GUIs and the profile-scoped server panel/API
> controls, worker-lifetime server metrics/logging, and explicit safe packaged examples are complete.
> Phase 5 is source-complete, while Phase 6 device/soak gates remain open.
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
| **UDP** (fake-TLS / QUIC masking / obfs / AWG) | Fully seamless after `UDP_ROAM_V1 + DATA_FRAG_V1` negotiation | All modes switch after AuthOK to one directional-CID envelope; PATH_CHALLENGE/PATH_RESPONSE validation commits the peer address |
| **TCP** (reality-tls / fake-tls / obfs / plain) | Seamless with make-before-break; otherwise a short gap | Multipath JOIN over the new network *before* the old dies; fallback — grace + JOIN-resume |
| **raw plain** | TCP only | The current protocol has no separate raw-plain UDP profile |

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

Today the legacy QUIC-masked mode picks one stable four-byte CID, while unmasked fake-TLS/obfs
has no pre-auth CID. In either case the server demuxes an established legacy session by source
`SocketAddr`; an address change is a map miss and causes a full handshake.

Change: after authenticated `UDP_ROAM_V1` negotiation every UDP camouflage mode atomically switches
to the same rotating eight-byte destination-CID envelope. It sits outside the session PacketCodec,
because the server has to identify the session before selecting that session key, but inside any
profile-wide UDP obfs transform: fake-TLS and QUIC masking expose the CID-shaped header, whereas
obfs/AWG seals it with the profile obfs key before it reaches the physical wire. Its flags retain
the ordinary QUIC-short shape, but this roaming demux envelope does not require the legacy `quic`
masking option and adds no fixed qeli-specific marker. On an
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
**8 bytes wide** (vs today's 4) — for collision safety; this is a wire change to the negotiated
roaming header ([protocol/roaming.rs](../../../qeli/src/protocol/roaming.rs)). Every UDP mode uses
it only after mutual authenticated capability opt-in; legacy sessions remain byte-for-byte
unchanged (real QUIC CIDs may be up to 20 bytes).

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
- `handle_udp_datagram`: (1) lookup by address — as today; (2) miss + valid roaming short header →
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
  and a global observer correlates by timing/volume. This residual is now documented in
  `THREAT-MODEL.md`; CID rotation is not presented as an anonymity guarantee.
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
- **e2e on the lab (.10/.11):** a script flips the client's src-addr mid-flow.
  `roaming_udp_all_modes_netns_e2e.sh` runs the same success gate for QUIC, fake-TLS, obfs, and
  obfs+AWG; each must retain the session with zero reconnects. TCP uses make-before-break with
  two live networks and JOIN-resume <grace on a hard handover; measure gap/loss/"Argon2 skipped".
- **Regression:** throughput unchanged (the CID lookup runs only on an address miss,
  not per packet).

## 7. Phasing

No production stage may expose roaming without authenticated JOIN proof, path validation,
anti-amplification, PMTU reset, and bounded DATA_FRAG/reassembly.

- **Phase 0 — ✅ source complete:** capabilities, CONTROL_V2, KDF labels, proofs, wire
  limits, and KATs are frozen behind the default-off feature gate.
- **Phase 1 — ✅ source complete:** ABI 1.12 provides bounded generation-scoped
  PathUpdate plus PREPARE/BIND/COMMIT/ABORT, V3 roaming telemetry, strict correlation,
  lifecycle cleanup, and mock fault injection. ABI 1.13 adds the capability-gated same-path
  refresh request without changing the fixed event/stats prefixes. Linux handles it in-process;
  Android returns a snapshot of the unchanged `Network`. Other native adapters do not advertise
  the bit and retain reconnect fallback.
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
  local path. Android enables `ROAMING_PATH` for feature TCP and all UDP modes, and advertises
  `PATH_REFRESH` only when an ABI 1.13 core exposes the matching core capability.
  Windows, macOS and iOS advertise both path capabilities for ordinary profiles when the feature
  core exposes the matching ABI. On iOS, `NWPathMonitor`, interface-scoped endpoint resolution,
  Darwin socket binding and exact carrier `excludedRoutes` execute the same transaction. Explicit
  `local`/non-zero `lport`, default/old cores and unsupported peers retain reconnect fallback.

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

  Real devices, platform-specific same-network NAT rebinding, Windows/macOS/iOS device/race
  acceptance, iOS Xcode/NetworkExtension compilation, and the broader
  transport/family/NAT64/per-app/race/soak matrix remain.
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
  these invariants; strict feature Clippy and the full feature library suite (943 passed, three
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

  The common client actor now constructs epoch-zero roaming state immediately after AuthOK and
  atomically selects one post-auth framing snapshot. Ordinary data, DATA_FRAG, recordizer output,
  heartbeat/cover, authenticated reports, startup/live PMTU probes and both PMTU ACK directions all
  use that same snapshot. Roaming ingress requires the exact server-to-client CID before consuming
  PacketCodec/replay state; egress uses the client-to-server CID. The data-fragment and PMTU budgets
  subtract the actual 13-byte roaming header instead of the legacy nine-byte header. Legacy masked
  and unmasked paths remain byte-for-byte compatible. Three focused framing tests cover passthrough,
  legacy compatibility and directional-CID rejection.

  Behind `experimental-roaming`, the live UDP actor now consumes a prepared `PathUpdate`, performs
  exact BIND-before-connect through the shared Unix candidate dialer, and starts a separate bounded
  receive pump for the candidate. PATH_INIT and bounded retries use the shared PacketCodec; only
  authenticated PATH_CHALLENGE/PATH_COMMIT/PATH_ABORT with exact CID, message id, and epoch can
  advance the state machine. After peer PATH_COMMIT, the actor first awaits the exact platform
  `COMMIT_PATH` acknowledgement and then publishes the new socket, receive pump, directional CID
  framing, and conservative family-aware PMTU/record budget in one actor transaction. Already queued
  old-epoch packets are rejected, while candidate DATA cannot become active before the new epoch is
  published. Expiry, send failure, peer abort, and teardown release the socket and issue the exact
  platform ABORT. Because the server has already switched by the time PATH_COMMIT is received, any
  local failure after it terminates the actor for a fail-closed full reconnect instead of pretending
  the old path is usable. A focused test pins candidate-to-active receive classification and stale
  epoch rejection; strict default and feature Clippy, the default suite at 871 passed/1 ignored, and
  the feature suite at 952 passed/3 ignored all pass.

  `UDP_ROAM_V1` now activates in `experimental-roaming` for every UDP camouflage mode when the
  server advertises the same bit, authenticated `DATA_FRAG_V1` is present, and the platform provides
  complete `ROAMING_PATH`. Linux and Android no longer duplicate a QUIC-only platform gate; a
  live four-mode matrix passed QUIC, fake-TLS, obfs, and obfs+AWG: 4/4 modes and 68/68 checks
  retained PID, TUN, and the authenticated session without top-level reconnect. Fixed-source,
  legacy peers, and default builds retain reconnect behavior. The
  original isolated two-path Linux UDP+QUIC netns e2e passed 17/17 with old-path removal and no PID/TUN replacement or top-level reconnect;
  its paired rollback case passed 20/20 with a path-B-only blackhole, bounded expiry, exact platform
  ABORT, and the carrier `/32`, PID/TUN, and traffic retained on path A without reconnect. A three-path
  supersede gate passed 24/24: B crossed BIND/PATH_INIT, exact ABORT of that old candidate preceded
  PREPARE C, the actor rejected late B proof, and exactly one C commit was published. Adversarial late-
  control and commit linearization now have their first completed race slice. The shared client state
  machine rejects an old message-id challenge/commit after ABORT and stale platform completion cannot
  mutate its replacement. A path transaction may replace only a truly unobserved PREPARE without ABORT;
  an unobserved BIND already follows applied PREPARE state and therefore requires exact ABORT. Once
  COMMIT starts, only the latest new PathUpdate is queued behind its linearized ACK because the server
  may already have switched. The Linux in-process executor serializes emit/consume/OS mutation so a
  concurrent detector cannot steal BIND/COMMIT. Its deterministic live commit-race passed 24/24 with
  exact B→C order, two single commits, unchanged PID/TUN, and no reconnect. The first packet-loss
  slice is also complete: a fixed-length firewall gate dropped exactly the first PATH_CHALLENGE and
  PATH_COMMIT, fresh encrypted retries recovered both, and the 18/18 live gate retained PID/TUN and
  published one commit. The symmetric and asymmetric Linux IPv4 PMTU slices are now complete as well.
  Negotiated bare PMTU control is consumed before PacketCodec decoding only after the directional CID
  resolves the session and the exact committed epoch, receiving socket, and peer match; candidate paths
  remain restricted to authenticated PATH control. Epoch-zero probing certified 1461-byte payload
  budgets in both directions. A bidirectional MTU-1280 carrier independently re-certified 1161 bytes
  in both directions while retaining inner MTU 1400 and carrying a 1350-byte DATA_FRAG payload. On the
  asymmetric gate, C2S stayed at 1461 while an S2C-only 1280 blackhole forced the server down the same
  shared ladder to 1161; a 1350-byte reverse payload crossed through DATA_FRAG. One exact pending marker
  spans the whole descent, so duplicate reports cannot start another scheduler and an epoch/peer change
  cancels it. The Linux IPv4 in-flight receive-drain slice is complete as well. After PATH_COMMIT,
  the exact immediately previous epoch/peer/socket/CID remains receive-only for one DATA_FRAG
  reassembly timeout; old path control and PMTU remain rejected, and expiry releases the old receive
  task/socket snapshot. A deterministic 26/26 gate used MTU 1280 and three-second gap reordering in
  both directions on old path A, committed B while both 1350-byte records were incomplete, then
  completed both records through the bounded drain. Duplicate DATA_FRAG on active B remained
  idempotent, with the same PID/TUN and no reconnect. The Linux outer-family slice is complete too:
  a deterministic dual-listener 32/32 gate moved one authenticated session IPv4 → IPv6 → IPv4,
  retained the codec owner/PID/TUN, re-certified both directions at 1461 → 1341 → 1461, carried a
  DATA_FRAG-sized packet, and removed the stale qeli-owned route after each commit. Continuous traffic
  retained at least 245 of 260 probes without top-level reconnect. The deliberate DATA_FRAG-loss
  slice is complete too: a 25/25 gate dropped one full-size fragment in each direction while retaining
  each tail, committed path B with both records incomplete, then completed new fragmented records in
  both directions after the five-second reassembly timeout and removal of path A. PID/TUN and the
  authenticated session remained unchanged and no reconnect occurred. The deterministic Linux
  same-network NAT dead-mapping slice is complete too: a 21/21 stateless-translation gate changed
  only the server-observed external peer, kept the client path/PID/TUN/session unchanged, emitted one
  `SameNetworkNatFailure` update after authenticated RX silence, and committed one candidate without
  another AUTH or reconnect. Its request/wait/grace/fallback policy is shared Rust state; platform
  controllers supply only a bounded same-path snapshot hook and retain ownership of update IDs.
  Real-device NAT-rebinding and soak gates remain. The Phase 4 Linux/OpenWrt
  adapter now consumes the shared ordered family-compatible candidate projection: a physical path must have
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
  source-aware FIB lookup; a later IPv4/IPv6 failure restores earlier routes in reverse order. Once
  the new route is usable, COMMIT retires only previous qeli-owned carriers absent from the desired
  family set; a retirement failure rolls back the new route and restores already retired routes and
  journal ownership. Active pinning and generation-scoped A/AAAA discovery are separate: alternatives
  remain eligible only for a future authenticated candidate transaction and never enter the active
  bypass or bonded set early. Every TCP wire mode (`reality-tls`, `obfs`, `fake-tls`, `plain`)
  now creates a separate unbound candidate socket, receives BIND acknowledgement before connect, and
  uses only the first compatible address from that PathUpdate. After authenticated JOIN, COMMIT applies
  routes first and only then publishes the new pinned carrier-address set for later bonded streams. An
  unprivileged regression proves that the dialer ignores an intentionally unreachable configured address,
  connects to the candidate address, and binds before connect. Linux observation, capability activation,
  and initial live acceptance are complete. Android TCP exact-Network DNS/bind/protect,
  PREPARE/BIND/COMMIT/ABORT, stale/supersede guards, and Wi-Fi↔cellular plus sleep/wake emulator
  acceptance are complete. The Android source adapter now exposes that same transaction for every
  UDP mode and answers a core-requested same-network NAT refresh without owning retry/fallback policy.
  The complete UDP API 34 feature-APK gate covers fake-TLS, QUIC, obfs and obfs-AWG with a
  same-Network, same-session NAT rebind and no AUTH/reconnect; real-device UDP/NAT-rebinding remains
  pending.
  A repeat gate after a clean build of the current feature core and APK `0.8.0` (`versionCode=720`,
  SHA-256 `710185c288ac0d19e1adfd843d409d8f450270239a5bd241dd91764d996d9ead`) again passed all
  44/44 invariants across the four modes: a new UDP source port, exactly one AUTH and NetworkPlan,
  unchanged application PID/TUN, and 5/5 tunnel ping both before and after commit.
  The native candidate contract now preserves a borrowed signed 64-bit Unix descriptor or Windows
  `SOCKET`, and the same UDP migration actor compiles on Windows. Strict Windows-host and Linux
  all-target feature checks pass; the Windows/macOS C# and iOS Swift path executors are
  source-complete and their live acceptance remains pending. The iOS adapter observes only physical
  `NWPathMonitor` paths, resolves an effective local/remote endpoint on the selected interface,
  protects old+new then new-only carrier addresses with exact NetworkExtension excluded routes,
  binds the borrowed descriptor with Darwin interface/source options and ACKs the same shared
  PREPARE/BIND/COMMIT/ABORT commands used by ordinary TCP and all UDP modes. The feature Rust slice
  passes strict `aarch64-apple-ios` cross-target Clippy; Xcode 16 compilation and physical-device
  Wi-Fi/cellular, wake, NAT64, rollback, per-app/MDM and soak gates remain.
  Linux IPv4 packet delay/reorder/duplicate
  and in-flight receive-drain acceptance, the Linux IPv4↔IPv6 PMTU round-trip, and deliberate
  bidirectional DATA_FRAG-loss are complete. Deterministic Linux same-network NAT dead-mapping is
  accepted in netns. Linux exit-node acceptance is complete for TCP and every UDP camouflage mode;
  real-device race/soak/NAT-rebinding and Windows/macOS/iOS acceptance remain.
- **Phase 4 — 🟡:** Linux/OpenWrt and Android TCP feature adapters are complete at initial
  live-acceptance level; Android UDP is source-complete and its complete emulator NAT-rebinding
  matrix is accepted. Linux exit-node TCP and all-UDP acceptance is complete. The Windows shared
  core plus Windows/macOS/iOS path executors are source-complete; desktop/iOS device and race
  acceptance, iOS Xcode compilation, and real-device soak/NAT-rebinding remain.
- **Phase 5 — 🟢 source-complete:** flat-INI, non-default `qeli://` sharing,
  and all four client models/editors are complete. Windows/macOS/Android/iOS expose
  `Auto / Required / Off`, persist it through their shared platform model, and reject `required`
  with a hidden source pin. The server panel/API exposes the profile-scoped default-off rollout
  switch, grace period, and bounded orphan session/memory budgets. Read-only control/status and
  the transport-aware dashboard expose worker-lifetime attempts, commits, final failures, TCP grace
  expiry, and pending paths without identifiers or secrets. Every shipped server profile explicitly
  retains the safe default-off budgets, and every client template explicitly selects `auto`, including
  the multiprofile installer source, Reality release files, Keenetic, and OpkgTun.
- **Phase 6:** full lab matrix, soak, canary profiles, staged rollout, and legacy fallback. A
  configurable same-session harness now defaults to 10,000 sequential A/B commits for both TCP and
  every UDP camouflage mode. It checks PID/TUN, AUTH/reconnect, exact routes, independent client/server
  commit counts, fd, and sampled RSS. The 100-migration TCP and all four UDP wire-mode harness
  smokes pass while retaining one authenticated session. The representative Linux TAP gate passes
  TCP fake-TLS 17/17 and UDP QUIC 19/19 while preserving the same TAP, process, and authenticated
  session across the handover; the default TUN regression passes the same 17/17 and 19/19. Both
  device types use the same TCP/UDP roaming state machines and the harness verifies their actual
  kernel kind. The TCP harness also covers `max_streams=1`, fixed bonding, and adaptive bonding.
  A live regression exposed old secondary writers that kept accepting flow-pinned packets after
  slot 0 moved; path COMMIT now retires the complete old carrier set and the shared stable-slot
  maintainer rebuilds the learned width through the committed route. Single passes 17/17, fixed
  passes 21/21, and adaptive passes 22/22 after growing to three streams under real tunnel load;
  restored secondary JOINs originate from path B and the session/TUN survive without reconnect.
  The feature suite passes 973 tests with three ignored, and strict feature/default Clippy passes.
  The UDP all-modes wrapper forwards the same selected case, including `soak`, through
  QUIC, fake-TLS, obfs, and obfs+AWG. A live
  0.8.0↔0.7.14 binary matrix passes 24/24 TCP/UDP checks: current server with legacy client and
  legacy server with current `auto` carry traffic after one full AUTH without entering roaming,
  while current `required` remains pre-TUN and pre-full-AUTH across retries. The full 10k and
  platform gates remain open.

## 8. Compatibility / rollout
Each roaming feature is negotiated through the existing authenticated capability trailer.
A feature-enabled server advertises only implemented server bits, and a session enters the TCP
roaming lifecycle only after the authenticated client extension opts in. Legacy peers keep the
normal full-reconnect path, so rollout does not require a lockstep server/client upgrade.
A source regression now pins this for both TCP and UDP against both an absent capability trailer
and a pre-`AUTH_EXT_V1` peer: `auto` keeps legacy AUTH, while `required` fails before credentials/
full AUTH. The live netns matrix additionally validates the actual 0.8.0 and 0.7.14 binaries in both
server/client directions for TCP and UDP. All compatible pairs establish a TUN, carry traffic, and
perform exactly one full AUTH without negotiating roaming; `required` against the legacy server
remains fail-closed before the TUN and full AUTH even while the headless CLI retries.
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
