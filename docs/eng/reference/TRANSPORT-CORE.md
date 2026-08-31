# qeli — a shared transport core in Rust for every client

Proposal and plan: move connection setup, transport selection, the handshake, roaming,
multipath, automatic fallback and configuration handling into **one** Rust core, linked
into every client over FFI. Platform code keeps the TUN, the UI, notifications and system
APIs.

The format is a working checklist in the style of [REFACTOR-PLAN.md](../archive/plans/REFACTOR-PLAN.md):
every item has an ID, a size, an approach and an **acceptance criterion**.

Status legend: ⬜ not started · 🟦 in progress · ✅ done · 🧪 awaiting build/e2e.

**Initiative status: ✅ source refactor complete.** All production clients use the shared
Rust transport core; the current source API is additive ABI 1.15. ABI 1.15 adds typed server
`NOTICE`/`KICK` events and the `MANAGEMENT_EVENTS` capability without changing the fixed event
header or export counts. The committed `.so`/`.dll`/`.dylib` files are still the last certified
ABI 1.14 set; they must be rebuilt from the final 0.8.0 commit before packaging. Final
applications still have to pass signing/platform/E2E gates. Remaining acceptance gates include
administrator Wintun full-tunnel, live macOS utun, and physical-device iOS/Xcode.
Written 2026-07-30; native-core status refreshed 2026-08-31.
**Reality/H2 delivery rule.** The current `reality-tls` H2 carrier is owned by this common Rust
core, not by platform UI code. A platform receives it only when its native `.so`/`.dll`/`.dylib`
or XCFramework is rebuilt from the updated source, packaged into the app and installed. A server
upgrade cannot make an already installed client inherit the new wire implementation.

ABI 1.10 extended statistics while preserving the 64-byte V1 prefix. ABI 1.11 adds the
dual-family NetworkPlan/platform-capability contract without changing those prefixes. The fields expose
UDP kernel drops, internal bounded-queue drops, receive-buffer grow events and the size the OS
actually granted. With no size key, the shared controller starts at 4 MiB and grows
4→8→16 MiB only on local overflow or a measured rate/stall budget; an explicit size remains
fixed and `0` leaves the OS setting alone.

ABI 1.12 adds a gated `experimental-roaming` candidate-path transaction: a bounded,
generation-scoped `PathUpdate`, `PREPARE/BIND/COMMIT/ABORT` commands, strict
generation/candidate/sequence correlation, and a 144-byte V3 statistics layout. The 64/96-byte
V1/V2 prefixes remain compatible. ABI 1.13 adds the optional no-payload, generation-scoped
`PATH_REFRESH` event and matching core/platform capability bits. The shared core owns request rate,
grace time and reconnect fallback; a capable adapter only returns a fresh same-path `PathUpdate`.
Linux handles that request in-process, while Android re-snapshots its unchanged `Network`. Adapters
that do not advertise the new platform bit never receive the event. ABI 1.14 adds three explicit
path-command outcomes: accepted, rollback-safe rejected, and platform-state-unknown. The last one
is reserved for an incomplete internal rollback; it terminates the current generation without a
stale `ABORT_PATH`. Path transactions are capability-gated off when a desktop, Android, or iOS
adapter loads a pre-1.14 core. ABI 1.15 adds negotiated, bounded server `NOTICE` and terminal
`KICK` events; older peers do not advertise `MANAGEMENT_V1` and keep their previous behaviour.
The fixed 48-byte event header, statistics prefixes and export counts remain unchanged.

---

## 1. The verdict: what justifies this, and what does not

**Justified by implementation divergence. Not justified by speed.**

Worth settling before any work starts, because the stated goal decides how success is
measured. Selling this as "make the clients faster" is not supportable: the measurement
(§2) shows the client data plane is nowhere near being the constraint.

**The risk is already proven.** The **M6** fix (deterministic nonce via a PRP) shipped in
three implementations out of four and **silently skipped Android**. That is a divergence
in cryptography, not in the UI, and it was only found because cross-language KAT vectors
were built specifically to look for it (`conformance/`). Four independent implementations
of one protocol are a standing source of such defects, and the cost of getting one wrong
is not measured in megabits.

Where speed *is* an argument — where the unit is cycles, not megabits:

- **mobile clients** — 2.4× fewer cycles per byte plus no GC pressure (see §2: C#
  allocates 2.3 GB to move 280 MB) — that is battery and responsiveness;
- **weak targets** — the router port ([KEENETIC-PORT.md](KEENETIC-PORT.md)), where there
  is no managed runtime at all.

---

## 2. The measurement behind the verdict

Run 2026-07-30. Both implementations **on the same CPU**, 200,000 packets of 1400 B,
single-threaded, padding disabled on both sides. Like was compared with like:
`PacketCodec` (framing + AEAD), and the AEAD on its own.

**Rig A — the lab (QEMU Virtual CPU, 2 cores; has `aes`, `ssse3`, `sse4_2`; no AVX2):**

| What | MB/s | ≈ Mbps |
|---|---|---|
| C# `PacketCodec` encrypt | 81.9 | 687 |
| C# `PacketCodec` decrypt | 133.1 | 1117 |
| **Rust `PacketCodec` encrypt** | **208.4** | **1749** |
| **Rust `PacketCodec` decrypt** | **317.5** | **2664** |
| AEAD BouncyCastle (fresh instance per packet) | 169.7 | — |
| AEAD .NET built-in (reused) | 226.5 | — |
| **AEAD Rust (reused)** | **410.3** | — |

Allocation over the run: C# — **2311 MB to move 280 MB of payload** (an 8× amplification),
309 gen0 collections. Rust has no GC.

**Rig B — real hardware (Intel i5-14600KF), C# only:** encrypt 158.7 MB/s (1331 Mbps),
decrypt 225.4 MB/s, BouncyCastle AEAD 315.1 MB/s.

### What follows

1. **The Rust core is 2.4–2.5× faster** — and that is a **lower bound**: rig A has no
   AVX2, and Rust's ChaCha20 has an AVX2 backend while BouncyCastle is scalar regardless.
2. **There is no cheap "just optimise the C#" alternative on Windows.** .NET's built-in
   `ChaCha20Poly1305` reports `IsSupported = False` there (Windows CNG does not provide
   it) — verified on rig B. On Linux it exists and beats BouncyCastle by 33%, but the main
   desktop client stays on managed BouncyCastle. That is most likely why it was chosen.
3. **Speed constrains nothing today.** Even the C# client pushes ~1.3 Gbps encrypting,
   against a production server ceiling of ~311 Mbps (one-core bound, see
   [BENCHMARK.md](../reports/BENCHMARK.md)).
4. **Client crypto is not uniform.** Android encrypts with native Conscrypt (BoringSSL),
   C# with managed BouncyCastle. "Managed" is not one category, and Android will gain
   noticeably less from the move than Windows/macOS.

> The original benches were one-off. In 0.7.15 they were replaced by permanent release-mode
> Rust/C# harnesses and CI gates; commands and bounds are documented in **TC-0.3** below.

### Performance resume point: `b6e0796`

A reproducible checkpoint was recorded on the 2-vCPU lab before platform refactoring
continues. TCP fake-TLS reached 468.7 up / 700.6 down Mbps with zero session drops. One UDP
flow produced: 300 Mbps at 0.06% loss, 400 Mbps at 1.86%, and 500 Mbps at 8.27%; on the last
step the server counted 745 kernel receive-buffer errors against 21,554 lost iperf datagrams,
with no internal session drops. These are a baseline for the next measurement cycle, not
release promises.

Buffer and throughput work resumes **from commit `b6e0796`**, separately from the current
ABI/TUN changes. The next cycle first adds client-side UDP send/drop and qdisc counters, then
examines one-flow affinity to one `SO_REUSEPORT` worker and the sequential
unwrap/decrypt/ACL/TUN segment. Only after localisation should the fixed benchmark sweep the
4-MiB budget, pool slot size/count and bounded-queue depths; blindly raising limits without
counters does not count as a fix. The permanent Rust/C# `PacketCodec` benchmarks from TC-0.3
now provide a micro-level guard for this cycle, but do not replace the end-to-end lab baseline.

---

## 3. What is duplicated today

Counted by file, excluding tests and build artefacts (2026-07-30):

This is the pre-migration baseline; TC-3/TC-5 below record the actual deletions and current state.

| Codebase | Total lines | Of which protocol/transport core |
|---|---|---|
| `qeli-shared` (C#, shared by Windows and macOS) | 7,627 | ~6,200 |
| `qeli-android` (Kotlin) | 8,469 | ~5,200 |
| `qeli-ios` (Swift) | 10,668 | ~5,700 |
| **Duplicated total** | | **~17,000** |

Plus ~930 lines of conformance scaffolding in C# and ~250 each in Kotlin/Swift, which
existed **only** because there were four implementations.

The largest sites of duplication:

| File | Lines | What it does |
|---|---|---|
| `qeli-android/.../QeliService.kt` | 3,162 | VpnService + connection + transport |
| `qeli-shared/.../Vpn/VpnTunnelBase.cs` | 2,866 | connection, handshake, transport, reconnect |
| removed iOS QeliTunnelEngine.swift | 1,436 | the same for iOS at the baseline |
| `qeli-shared/.../Model/VpnConfig.cs` | 1,060 | configuration handling |
| `qeli-android/.../model/Config.kt` | 929 | the same |
| `qeli-ios/QeliCore/Model/VPNConfig.swift` | 733 | the same |

For comparison the Rust side (already exists, already shared with the server): `client/`
7,609, `protocol/` 11,514, `config/` 6,682, `crypto/` 1,879. **The core needs almost no
new code — it needs a new consumer.**

---

## 4. Where the boundary goes

### 4.1. What already exists

The FFI does not need inventing — it exists, but it is narrow:
`qeli/src/protocol/realtls/ffi.rs` (474 lines) and `jni.rs` (372) export a **sans-io**
realtls core: `qeli_realtls_new/recv/seal/open/free`, `qeli_mlkem_*`,
`qeli_build_faketls_clienthello`.

Two consequences:

- **The FFI cost is already paid and already tolerated.** In reality-tls mode Windows,
  macOS and Android call Rust **on every TLS record** — that is a production mode.
- **The current contract must not be carried onto the data plane as it stands.**
  `qeli_realtls_seal` does `Box::into_raw` and requires a matching `qeli_realtls_buf_free`
  — an **allocation, a free and a copy per record**. At data-plane rates that is not
  acceptable (see TC-1.2).

### 4.2. Who owns the TUN — the real question, and the real cost driver

The right cut is **the core owns the socket and the TUN**. Then packets never cross the
FFI at all and the boundary becomes a control plane. It all hinges on whether the platform
hands out a descriptor:

| Platform | What the OS gives | FFI crossings per packet |
|---|---|---|
| Android | `VpnService.establish()` → fd | **none** (needs a `protect(socket)` upcall) |
| macOS | utun fd | **none** |
| Windows | Wintun (ring buffer) | **none**, if Rust owns the ring |
| iOS | `NEPacketTunnelProvider.packetFlow` — **no descriptor** | yes, but **in batches** |

Cost estimate for iOS: at 100 Mbps with 1400 B that is ~9,000 packets/s; `readPackets`
delivers them in batches of ~30 → ~300 calls/s. Negligible.

**The original binding constraint:** `qeli/src/tun/` was **335 Linux-only lines**
(`/dev/net/tun`, `#[cfg(target_os = "linux")]`). The common core fd pump now also serves
Android and macOS utun; Wintun now has a dedicated Rust backend, while iOS is the only
platform whose `packetFlow` API must cross the language boundary in batches.

### 4.3. What does NOT go into the core

Kill-switch, route programming, DNS, autostart, notifications, UI, permission flows.
These are platform APIs, and that is exactly where platform-specific defects have been
caught (both kill-switch bugs in 0.7.14 came from this area).

The contract: **the core emits a plan, the platform executes it.** The core says "install
these routes, this DNS, raise the kill-switch" — the platform brings the system to that
state and reports back.

---

## 5. Transport API

### 5.1. Implemented control-plane ABI 1.x

The public contract lives in `qeli/include/qeli_transport_core.h`, with the implementation
in `qeli/src/transport_core/`. The opt-in `transport-core-ffi` feature inherits the mandatory
FFI `panic = "unwind"` contract.

```text
qeli_client_abi_version()                                      -> 0x0001000C
qeli_client_core_capabilities()                                -> bitmask
qeli_client_udp_probe(config, len, timeout_ms, *latency_ms)     -> rc  // ABI 1.8
qeli_client_new(config, len, platform_caps, queue_cap, *handle) -> rc
qeli_client_start(handle)                                      -> rc
qeli_client_run(handle, json, len)                             -> rc  // ABI 1.6, blocking
qeli_client_stop(handle)                                       -> rc
qeli_client_set_device_id(handle, id, 16)                      -> rc  // ABI 1.3
qeli_client_publish_handshake_network(handle, json, len, *gen) -> rc  // ABI 1.5
qeli_client_set_tun_fd(handle, generation, fd)                 -> rc  // ABI 1.1
qeli_client_set_wintun_adapter(handle, generation, name, len)  -> rc  // ABI 1.9
qeli_client_poll_event(handle, *event, payload, cap, *needed)   -> rc
qeli_client_network_plan_result(handle, generation, rc, reason) -> rc
qeli_client_path_update(handle, json, len, *candidate)          -> rc  // ABI 1.12
qeli_client_path_command_result(handle, generation, candidate, sequence, rc, reason) -> rc  // ABI 1.12
qeli_client_socket_protect_result(handle, sequence, rc, reason) -> rc  // ABI 1.2
qeli_client_server_identity_result(handle, sequence, rc, reason)-> rc  // ABI 1.4
qeli_client_state(handle, *state)                              -> rc
qeli_client_stats(handle, *stats)                              -> rc
qeli_client_tun_push(handle, generation, bytes, bytes_len, lengths, count, *accepted) -> rc // ABI 1.7
qeli_client_tun_pull(handle, generation, bytes, cap, lengths, count_cap, *count, *bytes) -> rc // ABI 1.7
qeli_client_free(handle)                                       -> rc
```

The state machine no longer permits an optimistic "tunnel is up" before system setup:

```text
Created → Connecting → AwaitingNetwork ── ACK ──→ Running
                              └──────── reject ─→ Failed
Running/Failed/Created → Stopping → Stopped
```

- input is strict flat INI or a `qeli://` link, parsed and validated by Rust;
- handles are generation-checked `u64` values; stale use and double-free return an error;
- the event queue is bounded (64 by default, 256 maximum) and applies backpressure without
  leaving a partially completed request-driven state transition; a terminal background-runner
  failure cannot be retried by its caller, so it preempts the oldest queued events and always
  publishes an Error carrying the Failed state (plus StateChanged when capacity is at least 2);
- the event header has a fixed C-layout structure and version; plan, socket-protect,
  server-identity and path-command payloads are UTF-8 JSON, an error is UTF-8, while state
  transitions and the ABI 1.13 path-refresh request carry no payload;
- before `new`, an adapter checks the ABI with `QELI_CLIENT_ABI_IS_COMPATIBLE`: the major
  must match and the library minor must be at least the header minor; unknown capability bits,
  event kinds and additive JSON fields are not errors;
- `QELI_CLIENT_EVENT_INIT` and `QELI_CLIENT_STATS_INIT` set caller-owned `struct_size`.
  The core preserves it, writes only the prefix known to both sides, and rejects a short
  ABI-1.0 struct without consuming an event. The header compile-time checks the 48-byte event
  and the 64/96/144-byte V1/V2/V3 statistics prefixes;
- ABI 1.12 accepts only a bounded `PathUpdate` for the active generation, with a monotonic
  `update_id`, a physical-network token or non-zero interface index, local addresses, A/AAAA
  results with TTL, a reason, and consistent flags. Rejecting `PREPARE/BIND/COMMIT` always
  emits `ABORT`; rejecting rollback returns a platform error, increments
  `roam_reconnect_fallbacks`, and requires the adapter to clear candidate state before a full
  reconnect. `stop/start` and terminal failure discard commands that have not crossed the ABI;
- if the caller buffer is too small, the API reports the required length and does **not**
  consume the event;
- ABI 1.13 emits a path-refresh request only when both core and platform capability bits are
  present. Its positive `sequence` and `plan_generation` reuse the fixed 48-byte header. The
  adapter answers with a same-generation `PathUpdate` whose reason/flag is
  `same_network_nat_failure`; it does not implement a second retry timer or reconnect policy.
  `stop/start` and terminal failure discard a queued refresh together with queued path commands;
- a plan carries its generation, address/prefix, MTU, tunnel gateway, the actual carrier IP,
  routes with
  gateway/metric, DNS with address/port, full-tunnel, kill-switch, `max_streams` and
  `adaptive`. The platform must
  acknowledge that same generation as a unit; rejection moves the core to `Failed`;
- the ABI currently builds only for 64-bit GUI targets. 32-bit router builds leave the feature
  disabled and continue to build without FFI.
- input bytes are borrowed only for a call and output buffers always remain caller-owned.
  Distinct handles run concurrently while operations on one handle are serialized; an adapter
  must quiesce its workers before `free`;
- a panic inside a handle operation invalidates only that generation and returns
  `QELI_CLIENT_PANIC` instead of being disguised as `QELI_CLIENT_INVALID_HANDLE`.
- ABI 1.1 adds generation-scoped TUN-fd ownership. `set_tun_fd` makes its own atomic
  `CLOEXEC` duplicate, never takes the caller's fd, and closes the native copy on replacement,
  rejection, stop or free. If an adapter declared `QELI_PLATFORM_TUN_FD`, a positive plan ACK
  is forbidden until attach succeeds. ABI 1.1 itself started no packet IO; ABI 1.6 now consumes
  that duplicate in the native packet workers.
- ABI 1.2 carries `SocketProtect` through the same bounded queue. The payload contains only
  the fd, `event.sequence` is its one-shot request ID, and
  `qeli_client_socket_protect_result` reports the synchronous platform result. The Rust socket
  owner keeps the descriptor open until ACK and receives the result through a oneshot; stop/free
  cancel the wait, while unknown or repeated IDs receive `STALE_REQUEST`. The producer is now
  connected: Android `start()` creates a nonblocking IPv4 TCP/UDP carrier, and a positive ACK
  moves it from pending ownership into a protected socket slot consumed by ABI 1.6.
  Rejection closes the fd and moves the core to `Failed` with an error event.
- ABI 1.3 adds explicit `qeli_client_set_device_id` input and the
  `QELI_CORE_DEVICE_ID_INPUT` capability. An adapter supplies exactly 16 non-zero bytes before
  `start()`; the core copies the value, wipes a replaced/free copy, and never invents a
  competing identity. Android supplies its existing persisted `SharedPreferences` ID and
  wipes temporary Kotlin/JNI arrays. ABI 1.6 feeds this identity into the sole shared handshake;
  no second session exists.
- ABI 1.4 adds a correlated `ServerIdentity` request and
  `qeli_client_server_identity_result`. Its JSON payload contains `server_id` and a 64-character
  lowercase public key; `event.sequence` is the one-shot request ID. The producer must publish
  it only after the server-auth proof has established possession of that key. Android applies
  its existing persisted `qeli_known_hosts` policy, synchronously records a first-use key only
  after that proof, and rejects a changed key or persistence failure fail-closed. ACK,
  rejection, stale IDs and stop/free
  cancellation use the same bounded queue and oneshot contract as socket protection. The
  shared TCP handshake verifier is now async so it can await that platform decision without
  busy polling.
- ABI 1.5 adds the bounded `qeli_client_publish_handshake_network` migration input and
  `QELI_CORE_HANDSHAKE_NETWORK_INPUT`. Android passes the complete authenticated `OK:`
  plaintext, final path/config MTU, and an explicit compatibility DNS fallback. Rust re-parses
  server DNS/routes, assigns the next generation, and emits the canonical `NetworkPlan`.
  Android applies address/prefix/MTU, full/split routing, routes and DNS from that plan, adopts
  the TUN fd, and only then ACKs the generation. The synchronous publish+poll operation holds
  the JNI owner monitor, so the background event pump cannot steal the plan. Android advertises
  `KILL_SWITCH` only when the system Always-on VPN lockdown is already enabled and verifies it
  again before ACK; a profile that requires protection otherwise fails closed. A DNS plan with a
  non-standard port is rejected for the same reason; all post-publication validation failures
  go through the negative-ACK/retire path.
- ABI 1.6 adds the `QELI_CORE_NATIVE_DATA_PLANE` capability and blocking
  `qeli_client_run`. A generation-safe registry lease keeps a running owner alive without
  holding the registry mutex and prevents handle reuse/UAF while `stop` or `free` cancels it.
  The Android runtime consumes the protected carrier, runs the common TCP/UDP handshake and
  packet loops, publishes `NetworkPlan`, waits for the exact ACK and attached TUN descriptors,
  and reports live byte/packet counters through the existing stats ABI. TCP supports
  fake-TLS, plain, obfs, Reality-TLS and fixed/adaptive bonding. UDP supports fake-TLS and
  obfs, the QUIC wrapper, handshake retransmission/fragmentation, active MTU probing,
  heartbeat, shaping, padding and normalization. Cancellation is checked in every wait and
  packet loop; `stop/free` wakes the owner even when the event queue is full.
- ABI 1.7 adds `QELI_CORE_TUN_PACKET_IO`, the platform capability
  `QELI_PLATFORM_TUN_PACKET_BATCH`, and generation-scoped `qeli_client_tun_push/pull` for
  TUN implementations which cannot provide a portable fd. The caller supplies one contiguous
  byte buffer plus packet lengths; packets are capped at 65,535 bytes, batches at 64 packets,
  and both queues and reusable buffer pools are bounded with backpressure and no fallback
  allocation. A stale generation, malformed lengths, or IO before a positive `NetworkPlan`
  ACK is rejected. ABI 1.7 was an interim Windows packet seam and remains active for iOS.
  Windows and macOS run the same `qeli_client_run`: Rust owns DNS/connect, the carrier,
  handshake, crypto, TCP/UDP/QUIC/Reality, bonding and packet loops. After TC-2.2 macOS C# only opens utun,
  applies routes/DNS/kill-switch, and passes the fd through the existing ABI 1.1 `TUN_FD`
  contract. `NetworkPlan.carrier_address` is the peer IP actually connected, so the bypass
  route never performs a second, potentially different DNS resolution.
- Runtime input now carries every ordered IPv4 carrier candidate resolved by the platform on
  the physical network. Android uses `Network.getAllByName`; desktop and iOS cache the set
  before DNS can be captured by a retained TUN. Rust tries all candidates for TCP and platform
  reconnect generations rotate the list for UDP. This closes both first-A-record failure and
  hostname reconnect loops without moving DNS policy or sockets back out of the core.
- ABI 1.8 connects the iOS Packet Tunnel to the same packet seam and adds the handle-free
  `qeli_client_udp_probe`/`QELI_CORE_UDP_DIAGNOSTIC` surface for Windows, macOS and iOS.
  Additive `NetworkPlan.pushed_routes` keeps authenticated server routes distinct from
  client/local routes, while `NetworkPlan.data_plane` exposes effective post-push padding,
  heartbeat and shaping facts for status UI only. Rust already applies those values. The iOS
  adapter rejects the complete plan before ACK if any route cannot be represented as an
  `NEIPv4Route`; it never reports a partially installed plan as successful.
  iOS also applies its parsed `ReconnectPolicy`: transient runner and packet-pump failures
  create a fresh native handle after bounded backoff while the NetworkExtension settings stay
  fail-closed; identity/config/unsupported-plan failures remain terminal.
- ABI 1.9 adds `QELI_PLATFORM_TUN_WINTUN`, `QELI_CORE_WINTUN_IO`, and
  `qeli_client_set_wintun_adapter`. Windows C# creates the unique interface and applies the
  platform network plan, but passes its actual name to the core before ACK. Rust opens an
  independent adapter handle, owns the session/read event/rings, and releases receive packets
  through RAII. Managed code no longer sees payload or synchronizes ring lifetime.
- Android creates `ClientCore` through the generation-safe JNI adapter and runs the real
  service lifecycle through `new/start/run/stop/free`. Kotlin polls the same bounded event
  queue on `Dispatchers.IO`, performs only platform operations (`VpnService.protect`, persisted
  server trust and `NetworkPlan`/TUN setup), then hands the TUN fd to Rust. JNI adds no second
  queue or callback. The adapter requires ABI 1.6 plus `NATIVE_DATA_PLANE`; failure to load or
  negotiate the native core is fail-closed, with no Kotlin payload fallback. At the JNI
  boundary Android translates its compatibility spelling `dns = <ip>` into the shared
  `dns_servers = <ip>` form and makes its historical full-tunnel default explicit as
  `gateway = true`. Lab e2e verifies native ownership and reverse TUN traffic for TCP fake-TLS,
  plain, obfs and Reality-TLS; UDP fake-TLS, obfs and QUIC; heartbeat/shaping; MTU reporting;
  and adaptive bonding ramping beyond the primary connection, up to the configured four
  protected streams. Temporary profiles/users are removed
  afterward.

The authenticated TCP/UDP sessions and safe `NetworkPlan` construction are now common client
code: identity/trust, device ID, protected carriers and TUN setup are explicit adapter inputs.
Linux consumes them through its in-process adapter, Android through ABI 1.6, Windows through
Wintun ownership ABI 1.9, macOS through fd ownership ABI 1.9, and iOS through the ABI 1.8 packet
seam. Every transport must complete
`NetworkPlan → platform apply → TUN attach/packet seam → ACK` before packet loops start.
After ACK, the shared Android/Linux fd-backed backend owns both `OwnedFd` values, bounded
queues, reader/writer workers and TUN/TAP conversion. Its uplink reader uses a preallocated pool
capped at 4 MiB per connection:
`TunPacket` crosses the TCP distributor or UDP encrypt path without a copy and returns its
allocation through `Drop` before the first socket await. On Android the two native packet
workers are the sole payload readers/writers; Kotlin never reads, encrypts or writes a tunnel
packet on the active path.
`PacketCodec::encrypt_packet_into`
then builds the record in caller-owned storage: each TCP/UDP writer allocates real/cover
buffers once per connection, and UDP-QUIC reuses a separate envelope. The allocating entry
points remain for handshake/control and compatibility. `Obfuscator` now has caller-owned
variants as well: client TCP/UDP writers reuse scratch storage for normalization and padding of
real/cover/heartbeat traffic, while the server TCP/UDP handlers and shared downlink forwarder
use task-owned padding scratch. Allocating wrappers remain for compatibility and cold paths.
The server outbound wire path uses a separate RAII pool capped at 4 MiB per authenticated
session. Slot capacity follows the largest payload that the profile can actually emit
(`tun.mtu`, heartbeat, or traffic-shaping maximum), rather than the absolute receive ceiling:
a 1400-byte profile gets 2,906 slots instead of 251. Every bonded TCP stream shares the pool,
and it is created only after AUTH, so half-open TCP/UDP sessions reserve none of the budget.
The shared forwarder encrypts directly into pooled storage, rejects a record whose exact size
would exceed the slot before `Vec` can grow, and the bounded writer queue retains ownership
through the actual socket write. Recycling uses a short shared stack plus a semaphore rather
than an async mutex and mpsc hop. TCP cover/heartbeat records use one writer-owned scratch;
UDP cover/heartbeat use the session pool, and QUIC uses one reusable envelope.
On the return path a separate RAII pool
caps requested payload capacity at 4 MiB per Linux connection generation: 251 record slots sized for
`TLS_RECORD_HEADER + MAX_RECORD_SIZE`. `read_record_into` reads TCP framing directly into a
checked-out slot, while borrowed `unwrap_quic_payload` extracts UDP-QUIC payload without an
intermediate `Vec`. `decrypt_packet_in_place` turns the record into plaintext in that same
allocation; TCP inline/pipeline and UDP retain ownership through the TUN-writer queue, and
`Drop` returns the slot only after write or discard. Exhausted TCP readers apply backpressure
before the next read, while UDP drops the datagram without blocking heartbeat/liveness timers;
neither path creates a fallback allocation. Wire format is therefore unchanged.
The generation-scoped data-plane seam is implemented with real ownership: Unix fd-backed
frontends attach a duplicated descriptor, Windows attaches the platform-created Wintun adapter,
and packetFlow/compatibility frontends use bounded push/pull batches.

### 5.2. Implemented data-plane surface

```text
qeli_client_set_tun_fd(handle, generation, fd)                    -> rc
qeli_client_set_wintun_adapter(handle, generation, name, name_len)-> rc
qeli_client_tun_push(handle, generation, pkts, bytes, lens, n, *accepted) -> rc
qeli_client_tun_pull(handle, generation, buf, cap, lens, lens_cap, *n, *bytes) -> rc
```

Contract requirements that follow from §4.1:

- **the caller provides the buffers**; the core never returns `Box::into_raw` on the hot
  path;
- **events are a polled queue**, not callbacks: calling back from Rust into the JVM/CLR
  needs thread attach and complicates lifetimes;
- **configuration crosses as text** (flat-INI or `qeli://`) and the core parses it — that
  removes three parser implementations at once.

---

## 6. The plan

### TC-0. Prerequisites

| ID | Item | Status |
|---|---|---|
| TC-0.1 | **Build the FFI cdylib with `panic = "unwind"`.** The `ffi-cdylib`/`transport-core-ffi` feature stops a release build with `panic = "abort"`; standard build scripts set unwind, and an intentional-panic test proves an error code returns without unwinding through the ABI. | ✅ 0.7.15 |
| TC-0.2 | Settle iOS: a Network Extension has a hard memory ceiling and jemalloc is unavailable there. Budget the core's buffers before work starts. | ✅ ABI 1.8: two 32 × 65,535 packet pools = 4,194,240 bytes; Swift caller buffers ≤ 768 KiB; 128-slot queues, no fallback allocation |
| TC-0.3 | Make the `PacketCodec` benches (Rust and C#) **permanent**, so a regression is caught by CI rather than by a one-off. | ✅ release-mode Rust/C# harness plus CI gate |
| TC-0.4 | Measure managed vs Rust on the same hardware. | ✅ 2026-07-30, §2 |

**Acceptance for TC-0:** a panic in the FFI returns an error code instead of killing the
process (proven by a test that panics on purpose); the iOS memory budget is a number.

The permanent TC-0.3 measurement needs no external benchmark framework:
`cargo run --release --no-default-features --features packet-bench --bin packet-codec-bench -- --ci`
for Rust and `dotnet run --project qeli-shared/QeliConformance -c Release -- packetbench --ci`
for the managed codec. Both execute a
real 1,400-byte encrypt/decrypt round-trip after warm-up and verify the plaintext. Rust also
requires the caller-owned `Vec` to stop growing; C# records allocated bytes per round-trip.
The CI floors (50 MiB/s Rust, 10 MiB/s C#, 32 KiB managed allocation ceiling) deliberately
catch a many-fold regression without presenting a noisy shared runner as a release speed claim;
precise throughput remains a lab measurement.

### TC-1. Transport API and core extraction — 2–3 weeks

| ID | Item | Status |
|---|---|---|
| TC-1.1 | Design and freeze the C-ABI (§5), including the error taxonomy and the event format | ✅ ABI 1.0 freeze review: version/capability negotiation, extensible output structs, ownership/concurrency, panic and event/JSON contracts are pinned by the header and tests |
| TC-1.2 | A data-plane path with **no per-packet allocation**: caller-provided buffers, no `Box::into_raw` on the hot path | ✅ Every active path uses bounded reusable pools/caller buffers. macOS payload uses the fd; Windows uplink retains the Wintun ring packet until RAII release and downlink copies from a bounded Rust pool straight into the send ring. Desktop managed code has no per-packet allocation/copy |
| TC-1.3 | Configuration handling entirely in the core: accept flat-INI and `qeli://` | ✅ every production transport passes the strict Rust parser; platform models remain for UI/editor validation |
| TC-1.4 | The route/DNS plan as a core **event**, not a core action | ✅ Linux/Android/Windows/macOS/iOS use the canonical plan and mandatory generation ACK |

**Acceptance:** the Linux Rust client runs **through the new API** (not around it), lab
e2e green, the wire byte-for-byte unchanged.

The configuration boundary keeps deliberate platform differences without allowing schema
drift. A source contract now proves that Rust, Android, C# and Swift recognize the exact same
80-key union. The historical 0.7.14 → 0.7.15 comparison is in the
[client config-key matrix](CLIENT-CONFIG-MATRIX.md). Platform editors model only applicable fields and carry the rest through
open/save. Android now models `kill_switch` too: the common plan requires the capability and
the platform adapter acknowledges it only after verifying the system Always-on VPN lockdown.
The system toggle still belongs to the user or MDM, so missing lockdown is a fail-closed
refusal rather than a false positive ACK.

The lifecycle criterion is met; Android, Windows, macOS and iOS now use the shared transport data plane. The full
lab build is green (the full default library/binary/integration suite;
the minimal `transport-core-ffi` profile has 333 passed and 1 ignored), strict default clippy
is green, and Android has 67/67 JVM tests plus a warning-free arm64/x86_64 NDK build and APK;
routing/kill-switch netns e2e is 26/26, and the final 2-vCPU lab binary reaches 469 up/701 down
Mbps in TCP fake-TLS and 540 up/562 down Mbps in TCP obfs, with zero server session drops.
UDP reaches 300 Mbps at 0.06% loss and 400 Mbps at 1.86%; 500 Mbps loses 8.27% and remains a
single-flow/single-worker ceiling rather than a release claim. Ping loss is zero in every mode.
Uplink TUN allocations now use hard
backpressure instead of fallback allocation, while uplink encryption and the QUIC envelope
use connection-owned buffers instead of a new wire `Vec` per packet. A fixed downlink pool now
owns each record through the actual TUN write: TCP gets backpressure, UDP uses drop-on-exhaustion,
and neither creates a fallback allocation. Normalization and padding for real/cover/heartbeat
records now use caller/task-owned scratch instead of a temporary `Vec` as well. Encrypted server
downlink records likewise stay in a bounded session pool through the socket write; bonded streams
share one budget and half-open sessions never allocate it. The inbound dedicated TUN writer now
drains the original bounded queue directly; removing the async bridge and its second 256-slot
queue eliminates a measured internal UDP burst-drop point without increasing the memory bound.
The server TUN→client reader now reads directly into a profile-wide RAII pool (32 MiB target,
at least one slot per queue) and returns the allocation after forwarding. In the other direction,
TCP reads a record directly into a second bounded pool, decrypts it in place, and passes the same
allocation to the TUN writer; UDP receive/QUIC unwrap uses a borrowed view and pooled decrypt with
no intermediate `Vec`s. macOS passes the utun fd to the core, while Windows ABI 1.9 opens the
Wintun session/rings inside Rust: an uplink packet remains in the receive ring until RAII release,
and downlink goes from the bounded decrypt pool directly into `WintunAllocateSendPacket`. No
desktop payload crosses C#. The TC-1, TC-2.2, and TC-2.3 code criteria are complete; separate UDP
throughput/buffer tuning remains. XCFramework/Xcode simulator validation is in CI; live utun and
Wintun full-tunnel validation with newly built native libraries remains a release gate.

### TC-2. TUN backends in Rust — 5.5 weeks

| ID | Platform | Size |
|---|---|---|
| TC-2.1 | Android: adopt the `VpnService` fd + a `protect()` upcall | 1 wk |
| TC-2.2 | macOS: utun | 1 wk |
| TC-2.3 | Windows: Wintun, with Rust owning the ring | 2 wks |
| TC-2.4 | iOS: the packet seam to `packetFlow` | 1.5 wks |

TC-2.1 is **complete for the active Android path**: ABI 1.1 adopts a generation-scoped CLOEXEC duplicate for the TUN fd,
ABI 1.2 adds a correlated socket-protect request/ACK with oneshot waiting, ABI 1.3 accepts the
stable platform device ID, ABI 1.4 adds server-identity trust request/ACK, ABI 1.5 publishes
the real Android network plan and adopts its generation-scoped TUN fd, and ABI 1.6 runs the
protected carrier plus common packet pumps. Android advertises `SOCKET_PROTECT`,
`SERVER_IDENTITY`, `TUN_FD` and `NATIVE_DATA_PLANE`; Kotlin services those platform requests
and owns no payload bytes on the active path. The transport half of `QeliService.kt` has also
been physically removed (3,921 to 1,443 lines): no dormant handshake, codec, TCP/UDP/Reality,
MTU/QUIC pump or bonding fallback remains in the service. Android TC-3.1 is now complete:
the pre-connect UDP reachability check is a handle-free `TransportCore` JNI call which accepts
a credential-free profile and uses the exact Rust hybrid-PQ ClientHello flight, fragmentation,
QUIC and obfs helpers used by the live transport. The Kotlin `protocol/*`, transport crypto,
RealTls/ML-KEM/TrafficShaper wrappers, their duplicated conformance suites and 14 legacy JNI
entry points are gone. Only `BackupCrypto` remains, for profile import/export rather than wire IO.

TC-2.2 is **source-complete with local gates and no ABI bump**: macOS C# opens utun and retains
the original fd only for lifecycle/route cleanup; before the positive `NetworkPlan` ACK the core
receives a generation-scoped CLOEXEC duplicate through ABI 1.1 `TUN_FD`. The common Rust fd pump
strips/adds the four-byte utun address-family prefix, uses `writev` without a temporary payload
buffer, and runs nonblocking reader/writer workers. `UtunDevice` has no payload read/write methods.
The ABI 1.9 universal2 dylib has now passed a byte-identical A/B lab rebuild, copy/provenance
checks and signed app packaging. A live full-tunnel macOS e2e remains a hardware gate because
the available lab is Linux and has no utun/macOS runtime.

TC-2.3 is **source-complete with local gates in ABI 1.9**: Windows C# only creates a unique
qeli-owned adapter and keeps its creator handle for interface lifetime/network cleanup. Before
ACK the core receives the actual name, opens an independent handle through the already loaded and
verified `wintun.dll`, starts the session, and exclusively owns the read event/rings. Uplink is not
copied out of the ring: a Rust value retains the pointer and releases it in `Drop`; downlink needs
one system copy from the bounded decrypt pool into the send ring, but no FFI/managed seam. Stop
closes queues, joins reader/writer, and only then ends the session, removing the old UAF class with
managed `ReceivePacket`/`SendPacket`. The rebuilt ABI 1.9 `qeli.dll` passed byte-identical A/B,
exports/provenance, Release build/selftest and a live server handshake that received the full
NetworkPlan. An administrator full-tunnel Wintun data-plane run remains the platform gate.

TC-2.4 is **complete in ABI 1.8**: `NEPacketTunnelFlow.readPackets/writePackets` is connected
to generation-scoped bounded `tun_push/pull`; packet pools and queues have a fixed iOS budget.
The platform adapter applies or rejects the whole NetworkPlan before pumps start.

**Acceptance for each:** the tunnel comes up and carries traffic under the core, with the
platform code touching not one byte of payload.

> TC-2.3 deserves a note: the Windows client has already had a **UAF in `wintun.dll`**.
> ABI 1.9 removes the managed session and concurrent Dispose: the Rust session lives under
> `Arc`, worker join precedes `WintunEndSession`, and every outstanding receive packet retains it.

### TC-3. Client integration — 8 weeks

| ID | Client | What gets deleted | Size |
|---|---|---|---|
| TC-3.1 | Android | ✅ service transport, `protocol/*`, transport crypto and legacy JNI removed; UDP diagnostic shares the Rust first-flight builder | complete in 0.7.15 |
| TC-3.2 | Windows | ✅ ABI 1.9 library rebuilt; source path owns Wintun session/rings in Rust; managed runtime and packet methods removed; live handshake/NetworkPlan green | platform gate: administrator Wintun full-tunnel data plane |
| TC-3.3 | macOS | ✅ ABI 1.9 universal2 dylib rebuilt and packaged; source path hands the utun fd to Rust and touches no payload | hardware gate: live Mac utun e2e |
| TC-3.4 | iOS | ✅ eight Swift runtime files (4,046 lines) removed; the compact platform adapter uses the shared Rust transport and conditionally advertises fail-closed ABI 1.14 path transactions, including the `PATH_REFRESH` event introduced by ABI 1.13, only when the loaded core exposes them | code complete; Xcode/device gate remains |

**The order is deliberate:** Android first — it is the one that silently skipped M6, so the
divergence risk there is demonstrated; iOS last — the only platform with no fd and with a
memory ceiling.

**Acceptance for each:** that client's existing conformance tests still pass **against the
core**; lab e2e against a server; no regression in UI or notifications.

### TC-4. Build, CI, packaging — 2 weeks

| ID | Item |
|---|---|
| TC-4.1 | The previous whole-client cross-build matrix passed for Android arm64/x86_64, Windows x64, and macOS universal2 with 6 Reality + 20 client exports; source ABI 1.12 raised the gate to 22 client exports and 21 Android JNI exports. ABI 1.13 adds only event/capability values and keeps those export counts; ABI 1.14 adds typed path results without new exports. The iOS base compatibility floor remains ABI 1.11, while fail-closed path transactions (including `PATH_REFRESH`) require 1.14; `build_native.sh` now enables `transport-core-ffi experimental-roaming` by default. The `aarch64-apple-ios` feature Clippy gate is green, while a real device+simulator XCFramework/Xcode build still requires macOS |
| TC-4.2 | ✅ All four libraries passed live byte-identical A/B builds on labs `.10`/`.11`; the shared mock-tested harness performs scoped source sync, exact-target preflight and verified atomic pulls. Rust 1.97.0, Zig 0.13.0, cargo-zigbuild 0.23.0, GNU ld 2.44, apple-codesign 0.29.0, NDK 26.3.11579264 and cargo-ndk 4.1.2 are pinned. macOS normalizes the install name, content-derived UUID and Zig's invalid non-deterministic GOT index before deterministic ad-hoc signing; SHA256, exports and provenance are fail-closed gates |
| TC-4.3 | ✅ Conformance freshness plus the release-mode Rust/C# TC-0.3 benches run in Linux/Windows/macOS CI |

### TC-5. Deleting the duplicates — 1.5 weeks

| ID | Item |
|---|---|
| TC-5.1 | ✅ Production runtime duplicates are gone from Android, Windows/macOS and iOS; C#/Swift wire/crypto remains only for conformance/KAT, and neither production iOS target compiles the retained Swift wire code |
| TC-5.2 | ✅ Windows/macOS/iOS reachability uses ABI 1.8 `qeli_client_udp_probe`; old language first-flight helpers are outside the active build |

The 0.7.15 desktop cleanup reduced `VpnTunnelBase.cs` from 3,287 to 1,126 lines and
removed the separate 139-line `RealTls` wrapper: a net deletion of 2,300 lines. The
remaining C# `Protocol/` and `Crypto/` code is not a production fallback; CLI/UI
reachability diagnostics and cross-language KATs still consume it.

**Total: ~19–21 weeks of focused work**, realistically **5–7 months** solo once regressions
and live testing are counted.

---

## 7. Risks

| Risk | Assessment | What to do |
|---|---|---|
| A panic in the FFI kills the host app | **high, and it exists today** | TC-0.1 — blocker |
| Network Extension memory ceiling on iOS | medium | TC-0.2, budget before starting |
| Downlink copy from the Rust decrypt pool into the Wintun send ring | measurable | platform/FFI copy removed in ABI 1.9; include it in lab throughput and later buffer tuning |
| Binary size: +3.7 MB (win dll), +8.5 MB (mac universal), one `.so` per Android ABI | low | Android ABI splits |
| Debugging across the boundary: managed stack traces are lost | medium | native crash symbolication, error codes instead of exceptions |
| End-to-end throughput regression | **open risk** | §2 core microbenchmarks are insufficient; retain TC-0.3 plus lab TCP/UDP baselines, then tune queues/buffers |

---

## 8. Sequencing against the roadmap

The argument for doing this now rather than later:

- **roaming** ([ROAMING.md](../plans/ROAMING.md)) — the shared TCP/UDP core and Android, Linux/OpenWrt, Windows, macOS and iOS path executors are source-complete behind the feature gate; real-device/race/soak matrices and staged rollout remain;
- **multipath** — implemented only in the Rust client.

Build the core after those and both features get written four times. Build it before and
they get written once. That is the strongest scheduling argument, and it only gets more
expensive with time.

A side effect: the conformance fixtures added in 0.7.14 become the **acceptance test for
the migration** — after the core is swapped in, each client's existing tests must still
pass.

---

## 9. Open questions

1. **When to drop the platform implementation.** Do we keep the managed one as a fallback
   during migration, or switch hard? A fallback preserves the very divergence this exists
   to remove.
2. **The Windows service.** Some logic lives in the service today and some in the UI —
   which side gets the core, and who owns its lifetime.
3. **Updating the core independently of the app** — tempting for fast protocol fixes, but
   constrained by App Store and Play rules on iOS and Android.
