# qeli — a shared transport core in Rust for every client

Proposal and plan: move connection setup, transport selection, the handshake, roaming,
multipath, automatic fallback and configuration handling into **one** Rust core, linked
into every client over FFI. Platform code keeps the TUN, the UI, notifications and system
APIs.

The format is a working checklist in the style of [REFACTOR-PLAN.md](REFACTOR-PLAN.md):
every item has an ID, a size, an approach and an **acceptance criterion**.

Status legend: ⬜ not started · 🟦 in progress · ✅ done · 🧪 awaiting build/e2e.

**Initiative status: 🟦 in progress.** Implementation started on 2026-08-08; the first
compatible control-plane slice was added without switching existing clients. Written 2026-07-30.

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
   [BENCHMARK.md](BENCHMARK.md)).
4. **Client crypto is not uniform.** Android encrypts with native Conscrypt (BoringSSL),
   C# with managed BouncyCastle. "Managed" is not one category, and Android will gain
   noticeably less from the move than Windows/macOS.

> Reproduction: the benches were one-off (a C# console with a `ProjectReference` to
> `qeli-shared`, published self-contained for linux-x64, and `examples/bench_codec.rs` in
> the Rust crate). Neither was committed. If the work starts they should be re-created as
> permanent fixtures — see **TC-0.3**.

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
counters does not count as a fix. Permanent Rust/C# `PacketCodec` benchmarks remain the
separate TC-0.3 item.

---

## 3. What is duplicated today

Counted by file, excluding tests and build artefacts (2026-07-30):

| Codebase | Total lines | Of which protocol/transport core |
|---|---|---|
| `qeli-shared` (C#, shared by Windows and macOS) | 7,627 | ~6,200 |
| `qeli-android` (Kotlin) | 8,469 | ~5,200 |
| `qeli-ios` (Swift) | 10,668 | ~5,700 |
| **Duplicated total** | | **~17,000** |

Plus ~930 lines of conformance scaffolding in C# and ~250 each in Kotlin/Swift, which
exist **only** because there are four implementations.

The largest sites of duplication:

| File | Lines | What it does |
|---|---|---|
| `qeli-android/.../QeliService.kt` | 3,162 | VpnService + connection + transport |
| `qeli-shared/.../Vpn/VpnTunnelBase.cs` | 2,866 | connection, handshake, transport, reconnect |
| `qeli-ios/QeliPacketTunnel/QeliTunnelEngine.swift` | 1,436 | the same for iOS |
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

**The binding constraint:** `qeli/src/tun/` is **335 lines and Linux-only**
(`/dev/net/tun`, `#[cfg(target_os = "linux")]`). No Wintun, no utun, no iOS. That, not the
FFI, is what sets the size of this work.

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
qeli_client_abi_version()                                      -> 0x00010007
qeli_client_core_capabilities()                                -> bitmask
qeli_client_new(config, len, platform_caps, queue_cap, *handle) -> rc
qeli_client_start(handle)                                      -> rc
qeli_client_run(handle, json, len)                             -> rc  // ABI 1.6, blocking
qeli_client_stop(handle)                                       -> rc
qeli_client_set_device_id(handle, id, 16)                      -> rc  // ABI 1.3
qeli_client_publish_handshake_network(handle, json, len, *gen) -> rc  // ABI 1.5
qeli_client_set_tun_fd(handle, generation, fd)                 -> rc  // ABI 1.1
qeli_client_poll_event(handle, *event, payload, cap, *needed)   -> rc
qeli_client_network_plan_result(handle, generation, rc, reason) -> rc
qeli_client_socket_protect_result(handle, sequence, rc, reason) -> rc  // ABI 1.2
qeli_client_server_identity_result(handle, sequence, rc, reason)-> rc  // ABI 1.4
qeli_client_state(handle, *state)                              -> rc
qeli_client_stats(handle, *stats)                              -> rc
qeli_client_tun_push(handle, generation, bytes, lengths, count, *accepted) -> rc // ABI 1.7
qeli_client_tun_pull(handle, generation, bytes, cap, lengths, count_cap, ...) -> rc // ABI 1.7
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
  leaving a partially completed state transition;
- the event header has a fixed C-layout structure and version; plan, socket-protect and
  server-identity payloads are UTF-8 JSON, an error is UTF-8, and a state transition has no
  payload;
- before `new`, an adapter checks the ABI with `QELI_CLIENT_ABI_IS_COMPATIBLE`: the major
  must match and the library minor must be at least the header minor; unknown capability bits,
  event kinds and additive JSON fields are not errors;
- `QELI_CLIENT_EVENT_INIT` and `QELI_CLIENT_STATS_INIT` set caller-owned `struct_size`.
  The core preserves it, writes only the prefix known to both sides, and rejects a short
  ABI-1.0 struct without consuming an event. The header compile-time checks the 48/64-byte
  layouts;
- if the caller buffer is too small, the API reports the required length and does **not**
  consume the event;
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
  the JNI owner monitor, so the background event pump cannot steal the plan. Android no longer
  advertises `KILL_SWITCH`, which `VpnService.Builder` cannot actually install; a profile that
  requires it therefore fails closed instead of receiving a false ACK. A DNS plan with a
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
  ACK is rejected. Windows and macOS run the same `qeli_client_run`: Rust owns DNS/connect,
  the carrier, handshake, crypto, TCP/UDP/QUIC/Reality, bonding and packet loops; C# retains
  platform Wintun/utun, routes/DNS/kill-switch, trust/device ID and moves raw IP packets over
  the seam. `NetworkPlan.carrier_address` is the peer IP actually connected, so the bypass
  route never performs a second, potentially different DNS resolution.
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
Linux consumes them through its in-process adapter, Android through ABI 1.6, and Windows/macOS
through ABI 1.7. Every transport must complete
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
`qeli_client_set_tun` and C-ABI data-plane calls arrive only with real TUN ownership, avoiding
exported stubs that report false success.

### 5.2. Target data-plane surface

```text
qeli_client_set_tun(handle, fd | ring)       -> rc  // Android/macOS/Windows
qeli_client_tun_push(handle, pkts, lens, n)  -> rc  // iOS packetFlow into the core
qeli_client_tun_pull(handle, buf, cap, *n)   -> rc  // core into iOS packetFlow
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
| TC-0.2 | Settle iOS: a Network Extension has a hard memory ceiling and jemalloc is unavailable there. Budget the core's buffers before work starts. | ⬜ |
| TC-0.3 | Make the `PacketCodec` benches (Rust and C#) **permanent**, so a regression is caught by CI rather than by a one-off. | ⬜ |
| TC-0.4 | Measure managed vs Rust on the same hardware. | ✅ 2026-07-30, §2 |

**Acceptance for TC-0:** a panic in the FFI returns an error code instead of killing the
process (proven by a test that panics on purpose); the iOS memory budget is a number.

### TC-1. Transport API and core extraction — 2–3 weeks

| ID | Item | Status |
|---|---|---|
| TC-1.1 | Design and freeze the C-ABI (§5), including the error taxonomy and the event format | ✅ ABI 1.0 freeze review: version/capability negotiation, extensible output structs, ownership/concurrency, panic and event/JSON contracts are pinned by the header and tests |
| TC-1.2 | A data-plane path with **no per-packet allocation**: caller-provided buffers, no `Box::into_raw` on the hot path | 🟦 Linux/Android and the ABI 1.7 packet seam use bounded reusable pools/caller buffers; client wire records, UDP-QUIC envelopes, normalization and padding reuse storage; the C# ITun adapter still copies a packet and server raw/inbound buffers remain |
| TC-1.3 | Configuration handling entirely in the core: accept flat-INI and `qeli://` | 🟦 Linux, Android, Windows and macOS use the strict Rust parser; iOS remains |
| TC-1.4 | The route/DNS plan as a core **event**, not a core action | ✅ Linux/Android/Windows/macOS use the canonical plan and mandatory generation ACK |

**Acceptance:** the Linux Rust client runs **through the new API** (not around it), lab
e2e green, the wire byte-for-byte unchanged.

The lifecycle criterion is met; Android, Windows and macOS now use the shared transport data plane. The full
lab build is green (the full default library/binary/integration suite;
the minimal `transport-core-ffi` profile has 325 passed and 1 ignored), strict default clippy
is green, and Android has 64/64 JVM tests plus a warning-free arm64/x86_64 NDK build and APK;
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
TC-1 as a whole is not complete: server raw TUN/inbound buffers, the iOS data-plane seam and
managed C# duplicate removal remain, while UDP throughput/buffer tuning is tracked
as a separate follow-up rather than hidden inside this ownership migration.

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

TC-2.2/TC-2.3 are **partially complete through ABI 1.7**: the shared Rust transport already
accepts and emits packets over the bounded packet seam, but opening utun/Wintun, reading/writing
their platform APIs and system setup remain in C#. The active protocol is no longer duplicated,
but the strict TC-2 criterion ("platform code touches no payload") is not met yet. Moving Wintun
ring ownership and utun IO into Rust remains a separate stage alongside later throughput tuning.

**Acceptance for each:** the tunnel comes up and carries traffic under the core, with the
platform code touching not one byte of payload.

> TC-2.3 deserves a note: the Windows client has already had a **UAF in `wintun.dll`**
> (fixed in 0.7.x). Moving ownership of the ring into Rust removes the class outright, but
> demands care with lifetimes — budget review time.

### TC-3. Client integration — 8 weeks

| ID | Client | What gets deleted | Size |
|---|---|---|---|
| TC-3.1 | Android | ✅ service transport, `protocol/*`, transport crypto and legacy JNI removed; UDP diagnostic shares the Rust first-flight builder | complete in 0.7.15 |
| TC-3.2 | Windows | 🟦 active transport uses ABI 1.7; live native handshake is green and the dormant managed runtime has been deleted | remaining: full Wintun data-plane acceptance |
| TC-3.3 | macOS | 🟦 the same shared C# adapter and universal2 whole-client dylib; the dormant managed runtime has been deleted | remaining: live Mac utun e2e |
| TC-3.4 | iOS | `QeliTunnelEngine`, `*Transport`, `PacketCodec` | 2.5 wks |

**The order is deliberate:** Android first — it is the one that silently skipped M6, so the
divergence risk there is demonstrated; iOS last — the only platform with no fd and with a
memory ceiling.

**Acceptance for each:** that client's existing conformance tests still pass **against the
core**; lab e2e against a server; no regression in UI or notifications.

### TC-4. Build, CI, packaging — 2 weeks

| ID | Item |
|---|---|
| TC-4.1 | Whole-client cross-builds are complete for Android arm64/x86_64, Windows x64 and macOS universal2 with a 6 Reality + 18 client export gate; the iOS device+simulator **XCFramework** remains crypto/realtls-only |
| TC-4.2 | Provenance and reproducibility for the native libraries |
| TC-4.3 | Gate: conformance vectors plus the TC-0.3 benches in CI |

### TC-5. Deleting the duplicates — 1.5 weeks

| ID | Item |
|---|---|
| TC-5.1 | 🟦 Delete ~17,000 lines of ported protocol: Android and the Windows/macOS runtime duplicates are gone; iOS and the retained C# diagnostics remain |
| TC-5.2 | 🟦 Old **runtime language implementations** are deleted only after their client migrates. Keep conformance/KAT fixtures as wire, crypto, configuration and `qeli://` regression tests; move reachability diagnostics to the native API before deleting their C# helpers |

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
| Per-packet allocation across the boundary | medium | TC-1.2, caller-provided buffers |
| Binary size: +3.7 MB (win dll), +8.5 MB (mac universal), one `.so` per Android ABI | low | Android ABI splits |
| Debugging across the boundary: managed stack traces are lost | medium | native crash symbolication, error codes instead of exceptions |
| Throughput regression | **low, measured** | §2: the core is 2.4–2.5× faster; TC-0.3 keeps it that way in CI |

---

## 8. Sequencing against the roadmap

The argument for doing this now rather than later:

- **roaming** ([ROAMING.md](ROAMING.md)) — no code written yet;
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
