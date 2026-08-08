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

### 5.1. Implemented first slice (ABI 1.0)

The public contract lives in `qeli/include/qeli_transport_core.h`, with the implementation
in `qeli/src/transport_core/`. The opt-in `transport-core-ffi` feature inherits the mandatory
FFI `panic = "unwind"` contract.

```text
qeli_client_abi_version()                                      -> 0x00010000
qeli_client_core_capabilities()                                -> bitmask
qeli_client_new(config, len, platform_caps, queue_cap, *handle) -> rc
qeli_client_start(handle)                                      -> rc
qeli_client_stop(handle)                                       -> rc
qeli_client_poll_event(handle, *event, payload, cap, *needed)   -> rc
qeli_client_network_plan_result(handle, generation, rc, reason) -> rc
qeli_client_state(handle, *state)                              -> rc
qeli_client_stats(handle, *stats)                              -> rc
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
- the event header has a fixed C-layout structure and version; a plan payload is UTF-8 JSON,
  an error is UTF-8, and a state transition has no payload;
- if the caller buffer is too small, the API reports the required length and does **not**
  consume the event;
- a plan carries its generation, address/prefix, MTU, tunnel gateway, routes with
  gateway/metric, DNS with address/port, full-tunnel and kill-switch. The platform must
  acknowledge that same generation as a unit; rejection moves the core to `Failed`;
- the ABI currently builds only for 64-bit GUI targets. 32-bit router builds leave the feature
  disabled and continue to build without FFI.

The core still does not open wire sockets or perform the handshake/encryption. The Linux
client now consumes it through an in-process adapter: configuration goes through `ClientCore`,
and both handshake paths (TCP and UDP) must complete `NetworkPlan → platform apply → ACK`
before packet loops start. After the ACK, the shared `transport_core::linux_tun` owns both
`OwnedFd` values, bounded queues, reader/writer workers and TUN/TAP conversion for both
transports. Its uplink reader uses a preallocated pool capped at 4 MiB per connection:
`TunPacket` crosses the TCP distributor or UDP encrypt path without a copy and returns its
allocation through `Drop` before the first socket await. `PacketCodec::encrypt_packet_into`
then builds the record in caller-owned storage: each TCP/UDP writer allocates real/cover
buffers once per connection, and UDP-QUIC reuses a separate envelope. The allocating entry
points remain for handshake/control and compatibility. `Obfuscator` now has caller-owned
variants as well: client TCP/UDP writers reuse scratch storage for normalization and padding of
real/cover/heartbeat traffic, while the server TCP/UDP handlers and shared downlink forwarder
use task-owned padding scratch. Allocating wrappers remain for compatibility and cold paths.
The server outbound wire path uses a separate RAII pool capped at 4 MiB per authenticated
session: 251 same-sized record slots shared by every bonded TCP stream. The pool is created only
after AUTH, so half-open TCP/UDP sessions do not reserve that budget. The shared forwarder
encrypts directly into pooled storage, the bounded writer queue retains the slot through the
actual socket write, and pool or queue exhaustion becomes an accounted drop without fallback
allocation. TCP cover/heartbeat records use one writer-owned scratch buffer, UDP
cover/heartbeat records use the session pool, and QUIC uses one reusable envelope.
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
| TC-1.1 | Design and freeze the C-ABI (§5), including the error taxonomy and the event format | 🟦 ABI 1.0 and header implemented; the first Linux adapter refined the route/DNS payload, final freeze review remains |
| TC-1.2 | A data-plane path with **no per-packet allocation**: caller-provided buffers, no `Box::into_raw` on the hot path | 🟦 Linux TUN uplink/downlink and server encrypted downlink records use bounded reusable pools; client TCP/UDP wire records, UDP-QUIC envelopes, normalization and padding reuse caller/task-owned storage; the external FFI seam and remaining server raw/inbound buffers remain |
| TC-1.3 | Configuration handling entirely in the core: accept flat-INI and `qeli://` | 🟦 Linux uses the shared strict parser; external clients remain |
| TC-1.4 | The route/DNS plan as a core **event**, not a core action | ✅ Linux TCP/UDP handshakes use the bounded queue and mandatory generation ACK |

**Acceptance:** the Linux Rust client runs **through the new API** (not around it), lab
e2e green, the wire byte-for-byte unchanged.

The lifecycle criterion is met and the TUN half of the data plane now has its first shared
backend: the full lab build is green (525 library tests), routing/kill-switch netns e2e is
26/26, TCP fake-TLS reaches 524 up/605 down Mbps, TCP obfs 570 up/514 down Mbps, UDP reaches
400 Mbps at 1.25% loss, and ping loss is zero in every mode. Uplink TUN allocations now use hard
backpressure instead of fallback allocation, while uplink encryption and the QUIC envelope
use connection-owned buffers instead of a new wire `Vec` per packet. A fixed downlink pool now
owns each record through the actual TUN write: TCP gets backpressure, UDP uses drop-on-exhaustion,
and neither creates a fallback allocation. Normalization and padding for real/cover/heartbeat
records now use caller/task-owned scratch instead of a temporary `Vec` as well. Encrypted server
downlink records likewise stay in a bounded session pool through the socket write; bonded streams
share one budget and half-open sessions never allocate it. TC-1 as a whole is not complete:
server raw TUN/inbound buffers and the wire socket/handshake/codec remain in the legacy module,
and the external data-plane seam is not yet connected for the other platforms.

### TC-2. TUN backends in Rust — 5.5 weeks

| ID | Platform | Size |
|---|---|---|
| TC-2.1 | Android: adopt the `VpnService` fd + a `protect()` upcall | 1 wk |
| TC-2.2 | macOS: utun | 1 wk |
| TC-2.3 | Windows: Wintun, with Rust owning the ring | 2 wks |
| TC-2.4 | iOS: the packet seam to `packetFlow` | 1.5 wks |

**Acceptance for each:** the tunnel comes up and carries traffic under the core, with the
platform code touching not one byte of payload.

> TC-2.3 deserves a note: the Windows client has already had a **UAF in `wintun.dll`**
> (fixed in 0.7.x). Moving ownership of the ring into Rust removes the class outright, but
> demands care with lifetimes — budget review time.

### TC-3. Client integration — 8 weeks

| ID | Client | What gets deleted | Size |
|---|---|---|---|
| TC-3.1 | Android | the transport half of `QeliService.kt`, `protocol/*`, `crypto/*` | 2 wks |
| TC-3.2 | Windows | `VpnTunnelBase.cs` and `Protocol/*` from `qeli-shared` | 2 wks |
| TC-3.3 | macOS | the same (shared library with Windows) | 1.5 wks |
| TC-3.4 | iOS | `QeliTunnelEngine`, `*Transport`, `PacketCodec` | 2.5 wks |

**The order is deliberate:** Android first — it is the one that silently skipped M6, so the
divergence risk there is demonstrated; iOS last — the only platform with no fd and with a
memory ceiling.

**Acceptance for each:** that client's existing conformance tests still pass **against the
core**; lab e2e against a server; no regression in UI or notifications.

### TC-4. Build, CI, packaging — 2 weeks

| ID | Item |
|---|---|
| TC-4.1 | Android, Windows, macOS universal2 and iOS device+simulator **XCFramework** builds already exist for the native crypto/realtls core; extend that matrix to the whole-client core after the data plane is wired |
| TC-4.2 | Provenance and reproducibility for the native libraries |
| TC-4.3 | Gate: conformance vectors plus the TC-0.3 benches in CI |

### TC-5. Deleting the duplicates — 1.5 weeks

| ID | Item |
|---|---|
| TC-5.1 | Delete ~17,000 lines of ported protocol |
| TC-5.2 | Delete old **language implementations** only after the final client migrates. Keep the conformance/KAT fixtures as wire, crypto, configuration and `qeli://` regression tests even after only one executing implementation remains |

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
