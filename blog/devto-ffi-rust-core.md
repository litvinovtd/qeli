---
title: "FFI Is Not a Function Call: Moving Four VPN Clients into One Rust Core"
published: false
description: "How I replaced four drifting VPN transport implementations with one Rust data plane—and what TUN ownership, Wintun rings, iOS packetFlow, bounded memory, and a versioned C ABI taught me."
tags: rust, networking, mobile, opensource
---

I used to describe my VPN as having “one Rust core on every platform.”

That statement was technically true, but architecturally misleading.

The Android, Windows, macOS, and iOS clients all called Rust for important cryptographic operations. They did **not** share one complete transport implementation. Connection setup, configuration parsing, packet framing, reconnect logic, TUN handling, UDP behavior, and parts of the protocol still existed in Kotlin, C#, and Swift.

In other words, I had moved the algorithm but not the ownership.

That distinction became impossible to ignore when a protocol hardening change shipped in three implementations and silently failed to reach Android. The missing change was not a color, a label, or a notification. It affected how packet nonces were derived.

Cross-language known-answer tests caught it. Production architecture had allowed it.

So I decided to remove the duplicated transport implementations and make Rust own the entire client data plane: configuration, connection lifecycle, handshake, trust, TCP and UDP carriers, packet encryption, obfuscation, multipath, liveness, and packet pumps.

The platform applications would keep the things only a platform application can own:

- UI and notifications;
- Android `VpnService` and socket protection;
- Windows adapter and firewall integration;
- macOS routes, DNS, and `utun` creation;
- iOS `NetworkExtension` and `NEPacketTunnelFlow`;
- secure platform storage;
- applying a network plan to the operating system.

Everything that could affect bytes on the wire would have one implementation.

This article is about what that migration actually required. It is not a “call Rust from C# in five minutes” tutorial. Calling a function is the easy part. The hard part is deciding who owns a live tunnel while the network changes, the UI disappears, a file descriptor is duplicated, a worker fails, and another thread calls `stop()`.

The project is [Qeli](https://github.com/litvinovtd/qeli), an open-source self-hosted L3 VPN with a Rust server and native clients. It supports TCP and UDP transports, several wire modes, a hybrid X25519 + ML-KEM-768 handshake, and a full TUN data plane. The details are specific to a VPN, but most of the lessons apply to databases, media engines, browsers, game runtimes, and any other native core embedded into several host languages.

## The starting point: four implementations of “the same” client

Before the migration, the rough production-code picture looked like this:

| Codebase | Total lines | Protocol/transport logic |
|---|---:|---:|
| Shared C# code for Windows and macOS | 7,627 | about 6,200 |
| Android/Kotlin | 8,469 | about 5,200 |
| iOS/Swift | 10,668 | about 5,700 |
| **Duplicated logic** | | **about 17,000** |

The largest files told the story:

- Android's `QeliService.kt` mixed `VpnService`, connection lifecycle, packet transport, and reconnect behavior;
- the shared C# `VpnTunnelBase.cs` handled configuration, handshakes, transport, packet loops, and recovery;
- iOS had its own `QeliTunnelEngine.swift`;
- every platform parsed a similar but not perfectly identical configuration model.

The Rust server already had mature implementations of the client protocol, configuration, crypto, TCP, UDP, REALITY-style TLS transport, QUIC-shaped datagrams, traffic shaping, and bonding. The migration did not need another protocol implementation. It needed a safe way for four very different operating systems to consume the existing one.

That sounds like an FFI problem. It is really an ownership problem with an FFI boundary in the middle.

## Why wrappers were not enough

The project already exposed native functions for operations such as key exchange and TLS record handling. A managed client could call Rust, receive a byte array, and continue in Kotlin or C#.

This removed some cryptographic duplication, but it preserved the most dangerous kind of duplication: **the state machine around the cryptography**.

A VPN client is not a pure function from configuration to encrypted packet. It is a long-lived collection of state:

```text
configuration
    ↓
physical-network DNS resolution
    ↓
TCP/UDP carrier
    ↓
server identity decision
    ↓
authenticated NetworkPlan
    ↓
routes + DNS + TUN attachment
    ↓
packet workers + heartbeat + reconnect
    ↓
ordered teardown and OS-state restoration
```

If Rust encrypts packets while C# owns reconnects and Kotlin owns TUN teardown, there is no single component that can state the tunnel's invariants.

For example:

- Is a connection “running” after authentication, or only after routes and DNS were applied?
- Can packet workers start before the platform has protected the Android carrier socket from the VPN itself?
- What happens if a network plan belongs to generation 12 but the UI acknowledges it after generation 13 has started?
- Who is allowed to close the Wintun session while a Rust worker still holds a received ring packet?
- Does `stop()` mean “request cancellation,” “the native workers exited,” or “the operating system's DNS has been restored”?

A thin crypto wrapper cannot answer any of those questions.

## Drawing the boundary

The first useful design decision was a rule:

> Rust owns protocol truth and tunnel lifetime. The platform owns privileged operating-system effects.

The Rust core owns:

- strict parsing of the complete client profile;
- carrier creation and connection deadlines;
- protocol and server authentication;
- device identity input and server trust requests;
- the authenticated network plan;
- TCP, UDP, QUIC-shaped and TLS-based transports;
- packet encryption and decryption;
- heartbeat, liveness, traffic shaping, and multipath;
- packet queues, buffer pools, counters, and reconnect policy;
- one complete connection generation from start to teardown.

The host application owns:

- obtaining or creating the platform's packet interface;
- applying IP addresses, routes, MTU, DNS, and kill-switch policy;
- Android's `VpnService.protect()` call;
- presenting an unknown server identity to the user and reading the decision;
- secure persistence of device and trust state;
- platform-specific recovery after a crash;
- UI, logs, and notifications.

The boundary is deliberately asymmetric. Rust produces a declarative `NetworkPlan`; it does not shell out to `route`, edit Windows interfaces, or call Apple frameworks through a growing forest of conditional compilation. The platform applies the plan and explicitly acknowledges success or failure.

That gave me a portable invariant:

```text
authenticate
    → publish NetworkPlan(generation)
    → platform applies it
    → platform attaches packet device
    → platform ACKs the same generation
    → and only then may packet loops run
```

No ACK, no data plane.

## A C ABI that represents a lifecycle

The public ABI started small, then grew additively as each platform exposed another missing assumption. The current header identifies ABI 1.10:

```c
#define QELI_CLIENT_ABI_VERSION UINT32_C(0x0001000a)

uint32_t qeli_client_abi_version(void);
uint64_t qeli_client_core_capabilities(void);

int32_t qeli_client_new(
    const uint8_t *config,
    size_t config_len,
    uint64_t platform_capabilities,
    uint32_t event_capacity,
    uint64_t *out_handle
);

int32_t qeli_client_start(uint64_t handle);
int32_t qeli_client_run(
    uint64_t handle,
    const uint8_t *input,
    size_t input_len
);
int32_t qeli_client_stop(uint64_t handle);
int32_t qeli_client_free(uint64_t handle);
```

This looks conventional until `run()` enters the picture. `run()` owns one complete transport generation and blocks on a platform I/O worker. A second worker drains events and acknowledges platform requests. The core must therefore allow `stop()` while `run()` is active.

A naive implementation would lock the handle, call the long-running Rust future, and keep the lock until it returned. That makes `stop()` wait for `run()`, while `run()` waits for cancellation from `stop()`: an FFI-shaped deadlock.

The handle layer instead validates and leases the session, releases its short control lock, and only then enters the blocking runner. `free()` invalidates the public handle and requests cancellation, but the adapter still joins its own worker because the leased runner may return after the public handle has disappeared.

This is the kind of contract that needs to be written down. “Thread-safe” is too vague to be useful.

## Versioning: structures grow, prefixes do not move

I wanted minor ABI versions to be additive. A newer library can serve an older host as long as the major version matches and the library minor version is not older than the header expected by the host.

Output structures begin with their size and ABI version:

```c
typedef struct qeli_client_stats {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t state;
    uint32_t reserved;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t reconnects;
    uint64_t uptime_ms;

    /* Appended in ABI 1.10. */
    uint64_t udp_kernel_drops;
    uint64_t udp_internal_drops;
    uint64_t udp_buffer_grows;
    uint64_t udp_recv_buffer_bytes;
} qeli_client_stats_t;
```

The original V1 prefix remains 64 bytes. ABI 1.10 appends fields instead of changing the prefix. The caller provides `struct_size`; Rust writes only the portion the caller understands.

The same rule applies to capabilities, event kinds, negative result codes, and JSON payloads:

- unknown capability bits must be ignored;
- unknown additive JSON fields must be tolerated;
- an unknown negative result is still a failure;
- the major ABI must match;
- callers must check the capability they need instead of inferring it from a version number.

Capabilities made staged migration possible. An Android build could require native data-plane ownership and socket-protection acknowledgements, while an older desktop build could continue using only the functions it understood.

## Upcalls without calling arbitrary host code from Rust

Rust sometimes needs an operation that only the host can perform. Android is the clearest example: every VPN carrier socket must be passed to `VpnService.protect()` or the socket's own traffic may be routed back into the VPN.

I could have stored language callbacks and invoked Kotlin, C#, or Swift directly from arbitrary Rust worker threads. I chose not to.

Instead, the core publishes bounded events:

```c
enum qeli_client_event_kind {
    QELI_CLIENT_STATE_CHANGED = 1,
    QELI_CLIENT_NETWORK_PLAN = 2,
    QELI_CLIENT_ERROR = 3,
    QELI_CLIENT_SOCKET_PROTECT = 4,
    QELI_CLIENT_SERVER_IDENTITY = 5
};
```

The platform event pump polls them, performs the operation in its own runtime, and returns an acknowledgement containing the request or plan generation.

This design costs more ceremony than a callback, but it provides several useful properties:

- no surprise re-entrancy into the managed runtime;
- no callback executing on an undocumented Rust thread;
- every request has a correlation identifier;
- stale acknowledgements can be rejected;
- the event queue is bounded;
- the protocol is testable without Android, Windows, or Apple frameworks;
- platform rejection becomes an explicit state transition, not a thrown exception crossing FFI.

The core also refuses to pretend an unsupported feature succeeded. If a network plan requires a kill switch, the platform must advertise that capability and positively acknowledge enforcement. An Android app without system Always-on VPN lockdown cannot truthfully claim the requested fail-closed behavior, so the connection is rejected instead of silently weakening the profile.

## Generations: handles are not enough

A 64-bit handle prevents the host from passing raw Rust pointers around. It does not solve stale asynchronous work.

Consider this sequence:

1. generation 41 authenticates and publishes a network plan;
2. the physical network changes;
3. generation 41 is cancelled;
4. generation 42 starts;
5. a delayed UI or platform worker acknowledges generation 41.

If the core accepts that ACK, generation 42 may start packet loops using routes, DNS, or a TUN descriptor created for generation 41.

Every long-lived platform interaction is therefore generation-scoped:

- network plans;
- TUN file descriptors;
- iOS packet batches;
- Android socket-protection requests;
- server-identity decisions.

Stale inputs fail with a distinct error instead of being “close enough.” This also prevents a descriptor from a previous connection from being attached to a reused public handle.

It felt repetitive while implementing the ABI. It became invaluable as soon as reconnects, sleep/wake transitions, and cancellation started racing each other.

## Android: a file descriptor plus one critical upcall

Android's `VpnService` creates the TUN interface and returns a file descriptor. Rust cannot create that interface by itself because Android owns the permission and user-consent flow.

The active path now works like this:

1. Kotlin creates a client-core handle and starts its event pump.
2. Rust resolves and creates a carrier.
3. Rust requests socket protection.
4. Kotlin calls `VpnService.protect()` and acknowledges the exact request.
5. Rust authenticates and publishes a `NetworkPlan`.
6. Kotlin configures `VpnService.Builder`, establishes the TUN, and passes a generation-scoped descriptor to Rust.
7. Rust duplicates it with close-on-exec semantics and becomes the sole payload reader and writer.
8. Kotlin ACKs the plan; packet workers start.

There is no Kotlin fallback packet engine in the production path. That deletion matters. A dormant second implementation has a habit of becoming an accidental fallback after a future error-handling change.

The migration reduced `QeliService.kt` from 3,921 to 1,443 lines. The remaining service code handles Android lifecycle, notification state, user-visible configuration, the platform network plan, and other things that actually belong in Kotlin.

## Windows: Wintun rings and a real use-after-free class

Windows was the strongest argument for moving ownership, not merely byte transformations.

Wintun exposes a ring-oriented API. The old managed path opened the session and let C# coordinate receive packets, sends, cancellation, and disposal. That created a dangerous ordering problem: a session could be disposed while another worker still held a packet obtained from its ring.

The failure class was a use-after-free inside `wintun.dll`.

The new ABI lets Rust own the Wintun session and its rings:

- C# creates a uniquely named Qeli adapter and keeps the creator handle for interface lifetime and network cleanup;
- Rust opens an independent Wintun handle and starts the session;
- a received uplink packet stays in the Wintun ring until a Rust RAII owner releases it;
- workers are joined before `WintunEndSession`;
- the session lives behind shared Rust ownership while packets are outstanding.

The uplink path no longer copies payload through C#. The downlink still requires one unavoidable copy from the bounded Rust decrypt buffer into a Wintun send-ring allocation, but there is no managed/FFI packet hop.

This is a good example of why language memory safety is not enough. Rust cannot make a native library safe if another language can destroy the resource behind Rust's borrowed pointer. The ownership model has to include the foreign resource.

## macOS: `utun` is a file descriptor, with a prefix

The global-tunnel macOS client can hand Rust a duplicated `utun` descriptor. That sounds similar to Android, but `utun` packet framing includes a four-byte address-family prefix.

The shared Rust backend therefore:

- removes the prefix on uplink;
- adds it on downlink;
- uses nonblocking reader and writer workers;
- uses vectored writes so adding the prefix does not require building a temporary payload buffer;
- owns only the duplicate, while the platform retains what it needs for interface and route cleanup.

The C# macOS layer no longer has payload read/write methods. It opens the interface, applies the plan, hands over the fd, and deals with macOS-specific DNS and route restoration.

Per-application routing is a separate platform path using signed Network Extensions, but selected flows still enter the same Rust packet-device ABI. The transport is not reimplemented inside the extension.

## iOS: there is no TUN file descriptor

iOS forced the API to become honest.

`NEPacketTunnelProvider` exposes `NEPacketTunnelFlow.readPackets()` and `writePackets()`. It does not give the application a TUN file descriptor that Rust can poll.

So iOS uses a bounded batch seam:

```c
int32_t qeli_client_tun_push(
    uint64_t handle,
    uint64_t generation,
    const uint8_t *packets,
    size_t packets_len,
    const uint32_t *lengths,
    size_t packet_count,
    size_t *out_accepted
);

int32_t qeli_client_tun_pull(
    uint64_t handle,
    uint64_t generation,
    uint8_t *packets,
    size_t packets_capacity,
    uint32_t *lengths,
    size_t length_capacity,
    size_t *out_packet_count,
    size_t *out_bytes
);
```

Swift batches packets into caller-owned contiguous storage. Rust may accept only a prefix when its bounded queue is full; the caller retains and retries the remainder. Downlink polling similarly writes into buffers supplied by Swift.

The memory budget had to be designed before the implementation because Network Extensions have a strict practical memory ceiling. The core uses two pools of 32 × 65,535 bytes—4,194,240 bytes in total—plus Swift-side caller buffers capped below 768 KiB and bounded queues of 128 entries. There is no fallback allocation that quietly turns a burst into an out-of-memory termination.

Eight Swift runtime files, totaling 4,046 lines, were removed from the active transport path. Swift now owns Apple-specific policy and packetFlow adaptation rather than a second VPN protocol.

There is an important status caveat: the iOS code is feature-complete and built by CI for device and simulator targets, but it has not yet completed physical-device interoperability and release signing. It does not ship today. “Compiles for iOS” and “is a released iOS VPN” are very different claims.

## The hot path: moving ownership without moving allocations

Centralizing the transport would have been a regression if every packet crossed FFI as a new allocation.

The target was not “zero allocation everywhere.” Handshake, control messages, and configuration parsing are not hot enough to justify hostile APIs. The target was:

> No new allocation or managed-language copy for each data-plane packet on active paths.

The core uses bounded, reusable storage:

- TUN readers obtain packets from a pool;
- encryption writes into caller-owned or connection-owned buffers;
- decryption happens in place;
- padding and normalization reuse task-owned scratch space;
- QUIC-shaped UDP envelopes reuse a dedicated buffer;
- server downlink records live in a bounded session pool until the socket write completes;
- bonded TCP streams share one session budget rather than multiplying memory by stream count.

The pool capacity follows what a profile can really emit—its MTU, heartbeat, and shaping limits—rather than always allocating for the absolute protocol maximum. Pools are created only after authentication, so half-open connections cannot reserve several megabytes each before proving who they are.

Exhaustion behavior depends on transport semantics:

- TCP applies backpressure;
- UDP drops and increments an observable counter;
- neither path performs an emergency allocation that defeats the memory bound.

This distinction is important. A “bounded queue” followed by `Vec::reserve()` on overflow is not a bounded system. It is a system with a decorative bound.

## Performance was evidence, not the reason

Before the migration I benchmarked equivalent packet-codec operations over 200,000 packets of 1,400 bytes on the same two-core lab CPU.

| Operation | Managed C# | Rust |
|---|---:|---:|
| Packet encryption | 81.9 MB/s | 208.4 MB/s |
| Packet decryption | 133.1 MB/s | 317.5 MB/s |

The managed run allocated about 2.3 GB while processing 280 MB of useful data and triggered 309 generation-0 collections. Rust's packet codec was roughly 2.4–2.5 times faster in that microbenchmark.

Those numbers made the mobile battery and GC argument easier. They did **not** justify the refactor by themselves. Even the older C# implementation could encrypt faster than the production server's one-core throughput ceiling. The migration was justified by semantic drift, testing cost, and ownership defects.

After the shared core was active, the lab baseline still reached approximately:

- TCP fake-TLS: 469 Mbit/s upload and 701 Mbit/s download;
- TCP obfs: 540 Mbit/s upload and 562 Mbit/s download;
- UDP: 300 Mbit/s with 0.06% loss, rising to 1.86% at 400 Mbit/s on that host.

These are regression baselines, not universal product claims. VM contention, host CPU, transport mode, and network conditions matter much more than a single impressive number.

## Migration order: prove the architecture before deleting the old path

I did not replace all clients in one commit.

The migration was staged:

1. **Freeze the control ABI.** Define result codes, states, events, capabilities, ownership, panic behavior, and structure versioning.
2. **Route the Linux client through the same lifecycle internally.** This proved the API against the existing Rust implementation without crossing a language boundary.
3. **Move Android incrementally.** TUN ownership, socket protection, stable device identity, server trust, authenticated network plans, then the complete native data plane.
4. **Move desktop clients.** Add the generic packet seam, switch Windows and macOS transport, then move native `utun` and Wintun ownership into Rust.
5. **Connect iOS packetFlow.** Use the same lifecycle with a platform-specific batched packet adapter.
6. **Delete production duplicates.** Keep cross-language known-answer code only where it still provides independent conformance evidence.

The order mattered. Android went first because it had already demonstrated real protocol drift. iOS went last because it was the only platform without a file descriptor and had the strictest memory constraints.

During a staged migration, dual paths are tempting: “If the new native core fails, fall back to the old Kotlin engine.” I removed that fallback once each path met its acceptance criteria. A hidden fallback preserves the maintenance problem and can turn a strict failure into silent protocol divergence.

## How I checked that one implementation still behaved like four clients

Deleting independent implementations reduces one kind of test diversity. I did not want to replace it with faith in a shared library.

The verification layers are different because they catch different failures.

### Cross-language conformance fixtures

The repository contains generated and hand-written JSON vectors for:

- HKDF derivation;
- packet encode/decode;
- nonce permutation;
- replay windows;
- UDP fragmentation;
- QUIC-shaped envelopes;
- configuration links.

Each fixture declares its schema and semantics. CI regenerates derived fixtures and fails if committed vectors are stale.

Randomized objects such as a browser-shaped ClientHello cannot be pinned byte for byte, so their tests check structural invariants instead. “Golden file everything” is not a useful strategy when randomness is part of the protocol.

### Configuration source contracts

The Rust parser is authoritative for production transport. Platform editors still need to open, preserve, validate, and save applicable fields. A source-level contract checks that Rust, Kotlin, C#, and Swift recognize the same set of 73 configuration keys.

This does not make four parsers equally authoritative. It prevents a GUI from silently deleting a field it does not display.

### ABI layout and panic tests

The C header contains compile-time size assertions. Rust tests verify that headers expose expected symbols and structure sizes.

The FFI build uses unwind semantics and catches panics at the boundary, converting them to a stable error code. A Rust panic must never unwind into Kotlin, C#, Swift, or C.

### Permanent microbenchmarks

The one-off PacketCodec comparison became release-mode Rust and C# benchmark gates. They are regression alarms, not marketing benchmarks.

### End-to-end tests

Network-namespace tests cover routing and kill-switch behavior. Lab tests create temporary profiles and users, authenticate real TCP and UDP sessions, move packets through TUN, exercise multiple wire modes, and clean up afterward.

Compile-only checks remain useful, but they are labeled honestly. A Windows DLL exporting the right symbols does not prove that an elevated Wintun tunnel passes traffic. An iOS XCFramework does not prove that NetworkExtension survives on a physical device.

## Native artifacts became part of the threat model

Once every client embeds the same Rust transport, a stale or incorrectly built native library can invalidate all source-level guarantees.

The repository therefore treats native artifacts as controlled inputs:

- toolchain versions are pinned;
- required exports are checked;
- canonical libraries and copies consumed by each app must match;
- SHA-256 manifests are verified;
- source provenance is recorded;
- independent A/B builds must be byte-identical before an artifact is accepted.

The reproducibility work found platform-specific noise, especially in Mach-O metadata. The build pipeline normalizes items such as install names and content-derived identifiers before comparing outputs.

This may sound separate from FFI design. It is not. If a host binary and native core disagree about ABI or source revision, the boundary is broken before the first function call.

## What the migration removed—and what it did not

The source migration removed roughly 17,000 lines of duplicated protocol and transport logic.

Some visible reductions were:

- Android service transport: 3,921 → 1,443 lines;
- shared desktop `VpnTunnelBase.cs`: 3,287 → 1,126 lines;
- iOS: eight transport runtime files and 4,046 lines removed;
- managed desktop payload reads and writes removed from the active path.

But “less code” was not the most important result.

The more important result was a change in what can diverge:

- Android can have different notification behavior, but not a different packet nonce algorithm;
- iOS can have different packet-interface plumbing, but not different TLS record parsing;
- Windows can have different route and firewall integration, but not a different reconnect state machine;
- macOS can have a different DNS recovery mechanism, but not a different authenticated network plan.

Platform differences are now explicit adapters instead of accidental forks.

The migration did **not** remove platform complexity. Windows still has Wintun and firewall state. macOS still has code signing and Network Extensions. Android still has `VpnService` lifecycle and system lockdown policy. iOS still has packetFlow, entitlements, and strict memory constraints.

One Rust core does not make operating systems uniform. It makes their differences visible at one boundary.

## Mistakes and lessons

Several conclusions became clearer only after doing the work.

### 1. An FFI API is a concurrency protocol

Function signatures are the smallest part of the design. Document:

- which calls may block;
- which calls may run concurrently;
- who owns each buffer and handle;
- whether `stop()` requests or completes shutdown;
- what happens when `free()` races with a runner;
- how callbacks or events are scheduled;
- how stale asynchronous results are rejected.

If the documentation only lists parameters, the real ABI exists as folklore.

### 2. Put generation numbers on asynchronous authority

Any operation that can outlive a connection attempt needs a generation or correlation identifier. Handles alone do not prevent a delayed response from mutating a newer session.

### 3. Do not cross FFI per packet unless the buffers are designed first

An API that returns a newly allocated `Vec<u8>` for every packet is fine for a prototype and expensive as a permanent architecture. Decide buffer ownership, batching, backpressure, and exhaustion semantics before moving the hot path.

### 4. Move resource ownership, not just algorithms

The Wintun UAF class disappeared only when the session, outstanding packets, worker joins, and teardown order entered one ownership model. Wrapping encryption in Rust would never have fixed it.

### 5. Keep OS policy out of the portable core

The portable core should say what network state is required. The platform should say whether it can enforce that state. This keeps the Rust state machine testable and prevents a maze of half-portable system calls.

### 6. Reject unsupported security properties

If a platform cannot apply a kill switch, server trust decision, route, or DNS requirement, return a failure. Silently dropping a requirement makes a green “Connected” badge a security bug.

### 7. Observability is part of the ABI

The first versions focused on control and packet flow. Once the managed implementations disappeared, so did some familiar logs and counters. I had to expose a native connection journal, structured state events, and UDP drop/buffer telemetry.

Centralizing behavior without centralizing diagnostics makes every platform feel less debuggable.

### 8. Reproducible native builds are not optional glue

When four apps embed one privileged network engine, knowing which source produced each `.so`, `.dll`, or `.dylib` is part of security and incident response.

### 9. A successful cross-build is not a platform test

The code migration is complete, but several acceptance gates still require the real environment: elevated Wintun full-tunnel testing, live macOS `utun`, and physical-device iOS interoperability. Those are release gates, not footnotes to be hand-waved away.

## Current status

At the time of writing:

- Linux uses the common lifecycle through an in-process adapter;
- Android uses the Rust-owned transport and packet pumps;
- Windows uses the shared transport, with Wintun ownership implemented in Rust;
- macOS passes `utun` packet ownership to Rust;
- iOS uses the common core through the bounded packetFlow seam;
- production Kotlin, C#, and Swift transport duplicates have been removed;
- native libraries use additive ABI 1.10;
- conformance, ABI, benchmark, fuzz, build, and provenance gates run in CI.

The project is still pre-1.0. The iOS client is not released and has not completed physical-device testing. The remaining platform acceptance work is tracked openly rather than converted into a claim of universal readiness.

That honesty is important for low-level software. “Source complete,” “CI builds,” “lab-tested,” and “released on real hardware” are four different milestones.

## Closing thought

Before this migration, I thought of FFI as a border between languages.

Now I think of it as a border between ownership models.

The border has to carry more than byte arrays. It has to carry state, authority, cancellation, memory limits, errors, capabilities, generations, and proof that the platform really applied what the core requested.

Once that contract existed, the language boundary became almost boring—which is exactly what I wanted. Kotlin, C#, and Swift stopped being independent VPN implementations and became native platform adapters around one Rust transport.

The result was not “Rust everywhere.” The result was one place where the protocol is true.

Qeli is open source, and the transport-core design, C header, conformance fixtures, and platform clients are available in the [GitHub repository](https://github.com/litvinovtd/qeli). If you are building a multi-platform native core, I would be especially interested in how you handle generation-safe platform requests, packet-buffer ownership, and reproducible native artifacts.
