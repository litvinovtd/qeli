# Q22: transport core, FFI/JNI and memory

<!-- normative-sync: audit-q22-final-v1 -->

**DONE/PASS. Plan: 22/37 (59.5%), 15 remaining.** 4 October 2026.
[Evidence](../../../../release/certification/evidence/q22-core-20261004.json).
ABI remains **1.16**; no configuration values or wire formats changed.

## Confirmed defects

| ID | Before | Fixed behavior |
|---|---|---|
| Q22-F001, P2 | Registry looked up an Arc before locking its object. A concurrent caller already queued on that mutex could observe partially mutated state after another operation panicked. The guard lived outside catch_unwind, so the mutex was not poisoned; retiring the public generation did not invalidate the queued Arc. | Acquire the object guard inside the unwind boundary. A panic poisons it before a queued caller can acquire it; poisoned access returns Panicked without invoking the operation. Retirement still checks the original generation, preserving replacement slots and unrelated handles. |
| Q22-F002, P2 | A control-operation panic retired the public ClientCore handle while an already leased native runner retained its Arc and an uncancelled token. Further stop/free through the retired handle could no longer request cancellation. | Every short client operation crosses one helper that sets the generation's cancellation token before resuming the unwind. Registry then poisons and retires that handle. The platform still joins its own IO worker before network cleanup. |

Both reproductions deliberately inject an internal Rust panic. No remote trigger,
Rust memory UAF or arbitrary-pointer safety guarantee is claimed. Baseline F001:
9 controls PASS and the queued-state regression FAIL with `Ok(77)`. Baseline
F002: 16 FFI controls PASS and the leased-runner cancellation assertion FAIL.
Fixed versions pass in the actual production modules.

## Layers reviewed

| Layer | Contract and qualification |
|---|---|
| Configuration and policy | Strict INI/qeli-link parsing and the pure configuration API remain shared. Service DTO JSON is separate from profile format. JNI temporary inputs and core-owned secret fields use their existing wipe paths; this is not a proof that every allocator copy is scrubbed. |
| Handles and concurrency | Opaque slot/generation handles reject stale/double free. Lookup does not hold the global registry mutex through an operation; separate objects remain parallel. Panic containment now covers queued short calls and cancellation of leased whole-generation runners. |
| Lifecycle and events | Create/start/plan ACK/stop/free, queue limits, typed protect/trust/management events and stale correlations. No packet backend before positive ACK. Stop requests cancellation even when event backpressure prevents state publication; callers must handle the returned error and drain/retry or dispose. |
| Runner and callbacks | One runner per handle, validated carrier inputs, shared handshake/data loops and task ownership. Cancellation races DNS/connect/handshake and callback waits. Completion uses the current counter identity, preventing an old generation from overwriting a later one. Rust events are polled into caller storage; Android serializes its two-stage poll through TransportCore's monitor. |
| Buffers and queues | Packet batches contain at most 64 packets with bounded lengths and exact partitioning. Pools apply backpressure, return allocations on drop and do not add fallback packet slots. Event and stats output preserve old prefixes, caller size markers and future tails. Pool byte budgets describe initial reservations; a retained Vec may grow for a larger supported record, so they are not universal hard heap limits. |
| Worker/descriptor ownership | Shared TaskGroup/TunWorkers own cancellation and joining; fd adoption duplicates the caller descriptor. Bridge generations, stale ACK and stop gates remain tested. Earlier Q21 privileged TUN evidence retains its original execution and unchanged-input scope. free invalidates public access; it is not a synchronous OS-route cleanup or a replacement for joining the platform worker. |
| Protocol and path seams | Session, framing, UDP receive/buffer/batch and TCP/UDP path adapters retain current-unit and Q10/Q12/Q17/Q21 scoped evidence. PREPARE/BIND/COMMIT outcomes distinguish reversible rejection from unknown platform state; failed cleanup remains terminal. Detailed roaming/resume review is Q23. |
| ABI and packaging | Fixed event=48 and stats V3=144 layouts, additive minor-version rules, 64-bit handles and required exports. Native cdylib builds enforce unwind; abort/fatal faults are outside catch_unwind recovery. All four packaged artifacts pass independent A/B and canonical/consumer matching. |
| Dead code | Reviewed helpers either serve active common paths, platform/feature-specific adapters or deliberate compatibility exports. cfg/allow(dead_code) alone is not evidence that a helper is unused. No additional separate parser or packet implementation was introduced. |

## Executed qualification

- **2402 full Linux units PASS, 60 ignored**, with `transport-core-ffi` enabled;
  strict all-target Clippy with that feature and CLI release PASS. Of these,
  213 cover transport_core, 17 cover its C ABI, and 10 cover the handle registry.
  The first default-feature pass also has 2384 PASS/60 ignored. The new queued
  regression and strengthened cancellation assertion both execute successfully.
- **22 checks on the fresh packaged Windows DLL PASS**: frozen/future output
  buffers, copied plans, stale ACK, packet-pool backpressure, 100 slot-reuse
  cycles, eight concurrent frees and actual localhost handshake cancellation.
  A second runner is refused; concurrent free cancels and joins the first.
  No Wintun or Windows route/DNS/firewall setup is exercised.
- **23 JNI checks PASS on Android 14/API34/x86_64** through a private app_process
  DEX loading the new A/B-verified libqeli.so. Includes real event framing,
  failure-vs-empty poll, 100 handle reuse cycles, cancellation before UDP probe
  registration and free/join while a real runner awaits socket-protect ACK.
  No APK is installed and no VpnService/TUN plan is applied. Original read-only
  AVD userdata hashes, packages and link inventory are preserved.
- Public header compiles/runs under **C11 and C++11**, checking layout offsets,
  initializers and major/minor compatibility. **Four native A/B PASS**:
  Windows x86_64, macOS universal2, Android arm64-v8a and x86_64. Current source
  provenance and all consumer copies match.

Linux CLI release is byte-identical to Q21:
`36a0e491f9437773b73b3e29f9c7ab0b7f624142e782dd78777f0c6168e6cef1`.
Its previous qualified network executions keep their real dates/evidence;
this pass does not claim another full Linux matrix or benchmark. Native libraries
changed and have fresh qualification.

## Boundaries and preserved state

The C ABI requires valid caller-owned memory and lifetimes; it cannot sandbox an
arbitrary invalid address. Panic recovery covers unwinding, not OOM abort or
process-fatal faults. The finite 32-bit slot generation retains its documented
wrap boundary; indefinite handle uniqueness is not asserted.

No Mac/iOS/router/Windows VM network runtime is claimed; those user-excluded
platforms keep their scope. Android proof is JNI lifecycle on the emulator,
not installed-app E2E or real VPN forwarding. No new config JSON support.

Both lab services and active/working executable hashes are preserved. The
previously accepted three-rule ambient legacy firewall delta on desktop remains
scoped. Native Android's 8 GiB preflight initially refused the build; only verified
inactive private Linux test/Clippy caches were removed after recording successful
results. Preparation failures are retained separately from final PASS. No working
binary replacement, push/deploy or new benchmark.

Next: **Q23 roaming, resume and CONTROL_V2**.
