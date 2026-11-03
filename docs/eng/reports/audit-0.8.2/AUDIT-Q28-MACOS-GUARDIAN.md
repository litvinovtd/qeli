# Q28: guardian readiness and generation ownership

<!-- normative-sync: audit-q28-macos-guardian-v1 -->

**5 October 2026: C# stage PASS; Swift SOURCE REVIEW, compile/runtime USER SKIPPED. Q28 IN_PROGRESS, plan 27/37 (73.0%), 10 sections remain.**

## Fixes

| ID | Problem and change |
|---|---|
| F265 | A live child was treated as ready before consuming state; guard published state before parent validation. Parent is checked before handoff read and again before claim. C# waits for the exact 32-byte token after claim (up to 5 seconds), refuses exit/foreign/empty/oversized acknowledgements and never reuses an unacknowledged child. Handoff removal follows acknowledgement or error handling. |
| F266 | Heartbeat/down/stop and dead-guardian cleanup acted on whichever state existed; a file lock did not protect manager operations from old generations. Schema v5 carries owner PID/token, guardian PID and confirmed release. Every mutation checks its generation; manager operations and claims are serialized separately from heartbeat. Replaced/retired guardians exit without manager mutation. Update preserves the current lease instead of restoring stale handoff time. State reads/writes are capped at 1 MiB; flock waits at 5/190 seconds. |
| F267 | Join retry repeated stop after confirmed cleanup; reconfiguration could resume before join. The controller remembers confirmed stop, retries join only, including a missing helper file. New start waits for retirement; successful retirement rotates the token. Log observer errors no longer replace activation/recovery outcomes. |

## Checks

- perapp-selftest **39/39 PASS**, including **17 new** checks over the previous 22. Production controller with fake helper/platform plus real isolated child processes for readiness/join: delayed exact ack, no ack, foreign/empty/oversized token, early exit and stale ack. Covers DTO/down/stop token, update stability/new-start rotation, reconfiguration refusal until join, retry without another stop/helper file and observer errors.
- Unchanged old C# controller: **9/9 expected FAIL**. Transitions use its original injected constructor; actual private EnsureGuardian is invoked by reflection with an owned no-ack child. Only platform/helper boundaries are replaced; Swift ownership is neither simulated nor validated by these cases. Nine scenarios do not mean nine independent defects.
- Fresh related checks: forwarding **58**, network **117**, control **83**, storage **54**, Windows **325**, shared **549 PASS**; total **1225 managed PASS**. Three Release builds, baseline and no-ack child build have zero warnings/errors; Shared DLLs match byte-for-byte. Docs/bindings/panel/diff PASS; Rust/native source digest and all 14 native hashes remain unchanged.
- **10 Swift owner/policy cases** added; helper/store/provider interfaces reviewed by source. These cases and Swift compiler/Xcode were **not executed**. Darwin parenthood/flock/app group, manager callbacks, activation/signing, actual helper readiness and crash/network cleanup **USER SKIPPED**, not PASS. C# tests do not validate Swift manager serialization/runtime.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-guardian-20261005.
Evidence: release/certification/evidence/q28-macos-guardian-20261005.json.

## Compatibility and boundaries

Helper, host and extension use internal schema v5 and must be upgraded together as one signed bundle. Stop old profiles and join old guardians first. Version-4/unknown-owner state is not automatically taken over. If old per-app-state.json remains, first confirm old Qeli managers/guardians stopped, preserve a copy, then remove only that stale state in the Qeli app-group container. Do not remove active/unknown-owner state. New completed tombstones remain: subsequent claim is allowed after confirmed stop even while the old parent is alive.

One active Qeli per-app owner is allowed per Mac. A foreign live PID blocks takeover; PID reuse may conservatively refuse and require administrator inspection. Token and parenthood protect cooperating v5 Qeli, not old binaries, independent writers or app-group compromise. Missing state/unknown cleanup remains an error; absence does not prove manager stop. Providers retain the existing expired-lease policy: fail open after owner loss. Heartbeat is not a continuity guarantee under lock/I/O stalls.

190 seconds bounds operation-lock waiting and separately the short helper runner, not all NetworkExtension callbacks combined. A 5-second readiness budget does not guarantee arbitrary filesystem syscall interruption. Callback timeout/process death cannot guarantee cancellation of OS operations already admitted. Actual Mac is user-excluded. User configs remain INI; JSON is internal DTO exchange.

Remaining Q28: native socket lifetime/connect/write bounds and final integration review, including old DNS/PF UTC identity stamps. Historical release cases, artifact/timestamps and physical rows are preserved; no fresh Linux/JNI/native A/B/soak/benchmark. Lab, network, services and user profiles were unchanged; no push/deploy.
