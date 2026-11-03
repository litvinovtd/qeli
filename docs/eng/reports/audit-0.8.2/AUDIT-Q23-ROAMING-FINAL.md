# Q23: roaming, resume and CONTROL_V2

<!-- normative-sync: audit-q23-final-v1 -->

**DONE/PASS. Plan: 23/37 (62.2%), 14 remaining.** 4 October 2026.
[Evidence](../../../../release/certification/evidence/q23-roaming-20261004.json).
No INI option, public ABI or wire-format change.

## Confirmed defect Q23-F001 (P2)

The one-shot TCP orphan reaper correctly defers to a prepared resume. If its
original grace deadline passes and the resume then aborts, the old code returns
to Orphaned without another timer. The session can retain its address, locator,
4 MiB record reservation and profile orphan budget until another external
cleanup; ordinary grace expiry alone no longer releases them.

abort_resume now returns the exact original ReapTicket for an orphan fallback.
A single server helper rearms an overdue ticket on all four failure paths: stream admission,
JOINOK send, client commit confirmation and server commit. The generation and
original deadline are preserved; an overdue ticket runs immediately. Before the deadline the original timer remains responsible, avoiding duplicate future timers. Active
fallback returns no ticket. Stale/terminal abort does not spawn cleanup. Duplicate
or superseded reapers cannot remove a resumed/replaced session or release twice.

Two counterfactual regressions fail on the old state transitions and pass on the
fix. The standalone baseline adds only an old () -> Ok(None) return-shape shim to
compile the ticket assertion; it is not an untouched whole-server binary run.
Final units also exercise the actual server wrapper. Live gates qualify normal
resume and expiry; they do not inject the exact delayed JOIN-abort race in a
running process. That interleaving is deterministically checked in unit tests.

## Test fixture correction Q23-T001

The multinode fixture used two workers in one network namespace, conflicting
with the existing exclusive worker owner. The second node now has its own
namespace and router link; DNAT preserves the client endpoint. Foreign locator
rejection and full AUTH remain required. The failed fixture run is retained,
then the corrected case passes all 28 checks. No production owner guard is weakened. UDP supersede/commit-race also move the
physical C probe before client startup, bind its device and restore rp_filter;
the previous post-start source-bound probe conflicted with the active A bypass.
These fixture corrections leave product transport code and gate assertions intact.

## Layers reviewed

| Layer | Contract and evidence |
|---|---|
| Negotiation | Authenticated capability intersections, profile enablement and complete platform ROAMING_PATH contract. Resume and make-before-break are separate authorities. Legacy bearer JOIN is refused for an authenticated-resume session. |
| TCP proof/reservation | Locator, fresh-handshake transcript, epoch, logical slot and handover bit enter the proof. Epoch burns on reservation; one candidate and bounded orphan sessions/bytes. Invalid proof, stale epoch, busy/draining slot, revoke and replacement generations remain tested. |
| TCP commit/cleanup | JOINOK only prepares a real non-ready stream slot. Client commits the platform before JOINCOMMIT; server publishes and retires the old carrier before JOINCOMMITOK. Explicit rejection remains reversible; lost/unknown platform commit requires reconnect. Abort after deferred grace now rearms the exact ticket. |
| UDP ingress/validation | Session codec performs AEAD and replay checks before candidate mutation. Directional CIDs/epoch and exact peer/receiving worker/token bind validation; immutable codec owner survives family/listener switch. Unvalidated egress is capped at three times authenticated ingress, with byte accounting, profile candidate count/rate and fixed 10-second TTL. Duplicate INIT cannot refresh lifetime. |
| UDP commit/retry | Publish callback runs before registry rotation; rejected publication retains the candidate. Exact committed response is replayed without publication again. Client retry interval 500 ms/max four transmissions, two-phase platform ACK, generation-scoped abort and one 15-second NAT recovery attempt per active epoch. |
| PMTU/drain | Commit creates a new PMTU generation and conservative payload budget; stale tickets cannot raise it. Previous-path drain is receive-only and bounded; old control/PMTU cannot advance current state. Q21 PMTU/fragment evidence remains unchanged-input scoped. Fresh family and NAT gates retain process/TUN/session ownership. |
| CONTROL_V2 | Authenticated/capability-gated framing, strict lengths/status flags and ordered bounded fragments. At most 8 inflight messages, 16 parts/64 KiB each, 5-second expiry and 64 completed IDs. Duplicate identity includes type, flags, parts and payload digests. Management receipt follows semantic acceptance; failed payload cannot poison a corrected ID. |
| Restart/APPLY/server boundary | Resume state is process-local. An independent server rejects the foreign locator; auto falls back to full AUTH after carrier loss. No transparent cross-server session replication or restart resume. Existing profile APPLY/rollback evidence keeps its own scope; no PUSH_CONFIG handler exists beyond the framing constant/tests, so live hot push is not claimed. |
| Ownership/dead code | TCP/UDP actors share core state and task owners; platform adapters own sockets/routes/ACK. Reviewed state methods and wire helpers have production, feature or compatibility callers. No duplicate implementation or removable dead path was confirmed. |

## Executed qualification

- **2405 full Linux units PASS, 60 ignored**, with transport-core-ffi;
  strict all-target Clippy and release PASS on .10 with Rust 1.97.0,
  one build job and dev/test debug=0. Three new regressions: overdue
  hard-resume abort, old-carrier loss during prepared handover, server wrapper.
- **24 targeted TCP/CONTROL_V2 tests PASS** in actual copied production modules;
  wire module production is included, its full-crate-dependent tests omitted
  from this small harness and executed by the full unit run. The focused harness
  completed earlier on .11; final full Linux qualification runs on .10. Two baseline
  expected failures are separate from final PASS.
- **12 fresh isolated Linux cases, 281 checks PASS**: TCP handover, hard
  resume, grace expiry, independent-server rejection/full AUTH; UDP success,
  rollback, supersede, commit race, loss/replay, IPv4/IPv6 switch and NAT rebind;
  TCP soak with **100 committed path flips**. Soak resource samples cover fd,
  socket, state and RSS bounds; 100 is the bounded release gate, not
  a new 10,000-flip endurance run or throughput benchmark.
- All **four native artifacts pass independent A/B**; canonical and consumer
  copies match current provenance. They remain byte-identical to Q22, so its
  22 Windows ABI, 23 Android JNI and header qualifications retain their original
  dates/libraries. No repeated device or OS network execution is claimed.

All runtime gates use the new private Linux candidate. Only the existing
linux.roaming-flap-soak certification row receives fresh execution/SHA/evidence;
other matrix rows retain their actual prior artifacts/dates and scoped evidence.
This is not another full transport-mode/IPv6 release matrix. Baseline harness
preparation failure and the outdated multinode fixture failure are retained
separately. Android A/B uses the pinned recipe on .10 with one build job after
network execution; compilation flags, toolchain and A/B/export/hash gates remain
unchanged. Final service/active-binary preservation is verified on .10, as are
the user's two unrelated local edits.

.11 stopped sending an SSH banner during overlapping private compilations.
The cause is unconfirmed: memory overload is plausible, no OOM diagnosis is
claimed. Those attempts are not counted as qualification. No accessible VM
console/hypervisor was found; final .11 service state is unverified. The complete
required full Linux/runtime/native Q23 gates run on .10; .11 availability remains a separate lab incident.

## Boundaries

NAT64, physical Wi-Fi/LTE/sleep-wake and installed Android VPN app E2E are not
rerun here. Mac/iOS/router/Windows VM network runtime stays user-excluded. Existing
accepted Q25-A125 WAN replacement and ambient legacy firewall limits remain.
Completed-ID caching is bounded, not infinite semantic replay history. CONTROL_V2
is service traffic; profile configs remain INI. No deployment or push.

Next: **Q24 multipath, bonding and shared budget**.
