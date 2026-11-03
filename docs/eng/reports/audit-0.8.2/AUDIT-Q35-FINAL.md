# Q35 — final fuzz, fault, concurrency, DoS and soak review

<!-- normative-sync: audit-q35-final-v1 -->

13 October 2026. **Q35 DONE within the verified bounded scope.**
The plan is **33/37 (89.2%)**; Q29/Q31/Q34/Q36 remain open.
[Machine-readable criteria](../../../../release/certification/evidence/q35-final-20261013.json).
This reconciles retained evidence rather than repeating previous executions.

| Criterion | Completion basis |
|---|---|
| Review and dead code | All 15 Cargo fuzz bins, shared CI inventory and four missing targets fixed; stability/admission/isolation/SUN_LEN/phase-marker review and Q37 dead-code dispositions |
| Positive, boundary and negative cases | 15 actual ASan targets, followed by stronger fragment/INI oracles; original corpora, sanitizer binaries and dates retained |
| Faults and concurrency | 14 actual TCP/UDP cases, 320 assertions and seven concurrent pairs, supplemented by completed Q05 transactions, Q09 pre-auth, Q14 lifecycle, Q15 leases/caps and Q25 rollback audits |
| Integration and target platform | Concurrent TCP/QUIC 900 cycles over 30 minutes; current full eight-phase endurance over 13 h 4 min with fixed resource and performance budgets |
| Fixes, verification and evidence | Original failures preserved; input/archive SHA, actual cleanup and host state verified; runner fixes adopted and checked |

## Fuzz source applicability

The original pinned ASan execution of all 15 targets completed **85,930,590**
iterations. Later fragment runs completed 246,813 iterations, client_config
18,494. These counts retain their original executions; no new ASan run occurred
on 13 October.

All 902 original archive inputs and actual final fragment/client_config files
were verified. The initial fragment archive contains an earlier version;
applicability uses the corrected source archived after its final successful
run. Pinned Rustfmt 1.97 reproduces the current bytes of all 15 targets from
these qualified sources. Four apparent untested target changes were formatting.

The fuzz lock changed: qeli→mio and mio→log edges were removed. All 146 package
versions, sources and checksums are unchanged. This is recorded explicitly;
the new lock is not called byte-identical. Parser entrypoints do not exercise
mio/poll/log. Obfs changes gate client batch helpers; REALITY client changes
gate server/test fingerprint metadata, an owned helper and test HMAC. Shared
ServerHello validation and record crypto algorithms remain. Buffer-pool,
platform-thread and counter changes belong to their completed owners; none of
the 15 targets calls transport_core, so fuzz does not claim coverage of those
new paths. Current hosted nightly/CI remains a separate Q34 criterion.

Fragment oracles check exact assembled bytes, MAC/conflict/replay/recovery,
32 incomplete records and 512 KiB, up to 24 UDP fragments and historical
1200-byte fragments. Client INI/qeli:// exercises structured valid inputs and
canonical reparse. Oversized/corrupt config/archive and admission boundaries
also use the completed audits of their owning modules.

## Resources and faults

The DoS review covers declared limits: framing/partial entries, TCP/UDP/Argon2
admission, bounded queues, deadlines, quotas, leases, fragment budgets and
resource release after failures/cancellation. It combines actual Q09/Q15
AUTH/proof/capability and caps/pool checks, Q14 control/reload/hook pressure,
Q05/Q25 acquire/apply/save/rollback/cleanup boundaries and the Q35 race matrix.
This does not require fault injection at every arbitrary await or guarantee
survival against unlimited flood or external network failure.

Another 24 current persistent AUTH runs of 60 seconds completed 34,644
admissions at concurrency 4, with peak RSS 336,320 KiB below the 512 MiB limit.
This is closed-loop resource qualification, not saturation capacity. Original
host failures and partial-run/refusal statuses remain; the complete host PASS
belongs to the separate current endurance packet.

[Full endurance](AUDIT-Q35-LONG-SOAK.md) measured 10k TCP/10k QUIC and 1k each
for three other UDP adapters, performance and 28 cross-node checks. There are
9,403 snapshots and 18,786 process observations. Cross-node means two processes
on one VM, not physical server handover. RSS/fd/socket/thread limits were
declared in advance; cgroup peak/OOM/throttling counters are retained separately.
The original 6.8627% upload FAIL against a 5% threshold remains a FAIL; its
cause belongs to Q36 and is not inferred from the later PASS.

The remaining owners are unchanged: Q29 platform scope, Q31 source bootstrap,
Q34 public source cut/hosted CI and Q36 asymmetry/loss causes and capacity.
Unavailable physical platforms receive no PASS. Q35 closure does not complete
the whole audit or qualify a public release. `NO_PUSH_DEPLOY_RELEASE`.
