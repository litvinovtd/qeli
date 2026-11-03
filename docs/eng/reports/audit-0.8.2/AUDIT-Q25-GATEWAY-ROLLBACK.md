# Q25: gateway rollback, scope isolation and firewall inspection

Date: 23 September 2026. Baseline: `86b8cccb`.
Q25-F040–F042 are fixed within the scope below. Sections 17/18/25 remain **IN_PROGRESS**.

## Findings

**Q25-F040, P2 — global gateway flags lost another tunnel's cleanup state.**
A single IPv4 flag and a single IPv6 flag represented every client in the process.
After two profiles engaged a family, cleaning the first reset its global flag, so
cleaning the second skipped its rules. Even cleanup of an inactive TUN could reset
another TUN's flag. A failed cleanup lost its retry state when a sibling stopped.

**Q25-F041, P1 — failed kill-switch inspection could insert ACCEPT ahead of protection.**
`ensure_rule` treated every failed presence query as absence. If the rule query
reported absent, the kill-switch query failed, and insertion succeeded, the permit
went to position 1 even with an existing kill-switch jump. A later successful
permit check accepted that state. A matching existing permit also bypassed the
jump-order check, allowing reconnect to accept an already misplaced permit.
Unknown initial NAT/rule snapshots could trigger blind additions as well.

**Q25-F042, P2 — cleanup reconstructed MASQUERADE from the latest configuration.**
Changing the LAN subnet for the same TUN left the earlier tagged MASQUERADE
unaccounted for. Cleanup removed the latest subnet only and still reported success.

## Changes

Gateway state now records each TUN, IP family and attempted LAN subnet before the
first sysctl mutation. Cleanup uses those saved selectors, attempts every recorded
subnet and the shared rules in both families, and clears only a fully verified
family. An inactive TUN does not inspect/delete another scope's rules. Failed
families retain their records for another cleanup attempt.

The single public `disengage_plan` path serves shutdown and NetworkPlan rollback.
Its callers no longer copy/pass current LAN subnets for undo. Unused partial
`disengage`/`disengage_exit` wrappers were removed after a repository call-site check.

Rule installation uses the existing shared presence/absence/error classifier.
Inspection errors prevent that rule's mutation. New and reused FORWARD permits
must verify that a detected Qeli kill-switch jump is first; new permits go behind
it. Listing helpers reject invalid UTF-8. Post-install checks remain authoritative:
a lying success is rejected, while a rule observed after lost command completion
is still tracked through its scope and cleaned up.

Public router operations, including exit-path refresh and sysctl release, are
serialized within the process. This closes the interleaving between cleanup and
a new gateway acquisition. It is not an atomic kernel transaction or a lock around
the complete multi-step NetworkPlan. The shared persistent sysctl journal is
unchanged: cleanup still attempts release after firewall failures, aggregates both
errors, and preserves other owners' leases. Failed firewall cleanup does not become
success just because sysctl release succeeded.

## Validation

**8 regressions FAIL on baseline → PASS with the fixes.**
The baseline runs actual production functions with only host-access adaptation.
The eight reproducing test bodies are unchanged apart from formatting.
**25 new isolated command/sysctl tests**, plus five existing gateway tests newly
included in the host suite. Existing WAN tests remain covered once.

Controls include both families, no-NAT forwarding, reconnect idempotence, inactive
cleanup, partial setup rollback, lying add/delete, lost add completion, sysctl
acquire/release failure, combined cleanup errors, retry and preservation of
untagged administrator rules. Sysctl callbacks check that operation serialization
is held. An inactive exit refresh also returns while another router operation is locked,
so an ordinary client does not wait for unrelated firewall work. Models intercept commands per thread; no host firewall/TUN/sysctl changes.

**1216 host unit + 52 editor/policy + 7 examples + 12 server INI = 1287 Rust tests PASS.**
All nine matrix commands PASS: host/config tests, Linux all-targets Clippy,
client-only, server-only, minimal FFI, client without roaming, no-feature compatibility
and rustfmt. Linux checks are cross-compilation, not runtime execution.
Rust 1.98.0; the existing `chunks_exact_to_as_chunks` Clippy exception remains.
RU/EN documentation checks pass. Evidence:
C:/Users/litvi/OneDrive/Documents/qeli/gateway-rollback-audit-20260923.

## Limits and next work

Rule records are in memory and keyed by TUN name, not a durable generation lease.
Exact tagged rule selectors are not proof of authorship in an external race;
external processes can still mutate firewall state between queries. Cleanup
retains the existing eight-attempt deletion bound. Commands have 15 s deadlines,
but the complete serialized operation has no overall deadline.

The sysctl model tests gateway orchestration, not kernel knob behavior or the
journal's on-disk persistence. The full client guard, route/TUN teardown and real
packet leakage need Linux integration evidence. This pass does not certify
multiple simultaneous kill-switch chains or shared exit-node WAN/NAT ownership.
Those are next, followed by IPv6 protection discovery, remaining DNS/carrier globals,
Q14-F027 TUN workers/FD, crash recovery, native certification and a new benchmark.
INI keys and internal JSON protocols are unchanged. The full audit is not complete.

Follow-up: [exit NAT ownership and kill-switch conflicts](AUDIT-Q25-EXIT-OWNERSHIP.md).
