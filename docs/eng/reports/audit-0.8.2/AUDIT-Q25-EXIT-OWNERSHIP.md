# Q25: exit-node NAT ownership and conflicting kill-switch policies

Date: 23 September 2026. Baseline: `166ece80`.
Q25-F043–F045 are fixed within the scope below. Sections 17/18/25 remain **IN_PROGRESS**.

## Findings

**Q25-F043, P2 — stopping an exit node removed a sibling's shared-WAN NAT.**
`exit_masq_rule` contained WAN, packet mark and the same comment for every TUN.
Two profiles therefore reused one rule. Cleaning either removed that rule while the
other profile remained active. The same defect affected IPv4, IPv6 and old/new WANs
retained during roaming. Per-TUN WAN maps did not make the NAT rule itself distinct.

**Q25-F044, P2 — cleanup inferred ownership from the current default route.**
With no recorded WAN, cleanup discovered the current WAN and deleted matching rules.
An unstarted exit profile could remove an active profile's shared NAT. After a
partial dual-stack cleanup, retry could rediscover and touch an already-clean family.

**Q25-F045, P2 — distinct kill-switch chains still conflicted as host-wide policies.**
Each per-TUN chain ends in DROP and is inserted at the top of OUTPUT/FORWARD.
Starting another profile could succeed while its earlier DROP blocked the first
profile's carrier. The old migration path also removed the shared `QELI_KS` chain
without evidence that the new profile owned it. Distinct names scoped deletion,
but did not make packet policies composable.

## Changes

Exit NAT rules now have an exact `qeli-exit-node:<tun>` comment. Other exit rules retain
`qeli-exit-node` and are already distinguished by their interface selectors.
Each TUN/WAN NAT rule can be removed independently, including when another TUN's
rule belongs to a different process and has no local owner record. This does not
require a process-local reference count for the shared match.

The packet predicate remains the same WAN/mark match: these are equivalent NAT
rules with distinct cleanup identities, not separate per-TUN packet marks.
Bits selected by `0x51/0x51` are reserved for Qeli exit traffic; unrelated firewall
marking must not reuse them. Other bits remain unchanged.

Cleanup uses only remembered installation targets. The WAN discovery fallback and
its two obsolete helper tests were removed. Production tests now cover no-owner
cleanup as a no-op and retry of a partially cleaned family. Failed families retain
their targets; other families and sysctl release are still attempted.

The public kill-switch entry point inspects both available filter tables before
any rule mutation. It requires successful UTF-8, structurally valid inventory with
all three built-in policies and declared rule sources. Another `QELI_KS_<tun>` or
legacy `QELI_KS` causes an explicit conflict error, even with leak overrides enabled.
Unknown, malformed or incomplete inventory also refuses before installation.
The same TUN can rebuild its own chain. Unrelated administrator chains are preserved.
Public engage, server-address refresh and cleanup are serialized within the process,
so two simultaneous starts cannot both pass the initial checks.

This is explicit rejection of incompatible simultaneous protected full-tunnel
profiles in one network namespace, not support for combining their policies.
Normal gateway/exit-node profiles without this conflicting kill-switch remain
independent. Use separate network namespaces for independently protected tunnels.

## Upgrade and recovery

New cleanup does not adopt or remove an old unsuffixed exit MASQUERADE rule.
After stopping/recovering its confirmed old owner, inspect exact family/table/WAN/
comment selectors before manual removal; a blanket deletion by tag may affect live
profiles. The legacy `QELI_KS` chain also needs explicit recovery before a new profile
can arm. An unhooked foreign per-TUN chain is conservatively a conflict.

The netns exit-node harness now checks `qeli-exit-node:qrex0` for MASQUERADE.
Its shell syntax was checked, but the namespace scenario was not executed.
INI configuration keys and internal JSON protocols are unchanged.

## Validation

**13 reproducing tests FAIL on the original behavior → PASS after the fixes**:
seven exit-node and six public kill-switch cases. Their bodies remain unchanged
apart from formatting. **30 new tests**, with two obsolete WAN-fallback helper
tests removed: 16 exit-node and 14 kill-switch tests.

Controls cover same/different WANs, dual stack, roaming, partial NAT setup,
unknown cleanup, retry, rule identity without a local owner, preservation of legacy
NAT, own-chain rebuild, administrator chains, invalid UTF-8, malformed/duplicate
inventory, IPv6 preflight failure, stale foreign chains, replacement after cleanup
and concurrent starts. The packet model independently checks that the first
carrier remains permitted; it is a narrow model of the exercised OUTPUT rules.

**1244 host unit + 52 editor/policy + 7 examples + 12 server INI = 1315 Rust tests PASS.**
All nine matrix commands PASS, including Linux all-targets Clippy, isolated
client/server features, minimal FFI, no-roaming, no-features and rustfmt.
Rust 1.98.0; the existing `chunks_exact_to_as_chunks` Clippy exception is unchanged.
RU/EN documentation checks pass. No host networking was modified.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/exit-nat-audit-20260923.

## Limits and next work

Linux checks are cross-compilation, not runtime. Command/sysctl models do not verify
kernel forwarding, conntrack/NAT flow continuity or on-disk sysctl leases. The shared
sysctl journal was not changed. A distinct NAT comment proves selector separation,
not a cross-process generation lease; simultaneous use of the same TUN name remains
outside that guarantee.

Kill-switch admission is a snapshot plus an in-process mutex, not an interprocess
transaction. Concurrent separate processes or administrator changes can still race.
A process killed after partial setup may leave a chain requiring recovery.
No overall operation deadline, new benchmark or native certification was added.
Next: cross-process admission and stale TUN identity, IPv6-protection evidence,
DNS/carrier globals, Q14-F027 TUN workers/FD and Linux E2E recovery.

Follow-up: [Q25-F046–F047](AUDIT-Q25-KILL-SWITCH-LIFETIME.md) adds a cooperative
lease spanning a protected Linux session and fail-closed IPv6 inspection.
The cross-process limitation above describes the state at this report's baseline.
