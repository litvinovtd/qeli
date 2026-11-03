# Q14: partial IPv6 sysctl acquisition and rollback retry

Date: 23 September 2026. Baseline commit: `44049922`.
Sections 14, 17, 18 and 19: **IN_PROGRESS**. Q14-F031 is fixed; Q14-F027 remains partial.

## Confirmed problem

**Q14-F031, P2 — partially acquired IPv6 sysctls escaped final cleanup.**
`acquire_ipv6_sysctls` registered a profile lease only after acquiring both `accept_ra=2`
and global IPv6 forwarding. Failure of the second acquire triggered rollback, but rollback
failure was only logged: the profile was still absent from the registry, so
`finish_owned_cleanup` could not retry releasing its scope.

Failure of the first acquire returned through `?` without rollback. This did not prove
that no mutation occurred: a sysctl write could succeed before value verification or
journal handling failed. The low-level sysctl journal retained evidence, but the running
worker did not account for it as pending profile cleanup.

## Change

The portable `qeli/src/server/nat/ipv6_sysctl.rs` owns the profile registry and acquire/release
algorithm. The Linux NAT adapter uses this same algorithm with the actual journal APIs;
`nat.rs` no longer maintains a separate ownership implementation.

The scope is registered after parameter checks, **before the first acquire attempt**.
Any failure, including the initial accept_ra setting, triggers scope release. Successful
rollback removes the entry; failed rollback retains it for ordinary profile cleanup and
final worker retry. The returned error includes the initial cause and `rollback incomplete`
when rollback also fails. Even a panic after mutation begins leaves the scope available
for subsequent cleanup.

The accept_ra → forwarding order is preserved. Retrying the same WAN/TUN re-applies both
settings; a different WAN/TUN cannot replace a retained lease. Successful release removes
the entry and permits later settings. The final pass visits profiles in stable order and
continues after DNS or another profile fails.

`off` and `manual`, firewall rules, sysctl journal algorithms, INI keys, ABI and wire format
are unchanged. Partial acquisition now enters the existing `owned network cleanup`
category: unresolved failure prevents a successful worker shutdown outcome. Successful
final retry clears that network failure; the current generation's original error may
independently remain under `profile/worker task cleanup`.

## Validation

11 new host regressions cover failure of either acquire, successful/failed rollback,
both causes, final retry, RA/forwarding order, absent WAN, reacquisition, identity conflict,
invalid WAN, multiple profiles, DNS failure and panic after mutation begins. One existing
Linux-only scope-encoding test was also moved into the shared host suite.

**1001 host unit + 52 editor/policy + 7 examples + 12 server INI = 1072 Rust tests PASS.**
Linux all-targets Clippy, client-only, server-only, client without roaming, minimal FFI,
compatibility without features and rustfmt PASS. Existing feature-specific warnings and
the Clippy `chunks_exact_to_as_chunks` exception remain.

A separate harness uses extracted production NAT adapters with fixture sysctl APIs.
Three regression cases fail on the baseline and two controls pass; all five pass with
the fix. These are not added to 1072. Registration/release ordering is tested without
changing system settings. Evidence:
C:/Users/litvi/OneDrive/Documents/qeli/ipv6-partial-acquire-audit-20260923.

## Open boundaries

Q14-F027 remains open for generic NAT cleanup and incomplete cleanup of older TUN/queue
generations after retry/replacement. The subsequent [Q14-F032 pass](AUDIT-Q14-NAT-COMMANDS.md) bounds each
server NAT command. Overall network-operation deadlines and persistent DNS journaling remain open. Low-level sysctl restoration depends on the
retained journal; this pass does not establish behavior after journal loss or failure
to persist the entry itself. Worker-lifetime IPv4 forwarding ownership is unchanged.

Actual Linux kernel/sysctl/firewall/TUN/systemd, cross-process permissions and locking,
devices, native release and benchmarks were not run.

Previous pass: [sysctl recovery and repeated acquisition](AUDIT-Q14-SYSCTL-RECOVERY.md).
