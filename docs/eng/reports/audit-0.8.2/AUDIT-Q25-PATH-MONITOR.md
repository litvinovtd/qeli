# Q25: bounded Linux path-monitor commands

Date: 23 September 2026. Baseline: `722dae31`.
Sections 22, 23 and 25 remain **IN_PROGRESS**. Q25-F020 is fixed.

## Problem and change

**Q25-F020, P2 — read-only path-monitor commands could retain generation shutdown.**
`client/roaming_linux.rs::ip_json` directly called `std::process::Command::output`:
IPv4/IPv6 default routes and interface addresses were read without a deadline or output limit.
Observation already ran through generation-owned `tasks.blocking`. Cancelling its async
receiver preserves the blocking join handle, so a stalled child retained
`TaskGroup::finish`. Task ownership alone did not bound command execution.

The adapter now uses existing `crate::system_command::Command`: 15 seconds per command,
separate 16 MiB stdout/stderr limits, concurrent pipe draining, termination request and
child wait on timeout/overflow. No new runner or detached spawn_blocking is added.
Task ownership, observation order, family/route selection, address filters, generation/update
IDs, ABI and INI are unchanged.

Command or parse errors propagate out of observation. The monitor logs them at debug
and skips that sample before changing baseline/pending/update ID or sending PathUpdate.
Errors do not become empty successful snapshots. No routes, tunnel-only routes or no
usable addresses retain the existing `Ok(None)` outcome. A disappeared interface record
or malformed response remains an error.

A new portable regression combines the actual shared runner and actual TaskGroup:
a child reports startup through a loopback socket and stalls; stopping the group aborts
the async collector but waits for timeout and return of the blocking command. The test
checks socket closure and absence of late result delivery. This tests the ownership
contract, not the complete Linux monitor/controller or every handover scenario.

## Validation

**1027 host unit + 52 editor/policy + 7 examples + 12 server INI = 1098 Rust tests PASS.**
One new host regression uses a real child. Linux all-targets Clippy, client-only,
server-only, client without roaming, minimal FFI, compatibility without features and rustfmt PASS.
Existing feature-specific warnings and the `chunks_exact_to_as_chunks` exception remain.
Linux-only monitor/controller tests were compiled; the live observation test using actual
`ip` was not run.

A separate harness extracts production `observe_physical_path` with its parsers and
command adapter. Finite children replace `ip` only in the test child's PATH; exact argv
are checked for all three queries. The baseline has **9 expected regression failures**
(deadline and stdout/stderr overflow for each query) and **14 passing controls**.
The fixed version passes **23/23**: also nonzero/malformed output at each stage,
dual-stack, preferred IPv6 on another interface, IPv4-only/IPv6-only, no routes,
tunnel-only, no ready addresses and a disappeared interface.
Overflow stdout is valid data with an oversized whitespace tail: the baseline really
accepts it, so a parse error cannot mask the missing limit.
The production timeout is exercised with a real wait (~15 seconds); the loopback witness
closes before return. These 23 scenarios are not added to 1098.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/path-monitor-audit-20260923.

## Boundaries

These are individual observation-command deadlines, not a whole-sample, handover or
shutdown deadline. Spawn/kill/reap and uninterruptible kernel waits may extend the call;
descendants leaving the Linux process group have no group-termination guarantee.
Linux signals were not executed here.

Gateway WAN discovery is subsequently migrated in [Q25-F021/F022](AUDIT-Q25-GATEWAY-WAN.md).
Route mutations inside submit_path_update and client route/kill-switch/gateway firewall
commands still need separate migration and ownership checks for uncertain outcomes. Forced Drop
of the entire group does not replace async join. Actual Linux TUN/firewall, network
changes, suspend/resume, systemd, devices, native release and benchmarks were not run.
The overall audit remains open.

Previous passes: [TCP/monitor ownership](AUDIT-Q25-TCP-TASKS.md),
[shared runner](AUDIT-Q25-SYSTEM-COMMANDS.md), [preflight](AUDIT-Q05-PREFLIGHT.md).
