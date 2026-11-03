# Q05: deadlines and output limits for preflight host observations

Date: 23 September 2026. Baseline: `fd03a292`.
Sections 05 and 14: **IN_PROGRESS**. Q05-F001 is fixed; full transaction validation is open.

## Confirmed problem

**Q05-F001, P2 — four preflight commands had no deadline or output limit.**
Direct `std::process::Command::output` in `qeli/src/server/preflight.rs` launched
IPv4/IPv6 `ip ... addr show` and `ip ... route show`. A stalled backend/pipe could
retain the call indefinitely, while stdout/stderr were collected without a size limit.

Preflight runs before panel/worker startup, in check-config, Quick Start, Form/INI saves,
history restore and backup restore. Configuration-mutating handlers hold
`config_write_lock` during this call, so a stall delays subsequent transactions.
Call sites were inspected in source; HTTP E2E was not run.

## Change

All four commands reuse `crate::system_command::Command`: 15 seconds per command and
separate 16 MiB stdout/stderr limits. Both pipes are drained concurrently; oversized
partial results never reach the parser. The runner requests process termination and
waits for it, preserving existing Linux process-group ownership.
No additional runner, shell or INI keys are introduced; argv and observation order remain.

Snapshot construction now accepts a command executor for testing failures without
querying the host network. The existing policy is preserved:

- Spawn/read errors, timeouts, output overflow or nonzero exits of either IPv4 probe
  produce `None`. `run()` warns about unavailable host state and permits startup.
- IPv6 address and route errors are handled independently. Successful IPv4 observations
  and the available IPv6 part survive; only the unavailable part is empty.
- Empty output with successful exit remains a valid observation, not a command failure.
- Observed collisions still cause rejection. Tentative IPv6 addresses count for collision
  checks but do not qualify as ready egress addresses.

Fail-open does not prove absence of collisions when state is unavailable.
Partial IPv6 failure still has no separate warning.

## Validation

**1026 host unit + 52 editor/policy + 7 examples + 12 server INI = 1097 Rust tests PASS.**
The host suite now includes 20 existing preflight tests previously excluded on Windows
and 4 new snapshot/failure-policy tests. The increase of 24 is not 24 newly written tests.
This module's tests never invoke real `ip`.

Linux all-targets Clippy, client-only, server-only, client without roaming, minimal FFI,
compatibility without features and rustfmt PASS. Existing feature-specific warnings
and the Clippy `chunks_exact_to_as_chunks` exception remain.

A separate harness extracts actual production snapshot code with its parsers.
Finite child processes replace `ip` only in the test child's PATH; all argv are checked.
Each of the four probes is tested for deadline, stdout/stderr overflow, exit 17 with
plausible stdout and successful empty output, plus one complete successful snapshot.
The baseline has **12 expected regression failures** and **9 passing controls**.
The fixed version passes **21/21**. The full production timeout is exercised with a real
wait; a loopback witness confirms the child's socket closes before return (EOF or Windows RST).
Partial IPv6 policy is checked both by portable tests and these production adapters.
The 21 scenarios are not added to 1097.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/preflight-audit-20260923.

## Open boundaries

The deadline applies to one command. Four sequential probes and multiple preflight
calls within an operation can take longer than 15 seconds. There is no transaction-wide
deadline. A synchronous call from an async handler still occupies an executor thread and
holds the write lock; moving to the runner alone does not resolve that.

Spawn/kill/reap and uninterruptible kernel waits have no hard aggregate upper bound.
Linux process-group signals were not executed here; a descendant that leaves the group
has no group-termination guarantee. A multi-command snapshot is not atomic against network changes.

Read-only path monitoring is subsequently migrated in [Q25-F020](AUDIT-Q25-PATH-MONITOR.md).
Client route/kill-switch/gateway commands still require migration with
ownership checks after uncertain mutations. Older profile/TUN generations, Linux
API/restart/restore, actual firewall/sysctl/systemd, devices, native release and a new
benchmark are not closed by this pass.

Previous passes: [NAT commands](AUDIT-Q14-NAT-COMMANDS.md) and
[shared runner](AUDIT-Q25-SYSTEM-COMMANDS.md).

24 September update: the four-probe budget, async handlers and config lock were addressed in [Q05-F002–F004](AUDIT-Q05-PANEL-TRANSACTIONS.md). Historical limits above describe the older snapshot; the overall backup/restore deadline remains open.
