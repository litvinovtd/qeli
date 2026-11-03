# Q25: TUN and DNS system-command deadlines

Date: 23 September 2026. Baseline commit: `29e11399`.
Sections 14, 19, 21 and 25: **IN_PROGRESS**; the full audit remains open.

## Findings

**Q25-F016, P2 — TUN and resolvectl commands lacked execution and output bounds.**
`std::process::Command::output` synchronously waited for process exit and EOF on both pipes.
A stuck `ip`/`resolvectl` or a descendant retaining a pipe could delay setup, shutdown and
rollback. These calls also run inside synchronous Drop guards. An async timeout around a
blocking-task wait does not stop that task's child process. Output was collected without a cap.

**Q25-F017, P3 — DNS diagnostics claimed successful rollback without checking its result.**
After per-link DNS setup failed, the code ignored the immediate `resolvectl revert` result
but reported that the partial change had been reverted. The marker was already retained
for cleanup retry; the defect was misleading diagnostics, not absence of the marker.

## Fix and scope

`qeli/src/system_command.rs` provides a synchronous Command for Linux setup/rollback.
Each command has a 15-second deadline, with up to 16 MiB stdout and 16 MiB stderr. Complete
binary output is preserved within the limit; overflow returns InvalidData without a partial
Output. Timeout returns TimedOut; a nonzero exit remains an ordinary Output with the process
status. Stdin is closed. No new INI setting was added.

The runner reuses OwnedProcess from `qeli/src/hooks/process.rs`. New
`qeli/src/hooks/output.rs` collects complete machine-readable output; hook diagnostic tails
and credential collection retain their separate contracts. Both pipes are drained together.
On timeout/I/O error/overflow, readers close before terminating and waiting for the child.
Linux uses the existing process-group handling: the leader remains unreaped until pipe EOF,
so a later cancellation cannot signal a recycled PGID.

The synchronous adapter creates and joins a scoped thread with its own current-thread Tokio
runtime. It works from Drop, outside a runtime and inside either Tokio runtime flavor, without
leaving a detached spawn_blocking task. The caller still blocks; this does not migrate the
entire network setup to async. The deadline starts before the helper thread is spawned.

All five `ip` invocations in `tun/iface.rs` now use it: address, link up/MTU, MAC, queue length
and TUN/TAP deletion. This interface is shared by the Linux client and server. All client DNS
`resolvectl` calls were migrated: apply, immediate rollback and marker-based recovery.
No per-client runner duplicates were added. INI, wire format and ABI 1.16 are unchanged.

Immediate DNS rollback now logs a failed command. The resulting setup error reports attempted
rollback and a retained marker. Marker retirement moved without duplication into
`dns_backup::revert_link_marker`: only confirmed revert permits removal; command/read/remove
errors propagate to its caller. The actual ordering is host-tested through an injected command
callback and real temporary files.

A mutation timeout does not prove that no changes were applied. The DNS marker is persisted
before mutation and retained for retry. TUN failures use the existing interface ownership
guards and Linux-client cleanup journal. This pass does not validate complete atomic rollback
of all network state.

## Validation

17 additional host tests (including the child-fixture entry point) cover complete binary
output on both pipes, reusable builders, absent/current-thread/multi-thread runtimes, closed
stdin, nonzero exit versus spawn failure, expired deadlines, stuck children, stdout/stderr
floods, async collector cancellation, exact limits/overflow/read errors, and DNS-marker
retention on failures with successful retry and removal failure.

Two regressions also run the previous direct std Command::output behind a test signature
adapter: a finite slow command incorrectly succeeds after the deadline, and finite oversized
output incorrectly reaches the parser. Both tests fail as expected and pass with the fix.
The baseline reproduction did not use an infinite child process.

**915 host unit + 52 editor/policy + 7 examples + 12 server INI = 986 Rust tests PASS.**
Two new Linux group tests (a waiting shell and an exited leader with inherited pipes) were
cross-compiled only. Linux all-targets Clippy, client-only, client without roaming, server-only,
minimal FFI, compatibility without features and rustfmt pass. Existing diagnostics remain:
23 server-only warnings, terminal_sender without roaming, 33 compatibility warnings in
unchanged modules and an informational MSVC linker message. The Clippy
chunks_exact_to_as_chunks exception concerns unchanged ndp_proxy.
Nine documentation checks and git diff --check pass.
Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/system-command-audit-20260923.

## Open boundaries

15 seconds is a command deadline, not a hard upper bound on total shutdown. Process
termination/reaping, synchronous filesystem operations and other cleanup steps are separate.
Spawn, a child in an uninterruptible kernel wait or failed kill can delay return; a descendant
that deliberately leaves its process group has no group-termination guarantee.

Server NAT, including its firewall/probe/WAN lookup commands, is subsequently migrated in
[Q14-F032](AUDIT-Q14-NAT-COMMANDS.md). Route mutations and client kill-switch/gateway firewall
commands still use the previous execution path. Gateway WAN discovery is migrated in
[Q25-F021/F022](AUDIT-Q25-GATEWAY-WAN.md). Read-only path monitoring is migrated in
[Q25-F020](AUDIT-Q25-PATH-MONITOR.md). Server preflight is migrated in
[Q05-F001](AUDIT-Q05-PREFLIGHT.md). Migrating remaining mutations requires checking ownership journals after an
unknown outcome and preserving fail-closed behavior. Do not treat the entire system-command
layer as fixed. Server cleanup errors and overall operation serialization also need review.

Linux runtime, real TUN/firewall/DNS, SSH/systemd/Actions, native release builds, device apps
and new benchmarks were not run. New fixtures use test child processes, loopback witnesses
and temporary files.

Previous passes: [cleanup failures](AUDIT-Q25-TUN-CLEANUP.md) and
[server H2](AUDIT-Q14-H2-TASKS.md).

Follow-up: [Q14-F024/F025](AUDIT-Q14-NAT-CLEANUP.md) makes the generic NAT sweep finite
and adds diagnostics. Server NAT command deadlines are added in [Q14-F032](AUDIT-Q14-NAT-COMMANDS.md);
overall operation deadlines and complete teardown error propagation remain open.

D05 continuation: [shared client DNS application deadline](AUDIT-Q25-DNS-BUDGET.md). The dns/domain sequence now shares one deadline; rollback remains a separate owned operation.
