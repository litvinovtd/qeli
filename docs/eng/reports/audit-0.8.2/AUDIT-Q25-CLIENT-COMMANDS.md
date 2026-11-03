# Q25: bounded client system commands and IPv4 protection checks

Date: 23 September 2026. Starting commit: `0c5cd0f7`.
Q25-F035/F036 are fixed within the scope below. Sections 22/23/25 remain **IN_PROGRESS**.

## Findings

**Q25-F035, P2 — client route and firewall commands bypassed the bounded runner.**
`client/route.rs` still used direct `std::process::Command::output` calls for initial
setup, roaming, route snapshots, cleanup/orphans, TUN/pushed/local routes and hook
discovery. A child could retain the route operation mutex indefinitely, with no application
limit on collected stdout/stderr. `killswitch.rs` had the same issue in iptables execution,
binary probing, default-route reads and server-allow inventory. Gateway delegates firewall
commands to `killswitch::ipt`; its WAN discovery was already bounded in an earlier pass.

**Q25-F036, P1 — failed IPv4 inspection could skip mandatory protection.**
When IPv4 firewall setup was unavailable or failed, `ip -4 route show default` returned
`false` for both an absent route and a spawn/status error. With the other family protected
or not required, the client could report an engaged kill-switch without establishing
whether an unprotected IPv4 path existed. A new command timeout would also have entered
this branch without a separate policy fix.

## Changes

Every command launch in `route.rs` and `killswitch.rs` uses the existing
`system_command::Command`: **15 seconds per command**, with separate limits of
**16 MiB stdout and 16 MiB stderr**. Overflow never forwards partial output to parsers.
The shared runner terminates the child, and its process group on Linux, and waits for
exit. Synchronous apply/rollback/Drop ordering is preserved. No duplicate runner or new
INI parameters were introduced. Gateway inherits these bounds through the shared
iptables helper; its complete rollback algorithm was not rewritten.

Timeout does not prove that a mutation had no effect. An initial physical add with an
unknown outcome remains pending without delete authority and closes owner admission.
A failed pre-query prevents writing. An applied flush can succeed after independent
confirmation of empty state, but timeout/overflow in that query preserves cleanup failure
and requires retry. The other IP family is still processed. Firewall checks do not call
an unreadable chain absent or begin a blind flush.

When the IPv4 firewall leg is unprotected, only a successful empty default-route listing
permits skipping protection. Failed status, spawn error, timeout, overflow or nonempty
output requires protection. The existing explicit `allow_ipv4_leak = true` keeps its
meaning and skips the unnecessary IPv4 probe. IPv6 inspection through `/proc` was
not changed in this pass.

## Validation and reproduction

20 new permanent tests call production command boundaries using thread-local program/
response replacement. Real finite child processes generate timeout and overflow with
smaller test limits; route state is modeled. Parent PATH/environment stays unchanged,
and actual host ip/firewall commands are never executed.

Sensitivity checks were separate from the final build matrix:

- Restoring the two previous IPv4-policy expressions: **3 tests FAIL**; fixed policy PASS.
- Temporarily replacing the collector with an unbounded std backend, finite fixtures only:
  **9 tests FAIL / 11 PASS**. This is a mutation control of the shared mechanism, not a
  full baseline-commit run. Production files were restored after the experiment.
- Full suite: **1163 host unit + 52 editor/policy + 7 examples + 12 server INI =
  1234 Rust tests PASS**. Existing kill/reap, both-pipe and Linux process-group checks
  are retained; Linux-only checks are cross-compiled here, not executed.

All nine matrix commands and the RU/EN docs gate pass. Rust 1.98.0; the existing Clippy
`chunks_exact_to_as_chunks` exception remains, with no new exceptions. Existing no-feature/
server-only dead-code warnings and the no-roaming `terminal_sender` warning are not
claimed fixed. Evidence: C:/Users/litvi/OneDrive/Documents/qeli/client-command-bounds-audit-20260923.

## Limits and next work

15 seconds is a per-command deadline, not an overall setup/cleanup/reconnect bound.
Commands and verification queries run sequentially; the operation mutex remains held,
and kill/reap can wait on the kernel. The synchronous adapter does not make calls from
async handlers nonblocking. No new benchmark was run; the effect of additional runtime
starts on setup latency has not been measured.

TUN/pushed/local route paths only changed runner; ownership and postcondition policies
have not been unified. Next: those mutations, full gateway rollback and global-state
isolation. Q14-F027 TUN workers/FD, overall preflight deadline, Linux E2E, durable crash
recovery, policy tables/VRFs and native certification remain open. There are no new
throughput measurements or claims that the full audit is complete.

Previous pass: [initial setup and flush](AUDIT-Q25-SETUP-FLUSH.md).

Next pass: [TUN/TAP and route_local](AUDIT-Q25-TUNNEL-ROUTES.md). Call-graph clarification: old apply_pushed_routes/apply_local_networks were unused; active pushed/local routes already used NetworkPlan. Those obsolete duplicates were removed in the next pass.

D06 continuation: [Q25-F122](AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV4.md) removes the one-time empty default-route admission described above. Earlier results describe the 23 September snapshot.
