# Q14: deadlines and output limits for server NAT commands

Date: 23 September 2026. Baseline commit: `253b6455`.
Sections 14, 17, 18, 19 and 25: **IN_PROGRESS**. Q14-F032 is fixed; the overall audit is open.

## Confirmed problem

**Q14-F032, P2 — server NAT commands lacked deadlines and output limits.** All five
launch sites in `qeli/src/server/nat.rs` used direct `std::process::Command::output`:
the common iptables/ip6tables adapter, two PATH version probes and two route queries
for WAN selection. `--wait 5` bounded only the xtables lock wait, not a stalled backend,
pipe EOF waiting or stdout/stderr size.

A stalled command could retain the common firewall mutex, delay other profiles,
Drop/rollback and final DNS ownership cleanup. Large output was retained without a limit.

## Change and scope

All five launches now use the existing `crate::system_command::Command`, shared with TUN
and per-link DNS. No separate runner is added. Each command gets 15 seconds, with stdout
and stderr limited to 16 MiB each. The deadline starts before helper-thread creation.
Both pipes are drained concurrently; overflow never returns partial output.

Timeout returns TimedOut and overflow returns InvalidData. The runner requests process
termination and waits for it; Linux uses the existing process-group ownership. Nonzero
exit remains Output with its original status/stderr. Arguments pass without a shell;
`--wait 5`, tool selection and IPv4/IPv6 WAN selection are preserved.

A mutation timeout does not prove the rule was unchanged. Installation retains its
subsequent verification, and exact DNS cleanup retains rule specifications for retry
after failure. A new regression models deletion timing out both before and after mutation:
TCP cleanup continues despite UDP failure; the final pass checks both exact rules, repeats
only still-needed deletion and then releases ownership.

Generic NAT cleanup remains best effort: unavailable `iptables-nft -S` on mixed native nft
does not become an unconditional startup failure. `off`/`manual`, INI keys, firewall rules,
the sysctl journal, ABI and wire format are unchanged.

## Validation

**1002 host unit + 52 editor/policy + 7 examples + 12 server INI = 1073 Rust tests PASS.**
One domain regression with two unknown-mutation outcomes was added. Existing runner,
ownership and cleanup tests were rerun. Linux all-targets Clippy, client-only, server-only,
client without roaming, minimal FFI, compatibility without features and rustfmt PASS.
Existing feature-specific warnings and the Clippy `chunks_exact_to_as_chunks` exception remain.

Extracted production adapters were also tested with actual finite child processes.
Three baseline scenarios expose missing limits: late success, oversized stdout and
oversized stderr. Three controls verify exit 17/stderr, exact argv with literal shell
characters, and all four discovery/probe calls. With the fix, **6/6 scenarios PASS**.
The production deadline fired in about 15 seconds; a loopback witness confirmed the
child socket was closed by return. Fixture PATH changes apply only to the child test
process; actual `ip`/iptables are not run. These six scenarios are not added to 1073.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/nat-command-audit-20260923.

## Open boundaries

15 seconds is a per-command deadline, not the duration of complete cleanup or firewall
mutex ownership. Sequential checks/deletions can take longer; spawn, kill/reap and
uninterruptible kernel waits do not receive a hard overall upper bound. A descendant
leaving its process group is outside group-termination guarantees. Two existing Linux
group tests were compiler-checked; Linux signal delivery was not executed here.

Preflight is subsequently migrated in [Q05-F001](AUDIT-Q05-PREFLIGHT.md).
Read-only path monitoring is subsequently migrated in [Q25-F020](AUDIT-Q25-PATH-MONITOR.md).
Client routes/kill-switch/gateway commands are not migrated by this pass. Q14-F027, older-generation resources, overall network-operation deadlines
and persistent DNS journaling remain open. Checks/deletions are not atomic against an
external firewall manager. Actual Linux firewall/TUN/sysctl/systemd, devices, native
release and benchmarks were not run.

Previous passes: [shared TUN/DNS runner](AUDIT-Q25-SYSTEM-COMMANDS.md) and
[partial IPv6 acquisition](AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md).

Follow-up: [Q14-F034 — shared cleanup deadline](AUDIT-Q14-NAT-CLEANUP-BUDGET.md)
covers profile/startup/final cleanup admission and commands; the earlier results above
refer to their own snapshot. NAT setup/rollback, DNS lease Drop/setup admission and
persistent recovery remain open.
