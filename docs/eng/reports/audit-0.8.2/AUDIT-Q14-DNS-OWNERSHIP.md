# Q14: DNS rule ownership after failed cleanup

Date: 23 September 2026. Baseline commit: `de7a395f`.
Sections 14, 17, 18 and 19: **IN_PROGRESS**; the full audit remains open.

## Fixed finding

**Q14-F028, P2 — failed cleanup discarded exact DNS INPUT rule specifications.**
`DnsInputLease::drop` attempted to remove UDP/TCP permits and merely logged failure.
The lease and its profile/interface/pool/resolver/port data then disappeared. A later
`nat::cleanup(profile)` knew the tag, but mixed native nft chains may reject listing
through `iptables-nft -S`. The original exact `-C`/`-D` operations could no longer be retried.

Failed setup rollback had the same problem: leases were created only after successful
installation, leaving partially installed rule specifications in local variables.
An unavailable firewall tool also discarded the specification. Confirmed by review
and extracted production-adapter comparisons; live Linux was not exercised.

## Change

`qeli/src/server/nat/dns_input.rs` retains complete UDP/TCP rule specifications and their
address family in a worker registry. Ownership is reserved before the first `-I`,
including partial setup. The shared `dns_input_rule` builder moved there without a
second copy. Leases carry unique tokens; entries distinguish active ownership from
pending retirement. Retirement is marked before cleanup, so failure or unwind retains
the specification. Only successful verified cleanup removes the entry.

Retries run from `nat::cleanup(profile)`, `cleanup_all()` and before new DNS permits
for the same profile are installed. Failed pending cleanup prevents that profile's
new DNS installation. Later pending entries are attempted even after an error. Exact
retry skips active entries and other profiles. A stale lease after successful retry
cannot delete replacement rules: tokens never repeat, and entry identity rather than
profile-name equality controls retirement. This guarantee applies to exact retry;
the existing generic tag sweep retains its separate contract.

The registry holds at most 4096 active/pending rule sets, each representing one resolver's
UDP+TCP permits. Exhaustion refuses new installation before firewall mutation without
evicting existing evidence. Cleanup releases capacity. IPv4 and IPv6 use separate sets.
No new INI parameters were added. Rule arguments, manual IPv6, ABI and wire format remain.

In `enable_dns_input`, the lease belongs to the outer scope and the firewall mutex guard
to an inner scope. Setup failure releases the mutex before dropping the lease, avoiding
recursive locking during rollback. Registry and firewall operations remain serialized
by the common firewall mutex; cleanup callbacks do not re-enter the registry.

## Validation

12 new host tests cover reservation before mutation, duplicate live owners, full retained
specifications, failed/successful retry, replacement tokens and stale leases, profile and
family isolation, active entries, continuation after errors, idempotency, panic, token
overflow and capacity. Partial UDP failure uses the production exact-deletion algorithm:
TCP is removed, UDP remains, and retry removes the remainder without `-S`.

Three separate regressions compare enable/lease/Drop/cleanup adapters extracted from
baseline and fixed `nat.rs`. Only external firewall operations, tool discovery and policy
are stubbed; the generic sweep models unavailable listing. The baseline loses retry after
failed Drop, setup rollback or disappearing tools. All three pass with the fix. Setup
failure additionally has a three-second wait bound to detect recursive mutex acquisition.
These tests are preserved in harness copies, do not run a Linux worker and are not included
in the main Rust-suite count below.

**957 host unit + 52 editor/policy + 7 examples + 12 server INI = 1028 Rust tests PASS.**
Linux all-targets Clippy, client-only, client without roaming, server-only, minimal FFI,
compatibility without features and rustfmt pass. Existing 23 server-only, one no-roaming,
33 compatibility warnings and MSVC linker output remain; the Clippy
chunks_exact_to_as_chunks exception belongs to unchanged ndp_proxy.
Nine documentation checks and `git diff --check` pass.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/dns-ownership-audit-20260923.

## Open boundaries

The registry exists **only in the current worker's memory**. SIGKILL, crashes and process
restarts lose it; reliable exact-permit recovery across them needs a protected persistent
journal. Generic startup sweeps still help on enumerable chains but cannot replace that
journal on mixed native nft. There is no independent background retry: retries occur at
the cleanup/setup calls listed above.

**Q14-F027 is partially addressed:** subsequent [final checks](AUDIT-Q14-OWNED-SHUTDOWN.md)
propagate unresolved DNS/sysctl errors through the worker and outer supervisor; current
generation task/TUN failures are also included. Generic NAT and older generations remain open.
The subsequent [Q14-F032 pass](AUDIT-Q14-NAT-COMMANDS.md) bounds each server NAT command.
Overall operation/mutex duration and external rule changes need separate validation.

Linux runtime, real firewall/TUN/DNS, devices, native release builds, SSH/systemd/Actions
and benchmarks were not run. Generic NAT outcomes, older generations
and a separate safe-recovery-journal design remain open.

Previous pass: [shared firewall checks](AUDIT-Q14-Q25-FIREWALL-CHECKS.md).

Follow-up: [final verification of known DNS/sysctl leases](AUDIT-Q14-OWNED-SHUTDOWN.md)
propagates their unresolved errors to worker exit status. Q14-F027 is partially addressed;
[Profile tasks and TUN teardown](AUDIT-Q14-PROFILE-SHUTDOWN.md) also propagate current-generation
failures; generic NAT and unfinished cleanup of older generations remain open.

Follow-up: [Q14-F035 — DNS INPUT setup/Drop](AUDIT-Q14-DNS-INPUT-BUDGET.md)
covers their shared deadlines including admission and retirement without lock waits.
Earlier results above describe their own snapshot. Exact generic NAT and older-generation
outcomes are addressed in [D01](AUDIT-Q14-RETAINED-CLEANUP.md); persistent recovery,
DNS REDIRECT and other NAT setup remain open.
