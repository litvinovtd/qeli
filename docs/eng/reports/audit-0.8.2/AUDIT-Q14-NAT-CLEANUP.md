# Q14: finite NAT rule cleanup and failure diagnostics

Date: 23 September 2026. Baseline commit: `9c520fbe`.
Sections 14, 17, 18 and 19: **IN_PROGRESS**; the full audit remains open.

## Fixed findings

**Q14-F024, P2 — a successful no-op deletion could loop forever.**
After each `iptables -D`, the old algorithm selected the first matching rule from a
fresh `-S` listing. If the backend reported success without removing it, cleanup never
finished and kept the shared firewall mutex locked. Rule installation already accounts
for successful no-ops in `nat.rs`; deletion did not. A command fixture reproduces this;
no particular iptables/nft version was exercised on live Linux in this pass.

**Q14-F025, P2 — the sweep hid failures and skipped remaining rules in the same chain.**
A listing error looked like no rules; a deletion error silently stopped processing the
chain. Later chains were still attempted, but later rules in the failed chain remained
until another cleanup. Spawn, exit-status, parsing and verification failures now leave
the algorithm as errors; the Linux adapter logs
`NAT cleanup via ... for '...' incomplete: ...` with table/chain context.

## Change

Shared code in `qeli/src/server/nat/cleanup.rs` serves the server and host tests.
The previous parser and algorithm copy was removed from `nat.rs`. A chain snapshot is
fully parsed before deletion, followed by one deletion attempt per matching occurrence.
A final `-S` verifies that no owned rules remain. This gives a finite number of calls
for a finite snapshot without reintroducing a 64-rule cap.

A failed deletion does not skip later rules or chains. Invalid UTF-8, quoting or
unexpected lines reject the snapshot before deletion; they cannot establish absence.
Diagnostics bound the number and length of messages. The chain set is unchanged:
nat POSTROUTING/PREROUTING, filter INPUT/FORWARD and mangle FORWARD. Exact profile tags,
the startup prefix `qeli-nat:` and quoted arguments are preserved; administrator rules
and similarly named profiles remain untouched.

The outer best-effort cleanup contract remains: a warning does not change worker exit
status. Some native nft chains cannot be listed through `iptables-nft -S` although exact
`-C`/`-D` works; the DNS lease handles that separate path. Making every generic listing
failure fatal requires validating this compatibility case first. INI, IPv6 modes, ABI,
DNS leases, the supervisor and teardown ordering are unchanged.

## Validation

13 new host tests cover empty chains and retries, all five chains, exact and prefix
ownership, foreign rules, quoting, 129 duplicates, successful no-op deletion, read and
delete failures with continued cleanup, malformed snapshots, failed verification,
concurrent additions and bounded diagnostics. They exercise the production algorithm
through injected command results without changing the host firewall.

Two tests fail against the algorithm from `9c520fbe`: no-op deletion exceeds the
fixture's finite command budget, and listing failure returns false success. The only
adapter converts the previous `()` return into `Ok(())`; the old loop is unchanged.
Both pass with the new algorithm. Comparisons use separate harness copies.

**928 host unit + 52 editor/policy + 7 examples + 12 server INI = 999 Rust tests PASS.**
Linux all-targets Clippy, client-only, client without roaming, server-only, minimal FFI,
compatibility without features and rustfmt pass. Existing warnings in unchanged modules
remain; the Clippy chunks_exact_to_as_chunks exception belongs to ndp_proxy.
Nine documentation checks and `git diff --check` pass.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/nat-cleanup-audit-20260923.

## Open findings and next checks

**Q14-F026, P2 — exact DNS INPUT cleanup conflates absence and failed checks.**
`delete_exact_rule` uses boolean `rule_present`: any spawn failure or unsuccessful `-C`
status becomes false and successful cleanup. Removing exactly 1024 copies also reports
the limit without a final absence check. Confirmed by review; not fixed in this commit.
Next: portable negative fixtures, separate present/absent/unknown outcomes and a mixed
native nft chain compatibility check.

Follow-up on 23 September: Q14-F026 is fixed in the [next pass](AUDIT-Q14-Q25-FIREWALL-CHECKS.md).
Exact cleanup shares result interpretation with Linux kill-switch; a final check validates
the 1024 boundary. Mixed native nft compatibility is still covered by fixtures only.

**Q14-F027, P2 — resource cleanup errors do not reach the stop result.**
`cleanup(profile)` returns `()`, DNS leases clean up from Drop, and the stopping supervisor
does not collect profile errors. Signal-driven worker exit status depends on accounting
flush, so a successful exit does not confirm firewall/TUN cleanup. This pass adds generic
sweep diagnostics; Result propagation and lifecycle changes are still pending. Tests must
cover continued cleanup, combined failures and native nft compatibility.

`--wait 5` bounds xtables lock acquisition. The subsequent
[Q14-F032 pass](AUDIT-Q14-NAT-COMMANDS.md) adds the shared runner and a deadline per NAT
command; there is still no overall cleanup-sequence deadline. Listing and deletion are not atomic
against external administration; changes after the final verification remain possible.
Linux runtime, actual TUN/firewall/DNS, release libraries, device applications,
SSH/systemd/Actions and new benchmarks were not run.

Previous pass: [TUN/DNS command deadlines](AUDIT-Q25-SYSTEM-COMMANDS.md).
