# Q14/Q25: shared firewall checks and exact DNS cleanup

Date: 23 September 2026. Baseline commit: `ee613a60`.
Sections 14, 17, 18, 19 and 25: **IN_PROGRESS**; the full audit remains open.

## Fixed findings

**Q14-F026, P2 — failed DNS-rule inspection became successful cleanup.**
The old `delete_exact_rule` used boolean `rule_present`. Spawn errors and every nonzero
`-C` status became absence, so cleanup returned success. Removing exactly 1024 copies
also reported the limit without a final check. Inspection failure now remains an error,
and the last permitted deletion is followed by another `-C`. A remaining rule, including
a successful no-op deletion, produces failure.

**Q25-F018, P2 — kill-switch checks treated general errors as absence.**
`absent_check` accepted every exit code 1 and recognized absence text regardless of exit
status. A permission error on stderr could therefore confirm an uninspected chain's
absence. Code 1 is not exclusive to missing rules; other errors use it too, as described
in [Netfilter's DIAGNOSTICS manual section](https://ipset.netfilter.org/iptables.man.html).
This is a cleanup-confirmation defect; actual Linux traffic leakage was not tested here.

**Q25-F019, P2 — another chain's diagnostic could confirm the expected chain's absence.**
The previous code lowercased the entire message and used substring matching, allowing
`QELI_KS_edge2` or `QELI_KS_Edge` to match expected `QELI_KS_edge`. Quoted chain names
now require an exact, case-sensitive match.

## Shared implementation and compatibility

`qeli/src/firewall_check.rs` interprets command results for server NAT and checked Linux
kill-switch operations. The separate `absent_check` implementation was removed. The
shared parser returns present, absent or an unknown-state error. Ordinary boolean setup
probes keep their previous contract; their remaining call sites need a separate audit.

For `-C`, the existing silent-miss contract is retained: code 1 with empty stderr means
absence. This is a compatibility assumption for the normal tool/wrapper; it cannot
distinguish an arbitrary broken wrapper returning the same result. Empty stderr on
failed `-S` no longer establishes absence. Known missing-rule diagnostics are accepted
with code 1. Missing named targets/chains with code 1 or 2 require the exact expected
name; legacy/nft quoting and the standard help line are supported. Unknown messages,
additional errors and other exit codes do not establish absence.

Exact deletion moved into `qeli/src/server/nat/cleanup.rs`; the separate server loop was
removed. `cleanup_dns_input_with` supplies both UDP and TCP rules. One failed branch
cannot skip the other, and diagnostics retain both causes. Check/delete commands carry
the same table/chain and complete rule specification, including tag, interface, addresses,
port and protocol. No generic `-S` is required, preserving the mixed native nft path
whose chain listing is unavailable. There are at most 1024 deletes per exact rule.

INI, manual/route/nat66/off, ABI and client applications are unchanged. The module serves
Linux server/client code and host tests; it does not replace Windows/macOS firewall code.
DNS leases, the supervisor, teardown ordering and process execution were not redesigned.

## Validation

17 new host tests: nine shared-parser and eight exact-cleanup cases. They cover general
status-1 failures, unknown statuses/diagnostics, exact names, legacy/nft messages, silent
misses, failed listing, invalid bytes, idempotency, spawn/verification/delete errors,
1024/1025 copies, no-op deletion and TCP cleanup after UDP failure. One new Unix signal
test and one Linux adapter test with a fake iptables were cross-compiled only. Previous
missing-target cases now run in the host suite; the Linux Qeli-target extraction test remains.

Four regressions fail with code extracted from `ee613a60` and pass with the fix: failed
exact inspection, exactly 1024 deletions, general status 1 and another chain's name.
The baseline only adapts the executor/return interface; old classification and iteration
limits remain intact. Harness copies and logs are preserved.

**945 host unit + 52 editor/policy + 7 examples + 12 server INI = 1016 Rust tests PASS.**
Linux all-targets Clippy, client-only, client without roaming, server-only, minimal FFI,
compatibility without features and rustfmt pass. Existing 23 server-only, one no-roaming,
33 compatibility warnings and MSVC linker output remain; the Clippy
chunks_exact_to_as_chunks exception belongs to unchanged ndp_proxy.
Nine documentation checks and `git diff --check` pass.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/firewall-presence-audit-20260923.

## Open boundaries

Q14-F027 is partially addressed by subsequent passes: [known DNS/sysctl leases](AUDIT-Q14-OWNED-SHUTDOWN.md)
and [current-generation task/TUN failures](AUDIT-Q14-PROFILE-SHUTDOWN.md) reach the final
shutdown outcome. Generic NAT and unfinished cleanup of older generations remain open.
The subsequent [Q14-F032 pass](AUDIT-Q14-NAT-COMMANDS.md) moves server NAT to the bounded
runner. Client kill-switch and overall network-operation deadlines remain open.
Inspection/deletion is not atomic against external administration. Actual backend,
version and locale combinations need target Linux validation: unknown diagnostics
produce inspection errors. Linux runtime, real firewall/TUN/DNS, devices, native release
builds, SSH/systemd/Actions and benchmarks were not run.

Previous pass: [finite NAT sweep](AUDIT-Q14-NAT-CLEANUP.md).

Follow-up: [Q14-F028](AUDIT-Q14-DNS-OWNERSHIP.md) preserves exact ownership after failed
Drop/rollback in worker memory and adds retry. Q14-F027 and restart recovery remain open.

24 September follow-up: [16 native mixed/firewalld scenarios](AUDIT-Q14-MIXED-FIREWALL.md) verify rule and journal preservation. A native nft expression can break absent-rule `-C` confirmation after successful `-D`; evidence remains until an administrator restores compatibility. The wrapper that disabled only `-S` did not cover this case.

Final D04 follow-up: [client mixed packet/recovery matrix and Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) completed; D04 is DONE in the current register. Historical IN_PROGRESS statements above refer to earlier snapshots. D10 (broader policies/topologies) and D13 (state growth) remain open.
