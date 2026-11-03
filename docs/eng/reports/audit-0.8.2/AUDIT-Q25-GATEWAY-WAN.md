# Q25: gateway WAN discovery and cleanup

Date: 23 September 2026. Baseline: `b5669e87`.
Sections 22 and 25 remain **IN_PROGRESS**. Q25-F021 and Q25-F022 are fixed.

## Findings and changes

**Q25-F021, P2 — unbounded WAN probes could retain gateway setup or teardown.**
Four read-only `ip` command launches in `client/gateway.rs` used
`std::process::Command::output` without a deadline or output limit. A stalled child
could retain engage, verification/reconnect or cleanup; excessive output was accepted.

WAN selection now lives in `client/gateway/wan.rs` and uses the existing shared runner:
15 seconds per command, separate 16 MiB stdout/stderr limits, concurrent pipe draining,
termination request and child wait after timeout/overflow. Both families keep their
own queries: default route first, then route-get for `1.1.1.1` or
`2606:4700:4700::1111`. The first usable default-route device still wins.
These are local routing-table queries, not packets sent to those addresses.

A failed, nonzero, empty or unusable first result retains the existing fallback policy.
If route-get also fails or has no usable device, selection returns `None`.
Timeout/overflow output is discarded rather than parsed as a partial WAN result.
This pass does not change callers' treatment of `None` or add per-probe diagnostics.

**Q25-F022, P2 — cleanup queried current routes even with complete remembered WANs.**
`remove_exit_rules` eagerly evaluated both discovery functions before calling
`remove_family`, although the result was only used with empty ownership.
A stuck route lookup could therefore delay deletion of rules whose interfaces were
already known. Discovery is now lazy and performed only for a family without
remembered WANs. Every old/new WAN recorded for that TUN remains a cleanup target.

Family ownership is still cleared only after successful cleanup. A failed IPv4 cleanup
does not prevent IPv6 cleanup, and retains IPv4 targets for retry. Sibling TUN records
are untouched. Empty ownership and unavailable fallback retain the previous best-effort
success behavior; this is not persistent recovery after a crash.

## Validation

**1034 host unit + 52 editor/policy + 7 examples + 12 server INI = 1105 Rust tests PASS.**
Seven new portable regressions cover default-route preference, exact IPv4/IPv6 argv,
fallback/error/output contracts and lazy cleanup target selection.
All nine matrix commands pass: host and config suites, Linux all-targets Clippy,
client-only, server-only, client without roaming, minimal FFI, compatibility without
features and rustfmt. Existing feature-specific warnings and the
`chunks_exact_to_as_chunks` Clippy exception remain.

A separate harness extracts production WAN functions from baseline/fixed sources.
Real finite children replace `ip` only in the test child's PATH. **28/28 fixed cases**
cover both query stages and families under deadline, stdout/stderr overflow, nonzero,
unusable/empty output and success. The four production timeout cases return in about
15 seconds; the loopback witness is closed on return. Oversized stdout retains valid
route text so parsing failure cannot hide the missing output limit.

Another adapter extracts actual `remove_exit_rules`, ownership helpers and rule builders;
only discovery/firewall operations are test doubles. **5/5 fixed cases** cover remembered
old/new WANs, failed-family retry, missing-tool retry, mixed remembered/discovered families,
and discovery with no remembered targets. It checks rule targets, sibling isolation and
per-family retention. It does not execute iptables or prove actual kernel rule deletion.

Across both adapters the baseline reproduces **16 expected regression failures** and
passes **17 controls**. The fixed version passes **33/33**; these are separate from 1105.
Reproduction script, source hashes, argv, stdout/stderr and command logs:
C:/Users/litvi/OneDrive/Documents/qeli/gateway-wan-audit-20260923.
RU/EN documentation checks pass.

## Boundaries and next work

No INI fields, API or ABI changed. The limit is per query, not per discovery, gateway
operation or shutdown: fallback is sequential, and process spawn/kill/reap or an
uninterruptible kernel wait can extend execution. Linux descendants leaving the process
group are outside group termination guarantees; Linux signals were not tested here.

Client route mutations and gateway/kill-switch firewall commands still need deadlines
and ownership checks after uncertain mutation outcomes. They are not migrated by this
read-only change. Real Linux TUN/firewall, network changes, systemd, device apps, native
release and new benchmarks were not run. The full audit remains open.

Previous passes: [path monitor](AUDIT-Q25-PATH-MONITOR.md),
[shared command runner](AUDIT-Q25-SYSTEM-COMMANDS.md).

Follow-up: [Q25-F023/F024](AUDIT-Q25-ROUTE-OUTCOME.md) corrects failed route mutation
outcomes; pending ownership/recovery and command deadlines remain open.
