# Q25: disabled IPv6 and TUN reservations for every Linux client

Date: 23 September 2026. Baseline: `f5c5677c`.
Q25-F048–F049 are fixed within the described scope; sections 17/18/25 remain **IN_PROGRESS**.

## Findings and changes

**Q25-F048, P2 — installed ip6tables blocked an IPv4 client with IPv6 fully disabled.**
Public engage required filter inventories from both discovered tools. With
`ipv6.disable=1`, the IPv6 utility may exist while its table is unavailable.
Startup refused before installing IPv4 rules. Subsequent refresh/cleanup also
did not distinguish an installed binary from disabled kernel functionality.

A narrow source of positive evidence now reads
`/sys/module/ipv6/parameters/disable`: exactly `1` with an optional trailing LF.
At most 17 bytes are read. Errors, including after a `1` prefix, absence, empty,
other or excessive contents do not establish disablement. No sysfs/sysctl is written.
The disabled family is excluded from ip6tables discovery, kill-switch address
inspection, refresh and cleanup. Gateway also uses this common firewall-discovery helper.

This is the module functionality parameter, not per-interface `disable_ipv6` or an
empty global address inventory. Official [kernel documentation](https://www.kernel.org/doc/html/latest/networking/ipv6.html)
distinguishes these modes; the [kernel source](https://github.com/torvalds/linux/blob/master/net/ipv6/af_inet6.c)
declares module parameter `disable` as an integer with permissions 0444.
Unknown-state failures still cannot bypass firewall inspection. The exception does
not bypass IPv4 conflicts/inventory errors or the namespace lease.

**Q25-F049, P2 — clients without kill-switch did not reserve a TUN for their session.**
The previous lease was acquired only with kill-switch enabled. In particular,
`dev_attach` can open a queue of an external multi-queue TUN: separate processes
can attach to the same name without taking the foreign-device reclaim branch.
Process-local route/gateway/exit ownership does not coordinate them; the same name
also coincides in firewall selectors. Ordinary create already checked foreign devices,
so this report does not claim those checks were always bypassed. An absent interface
during reconnect also does not prove the absence of a live client session.

The mechanism moves from `client/killswitch/lease.rs` into shared
`client/network_lease.rs`; the separate old module is removed.
Every Linux client first reserves `qeli.client.tun:<dev>`. Protected clients then
also claim the existing `qeli.client.kill-switch` name, preserved for compatibility
with the previous version. Failure of the second claim releases only the temporary
first reservation, preserving other owners.

The guard is declared before the adapter and spans reconnect, cleanup and post_down.
Both claims precede DNS recovery and network setup. Distinct TUNs without conflicting
kill-switches remain independent. `dev_attach` reserves the client session's use of a
name; external device ownership does not change and deletion authority is not granted.
Qeli servers, old clients and external tools do not participate in the TUN protocol;
kernel checks remain. No new INI keys or JSON configuration formats were added.

## Verification

**17 new host tests**: six public kill-switch scenarios, three sysfs evidence reader
checks and eight shared lease coordinator scenarios.
Three module-disabled IPv6 cases: **FAIL on the original logic → PASS after the fix**,
with unchanged bodies after rustfmt. The baseline includes the new test evidence
source, which original production logic did not yet consult.

Coverage includes startup/refresh/cleanup without IPv6 tables, no unnecessary address
probe, refusal on unknown state and IPv4 conflicts, failed/oversized reads, identical
names with every kill-switch combination, distinct names, partial-claim rollback and
unwind release. Coordinator tests call the production helper with an atomic-bind model.
They do not run two real VPN processes or an external multi-queue TUN.

**1270 host unit + 52 editor/policy + 7 examples + 12 server INI = 1341 Rust tests PASS.**
All nine matrix commands PASS, including Linux all-targets Clippy, separate client/server,
minimal FFI, no-roaming, no-features and rustfmt.
The six existing Linux socket tests and ignored child fixture moved with the mechanism;
they were compiled but not executed. The first run exposed duplicate inclusion of
the new host tests through FFI; Linux cfg was corrected and the matrix rerun.
Firewall models and IPv6 command-boundary tests set module state per test thread,
so actual ipv6.disable=1 on a test host does not alter their fixtures.
No new warning headlines. Rust 1.98.0; the existing `chunks_exact_to_as_chunks`
exception is retained.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/client-namespace-audit-20260923.

## Limits and next work

Linux runtime with ipv6.disable=1, namespaces, iptables-nft/legacy, two processes,
dev_attach and reconnect remains unverified. An absent IPv6 module is not treated
as proven disablement. IPv6 appearing after an initially empty inventory remains open.
This run did not change host networking.

Next: unknown sysctl owner state, namespace identity in its journal, incomplete /proc
during TUN-owner discovery, DNS/carrier globals, deadlines and crash recovery.
The shared sysctl journal is not yet separated by network namespace: isolated leases
do not prove isolation of every subsystem. Native certification, a new benchmark
and the full audit remain unfinished.

Follow-up: [Q25-F050–F051](AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md) fixes unknown-owner handling and preserves
entries after inconclusive sysctl inspection; namespace identity remains open.

Follow-up: [Q25-F052–F053](AUDIT-Q25-SYSCTL-NAMESPACE.md) isolates network journal groups,
checks PID/time context and documents v1 → v2 migration. Runtime limits remain.

Follow-up: [Q25-F054–F055](AUDIT-Q25-TUN-ADMISSION.md) removes partial procfs holder
discovery and destructive recovery; the first queue is created exclusively.
Attach/teardown identity and Linux runtime remain open.
