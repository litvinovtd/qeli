# Q25: route deletion specifications and verified cleanup

Date: 23 September 2026. Baseline: `fa326e5e`.
Q25-F025/F026 are fixed within the scope below. Sections 22, 23 and 25 remain **IN_PROGRESS**.

## Findings and changes

**Q25-F025, P2 — a destination-only journal could delete or overwrite a replacement route.**
Physical carrier and exclude setup recorded `route del <destination>`, dropping the
installed gateway/interface. Roaming trusted journal membership by destination; cleanup
could delete an administrator's later replacement, and rollback could overwrite one.

The in-memory journal now retains the delete specification derived from the successful
installation, including supplied gateway, device, source and other command attributes.
Records are replaced by family/type/destination key when a successful roaming change
moves the route; rollback restores the previous specification. The legacy setup path
also records its known gateway/device. Blackhole records retain their type.

Before claiming an existing carrier for replace or retirement, the adapter compares its
requested identity fields with the observed route. Mismatch discards stale ownership:
a conflicting operator route blocks replace; an operator route is not retired.
Rollback inspects the current route before restoring. A different observed route is
preserved and reported as unknown state. Restoring an absent route uses `add`, so it
cannot unconditionally overwrite a route appearing after the query.

The comparison covers destination/type, supplied `via/dev/src/metric/proto` and absence
of `via` for a direct route. It is not full kernel identity or an atomic ownership token.
Kernel-added display defaults are not compared as requested attributes.

**Q25-F026, P2 — cleanup discarded ownership based on exit status or error text alone.**
A successful delete or “already absent” message previously removed the journal entry
without checking the table. Conversely, an I/O error retained the entry even when the
delete had completed. Cleanup now reads `route show exact <destination>` before deletion
and again afterward. An absent route needs no delete; changed identity is preserved.
A remaining matching route, unreadable/malformed snapshot or multiple nonempty lines
returns an error and retains the exact specification for retry. Verified absence permits
completion even after a lost delete result. Both TUN-family flush attempts still run.

The shared removal helper is also used to roll back newly added candidate routes.
Replacement/retirement restoration updates journal specifications after success.
The helper and existing transaction still use the previous command runner; this pass
does not introduce deadlines or change user INI, API or ABI.

## Validation

**1073 host unit + 52 editor/policy + 7 examples + 12 server INI = 1144 Rust tests PASS.**
Sixteen new permanent regressions use actual pin/commit/cleanup/rollback functions and
a stateful command fixture. Both families, changed gateway/device/source, on-link routes,
a replacement between check and delete, stale membership before replace/retirement,
operator changes during rollback/restoration, false delete success, misleading absent
errors, lost results, unreadable/malformed/ambiguous snapshots and retries are covered.

The same 16 tests run against extracted baseline/fixed code: **baseline 15 expected
failures + 1 control; fixed 16/16 PASS**. These repetitions are not added to 1144.
The fixture models command effects and selectors; it does not execute real netlink or
iptables. Existing Linux shell fixtures were updated to retain route state for the new
exact queries and to seed full ownership records; they were cross-compiled, not run.

All nine matrix commands pass: host/config, Linux all-targets Clippy, client-only,
server-only, client without roaming, minimal FFI, compatibility without features and
rustfmt. Existing feature warnings and the `chunks_exact_to_as_chunks` exception remain.
RU/EN documentation checks pass.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/route-ownership-audit-20260923.

## Kernel semantics and boundaries

The fixture's interface/gateway selector behavior was checked against primary source:
[Linux 6.12 IPv4 fib_nh_match](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/fib_semantics.c#L823)
and [IPv6 ip6_route_del](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/route.c#L3786).
This is source review, not execution on supported router/kernel versions.
IPv6 deletion does not match preferred source like IPv4; unspecified fields and
nexthop-object routes also limit selector guarantees. Therefore snapshot checking plus
qualified deletion is not a general compare-and-swap transaction.

Remaining work includes concurrent changes after validation (especially replace),
complete route identity, multipath/VRF support, retirement/restore result verification,
pending operations with unknown results, and persistent recovery. The journal is still
process-global, without TUN/generation ownership; overlapping profiles and stale cleanup
need a separate fix. No blind registration of an uncertain add was introduced.

Commands and whole operations are still unbounded. Real Linux TUN/firewall/handover,
crash/restart, devices, native release and new benchmarks were not run.
Previous pass: [mutation outcomes](AUDIT-Q25-ROUTE-OUTCOME.md).


Follow-up: [Q25-F027/F028 — connection owners](AUDIT-Q25-ROUTE-SCOPE.md) separates journals
and closes admission on cleanup; the historical limits above describe this report’s baseline.

Follow-up: [Q25-F099](AUDIT-Q25-ROUTE-ATTRIBUTES.md) separates borrowing from ownership and checks implicit route attributes; the earlier comparison of supplied fields no longer grants authority to delete a changed physical route.

D04 follow-up: [Q25-F100](AUDIT-Q25-ROUTE-JOURNAL.md) adds durable physical route ownership and crash recovery. The process-local contract described here is extended with intent/confirmed state; uncertain operations still grant no delete authority.
