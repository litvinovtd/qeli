# Q25: shared TUN/TAP route installation and removal of obsolete implementations

Date: 23 September 2026. Baseline: `d6b2c079`.
Q25-F037–F039 are fixed within the scope below. Sections 22/23/25 remain **IN_PROGRESS**.

## Findings

**Q25-F037, P2 — active TUN installation neither verified completion nor tracked ownership.**
`setup_network_plan_routes` used `add_tunnel_route` for connected pools, full-tunnel
capture, `NetworkPlan.routes` and connected-prefix overrides. Successful exit status
was accepted without a post-query. On `File exists`, device/gateway were checked but
metric was not; direct L3 TUN routes could borrow a route containing `via`.
Installed entries were absent from the shared journal. Lost add completion neither
closed admission nor reserved a possible leftover. CIDR validation checked only the
address before the slash.

**Q25-F038, P3 — unused client implementations duplicated shared core behavior.**
Call-graph review found no callers of `apply_local_networks` or `apply_pushed_routes`
outside their own chain. The local `PushedRoute` and second parser remained beside
the active NetworkPlan path. They and unused wrappers were removed.
The real planner in `transport_core/network.rs` remains; its single-address test adapter
is now `cfg(test)`. Old route-query helpers serve historical Linux fixtures only and
are also excluded from production. Internal pushed-route wire data is unchanged;
user configuration remains INI.

**Q25-F039, P2 — route_local silently skipped malformed address inventory.**
Lossy UTF-8 conversion and `continue` on malformed rows turned inspection errors into
an empty or incomplete set of connected networks. Required more-specific tunnel routes
could be omitted while setup succeeded and a physical connected route still determined
the path to the local network.

## Changes

`install_initial_route` is shared by physical bypass/blackhole and TUN/TAP routes.
Before add it checks other owners' claims/pending records and the exact destination
snapshot. Matching existing state is borrowed without add/claim; conflicts or invalid
snapshots prevent writing. Every add result requires a post-query. Only success plus
a matching snapshot grants ownership; confirmed absence fails without a claim; an
unknown leftover becomes pending and closes owner admission.

Checks include destination, interface, requested metric, TAP gateway and absence of
a gateway for direct TUN routes. CIDR and gateway family are validated before mutation.
Pushed/include/DNS/RFC1918 blanket routes already reside in `NetworkPlan.routes` and
use the same installer; the separate client parser/application path is unnecessary.
The shared planner still filters prohibited server pushes.

Linux metric display is handled explicitly: IPv4 omits zero `RTA_PRIORITY` in dumps,
so absent metric matches only an explicitly requested IPv4 zero.
[Linux IPv4 fib_dump_info](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_semantics.c).
Linux converts IPv6 metric 0 to 1024; Qeli records that effective value in add and undo,
preserving the previous kernel outcome.
[Linux IPv6 route](https://github.com/torvalds/linux/blob/master/net/ipv6/route.c),
[IP6_RT_PRIO_USER](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ipv6_route.h).
The `default` label is accepted only for an expected /0 in the query's family.

Cleanup deletes proven records with saved selectors, then independently performs a
verified flush of the owner's interface. Pending alone never authorizes `route del`.
Absence is now checked after flush: an unknown TUN add removed by that independent
cleanup does not leave a false reservation. Routes on other interfaces survive flush;
a remaining destination or failed query retains pending and cleanup failure.
Whole-interface ownership predates this pass: even a borrowed route on that owned
TUN/TAP is covered by its flush. `dev_attach` skips this NetworkPlan setup and does
not acquire someone else's interface through it.

route_local inventory now requires UTF-8 and valid primary fields in every nonempty
row: positive index, nonempty name, `inet` and an IPv4 address/prefix. Invalid rows fail
setup before route mutations. Host bits in interface addresses are valid; the prefix
determines the network. Controls cover `@peer`, multiple addresses, duplicates, empty
inventory, skipping the owned TUN and non-RFC1918 networks. This is not a full parser
of every iproute2 attribute.

## Validation

**8/8 regressions FAIL on baseline production code → PASS after the fix.**
Two further inventory regressions reproduced the previous parser defect: FAIL → PASS.
The first eight test bodies remain unchanged apart from formatting.
**23 new tests** total: ten reproductions and thirteen positive/protective controls.
They run production NetworkPlan setup/cleanup against an isolated command-state model
without modifying host networking.

**1186 host unit + 52 editor/policy + 7 examples + 12 server INI = 1257 Rust tests PASS.**
All nine matrix commands PASS: host/config, Linux all-targets Clippy, client-only,
server-only, minimal FFI, client without roaming, compatibility without features and
rustfmt. Linux checks are cross-compilation, not runtime execution. Rust 1.98.0 with
the existing Clippy `chunks_exact_to_as_chunks` exception; no new exceptions.
The RU/EN docs gate passes.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/route-tunnel-audit-20260923.

## Limits and next work

Shared core defines policy; Linux applies the plan. This pass does not move OS commands
into the portable core or rebuild shipped native cores. Removed Linux Rust helpers were
not C ABI/panel API functions. INI and the network protocol are unchanged.

Snapshots provide neither atomic kernel CAS nor proof of authorship in external races.
Multiple exact routes are rejected as ambiguous; arbitrary policy tables, VRFs and
multipath are not certified. The journal is in memory. Additional pre/post queries add
setup/cleanup work; performance was not measured. The 15-second deadline still applies
per command, not to the entire operation under the mutex.

Next: full gateway rollback, partial firewall/sysctl changes and global-state isolation;
IPv6-protection evidence, Q14-F027 TUN workers/FD, overall preflight deadline,
Linux E2E restart/restore/manual+NDP, native certification and a new benchmark.
The full audit is not complete.

Previous pass: [command bounds and IPv4 protection](AUDIT-Q25-CLIENT-COMMANDS.md).

Gateway follow-up: [scope rollback and firewall inspection](AUDIT-Q25-GATEWAY-ROLLBACK.md).
