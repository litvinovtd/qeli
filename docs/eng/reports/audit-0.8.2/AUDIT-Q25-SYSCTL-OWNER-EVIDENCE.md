# Q25: sysctl owner evidence and preserving recovery

Date: 23 September 2026. Baseline: `67e02ba8`.
Q25-F050–F051 are fixed within the described scope. Sections 14/17/18/25 remain **IN_PROGRESS**.

## Findings and changes

**Q25-F050, P2 — an uninspectable process was treated as a dead owner.**
The shared server/client journal checked `PID + process-start-time + scope` by reading
`/proc/<pid>/stat`. Every error became false: permission failure, I/O failure, malformed
contents or hidden procfs could remove a live owner. If it was the last owner, a subsequent
acquire/release/recovery restored original forwarding, `rp_filter` or `accept_ra` beneath
an active component.

The check now distinguishes live, confirmed dead and unknown owners. A readable different
start-time establishes PID generation replacement. Missing stat requires a separate
process-presence check: `kill(pid, 0)` delivers no signal; `ESRCH` confirms absence in the
current PID namespace, while `EPERM` or success establishes presence. An existing process
with unreadable start-time remains unknown. Other errors also preserve its entry.
The PID reported by stat must match; zero/out-of-range positive pid_t values and malformed
start-times are rejected.

Unknown owners are retained and reported. Acquisition and startup recovery return
`cannot verify host sysctl owner(s)` before acquiring a new lease. Preliminary cleanup of
other confirmed stale entries may already have run; its result is persisted before the
error returns. Release removes its own verified scope, continues independent cleanup,
retains unknown co-owners and returns an aggregated error.

**Q25-F051, P2 — failed sysctl inspection could lose the original value needed for retry.**
`Path::exists` collapsed metadata errors into absence, allowing recovery to discard the
entry. Empty or malformed contents were treated as an administrator change. Any missing
path, including global forwarding, was also treated as completed cleanup.

The value is now read directly and validated as `0`/`1`/`2`. Read failures and malformed
values retain recovery entries. A missing sysctl can be forgotten only for a named
interface whose absence is confirmed by a complete successful `/sys/class/net` inventory.
This exception excludes `all`/`default`, global settings, existing interfaces and failed
inventories. Valid administrator changes are preserved; failed restoration writes also
retain the original value in the journal.

## Verification

Added **20 host tests** of production prune/restore/release helpers and admission policy
with an isolated process/sysctl I/O model. One existing sysctl validation test now also
runs on Windows. Test I/O injection is mandatory: it never accesses real procfs/sysfs,
writes sysctl or performs the operating-system process probe.

Eight regressions cover failed/malformed stat, hidden existing processes, unknown process
presence, failed sysctl observation, empty/invalid values, missing global settings and
unconfirmed interface disappearance. Original logic: **8 FAIL / 5 PASS**. After fixing:
**20 PASS**, with unchanged bodies for the eight regressions after rustfmt. The baseline
includes a test I/O seam; its old exists models failed metadata observation, not a real
Linux ACL scenario.

Controls cover live generations with spaces/parentheses in comm, PID reuse, confirmed
process/interface disappearance, administrator changes, refusing acquisition on unknown
ownership, invalid PIDs, retry after access recovers, preserving unknown co-owners,
independent cleanup and failed restoration writes.

**1291 host unit + 52 editor/policy + 7 examples + 12 server INI = 1362 Rust tests PASS.**
All nine matrix commands PASS: host unit, config integration, Linux all-targets Clippy,
client-only, server-only, minimal FFI, client without roaming, no-features and rustfmt.
No new warning headlines; Rust 1.98.0 and the existing `chunks_exact_to_as_chunks` exception
are retained. RU/EN manuals, indexes and the plan are synchronized.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/sysctl-owner-evidence-audit-20260923.

## Limits and next work

The journal version/internal format, INI keys and API/ABI are unchanged. No new user
configuration format. New tests do not execute cross-process flock, atomic journal writes
or a complete public journal transaction. Linux syscall branches are compiled; this is
not actual Linux E2E, reboot/SIGKILL or container execution.

**The journal still lacks PID/network namespace identity.** Process checks require the
same PID namespace and a consistent procfs view; sysctls belong to the corresponding
network namespace. This pass does not make a shared state directory safe across distinct
namespaces. Their isolation is next, together with incomplete /proc during TUN-owner
inspection. DNS/carrier globals, deadlines, durable crash recovery, Q14-F027 workers/FD,
native certification and a new benchmark remain open. Of 37 plan sections, 19 are
IN_PROGRESS and 18 TODO; none has full PASS. Preparation stage 00 is complete.

Follow-up: [Q25-F052–F053](AUDIT-Q25-SYSCTL-NAMESPACE.md) isolates network journal groups,
checks PID/time context and documents v1 → v2 migration. Runtime limits remain.

Continuation: [Q25-F083 — v3 and original sysctl fd](AUDIT-Q25-SYSCTL-TARGET.md). Historical limitations above describe this report’s snapshot; name disappearance no longer permits forgetting the original.
