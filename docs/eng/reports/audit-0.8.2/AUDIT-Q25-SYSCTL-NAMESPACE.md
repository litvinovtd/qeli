# Q25: namespace isolation for the sysctl journal

Date: 23 September 2026. Baseline: `fa883796`.
Q25-F052–F053 are fixed within the stated boundaries; sections 14/17/18/25 remain **IN_PROGRESS**.

## Confirmed problems

**Q25-F052, P2 — recovering another network namespace's entries.**
A single `sysctls.state` was indexed only by sysctl path. With a shared state directory,
two network namespaces have identical paths but different kernel settings. Recovery
could restore another network's original value into the current network and discard
its pending entry. Acquisition also mixed original values and owners of independent knobs.

The internal journal now uses version 2: groups keyed by network namespace identity
retain independent entries. The shared path and file lock remain. Acquisition, release
and recovery process only the current group; foreign owners are not probed. Rewriting
the whole journal preserves other groups. Empty groups are excluded from the saved
snapshot; an empty journal is removed. The total serialized size is checked before
writing, avoiding creation of a journal that exceeds its reader's limit.

**Q25-F053, P2 — PID and start-time could be checked in a different coordinate system.**
Processes in one network namespace but different PID namespaces may assign different
meanings to the same PID number. An inherited procfs can also expose ancestor PIDs while
`kill(pid, 0)` uses the current numbering. A foreign owner could be misclassified as dead.
Different time namespaces affect observed start-time too: the kernel applies a time
offset when emitting the field in
[proc/array.c](https://raw.githubusercontent.com/torvalds/linux/master/fs/proc/array.c).

Each group now records PID and, when exposed, time namespace identity. Mismatch stops
the transaction **before pruning, sysctl changes or rewriting the journal**. Different
PID namespaces sharing one network do not receive separate journals, which would lose
shared ownership. Procfs must report a single `NStgid` value matching the current PID;
missing/multiple/duplicate values, another PID and read failures are rejected.
The ordering is documented by [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html).

Namespace identity is the target object's `st_dev:st_ino` from
`/proc/thread-self/ns/{net,pid,time}`, not the symbolic link inode. The calling thread
is used because setns affects that thread. See
[namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html) and
[setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html).
Missing `ns/time` permits kernels without that capability; other failures stop the
operation. Saved presence/absence of time identity cannot silently change.

## Migration and compatibility

A nonempty v1 journal from the current boot has no namespace evidence, even without
owners. Automatically assigning the current context would be a guess. Its bytes remain
unchanged and the operation returns `legacy host sysctl journal has no namespace identity`.
Complete recovery with the previous version in the original namespaces before upgrading.
If that is impossible, the transition can accompany a planned host reboot, running the
new version afterward: previous-boot values are never replayed. Restarting Qeli alone
does not change boot-id. Stopping an old server worker does not guarantee an empty
journal: its IPv4 lease may remain until the next recovery pass.

Empty v1 and valid previous-boot journals allow transition without replaying old settings.
Unknown versions or corrupt journals are not removed, even with another boot-id. Old
binaries cannot read v2; sharing state between old/new versions and downgrading with a
nonempty v2 journal are unsupported. No new INI keys, JSON configuration format or
API/ABI changes; only internal recovery metadata changes.

## Verification

**24 new host tests.** Four original scenarios produced **4 FAIL / 1 PASS**, including a
previous-boot control; their test bodies remain identical after rustfmt. The baseline
adapter followed original load → prune → persist logic; original code ignored namespace
inputs. One failing scenario establishes v1 migration admission policy; the other three
cover namespace/procfs isolation.

Tests use real temporary files, production transaction/acquire/release/recovery and the
atomic writer. Process/sysctl/namespace I/O is replaced. Coverage includes independent
original values, no foreign PID probes, final-group cleanup, incompatible PID/time
contexts, failed/malformed observations, migration, unknown versions, corrupt foreign
groups, write size limits, failed acquisition and restoration followed by retry.

**1315 host unit + 52 editor/policy + 7 examples + 12 server INI = 1386 Rust tests PASS.**
All nine matrix commands PASS: host unit, config integration, Linux all-targets Clippy,
client-only, server-only, minimal FFI, no-roaming, no-features and rustfmt. The existing
`chunks_exact_to_as_chunks` exception remains; no new warning headlines.
One full run encountered Windows 10013 (PermissionDenied) binding a loopback port
in an existing DNS test. Its isolated retry and the next full run passed without DNS
code changes. The failed log is retained; fixture instability is not claimed fixed.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/sysctl-namespace-audit-20260923.

## Limits and next work

Actual namespaces/sysctls, cross-process flock, SIGKILL/reboot and crash durability
were not executed. Windows filesystem tests and Linux cross-compilation do not replace
E2E. Accessible `NStgid` and net/pid namespace metadata are required; unsupported/restricted
procfs is rejected. Minimal kernels/OpenWrt without these capabilities need validation.
Consistent procfs/sysfs mounts are assumed. Mount substitution and a mismatched sysfs
inventory are not addressed here. Namespace objects are not pinned permanently; inode
reuse after namespace destruction needs a separate solution. The current key is not an
eternal identifier. Foreign stale groups are not automatically collected.

Next: incomplete /proc during TUN-owner discovery, durable namespace identity, file trust/
lock deadlines, DNS/carrier globals, crash recovery and Q14-F027 workers/FD. Native
certification and a new benchmark were not run. Plan: 37 sections, 19 IN_PROGRESS,
18 TODO, 0 full PASS; stage 00 is complete.

Follow-up: [Q25-F054–F055](AUDIT-Q25-TUN-ADMISSION.md) removes partial procfs holder
discovery and destructive recovery; the first queue is created exclusively.
Attach/teardown identity and Linux runtime remain open.
