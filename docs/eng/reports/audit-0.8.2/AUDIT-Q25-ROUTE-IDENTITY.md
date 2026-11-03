# Q25: original TUN and namespace during route cleanup

Date: 23 September 2026. Baseline: `bac06814`.
Q25-F063–F064 are fixed within the limits below. Sections 21/22/25 remain **IN_PROGRESS**.

## Findings

**Q25-F063, P2 — a saved name could authorize cleanup of a replacement TUN.**
After external rename/delete, a new device could reuse the configured name. Cleanup first
matched journal selectors containing that name, then ran a broad IPv4/IPv6 `route flush dev`.
Neither the route journal nor retaining the original fd proved the current meaning of the
name. Exact deletion could match an identical replacement route; flush also affected routes
absent from the journal. TCP, UDP, TunGuard Drop and partial setup rollback shared this path.

**Q25-F064, P2 — route owners did not verify the cleanup thread's namespace.**
The journal tracked generation/name/process-local id, while commands used the current
network namespace. Calling an owner from another namespace could delete a physical bypass
with identical selectors. Orphan recovery could also accept absence in the wrong namespace
as proof that old state was gone. The ordinary client does not perform such a transition;
the trigger requires an external/in-process thread namespace change.

## Fix

RouteOwner retains an open `/proc/thread-self/ns/net`, including unresolved orphan
reservations. The held descriptor's device/inode must match the calling thread's current
namespace. The open descriptor keeps the namespace object alive, preventing its identity
from being reused while that reservation exists.
[Linux namespace contract](https://man7.org/linux/man-pages/man7/namespaces.7.html).
Setup/roaming operation admission and orphan recovery also verify the namespace.

A managed TUN owner binds once to the original device index before address/up and other
plan mutations. Permitted `TUNGETIFF`/`TUNGETDEVNETNS`, CAP_NET_ADMIN and procfs namespace
metadata are required even with `dns=off`. An actual/configured name mismatch refuses setup
before those mutations. Rebinding is forbidden. `dev_attach` continues to skip managed
route installation and cleanup.

Every production cleanup caller supplies the original TunInterface. The common algorithm
checks namespace before every command, including queries that can release a journal entry.
TUN records and both family flushes also observe the original fd: its device must retain
the original namespace, name and index. These observations reuse the shared TUN backend.
[Linux TUN ioctl](https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c).

Rename, detached fd, changed index or unavailable metadata/ioctl refuse the command.
Ownership/pending records and errors survive; a new generation cannot adopt leftovers.
This is a conservative refusal: absence under the saved name does not release a reservation.
Restored evidence permits retry by the live guard. If the guard is lost after an unconfirmed
flush, the name stays reserved until process exit. No new on-disk route journal is created.

Physical bypass/blackhole cleanup remains independent when namespace is proven; a lost
TUN does not abort the entire loop. Borrowed physical routes gain no deletion authority.
Pending TUN records cannot be released from an unverified replacement's snapshot either.
Existing selectors, before/after queries and lost-completion handling remain intact.

## Verification

**8 new regressions: FAIL on original logic → PASS after the fix.**
The baseline used a thin test adapter invoking original cleanup while ignoring identity
callbacks that did not exist yet. Command models and the eight scenario bodies are shared;
no real host network commands run. Five additional controls cover namespace recheck before
physical delete, lost postcheck, independent physical pending release, orphan name retention
and borrowed-route preservation.

**1388 host unit + 52 editor/policy + 7 examples + 12 server INI = 1459 Rust tests PASS.**
The eight baseline regressions are included in the 13 new host tests, not counted twice.
The single ignored host fixture is the DNS-lock child explicitly run by its parent test.
All nine matrix commands pass, with no new warning headlines or Clippy exceptions.
Linux checks are cross-compilation, not runtime verification.

Three new ignored native tests use actual TUN/ip in a fresh namespace on a disposable
thread: rename/name replacement with independent physical cleanup, delete/identical
replacement route, and namespace transition/identical physical selectors with retry after
return. No network mutation occurs before successful unshare. They were **compiled only**:

```bash
cargo test --manifest-path qeli/Cargo.toml --lib identity_linux_tests -- --ignored
```

Requires Linux, CAP_SYS_ADMIN/CAP_NET_ADMIN, `/dev/net/tun` and `ip`.
Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/route-identity-audit-20260923.
RU/EN manuals and the docs gate are updated.

## Remaining limits

Fd observations and iproute2 commands are not atomic. Privileged external rename/delete,
move or name/index reuse after the last check can still race. Removing this boundary needs
a separate netlink/route-ownership design; replacing a name with an ifindex alone is not
kernel CAS. Physical interface identity still relies on previous selectors rather than
per-uplink descriptor/namespace leases. Broad flush of a proven owned TUN remains.

Setup and roaming verify namespace at operation admission, but do not yet verify the TUN
before every mutation. Address/up/gateway/firewall need a separate pass. Parser/backend
name consistency is currently enforced by refusing a mismatch, not by supporting templates
or rename. An unresolved owner's namespace FD retains resources until reservation/process
release; the registry has no durable crash recovery. Route cleanup errors remain part of
the existing kill-switch retention policy.

Next: setup/roaming and other name-based commands, resolver service/bus identity, sysfs
attach, physical uplinks, overall deadlines, Q14-F027 and Linux E2E. Native certification
and a new benchmark were not run. Plan: 37 sections, 19 IN_PROGRESS, 18 TODO, no full PASS.

Follow-up: [Q25-F065–F066](AUDIT-Q25-SETUP-IDENTITY.md) adds checks to route setup/roaming
and before direct managed MAC/address/up; gateway/firewall remain a separate task.

Follow-up: [Q25-F099](AUDIT-Q25-ROUTE-ATTRIBUTES.md) separates borrowing from ownership and checks implicit route attributes; the earlier comparison of supplied fields no longer grants authority to delete a changed physical route.

D04 follow-up: [Q25-F100](AUDIT-Q25-ROUTE-JOURNAL.md) adds durable physical route ownership and crash recovery. The process-local contract described here is extended with intent/confirmed state; uncertain operations still grant no delete authority.
