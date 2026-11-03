# Q25: DNS ownership belongs to a connection generation

Date: 23 September 2026. Baseline: `e9193f57`.
Q25-F061–F062 are fixed within the stated scope. Sections 14/21/25 remain **IN_PROGRESS**.

## Confirmed findings and changes

**Q25-F061, P2 — cleanup could revert DNS that this plan never installed.**
TCP/UDP and the fallback guard called `restore_dns_for(name)` regardless of `dns=off`,
an empty DNS plan or whether marker acquisition had succeeded. Setup marked DNS as
started before attempting it. A same-name marker from another owner therefore granted
cleanup authority to a connection that had never changed DNS. Plain marker writes also
overwrote the previous owner without interprocess exclusion.

The setup guard now receives an optional DNS lease before the first resolver mutation.
Only that lease transfers into the established TUN guard. Disabled/empty DNS plans and
failed ownership acquisition leave it absent, so their teardown performs no per-link
DNS operation. A partial apply remains owned and is reverted by the setup guard.
Successful cleanup retires the lease once; a later route-error retry cannot use a newly
appearing foreign marker. DNS errors still reach the sticky failure report/kill-switch.

New private `dns-link-v1-<boot>-<netns-device>-<netns-inode>-<ifindex>.state` records
contain version, random generation token and link identity. These are internal recovery
records, not user configuration; user configs remain INI. A stable `.lock` sidecar is
held for the lease lifetime. Contention refuses immediately; Qeli neither overwrites an
existing unrecovered marker nor unlinks a live lock. `File::try_lock` provides the
nonblocking lock ([Rust API](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock),
stable since Rust 1.89). Marker reads are limited to 2048 bytes; Linux rejects symlinks,
nonregular files and multiple hard links, and uses nonblocking opens to reject FIFOs.
Cleanup checks the exact record before the command and before retirement.

**Q25-F062, P2 — saved names and sysfs absence did not establish device identity.**
A renamed/deleted TUN could be replaced under its former name. Startup also used
`Path::exists`, dropped directory-entry errors and converted marker read errors to empty
names before attempting recovery. A stale name cannot authorize changing a live resolver.

Each DNS/domain/revert now observes the original queue descriptor via `TUNGETIFF`, checks
its actual network namespace with `TUNGETDEVNETNS`, and compares boot/namespace/ifindex
with the lease. Namespace checks bracket name/index observation. A normal rename keeps
the numeric target; a detached original causes marker retirement without a revert on
its replacement. Changed identity, inaccessible metadata or ioctl failure refuses the
mutation and preserves the record. The ioctl semantics are in
[Linux tun.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/tun.c).
`resolvectl` accepts the numeric link and calls its per-link API by index:
[systemd source](https://raw.githubusercontent.com/systemd/systemd/v256/src/resolve/resolvectl.c).

Startup never calls `resolvectl revert` from a durable marker alone. It skips active locks
and foreign boot/namespaces, preserves live/reused indices, and retires only markers whose
index is confirmed absent in the current scope. Lookup/read/iteration errors are reported;
absence is not inferred from failure. Legacy resolver-file backup recovery remains separate.

## Compatibility and operator recovery

Linux managed DNS now requires permitted `TUNGETIFF`/`TUNGETDEVNETNS`, namespace procfs
metadata and boot ID. The namespace ioctl requires CAP_NET_ADMIN in the owning user
namespace. Unsupported/denied observation refuses DNS setup; `dns=off/system` and empty
DNS plans do not acquire a lease or perform these DNS observations.

Old `dns-resolvectl-*` markers have no namespace/generation identity. Startup preserves
and reports them; a colliding legacy marker blocks new DNS takeover. Do not upgrade a
live DNS owner in place or mix old and new owners of the same link. For an orphaned marker,
stop the affected owner, inspect the actual link and `resolvectl status`, restore DNS
through its legitimate network manager (or explicitly revert a verified Qeli-owned link),
then archive/remove only that exact `.state` or legacy marker. Never remove `.lock` while
Qeli runs. A crash on an external persistent link may require this recovery; a crash of
an ordinary non-persistent TUN normally leaves an absent index which startup can retire.
See [manual §6.50](../../manuals/TROUBLESHOOTING.md).

## Validation

24 new portable tests PASS, including a real child process contending for the owner's
lock. The ignored subprocess fixture is invoked by that parent test, not silently omitted.
Two additional Unix-only filesystem tests (FIFO and symlink refusal) compile on Linux.
Three previous unsafe name-marker tests were replaced by lease coverage.

A separate harness extracts the actual client guards, with mocked DNS/route adapters
and constructor/caller adaptations: **baseline 3 FAIL / 3 PASS; fixed 6 PASS**. Failures
cover no DNS plan, failed ownership acquisition and a foreign marker appearing between
successful DNS cleanup and a route-error Drop retry. It is not a Linux resolver E2E test.

**1375 host unit + 52 editor/policy + 7 examples + 12 server INI = 1446 Rust tests PASS.**
All nine primary matrix commands and an extra Linux no-feature test compilation PASS.
Existing warnings/Clippy exceptions remain unchanged. A Linux command-adapter test checks
identity loss between DNS and domain commands. One new isolated native ioctl test rejects
a descriptor from another namespace with the same name/index; two existing tests now
check descriptor identity after rename/delete. The seven ignored native tests and the
Linux-only adapter/filesystem cases are **compiled, not executed here**.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/dns-lease-audit-20260923.
Native ioctl command (Linux, CAP_SYS_ADMIN/CAP_NET_ADMIN, `/dev/net/tun`, `ip`):

```bash
cargo test --manifest-path qeli/Cargo.toml --lib tun::iface::linux_tests -- --ignored
```

## Remaining boundaries

The observations and resolver command are not atomic. A privileged external delete/move
and deliberate ifindex reuse after the final check remain possible. The connected
systemd-resolved service must manage the same namespace; service/bus namespace identity
is not proved here. External managers may also replace DNS on the same live link; Qeli
does not snapshot/restore their previous per-link settings. Locks coordinate this Qeli
implementation, not older clients or arbitrary privileged state-directory writers.

Route cleanup still flushes by configured interface name; it must receive its own identity
review and preserve independent physical bypass cleanup. DNS server address selection,
attach sysfs provenance, parser/backend names, whole-operation deadlines and Q14-F027
remain open. No Linux E2E, native certification or new benchmark. Plan: 37 sections,
19 IN_PROGRESS, 18 TODO, no complete PASS.

Follow-up: [Q25-F063–F064](AUDIT-Q25-ROUTE-IDENTITY.md) adds original-TUN and held-namespace
evidence to route cleanup while preserving independent physical cleanup.
Post-check races and setup/roaming remain open.

Follow-up: [Q25-F094/F095](AUDIT-Q25-RESOLVER-CONTEXT.md) binds the bus/service context and command receiver, validates real resolved and fixes nonstandard DNS ports. Historical results above are unchanged.

Follow-up: [Q25-F096/F097](AUDIT-Q25-DNS-MARKER-STORAGE.md) moves DNS markers to v2 with SO_NETNS_COOKIE and a trusted held directory, testing SIGKILL/restart with real resolved. Counts and the v1 contract above describe the historical snapshot; current operations are in TROUBLESHOOTING §6.50.
