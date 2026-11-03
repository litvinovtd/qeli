# Q25: retain original TUN descriptors through cleanup

Date: 23 September 2026. Baseline: `cae97262`.
Q25-F059–F060 are fixed within the boundaries below; sections 14/21/25 remain **IN_PROGRESS**.

## Confirmed findings

**Q25-F059, P2 — teardown reopened an interface name without device ownership.**
Client normal teardown, error/NetworkPlan guards and server profile teardown used
`TunInterface::delete`. Its four mode/queue combinations ran `ip tuntap del`.
That command attaches by name and clears persistence; it is not a deletion tied to
Qeli's original descriptor. A same-name persistent replacement could lose persistence.
With an absent name, the unguarded open could even create a temporary device.
See the actual ioctl sequence in [iproute2](https://raw.githubusercontent.com/iproute2/iproute2/v6.12.0/ip/iptuntap.c).

The helper and all callers are removed. Qeli-created devices are non-persistent:
closing the last attached descriptor releases them. An external owner in attach mode
retains its own descriptors/persistence. Qeli no longer reopens a name or changes
persistence during teardown. Linux's last-queue release and detached-fd behavior are
implemented in [tun.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/tun.c).

**Q25-F060, P2 — original descriptors did not cover host cleanup lifetime.**
TCP and UDP graceful teardown closed `tunnel_tun` before route cleanup and a possible
Drop retry. The original device could already be gone when route flushing started.
On the server, originals were dropped after duplication; setup failure or an early
worker exit could release all descriptors before the outer guard cleaned host state.

The client guard now owns the original `TunInterface`. It keeps it through DNS/route
cleanup, retries and early return. `NetworkPlanApplyGuard` borrows that interface,
so Rust enforces rollback before release; after commit, ownership moves to `TunGuard`.
The server guard owns all originals during setup, then retains one after worker-fd
duplication through NAT cleanup and worker stop. This costs one retained fd per profile,
not one per queue; it does not open an additional queue.
They close when the guard fields drop, after its cleanup body.

Physical bypass-route cleanup still runs explicitly. DNS/route/forwarding errors remain
sticky; their later successful retry does not clear the failure or release the kill-switch.
The obsolete TUN-delete failure category is removed: the bounded client record now has
three categories. Server queue timeout/panic reporting remains. RAII close is not a
new verification that every other holder has exited. No INI, API or FFI ABI changes.

## Validation

A host harness extracts the actual client guard/rollback bodies and server resource
teardown prefix from baseline and fixed source, substituting fake descriptors and
DNS/route/NAT/thread adapters. The 12 scenario bodies are shared: **baseline 7 FAIL /
5 PASS; fixed 12 PASS**. They cover graceful cleanup, retry, error exit, attach,
rollback/handoff, early server setup failure and reported queue timeout.
The harness adapts constructors to old/new ownership and models the caller's descriptor
release order. It does not execute Linux ioctls, worker scheduling or async registry
fallback, and the seven failures represent scenarios of two findings, not seven bugs.
Evidence and reproducible harness: C:/Users/litvi/OneDrive/Documents/qeli/tun-lifetime-audit-20260923.

**1354 host unit + 52 editor/policy + 7 examples + 12 server INI = 1425 Rust tests PASS**,
in addition to the 12 harness scenarios. All nine matrix commands PASS, including
Linux all-target Clippy, client/server feature builds and formatting. An additional
Linux no-features test compile PASS. Existing warning/Clippy allowances are unchanged.

Three added Linux tests cover renamed and externally deleted originals with persistent
same-name replacements, and duplicate worker-fd release before the original closes.
They join the three existing real-ioctl tests in `qeli/src/tun/attach_linux_tests.rs`.
All six are ignored by default and **compiled, not executed here**. Each mutating test
first enters a fresh network namespace on a disposable OS thread; failed isolation is
an error. Run on Linux with CAP_SYS_ADMIN/CAP_NET_ADMIN, `/dev/net/tun` and `ip`:

```bash
cargo test --manifest-path qeli/Cargo.toml --lib tun::iface::linux_tests -- --ignored
```

## Limits and next work

Retaining descriptors prevents Qeli's own last close from freeing the name before
cleanup. It does not lock out a privileged external rename/delete or prove that
name-based DNS/route commands still target the original. DNS markers still store names;
route flushing, marker identity/recovery and sysfs namespace provenance need further work.
Client parser/backend naming consistency also remains open.

An external holder or changed persistence can keep a device alive. A server worker that
misses the three-second stop deadline still reports an error and may retain its fd;
Q14-F027 remains open. The new lifetime does not promise disappearance in those cases.
Actual Linux E2E, old kernels/OpenWrt, native certification and a new benchmark were not
run. The 37-section plan remains 19 IN_PROGRESS, 18 TODO, no complete PASS.

Follow-up: [Q25-F061–F062](AUDIT-Q25-DNS-LEASES.md) adds generation-owned DNS and descriptor/namespace observations; route identity and non-atomic resolver races remain open.
