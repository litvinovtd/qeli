# Q25: attach without creating a TUN and preserve device framing

Date: 23 September 2026. Baseline: `e93d165c`.
Q25-F057–F058 are fixed within the stated boundaries; sections 14/21/25 remain **IN_PROGRESS**.

## Confirmed findings

**Q25-F057, P2 — attach could create a device after the original disappeared.**
An external TUN could disappear after the existence check and `tun_flags` read.
Nonexclusive `TUNSETIFF` then created a new non-persistent interface, despite
`dev_attach` promising to borrow one. The same transition was possible when opening
a later multiqueue descriptor after another manager removed the original device.

The shared opening sequence now calls `TUNSETIFINDEX` with index 1 before every
nonexclusive `TUNSETIFF`. That ioctl supplies an index only to the creation branch;
it does not change an existing TUN's index. Linux reserves index 1 for loopback:
see [flow.h](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/net/flow.h)
and its assertion in [loopback_net_init](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/loopback.c).
The ioctl branches are in [tun.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/tun.c);
[register_netdevice/dev_index_reserve](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/core/dev.c)
rejects registration at an occupied index.

Consequently an absent name cannot be registered as a replacement TUN by this call.
The open fd retains its network namespace; the loopback name is unused, so renaming
it does not bypass the guard. This deliberately combines existing ioctls; there is
no separate attach-only kernel flag.

A failed `TUNSETIFINDEX` stops before `TUNSETIFF`, with no unguarded fallback.
Exclusive first-queue creation does not need this step. `dev_attach` and second/later
queues now require supported and permitted `TUNSETIFINDEX`. Unsupported kernels or
ioctl restrictions cause an explicit refusal. The ioctl number uses libc's architecture
specific constant.

**Q25-F058, P2 — attach accepted incompatible framing and reset external features.**
The helper checked `IFF_NO_PI` but not `IFF_VNET_HDR`. A device using virtio headers
could reach the ordinary IP/Ethernet packet path. The driver can also rewrite features
on the first queue attachment: the previous helper requested only type, NO_PI and MQ,
losing ONE_QUEUE/NAPI/NAPI_FRAGS.

Validation and parsing moved from the platform ioctl wrapper into shared testable policy.
Virtio headers and unknown bits are refused before opening a descriptor. Supported
ONE_QUEUE/NAPI/NAPI_FRAGS are preserved along with type, NO_PI and MQ. Read-only PERSIST
is excluded from requested flags; no persistence-changing ioctl is called. Matching
device type and no packet-information header remain required. INI, API and FFI ABI
are unchanged.

## Validation

**18 new host tests** and one existing parser test now also executed on Windows.
The previous-sequence adapter produced **6 FAIL / 4 PASS**. The six scenario bodies
are unchanged after rustfmt. Four cover disappearance during attach/later-queue opening,
VNET_HDR and lost features; two establish the new refusal contracts for a failed guard
and unknown flags. These model kernel contracts and policy, not old Linux ioctl
execution on Windows. The model does not check the exact Linux errno.

**1354 host unit + 52 editor/policy + 7 examples + 12 server INI = 1425 Rust tests PASS.**
Nine primary matrix commands and additional Linux no-features test compilation PASS.
The existing `chunks_exact_to_as_chunks` exception remains; no new warning headlines
in the primary matrix.

Three new Linux-only tests use actual ioctls on a disposable OS thread after successful
`unshare(CLONE_NEWNET)`. They check refusal to create during attach, borrowing an existing
device, and multiqueue/last-fd release. The first case establishes successful control
TUN creation so missing `/dev/net/tun` or privileges cannot produce a vacuous PASS.
These tests were **compiled, not executed**, and are ignored by default. On a prepared
Linux host with CAP_SYS_ADMIN/CAP_NET_ADMIN and `/dev/net/tun`:

```bash
cargo test --manifest-path qeli/Cargo.toml --lib tun::iface::linux_tests -- --ignored
```

The tests leave the original network namespace unchanged; failed isolation is an error,
not a skip. They do not exercise the entire public sysfs-based attach path.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/tun-attach-audit-20260923.

## Limits and next work

Preventing registration of an absent device does not establish the identity of an
existing replacement with the same name. Replacement/renaming between observations,
external feature changes and sysfs mounted for another namespace remain open.
The external manager must keep the device and its framing stable during attachment.

Cleanup review found remaining name-based operations: client guards and server teardown
call `TunInterface::delete` via `ip tuntap del`. It reopens the name without proving
the original device's identity. Independent route flushing and DNS cleanup also need
review. This pass does not change them. Next: descriptor ownership and device release,
binding route/DNS cleanup to its lifetime, consistent parser/backend naming, then
the remaining namespace/journal/deadline items.

Full Linux E2E, old/minimal kernels, OpenWrt, native certification and a new benchmark
were not run. The 37-section plan remains 19 IN_PROGRESS, 18 TODO, no complete PASS.

Follow-up: [Q25-F059–F060](AUDIT-Q25-TUN-LIFETIME.md) removes name-based TUN deletion and retains original descriptors through cleanup. DNS/route identity during external replacement and worker timeout remain open.
