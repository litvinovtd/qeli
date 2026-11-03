# Q25 — pinning namespaces during sysctl transactions

<!-- normative-sync: audit-q25-namespace-pin-v1 -->

Date: 24 September 2026. Base: `34b3af41`. Partial D02 closure in the
[debt register](../../plans/AUDIT-DEBT.md).

## Q25-F082, P2 — saved numbers did not keep the original namespace alive

The guard compared network, PID and time namespace device/inode numbers before
and after I/O, but retained strings alone. Once the last namespace reference is
gone, its number can be reused; equal numbers no longer prove the original
object. Identity checks themselves did not retain it.

`Context` now opens `/proc/thread-self/ns/{net,pid,time}` and retains the file
descriptors. Identity comes from metadata on that same open fd. Capture happens
before either local/flock wait; descriptors survive the transaction, including
persistence and failures. Each subsequent check also obtains identity from an
open fd, releasing its temporary handles after comparison. A missing time
namespace remains supported; other errors refuse the operation.

An open namespace fd keeps the object alive; CLOEXEC prevents its inheritance
by executed commands. This is the standard
[namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html) contract.
Production code does not call setns, move the thread back, or revive a failed
transaction. INI, ABI and journal v2 are unchanged; no new kernel ioctl or socket
option is required.

## Validation

A new privileged Linux regression creates a namespace in a disposable thread,
opens the production pin, then leaves as its last member. The retained fd allows
re-entering the same object; a new namespace has a different identity. It checks
CLOEXEC and EBADF after Drop. The test runs inside isolated namespaces, serially
with other privileged tests. It verifies fd ownership; actual forced reuse of a
namespace inode was not reproduced.

All 9 host/feature/cross/lint commands PASS: **1458 host unit + 71 config integration**.
Linux: **1922 ordinary + 29 privileged + 8 worker lifecycle E2E PASS**.
Worker SHA256: `def5577ee4174e05b3ddcd1f40bb2b865580690f56797ba7d08a0e93036bbfa9`.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/namespace-pin-phase/`,
`namespace-pin-final.log`, `lifecycle-namespace-pin/`.

## Remaining boundaries

Descriptors retain identity only during a live transaction. Between transactions
and after a crash, journal v2 still holds only device/inode numbers. Durable
namespace generation and original-interface generation remain open in D02.
Neither an interface name nor ifindex proves continuous lifetime, and a procfs
inode is not a durable interface identifier. This phase does not claim safe
automatic recovery after arbitrary rename/delete/recreate operations.

[Internal I/O guard](AUDIT-Q25-SYSCTL-CONTEXT-IO.md) ·
[State directory](AUDIT-Q25-STATE-DIRECTORY.md)

Continuation: [Q25-F083 — v3 and original sysctl fd](AUDIT-Q25-SYSCTL-TARGET.md). Historical limitations above describe this report’s snapshot; name disappearance no longer permits forgetting the original.
