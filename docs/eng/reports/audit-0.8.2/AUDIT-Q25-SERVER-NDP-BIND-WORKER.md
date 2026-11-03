# Q25-F118: NDP proxy bind off the async executor

Date: 25 September 2026. Baseline commit: `f52aa083`. D05/D09/D10: partial closure.

## Confirmed problem

`run_profile_generation` started the NDP proxy synchronously. Inspecting the
network interface, opening and binding an `AF_PACKET` socket and joining its
socket-local multicast membership ran on the async executor. A delayed kernel
call could stall other profiles. Moving the former `NdpProxy::bind` wholesale
to a worker would be incorrect: it registered `tokio::io::unix::AsyncFd`, which
belongs to the original runtime.

## Change

`BoundNdpProxy` creates and binds a plain nonblocking `OwnedFd` on a joined
worker in the original network namespace. Only after explicit adoption does
`NdpProxy::register` create `AsyncFd` in the profile's Tokio runtime. A
cancelled waiter closes an unadopted fd on the worker before releasing outer
profile resources. `off`/`auto`/`required` behavior, interface selection,
errors and the INI contract are preserved; registration failure remains
optional for `auto` and fatal for `required`. The privileged namespace test
now covers the complete async start path.

## Validation and limits

Lab `.11`: 5/5 NDP unit, 1/1 privileged namespace test, 8/8 TCP/UDP × IPv6
`off`/`manual`/`route`/`nat66` lifecycle and 22/22
recovery/ownership/SIGKILL checks PASS in private NET/mount/PID namespaces.
Both `manual` worker logs confirm the active responder on `wan0`.
Linux Clippy `--lib --bins -D warnings`, rustfmt and `git diff --check` PASS.
Full `--all-targets` was not run in the partial source snapshot: integration
`include_str!` needs `release/` fixtures absent from that snapshot; the changed
library and binary were checked. Source was verified before and after execution
(362 files). Binary SHA256:
`d2ddf836a01b4dd1b51df62a11559ad4d27b6f688651326f6899a4fc0706e039`.
Logs and manifest:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-ndp-bind-phase/`.

A whole-setup deadline, arbitrary kernel/fs I/O and forced Drop waiting for
workers remain open. D05 stays IN_PROGRESS.
