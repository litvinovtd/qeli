# Q25: safe Linux TUN/TAP admission and creation

Date: 23 September 2026. Baseline: `a380ac77`.
Q25-F054–F056 are fixed within the stated boundaries; sections 14/21/25 remain **IN_PROGRESS**.

## Confirmed findings

**Q25-F054, P2 — incomplete observation could authorize deletion of an occupied TUN.**
`tun_fd_holders` skipped procfs, fd and fdinfo read failures. When only the current
PID appeared, `reclaim_stale_tun` treated the device as its own leftover and requested
deletion. A hidden foreign holder or borrowed descriptor invalidates that conclusion.
`Path::exists` also collapsed observation errors into interface absence.

Procfs holder discovery and destructive recovery were removed. The client queries
the calling thread's network namespace with `if_nametoindex`: only `ENODEV` means
absence; other errors stop setup.
See the [if_nametoindex(3) contract](https://man7.org/linux/man-pages/man3/if_indextoname.3.html).

An occupied name now triggers passive waiting: at most 120 pauses of 50 ms and repeated
queries, approximately six seconds plus query time. This applies to any interface type.
Disappearance permits a creation attempt; a changed observed ifindex, query failure or
timeout refuses setup. This path cannot delete a device, detach queues or change
persistence. An owned non-persistent TUN must disappear when the previous connection's
last descriptors close. A leaked fd remains a visible failure rather than permission
to take over a device. `dev_attach=true` requires an existing interface and does not
wait for its release.

**Q25-F055, P2 — creation could attach to somebody else's device.**
A foreign TUN could appear between the preliminary lookup and `TUNSETIFF`. Without
the exclusive flag the ioctl can attach to an existing device. Multiqueue also
repeated the original requested name: a `tun%d` template could yield different
devices for different queues.

The shared opening policy sets `IFF_TUN_EXCL` for single TUN/TAP creation and the
first multiqueue open. Later queues omit that flag and use the actual name returned
by the first queue; `IFF_MULTI_QUEUE` and `IFF_NO_PI` are retained. Any queue failure
drops previously opened descriptors through RAII.
Linux [tun.c v6.12](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/tun.c)
returns `EBUSY` for an occupied name with `IFF_TUN_EXCL` under the rtnl lock; the flag
is defined in [if_tun.h](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/if_tun.h).
A preliminary absence observation therefore does not confer ownership.

Client and server share the Linux backend. The server's preliminary lookup also
queries the current network namespace instead of sysfs; it immediately refuses an
occupied name. Client reservations still coordinate participating clients only and
do not replace exclusive creation. No INI keys, configuration formats or FFI ABI changed.

**Q25-F056, P3 — Linux example tests did not compile without the server feature.**
Two references to `qeli::server::validate_profiles` were gated only on Linux, although
the module requires `feature = "server"`. An additional Linux `cargo check --tests --lib`
with `--no-default-features` reproduced two E0433 errors. Conditions now match module
availability: shared INI checks remain, and server runtime validation compiles only
with the server enabled. The same compile-check now passes. Linux tests were not run.

## Validation and evidence

Added **20 host tests**: 11 admission/wait tests and 9 queue-opening tests.
Adapters of the previous logic produced **7 FAIL / 4 PASS**: partial holder discovery,
initial/wait observation failures, changed ifindex, single and multiqueue creation over
a foreign device, and repeated use of the original name template.
The seven regression bodies are unchanged after rustfmt.

These reproduce control flow and the kernel-open contract with models, not original
Linux procfs/ioctl execution on Windows. After the fix, the same tests call production
policy; I/O, waiting and the kernel are substituted. The ioctl model uses
`AlreadyExists` for refusal; host tests do not check the exact Linux errno.
Additional cases cover release at the last poll, bounded timeout, attach observation
failure, exclusivity only on the first queue, retained external ownership and
rollback after partial queue creation.

**1335 host unit + 52 editor/policy + 7 examples + 12 server INI = 1406 Rust tests PASS.**
Nine matrix commands PASS: host unit, config integration, Linux all-targets Clippy,
client-only, server-only, minimal FFI, no-roaming, no-features and rustfmt.
The existing `chunks_exact_to_as_chunks` exception is retained.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/tun-admission-audit-20260923.

## Limits and next work

Actual TUN/TAP, ioctl, netns, concurrent processes and reconnect were not executed.
Linux E2E must cover creation races, persistent/non-persistent devices, single/multiqueue,
delayed reader release, failed lookup, server/client conflicts and unchanged external
devices after refusal.

`dev_attach` still checks the device before a nonexclusive ioctl: disappearance
between those actions remains a separate race. Identity checks before cleanup and
deletion by name are also outside this fix. An ifindex is not an eternal identity;
waiting never gains deletion authority even when it stays the same.
First-queue exclusivity does not certify forced deletion or renaming by an external
privileged process between queue opens. Parser/backend name templates and truncation,
blocking setup waits, namespace inode reuse, journal file trust, deadlines and
crash recovery remain on the plan. No new benchmark or native certification was run;
full section PASS is not claimed.

Follow-up: [Q25-F057–F058](AUDIT-Q25-TUN-ATTACH.md) prevents new-device registration
during attach and preserves supported features; VNET_HDR is refused. Existing
replacement identity, sysfs provenance and name-based cleanup remain open.
