# Q25: HTTP/2 workers and client-generation shutdown

Date: 23 September 2026. Baseline commit: `e4605d2e`.
Sections 22–25: **IN_PROGRESS**; the full audit remains open.

## Finding

**Q25-F015, P2 — joining outer TCP tasks did not wait for nested H2 transport release.**
The HTTP/2 carrier held AbortHandles for its bridge and connection driver. Carrier Drop
requested cancellation, but the client-generation group owned only outer TCP tasks. Their
finish could return while the driver was still destroying its outer stream. Normal DNS/TUN
cleanup could start earlier. The primary H2 driver was created before the TCP-tunnel group,
so registering workers only after the data loop started would not cover this boundary.

A reproducer runs real H2 over duplex I/O and delays the outer-I/O destructor. It confirmed
parent-group completion before that destructor finished. This verifies ownership ordering,
not a permanent leak, out-of-tunnel traffic or OS failure. Previous tests verified eventual
release after scheduler progress.

## Fix

Linux CLI and the common native runner create TaskGroup before connecting. Primary,
additional and migrating H2 carriers receive a weak Spawner and register their driver/bridge
through connect_owned. The same group then owns TCP readers/writers, producers and Linux
path workers. Individual AbortHandles preserve cancellation of one carrier without stopping
others; the generation retains joining responsibility. A closed owner rejects new tasks.

Normal teardown, including management-event errors, finishes the group before DNS/TUN
cleanup. Early connect/handshake errors pass through a final join before the Linux TCP
attempt returns. In the native runner, the outer owner survives run_attempt cancellation and
joins TCP tasks before finish_generation, including an H2 response wait before TUN startup.

TaskScope closes admission and requests abort before destroying the cancelled future and
its network guards. The outer TaskGroup retains handles for async joining. This preserves
cancellation ordering when moving the owner outward; Drop never synchronously waits for
async tasks. Cancelling finish preserves handles and permits retry.

Shared code lives in `qeli/src/transport_core/tasks.rs` and
`qeli/src/protocol/h2_carrier.rs`; no separate client H2 pumps were added. Clean half-close,
reverse replies, END_STREAM, batching and flow control remain intact. Server accept and
public standalone connect retain their previous cancellation contract. The one-second
flush for a rejected server request is unchanged. INI, wire format and ABI 1.16 are unchanged;
release native libraries were not rebuilt.

## Validation

Eight new H2 tests cover: delayed I/O destruction with cancelled/retried joining; cancelling
connect while the response is withheld; request-build failure; a closed owner; dropping the
owner while a carrier survives; half-close with a reply; a blocked bridge with a zero H2
window; and cancelling one carrier while another in the same group remains active. A ninth
test checks admission closes before attempt network guards are destroyed.

The join regression was also run against the original h2_carrier from `e4605d2e`. A test-only
connect_owned signature adapter delegates to the previous connect without task registration.
The test fails on early finish. It passes with the fix. New fixtures use in-memory I/O and
change no drivers or networking. The existing H2/REALITY round-trip passes as well, but uses
a test duplex rather than a real TLS/TCP session with a server.

**885 host unit + 52 editor/policy + 7 examples + 12 server INI = 956 Rust tests PASS.**
Linux all-targets Clippy, client-only, client without roaming, server-only, minimal FFI,
compatibility without features and rustfmt pass. Existing diagnostics remain: 23 server-only
warnings, terminal_sender without roaming and an informational MSVC linker message. The
compatibility check reports 33 dead-code warnings in unchanged protocol/UDP modules. The
Clippy chunks_exact_to_as_chunks exception concerns unchanged ndp_proxy. Nine documentation
checks and diff checks pass. Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/h2-task-audit-20260923.

Linux validation is cross-compilation. Linux runtime, real TUN/firewall/DNS, platform apps,
SSH/systemd/Actions and new benchmarks were not run.

## Remaining work

Dropping the entire owner/runtime still cannot guarantee async joining; Drop requests
cancellation. Synchronous rollback of a partially applied network plan may run in a local
guard before the final outer join on an early setup error. This change does not validate
all platform ACK/rollback behavior or UI-state publication. UDP retains its own group;
its forced cancellation is not fixed by this pass.

Next: server-profile and standalone H2 task ownership, system-command deadlines, platform
fault injection and fresh native builds with validation on real devices.

Follow-up on 23 September: [Q14-F022/F023](AUDIT-Q14-H2-TASKS.md) adds profile joining
for server H2 drivers/bridges and rejection flushes, retaining pre-auth admission until
a rejected connection is released. Standalone API behavior and other limits remain.
