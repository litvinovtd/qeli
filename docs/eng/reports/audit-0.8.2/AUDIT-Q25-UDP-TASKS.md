# Q25: UDP task ownership and path-rollback ordering

Date: 23 September 2026. Baseline commit: `2fb468f4`. Sections 22–25: **IN_PROGRESS**.

## Findings

**Q25-F012, P1 — early UDP exit left the receive task without an owner.**
The active receive pump, candidate connection and old-path receivers held separate
JoinHandles. A core.management_event error returned through `?`, bypassing normal task
joining and explicit cleanup. Dropping a JoinHandle does not cancel its task: an idle pump
could keep waiting with its socket and buffers while the outer loop cleaned up or recreated
the network. Normal teardown already aborted and awaited the active and final draining
pumps; the defect concerned bypass exits and intermediate ownership.

One shared Rust TaskGroup now owns active UDP receive, candidate-connect, candidate receive,
draining receive and the Linux path monitor including its blocking jobs. Management-event
errors are preserved and follow the normal teardown sequence. Typed terminal kicks and
combined cleanup errors remain intact. Owner Drop closes admission and requests cancellation;
normal finish joins every accepted task. This is the common Linux/Android/Windows/macOS/iOS
UDP loop, rather than a separate Linux implementation.

**Q25-F013, P1 — path rollback could precede candidate-connect termination.**
Shutdown only aborted candidate-connect, then immediately queried prepared_candidate and
started ABORT_PATH. A running synchronous section could still publish a path-binding result.
Receiving a connect result also immediately discarded its handle. Expired draining pumps and
rejected candidates were aborted without waiting for resource release. Abort requests
cancellation; it does not acknowledge completion.

The group now finishes before querying and rolling back the platform candidate. Each path
has a TaskHandle that moves during candidate → active → draining transfer. Dropping it
cancels its task, while the group JoinSet retains responsibility for joining. TaskHandle
waiting completes after its captured future and resources are destroyed, including for a
never-polled or panicked task. Cancelling the wait keeps ownership and permits retry.
Candidate rejection/expiry and draining replacement/expiry branches now wait for their
receive pump. After a candidate-connect result arrives, its task also finishes before result
processing. Cancelling another candidate preserves the active receive path; commit/epoch
protocol behavior and the drain window are retained.

This extends transport_core::tasks from the TCP pass. UdpClientLiveCandidate's separate Drop
and raw UDP pump JoinHandles/spawning are removed; shared TaskHandle owns cancellation.
The previous separate UDP Linux-monitor group is folded into the connection group. INI,
wire format and ABI 1.16 are unchanged; release native libraries were not rebuilt.

## Validation

Five new owner tests cover never-polled/rejected work, waiting for a delayed resource Drop,
cancelling a path wait and dropping its TaskHandle, normal completion/panic, and dropping
the generation while a path handle survives. Four loopback tests run the real UDP receive
pump: full output queue, candidate cancellation while active receive survives, candidate →
active transfer with old-path draining/retirement, and early owner Drop. They check epoch,
delivery, channel closure and socket-reference release. Tests use only 127.0.0.1 and change
no system routes or TUN. The rollback-order test models synchronous work; it is not live
ABORT_PATH validation.

**869 host unit + 52 editor/policy + 7 examples + 12 server INI = 940 Rust tests PASS.**
Linux all-targets Clippy, client-only, client without roaming, server-only, minimal FFI and
rustfmt pass. The existing chunks_exact_to_as_chunks exception in unchanged ndp_proxy and
23 server-only transport warnings remain. Nine documentation checks and diff checks pass.
Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/udp-task-audit-20260923.

Linux validation is cross-compilation. Linux runtime, real TUN/firewall/DNS, physical network
handover, native apps on devices, SSH/systemd/Actions and new benchmarks were not run.

## Remaining work

Forced cancellation of the entire future cannot guarantee async joining or rollback; Drop
only requests cancellation. Abort cannot interrupt running blocking work. Deadlines for
ip/iptables/resolvectl, platform ACK rollback, nested H2/transport workers and TUN-shutdown
cancellation remain separate checks. Release requires fresh native builds and real platform
scenarios. The full audit remains open.

Follow-up on 23 September: TUN/Wintun worker-shutdown cancellation was validated and fixed
in [Q25-F014](AUDIT-Q25-TUN-WORKERS.md). The other limits above remain.
