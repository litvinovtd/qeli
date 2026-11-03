# Q25: TCP task ownership and Linux path-monitor shutdown

Date: 23 September 2026. Baseline commit: `9e0c4fd8`. Sections 22–25: **IN_PROGRESS**.

## Findings

**Q25-F010, P1 — TCP tasks could outlive their connection cleanup.**
The shared registry held JoinHandles in a Vec. Shutdown aborted ramp, maintenance and
handover without joining them, then drained and aborted stream handles without joining.
A producer already executing synchronous code could register another stream after the drain;
its registry clone kept those tasks alive. Even tasks accepted before the drain did not
necessarily release sockets, codecs and TUN channels before DNS restoration and TUN removal.
A core.management_event error bypassed normal teardown through `?`. Cancelling the entire
future dropped JoinHandles, which does not itself cancel their tasks.

The shared transport_core::tasks module now separates the TaskGroup owner from a cloneable
Spawner holding a weak reference. The group owns readers/writers, pipeline decryption,
adaptive ramp, maintenance, handover and the Linux path monitor. Spawning and closing use
the same mutex: a closed group rejects a future before spawning it. New spawns reap completed
handles to avoid accumulation during long-lived handovers. Normal finish closes admission,
aborts and joins all accepted tasks before network cleanup. Cancelling the waiter leaves
handles in the group for a subsequent finish; &mut self permits only one waiter. Drop closes
admission and requests cancellation without async joining. Weak references avoid the
producer → registry → producer ownership cycle.

Management-event errors and typed terminal kicks are retained as the result and returned
after the same teardown sequence. This is the common TCP loop for Linux/Android/Windows/
macOS/iOS; INI and ABI are unchanged. The old Vec registry, register_tcp_stream_task and
separate producer handles are removed. Server ProfileTasks supports multiple shutdown
waiters, and WorkerServices completes its current cycle; those contracts were not replaced
with this client connection owner.

**Q25-F011, P1 — monitor blocking work could change a path after monitor shutdown.**
The Linux monitor spawned independent blocking operations to observe routes and run
submit_path_update. Aborting its async task cannot stop an already running blocking job.
Joining only the monitor would still allow path mutation to outlive network-plan cleanup.

The monitor is now a future spawned by its owner. Its blocking jobs register with the same
group before launch and return results through oneshot. Aborting the async receiver does
not lose the blocking handle. Finish waits for running jobs, while closed admission rejects
new jobs. TCP uses its connection group; UDP uses the same owner for its monitor and jobs.
Other UDP tasks were not migrated in this pass. This changes source; existing release native
libraries are not automatically updated.

## Validation

Nine owner tests cover a running producer's late spawn, cancelled/retried finish, Drop with
surviving Spawners, early error/unwind, completed-handle reaping, a child panic, joining blocking
work after its waiter is aborted, rejecting blocking work after closure, and a rejected
future's destructor reusing its Spawner. The previous handle-reaping test moved into this
suite. Two additional Windows host tests run the actual spawn_stream on a duplex pair and
in-memory TUN channel, with inline and pipeline receive. Finish must yield socket EOF, a
closed writer queue and no remaining TUN-channel owners. No real network is used.

**860 host unit + 52 editor/policy + 7 examples + 12 server INI = 931 Rust tests PASS.**
Linux all-targets Clippy, client-only, client without roaming, server-only, minimal FFI and
rustfmt pass. The existing chunks_exact_to_as_chunks exception concerns unchanged ndp_proxy;
23 server-only transport warnings remain. RU/EN documentation and diff are checked.
Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/tcp-task-audit-20260923.
Linux validation is cross-compilation. Linux runtime, real TUN/DNS/firewall, mobile devices,
SSH, systemd restart, Actions, release-native rebuilds and new benchmarks were not run.

## Remaining work

Forced cancellation of the entire future, process panic or SIGKILL cannot guarantee async
joining; abort cannot stop a running blocking job. TUN/DNS deadlines were subsequently
added in [Q25-F016](AUDIT-Q25-SYSTEM-COMMANDS.md), and read-only monitor deadlines in
[Q25-F020](AUDIT-Q25-PATH-MONITOR.md). Route mutations and client firewall commands
remain open; there is no overall join deadline. Nested transport-library/connector
tasks, UDP candidate/receive/draining lifetime, TUN-shutdown cancellation and Linux fault
injection require subsequent passes. The full audit remains open.

Follow-up: [UDP task ownership](AUDIT-Q25-UDP-TASKS.md) applies the same model to active/candidate/draining and candidate-connect, fixing early exits and joining before rollback. Forced cancellation and nested transport workers remain open.

Follow-up on 23 September: client H2 driver/bridge ownership now spans connect through
generation joining; see [Q25-F015](AUDIT-Q25-H2-TASKS.md). Other limits remain.
