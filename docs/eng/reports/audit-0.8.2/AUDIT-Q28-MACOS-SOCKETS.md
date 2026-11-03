# Q28: native socket lifetime and I/O budgets

<!-- normative-sync: audit-q28-macos-sockets-v1 -->

**5 October 2026: Swift SOURCE REVIEW; compiler/runtime USER SKIPPED. Related managed regressions PASS. Q28 IN_PROGRESS, plan 27/37 (73.0%), 10 sections remain.**

## Source changes

| ID | Problem and change |
|---|---|
| F268 | DispatchSource cancellation was asynchronous but fd closed immediately; global read callbacks/send could use its reused number. All relay descriptor/source operations now share one serial queue. Published fd closes only in the cancel handler; DispatchGroup/closures retain release responsibility. Stop latch rejects late TCP/UDP socket publication; queued operations check cancellation before I/O. Private connect/DNS sockets without a source close through their worker catch/defer. |
| F269 | Blocking connect/send and per-server DNS timeouts lacked an overall budget. Sockets are nonblocking/CLOEXEC; SO_NOSIGPIPE setup must succeed. Connect checks SO_ERROR. Shared monotonic budgets: 10 seconds for TCP connect including DNS/candidates; 5 seconds for TCP send and the entire UDP batch; each DNS query at most 2 seconds within the caller's budget. Poll slices at most 100 ms; EINTR/EAGAIN do not extend deadlines. |
| F270 | Empty UDP datagrams were mistaken for EOF; zip hid array mismatches; framework writes could accumulate; errno was observed later. Empty datagrams remain data, cardinality is checked, inbound writes pause/resume sources. A 10-second framework-write watchdog runs outside the I/O queue; atomic tickets prevent stale timers/late completion affecting the next write. Errors capture errno. |

## Checks and evidence limits

**20 Swift cases** added for production RelayLifetime/RelayDeadline: stop/publication gate, repeat stop, poll slice/deadline, nested DNS budgets, pending write tickets, old timeout and late completion. RelayWork.swift is included in the policy-test target. **Cases were not executed; Swift compiler/Xcode and Darwin/NetworkExtension runtime USER SKIPPED.** No simulated fd reuse or actual native baseline is claimed PASS/FAIL here. SocketRelay changes were reviewed by source and Apple contracts only.

Fresh related managed checks: per-app **39**, forwarding **58**, network **117**, control **83**, storage **54**, Windows **325**, shared **549 PASS**, total **1225**. These validate C# regressions and ABI/DTO boundaries, **not the changed Swift relay**. Three C# Release builds have zero warnings/errors; Shared DLL copies match. Docs/bindings/panel/diff PASS; Rust/native digest and 14 artifact hashes unchanged. New Swift source and project.yml are pinned separately from unchanged Rust libraries.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q28-macos-sockets-20261005-r2.
Evidence: release/certification/evidence/q28-macos-sockets-20261005.json.

## Behavior

TCP connect's deadline spans all candidates; a blackholed first address can consume the budget before fallback. Send timeout after partial transmission closes the relay; the old stream is not resumed. Framework-write timeout rejects its current write without guaranteeing cancellation of an admitted OS callback. Stop is asynchronous: its latch refuses new I/O, while queued cleanup/cancel handlers release fd later; returning from stop does not prove completed kernel release. Late completion cannot revive sources. One inbound write per relay bounds response accumulation; real Mac throughput/latency was not measured.

Budgets do not interrupt arbitrary syscalls and depend on queue scheduling. Socket creation, bind/fcntl/getaddrinfo and framework calls may stall outside poll. No overall relay/manager teardown deadline or proven leak-free NetworkExtension behavior is claimed. UDP DNS correlation/policy and family-specific IP_BOUND_IF remain. Configs stay INI with no new settings; existing v5/internal JSON remains unchanged. Actual Mac is user-excluded.

Remaining Q28: final integration review, including old DNS/PF UTC identity stamps. Historical release cases/artifacts/timestamps and physical rows are preserved. No fresh Linux/JNI/native A/B/benchmark/soak; lab, network, services and user profiles untouched. No push/deploy.

Primary contracts: [DispatchSource cancellation and fd close](https://developer.apple.com/documentation/dispatch/dispatchsourceprotocol/setcancelhandler%28handler%3A%29), [connect](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/connect.2.html), [SO_ERROR](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getsockopt.2.html), [poll](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/poll.2.html).

Final source review replaced per-write delayed timers with one watchdog per relay (250 ms polling); delayed-task heap no longer grows with packet count. Initial qualification is preserved separately; this is a source refinement, not a reproduced runtime regression.
