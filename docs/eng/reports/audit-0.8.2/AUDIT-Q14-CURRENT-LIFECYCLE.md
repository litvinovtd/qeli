# Q14: supervisor, workers and profiles

<!-- normative-sync: audit-q14-current-lifecycle-v2 -->

**Q14 DONE/PASS. Overall plan: 14/37 (37.8%), 23 sections remaining.**
4 October 2026. Core `8b4f11aae0646696b2065e6044f40ddfbfc16e94`, Linux candidate
`01bfeb9e32ff9cbce67f435f4555c1dc12d725ca6ac940245b498af911f94d36`.
Evidence: `release/certification/evidence/q14-supervisor-20261004.json`.

## Q14-F039, P2

`run_supervisor` discarded panel, metrics and autostart handles. With a surviving
runtime, the panel retained its port and state after normal return or cancellation.
Normal CLI exit masked this by ending the entire runtime. Both previous shipping-rlib
probes retained the listening port after stop/cancel; original hashes/results remain.

A scoped JoinSet and stop watch now own all three services. Normal shutdown concurrently
finishes worker, clients, notifications and services, then joins their results. Failures
retain their causes across repeated cleanup. Outer cancellation announces stop and aborts
owned tasks. Metrics/autostart observe stop. HTTP/HTTPS listeners and accepted connections
close, including incomplete TLS handshakes. Normal panel shutdown allows 2 seconds graceful
drain plus 2 seconds forced-drain confirmation. INI, service API, client ABI and dependencies
are unchanged.

## Final validation

- **2368 ordinary Linux PASS / 60 ignored**, including three new ownership regressions;
  full/minimal Clippy and fmt PASS. **101 selected supervisor/tasks/control/hooks/shutdown
  tests** belong to that same run, not extra executions.
- **4 rlib cases: HTTP/HTTPS × stop/cancel**, real HTTP/HTTPS requests before stopping,
  listener and idle/partial request/ClientHello closure while the runtime survives.
- **38 full-process checks, TCP and UDP**: SIGKILL/respawn with new PID, SIGHUP retaining
  the generation, six panel restart requests, healthy profile with occupied bind/TUN
  siblings, 24 silent/oversized control clients, bounded fd and stop drain. Foreign
  listener/dummy interface preserved; normalized network snapshot restored.
- **5 privileged executions / 4 selected ignored tests**: delayed hook context write/unlink
  preserves heartbeat, preparation cancellation starts no command, running-hook cancel
  joins reap/context removal; cancelled profile scope retains TUN/DNS through child Drop.
- Production library supervisor stopped during backoff after two deliberately failing
  fixture-child exits, without waiting for the retry timer. The fixture failure is
  intentional, not a failure of the real worker.
- **18/18 matrix / 327 checks**, aggregate IPv4/IPv6 leak,
  **100 TCP + 100 QUIC / 33 soak checks**, **24 REALITY-TLS/H2 checks** on this candidate.
- Four independent native A/B builds, exports, copies and provenance PASS. Client
  libraries equal previous Q13 bytes; the fix is server-only.

Review covers Child/PID ownership, stop/retry/Restart/Reload ordering, queue closure,
bounded control IO/drain, profile startup/cleanup boundaries, loaded-INI trust,
ready-generation once-only post_down, hook output/process groups and 45-second worker /
60-second supervisor budgets. Shared production unit tests cover slow-writer deadlines
and queue coalescing; live runtime covers admitted control pressure and stop. All five
Q14 criteria are complete within available scope.

Earlier 8 worker / 80 reload / 22 recovery / 14 multiprofile checks below retain original
hashes; nine relevant modules match byte-for-byte. They are not claimed as new executions.
New tests/current matrix rerun. The first new-service unit run caught lost failure details;
fixed and the complete run repeated. Original FAIL retained in raw evidence.

Outer cancellation is emergency termination: Drop cannot synchronously join every async
destructor, so graceful network cleanup after SIGKILL is not promised. Listener/connection
checks ran with a surviving runtime. Other ignored tests are not claimed executed. Active
lab services/executables preserved; raw desktop snapshot=false retains its exact previously
accepted legacy firewall delta. No fresh installed-app E2E; unavailable Mac/router/Windows VM
runtime remains user-excluded. Next: Q15 sessions, IP pools and limits.

## Earlier worker lifecycle batch

**Batch PASS; Q14 IN_PROGRESS.** 4 October 2026.
Source `711782d6d1cb6e41889c7c359f964e7242e314fc`, Linux artifact `5605f4b7867cefb0886f14c943c499693fb41a0d0f767f8675292115d5f27c55`.
Evidence: `release/certification/evidence/q14-lifecycle-current-20261004.json`.

Three existing isolated fixtures rerun on this release:

- **8/8 worker cases**: TCP/UDP × IPv6 off/manual/route/nat66; malformed INI,
  second-worker rejection, rejected SIGHUP, working control, once-only post_down,
  TUN/NAT/sysctl removal and before/after snapshots. **80 valid reloads** keep
  fd/socket/task and sampled RSS within established limits.
- **22/22 recovery checks**: different control/state paths and nested mount/PID
  cannot bypass namespace admission; SIGKILL, deleted profile, foreign rules preserved,
  post_down retains the lease; startup failure releases admission for a later launch.
- **14/14 multiprofile checks**: simultaneous TCP+UDP, invalid and 10 valid
  reloads, stop, SIGKILL and recovery after sibling removal; once-only hooks and
  final network/control/journal restoration.

Fresh ordinary Linux units: **2365 PASS / 60 ignored**. Evidence selects the passed
supervisor/tasks/control/hooks/shutdown module groups from that same run, not extra
test executions. Privileged ignored tests are not claimed PASS. Fixtures own fresh
NET/mount/PID namespaces and private /etc/qeli. Parent host snapshots match;
active service/executable unchanged.

Review covers Child/PID ownership, retry/Restart/Reload queue, cancel-safe join, deferred
profile resources, control path/IO/drain, loaded-INI trust, once-only post_down, hook process
groups/output bounds, and 45/60-second budgets. No new confirmed defect in this batch.
Earlier D09/D13 and related evidence retain their original SHA and limits.

Next Q14 batch: full supervisor crash/respawn/restart/stop, occupied bind/TUN with a
healthy sibling, control-client pressure and hook failure/cancellation at generation
boundaries. Supervisor panel/metrics/autostart ownership on stop and outer-future
cancellation also requires verification. Those remain open, so Q14 is not complete. Overall after Q13: **13/37 (35.1%)**.
