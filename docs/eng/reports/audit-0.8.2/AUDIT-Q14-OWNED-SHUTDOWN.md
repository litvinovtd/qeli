# Q14: final DNS and IPv6 sysctl verification during worker shutdown

Date: 23 September 2026. Baseline commit: `44f19ce8`.
Sections 14, 17, 18 and 19: **IN_PROGRESS**. Q14-F027 is **partially** addressed.

## Confirmed problem

After Q14-F028, exact DNS rule specifications survived a failed Drop; IPv6 sysctl leases
also remained after restoration failures. Yet signal-driven worker shutdown exited 0
when accounting was flushed successfully. Resource errors remained in logs, while
`Server shutdown complete` appeared even after an accounting flush failure.
Concurrent worker and flush failures returned only the first cause.

## Change

After profile supervisors, ordinary tag sweeps and post_down finish,
`nat::finish_owned_cleanup()` retries all pending DNS records and all remaining IPv6
sysctl leases owned by this worker, under the common firewall mutex. A DNS failure
does not skip sysctls; a profile failure does not skip other profiles. Failed cleanup
retains ownership for retry; verified successful cleanup removes the record.

The DNS registry also checks for active leases: none should remain after profiles stop.
An active lease produces `DNS INPUT lease still active at worker shutdown`; its rules
are not deleted by this check. Incomplete ownership is reported without assuming that
an active record is already unused.

`qeli/src/server/shutdown.rs` combines the original worker failure, the final failure
of known network resources and the usage flush failure. Each category is preserved,
with its text bounded to 2048 characters. Accounting is flushed even after network
failure; the exclusive control socket lease remains held until that attempt finishes.

On SIGINT/SIGTERM shutdown the worker exits 1 when the final result is an error.
Non-signal shutdown returns the same Result. `Server shutdown complete` is logged only
for success; otherwise the log says `Server shutdown failed: ...`. A previously observed
transient failure alone does not fail shutdown if final retry confirms release.
Earlier errors remain in logs but do not become a sticky failure flag.

This check deliberately covers **ownership known to the current worker**. Generic NAT
sweeps retain their existing behavior: unavailable `iptables-nft -S` on mixed native nft
does not become an unconditional startup failure. No new INI keys; ABI and wire format
are unchanged.

## Validation

14 new host tests: four DNS registry, four orchestration and six final worker outcome
cases. Coverage includes active/pending entries, permanent failure and successful retry,
retained specs, continuing after failures, all error categories and bounded diagnostics.

**971 host unit + 52 editor/policy + 7 examples + 12 server INI = 1042 Rust tests PASS.**
Linux all-targets Clippy, client-only, client without roaming, server-only, minimal FFI,
compatibility without features and rustfmt PASS. Existing feature-specific warnings
remain; Clippy keeps the prior chunks_exact_to_as_chunks exception for ndp_proxy.

Additionally, eight isolated host-process scenarios use the extracted production
`run_worker` tail, actual `process::exit`, production NAT adapters and portable registry.
Firewall/sysctl, accounting and the control lease are fixtures. No real Linux worker
or signal delivery was run; a parameter selects the signal branch.
Six baseline scenarios expose defects and two controls pass; all eight pass with the fix.
They verify exit 1 for permanent DNS/sysctl failure or an active lease, exit 0 after
successful retry, all error causes and flush before lease release. These scenarios are
not included in 1042. Evidence and logs:
C:/Users/litvi/OneDrive/Documents/qeli/owned-shutdown-audit-20260923.

## Follow-up: propagation through the outer supervisor

A separate pass based on `ea2d377b` confirmed that `supervise` received the worker exit
status but returned Ok on final stop regardless of it. Forced termination after the
shutdown deadline also counted as success, hiding the worker failure from
`run_supervisor` and its calling CLI.

In `qeli/src/server/supervisor.rs`, the termination result is retained until the published
PID is cleared. Final stop returns an error for unsuccessful exit status, and TimedOut
for a kill after the grace deadline. Command-channel closure follows the same contract.
Successful exit returns Ok. `run_supervisor` shuts down outbound clients and notifications,
then reports `Supervisor shutdown failed: ...` and returns the error to its calling CLI.

Explicit Restart and unexpected exit without a stop request keep the existing respawn
policy; unsuccessful termination is also logged. Failed cleanup before such a restart
does not prevent respawn in this change; that remains a separate policy question.

Five real-child host tests were added: clean/nonzero stop, command-channel closure with
exit 7, simultaneous ready exit/channel closure and automatic restart after unexpected exit 7. Five existing kill fixtures now
expect an error while retaining deadline, PID, signal-count and restart-coalescing checks.

**Total for this pass: 976 host unit + 71 config integration = 1047 Rust tests PASS.**
The entire prior build/Clippy/rustfmt matrix was rerun and passes; all nine docs checks PASS.
A separate production-supervisor copy with host children confirms baseline loss of
exit 7 and forced-kill errors. Both return Err with the fix; clean stop remains Ok and
PID is cleared in every case. These three scenarios are not included in 1047.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/supervisor-stop-audit-20260923.
Linux signal delivery and systemd runtime were not tested.

## Open boundaries

The subsequent [profile task and TUN pass](AUDIT-Q14-PROFILE-SHUTDOWN.md) adds shutdown
JoinSet errors, TUN deletion failures and queue timeouts/panics to the worker outcome.
Q14-F027 **remains open**: generic NAT cleanup and unfinished cleanup of earlier generations
need separate accounting. The outer supervisor propagates final stop failure, but live
systemd reporting has not been tested.

Only in-memory worker leases are checked. The subsequent
[Q14-F031 pass](AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md) also registers partial IPv6 acquisition.
Previous-worker journal records and worker-lifetime IPv4 forwarding are not separately
covered by this final pass. The subsequent
[sysctl recovery pass](AUDIT-Q14-SYSCTL-RECOVERY.md) fixes false Ok after persisting
unresolved stale entries and ownership loss on failed reacquisition.
The DNS registry does not survive crashes/restarts; persistent journaling is absent.

The subsequent [Q14-F032 pass](AUDIT-Q14-NAT-COMMANDS.md) bounds individual server NAT
commands; the complete final verification still lacks an overall deadline. Linux runtime, actual firewall/TUN/DNS, devices, native release,
SSH/systemd/Actions and benchmarks were not run.

Previous pass: [retained DNS ownership](AUDIT-Q14-DNS-OWNERSHIP.md).

Follow-up: [24 September — generic NAT, retired generations and IPv4 lease](AUDIT-Q14-RETAINED-CLEANUP.md).
