# Q14: control socket, API bounds and lifecycle hooks

Date: 23 September 2026. Baseline: `dc93d50c`. Section 14 status: **IN_PROGRESS**.

## Findings and fixes

| ID | Priority | Reachable failure and impact | Fix |
|---|---|---|---|
| Q14-F008 | P1 | A second worker unconditionally unlinked control.sock, orphaning a live listener's pathname; a regular file at the configured path was also deleted. | Nonblocking flock on a persistent sidecar for the worker lifetime; type/owner checks, active/stale probe, dev/inode guarded cleanup. |
| Q14-F009 | P1 | QELI_CONTROL_SOCKET=/tmp/custom.sock made a root process chmod shared /tmp to 0700. | Validate existing parent without chmod; create new directories as 0700, reject unsafe ancestors and symlink parents; systemd RuntimeDirectoryMode=0700. |
| Q14-F010 | P2 | take(limit).lines() manufactured EOF and accepted a valid JSON prefix of an oversized command; CLI could return a truncated reply. | Shared bounded reader with lookahead, explicit overflow and LF/CRLF; CLI consumes one line without waiting for subsequent EOF. |
| Q14-F011 | P2 | A peer not reading a large reply could occupy one of 16 handlers indefinitely; CLI connect/write also lacked deadlines. | Writes and CLI connect get 5 s; requests 64 KiB, replies 8 MiB, CLI reads 15 s; outbound size checked before writing. |
| Q14-F012 | P2 | Control mutations remained available during profile teardown; aborting the parent did not join handlers. Startup failure after spawn could also leave the task running. | Stop control, close listener, join accepted handlers, then tear down profiles; lease survives until worker cleanup. Fallible NAT cleanup precedes task spawn. |
| Q14-F013 | P2 | post_down ran for disabled/not-yet-ready profiles. Snapshot and done-set used separate locks, allowing a fallback to replace actual WAN metadata. | Atomic snapshot removal both proves readiness and claims the hook; remove done-set and repeated WAN detection fallback. |

Control admission closes on stop or accept failure. Accepted commands finish to avoid
cancelling a disk/runtime mutation at an arbitrary await. This cannot guarantee completion
under SIGKILL: the supervisor still enforces its overall 60 s grace. The worker owns the
lease beyond the control task, preventing another worker's NAT cleanup during profile
teardown. Same-uid/root processes deliberately replacing locks/directories are not a
separate security boundary; filesystem trust requirements still apply.

The hook snapshot is armed after TUN/routing/NDP setup, before post_up. An empty, failed
or interrupted post_up does not disarm cleanup for that generation. Early setup failures
and disabled profiles never arm it. The trusted-file check remains in place. Configuration
syntax stays INI; JSON is only the service API envelope.

## Validation

- Seven host tests of production control_io: LF/CRLF/EOF boundaries, overflow/UTF-8,
  valid JSON prefix, reply without EOF, read/write deadlines and outbound frame validation.
  Two regressions fail with the old reader algorithm; all seven pass with the fix.
- Windows unit suite: 748 PASS; config editor/policy 52, examples 7, server INI 12:
  **819 Rust tests PASS**. Minimal transport-core-ffi check PASS.
- Twelve new Linux-only tests written and compiled, **not executed**: eight filesystem/lease,
  three control shutdown/admission/drain, one hook generations/disabled/early failure/snapshot.
- Linux all-targets Clippy passes with the previously documented
  clippy::chunks_exact_to_as_chunks exception in unchanged ndp_proxy.rs. Not a strict Clippy PASS.
- Rustfmt, git diff check and nine documentation checks PASS. RU/EN manuals, registry and
  the packaged systemd unit updated.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/control-audit-20260923 contains baseline
files, before/after logs, final diff and verification.json. No live TUN/firewall or external
SSH scenarios were used; this pass makes no performance claim.

## Remaining checks and next area

Linux runtime checks remain mandatory for Unix permissions/flock, concurrent workers,
systemd upgrades, real SIGTERM/accept failure and shell hooks. Forced outer worker future
cancellation/panics, hook descendants, bounded hook stdout/stderr, and binding trusted
config file descriptors to parsed contents remain separate work. Next: hook process
ownership/output bounds and startup rollback. Neither Q14 nor the full audit is closed.

Follow-up: [Q14-F037](AUDIT-Q14-WORKER-NETWORK-LEASE.md) prevents bypassing the control lease through another path/filesystem namespace. A new kernel lease scopes server-worker admission to the network; SIGKILL/deleted-profile recovery was tested for listable tagged rules. Persistent exact-rule journaling and mixed nft remain open.

Later follow-up: [Q14-F038](AUDIT-Q14-FIREWALL-JOURNAL.md) adds a persistent exact server firewall journal and verifies recovery with listing failures. Client crash recovery and the general mixed nft/firewalld matrix remain open.
