# Q25/Q14: bounded password files and final client status

Date: 23 September 2026. Baseline: `506c4e05`. Sections 14 and 25: **IN_PROGRESS**.

## Findings and fixes

**Q25-F002, P2 — unbounded synchronous password_file and unprotected temporary secret.**
The effective AUTH size check ran after read_to_string had buffered an entire file on
an async runtime worker. FIFO input could block before the stop token was observed.
Trimming copied the secret into Zeroizing, leaving the original String allocation unwiped.

File and command suppliers now share SecretBuffer: preallocated 16 KiB raw storage,
overflow refusal, strict UTF-8 and outer whitespace trimming. Raw storage, 4 KiB scratch
and the final string zeroize on Drop. There is no Vec growth/reallocation or truncated
credential. Existing AUTH wire limits, source precedence and empty/whitespace behavior
are unchanged. GUI capabilities and INI keys are unchanged.

The file loader opens once, fstats that descriptor and accepts only a regular file.
Symlinks remain supported for secret-store rotation; shell-command config owner checks
are not imposed on a data file. O_NONBLOCK allows FIFO rejection before any read. Size
is checked before and during reading; a metadata stamp shared with config_source and
the byte count reject detected in-place changes. Path replacement never supplies bytes
from a second file. This is not an atomic guarantee against every privileged writer.

One blocking I/O job per process runs outside async runtime workers. Its 30-second
cooperative deadline includes admission; cancellation/deadline are checked between
filesystem operations. Ordinary stop/timeout cancels queued work and awaits an active
job, discarding any late secret. The task owns its admission permit and buffers, so
forced cancellation cannot admit additional blocking reads while it remains alive.

Filesystem syscalls cannot always be interrupted. An active read/open/fstat on a stalled
filesystem may outlive 30 seconds; ordinary shutdown waits. On forced caller Drop, at
most that single active job remains until I/O returns and its cancellation check runs.
This is explicit bounded residual work, not a hard I/O timeout or synchronous Drop join.

**Q14-F021, P2 — final status raced an in-flight sampler write.** Dropping the client's
JoinSet only requested abort. A sampler that had already captured an older snapshot could
finish a synchronous file write after the main path published stopped/failed. Early
credential/startup errors also skipped the terminal publication used by later exits.

run_client now owns an outer wrapper around all startup/retry returns. It aborts and joins
watchers/sampler before setting and publishing terminal state. Four duplicate terminal
publication blocks were removed. Errors after diagnostic reporter initialization, including
password source errors, use the same boundary. Parse/adapter construction failures before
that initialization still have no reporter. Forced cancellation of the entire future does
not promise final publication; synchronous diagnostics can delay the join.

## Validation

- Nine new portable file tests: real UTF-8/trim and exact/over limit, malformed/empty/
  missing/directory inputs, in-place mutation, pathname replacement, pre-cancel and
  admission timeout, cooperative stop, deadline, forced cancellation and retained permit,
  panic redaction/admission release. Some checks share one scenario.
- Three new portable finalization tests: a blocked old writer must end before final,
  cancellation/retry keeps its handle, and a panicked task does not skip other destructors.
  Existing command tests now exercise the shared buffer and remain green.
- Two new Unix tests cover secret-file symlinks/device rejection and FIFO without a writer.
  They were cross-checked only, not executed on Linux.
- **824 host unit + 52 editor/policy + 7 examples + 12 server INI = 895 Rust tests PASS.**
  Linux all-targets Clippy PASS with the previous chunks_exact_to_as_chunks exception in
  unchanged ndp_proxy.rs. Client-only, server-only and minimal FFI checks PASS; server-only
  still has 23 unchanged transport dead-code warnings. Rustfmt, diff and nine docs checks PASS.
- Local regular files, controlled blocking jobs and fake status writers were used. No real
  VPN/firewall/service restart, remote SSH, GitHub Actions or benchmark was run. Cross-checks
  do not validate real Linux signals, filesystem failure modes or systemd shutdown.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/password-file-audit-20260923.

## Remaining work

Client startup/network rollback and live monitoring of failed background services still
need review. Diagnostic file writes remain synchronous and best effort. The new final join
covers the three owned startup tasks, not a blanket proof for every nested transport task.
Supervisor panel/metrics/autostart, notification cache/config load, installer/update/restore,
release provenance and Linux runtime E2E remain open. The full audit is not complete.
