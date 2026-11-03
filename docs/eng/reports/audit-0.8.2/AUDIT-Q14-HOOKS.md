# Q14: bounded hook output and hook process cleanup

Date: 23 September 2026. Baseline: `843d2eaa`. Section 14: **IN_PROGRESS**.

## Findings and fixes

**Q14-F014, P2 — retaining all stdout/stderr before truncating the log.** Both Linux
hook paths used Command::output(). logged_output capped only the final log string,
after allocating two full output buffers and another concatenated copy. An accidentally
noisy trusted command could exhaust worker/client memory within the 30-second allowance.

One shared runner now drains both pipes concurrently in 4 KiB blocks, retaining an
8 KiB ring tail per stream. Reaching the retention limit does not stop reading. Log
formatting uses only those tails, labels each stream and explicitly marks truncation.
Invalid UTF-8 is replaced for display, so the formatted record may be larger than the
retained raw bytes but remains bounded. Timeouts retain diagnostics too. Spawn errors
and I/O/cleanup errors have distinct typed results and log messages.

**Q14-F015, P2 — shell descendants survived timeout/cancellation.** The former
kill_on_drop(true) applied only to /bin/sh. Descendants could keep changing networking
or hold inherited output pipes after shell exit. Dropping the output() future did not
terminate those descendants once the shell had already completed.

Linux commands now start in an isolated process group. Timeout, read failure and
cancellation send SIGKILL to that group; the owned Child remains the shell fallback.
Normal and timeout/error paths await the shell. Drop/cancellation delegates eventual
reaping to Tokio without spawning another detached application task.

PID reuse protection: wait/try_wait is never polled until both output pipes close.
The unreaped leader reserves the group identifier even after its exit. Group signaling
is disarmed immediately after wait, without another await. Normal shell completion
with EOF on both streams **preserves** deliberately redirected background services.
The runner is shared by server and standalone Linux client; native GUI release libraries
exclude it.

## Validation

- A real isolated regression child emits 1 MiB to each pipe. The old output() retained
  1,048,599 stdout bytes including the test harness, so the regression failed. The fixed
  runner retains at most 8 KiB per stream while preserving the final diagnostics.
- **Eight behavioral host tests plus one child fixture PASS**: two-pipe flood, continuous
  flood deadline, timeout, cancellation with a TCP witness, exit/spawn errors, broken
  reader, ring boundaries and UTF-8. The first cancellation oracle required FIN; Windows
  returned ConnectionReset after termination. The oracle now accepts FIN/reset as closure,
  while timeout still fails. The initial log is retained.
- Windows unit suite 757 PASS; config editor/policy 52, examples 7, server INI 12:
  **828 Rust tests PASS**. MSVC reported creating an import library via linker_messages;
  this is informational linker stdout, not a compilation error.
- **Four new Linux-only tests compiled, not executed**: shell waiting for a descendant;
  timeout after leader exit with inherited pipes; cancellation after leader exit;
  normal preservation and explicit shutdown of a redirected background fixture.
- Linux all-targets Clippy passes with the previous chunks_exact_to_as_chunks exception
  in unchanged ndp_proxy.rs:504. A separate strict run reproduces only that warning.
- Linux client-only check, minimal FFI check, rustfmt, diff check and nine docs checks PASS.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/hooks-audit-20260923 contains before/after
sources and logs, diff, SHA and verification.json. Only isolated subprocesses and loopback
were used. No live TUN/firewall, external SSH or benchmark. Configurations remain INI;
internal API/context JSON is unchanged.

## Limits and continuation

Linux shell/group semantics still require running the tests on Linux. SIGKILL cannot
force prompt exit from uninterruptible kernel sleep; cancellation reaping depends on
runtime lifetime. Groups cannot contain descendants deliberately using setsid/changing
groups or privileges. This manages trusted hook commands, not hostile code isolation.
Stopping intentionally launched background services remains the hook/service manager's job.

Next: startup rollback and background usage_sweep/udp_drop_report lifetime, tying config
trust validation to the actual parsed file, and Linux profile/worker cancellation E2E.
Neither section 14 nor the full Qeli audit is closed.
