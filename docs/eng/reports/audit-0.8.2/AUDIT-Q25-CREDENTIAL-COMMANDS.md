# Q25/Q33: bounded credential commands and early client shutdown

Date: 23 September 2026. Baseline: `965fdcc8`. Full audit remains **IN_PROGRESS**.

## Findings and fixes

**Q25-F001, P2 — unbounded blocking password supplier.** The Linux client called
std::process::Command::output from async startup. A stalled supplier could block a
runtime worker indefinitely; stdout/stderr were fully buffered before the effective
credential-size check. A long token was rejected too late to prevent memory growth.

The new credential collector uses the same OwnedProcess implementation as lifecycle
hooks: null stdin, Linux process group, direct-child fallback and kill-on-drop. The
shell is the fixed `/bin/sh`, not a PATH lookup. Execution, stdout EOF and shell wait
share 30 seconds. At most 16 KiB of raw stdout is retained before trim; overflow aborts
and rejects the whole result. UTF-8 decoding is strict. The existing AUTH wire budget
and pass/password_file/password_command precedence remain unchanged. No INI keys were
added. GUIs still preserve these fields without executing them.

The credential path deliberately does not reuse the hook diagnostic tail: losing the
beginning of a password must never produce a different accepted credential. Its 4 KiB
read scratch buffer, preallocated 16 KiB output buffer and returned string are zeroized
on Drop; no raw-output Vec reallocation leaves earlier secret copies in freed buffers.
This is not a claim that every copy in the shell, OS or entire client is erased.

**Q33-F002, P1 — stderr exposed through startup errors.** Failed suppliers embedded
all stderr in anyhow errors, which could include secrets or shell-expanded arguments.
The new collector redirects stderr to null at spawn: it cannot fill a pipe or be retained
for logging. Errors contain only OS error/category/exit status, never raw output or the
command. Debug formatting of typed failures also has no secret-bearing byte fields.

**Q14-F020, P2 — shutdown was registered after credential execution.** A supplier
started before SIGINT/SIGTERM registration. With an isolated process group, ordinary
termination of Qeli during this interval could leave a supplier alive. Signal streams
are now registered synchronously before any supplier spawn, using the same cancellation
token as the active carrier and reconnect backoff. A pre-existing stop avoids spawn;
a stop while reading kills the group and awaits the shell before startup returns cleanly.

SIGUSR1 watcher, diagnostic sampler and stop watcher now belong to a client JoinSet,
whose Drop aborts them on startup failure/return/cancellation. This bounds ownership;
it does not add an asynchronous final drain or guarantee that synchronous diagnostic
I/O can be interrupted. Further client cleanup/task monitoring remains open.

**Q34-F001, P2 — server-only feature compilation was broken.** The extra validation
`--no-default-features --features server --lib` found six unresolved TUN imports.
The baseline gated Linux TUN on client alone although server also imports it. TUN now
builds for either feature. CI checks the server library without client and the standalone
client without server, in addition to existing full/FFI checks. This does not introduce
a new server executable; the existing qeli binary still requires both features.

## Validation

- Nine new portable tests exercise byte limit/excess, strict decode/outer trim, exact
  subprocess stdout with noisy stderr, failure/Debug redaction, spawn failure, read
  failure, real-child overflow, timeout/runtime responsiveness, forced cancellation,
  cooperative stop and pre-cancel. Several assertions share a scenario.
- Four new Linux tests cover `/bin/sh` plus closed stdin, deadline after stdout closes,
  and timeout/cancellation with a descendant holding stdout after shell exit. These were
  cross-checked only, not run on Linux. Cooperative-stop tests inject a local stop event;
  they are not an OS-signal or full client E2E test.
- **812 host unit + 52 editor/policy + 7 examples + 12 server INI = 883 Rust tests PASS.**
  Linux all-targets Clippy PASS with the prior chunks_exact_to_as_chunks exception in
  unchanged ndp_proxy.rs. Standalone client, server-only library and minimal FFI checks
  PASS. Server-only reports 23 dead-code warnings in unchanged shared transport code;
  it is a successful check, not a warning-free Clippy result.
- Rustfmt, staged diff and nine docs checks PASS. CI commands were checked locally by
  cross-compilation; GitHub Actions was not run. Tests use isolated child executables
  and loopback witnesses. No real VPN, firewall, service restart, SSH, external supplier
  command, notification or benchmark was run.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/password-command-audit-20260923 contains
baseline, before/after sources, failed and final check logs, diff and verification metadata.

## Limits and next steps

Timeout/overflow/cooperative stop await shell cleanup; abrupt future cancellation delegates
reaping to Tokio. Kernel uninterruptible sleep prevents a hard wall-clock return guarantee.
A descendant can deliberately escape its group. Successful, explicitly redirected background
services keep the existing hook behavior. The shell is fixed; commands inside it still use
the operator's PATH and script trust chain. The helper is not a sandbox for untrusted commands.

Follow-up: [password files and final status](AUDIT-Q25-PASSWORD-FILES.md) adds bounded
regular-file reading, shared zeroizing storage and a joined final publication boundary.
Client network rollback, background fault monitoring, supervisor tasks, real Linux
SIGINT/SIGTERM/systemd, release provenance and the wider feature matrix remain open.
Sections 14/25/33/34 and the full audit are not complete.
