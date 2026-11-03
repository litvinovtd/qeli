# Q14/Q33: config snapshot authorization for Linux commands

Date: 23 September 2026. Baseline: `e8a78b90`. Sections 14 and 33: **IN_PROGRESS**.

## Findings and fixes

**Q33-F001, P1 — permissions checked on different bytes from those executed.** Linux
startup first read and parsed the config, then reopened its pathname to authorize
`post_up`, `post_down` or `auth.password_command`. O_NOFOLLOW and fstat on that second
open did not bind permission to the first read. A local actor able to replace the path
could supply untrusted commands for parsing and restore a trusted file before the gate.
Late chmod could similarly upgrade permission for commands already retained in memory.
This finding does not assume remote panel permission to edit shell fields.

The common config_source loader now reads and fstats one descriptor. A command is
permitted only for a regular, non-symlink file owned by root or the effective UID,
without group/world write bits. Metadata is compared before and after reading;
detected content/owner/permission changes reject the entire load. Reads stop at the
observed length plus one byte so a continually appended file cannot extend the read
indefinitely. This is not an absolute size limit for a large file already present.

O_NONBLOCK lets the loader reject FIFOs before reading instead of hanging in open.
For compatibility, a symlink to a regular file can supply a non-command config, but
its snapshot always denies commands, including if the path changes before fallback
open. Invalid UTF-8 is rejected. Unsupported platforms fail closed on command trust;
native GUI release libraries do not include this Linux runtime loader.

Client startup, worker startup, supervisor startup and SIGHUP reading use the loader.
Hooks and password_command use the immutable permission captured with the startup
bytes. A denied hook remains ignored; a denied password_command fails client startup.
Profile retry cannot gain permission from a changed path. SIGHUP continues to reload
users/brute-force settings only and cannot authorize or replace startup hooks. Fixing
ownership/permissions requires a fresh client/worker startup to load trusted commands.
The obsolete pathname-based authorization function and its permissive non-Linux stub
were removed; no duplicate client/server permission gate remains.

**Q14-F019, P2 — valid cleanup depended on the later config pathname.** Server stop
reopened the file to decide whether to run an already-configured post_down, so removal
or permission changes could silently skip cleanup for a generation that had started.
The ready-generation snapshot now keeps its exact command alongside interface/pool
values. Cleanup claims it once and uses startup authorization, regardless of subsequent
path removal/replacement. Editing the file does not revoke already-armed cleanup.

## Validation

- Ten new portable tests cover exact UTF-8/CRLF input, the Unix owner/mode policy,
  path replacement before/after read, immutable allow/deny across retries, in-place
  modification, permission changes during reading, forced symlink denial, malformed
  UTF-8 and missing/directory inputs. Filesystem race fixtures on Windows use an
  injected read-only-bit policy marker; they do not claim to exercise Linux ownership.
- Three new Unix tests cover actual symlink, chmod and FIFO behavior. One new Linux
  lifecycle test verifies that later chmod cannot enable post_down on profile retry;
  an existing once-per-ready-generation test now removes the loaded config before
  cleanup. These tests were cross-checked, **not executed on Linux**.
- **803 host unit + 52 editor/policy + 7 examples + 12 server INI = 874 Rust tests PASS.**
  Linux all-targets Clippy PASS with the existing chunks_exact_to_as_chunks exception
  in unchanged ndp_proxy.rs. Standalone Linux client and minimal FFI checks PASS.
  Rustfmt, diff and nine documentation checks PASS.
- No live TUN/firewall, external shell command, SSH, service restart or benchmark was
  run. Only isolated host fixtures were executed; the Linux hook marker tests await
  Linux runtime execution.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/config-trust-audit-20260923 contains
before/after sources, test/check logs, review diff and verification metadata.

## Remaining work

This closes the separate-read/path-authorization race, not the full script trust chain.
Called scripts, their dependencies and privileged writers remain operator-controlled;
metadata comparison is not an atomic transaction against every hostile in-place edit.
General config size limits, installer/update/restore boundaries, notification cache
loading and supervisor/client startup task ownership need separate passes.

Follow-up: [credential command audit](AUDIT-Q25-CREDENTIAL-COMMANDS.md) fixes the blocking,
unbounded password_command path, secret-bearing stderr and early signal cancellation.
The later [file/status audit](AUDIT-Q25-PASSWORD-FILES.md) also adds password_file bounds
and joins client background tasks before final publication. Network rollback and Linux
runtime/signal/systemd integration remain open. Sections 14/33 and the full audit are not complete.
