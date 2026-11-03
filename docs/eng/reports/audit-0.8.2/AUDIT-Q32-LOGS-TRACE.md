# Q32: bounded log reads and trace publication

<!-- normative-sync: q32-logs-trace-v1 -->

8 October 2026. F385–F388 / Q32-F006–F009. Scope: panel log API/page,
whitelist/opening/tail/filter/admission, trace ring/dump/watch and capture callers.
Q32 remains IN_PROGRESS; roaming metrics, notification trust and complete
integration remain open. SSE is not implemented: Logs uses authenticated polling.

## Findings and changes

| ID | Failure | Change |
|---|---|---|
| F385 / F006, P2 | A checked canonical log path can be swapped to an outside symlink or FIFO before File::open. The second open can read outside the whitelist or block. | Walk the canonical path through owned directory fds with NOFOLLOW on every component; NONBLOCK and fstat reject special files. Tail reads the same final fd. Stable in-whitelist symlinks still resolve before opening; raced symlinks are refused. Rotation cannot redirect an opened inode. |
| F386 / F007, P2 | Authenticated reads independently queue spawn_blocking jobs, each allocating the 4 MiB tail and derived strings. | Four admitted jobs per process, acquired before scheduling and held by the job after HTTP cancellation. Saturation returns ok=false. API filter is limited to 1024 UTF-8 bytes. |
| F387 / F008, P3 | Every nonzero tail offset drops a first line even at a true line boundary; a window without newline returns an incomplete fragment despite its contract. | Inspect one preceding byte; preserve a complete boundary line and discard an incomplete prefix. Zero cap returns empty; lossy UTF-8 remains supported. |
| F388 / F009, P2 | Trace File::create follows/truncates a destination symlink, can hang on a FIFO and destroys the previous file before completing the dump. Signal watcher performs disk I/O directly on a Tokio worker. Concurrent public dump calls have no admission. | Reuse the production atomic private writer: render snapshot, publish by rename, mode 0600. One admitted dump, held through blocking I/O and cancellation. Signal I/O moves to spawn_blocking. Failure before publication preserves the destination; final directory-sync failure remains an uncertain published outcome. |

The log-path failure assumes an actor able to replace a file/ancestor during the
validation/open interval. This is a controlled pathname-race reproduction,
not a demonstrated unauthenticated remote exploit. Trace destination is an
operator-selected diagnostic path. No network policy or payload format changed.

## Verification

The baseline harness extracts the original tail algorithm and trace write body.
Only the open/read seam adapts a File argument; three tests reproduce outside-link
opening, complete-line loss and destruction of a trace symlink target. It does
not reproduce the old admission or async scheduling policy: those are source
findings checked by new cancellation regressions. FIFO baseline is deliberately
not executed without a cancellation backstop.

The fixed extracted harness passes 11 tests, also as UID/GID 65534 with
no-new-privileges. Trace source matches production after CRLF normalization; log helpers and
four filesystem/admission tests are extracted unchanged. Production atomic writer
and atomic_file.rs are included. Harness-only unused-import warnings are retained.
A separate process runs actual init/record/watch with two real SIGUSR1 signals:
65538 recorded events produce 65536 ordered rows, first sequence 2, last 65537,
overwritten 2, contended 0, mode 0600. SIGINT joins the watcher and does not rewrite
the dump. This qualifies signal/ring I/O, not a real VPN packet capture.

Immutable 85ea8fa9: 2434 library tests PASS, 60 preexisting ignored;
strict all-targets Clippy(-D warnings) and debug daemon PASS. Tests use isolated
net/mount/PID namespaces and private /run,/var/lib,/var/log,/tmp. The real Axum
route test verifies unauthorized refusal, filter bounds and a changed current INI
outside-whitelist error without leaking its file content. Full Linux host/service
baseline is preserved. The first archive omitted conformance fixtures; a second
run exposed an invalid new API test fixture lacking its mandatory profile.
Both failures are retained; the fixture was corrected before qualification.
An all-targets Clippy preparation also lacked release config samples. A complete
Git archive fixed that input set; the successful library run was reused from the
same commit with exact source hashes, without repeating it.
The first small-harness compile omitted its thiserror dependency; its failure is
also retained. The initial baseline on .10 observed the same three legacy IPv4
rules changing. Only those exact lines are excluded from its guard; all other
network fields/services agree. No network-policy mutations were issued and
whole-host firewall invariance for that baseline is not claimed.

## Limits and evidence

The ring remains 65536 events and the disabled record fast path remains one
relaxed atomic load. Dump loss counters are captured with the ring snapshot.
No automatic shutdown dump exists. Source capture sites cover Rust client TCP/UDP
and server TCP; server UDP/core-owned paths/standalone qeli-client tracing are not
qualified. Missing records do not prove loss. Parent-directory races for trace
are not addressed by the log reader's separate fd walk. Atomic publication
replaces destination symlinks/FIFOs rather than writing through them.

Admission bounds blocking read/dump jobs, not all outstanding HTTP response
buffers. Regular-file syscalls cannot be force-interrupted; stalled I/O retains
admission. Log lines are limited to 2000 and recent 4 MiB, not the full file. The
no-file response supplies journald hints without reading journald. Browser output
uses x-text, filters are local, polling does not overlap background requests and
stale results are rejected; 118 actual embedded-component Node VM groups and the static panel gate
(11 templates/1160 RU strings) pass. These include log polling/cancellation/
stale-result/error preservation. This is not a browser DOM/runtime run.
Notification delivery and broad secret-redaction qualification remain open.

Four exact-source native cores pass independent A/B and export checks; macOS
load commands/ADHOC structures checked, without Mac runtime or cryptographic
signature verification. Windows ABI 22 and Android ART JNI 23 pass on final bytes.
The first JNI runtime passed 23 checks but its guest-link guard failed: eth0
changed DOWN/noop to UP/LOWER_UP/pfifo_fast during emulator startup; packages and
original userdata were unchanged. That failure is retained. The qualified repeat
waits for both wlan0 and eth0 plus five stable full-link observations before
testing the same native bytes; original AVD userdata/packages/links are preserved. No ARM runtime, managed-app
rebuild or physical-platform VPN/E2E. Separate targets/private caches do not
establish cross-path hermeticity. The early desktop build was deliberately
interrupted after the API fixture failure; its completed Windows pass/logs were
saved and owned root cleaned before the corrected-source rebuild.

Raw packet: audit-debt-20260924/q32-logs-trace-20261008. Qualified source archives and logs of all
failed/fixed runs, actual signal program/CSV, final test binary/daemon/native A+B
and JNI DEX/logs are saved with SHA checks. Eight owned laboratory roots removed after source/binary backups and path/process/mount guards; original Qeli services preserved.
Native provenance and 14 manifest SHA entries, docs 9 checks, bindings and
diff checks PASS. Historical 41 certification cases and 49 prior supplements
are preserved modulo the manifest source digest; a scoped supplement is added.
Older standalone evidence remains unchanged. Configs remain INI, internal JSON
remains. Q32 IN_PROGRESS; overall 28/37 (75.7%), nine remain; debt 14 DONE plus
D06 ACCEPTED_LIMITATION. Q29/Q30/Q31 and physical-platform exclusions unchanged.
No push, deployment or release.
