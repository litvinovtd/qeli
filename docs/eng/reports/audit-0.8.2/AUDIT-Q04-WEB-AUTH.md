# Q04: panel authentication and API boundaries

Date: 3 October 2026. Status: **PASS for Q04 authentication and API boundaries**.

## Scope

Reviewed `web/auth.rs`, `web/mod.rs` middleware and `web/api` handler authorization.
Inventory covers 56 methods: only POST `/api/login` is public; the other 55 take
`AuthGuard`. HTML requires a cookie; Basic is an API feature. Web-panel TOTP is
absent and receives no artificial PASS; VPN TOTP belongs to its separate audit.
Positive business mutations, INI transactions, restore and control remain Q05/Q07.
This batch checks denial of these methods without credentials or with an invalid
Origin, and unchanged configuration, identity, session files and supervisor PID.

## Confirmed defects

| ID | Before | Fix |
| --- | --- | --- |
| Q04-F001 | All 24 parallel attempts from one IP ran Argon2 and returned 401 with a threshold of 3 and two permits. Lockout was checked before queueing; cancellation could lose result accounting. | Shared login/Basic IP check at actual blocking-job admission. Record the result inside the job before releasing its permit, including cancelled waiters. Already admitted jobs may finish after lockout. |
| Q04-F002 | Correct `basic`/`bAsIc` credentials returned 401. | Compare the scheme without case sensitivity and accept `1*SP`; preserve exact username/password. Reject invalid Base64/UTF-8, missing colon and other schemes. |
| Q04-F003 | Authenticated `/audit/login` redirected to `/audit/`, requiring another redirect to `/audit`. | Root Location goes straight to the canonical slashless mount; other paths retain their semantics. |
| Q04-F004 | Two Q03 Rust assertions searched for removed `obfMode` and the old fetch spelling without `cache: no-store`. | Remove dependence of backend tests on stale JS text. Rust verifies the canonical profile; existing actual-component JS tests verify default consumption and copy ownership. |
| Q04-F005 | Pinned Clippy 1.97 rejected two platform-dependent packet-info conversions and seven test-fixture constructs. | Keep checked Android conversions with two statement-local allows explaining type differences; use fixture initializers and C-string literals. Full and minimal CI lint passed again. |

Case-insensitive schemes are specified by [RFC 9110 §11.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1).

## Checks

Previously qualified release `f5c4bd0a36ba23dd2ba27ec638b5960b19414281f10fec59122f2f009eced199`:
289 checks PASS with separate observations reproducing F001–F003. Coverage:
three unauthorized styles for every protected method, cookie-only HTML, nonce CSP,
security/cache headers, every mutator CSRF, Origin/Referer, CLI without Origin,
TTL and independently signed invalid/expired tokens, trusted/untrusted proxy chain,
HTTPS/prefix, page/asset/API allowlist, lockout/expiry, cookie persistence and
revocation over restarts, session.gen/session.key faults/corruption, explicit
passwordless mode, actual native TLS and HSTS.

CSRF compares host/port; allowed_origins URL schemes are normalized under the
existing documented contract. It is not strict full-origin equality. Configuration
files remain INI; JSON is used for API payloads and audit evidence.

New deterministic Rust regressions cover queued admission after lockout, cancelled
running-job accounting before permit return, success/disabled policy and Basic
grammar. All 116 Q03 actual-JS groups passed again.

Lab .11 uses private NET/mount/PID namespaces and the exact release SHA. Full host
snapshots, live-service identity and its working binary are compared before/after.
The running service is not replaced. Repeat with `scripts/audit_web_auth_lab.py`
and `scripts/audit_web_auth_boundary.py`.

Failed diagnostics are retained: worker readiness before identity generation, lazy
session-key initialization, canonical-redirect expectation, and the first local
patch's incorrect CP1251 conversion. The encoding is repaired before final
qualification; the first incorrect unit input is not reused as PASS. Previous Q03
Rust reuse missed the HTML-dependent assertions; this fresh full run closes that gap.

## Final qualification

All five Q04 criteria are complete. Release SHA `8fa8590104ebbceecb78c09d7c146b3ee101719b53820d0d1a1bc3cff664b3b7`.

- Fresh full Linux units: **2261 PASS**, 60 ignored; ignored tests are not claimed executed. The four new regressions are included.
- Pinned Clippy 1.97: all-targets and minimal transport-core-ffi with `-D warnings` PASS; formatting PASS.
- Actual HTTP: **293 checks PASS**, 56 methods / 55 guards. With threshold 3 and two permits, both 24 login and 24 mixed login/Basic attempts now yield **4×401 + 20×429**, previously 24×401; an already running job is accounted for.
- Actual panel JS: **116 groups PASS**.
- Release matrix: **18 cases / 327 checks PASS**, aggregate leak PASS. After lint-only fixture fixes, the final release is byte-identical to the HTTP/matrix artifact: exact-SHA reuse, no repeat execution claimed.
- Fresh final-tree soak: **100 TCP + 100 QUIC / 33 checks PASS**.
- Desktop and Android: fresh independent native A/B on sealed tree `327de78b`, provenance and all library pairs PASS. Native binaries remain byte-identical; no fresh physical-device runtime is claimed.

All 322 compilation input hashes match the final source. Lab network state, service PID/start identity and checked working artifacts are preserved. Automated release certification is refreshed; 21 physical rows and previous benchmarks remain unchanged. This closes Q04, not the entire audit.

[Final evidence](../../../../release/certification/evidence/q04-web-auth-20261003.json). Failed intermediate lint/build/fixture attempts remain separate and are not counted as PASS.
