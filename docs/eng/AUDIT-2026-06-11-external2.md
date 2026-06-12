# qeli — review of the second external audit (2026-06-11)

Source: a second external audit of qeli v0.6.0 (brought in by the user, separately from
[`AUDIT-2026-06-11.md`](AUDIT-2026-06-11.md)). Each item is checked against the code.

> **The meta-conclusion: the audit is mostly hallucinated.** Many claims are refuted by a
> direct check of the repository — it confidently describes non-existent "stubs" and
> missing CI jobs. When such basic facts are wrong, the rest can't be trusted without
> verification. Of ~30 items, **~13 are verifiably false** (including both "🔴"), most of
> the rest is by-design or trivialities. Genuinely substantiated is practically one item
> (`panic=abort`), and it only strengthens the priority of the already-known T2.

> **Verification of the fixes (2026-06-11):** 2 hygiene edits made (see below); run through
> the common lab gate — Rust (.10) `build`/`test` **188 passed**/`clippy -D warnings`/`fmt`
> — all green.

---

## Trust-fatal examples (verifiable falsehood)

| The audit's claim | The fact |
|---|---|
| "DHCP/DNS are not implemented, the `pub mod` is an empty file" | `server/dhcp.rs` = **506 lines**, `server/dns.rs` = **162 lines** of working code |
| "macOS doesn't build in CI (no macos-latest)" | `ci.yml` contains the job `macos-build: runs-on: macos-latest` |
| "mipsel/aarch64 are only declared, CI builds amd64" | `ci.yml` `keenetic-cross` with the matrix `aarch64-musl` + `mipsel-musl` |
| "FFI: most methods `throw NotImplementedException`" | **0 matches** in all the C# (`grep` over qeli-shared/win/mac) |

---

## The full review

### ❌ False (with proof)

| Claim | The fact |
|---|---|
| `thread_rng()` "not crypto-secure" | `rand::thread_rng()` is a **CSPRNG** (ChaCha, seeded from the OS). A factual error about the crate |
| the rate-limiter "a blocking std Mutex in async over await" (mod.rs:1307) | It's a `tokio::sync::Mutex` (`.lock().await`), held for microseconds, **not** across an await |
| exchange.rs "doesn't check the 5 low-order points" | The **all-zero result** check = the RFC 7748 §6.1 way to cut off all low-order points; a separate block-list isn't needed. Documented + the test `derive_shared_checked_rejects_low_order_point` |
| the cookie "no Secure/HttpOnly/SameSite" | `login.rs` — `HttpOnly; SameSite=Strict` + a conditional `Secure` (forcing Secure on HTTP would break the cookie) |
| `build_auth_ok` "a leak, OK: without JSON" (🔴) | `serde_json::to_string` on a `json!` `Value` practically never fails — the branch is unreachable (= T5 from the first audit) |
| REPLAY_WINDOW=64 "false positives on 100k packets" | A misunderstanding: the window **slides** with each packet — this is a tolerance for reordering of 64 packets, not a limit on the total count |
| the UDP writer "hanging on a dead channel" (🔴) | `writer_rx.recv()` on a closed channel → `None => break`; it can't hang |
| recv_peek "not cancellation-safe" | `stream.peek().await` is cancel-safe; cancelling the task drops the future and interrupts the peek immediately |
| the control socket "two workers compete, SO_REUSEADDR needed" | The socket is bound by **one** supervisor; for a Unix socket SO_REUSEADDR doesn't work that way; the permission window is closed by the directory's 0700 lock (L2) |

### ⚪ By design / not a defect

- **fake-tls cert without chain-verify** — *they say it themselves: "by design"*. fake-tls's
  security comes not from the certificate but from the X25519 proof + channel-binding; for
  real TLS there's `reality-tls`.
- **the v1→v2 proof "no migration"** — v2 is a deliberate security upgrade (channel-binding),
  a single version 0.6.0 on all components, v1 clients don't exist.
- **TUN strip → silent drop** — dropping a **metric**, not a bug; and only in TAP (not
  connected).
- **config hot-reload** — partly wrong: users/brute-force are **hot**-reloaded on SIGHUP
  (`WorkerCmd::ReloadUsers`); a restart is needed only for listener/crypto changes.
- **No prometheus/structured logs** — an honest roadmap gap, not a defect.

### 🟡 Genuinely worth attention — and made

- **`panic = "abort"` (Cargo.toml)** — the only truly useful item. Most likely
  **deliberate** (unwinding a panic across the FFI/JNI boundary is UB, abort is safer). The
  inference is correct: a panic in a task kills the whole worker (the supervisor will
  restart, but active sessions drop) → it strengthens the priority of **T2** (a triage of
  reachable `unwrap/expect`). **The triage is done:** on the network path there are **NO
  reachable panics** — all non-test `unwrap/expect` are infallible on fixed sizes (crypto
  keys, HKDF/HMAC) / startup config (fail-fast) / the send path. The incoming-byte parsing
  path is panic-free by construction. Changing `panic=abort` is not required.

#### The hygiene fixes made

**1. Portability of `set_tcp_keepalive`** (`qeli/src/transport/tcp.rs`). The Linux-specific
`TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT` are now under `#[cfg(target_os = "linux")]`
with a no-op fallback for other targets; the `use AsRawFd` moved inside the Linux branch
(at the top level it would break non-Linux compilation). There was no practical bug (the
crate builds only under Linux/musl, the desktop clients are C#), it's hygiene.

**2. Uniformity of the poisoned lock** (`qeli/src/server/reality.rs`). `reality_borrow` is
read via `read().unwrap_or_else(|e| e.into_inner())` (recover-from-poison, like
`lock_or_recover`/T6), not `expect`. Under `panic=abort` the branch is moot (a panic under
the lock aborts the process before poisoning), but the pattern is now uniform and correct
if the panic strategy changes.

### ⬜ A tuning note (not made)

- **REPLAY_WINDOW=64 for UDP** — the audit's rationale is wrong, but a 64-packet reordering
  window is small for high-bitrate UDP (WireGuard holds ~8192-bit). If sporadic drops
  appear on UDP links — widen it. Not a bug; touching the working anti-replay crypto
  without a proven need isn't worth it.

---

## Status

Made: 2 hygiene fixes (`set_tcp_keepalive` cfg, `reality_borrow` poison-recover). T2 — the
triage is done, there are no targets. The rest — falsehood / by-design / a tuning note.

**Affected:** `qeli/src/transport/tcp.rs`, `qeli/src/server/reality.rs` (Rust).
**Verification:** the common lab gate on .10 — `build`/`test` (188 passed)/`clippy -D
warnings`/`fmt --check` green.
