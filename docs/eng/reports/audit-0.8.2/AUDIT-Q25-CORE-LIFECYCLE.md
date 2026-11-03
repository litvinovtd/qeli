# Q25: core lifecycle failures must reach terminal cleanup

Date: 23 September 2026. Baseline: `3fc5bf8b`. Sections 14/25: **IN_PROGRESS**.

## Findings and changes

**Q25-F004, P2 — core startup error bypassed client cleanup and post_down.**
After kill-switch setup, the retry loop used `begin_connection(...)?`. A returned error
exited directly through status finalization, skipping forwarding cleanup and the terminal
hook. Startup failure now enters an explicit terminal path, attempts core stop and routing
cleanup, invokes the authorized post_down once and returns failure. It never dials or enters
reconnect after the failed begin. If subsequent core and forwarding cleanup succeed, the
kill-switch can be released; cleanup success does not erase the original startup failure.

**Q25-F005, P1 — failed core teardown could become a successful stop.**
finish_connection errors were logged and ignored. The loop could then release the kill-switch,
report clean signal shutdown or enter reconnect. ClientCore::stop can return EventQueueFull:
cancellation is requested, but its state and remaining teardown are not completed until the
caller handles queue backpressure. A portable regression fills a real two-slot core queue
with Created/Connecting events and confirms that stop fails while state is still Connecting.
This is a controlled core-API fault reproduction, not evidence that a normal first Linux
connection fills the default queue or that a remote peer can trigger it.

A teardown error now terminates the client with failure, ahead of signal-success/reconnect
branches. Gateway/exit-node cleanup is still attempted; an enabled kill-switch is retained
unless both core and forwarding cleanup succeed. Disabled protection is neither touched nor
claimed. Combined errors keep startup/carrier and cleanup causes visible; primary typed errors
remain downcastable. A core error includes event-drain errors even if stop already changed the
state: retention is deliberately conservative when adapter teardown cannot be confirmed.

post_down receives reason/code `core_start_failed`/`core_start`, or
`core_stop_failed`/`core_stop`. Stop failure takes precedence if both fail. Hooks remain
operator-controlled and may change firewall rules independently. No new INI keys, ABI changes,
unconditional Drop cleanup or automatic core-stop retry were introduced. Crash/SIGKILL
persistence remains unchanged. A retained barrier may require administrator recovery.

## Validation

Six new host regressions cover actual core queue backpressure and explicit recovery,
combined core/forwarding errors, startup failure with successful or failed cleanup,
disabled kill-switch and preservation of primary error types.

**834 host unit + 52 editor/policy + 7 examples + 12 server INI = 905 Rust tests PASS.**
Linux all-targets Clippy, client-only, server-only and minimal FFI checks pass; Clippy keeps
the existing chunks_exact_to_as_chunks exception in unchanged ndp_proxy.rs, and server-only
keeps 23 existing transport dead-code warnings. Rustfmt, diff and nine docs checks pass.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/client-lifecycle-audit-20260923.

The host tests exercise real ClientCore state and injected routing callbacks. The Linux
adapter branches were reviewed and cross-compiled; they were not executed on Linux. No live
firewall, VPN E2E, external SSH, systemd, GitHub Actions or benchmark was run.

## Remaining work

Route/DNS cleanup errors in lower-level resource guards, firewall subprocess deadlines,
Linux lifecycle fault injection and nested task ownership still need audit. This pass does
not prove complete kernel-state rollback or availability after an uncertain teardown.

Follow-up: [TUN cleanup audit](AUDIT-Q25-TUN-CLEANUP.md) propagates explicit resource and rollback-guard failures to the client stop policy. Live Linux E2E and complete task shutdown remain open.
