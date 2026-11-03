# Q30: provider ownership, stop/start and late OS completions

<!-- normative-sync: q30-ios-lifecycle-v1 -->

6 October 2026. Scoped source fixes F295–F297. Q30 IN_PROGRESS; no iOS runtime
qualification, native-worker join or whole-section completion is claimed.

## F295: a suspended start could resurrect the path monitor after stop

The engine awaited physical DNS before starting a lazy roaming controller. Stop
could run during DNS, cancel the controller and mark the engine stopped, but the
resumed start could start its monitor again before network-settings validation
rejected the stopped engine. Repeated stop then returned early. Concurrent access
to the lazy controller also did not guarantee one controller instance.

The engine now constructs one controller eagerly without a self-reference and
binds its weak engine when starting. A single-use lifecycle makes stop terminal,
including stop-before-start. Late path callbacks/arm are rejected after stop.
Start checks cancellation/stopped ownership before and after suspended stages.
Provider catch paths always stop their own partially started engine, including
obsolete generations; they never clear another engine. Completed start tasks are
not retained if their completion owner has already been cleared.

## F296: local stopped/generation checks did not fence provider-wide effects

Network settings checked a generation, then later published facts without repeating
that check in the publication transaction. Constructors and old engine stop/stats/
terminal callbacks wrote the shared snapshot directly. An obsolete engine could
also toggle provider reasserting, cancel the provider or write packets belonging
to the old connection after replacement.

The provider now admits snapshots, reasserting/cancel, network-settings requests
and packet reads/writes only from its current engine under its lifecycle lock.
The recursive lock supports synchronous API reentry. Installation reads the engine
snapshot before taking the provider lock, avoiding lock inversion. Packet callback
handoff runs in the already-required release task before releasing its lease, so
an OS callback does not take an engine lock while admission holds the provider lock.
Both network-fact branches recheck stopped/request generation while mutating facts;
activePlan installation additionally checks native identity. Delayed statistics,
Connected publications, pump installation and downlink writes also match the current
native handle and plan generation inside the engine state transaction, including
reconnects that reuse the same engine. Start-failure and final
stop publications are generation-fenced. Constructors do not publish before install.

The engine retains its provider until Swift workers finish; stop/replacement clears
the provider's engine reference to break the installed-owner cycle. This prevents
an old worker's unowned-provider dereference. Cancellation remains distinct from
joining every worker or receiving a non-cancellable OS callback.

## F297: per-engine gates and timeout release permitted overlapping OS operations

Read/settings gates previously belonged to each engine. A replacement could issue
a second read while the old non-cancellable read was pending. Settings timeout
released admission even though the old OS apply could still complete later and
replace a newer route set. The cached successful fingerprint could then describe
settings that a late apply had already changed.

Two provider-wide operation gates serialize settings and packet reads across
engines. Queued waiters are cancellable; settings queue plus OS wait share the
existing 15-second budget. Lease identity rejects duplicate/old release calls.
After an OS request is issued, timeout/cancellation resumes Swift but only its real
callback releases admission. Before issuing an apply, the old fingerprint is cleared;
only a current successful result restores it. A timed-out apply can no longer make
an old cached fingerprint count as proof of current system settings.

A shared AsyncResultCompletion replaces duplicate settings/DNS completion classes.
It retains the original success/error when finish precedes park, so cancellation
introduced by the new handler is not relabelled as timeout. Exactly-once completion
and late-result rejection remain explicit.

## Checks and limitations

Thirteen new XCTest: six operation-gate cases (FIFO, waiter timeout/cancellation,
stale release, zero budget and precancelled admission), three single-use lifecycle
cases and four completion-order cases. They exercise production helpers; NOT_RUN.
Swift compilation, actual PacketTunnel replacement/stop, shared gates with real
readPackets/setTunnelNetworkSettings callbacks, synchronous reentry, memory/lifetime,
leak behavior, simulator and signed IPA are NOT_RUN. Windows has no Swift/Xcode;
a read-only probe also found no Swift on Linux lab .11. No toolchain installed and
no lab services/network state changed. Apple runtime remains user-excluded.

Six Python IPA-verifier fixture regressions, ten XML structural reads, documentation
(all nine checks), generated config bindings and diff checks PASS. These do not
prove Swift syntax or actual Apple API behavior. Rust/native/Android and other
client Git inputs retain their previous hashes; runtime matrices were not repeated.

If the OS never returns a pending callback, its gate deliberately stays occupied;
settings waiters report timeout and packet-read waiters remain cancellable. Whether
real iOS reliably drains those callbacks across stop/start is an OPEN platform
qualification, not an accepted success/automatic unlock or a newly hidden limitation.
No claim that stop completion joins every runner or removes every pending OS action.
Remaining source review includes app/UI/settings/provider-message ownership and
whole-section memory/dead-code reconciliation.

Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q30-ios-lifecycle-20261006.
Evidence: release/certification/evidence/q30-ios-lifecycle-20261006.json.
Overall28/37 DONE/PASS(75.7%),9 remain. Q29 SIGKILL FAIL/auto-null ENONET, D06 and
user platform skips unchanged. Q30 IN_PROGRESS.
