# Q25: propagate TUN, route and DNS cleanup failures

Date: 23 September 2026. Baseline: `85cbf8fa`. Sections 14/19/25: **IN_PROGRESS**.

## Findings

**Q25-F007, P1 — resource cleanup faults could become a clean signal stop or reconnect.**
TCP/UDP graceful teardown returned DNS/route/TUN errors as ordinary connection errors.
The shutdown-signal branch used that result only for hook text, then returned firewall
cleanup success and released the kill-switch. TunGuard and NetworkPlanApplyGuard failures
were only logged, so early-return rollback faults were invisible to the outer retry policy.

LinuxCoreAdapter and its guards now share one in-memory failure record. Explicit DNS/route/
TUN cleanup and partial-plan rollback record their errors before returning or logging them.
After the connection future and its local guards finish, the outer loop checks that evidence
along with core teardown, before signal-success and reconnect branches. Any recorded fault
is terminal: forwarding cleanup is still attempted, but an enabled kill-switch is retained.
The original connection error and cleanup causes remain visible in the returned error.

The record retains the first error for each of DNS, routes, TUN and forwarding/NAT, at most
2048 Unicode characters per category. It belongs to one client run and is never reset between
attempts. A successful fallback retry cannot erase an earlier reported failure; this is a
conservative stop policy, not a claim that the retry failed. Independent clients have separate
records. Disabled kill-switches are not touched or described as retained.

**Q25-F008, P2 — the applied TUN had no resource guard before core ACK.**
setup_tunnel disarmed its local rollback guard before returning. The data-plane guard was
created only later, after core ACK/event processing and the awaited post_up hook. An error
or cancellation in that gap could drop descriptors without restoring DNS/bypass routes.
TunnelSetup now owns TunGuard before it leaves setup; TCP/UDP take that same guard when
starting their pump. Normal teardown disarms it only after cleanup succeeds. Attach-mode
ownership remains explicit: borrowed interfaces/routes are not deleted by this guard.
This closes the resource-ownership gap; it does not prove all async task shutdown behavior.

**Q25-F009, P2 — cleanup error could hide a terminal server kick.**
Both data planes returned cleanup errors before constructing ServerKickError. A kick with
reconnect_allowed=false could lose its type and enter ordinary retry handling. They now
combine the typed kick with cleanup errors, preserving its downcastable policy and message.
A recorded cleanup fault is itself terminal even when the server would otherwise allow retry.

post_down adds reason/code `network_cleanup_failed`/`network_cleanup`. Core-stop failure
has higher reason priority when both fail; the combined error still contains both causes.
No INI keys or native ABI changed. Operator hooks can independently change firewall rules;
this policy does not constrain those scripts or remove deliberate crash/SIGKILL protection.

## Validation

Eight new host regressions cover terminal cleanup policy, sticky retry evidence, late old-
guard reports, Drop/unwind reporting, bounded storage, concurrent resource failures, actual
ServerKickError preservation, and reason priority/disabled protection. Two Linux adapter
fault-injection tests cover rejected core ACK and partial-apply rollback using test values;
they are cross-compiled only and use no live TUN/firewall mutations.

**850 host unit + 52 editor/policy + 7 examples + 12 server INI = 921 Rust tests PASS.**
Linux all-targets Clippy, client-only, server-only, minimal FFI, rustfmt, nine docs checks and
diff checks pass. Existing chunks_exact_to_as_chunks allowance and 23 server-only transport
warnings remain. Evidence: C:/Users/litvi/OneDrive/Documents/qeli/tun-cleanup-audit-20260923.
No live Linux E2E, DNS/firewall changes, SSH, systemd restart, Actions or benchmark was run.

## Remaining work

Joining every TCP/UDP generation task, synchronous command deadlines and real Linux fault
injection remain open. The record observes reported cleanup errors; it is not a kernel-state
verification or a substitute for joining background work. Forced cancellation of the entire
client and SIGKILL still cannot promise final status or hook delivery. Other OS adapters and
legacy DNS recovery concurrency require their own audit; the full audit remains in progress.

Follow-up: [TCP and Linux path workers](AUDIT-Q25-TCP-TASKS.md) adds closed admission and task joining on normal teardown. Full UDP ownership and forced cancellation still need auditing.

Follow-up on 23 September: [Q25-F016/F017](AUDIT-Q25-SYSTEM-COMMANDS.md) bounds
TUN/resolvectl commands and tests DNS-marker retention on errors. Route/firewall commands
and an overall shutdown deadline remain open.

Follow-up: [Q25-F059–F060](AUDIT-Q25-TUN-LIFETIME.md) removes name-based TUN deletion and retains original descriptors through cleanup. DNS/route identity during external replacement and worker timeout remain open.

Follow-up: [Q25-F105](AUDIT-Q25-NETWORK-TASK.md) moves NetworkPlan application and unadopted-result rollback to a joined worker. Established-tunnel cleanup remains separate D05 work; historical results above are retained.

Follow-up: [Q25-F106](AUDIT-Q25-TUN-TEARDOWN.md) shares graceful established TCP/UDP tunnel teardown on a joined worker. Early error/Drop fallback and overall D05 remain open; historical results above are retained.
