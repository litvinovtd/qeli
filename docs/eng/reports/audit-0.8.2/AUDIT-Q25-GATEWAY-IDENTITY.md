# Q25: gateway ownership during setup, roaming and cleanup

Date: 24 September 2026. Baseline: `ac86c442` (work started on 23 September).
Q25-F067–F068 are fixed within the stated boundaries. Sections 21/22/25 remain **IN_PROGRESS**.

## Findings

**Q25-F067, P2 — gateway commands continued after losing the original TUN/namespace.**
Route checks around a roaming callback did not protect operations inside it. Gateway/exit
entry points received only a name, allowing firewall and sysctl setup to continue after
external rename/delete or namespace changes. Identity loss during best-effort MSS/rp_filter
could still return success. Initial setup of both families had the same gap. The normal
callback does not call setns; fault injection tests environmental changes rather than
claiming that normal reconnect performs setns.

**Q25-F068, P2 — gateway cleanup lacked generation and TUN lifetime ownership.**
Rules and sysctls survived full reconnects. Terminal cleanup by name happened after the
session and its TUN had been released. It did not verify the original namespace, while
per-interface sysctl restoration could address a replacement with the same name.
Successful route cleanup alone did not retain the generation for remaining router resources.

## Changes

Gateway binds the original RouteOwner before its first mutation. Its registry retains the
generation/namespace until confirmed cleanup; Weak TUN evidence does not keep the fd alive.
Unfinished cleanup prevents a new owner using that name. Partial setup and TunGuard clean
only a matching owner; terminal retries by name use retained ownership. An absent record
authorizes no cleanup.

Active gateway/exit operations check the original TUN, name/index, pinned namespace and
generation admission before/after each firewall query/mutation and WAN lookup. Sysctl checks
surround the shared journal call, not each internal I/O. A final check prevents best-effort
MSS/rp_filter from masking identity loss. Cleanup closes admission; restored evidence permits
cleanup retries, never renewed setup by the stopped generation.

Deleting recorded tagged gateway/exit rules requires the original namespace before/after
each command and can proceed without the TUN. Failed/uncertain family records remain
retryable. Loss of TUN defers restoration of the entire sysctl scope, including shared
forwarding/rp_filter: the journal also holds per-interface values that cannot safely be
restored by name alone. This is a conservative refusal, not automatic full host recovery.

TCP/UDP graceful cleanup, emergency TunGuard and partial-plan rollback now clean router
state before closing the original fd. Full reconnect creates a new owner and reinstalls
rules. Roaming within a generation retains its old WAN rules until that generation ends.
An enabled kill-switch continues across reconnect under its existing contract. Cleanup
errors remain sticky and prevent successful completion/reconnect. With router features,
`dev_attach=true` also binds the original fd; the external owner's addresses/routes do not
become Qeli-owned. Attach without router features does not require this bind.

## Validation

Nine regressions reproduce failures on an isolated copy of `ac86c442` (**9 FAIL**) and
pass after the fix (**9 PASS**). The baseline adapter only adds fault injection, inert
synthetic evidence and a Result wrapper around the unchanged void rp_filter API; it does
not change firewall/sysctl decisions. Cases cover admission, loss after query/sysctl/MSS,
roaming WAN lookup, cleanup namespace loss before/after deletion, and independent rule
cleanup with a missing TUN while retaining sysctls.

Four further tests use the actual RouteOwner with explicit synthetic TUN evidence:
unbound production owners refuse binding; reservations outlive callers until cleanup;
failed cleanup retains the generation; stopped owners reject setup but permit cleanup.
Production has no synthetic authorization fallback.

**1414 host unit + 52 editor/policy + 7 examples + 12 server INI = 1485 Rust tests PASS.**
The 13 new host tests are included. One ignored fixture is a DNS-lock child explicitly
run by its parent test. Nine matrix commands and Linux no-default-features test compilation
are checked separately; the existing Clippy allowance was not expanded. RU/EN docs gate PASS.

Linux E2E was not run. The earlier seven native route identity and seven TUN ioctl tests
were only compiled here. Real firewall/sysctl/namespace and physical reconnect behavior
still need an isolated Linux lab. No benchmark was run.
Artifacts: C:/Users/litvi/OneDrive/Documents/qeli/gateway-identity-audit-20260923.

## Limits and next work

Observation and external commands are not atomic. Rename/delete/move/reuse after the last
check remains possible. For sysctl, the window includes waiting for the shared journal lock
and internal read/prune/write operations. This pass does not redesign that backend, its
crash recovery or physical WAN identity. After process death, stale journal and firewall
recovery need separate review; this registry does not establish their safety.

Gateway ownership is in memory, not a durable journal; it retains the namespace until
cleanup or process exit. Do not drop reservations or delete sysctls.state just to bypass an
error. First establish owners and actual state. Shared sysctls can remain enabled after
losing the original TUN.

Next: sysctl internals (stale owners, namespace and interface-name reuse), then the independent
kill-switch lifecycle. Resolver service/bus namespace, procfs/sysfs trust, parser/backend
names, deadlines, dynamic IPv6, DNS/carrier globals, Q14-F027 workers/FD, native certification
and a new benchmark remain open. Plan: 37 sections, 19 IN_PROGRESS, 18 TODO, no full PASS.
