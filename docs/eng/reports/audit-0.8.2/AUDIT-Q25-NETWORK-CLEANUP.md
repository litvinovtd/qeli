# Q25: retain the kill-switch when forwarding cleanup fails

Date: 23 September 2026. Baseline: `7ab16ac7`. Section 25: **IN_PROGRESS**.

**Q25-F003, P1 — failed NAT cleanup still released the egress barrier.**
cleanup_routing_features attempted gateway/exit-node cleanup, saved an error and then
unconditionally attempted kill-switch removal. The comment promised fail-closed order,
but merely calling forwarding cleanup first did not require it to succeed. Residual
forwarding/NAT state could remain after the client opened host egress.

The cleanup policy now invokes kill-switch removal only after forwarding cleanup
succeeds. A failure returns the original cause plus an explicit `kill-switch retained`
reason. Existing stop, server-kick and retry-limit paths all use this policy. When the
kill-switch is disabled, no barrier operation or retention claim is made. Failure of
the barrier removal itself remains an error; it is not falsely described as retention
because removal may already have partially succeeded.

This changes ordinary error cleanup. The existing intentional persistence after a
crash/SIGKILL is preserved; no unconditional Drop cleanup was added. A retained barrier
can keep the host restricted until the underlying failure is resolved and cleanup or
administrator recovery succeeds. Configured post_down scripts remain operator-controlled
and can make their own firewall changes outside this policy.

## Validation

Four new portable fault-injection tests exercise failed forwarding with the barrier still
installed, successful order, a barrier-removal error and disabled-barrier behavior.
They model cleanup results and calls, not real packet filtering.

**828 host unit + 52 editor/policy + 7 examples + 12 server INI = 899 Rust tests PASS.**
Linux all-targets Clippy passes with the existing chunks_exact_to_as_chunks exception in
unchanged ndp_proxy.rs. Client-only, server-only and minimal FFI checks pass; server-only
retains 23 unchanged transport dead-code warnings. Rustfmt, diff and nine docs checks pass.
No live firewall/routes, external SSH, systemd restart, GitHub Actions or benchmark was run.

Evidence: C:/Users/litvi/OneDrive/Documents/qeli/network-cleanup-audit-20260923.

## Remaining work

The begin_connection error path after kill-switch engagement still needs explicit audit;
this patch does not claim complete network rollback. Retaining an already-installed
barrier is not proof that every kernel rule exists or that external actors leave it intact.
Linux fault-injection/E2E, nested task ownership and the wider audit remain open.

Follow-up: [core lifecycle audit](AUDIT-Q25-CORE-LIFECYCLE.md) handles the early startup error path and makes failed core teardown terminal. Full route/DNS rollback and live Linux E2E remain open.
