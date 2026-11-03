# Q25 — standalone kill-switch ownership and reconnect checks

<!-- normative-sync: audit-q25-kill-switch-identity-v1 -->

Date: 24 September 2026. Baseline: `06dd974e`. D03 in the
[debt register](../../plans/AUDIT-DEBT.md); this does not close crash recovery (D04),
operation deadlines (D05) or all external-resource context (D06).

## Findings and fixes

| ID | Problem | Fix |
|---|---|---|
| Q25-F072, P2 | Standalone kill-switch refresh/rebuild/cleanup selected rules by TUN name in the calling namespace. A later call in another namespace could change an unrelated same-name chain. | Pin the original namespace by fd before resolution/waiting. Verify before/after firewall commands, and before accepting success. Retain the owner after failed cleanup; identity loss is sticky for forward operations. Cleanup is allowed after returning to the original namespace. |
| Q25-F073, P2 | Cleanup unconditionally required the IPv4 tool, even after a valid IPv6-only start, but could skip previously touched IPv6 when rediscovery failed. Name-only cleanup had no live owner requirement. | Remember each attempted family/tool before mutation. Clean exactly those families using the recorded tool, fail on unavailable/uninspectable tools, and remove ownership only after verified absence. No owner means no cleanup authority; it does not prove crash residue absent. |
| Q25-F074, P2 | Refresh silently skipped a missing OUTPUT hook; the client logged refresh errors and continued reconnecting. | Before each dial, check OUTPUT and terminal DROP, plus FORWARD for gateway mode. Verification/update failure stops reconnect, reports `kill_switch_failed` / `kill_switch` to post_down and retains remaining protection. |
| Q25-F075, P2 | A failed addition of a replacement server address still allowed removal of the previous address. | Do not withdraw stale addresses in that family unless every replacement addition was verified. Other rule errors remain visible. |

Routes and kill switch share `network_namespace.rs`; there is no second implementation
of the live Linux namespace-fd check. The kill-switch owner does not hold a TUN fd, so
TUN removal/recreation across reconnect does not invalidate protection. The in-memory
owner registry is bounded at 256; it never evicts unresolved cleanup. Leak overrides
cannot bypass namespace identity loss. INI, API and ABI contracts are unchanged.

## Verification

- Eleven new portable tests cover identity loss before/after commands, cleanup retry,
  missing tools, unowned cleanup, missing protection, failed address rotation and IPv6-only stop.
- Two new native tests use fresh network namespaces: public refresh/rebuild/cleanup
  preserve foreign same-name chains; real IPv4/IPv6 ping packets increment ACCEPT for
  the server and DROP for other destinations before/after TUN removal and address rotation.
- Baseline `06dd974e` plus fixtures: **2 expected FAIL** — foreign-chain mutation and
  withdrawal of the previous server allowance after a failed replacement addition.
- Host: **1437 unit + 71 config integration PASS**; nine feature/cross/lint commands PASS.
- Linux: **1885 ordinary + 20 privileged tests PASS**. The two child-process fixtures
  remain excluded from the direct ignored-test run. Final fixture isolation was checked
  separately with the kill-switch subsets and both native kill-switch tests.
- The first Linux pass exposed two old fixtures that installed rules without recording
  an owner; those fixtures now bind ownership explicitly. A later comparison reused a
  baseline executable from the shared Cargo target: that purported fixed result is
  discarded. `cargo clean -p qeli` in the isolated target forced a current-source build.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/killswitch-phase/`,
`killswitch-final.log` (baseline failures), `killswitch-final-fixed.log` (full fixed run),
`killswitch-fixture-final.log` (final scoped rerun), and the final source manifest.
No native GUI packages, platform certification or benchmark were produced in this pass.

## Operational limits

This is live-process authority, not a durable crash journal. A new process still uses
existing admission/recovery rules; legacy or another TUN's chains are preserved for
explicit recovery. Same-name resources cannot be attributed across arbitrary privileged
external replacement, and iptables checks plus mutation are not one atomic transaction.
The saved command path is not a pinned executable/backend identity. DNS resolution,
operation mutex waits and complete command sequences remained D05; the `disengage`
budget is addressed in the [next phase](AUDIT-Q25-KILL-SWITCH-BUDGET.md);
later refresh/engage phases are linked below. Arbitrary
multi-namespace execution in one client process is unsupported; detection fails closed.
Family/address/rule changes by an external administrator require coordinated recovery.

[Operational instructions](../../manuals/TROUBLESHOOTING.md#656-linux-kill-switch-identity-or-reconnect-verification-failed).

Linux test binary SHA256: `805ae05534408637e5295370b38f5e786717e5b7a12f086f9a77dc659cbff544`.

Next phase: [shared refresh deadline and unknown inspections](AUDIT-Q25-KILL-SWITCH-REFRESH.md). The refresh command sequence is addressed within the stated limits; [setup and rollback](AUDIT-Q25-KILL-SWITCH-SETUP.md) are addressed by the following phase. Synchronous DNS/NSS remains open.

Follow-up: [Q25-F098](AUDIT-Q25-KILL-SWITCH-REBUILD.md) fixes the crash-rebuild leak window. Exact temporary DROP guards survive failure/repeated SIGKILL and retire after replacements are ready; the earlier limitations describe the historical snapshot. Overall deadlines, external firewall writers and remaining D04 criteria stay separate.
