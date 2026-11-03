# Q25: Linux route ownership after administrator changes

Date: 24 September 2026. Baseline: `ff4b4187`.
Q25-F099 is fixed within the limits below. D04 remains **IN_PROGRESS**.

## Finding

**Q25-F099, P2 — a matching path incorrectly retained delete/replace authority.**
The matcher compared only attributes supplied to the original `ip route add`. When
`proto`, `metric` or `src` was omitted, adding that attribute did not change ownership.
Scope, MTU or next-hop form changes could also pass. An administrator could replace a
route while keeping destination/gateway/device, then cleanup deleted it or roaming
replaced/retired it. Blackholes had the same problem.

The previous matcher deleted **10 operator replacements** on a real kernel: IPv4/IPv6
protocol/priority/source/MTU changes and two blackholes with `proto static`. Two unchanged
owned controls were also removed as intended. A separate original-binary run with real
server/client, handshake and traffic confirmed that orderly SIGTERM deleted a static
carrier bypass: **15 PASS, 1 FAIL**.

## Change

Usability of a pre-existing route is separate from ownership. A suitable operator route
can still be borrowed without a journal claim. New ownership, cleanup, rollback and
roaming also compare implicit defaults: `proto boot`, metric 0 for IPv4 / 1024 for IPv6,
absence of an unrequested preferred source, IPv4 scope and IPv6 preference. Normal kernel
display forms are supported: hidden IPv4 metric 0, `proto boot`/`3`, IPv6 blackholes with
`dev lo`, and IPv6 not retaining a requested `scope link`. Dynamic `linkdown` alone does
not transfer route ownership.

Unknown additional attributes, MTU, multipath, `nhid`, `onlink`, duplicate or incomplete
fields do not grant delete/replace authority. A replaced physical route is preserved and
the stale ownership entry is released. Unknown mutation outcomes still do not grant
ownership; negative command completion does not prove absence. INI, ABI and wire formats
are unchanged.

## Validation

- **1519 host + 71 config; all 9 feature/cross/lint checks PASS**.
- **2068 Linux + 40 privileged + 8 worker lifecycle PASS**.
- 11 new portable tests cover defaults, protocol, priority, source, scope/preference,
  additional/malformed fields, blackholes, borrowing, cleanup and roaming retirement/replace.
- One new privileged test runs production install/cleanup on the real kernel: 10 changed
  routes must remain and 2 unchanged controls must be removed.
- The counterfactual replaces only the ownership matcher with the former usability check:
  **10 portable FAIL + 1 default control PASS; 1 native FAIL**. Wrapper exit 0 validates
  expected test exit 101; sources are restored and verified before/after.
- Packet matrix: **17/17 cases, 384 assertions PASS**. Existing DNS
  SIGKILL/restart and kill-switch guards remain enabled. `QELI_ROUTE_IDENTITY_CHECK=1`
  additionally changes the carrier bypass to `proto static` before stop in full-tunnel
  cells without DNS and compares real before/after route tables. DNS crash cells cannot
  prove this regression because the original process ownership was already lost.
- The portable kernel model now discards `scope link` on IPv6 add. An initial local
  exploratory run exposed that fixture mismatch; native snapshots and final suites
  validate production behavior.

Source snapshot: 336 files, archive SHA256 `98ecffa7867ca651b4ac2339be1e60dc84b72f422f8d4d3db8c05fd64a652322`.
Worker SHA256: `584a4bd5283ba46f791ace79784c38cc8db7f6c054062eed19461b0289ebda91`.
Baseline worker SHA256: `d15a3fc82c33b7a8da709817e3a85ee43bf5231f88369891ec7bd13b7c9f7c87`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/route-identity-phase/`,
`route-identity-baseline-v1.log`, `route-identity-baseline-runtime-v1.log`,
`packet-matrix-route-identity-baseline-v1/`, `route-identity-final-v1.log`,
`lifecycle-route-identity/`, `packet-matrix-route-identity-v1/`.
Linux Rust 1.97; host Rust 1.98; existing Clippy allowance `chunks_exact_to_as_chunks`.

## Limits

The snapshot check and subsequent command are not atomic. Replacement between them or
identical recreation by another root cannot be distinguished; arbitrary VRF/multipath/
nexthop configurations are not certified. Unrecognized entries are preserved. The
independently owned managed TUN can still have its interface routes flushed: this fix
protects physical bypass/exclude routes and blackholes, and does not promise to preserve
administrator routes placed on a Qeli TUN being removed.

A persistent client route journal **has not been added**: SIGKILL loses process ownership
and physical bypasses/blackholes can remain. Recovery still needs durable intents versus
confirmed ownership, namespace generation, unknown outcomes and overlapping clients.
This step corrects the unsafe matcher before adding that recovery. Legacy global DNS,
live persistent TUN and the mixed firewall matrix also remain open. Network tests use
private namespaces on `.11`; `.10` was unchanged. Windows VM/Mac/iOS/router runtime
remain SKIPPED by user decision.

[Debt register](../../plans/AUDIT-DEBT.md) · [Operations](../../manuals/OPERATIONS.md)

Follow-up: [Q25-F100](AUDIT-Q25-ROUTE-JOURNAL.md) adds durable intent/confirmed state and physical route recovery after SIGKILL. The missing-journal limitation above describes this report’s baseline; the other ownership boundaries remain.
