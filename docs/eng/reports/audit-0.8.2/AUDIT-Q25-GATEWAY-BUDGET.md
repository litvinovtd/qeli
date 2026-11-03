# Q25 — shared gateway/exit-node operation deadline

<!-- normative-sync: audit-q25-gateway-budget-v1 -->

24 September 2026. Base: `68983ac2`. Partial D05/D09 closure.

## Q25-F091, P2 — per-command timeouts did not bound a router plan

Blocking `ROUTER_OPERATION.lock()` could wait indefinitely, while each discovery, WAN
and IPv4/IPv6 firewall command received a fresh 15 seconds. A slow backend could delay
shutdown or rollback across the entire sequence.

Each public setup, refresh and cleanup attempt now shares 15 seconds across router
mutex admission, firewall discovery, WAN route queries and iptables/ip6tables probes and
mutations. Cleanup shares it across gateway rules, remembered exit WANs, both families
and sysctl callback boundaries. Late results do not establish success; no new command
starts after expiry.

The deadline belongs to the attempt, not the retained owner. Partial rules, subnet/WAN
selectors and sysctl ownership remain for a fresh verified cleanup. Existing generation
cleanup performs rollback after failed setup with a new deadline; engage does not gain a
hidden rollback. Inactive exit refresh remains a no-op. Namespace/TUN checks and firewall
classification stay strict; binary lookup and Qeli-chain extraction are shared with kill-switch.

## Validation

5 portable + 1 Linux regression: expired/busy admission without host I/O; late NAT ack
retaining a partial plan; shared IPv4/IPv6 cleanup deadline; late WAN response without
new rules; expired context; real `sleep 5` child terminated at 120 ms (2-second external
test allowance). Firewall/sysctl tests use an isolated model; the process test touches no
host networking.

**1484 host unit + 71 config**, all 9 feature/cross/lint checks PASS.
**2001 ordinary Linux + 32 privileged + 8 worker lifecycle E2E PASS**.
Disabling deadline checks and restoring per-command timeouts reproduces **6/6 FAIL**;
byte-restored sources pass **107 gateway tests**. All 320 source hashes verified before
and after full and counterfactual runs.

The first host regression omitted Windows PATH discovery from its expected command count;
corrected rule-operation counting passes. The first Linux attempt stopped before compilation
because the lab still held the previous source manifest; the exact manifest then passed and
the complete run succeeded. Both preparation logs are retained. Linux Rust 1.97, host 1.98;
existing Clippy `chunks_exact_to_as_chunks` allowance.

Debug worker SHA256: `1a08fceb53e76d9931927a56ab1751bf6fa8d0a057f16398f78ce5fcda0aafd8`.
Source archive SHA256: `4ac2dbae65e440b872ff4a15222e12e60927c238d955ce02872fd448ff12d3a7`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/gateway-budget-phase/`,
`gateway-budget-final-v2.log`, `gateway-budget-counterfactual/`, `lifecycle-gateway-budget/`.
Private namespaces on lab `.11`; live `.10` unchanged.

## Limits

This bounds commands and router mutex admission, not complete shutdown to 15 seconds.
Synchronous filesystem/sysctl I/O and internal route/sysctl locks are not preempted by this
wrapper; late results are rejected after returning. NetworkPlan contains multiple operations.
Whole route-sequence deadlines and executor isolation remain D05; persistent crash recovery
remains D04; full packet/fault/resource coverage remains D09/D10/D13. User configurations
remain INI, with no new keys. Windows VM/Mac/iOS/router runtime excluded by user decision.

[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/CONFIG.md)
