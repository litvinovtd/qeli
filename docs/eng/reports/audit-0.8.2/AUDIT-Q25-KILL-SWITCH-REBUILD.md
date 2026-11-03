# Q25 — kill-switch protection across crash restart

<!-- normative-sync: audit-q25-kill-switch-rebuild-v1 -->

24 September 2026. Base `5e1c980f`. Partial D04/D09/D10 closure.

## Q25-F098, P1 — rebuilding removed the prior barrier

Kernel `QELI_KS_<tun>` chains survived process loss. A subsequent `engage` first
removed their OUTPUT/FORWARD jumps and chains, then built replacements. Packets
could reach the physical default route in that interval. A failed IPv6 DROP setup
rolled back both families and left the host without its previously installed protection.

On the original code, a native regression that discarded process-local ownership and
sent packets after each mutation observed WAN counters **[0, 0] → [19, 16]** (IPv4/IPv6).
A separate real client after SIGKILL and a failed IPv6 DROP observed **[8, 14] → [22, 27]**:
14 IPv4 and 13 IPv6 UDP probes reached the permissive WAN rule. The replacement client
exited with an error, but that alone did not retain protection.

## Change

Before removing prior chains, exact temporary DROP rules carry the comment
`qeli-ks-rebuild:<tun>` in OUTPUT and, for previous/requested forwarding or a surviving
FORWARD guard, FORWARD. Both available families complete this stage before either
is rebuilt. `-C` verifies command results; a missing guard never authorizes deleting
the inherited chain. A foreign recovery guard blocks admission even without a normal chain.

Rollback touches only ordinary chains whose rebuilding actually started. It never
removes guards. Failure, timeout or another SIGKILL retains the barrier; neither
`allow_ipv4_leak` nor `allow_ipv6_leak` accepts failed replacement of prior protection.
Guards retire only after every required family is installed. Failure at this last
stage preserves the new ordinary chains: after IPv4 guard removal, failed IPv6 guard
cleanup must not roll back the already working IPv4 barrier. A same-TUN restart can
recover guard-only state. An explicit clean stop removes ordinary chains followed by
exact guards, preserving unrelated rules.

These are deliberately strict temporary DROP rules: before a new ruleset is reachable,
previous allowances including DNS/loopback may be blocked. After failed rebuilding,
startup with a server hostname may fail during resolution. Use a verified server IP
or administrator recovery after stopping the owner. `Kill-switch ENGAGED` is logged
only after guard retirement completes.

## Validation

- **1508 host + 71 config; 9 feature/cross/lint checks PASS**.
- **2057 Linux + 39 privileged + 8 worker lifecycle PASS**.
- 2 portable admission regressions and 2 privileged scenarios cover packets throughout
  setup/rollback, no-op guard insertion, failed second-guard retirement, leak-flag refusal,
  guard-only recovery and preserved operator rules.
- Native baseline: expected test exit 101; wrapper exit 0 verifies the expected FAIL.
  That regression explicitly models owner loss; the next runner uses actual SIGKILL.
- `scripts/audit_kill_switch_recovery.py`: **14 checks PASS**; a real client, SIGKILL,
  failed IPv6 DROP, another SIGKILL during rebuilding, retry, clean stop and UDP counters
  after each firewall mutation. A wrapper invokes real iptables-nft; a server/handshake
  is not required and is not validated by this scenario.
- Final worker packet matrix: **17/17 cases, 339 assertions PASS**, including DNS SIGKILL/restart.
- The first full Linux run is retained as `ks-rebuild-final-v1`: the old five-command
  cleanup assertion omitted guard checks; the fixture now verifies first-family completion
  and no further second-family commands after the deadline. Another failure was an immediate
  zero-timeout lock retry after drop. Retry now permits 1 second: a parallel fork can
  briefly retain an inherited fd until exec. Contention/zero-timeout with a live owner
  remain tested. Production FileLock is unchanged; the final run is v2.

Source snapshot: 335 files, archive SHA256 `bb66e3694a2586dd935df2ed7fc99c30a7ce6752a032acc7be278f6f80350d86`.
Worker SHA256: `d15a3fc82c33b7a8da709817e3a85ee43bf5231f88369891ec7bd13b7c9f7c87`.
Baseline worker SHA256: `88af383f121304b8e3b7d40b89e62ff22088aa624004ccfbc25b76f8ed8782b2`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/ks-rebuild-phase/`,
`ks-rebuild-baseline-v1.log`, `ks-rebuild-baseline-runtime-v1/`, `ks-rebuild-final-v2.log`,
`ks-rebuild-fixed-runtime-v1/`, `lifecycle-ks-rebuild/`, `packet-matrix-ks-rebuild-v2/`.
Linux Rust 1.97; host Rust 1.98; existing Clippy allowance `chunks_exact_to_as_chunks`.

## Boundaries

Recovery requires the same network namespace, TUN name and firewall backend. Chain
names and `qeli-ks-rebuild:*` are reserved for Qeli: cooperative ownership does not
prove ownership against root deliberately creating identical rules. Backend changes,
arbitrary nft/firewalld policies and external changes between check and command are
not certified. The cross-family transaction is not atomic; temporary loss of access
is acceptable, removing the existing barrier before its replacement is ready is not.
Setup and separate rollback still have 15 seconds each; DNS/NSS and internal I/O have
not become interruptible. First installation without a prior barrier makes no claim
of blocking traffic from process launch. No new INI keys, ABI or wire changes.

D04 remains IN_PROGRESS: client routes, legacy global DNS, live persistent TUN and
the full mixed-firewall matrix need further work. All network checks ran in private
namespaces on `.11`; the live `.10` server was unchanged. Windows VM/Mac/iOS/router
runtime remain SKIPPED by user decision.

[Debt register](../../plans/AUDIT-DEBT.md) · [Troubleshooting](../../manuals/TROUBLESHOOTING.md)

Additional v2 matrix enables `QELI_DNS_KILL_SWITCH=1` with `QELI_DNS_CRASH_CHECK=1`: both DNS4/DNS6 cells check real tunnels, retained kill-switch after SIGKILL, restored DNS/protection and retired guards. The v1 control matrix without enabled kill-switch in these cells also passed 17/17 and 323 assertions. The fixed runtime runner preserved WAN counters **[8, 14] → [8, 14]**.

Final D04 follow-up: [client mixed packet/recovery matrix and Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) completed; D04 is DONE in the current register. Historical IN_PROGRESS statements above refer to earlier snapshots. D10 (broader policies/topologies) and D13 (state growth) remain open.

Follow-up: [Q25-F107/F108](AUDIT-Q25-FIREWALL-TASK.md) moves firewall operations to joined workers and prevents flushing a chain when hook removal is unconfirmed. Historical results above are retained; overall D05 remains open.
