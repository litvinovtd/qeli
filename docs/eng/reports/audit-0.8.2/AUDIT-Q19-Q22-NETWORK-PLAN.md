# Q19/Q22 audit: shared DNS and route planning

Date: 22–23 September 2026. Baseline: `fc6f4a5dc8df7f119f2d99a6b72b08916ae7a268`
plus uncommitted fixes from earlier passes. Sections 19 and 22 remain **IN_PROGRESS**.

## Scope

Reviewed post-handshake DNS selection, legacy IPv4/v2 parity, configuration precedence,
family/count limits, protected DNS routes, CIDR exclusions and the adapter policy API.
Reviewed Linux routes → DNS → generation publication; Android/iOS/C# consume the shared
NetworkPlan. This is not a complete DNS proxy or OS lifecycle audit.

## Findings and fixes

| ID | Priority | Reproduction and consequence | Fix |
|---|---|---|---|
| Q19-F001 | P2 | An off-subnet legacy IPv4 DNS push in split mode produced no resolver or a fallback, while v2 accepted it. The old subnet check ignored existing DNS host routes. | Both wire forms share DNS selection. Each selected resolver gets a protected `/32` or `/128` tunnel route; broad excludes preserve it, exact DNS host exclusions are rejected. |
| Q19-F002 | P2 | Malformed legacy DNS (`not-an-ip`, `--option`, `IP:port`) silently became an empty list, leaving host DNS active in split mode. v2 failed. | Invalid selected push fails before network apply. Explicit client DNS still overrides push; `off`/`system` ignores it. |
| Q19-F003 | P3 | The legacy planner accepted 9 configured resolvers, while v2 failed immediately. Later NetworkPlan validation already enforced the limit: this was inconsistent early validation, not a demonstrated final-limit bypass. | One validator and `MAX_DNS_SERVERS` cover every source: 8 accepted, 9 refused. |
| Q22-F001 | P2 | Sequential CIDR subtraction exceeded 256 temporary fragments before processing a later broad exclusion. Even a fully excluded route could fail connection setup depending on input order. | Subtract the exclusion union and emit only final disjoint prefixes. Memory/route limits remain enforced; permutations and duplicates cannot change the result. |

Removed obsolete `planned_dns_server`, `setup_dns_for_interface` and the old policy test
from Linux `client/dns.rs`. The large setup copy existed only under `cfg(test)` and had
no callers. Recovery of DNS state written by older releases remains supported. Removed
the separate exclusion-sort workaround from policy API; correctness now belongs to the
shared algorithm. Configuration stays INI; JSON is only a service DTO.

## Verification

Five new regressions failed before the fixes: DNS parity, malformed push, DNS count,
a late broad exclusion and the union of 1024 host exclusions. All pass afterward.
Additional coverage checks all 256 subsets of eight IPv4 and IPv6 hosts, permutations,
duplicates, `/0`, `/32`, `/128`, the exact route budget and a genuinely oversized result.

- Rust: **661 unit + 52 editor/policy + 7 examples + 12 server-INI = 732**, PASS.
- Fresh host Release DLL: **466 C# conformance**, **143 Windows selftest**,
  **154 Kotlin/JVM, 0 skips**, plus **10 direct C ABI probes** — PASS.
- Linux all-targets Clippy passes with the existing Rust 1.98 NDP exception for
  `chunks_exact_to_as_chunks`; minimal FFI passes `-D warnings` without exceptions.
  These are cross-checks, not execution of Linux tests.

Local evidence: `C:/Users/litvi/OneDrive/Documents/qeli/routing-dns-audit-20260922/`.
`before-network.log` records the initial failures; `before/` contains this pass's file
snapshots; `review.diff`, `verification.json` and `RESULT.md` hold changes, results and hashes.

Both manuals and parameter matrices now describe split/full DNS, legacy/v2 parity,
protected host routes, final CIDR limits and Linux per-link systemd-resolved use instead
of newly overwriting `/etc/resolv.conf`.

## Remaining work

- DNS proxy UDP/TCP upstream, truncation, malformed responses, cache and timeout.
- Actual Linux resolved apply/rollback, custom port, attach mode, two profiles,
  SIGKILL/recovery and physical DNS route verification.
- Android/iOS/macOS DNS APIs, reconnect/roaming, sleep/wake and apply failures.
- Concurrent transport-core lifecycle, stale callbacks and handles.
- Platform-native release rebuilds and A/B provenance.

No overall section 19/22 PASS or new benchmark results are claimed.
