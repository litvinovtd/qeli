# Q25-F102: legacy-table advice prevented client startup

24 September 2026. D04/D09/D10; shared client/server `firewall_check`.

## P2 defect and fix

With nft and legacy rules present simultaneously, real iptables 1.8.11 reports:

```text
# Warning: iptables-legacy tables present, use iptables-legacy to see them
iptables: No chain/target/match by that name.
```

For `-S QELI_KS_<dev>`, this is exit 1 with an explicit missing-chain diagnostic.
The previous shared classifier rejected every additional line. A new client with kill-switch therefore
aborted before TUN/handshake even though the selected backend was functional. Smoke v1
reproduced this on the previous `3f52a9d5…` worker with IPv4=nft, IPv6=legacy and real
firewalld. No leak was demonstrated: this is an availability/recovery defect, not evidence
that previous protection failed open.

Only the two exact advisory lines for `iptables-legacy` and `ip6tables-legacy` are now
ignored. A valid exit and explicit recognized absence diagnostic are still required;
chain names still match exactly. Advice alone cannot establish absence. Unknown warnings,
permission/backend errors, `Parsing nftables rule failed`, additional errors and exit 3
remain failures. Configuration remains INI; the configuration format is unchanged.

## Real packet verification

`audit_client_mixed_matrix.py` runs the existing release matrix inside fresh NET/mount/PID
namespaces. `ipv6_netns_case.sh` adds optional lifecycle hooks, and
`audit_client_mixed_firewall.py` probes the real client firewall. Each cell creates separate
client/router/server NET namespaces. Per-family selection executes real xtables multi-call
binaries; responses are not fabricated. Both backend snapshots use saved original executables.

All full tunnels enable kill-switch; split controls retain direct access. Coverage includes
TCP fake-TLS, UDP fake-TLS/QUIC, outer/inner IPv4/IPv6, split, TAP NDP/RA, DNS A/AAAA through
real systemd-resolved and IPv4/IPv6 upstreams, MTU/PMTU/PTB. Existing route/DNS recovery and
a fresh process follow SIGKILL. Operator rules exist in both families of both backends and
in a separate native inet table. Firewalld uses a private D-Bus, nftables backend and
`DefaultZone=trusted`; it reloads with the tunnel active and after SIGKILL.

At each stage, UDP sockets explicitly bind to the physical interface and send four packets
per family to the adjacent router. This is not an unreachable destination behind a leftover
blackhole: all responses must arrive before VPN and after graceful shutdown; with protection
active, real DROP counters must increase and the receiver must see no packets. Snapshots
verify foreign-rule preservation across setup/crash/recovery/stop and full ruleset
preservation across firewalld reload.

## Results

**8/8 backend/firewalld combinations, 136/136 release-matrix rows = 152/152 network
cells PASS.** These include 136 SIGKILL/recovery cases, 4880 main assertions
and 3224 detailed nested checks (not independent tests; do not add the counts).
All 4352 direct UDP attempts under protection were blocked. All 2624
allowed probes received replies. An additional evidence check excluded route/socket
errors from blocking proof: denied probes reported only EPERM and counters increased.

Host: **1528 unit + 71 config integration**, all nine feature/cross/lint gates PASS.
Linux: **2080 ordinary + 43 privileged + 8 worker lifecycle PASS**. Shared negative
regressions cover warning-only/unknown/error/exit3. Server mixed tests reran on the new
worker: **16/16 scenarios, 476 checks PASS**, including native parse failures and manual
recovery. Scripts: bash syntax, Python compilation and 8 existing matrix contract tests PASS.

Lab `.11`: Linux 6.12.105+deb13-amd64, iptables 1.8.11, nftables 1.1.3; privately
extracted firewalld 2.3.1. Four isolated groups ran concurrently. Working server `.10`
was unchanged. Benchmark and platform certification were not updated. All 340 Rust/
conformance files and 16 scenario files match the current tree. Base `05b8a05f` plus
`firewall_check.rs` changes; the manifest records the exact snapshot.
Worker SHA256: `cf0af9429d061ac491f0c1c566c6429ee3cf5fce39bd20c755be1b48bf0f5eb7`.
Source archive SHA256: `4007b16e3838e89e2cb594cf0fd1818f3e84d0a0bf75accbccbb3c1d28907c64`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/client-mixed-phase/`,
`client-mixed-matrix-v1/`, `mixed-firewall-regression-v1/`, `lifecycle-client-mixed/`
and their `.tar.gz` archives. Logs/exits: `client-mixed-matrix-v1`,
`mixed-firewall-regression-v1`, `client-mixed-linux-final-v1` (`.log/.rc`).
Commands: `matrix.sh`, `server-regression.sh`,
`linux-final.sh`, `run_checks.py`; results/hashes: `evidence.json`, source/scripts manifests.
Client archive SHA256: `142756ce52d8d00302a31a96bbaade16c77c874532b717e10fde18a5a955b1b0`.

Smoke v1 reproduces the defect on the old binary. In v2 the fixed client works, but the
snapshot comparison incorrectly treats nft table dump order as significant. V3 fixes
object grouping while preserving rule order within each chain; 52 main checks PASS.
Earlier failures remain preserved and are not counted as PASS. The final full run is
`client-mixed-matrix-v1`.

**D04 DONE** with the documented manual boundaries. Debt register: **4/15 DONE
(26.7%), 9 IN_PROGRESS, 2 TODO**; this does not complete the 37-section full audit.

| IPv4 | IPv6 | firewalld | Cells | Assertions | Nested checks |
|---|---|---|---:|---:|---:|
| legacy | legacy | no | 19/19 | 610 | 330 |
| legacy | legacy | yes | 19/19 | 610 | 476 |
| legacy | nft | no | 19/19 | 610 | 330 |
| legacy | nft | yes | 19/19 | 610 | 476 |
| nft | legacy | no | 19/19 | 610 | 330 |
| nft | legacy | yes | 19/19 | 610 | 476 |
| nft | nft | no | 19/19 | 610 | 330 |
| nft | nft | yes | 19/19 | 610 | 476 |

## Boundaries

Each family's backend stays fixed across startup, SIGKILL, recovery and stop. This does not
certify automatic client backend migration. Arbitrary firewalld zones/policies, concurrent
root rule replacement, the full off/manual/route/nat66 × NDP and multiprofile matrix remain
separate D10 obligations. Native parse errors still require administrator compatibility
repair; lost WAN sysctl witnesses and persistent TUN retain their documented manual boundaries.
Windows VM, Mac/iOS and physical-router runtime remain SKIPPED by user decision.

[Debt register](../../plans/AUDIT-DEBT.md) · [Server mixed matrix](AUDIT-Q14-MIXED-FIREWALL.md).
