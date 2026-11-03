# Q14: mixed nft/legacy/firewalld after SIGKILL

24 September 2026. Verified code `ab5ccc7d`; Rust unchanged.
**16/16 scenarios, 476 checks PASS.** This covers the server portion of D04/D09/D10.
No new core defect was found; actual automatic-recovery limits are now documented.
D04 remains IN_PROGRESS: mixed-firewall client packet/recovery validation is still required.

## Matrix

| IPv4 backend | IPv6 backend | Scenarios | Checks |
|---|---|---:|---:|
| nft | nft | 4/4 PASS | 124 |
| nft | legacy | 4/4 PASS | 124 |
| legacy | nft | 4/4 PASS | 124 |
| legacy | legacy | 4/4 PASS | 104 |

Each row separately changes the IPv4 or IPv6 backend after SIGKILL; both variants run
without firewalld and with real firewalld 2.3.1 using its nftables backend. Operator
rules exist in both families of both backends, alongside a native inet table and,
when enabled, firewalld's table. The worker creates 18 exact NAT/NAT66, FORWARD, MSS
and DNS INPUT/REDIRECT rules across both families.

`audit_mixed_firewall.py` creates private net/mount/PID context and separate state,
config, log and control paths. A private mount wrapper selects real nft/legacy
multi-call executables. `-C/-D/--version` responses are not fabricated. Snapshots use
saved original executables for each backend. Isolated firewalld uses a private
D-Bus broker, DefaultZone=trusted and its own config; reload must preserve Qeli rules
and operator configuration.

## Confirmed behavior

- All 18 journal specifications are checked using real `-C` before SIGKILL. The
  profile is then deleted from configuration, so the new INI cannot reconstruct its rules.
- Changing one backend aborts startup before the profile hook. Affected rules remain
  in the original backend. Independent deletions in the other family continue;
  only confirmed absence retires a journal record.
- Native `meta mark set numgen inc mod 2` makes FORWARD incompatible with `-S`.
  Exact checks of present rules and `-D` work, but **after deletion an absent `-C`
  returns exit 3: `Parsing nftables rule failed`**. This does not confirm absence.
  Qeli retains two FORWARD records per affected nft family and refuses startup.
- Restoring the original backend does not repair the incompatible chain. The test
  administrator removes only its opaque expressions by exact handle from affected
  chains; every other rule remains. Qeli can then confirm absence and retire the
  firewall journal. No whole-table flush occurs.
- NAT66 also reaches the known D02 boundary: the live WAN `accept_ra` witness is lost.
  Firewall recovery has completed, but startup retains the sysctl record and refuses.
  The fixture administrator kept its original sysctl fd across the crash, restores
  the original value through it and retires only that verified record. This is an
  explicit operator action, not automatic Qeli identity recovery by name/ifindex.
- The new worker then starts and stops cleanly, the journal is empty, IPv4/IPv6
  forwarding is restored and remaining operator rules are preserved.

The previous wrapper test that disabled only `-S` did not cover every native
compatibility case: `-C` can also become unusable. Weakening `firewall_check` to treat
a parse error as absence would be incorrect.
[Procedure §6.83](../../manuals/TROUBLESHOOTING.md#683-linux-mixed-nftlegacyfirewalld-recovery).

## Evidence and reproduction

Lab `.11`: Debian, Linux `6.12.105+deb13-amd64`, x86_64, iptables 1.8.11,
nftables 1.1.3. Firewalld 2.3.1 and dependencies were extracted from Debian packages
into a private directory; no system service was installed or started. The running
server on `.10` was not replaced. The matrix ran two isolated scenarios at a time.

Worker SHA256: `3f52a9d5c1b3484592d5df9214372eebb7f90e44b30265df20b5d714325de8c0`.
Harness SHA256: `a2e482edb7cebd845c11bfe3b02167f6518257b43842d0006374419dd15f41f1`.
All 340 Rust/conformance files match the previously verified worker; remote source was
checked before/after. Full Rust suites and benchmarks were not rerun because core code
was unchanged.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/mixed-firewall-phase/`,
`mixed-firewall-matrix-v3/`, `mixed-firewall-matrix-v3.log/.rc/.tar.gz`.
Commands, before/after rules and journals, diagnostic logs and package hashes are
retained. `mixed-firewall-phase/matrix-v3.sh` contains the exact invocation. The new
runner accepts `--qeli`, `--artifacts`, `--ipv4 nft|legacy`, `--ipv6 nft|legacy`,
`--drift 4|6` and optional `--firewalld` pointing at extracted packages.

Early smoke and matrix v1/v2 runs are retained but are not PASS: the nft snapshot
collector (JSON omits xt-comment payload), assumptions about absence/sysctl recovery,
and control socket paths (SUN_LEN, private directory) were corrected. Only matrix v3
is final confirmation. Fixture failures are not reported as Qeli defects.

## Remaining scope

This validates server rules and recovery, not the client packet path. It does not
certify arbitrary firewalld zones/policies, every reload configuration, concurrent
replacement by another root or automatic backend migration. Qeli must not remove
an administrator's native opaque rules to force startup.
Mixed-environment client kill-switch/DNS/route packet recovery remains D04/D10;
the full off/manual/route/nat66 × NDP and multiprofile matrix also remains D10.
Overall register: **3/15 DONE, 10 IN_PROGRESS, 2 TODO — 20% by closed groups**.

[Register](../../plans/AUDIT-DEBT.md) · [Operations](../../manuals/OPERATIONS.md).

Final D04 follow-up: [client mixed packet/recovery matrix and Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) completed; D04 is DONE in the current register. Historical IN_PROGRESS statements above refer to earlier snapshots. D10 (broader policies/topologies) and D13 (state growth) remain open.

Follow-up, 2 October 2026: D13 is closed by [worker churn/lifecycle](AUDIT-Q25-WORKER-RESOURCE-CHURN.md); D10 is closed within supported Linux scope by Q25-F211/F212/F213 in the [current register](../../plans/AUDIT-DEBT.md). The new batch checks four mixed backend pairs with four IPv6 profiles, public firewalld zone/policy and reload/restart: 416 checks + 19 targeted tests PASS. [Evidence](../../../../release/certification/evidence/firewalld-profiles-20261002.json). Historical open statuses above are retained; arbitrary root rewrites/automatic backend migration and every zone/policy are not certified.
