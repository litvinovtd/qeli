# Q25-F104: resolver-file reads before kill-switch installation

25 September 2026. Base `8f4071ea`. Partial D05/D09 closure; Linux client.

## Defects and fix

Kill-switch read `/run/systemd/resolve/resolv.conf` and `/etc/resolv.conf` synchronously,
without a size limit, separately for each family and after firewall changes had begun.
A FIFO or slow read blocked stop processing with a partially created chain.
The parser accepted `nameserver192.0.2.53` without a separator but discarded valid
entries followed by comments. Changing the file between IPv4 and IPv6 setup produced
different system-DNS snapshots for the two families.

Files are now read once before the first firewall mutation. The read-only worker shares
four slots with system DNS/NSS; queue waiting and reading consume the existing
15-second kill-switch setup budget. SIGTERM/SIGINT cancel waiting before mutations.
A late worker owns no chains, routes or TUN and cannot continue network setup.
Context is pinned before waiting and checked again before changing the network.

`transport_core/resolver/system_config` shares reading and parsing between kill-switch
and systemd stub detection. Unix uses `O_NONBLOCK`; the opened fd must be a regular file
of at most 64 KiB. Reading is capped at 64 KiB + 1 byte; length and metadata are checked
before/after. Ordinary symlinks are supported; a filename never establishes contents.
Each file and the merged result have a limit of 64 distinct entries.

An exact `nameserver` token and complete numeric IP are required; trailing `#`/`;`
comments must be separated from the address by whitespace. Glued keywords are ignored.
NUL, malformed directives, unsuitable file type/size, invalid UTF-8 and detected file
changes discard the entire affected file without a partial allowance list. Another valid
file remains usable; exceeding the merged limit aborts setup before mutation. This is a
conservative allowance parser, not an emulation of every libc extension.

Scoped IPv6 (`fe80::53%wan0`, `%2`) retains a scope marker: the entry cannot become an
unrestricted allowance across interfaces and does not discard adjacent valid IPv4 DNS.
A list containing scoped DNS is never stub-only. System resolver scope handling was
checked against [glibc 2.41 source](https://github.com/bminor/glibc/blob/release/2.41/master/resolv/res_init.c).
Existing loopback/link-local/multicast/unspecified filtering is not broadened.
No new INI parameters or ABI changes are introduced.

## Validation

**9 new unit regressions** (7 portable + 2 Unix) cover separators/comments/scope,
deduplication and list limits, refusal of partial parsing, 64 KiB/UTF-8, changed opened
inodes, the merged two-file limit, symlinks and FIFOs. Stub-only checks also cover mixed
and scoped entries. Existing slot-retention-after-cancellation checks remain green.

`audit_resolver_files.py`: **7 baseline/fixed pairs (14 launches)** with actual UDP/53.
Every launch first verifies delivery to all three addresses without kill-switch.

- FIFO without a writer: baseline hangs after partial installation; fixed refuses the FIFO.
- A read delayed for 45 seconds by test-only LD_PRELOAD: baseline has already changed
  firewall, while fixed waits before mutation. Both old hung processes fail to exit
  within 3 seconds of SIGTERM; the fixture kills them. Fixed exits normally.
- File over 64 KiB and a glued keyword: the old client permits packets to both DNS
  addresses; fixed refuses these allowances.
- Valid trailing comments: the old client blocks both DNS addresses; fixed permits them.
- Replacing the file between IPv4/IPv6 setup: the old client permits the new IPv6 DNS;
  fixed uses the original shared snapshot.
- Scoped IPv6 mixed with IPv4: IPv4 remains available in both versions, with no erased
  scope or unrestricted IPv6 allowance.

All seven fixed launches exit with code 0, preserve original operator rules/routes and
leave no TUN or journals. Measured stop times are **0.003–0.716 seconds**; these are
scenario results, not a general SLA. Across 33 address probes, **48 allowed packets
receive replies and 84 blocked attempts yield EPERM with zero delivery**.

Final hostname matrix: IPv4=nft/IPv6=legacy without firewalld and the reverse pair with
real private firewalld. **38/38 network cells, 34 SIGKILL/recovery cases, 1220 main
assertions and 806 nested checks PASS**. All **1088** protected direct UDP attempts
are blocked with EPERM/increasing DROP counters/zero delivery; all **656** allowed
probes receive replies. TCP/UDP/QUIC, IPv4/IPv6 carrier/tunnel, split, TAP, DNS A/AAAA and
MTU/PMTU/PTB pass. Nested assertions are not additional independent tests.

Host: **1544 unit + 71 config integration**, all 9 feature/cross/lint gates PASS.
Linux: **2098 ordinary + 44 privileged + 8 worker lifecycle PASS**. Python compilation,
bash syntax and all 9 RU/EN documentation checks PASS. Rust 1.98 host / 1.97 Linux;
the existing `chunks_exact_to_as_chunks` Clippy exception is retained.

The first native v1/v2 runs remain fixture FAIL evidence: initially the reverse IPv6
neighbor was missing, then DAD completed after the route snapshot. The fixture now
sets both neighbors, verifies delivery and waits for DAD. Intermediate repro v3/matrix
v1 PASS do not replace final evidence: results above use **repro v4/matrix v2**, after
the scoped/attached-comment regressions.

## Evidence and boundaries

Lab `.11`, private NET/mount/PID; working `.10` was unchanged.
All 345 Rust/conformance files and 18 scenario hashes were verified.
Worker SHA256: `0c0d6cb201137a55a26fe7a13daa8c245f733cd0282bf2f1b869213186d460c4`.
Source archive SHA256: `491778adc5a9d2812ffb2147d9a46b1fe8739030ffb370e48c6eae9863c526ab`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/resolver-files-phase/`,
`resolver-files-repro-v4/`, `resolver-files-matrix-v2/`, `lifecycle-resolver-files-v2/`
+ `.tar.gz`; logs/exits: `resolver-files-linux-v2`, `resolver-files-repro-v4`,
`resolver-files-matrix-v2` (`.log/.rc`). Commands: `run_checks.py`, `linux-final-v2.sh`,
`repro-v4.sh`, `matrix-v2.sh`; manifests/results: `evidence.json`,
`linux-source-final-manifest.json`, `scripts-manifest.json`.
Matrix archive SHA256: `d7cb15a43daef83749ebe5e3cef6817821db168598ff641335a136df6e7c46aa`.
Resolver-file archive SHA256: `2c1a2295727c4763d39e0f486b4dfe86527c6e1ed8f28f000d2d9d384c96ef70`.

Waiting is bounded, but an arbitrary filesystem syscall cannot be safely interrupted.
It may retain one of the four threads/slots until completion; runtime destruction does
not wait for this read-only worker. A numeric IP bypasses NSS, but kill-switch setup
still waits for resolver-file discovery through the shared queue. Cancelling before
installation begins does not mean protection has already become active.

Per-link DNS stub detection uses the common bounded reader/parser but remains synchronous.
Firewall/routes/gateway/DNS mutations, internal locks/I/O and whole NetworkPlan/shutdown
budgets remain D05. There is no promise of atomicity across both files or protection
against external root changes between checks; later DNS changes do not automatically
refresh allowances. Scoped DNS remains unsupported by kill-switch address-only rules.

D05 stays **IN_PROGRESS**; D06/D10/D13 and the whole audit remain open. Shipped platform
libraries and benchmarks were not updated here. Windows VM, Mac/iOS and physical-router
runtime remain **SKIPPED by user decision**, not PASS. Debt: **4/15 DONE (26.7%),
9 IN_PROGRESS, 2 TODO**.

[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/CONFIG.md#kill-switch-kill_switch).

Follow-up: [Q25-F105](AUDIT-Q25-NETWORK-TASK.md) moves NetworkPlan application and unadopted-result rollback to a joined worker. Established-tunnel cleanup remains separate D05 work; historical results above are retained.
