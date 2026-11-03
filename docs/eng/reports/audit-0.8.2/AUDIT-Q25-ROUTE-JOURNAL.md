# Q25: physical client route recovery after a crash

Date: 24 September 2026. Baseline: `9b650ed6`.
Q25-F100 is fixed within the boundaries below. D04 remains **IN_PROGRESS**.

## Finding

**Q25-F100, P2 — SIGKILL lost ownership of physical routes.**
The nonpersistent TUN disappeared when its last descriptor closed, but carrier bypass,
exclude and blackhole routes survived in the kernel. A fresh process borrowed suitable
entries without delete authority. A subsequent clean stop could leave bypass routes
and an IPv6 block behind.

The real baseline binary with handshake and traffic produced **18 PASS, 3 FAIL**:
the carrier bypass and IPv6 blackholes remained, and direct IPv6 did not return after
stop. Reconnect itself succeeded; that was insufficient evidence of recovery.
This reproduction used TCP fake-tls outer IPv4 / inner IPv4, full tunnel.

## Change

The Linux managed client uses `/var/lib/qeli/client-routes.state` and a stable
`client-routes.state.lock`. An open descriptor pins the trusted directory; ownership,
permissions, symlinks, file size and schema are checked. Every route operation holds
a shared interprocess lock. Atomic publication syncs both data and the directory.
Limits are 8 MiB, 128 groups and 8192 total records.

Groups use boot ID, `SO_NETNS_COOKIE` and TUN name. An abstract socket
`qeli.client.routes:<tun>` prevents a second live owner of that TUN in the same network,
even through a different state path. Cross-TUN physical destination reservations are
checked in the shared journal before borrowing/mutation. All clients in the same
network must therefore see the same trusted `/var/lib/qeli` and lock.

An intent is persisted before add/replace. Confirmed ownership requires successful
command completion and a fresh exact route observation. Journal errors close forward
admission and give roaming a terminal/unknown-state error, including a write failure
after retiring the old path. RAM retains proven ownership until cleanup results are
persisted, allowing cleanup retry after an I/O problem is repaired. An unfinished
intent never becomes permission to delete an observed route.

Startup recovers before DNS resolution/handshake and checks again before creating
the managed TUN. The current group's TUN must be absent; a live or persistent device
is neither deleted nor adopted. Confirmed records require matching explicit and
implicit attributes; operator replacements are preserved. Failed deletions retain
their records while successful siblings retire independently. Pending reservations
retire only after verified destination absence.

Only validated exact main-table unicast/blackhole specifications can be replayed;
arbitrary commands, foreign tables/protocols and unsupported attributes are refused.
Foreign namespace/TUN groups are preserved. After a boot ID change valid old records
reset without commands; reboot does not mask malformed state. Empty state and the
stable lock are expected after cleanup. TUN routes are not durable records; existing
descriptor-based TUN management is unchanged. Attach does not enable physical route
management. User configuration remains **INI**; internal state is not a user config.
There are no ABI or wire protocol changes.

## Validation

- **1530 host + 71 config; all 9 feature/cross/lint checks PASS**.
- **2087 Linux + 43 privileged + 8 worker lifecycle PASS**.
- 11 portable tests cover grammar/limits/duplicates, intent/confirm, boot/cookie/TUN,
  cross-client reservations and separate pending/owned retirement.
- 6 Linux file/lock tests cover trusted storage, roundtrip, live lease across paths,
  foreign reservations, lock deadline and failed atomic publication.
- 2 Linux tests use a kernel model and real journal: failed intent write before the
  command and failed retirement write after old path deletion; admission stops and
  cleanup can retry.
- 3 privileged tests cover IPv4/IPv6 cleanup, static replacement/pending/foreign group
  preservation, live TUN and namespace refusal, retaining a failed deletion while
  cleaning a successful sibling, then retrying.
- Packet matrix: **17/17 cases, 489 assertions PASS**. In 15
  full-tunnel cells a real client receives SIGKILL and restarts: journal, new TUN,
  authenticated traffic and subsequent carrier/IPv4/IPv6 blackhole cleanup are checked.
  An unrelated static route is preserved. Existing DNS SIGKILL/restart, kill-switch,
  split, TAP and PMTU checks remain enabled.
- Initial full Linux v1 exposed a test race: a neighboring fork briefly inherited the
  CLOEXEC socket before exec while the test demanded immediate rebind. Only the test
  reopen now retries for up to one second; production live-owner refusal is unchanged.
  Intermediate v3 failed to compile because a new assertion compared the wrong type;
  corrected. Final v4 and all its checks are retained separately from these failures.

Full Linux v4 completed both test suites and the build, but its lifecycle wrapper
returned 1 because v2 had already created the artifact directory (`FileExistsError`).
Without repeating successful suites, `route-journal-lifecycle-v4` runs lifecycle in
a new directory on the same binary, with manifest verification before/after.

Source snapshot: 340 files, archive SHA256 `6e0e55d0a0ff52d537fc3238ba80ade4a6cf9f15a34a439617c345502588c03b`.
Worker SHA256: `de18b1b171701704e548c0d4067fbfa7d398f9567f434c95aedc1d97ab228fed`.
Baseline worker SHA256: `584a4bd5283ba46f791ace79784c38cc8db7f6c054062eed19461b0289ebda91`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/route-journal-phase/`,
`route-journal-baseline-runtime-v2.log`, `packet-matrix-route-journal-baseline-v2/`,
`route-journal-final-v4.log`, `route-journal-lifecycle-v4.log`, `lifecycle-route-journal-v4/`, `packet-matrix-route-journal-v1/`.
Source is verified before/after Linux runs and against the git index; baseline and
fixed packet runs use the same harness. Linux Rust 1.97, host Rust 1.98; the existing
Clippy `chunks_exact_to_as_chunks` exception remains.

## Limits and next work

Recovery runs on the next start, not immediately after the crash. SIGKILL between
command and confirmation leaves pending state requiring manual investigation, not
unconditional retry/delete. Snapshot checks and commands are not atomic; identical
recreation by another root cannot be distinguished. Older unjournaled binaries and
different mount views of `/var/lib/qeli` do not participate in shared ownership.
Do not move state to another network, rewrite cookie/boot or delete locks to bypass refusal.

The 15-second command/lock budget does not interrupt internal filesystem I/O. Long
churn, foreign group growth and final release measurements remain D13/D14. Legacy
global DNS, live persistent TUN recovery and the full mixed nft/firewalld matrix remain
D04. Overall debt remains **3/15 DONE, 10 IN_PROGRESS, 2 TODO (20% by closed groups)**.
Tests ran in private namespaces on `.11`; `.10` was untouched.
Windows VM/Mac/iOS/router runtime remain SKIPPED by user decision.

[Operations](../../manuals/OPERATIONS.md) · [Troubleshooting §6.81](../../manuals/TROUBLESHOOTING.md#681-linux-physical-route-journal-recovery) · [Debt register](../../plans/AUDIT-DEBT.md)

Follow-up: [Q25-F101](AUDIT-Q25-LEGACY-DNS.md) closes legacy global DNS through refusal of automatic replay and manual migration. An old snapshot does not prove ownership of the current resolver; automatic restore/refcount and their test implementations were removed. Historical results above describe the earlier behavior.

24 September follow-up: [persistent TUN/TAP validated in 17 crash scenarios](AUDIT-Q25-PERSISTENT-TUN.md). Safe refusal and explicit removal of a verified orphan close this portion of D04; the full mixed firewall matrix remains open.

Final D04 follow-up: [client mixed packet/recovery matrix and Q25-F102](AUDIT-Q25-CLIENT-MIXED-FIREWALL.md) completed; D04 is DONE in the current register. Historical IN_PROGRESS statements above refer to earlier snapshots. D10 (broader policies/topologies) and D13 (state growth) remain open.
