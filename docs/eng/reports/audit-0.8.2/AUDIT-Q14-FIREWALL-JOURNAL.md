# Q14 — exact server firewall recovery after a crash

<!-- normative-sync: audit-q14-firewall-journal-v1 -->

24 September 2026. Base `855d1906`. Partial D04/D09/D10 completion.

## Q14-F038, P1 — SIGKILL lost exact NAT and DNS specifications

The live worker retained exact rules in RAM. After SIGKILL startup recovery only
searched comments through `iptables -S`. A listing failure was a warning: a new
profile started while the deleted profile's NAT, FORWARD, MSS, DNS INPUT and REDIRECT
rules remained. The baseline reproduced **9 → 9 remaining rules** after the new
profile was listening and the old configuration was deleted. `-C/-D` still worked.

`server-firewall.state` now lives in `STATE_DIRECTORY` (default `/var/lib/qeli`).
Before each attempted `-A/-I`, an atomic write with fsync saves the family, table,
chain, exact arguments and backend (`nft`/`legacy`). This is internal recovery state;
user configuration remains INI. Limits are 8 MiB, 32768 specifications and 64 network
namespace groups. Allowed chains, command arguments, targets and Qeli comments are
validated; unsupported versions and corruption are errors.

Groups use boot ID and `SO_NETNS_COOKIE`. A live descriptor pins the namespace;
observed context loss permanently invalidates the session. Valid data from another
boot no longer supplies recovery commands. Foreign groups are neither probed nor
removed. Server workers require `SO_NETNS_COOKIE` support and trusted state storage,
even for profiles without NAT. Missing context never falls back to inode comparison.

After exclusive worker admission, before sysctl recovery, tagged sweeps or profiles,
the journal removes the current group's rules using `-C/-D`, independently of config
and `-S`. Absence is verified separately. Deletion failure, unknown results, backend
changes or corrupt state preserve unresolved evidence and abort startup. Successfully
removed siblings are persisted individually; retries continue pending work. Live
cleanup uses the same records. Cleanup retains an empty envelope and stable `.lock`;
never delete the lock file.

Trusted directory traversal and bounded descriptor reads moved from sysctl to shared
`state_storage`; SO_NETNS_COOKIE also uses shared code. Symlink/FIFO/hardlink refusal,
owner policy, 0600 permissions, cross-process flock and atomic replace are preserved.
Admission and commands share the existing 15-second operation budget; uninterruptible
filesystem I/O is not thereby converted into a hard deadline.

## Verification

- **1501 host + 71 config; 9 feature/cross/lint checks PASS**.
- **2044 Linux + 35 privileged + 8 worker lifecycle PASS**.
- 10 new portable, 7 Linux and 1 privileged regressions cover reload after uncertain
  mutation, persistence before callbacks, failed siblings, namespace/boot/backend,
  corruption, unsafe files, flock deadlines and sticky context loss.
- `scripts/audit_firewall_recovery.py`: **27 checks PASS** in private
  net/mount/PID namespaces. Real iptables-nft runs under a wrapper that selectively
  rejects `-S`/`-D` or changes the `--version` response. Deleted-profile NAT/DNS recovers
  after SIGKILL; deletion failure, backend mismatch and corruption abort the worker
  and retain evidence; retry after fixing the fault succeeds; operator IPv4/IPv6
  rules survive.
- The same final runner on the baseline: expected exit 1, new worker listening,
  all nine rules left behind. The initial recovery fixture incorrectly enabled
  `forward_private`; its failed run remains `baseline-v1` and is not bug evidence.
  `baseline-v2` reproduced the bug; the final runner is `baseline-v3`.
- Current packet matrix: **17/17 cases, 301 assertions PASS**; real resolved/D-Bus and packet checks.

Source snapshot: 333 files, archive SHA256 `c90eac3576017ed63738ff71da850f530494d456088dd413aa85715457d81d34`.
Worker SHA256: `4d08ba79721bd4d9d24439fce16feecc21671d0c8ad6a7ca7c71da1c5d0e59f2`.
Baseline SHA256: `dfcbd8c654a57dd805aa15c3a7fc0feed1b372e66093a5cc251a7f91f9b5a72a`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/firewall-journal-phase/`,
`firewall-journal-final-v1.log`, `firewall-journal-baseline-v3/`, `firewall-journal-fixed-v1/`,
`lifecycle-firewall-journal/`, `packet-matrix-firewall-journal-v2/`.
Linux Rust 1.97; host Rust 1.98; existing Clippy allowance `chunks_exact_to_as_chunks`.

## Operational limits

Keep the original `STATE_DIRECTORY`, network namespace and backend for recovery.
Changing state paths does not migrate evidence. Stop the previous worker before an
upgrade: old binaries neither participate in the network lease nor record exact
state. Their rules depend on the historical tagged sweep; unavailable enumeration
cannot reconstruct unknown specifications. The wrapper test does not certify arbitrary
native nft/firewalld rules or concurrent administrator changes to the backend.

`qeli-nat:*` is reserved for the Qeli server. This is cooperative ownership, not proof
for an arbitrary rule deliberately created by root with an identical specification.
Checks and external kernel commands are not atomic against root intervention. Full
client route/DNS/kill-switch crash recovery and D04 remain open. ABI, wire and INI
keys are unchanged. `.10` was not modified; runtime checks used `.11`.
Windows VM/Mac/iOS/router runtime remains SKIPPED at the user's request.

[Register](../../plans/AUDIT-DEBT.md) · [Operations](../../manuals/OPERATIONS.md)

The first packet-matrix invocation stopped before network cases because its harness archive omitted `release_certification.py`. The archive was corrected; the final run is `firewall-journal-packet-matrix-v2`, and the original failure is retained.

24 September follow-up: [16 native mixed/firewalld scenarios](AUDIT-Q14-MIXED-FIREWALL.md) verify rule and journal preservation. A native nft expression can break absent-rule `-C` confirmation after successful `-D`; evidence remains until an administrator restores compatibility. The wrapper that disabled only `-S` did not cover this case.
