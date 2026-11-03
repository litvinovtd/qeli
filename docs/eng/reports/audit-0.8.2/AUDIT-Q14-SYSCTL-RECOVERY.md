# Q14: sysctl recovery outcome and repeated lease acquisition

Date: 23 September 2026. Baseline commit: `66f2714d`.
Sections 14, 17, 18 and 19: **IN_PROGRESS**.

## Confirmed defects

**Q14-F029, P2 — stale sysctl recovery reported false success.** The pre-pass in
`with_locked_journal` removed dead owners, attempted restoration and persisted unresolved
entries. However, `recover()` then unconditionally returned Ok. Consequently,
`nat::cleanup_all()` could miss failed restoration at worker startup.

After journal persistence, `recover()` now checks remaining ownerless entries. They produce
`could not restore stale host sysctl value(s): ...` with the affected paths. The pre-pass
attempts every entry; one failure does not skip the others. The journal is persisted before
the error is returned, allowing retry. Entries with live owners are not recovery failures.

**Q14-F030, P2 — failed repeated acquisition removed an existing owner.** An active
component could request the same setting again. If the current value differed from managed
and the new write failed, rollback removed its owner even when that lease had succeeded
earlier. Subsequent recovery could restore the original value beneath the live component.

Acquisition now retains the owner-insertion result. Write failure removes only ownership
added by that call. A previously existing lease remains in the journal, as do other owners.
A new failed acquisition still leaves an empty entry: verification may fail after the
write has already changed the setting.

## Validation

An isolated production `sysctl.rs` copy uses fixtures for sysctl reads/writes, process and
boot identity, FileLock and atomic writing. Acquisition, pruning, release, recovery,
journal-format and ownership algorithms are preserved. The journal is written to a separate
directory; system `/proc` is not changed and cross-process flock is not tested.

Two baseline scenarios confirm the defects, two controls cover live ownership and external
changes, and one checks journal grammar. With the fix, **7 checks PASS**: corrected scenarios,
existing controls, retaining another owner after failed new acquisition, continuing other
restorations after a failure, and grammar. Successful retry lets `recover()` return Ok after
a transient failure. Running the same seven checks against the baseline gives three
expected failures and four passing controls; all seven pass with the fix. These checks
are not added to the main project matrix.

**1060 Rust tests PASS** (989 host unit + 71 config integration). Linux all-targets Clippy,
client-only, server-only, client without roaming, minimal FFI, compatibility without features
and rustfmt PASS. The existing Clippy exception and feature-specific warnings remain.
Evidence: C:/Users/litvi/OneDrive/Documents/qeli/sysctl-recovery-audit-20260923.

## Boundaries

No new INI keys. The internal sysctl journal format, ABI and wire format are unchanged.
This is recovery metadata, not a user JSON configuration.
Failed startup recovery now stops worker startup through the existing `?`; supervisor
retry/respawn policy is unchanged.

The subsequent [Q14-F031 pass](AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md) fixes tracking of partial
IPv6 acquisition before both settings complete. Q14-F027 remains open: generic NAT cleanup,
earlier-generation resources, persistent DNS journaling and overall network-operation
deadlines need separate passes. Server NAT command deadlines are added in
[Q14-F032](AUDIT-Q14-NAT-COMMANDS.md). Actual Linux sysctl/firewall/TUN/systemd,
devices, native release and benchmarks were not run.

Previous pass: [profile tasks and TUN teardown](AUDIT-Q14-PROFILE-SHUTDOWN.md).

Follow-up: [Q25-F050–F051](AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md) fixes unknown-owner handling and preserves
entries after inconclusive sysctl inspection; namespace identity remains open.
