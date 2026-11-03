# Q25 — link observations in the calling namespace

<!-- normative-sync: audit-q25-link-observation-v1 -->

Date: 24 September 2026. Baseline: `0f4434bf`. Partial D02/D06 closure in the
[debt register](../../plans/AUDIT-DEBT.md); both groups still have remaining criteria.

## Q25-F076, P2 — inherited sysfs is not the calling network namespace

A process can enter a fresh network namespace while retaining a sysfs mount from its
previous namespace. NDP proxy combined a kernel ifindex from the current namespace
with link type/MAC read from that inherited mount. An otherwise valid `required` proxy
failed to start when the name was absent from sysfs, or could observe the wrong MAC
when names overlapped. The TAP MAC reader and lifecycle hook ifindex had the same problem.
Panel device assignment could select an already occupied name, and the sysctl absence
probe could wrongly consider a live interface absent when retiring recovery evidence.

`network_interface.rs` now provides the shared index and Ethernet observation boundary.
It uses a CLOEXEC control socket and libc's platform-specific ifreq/ioctl layout.
SIOCGIFINDEX and SIOCGIFHWADDR address the socket's network namespace; a second index
query detects ordinary name replacement during observation. Invalid names fail and
only ENODEV proves absence; permission or socket errors remain unknown. NDP keeps its
Ethernet/unicast checks. TAP, hooks, sysctl and panel selection consume the same boundary;
the old TUN index helper re-exports it. Duplicate sysfs MAC parsers were removed.

The worker lifecycle runner intentionally keeps inherited sysfs now, so a remount cannot
mask this regression. It still creates private network/mount/PID namespaces and keeps
all configuration, firewall and sysctl changes isolated.

## Verification

- Baseline `0f4434bf` with the caller regression fixtures: **2 expected FAIL**.
  NDP cannot read the new link's type through inherited sysfs; TAP MAC reading also
  returns ENOENT although the kernel interface exists. These are actual Linux failures.
- Fixed Linux snapshot: **1887 ordinary + 25 privileged tests PASS**. Five new native
  cases cover the common query, NDP bind, TAP/hook metadata, sysctl presence and panel
  name selection. Two new ordinary tests reject invalid names and non-Ethernet MAC queries.
- All **8 worker lifecycle E2E PASS** with inherited sysfs: TCP/UDP × off/manual/route/nat66,
  including required NDP in manual mode. Earlier isolation and cleanup assertions remain.
- Host **1437 unit + 71 config integration PASS**; all nine feature/cross/lint commands PASS.
  The existing Clippy compatibility allowance was not expanded. A new client-only unused
  field warning was removed; unrelated pre-existing feature-only warnings remain.
- RU/EN documentation: 228 Markdown files, all nine documentation gates PASS.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/network-view-phase/`,
`network-view-compare.log`, `network-view-final.log`, `lifecycle-network-final/` and the
saved source manifest. The comparison explicitly clears only Qeli's package artifacts
in the isolated Cargo target before switching back from baseline to fixed source.
Final Linux worker SHA256: `77017068e66802e88f45fc3ae42d2c548aeb1899a5ef137c4b90d0d2423f8fb0`.

## Remaining scope

This observation is not a durable original-interface identity or an atomic lease across
subsequent privileged rename/delete/recreation. Per-link sysctl restore after name reuse,
WAN changes after capture, dynamic IPv6, resolved/bus context, DNS/carrier globals and
journal directory trust remain open. `dev_attach` still reads TUN flags through sysfs;
this pass does not certify attach with an inherited/mismatched mount. NDP packet delivery
and the complete network/backend matrix remain D10; successful bind alone is not that test.
No INI/API/ABI fields were added. No current native GUI packages or benchmark were produced.

[Operational guidance](../../manuals/TROUBLESHOOTING.md).
