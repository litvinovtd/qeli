# Q15: sessions, IP pools and limits

<!-- normative-sync: audit-q15-sessions-v1 -->

**DONE/PASS. Plan: 15/37 (40.5%), 22 sections remaining.** 4 October 2026.
Core 86dbde48f5c2280f54ad59878f0987b90458b4f1, Linux candidate 5e3940eadec0981051006b0a605f7ad79e3b955a44a0cb56843095ebeafe5dcc.
Evidence: release/certification/evidence/q15-sessions-20261004.json.

## Q15-F003, P2: growing freed-address history

Fixed allocation does not consume the dynamic reuse stack. Every release appended
a stale address; DHCP sub-range allocation has the same behavior. After 100,000 cycles,
IPv4 and IPv6 each retained 100,000 entries with zero live leases. Transactional allocation
clones the pool: admission cost grew along with memory.

A membership set retains one pending entry per address. Pop clears membership and
rechecks ownership; dynamically unusable reservations are not queued. LIFO remains;
dual rollback restores stack and membership. The fixed 100,000-cycle probe retains
one entry per family. Two regressions also cover DHCP ranges, reservations, exhaustion
and duplicate-address prevention. INI, API and ABI are unchanged.

## Final checks

- **2370 Linux unit PASS / 60 ignored**; full/minimal Clippy and fmt PASS.
  The 26 pool tests belong to this run; counter, alias, teardown and auth-deadline tests ran.
- **11 runtime scenarios / 148 checks**, TCP/UDP/QUIC: devices, reconnect, oldest eviction,
  six concurrent AUTHs, user/profile caps, exclusions, reservation, dual IPv6 exhaustion
  and both-family release. Kick removes installed client_subnet/kernel routes.
  Quota/expiry/disable/enable, UDP reap with idle_timeout=0, normalized network
  restoration and TUN removal PASS.
- **54 actual TUN uplink checks**, TCP/UDP/QUIC: valid PQ/AEAD peers inject IPv4/UDP
  toward the server; quota, expiry and disable stop delivery, reset/enable restore it.
  A private sidecar seeds 1 GB historical download before enabling the cap through
  production control. No 1 GB traffic run or throughput benchmark is claimed.
- Real fixed/adaptive bonded clients retain one logical session and one IPv4 lease
  across several carriers and path change: **51 checks PASS**.
- **18/18 matrix / 327 checks**, aggregate IPv4/IPv6 leak;
  **100 TCP + 100 QUIC / 33 soak checks**; **24 REALITY-TLS/H2 checks**.
- Four independent native A/B builds, exports/copies/provenance PASS.
  Client libraries equal Q14 bytes; pool is server-only.

Review: sparse IPv6/IPv4 boundaries, fixed/exclude/reservation, atomic dual rollback,
TCP/UDP admission ownership, eviction/reconnect/caps, session/token/address aliases,
guarded reap/kick/quota cleanup and short-session/writer-tail/reset/usage persistence.
No confirmed dead production API was found; DHCP-only methods have live callers.

## Reproduction and limits

Exact tested fixtures: scripts/audit_session_lifecycle.py + scripts/audit_session_peer.rs;
scripts/audit_session_data_plane.py + scripts/audit_session_data_peer.rs.
Python accepts --qeli, --peer, --root; root and fresh Linux NET/mount/PID are required.
Private state/control/INI and shadow /run, /var/lib, /var/log, /etc/qeli are used.
Peers compile against the shipping rlib/dependencies from the same build.
Commands, source, SHA/logs:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q15-sessions-20261004.

Earlier 142 + 54 checks retain their Q14 hash; final 148 + 54 checks use this candidate.
Allocator probe is not 100,000 network reconnects. Quotas/policy catch-up retain the periodic
sweep; no per-packet accounting or instant concurrent policy-update guarantee is added.
Other ignored tests are not claimed executed. No fresh installed-app E2E; Mac/router/
Windows VM runtime remains user-excluded. Active services/ELFs/user WIP preserved.
Both native host snapshots matched their baselines.
No push/deploy. Next: Q16 ACL, push routes and site-to-site.
