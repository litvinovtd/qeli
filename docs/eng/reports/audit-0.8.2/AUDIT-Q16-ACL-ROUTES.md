# Q16: ACL, push routes and site-to-site

<!-- normative-sync: audit-q16-acl-routes-v1 -->

**DONE/PASS. Plan: 16/37 (43.2%), 21 remaining.** 4 October 2026.
Core: 1342edbd9cd5d16af3d35161684f0bec3999a8ca. Linux SHA256: eb2b90bf1bc60c985190d65560ef205a4769212ffcaf9169048c371b31ad5932.
Evidence: release/certification/evidence/q16-acl-20261004.json.

## Q16-F001, P1: configured prefixes are not current ownership

The first client acquired a conflicting client_subnet route. The second authenticated
without that route, but its compiled SrcGuard still allowed every configured prefix.
Actual PQ/AEAD packets from the second client reached the TUN using the first client's
subnet source, both while the owner was connected and after its kick. The Q15 baseline
reproduces IPv4/IPv6 on TCP, UDP and QUIC: three scenarios, 78 checks.
Broad delegated prefixes and exit defaults must also yield to more specific owners.

Shared TunIngress now checks the authoritative SessionMap immediately before delivery:
exact lease, then longest prefix; the same session_id must still occupy the primary map
and be neither revoked nor closing. The check occurs after pacing/queueing and covers
ordinary/reassembled TCP/UDP/QUIC and paced UDP ingress. An exit /0 permits external
reply sources but yields to exact leases and more specific iroutes. A new authentication
can claim a freed conflicting route; the previously refused client does not inherit it.
INI, API and ABI are unchanged.

## Q16-F002, P2: exit defaults captured server endpoints

With client_to_client=true and an active exit /0, destination lookup sent traffic
for the server's own tunnel address to the exit client. The unchanged baseline
reproduces this across TCP/UDP/QUIC and IPv4/IPv6: 42 checks. Active tunnel addresses
are now cached per profile and retain local TUN delivery. Clients also cannot claim
reserved server tunnel addresses as packet sources. A unit regression and actual
encrypted wire traffic verify local delivery; the wire cases also reject reserved
server-source spoofing.

## Checks

- **2374 unit PASS / 60 ignored**, full/minimal Clippy and fmt PASS.
  Four new regressions cover both families, exact/LPM/default, closing/revoked,
  removed primary membership and replaced session IDs. The current suite includes
  15 ACL,
  25 shared NetworkPlan and
  7 route tests.
- **6 real scenarios / 486 checks**:
  TCP/UDP/QUIC × client_to_client off/on, both inner families in each case.
  Actual TUN delivery, refused conflicting/unregistered sources, reconnect/ownership,
  exact/LPM/default, pool/delegated-source isolation, user-over-group ACL,
  user-over-profile routes and permitted/unauthorized exit use are covered.
- The same run covers profile access denial, a foreign kernel route without overwrite
  or leaked lease/session, group ACL change revocation and reconnect with fresh policy.
  Concurrent admissions for one prefix retain unique leases and exactly one owner in
  both families. Kicking that owner does not give the losing client the route; reconnect
  can acquire it. Normal stop removes owners, iroutes and TUN and restores networking.
- **18/18 matrix / 327 checks** and aggregate IPv4/IPv6 leak; fixed/adaptive bonding
  **51 PASS**; **100 TCP + 100 QUIC / 33 soak checks**; REALITY-TLS/H2 **24 PASS**.
  All use the new candidate.
- Four independent native A/B builds, exports/copies/provenance PASS. Client libraries
  equal Q15 bytes; only the server module changed.

Review covers effective_allowed_networks, SrcGuard/DstAcl, canonical CIDR/bare IP,
SessionMap/iroutes/teardown, TCP/UDP ingress, control policy, user/profile push and shared
NetworkPlan family/gateway validation, exclusions, bounded subtraction and pushed-route
provenance. No confirmed dead API was removed: SrcGuard::new is a public legacy constructor
with tests; production uses new_dual. Reviewed NetworkPlan helpers have active callers.

## Reproduction and limits

Tested fixtures: scripts/audit_acl_routes.py and scripts/audit_acl_peer.rs. Python accepts
--qeli, --peer, --root; --baseline reproduces the old behavior. Root and fresh NET/mount/PID
are required; state, INI, control and routes are private. Peer compilation uses the shipping
rlib/dependencies from the same build. Source, commands, SHA and logs:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q16-acl-20261004.
The initial TCP reproduction remains recorded. UDP preflight rejected heartbeat/shaping
both disabled with unlimited idle timeout; the fixture changed to finite 120 seconds
before the full baseline. This was a fixture configuration correction.
Intermediate runtime exposed Q16-F002 and retains its original SHA. Gateway baseline
receive filters by UDP protocol and a unique fixture data marker so an unrelated IPv6
packet cannot mask expected delivery. Failed build attempts and intermediate results
remain separate; final acceptance uses the final build.

Ownership is checked before channel delivery; packets authorized before a subsequent
ownership change, including channel-capacity waiters, are not retroactively cancelled.
The SessionMap read lock is released before channel awaits. ACL reload retains the
periodic sweep; no instantaneous in-flight-packet purge is claimed. Earlier Q15 results
retain original hashes. This is correctness/stability qualification, not a throughput
benchmark. Native A/B does not replace installed-app E2E. Mac/router/Windows VM runtime
remains user-excluded; other ignored tests are not claimed executed. Active services,
executables and user WIP are preserved; raw snapshots and any recorded accepted desktop
legacy delta are retained. No push/deploy. Next: Q17 IPv4 NAT, forwarding and sysctl.
