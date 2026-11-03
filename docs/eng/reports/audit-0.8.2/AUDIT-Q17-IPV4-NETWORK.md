# Q17: IPv4 NAT, forwarding and sysctls

<!-- normative-sync: audit-q17-network-v1 -->

**DONE/PASS. Plan: 17/37 (45.9%), 20 remaining.** 4 October 2026.
Core: `1342edbd9cd5d16af3d35161684f0bec3999a8ca`.
Linux SHA256: `eb2b90bf1bc60c985190d65560ef205a4769212ffcaf9169048c371b31ad5932`.
[Evidence](../../../../release/certification/evidence/q17-network-20261004.json).

## Review outcome

No new confirmed functional defects were found in the NAT/gateway/sysctl engine.
Review covers NAT44 and RFC1918/off-WAN guards, pool-only MASQUERADE, forward_private,
cross-profile DROP/permit order, MSS and backend errors. Exact rule ownership is
reserved before mutation; failed cleanup retains retry records. Setup and rollback/
cleanup each have a shared 15-second budget; kernel file I/O is not forcibly interrupted.

Gateway review covers TUN generation, family/subnet and remembered WAN ownership,
kill-switch order, partial exit setup guards, independent cleanup and sysctl release.
Cleanup uses installed selectors. The shared sysctl journal persists originals before
writes, verifies PID/start-time, namespace cookie and original interface witnesses,
confirms readback and preserves administrator-changed values. No dead production
helper was confirmed; active compatibility/recovery paths remain.

## Q17-F001, P2: unsafe historical gateway harness

The old test_gateway_nat.py copied an executable to the lab, killed processes by
configuration substring, deleted host rules by tag substring and removed shared
known_hosts. Command failures did not reliably fail the runner. Its replacement
requires candidate SHA/output/read-only package directory, fresh NET/mount/PID and
private state; command or host-state failure is fatal. Active services are preserved.
Client hook trust checks belong to Q32 and are not claimed by this runner.
The shared packet fixture adds --ipv4-gateway.

## Qualification

| Check | Result and basis |
|---|---|
| Current Linux code | Q16 retained run: 2374 unit PASS, 60 ignored; 319 selected NAT/cleanup/journal/sysctl/gateway tests. Not rerun here. |
| Current candidate | Four fresh isolated cases, 228 checks PASS: route-policy plus three pairwise gateway backend combinations. |
| Gateway LAN | Real LAN peer, TUN and WAN MASQUERADE, private server LAN, explicit permits under DROP policy, MSS rules and forwarding readback. |
| forward_private | Actual IPv4 UDP tunnel preserves 10.87.0.2; explicit forwarding works under FORWARD DROP. |
| Stop | Exact foreign rules/routes/ip_forward/rp_filter restored; stopped gateway no longer forwards LAN. Worker restores networking and retires socket/journal. |
| Prior matrix | 204 packet checks/four backends and 416 firewalld multiprofile checks retain original hashes/times; 979 raw files verified. |

51 relevant NAT/gateway/sysctl/shared adapter source files match the 2 October evidence.
Other auth/protocol/server inputs changed since then; current Q16 qualification and
fresh packets cover them. Historical namespace/target native cookie/crash evidence
retains its own scope; the common storage/cookie refactor was reviewed separately.
No blanket execution claim is made for ignored tests.

Two fixture preparation failures remain recorded: missing return route for the new
IPv4 pool, then timestamp/counter differences in iptables-save. Final corrected cases
PASS. Raw snapshots remain complete; comparison excludes only timestamps/counters
while preserving policies, selectors and rule order.

## Reproduction and limits

scripts/test_gateway_nat.py requires --qeli, --sha256, --output and --package; use
--ipv4/--ipv6 for backends. Password is read from QELI_LAB_PASS. Raw artifacts:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q17-network-20261004.

Q25-A125 remains accepted: stop and verify cleanup before WAN rename/delete/recreate,
then reconfigure/restart. No BPF is integrated. Gateway/exit ownership is in memory;
clean stop is tested, new automatic gateway NAT replay after SIGKILL is not claimed.
Lost sysctl interface witnesses require confirmed manual recovery. Arbitrary root
rewrites and automatic backend migration are not certified.

Fresh gateway combinations are pairwise nft/legacy, legacy/nft and nft/nft. UDP inner
payload over actual TCP/UDP carriers is not a new TCP MSS/throughput benchmark; MSS
rules are verified and earlier PMTU evidence retains its scope. Rust/ABI/native inputs
are unchanged, so Q16 builds were reused. Mac/router/Windows VM runtime is user-excluded.
Active services/executables are preserved. Next: Q18 IPv6/NDP.
