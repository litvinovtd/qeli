# Q18: IPv6 off/manual/route/nat66 and NDP

<!-- normative-sync: audit-q18-ipv6-v1 -->

**DONE/PASS. Plan: 18/37 (48.6%), 19 remaining.** 4 October 2026.
Core: `5556a6b921bec30185f4ab8d760afc46f613e81b`.
Linux SHA256: `4c70a6595b6f5a9a9b2809c7975f12212895347fdabc9e05d4135f5a69a8a2f3`.
[Evidence](../../../../release/certification/evidence/q18-ipv6-20261004.json).

## Fixed findings

**Q18-F001, P2 — answer to invalid unicast DAD.** NS validation accepted source `::`
with a unicast destination. Three such requests received three NAs on the original
candidate. DAD now requires the target solicited-node multicast destination, as required
by [RFC 4861 §7.1.1](https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.1).
All four fresh packet cases return no answer on the fixed candidate; valid DAD still
receives an all-nodes NA with the proper flags and checksum.

**Q18-F002, P2 — warning flood at the NDP limit.** A 513-request burst on the original
candidate produced 256 answers and 257 warnings. Draining pending after logging let
every next denied packet request another warning. A per-window reported flag now
limits logging: each of the four fresh bursts produces 256 answers and one warning.
Responses resume in the next window. Existing limits remain 256/MAC and 4096 globally
per second, with at most 4096 tracked MACs. Two new unit regressions PASS.

## Layer review

| Layer | Reviewed contract |
|---|---|
| INI/validation | All 36 family × mode × NDP configurations. IPv4-only accepts off/off; NDP off accepts four IPv6 modes, auto/required only manual/route. IPv6-only fixtures disable NAT44. |
| off/manual | off installs explicit profile IPv6 transit DROP. manual leaves IPv6 firewall, forwarding, RA and DNS rules to the administrator. |
| route/nat66 | route preserves sources; nat66 restricts MASQUERADE to pool/WAN and cleans remembered exact selectors. IPv4 remains independent. |
| sysctl/cleanup | Original values journaled before writes; accept_ra=2 before forwarding. Namespace/generation witnesses and readback, foreign state preservation and retained retry ownership. Shared 15-second setup/cleanup budgets remain. |
| NDP socket/task | AF_PACKET nonblocking/CLOEXEC, Ethernet ifindex/MAC checks, socket-local ALLMULTI; supervision and fd closure on cancellation/exit. |
| NS/NA | Bounded Ethernet/VLAN parsing, IPv6 next-header, hop 255, checksum/code, nonzero options, target and DAD constraints. NA clears Override and has proper solicited/DAD flags. |
| Ownership | Active exact lease wins; delegated prefixes require session-registry ownership. `/0` does not authorize NDP. Revoked/closing sessions cannot authorize a new answer. |

No dead production helper was confirmed; compatibility and recovery paths remain.
RU/EN manuals now explain DAD, rate limits and the in-flight answer boundary on revoke.

## Qualification and reproduction

- 2376 Linux unit PASS, 60 ignored; strict all-target Clippy and release build PASS.
- Four fresh NS/NA cases: nft/route/TCP, nft/manual/UDP, legacy/route/UDP,
  legacy/manual/TCP — 184 checks PASS. Real authentication, exact/delegated addresses,
  default `/0`, upstream reachability, malformed NS, disconnect/reconnect, control kick,
  clean stop and a separate responder SIGKILL phase.
- nft and legacy: 446 checks PASS — four simultaneous profiles, DNS UDP/TCP A/AAAA
  on both families, reload/refusal, 36 configurations and all 16 ordered mode pairs
  through stop/restart, including four same-mode restarts. The same profile/TUN/listener/
  pool is used across steps, with cleanup verified after each stop.
- 630 fresh runtime checks on the fixed SHA. Original baseline: 35 separate checks;
  its invalid DAD answers and warning flood are not declared fixed-candidate PASS.
- Four native targets pass independent A/B builds; copies, manifest and provenance
  verified. Windows/macOS and Android arm64/x86_64 builds are not installed-app E2E.

Use scripts/audit_ndp_session_packet.py (--extended; --baseline for the original defect)
and scripts/audit_worker_ipv6_multiprofile.py (--transitions), with mandatory binary SHA
and fresh NET/mount/PID. Raw:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q18-ipv6-20261004.

Earlier 248 NDP and 118 multiprofile checks retain original SHAs/times. 513 raw files
are verified, with 32 relevant unchanged source hashes per record. Changed NDP code
gets fresh qualification; old execution is not relabeled with the new SHA. Q16 transport,
leak and soak evidence retains its scope: changes are confined to server NDP. No new benchmark.

Preparation failures remain recorded: slash in a baseline packet filename; NAT44 enabled
in an IPv6-only fixture; insufficient Android disk headroom. Corrected runs PASS.
Only completed private unit/Clippy caches were retired. Working services/executables and
user WIP are preserved. The previously accepted ambient legacy firewall delta on the
desktop lab is separately recorded without causal attribution.

## Limits

Configuration validation is exhaustive for three families; runtime transitions are dual-stack
and restart-based, not live SIGHUP routing mutation or the full family × carrier product.
Earlier IPv6-only runtime qualification retains its scope. Fresh NDP coverage is pairwise,
not eight fresh cells. Physical provider/SG and VLAN trunk behavior is not certified.

Clean stop verifies rules/routes/sysctls restore. SIGKILL verifies responder cessation
and socket-local ALLMULTI release, not full firewall/sysctl restore. Lost interface
witnesses require confirmed manual recovery. Registry removal prevents NEW answer
authorization, but a previously built/queued NA may leave later. UDP process death may
first require a liveness timeout. No instantaneous in-flight purge is promised.

Q25-A125 same-name WAN replacement remains user-accepted: stop/verify cleanup before
replacement, then reconfigure/restart. No BPF integrated. Mac/router/Windows VM runtime
is user-excluded. No blanket execution claim for the 60 ignored tests. Next: Q19 DNS.
