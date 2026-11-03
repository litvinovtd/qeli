# Q15-F002: local reply address for wildcard UDP

25 September 2026. Base `f7f6a7a8`. D06/D09/D10, Linux server. **P1, availability.**

## Defect and reproduction

After a server-address change, the client could receive no ServerHello even though the
server received ClientHello and sent replies. With `bind.address = 0.0.0.0`, traffic to a
secondary local IP received ordinary `send_to` replies from the route's primary address.
The client's connected UDP socket rejected the different endpoint. `recvmmsg` retained
only the remote peer, losing each incoming datagram's local destination.

The original [Q25-F107/F108](AUDIT-Q25-FIREWALL-TASK.md) FAIL is retained. Additional capture
of **actual Qeli** packet headers confirmed 62 packets to `192.0.2.3` and 127 replies from
`192.0.2.1`. This verifies the application, not merely a separate UDP echo socket.

## Fix

Shared `udp_source` owns a local-address value. The Linux server enables `IP_PKTINFO` or
`IPV6_RECVPKTINFO`; `recvmmsg` receives a separate control buffer per datagram. Parsing
checks sizes, truncation, duplicate pktinfo and unicast, retaining IPv6 link-local scope.
Missing/invalid metadata never authorizes a random or previous source. Control buffers
have 64 bytes and native alignment on 32/64-bit targets. Scratch pointers are cleared
after syscalls; old addresses are cleared before the next receive.

`ObfsUdp` creates an immutable view of the original listener with its local address.
A bounded 32-view cache per receive worker creates no additional kernel sockets; sessions
retain their `Arc` independently of eviction. The address travels through handshake,
AUTH, data, control messages and roaming mailboxes. Single/try/batch sends use
`sendmsg`/`sendmmsg` with that pktinfo, without shared source-address mutation or a mutable
last-client-address cache.

Roaming identity compares the shared socket and local endpoint: a recreated view after
cache eviction still denotes the same path; another local IP denotes another path.
Reverse PMTU probes bind their temporary socket to the active path's actual address,
not wildcard. IPv4 sets `ipi_spec_dst` without a nonzero `ipi_ifindex` overriding it with
the interface's primary address. IPv6 link-local retains its scope.

INI, wire format and C ABI are unchanged; no new options. Connected client APIs retain
their ordinary behavior; shared batch/obfs algorithms were not duplicated.

## Validation

- **6 new Linux regressions + 1 privileged IPv6 PASS**: invalid/missing/duplicate pktinfo,
  link-local scope, retained sources across interleaved destinations, plain/obfs,
  single/try/batch sends, no stale source after failure, and short peer-address arrays.
- Real server with **2 SO_REUSEPORT workers** and two active clients: IPv4/IPv6 ×
  fake-tls/obfs, **8/8 fixed connections**. **256/256 inner UDP echo packets** returned.
  Capture of **332 reply datagrams** found no wrong source IP. Data sets included
  short and 1202-byte packets; this is not a throughput test.
- Baseline `f7f6a7a8`, both IPv4 wire modes: primary address works, secondary cannot connect;
  **96 wrong-source replies**. Harness exit 0 explicitly verifies that defect; secondary
  client exits 1. This is not a baseline availability PASS.
- Original wildcard refresh-fault recovery rerun: client exit 1/failed retains protection,
  six direct UDP probes blocked, explicit restart reaches Running and restores exact network
  state. Heartbeat remains 8/8 ticks. The F107 client driver is unchanged: the server is fixed.
  New capture replies use `192.0.2.3`.
- **38/38 network cells**, 34 crash/recovery, **1220 main + 806 nested checks PASS**. Both
  nft/legacy arrangements, the second with private firewalld: **1088** protected direct
  attempts blocked; **656** allowed probes received replies.
- Final snapshot: **1564 host + 71 config; 2125 Linux + 47 privileged + 8 lifecycle PASS**.
  All 9 host/cross/feature/lint/format commands PASS; the existing Clippy
  `chunks_exact_to_as_chunks` allowance remains. RU/EN docs-as-code and `git diff --check` PASS.

## Evidence and limits

Lab: only `10.66.116.11`, Debian/Linux 6.12.105+deb13, Rust 1.97;
local Windows/Rust 1.98. `10.66.116.10` was not used. Runtime uses private NET/mount/PID
and separate `/run`, `/var/lib`, `/var/log`, `/etc/qeli`, `/tmp`.

Artifacts: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`.
`udp-local-phase/evidence.json` verifies **351 source files**, 22 scenario hashes,
packet headers, client status/exit, UDP echo results, before/after rules/routes/TUN,
state markers, matrix and archives. Packet payloads are not retained in capture.
`udp-local-native-v1` contains two baseline and four fixed scenarios, two clients each;
`udp-local-baseline-v1`/`udp-local-recovery-v1` retain the original FAIL and successful
recovery under the same conditions with the unchanged old client driver.
`udp-local-matrix-v1` is the full repeated matrix; `udp-local-linux-v3` contains final
unit/privileged/build/lifecycle results.

Intermediate Linux v1 FAIL is retained: the new test cloned an empty BytesMut and obtained
buffers without spare capacity. V2 passed after fixing the test. Final v3 changed
`[usize; 8]` to 64 bytes independent of pointer width. V2 and v3 executables are
**byte-identical by SHA-256**: native-v1 used frozen v2, matrix/recovery and final tests
used v3. Native evidence therefore covers the same executable; the validator separately
checks the sole source difference and both binary hashes.

Reproduce: `scripts/audit_udp_local_address.py --qeli <fixed-worker> --baseline <F107-worker>
--artifacts <new-directory>`. Requires root and a disposable Linux lab. These are actual
Qeli clients/server; INI, accounts and keys are fixtures. Exact original fault-recovery
reproduction is retained in `udp-local-phase/capture-baseline.py` and job commands.
| Artifact | SHA-256 |
|---|---|
| `qeli-udp-local-v2-worker / qeli-udp-local-v3-worker` | `41ee7a9b03f1c44350054683f00703f6a395fd067aa3886e58488ae876087a36` |
| `qeli-firewall-task-v1-worker (baseline)` | `584d73ff8048be5da5cb5391b462f6dfeea4447f89a0fe86317defc3c808651d` |
| `linux-source-final.tar.gz` | `9c676d6e9af5bae730f20e2341e28765a0491c66824d1ce4af703eca4f776703` |
| `udp-local-matrix-v1.tar.gz` | `02cedacbad442e719a967ded4e0a9928dd9ac28fe974f941ab7487198b864c50` |
| `udp-local-native-v1.tar.gz` | `2430cf569c13eb4a2ef90c8cc4395a5cc430740f00fc0d1a1aa13eee714e7855` |
| `udp-local-baseline-v1.tar.gz` | `69525a08935d1286e62a88943b308767417c5cb80526ae240fefc2c23016639d` |
| `udp-local-recovery-v1.tar.gz` | `0388e1ca75a739ed7dc78abcd1741f20b4181af570fa663b01bb87782aead8e7` |
| `lifecycle-udp-local-v3.tar.gz` | `0e54313a1a05e2efd2370723b93ce5f4dc62dd3729f647b5a5669ec3132bc11b` |
| `udp-local-scripts-v1.tar.gz` | `5d8fe861872e88008090544b7ee109c63ce763d4f422f7ebd5a774cb1cb58bd0` |


Wildcard UDP with two local addresses is closed within the tested boundaries. D06/D10
remain open for process-global DNS/carrier state, dynamic WAN/IPv6, all multiprofile/
firewalld combinations and the full roaming matrix. Link-local scope is checked at the
value/control-parser layer; new native IPv6 scenarios use ULA. These tests do not certify
multicast/broadcast, IPv4-mapped listeners or arbitrary policy-routing/VRF combinations.
Loss of a local address carries no promise of seamless migration of an established path.
No performance measurements were taken here; D14 remains open.

D05 and D11/D12/D13/D15 also remain open. No new full-audit sections were opened.
Windows VM, Mac/iOS and physical-router runtime remain **SKIPPED by user decision**, not PASS.
Debt: **4/15 DONE (26.7%), 9 IN_PROGRESS, 2 TODO**.

Linux contract: [in_pktinfo](https://man7.org/linux/man-pages/man2/in_pktinfo.2type.html),
[IPv6 packet information](https://man7.org/linux/man-pages/man2/IPV6_RECVPKTINFO.2const.html).
[Register](../../plans/AUDIT-DEBT.md) · [Manual](../../manuals/OPERATIONS.md).
