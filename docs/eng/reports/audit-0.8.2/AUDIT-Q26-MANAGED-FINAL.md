# Q26: shared C# and managed/native boundary — DONE/PASS

5 October 2026. Base `73aa48a2`; .NET SDK 10.0.300, Windows. Closed within available
scope; Mac/iOS, router and Windows VM network runtime are user exclusions. This is
neither a live desktop VPN connection result nor a new benchmark.

<!-- normative-sync: audit-q26-managed-final-v1 -->

## Reviewed layers

| Layer | Checks and conclusion |
|---|---|
| Configuration | ConfigCore, generated VpnConfig, INI/link import/export/runtime and native validation. The shared Rust parser owns policy; generated bindings/matrix match the schema. JSON remains service DTO/API, fixtures and internal storage; user configuration is INI. |
| Profiles/settings | Null/ID validation and ID migration, bounded reads, atomic writes/backup, quarantine before empty recovery, sidecar locking and stale-write refusal. Conformance races two independent processes and verifies exact winner/backup bytes. Platform DPAPI/Keychain encryption belongs to Q27/Q28. |
| ABI | Cdecl, sequential structure sizes, synchronous pinned buffers and copying responses before release; temporary config/request buffers are zeroed. The existing ABI floor is 1.16; stale 1.11/1.15 comments were corrected. Managed notifications are not native callbacks retaining function pointers. |
| Lifetime | New/stop/free, events/sequence/stats, invalidated handles, packet tasks/cancellation and ownership after timeout. No Rust memory UAF is claimed: the registry retains leased Arcs; premature managed TUN/network-state reuse was the problem. |
| Dead code | Production QeliShared excludes Crypto/Protocol and LinkConformance. Reflection confirms PacketCipher/PacketCodec/LinkConformance and BouncyCastle references are absent. Retained primitives have standalone conformance consumers and are not deleted as dead code. |
| Harness | Desktop CI requires fixtures. Missing fixtures, empty config corpus and removed generated csharp platform all fail with exit 1 and no SKIP. README clarifies the separate legacy hand-written schemas. |

## Confirmed defects and changes

- **Q26-F218 — observer exceptions.** Log/Status/ConnectionDropped could interrupt
  lifecycle/cleanup; RunCompleted protected only the whole multicast. Every subscriber
  in all four notifications is now isolated. Failures are not sent back through LogLine.
  Four old-code FAILs reproduce interrupted Log/Stop and skipped later subscribers.
- **Q26-F219 — packet tasks and ownership.** Pump faults/early completion were not
  monitored in the native event loop. Cleanup ignored unfinished timed joins (2/2/5s)
  and could free the handle before teardown/reconnect reused managed state. The loop
  now reports the pump's original cause; the generation owner joins all workers before
  free. Outer Stop retains its existing 8s limit: timeout keeps the live task, TUN and
  ownership for a later Stop. CTS disposal follows join. Conformance executes the real
  Stop timeout and successful retry using a fake TUN.
- **Q26-F220 — update response body.** ResponseHeadersRead ended HttpClient.Timeout at
  the headers; JSON body reading could stall or grow without a budget. One linked token
  bounds headers+body to 10s; reading stops at 1 MiB plus one sentinel byte. Errors still
  produce no update notification. Ordinary/exact-limit/endless/stalled/malformed bodies
  are covered. No real HTTP endpoint or full 10s network stall was injected.
- **Q26-F221 — route_file reading/batching.** File.ReadLines allocated a line without a
  pre-newline bound; 512 long Unicode-comment lines could exceed the 2 MiB service
  request after serialization. The old parser actually reproduces Configuration request
  too large on eight valid long comments. The shared desktop reader caps lines at 65,536
  UTF-16 units and checks cancellation per 4096-character chunk; batches are capped at
  512 lines/131,072 characters. CR/LF/BOM behavior is retained; overflow names source/line.
  The existing 250,000 unique-route limit stays. Boundary, mixed endings, pre-newline
  cancellation and Unicode batching pass alongside the 14,113-route CIDR/OpenVPN,
  merge and cancellation regressions.

An empty config-boundary corpus now fails the gate; this is a harness correction, not a
new user-parser defect. Rust still owns limits/validation policy.

## Validation

- **543/543 shared conformance PASS**, 0 FAIL/SKIP; 32 new checks above the 511 baseline.
- **143/143 Windows platform selftest PASS**; Release QeliConformance/QeliWin/QeliMac
  builds have no warnings/errors. Mac was compiled on Windows using the local NuGet
  cache; compile-only, not macOS runtime. The initial no-restore/missing-assets failure
  is retained; offline restore changed build prerequisites only.
- 32 actual DLL handle generations exercise New/SetDeviceId/Start/Poll/Stats/Stop/Free,
  sequence order and invalidated IDs without OS route installation.
- Three negative runs on isolated final-runner copies produce expected exit 1:
  missing fixtures (8 FAIL), empty boundary (1 FAIL), removed csharp (1 FAIL), 0 SKIP.
- Generated bindings/matrix, RU/EN docs, panel, diff and native provenance/checksums pass.
  Rust/native inputs and all 14 checksum rows are unchanged. Native A/B and Linux network
  matrix were not rerun; prior executions retain their dates and qualification limits.

## Evidence and scope

`release/certification/evidence/q26-managed-20261005.json` records source/artifact hashes,
results and raw hashes. Raw root:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q26-managed-20261005`.

Initial harness mistakes remain: expecting stale -11 without a pending plan where the
ABI correctly returns InvalidState -3, and catching the wrong wrapper exception type in
baseline route reproduction. Only harness expectations were corrected; reruns are separate.

No live desktop connection with real TUN/firewall, Mac runtime, physical roaming, peak
benchmark or endurance soak is claimed. Observer callbacks must return; exceptions are
isolated but arbitrary stuck subscriber code cannot be interrupted. Synchronous OS file
reads are not forcibly interrupted; cancellation is checked between chunks. A stuck
worker makes Stop time out while refusing state reuse. Zeroing temporary byte arrays
cannot guarantee erasure of immutable managed strings.

Working services/labs and native binaries were untouched. D06 remains the accepted WAN
identity boundary without BPF. Transfer to dev preserves human CHANGELOG/users.html
changes; no push/deploy.

**Plan: 26/37 DONE/PASS (70.3%), 11 remaining. Next Q27 — Windows GUI/service/drivers.**
