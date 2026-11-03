# Q24: multipath, bonding and shared budgets

<!-- normative-sync: audit-q24-bonding-v3 -->

**DONE/PASS. Overall plan: 24/37 (64.9%), 13 remaining; next Q25.** 4 October 2026.
[Evidence](../../../../release/certification/evidence/q24-bonding-20261004.json).

## Q24-F001: one stalled carrier stopped healthy flows (P2)

The isolated Linux baseline delivered 480/480 UDP echoes across 16 inner flows.
Blackholing one secondary outer TCP carrier and starting a bounded ten-second
UDP flood stopped every flow: upload received 11 echoes, download 68, and both
received zero in the last five seconds. The baseline also timed out on the
downlink recovery ping: 16 checks passed, three failed; these failures are retained.

The client's 4096-entry queue retained TunPacket values from the small shared
native pool. A stalled writer could exhaust it and stop TUN reads for healthy
carriers. The server queue could likewise retain its whole shared 4 MiB wire pool.

The common client core now snapshots bonded uplink into one fixed pool of at
most 4 MiB. Queues retain PooledBuffer and immediately release native TUN packets,
including FIFO Wintun reservations. Client/server queues receive bounded shares,
leaving capacity for healthy streams and a temporary resume candidate. There is
no fallback allocation; overload drops the pinned flow's packet. The single-stream
TCP path is unchanged. No new INI option, wire format or public ABI.

Two new regressions exercise real pool starvation/reclamation and boundary
budgets. On the fixed binary, healthy flows received 450 echoes in the last five
seconds in **both directions**; all 19 checks passed, including recovery with
the same client process and TUN. The blocked flow may drop packets; the fix
preserves other carriers' progress, not delivery over the blackholed path.

## Layer review

Reviewed primary AUTH/server push, bearer/authenticated JOIN proofs, transcript
and epoch binding, stream caps, admission/revocation, fixed/adaptive actors,
logical slots and IPv4/IPv6 fragment affinity, directional rate buckets, shared
cover/stealth budgets, quota accounting, close/reconnect and task/socket release.
Bearer JOIN remains needed for compatibility. No other confirmed production
bug or dead production implementation was found in this section.

The manual covers the 1–16 range, ordinary stream cap and one temporary candidate,
fixed target/retry, adaptive three-second ramp without downscaling, negotiated
stable slots versus legacy modulo scheduling, and per-flow affinity. It explains
the additional bounded snapshot pool and shared session budgets. Old throughput
numbers are labelled historical, without a recorded date/SHA and not rerun here.

## Fresh qualification

| Gate | Result |
|---|---|
| Linux full-feature units | 2407 PASS, 60 ignored; strict all-target Clippy and release PASS |
| Isolated current-binary Linux runtime | 12 scenarios, 283 checks PASS |
| Shared bandwidth cap | 8 inner flows, 8 Mbps session cap; receiver 6.466312–7.777372 Mbps |
| Native reproducibility | Four independent A/B artifact pairs PASS: Windows, macOS universal, Android arm64 and x86_64 |
| Actual client boundary | 22 Windows ABI/runner checks, 23 Android JNI checks PASS |
| Frozen header | C11 and C++11 layouts/version checks PASS |
| Docs/panel | Nine documentation checks; 11 templates/1160 RU strings PASS |

Runtime includes fixed/adaptive handover and resume, grace expiry, single/fixed/
adaptive bonding, exact secondary socket failure/restoration, user revocation,
shared upload/download caps and bounded asymmetric impairment. Fake TLS, plain,
REALITY-TLS and obfs-ws are exercised. Bidirectional stalled-carrier fairness is
an additional scenario. The capacity test is not a peak-throughput benchmark.

All 347 Linux compilation inputs and fresh native source digests match the
qualified source. Canonical/consumer native copies and A/B hashes match. This
client-core change requires fresh native builds and ABI/JNI execution; old Q23
byte identity is not reused. The Java fixture runs against the actual x86_64
library on an isolated Android 14/API34 read-only AVD on .10.

## Fixture corrections and limits

A resume fixture expected 1/1 instead of the negotiated fixed/adaptive width;
it now requires the restored width. Persistent 15% loss in REALITY-TLS delayed
iperf's final control exchange until timeout. Impairment is now bounded to 18
seconds and each phase retains its own logs. The original failure remains
recorded and is not classified as a confirmed production regression.

Raw aggregate_leak_passed remains false: these Q24 fixtures do not execute the
full dedicated leak matrix. A raw host_restored=false is preserved where only
the exact three accepted ambient legacy firewall rules differ; every other
ordered rule/state must match. Working .10 service PID and binary remain unchanged.

Lab .11 still accepts TCP/22 without an SSH banner; its final host state is
unverified. All heavy jobs ran sequentially on .10 with one compiler job. The
private SDK was temporarily archived to local temporary storage for build capacity
and restored for JNI. Missing runtime libraries were extracted privately. The new
emulator enforced 6 GiB userdata and 2560 MiB RAM; inactive compiler caches were
cleared while preserving all mapped files and the working executable. First boot
created two base userdata files without changing the original seed. Repeated
read-only boot of this incomplete template timed out; kernel diagnostics showed
a /data/misc encryption-policy failure before Qeli loaded. A separate newly
owned AVD was initialized normally (23 JNI checks). Its read-only cold boot then
passed 23 JNI checks with userdata and encryption files unchanged. Original AVD
userdata stayed unchanged; all earlier raw failures remain. The fixture uses
a unique guest directory for each run, avoiding initialization-directory collisions. Mac/iOS/router/Windows VM network runtime remain user
exclusions. Physical Wi-Fi/LTE/sleep-wake, NAT64 and installed-app E2E were not
rerun. The 60 ignored tests remain excluded. No service deployment or push.
Listener snapshots compare all six fields independently of ss column padding;
PID, descriptor, address/port and state differences still fail. The final strict
JNI outer wrapper exits0 and host_restored=true without ignoring firewall rules.
Earlier raw wrapper failures are retained. Profiles remain INI-only; service/API
JSON remains permitted.
