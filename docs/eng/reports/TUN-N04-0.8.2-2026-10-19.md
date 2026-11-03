# N04: Linux TUN drops — 19 October 2026

Client TUN queue overflow was confirmed. Linux raw TUN input in UDP sessions now
runs on the transport runtime, removing the per-packet reader-thread handoff.
The buffer budget and `tun.tx_queue_len` were not increased. Controlled A/B showed
about 12–13% less client CPU and substantially fewer TUN drops. This is not a
universal zero-loss or throughput guarantee.

## Identity and method

Original candidate: commit `7fb94dd3858072cf67ecb3633619728b8a2cbd3c`, Linux SHA256
`15a181d5f9de851826839dfe8413ea4ee9b1ff798cb25d6d403ac2bcddcdda9a`.
Final **test ELF**, not a published release asset: SHA256 `8e3c4bc0de6abe2a9cd1bf76a5d283210d29d0bad2d57d5d6c2c8c5bf59f7008`.
[Compact evidence](../../../release/lab-results/n04-tun-20261019.json) contains the
source hashes, build commands and numeric results.

VM300/server and VM301/client: 2 vCPUs / 2 GiB each, kernel
`6.12.111+deb13-amd64`. VM302 built binaries; builds and measurements did not overlap.
Native UDP FakeTLS/QUIC, Recordizer **required**, verified `PACKET_MUX_V1 active`;
inner IPv6 upload, 1200-byte UDP payload, `15 s / -O 3`. Outer IPv4 MTU1500,
TUN MTU1400; both kernel queues remained 1000 during A/B. Only the client changed;
the server retained the exact original candidate.

`tun.tx_queue_len` counts **kernel → Qeli queued packets**. `tun.queues` counts
server multiqueue descriptors: these sessions actually opened **2 server and 1
client descriptors**. The kernel's advertised `num_tx_queues=256` is not that count.

Neither current guest has `vpn-nat.service`. The historical environment-control
FAIL involving that service on the older lab is preserved and is not used to
explain current drops. A separate final check of both guests passed: no owned
processes, TUN interfaces, lock or private trace instances remain.

## Locating the losses

On the exact original candidate, the built-in `skb:kfree_skb` histogram reported:

| Diagnostic load | Client queue | TUN TX drops | FULL_RING at tun_net_xmit | Histogram missed hits |
|---|---:|---:|---:|---:|
| QUIC UDP1500 | 1000 | 922359 | 922359 | 0 |
| QUIC UDP1500 | 2000 | 46414 | 46414 | 0 |

These are overload diagnostics, not qualified throughput results. Queue2000 did
not remove pipeline overload: the server's Qeli UDP sockets also dropped 108525
datagrams in that window. Reducing one counter does not remove all end-to-end loss.
No larger default was introduced. A [kernel event histogram](https://docs.kernel.org/trace/histogram.html)
aggregated reason/location counts; no BPF program or packet contents were collected.

The measuring program had another bottleneck: `Udp6RcvbufErrors` grew at the
iperf receiver while Qeli's checked carrier sockets had zero drops in the first
47 windows. Later A/B explicitly requested `--window 4194304`; both endpoints'
JSON reports verified 8388608-byte actual buffers on Linux. Receiver-buffer errors
were absent from those later A/B windows. Global sysctls were unchanged.

Profiling found crypto cost and frequent thread switches. The change removes the
packet/buffer handoff, preserving crypto, wire format, Recordizer, replay protection
and fragment limits. Batch handoff and a smaller `try_send` optimization were
rejected after three pairs each: passing unit tests did not establish a network gain.

## Controlled reader comparison

Three alternating stock/new pairs used identical server, INI, queues and MTU.
This is prototype3, SHA256
`e1a18682c3f1685653b7f10cfd99eae2a05a91d56898f36baa4c495ff15a55ac`.
CPU medians use **100% = one logical CPU**, not the entire two-vCPU guest.
Each TUN-drop triplet lists all three windows.

| Mode / offered | Stock TUN drops | New TUN drops | Stock → new CPU | Median goodput stock → new, Mbps |
|---|---|---|---|---|
| FakeTLS / 900 | 19519, 0, 0 | 0, 0, 0 | 114.24% → 99.33% | 899.44 → 899.61 |
| QUIC / 950 | 7475, 3465, 0 | 0, 178, 148 | 116.56% → 102.38% | 949.43 → 949.24 |

QUIC's total TUN drops fell by 97%; **326 remained and are retained**.
Median context switches fell by about 24% / 39%, respectively. This improves cost
and resilience, not throughput above the offered rate. TUN counters include warmup;
iperf summaries have a different counter source and interval and must not be equated.

## Final implementation and validation

Direct input applies **only to Linux raw TUN in UDP sessions**. TCP and TAP keep
their existing reader workers; Android/macOS retain their backends. The owned fd
uses `AsyncFd::register_with_interest`; registration failure closes it before
rollback. A cancelled read returns its loan to the same bounded pool, and task
budget is charged only for completed reads. No user-facing switch was added.

A separate confirmation used the **final bytes**, after narrowing scope and
refining cooperative waiting; prototype identity is not reassigned to that ELF:

| Mode / offered | TUN drops, 3 windows | Goodput, Mbps | iperf UDP loss, % |
|---|---|---|---|
| FakeTLS / 900 | 0, 0, 0 | 899.63, 899.42, 899.77 | 0, 0, 0 |
| QUIC / 950 | 402, 77, 0 | 949.12, 949.45, 949.42 | 0.042074, 0.013126, 0.00074 |

At queue1000 the final client had zero TUN drops in three FakeTLS900 windows. QUIC950 retained **479 TUN drops** across three windows; these are not claimed fixed. Queue2000 had zero TUN drops in all three checked windows, but small end-to-end UDP losses remained. These final UDP series had no Qeli carrier-socket drops or UDP6 receiver-buffer errors at the measuring program.

The existing `tun.tx_queue_len = 2000` was also checked at UDP950 on the stock
and final clients, three windows each with the same server:

| Client | TUN drops | Goodput, Mbps | iperf UDP loss, % |
|---|---|---|---|
| stock | 0, 49401, 0 | 949.61, 917.94, 949.72 | 0.010436, 3.327378, 0.006462 |
| final | 0, 0, 0 | 949.45, 949.51, 949.28 | 0.013464, 0, 0.014136 |

This checks sensitivity to an existing parameter; no new default is introduced.
Loaded RTT was not qualified in this supplementary series, so no optimal-size or
cost-free loss-elimination claim is made.

- fmt; all-targets Clippy with transport-core-ffi and `-D warnings`; separate
  no-default-features FFI/client-bin checks: PASS.
- **17 TUN tests; 2490 library PASS / 61 ignored**. Cancellation, buffer exhaustion,
  external stop, registration errors and cancelled shutdown without runtime progress
  are covered. `nofile=8192` applied only to the test process.
- Final ELF: **8 TCP checks**, both carriers, inner IPv4/IPv6 and both directions.
  Reader-worker presence in TCP and absence in UDP were verified. Short functional
  windows are not a newly qualified TCP performance benchmark.
- Launcher exec-identity race fixed while preserving PID/start/PGID checks:
  **28 portable and 10 Linux Python tests PASS**, with a negative baseline test.

The initial `histcapacity` cleanup FAIL remains: its receipt captured Python before
the same PID/start became Qeli. A separate subsequent restoration check passed.
Original files, boot IDs, networking, firewall, qdisc and sysctls were preserved;
private trace instances were removed and global tracing restored. Foreign processes
were not signalled.

The agreed 37/37 audit scope, accepted unfixed API34 ENONET, original failures and
excluded physical platforms remain in the [debt register](../plans/AUDIT-DEBT.md).
These Linux windows do not qualify WAN or physical/mobile platform performance.
This report records the diagnostic ELF and its measurements. Distribution rebuilds,
source/native provenance and exact-commit CI are recorded separately in the
[release qualification](../../../release/certification/0.8.2.json). Measurements of
the diagnostic ELF are not automatically assigned to newly packaged files.
No release was published.

## Follow-up: local Linux CLI I/O driver

A further thread boundary remained after removal of the reader-channel handoff:
`qeli client` awaited its transport directly in a multithreaded runtime's root
`block_on`, while an I/O worker drove readiness. Frequent wakeups and context
switches reduced the CPU headroom available to drain TUN. Control-window TUN
drops exactly matched `FULL_RING` at `tun_net_xmit`. Tokio documents the root
future's execution model in its [1.53.3 documentation](https://docs.rs/tokio/1.53.3/tokio/attr.main.html#non-worker-async-function).

The `qeli client` command and standalone `qeli-client` now use `current_thread`,
placing the transport loop and I/O driver on the same thread. Server and `_worker`
retain `multi_thread`. Async background tasks and separate blocking workers remain.
Memory limits, encryption, wire format, replay protection, Recordizer and the
default queue1000 are unchanged. Native Android/iOS/macOS/Windows FFI runtimes
are outside this change.

The new baseline is dev `4a562cad76cf6d2734523d4f57c7a99ab9b67f9f`, already containing
the earlier reader fix. Both diagnostic ELFs use the same existing toolchain/cache.
Each endpoint uses the ELF of its variant; the server runtime policy stays unchanged.
Queues1000/1000, actual TUN descriptors1/2, required Recordizer, inner IPv6 UDP upload,
payload1200, QUIC950, 15 s / omit3. Order: baseline/new/new/baseline/baseline/new,
without a CPU profiler. Measuring sockets requested4 MiB and verified8 MiB on both ends.

| Variant | TUN drops, three windows | Median CPU, 100% = one core | Median context switches | Median goodput, Mbit/s |
|---|---|---|---|---|
| Baseline | 2147, 0, 804 | 101.95% | 1005173 | 949.45 |
| Local I/O driver | 0, 0, 0 | 83.07% | 217357 | 949.32 |

The additional CPU reduction is 18.5%, with 78.4% fewer
context switches. Percentages from different baselines must not be added.
A separate **60 s / omit3** QUIC950 window at queue1000 had **0 TUN drops**,
**949.91 Mbit/s** goodput and **0.00047113%** end-to-end UDP loss.
Qeli carrier sockets and the measuring receiver's UDP6 buffers recorded no drops
in these A/B and long windows. Zero TUN drops do not imply zero end-to-end loss.

Another **16 functional windows** covered TCP FakeTLS/Reality-TLS and UDP
FakeTLS/QUIC, inner IPv4/IPv6 and both directions. These used uncapped inner TCP:
some TUN drops at saturation remain and are retained in the evidence. They are
functional checks, not a new speed qualification or universal zero-loss claim.
TCP reader workers and direct UDP reads were verified. fmt, all-targets Clippy
with transport-core-ffi/client-bin and `-D warnings`, CLI unit tests and a standalone
Linux client release build passed. Original files/network state were preserved
on both hosts after every run; private trace instances were removed.

Original helper-setup, formatting and missing-fixture failures remain locally;
ownership, restoration, build targets and warning checks were not weakened.
Rustfmt later removed one blank line without changing Rust tokens. Diagnostic ELF
and source identities and exact numbers are in the [compact evidence](../../../release/lab-results/n04-quic-locality-20261019.json).
Previous packaged-ELF `bae6320b…` results, including 221/355 drops, remain unchanged.
This receipt describes the diagnostic stage. Rebuilt distribution identities and
the draft qualification are tracked separately in the
[release manifest](../../../release/certification/0.8.2.json); diagnostic-ELF
measurements are not reassigned to new files. No publication.
