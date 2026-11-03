# Qeli 0.8.2 — consistent configuration and reliable operation / единые конфиги и надёжность

The 0.8 line remains beta. Линейка 0.8 остаётся бета-версией.

**Language / Язык:** [English](#english) · [Русский](#русский).

## English

### What we worked on and why

Qeli 0.8.2 focuses on consistent configuration and reliable operation through reconnects,
restarts and partial failures. We reviewed the path from entering a setting in the panel
to parsing it in the core, applying it to the operating system and recovering from errors.

The work followed a [37-section system audit plan](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/plans/FULL-SYSTEM-AUDIT.md):
configuration, panel and API, authentication and cryptography, transports, IPv4/IPv6,
DNS, clients, installation, dependencies, tests and documentation. Each section covered
code review, normal and invalid inputs, failures and concurrency, available integration
tests, and verification of fixes. All 37 sections are complete within the agreed scope.
This was an internal engineering audit; accepted limitations and excluded physical
platforms remain recorded in the [audit debt register](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/plans/AUDIT-DEBT.md).

### Scale and main outcomes of the audit

At the qualified release-preparation snapshot [`3acf33f0`](https://github.com/litvinovtd/qeli/commit/3acf33f0af881ecd762fa2c5ec2dc70fc327460c)
on 17 October, development since 0.8.1 comprised **1,233 commits: 1,208 non-merge
commits and 25 merge commits**. This includes product changes, refactoring, tests,
build tooling and documentation; it is not a count of individual defects. The audit covered
**37 system areas**, with **323 audit reports**, each available in English and Russian;
translations are not counted as additional investigations.
[Changes since 0.8.1](https://github.com/litvinovtd/qeli/compare/v0.8.1...3acf33f0af881ecd762fa2c5ec2dc70fc327460c)
· [Audit report catalogue](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/audit-0.8.2/README.md).

The most important results are stronger rules for how the system behaves:

- **Failure must not silently remove protection.** Audited network operations track
  resource ownership and verify rollback; incomplete cleanup retains the protective
  block and the information needed to retry recovery.
- **Verify the server before sending credentials.** The shared core rejects invalid
  server proofs and degenerate static keys in the reviewed authentication paths.
  Key-file errors no longer silently replace an existing identity with a new one.
- **One interpretation of configuration.** Clients share the native INI/URI contract,
  while panel transactions detect stale edits and validate configuration before
  applying changes.
- **Evidence beyond a successful build.** Native A/B rebuilds, ABI/JNI checks,
  source/artifact hashes and exact-commit CI tie checks to identified inputs.
  Historical results and unavailable physical platforms are not silently counted
  as fresh successful tests.

For Qeli, this means a more predictable foundation: fewer client-specific differences,
explicit failures instead of false success, and more controlled recovery after an
interrupted operation. It does not mean that every possible failure has been eliminated.

### Main changes since 0.8.1

- **One configuration contract across clients.** INI and `qeli://` parsing and validation
  now use the shared native core. Duplicate client parsers were removed; common positive
  and negative fixtures check the adapters. This reduces differences in how clients
  interpret the same settings. Feature availability still depends on the OS.
  [Configuration-core plan](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/plans/CLIENT-CONFIG-CORE.md).
- **INI configuration throughout.** The panel retains its form and INI editor; its JSON
  configuration editor was removed. Notifications use `notify.ini`. JSON remains a format
  for internal API messages and service payloads.
- **Safer panel changes.** Saves detect stale revisions; INI writes are private and
  atomic. Validation, quoting, masked secrets, access lists, backup/restore and restart
  checks were corrected. Loading or validation failures preserve the working
  configuration. Listener changes require a full restart instead of an ineffective
  worker restart.
- **Authentication and key handling.** Panel and VPN password checks share a bounded
  Argon2 budget. TCP authentication has time/input limits; retained hybrid key material
  is wiped, and degenerate static-key binding is rejected.
  [Cryptographic review](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/audit-0.8.2/AUDIT-Q08-CRYPTO-KEYS.md).
- **Controlled network recovery.** Route, firewall, DNS and forwarding operations have
  stronger ownership, rollback and crash-recovery checks. NetworkPlan setup and cleanup
  each have a shared 15-second budget. Incomplete cleanup retains the protective block
  and reports the failure.
- **Transport and session fixes.** HTTP/2 tasks are released on cancellation; sending
  handles partial flow-control windows, and bonded rate limiting keeps the full shared
  debt. Incomplete management messages no longer receive premature acknowledgements,
  and conflicting duplicates are rejected. DATA_FRAG authentication and resource limits
  received additional tests. REALITY-TLS traffic keys have explicit lifetime limits
  followed by reconnection.
- **Client lifecycle and private storage.** Targeted fixes cover Android startup readiness
  and recovery, Windows GUI/service transitions and trusted DLL/profile loading, macOS
  helper/storage ownership, and iOS profile/Keychain/MDM handling. Native startup, protected
  storage and cleanup errors are reported instead of appearing as successful connections.
  Windows/macOS retry transient network restoration before reconnecting, with bounded
  failures and cancellation. Incomplete cleanup retains the kill-switch and resource
  ownership; unexpected reconnect-loop faults reach a visible Error state.
  Android and iOS clear the saved log after a completed VPN disconnect by default;
  the new setting can be disabled to retain diagnostics. Reconnects and network pauses
  preserve the log.
- **More useful administration.** Responsive host-load cards, interactive log-level filters
  and refreshed user bandwidth limits improve the panel. Linux/OpenWrt/Keenetic lifecycle
  hooks receive the applied network/connection context. Installer, updater, permissions
  and secret-handling paths were reviewed and corrected.
- **Verified build inputs.** Native libraries were refreshed and independently rebuilt A/B
  for reproducibility, ABI/JNI and configuration checks. Updates include rustls 0.23.46,
  tokio-rustls 0.26.6 and h2 0.4.20. The TLS update restores propagation of deferred read
  errors; h2 fixes framing, stream-limit and shutdown handling. Gradle 9.8.1 addresses
  three high-severity build-tool vulnerabilities; its Kotlin locks/checksums and
  AndroidX Core 1.19.1 runtime notices are aligned. Publication tooling checks source identity, runtime
  evidence, notices and exact-commit CI. Pending CI is now awaited instead of causing
  premature publication refusal.
  The final dependency update also includes Tokio 1.53.3, serde_json 1.0.154,
  libc 0.2.190, sha2 0.11.1 and zeroize 1.9.1. NDP socket registration follows
  Tokio's explicit ownership contract; CI actions use setup-java 6.1.0 and
  upload-artifact 7.0.2. Temporary Git test repositories disable automatic
  maintenance so detached maintenance cannot race their cleanup.
- **Less duplicate and obsolete code.** Besides client parsers, obsolete loading paths
  and six unused performance implementations were retired. Benchmark checks reject
  incomplete or duplicated measurement phases.

### IPv6 with administrator-managed routing

The new `routing.ipv6.mode = manual` separates external network administration from
Qeli's tunnel and explicitly requested NDP proxy.

| Mode | Responsibility |
| --- | --- |
| `off` | Qeli blocks the profile's IPv6 transit. |
| `manual` | The administrator manages external routing, firewall and forwarding; Qeli retains tunnel addressing/client routes and can run the requested NDP proxy. |
| `route` | Qeli configures forwarding while preserving client addresses. |
| `nat66` | Qeli configures forwarding and NAT66. |

NDP proxy supports `manual` and `route`. `ndp_proxy = required` remains a startup
requirement; `manual` does not enable external forwarding automatically.
[Configuration manual](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/manuals/CONFIG.md).

### Testing and results

- Unit, configuration-conformance and regression tests covered malformed inputs,
  cancellation, concurrent operations and preservation of the working state.
- Retained evidence covers **20 required Linux runtime cases**, including network
  application/recovery and IPv4/IPv6. ABI/JNI checks and Android emulator tests
  complemented platform builds.
- Cryptographic checks included **60 NIST ML-KEM-768 known-answer cases**, RFC vectors
  for X25519 and ChaCha20-Poly1305, and independent HKDF checks.
  These check implementation consistency, not external security certification.
  [Cryptographic checks and limits](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/audit-0.8.2/AUDIT-Q08-CRYPTO-KEYS.md).
- During the audit, **15 ASan fuzz targets** exercised parser/protocol boundaries;
  their original pinned run completed **85,930,590 iterations**. A complete
  eight-phase endurance run lasted approximately **13 hours 4 minutes**, including
  10,000 TCP and 10,000 QUIC cycles, additional UDP adapters and predefined resource
  budgets. These are retained audit-campaign executions, not claims that the full
  campaign was rerun for each subsequent release candidate.
  [Q35 summary](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/audit-0.8.2/AUDIT-Q35-FINAL.md)
  · [Endurance report](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md).
- The Linux client queue change is integrated into `dev`, rather than left in a
  separate worktree. The release is rebuilt from that unified source: native cores,
  Linux/DEB, Android, Windows, macOS and router binaries. Admission requires the
  existing CI suite and fresh execution of the required Linux runtime cases against
  the actual new CLI; old candidate results are not rebound across changed code.
  [Current qualification and artifact identities](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/certification/0.8.2.json).
  Historical `e90bf0c2`/`3acf33f0` qualification remains in Git and its original
  evidence; it does not prove that the queue feature was present in those binaries.

These are separate test populations, not a combined test count. Reports retain source
and artifact identities, test conditions and original failures.

### Known limits

- On the measured Android 14/API34 emulator, the automatic-family `DnsResolver` call
  without an explicit network returned `ENONET` before sending a query. An independent
  minimal VPN reproduced it. Ordinary DNS, typed A/AAAA and explicit VPN-network queries
  worked in the tested scenarios. This accepted limitation remains unfixed. Secure VPN
  and the system kill switch are retained; no DNS bypass mode is added.
  [DNS investigation](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).
- Continuous identity across replacement of a selected WAN interface remains an accepted
  limitation, D06. Stop the profile and confirm cleanup before replacing that interface.
  [Details](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/plans/AUDIT-DEBT.md).
- Physical Mac/iOS, router and Windows network-VM tests were excluded from the agreed
  scope. Builds, simulator and adapter tests retain their own scope and do not certify
  every device or OEM.

### Upgrade notes

Keep the previous binary and its INI files together for rollback. Recheck settings with
the current validator: malformed addresses, duplicate sections and unsupported fields
may now be rejected. Transfer required legacy notification settings manually to
`notify.ini`: automatic `notify.json` import is removed, and restore rejects that legacy
sidecar. On Windows, refusal of an untrusted legacy service-profile store requires
explicit reconfiguration from an elevated GUI after preserving the required user data.

Windows distributions are single-file `QeliWin-standalone.exe` and
`QeliWin-net-required.exe` again. Original Cargo/.NET, core/client and driver license
texts are embedded; **About → Licenses** reads and exports them offline. Linux and
router executables provide `licenses --list`, `licenses --file PATH` and
`licenses --export NEW_DIRECTORY` without starting VPN. The separate
`qeli-native-legal.zip` is no longer a release download; original texts and indexes
remain available inside the binaries. This does not replace source availability
or other license obligations.

The download set contains 16 files including `SHA256SUMS`: Android APK, two Windows
EXEs, the macOS universal ZIP, Linux executable and DEB, six router executables,
and three router installation/feed files. Qualification records are kept in the
[source repository](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/certification/0.8.2.json),
not as separate `PROVENANCE.json` / `QUALIFICATION.json` downloads. This beta retains
the qualified DEB without a new release-build attestation; strict attestation
verification must refuse when no matching attestation is available. Docker publishes
the versioned `0.8.2` image separately after tag admission; a beta does not replace
the stable `latest` tag. Uploading download files alone does not create that image.

The macOS universal ZIP requires macOS 15 or newer, following the .NET 10 supported
OS baseline, and includes both Apple Silicon and Intel code;
extract the complete `Qeli.app` on macOS, preserving executable permissions. It uses
ad-hoc signatures, without Developer ID notarization or the per-app system extension.
The Android update retains the existing release certificate; package signatures,
alignment and the included current JNI libraries are checked. This does not replace
installation and upgrade testing on your physical device.

Full change list: [CHANGELOG.md](https://github.com/litvinovtd/qeli/blob/v0.8.2/CHANGELOG.md).

### Short check of the final Linux binary

On **19 October 2026**, a fresh short run tested the actual
`release/dist/v0.8.2/qeli-linux-amd64` on **both VM300/server and VM301/client**.
SHA256: `e4cb6e055854806bcef7c61f394ea696cbf9cde3de90fef7b5f0f02e60326ddb`.
These are new measurements of the packaged ELF, not reused diagnostic-build results.

Lab: Intel i5-8500, **2 vCPU / 2 GiB per VM**, Linux `6.12.111+deb13-amd64`;
IPv4 underlay MTU1500, TUN MTU1400, client/server queue **1000/1000**.
Only **Recordizer required**, with authenticated client settings and verified
`PACKET_MUX_V1 active`. No rebuild, reboot or tuning; neither Proxmox nor VM302
ran tests or builds for this repeat. iperf requested 4 MiB buffers on both sides,
with 8 MiB actual buffers confirmed. The **initial 23 windows** total about four minutes
of load; startup, state snapshots and restoration checks are additional.

UDP: inner **IPv6 upload**, 1200-byte payload, **three 15 s / omit 3 windows**:

| Native UDP profile / offered Mbps | Median receiver goodput, Mbps | UDP loss median / max, % | Client TUN drops, three windows | Median client CPU, 100% = one core |
| --- | ---: | ---: | --- | ---: |
| FakeTLS / 900 | 899.57 | 0.005329 / 0.009025 | 0 / 0 / 0 | 81.68% |
| QUIC / 950 | 949.46 | 0.000471 / 0.004981 | 0 / 0 / 0 | 83.41% |

The separate **60 s / omit 3 QUIC950** window delivered **949.80 Mbps** with
**0 TUN drops** and **0.009591% UDP loss**. Server TUN drops, carrier socket RX
drops and `Udp6RcvbufErrors` were zero in all seven UDP windows. This is not zero
end-to-end loss: nonzero UDP loss and IPv4 `SndbufErrors` remain in the evidence.
The offered rates are test inputs, not a new ceiling search.

#### Combined TCP and UDP results across four profiles

The final matrix combines **two separate sequential series on VM300/301**, not
simultaneous TCP/UDP traffic: **48 TCP windows and 48 UDP windows**, using the same
final ELF SHA256 above, Recordizer required, MTU1400 and client/server queues1000/1000.
Each IP/direction/protocol combination has **three 15 s / omit 3 windows**.
TCP uses **P1 without a rate cap**; UDP uses **600 Mbps offered load and a 1200-byte
payload**. Each series contributes about 14 minutes of load, excluding setup and
restoration. The profile names below identify the carrier; TCP and UDP columns
identify the inner test traffic.

Goodput is the **median receiver rate in Mbps**. ↑ means client → server upload;
↓ means server → client download. Retransmits and UDP loss show **median / maximum
across three windows**. TUN drops show **client / server sums across three windows**.

| Carrier profile | IP / direction | TCP Mbps | UDP600 Mbps | UDP loss med / max, % | TCP retrans med / max | TCP TUN client / server | UDP TUN client / server |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP FakeTLS | IPv4 ↑ | 1975.01 | 599.80 | 0 / 0 | 41 / 75 | 363 / 0 | 0 / 0 |
| TCP FakeTLS | IPv4 ↓ | 2205.10 | 600.00 | 0 / 0 | 75 / 102 | 0 / 821 | 0 / 0 |
| TCP FakeTLS | IPv6 ↑ | 2006.70 | 599.69 | 0 / 0 | 134 / 142 | 714 / 0 | 0 / 0 |
| TCP FakeTLS | IPv6 ↓ | 2170.34 | 600.00 | 0 / 0 | 107 / 113 | 0 / 1312 | 0 / 0 |
| TCP Reality-TLS | IPv4 ↑ | 1124.95 | 599.54 | 0 / 0 | 52 / 98 | 2070 / 0 | 0 / 0 |
| TCP Reality-TLS | IPv4 ↓ | 1059.83 | 599.99 | 0 / 0 | 49 / 109 | 0 / 2696 | 0 / 0 |
| TCP Reality-TLS | IPv6 ↑ | 1142.85 | 599.54 | 0 / 0 | 133 / 136 | 754 / 0 | 0 / 0 |
| TCP Reality-TLS | IPv6 ↓ | 1067.03 | 600.00 | 0 / 0 | 85 / 107 | 0 / 1004 | 0 / 0 |
| UDP FakeTLS | IPv4 ↑ | 1135.56 | 599.78 | 0 / 0 | 623 / 809 | 2392 / 0 | 0 / 0 |
| UDP FakeTLS | IPv4 ↓ | 1329.65 | 600.00 | 0 / 0 | 92 / 256 | 0 / 2632 | 0 / 0 |
| UDP FakeTLS | IPv6 ↑ | 1163.33 | 599.70 | 0 / 0 | 292 / 319 | 1519 / 0 | 0 / 0 |
| UDP FakeTLS | IPv6 ↓ | 1323.54 | 600.00 | 0 / 0 | 213 / 352 | 0 / 3066 | 0 / 0 |
| UDP QUIC | IPv4 ↑ | 1165.95 | 599.81 | 0 / 0 | 219 / 255 | 1632 / 0 | 0 / 0 |
| UDP QUIC | IPv4 ↓ | 1267.63 | 600.00 | 0 / 0 | 240 / 612 | 0 / 1744 | 0 / 0 |
| UDP QUIC | IPv6 ↑ | 1192.20 | 599.80 | 0 / 0 | 141 / 737 | 1415 / 0 | 0 / 0 |
| UDP QUIC | IPv6 ↓ | 1282.99 | 600.00 | 0 / 0 | 176 / 520 | 0 / 2740 | 0 / 0 |

All **96 matrix windows completed**. UDP600 recorded **zero receiver packet loss
and zero client/server TUN drops in all 48 windows**. This is a fixed-load result,
not a throughput ceiling, and does not replace the separate 900/950 Mbps results
above, which include small nonzero UDP loss.

**TUN drops and TCP retransmissions remain under unrestricted TCP load.** TCP
packet-loss percentage was not measured; retransmits are not UDP loss, and
retransmits do not apply to the inner UDP test. TUN counters cover the complete
window including warmup, while TCP retransmits use the iperf reporting interval;
their counts must not be compared one-for-one. Some native UDP carrier windows
under inner TCP load also recorded kernel socket-buffer errors; per-window
counters are retained. These matrix runs did not include `FULL_RING` tracing.

[All TCP windows, ranges, CPU/RSS, counters, raw locations and restoration checks](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/lab-results/n04-final-dist-tcp-matrix-20261019.json).
[All UDP600 windows, counters, separate raw locations and restoration checks](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/lab-results/n04-final-dist-udp-matrix-20261019.json).

The earlier **16 TCP functional windows, 3 s / omit 1**, remain in the
[initial short-check archive](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/lab-results/n04-final-dist-repeat-20261019.json)
and are **not included in these medians**.

Original files and network state passed restoration checks on both VMs after each
series; temporary processes, TUN interfaces and locks were removed. Old binaries,
results and the separate new raw directories were retained; SHA256 remained
unchanged. This short Linux check does not replace all-platform release
qualification. The release remains unpublished by this documentation update.

### Linux UDP TUN reader follow-up

N04 located the loss at the client **kernel → Qeli TUN queue**: the kernel could
not enqueue packets while userspace was not draining it fast enough. An overload
window recorded **922,359 TUN TX drops and exactly 922,359 `FULL_RING` events in
`tun_net_xmit`**, with no lost histogram entries. This identifies the drop site,
not a new sustainable-throughput result. Controlled changes below support
per-packet cross-thread work as a contributor to insufficient reader capacity.

Linux raw TUN input in UDP sessions now runs on the transport runtime, removing
the reader-thread packet handoff and cross-thread buffer return. The bounded
memory pool, cryptography, wire format and Recordizer are unchanged. TCP/TAP and
other platform backends retain their existing reader paths; there is no new switch.

In three alternating stock/prototype pairs, client CPU fell by about **12–13%**;
QUIC950 TUN drops fell from 7475/3465/0 to 0/178/148. The subsequent, separately
identified reader-fix ELF `8e3c4bc0…` was checked at queue 1000:

| Native UDP profile / offered Mbps | TUN drops in three windows | Median receiver goodput, Mbps | iperf UDP loss, % in each window |
| --- | --- | ---: | --- |
| FakeTLS / 900 | 0 / 0 / 0 | 899.63 | 0 / 0 / 0 |
| QUIC / 950 | 402 / 77 / 0 | 949.42 | 0.042074 / 0.013126 / 0.000740 |

Thus **479 QUIC TUN drops remained after the reader fix alone**. Queue 2000 had
zero TUN drops in three additional checked windows, but small end-to-end UDP loss
remained. The default stays 1000: loaded RTT was not qualified, so 2000 is not
established as universally preferred. Enlarging the queue is not the reader fix.

[N04 method, exact test-build identities and limits](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/TUN-N04-0.8.2-2026-10-19.md).
These are identified Linux lab results, not measurements of every packaged target.
The [release qualification](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/certification/0.8.2.json)
separately records the prepared files and their required checks.

### Linux CLI runtime locality

After the reader fix, another cross-thread boundary remained: the CLI transport
loop ran in the root `block_on` future, outside the multithreaded runtime's workers,
while the I/O driver handled readiness on a worker. At high packet rates, wakeups
and context switches consumed CPU needed to drain TUN. The Linux `qeli client`
loop and I/O driver now share a **`current_thread` runtime**; standalone
`qeli-client` uses the same policy. Server/supervisor and `_worker` retain
`multi_thread`; native FFI runtimes on other platforms are unchanged.

This second A/B starts from the **already reader-fixed** base `4a562cad…` and uses
two diagnostic ELFs, baseline `c5625562…` and local I/O `04412c2a…`. Both endpoints
use the corresponding ELF, but server runtime policy is unchanged. Three pairs
ran in baseline/new/new/baseline/baseline/new order, without a CPU profiler:

| QUIC950, queue 1000 | Baseline | Local I/O driver |
| --- | ---: | ---: |
| Client TUN drops, three windows | 2147 / 0 / 804 | 0 / 0 / 0 |
| Median client CPU, 100% = one logical core | 101.95% | 83.07% |
| Median client context switches per window | 1,005,173 | 217,357 |
| Median receiver goodput, Mbps | 949.45 | 949.32 |

CPU decreased by **18.5%** and context switches by **78.4%** relative to this new
base; these percentages must not be added to the reader-fix series. The gain is
lower processing cost and fewer drops, not throughput above the offered rate.
A separate **60 s / omit 3** window delivered **949.91 Mbps**, **0 TUN drops** and
**0.00047113% end-to-end UDP loss**. Zero TUN drops does not mean zero total loss.

Both stages used VM300/server and VM301/client, **2 vCPU / 2 GiB each**, kernel
`6.12.111+deb13-amd64`; VM302 was build-only, with no compilation during load.
Native UDP, **Recordizer required / `PACKET_MUX_V1 active`**, inner IPv6 upload,
1200-byte UDP payload, **15 s / omit 3**, IPv4 underlay MTU1500, TUN MTU1400 and
client/server queue **1000/1000** were used for the comparisons. An iperf receive
buffer overflow was found before the matched series: both sides then requested
4 MiB and confirmed 8 MiB actual Linux buffers. These matched results must not be
treated as an identical-method comparison with the earlier default-buffer runs.
TUN counters include warmup; iperf loss uses its own measurement interval.

Another **16 functional windows** covered TCP FakeTLS/Reality-TLS and UDP
FakeTLS/QUIC, inner IPv4/IPv6 and both directions. Some drops at unrestricted
load remain in the evidence; these short checks are not a new TCP performance
qualification or a universal zero-loss guarantee.
[N04 report and limits](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/TUN-N04-0.8.2-2026-10-19.md)
and [exact diagnostic SHA256s and A/B data](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/lab-results/n04-quic-locality-20261019.json)
identify these measurements. They **do not qualify the final distribution binary**:
its checks remain separate in the release qualification. No release is published
by this documentation update.

### Linux client TUN queue size

The client INI now accepts the local `tun.tx_queue_len` setting in `[qeli]`:

```ini
[qeli]
tun.tx_queue_len = 1000
```

It controls the kernel-to-Qeli packet queue for a Linux client-owned TUN/TAP interface.
The default is `1000` packets; valid integer values are `1..32767`. There is no automatic
adjustment. Set `500` explicitly to restore the previous laboratory queue size.

The setting addresses burst-related upload losses identified during Reality-TLS diagnostics:
the client queue overflowed before H2/TLS, causing packet drops and inner TCP retransmissions.
An A/B/A `500 → 1000 → 500` test with the same unchanged binary (IPv4, three repetitions per
stage) showed higher P1/P4 upload throughput and fewer P4 drops and retransmissions at `1000`;
returning to `500` restored the previous throughput level.
A larger queue helps absorb bursts, but does not eliminate all losses or guarantee a speedup
on every profile or device, and may increase latency and memory use. This is not an H2
flow-control change or a fix for a demonstrated H2 bottleneck.

Use an updated client containing this feature, save the INI, then stop/start the client
(Disconnect → Connect in the panel). The setting is not carried by server push, share links
or QR codes; the same-named server setting remains independent. Omit the key entirely with
`dev_attach=true`, where the external interface owner controls the queue. Other operating
systems preserve the key without applying it. Older binaries, including earlier builds
labelled 0.8.2, do not gain this behaviour through configuration changes alone.

Configuration details and verification:
[CONFIG](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/manuals/CONFIG.md#client-tun-tx-queue).
Queue-size, IPv6 and three-transport results:
[lab report and limitations](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/TUN-QUEUE-SIZE-2026-10-16.md).

### A repeatable short pre-release check

A controller, observer and analyzer now define a fixed Linux test for transport
compatibility, inner IPv4/IPv6, transfer directions and separate mixed TCP/UDP load.
The harness checks complete results and lab-state restoration; incomplete or failed
runs do not become PASS. Its 24 unit tests pass, but the historical pilot does not
qualify newly built release binaries. The identified Linux lab snapshot below is
separate from that historical pilot and from full release qualification.
[Method and limitations](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/manuals/RELEASE-SHORT-TEST.md).

### Linux TCP and UDP lab snapshot

These measurements identify the earlier artifact below. They are not performance
qualification of the subsequent dependency-refresh binaries.

Tested Linux SHA256:
`1d94d4c412f6c1fd231765b760196b0b4f518c20135bf0ccd1b52b192710cf76`.
VM300/server and VM301/client: 2 vCPU/2 GiB each, Intel i5-8500 lab host,
kernel `6.12.111+deb13-amd64`, underlay MTU 1500, client MTU auto/effective 1400.
Recordizer **required** (`PACKET_MUX_V1 active`), client/server TUN queue **1000**;
client default verified in Linux. No rebuild, reboot or network tuning during the
measurements; Proxmox was only the hypervisor, VM302 was not used.

TCP P4, inner IPv4/IPv6, 15 seconds with `-O 3`, median of three untraced repeats,
Mbit/s. The profile name describes the carrier, not the inner workload.

| Profile | TCP IPv4 upload | TCP IPv4 download | TCP IPv6 upload | TCP IPv6 download |
|---|---:|---:|---:|---:|
| udp-faketls | 1077.1 | 1168.4 | 1074.6 | 1163.2 |
| udp-quic | 1087.0 | 1174.5 | 1074.2 | 1168.7 |

UDP is a separate earlier session on the same SHA/settings: one inner IPv6 upload
stream, payload 1200, 15 seconds with `-O 3`, n=3. Offered load is not goodput.

| Profile | Offered Mbit/s | Median goodput Mbit/s | Median loss | Maximum loss | Repeats with loss ≤1% |
|---|---:|---:|---:|---:|---:|
| udp-faketls | 600 | 599.6 | 0% | 0.0158% | 3/3 |
| udp-quic | 600 | 599.7 | 0% | 0% | 3/3 |
| udp-faketls | 900 | 885.8 | 1.5400% | 3.1293% | 1/3 |
| udp-quic | 950 | 948.9 | 0.0582% | 4.6690% | 2/3 |

UDP600 passes the loss threshold, but stable 900/950 Mbit/s in every repeat is not
established. TCP upload still has TUN drops. Only two profiles are covered; UDP
IPv4/download and the other ten profiles are not implied by these numbers.
[Full TCP/UDP tables, matched archived/current comparison, lab parameters and limitations](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/LINUX-LAB-0.8.2-2026-10-17.md).
[Separate remaining-TUN-drop diagnosis and its limits](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/eng/reports/TUN-READER-0.8.2-2026-10-18.md).

## Русский

### Короткая повторяемая проверка перед выпуском

Добавлены контроллер, наблюдатель и анализатор фиксированного Linux-теста:
совместимость транспортов, внутренние IPv4/IPv6, направления передачи и отдельная
смешанная TCP/UDP-нагрузка. Обвязка проверяет полноту результатов и восстановление
состояния стенда, не превращает неполный или неудачный прогон в PASS.
Её 24 unit-теста проходят; исторический пилот не квалифицирует новые бинарники.
Идентифицированный Linux-снимок ниже отделён от исторического пилота и полной квалификации релиза.
[Методика и ограничения](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/manuals/RELEASE-SHORT-TEST.md).


### Лабораторные TCP и UDP на Linux

Эти измерения относятся к прежнему артефакту с указанным ниже SHA. Они не являются
проверкой производительности последующих сборок после обновления зависимостей.

Проверенный Linux SHA256:
`1d94d4c412f6c1fd231765b760196b0b4f518c20135bf0ccd1b52b192710cf76`.
VM300/server и VM301/client: по 2 vCPU/2 GiB, лабораторный хост Intel i5-8500,
kernel `6.12.111+deb13-amd64`, underlay MTU 1500, клиентский MTU auto/фактический 1400.
Recordizer **required** (`PACKET_MUX_V1 active`), очередь TUN клиента/сервера **1000**;
клиентский default проверен в Linux. В ходе измерений — без пересборки, перезагрузки
и тюнинга сети; Proxmox только гипервизор, VM302 не использовалась.

TCP P4, внутренние IPv4/IPv6, 15 с с `-O 3`, медиана трёх повторов без трассировки,
Мбит/с. Название профиля обозначает carrier, а не внутреннюю нагрузку.

| Профиль | TCP IPv4 upload | TCP IPv4 download | TCP IPv6 upload | TCP IPv6 download |
|---|---:|---:|---:|---:|
| udp-faketls | 1077.1 | 1168.4 | 1074.6 | 1163.2 |
| udp-quic | 1087.0 | 1174.5 | 1074.2 | 1168.7 |

UDP — отдельная более ранняя сессия на том же SHA/настройках: один внутренний
IPv6 upload поток, payload 1200, 15 с с `-O 3`, n=3. Offered не равен goodput.

| Профиль | Offered Мбит/с | Goodput median Мбит/с | Loss median | Loss max | Повторы с loss ≤1% |
|---|---:|---:|---:|---:|---:|
| udp-faketls | 600 | 599.6 | 0% | 0.0158% | 3/3 |
| udp-quic | 600 | 599.7 | 0% | 0% | 3/3 |
| udp-faketls | 900 | 885.8 | 1.5400% | 3.1293% | 1/3 |
| udp-quic | 950 | 948.9 | 0.0582% | 4.6690% | 2/3 |

UDP600 проходит порог потерь, но стабильные 900/950 Мбит/с всеми повторами не
подтверждены. При TCP upload остались TUN drops. Здесь только два профиля;
UDP IPv4/download и остальные десять профилей этими числами не покрыты.
[Полные TCP/UDP-таблицы, сопоставление архивной/новой сборок, параметры лабы и ограничения](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/LINUX-LAB-0.8.2-2026-10-17.md).
[Отдельная диагностика остаточных TUN drops и её ограничения](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/TUN-READER-0.8.2-2026-10-18.md).

### Что мы делали и зачем

Qeli 0.8.2 посвящён согласованной конфигурации и надёжной работе при переподключениях,
перезапусках и частичных отказах. Мы проверили путь настройки от ввода в панели до
разбора в ядре, применения в операционной системе и восстановления после ошибки.

Работа шла по [плану полного аудита из 37 разделов](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/plans/FULL-SYSTEM-AUDIT.md):
конфиги, панель и API, аутентификация и криптография, транспорты, IPv4/IPv6, DNS,
клиенты, установка, зависимости, тесты и документация. Каждый раздел включал разбор
кода, штатные и некорректные входы, отказы и конкуренцию, доступные интеграционные
проверки и повторную проверку исправлений. Все 37 разделов завершены в согласованном
объёме. Это внутренний инженерный аудит; принятые ограничения и исключённые физические
стенды сохранены в [реестре техдолга](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/plans/AUDIT-DEBT.md).

### Масштаб и главные результаты аудита

На проверенном снимке подготовки релиза [`3acf33f0`](https://github.com/litvinovtd/qeli/commit/3acf33f0af881ecd762fa2c5ec2dc70fc327460c)
от 17 октября разработка после 0.8.1 включает **1 233 коммита: 1 208 обычных
и 25 merge-коммитов**. Это изменения продукта, рефакторинг, тесты, инструменты сборки
и документация; это не счётчик отдельных дефектов. Аудит охватил **37 направлений системы**;
подготовлены **323 отчёта**, каждый на русском и английском языках. Переводы
не считаются дополнительными независимыми проверками.
[Изменения после 0.8.1](https://github.com/litvinovtd/qeli/compare/v0.8.1...3acf33f0af881ecd762fa2c5ec2dc70fc327460c)
· [Каталог отчётов аудита](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/audit-0.8.2/README.md).

Главные результаты — более строгие правила поведения системы:

- **Ошибка не должна незаметно снимать защиту.** Проверенные сетевые операции
  учитывают владельца ресурсов и подтверждают откат; незавершённая очистка сохраняет
  защитную блокировку и сведения, необходимые для повторного восстановления.
- **Сначала проверка сервера, затем учётные данные.** Общее ядро отклоняет неверное
  криптографическое доказательство сервера и вырожденные статические ключи
  в проверенных путях аутентификации. Ошибки файлов ключей больше не приводят
  к молчаливой замене существующей identity новой.
- **Одинаковое понимание конфигурации.** Клиенты используют общий нативный контракт
  INI/URI; транзакции панели обнаруживают устаревшие правки и проверяют конфигурацию
  до применения изменений.
- **Подтверждение не ограничивается успешной сборкой.** Независимые пересборки A/B,
  проверки ABI/JNI, хеши исходников и артефактов, CI точного коммита связывают
  результаты с конкретными входами. Исторические проверки и недоступные физические
  платформы не выдаются за новые успешные прогоны.

Для Qeli это более предсказуемая основа: меньше различий между клиентами,
явные ошибки вместо ложного успеха и более управляемое восстановление после
прерванных операций. Это не означает, что устранены все возможные отказы.

### Основные изменения относительно 0.8.1

- **Общий контракт конфигурации для клиентов.** Разбор и валидация INI и `qeli://`
  перенесены в общее нативное ядро. Отдельные клиентские парсеры удалены; адаптеры
  проверяются общими положительными и отрицательными примерами. Это сокращает
  расхождения в понимании одних и тех же настроек. Доступность функций зависит от ОС.
  [План общего конфигурационного ядра](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/plans/CLIENT-CONFIG-CORE.md).
- **Конфиги в INI.** В панели сохранены форма и INI-редактор; JSON-редактор конфигурации
  удалён. Уведомления используют `notify.ini`. JSON остаётся форматом служебного
  обмена API и внутренних сообщений.
- **Надёжнее сохранение через панель.** Сохранение обнаруживает устаревшие ревизии,
  INI записывается приватно и атомарно. Исправлены валидация, кавычки, замаскированные
  секреты, списки доступа, backup/restore и проверки перезапуска. При ошибке загрузки
  или проверки рабочая конфигурация сохраняется. Изменение listener требует полного
  перезапуска вместо безрезультатного перезапуска worker.
- **Аутентификация и работа с ключами.** Проверки паролей панели и VPN используют
  общий ограниченный бюджет Argon2. TCP-аутентификация ограничена по времени и размеру
  входа; сохраняемый материал гибридных ключей очищается из памяти, вырожденная привязка
  статического ключа отклоняется.
  [Разбор криптографии](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/audit-0.8.2/AUDIT-Q08-CRYPTO-KEYS.md).
- **Управляемое восстановление сети.** Усилены проверки владельцев маршрутов,
  firewall, DNS и forwarding, отката и восстановления после аварии. Настройка
  NetworkPlan и очистка получили отдельные общие бюджеты по 15 секунд. Незавершённая
  очистка сохраняет защитную блокировку и сообщает об ошибке.
- **Исправления транспорта и сессий.** Задачи HTTP/2 освобождаются при отмене; отправка
  использует частичное flow-control окно, а общий ограничитель полосы учитывает весь
  накопленный долг. Неполные управляющие сообщения больше не получают преждевременный
  ACK, конфликтующие повторы отклоняются. Аутентификация и ресурсные лимиты DATA_FRAG
  получили дополнительные тесты. В REALITY-TLS заданы пределы использования traffic key
  с последующим переподключением.
- **Жизненный цикл и приватные хранилища клиентов.** Исправлены отдельные сценарии
  готовности и восстановления Android, переходы GUI/службы и доверенная загрузка
  DLL/профиля Windows, владение helper и хранилищами macOS, работа профилей,
  Keychain и MDM в iOS. Ошибки запуска ядра, защищённого хранилища и очистки
  сообщаются пользователю и не маскируются успешным подключением.
  Windows/macOS повторяют временно неудачное восстановление сети до нового подключения,
  с ограничением отказов и поддержкой отмены. Незавершённая очистка сохраняет kill-switch
  и владение ресурсами; неожиданные ошибки цикла переподключения приводят к видимому Error.
  Android и iOS по умолчанию очищают сохранённый журнал после завершённого отключения
  VPN; новую настройку можно выключить для сохранения диагностики. Переподключения
  и сетевые паузы историю не стирают.
- **Удобнее администрирование.** В панели появились адаптивные карточки нагрузки
  хоста, интерактивные фильтры уровней журнала и обновление лимитов полосы
  пользователей. Lifecycle-хуки Linux/OpenWrt/Keenetic получают контекст применённой
  сети и соединения. Проверены и исправлены пути установки, обновления, файловых
  прав и секретов.
- **Проверенные входы сборки.** Нативные библиотеки обновлены и независимо пересобраны
  A/B для проверки воспроизводимости, ABI/JNI и конфигурации. Обновлены зависимости,
  включая rustls 0.23.46, tokio-rustls 0.26.6 и h2 0.4.20. TLS-обновление восстанавливает
  передачу отложенных ошибок чтения; h2 исправляет обработку кадров, stream limits
  и завершения соединения. Gradle 9.8.1 закрывает три уязвимости высокой серьёзности
  в инструментах сборки; согласованы его Kotlin locks/checksums и лицензии
  AndroidX Core 1.19.1. Инструменты выпуска
  проверяют исходники, результаты runtime-проверок, лицензии и CI точного коммита.
  Незавершённый CI теперь ожидается вместо преждевременного отказа публикации
  только из-за того, что проверки ещё идут.
  Финальное обновление зависимостей включает Tokio 1.53.3, serde_json 1.0.154,
  libc 0.2.190, sha2 0.11.1 и zeroize 1.9.1. Регистрация NDP-сокета следует
  явному контракту владения Tokio; CI использует setup-java 6.1.0 и
  upload-artifact 7.0.2. Временные Git-репозитории тестов отключают автоматическое
  обслуживание, чтобы фоновая задача не конкурировала с их очисткой.
- **Меньше дублирования и устаревшего кода.** Помимо отдельных парсеров удалены
  устаревшие пути загрузки и выведены из эксплуатации шесть неиспользуемых
  реализаций performance-сценариев. Проверки бенчмарков отклоняют неполные
  и повторно учтённые фазы измерений.

### IPv6 с маршрутизацией под управлением администратора

Новый `routing.ipv6.mode = manual` отделяет администрирование внешней сети
от работы туннеля Qeli и явно запрошенного NDP proxy.

| Режим | Ответственность |
| --- | --- |
| `off` | Qeli блокирует IPv6-транзит профиля. |
| `manual` | Администратор настраивает внешнюю маршрутизацию, firewall и forwarding; Qeli сохраняет адреса туннеля/клиентские маршруты и может обслуживать запрошенный NDP proxy. |
| `route` | Qeli настраивает пересылку с сохранением адресов клиентов. |
| `nat66` | Qeli настраивает пересылку и NAT66. |

NDP proxy поддерживается в `manual` и `route`. `ndp_proxy = required` остаётся
обязательным условием запуска; `manual` сам не включает внешний forwarding.
[Руководство по конфигурации](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/manuals/CONFIG.md).

### Тестирование и результаты

- Модульные тесты, общие проверки конфигурации и регрессии охватывали некорректные
  входы, отмену, конкурентные операции и сохранение рабочего состояния.
- Сохранены результаты **20 обязательных Linux runtime-сценариев**, включая применение
  и восстановление сети и IPv4/IPv6. Сборки платформ дополнены проверками ABI/JNI
  и Android на эмуляторе.
- Криптографические проверки включали **60 эталонных случаев NIST ML-KEM-768**,
  векторы RFC для X25519 и ChaCha20-Poly1305, независимые проверки HKDF.
  Это проверка согласованности реализации, а не внешняя сертификация безопасности.
  [Проверки криптографии и их границы](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/audit-0.8.2/AUDIT-Q08-CRYPTO-KEYS.md).
- В ходе аудита **15 ASan fuzz-целей** проверяли границы парсеров и протокола;
  исходный закреплённый прогон выполнил **85 930 590 итераций**. Полный восьмиэтапный
  длительный прогон занял около **13 часов 4 минут**: 10 000 циклов TCP и 10 000 QUIC,
  дополнительные UDP-адаптеры и заранее заданные бюджеты ресурсов. Это сохранённые
  исполнения программы аудита, а не утверждение о повторении всей программы
  для каждого последующего кандидата релиза.
  [Итог Q35](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/audit-0.8.2/AUDIT-Q35-FINAL.md)
  · [Отчёт длительного прогона](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md).
- Клиентская настройка очереди Linux интегрирована в `dev`, а не оставлена в
  отдельном рабочем каталоге. Из объединённых исходников пересобирается весь комплект:
  нативные ядра, Linux/DEB, Android, Windows, macOS и роутерные бинарники. Допуск требует
  штатного CI и свежего исполнения обязательных Linux runtime-сценариев на новом CLI;
  результаты старого кандидата не переносятся на изменённый код.
  [Актуальная квалификация и идентификаторы артефактов](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/certification/0.8.2.json).
  Историческая квалификация `e90bf0c2`/`3acf33f0` сохранена в Git и исходных evidence,
  но не доказывает присутствие настройки очереди в тех бинарниках.

Это отдельные наборы проверок, их числа не складываются в один счётчик тестов.
В отчётах сохранены версии исполненных исходников и артефактов, условия
и первоначальные отказы.

### Известные ограничения

- На проверенном эмуляторе Android 14/API34 вызов `DnsResolver` с автоматическим
  выбором семейства адресов без явной сети возвращал `ENONET` до отправки запроса.
  Независимый минимальный VPN воспроизвёл результат. Обычный DNS, типизированные
  A/AAAA и запросы через явно выбранную VPN-сеть работали в проверенных сценариях.
  Принятое ограничение остаётся неисправленным. Сохраняются защищённый VPN
  и системный kill switch; DNS bypass-режим не добавляется.
  [Расследование DNS](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).
- Непрерывная идентичность при замене выбранного WAN-интерфейса остаётся принятым
  ограничением D06. Перед заменой интерфейса нужно остановить профиль
  и подтвердить очистку. [Подробности](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/plans/AUDIT-DEBT.md).
- Физические Mac/iOS, роутер и сетевая Windows VM исключены из согласованного объёма.
  Результаты сборок, симулятора и проверок адаптеров сохраняют собственные границы
  и не подтверждают работу каждого устройства или OEM.

### Порядок обновления

Сохраните прежний бинарный файл вместе с его INI для отката. Проверьте настройки
текущим валидатором: некорректные адреса, повторные секции и неподдерживаемые поля
теперь могут отклоняться. Нужные старые настройки уведомлений перенесите вручную
в `notify.ini`: автоматический импорт `notify.json` удалён, restore отклоняет этот
legacy-файл. Если Windows отказывает в доверии старому сервисному хранилищу,
сохраните нужные пользовательские данные и явно настройте службу из GUI
с правами администратора.

Windows снова распространяется отдельными single-file `QeliWin-standalone.exe`
и `QeliWin-net-required.exe`. Оригинальные тексты лицензий Cargo/.NET, ядра/клиента
и драйверов встроены; **О программе → Лицензии** позволяет читать и экспортировать
их без сети. Linux- и роутерные бинарники поддерживают `licenses --list`,
`licenses --file PATH`, `licenses --export NEW_DIRECTORY` без запуска VPN.
Отдельный `qeli-native-legal.zip` убран из загрузок релиза; исходные тексты и индексы
доступны внутри бинарников. Это не заменяет доступность исходников и остальные
условия лицензий.

Комплект загрузок — 16 файлов вместе с `SHA256SUMS`: APK Android, два Windows EXE,
universal ZIP macOS, Linux-бинарник и DEB, шесть роутерных бинарников и три файла
установки/feed для роутеров. Данные квалификации хранятся в
[исходном репозитории](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/certification/0.8.2.json),
а не в отдельных загрузках `PROVENANCE.json` / `QUALIFICATION.json`. Beta сохраняет
проверенный DEB без новой release-build аттестации; строгая проверка происхождения
обязана отказать, если соответствующей аттестации нет. Docker отдельно публикует
образ с тегом `0.8.2` после допуска Git-тега; beta не заменяет stable-тег `latest`.
Одна загрузка файлов релиза сама по себе не создаёт Docker-образ.

Universal ZIP для macOS содержит код Apple Silicon и Intel;
требуется macOS 15 или новее согласно поддерживаемой матрице .NET 10;
распакуйте весь `Qeli.app` с сохранением прав запуска. Подпись — ad-hoc,
без Developer ID notarization и системного расширения per-app.
Android-обновление сохраняет прежний релизный сертификат; проверяются подпись пакета,
выравнивание и включённые актуальные JNI-библиотеки. Это не заменяет проверку установки
и обновления на вашем физическом устройстве.

Полный список изменений — [CHANGELOG.md](https://github.com/litvinovtd/qeli/blob/v0.8.2/CHANGELOG.md).

### Короткая проверка итогового Linux бинарника

**19 октября 2026** проведён новый короткий прогон фактического
`release/dist/v0.8.2/qeli-linux-amd64` на **обоих концах — VM300/server и VM301/client**.
SHA256: `e4cb6e055854806bcef7c61f394ea696cbf9cde3de90fef7b5f0f02e60326ddb`.
Это свежие замеры готового ELF, а не перенос результатов диагностических сборок.

Лаба: Intel i5-8500, по **2 vCPU / 2 GiB**, Linux `6.12.111+deb13-amd64`;
IPv4 underlay MTU1500, TUN MTU1400, очереди клиента/сервера **1000/1000**.
Только **Recordizer required**, настройки клиента получены аутентифицированным
push, подтверждён `PACKET_MUX_V1 active`. Без пересборки, reboot и тюнинга;
Proxmox и VM302 не использовались для тестов или сборки этого повтора.
Буферы iperf: запрошены 4 MiB на обоих концах, подтверждены фактические 8 MiB.
Первоначальные **23 окна** дали около четырёх минут нагрузки; запуск, снимки состояния и
проверки восстановления занимают дополнительное время.

UDP: внутренний **IPv6 upload**, payload1200, **три окна 15 с / omit 3**:

| Native UDP профиль / offered Мбит/с | Медиана goodput приёмника, Мбит/с | UDP loss медиана / max, % | TUN drops клиента, три окна | Медиана CPU клиента, 100% = одно ядро |
| --- | ---: | ---: | --- | ---: |
| FakeTLS / 900 | 899.57 | 0.005329 / 0.009025 | 0 / 0 / 0 | 81.68% |
| QUIC / 950 | 949.46 | 0.000471 / 0.004981 | 0 / 0 / 0 | 83.41% |

Отдельное окно **QUIC950, 60 с / omit 3**: **949.80 Мбит/с**, **0 TUN drops**,
**0.009591% UDP loss**. Во всех семи UDP-окнах TUN drops сервера, RX drops
carrier-сокетов и `Udp6RcvbufErrors` равны нулю. Это не нулевые сквозные потери:
ненулевые UDP loss и IPv4 `SndbufErrors` сохранены в evidence.
Offered — заданная нагрузка, а не результат нового поиска потолка.

#### Единые результаты TCP и UDP по четырём профилям

Итоговая матрица объединяет **две отдельные последовательные серии на VM300/301**,
а не одновременную нагрузку TCP/UDP: **48 TCP-окон и 48 UDP-окон** на указанном выше
SHA256 итогового ELF, с Recordizer required, MTU1400 и очередями клиента/сервера1000/1000.
На каждую комбинацию IP/направление/протокол приходится **три окна 15 с / omit 3**.
TCP — **P1 без ограничения скорости**; UDP — **заданная нагрузка 600 Мбит/с,
payload1200**. Каждая серия дала около 14 минут нагрузки без учёта запуска и
восстановления. Названия профилей обозначают транспорт туннеля, столбцы TCP и UDP —
внутренний тестовый трафик.

Goodput — **медиана скорости приёмника в Мбит/с**. ↑ — upload клиент → сервер;
↓ — download сервер → клиент. Retransmits и UDP loss приведены как **медиана /
максимум трёх окон**. TUN drops — **суммы клиента / сервера по трём окнам**.

| Транспортный профиль | IP / направление | TCP Мбит/с | UDP600 Мбит/с | UDP loss мед / max, % | TCP retrans мед / max | TCP TUN клиент / сервер | UDP TUN клиент / сервер |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP FakeTLS | IPv4 ↑ | 1975.01 | 599.80 | 0 / 0 | 41 / 75 | 363 / 0 | 0 / 0 |
| TCP FakeTLS | IPv4 ↓ | 2205.10 | 600.00 | 0 / 0 | 75 / 102 | 0 / 821 | 0 / 0 |
| TCP FakeTLS | IPv6 ↑ | 2006.70 | 599.69 | 0 / 0 | 134 / 142 | 714 / 0 | 0 / 0 |
| TCP FakeTLS | IPv6 ↓ | 2170.34 | 600.00 | 0 / 0 | 107 / 113 | 0 / 1312 | 0 / 0 |
| TCP Reality-TLS | IPv4 ↑ | 1124.95 | 599.54 | 0 / 0 | 52 / 98 | 2070 / 0 | 0 / 0 |
| TCP Reality-TLS | IPv4 ↓ | 1059.83 | 599.99 | 0 / 0 | 49 / 109 | 0 / 2696 | 0 / 0 |
| TCP Reality-TLS | IPv6 ↑ | 1142.85 | 599.54 | 0 / 0 | 133 / 136 | 754 / 0 | 0 / 0 |
| TCP Reality-TLS | IPv6 ↓ | 1067.03 | 600.00 | 0 / 0 | 85 / 107 | 0 / 1004 | 0 / 0 |
| UDP FakeTLS | IPv4 ↑ | 1135.56 | 599.78 | 0 / 0 | 623 / 809 | 2392 / 0 | 0 / 0 |
| UDP FakeTLS | IPv4 ↓ | 1329.65 | 600.00 | 0 / 0 | 92 / 256 | 0 / 2632 | 0 / 0 |
| UDP FakeTLS | IPv6 ↑ | 1163.33 | 599.70 | 0 / 0 | 292 / 319 | 1519 / 0 | 0 / 0 |
| UDP FakeTLS | IPv6 ↓ | 1323.54 | 600.00 | 0 / 0 | 213 / 352 | 0 / 3066 | 0 / 0 |
| UDP QUIC | IPv4 ↑ | 1165.95 | 599.81 | 0 / 0 | 219 / 255 | 1632 / 0 | 0 / 0 |
| UDP QUIC | IPv4 ↓ | 1267.63 | 600.00 | 0 / 0 | 240 / 612 | 0 / 1744 | 0 / 0 |
| UDP QUIC | IPv6 ↑ | 1192.20 | 599.80 | 0 / 0 | 141 / 737 | 1415 / 0 | 0 / 0 |
| UDP QUIC | IPv6 ↓ | 1282.99 | 600.00 | 0 / 0 | 176 / 520 | 0 / 2740 | 0 / 0 |

Все **96 окон итоговой матрицы завершены**. Во всех **48 окнах UDP600 потери
приёмника и TUN drops клиента/сервера равны нулю**. Это результат при фиксированной
нагрузке, не потолок пропускной способности; он не заменяет отдельные результаты
900/950 Мбит/с выше, где есть небольшие ненулевые UDP loss.

**При неограниченном TCP сохраняются TUN drops и TCP retransmissions.** Процент
потерь TCP-пакетов не измерялся; retransmits — не UDP loss, а к внутреннему
UDP-тесту retransmits неприменимы. Счётчики TUN охватывают полное окно с прогревом,
TCP retransmits — отчётный интервал iperf; их нельзя сопоставлять один к одному.
В отдельных окнах с внутренней TCP-нагрузкой через native UDP-транспорты также
зарегистрированы ошибки socket buffers ядра; пооконные счётчики сохранены.
Трассировка `FULL_RING` в этих матрицах не выполнялась.

[Все TCP-окна, диапазоны, CPU/RSS, счётчики, пути raw и восстановление](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/lab-results/n04-final-dist-tcp-matrix-20261019.json).
[Все UDP600-окна, счётчики, отдельные raw и восстановление](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/lab-results/n04-final-dist-udp-matrix-20261019.json).

Прежние **16 функциональных TCP-окон, 3 с / omit 1**, сохранены в
[архиве первоначальной короткой проверки](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/lab-results/n04-final-dist-repeat-20261019.json)
и **не включены в новые медианы**.

После каждой серии проверки восстановления исходных файлов и сетевого состояния
обеих ВМ пройдены; временные процессы, TUN и locks удалены. Старые бинарники,
результаты и новые отдельные каталоги raw сохранены; SHA256 не изменился.
Короткая Linux-проверка не заменяет квалификацию релиза на всех платформах.
Это обновление документации не публикует релиз.

### Продолжение N04: чтение TUN в Linux UDP

N04 локализовал потери в клиентской **очереди TUN ядро → Qeli**: ядро не могло
поставить пакеты в очередь, пока userspace недостаточно быстро её вычитывал.
В перегрузочном окне зафиксированы **922359 TUN TX drops и ровно 922359 событий
`FULL_RING` в `tun_net_xmit`**, без потерянных записей гистограммы. Это подтверждение
места потерь, а не новый результат допустимой скорости. Контролируемые изменения
ниже подтверждают вклад межпоточной обработки каждого пакета в нехватку ресурса reader.

В Linux UDP-сеансах raw TUN теперь читает сетевой runtime: устранены передача
пакета из reader-потока и межпоточный возврат буферов. Ограниченный пул памяти,
шифрование, wire format и Recordizer не изменены. TCP/TAP и backends других
платформ сохраняют прежний путь чтения; нового переключателя нет.

В трёх чередующихся парах stock/прототип CPU клиента снизился примерно на
**12–13%**, а TUN drops в QUIC950 — с 7475/3465/0 до 0/178/148. Последующий
отдельный проверочный ELF reader-fix `8e3c4bc0…` проверен при очереди 1000:

| Native UDP профиль / offered Мбит/с | TUN drops в трёх окнах | Медиана goodput приёмника, Мбит/с | UDP loss iperf, % по окнам |
| --- | --- | ---: | --- |
| FakeTLS / 900 | 0 / 0 / 0 | 899.63 | 0 / 0 / 0 |
| QUIC / 950 | 402 / 77 / 0 | 949.42 | 0.042074 / 0.013126 / 0.000740 |

Таким образом, **после одного reader-fix в QUIC остались 479 TUN drops**.
При очереди 2000 в трёх дополнительных проверенных окнах TUN drops отсутствовали,
но небольшие сквозные UDP-потери сохранились. Default остаётся 1000: задержка под
нагрузкой не квалифицировалась, поэтому 2000 не объявляется универсально лучшим
значением. Увеличение очереди не подменяет исправление reader.

[Методика N04, точные сборки и ограничения](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/TUN-N04-0.8.2-2026-10-19.md).
Это результаты идентифицированного Linux-стенда, а не замеры всех готовых приложений.
[Квалификация релиза](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/certification/0.8.2.json)
отдельно фиксирует подготовленные файлы и обязательные проверки.

### Локальный I/O-драйвер Linux CLI

После reader-fix оставалась ещё одна межпоточная граница: транспортный цикл CLI
работал в корневой future `block_on`, вне workers многопоточного runtime,
а I/O-драйвер обрабатывал готовность на worker-потоке. При высокой частоте пакетов
пробуждения и переключения контекста отнимали CPU, необходимый для чтения TUN.
Теперь цикл Linux `qeli client` и I/O-драйвер работают в одном
**`current_thread` runtime**; standalone `qeli-client` использует ту же политику.
Сервер/supervisor и `_worker` сохраняют `multi_thread`; native FFI runtimes
других платформ не изменены.

Вторая A/B-серия начинается с **уже исправленного reader**, база `4a562cad…`:
два диагностических ELF — baseline `c5625562…` и local I/O `04412c2a…`.
На обоих концах используется ELF соответствующего варианта, но политика runtime
сервера не меняется. Три пары выполнены в порядке
baseline/new/new/baseline/baseline/new, без CPU-профайлера:

| QUIC950, очередь 1000 | Baseline | Локальный I/O-драйвер |
| --- | ---: | ---: |
| TUN drops клиента, три окна | 2147 / 0 / 804 | 0 / 0 / 0 |
| Медиана CPU клиента, 100% = одно логическое ядро | 101.95% | 83.07% |
| Медиана переключений контекста клиента за окно | 1005173 | 217357 |
| Медиана goodput приёмника, Мбит/с | 949.45 | 949.32 |

CPU снизился на **18.5%**, переключения контекста — на **78.4%** относительно
этой новой базы; проценты нельзя складывать с результатами reader-fix.
Выигрыш — меньшие затраты обработки и потери, а не скорость выше offered.
Отдельное окно **60 с / omit 3** дало **949.91 Мбит/с**, **0 TUN drops** и
**0.00047113% сквозных UDP-потерь**. Ноль TUN drops не означает ноль общих потерь.

Оба этапа: VM300/server и VM301/client, по **2 vCPU / 2 GiB**, kernel
`6.12.111+deb13-amd64`; VM302 — только сборка, компиляция с нагрузкой не совмещалась.
Сравнения: native UDP, **Recordizer required / `PACKET_MUX_V1 active`**, внутренний
IPv6 upload, UDP payload1200, **15 с / omit 3**, IPv4 underlay MTU1500, TUN MTU1400,
очереди клиента/сервера **1000/1000**. До сопоставимой серии обнаружено переполнение
приёмного буфера iperf: затем на обоих концах запрошены 4 MiB и подтверждены
фактические 8 MiB Linux. Эти A/B-результаты нельзя считать замерами по неизменной
методике относительно прежних окон с буфером по умолчанию. TUN-счётчики включают
прогрев; iperf считает потери за собственный измерительный интервал.

Ещё **16 функциональных окон** охватили TCP FakeTLS/Reality-TLS и UDP FakeTLS/QUIC,
внутренние IPv4/IPv6 и оба направления. При неограниченной нагрузке отдельные drops
сохраняются в evidence; короткие проверки не являются новой квалификацией скорости
TCP или гарантией отсутствия потерь.
[Отчёт N04 и ограничения](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/TUN-N04-0.8.2-2026-10-19.md)
и [точные SHA256 диагностических ELF и данные A/B](https://github.com/litvinovtd/qeli/blob/v0.8.2/release/lab-results/n04-quic-locality-20261019.json)
идентифицируют эти замеры. Они **не квалифицируют итоговый бинарник дистрибутива**:
его проверки фиксируются отдельно в квалификации релиза. Обновление документации
не публикует релиз.

### Размер клиентской TUN очереди Linux

Добавлен локальный параметр `tun.tx_queue_len` в секции `[qeli]` клиентского INI:

```ini
[qeli]
tun.tx_queue_len = 1000
```

Он задаёт размер очереди пакетов ядро → Qeli для собственного TUN/TAP Linux-клиента.
По умолчанию используется `1000` пакетов, допустимы целые значения `1..32767`.
Автоматической регулировки нет; для возврата к прежнему лабораторному размеру можно задать `500`.

Параметр появился после диагностики низкой скорости upload Reality-TLS: клиентская очередь
переполнялась ещё до H2/TLS, вызывая потери и повторные передачи внутреннего TCP. В проверке
на одном и том же бинарнике A/B/A `500 → 1000 → 500` (IPv4, по три повтора) увеличение
очереди повысило upload P1/P4 и уменьшило потери и повторные передачи в P4; возврат к `500`
вернул прежний уровень скорости. Более вместительная очередь
помогает переживать всплески, но не устраняет все потери и не гарантирует ускорения на любом
профиле или устройстве. Компромисс — возможный рост задержки и потребления памяти.
Это не изменение H2 flow control и не исправление доказанного ограничения H2.

Нужен обновлённый клиент с поддержкой параметра: сохраните INI и остановите/запустите клиент
(в панели — Disconnect → Connect). Ключ не передаётся через server push, ссылку или QR;
серверный одноимённый параметр остаётся независимым. При `dev_attach=true` ключ следует
полностью опустить: очередью управляет внешний владелец интерфейса. Другие ОС сохраняют ключ
без применения. Старые бинарники, включая прежние сборки с номером 0.8.2, не получают
это поведение от одного обновления конфигурации.

Подробности и проверка фактического размера очереди:
[CONFIG](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/manuals/CONFIG.md#client-tun-tx-queue).
Результаты разных размеров очереди, IPv6 и трёх транспортов:
[лабораторный отчёт и ограничения](https://github.com/litvinovtd/qeli/blob/v0.8.2/docs/ru/reports/TUN-QUEUE-SIZE-2026-10-16.md).
