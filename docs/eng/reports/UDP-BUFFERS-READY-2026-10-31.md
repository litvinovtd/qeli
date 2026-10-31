# UDP buffer-management completion — 31 October 2026

Result: Default/readback bugs fixed; existing bounded auto retained.
**14 targeted Rust tests**, client-only check and build passed on VM302.
**One functional acceptance** ran on VM300/301: five cases, 11 short UDP windows,
Recordizer required. Mode/readback checks passed and guests were restored.
This is not a new performance reference or release publication.

## Code changes

- Rust `ClientPerformanceConfig::default()` now agrees with INI/serde: receive
  4 MiB/auto, send 0. Derived Default previously produced receive 0/auto=false.
- Failed `getsockopt` after growth no longer substitutes a successful requested
  size. Unknown detailed readback is `null`.
- Per-live-socket metadata includes mode, requested RX/TX, raw OS readback,
  normalized bytes, cap, clipping flags and available inode. Changes are logged;
  identical state is not logged every tick.
- Linux client status: `stats.udp_socket_buffers`; server Unix control
  `queue-stats`: `udp_socket_buffers` by profile. Socket close removes its entry.
  Existing aggregate counters and FFI/JNI ABI remain unchanged.
- Auto 4→8→16 MiB, explicit fixed/0 and server RAM budgeting already existed;
  they are not presented as new development here. No new locks/JSON in the packet
  hot path; readback/metadata updates occur on the one-second tick.

Settings and field meanings: [UDP buffers](../manuals/UDP-BUFFERS.md).

## Build and scope

VM302 only, base `13c1dfdead0a9f8dcf833f6b5f1168529692fcea` plus an isolated
four-Rust-file UDP overlay. Unfinished neighboring REALITY/PQ/UI work was excluded.
The rustfmt output was verified byte-for-byte against the code selected for commit.

- SHA256 `9eaa7b3bfd3aa4a802082cc3ae650c0c54fe382ce6b851baf8914eb2f857ca41`.
- 15449784 bytes, native Linux amd64, jemalloc, rustc 1.97.0.
- Build raw: `/opt/qeli-udp-buffer-ready-20261031-r01` on 302.
- UDP unit: 10 passed; client/server buffer config: 2 passed;
  server INI/structured round-trip: 2 passed; client-only check and release build: code 0.
- Initial CLI test-target selection yielded zero UDP tests. The harness rejected
  that PASS and retained the failure/log. Target corrected to `--lib` without
  changing candidate sources; only the actual 14 tests count.

Experimental native candidate, not portable release/dist or ARM64 qualification.
Release artifacts were not replaced.

## VM300/301 acceptance

2 vCPU/2 GiB each (MemTotal 2020904 KiB), kernel `6.12.111+deb13-amd64`,
MTU 1400, TUN queue 1000, outer IPv4. New private binary copies in a new raw root;
old installed/archived binaries not overwritten. IPv4/IPv6 ping and actual
`PACKET_MUX_V1` verified in every session.

| Case | Explicit lab OS policy | Confirmed |
|---|---|---|
| QUIC auto, OS clamp | rmem_max/default 212992 | Initial 4 MiB request (later an 8 MiB attempt possible), actual normalized 212992, raw 425984; `receive_clamped=true` |
| UDP-FakeTLS auto | rmem_max 16 MiB, default 4 MiB | Actual 4→8→16 MiB growth; active sockets 16, idle server worker 4 MiB; within cap |
| QUIC auto | same | Actual 4→8→16 MiB growth, bounded cap |
| UDP-FakeTLS fixed | explicit receive 4194304 | Remains fixed 4 MiB; raw 8388608 |
| UDP-FakeTLS OS-default | explicit receive 0 | No explicit setsockopt; raw remains default 4194304, normalized 2097152; auto disabled |

`receive_os_bytes`/`send_os_bytes` matched `ss rb/tb` by inode on client and all
server UDP worker sockets. Readback failure is unit-tested, not induced by damaging
a live socket. Qeli did not change sysctls: the harness temporarily applied the
listed values with originals retained for rollback.

Auto windows: UDP600, payload 1200, 5+1 warm-up seconds, IPv4/IPv6 up/down, n=1.
The other three windows: UDP10, 2+1 s. Total configured traffic-window time: 57 s.

| Auto profile | IPv4 up | IPv4 down | IPv6 up | IPv6 down |
|---|---:|---:|---:|---:|
| UDP-FakeTLS, receiver Mbps | 599.09 | 569.87 | 598.87 | 599.99 |
| QUIC, receiver Mbps | 598.58 | 600.01 | 599.46 | 600.00 |

All 11 windows: loss=0, TUN TX drops=0; window CPU steal <=0.33%.
UDP-FakeTLS IPv4 download was **not replaced**: receiver 569.87 versus sender
600.00 Mbps, with different JSON intervals (5.000650 versus 5.262154 seconds).
These short n=1 windows are not an A/B proof of no speed regression. No claim
that larger buffers fix CPU steal, sustained overload or all remaining loss
in previously tested builds.

## Raw and restoration

Both-guest raw: `/opt/qeli-release-short-udp-buffer-ready-20261031-r01`.
UTC `16:40:30.721041`–`16:49:45.439034`, including old-archive hashing.
VM302 build completed before traffic; cargo/rustc verified absent. Private configs
and large raw are not published.

All 16 restoration checks passed per guest: boot, previous files, sysctls,
processes, network/routes/rules, qdisc and iptables/ip6tables. Independent check
confirmed original rmem/wmem values of 212992, no Qeli/iperf/IRTT/TUN/netns/lock,
inactive qeli/qeli-client and unchanged candidate SHA. No reboot.

With separate explicit approval, only old
`/opt/qeli-license-compression-20261030-r01/target/debug` was removed on 302.
104 ELF/`libqeli*` files were SHA-verified and archived at
`/opt/qeli-preserved-debug-udp-20261031-r01/legacy-debug.tar.gz`,
SHA256 `b59f2bf4e4967de1997f3397c2d682f678a9b268627282dc99cf0573d6e867de`.
Sources, logs, release-target, previous candidates and raw were not removed.
Compiler intermediates are recoverable by rebuilding; binaries from the archive.

No release publication. Functional acceptance does not replace portable builds,
both Linux architectures or final release gates.
