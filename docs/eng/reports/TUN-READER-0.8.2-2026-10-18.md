# TUN reader diagnostics with queue 1000

Remaining losses are confirmed at the client TUN, before the outer carrier.
**The exact hot function causing insufficient packet service has not been established.**
The leading candidate is the serial uplink consumer and its packet/buffer handoff
with the TUN reader. This is a profiling hypothesis, not a proven Recordizer or
scheduler fix.

Across three final diagnostic UDP950 windows, only 72 of 152305 FULL_RING drops
temporally overlapped recorded reader runqueue waits ≥1 ms; another 71 overlapped
sleep intervals ≥1 ms. A single long reader pause therefore does not explain the
bulk of these observations. Frequent shorter waits, queue accumulation and
observer effects remain possible.

## Scope and preservation

Both endpoints used Linux 0.8.2 SHA256
`1d94d4c412f6c1fd231765b760196b0b4f518c20135bf0ccd1b52b192710cf76`.
Recordizer **required**, actual `PACKET_MUX_V1 active`; VM300/server and VM301/client,
2 vCPU/2 GiB each, kernel `6.12.111+deb13-amd64`, both TUN queues 1000, client
MTU auto/effective 1400, underlay MTU 1500. The profiles were native `udp-faketls`
and `udp-quic`, **not outer TCP or H2**. These are not new Reality-TLS/H2 observations.

No binary/configuration, queue, MTU, qdisc, offload, affinity, resource or network
sysctl tuning; no rebuild/reboot. Proxmox and VM302 were not used. Only final
instrumented VM301 windows temporarily enabled `kernel.sched_schedstats=1` to emit
duration events; each window restored `0`, verified again at the end. This is
diagnostic accounting, not scheduler policy, but still potentially adds overhead.

Three sequential campaigns had 44, 20 and 10 windows respectively. The first
contained 24 **untraced** TCP P4 windows for the release snapshot. UDP windows
were 15 seconds with `-O 3`, inner IPv6 upload, payload 1200. High-load observation
windows were bracketed by uninstrumented windows. Previous artifacts/raw were
preserved; no packet payloads, keys, user stacks, memory dumps or pcap were collected.

Continuous sched/futex/poll recording overflowed and affected throughput; those
wait distributions were rejected, with original collectors/raw retained. Even
~50 Hz metadata sampling changed a FakeTLS bracket from 899.6/899.2 to 851.7 Mbit/s.
It was reduced to ~1 Hz, with only test-TUN drops and sparse own-thread delay
events ≥1 ms recorded. The final three throughput differences from neighboring
window means were −1.36%, +2.41%, −1.30%; the neighbors also varied substantially.
This does not prove zero overhead. Instrumented windows are not release benchmarks.

## Final QUIC UDP950 observations

| Repeat | Goodput Mbit/s | UDP loss | FULL_RING = TUN TX drops | Drops overlapping reader runqueue wait ≥1 ms | Drops overlapping reader sleep ≥1 ms |
|---|---:|---:|---:|---:|---:|
| 1 | 936.3 | 1.3330% | 35520 | 0 | 71 |
| 2 | 937.7 | 1.3644% | 32748 | 0 | 0 |
| 3 | 913.7 | 3.8127% | 84037 | 72 | 0 |
| UDP600 control | 599.8 | 0% | 0 | 0 | 0 |

All final captures had zero trace overruns/dropped events. Client outer qdisc
drops were 0/34/61; server Qeli UDP socket drops and UDP RcvbufErrors were zero.
TUN counter intervals include warmup, unlike iperf's post-omit goodput/loss period;
TUN drops must not be equated with iperf lost_packets.

Independent per-thread `/proc/.../schedstat` deltas over approximately 17.98 s:

| Repeat | Reader CPU s | Reader runqueue wait s | Reader CPU timeslices | Main client thread CPU s | Its runqueue wait s |
|---|---:|---:|---:|---:|---:|
| 1 | 4.184 | 3.517 | 485727 | 13.289 | 3.961 |
| 2 | 5.155 | 3.918 | 536950 | 12.802 | 3.554 |
| 3 | 4.754 | 4.208 | 719714 | 12.862 | 4.425 |
| UDP600 | 3.141 | 0.782 | 224614 | — | — |

The reader was observed in both poll and timed futex wait; UDP950 had 3/3/5
WAIT_BITSET snapshots, versus none in UDP600. These snapshot counts are **not time
fractions**. Syscall inspection favors blocked tasks, and syscall/wchan are read
nonatomically. They do not identify the reader's state at every drop.
See [scheduler statistics](https://www.kernel.org/doc/html/v6.12/scheduler/sched-stats.html)
and [proc fields](https://www.kernel.org/doc/html/latest/filesystems/proc.html).

## Buffer-pool hypothesis and next step

The subsequent [19 October N04 investigation](TUN-N04-0.8.2-2026-10-19.md)
used a newer, explicitly identified candidate, confirmed kernel queue overflow
and tested a Linux UDP reader fix. The original next steps and 18 October limits
below are preserved; their hashes and findings are not reassigned.

The [artifact's source](https://github.com/litvinovtd/qeli/blob/8b18038849873125219b2a2f6ed8f8d339800ee5/qeli/src/transport_core/linux_tun.rs)
waits for an available reusable buffer before read(TUN). Dropping TunPacket returns
it. At the default 65535-byte client read buffer, the 4 MiB budget and upper clamp
give **64 buffers**, independent of kernel queue 1000. The 4096-slot from_tun channel
does not create 4096 independent buffers. Delayed consumer recycling can therefore
stop the reader even with packets in the kernel.

Timed futex observations and frequent short handoffs make this a profiling target,
but buffer credits/depth and individual consumer service times were not measured.
Pool exhaustion as the cause of each drop, or dominance of Recordizer, encryption
or send processing, remains unproven. Accounting intervals starting before capture
were excluded: stale sleep_start values across disabled periods are not continuous
21/41-second observed stalls. Temporal overlap is not proof of causation and does
not exclude waits below 1 ms.

Do not blindly deepen the queue or introduce auto sizing based on this experiment.
The next useful step is low-overhead consumer profiling and buffer-wait,
encode/seal/send and actual-batch counters. Guests lack perf/BPF tools, and the
current ELF lacks the internal `.symtab` and debug sections (a dynamic `.dynsym`
is present). Exact function attribution needs
matching symbols for this artifact or a separately authorized instrumented build.
Neither was substituted under the same-binary constraint.

Raw is separate on both guests under
`/opt/qeli-release-short-gigabit-readerdiag1d94-20261017`,
`/opt/qeli-release-short-gigabit-readerdiaglight1d94-20261017` and
`/opt/qeli-release-short-gigabit-readertails1d94-20261018`.
All campaigns completed with guest restoration, previous file hashes and binary SHA
verified. No test process/TUN/trace instance/lock remains; scheduler accounting is
back to 0. Raw is sealed with verified SHA256SUMS.final and was not copied to C:.
An auxiliary six-second user/system CPU sample fell inside UDP600, not UDP950,
and is not used to explain the bad high-load windows.

[Sanitized counters and final raw manifest hashes](../../../release/lab-results/tun-reader-1d94-20261018.json) ·
[Untraced TCP/UDP release tables](LINUX-LAB-0.8.2-2026-10-17.md).
