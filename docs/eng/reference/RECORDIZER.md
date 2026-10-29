# Recordizer and Qeli record organization

Recordizer is a transport-independent layer between inner IP packets and Qeli
encryption. It changes the one-packet-to-one-record relationship: several packets
may share a record, and one packet may span multiple records. Its purposes are
changing observable traffic structure and grouping processing; it is not a separate
VPN protocol, H2 or another cipher.

Current settings and defaults belong in the
[obfuscation manual](../manuals/OBFUSCATION.md) and
[configuration reference](../manuals/CONFIG.md). This page describes the mechanism;
specific results belong in the [20 October required/off throughput measurements](../reports/benchmarks/recordizer_required_off_2026-10-20.md)
and [26–29 October latency/low latency report with charts](../reports/benchmarks/recordizer_latency_2026-10-29.md).

## Data path

```text
inner IPv4 or IPv6 packet
  → Recordizer queue and record formation
  → padding and size normalization
  → PacketCodec AEAD
  → selected carrier
  → outer carrier/path fragmentation when required
```

On reception, after removal of the outer carrier and AEAD verification, the
reassembler restores original packets for TUN delivery. Mux headers are encrypted.
Splitting an inner packet across mux records and externally fragmenting an encrypted
record over UDP are separate mechanisms.

## Policy negotiation

The server sets `obf.recordizer.policy` in its profile; effective settings reach the
client after authentication. There is no separate client `obf.recordizer.policy` key.

| Policy | Behavior |
| --- | --- |
| `off` | Legacy data plane: one encrypted record per inner packet |
| `prefer` | Enable with a `PACKET_MUX_V1` client; otherwise use legacy |
| `required` | Reject an incompatible client before allocating an address |

`required` and `prefer` are not different forwarding algorithms: when Recordizer is
negotiated, the mechanism is `PACKET_MUX_V1`. Policy controls admission and fallback.
The wire mechanism described here is V1; a policy name does not imply PACKET_MUX_V2.

In `reality-tls`, both required and off retain genuine TLS/H2. A
`legacy packet-per-record` message refers to Recordizer, not disabling H2, TLS or
encryption. Check `PACKET_MUX_V1 active`, not just the INI setting.

## Aggregation and limits

In `timed`, the first packet starts a flush deadline. A record may also become ready when its
target size or batch limits are reached. The target stays within the carrier/path
budget; it is a send threshold, not a promise to pad every record to that size.
Queues, fragment counts, incomplete packets and reassembly memory are bounded.

Larger records can amortize record processing and carrier operations. Trade-offs
include accumulation delay with sparse traffic and several inner packets depending
on one lost outer datagram. Additional fragments cost CPU, headers and reassembly
state. Increasing batching or limits for throughput alone requires checking latency
and loss as well.

Recordizer does not resize the TUN queue, eliminate CPU limits or replace outer TCP
or H2 flow control. Recordizer aggregation, H2 carrier batching and producer-side
handoff of ready packets are separate stages.

## Two batching strategies

Policy `off/prefer/required` controls negotiation. Separate
`obf.recordizer.batch.mode` controls waiting **after Recordizer is enabled**:

| Mode | Algorithm | Trade-off |
| --- | --- | --- |
| `timed` (default) | First packet starts a random `delay_min_ms..delay_max_ms` deadline (2..8 ms); flush earlier at target/limits | Existing temporal morphology and better sparse ACK coalescing, with accumulation delay |
| `opportunistic` | Writer drains bounded already-ready packets without waiting for future input; sends ready records and explicitly flushes the partial tail at batch completion | Almost removes accumulation delay; smaller batches increase processing/send costs |

This is not ACK suppression, wire V2 or unbounded accumulation. Opportunistic has
no Recordizer deadline: callers must complete ready batches with `finish_ready_batch`.
Current TCP/UDP pumps do so at both ends. Ready drains are bounded by `MAX_BATCH`;
individual records still obey `max_packets`/payload budgets. Limits are not enlarged.

For Reality-TLS, the new strategy also switches H2 DATA accumulation to ready-only
reads: `Pending` ends the batch. H2 flow control, backpressure, deadlines, AEAD and
reassembly remain. Pre-authentication H2 keeps the old strategy. With `policy=off`,
the field is dormant and does not independently switch H2 batching.

### Enable and roll back

In the server's **existing** profile section:

```ini
[profile:interactive]
obf.recordizer.policy = required
obf.recordizer.batch.mode = opportunistic
```

This is a fragment, not a complete profile. Preserve listener/identity/TUN/obfuscation
fields. In the panel: profile → obfuscation → PACKET_MUX recordizer → Batch mode.
Delay inputs are disabled in opportunistic but their values are preserved.
No client INI or qeli-link edits are needed.

Both cores must contain the implementation. An older client can advertise
`PACKET_MUX_V1` yet ignore the new field. Update both sides, apply configuration
through the normal lifecycle and reconnect. Verify `PACKET_MUX_V1 active` **and**
`Recordizer batching: opportunistic`, then measure latency. Set `timed` and reconnect
to roll back.

`delay_min_ms`/`delay_max_ms` no longer wait in opportunistic but must remain valid
(`min <= max`) and are retained for rollback. `timed` with `0/0` flushes every push;
it is **not** opportunistic ready draining. `max_packets` counts mux frames including
fragments; it, `max_queue_bytes`, `record.*` and `fragment.*` remain active. MTU,
TUN queues, padding, shaping, stealth and bandwidth settings are unchanged; the
latter can independently add delays. This is not a hard delivery-time guarantee.

### Gain and cost

In the [measured A/B](../reports/benchmarks/recordizer_latency_2026-10-29.md), sparse
VoIP p50 fell from 13.3–13.4 ms (25.7–25.9 ms with Reality/H2) to 0.82–0.95 ms;
p99 jitter fell from roughly 10–16 ms to 1.5–3.3 ms. **Artificial accumulation delay
is almost removed at around 8–9% peak TCP P4 upload cost for FakeTLS.** Reality-TLS
throughput increased; other directions differ, so there is no universal 8% penalty.
These are experimental SHA-specific Linux LAN results, not final dist qualification.
Temporal camouflage changes; equal DPI resistance was not established. The new
strategy is explicit opt-in, not a replacement default.

### Measuring timing and distinguishability

The [29 October Reality-TLS pilot with charts](../reports/benchmarks/recordizer_masking_pilot_2026-10-29.md)
used one binary, required, `timed/opportunistic` and a synthetic TLS/H2 control:
ten independent sessions per arm. Inner/outer timing correlation rose from 0.113
to 0.796 for voice and 0.033 to 0.782 for games: temporal blurring really decreased.
Control correlation was higher still (0.965/0.972), so rhythm is not a VPN fingerprint.

Sizes and timing separated both modes from this small control (AUROC 1.00);
timing alone separated the new mode less well (1.00 → 0.93). This is not a “stealth
percentage” or industrial-DPI/browser-corpus qualification. A 0/10 result at threshold
0.5 is not invisibility: predeclared maximum-window aggregation detected the new
mode in 10/10 with 0/10 false positives in this control. All threshold/aggregation
results, limitations, overhead and restoration are retained in the report.

## What the measurements established

The [single-pass required/off comparison of one 0.8.2 build](../reports/benchmarks/recordizer_required_off_2026-10-20.md)
recorded higher mean TCP P4 throughput with required across all 12 profiles. The
difference was about 6% for Reality-TLS and larger for the other profiles. In ordinary
TCP carriers, off increased CPU cost per useful traffic and inner TCP delay; UDP600
upload was accompanied by client TUN TX drops.

These are measurements on a Linux lab with 2 vCPU / 2048 MiB, not universal speedup
factors. Required still had large UDP600 losses on UDP carriers. The experiment did
not identify a specific CPU hot-path function or test DPI detectability.

## Implementation and related documents

- [Recordizer and Reassembler](../../../qeli/src/protocol/recordizer.rs).
- [Client data path](../../../qeli/src/client/mod.rs),
  [TCP server](../../../qeli/src/server/handler.rs),
  [UDP server](../../../qeli/src/server/udp_handler.rs).
- [Settings and compatibility](../manuals/OBFUSCATION.md).
- [Technologies and measurements](TECHNOLOGIES.md).

Source links describe the current repository implementation. A dated report is tied
to its own binary SHA and does not establish that subsequent source changes were
verified by that experiment.
