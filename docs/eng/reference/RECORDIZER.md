# Recordizer and Qeli record organization

Recordizer is a transport-independent layer between inner IP packets and Qeli
encryption. It changes the one-packet-to-one-record relationship: several packets
may share a record, and one packet may span multiple records. Its purposes are
changing observable traffic structure and grouping processing; it is not a separate
VPN protocol, H2 or another cipher.

Current settings and defaults belong in the
[obfuscation manual](../manuals/OBFUSCATION.md) and
[configuration reference](../manuals/CONFIG.md). This page describes the mechanism;
specific results belong in the [20 October 2026 measurements](../reports/benchmarks/recordizer_required_off_2026-10-20.md).

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

The first packet starts a flush deadline. A record may also become ready when its
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
