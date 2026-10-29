# Obfuscation and PACKET_MUX recordizer

This guide explains how the masking layers fit together, how to tune the transport-independent
recordizer, and which combinations are safe. It complements the complete key reference in
[CONFIG.md](CONFIG.md) and the measured limitations in [DPI-AUDIT.md](../reports/DPI-AUDIT.md).

Algorithm overview: [Recordizer and record organization](../reference/RECORDIZER.md).
[Required/off measurements on 12 profiles on 20 October 2026](../reports/benchmarks/recordizer_required_off_2026-10-20.md)
provide engineering results for one build, CPU, loss and interpretation limits,
not a public release benchmark. [Other technologies and measurements](../reference/TECHNOLOGIES.md).

[26–29 October latency A/B with charts](../reports/benchmarks/recordizer_latency_2026-10-29.md)
separates off/required from timed/opportunistic: accumulation delay is almost removed
at around 8–9% FakeTLS TCP upload cost, not for every profile. It is not final dist qualification.

The [29 October timing pilot](../reports/benchmarks/recordizer_masking_pilot_2026-10-29.md)
measured reduced rhythm blurring, not a percentage increase in VPN detectability:
the control is synthetic, not browser traffic; sizes/timing separated both modes
from it. Do not turn throughput percentages into “camouflage percentages”.

## 1. What the recordizer changes

The legacy data plane usually turned one inner IPv4/IPv6 packet into one encrypted qeli record.
That stable boundary and size relationship can contribute to a statistical DPI classifier.
Negotiated `PACKET_MUX_V1` changes the relationship before encryption:

- several inner packets can share one encrypted record;
- one inner packet can be split across several encrypted records;
- the target record size and the batch deadline vary;
- all mux headers stay inside `PacketCodec` AEAD and are not visible on the wire.

The order is important:

```text
inner IPv4/IPv6 packet
  -> PACKET_MUX recordizer
  -> padding / traffic normalization
  -> PacketCodec encryption
  -> selected carrier (plain, fake-TLS, Reality/H2, obfs/WS or UDP/QUIC shape)
  -> carrier/path fragmentation when required
```

The recordizer is not a transport mode and does not make the outer carriers identical. In
particular, `plain` is still a conspicuous high-entropy stream, fake-TLS is not genuine TLS,
QUIC shape is not genuine HTTP/3, and only Reality handles unauthenticated active probes by
bridging them to its target.

## 2. Recommended default

Put this block in every new server profile. These are the shipped balanced values:

```ini
obf.recordizer.policy = prefer
obf.recordizer.batch.delay_min_ms = 2
obf.recordizer.batch.delay_max_ms = 8
obf.recordizer.batch.max_packets = 16
obf.recordizer.batch.max_queue_bytes = 262144
obf.recordizer.record.max_payload_bytes = 0
obf.recordizer.record.small_min_ratio = 0.25
obf.recordizer.record.small_max_ratio = 0.875
obf.recordizer.record.full_probability = 0.72
obf.recordizer.fragment.enabled = true
obf.recordizer.fragment.reassembly_timeout_ms = 3000
obf.recordizer.fragment.max_inflight_packets = 64
obf.recordizer.fragment.max_reassembly_bytes = 4194304
obf.recordizer.fragment.max_fragments_per_packet = 64
```

The server owns this block and sends the effective configuration in the authenticated AUTH
response. There are no client-side `obf.recordizer.*` keys and qeli links do not change. A
configuration change takes effect after sessions reconnect.

Use `prefer` during rollout. It enables recordization with a client advertising
`PACKET_MUX_V1` and keeps the legacy data plane for an old client. Change to `required` only
after every client core is upgraded; an old client is then rejected before address allocation.
`off` explicitly selects the legacy one-packet/one-record data plane.

## 3. Every parameter

| Key | Default | Meaning and limits |
|---|---:|---|
| `obf.recordizer.policy` | `off` in the sparse schema baseline; `prefer` in shipped and newly created profiles | `off`, `prefer`, or `required`; negotiation policy described above |
| `obf.recordizer.batch.mode` | `timed` | `timed` retains the randomized wait; `opportunistic` groups already-ready packets and immediately flushes the bounded batch tail |
| `obf.recordizer.batch.delay_min_ms` | `2` | lower bound of the random flush deadline in `timed` mode |
| `obf.recordizer.batch.delay_max_ms` | `8` | upper `timed` deadline; must be at least `delay_min_ms`; `0/0` flushes each push, unlike opportunistic batching |
| `obf.recordizer.batch.max_packets` | `16` | maximum mux frames placed in one record; must be greater than zero |
| `obf.recordizer.batch.max_queue_bytes` | `262144` | hard per-direction queue/record memory ceiling, `64..=4194304` bytes |
| `obf.recordizer.record.max_payload_bytes` | `0` | `0` uses the largest safe plaintext for the active carrier and path; an explicit value is clamped to that safe budget and must be `64..=MAX_TUNNEL_MTU` |
| `obf.recordizer.record.small_min_ratio` | `0.25` | minimum random partial target as a fraction of the safe payload ceiling |
| `obf.recordizer.record.small_max_ratio` | `0.875` | maximum random partial target; ratios must satisfy `0 < min <= max <= 1` |
| `obf.recordizer.record.full_probability` | `0.72` | probability of selecting the full safe target instead of a partial target, `0..=1` |
| `obf.recordizer.fragment.enabled` | `true` | permits one inner packet to cross record boundaries; keep enabled unless the full packet is guaranteed to fit |
| `obf.recordizer.fragment.reassembly_timeout_ms` | `3000` | expiry time for an incomplete inner packet; must be greater than zero |
| `obf.recordizer.fragment.max_inflight_packets` | `64` | maximum incomplete packet IDs held per direction; must be greater than zero |
| `obf.recordizer.fragment.max_reassembly_bytes` | `4194304` | hard total reassembly-memory ceiling per direction; must be at least 64 bytes |
| `obf.recordizer.fragment.max_fragments_per_packet` | `64` | maximum mux fragments accepted for one inner packet; must be greater than zero |

A target size is a flush target, not padding by itself. A sparse batch can be sent below its
target when its deadline expires. Padding and traffic normalization run afterwards and can
increase the encrypted record size up to the carrier budget.

`batch.mode` is configured by the server and pushed after authentication with Recordizer. In a new client, `opportunistic` also removes the additional Reality-TLS H2 DATA accumulation wait; pre-authentication keeps the existing `timed` behavior. Older clients may ignore the new field and retain their existing behavior. QRM1, AEAD, memory bounds, fragmentation and HTTP/2 flow control remain enabled. The delay values are retained for switching back to `timed`.

To enable, edit the **existing server profile**:

```ini
obf.recordizer.policy = required
obf.recordizer.batch.mode = opportunistic
```

An already negotiated `prefer` policy need not change for batching. This is not a
complete profile. The default stays `timed`. Both server **and** client cores need
support; an older client's `PACKET_MUX_V1` capability alone does not prove support
for this field. Apply configuration through the normal lifecycle and reconnect;
check active mux and `Recordizer batching: opportunistic` logs at both ends.
To roll back, set `timed` and reconnect. The panel exposes the strategy selector;
delay fields are disabled in opportunistic but not zeroed.

`delay_min_ms <= delay_max_ms` is required in the new strategy too; retain the values
for rollback. Limits, `record.*`, `fragment.*`, MTU, TUN queue, padding and shaping
remain active. In `off`, batching is dormant and does not independently switch H2.
No intentional accumulation does not mean zero RTT: backpressure, pacing and
scheduling remain. [Full algorithm](../reference/RECORDIZER.md),
[operational verification](OPERATIONS.md#recordizer-batch-mode).

The low-latency strategy changes temporal morphology and does not promise identical DPI resistance. Explicit bandwidth/stealth pacing still applies. Latency gains and peak-throughput cost require a separate A/B on the exact build; an experimental candidate is not a published release.

## 4. Compatibility with the other masking controls

| Feature | Compatible? | Interaction |
|---|---|---|
| TCP `plain` | Yes | Boundary correlation is reduced, but the outer stream remains uncamouflaged high-entropy traffic. Use only on trusted networks. |
| TCP `fake-tls` | Yes | The inner relation is hidden; fake-TLS syntax and active-probe behaviour remain separate tells. |
| TCP `reality-tls` / Reality/H2 | Yes | Recordizer runs inside genuine TLS/H2. In `timed`, its batch delay and H2 accumulation can add together; `opportunistic` removes both post-AUTH waits when both cores support it. |
| TCP `obfs`, with or without WebSocket | Yes | Recordizer is inside the obfs/WS carrier; it does not make a WS session reproduce browser application semantics. |
| UDP `fake-tls` / `obfs` | Yes | The payload budget is derived from the UDP carrier and PMTU. Large batches can amplify loss because one lost datagram can contain several inner packets. |
| `obf.quic.enabled` | Yes, UDP only | QUIC-shaped overhead is included in the automatic safe budget. It remains QUIC shape, not a genuine QUIC/HTTP/3 implementation. |
| `obf.awg.*` | Yes | AWG junk is a pre-handshake feature; recordizer begins only after authenticated negotiation. TCP obfs still requires matching `jc`. |
| `obf.padding.*` | Yes | Padding is generated after recordization. It complements boundary changes but costs bytes. |
| `obf.traffic_normalization.*` | Yes | Round-size padding applies to the recordized plaintext. Keep round sizes within the real carrier/MTU budget. |
| `obf.traffic_shaping.*` | Yes | Idle cover is independent. `stealth` pacing can reduce throughput and add delay in either strategy; Recordizer's separate timer wait exists only in `timed`. |
| `obf.heartbeat.*` | Yes | Heartbeat records are control/cover traffic, not source packets to batch. Shaping replaces fixed heartbeat; Reality/H2 disables the qeli heartbeat. |
| `obf.fragmentation.*` | Yes, but different | This legacy control fragments selected handshake/carrier writes. It does not reassemble inner IP packets and does not replace `obf.recordizer.fragment.*`. |
| negotiated UDP `DATA_FRAG` / PMTU | Yes, automatic | This outer layer splits an encrypted record to fit the path. Recordizer fragmentation is inside encryption and preserves one inner-packet boundary for the receiver. |
| `obf.multipath.*` | Yes, TCP only | Each ordered TCP stream has independent sender/reassembler state. UDP must keep multipath disabled. |
| IPv4, IPv6 and dual-stack | Yes | The payload is treated as opaque authenticated bytes. The selected profile still has to pass its normal family, routing and MTU validation. |
| TUN and TAP | Yes | Qeli transports IPv4/IPv6 packets; TAP strips/restores the Ethernet header at the edge. Arbitrary L2 frames are not recordized across the tunnel. |

The following are real compatibility failures or unsafe combinations:

- `policy = required` with a client core that does not advertise `PACKET_MUX_V1`;
- `fragment.enabled = false` when an inner packet plus mux header cannot fit in one safe
  record; the packet is dropped instead of violating the carrier budget;
- a small explicit `max_payload_bytes` together with too small
  `max_fragments_per_packet`; a large inner packet then exceeds the configured fragment cap;
- invalid transport combinations that already fail without recordizer: Reality on UDP,
  QUIC masking on TCP, or multipath on UDP.

## 5. Why the balanced values look like this

`2..8 ms` is long enough to coalesce bursts but short enough not to dominate ordinary
interactive latency. Sixteen frames permit burst mixing without making a single loss carry an
unbounded number of packets. `max_payload_bytes = 0` is deliberate: the TCP, H2, obfs, QUIC and
PMTU budgets differ, so a hand-picked constant can either waste capacity or cause extra
fragmentation. The partial range changes the record-size histogram, while a 0.72 full-target
probability preserves throughput and amortizes encryption/carrier overhead. Reassembly limits
are resource-safety bounds for authenticated peers, not DPI knobs.

Do not copy values merely because they produce more fragments. More fragmentation adds headers,
CPU, loss sensitivity and latency; it is not automatically better camouflage. Validate a change
against a clean PCAP control corpus and a throughput/loss benchmark for the same carrier.

## 6. Tuning profiles

Start from the balanced block above and change one dimension at a time.

### Latency-sensitive traffic

```ini
obf.recordizer.batch.delay_min_ms = 0
obf.recordizer.batch.delay_max_ms = 2
obf.recordizer.batch.max_packets = 4
```

This reduces queueing, at the cost of fewer coalesced packets and a weaker change to the size
histogram. Keep `fragment.enabled = true` and `max_payload_bytes = 0`.

### Lossy UDP path

```ini
obf.recordizer.batch.delay_min_ms = 0
obf.recordizer.batch.delay_max_ms = 2
obf.recordizer.batch.max_packets = 2
obf.recordizer.record.full_probability = 0.85
```

Smaller batches reduce loss amplification. Automatic payload sizing lets authenticated PMTU
raise the safe budget without creating oversized datagrams.

### Stronger experimental morphology

```ini
obf.recordizer.batch.delay_min_ms = 3
obf.recordizer.batch.delay_max_ms = 12
obf.recordizer.record.full_probability = 0.55
```

This creates more partial targets and more batching opportunity, but adds latency and overhead.
Treat it as an experiment until PCAP and application tests show an improvement for the exact
outer carrier and network.

## 7. Rollout and verification

1. Upgrade the server core and add the balanced block with `policy = prefer` to every profile.
2. Restart qeli and reconnect a current client. Confirm the log contains
   `Packet recordizer: PACKET_MUX_V1 active` for TCP or UDP.
3. Verify IPv4 and IPv6 bidirectional traffic, DNS, reconnect, PMTU and sustained load.
4. Verify an old client still connects through the legacy data plane while policy is `prefer`.
5. Upgrade every client application/core. Only then, if fail-closed operation is wanted, change
   the profile to `required` and reconnect sessions.
6. Compare packet-size and timing distributions against genuine control traffic. A throughput
   test alone cannot prove DPI camouflage.

For rollback set `obf.recordizer.policy = off`, restart the profile/service and reconnect. No
client configuration or connection link has to be rolled back.

There is no defensible setting that makes a protocol “completely invisible”. Recordizer removes
one transport-independent boundary correlation; the chosen carrier, endpoint reputation,
active-probe behaviour, long-term timing and traffic volume remain observable.

## Shared shaping budget and pacing deadlines

<!-- normative-sync: shaping-budget-v1 -->

`obf.traffic_shaping.enabled = true` enables idle cover. With `stealth = true`,
real data is paced **only over TCP**. UDP deliberately retains idle cover only,
even when a saved setting requests stealth. `stealth_rate_mbps` must be positive only while both
shaping and stealth are enabled. A value of `0` for inactive stealth survives
client INI parsing and serialization.

All bonded client TCP writers reserve the data rate from one shared budget.
The server also uses an aggregate session-direction budget. Upload and download
remain independent; this is not a cap on their sum. Cover has a separate shared
`budget_bytes_per_sec`, which does not multiply with the stream count.

Pacing waits for the entire calculated pause, including its final 6 ms. That
short remainder emits no extra cover but still delays the data until its deadline.
Slow cover writes count towards the pause. Up to one second of accumulated credit
may allow an initial burst; a short measurement need not equal the configured rate.

Active cover sizes must fit `MAX_TUNNEL_MTU`, and the budget must be at least
`max_size`. UDP further clamps the size to its carrier/path budget. Local INI and
authenticated AuthOK settings share these active checks. The local client still
checks positive, ordered saved ranges when shaping is disabled.

`budget_bytes_per_sec` meters requested cover-padding bytes. AEAD and outer
carrier headers increase actual interface traffic; this is not a total wire-rate
limit. Shaping and recordization do not guarantee DPI evasion.


## Combined padding targets and malformed mux-record handling

<!-- normative-sync: morphology-contract-v1 -->

`obf.traffic_normalization.round_sizes` targets **data + all padding** before encryption.
Random padding is generated first;the nearest fitting target includes those bytes:
payload70 + padding3 with target128 gets55 additional bytes,not58. AEAD and the outer
carrier add their own overhead. With no target below the carrier budget,normalization
adds nothing;existing padding remains.

`obf.padding.probability = 0` means exactly no random padding;normalization can add its
own bytes independently. NaN/Inf are rejected even with padding disabled or
`obf.recordizer.policy = off` because service API/AuthOK cannot preserve them. Other
finite dormant tuning is retained;active features validate their ranges.

If any mux-envelope frame errors,no completed packet from that record reaches the
callback. Internal reassembly state remains incremental:accepted partial fragments may
remain until timeout;conflicting state is removed. This promises neither full receiver
state rollback nor a wire-format change.
