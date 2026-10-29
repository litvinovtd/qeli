# Recordizer: latency, jitter and the low latency trade-off

Report dated 29 October 2026, covering experiments on 26–29 October. These are
engineering Linux A/B measurements, **not final `release/dist` qualification or a
published release**. Measured binaries identified as 0.8.3; current dev sources are 0.8.4.

## Conclusion

The previous `timed` strategy added about **12–13 ms RTT** to sparse traffic.
Reality-TLS had another H2 accumulation stage, reaching **25.7–25.9 ms p50**.
The `opportunistic` candidate measured **0.82–0.95 ms p50**, **1.87–3.00 ms p99**:
it practically removes the **artificial accumulation delay**, not network latency itself.

The measured price for FakeTLS TCP P4 upload is **around 8–9% peak throughput**:
TCP-FakeTLS −8.90%/−9.36%, UDP-FakeTLS −8.49%/−8.28% for IPv4/IPv6.
This is **not a universal per-profile penalty**: Reality-TLS became faster.
The old strategy remains available and the `timed` default is unchanged. Several
cells exceeded the proposed 5% speed-loss tolerance; latency success does not make
the entire initial A/B an unconditional pass. Two later ACK experiments failed to
produce the required recovery and were removed from working sources.

## Experiments performed

| Series | Changed factor | Workload and replication |
| --- | --- | --- |
| 20 October, [archived throughput](recordizer_required_off_2026-10-20.md) | Required/off, one 0.8.2 binary, 12 profiles | n=1 speed pass, not interactive jitter measurement |
| 26 October, off/required | Policy only in the old binary; Reality retains H2 in both arms | 5 profiles × IPv4/IPv6 × VoIP/game × idle/background; n=3 paired windows |
| 27 October, timed/opportunistic | Archived timed versus opportunistic candidate, both required; additional candidate timed control | Same latency matrix; TCP P4/UDP600 n=3; diagnostic P1/UDP1000 n=1 |
| 29 October, localization | Raw, source, waits and send-frequency analysis | Smaller ACK batches and synchronous usage fsync identified as distinct mechanisms |
| 29 October, independent changes | Two ACK variants and separate usage offload, required | ACK n=3 rejected; usage A/B and independent confirmations including longer windows |

Profiles: `tcp-faketls`, `tcp-reality-tls`, `udp-faketls`, `udp-quic`, `udp-obfs`.
VoIP: 172 bytes every 20 ms; game pattern: 128 bytes every 7.8125 ms; 60-second windows.
`bidir100` background is **UDP 100 Mbit/s in each direction**, not TCP saturation.
Extra diagnostics: sparse 96 bytes/100 ms/30 s; bounded 250 pps/10 s. Direct-only
1000/5000 pps controls exposed IRTT timer limits, not maximum VPN packet rate.
TCP P4/UDP600: 15 s, `-O 3`; UDP1000 is offered load, not a discovered ceiling.

Lab: VM300 server, VM301 client; **2 vCPU / 2048 MiB each**, Linux kernel 6.12.111,
i5-8500 host, isolated local LAN. TUN MTU 1400, TX queue 1000 at both ends, two server
TUN queues. No between-arm resource/config tuning. VM302 was used only for builds.
Old binaries/raw were retained and 300/301 restored. No new load was run on 300/301
as part of this documentation/source check.

## Binaries and reproducibility

| Role | SHA256 |
| --- | --- |
| Archived 0.8.3: off/required and timed A | `9cc1dfb84ccdee3bc0fb23aa3b0745882b0d520a325134112be2575512b62a1d` |
| Low latency B; same candidate's timed control C | `df933b86f6efc0613c9c20d11a35fef5a4a31ca6b2f13c198e774a7b9fd2c1aa` |
| Separate later usage-only candidate | `41b724726116aac49308ab971be8ef7f9ebeac0c8f9585daf13f0fa7fafe23b4` |

[Compact data](../../../data/benchmarks/recordizer_latency_2026-10-29.json) retains
input-summary SHA values, all main IPv4/IPv6 conditions, paired changes, speed-window
loss/retransmits/TUN drops, original reviews and restoration. Large raw remains in
separate guest directories:

```text
/opt/qeli-release-short-083-latency-ab-20261026-resume1
/opt/qeli-release-short-083-lowlat-ab-20261027
/opt/qeli-release-short-083-lowlat-localization-20261029
/opt/qeli-release-short-083-ack-usage-20261029-a3-main
/opt/qeli-release-short-083-ack-usage-20261029-quic-confirm
/opt/qeli-release-short-083-ack-usage-20261029-tail-confirm
```

Reproduce charts without lab access: `python scripts/render_recordizer_latency.py`;
verify using `--check`. The [SVG generator](../../../../scripts/render_recordizer_latency.py)
uses compact data only. Latency charts explicitly select IPv4; IPv6 remains below and
in JSON. Off comes from a separate series, not a third arm of the same A/B.

## Latency and jitter

Values are medians of three window quantiles, not quantiles of pooled packets.
RTT is round trip, not absolute one-way delay; do not divide RTT by two.
Jitter means **p99 absolute adjacent-packet RTT IPDV**, not mean jitter or RTP
interarrival jitter. p99 is not the maximum.

![Sparse VoIP RTT p50 and p99](../../../data/benchmarks/recordizer_latency_2026-10-29_rtt.svg)

![Jitter: p99 absolute RTT IPDV](../../../data/benchmarks/recordizer_latency_2026-10-29_jitter.svg)

VoIP idle, IPv4 / IPv6 values, ms:

| Profile | Off p50 | Timed required p50 | Opportunistic required p50 | New p95 | New p99 | Jitter p99: timed → new |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP-FakeTLS | 0.83 / 0.82 | 13.37 / 13.37 | 0.84 / 0.85 | 1.00 / 1.00 | 2.12 / 1.89 | 10.15 / 9.97 → 2.78 / 1.70 |
| Reality-TLS/H2 | 13.44 / 13.47 | 25.66 / 25.85 | 0.95 / 0.95 | 1.10 / 1.12 | 2.60 / 3.00 | 16.09 / 15.92 → 3.28 / 3.03 |
| UDP-FakeTLS | 0.81 / 0.84 | 13.36 / 13.32 | 0.83 / 0.84 | 0.96 / 0.96 | 2.80 / 2.53 | 10.19 / 9.96 → 2.59 / 3.17 |
| UDP-QUIC | 0.81 / 0.83 | 13.35 / 13.35 | 0.83 / 0.84 | 0.97 / 0.97 | 1.87 / 1.89 | 10.11 / 10.03 → 1.92 / 1.53 |
| UDP-OBFS | 0.82 / 0.83 | 13.33 / 13.38 | 0.82 / 0.84 | 0.96 / 0.98 | 2.18 / 2.19 | 10.15 / 10.04 → 2.40 / 2.72 |

Timed columns here use the 27 October A/B; off uses 26 October. In the original
off/required A/B, timed p50 was 13.3–13.4 ms, or 25.7–25.9 ms with Reality-TLS.
Between-series differences must not be presented as exact paired changes.

![Game-pattern p99 idle and with UDP 100+100 Mbit/s](../../../data/benchmarks/recordizer_latency_2026-10-29_loaded.svg)

With game pattern plus background, new p99 was **2.44–3.60 ms** across all five
profiles and both families, versus **14.07–18.86 ms** timed, with no IRTT loss in
these windows. This is not a real game, voice codec or mobile-network test.

## Throughput cost

![Paired TCP P4 throughput changes with the range of three repetitions](../../../data/benchmarks/recordizer_latency_2026-10-29_speed.svg)

Point: median **paired percentage change**. Whisker: min/max of three pairs, not a
confidence interval. This is not the ratio of separately calculated Mbps medians.

| Profile | IPv4 upload | IPv4 download | IPv6 upload | IPv6 download |
| --- | ---: | ---: | ---: | ---: |
| TCP-FakeTLS | −8.90% | −3.52% | −9.36% | −3.21% |
| Reality-TLS/H2 | +34.68% | +36.07% | +29.72% | +27.55% |
| UDP-FakeTLS | −8.49% | −2.69% | −8.28% | +1.19% |
| UDP-QUIC | −3.16% | −5.09% | −5.09% | −2.72% |
| UDP-OBFS | −4.08% | +0.44% | −5.44% | +0.81% |

Direct baseline drift: upload −1.56%, download +1.76%. Variable UDP-OBFS windows
and cells around/below −5% remain in review. “Almost no accumulation delay for about
8% throughput” describes **measured FakeTLS upload**, not every profile, direction,
UDP600 workload or device.

## Initial failures and follow-up

1. The initial lowlat UDP-FakeTLS IPv4 VoIP window reported **47/3000 = 1.57%** loss.
   Raw is retained. Localization identified IRTT 0.9.0 reflector `ShortInterval`
   rejects with `-i 50us` after a real pause, not demonstrated Qeli packet loss.
   Subsequent A/B used `irtt server -i 0` in every arm. The real pause was not dismissed.
2. Synchronous usage `fsync` ran on Tokio. In a separate usage-only A/B, 12/12
   baseline calls were on `tokio-rt-worker`, and 12/12 candidate calls on `qeli-usage-save`.
   Durability was retained. The original up-to-583 ms stall was not reproduced:
   a confirmed blocking mechanism was removed, not every possible latency tail.
3. The initial usage-only p99 increase **+1.13 ms** is retained. Independent n=3
   60-second pairs measured **+0.73 ms** median paired change; median changes in all
   six 10-second bins stayed below +1 ms. This does not prove zero usage impact.
4. Neither zero-wait ACK variant produced the required sustained upload recovery;
   both were rejected and removed. A proposed ACK-only window around 1 ms is
   **not implemented by this report**.

## Source readiness and qualification boundary

On 29 October, a separate current-dev snapshot on **302** was checked for INI
read/write, defaults/validation/JSON, server AUTH push/client parsing, opportunistic
no-deadline/single-packet/fragment-tail behavior and legacy timed behavior; H2
without advancing test time, flow control and stalled-stream deadlines.
Client/server TCP/UDP ready-batch completion sites and reconnect/additional TCP
streams were reviewed. Transport-core calls the same client pumps. A RU/EN panel
selector preserves timed delay values and the `timed` default. Commands, outcomes
and snapshot SHA are in the shared JSON `source_check`.

VM302 outcomes: Recordizer filter 22 passed; H2 5 passed; AUTH and INI roundtrip
one passed each; web 181 passed / 5 ignored. Standalone client and FFI `cargo check`
passed. Local editor JS: 125 passed, including mode/delay preservation across
normalization and rollback. INI generator coverage includes the new key. Some tests
overlap between filters; do not add these counts as unique tests.

These are targeted Linux unit/check results, **not a complete security audit, all
platform builds, Android/iOS/Windows device tests or final ELF qualification**.
Both cores need the new field. An older `PACKET_MUX_V1` client may ignore it;
the capability alone is insufficient proof. A final candidate needs its own
short release test tied to its exact SHA.

## Operational interpretation

Measured latency favors the new strategy for interactive traffic; `timed` remains
available for peak throughput and the previous temporal camouflage.
**Unchanged DPI resistance is not promised:** removing waits changes traffic timing.
Crypto, QRM1, limits, reassembly and H2 flow control stay enabled. Network RTT,
queues, CPU, bandwidth limits and stealth pacing can still delay packets.

An unnecessary 12–25 ms RTT matters for latency-sensitive games, but does not
automatically imply unusable voice. Real VoIP jitter buffers, WAN loss, mobile RTT
and link saturation were not qualified by this LAN experiment.
See [modes and configuration](../../reference/RECORDIZER.md),
[obfuscation](../../manuals/OBFUSCATION.md) and [operations](../../manuals/OPERATIONS.md#recordizer-batch-mode).

## Follow-up: temporal camouflage

A separate [Reality-TLS timing pilot](recordizer_masking_pilot_2026-10-29.md) followed
this A/B using the same lowlat SHA, required and an H2 control. It quantitatively
separates reduced rhythm blurring from VPN detection, with charts, all classifier
variants and corpus limits. Its echo/offload conditions do not replace the IRTT
and throughput values above. An 8–9% speed loss does not mean 8–9% lost stealth.
