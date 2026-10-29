# Recordizer: Reality-TLS timing and distinguishability pilot

29 October 2026. Follow-up to the [latency/throughput A/B](recordizer_latency_2026-10-29.md).
This is a **limited IPv4 LAN pilot**, not an industrial-DPI detection probability,
browser-equivalence test or final `release/dist` qualification.

## Main conclusion

`opportunistic` transfers application timing much more faithfully: the loss of
temporal blurring is measurable. This **does not automatically make VPN detection
easier**: the synthetic interactive H2 control also transfers that rhythm.
Full features separated both strategies from this synthetic control (AUROC 1.00);
timing-only features separated the new strategy less well (1.00 → 0.93).

These are not “X% lost stealth”. In particular, the previously measured **8–9%
FakeTLS peak-upload loss** is a different experiment and metric, not a camouflage
cost. Timed's advantage in blurring rhythm is established; a universal DPI advantage
is not. The default was not changed.

## Lab, binary and changed factor

- VM300/server and VM301/client: **2 vCPU / 2048 MiB each**, kernel 6.12.111.
- One experimental `qeli 0.8.3` binary at both ends, not rebuilt:
  SHA256 `df933b86f6efc0613c9c20d11a35fef5a4a31ca6b2f13c198e774a7b9fd2c1aa`.
- Only `tcp-reality-tls`, **Recordizer required**. Between Qeli arms, only
  `obf.recordizer.batch.mode` changed: `timed` / `opportunistic`.
- TUN MTU 1400, TX queue 1000 at both ends, two server TUN queues;
  padding false, traffic shaping true, stealth false. No queue/RAM/vCPU tuning.
- Third arm: an owned synthetic **TLS 1.3 / genuine H2 streaming POST/echo** app,
  ALPN `h2`, status 200 and identical useful-message cadence. It is not a browser,
  video service or representative Internet negative corpus.
- Neither VM302 nor Proxmox was used. H2 tools were unpacked in a private test
  prefix; system packages were not installed or upgraded.

## Method

Ten chronological blocks, each with a fresh session of every arm. Arm order was
rotated and reversed. Each session carried four eight-second windows:

| Pattern | Useful message | Schedule | Offered useful load in one direction |
| --- | ---: | --- | ---: |
| Voice rhythm (`voip`) | 172 bytes | every 20 ms | 0.0688 Mbit/s |
| Game rhythm (`game`) | 128 bytes | every 7.8125 ms | 0.131072 Mbit/s |
| Bursts (`burst`) | 128 bytes | 8 messages every 100 ms | 0.08192 Mbit/s |
| Continuous (`bulk`) | 1200 bytes | every 1 ms | 9.6 Mbit/s |

Echo provides the reverse direction. Offered load is matched; this is **not** a
peak-throughput search. Total: 30 main sessions / 120 windows, plus 3 preflight
sessions / 15 windows. Preflight is excluded from classifier evaluation.

Capture was on client `eth1`, with kernel BPF restricted to the test peer pair and
TCP 443/8443. Only `t_ns`, direction, IP/TCP lengths, flags, seq and ack were saved;
no packet bytes, TLS secrets or application content. Handshake sessions and active
probing were outside scope. IP, ports, certificates, filenames and arm labels were
not classifier features.

GRO/GSO/TSO/rx-gro-hw on test `eth1` were disabled symmetrically for capture and
restored afterward. All main IP packets were at most 1500 bytes. These are separate
**instrumented conditions**: disabling offload changes packetization/CPU itself,
so absolute values must not be pooled with earlier IRTT or production results.

## How much rhythm reaches the outside

Each session correlates known test-generator sends with external client→server
payload-packet time series: 1 ms bins, maximum across 0..40 ms shifts. Values below
are medians of ten session maxima. This is descriptive known-input ground truth,
**not** a feature available to a single passive DPI observer. Periodicity aliases
are possible; the maximizing shift is not one-way network delay. Send timestamps
were recorded after submitting the message to the send API.

| Pattern | Timed | Opportunistic | H2 control |
| --- | ---: | ---: | ---: |
| Voice | 0.113 | **0.796** | 0.965 |
| Game | 0.033 | **0.782** | 0.972 |
| Bursts | 0.164 | **0.759** | 0.989 |

A larger coefficient means less rhythm blurring, not “X% lost protection”. Even
low correlation under this metric does not exclude application identification by
other features, such as spectral features. Bulk is omitted from the correlation
plot because a nearly constant input makes interpretation especially generator-dependent.

![Timing transfer and RTT in three arms](../../../data/benchmarks/recordizer_masking_pilot_2026-10-29_timing.svg)

## Distinguishability evaluation

Seven passive features: mean TCP-payload size and its CV; median same-direction
payload gap and its CV; fraction of gaps below 1 ms; direction-change fraction;
maximum gap. A separate ablation retains only five timing features. Packet counts
were not presented as millions of independent examples.

Predeclared model: L2 logistic regression, log1p, **training-only** standardization,
balanced classes, lambda 0.1, 1000 steps with learning rate 0.2, no hyperparameter
search. Leave-one-block-out excludes the entire block and all its connections and
windows. Primary session score averages four windows; predeclared sensitivity
analysis takes the maximum window score.

The initial plan was clarified before feature extraction: outer-packets-per-useful-
message remains descriptive but is **excluded from the classifier** because it
requires internal send ground truth. The specification and SHA are retained.

| Task / features | Timed AUROC | Opportunistic AUROC |
| --- | ---: | ---: |
| Qeli versus H2: sizes + timing | **1.00** | **1.00** |
| Qeli versus H2: timing only | 1.00 | 0.93 |

The separate task of distinguishing **the two Qeli modes** achieved AUROC 1.00
with full or timing-only features. This establishes a changed fingerprint, not VPN detection.

![ROC on held-out sessions](../../../data/benchmarks/recordizer_masking_pilot_2026-10-29_classifier.svg)

Complete fixed-threshold 0.5 results, sessions labelled “Qeli”:

| Features / window aggregation | Timed | Opportunistic | H2 control (false positives) |
| --- | ---: | ---: | ---: |
| Sizes + timing / mean | 10/10 | **0/10** | 0/10 |
| Sizes + timing / maximum | 10/10 | **10/10** | 0/10 |
| Timing only / mean | 10/10 | 0/10 | 0/10 |
| Timing only / maximum | 10/10 | 10/10 | **10/10** |

**0/10 at one threshold is not invisibility.** Full-feature scores for the new
strategy still ranked above every control score, producing AUROC 1.00. Another
threshold can separate them in this observed corpus; it is not an independently
validated operational DPI threshold. Maximum/timing-only labelled everything and
is unusable as a detector here. These unfavorable results were not omitted.

There are only ten negative sessions: empirical FPR steps are ten percentage
points. Control uses Python/OpenSSL and the h2 library; Qeli uses a different stack.
Some separation may characterize this particular control implementation rather than
a unique VPN/Recordizer tell. One control service does not cover ordinary HTTPS/H2
diversity, including arbitrary application sizes and exchange patterns.

Even 0/10 gives an ordinary Wilson upper bound around 27.8% (95%), not
1% or 0.1% FPR qualification. Such intervals also omit traffic-domain shift and
training uncertainty. Scores are not real-censor detection probabilities. Full
features hit a distinguishability ceiling in this small corpus.

## Latency and measurement quality

This is an owned UDP/H2 echo generator, **not the earlier IRTT**. Values are
medians of session p50/p99 quantiles, not pooled-packet quantiles:

| Pattern | Timed p50 / p99, ms | Opportunistic p50 / p99, ms | H2 p50 / p99, ms |
| --- | ---: | ---: | ---: |
| Voice | 25.99 / 35.08 | 1.21 / 1.62 | 0.93 / 1.11 |
| Game | 23.52 / 34.44 | 1.17 / 1.44 | 0.93 / 1.08 |
| Bursts | 26.22 / 35.51 | 1.50 / 2.75 | 1.13 / 1.46 |
| Continuous | 18.46 / 29.20 | 0.59 / 1.55 | 0.58 / 0.78 |

All 301,920 main useful messages received echo replies; capture-socket drops were
zero in all 132 captures. Replies were awaited for up to 0.75 s after a window:
this is echo accounting, not independent proof of no network retransmissions.
Generator timing is imperfect; actual sends/lateness remain in evidence. Median
p99 lateness for voice: 2.17 / 2.24 / 2.23 ms; game: 1.23 / 1.24 / 1.25 ms in
timed/opportunistic/H2 order. Burst differed more (2.29 / 1.38 / 1.79 ms), limiting interpretation.

Capture cost roughly 1–3.5% of one core for sparse traffic. Bulk medians were
8.17% / 25.08% / 15.36%, maximum 26.25% of one core. Only voice had one sequential
captured/uncaptured preflight pair; bulk had none. Zero observer effect is not
established. This binary also retains the earlier synchronous usage path; VM/I/O
tails cannot all be attributed to batching.

## Restoration and artifacts

300/301 were restored: 17 baseline checks each, original usage file and SHA.
An additional **full** offload comparison found that re-enabling parent TSO had
enabled originally-disabled `tx-tcp-mangleid-segmentation`. That single derived
flag was separately restored to `off` at both ends; the full feature map then
matched. The initial result was not rewritten; follow-up evidence is retained.
Owned processes stopped, locks removed, old binaries/raw unchanged. No release was published.

Raw remains in private `/opt/qeli-release-short-mask-pilot-20261029` guest directories.
They include private test configurations and the owned TLS-control key:
**do not publish the entire directories**. The repository contains only
[sanitized data/features](../../../data/benchmarks/recordizer_masking_pilot_2026-10-29.json),
charts and offline reproduction scripts. Without guest access:

```sh
python scripts/analyze_recordizer_masking_pilot.py --check
python scripts/render_recordizer_masking_pilot.py --check
```

[Classifier recomputation](../../../../scripts/analyze_recordizer_masking_pilot.py)
and [chart rendering](../../../../scripts/render_recordizer_masking_pilot.py) use
compact features only; they do not repeat initial header-metadata extraction.
Original input and algorithm hashes are retained in JSON.

## Operational decision

The new mode blurs **application rhythm** less, but the pilot did not establish
a percentage loss in **VPN indistinguishability**. The old random timer also
creates a fingerprint. Both strategies and default `timed` remain. Changing the
default or promising unchanged DPI resistance needs a separate decision and a
broader corpus: browser TLS/H2 implementations, applications, workloads and
independent sessions. Neither cryptographic strength nor active-probe resistance
was evaluated by this passive pilot.

See [Recordizer](../../reference/RECORDIZER.md), [settings](../../manuals/OBFUSCATION.md)
and [technologies and measurements](../../reference/TECHNOLOGIES.md).
