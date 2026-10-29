# Qeli technologies and measurements

This section explains how Qeli mechanisms work, where to configure them and which
measurements support particular properties. Choose a topic, then follow its manual
or dated report. An algorithm description is not an executed verification, and lab
throughput is not a performance guarantee.

## Mechanisms and services

| Topic | Design and configuration | Verification and measurements |
| --- | --- | --- |
| Recordizer record organization | [How PACKET_MUX_V1 works](RECORDIZER.md); [settings and compatibility](../manuals/OBFUSCATION.md) | [Required versus off across 12 profiles, 20 October 2026](../reports/benchmarks/recordizer_required_off_2026-10-20.md) — one engineering pass of the same build |
| Shared transport layer | [Rust transport core and platform adapters](TRANSPORT-CORE.md) | Contracts and verification boundaries are listed in the core reference |
| Low latency Recordizer and H2 | [Timed/opportunistic strategies](RECORDIZER.md); [switching](../manuals/OPERATIONS.md#recordizer-batch-mode) | [26–29 October A/B, RTT/jitter/throughput and charts](../reports/benchmarks/recordizer_latency_2026-10-29.md): almost no accumulation delay, around 8–9% FakeTLS upload cost; not final dist |
| Recordizer timing pattern | [Rhythm blurring and VPN detection are different goals](RECORDIZER.md) | [29 October Reality-TLS pilot](../reports/benchmarks/recordizer_masking_pilot_2026-10-29.md): timing correlation, classifiers, charts and limited H2 control; not a DPI-protection percentage |
| Camouflage and Reality TLS/H2 | [Obfuscation layers](../manuals/OBFUSCATION.md); [threat model](THREAT-MODEL.md) | [DPI analysis](../reports/DPI-AUDIT.md); throughput alone does not establish DPI resistance |
| Linux TUN, queues and diagnostics | [TUN settings](../manuals/CONFIG.md); [troubleshooting](../manuals/TROUBLESHOOTING.md) | TUN drops in the [current Recordizer comparison](../reports/benchmarks/recordizer_required_off_2026-10-20.md); not FULL_RING tracing |
| IPv6 and routing | [Dual stack, routes and NDP](../manuals/IPV6.md) | Dated reports include an IPv4/IPv6 matrix |
| Web panel and server management | [Panel](../manuals/PANEL.md); [operations](../manuals/OPERATIONS.md) | Verification status is recorded in the [audit catalog](../reports/audit-0.8.2/README.md) |

## Where material belongs

This section is a navigation entry point, not another copy of existing documentation.

- `reference/` describes a mechanism's purpose, data path, state, algorithm, limits and
  implementation references. It explains why a solution was chosen.
- `manuals/` covers settings, operator actions, compatibility and troubleshooting.
- `reports/benchmarks/` contains dated measurements with binary SHA, lab conditions,
  full methodology, results and limitations. Other engineering checks remain in the
  appropriate part of `reports/`.
- `docs/data/benchmarks/` holds compact shared table data without secrets. Large raw,
  private configs and diagnostic dumps are not copied into documentation.
- `plans/` holds solutions not yet implemented and proposed experiments.

Dated reports preserve original results, including failed windows. A corrected method
or another build gets a new report or an explicitly identified addendum; a later
experiment must not replace earlier numbers. Linking withdrawn measurements here does
not reinstate them as published release benchmarks.

## Minimum contents of new material

A mechanism description identifies the problem, inputs and outputs, processing order,
state owner, memory and queue limits, failures, configuration and verified boundaries.
Keep current implementation separate from proposed optimizations.

A measurement records date, version and full SHA, OS and resources, changed factor,
phase order, workloads, duration, repeat count, every direction, metrics and raw
location. Separate observations, interpretation and further verification needs.
Include confirmation that the lab was restored.

Add material at matching paths under `docs/ru/` and `docs/eng/`, link it from both
`index.md` maps and its relevant manual. Structural checks are provided by
[`scripts/check_docs.py`](../../../scripts/check_docs.py).
