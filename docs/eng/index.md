# Qeli documentation — map

> Preliminary development performance measurements for 0.8.2 have been withdrawn from publication. Complete original data and reports are retained locally for internal audit. They are not a public release benchmark or a basis for comparing version performance.

The documentation is organized by **document type**. The same directory layout is used for
English and Russian, and every active page is linked from this map.

> New here? Start with **[Getting started](manuals/GETTING-STARTED.md)**, then
> **[Configuration](manuals/CONFIG.md)**. If something does not work, open
> **[Troubleshooting](manuals/TROUBLESHOOTING.md)**.

**Русская версия → [../ru/index.md](../ru/index.md)**

## Overview

| Document | What it covers |
|---|---|
| [README.md](README.md) | Project overview: purpose, wire modes, crypto stack and repository layout |

## Manuals (`manuals/`)

Practical installation, configuration and operations guides.

[Short release test](manuals/RELEASE-SHORT-TEST.md) — fixed Linux transport and performance checks.

[16 October 2026 pilot](reports/RELEASE-SHORT-PILOT-2026-10-16.md) — publication status and qualification limits.

| Document | What it covers |
|---|---|
| [GETTING-STARTED.md](manuals/GETTING-STARTED.md) | Installation and first run, step by step |
| [CONFIG.md](manuals/CONFIG.md) | Complete flat-INI server and client configuration reference |
| [OPERATIONS.md](manuals/OPERATIONS.md) | Compatibility, upgrades, rollback, backup and firewall operations |
| [PANEL.md](manuals/PANEL.md) | Web panel installation and use |
| [IPV6.md](manuals/IPV6.md) | IPv4/IPv6/dual-stack setup, `off/manual/route/nat66`, NDP proxy and diagnostics |
| [OBFUSCATION.md](manuals/OBFUSCATION.md) | Recordizer setup, masking-layer compatibility and tuning profiles |
| [TROUBLESHOOTING.md](manuals/TROUBLESHOOTING.md) | Connection diagnostics and error reference |
| [KEENETIC-DEPLOY.md](manuals/KEENETIC-DEPLOY.md) | Step-by-step client deployment on Keenetic |

## Use cases (`scenarios/`)

Complete deployments with required inputs, configs, verification and recovery steps.

| Document | What it covers |
| --- | --- |
| [Use-case catalog](scenarios/README.md) | Available scenarios, requirements and qualification reports |
| [Client → A → B → Internet](scenarios/CHAINED-SERVERS.md) | Two servers, built-in A → B client, INI hooks, root/non-root and autostart |

## Reference (`reference/`)

Technical contracts and architecture that describe the current implementation.

| Document | What it covers |
|---|---|
| [CLIENT-CONFIG-MATRIX.md](reference/CLIENT-CONFIG-MATRIX.md) | Current client-key contract by platform and migration history |
| [THREAT-MODEL.md](reference/THREAT-MODEL.md) | Threat model, trust boundaries and assurance status |
| [TRANSPORT-CORE.md](reference/TRANSPORT-CORE.md) | Shared Rust transport core, source/ABI contract and release gates |
| [KEENETIC-PORT.md](reference/KEENETIC-PORT.md) | Keenetic port architecture and dual-arch build rationale |

## Plans (`plans/`)

Active development direction and implementation plans. These are not end-user instructions.

| Document | What it covers |
|---|---|
| [ROADMAP.md](plans/ROADMAP.md) | Product and engineering roadmap |
| [ROAMING.md](plans/ROAMING.md) | Normative client-roaming implementation plan |
| [IPV6-IMPLEMENTATION-PLAN.md](plans/IPV6-IMPLEMENTATION-PLAN.md) | IPv6 architecture, stages and release gates |
| [CLIENT-CONFIG-CORE.md](plans/CLIENT-CONFIG-CORE.md) | Shared Rust INI/URI APIs, removed client duplicates and remaining checks |

## Audits

Engineering-audit material is organized in separate versioned catalogs.
The complete Q01–Q37 list and individual verification results belong inside the audit
catalog rather than the general report list.

| Document | About |
|---|---|
| [0.8.2 audit: Q01–Q37 catalog](reports/audit-0.8.2/README.md) | All reports grouped by audit-plan stage |
| [0.8.2 documentation review](reports/audit-0.8.2/DOCUMENTATION-REVIEW.md) | Final post-audit documentation review |
| [Full system-audit plan](plans/FULL-SYSTEM-AUDIT.md) | Scope, criteria, environments and execution history |
| [Audit debt register](plans/AUDIT-DEBT.md) | Required fixes, verification and accepted limitations |

## Reports (`reports/`)

General analysis, the security model and published benchmarks. Detailed release-audit material is available in the Audits section above.

| Document | What it covers |
|---|---|
| [AUDIT.md](reports/AUDIT.md) | Current security model and audit status |
| [DPI-AUDIT.md](reports/DPI-AUDIT.md) | DPI detectability analysis and mitigations |
| [BENCHMARK.md](reports/BENCHMARK.md) | Load-testing method and per-mode measurements |
| [C → A → B chain, 30 October 2026](reports/CHAINED-SERVERS-2026-10-30.md) | Independent C/T, faults, real A/B reboots and qualification limits |
| [INI-hook chain, 30 October 2026](reports/CHAINED-SERVERS-HOOKS-2026-10-30.md) | 17 scenarios: repeat application without duplicates, restarts, transport loss and A/B reboots |
| [0.8.4 chain: reconnect and panel autostart](reports/CHAINED-SERVERS-084-2026-10-30.md) | Repeated post_up, one client process, 9 scenarios and A/B reboots without a separate client service |
| [Qeli 0.8.0: 34 VPN modes](reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md) | Full dated cross-protocol run, CPU/RSS, and interpretation limits |
| [COMPARISON.md](reports/COMPARISON.md) | Comparison with WireGuard, OpenVPN and V2Ray |

## Technologies and measurements

Mechanism design, interactions and dated engineering verification.

| Section | Contents |
| --- | --- |
| [Technologies and measurements](reference/TECHNOLOGIES.md) | Mechanism catalog and placement rules |
| [Recordizer](reference/RECORDIZER.md) | PACKET_MUX_V1, data path, negotiation and limits |
| [Recordizer: latency and low latency strategy, 26–29 October](reports/benchmarks/recordizer_latency_2026-10-29.md) | Off/required and timed/opportunistic A/B, RTT/jitter/throughput charts, around 8–9% FakeTLS upload trade-off |
| [Recordizer: timing and distinguishability, 29 October](reports/benchmarks/recordizer_masking_pilot_2026-10-29.md) | Timed/opportunistic and H2-control pilot, correlation/ROC charts; not industrial DPI qualification |
| [Required versus off on 12 profiles on 20 October 2026](reports/benchmarks/recordizer_required_off_2026-10-20.md) | Engineering n=1 comparison of one 0.8.2 build, not a public release benchmark |

## Archive (`archive/`)

Frozen historical documents are preserved for traceability and are not maintained as current
guidance. Start with the **[archive map](archive/README.md)**.

### Completed plans and design logs

| Document | Frozen context |
|---|---|
| [REFACTOR-PLAN.md](archive/plans/REFACTOR-PLAN.md) | Completed production-duplicate removal plan and log |
| [DESIGN-remaining.md](archive/plans/DESIGN-remaining.md) | June 2026 REALITY development snapshot |
| [RELEASE-FIXES.md](archive/plans/RELEASE-FIXES.md) | Historical stabilization plan for early pre-1.0 releases |

### Historical audits

| Document | Date |
|---|---|
| [AUDIT-2026-06-10.md](archive/audits/AUDIT-2026-06-10.md) | 2026-06-10 — security and reliability audit |
| [AUDIT-2026-06-11.md](archive/audits/AUDIT-2026-06-11.md) | 2026-06-11 — external audit review and fixes |
| [AUDIT-2026-06-11-external2.md](archive/audits/AUDIT-2026-06-11-external2.md) | 2026-06-11 — second external audit review |
| [AUDIT-2026-06-12.md](archive/audits/AUDIT-2026-06-12.md) | 2026-06-12 — audit and fixes for 0.7.1 |

## Client documentation (next to client code)

| Client | Document |
|---|---|
| Windows | [qeli-win/README.md](../../qeli-win/README.md) |
| macOS | [qeli-mac/README.md](../../qeli-mac/README.md) |
| iOS ⚠️ | [qeli-ios/README.md](../../qeli-ios/README.md) · MDM: [qeli-ios/MDM/README.md](../../qeli-ios/MDM/README.md) — feature-complete but **never run on a device**, and nothing ships from it |
| Routers (OpenWrt) | [qeli-openwrt/README.md](../../qeli-openwrt/README.md) · Keenetic: [KEENETIC-DEPLOY.md](manuals/KEENETIC-DEPLOY.md) |
| Android | [qeli-android/README.md](../../qeli-android/README.md) (in Russian) |
| Linux CLI | [GETTING-STARTED §8.2](manuals/GETTING-STARTED.md) |

## Outside this directory

- **[../../CHANGELOG.md](../../CHANGELOG.md)** — all changes by version.
- **[../../release/RELEASE_NOTES_0.8.1.md](../../release/RELEASE_NOTES_0.8.1.md)** — bilingual
  0.8 architecture consolidation, user-visible outcomes, upgrade order, artifacts and release
  validation.
- **[../../release/RELEASE_NOTES_0.8.0.md](../../release/RELEASE_NOTES_0.8.0.md)** — development
  Reality/H2 migration, defaults, upgrade order and verification.
- **[../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md](../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md)** — dated H2 PCAP/DPI result and limitations.
- **[../../release/RELEASE_NOTES_0.7.16.md](../../release/RELEASE_NOTES_0.7.16.md)** — bilingual
  `0.7.16` release notes and upgrade impact.
- **[../../SECURITY.md](../../SECURITY.md)** — security policy and reporting.
- **[../../CONTRIBUTING.md](../../CONTRIBUTING.md)** — how to contribute.
- **[../../release/docker/README.md](../../release/docker/README.md)** — running the server in Docker.

- [Linux client TUN queue size](reports/TUN-QUEUE-SIZE-2026-10-16.md) — 16 October 2026.
- [Linux 0.8.2: TCP/UDP on an identified binary](reports/LINUX-LAB-0.8.2-2026-10-17.md) — lab setup, settings and measurement limits, 17 October.
- [Remaining TUN-drop diagnosis](reports/TUN-READER-0.8.2-2026-10-18.md) — 18 October; the cause is not claimed to be established.
- [N04: TUN-drop cause and Linux UDP reader fix](reports/TUN-N04-0.8.2-2026-10-19.md) — 19 October; A/B, queues 1000/2000 and remaining limits.
