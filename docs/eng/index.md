# Qeli documentation — map

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

| Document | What it covers |
|---|---|
| [GETTING-STARTED.md](manuals/GETTING-STARTED.md) | Installation and first run, step by step |
| [CONFIG.md](manuals/CONFIG.md) | Complete flat-INI server and client configuration reference |
| [OPERATIONS.md](manuals/OPERATIONS.md) | Compatibility, upgrades, rollback, backup and firewall operations |
| [PANEL.md](manuals/PANEL.md) | Web panel installation and use |
| [IPV6.md](manuals/IPV6.md) | IPv4/IPv6/dual-stack setup, NAT66, routing and diagnostics |
| [OBFUSCATION.md](manuals/OBFUSCATION.md) | Recordizer setup, masking-layer compatibility and tuning profiles |
| [TROUBLESHOOTING.md](manuals/TROUBLESHOOTING.md) | Connection diagnostics and error reference |
| [KEENETIC-DEPLOY.md](manuals/KEENETIC-DEPLOY.md) | Step-by-step client deployment on Keenetic |

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

## Reports (`reports/`)

Current analyses and measured results. Dated, frozen reports live in the archive.

| Document | What it covers |
|---|---|
| [AUDIT.md](reports/AUDIT.md) | Current security model and audit status |
| [DPI-AUDIT.md](reports/DPI-AUDIT.md) | DPI detectability analysis and mitigations |
| [BENCHMARK.md](reports/BENCHMARK.md) | Load-testing method and per-mode measurements |
| [Qeli 0.8.0: 34 VPN modes](reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md) | Full dated cross-protocol run, CPU/RSS, and interpretation limits |
| [COMPARISON.md](reports/COMPARISON.md) | Comparison with WireGuard, OpenVPN and V2Ray |

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
- **[../../release/RELEASE_NOTES_0.8.0.md](../../release/RELEASE_NOTES_0.8.0.md)** — development
  Reality/H2 migration, defaults, upgrade order and verification.
- **[../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md](../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md)** — dated H2 PCAP/DPI result and limitations.
- **[../../release/RELEASE_NOTES_0.7.16.md](../../release/RELEASE_NOTES_0.7.16.md)** — bilingual
  `0.7.16` release notes and upgrade impact.
- **[../../SECURITY.md](../../SECURITY.md)** — security policy and reporting.
- **[../../CONTRIBUTING.md](../../CONTRIBUTING.md)** — how to contribute.
- **[../../release/docker/README.md](../../release/docker/README.md)** — running the server in Docker.
