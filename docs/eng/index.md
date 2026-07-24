# Qeli documentation — map

The single navigation point. Documents are grouped **by audience**: what a user and an
operator need first, then internal and historical material.

> New here? Start with **[Getting started](GETTING-STARTED.md)**, then
> **[Configuration](CONFIG.md)**. If something doesn't work — **[Troubleshooting](TROUBLESHOOTING.md)**.

**Русская версия → [../ru/index.md](../ru/index.md)**

---

## 👤 For users

| Document | What it covers |
|---|---|
| [GETTING-STARTED.md](GETTING-STARTED.md) | Installation and first run, step by step from scratch |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Connection diagnostics and error reference |

## 🛠 For server operators

| Document | What it covers |
|---|---|
| [CONFIG.md](CONFIG.md) | Configuration (flat-INI): every server and client parameter |
| [PANEL.md](PANEL.md) | Web panel: installation and usage |
| [OPERATIONS.md](OPERATIONS.md) | Operations: compatibility, upgrades and rollback, backup, firewall |

## 📡 Routers (Keenetic / OpenWrt)

| Document | What it covers |
|---|---|
| [KEENETIC-DEPLOY.md](KEENETIC-DEPLOY.md) | Step-by-step client deployment on Keenetic |
| [KEENETIC-PORT.md](KEENETIC-PORT.md) | Porting the client to Keenetic (dual-arch: mipsel + aarch64) |

## 🔐 Security

| Document | What it covers |
|---|---|
| [AUDIT.md](AUDIT.md) | Security model and current status |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Threat model |
| [DPI-AUDIT.md](DPI-AUDIT.md) | DPI detectability audit: tells and their mitigation |

## 📖 Design, comparison, measurements

| Document | What it covers |
|---|---|
| [README.md](README.md) | Project overview: what it is, why, wire modes, crypto stack |
| [COMPARISON.md](COMPARISON.md) | Comparison with WireGuard / OpenVPN / V2Ray |
| [BENCHMARK.md](BENCHMARK.md) | Load testing and per-mode measurements |
| [ROAMING.md](ROAMING.md) | Client roaming (seamless network change) |

## 🧭 Development and process

> Internal documents: plans and status, not end-user guides.

| Document | What it covers |
|---|---|
| [ROADMAP.md](ROADMAP.md) | Roadmap |
| [REFACTOR-PLAN.md](REFACTOR-PLAN.md) | Refactoring plan: eliminating code duplication |
| [DESIGN-remaining.md](DESIGN-remaining.md) | REALITY development stages: status and remainder |
| [RELEASE-FIXES.md](RELEASE-FIXES.md) | Plan to finish off toward a stable release |

## 🗄 Archive: historical audits

> Point-in-time reports of past reviews, kept for the record — for the **current** security
> posture read [AUDIT.md](AUDIT.md), not these.

| Document | Date |
|---|---|
| [AUDIT-2026-06-10.md](archive/AUDIT-2026-06-10.md) | 2026-06-10 — security and reliability audit |
| [AUDIT-2026-06-11.md](archive/AUDIT-2026-06-11.md) | 2026-06-11 — external audit review and fixes |
| [AUDIT-2026-06-11-external2.md](archive/AUDIT-2026-06-11-external2.md) | 2026-06-11 — review of the second external audit |
| [AUDIT-2026-06-12.md](archive/AUDIT-2026-06-12.md) | 2026-06-12 — audit and fixes (release 0.7.1) |

---

## Client documentation (lives next to each client's code)

| Client | Document |
|---|---|
| Windows | [qeli-win/README.md](../../qeli-win/README.md) |
| macOS | [qeli-mac/README.md](../../qeli-mac/README.md) |
| iOS | [qeli-ios/README.md](../../qeli-ios/README.md) · MDM: [qeli-ios/MDM/README.md](../../qeli-ios/MDM/README.md) |
| Routers (OpenWrt) | [qeli-openwrt/README.md](../../qeli-openwrt/README.md) · Keenetic: [KEENETIC-DEPLOY.md](KEENETIC-DEPLOY.md) |
| Android | [qeli-android/README.md](../../qeli-android/README.md) (in Russian) |
| Linux CLI | [GETTING-STARTED §8.2](GETTING-STARTED.md) |

## Outside this directory

- **[../../CHANGELOG.md](../../CHANGELOG.md)** — all changes by version.
- **[../../SECURITY.md](../../SECURITY.md)** — security policy and reporting.
- **[../../CONTRIBUTING.md](../../CONTRIBUTING.md)** — how to contribute.
- **[../../release/docker/README.md](../../release/docker/README.md)** — running the server in Docker.
