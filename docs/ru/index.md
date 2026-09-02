# Документация qeli — карта

Документация организована **по типам документов**. Русское и английское деревья имеют
одинаковую структуру, а каждый актуальный документ доступен из этой карты.

> Новичку: начните с **[Установки с нуля](manuals/GETTING-STARTED.md)**, затем откройте
> **[Конфигурацию](manuals/CONFIG.md)**. Если что-то не работает —
> **[Диагностика](manuals/TROUBLESHOOTING.md)**.

**English version → [../eng/index.md](../eng/index.md)**

## Обзор

| Документ | О чём |
|---|---|
| [README.md](README.md) | Обзор проекта: назначение, wire-режимы, криптостек и состав репозитория |

## Руководства (`manuals/`)

Практические инструкции по установке, настройке и эксплуатации.

| Документ | О чём |
|---|---|
| [GETTING-STARTED.md](manuals/GETTING-STARTED.md) | Установка и первый запуск, пошагово с нуля |
| [CONFIG.md](manuals/CONFIG.md) | Полный справочник flat-INI конфигурации сервера и клиентов |
| [OPERATIONS.md](manuals/OPERATIONS.md) | Совместимость, обновление, откат, резервное копирование и firewall |
| [PANEL.md](manuals/PANEL.md) | Установка и использование веб-панели |
| [IPV6.md](manuals/IPV6.md) | IPv4/IPv6/dual-stack, NAT66, маршрутизация и диагностика |
| [OBFUSCATION.md](manuals/OBFUSCATION.md) | Recordizer, совместимость слоёв маскировки и профили тюнинга |
| [TROUBLESHOOTING.md](manuals/TROUBLESHOOTING.md) | Диагностика подключения и справочник ошибок |
| [KEENETIC-DEPLOY.md](manuals/KEENETIC-DEPLOY.md) | Пошаговый деплой клиента на Keenetic |

## Справочники и архитектура (`reference/`)

Технические контракты и описание текущей реализации.

| Документ | О чём |
|---|---|
| [CLIENT-CONFIG-MATRIX.md](reference/CLIENT-CONFIG-MATRIX.md) | Актуальный контракт клиентских ключей по платформам и история миграции |
| [THREAT-MODEL.md](reference/THREAT-MODEL.md) | Модель угроз, границы доверия и уровень проверенности |
| [TRANSPORT-CORE.md](reference/TRANSPORT-CORE.md) | Общее транспортное Rust-ядро, source/ABI-контракт и release gates |
| [KEENETIC-PORT.md](reference/KEENETIC-PORT.md) | Архитектура порта Keenetic и обоснование dual-arch сборки |

## Планы (`plans/`)

Актуальные направления разработки и планы реализации. Это не пользовательские инструкции.

| Документ | О чём |
|---|---|
| [ROADMAP.md](plans/ROADMAP.md) | Продуктовый и технический план развития |
| [ROAMING.md](plans/ROAMING.md) | Нормативный план реализации клиентского роуминга |
| [IPV6-IMPLEMENTATION-PLAN.md](plans/IPV6-IMPLEMENTATION-PLAN.md) | Архитектура IPv6, этапы и release gates |

## Отчёты (`reports/`)

Актуальные анализы и результаты измерений. Датированные зафиксированные отчёты находятся в архиве.

| Документ | О чём |
|---|---|
| [AUDIT.md](reports/AUDIT.md) | Актуальная модель безопасности и статус аудита |
| [DPI-AUDIT.md](reports/DPI-AUDIT.md) | Анализ обнаружимости DPI и меры устранения |
| [BENCHMARK.md](reports/BENCHMARK.md) | Методика нагрузочного тестирования и замеры по режимам |
| [Qeli 0.8.0: 34 VPN-режима](reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md) | Полный датированный сравнительный прогон, CPU/RSS и ограничения интерпретации |
| [COMPARISON.md](reports/COMPARISON.md) | Сравнение с WireGuard, OpenVPN и V2Ray |

## Архив (`archive/`)

Зафиксированные исторические документы сохранены для прослеживаемости и не обновляются как
актуальные инструкции. Начните с **[карты архива](archive/README.md)**.

### Завершённые планы и design logs

| Документ | Зафиксированный контекст |
|---|---|
| [REFACTOR-PLAN.md](archive/plans/REFACTOR-PLAN.md) | Завершённый план и журнал устранения production-дублей |
| [DESIGN-remaining.md](archive/plans/DESIGN-remaining.md) | Снимок разработки REALITY от июня 2026 |
| [RELEASE-FIXES.md](archive/plans/RELEASE-FIXES.md) | Исторический план стабилизации ранних pre-1.0 релизов |

### Исторические аудиты

| Документ | Дата |
|---|---|
| [AUDIT-2026-06-10.md](archive/audits/AUDIT-2026-06-10.md) | 2026-06-10 — аудит безопасности и надёжности |
| [AUDIT-2026-06-11.md](archive/audits/AUDIT-2026-06-11.md) | 2026-06-11 — разбор внешнего аудита и исправления |
| [AUDIT-2026-06-11-external2.md](archive/audits/AUDIT-2026-06-11-external2.md) | 2026-06-11 — разбор второго внешнего аудита |
| [AUDIT-2026-06-12.md](archive/audits/AUDIT-2026-06-12.md) | 2026-06-12 — аудит и исправления для 0.7.1 |

## Документация клиентов (рядом с кодом)

| Клиент | Документ |
|---|---|
| Windows | [qeli-win/README.md](../../qeli-win/README.md) |
| macOS | [qeli-mac/README.md](../../qeli-mac/README.md) |
| iOS ⚠️ | [qeli-ios/README.md](../../qeli-ios/README.md) · MDM: [qeli-ios/MDM/README.md](../../qeli-ios/MDM/README.md) — реализован полностью, но **на устройстве не проверялся** и не выпускается |
| Роутеры (OpenWrt) | [qeli-openwrt/README.md](../../qeli-openwrt/README.md) · Keenetic: [KEENETIC-DEPLOY.md](manuals/KEENETIC-DEPLOY.md) |
| Android | [qeli-android/README.md](../../qeli-android/README.md) |
| Linux CLI | [GETTING-STARTED §8.2](manuals/GETTING-STARTED.md) |

## Вне этого каталога

- **[../../CHANGELOG.md](../../CHANGELOG.md)** — все изменения по версиям.
- **[../../release/RELEASE_NOTES_0.8.0.md](../../release/RELEASE_NOTES_0.8.0.md)** — dev-миграция
  Reality/H2, значения по умолчанию, порядок обновления и проверка.
- **[../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md](../../release/dpi_audit_dev_0.8.0_h2_2026-08-26/REPORT.md)** — датированный H2 PCAP/DPI-результат и ограничения.
- **[../../release/RELEASE_NOTES_0.7.16.md](../../release/RELEASE_NOTES_0.7.16.md)** — двуязычный
  выпускной документ `0.7.16` и влияние обновления.
- **[../../SECURITY.md](../../SECURITY.md)** — политика безопасности и приём отчётов.
- **[../../CONTRIBUTING.md](../../CONTRIBUTING.md)** — как участвовать в разработке.
- **[../../release/docker/README.md](../../release/docker/README.md)** — запуск сервера в Docker.
