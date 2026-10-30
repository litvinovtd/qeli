# Документация qeli · qeli documentation

Документация ведётся на русском и английском языках с одинаковой структурой каталогов.
Начните с карты нужной локали. The documentation is maintained in Russian and English with
the same directory layout; start from your locale's map.

| | |
|---|---|
| 🇷🇺 **Русский** | **[ru/index.md](ru/index.md)** — карта · [Установка](ru/manuals/GETTING-STARTED.md) · [Конфигурация](ru/manuals/CONFIG.md) · [Диагностика](ru/manuals/TROUBLESHOOTING.md) |
| 🇬🇧 **English** | **[eng/index.md](eng/index.md)** — map · [Getting started](eng/manuals/GETTING-STARTED.md) · [Configuration](eng/manuals/CONFIG.md) · [Troubleshooting](eng/manuals/TROUBLESHOOTING.md) |

Обзор проекта, быстрый старт одной командой и состав репозитория находятся в корневом
[README.md](../README.md). The project overview, one-command quick start and repository
layout live in the root [README.md](../README.md).

## Структура · Structure

Каталоги `ru/` и `eng/` зеркальны. The `ru/` and `eng/` trees are mirrors:

- `manuals/` — практические руководства по установке, настройке и эксплуатации;
  practical installation, configuration and operations guides.
- `scenarios/` — сценарии использования: готовые схемы, конфиги, проверка и восстановление;
  use cases: complete deployments, configs, verification and recovery.
- `reference/` — технические контракты, модель угроз и архитектура;
  technical contracts, threat model and architecture.
- `plans/` — актуальные roadmap и планы реализации; active roadmaps and implementation plans.
- `reports/` — актуальные аудиты, DPI-анализ, сравнения и замеры;
  current audits, DPI analysis, comparisons and measurements.
- `archive/plans/`, `archive/audits/` — завершённые планы и датированные отчёты, которые
  не переписываются задним числом; frozen completed plans and point-in-time audit reports.

Новый двуязычный документ добавляется в одинаковый путь обеих локалей и в каталог
раздела, доступный из `index.md`.
Паритет деревьев, охват оглавлением и относительные ссылки проверяет
[`scripts/check_docs.py`](../scripts/check_docs.py).

Актуальная безопасность: [RU](ru/reports/AUDIT.md) · [EN](eng/reports/AUDIT.md).
Настройка recordizer: [RU](ru/manuals/OBFUSCATION.md) · [EN](eng/manuals/OBFUSCATION.md).

## Сценарии использования · Use cases

Каталог практических схем: [RU](ru/scenarios/README.md) · [EN](eng/scenarios/README.md).
Первый сценарий — клиент → A → B → Интернет:
[RU](ru/scenarios/CHAINED-SERVERS.md) · [EN](eng/scenarios/CHAINED-SERVERS.md).
Требования к версии, правам и результаты проверки указаны внутри инструкции.

## Технологии и измерения · Technologies and measurements

Каталог механизмов и инженерных проверок: [RU](ru/reference/TECHNOLOGIES.md) ·
[EN](eng/reference/TECHNOLOGIES.md). Recordizer: [RU](ru/reference/RECORDIZER.md) ·
[EN](eng/reference/RECORDIZER.md).

Сравнение required/off на 12 профилях от 20 октября 2026:
[RU](ru/reports/benchmarks/recordizer_required_off_2026-10-20.md) ·
[EN](eng/reports/benchmarks/recordizer_required_off_2026-10-20.md). Это инженерный n=1 прогон,
не публичный бенчмарк релиза. Engineering n=1 run, not a public release benchmark.

## Бенчмарки · Benchmarks

Датированные полные лабораторные отчёты хранятся зеркально в обеих локалях. Dated full
laboratory reports are maintained in both mirrored locale trees.

- Qeli 0.8.0, 34 VPN modes: [RU](ru/reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md) ·
  [EN](eng/reports/benchmarks/vpn_protocol_benchmark_repeat_2026-09-01.md) — throughput,
  CPU/RSS, IPv4/IPv6, repeatability, and the limits of DPI-related conclusions.

## Общий исторический архив · Shared historical archive

Документы, существующие только на одном языке, лежат вне зеркальных деревьев:

- [AUDIT-FIXES-2026-07-05.md](archive/audits/AUDIT-FIXES-2026-07-05.md) — закрытый трекер
  находок аудита 2026-07-05.
- [AUDIT-2026-07-27-FIXES.md](archive/audits/AUDIT-2026-07-27-FIXES.md) — зафиксированный
  чек-лист исправлений аудита 2026-07-27.
