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
- `reference/` — технические контракты, модель угроз и архитектура;
  technical contracts, threat model and architecture.
- `plans/` — актуальные roadmap и планы реализации; active roadmaps and implementation plans.
- `reports/` — актуальные аудиты, DPI-анализ, сравнения и замеры;
  current audits, DPI analysis, comparisons and measurements.
- `archive/plans/`, `archive/audits/` — завершённые планы и датированные отчёты, которые
  не переписываются задним числом; frozen completed plans and point-in-time audit reports.

Новый двуязычный документ добавляется в одинаковый путь обеих локалей и в `index.md`.
Паритет деревьев, охват оглавлением и относительные ссылки проверяет
[`scripts/check_docs.py`](../scripts/check_docs.py).

Актуальная безопасность: [RU](ru/reports/AUDIT.md) · [EN](eng/reports/AUDIT.md).
Настройка recordizer: [RU](ru/manuals/OBFUSCATION.md) · [EN](eng/manuals/OBFUSCATION.md).

## Общий исторический архив · Shared historical archive

Документы, существующие только на одном языке, лежат вне зеркальных деревьев:

- [AUDIT-FIXES-2026-07-05.md](archive/audits/AUDIT-FIXES-2026-07-05.md) — закрытый трекер
  находок аудита 2026-07-05.
- [AUDIT-2026-07-27-FIXES.md](archive/audits/AUDIT-2026-07-27-FIXES.md) — зафиксированный
  чек-лист исправлений аудита 2026-07-27.
