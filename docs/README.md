# Документация qeli · qeli documentation

Документация ведётся на двух языках. Начните с карты своей локали — там все документы
сгруппированы по аудитории.

The documentation is maintained in two languages. Start from your locale's map, where every
document is grouped by audience.

| | |
|---|---|
| 🇷🇺 **Русский** | **[ru/index.md](ru/index.md)** — карта · [Установка с нуля](ru/GETTING-STARTED.md) · [Конфигурация](ru/CONFIG.md) · [Диагностика](ru/TROUBLESHOOTING.md) |
| 🇬🇧 **English** | **[eng/index.md](eng/index.md)** — map · [Getting started](eng/GETTING-STARTED.md) · [Configuration](eng/CONFIG.md) · [Troubleshooting](eng/TROUBLESHOOTING.md) |

Обзор проекта, быстрый старт одной командой и состав репозитория — в корневом
[README.md](../README.md).
The project overview, the one-command quick start and the repository layout live in the
root [README.md](../README.md).

## Что лежит здесь · What lives here

- `ru/`, `eng/` — параллельные деревья документации. Наборы файлов в них **совпадают**:
  новый документ добавляется сразу в оба и в `index.md` (это проверяет
  `scripts/check_docs.py`).
  Parallel documentation trees. Their file sets are **identical**: a new document goes into
  both trees and into `index.md` — enforced by `scripts/check_docs.py`.
- `ru/archive/`, `eng/archive/` — зафиксированные отчёты прошлых проверок. Актуальное
  состояние безопасности — в `AUDIT.md`, а не в архиве.
  Frozen reports from past reviews. The current security state is in `AUDIT.md`, not here.
- [AUDIT-FIXES-2026-07-05.md](AUDIT-FIXES-2026-07-05.md) — трекер устранения находок аудита
  2026-07-05 (**закрыт**, только на русском; хранится как история).
  Tracking document for the 2026-07-05 audit findings (**closed**, Russian only; kept as a
  historical record).
