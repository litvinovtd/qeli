# Q05 — асинхронная проверка firewall tools в панели

<!-- normative-sync: audit-q05-health-probes-v1 -->

Дата: 24 сентября 2026. База: `1bfb9920dd812f29484c0d977b8b7660012f5bfe`.
Частичное закрытие D05/D09 [реестра техдолга](../../plans/AUDIT-DEBT.md).

## Q05-F008, P2 — диагностика блокировала async executor

`/api/status` и `/api/transport/health` вызывали синхронный `nat::available()` внутри
async-handler. Когда iptables отсутствовал в стандартных каталогах, fallback запускал
`iptables --version` через синхронный runner. Зависший процесс/pipe занимал поток Tokio
до 15 секунд плюс завершение процесса; на одном потоке задерживались соседние запросы.
Transport health выполнял проверку даже без профилей, запрашивающих NAT.

Это оставшийся read-only путь панели: перенос config preflight в async ранее не покрывал
status/health. API не держали config-write-lock в этом месте, но блокировали executor.

## Исправление

Оба handler используют общий NAT diagnostic и асинхронное discovery. IPv6 discovery
Quick Start подключён к тому же механизму. Стандартные пути утилит определяются в одном
модуле и используются также прежними синхронными server CLI probes. При отсутствии
кандидата fallback `--version` запускается через общий async process collector.

- Четыре общих слота ограничивают одновременно допущенные async fallback-пробы
  iptables/ip6tables. Очередь входит в срок запроса; новый срок после ожидания не выдаётся.
- Status/health получают 15 секунд на discovery; Quick Start передаёт остаток своего
  preflight deadline. Просроченный вызов не принимает даже готовый результат fast path.
- Stdout и stderr ограничены каждый 64 КиБ; частичный переполненный вывод не принимается.
- Timeout запрашивает остановку группы и ждёт child; отмена запроса сигналит принадлежащую
  ему группу, а завершающий reap при отмене остаётся у Tokio. Detached blocking task нет.
- Без профилей с NAT эти два handler не запускают probe. Подтверждённое отсутствие
  iptables остаётся critical; timeout, permissions, overflow и nonzero exit означают
  `Could not verify iptables availability` уровня warning. API-структура и авторизация
  не меняются; конфиги остаются INI, новых параметров/ABI нет.

## Проверки

Восемь новых обычных Linux-тестов проверяют exit/argv, NotFound, overflow, истёкший
и занятый budget без запуска процесса, общий срок очереди/команды, ограничение четырьмя
слотами для восьми запросов, отмену реального ребёнка с освобождением слота и reap,
изоляцию task-local test probes, различение missing/unknown и пропуск ненужной проверки.
Task-local override подменяет только поиск fixture-программы; PATH и соседние запросы
не изменяются. Production collector и дочерние процессы остаются настоящими.

Новый privileged тест создаёт private mount/network namespaces и скрывает реальный
control socket частным `/run`. Через настоящий Axum router, routing и AuthGuard тестовой
конфигурации выполняются HTTP-запросы in-process. На current-thread Tokio status и
transport health по очереди ждут fixture-процесс 1,5 секунды, а `/system` отвечает
за выделенные 300 мс до завершения этой пробы. Сеть/сервисы хоста не изменяются.
Это не wire-level HTTP/TLS и не системный supervisor E2E.

Контрольная подмена вернула только синхронный `.output()` с отдельными 15 секундами,
сохранив новые semaphore/handlers/tests. Две регрессии ожидаемо упали с exit 101:
поздний успех после бюджета очереди и блокировка `/status` до завершения ребёнка.
Исходный файл затем восстановлен побайтно. Это сравнение старого поведения в той же
границе, а не полный запуск прежнего коммита.

Окончательный снимок: **1468 host unit + 71 config integration PASS**; девять
feature/cross/lint-команд PASS. Linux: **1943 обычных + 30 привилегированных PASS**,
**8 worker lifecycle E2E PASS** (TCP/UDP × off/manual/route/nat66). Два child helper
не запускаются отдельно, их вызывают родительские тесты. Новая функциональность
проверяется process/HTTP-router тестами; server lifecycle — общая регрессия.
Linux Rust 1.97, host Rust 1.98; прежнее исключение Clippy `chunks_exact_to_as_chunks`.

Worker SHA256: `e94a95ce5be1b7cdf057b1705e3248c0f2ce4477c248de59d980ddee0b148eef`.
Source archive SHA256: `638e023059e86deb32595eaf38e308fb063427bde150dba3975969c19b056be3` (310 файлов `qeli`/`conformance`, до коммита).
Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/panel-probes-phase/`,
`panel-probes-clean.log`, `lifecycle-panel-probes-clean/`,
`panel-probes-counterfactual/`. Первый прогон `panel-probes-final` предшествовал
уточнению PID-handshake теста отмены; финальные результаты относятся к `clean`.
Промежуточный `panel-probes-verified` использовал контрольный test binary из Cargo cache:
распаковка tar восстановила старые mtime исходников. Его четыре FAIL не относятся
к исправленной сборке и не засчитаны. Финальный `clean` проверяет SHA всех 310 файлов
до/после и очищает только пакет qeli в приватном target перед компиляцией. Все работы
на `.11`; рабочий сервер `.10` не изменялся.

## Оставшиеся границы

Это deadline discovery, а не всех обработчиков/HTTP-запроса. Проверка стандартных
файловых путей остаётся синхронной. File I/O, spawn и kill/reap не получают жёсткой
верхней границы от таймера. Найденный путь не доказывает работоспособность firewall,
а разрешённое число probes не сертифицирует нагрузочную устойчивость панели.
Бюджеты NAT/routes/kill-switch, прочие lock waits, полный HTTP fault/systemd и D13
остаются открытыми. D05 и D09 целиком не закрыты. В §6.36 troubleshooting также
исправлено устаревшее описание preflight: общий срок и async уже реализованы ранее.

[Предыдущая фаза панели](AUDIT-Q05-PANEL-TRANSACTIONS.md) ·
[Мануал панели](../../manuals/PANEL.md) · [Диагностика](../../manuals/TROUBLESHOOTING.md)
