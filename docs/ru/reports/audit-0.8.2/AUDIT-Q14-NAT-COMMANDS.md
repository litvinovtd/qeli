# Q14: сроки и лимиты вывода серверных NAT-команд

Дата: 23 сентября 2026. Исходный коммит: `253b6455`.
Разделы 14, 17, 18, 19 и 25: **IN_PROGRESS**. Q14-F032 исправлена; общий аудит открыт.

## Подтверждённая проблема

**Q14-F032, P2 — серверный NAT запускал команды без срока и лимита вывода.**
Все пять точек запуска в `qeli/src/server/nat.rs` использовали прямой
`std::process::Command::output`: общий iptables/ip6tables адаптер, две проверки версии
через PATH и два запроса маршрута для выбора WAN. `--wait 5` ограничивал только xtables
lock, но не зависание backend, ожидание EOF pipes или размер stdout/stderr.

Зависшая команда могла удерживать общий firewall mutex, задерживать другие профили,
Drop/rollback и финальный проход DNS ownership. Большой вывод целиком накапливался в памяти.

## Исправление и охват

Все пять запусков используют существующий `crate::system_command::Command`, общий с
TUN и per-link DNS. Отдельного runner не добавлено. На каждую команду отводится 15 секунд,
stdout и stderr ограничены каждый 16 МиБ. Deadline начинается до создания helper thread.
Обе трубы читаются одновременно; частичный вывод при превышении лимита не возвращается.

Timeout возвращает TimedOut, overflow — InvalidData. Runner запрашивает завершение
процесса и ожидает его; на Linux используется существующее владение process group.
Ненулевой exit остаётся Output с исходными status/stderr. Аргументы передаются без shell;
`--wait 5`, выбор утилит и IPv4/IPv6 WAN сохраняются.

Timeout мутации не доказывает, что правило не изменилось. Установка сохраняет прежние
последующие проверки, а exact DNS cleanup при ошибке удерживает rule specs для retry.
Новая регрессия моделирует timeout удаления как до изменения, так и после него: TCP
очищается несмотря на отказ UDP; финальный проход проверяет оба точных правила, повторяет
только ещё нужное удаление и затем освобождает ownership.

Generic NAT cleanup остаётся best effort: отсутствие возможности `iptables-nft -S` на
mixed native nft не превращено в безусловный отказ запуска. `off`/`manual`, INI-ключи,
правила firewall, sysctl journal, ABI и wire format не менялись.

## Проверка

**1002 host unit + 52 editor/policy + 7 examples + 12 server INI = 1073 Rust tests PASS.**
Добавлена одна доменная регрессия с двумя вариантами неизвестного результата мутации.
Существующие тесты общего runner, ownership и cleanup также повторены.
Linux all-targets Clippy, client-only, server-only, client без roaming, minimal FFI,
compatibility без features и rustfmt PASS. Прежние feature-specific warnings и исключение
Clippy `chunks_exact_to_as_chunks` сохранены.

Отдельно проверены извлечённые production-адаптеры с настоящими конечными дочерними
процессами. На baseline три сценария выявляют отсутствие ограничений: поздний успех,
слишком большой stdout и stderr. Три контроля проверяют exit 17/stderr, точный argv
с буквальными shell-символами и все четыре discovery/probe вызова.
С исправлением **6/6 сценариев PASS**; production deadline сработал примерно за 15 секунд,
loopback witness подтвердил закрытие сокета дочернего процесса к возврату вызова.
Фикстуры подменяют PATH только дочернего тестового процесса; реальные `ip`/iptables
не запускаются. Эти шесть сценариев не прибавляются к 1073.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/nat-command-audit-20260923.

## Открытые границы

15 секунд — срок отдельной команды, а не всего cleanup или удержания firewall mutex.
Последовательность проверок/удалений может занять дольше; ожидание spawn, kill/reap или
непрерываемого kernel wait не получает жёсткой общей верхней границы. Потомок, покинувший
process group, не покрывается гарантией её завершения. Два существующих Linux group-теста
проверены компилятором; доставка Linux-сигналов здесь не исполнялась.

Preflight позднее перенесён в [Q05-F001](AUDIT-Q05-PREFLIGHT.md).
Read-only path monitor позднее перенесён в [Q25-F020](AUDIT-Q25-PATH-MONITOR.md).
Клиентские routes/kill-switch/gateway этим проходом не перенесены.
Q14-F027, ресурсы старых поколений, общий срок всей сетевой операции и постоянный DNS
journal остаются открытыми. Проверки/удаления не атомарны относительно внешнего firewall.
Реальные Linux firewall/TUN/sysctl/systemd, устройства, native release и бенчмарки не запускались.

Предыдущие этапы: [общий TUN/DNS runner](AUDIT-Q25-SYSTEM-COMMANDS.md) и
[частичный IPv6 acquire](AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md).

Следующая фаза: [Q14-F034 — общий срок очистки](AUDIT-Q14-NAT-CLEANUP-BUDGET.md)
покрывает admission и команды profile/startup/final cleanup; прежние результаты выше
относятся к своему снимку. NAT setup/rollback, DNS lease Drop/setup admission и
persistent recovery остаются открытыми.
