# Q25: ограниченные команды Linux-монитора сети

Дата: 23 сентября 2026. База: `722dae31`.
Разделы 22, 23 и 25 остаются **IN_PROGRESS**. Q25-F020 исправлена.

## Проблема и исправление

**Q25-F020, P2 — read-only команды монитора пути могли удерживать остановку поколения.**
`client/roaming_linux.rs::ip_json` напрямую вызывал `std::process::Command::output`:
без срока и лимита вывода читались IPv4/IPv6 default routes и адреса интерфейса.
Наблюдение уже выполнялось через принадлежащую поколению `tasks.blocking`. Отмена
async-получателя сохраняет join handle этой работы, поэтому зависший child удерживал
`TaskGroup::finish`. Наличие владельца задачи само по себе не ограничивало команду.

Адаптер теперь использует существующий `crate::system_command::Command`:
15 секунд на команду, по 16 МиБ stdout/stderr, совместное чтение труб, запрос остановки
и ожидание child при timeout/overflow. Новый runner или отдельный spawn_blocking не добавлен.
Не менялись владелец задачи, порядок наблюдений, выбор семейства/маршрута, фильтры адресов,
generation/update IDs, ABI и INI.

Ошибки команды или разбора возвращаются из наблюдения. Monitor loop журналирует их
на debug и пропускает этот sample до изменения baseline/pending/update ID или отправки
PathUpdate. Ошибка не превращается в пустой успешный snapshot. Если маршрутов нет,
остался только TUN или нет подходящих адресов, прежний результат `Ok(None)` сохраняется.
При исчезновении записи интерфейса или malformed ответе сохраняется ошибка.

Новая переносимая регрессия объединяет настоящий общий runner с настоящим TaskGroup:
child подтверждает запуск loopback-сокетом и зависает; остановка отменяет async collector,
но ждёт timeout и возврат blocking-команды. Проверяются закрытый socket и отсутствие
поздней доставки результата. Это проверка контракта владельца, не исполнение полного
Linux monitor/controller и не доказательство всех сценариев handover.

## Проверки

**1027 host unit + 52 editor/policy + 7 examples + 12 server INI = 1098 Rust tests PASS.**
Добавлена одна host-регрессия с реальным child. Linux all-targets Clippy, client-only,
server-only, client без roaming, minimal FFI, compatibility без features и rustfmt PASS.
Существующие предупреждения отдельных features и исключение `chunks_exact_to_as_chunks`
сохранены. Linux-only тесты самого monitor/controller проверены компилятором; live
observation test с настоящим `ip` не запускался.

Отдельная обвязка извлекает production `observe_physical_path` вместе с парсерами и
адаптером. Конечные дочерние процессы подменяют `ip` только в PATH тестового child;
проверяется точный argv всех трёх запросов. На baseline **9 ожидаемых отказов регрессии**
(deadline и stdout/stderr overflow для каждого запроса), **14 успешных контролей**.
На исправлении **23/23 PASS**: дополнительно nonzero/malformed для каждой стадии,
dual-stack, приоритет IPv6 на другом интерфейсе, только IPv4/IPv6, отсутствие маршрутов,
только TUN, отсутствие готовых адресов и исчезнувший интерфейс.
Overflow stdout содержит валидный документ с чрезмерным пробельным хвостом: baseline
действительно принимал его, поэтому ошибка парсера не маскирует отсутствие лимита.
Production timeout проверен настоящим ожиданием (~15 секунд); loopback witness закрыт
к возврату вызова. Эти 23 сценария не прибавляются к 1098.
Материалы: C:/Users/litvi/OneDrive/Documents/qeli/path-monitor-audit-20260923.

## Границы

Это сроки отдельных команд наблюдения, не всего sample, handover или shutdown.
Spawn/kill/reap и непрерываемые kernel waits могут продлить вызов; потомки, покинувшие
Linux process group, не покрыты групповой остановкой. Linux signals здесь не исполнялись.

Gateway WAN discovery позднее перенесён в [Q25-F021/F022](AUDIT-Q25-GATEWAY-WAN.md).
Изменяющие маршруты команды внутри submit_path_update и firewall-команды kill-switch/gateway
ещё требуют отдельного переноса и проверки ownership при неизвестном результате.
Принудительный Drop всей группы не заменяет async join. Реальный Linux TUN/firewall,
сеть и смена интерфейса, suspend/resume, systemd, устройства, native release и benchmark
в этом проходе не запускались. Общий аудит открыт.

Предыдущие этапы: [владение TCP/monitor](AUDIT-Q25-TCP-TASKS.md),
[общий runner](AUDIT-Q25-SYSTEM-COMMANDS.md), [preflight](AUDIT-Q05-PREFLIGHT.md).
