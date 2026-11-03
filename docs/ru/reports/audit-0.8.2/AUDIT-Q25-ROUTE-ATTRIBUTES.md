# Q25: владение Linux-маршрутами после изменений администратором

Дата: 24 сентября 2026. Baseline: `ff4b4187`.
Q25-F099 исправлен в описанных пределах. D04 остаётся **IN_PROGRESS**.

## Находка

**Q25-F099, P2 — совпадение пути ошибочно сохраняло право удалить или заменить маршрут.**
Проверка сравнивала только переданные в исходный `ip route add` параметры. Если
`proto`, `metric` или `src` не задавались, новый атрибут в таблице не менял ownership.
Смена scope, MTU или формы next hop тоже могла пройти проверку. Администратор мог
заменить маршрут, сохранив destination/gateway/device, после чего cleanup удалял его,
а roaming — заменял либо удалял при retirement. Blackhole затрагивались аналогично.

Контрпроверка прежнего matcher на настоящем ядре удалила **10 операторских замен**:
IPv4/IPv6 с изменёнными protocol/priority/source/MTU и два blackhole с `proto static`.
Два неизменённых собственных маршрута также удалялись, как и должны. Отдельный запуск
исходного бинарника с настоящими server/client, handshake и трафиком подтвердил
удаление статического carrier bypass при штатном SIGTERM: **15 PASS, 1 FAIL**.

## Исправление

Проверка пригодности заранее существующего маршрута отделена от проверки владения.
Подходящий операторский маршрут по-прежнему можно использовать без записи в журнал.
Для нового ownership, cleanup, rollback и roaming сравниваются также неявные значения:
`proto boot`, metric 0 для IPv4 / 1024 для IPv6, отсутствие незапрошенного source,
IPv4 scope и IPv6 preference. Учтены обычные формы вывода ядра: скрытый IPv4 metric 0,
`proto boot`/`3`, IPv6 blackhole с `dev lo`, отсутствие сохранённого IPv6 `scope link`.
Динамический `linkdown` сам по себе не передаёт маршрут другому владельцу.

Дополнительные неизвестные атрибуты, MTU, multipath, `nhid`, `onlink`, дублированные
или неполные поля не дают delete/replace authority. Замена физического маршрута
сохраняется, устаревшая запись ownership освобождается. Неопределённые исходы мутаций
по-прежнему не присваиваются; отрицательный результат команды не доказывает отсутствие.
Формат INI, ABI и протокол обмена не менялись.

## Проверки

- **1519 host + 71 config; все 9 feature/cross/lint checks PASS**.
- **2068 Linux + 40 privileged + 8 worker lifecycle PASS**.
- 11 новых portable tests: defaults, protocol, priority, source, scope/preference,
  дополнительные/повреждённые поля, blackhole, borrowing, cleanup и roaming retirement/replace.
- Один новый privileged test исполняет production install/cleanup на реальном ядре:
  10 изменённых маршрутов должны сохраниться, 2 неизменённых — удалиться.
- Counterfactual меняет только ownership matcher на прежнюю проверку пригодности:
  **10 portable FAIL + 1 default control PASS; 1 native FAIL**. Wrapper exit 0 проверяет
  ожидаемые test exit 101; исходники восстановлены и проверены до/после.
- Packet matrix: **17/17 cases, 384 assertions PASS**. Включены прежние
  DNS SIGKILL/restart и kill-switch guards; `QELI_ROUTE_IDENTITY_CHECK=1` дополнительно
  заменяет carrier bypass на `proto static` перед stop в full-tunnel ячейках без DNS.
  Сравниваются реальные таблицы до/после остановки. DNS crash ячейки исключены из этой
  новой проверки: после SIGKILL исходного process ownership уже нет.
- Модель ядра в portable fixture исправлена: IPv6 add не сохраняет `scope link`.
  Первоначальный локальный пробный прогон выявил эту неточность fixture; production
  поведение подтверждено native snapshots и окончательными наборами тестов.

Source snapshot: 336 files, archive SHA256 `98ecffa7867ca651b4ac2339be1e60dc84b72f422f8d4d3db8c05fd64a652322`.
Worker SHA256: `584a4bd5283ba46f791ace79784c38cc8db7f6c054062eed19461b0289ebda91`.
Baseline worker SHA256: `d15a3fc82c33b7a8da709817e3a85ee43bf5231f88369891ec7bd13b7c9f7c87`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/route-identity-phase/`,
`route-identity-baseline-v1.log`, `route-identity-baseline-runtime-v1.log`,
`packet-matrix-route-identity-baseline-v1/`, `route-identity-final-v1.log`,
`lifecycle-route-identity/`, `packet-matrix-route-identity-v1/`.
Linux Rust 1.97; host Rust 1.98; прежнее исключение Clippy `chunks_exact_to_as_chunks`.

## Границы

Проверка снимка и следующая команда не атомарны. Замена между ними и идентичное
воссоздание маршрута другим root не различаются; произвольные VRF/multipath/nexthop
конфигурации не сертифицированы. При неизвестной форме записи она сохраняется.
На собственном managed TUN сохраняется отдельное право очищать маршруты интерфейса:
это исправление защищает физические bypass/exclude и blackhole, а не обещает сохранить
добавленные администратором маршруты на удаляемом Qeli TUN.

Постоянный журнал клиентских маршрутов **ещё не добавлен**: SIGKILL теряет process
ownership, физические обходы/blackhole могут остаться. Для восстановления нужно отдельно
решить durable intent/confirmed ownership, namespace generation, неопределённый исход
и пересекающиеся клиенты. Этот этап устраняет опасный matcher до такого recovery.
Открыты также legacy global DNS, live persistent TUN и mixed firewall matrix.
Сетевые проверки выполнялись в приватных namespaces `.11`; `.10` не изменялся.
Windows VM/Mac/iOS/router runtime остаются SKIPPED по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Эксплуатация](../../manuals/OPERATIONS.md)

Продолжение: [Q25-F100](AUDIT-Q25-ROUTE-JOURNAL.md) добавляет постоянный intent/confirmed journal и recovery физических маршрутов после SIGKILL. Ограничение отсутствия журнала выше относится к baseline этого отчёта; остальные границы ownership сохраняются.
