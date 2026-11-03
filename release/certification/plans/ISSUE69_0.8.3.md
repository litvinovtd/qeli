# Issue #69: план и границы реализации 0.8.3 / implementation scope

Основание: [комментарий Singijeon](https://github.com/litvinovtd/qeli/issues/69#issuecomment-6301263287),
проверенный по dev `f9c07781` 22 октября 2026. Цель — согласовать применимость
параметров и наблюдаемость сетевого поведения, сохранив userspace, INI и защитные
проверки dev. Публикация релиза этим планом не разрешается.

| Этап / Stage | Реализация / Implementation | Приёмка / Acceptance |
|---|---|---|
| SNI / HTTP Host | Применимость mode/proto/front, оба генератора ссылок, desktop Host field | Матрица TLS/obfs/plain/REALITY, legacy import и round trips |
| MTU / UDP | Независимый ручной TUN MTU, source/reason бюджета, DATA_FRAG counters | Probe on/off, Recordizer on/off, IPv4/IPv6 budgets, захват и различение IP/DATA_FRAG/control |
| NDP | Assigned uplink source, проверка готовности/поколения владельца, MLD, bounded appearance NA | Packet fields/checksum/flags, DAD, source namespace, join/leave, active/removed owner |
| Маршруты / Routes | Общий pull_routes=true, INI/URI/model parity, сохранение gateway=false | IPv4/IPv6/dual, local routes, protected DNS и независимый full tunnel |
| Windows UI | Typed IP/copy, размеры редакторов, bounded traffic graph | Компиляция, service DTO validation, counter/session/gap regressions |
| Windows bindings | Opt-in windows_disable_sharing=false, creator handle + LUID/GUID + CIM association | Foreign/missing/ambiguous owner и readback fault injection; реальные Windows networking проверки учитываются отдельно |
| Интеграция / Integration | Свежие native cores, окончательные пакеты и только draft 0.8.3 | Source identity, A/B reproducibility, CI, package/hash/signature checks и Linux qualification |

Реализованные параметры и ограничения описаны в [RU CONFIG](../../../docs/ru/manuals/CONFIG.md),
[EN CONFIG](../../../docs/eng/manuals/CONFIG.md), [RU IPv6](../../../docs/ru/manuals/IPV6.md)
и [EN IPv6](../../../docs/eng/manuals/IPV6.md). Итоги тестов включаются в candidate
verification черновика только после завершения текущей интеграции.

## Отдельные опциональные этапы / Separate optional stages

Fit-path (новая политика выбора inner MTU), периодические NDP-анонсы и постоянный
Windows adapter после Disconnect остаются отдельными этапами. Они не включаются
в текущую реализацию и не меняют default/persist_tun незаметно. Wire/AF_XDP и
ядровой модуль относятся к отдельному отложенному исследованию.

## Достоверность проверки / Verification boundaries

Реальный Windows networking VM, физические Apple/iOS и роутерные стенды ранее
исключены пользователем. Mocked tests не выдаются за проверку физических bindings
или MLD-snooping на коммутаторе провайдера. Linux namespaces проверяют применимый
сетевой путь; throughput в VM не является обещанием Internet/single-client speed.
Прежний аудит 37/37 относится к согласованному объёму; принятое, неисправленное
API34 ENONET и первоначальный FAIL остаются в исторических отчётах.

The current implementation covers the main stages above. Fit-path, periodic NDP
and a persistent adapter are separate optional work. Every validation claim must
identify the tested platform and source. The existing accepted API34 limitation
and excluded physical rigs are not reclassified as fixed or tested.
