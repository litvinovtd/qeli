# Q25 — общий срок операций gateway/exit-node

<!-- normative-sync: audit-q25-gateway-budget-v1 -->

24 сентября 2026. База: `68983ac2`. Частичное закрытие D05/D09.

## Q25-F091, P2 — срок одной команды не ограничивал router-план

Синхронный `ROUTER_OPERATION.lock()` мог ждать чужой операции без ограничения,
а последовательность discovery, WAN, IPv4/IPv6 firewall-команд получала новые 15 секунд
для каждой команды. Сложный или зависший backend задерживал остановку/откат.

Каждая публичная операция setup, refresh и cleanup теперь получает общий срок
15 секунд. Он включает admission mutex, поиск firewall tool, WAN route queries,
проверки и мутации iptables/ip6tables. Очистка делит один срок между gateway,
всеми запомненными exit WAN, обеими семьями и границами sysctl callbacks.
Поздний ответ не подтверждает успех; после истечения срока новые команды не запускаются.

Срок принадлежит попытке, а не сохранённому владельцу. Частично установленные правила,
subnet/WAN selectors и sysctl ownership остаются для нового verified cleanup.
Откат после неудачного setup выполняется существующим generation cleanup и получает
свежий срок; этот этап не добавляет скрытый rollback внутри engage. Неактивный exit
refresh остаётся no-op. Проверка namespace/TUN и классификатор firewall не ослаблены;
поиск бинарников и извлечение Qeli chain разделяются с kill-switch.

## Проверки

5 новых переносимых + 1 Linux-тест: истёкший/busy admission без host I/O; поздний NAT ack
с сохранённым частичным планом; общий cleanup IPv4/IPv6 без сброса срока; поздний WAN
query без новых правил; истёкший контекст; реальный child `sleep 5`, прерванный сроком
120 мс (внешний допуск теста 2 секунды). Тесты firewall/sysctl используют изолированную
модель, а последний тест запускает настоящий процесс без изменения сети хоста.

**1484 host unit + 71 config**, все 9 feature/cross/lint checks PASS.
**2001 обычный Linux + 32 privileged + 8 worker lifecycle E2E PASS**.
Временное отключение проверок срока и возврат per-command timeout воспроизводят
**6/6 FAIL**; восстановление исходников даёт **107 gateway PASS**. Хеши всех 320
исходных файлов проверены до/после полного и контрольного прогонов.

Первая локальная регрессия ожидала две команды и не учитывала Windows PATH probe;
исправлен счётчик мутаций/проверок, итоговый прогон зелёный. Первая Linux-попытка
остановлена source verifier до сборки из-за старого manifest на стенде; после загрузки
точного manifest полный прогон выполнен. Оба подготовительных лога сохранены.
Rust Linux 1.97, host 1.98; прежнее Clippy-исключение `chunks_exact_to_as_chunks`.

Debug worker SHA256: `1a08fceb53e76d9931927a56ab1751bf6fa8d0a057f16398f78ce5fcda0aafd8`.
Source archive SHA256: `4ac2dbae65e440b872ff4a15222e12e60927c238d955ce02872fd448ff12d3a7`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/gateway-budget-phase/`,
`gateway-budget-final-v2.log`, `gateway-budget-counterfactual/`, `lifecycle-gateway-budget/`.
Лаба `.11`, приватные namespaces; работающий сервер `.10` не изменялся.

## Границы

Это общий командный срок и ограничение router operation mutex, а не гарантия полного
shutdown за 15 секунд. Синхронный filesystem/sysctl I/O и внутренние route/sysctl locks
не прерываются этой обёрткой; поздний результат отвергается после возврата. Полный
NetworkPlan включает отдельные операции. Общий срок route-последовательностей и
изоляция executor остаются D05. Persistent crash recovery остаётся D04, полный
packet/fault/resource охват — D09/D10/D13. Пользовательские конфиги остаются INI,
новых параметров нет. Windows VM/Mac/iOS/router runtime исключён по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Мануал](../../manuals/CONFIG.md)
