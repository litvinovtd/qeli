# Q25-F132: неоднозначный auto-WAN серверного профиля

25 сентября 2026. База: `280c4d93`. D06 остаётся **IN_PROGRESS**.

## Дефект и исправление

Серверный `detect_wan_until` выбирал WAN только по `ip route get 1.1.1.1`
или одному фиксированному IPv6-адресу. При ECMP этот ответ представляет один
hash bucket, а другие адреса могут выходить через иной интерфейс. Qeli затем
устанавливал NAT/FORWARD-правила для одного имени WAN. Клиентский gateway уже
имел parser `ip route show default`, который учитывает все nexthop и метрики.

Parser `preferred_default_device` и состояние `DefaultDevice` вынесены в общий
`network_default_route`. Клиент использует тот же алгоритм. Сервер при
автоопределении сначала читает все default routes, выбирает единственный WAN
с минимальной метрикой и отклоняет ECMP либо равноприоритетные лучшие маршруты
на разных устройствах. Ошибка возникает до включения forwarding и установки
новых правил. На этом историческом снимке при непригодном выводе или ошибке
команды оставался `route get` fallback; [Q25-F135](AUDIT-Q25-SERVER-AUTO-WAN-FAILURE.md)
позднее запретил его для NAT44/NAT66.

## Проверки

На изолированной Linux `.11` прошли Rustfmt, **11/11** тестов общего parser,
1/1 тест наличия WAN, строгий Clippy и сборка. С этим бинарником **8/8**
обычных worker lifecycle TCP/UDP × off/manual/route/nat66 с **автоматическим**
IPv4 и IPv6 WAN прошли со снимками сети до/после.

В отдельных NET/mount/PID namespaces созданы два WAN с действительными
IPv4/IPv6 ECMP default routes. `route get` для обоих фиксированных адресов
выбрал `wan0`, тогда как `route show default` содержит `wan0` и `wan1`.
Автоматические IPv4 NAT и IPv6 route отказали с `ambiguous default WAN`:
**2/2 PASS**, forwarding и firewall не изменились, TUN удалён при остановке.
Установленные службы `.11` и сервер `.10` не тронуты.

SHA256 бинарника: `0a67306e187e21edb9dfd693cc9b9d64b82eb219ca34a1bca8b0a57021c98646`.
SHA256 общего parser: `0c1cb45dca572ad3a21d3db3cfafd160d1af458b09f372041be0b41cc6bbaa3c`.
Логи, return codes, маршруты, сетевые снимки и скрипты:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-ecmp-phase/`.

## Оставшаяся граница

Это отказ только **автоматического** выбора при наблюдаемом неоднозначном
default route. Явно заданный WAN, маршруты отдельных policy tables,
ошибка чтения списка default routes и изменение маршрута после установки
не защищены этим исходным исправлением. Первую границу для NAT44/NAT66
закрыл [Q25-F135](AUDIT-Q25-SERVER-AUTO-WAN-FAILURE.md). Серверные NAT44/NAT66 правила сопоставляют
выход по имени; при фактическом выходе через другой интерфейс MASQUERADE
может не совпасть. [NAT66 off-WAN guard](AUDIT-Q25-SERVER-NAT66-EGRESS.md)
закрывает этот packet-level выход для NAT66. IPv4 NAT44, mixed-backend recovery
и [повторное использование имени](AUDIT-Q25-WAN-NAME-REUSE.md) остаются D06/D10.
