# Q34/Q25 — Linux packet matrix и проверка переключений

<!-- normative-sync: audit-q34-linux-matrix-v1 -->

24 сентября 2026. Ядро: `86242da6` (исходники из подтверждённого снимка D02),
SHA256 executable: `96f96c31d42b501773bd0eeb223f923da966a3d5d6b5420862962c679d03183d`. Debug binary Rust 1.97.0; это developer integration,
а не release certification и не benchmark пропускной способности.

## Q34-F004, P2 — сетевые скрипты отстали от runtime-контракта

В `ipv6_netns_case.sh`, `roaming_netns_e2e.sh` и `roaming_udp_netns_e2e.sh` рабочий
каталог теперь создаёт `mktemp -d` с правами 0700; предсказуемый каталог с 0755
правильно отвергался проверкой control socket. Каждый независимый сценарий получает
свой `STATE_DIRECTORY`: его новые namespaces не должны наследовать sysctl-журнал
уже уничтоженной сети предыдущего сценария. Внутри сценария участники используют
общий каталог, разделённый на namespace-группы.

IPv4/IPv6 route-get теперь ожидает установку маршрута до пяти секунд: появление TUN
и адреса происходит раньше окончания NetworkPlan. Ранняя однократная проверка давала
FAIL при фактически работающем туннеле. DNS-проверки используют наблюдаемый ifindex,
как текущий клиент, и проверяют существование, затем удаление точного `dns-link-v1`
маркера. Прежняя проверка отсутствующего legacy-файла не подтверждала очистку.

## Результаты

**17/17 строк матрицы, 297 утверждений PASS**. Проверены outer IPv4/IPv6 × inner
IPv4/IPv6 × TCP fake-tls / UDP fake-tls / UDP quic-shape; dual-stack split для TCP/UDP;
TAP NDP/RA; DNS A/AAAA через обе семьи и IPv4/IPv6 upstream; PMTU, DATA_FRAG,
явный MTU 1280 и ICMPv6 Packet Too Big. Чистый stop клиента удаляет TUN и возвращает
прямую IPv4/IPv6 связность. Встроенный DNS передаёт реальные пакеты; resolvectl
представлен контролируемым stub, реальная D-Bus-служба resolved этим не проверена.
8 контрактных Python-тестов матрицы PASS.

Ранние прогоны сохранены: отказ control socket, гонка route-get, общий журнал между
сценариями и старые DNS assertions. В первой доставке файлов в лабу также отсутствовал
TAP helper; это ошибка комплектации тестового пакета, исправлена перед финальным прогоном.
Критерии матрицы не ослаблялись.

**Soak TCP 100 переключений: FAIL по RSS**. Все 100 handover завершены точно по одному
разу на сервере и клиенте, сохранены одна сессия и исходные процессы/TUN, orphan=0.
Максимум fd: клиент 15, worker 18; socket fd: 5/6. Последний sampled RSS:
41184/101028 KiB. Порог прироста 32768 KiB превышен. Исходный скрипт не печатает baseline,
поэтому точную дельту из этого лога восстановить нельзя; нужны дополнительные измерения.
UDP-часть wrapper после TCP FAIL не запускалась. Порог не повышен; D13 остаётся открыт.

## Воспроизводимость и границы

Лаба `.11`, приватные net/mount/PID namespaces, отдельные `/run`, `/var/lib`, `/var/log`,
`/tmp` и `/etc/qeli`; рабочий сервер `.10` не изменялся. Source archive D02:
`0908e9bc9fd9aa140470a6cf1e7dfb0b08b58cdf4b3a69750263dac8ee634de4`.
Нормализованные LF-скрипты имеют отдельный SHA manifest. Артефакты:
`C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/packet-matrix-phase/`,
`packet-matrix-full-v4/`, `packet-matrix-full-v4.log`, `roaming-soak-100/` и одноимённый лог.

D09/D10/D13/D14 целиком не закрыты. Остаются полный off/manual/route/nat66 × NDP,
реальный resolved/firewalld/mixed nft, multiprofile/fault/crash-recovery,
полное измерение ресурсов и текущие release A/B/benchmark. Изменения gateway следующего
этапа не входят в этот binary. Windows VM, Mac/iOS и роутер исключены по решению
пользователя, без заявления PASS.

[Реестр](../../plans/AUDIT-DEBT.md) · [Полный план](../../plans/FULL-SYSTEM-AUDIT.md)

D13: [release TCP/UDP по 100 handover](AUDIT-Q34-RELEASE-SOAK.md): 30/30 утверждений PASS, прирост RSS в прежнем лимите 32 MiB; debug FAIL сохранён. Полный ресурсный/fault охват и итоговый снимок ещё открыты.

Продолжение: [Q25-F096/F097](AUDIT-Q25-DNS-MARKER-STORAGE.md) переводит DNS-маркеры на v2 с SO_NETNS_COOKIE и доверенным открытым каталогом, проверяет SIGKILL/restart с реальным resolved. Исторические цифры и v1-контракт выше описывают прежний снимок; актуальная эксплуатация — в §6.50 TROUBLESHOOTING.
