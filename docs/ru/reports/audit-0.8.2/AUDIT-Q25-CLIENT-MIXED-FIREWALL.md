# Q25-F102: предупреждение о legacy-таблицах блокировало клиент

24 сентября 2026. D04/D09/D10, общий `firewall_check` клиента и сервера.

## Дефект P2 и исправление

При одновременном наличии nft и legacy правил настоящий iptables 1.8.11 сообщает:

```text
# Warning: iptables-legacy tables present, use iptables-legacy to see them
iptables: No chain/target/match by that name.
```

У `-S QELI_KS_<dev>` это exit 1 с явным сообщением об отсутствующей цепочке.
Прежний общий распознаватель отвергал любую дополнительную строку. Поэтому новый
клиент с kill-switch прекращал запуск до TUN/handshake, хотя выбранный backend был исправен.
Smoke v1 воспроизвёл этот отказ на прежнем worker `3f52a9d5…` при IPv4=nft,
IPv6=legacy и настоящем firewalld. Утечки этим сценарием не обнаружено: это дефект
доступности и восстановления, а не основание объявлять предыдущую защиту открытой.

Теперь пропускаются только две точные advisory-строки для `iptables-legacy` и
`ip6tables-legacy`. После них по-прежнему нужны допустимый exit и явная известная
диагностика отсутствия; имена цепочек сравниваются точно. Предупреждение само по
себе не доказывает отсутствие. Неизвестные предупреждения, permission/backend ошибки,
`Parsing nftables rule failed`, дополнительные ошибки и exit 3 остаются отказом.
Конфиги остаются INI; формат конфигурации не менялся.

## Проверка реальными пакетами

`audit_client_mixed_matrix.py` запускает существующую release-матрицу внутри новых
NET/mount/PID namespaces. `ipv6_netns_case.sh` добавляет необязательные lifecycle
hooks, а `audit_client_mixed_firewall.py` проверяет настоящий firewall клиента.
Каждая ячейка создаёт отдельные client/router/server NET namespaces. Backend каждого
семейства выбирается исполнением настоящего xtables multi-call; ответы не подделываются.
Снимки обоих backend используют сохранённые оригинальные executable.

Во всех полных туннелях включён kill-switch; split-контроли сохраняют прямой выход.
Проверяются TCP fake-TLS, UDP fake-TLS/QUIC, outer/inner IPv4/IPv6, split, TAP NDP/RA,
DNS A/AAAA через настоящий systemd-resolved и IPv4/IPv6 upstream, MTU/PMTU/PTB.
После SIGKILL выполняются существующие route/DNS recovery и запуск нового процесса.
Операторские правила существуют в обоих семействах обоих backend и в отдельной
нативной inet-таблице. Firewalld использует приватную D-Bus-шину, nftables backend,
`DefaultZone=trusted`; reload выполняется при активном туннеле и после SIGKILL.

На каждом этапе UDP-сокеты явно привязаны к физическому интерфейсу и отправляют
по четыре пакета каждого семейства соседнему router. Это не проверка недоступного
адреса через оставшийся blackhole: до VPN и после штатной остановки получены все
ответы; при действующей защите должны вырасти реальные DROP-счётчики и отсутствовать
пакеты у получателя. Снимки проверяют сохранность чужих правил после setup/crash/
recovery/stop и сохранность всего ruleset после firewalld reload.

## Результаты

**8/8 сочетаний backend/firewalld, 136/136 строк release-матрицы = 152/152 сетевые
ячейки PASS.** В них 136 сценариев SIGKILL/recovery; 4880 основных утверждений
и 3224 подробных вложенных проверок (не независимые тесты, их не складываем).
Все 4352 прямых UDP-попыток при защите заблокированы. Все 2624 разрешённых
проб получили ответ; дополнительная проверка evidence исключила route/socket errors
из доказательств блокировки: у denied-проб только EPERM, счётчики выросли.

Локально: **1528 unit + 71 config integration**, все девять feature/cross/lint gates PASS.
Linux: **2080 обычных + 43 privileged + 8 worker lifecycle PASS**. Общие negative-regressions
проверяют warning-only/unknown/error/exit3; серверная mixed матрица повторена на новом
worker: **16/16 сценариев, 476 checks PASS**, включая native parse errors и ручной recovery.
Скрипты: bash syntax, Python compile и 8 существующих matrix contract tests PASS.

Стенд `.11`: Linux 6.12.105+deb13-amd64, iptables 1.8.11, nftables 1.1.3;
приватно извлечённый firewalld 2.3.1. Четыре изолированные группы одновременно.
Рабочий сервер `.10` не менялся. Benchmark и платформенная certification не обновлялись.
Все 340 Rust/conformance файлов и 16 сценарных файлов сверены с текущим деревом.
База `05b8a05f` + изменение `firewall_check.rs`, точный снимок зафиксирован в manifest.
Worker SHA256: `cf0af9429d061ac491f0c1c566c6429ee3cf5fce39bd20c755be1b48bf0f5eb7`.
Source archive SHA256: `4007b16e3838e89e2cb594cf0fd1818f3e84d0a0bf75accbccbb3c1d28907c64`.

Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/client-mixed-phase/`,
`client-mixed-matrix-v1/`, `mixed-firewall-regression-v1/`, `lifecycle-client-mixed/`
и их `.tar.gz`. Логи/exit: `client-mixed-matrix-v1`, `mixed-firewall-regression-v1`,
`client-mixed-linux-final-v1` (`.log/.rc`). Команды — `matrix.sh`, `server-regression.sh`,
`linux-final.sh`, `run_checks.py`; результаты/хеши — `evidence.json`, source/scripts manifests.
Client archive SHA256: `142756ce52d8d00302a31a96bbaade16c77c874532b717e10fde18a5a955b1b0`.

Smoke v1 — воспроизведение дефекта на старом бинарнике. Smoke v2 — исправленный
клиент уже работает, но сравнение snapshot неверно учитывало порядок таблиц в nft dump.
В v3 исправлена группировка объектов с сохранением порядка правил внутри каждой цепочки;
52 основных проверки PASS. Ранние отказы сохранены и не засчитаны за PASS.
Окончательная полная матрица — `client-mixed-matrix-v1`.

**D04 DONE** с перечисленными ручными границами. Реестр техдолга: **4/15 DONE
(26,7%), 9 IN_PROGRESS, 2 TODO**; полный аудит из 37 разделов этим не завершён.

| IPv4 | IPv6 | firewalld | Ячейки | Утверждения | Вложенные проверки |
|---|---|---|---:|---:|---:|
| legacy | legacy | нет | 19/19 | 610 | 330 |
| legacy | legacy | да | 19/19 | 610 | 476 |
| legacy | nft | нет | 19/19 | 610 | 330 |
| legacy | nft | да | 19/19 | 610 | 476 |
| nft | legacy | нет | 19/19 | 610 | 330 |
| nft | legacy | да | 19/19 | 610 | 476 |
| nft | nft | нет | 19/19 | 610 | 330 |
| nft | nft | да | 19/19 | 610 | 476 |

## Границы

Backend каждого семейства сохраняется между запуском, SIGKILL, recovery и stop.
Автоматическая миграция клиента на другой backend этой проверкой не сертифицируется.
Произвольные firewalld zones/policies, параллельная перезапись правил другим root,
полная off/manual/route/nat66 × NDP и multiprofile матрица остаются отдельным D10.
Native parse errors по-прежнему требуют устранения несовместимости администратором;
потерянный WAN sysctl witness и persistent TUN сохраняют ранее описанные ручные границы.
Windows VM, Mac/iOS и физический роутер SKIPPED по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Серверная mixed матрица](AUDIT-Q14-MIXED-FIREWALL.md).
