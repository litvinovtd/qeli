# Q29: Android Release в сети IPv6-only с DNS64/NAT64

<!-- normative-sync: q29-android-nat64-v1 -->

**5 октября 2026. TCP, UDP и QUIC masking через NAT64: три запуска Release/R8 PASS, 12 IPv4/IPv6 TCP/UDP payload-проб, 18 подтверждений приёмника. Q29 IN_PROGRESS; общий план 28/37 (75,7%).**

## Что подтверждено

Три последовательных readonly Android 14/API 34 x86_64 AVD на .11, в частных NET/MNT/PID namespaces. На выбранном WLAN-интерфейсе нет IPv4-адреса: Android получает IPv6 через SLAAC, маршрут через RA и DNS через RDNSS. Сервер слушает только тестовый IPv4 `192.0.2.10`; его имя `q29-v4-only.test` имеет исходную A-запись без исходной AAAA. DNS64 синтезирует `2001:db8:29:ffff::c000:20a`, TAYGA переводит реальные пакеты в IPv4 и ответы обратно в IPv6.

Штатный file-picker импортирует INI в недебажный Release. Настоящие Always-on + lockdown запускают профиль с `kill_switch = true`, `ipv6 = required`, `dns = off`. APK, JNI/Linux CLI, все 296 product inputs и семь managed-артефактов побайтно совпадают с [предыдущим Release-прогоном](AUDIT-Q29-ANDROID-RELEASE-FAULTS.md). Пересборки и изменения production proguard rules нет. Лабораторная подпись остаётся тестовой; instrumentation и запись приватных preferences не используются.

| Внешний транспорт | IPv4 TCP / UDP внутри VPN | IPv6 TCP / UDP внутри VPN | Auth / NetworkPlan | Revoke и очистка |
| --- | --- | --- | --- | --- |
| TCP/fake-tls | PASS / PASS | PASS / PASS | 1 / 1 | PASS |
| UDP/fake-tls | PASS / PASS | PASS / PASS | 1 / 1 | PASS |
| UDP/fake-tls + QUIC masking | PASS / PASS | PASS / PASS | 1 / 1 | PASS |

Отдельное приложение UID 10148 выполняет ordinary Java sockets без bind/protect/root/JNI; UID Qeli 10149. Каждая TCP-проба передаёт 16 KiB, UDP — 257 байт. Проверяются полные ответы, SHA запроса/ответа и TUN source в sink receipts. Независимый разбор pcap собирает TCP-запрос по sequence, включая framing и совпадение повторных байтов. До подключения отдельная IPv6-проба подтверждает физическую доступность вне пула; после подключения данные идут с адреса TUN. Это 12 целевых payload-проб и шесть коротких baseline/connected проб, а не 18 полных матричных сценариев.

Внешние captures на bridge и NAT64 TUN подтверждают IPv6 destination из DNS64, IPv4 destination сервера, source из пула транслятора и оба направления. Сравниваются совпадающие L4-записи после обнуления меняющихся TCP/UDP checksums; число совпадений сохранено в evidence. Серверные AUTH peer tuples присутствуют в capture. IPv4-внешнего соединения к порту профиля на bridge не наблюдается. Это ограниченный capture данного прогона, а не полная leak-матрица.

Android также автоматически запустил CLAT: виртуальный `v4-wlan0` имеет `192.0.0.4/32`, а базовый `wlan0` остаётся без IPv4. Это зафиксировано в connectivity и адресах; отдельный внешний путь к IPv4 literal через CLAT не проверялся.

## Исправления стенда и сохранённые отказы

TAYGA и radvd распакованы в отдельный каталог из Debian-пакетов, их SHA закреплены. Установка пакетов и запуск host services не выполнялись. Перед загрузкой AVD проверяется настоящий двусторонний TCP exchange через транслятор; немедленный отказ стенда не требует повторного долгого Android-прогона.

Сохранены три FAIL с исходными helpers, логами и pcap; они не входят в PASS-матрицу:

1. TAYGA 0.9.2 отверг префикс `64:ff9b:1::/96` с тестовым IPv4-адресом. В pcap есть исходящий SYN Qeli и ICMP unreachable от TAYGA. [Address mapping source](https://github.com/openthread/tayga/blob/master/addrmap.c) проверяет первые 32 бита WKP при запрете private/documentation IPv4. Исправлен префикс стенда: отдельный `2001:db8:29:ffff::/96` вне on-link SLAAC `/64`.
2. После успешных NAT64 Auth/NetworkPlan переключение на Cellular не завершило reconnect. Эмулятор публикует фиксированные IPv4/DNS параметры modem-интерфейса; этот интерфейс не получает IPv6-only параметры нашего TAP-стенда и не имеет доступного тестового DNS64. Такой переход не квалифицирован как NAT64 handover; [предыдущая матрица обычных переходов](AUDIT-Q29-ANDROID-RELEASE-RUNTIME.md) остаётся отдельной.
3. Новый `nat64` suite не был добавлен в два условия создания off-pool адресов и sink. Baseline до запуска продукта получил ICMP unreachable от стенда. Исправлено включение suite; отказ сохранён.

Обвязка выделяет NAT64 в отдельный suite; неверные сочетания suite/carrier/build отклоняются до изменения network namespace. Продуктовый код не менялся: выявленные отказы относятся к условиям стенда, а не доказанным дефектам клиента.

## Завершение и пределы

Реальный Settings revoke PASS: `desired=false`, consent `ignore`, сервис/TUN отсутствуют. Все шесть попыток сохранили host/service и постоянный userdata SHA/size/mtime; сервер завершился с кодом 0, адреса и sysctl частного namespace восстановлены. .10 не затронут. Python/CLI guards, девять docs checks, panel, generated bindings и сертификат PASS; JVM/.NET/build suites повторно не запускались при неизменных входах.

Raw: `audit-debt-20260924/q29-android-nat64-20261005`; evidence: `release/certification/evidence/q29-android-nat64-20261005.json`. Тест закрывает IPv6-only/DNS64/NAT64 передачу в доступном AVD для трёх транспортов. Реальные Internet/LTE, CLAT, NAT64 handover, немедленные пакеты при переходах и полная leak-матрица, долгий power/flapping, другие API/OEM/arm64 и остальные lifecycle-сценарии не квалифицированы. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) и прошлый matching instrumentation Trace FAIL остаются открытыми. Q29 IN_PROGRESS; USER_SKIPPED и D06 без BPF неизменны.
