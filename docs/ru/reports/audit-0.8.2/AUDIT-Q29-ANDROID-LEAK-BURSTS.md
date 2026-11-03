# Q29: пакеты на границе переключения сети и force-stop

<!-- normative-sync: q29-android-leak-bursts-v1 -->

**5 октября 2026. Четыре Release-прогона PASS: 1 056 проб, шесть переходов Wi-Fi ↔ Cellular, четыре force-stop. Физических утечек в проверенных окнах не обнаружено; 192 пробы после остановки заблокированы. Q29 IN_PROGRESS; общий план 28/37 (75,7%).**

## Метод и объём

Четыре последовательных readonly Android 14/API 34 x86_64 AVD на .11 в частных NET/MNT/PID namespaces. Три запуска используют прежний offline SLIRP backend с настоящей сменой Android Network handle; четвёртый — [IPv6-only/DNS64/NAT64](AUDIT-Q29-ANDROID-NAT64.md), включая наблюдаемый CLAT. Это эмулированные carrier networks, а не физический LTE/Internet.

Product Release APK, JNI/Linux CLI и семь managed-артефактов побайтно прежние. Из 296 source inputs изменён только Java receiver тестового APK; 295 идентичны. Свежий releaseAndroidTest/R8 build PASS за 17 s, с прежним product mapping и тем же лабораторным сертификатом. Production proguard rules не менялись. Недебажный Release импортирует INI через file-picker и запускается настоящими Always-on + lockdown. AndroidJUnitRunner и private preferences injection не используются; прежний runner FAIL не повторён и не назван PASS.

Receiver отдельного UID 10148 (Qeli UID 10149) создаёт одновременно четыре потока ordinary Java sockets: IPv4/IPv6 × TCP/UDP. Нет bind/protect/root/JNI. В каждом потоке 12 новых сокетов с 257-байтовым payload; номер запуска и sample записаны в payload. Между пробами 150 ms, connect/read timeout 250 ms. Это ограниченная серия, а не непрерывная передача в каждую миллисекунду. Время открытия/завершения каждой пробы, host/device action markers, полные ответы и SHA сохраняются. Burst начинается до действия и продолжает открывать сокеты после его завершения. Обвязка проверяет обе стороны интервала, а не только наличие последнего успешного ответа.

До VPN четыре вида исходящих запросов положительно калибруются по полному payload в физическом sink и pcap. В SLIRP короткий reply budget дал лишь 8 ответов из 48 в каждом baseline, но sink принял 46/48/44 полных запроса для TCP/UDP/QUIC запусков, включая обе семьи и протоколы. Эти timeout сохранены и не считаются успешной блокировкой. В NAT64 baseline 48/48 ответов и запросов. Калибровка доказывает доступность исходящего пути, а не отсутствие задержек обратного пути.

## Результаты

| Carrier / транспорт | Burst-пробы | Смена сети | Ответы connected-steady | Ответы после force-stop при lockdown | Sink receipts за весь запуск |
| --- | --- | --- | --- | --- | --- |
| SLIRP / TCP | 288 | 2 PASS | 48/48 | 0/48 | 208 |
| SLIRP / UDP | 288 | 2 PASS | 48/48 | 0/48 | 208 |
| SLIRP / QUIC masking | 288 | 2 PASS | 48/48 | 0/48 | 206 |
| IPv6-only NAT64 / TCP | 192 | Не проверяется | 48/48 | 0/48 | 114 |

Всего 736 sink receipts: baseline, burst и обычные контрольные пробы; это не число успешных burst-ответов. При уходе с Wi-Fi короткие серии получили 44/42/44 ответа; при возврате — 48 в каждом запуске. Доставленные запросы имеют TUN source. TCP создаёт новую Auth/NetworkPlan; UDP/QUIC выполняют path commits без новой Auth до force-stop. PID/TUN/ifindex/адреса сохранены в двух handover-сценариях каждого запуска. Сохранение TUN через force-stop не утверждается.

В серии, пересекающей force-stop, восемь ответов за запуск относятся к пробам начавшейся до остановки серии; само число восемь не объявляется утечкой. Все доставленные запросы шли через TUN. После завершения force-stop проверено отсутствие PID/TUN и сохранение OS lockdown; отдельные 48 новых сокетов в каждом запуске не получили ответа, sink receipt или захваченного запроса. Это 192 отрицательные пробы с предварительной положительной калибровкой всех четырёх исходящих путей.

## Независимая сверка пакетов

Новый capture на `any` внутри частного Linux namespace охватывает plaintext TUN, SLIRP proxy/loopback и NAT64/TAP paths к тестовому порту. Ноль kernel capture drops. Parser разбирает IPv4/IPv6, собирает полные framed TCP requests по sequence и проверяет одинаковые overlap/retransmission bytes; UDP проверяется целиком. Run/sample payload SHA связывает pcap, receiver и sink. Трансляторный IPv6 destination для IPv4 literal сопоставляется исходной IPv4-пробе, а не ошибочно IPv6-пробе.

В окне от connected-steady до завершения stopped-lockdown нет новых физических SYN/data/UDP к цели. Задержанные соединения физического baseline определяются по раннему SYN и не выдаются за новые утечки. У всех маркированных запросов после baseline source принадлежит TUN; физических источников нет. Если ответ истёк по timeout, поздняя доставка всё равно проверяется по всему захвату и sink. Эти результаты относятся к тестовым целям и сериям: не квалифицированы произвольный трафик, другие порты, DNS, split/per-app, холодный запуск и все промежутки между samples.

## Восстановление, проверки и остаток

После user force-stop пакет намеренно находится в stopped state. Обвязка явно открывает приложение и переустанавливает OS-политику; автоматический SIGKILL restart этим не проверяется. Все 16 контрольных IPv4/IPv6 TCP 16 KiB/UDP 257 probes после ручного восстановления PASS, с полными bytes/SHA и TUN source.

Реальный Settings revoke PASS: desired=false, consent ignore, нет сервиса/TUN. Host/service и постоянный userdata SHA/size/mtime сохранены во всех четырёх запусках, server exit 0 и namespace cleanup PASS; .10 не затронут. Python/CLI guards, девять docs checks, panel, generated bindings и сертификат PASS. JVM/.NET/native suites повторно не запускались при неизменных product inputs; свежая тестовая сборка и новый runtime выполнены.

Raw: `audit-debt-20260924/q29-android-leak-bursts-20261005`; evidence: `release/certification/evidence/q29-android-leak-bursts-20261005.json`. Полный capture analysis находится в sealed raw, агрегаты — в evidence. Нового дефекта продуктового кода в этом пакете не подтверждено. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md), прошлый matching instrumentation Trace FAIL, DNS/cold-start/split/per-app leak cases, долгий power/flapping и другие API/OEM/arm64 остаются. Q29 IN_PROGRESS; USER_SKIPPED и D06 без BPF неизменны.
