# Q29: ограниченный Doze и повторные переключения сети

<!-- normative-sync: q29-android-endurance-v1 -->

5 октября 2026. **Три Release runtime прогона PASS**: TCP, UDP и QUIC. Девять power-фаз,
18 переходов Wi-Fi ↔ Cellular, 36 payload-проб после пробуждения и 72 после переходов.
1 440 socket burst samples, включая 144 ожидаемые блокировки после force-stop;
45 DNS-операций, 72 A/AAAA/raw ответа. Q29 IN_PROGRESS; общий план 28/37 (75,7%).

## Матрица и результат

| Проверка | На каждом транспорте |
|---|---|
| Экран выключен | 30 секунд, не Awake; состояние сервиса и TUN сохранено |
| Forced deep Doze | Два периода по 120 секунд; IDLE/не Awake каждые 15 секунд |
| После трёх пробуждений | IPv4/IPv6 × TCP/UDP, системные A/AAAA; без новой Auth/NetworkPlan |
| Wi-Fi ↔ Cellular | Три полных цикла, шесть переходов; новые фактические Network handles |
| После каждого перехода | Четыре full-payload/SHA socket-пробы и системные A/AAAA |
| TCP reconnect | Новые Auth/NetworkPlan/CONNECTED, прежние PID/TUN/ifindex/адреса |
| UDP/QUIC roaming | Свежие commits целевого handle без новой Auth/NetworkPlan, прежний TUN |
| Stop/lockdown | 48 socket samples и две DNS-операции без ответа и без запроса в PCAP |
| Восстановление/revoke | Ручное восстановление четырёх payload-проб/DNS; реальный системный revoke |

Пробы выполняет ordinary UID отдельного `com.qeli.test`, без bindSocket/protect и
без Instrumentation. `com.qeli` имеет другой UID. INI импортирован через настоящий
UI; `apps_mode=all`, full tunnel, `kill_switch=true`, Always-on/lockdown включены
через Settings. Пользовательского battery exemption нет. Во время IDLE receiver
не запускается: проверяются удержание состояния и трафик после пробуждения,
а не непрерывная доставка во сне. Общая запрошенная выдержка power-фаз — 810 секунд.

Три независимых PCAP подтверждают положительную физическую калибровку всех четырёх
видов сокетов до VPN, полные маркированные payload/SHA через TUN после baseline,
отсутствие новых физических SYN/data/UDP в защищённом окне и DNS A/AAAA только
через TUN. TCP payload собран из сегментов; sink receipts сверены с capture.
Анализатор разделяет повторно использованный TCP tuple по новому SYN/sequence space
только после FIN/RST прежнего сеанса. Старый отказ анализатора сохранён.
Старое сравнение device started_ms и host action epoch не подтвердило новые старты
после END для 1 переходов; причина расхождения не установлена. Эта сильная
проверка не объявлена PASS. Отдельно подтверждены запросы PCAP до/после всех handover
по общим host-часам и четыре свежие socket-пробы после каждого завершённого перехода;
это не гарантия первого socket непосредственно после END. Оба вида timing evidence сохранены.
Kernel drops 0. Короткие timeout в burst не названы permanent packet discard:
при переходе возможны задержки/потери, после завершения перехода проверяется доставка.

## Исправление обвязки

При повторном возвращении на тот же Network старый commit мог удовлетворить
ожидание нового roaming. В `audit_android_network_handover.py` требуется увеличение
числа commits точного handle относительно снимка до действия; handle12 не совпадает
с handle123. Потеря log evidence не подтверждает успех. Пять regression tests
покрывают историческую запись, свежую повторную запись, другой/похожий handle и
сокращённый журнал. Старый предикат даёт false positive на неизменном журнале.

Добавлен `--suite endurance`: только Release с `--leak-bursts`, три power-фазы и
три handover-цикла; существующие короткие power/handover suites сохранены.
Неподдерживаемые сочетания отвергаются CLI до запуска namespace/AVD.

## Артефакты и границы

API34 x86_64 readonly AVD .11 в частных NET/MNT/PID namespaces. Точный production-R8
APK/тестовый APK и mapping переиспользованы из CONNECTED-gate; app SHA
`786e8954762b63a4c2cf8ad873376aeecd594bb5c98999df03d3f58710a8eaf2`, non-debuggable,
лабораторная подпись. Opt-in instrumented ABI APK не подменяет этот результат.
Product Kotlin/manifest/resources/native и production ProGuard не изменены.
Настройки power/сети, namespace addresses, host/service/firewall/routes и persistent
userdata восстановлены; server exit 0. .10 не затронут.
Первая UDP-попытка завершилась FAIL до запуска VPN: physical IPv4 Pending connect
failure, без IPv4 requests в capture. Её root cause не квалифицирован; raw сохранён,
cleanup/host/userdata PASS. Повтор в новом AVD с теми же APK/helpers прошёл всю матрицу.
Итого четыре попытки; неуспешная не включена в PASS-счётчики.

299 source inputs: изменён только README; 19 auxiliary inputs: три helper изменены,
один новый regression test. 14 native и 7 managed artifacts неизменны.
Свежие 11 helper tests, 3 CLI guards, 3 runtime/PCAP; прежние 172 JVM/lint checks
использованы по совпадающим inputs, повторная сборка не требовалась.

Raw: `audit-debt-20260924/q29-android-endurance-20261005`.
Evidence: `release/certification/evidence/q29-android-endurance-20261005.json`.

Ограниченная матрица Doze/flapping на доступном AVD закрыта. Физический CPU suspend,
lease renewal после многочасового сна, другие API/OEM/arm64 и real LTE не подтверждены.
Доверенный strict DoT, [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) и
[generic auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md)
остаются открыты. Mac/iOS/router/Windows VM — USER_SKIPPED; D06 без BPF сохранён.
