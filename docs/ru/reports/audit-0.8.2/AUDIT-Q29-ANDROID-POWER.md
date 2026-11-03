# Q29: Android — экран, deep idle и восстановление TCP

<!-- normative-sync: q29-android-power-v1 -->

**5 октября 2026. Три новых runtime-сценария PASS; Q29 IN_PROGRESS. План: 28/37 (75,7%), осталось 9 разделов.**

## Стенд и границы

Одна readonly AVD Android 14/API34, x86_64, `UE1A.230829.036.A1/11228894`, в частных NET/MNT/PID namespaces на .11. Debug APK и JNI точно переиспользованы из квалифицированного предыдущего этапа. Профиль сохранён штатным INI-парсером: TCP, full tunnel, reconnect=true, roaming=off, DNS=off, IPv6 required. Always-on и lockdown включены настоящими Settings. Пробы выполняет обычный UDP-сокет отдельного test UID10148, Qeli UID10149; shell/root трафик не заменяет клиентские пробы.

## Свежие результаты

| Сценарий | Проверка и результат |
| --- | --- |
| Bootstrap | 1 instrumented PASS за 2,105s; четыре TCP/UDP IPv4/IPv6 ответа вне пула |
| Экран выключен на 5s | PASS: экран действительно не Awake; PID, TUN, ifindex и все адреса сохранены; после пробуждения UDP-ответ через TUN |
| Forced deep idle на 20s | PASS: IDLE подтверждён до и после выдержки; тот же PID/TUN; после пробуждения UDP-ответ через TUN |
| TCP reset и автоматическое переподключение | PASS: реальный native transport error; TUN сохранён во время ошибки; новая Auth/NetworkPlan и ответ через TUN без ручного запуска |
| Системный revoke и очистка | PASS: сервис/TUN отсутствуют, desired=false, VPN consent отозван; сервер exit0, namespace-адреса и power settings восстановлены |

Оба пробуждения зарегистрированы как «same network, keeping the tunnel»: Auth=2 и NetworkPlan=2 остаются неизменными. PID2155, tun0/ifindex19, 10.86.0.2/32 и fd86:29:1::2/128 сохранены. TCP fault меняет счётчики 2→3, оставляя тот же TUN; лог подтверждает его переиспользование. Весь пакет занял 183,92s, прошёл с первой попытки. Host/service и userdata SHA/size/mtime неизменны; .10 не затронут.

Пользовательское постоянное battery exemption для Qeli отсутствует, запрос в UI отклонён. Временные framework exemptions не классифицированы полностью. Android Doze ограничивает сеть/CPU и может игнорировать wake locks; наличие foreground service само по себе не доказывает отсутствие ограничений. [Официальная документация Android](https://developer.android.com/training/monitoring-device-state/doze-standby).

## Пакет, отправленный во время обрыва

Отрицательная проба Q29BLOCKED получила SocketTimeoutException и **0 доставок в своём окне ожидания**. После удаления private INPUT TCP REJECT пакет из сохранённого TUN дошёл до ответчика: pcap показывает source10.86.0.2 и доставку через 0,207s после новой серверной Auth. Это отложенная доставка через VPN после восстановления; утверждение «пакет никогда не доставляется» здесь неверно. Анализ использует серверные AUTH timestamps и pcap с общими host-часами, не сравнивает напрямую часы AVD и host.

Всего ответчик зарегистрировал **10 пакетов**: четыре bootstrap, один физический baseline, четыре положительных Q29PROTECTED через TUN и один отложенный Q29BLOCKED через TUN. Нулевое число доставок во время fault-пробы не превращено в гарантию полного отбрасывания или полную leak-матрицу. Firewall fault затрагивает только порт24966 внутри private namespace; правило удаляется в finally.

## Изменения и воспроизводимость

Добавлен `--suite power` в scripts/audit_android_data_plane_lab.py и helper scripts/audit_android_power_lifecycle.py. Повторные tagged-пробы ждут новую строку COMPLETE, учитывая уже существующие записи: старый ответ больше не засчитывается за новое пробуждение. Shared UI/UDP helper и только pure state parsers из scripts/roaming_android_sleep_wake_gate.py входят в пять исполнявшихся исходников. Старый sleep gate с shell ping не используется как сетевое доказательство.

В qeli-android/README.md уточнены wake lock и пользовательское battery exemption. Из 296 ранее квалифицированных source inputs изменён только этот документ; остальные 295, product/test APKs, 14 native и 7 managed artifacts идентичны. Изменения ядра/JNI/продуктового Kotlin не потребовались. Новые docs/panel/bindings checks выполнены отдельно; старые 167 JVM/28 Android/1248 .NET, Release R8/lint и 3+6+7 интеграционных сценариев остаются историческими областями проверки, а не новым общим прогоном.

Raw: `audit-debt-20260924/q29-android-power-20261005`, включая runtime-initial, pcap, late-delivery-analysis.json, source-proof и raw-seal. Evidence: `release/certification/evidence/q29-android-power-20261005.json`.

## Что ещё открыто

Нет payload-пробы внутри IDLE: запуск receiver мог бы изменить power state. Проверены удержание состояния и трафик после пробуждения, не непрерывная доставка в Doze. Не подтверждены физический CPU suspend, длительный сон/renewal wake-lock lease, реальные Wi-Fi/LTE handover, UDP/QUIC fault grace, Release runtime и другие API/OEM. [Ранее воспроизведённый отказ перезапуска после SIGKILL](AUDIT-Q29-ANDROID-SYSTEM.md) остаётся FAIL; этот пакет его не повторяет и не закрывает. Mac/iOS/router/Windows VM остаются USER_SKIPPED; D06 без BPF — принятая граница. Следующий пакет Q29: реальные изменения default network и восстановление UDP/QUIC.
