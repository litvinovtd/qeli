# Q29: минифицированный Release и сетевой runtime Android

<!-- normative-sync: q29-android-release-runtime-v1 -->

**5 октября 2026. В Release/R8 прошли 24/24 проверки передачи данных после смены сети: TCP/UDP/QUIC × два перехода Wi-Fi/Cellular × IPv4/IPv6 TCP/UDP. Шесть переходов, три импорта INI через интерфейс приложения, 30 подтверждений от приёмника. Q29 остаётся IN_PROGRESS; общий план — 28/37 (75,7%).**

## Стенд и способ проверки

Три последовательных запуска Android 14/API 34 x86_64 AVD на .11, в отдельных NET/MNT/PID namespaces, с readonly userdata. Внешний backend изолирован и не использует Интернет. Сервер .10 не затронут. Штатный file-picker импортирует INI через Release Activity; настоящая политика Android Always-on + lockdown запускает сохранённый профиль. Instrumentation и запись приватных preferences для подготовки профиля не используются.

Команды `svc wifi disable/enable` действительно меняют Current Networks между WIFI (`wlan0`) и CELLULAR (`eth0`); смена Android netid/handle подтверждена. После каждого перехода отдельный UID 10148, отличный от Qeli UID 10149, открывает обычные Java sockets к приёмнику вне адресного пула VPN: IPv4/IPv6 × TCP 16 KiB/UDP 257 байт. Клиентские sockets не используют bind, protect, root или JNI. Приёмник работает из ReleaseAndroidTest APK как standalone receiver, без AndroidJUnitRunner.

Ответ TCP содержит весь payload в обратном порядке, UDP — префикс `Q29:` и весь payload. Receiver проверяет каждый байт и SHA-256 запроса/ответа; обвязка сверяет подтверждения приёмника и адрес источника TUN. Статус CONNECTED сам по себе не считается успехом.

## Результаты

| Внешний транспорт | Wi-Fi → Cellular | Cellular → Wi-Fi | Payload | Весь запуск |
| --- | --- | --- | --- | --- |
| tcp | 5.64 s | 10.26 s | 8/8 PASS | 196.03 s |
| udp | 5.19 s | 9.65 s | 8/8 PASS | 183.96 s |
| quic | 5.21 s | 9.24 s | 8/8 PASS | 179.99 s |

Время этапа включает ADB и четыре пробы, поэтому не является чистой длительностью простоя. Во всех запусках сохранены PID, `tun0`, ifindex и адреса. TCP заново выполняет Auth и NetworkPlan: 1/1 → 2/2 → 3/3, с новыми внешними портами и повторным использованием Android TUN. UDP path commits для TCP отсутствуют. UDP/QUIC сохраняют Auth/NetworkPlan 1/1; каждый новый commit token соответствует подтверждённой целевой сети, а сервер фиксирует новый порт и epoch.

Pcap подтверждает восемь запросов после переходов на каждый транспорт, с IPv4/IPv6 адресом TUN, после соответствующего серверного AUTH/PATH_COMMIT. TCP-запросы полностью собраны по sequence; совпадение повторных и перекрывающихся байтов и SHA всех 16 KiB проверено. Алгоритм сборки повторно используется из предыдущего этапа; привязка часов обновлена для запуска через UI без instrumentation bootstrap. На каждый запуск получено десять подтверждений: физическая baseline-проба, проба через подключённый VPN и восемь целевых payload-проб.

Настоящий Settings revoke и очистка прошли во всех трёх запусках: `desired=false`, consent `ignore`, сервис и TUN отсутствуют. Финальное состояние preferences только читается через root частного AVD; записи нет. Настройки Wi-Fi/mobile-data восстановлены. Host/service, SHA/размер/mtime userdata неизменны; сервер завершился с кодом 0, адреса namespaces восстановлены.

## Сборки, изменения и сохранённые отказы

```sh
./gradlew :app:assembleRelease :app:assembleReleaseAndroidTest \
  -PqeliTestBuildType=release -PqeliLabReleaseSigning=true \
  --offline --no-daemon --max-workers=2
```

Обе Release-сборки прошли R8; тестовая использует `-applymapping` продукта. APK подписаны тестовым debug certificate только для лабы; клиент не debuggable, что проверено package flags и отказом `run-as`. Без новых флагов остаются debug test variant и штатная production подпись либо unsigned Release. R8/shrinking/proguard не ослаблены. Из 296 входных файлов продукта 295 идентичны; изменён только `app/build.gradle.kts` для opt-in test variant/lab signing. Kotlin, receiver, proguard rules, JNI/Linux CLI и семь managed-артефактов неизменны; 11 вспомогательных файлов закреплены хешами.

Первый запуск matching Release instrumentation завершился FAIL до тела теста: `NoClassDefFoundError: androidx/tracing/Trace`. Предположение о shared optimized classpath основано на стеке и mapping; точная первопричина не доказана. Стек, исходная обвязка и нулевые bootstrap/receipts сохранены. Проверка через UI не закрывает этот отказ. [Официальная диагностика R8](https://developer.android.com/topic/performance/app-optimization/troubleshoot-the-optimization).

Сохранены ещё три неуспешные попытки обвязки: System UI ANR; преждевременный выбор фонового Downloads label при загрузке picker; запрещённое Debug `run-as` чтение XML после revoke недебажного клиента. Последняя попытка уже прошла восемь TCP payload-проб, но не прошла финальный gate и не включена в 24/24. Финальная обвязка ограниченно ждёт actual Wait/file rows и при необходимости выбирает наблюдаемый уникальный storage root. System UI ANR возник также при каждом успешном запуске и был снят через настоящий Wait; отказ ОС не скрыт.

Свежие Release/testRelease и default Debug builds, Python/CLI, девять docs checks, panel и generated bindings PASS. Предыдущие JVM/Android/.NET/integration результаты остаются историческими областями, а не свежим полным набором.

Raw: `audit-debt-20260924/q29-android-release-runtime-20261005`. Evidence: `release/certification/evidence/q29-android-release-runtime-20261005.json`.

## Пределы и остаток

Закрыта доступная AVD Release/R8 UI матрица передачи IPv4/IPv6 TCP/UDP после переходов для внешних TCP/UDP/QUIC. Каждый TCP probe открывает новое соединение; сохранение уже открытого длинного потока не проверено. Общий private offline backend не подтверждает physical Wi-Fi/LTE/Internet. IPv6 внутри VPN не означает IPv6-only outer/NAT64.

Остаются IPv6-only/NAT64, первые пакеты внутри перехода и полная leak-матрица, длительный/физический Doze/flapping, полный Release lifecycle fault suite, matching AndroidJUnitRunner FAIL, другие API/OEM/arm64. [SIGKILL recovery FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) остаётся открытым. Предыдущие [UDP/QUIC](AUDIT-Q29-ANDROID-HANDOVER.md), [TCP](AUDIT-Q29-ANDROID-TCP-HANDOVER.md) и [payload](AUDIT-Q29-ANDROID-HANDOVER-PAYLOAD.md) scopes сохранены. USER_SKIPPED и D06 без BPF не изменены; Q29 IN_PROGRESS.
