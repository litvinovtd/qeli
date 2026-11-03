# Q25-F202 — воспроизводимые native cores и Android runtime

<!-- normative-sync: audit-q25-native-rebuild-v4 -->

Последующая [проверка F203](AUDIT-Q25-ANDROID-NETWORK-IDENTITY.md) объяснила
фоновые пакеты и закрыла D12 в согласованном доступном объёме.

Дата: 1 октября 2026. Исходник для A/B: `27db1a22`, digest
`dce152196ab7b13ba42f9808a571ba95ac494c7ccbbd1c69578bd0de90c1979c`.
Проверенные артефакты перенесены в `dev` коммитом `08a1823d`.

## Исправленные блокеры

Рецепт native-сборки помещал release-вывод в `/tmp` клиентской VM, где доступен
tmpfs менее 1 ГиБ. Он теперь использует дисковый `/var/tmp` и до сборки требует
8 ГиБ свободного места. На .10 отказ старого бюджета воспроизведён; после
удаления только пересоздаваемых Cargo incremental caches на .10 и .11
места хватило. Работающие бинарники и службы не заменялись.

Android `libc::in6_pktinfo.ipi6_ifindex` имеет знаковый тип, Linux —
беззнаковый. Проверенные преобразования на приёме и отправке устранили
cross-compile error; `Control::send` теперь возвращает ошибку, а batch scratch
очищает указатели при отказе. Шесть Linux UDP unit и один privileged IPv6
wildcard-тест прошли. Рецепт Android JVM-тестов собирает host JNI из того же
синхронизированного исходника и задаёт путь к нему Gradle; прежние 88
`UnsatisfiedLinkError` исчезли.

## Артефакты и проверки

Два независимых release-прохода A/B дали одинаковые SHA-256 для каждой цели:

| Цель | SHA-256 |
|---|---|
| Windows x64 DLL | `c601cffa1ab922552276358ed977445fc6bb1258c37b3c925c06eb437cb84d13` |
| macOS universal2 dylib | `1f5037414c5c19e040094bfb7d3bb2f6064a4e0781718f83e4ead267a3c2034d` |
| Android arm64-v8a so | `d3ccc2389600c9559d612c9deea4f03eeda73963dd5af2aea07a835f8a18bbca` |
| Android x86_64 so | `6c4db7c9ac12c482c6d62fe74347e9abec891042acd0daaca44ed3135b53077e` |

Windows/macOS экспортируют 6 REALITY и 22 клиентских символа; Android —
дополнительно 21 TransportCore JNI-символ. Universal2 содержит обе архитектуры
Mach-O. Все канонические и потребляемые копии обновлены. Проверки
`native-libs/verify.sh` (14 записей) и `provenance.py --check` проходят после
переноса коммита. Локальные 71 тест рецептов PASS.

Windows .NET-сборка прошла без ошибок и предупреждений; selftest со свежей DLL:
143 PASS, 0 FAIL. Android Gradle debug APK и JVM-тесты: 167 PASS, 0 ошибок.
APK версии 0.8.2 (code 722), SHA-256
`9ec9967bc691bd7b575572a85c7fd28d6478728d6395f89b47e5bbb678eb9968`;
обе `.so` внутри ZIP побайтно совпадают с A/B-артефактами.

На read-only Android 14/API 34 x86_64 AVD прямой `adb shell am instrument`
дал **11/11 PASS**: INI/JNI, отказ JSON-конфига и поддельной ссылки,
диагностический журнал, шифрованное хранилище/версия/границы и TUN builder.
Временный эмулятор остановлен. `connectedDebugAndroidTest --offline` не смог
получить отсутствующий в Gradle cache UTP 32.2.1; это отказ запуска через
Gradle, а не результат тестов. Первый эмулятор завис при одновременной работе
Gradle; тесты прошли отдельно на экземпляре с ограничением памяти.

## Ограниченный Android VPN E2E на двух VM

На .10 отдельно от штатного сервиса запущен существующий профиль `e2e`
(`tcp://0.0.0.0:8503`, `e2e0`, REALITY) под `timeout` 240 секунд; после
истечения срока он был повторно запущен на 180 секунд только для проверки
обратного ICMP. На .11 в read-only Android 14 AVD установлен тот же APK,
тестовый **INI** импортирован через поддерживаемую миграцию старого
хранилища, подключение выполнено кнопкой UI. Служебный JSON-контейнер
хранилища не является форматом конфига.

Android logcat: `Auth OK`, адрес `10.60.0.2`, `Native NetworkPlan 1 APPLIED`,
`Rust owns the TUN payload`; UI показал `Connected`/`Tunnel active`.
Сервер → клиент через `e2e0`: **4/4 ICMP, 0% потерь**. После штатного
timeout клиент автоматически переподключился: второй `Auth OK` и
`NetworkPlan 2 APPLIED`. Клиент → сервер после переподключения:
**4/4 ICMP** обычным ping и **2/2** с исходным `10.60.0.2`.
Проба 0/3 в момент уже завершившегося тестового сервера не оценивает туннель;
её сохранили как контроль времени отказа, не как успешную проверку.

После `force-stop` и остановки AVD собственный тестовый процесс завершён;
`:8503` и `e2e0` исчезли. Штатный `qeli-server.service` остался active
и продолжил слушать `:443`; его файлы и служба не менялись.

В журнале сервера одновременно встречались отклонённые inner-пакеты с
физическим адресом эмулятора `10.0.2.16` вместо назначенного `10.60.0.2`.
Проверенный Android shell ICMP прошёл с правильным адресом. Источник
фоновых пакетов не установлен; сервер правильно отклонил их антиспуфингом.
Нужна адресная проверка другого Android UID/фонового трафика и lifecycle
VPN при смене сети. Это остаток D12, а не доказанный дефект основного
туннеля.

## Граница результата

D11 закрыт для актуальных native cores, A/B, ABI, копий, provenance и доступных
пакетов. D12 остаётся открытым для анализа фоновых inner-пакетов и непроверенных
lifecycle-сценариев; базовый Android VPN handshake и двусторонний ICMP PASS. Windows VM, Mac/Xcode/iOS и router runtime пропущены по
решению пользователя; macOS dylib структурно проверена, приложение и поведение
на Mac не подтверждены. Сборка APK — debug, не release-публикация.

## Обновление после Q25-F204: 1 октября 2026

Linux-only исправление candidate `rp_filter` изменило общий исходный digest,
поэтому прежние native cores не оставлены с устаревшим provenance. Из чистого
коммита `f638d957` (source digest
`d39a334335d8a0110a59683bbdf354dfbfb4bd8e5919bdc5981a4b08278f43a5`)
повторены два независимых прохода A/B для всех четырёх ABI 1.16 библиотек:

| Цель | Новый SHA-256, одинаковый в A/B |
|---|---|
| Windows x64 DLL | `653522e6bade8fce705a12ec1566c4c119d49b27d55cb7ba088c018b2bd1dd92` |
| macOS universal2 dylib | `61292c140318590e7441ba891d1ca39266a22f3ee72c6f31fb2d6b39ed474e6a` |
| Android arm64-v8a so | `0255a5d8f60114301761031331c7fdf3ce7a6d6895790f93ad9b760a445c1522` |
| Android x86_64 so | `4ae6eb05b0a498e6fb9aab6014fbc1f0d50552dd48c6f49541c94b90f561ba30` |

Проверены 6 Reality + 22 client exports, `qeli_config_request`, 21 Android
JNI exports и обе Mach-O архитектуры. Все четыре canonical/consumed пары,
14 записей `SHA256SUMS`, оба JSON A/B evidence и `provenance.py --check`
PASS. Windows Release-сборка: 0 ошибок/предупреждений, selftest **143/143**.
Android JVM XML: **167/167**, 0 failures/errors/skipped. Новый debug APK
0.8.2/code 722: SHA-256
`324e19e8460ec4f81956bb7931ff305643e538a6b288873460d0d18e1e55d1ca`;
обе `.so` внутри APK побайтно совпадают с A/B библиотеками.
На read-only Android 14/API 34 x86_64 AVD свежие основной и тестовый
APK установились; прямой `am instrument` дал **11/11 PASS**. Эмулятор
остановлен. Полный VPN-трафик на этом новом APK не повторялся:
проверенный выше E2E относится к прежнему APK, а исправление F204
компилируется только на Linux.
Прежние хеши и runtime-результаты выше относятся к прежней ревизии;
Windows VM, Mac/Xcode/iOS и router runtime по решению пользователя
не добавлены к этому обновлению. D11 остаётся DONE для нового исходника.

[Реестр техдолга](../../plans/AUDIT-DEBT.md) · [Рецепты native](../../../../native-libs/README.md)

## Итоговая сверка native для D15: 3 октября 2026

Из чистого `93cb845d` выполнены новые независимые A/B-сборки Windows x64,
macOS universal2 и двух Android ABI. Digest исходников и рецептов:
`1bcee8e99b5a365e28821122b19fe190adce0277a6a6cba5fcb1a14c600f48d9`.
Все четыре библиотеки побайтно совпали с результатами 1 октября в таблице выше:
поздние изменения касаются Linux-владения процессами и shutdown. Проверены
ABI/экспорты, обе Mach-O архитектуры, canonical/consumed пары, 14 записей
SHA256SUMS и обновлённый provenance. Windows Release: 0 ошибок/предупреждений;
новый read-only selftest **143/143 PASS**.

Для D08 сверены **164 adapter input и 288 Rust input SHA**, изменений нет;
DLL и обе упакованные Android библиотеки также не изменились. Поэтому прежние
**511 .NET, 167 JVM и 12 instrumentation** результатов сохраняют применимость
с исходными границами; это не новые прогоны и не новая проверка VPN-трафика.
Семь последних Linux-отчётов также имеют одинаковые SHA всех 288 Rust-файлов.

Android-стенд сохранил сеть и PID рабочего сервиса. Desktop A/B и ABI прошли,
но обёртка проверки стенда вернула FAILED: на .10 исчезли три legacy-правила
FORWARD/MASQUERADE. Журнал и точные `vpn-nat.sh`/`vpn-nat-stop.sh` подтвердили
их добавление/удаление сторонней службой `vpn-nat`, зависимой от циклически
падающей `vpn-obfuscated` (отсутствует `/etc/vpn-obfuscated`). Рабочий Qeli
сохранил PID; сборочные команды firewall и службы не меняли. Исходный FAILED
сохранён, неизменность всего firewall не заявляется. Службы и права стенда
не изменялись. Предварительный отказ Android из-за нехватки места также
сохранён; удалены только проверенные compiler caches, порог 8 GiB не снижен.

[Машинное свидетельство](../../../../release/certification/evidence/final-native-refresh-20261003.json)
и raw `audit-debt-20260924/d15-final-20261003/` фиксируют команды, SHA и границы.
D15 остаётся IN_PROGRESS: нужны свежий Linux release, общий runtime-прогон,
soak, benchmark и согласование текущего certification manifest. Платформенные
исключения пользователя сохраняются; BPF-внедрение отменено, Q25-A125 не исправлен.

## Native и текущая Linux-сверка — 7 октября 2026

Чистый исходник `2b2c1565`, digest native-исходников/рецептов `c2ac10e0f41c826129a7b10918db88e84a77e55109eb4537783b34f99abd2a8b`. Два независимых прохода воспроизвели каждую из четырёх библиотек ABI 1.16. Проверены все exports, обе Mach-O архитектуры, нормализация UUID/indirect symbols и две ad-hoc подписи; семь canonical/consumed пар и 14 SHA-записей совпадают. PROVENANCE теперь соответствует текущему дереву. Использованы установленные pinned tools, отдельные исходники, private offline caches, один Cargo worker и ограниченное время компиляторов. Предупреждения macOS кросс-сборки об отсутствии Xcode SDK сохранены; Apple runtime не проверялся.

| Target | A/B SHA-256 |
|---|---|
| Windows x64 | `a32aff872e5a57bfb24e1d6eca066f0580e86485bd09910eb95407de9b855ed9` |
| macOS universal2 | `dda6c2b1a1a094af4487133217b74325de30913530deeb3d38d738c7d6097c38` |
| Android arm64-v8a | `b3b195c4ee3d62a441d6d0d1cfe0a73b85f4d276c3d24c0cac22903aaadc58f9` |
| Android x86_64 | `49c9eccc21f822c805364edb10adb45208519957554ba89c21696d1edc2c6a04` |

Свежий Windows C ABI: 22 PASS; Windows platform selftest: 325 PASS; общая .NET conformance: 549 PASS. Обе Release-сборки без ошибок/предупреждений. Android JVM: 201 PASS, ноль failures/errors/skips; реальный Android 14/API34/x86_64 JNI: 23 PASS. Debug APK содержит точные копии двух пересобранных библиотек; SHA app/test APK сохранены. JNI запускается через private app_process без установки APK и применения VPN/TUN.

Точные текущие Git-входы Linux: 383 файла, включая семь release INI fixtures. Свежие library units: 2417 PASS, 60 штатно ignored; standalone CLI units: 12 PASS, ноль ignored. Строгий all-target Clippy Rust 1.97.0 и текущие debug-сборки client/daemon PASS. Тесты выполняются в отдельных network/mount/PID namespaces; PID службы и host snapshots сохранены. Это не новая общая VPN-матрица, release daemon, peak benchmark или soak. Старые результаты сохраняют свои артефакты/даты и границы применимости исходников.

Исходные FAIL JNI wrapper (переход Wi-Fi при загрузке эмулятора и размещение nft stderr) и подготовки Clippy (отсутствующие include_str release fixtures) сохранены. Повторный запуск ждёт готовности WLAN, отдельно сохраняет nft stderr и сравнивает полный stdout правил; source/fixtures проверены по SHA. Unit2417 после исправления только fixtures не повторялся. SHA исходных userdata AVD не изменились.

Явный ответ пользователя «продолжай» разрешил удаление восьми перечисленных старых каталогов после проверенных восстанавливаемых backup, неизменности файлов и mount/process guards. Оба локальных архива сохранены. Новый compiler cache Linux размером 1,37 ГБ удалён после сохранения свежих debug binaries по SHA; source/logs/native A/B артефакты сохранены. Рабочие службы, сетевые политики, глобальные настройки toolchain и релизы не менялись.

Текущая сверка пакета D11/D15 закрыта: **14/15 DONE плюс D06 ACCEPTED_LIMITATION**. Полный аудит остаётся **28/37 (75,7%), девять разделов впереди**. Наблюдения Q29 SIGKILL/auto-null ENONET, Q30 callback drain/Apple exclusions и Q31 SDK/release pipeline не переводятся в PASS. Без push/deploy. [Машинное свидетельство](../../../../release/certification/evidence/native-current-20261007.json); raw `audit-debt-20260924/native-refresh-build-20261007/`.
