# qeli-android

Android-клиент qeli: системный VPN через `VpnService` (весь трафик и DNS на уровне ОС, не
пер-приложенческий прокси). Connect, handshake, обфускация, криптография и packet pumps
выполняются общим Rust-ядром; Kotlin остаётся адаптером Android API и UI.

- Общая карта документации — [docs/ru/index.md](../docs/ru/index.md)
- Подключение «с нуля» (выдача `qeli://` на сервере) — [GETTING-STARTED §8.1](../docs/ru/manuals/GETTING-STARTED.md)
- Все ключи конфигурации — [CONFIG.md](../docs/ru/manuals/CONFIG.md)
- Если не подключается — [TROUBLESHOOTING.md](../docs/ru/manuals/TROUBLESHOOTING.md)

## Технологии

- **Kotlin**, `minSdk 28` (Android 9), `targetSdk 37`, Material Components.
- **`VpnService`** — TUN-интерфейс, маршруты, DNS, per-app split tunnel.
- **JNI к Rust-ядру** (`libqeli.so`, `app/src/main/jniLibs/{arm64-v8a,x86_64}/`) —
  единый TCP/UDP/Reality transport, ML-KEM-768, QUIC/MTU, shaping и bonding. JNI также
  предоставляет credential-free UDP first-flight probe для проверки доступности профиля.
- Foreground-сервис со `specialUse`-типом: туннель живёт, пока приложение свёрнуто.

## Структура

```
app/src/main/kotlin/com/qeli/
├── MainActivity.kt        — UI: профили, импорт (QR/ссылка/файл), лог, настройки, бэкап
├── QeliService.kt         — platform adapter: protect/trust, NetworkPlan/TUN, reconnect
├── TransportCore.kt       — JNI owner общего Rust transport и native UDP diagnostic
├── ProfileStore.kt        — хранилище профилей (AES-GCM + Android Keystore)
├── QeliTileService.kt     — плитка в «Быстрых настройках»
├── QeliWidgetProvider.kt  — виджет на рабочий стол
├── BootReceiver.kt        — автоподключение после перезагрузки
├── UpdateChecker.kt       — проверка обновлений (opt-in)
├── crypto/BackupCrypto.kt — шифрование импорта/экспорта профилей (не transport)
└── model/Config.kt        — разбор/сборка flat-INI и `qeli://`
```

## Возможности

| Возможность | Как работает |
|---|---|
| **Импорт профиля** | QR-код (камера), вставка `qeli://`-ссылки, тап по `qeli://`-ссылке (deep link) или UTF-8 файл в формате flat-INI (не более 256 КиБ). Неверная UTF-8 кодировка отвергается; исходный INI передаётся общему парсеру без обрезки конца. JSON как конфиг намеренно отвергается; JSON остаётся только форматом контейнера бэкапа |
| **Per-app split tunnel** | Выбор приложений в режиме «только эти» (`addAllowedApplication`) или «кроме этих» (`addDisallowedApplication`) |
| **Плитка Quick Settings** | Подключение/отключение из шторки |
| **Виджет** | Статус и переключение с рабочего стола |
| **Автоподключение** | После перезагрузки (`BOOT_COMPLETED`) и/или при запуске приложения |
| **Доверенный Wi-Fi** | Локальный список точных SSID: Qeli снимает VPN в доверенной сети и восстанавливает его после выхода. При Android lockdown/`kill_switch` пауза запрещена, потому что TUN обязан оставаться установленным |
| **Автоопрос профилей** | Opt-in, выключен по умолчанию; после включения проверяет доступность только пока приложение видно и VPN отключён, ручные проверки доступны всегда |
| **Доступ к локальной сети** | Тумблер «разрешить LAN» при full-tunnel (принтеры, NAS, роутер) |
| **Изменение активного профиля** | Если сохранить INI или список приложений при работающем туннеле, текущий сеанс продолжит использовать прежние настройки. Отключитесь и подключитесь снова; приложение покажет напоминание. Если список профилей изменился, пока открыт редактор, откройте его заново |
| **Несколько окон Qeli** | Если одно окно уже сохранило профили, устаревшее окно откажется записывать свой список. Перезапустите его перед повторной правкой; подтверждённый импорт резервной копии тоже проверяет, что хранилище не изменилось с момента открытия |
| **Бэкап профилей** | Экспорт/импорт JSON; **с парольной фразой** — шифрованный контейнер (PBKDF2-HMAC-SHA256 + AES-256-GCM), совместимый с десктопом. Пустая фраза = **открытый JSON с паролями**. JSON ограничен 8 МиБ, шифрованный файл — 12 МиБ; повреждённый UTF-8 отвергается |
| **Очистка логов после отключения** | Настройки → «Очищать лог после отключения», включено по умолчанию. После обычной остановки VPN очищает вкладку и приватный файл журнала, в том числе без открытой Activity. При ошибке запуска/подключения журнал всегда сохраняется, включая server key mismatch. Для сохранения истории обычных отключений выключите и сохраните опцию; автореконнект и доверенный Wi-Fi историю не стирают |
| **Формат времени в логе** | Пять вариантов, совпадают с серверным `[logging] time_format` — удобно сверять логи |
| **Проверка обновлений** | Opt-in, выключена по умолчанию |

## Разрешения и зачем они

| Разрешение | Зачем |
|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE` | сеть, выбранный физический carrier и реакция на его смену (Wi-Fi ⇄ LTE) |
| `NEARBY_WIFI_DEVICES`, `ACCESS_FINE_LOCATION` | чтение текущего SSID для доверенного Wi-Fi; без runtime-разрешения SSID считается неизвестным и VPN остаётся включённым |
| `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_SPECIAL_USE` + `FOREGROUND_SERVICE_LOCATION` | туннель и проверка доверенного SSID продолжают работать в foreground-сервисе без открытой Activity; location-тип включается только при активной функции и выданном разрешении |
| `POST_NOTIFICATIONS` | уведомление активного туннеля (Android 13+) |
| `WAKE_LOCK` | ограниченный partial wake lock активного туннеля; системный Doze может игнорировать его |
| `RECEIVE_BOOT_COMPLETED` | автоподключение после перезагрузки (если включено) |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | запрос исключения из оптимизации батареи; решение принимает пользователь, автоматический перезапуск зависит от Android |
| `CAMERA` | сканирование QR с профилем |
| `QUERY_ALL_PACKAGES` | список приложений для per-app split tunnel |

## Запуск

1. Установите APK со страницы **GitHub Releases** (или соберите, см. ниже).
2. На сервере выдайте ссылку: `qeli add-client <user> --link --host <хост:порт>`.
3. В приложении: **Add profile → Scan QR** или вставьте `qeli://`-ссылку — профиль
   появится со всеми параметрами и **запиненным ключом сервера**.
4. Нажмите кольцо подключения и подтвердите системный запрос VPN.

Full-tunnel, «маршрутизировать локальные сети», LAN-доступ и per-app split tunnel
переключаются в приложении и **не передаются** в `qeli://`-ссылке — это локальные настройки.
Список доверенных SSID также хранится только на устройстве. Совпадение выполняется точно и
регистрозависимо; точка доступа с тем же именем может подделать доверенную сеть, поэтому эту
функцию нельзя считать криптографической проверкой Wi-Fi.

## Сборка из исходников

Нужен Android SDK и JDK 17+.

```bash
cd qeli-android
./gradlew assembleDebug        # APK: app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest    # юнит-тесты config/UI adapters и бэкапа
```

Нативное ядро (`libqeli.so`) в репозитории уже собрано — пересобирать его нужно только при
изменении Rust-кода (см. `scripts/` в корне репозитория).

`reality-tls` H2 реализован именно в `libqeli.so`: установленный APK не получает его после
обновления сервера. Нужны пересборка native core, упаковка нового APK и обновление приложения.

> Инкрементальная сборка иногда раздувает APK — если размер вырос неожиданно, сделайте
> `./gradlew clean` и пересоберите.

## Shared native configuration core

The editor and portable policies require the Rust ABI 1.16 `ConfigCore` JNI service.
For JVM tests, run `python scripts/build_client_core.py --debug` from repository root
and set the printed `QELI_CONFIG_NATIVE_LIBRARY`. For APK builds, build with `--android`
and set `QELI_NATIVE_JNI_DIR` before Gradle. This replaces the jniLibs inputs.
See [shared configuration](../docs/eng/plans/CLIENT-CONFIG-CORE.md) for prerequisites and release A/B gates.


## Проверки JNI и Android runtime

JVM-тесты используют текущую host-библиотеку, указанную через
`QELI_CONFIG_NATIVE_LIBRARY`. Для тестового APK сначала соберите Android-ядро
командой `python scripts/build_client_core.py --android --debug` из корня
репозитория и передайте напечатанный `QELI_NATIVE_JNI_DIR` в окружение Gradle.
Для x86_64 эмулятора можно добавить `--abis x86_64`. Нужны NDK 26.3.11579264
и cargo-ndk 4.1.2; скрипт выбирает Android API 28 через `--platform`.

На выделенном эмуляторе после `installDebug` разрешите VPN для тестового приложения
через `adb shell appops set com.qeli ACTIVATE_VPN allow`, затем выполните
`./gradlew connectedDebugAndroidTest`. Проверяются упакованный ConfigCore JNI
(INI round-trip, отказ от JSON-конфига и поддельной ссылки), Android Keystore,
диагностический журнал и настоящий `VpnService.Builder.establish()` для трёх
сетевых планов. Это ещё не проверка передачи трафика через удалённый VPN-сервер.

Устаревший `e2e_android.py` (каталог `scripts/`), создававший JSON-конфиги и подставлявший старые
plaintext preferences, удалён. Служебные JSON-контейнеры и миграция старого
app-owned хранилища не меняются. Release A/B, arm64 и остальные runtime-режимы
проверяются отдельно от этой тестовой сборки.

Результаты прогона 24 сентября: [154 JVM + 6 Android instrumentation tests](../docs/ru/reports/audit-0.8.2/AUDIT-Q34-ANDROID-RUNTIME.md).

Сверка store 2 октября: [Q25-F210](../docs/ru/plans/AUDIT-DEBT.md). Прямая запись внешнего процесса в encrypted store в обход координации не поддерживается; после правки активного INI требуется явное переподключение.


## Legacy profile recovery и Release проверки

Неудачная миграция старой encrypted/Tink-базы сохраняет ciphertext и доступную revision,
блокирует обычную запись и разрешает только явно подтверждённый backup restore через CAS.
Системный cloud/device-transfer исключён явными правилами; для нового устройства нужен
экспорт/импорт backup. Потерянный Keystore key без backup не восстанавливается.
minSdk28 сохраняется; active index использует совместимый точный BigDecimal conversion.
[Q29 store/manifest/package](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md):
167 JVM,18 debug instrumentation PASS;Release/R8 build иlint с0errors/55warnings.
Debug test APK не является подходящим тестовым variant для minified Release. Production
signing,полный Release VPN и другие lifecycle режимы проверяются отдельно.


## Android VPN publication

Native NetworkPlan ACK starts the TUN packet pump; CONNECTED waits for Android's
VPN NetworkCallback matching plan addresses (and MTU on API29+). A fresh observer
also handles reconnect with a retained TUN and an owner excluded by per-app include.
Publication failure stops the native generation and retries while retaining
TUN/system lockdown. minSdk28 is preserved; API28 runtime is not qualified here.

ACK запускает native packet pump, а CONNECTED ждёт Android NetworkCallback с
адресами текущего плана и MTU на API29+. Новый observer работает и на прежнем TUN,
в том числе при исключённом UID владельца. При timeout генерация останавливается
для retry; TUN/системный lockdown сохраняются.
[Q29 F279: проверки и ограничения](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONNECTED-GATE.md).


## Инструментированный Release с R8

Для отдельного test APK R8 должен сохранить API общих библиотек, к которым
обращаются AndroidJUnitRunner и тесты. Matching mapping сам по себе не возвращает
удалённые классы. `-PqeliTestBuildType=release` подключает `app/instrumentation-abi.pro`:
это явно выбранный тестовый вариант, с minification/resource shrinking и дополнительным
сохранением ABI. Обычный Release без этого параметра использует прежние production-правила.
`-PqeliLabReleaseSigning=true` разрешён только для лаборатории; он подписывает APK
debug-ключом и не делает приложение debuggable.

После изменения AndroidTest или зависимостей соберите оба APK, получите classpaths,
перегенерируйте правила из pre-R8 классов и повторно соберите оба APK:

```bash
./gradlew -PqeliTestBuildType=release -PqeliLabReleaseSigning=true assembleRelease assembleReleaseAndroidTest
./gradlew -PqeliTestBuildType=release :app:printInstrumentationAbiClasspaths --console=plain > ../abi-classpaths.log
cd ..
python scripts/generate_android_instrumentation_abi.py --classpath-log abi-classpaths.log --r8-jar "$ANDROID_HOME/build-tools/36.0.0/lib/d8.jar" --android-jar "$ANDROID_HOME/platforms/android-37.0/android.jar" --evidence-dir abi-generation
cd qeli-android
./gradlew -PqeliTestBuildType=release -PqeliLabReleaseSigning=true assembleRelease assembleReleaseAndroidTest
cd ..
python scripts/generate_android_instrumentation_abi.py --classpath-log abi-classpaths.log --r8-jar "$ANDROID_HOME/build-tools/36.0.0/lib/d8.jar" --android-jar "$ANDROID_HOME/platforms/android-37.0/android.jar" --evidence-dir abi-verification --check
python scripts/check_android_instrumentation_abi.py --app qeli-android/app/build/outputs/apk/release/app-release.apk --test qeli-android/app/build/outputs/apk/androidTest/release/app-release-androidTest.apk
```

Каталоги evidence должны быть новыми; нужен JDK в `JAVA_HOME` или `PATH`.
Для другого SDK/R8 укажите фактические пути. Генератор отклоняет неизвестные
unresolved references; разрешены только известные отсутствующие platform stubs
runner и D8 bootstrap. Правила сохраняют имена ABI и разрешают R8 расширять
доступность классов: иначе перенос дочернего класса в другой пакет ломает наследование.
DEX-проверка проверяет три метода Trace и доступность superclass, но не заменяет
запуск тестов. Запускайте `connectedReleaseAndroidTest` на выделенном устройстве;
сетевым сценариям Q29 дополнительно нужен изолированный серверный fixture.

[Q29: проверка Release runner и границы результата](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-RELEASE-RUNNER.md).


## Per-app UID и Private DNS: лабораторная проверка

`scripts/build_android_network_probe.py` собирает второй framework-only пакет
из существующего AndroidTest receiver, без отдельной реализации сетевых проб.
Он предназначен только для выделенного стенда. `audit_android_data_plane_lab.py`
поддерживает `--suite app-policy --variant release --apps-mode include|exclude`:
нужны закреплённые `fixed/` APK/manifest и `probe/audit-probe.apk`/`manifest.json`.
Обвязка требует root и свой `/var/tmp/qeli-q29-data-*`, создаёт NET/MNT/PID namespaces
и readonly AVD, восстанавливает состояние. Запуск на рабочем сервере не требуется.

Проверяются два разных ordinary UID, IPv4/IPv6 TCP/UDP/DNS, семь состояний VPN/lockdown,
Private DNS off/Automatic и отрицательный strict-provider сценарий. Профиль этой
матрицы использует `kill_switch=false`, чтобы пользователь мог менять OS lockdown;
это отдельная проверка от `kill_switch=true`. Прямой трафик исключённого UID без
lockdown ожидаем; с lockdown он блокируется. Доверенный strict DoT проверяется отдельной матрицей ниже.
[Q29: результаты и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-APP-POLICY.md).


## Doze и повторные переключения сети: ограниченный прогон

`audit_android_data_plane_lab.py --suite endurance --variant release --leak-bursts`
с `--transport tcp|udp|quic` использует закреплённые `fixed/` APK/manifest в собственном
`/var/tmp/qeli-q29-data-*`: private namespaces, readonly AVD, root только на стенде.
Профиль `apps_mode=all`, `kill_switch=true`; per-app и NAT64 проверяются отдельными suites.
Три power-фазы (screen-off30s, два forcedDoze120s) и три Wi-Fi/Cellular цикла включают
IPv4/IPv6 TCP/UDP и системный DNS после пробуждений/переходов, stop/lockdown/recovery/revoke.
IDLE/экран наблюдаются каждые15s; receiver не запускается во сне. Это ограниченная
проверка AVD, без гарантии physical suspend, многочасового сна или всех API/OEM.
[Q29: результаты и оставшиеся ограничения](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-ENDURANCE.md).


## Доверенный strict Private DNS / DoT: лабораторная проверка

`audit_android_data_plane_lab.py --suite private-dns --variant release --leak-bursts`
с `--transport tcp|udp|quic`, `apps_mode=all`, `kill_switch=true` и закреплёнными fixed APK
проверяет untrusted CA, trusted CA, несовпадение SAN и восстановление. OpenSSL создаёт
короткоживущий CA только для root readonly AVD в частных namespaces; исходные CA stores
и Private DNS settings восстанавливаются. Product trust/TLS не меняются.
System lookup подтверждается A/AAAA, правильным SNI и TUN peer в TLS receipts; raw UDP
проверяется отдельно и не заменяет DoT. Bootstrap provider не смешивается с app nonce.
[Q29: результаты и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-DOT.md).


## Разрешения подключения: отмена и пересоздание Activity

Activity удерживает первоначально проверенный INI-профиль в памяти ViewModel до
завершения разрешений уведомлений/VPN. Отмена не позволяет позднему ответу запустить
сервис; редактирование или переключение профиля не подменяет уже начатый запрос.
Пересоздание Activity сохраняет запрос, смерть процесса требует нового подключения;
секреты запроса не сохраняются в Bundle или preferences.

`PermissionFlowInstrumentedTest` проверяет реальные Activity/registry/service/JNI
с инъецированной стадией ожидания и ответом. Он не автоматизирует системный диалог.
`audit_android_data_plane_lab.py --suite private-dns --variant release --leak-bursts
--ui-connect-restart --transport tcp` дополнительно проверяет обычную кнопку
отключения/подключения после OS lockdown bootstrap на выделенном readonly AVD.
Нужны закреплённые APK/manifest и частные namespaces; остальные suites/варианты
отклоняют этот opt-in до изменения стенда.
[Q29: результаты и ограничения](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-PERMISSIONS.md).


## Доверенный Wi-Fi: проверка сервиса в лабе

`audit_android_data_plane_lab.py --suite trusted-wifi --variant debug --transport tcp`
использует закреплённые fixed APK/manifest, реальный SSID readonly AVD, private
namespaces и off-pool TCP/UDP ответчики. Location/nearby Wi-Fi permissions выдаются
до instrumentation; настройки доверенной сети записываются тестом локально.
Проверяются пауза без TUN, фактический Wi-Fi/Cellular цикл, возврат payload-трафика,
отмена отложенного resume и отказ kill-switch без OS lockdown. Сокеты явно используют
VPN Network; это не Release/default-network/leak проверка. Другие варианты/транспорт
и несовместимые opt-in отклоняются до изменения стенда.
[Q29: результаты и открытые границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-WIFI.md).


## Доверенный Wi-Fi и lockdown

При `kill_switch=true` или системном Android lockdown пауза на доверенном SSID
запрещена. VPN продолжает работу и обычную смену carrier Wi-Fi/Cellular; доверенное
имя само по себе не должно отменять reconnect/roaming. Без обоих видов lockdown
явно включённая доверенная пауза сохраняет прежнее поведение.

`audit_android_data_plane_lab.py --suite handover --variant release --apps-mode all
--trusted-lockdown-handover --leak-bursts --transport tcp` включает реальный SSID
через редактор настроек production R8 и проверяет handover с OS lockdown.
Для UDP/QUIC меняется только `--transport`. Location/nearby permissions выдаются
извне; Save/readback и location foreground type наблюдаются. Служебный probe работает
от отдельного UID; matching Release instrumentation не запускается. Нужны закреплённые
APK/manifest, private namespaces и временный readonly AVD. Несовместимые suites,
варианты и per-app режимы отклоняются до изменений.
[Q29 F281: результаты и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-TRUSTED-LOCKDOWN.md).


## Владелец protect и потеря видимости SSID

Уже взятый из JNI-очереди protect request проверяет текущий core/config и отсутствие
остановки под монитором службы до выбора carrier, bind/protect и публикации upstream.
Retry sleeps и JNI ACK выполняются вне монитора. Отключение Android location visibility
не должно оставлять VPN на доверенной паузе: неизвестный SSID требует восстановления TUN.

`--suite trusted-wifi --variant debug --transport tcp` теперь объединяет пять
framework trusted-Wi-Fi сценариев, три protect owner/stop/monitor adapter проверки
с настоящими JNI socket requests и пять проверок владельца сетевого наблюдателя.
Всего 13 тестов; location/nearby permissions
выдаются извне, SSID settings задаются локально тестом. Location-switch redaction
не равна отзыву permission с возможным убийством процесса; queued pause/disconnect
не подтверждает точную точку внутри native join.
[Q29 F282–F283: результаты и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-CONTROLLER.md).

Сетевые callbacks принимаются только от текущего зарегистрированного наблюдателя,
под монитором lifecycle. При обычной остановке они отклоняются; намеренная trusted-пауза
сохраняет наблюдателя для возобновления VPN. Тесты поздней доставки используют настоящий
Android callback и carrier, но вызывают сохранённый callback напрямую на Context-attached
объекте службы; это не воспроизведение естественного порядка событий Android.

## Экспорт архива и выбор приложений

Чтение недоступного хранилища при экспорте показывает ошибку, сохраняя ciphertext.
Шифрование и запись файла выполняются вне UI-потока; успех сообщается после write/close.
Пустой stream, ошибки записи и закрытия — ошибки экспорта. Temporary bytes очищаются.
Формат архива и INI-конфигов не меняется; служебный JSON архива остаётся контейнером.

В per-app editor Save доступен после загрузки списка. Настроенные пакеты, которых нет в
Android inventory, отображаются по package name и сохраняются, пока пользователь сам
их не снимет. Доступность checkbox определяется текущим режимом, даже если он изменён
во время загрузки; закрытие диалога отменяет его job.

`audit_android_data_plane_lab.py --suite profile-ui --variant debug --transport tcp`
запускает десять сценариев: семь Activity/PackageManager/Keystore/file и три проверки
private diagnostic journal / bounded stream на disposable readonly AVD.
Тестовая инспекция dialog roots использует reflection; экспорт идёт в реальные private
`file:` destinations, не в сторонний SAF/cloud provider. Нет VPN payload в этой debug suite.
Другие варианты/транспорт отклоняются до изменения стенда.
[Q29 F284–F285: результаты и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-STORAGE-PACKAGE.md).

Update metadata ограничены4MiB; журнал при восстановлении читает ограниченный хвост.
Все imports используют общий bounded reader с прежними INI/archive budgets.
[Q29 F286–F288: source review, исправления и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-SOURCE.md).

Изменение LAN bypass в Settings запрашивает reconfiguration активного соединения;
обычный Connect сохраняет прежний guard. Ожидающий permission result не перехватывается.
`audit_android_data_plane_lab.py --suite settings-ui --variant debug --transport tcp`
выполняет три real-settings/native-pre-auth сценария без Auth/TUN/payload. Connected UI
и pending permission phase введены тестом; это не проверка LAN route reachability.
[Q29 F289: результат и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-SETTINGS.md).

Служба завершает прежний native runner/TUN перед explicit reconfiguration; Disconnect,
revoke и destroy отменяют отложенный config. Ordinary Connect не обходит generation guard.


## Dependency locks and integrity

Обычная сборка использует три committed Gradle lockfile и
`gradle/verification-metadata.xml`: проверяются транзитивные версии, SHA256 библиотек,
плагинов и их POM/module metadata. Удаление verification metadata или plugin lock
останавливает сборку; missing application lock отвергается STRICT mode.
Проверка дистрибутива wrapper и wrapper JAR остаётся отдельной.

При намеренном обновлении зависимостей сначала подготовьте production host JNI
для JVM-тестов, как описано выше. Из `qeli-android/` выполните:

```bash
./gradlew --write-locks --write-verification-metadata sha256 assembleDebug assembleRelease assembleDebugAndroidTest testDebugUnitTest
./gradlew --write-locks --write-verification-metadata sha256 lintRelease
./gradlew -PqeliTestBuildType=release --write-locks --write-verification-metadata sha256 assembleReleaseAndroidTest printInstrumentationAbiClasspaths
```

Проверьте origins и SHA256 новых файлов, обе testBuildType, штатные сборки без
write-флагов и lint. Коммитьте lockfiles/verification metadata вместе с зависимостями.
Linux-generation не добавляет автоматически SHA AAPT2 других ОС: текущие Windows/
macOS classifier JAR сверены с Google Maven; при смене AGP сверяйте их заново.
Не добавляйте write-флаги в CI или broad trusted-artifact исключения.
Неизвестный checksum требует проверки происхождения, а не отключения verification.
[Результаты и ограничения Q34](../docs/ru/reports/audit-0.8.2/AUDIT-Q34-ANDROID-DEPENDENCIES.md).


## Security versions и Maven CVE gate

`gradle/security-versions.properties` — единый список исправленных build dependency
версий для plugin classpath и project configurations. Kotlin обновляется через
buildscript classpath AGP built-in Kotlin; отдельный Kotlin Android plugin не нужен.
Это сборочная политика; формат VPN-конфигов остаётся INI.

Из корня репозитория запустите:

```bash
python3 -m unittest discover -s scripts -p test_audit_android_dependencies.py
python3 scripts/audit_android_dependencies.py
```

Gate опрашивает OSV по всем трём lockfile, включая build tooling и UTP, а также
проверяет согласованность security pins. Известная уязвимость, ошибка API, неполный
ответ или цикл пагинации приводят к ненулевому exit code; сбой сети не означает PASS.
При обновлении versions выполните матрицу генерации выше, удалите старые неиспользуемые
checksum entries и независимо проверьте новые файлы. Затем повторите gate и штатные
сборки без write-флагов. Изменение Kotlin требует JVM/R8/lint/instrumentation проверки.
[Результаты Q34](../docs/ru/reports/audit-0.8.2/AUDIT-Q34-MAVEN-SECURITY.md).


## APK licenses and Maven notices

Debug and release APKs include `assets/licenses/AGPL-3.0.txt` (native Qeli core),
`MPL-2.0.txt` (Android sources), `Apache-2.0.txt`, `MAVEN.tsv`, `ARTIFACTS.tsv`, and `INDEX.tsv`.
The per-variant Gradle generator checks the complete resolved Maven runtime graph
against `gradle/licenses/maven-runtime.tsv`. A new/removed coordinate or version
requires reviewing upstream licenses/attributions and updating this inventory
alongside the dependency locks; changing locks alone is insufficient.

The generator retains LICENSE/LICENCE/NOTICE/COPYING/COPYRIGHT resources from original
JAR/AAR artifacts, including AAR `classes.jar` and `libs/*.jar`. Files with the same
name remain separate; the index records the original coordinate/path and SHA256.
Generated assets are variant-specific and survive R8 resource shrinking. No extra
Python installation is needed to assemble an APK.

After building, run from the repository root:

```bash
python3 scripts/check_android_licenses.py --apk qeli-android/app/build/outputs/apk/debug/app-debug.apk
python3 scripts/check_android_licenses.py --apk qeli-android/app/build/outputs/apk/release/app-release-unsigned.apk
```

CI runs these checks after assembling both APKs. APKs also include the shared
`assets/licenses/native-rust/` Cargo.lock legal resource superset. The Gradle task
checks its lockfile binding/index/checksums and toolchain source inventory; the APK gate compares every native
legal asset byte for byte with the common bundle. Updating Cargo.lock requires
reviewing and regenerating this bundle, even when Maven dependencies are unchanged.
See [common bundle maintenance](../LICENSING.md).

The complete lockfile includes server/build/test/other-target dependencies and
is not a per-binary linkage list. Reviewed Rust std, Zig, NDK and GCC/MinGW
notices are preserved in `native-rust/toolchains/`. The external reviewed TSV is
a Gradle InputFile, so policy drift invalidates cached legal assets. Upstream
notices absent from this reviewed scope, matching source publication, signatures and
full release admission remain separate checks.


### Восстановление после смерти процесса

Qeli сохраняет зашифрованный INI текущего соединения и использует закрытую запись восстановления Android. На API34 после SIGKILL проверено восстановление аутентифицированного VPN; Disconnect и отзыв разрешения останавливают запись. Ограниченные окна наблюдения и оставшийся DNS/null: [результаты и границы](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-RECOVERY.md).


### Готовность подключения

`Native NetworkPlan APPLIED` подтверждает передачу TUN ядру. Пользовательский CONNECTED публикуется отдельно после Android VPN callbacks. Проверяйте новые сокеты после статуса «Подключено»; ранние отказы при CONNECTING/lockdown сохраняются как отдельное наблюдение. [Граница и результаты](../docs/ru/reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).
