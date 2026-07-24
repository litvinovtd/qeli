# qeli-android

Android-клиент qeli: системный VPN через `VpnService` (весь трафик и DNS на уровне ОС, не
пер-приложенческий прокси). Протокол, обфускация и крипто-канал — те же, что у остальных
клиентов; настоящий TLS 1.3 (`realtls`) и ML-KEM подключаются из общего Rust-ядра через JNI.

- Общая карта документации — [docs/ru/index.md](../docs/ru/index.md)
- Подключение «с нуля» (выдача `qeli://` на сервере) — [GETTING-STARTED §8.1](../docs/ru/GETTING-STARTED.md)
- Все ключи конфигурации — [CONFIG.md](../docs/ru/CONFIG.md)
- Если не подключается — [TROUBLESHOOTING.md](../docs/ru/TROUBLESHOOTING.md)

## Технологии

- **Kotlin**, `minSdk 28` (Android 9), `targetSdk 37`, Material Components.
- **`VpnService`** — TUN-интерфейс, маршруты, DNS, per-app split tunnel.
- **JNI к Rust-ядру** (`libqeli.so`, `app/src/main/jniLibs/{arm64-v8a,x86_64}/`) —
  `RealTls.kt` (настоящий TLS 1.3 для `reality-tls`) и `MlKem.kt` (ML-KEM-768 для
  PQ-гибрида). Остальная часть клиента — нативный Kotlin.
- Foreground-сервис со `specialUse`-типом: туннель живёт, пока приложение свёрнуто.

## Структура

```
app/src/main/kotlin/com/qeli/
├── MainActivity.kt        — UI: профили, импорт (QR/ссылка/файл), лог, настройки, бэкап
├── QeliService.kt         — VpnServiceImpl: хендшейк, data-plane, маршруты/DNS, reconnect
├── ProfileStore.kt        — хранилище профилей (EncryptedSharedPreferences)
├── QeliTileService.kt     — плитка в «Быстрых настройках»
├── QeliWidgetProvider.kt  — виджет на рабочий стол
├── BootReceiver.kt        — автоподключение после перезагрузки
├── RealTls.kt / MlKem.kt  — JNI-обвязка Rust-ядра
├── TrafficShaper.kt       — исходящий шейпинг/cover-трафик
├── UpdateChecker.kt       — проверка обновлений (opt-in)
├── crypto/                — ChaCha20, HKDF, PacketCipher, BackupCrypto
├── protocol/              — ObfsStream, TlsHandshake, Quic, packet codec
└── model/Config.kt        — разбор/сборка flat-INI и `qeli://`
```

## Возможности

| Возможность | Как работает |
|---|---|
| **Импорт профиля** | QR-код (камера), вставка `qeli://`-ссылки, тап по `qeli://`-ссылке (deep link), файл в формате flat-INI или legacy-JSON |
| **Per-app split tunnel** | Выбор приложений в режиме «только эти» (`addAllowedApplication`) или «кроме этих» (`addDisallowedApplication`) |
| **Плитка Quick Settings** | Подключение/отключение из шторки |
| **Виджет** | Статус и переключение с рабочего стола |
| **Автоподключение** | После перезагрузки (`BOOT_COMPLETED`) и/или при запуске приложения |
| **Доступ к локальной сети** | Тумблер «разрешить LAN» при full-tunnel (принтеры, NAS, роутер) |
| **Бэкап профилей** | Экспорт/импорт JSON; **с парольной фразой** — шифрованный контейнер (PBKDF2-HMAC-SHA256 + AES-256-GCM), совместимый с десктопом. Пустая фраза = **открытый JSON с паролями** |
| **Формат времени в логе** | Пять вариантов, совпадают с серверным `[logging] time_format` — удобно сверять логи |
| **Проверка обновлений** | Opt-in, выключена по умолчанию |

## Разрешения и зачем они

| Разрешение | Зачем |
|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE` | сеть и реакция на её смену (Wi-Fi ⇄ LTE) |
| `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_SPECIAL_USE` | туннель как foreground-сервис |
| `POST_NOTIFICATIONS` | уведомление активного туннеля (Android 13+) |
| `WAKE_LOCK` | не терять соединение в глубоком сне |
| `RECEIVE_BOOT_COMPLETED` | автоподключение после перезагрузки (если включено) |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | чтобы система не убивала туннель |
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

## Сборка из исходников

Нужен Android SDK и JDK 17+.

```bash
cd qeli-android
./gradlew assembleDebug        # APK: app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest    # юнит-тесты (крипто, obfs-фрейминг, бэкап)
```

Нативное ядро (`libqeli.so`) в репозитории уже собрано — пересобирать его нужно только при
изменении Rust-кода (см. `scripts/` в корне репозитория).

> Инкрементальная сборка иногда раздувает APK — если размер вырос неожиданно, сделайте
> `./gradlew clean` и пересоберите.
