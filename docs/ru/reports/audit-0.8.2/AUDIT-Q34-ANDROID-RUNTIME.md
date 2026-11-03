# Q34 — Android build recipe and runtime evidence

<!-- normative-sync: audit-q34-android-runtime-v1 -->

Дата: 24 сентября 2026. База: `ff2720ba8b8c444de8bbe2e94e7901614c301713`
и рабочие изменения этого этапа. Частичное закрытие D08/D11/D12
[реестра техдолга](../../plans/AUDIT-DEBT.md) для уже начатых разделов 02/22/34.
Полный аудит Android (29) этим прогоном не открывается и не закрывается.

## Q34-F002, P2 — штатная пересборка Android JNI не запускалась

`build_client_core.py --android` использовал корень репозитория как cwd, хотя
Cargo workspace находится в `qeli/`. cargo-ndk 4.1.2 читает metadata до передачи
`--manifest-path` следующей команде; исходный скрипт падал из-за отсутствия
Cargo.toml. После исправления cwd воспроизведён второй отказ: параметр `-p 28`
не является параметром Android API level. Используется `--platform 28`.

Скрипт запускает Cargo из `qeli/`; dev/CI и release A/B остаются разными рецептами.
Исправленный штатный helper собрал x86_64 JNI с Rust 1.97.0, NDK 26.3.11579264
и cargo-ndk 4.1.2, `--debug --offline --locked`, без default features,
с `transport-core-ffi`. Linux-only метод строгого sysctl lock ограничен Linux
вместо всех Unix; это убирает неиспользуемый метод из Android без изменения Linux.

## Q34-F003, P3 — устаревший Android harness проверял снятый формат

Удалён `e2e_android.py` (каталог `scripts/`): он генерировал JSON-конфиги и подставлял старые
plaintext preferences, поэтому не проверял текущий контракт INI и защищённого
хранилища. Активных CI-потребителей не обнаружено. Отдельный
`e2e_android_udpquic.py` не удалён и в этом этапе не запускался.
Служебный JSON API, тестовые fixtures и контейнеры хранилища сохраняются.

Добавлены две instrumentation-регрессии упакованного ConfigCore JNI: INI
parse/serialize/parse с `mtu_probe=off` и отказ от JSON-конфига/ссылки с внедрённой
новой строкой. Они входят в существующий `connectedDebugAndroidTest` CI.

## Проверки и происхождение артефактов

- **154 JVM-теста PASS**, без failures/errors/skipped, с текущей host DLL через JNI.
- **6 Android instrumentation-тестов PASS** на Android 14 / API 34 / x86_64:
  два ConfigCore, два Android Keystore (encrypted round-trip, tamper/AAD refusal),
  один private diagnostic journal и один production `VpnService.Builder.establish`
  для split IPv4, full IPv4 и dual-stack планов.
- **1458 host unit + 71 config integration PASS**, все 9 Rust feature/cross/lint-команд PASS.
  Rust host 1.98; cross-Clippy сохраняет прежнее единственное исключение
  `clippy::chunks_exact_to_as_chunks`, новые исключения не добавлены.
- Последний полный Linux-прогон на базе `ff2720ba`: **1922 + 28 privileged + 8 worker
  lifecycle E2E PASS**. После cfg-only изменения полный Linux набор повторно не
  запускался; cross-check выполнен, Linux-ветка кода не меняется.

APK собран Gradle 9.7.1 с `QELI_NATIVE_JNI_DIR`, который заменяет committed jniLibs.
Проверено содержимое ZIP: только свежая x86_64 libqeli.so; её хеш совпадает с
результатом Linux-сборки. Dev x86_64 не подтверждает arm64 или release A/B.

| Артефакт | SHA256 |
|---|---|
| Host DLL | `0810991935ef02423c2e0d2be0454ac6bfd1de0d3991dc472512ee3a1a78126f` |
| Android libqeli.so | `4927d240f5f0264ae226e43c948d0538fb1187d3bc517ca695af02013fadb542` |
| app-debug.apk | `e7720d27062687c11a3c4689190fa7027de59b1aafea42d52a955c9947ab3eae` |
| app-debug-androidTest.apk | `9e01ed8cfcd00a54ed31c1243d25660a0fd71cdf40a0a92b6c4bcd5fb36a4aa7` |

Стенд — выделенный read-only сеанс AVD `test` на клиентской Linux VM, emulator
36.6.11.0, без загрузки/сохранения snapshot. Для запуска установлен отсутствовавший
libxkbfile1. Сохранённые записи старых подписей main/test APK удалены только внутри
одноразового сеанса. Диагностический `ip link` выполнен через `su 0`: Android
запрещает netlink обычному ADB shell. Сам instrumentation выполняется обычным
Android test runner. Неудачные подготовительные попытки сохранены отдельно.

После force-stop приложения TUN отсутствует; после остановки эмулятора размеры,
mtime и SHA256 оригинальных userdata images совпадают с исходными. Рабочий сервер
Qeli и его конфиги не изменялись.

Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/`:
`android-runtime-phase/` (build/JVM/matrix/source manifests),
`android-runtime-evidence-4/` и `android-instrumented-netdiag.log` (финальный PASS).
`android-runtime-evidence`, `-2`, `-3` — подготовительные отказы, не успешные тесты.

## Что остаётся

Не проверены VPN handshake/трафик с удалённым сервером, roaming/soak, другие Android
API/ABI, Windows network runtime, Mac/iOS/router runtime и release A/B/provenance.
D08 и D11 остаются IN_PROGRESS; D12 содержит неподтверждённые внешние стенды.
Полная матрица конфигов и новый benchmark открыты. Предупреждения Gradle/Java и
существующее deprecated Android API не считаются устранёнными этой проверкой.

[Как повторить](../../../../qeli-android/README.md) · [Общее ядро](../../plans/CLIENT-CONFIG-CORE.md)
