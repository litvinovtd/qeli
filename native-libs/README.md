# native-libs — нативные зависимости сборок qeli-клиентов

Централизованная копилка нативных библиотек, которые встраиваются в клиентские
приложения. Раньше они лежали по разным местам (`qeli-android/.../jniLibs`,
`qeli-win/QeliWin/native`, `qeli-mac/QeliMac/native`, `wintun/`) — здесь собраны
в одном месте для обзора и переиспользования.

> **Это копии.** Каждый build-стек читает либу из СВОЕЙ папки (см. колонку
> «потребляется»). При обновлении либы клади и туда, и сюда (либо синкай отсюда).
> Источник Rust-кода — локальная `qeli/`; штатные скрипты каждый раз полностью синхронизируют
> его в собственные `/var/tmp/qeli-native-repro/desktop-source` на .10 и
> `/var/tmp/qeli-native-repro/android-source` на .11 перед сборкой. Каталоги исходников
> работающих сервисов не используются.

Предыдущая [сверка 7 октября 2026](../docs/ru/reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md): четыре свежих независимых A/B, все копии/SHA и PROVENANCE PASS; Windows C ABI и Android JNI проверены на пересобранных библиотеках. Mac runtime остаётся исключённым пользователем.

Историческая [квалификация 8 октября, F451–F454](../docs/ru/reports/audit-0.8.2/AUDIT-Q34-DEPENDENCY-POLICY.md): source1751a44f, свежие независимые A/B четырёх native targets, export gates/14SHA/copies/provenance и Windows ABI22 PASS. В пакет входят Rust dependency/CI policy и PEM TLS; Linux unit2445+60ignored/CLI5/14HTTPS/feature/release-checks PASS. Reproducibility проверена внутри собственного CargoHome; новый Android полный runtime и Mac/iOS runtime не заявлены. Q34 остаётся IN_PROGRESS; [завершённый Q33](../docs/ru/reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md) сохранён.

## Содержимое

Повторная пересборка 31 октября 2026 для `dev` 0.8.4 после сжатия CLI-лицензий:
Windows x64, macOS universal2 и обе Android ABI собраны из одного чистого
source cut `32312291`, source digest
`8e5226ae18230e9058c662be4a5d5311f382861a2491491ad857c29855a9aac0`.
Независимые A/B совпали побайтово; проверены ABI 1.17 exports и canonical/consumed пары.
Все четыре бинарника также совпали с предыдущим набором из `7a949489`: CLI-декодер
не входит в FFI. Это результат свежей полной A/B-пересборки, а не переноса старого
evidence на новый digest. Windows managed conformance self-test с этой DLL
завершился `ALL PASS` (671 проверка), включая отсутствие
аллокаций текста при повторном чтении неизменного лога (0 B в измеренном цикле).
Результаты сборок: [desktop](reproducibility/desktop.json) и
[Android](reproducibility/android.json). Это обновление native cores, не публикация
релиза и не замена отдельным физическим Mac/Android/iOS runtime-проверкам.

Предыдущая пересборка 17 октября 2026 после интеграции `tun.tx_queue_len` в `dev`:
четыре свежих независимых A/B и проверка экспортов/копий прошли; source digest —
`42672aca87de8e95b2e289cad35b576196f88e92874d121e1804e7845152976b`.
[Идентификаторы native и SDK source cut](../release/certification/evidence/integrated-source-build-20261017.json).
Это проверка ядер и экспорта исходников; квалификация приложений и Linux runtime
фиксируется отдельно, физические платформенные проверки этим не объявляются выполненными.

Текущий ABI общего Rust-клиента — **1.17** (`qeli/src/transport_core/mod.rs`),
включая versioned carrier diagnostics. API редактора конфигурации добавлен в ABI 1.16.
Проверяемые SHA-256 каждой canonical/consumed пары записаны в
[SHA256SUMS](SHA256SUMS), соответствие исходникам — в
[PROVENANCE](PROVENANCE), а два независимых прохода сборки — в
`reproducibility/{desktop,android}.json`. После любой правки Rust-исходников
или build-рецептов эти проверки обязаны выполняться заново.

| Файл | Таргет | Потребляется |
|---|---|---|
| `android/arm64-v8a/libqeli.so` | aarch64-linux-android | `qeli-android/app/src/main/jniLibs/arm64-v8a/` → APK |
| `android/x86_64/libqeli.so` | x86_64-linux-android | `qeli-android/app/src/main/jniLibs/x86_64/` → APK |
| `windows-x64/qeli.dll` | x86_64-pc-windows-gnu | `qeli-win/QeliWin/native/qeli.dll` → EmbeddedResource |
| `macos-universal/libqeli.dylib` | universal2 (arm64+x86_64) | `qeli-mac/QeliMac/native/libqeli.dylib` → `.app` Content |
| `third-party/windows-x64/wintun.dll` | x86_64 | `qeli-win/QeliWin/wintun/wintun.dll` |
| `third-party/windows-x64/windivert/WinDivert.dll` и `WinDivert64.sys` | x86_64 | `qeli-win/QeliWin/windivert/` |

Все четыре first-party библиотеки собираются из одного Rust-крейта `qeli`
с `--no-default-features --features transport-core-ffi`; серверный/web stack
в них не входит. Экспортная поверхность содержит 6 Reality C ABI,
23 `qeli_client_*`, `qeli_config_request` (чистый API редактора INI),
а Android дополнительно требует 22 `Java_com_qeli_TransportCore_*`.
Платформенные приложения хранят интерфейс, системные разрешения и TUN;
общее ядро выполняет parsing/policy, transport, handshake и data plane.
Исходный `qeli/src/client` Linux `rp_filter` код компилируется только для Linux
и не меняет API этих библиотек, но изменение общего исходного дерева всё равно
требует новой подтверждённой A/B сборки и provenance. iOS XCFramework
собирается отдельно с macOS/Xcode и не хранится в этом каталоге.

## Как собрать (всё на лаб-сервере .10/.11, на Windows Rust-тулчейна нет)

Штатный путь требует чистых и закоммиченных `qeli/src`, `Cargo.toml` и `Cargo.lock`, а пароль
лабы получает только из `QELI_LAB_PASS` (пользователь — `QELI_LAB_USER`, по умолчанию
`root`). Desktop строится на `.10`, Android — на `.11`:

```powershell
python scripts/build_native_libs_p4.py   # qeli.dll + universal2 libqeli.dylib
python scripts/build_android_so_11.py    # arm64-v8a + x86_64 libqeli.so
```

Оба скрипта используют один контракт `qeli-native-repro-v1`:

1. фиксируют commit, source digest и `SOURCE_DATE_EPOCH`, проверяют чистоту исходников;
2. до очистки прошлых pass roots требуют минимум 8 GiB свободного места на `/var/tmp`;
   при недостатке места или ошибке inventory ничего не удаляют. Проверяют exact Rust 1.97.0; дополнительно desktop — Zig 0.13.0,
   cargo-zigbuild 0.23.0, GNU ld 2.44 и apple-codesign 0.29.0, Android — NDK
   26.3.11579264 и cargo-ndk 4.1.2; необходимые Rust targets ставятся идемпотентно;
3. полностью синхронизируют локальный Rust source на соответствующую лабу;
4. дважды собирают `--locked --jobs 1` с `CARGO_INCREMENTAL=0`, `panic=unwind`, remap исходного пути
   и разными чистыми `CARGO_TARGET_DIR` (`a`/`b`); после сохранения конечного файла тяжёлый
   target-кэш прохода удаляется, чтобы A/B укладывался в свободное место лабы;
5. требуют byte-identical SHA256 для A/B и полный export gate (6 Reality + 23 client;
   Android дополнительно 22 JNI). Для macOS до ad-hoc подписи нормализуются случайный
   `LC_UUID` и недопустимый нестабильный Zig 0.13 GOT-index, install name закреплён как
   `@rpath/libqeli.dylib`;
6. только после этого атомарно заменяют canonical/consumed копии и создают
   `native-libs/reproducibility/{desktop,android}.json`.

SSH/SFTP, ограниченный source-sync, проверка удалённого SHA256 и атомарный pull реализованы
один раз в `scripts/native_lab.py`; обязательные A/B-проходы — в `scripts/native_repro.py`.
CI запускает regression/unit-тесты этих контрактов, включая отказ до записи при несовпадении хеша,
запрет destination вне репозитория, строгий toolchain и гарантию, что выполняются оба прохода
`a` и `b`, а также точное совпадение распознаваемых ключей конфигурации Rust/Android/
Windows/macOS/iOS.

На сервере с недостатком места сначала сохраните результаты предыдущих прогонов и
освободите только проверенные неиспользуемые временные каталоги. Скрипты не выполняют
общую очистку SDK, registry, toolchains или чужих данных. Desktop и Android используют
разные source/pass roots; одновременные запуски одной группы на одном сервере пока не
поддерживаются. Один Cargo job ограничивает параллелизм, но не обещает верхний предел RSS.

Раньше desktop-скрипт не синхронизировал локальный source и не забирал результат: он мог
собрать случайно оставшееся `/opt/qeli-src`, а затем позволить записать текущий digest против
чужих бинарников. Теперь `provenance.py --update` проверяет обе A/B-evidence, финальные файлы,
source digest и закреплённые версии и отказывается менять [PROVENANCE](PROVENANCE), если хотя
бы одно условие нарушено. После **обоих** lab-скриптов:

```
bash native-libs/verify.sh --update
python native-libs/provenance.py --update
```

APK после native gate собирается `scripts/rebuild_apk.py [--release]`: он использует уже
проверенные `jniLibs/*.so`, одним удалённым preflight создаёт каталоги синхронизации,
собирает unit tests + APK, проверяет подпись release-варианта и забирает файл только после
сверки удалённого SHA256, не затирая native cores. `scripts/build_mac_universal.py` так же
проверяет canonical dylib, пакетно подписывает и инспектирует каждый Mach-O и атомарно
забирает universal ZIP по SHA256. Каждый запуск Mac packager использует собственный remote workspace:
оба self-contained TAR и metadata передаются с SHA-проверкой, общий кэш не используется.
Unsafe TAR/stale canonical dylib отклоняются до SSH; соединения закрываются при ошибках.
Remote workspace сохраняется для диагностики; локальный ZIP заменяется только после SHA gate.
Если verified remote SHA256 уже совпадает со всеми локальными копиями, итоговый бинарник/ZIP
также не передаётся повторно.

### wintun.dll
Сторонняя, официальный Wintun **0.14.1** с https://www.wintun.net (WireGuard),
SHA-256 `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`.
Не пересобираем. Windows CI выполняет `scripts/verify_windows_drivers.ps1`: проверяет
FileVersion обеих копий, SHA-256 и валидную Authenticode-подпись `WireGuard LLC`
(certificate thumbprint `DF98E075A012ED8C86FBCF14854B8F9555CB3D45`). Замена бинарника требует
явного обновления версии, хеша и signer pin после проверки официального upstream archive.

### WinDivert (WinDivert.dll + WinDivert64.sys)
Сторонняя, официальный релиз 2.2.2 с https://reqrypt.org/windivert.html
(LGPL-3.0 OR GPL-2.0). Не пересобираем. NOTICE/LICENSE находятся в
`third-party/windows-x64/windivert/`. После замены обеих копий выполнить
`bash native-libs/verify.sh --update`.
