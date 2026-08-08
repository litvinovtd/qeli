# native-libs — нативные зависимости сборок qeli-клиентов

Централизованная копилка нативных библиотек, которые встраиваются в клиентские
приложения. Раньше они лежали по разным местам (`qeli-android/.../jniLibs`,
`qeli-win/QeliWin/native`, `qeli-mac/QeliMac/native`, `wintun/`) — здесь собраны
в одном месте для обзора и переиспользования.

> **Это копии.** Каждый build-стек читает либу из СВОЕЙ папки (см. колонку
> «потребляется»). При обновлении либы клади и туда, и сюда (либо синкай отсюда).
> Источник Rust-кода — `/opt/qeli-src` на лаб-сервере .10 (= локальная `qeli/`).

## Содержимое

| Файл | Таргет | Размер | Что это | Потребляется |
|---|---|---|---|---|
| `android/arm64-v8a/libqeli.so` | aarch64-linux-android | 670 КиБ | REALITY realtls FFI + JNI-мост | `qeli-android/app/src/main/jniLibs/arm64-v8a/` → APK |
| `android/x86_64/libqeli.so` | x86_64-linux-android | 761 КиБ | то же (эмулятор/x86-устройства) | `qeli-android/app/src/main/jniLibs/x86_64/` → APK |
| `windows-x64/qeli.dll` | x86_64-pc-windows-gnu | 4.11 МиБ | REALITY realtls FFI (C-ABI) | `qeli-win/QeliWin/native/qeli.dll` → EmbeddedResource в .exe |
| `macos-universal/libqeli.dylib` | universal2 (arm64+x86_64) | 9.93 МиБ | REALITY realtls FFI (C-ABI) | `qeli-mac/QeliMac/native/libqeli.dylib` → Content в `.app` |
| `third-party/windows-x64/wintun.dll` | x86_64 | 418 КБ | WireGuard Wintun userspace TUN (СТОРОННЯЯ, не наша) | `qeli-win/QeliWin/wintun/wintun.dll` → EmbeddedResource |
| `third-party/windows-x64/windivert/WinDivert.dll` + `WinDivert64.sys` | x86_64 | — | WinDivert 2.2.2 (СТОРОННЯЯ, LGPL-3.0 OR GPL-2.0) — per-app divert | `qeli-win/QeliWin/windivert/` → EmbeddedResource |

Все `qeli`-либы (so/dll/dylib) — это ОДИН Rust-крейт `qeli`
(`crate-type = ["rlib","cdylib","staticlib"]`), C-ABI в
`src/protocol/realtls/ffi.rs` (+ `jni.rs` для Android), кросс-скомпилированный под
разные таргеты. Экспорты: `qeli_realtls_{new,recv,seal,open,free,buf_free}`
(6 символов C-ABI) и на Android дополнительно 7 `Java_com_qeli_RealTls_*`.

**Версия:** все собраны 2026-08-08 из дерева 0.7.15 после первого этапа transport-core —
поддержка обоих cipher-suite (TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384) и
post-quantum hybrid X25519MLKEM768. Единый browser-grade отпечаток со всеми клиентами.

Эти compatibility-библиотеки пока собираются с `ffi-cdylib` и экспортируют только текущий
realtls/JNI контракт. Новый whole-client ABI включается отдельным `transport-core-ffi` и
появится в клиентских артефактах при миграции первого адаптера; существующие клиенты не
переключены на незавершённый data plane.

## Как собрать (всё на лаб-сервере .10/.11, на Windows Rust-тулчейна нет)

### Android (`.so`) — на .11 (есть NDK + cargo-ndk + android-таргеты)
```
cd /root/qeli   # синк свежего src сюда
ANDROID_NDK_HOME=/root/android-sdk/ndk/26.3.11579264 \
  cargo ndk -t arm64-v8a -t x86_64 \
  -o /root/android-project/app/src/main/jniLibs build --release --lib
```
Скрипт: `scripts/build_so_p3.py` (синк+сборка .so). APK собирается ОДНИМ скриптом
`scripts/rebuild_apk.py` (пушит jniLibs/*.so → синк Kotlin → build → pull APK; не
затирает jniLibs).

### Windows (`qeli.dll`) — на .10 (rustup x86_64-pc-windows-gnu + mingw)
```
cd /opt/qeli-src
cargo build --release --lib --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/qeli.dll
```

### macOS (`libqeli.dylib`) — на .10 (cargo-zigbuild + zig 0.13)
```
cd /opt/qeli-src
RUSTFLAGS="-C link-arg=-Wl,-headerpad_max_install_names" \
  cargo zigbuild --release --lib --target universal2-apple-darwin
# -> target/universal2-apple-darwin/release/libqeli.dylib  (headerpad нужен для rcodesign)
```
Win+Mac разом: `scripts/build_native_libs_p4.py` — он же **забирает** обе библиотеки в
дерево (в `native-libs/` и в ту копию, которую потребляет сборка). Раньше не забирал:
скрипт печатал «pull with the next step», а никакого следующего шага не существовало, и
ни один другой скрипт эти два файла не копирует. Поэтому пересборка оставляла свежие
ядра на .10, а в репозитории — старые, после чего `provenance.py --update` записывал
текущий digest исходников против бинарников, которые из них не собирались, — ровно та
ложь, ради предотвращения которой [PROVENANCE](PROVENANCE) и заведён, причём невидимая в
ревью: все контрольные суммы сходятся друг с другом, просто не с исходниками. Так через
дерево прошло **три** коммита «rebuild the FFI cores» со старыми win/mac ядрами (Android
свою `.so` забирал всегда). После сборки:

```
bash native-libs/verify.sh --update
python native-libs/provenance.py --update
```

### wintun.dll
Сторонняя, скачивается с https://www.wintun.net (WireGuard). Не пересобираем.

### WinDivert (WinDivert.dll + WinDivert64.sys)
Сторонняя, официальный релиз 2.2.2 с https://reqrypt.org/windivert.html
(LGPL-3.0 OR GPL-2.0). Не пересобираем. NOTICE/LICENSE — в
`third-party/windows-x64/windivert/`. После замены обеих копий:
`bash native-libs/verify.sh --update`.
