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
| `android/arm64-v8a/libqeli.so` | aarch64-linux-android | 1.04 МиБ | REALITY FFI + whole-client C ABI/JNI plan handoff | `qeli-android/app/src/main/jniLibs/arm64-v8a/` → APK |
| `android/x86_64/libqeli.so` | x86_64-linux-android | 1.20 МиБ | то же (эмулятор/x86-устройства) | `qeli-android/app/src/main/jniLibs/x86_64/` → APK |
| `windows-x64/qeli.dll` | x86_64-pc-windows-gnu | 4.19 МиБ | REALITY realtls FFI (C-ABI) | `qeli-win/QeliWin/native/qeli.dll` → EmbeddedResource в .exe |
| `macos-universal/libqeli.dylib` | universal2 (arm64+x86_64) | 10.22 МиБ | REALITY realtls FFI (C-ABI) | `qeli-mac/QeliMac/native/libqeli.dylib` → Content в `.app` |
| `third-party/windows-x64/wintun.dll` | x86_64 | 418 КБ | WireGuard Wintun userspace TUN (СТОРОННЯЯ, не наша) | `qeli-win/QeliWin/wintun/wintun.dll` → EmbeddedResource |

Все `qeli`-либы (so/dll/dylib) — это ОДИН Rust-крейт `qeli`
(`crate-type = ["rlib","cdylib","staticlib"]`), C-ABI в
`src/protocol/realtls/ffi.rs` (+ JNI-модули для Android), кросс-скомпилированный под
разные таргеты. Экспорты: `qeli_realtls_{new,recv,seal,open,free,buf_free}`
(6 символов C ABI); Android дополнительно содержит 15 `qeli_client_*`, 7
`Java_com_qeli_RealTls_*` и 14 `Java_com_qeli_TransportCore_*`.

**Версия:** все собраны 2026-08-09 из дерева 0.7.15 после ABI 1.5 transport-core —
поддержка обоих cipher-suite (TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384) и
post-quantum hybrid X25519MLKEM768. Единый browser-grade отпечаток со всеми клиентами.

Windows/macOS compatibility-библиотеки пока собираются с `ffi-cdylib` и экспортируют только
текущий realtls контракт. Android с 0.7.15 собирается с `transport-core-ffi` (он включает
`ffi-cdylib`), потому что `VpnService` уже запускает whole-client lifecycle через JNI
adapter. Payload остаётся в проверенном Kotlin data plane: ABI 1.5 уже публикует канонический
NetworkPlan, принимает TUN fd и подтверждает generation, но не запускает второй reader;
наличие ABI/JNI exports не означает, что незавершённый packet pump включён. ABI 1.2 socket-protect request/ACK binding
подключён к фоновому dispatcher: shadow-сервис заявляет capability, адаптивно опрашивает ту же
bounded core queue, вызывает `VpnService.protect(fd)` с retry и возвращает ACK. Native producer
теперь создаёт неблокирующий TCP/UDP carrier и сохраняет его только после положительного ACK;
connect/handshake и packet IO в shadow-пути ещё не включены. Вторая очередь или callback не
добавлялись; общий fd-backed TUN backend уже компилируется Android NDK для следующего handoff.
ABI 1.3 дополнительно принимает существующий 16-байтный Android device ID до `start()`;
ABI 1.4 добавляет async server-identity request/ACK через ту же bounded queue и Android
`qeli_known_hosts` adapter. Общий carrier уже умеет подключить защищённый TCP/UDP socket, но
shadow runtime намеренно не вызывает connect/handshake: это не создаёт второй live-сеанс.
ABI 1.5 добавляет bounded authenticated-handshake input, 15-й whole-client C export и два JNI
bindings для publish/ACK. Android применяет routes/DNS из Rust-плана, заявляет `TUN_FD`,
передаёт generation-scoped fd и остаётся единственным packet reader до следующего этапа.

## Как собрать (всё на лаб-сервере .10/.11, на Windows Rust-тулчейна нет)

### Android (`.so`) — на .11 (есть NDK + cargo-ndk + android-таргеты)
```
cd /root/qeli   # синк свежего src сюда
ANDROID_NDK_HOME=/root/android-sdk/ndk/26.3.11579264 \
  cargo ndk -t arm64-v8a -t x86_64 \
  -o /root/android-project/app/src/main/jniLibs build --release \
  --features transport-core-ffi --lib
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
