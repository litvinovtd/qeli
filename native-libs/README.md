# native-libs — нативные зависимости сборок qeli-клиентов

Централизованная копилка нативных библиотек, которые встраиваются в клиентские
приложения. Раньше они лежали по разным местам (`qeli-android/.../jniLibs`,
`qeli-win/QeliWin/native`, `qeli-mac/QeliMac/native`, `wintun/`) — здесь собраны
в одном месте для обзора и переиспользования.

> **Это копии.** Каждый build-стек читает либу из СВОЕЙ папки (см. колонку
> «потребляется»). При обновлении либы клади и туда, и сюда (либо синкай отсюда).
> Источник Rust-кода — локальная `qeli/`; штатные скрипты каждый раз полностью синхронизируют
> его в `/opt/qeli-src` на .10 и `/root/qeli-src` на .11 перед сборкой.

## Содержимое

| Файл | Таргет | Размер | Что это | Потребляется |
|---|---|---|---|---|
| `android/arm64-v8a/libqeli.so` | aarch64-linux-android | 1.88 МиБ | ABI 1.8 whole-client core + UDP diagnostic | `qeli-android/app/src/main/jniLibs/arm64-v8a/` → APK |
| `android/x86_64/libqeli.so` | x86_64-linux-android | 2.15 МиБ | то же (эмулятор/x86-устройства) | `qeli-android/app/src/main/jniLibs/x86_64/` → APK |
| `windows-x64/qeli.dll` | x86_64-pc-windows-gnu | 4.79 МиБ | ABI 1.8 whole-client core + REALITY C ABI | `qeli-win/QeliWin/native/qeli.dll` → EmbeddedResource в .exe |
| `macos-universal/libqeli.dylib` | universal2 (arm64+x86_64) | 11.40 МиБ | ABI 1.8 whole-client core + REALITY C ABI | `qeli-mac/QeliMac/native/libqeli.dylib` → Content в `.app` |
| `third-party/windows-x64/wintun.dll` | x86_64 | 418 КБ | WireGuard Wintun userspace TUN (СТОРОННЯЯ, не наша) | `qeli-win/QeliWin/wintun/wintun.dll` → EmbeddedResource |

> **Текущий переходный статус:** лежащие в git first-party binaries ещё собраны с ABI 1.8
> (19 `qeli_client_*`), тогда как исходник уже требует ABI 1.9 и 20 экспортов. Поэтому
> `provenance.py --check` намеренно красный до повторной A/B-сборки на обеих лабах; эти старые
> binaries нельзя включать в финальный 0.7.15.

Все `qeli`-либы (so/dll/dylib) — это ОДИН Rust-крейт `qeli`
(`crate-type = ["rlib","cdylib","staticlib"]`), C-ABI в
`src/protocol/realtls/ffi.rs`, `src/transport_core/ffi.rs` и Android JNI adapter,
кросс-скомпилированный под разные таргеты. Экспорты:
`qeli_realtls_{new,recv,seal,open,free,buf_free}` (6 символов C ABI) и 19
`qeli_client_*`; Android дополнительно содержит 17 `Java_com_qeli_TransportCore_*`.
Старые Kotlin-specific RealTls/ML-KEM/KeyExchange JNI
wrappers удалены после перехода всего Android transport на whole-client core.

**Версия лежащих сейчас бинарников:** собраны 2026-08-09 из промежуточного дерева 0.7.15 с
ABI 1.8 transport-core,
поддержка обоих cipher-suite (TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384) и
post-quantum hybrid X25519MLKEM768. Единый browser-grade отпечаток со всеми клиентами.

Все три платформенных варианта собираются с `transport-core-ffi` (он включает
`ffi-cdylib`). ABI 1.6 запускает весь Android payload в Rust: protected TCP/UDP carrier,
handshake, NetworkPlan/TUN handoff, шифрование, packet pumps,
QUIC/MTU/heartbeat/shaping и bonding. ABI 1.7 добавил Windows/macOS whole-client runtime,
capability `TUN_PACKET_IO` и bounded generation-scoped `qeli_client_tun_push/pull` для
существующих Wintun/utun adapters. Rust владеет carrier, handshake, crypto, TCP/UDP/QUIC,
Reality, bonding и packet loops; C# применяет `NetworkPlan`, хранит trust/device ID и
перекладывает raw IP packets между platform TUN и нативными очередями. Фактический peer IP
carrier публикуется в плане, чтобы full-tunnel bypass не выполнял второе DNS-разрешение.
ABI 1.8 подключает к тому же packet bridge iOS и добавляет общий handle-free
`qeli_client_udp_probe`; iOS XCFramework строится отдельно на macOS/Xcode и поэтому не хранится
в этом каталоге Windows/lab-артефактов.
ABI 1.9 передаёт Wintun adapter name в Rust и переносит Wintun session/read event/rings в
единое ядро; именно поэтому все четыре first-party библиотеки должны быть пересобраны после
этого изменения, даже если platform UI-код не менялся.
ABI 1.2 socket-protect request/ACK binding подключён к фоновому dispatcher: сервис адаптивно опрашивает ту же
bounded core queue, вызывает `VpnService.protect(fd)` с retry и возвращает ACK. Native producer
теперь создаёт неблокирующий TCP/UDP carrier и сохраняет его только после положительного ACK;
connect/handshake и packet IO выполняются единственным native owner. Вторая очередь или callback не
добавлялись; общий fd-backed TUN backend работает внутри Android NDK-библиотеки.
ABI 1.3 дополнительно принимает существующий 16-байтный Android device ID до `start()`;
ABI 1.4 добавляет async server-identity request/ACK через ту же bounded queue и Android
`qeli_known_hosts` adapter. ABI 1.5 добавляет bounded authenticated-handshake input и
generation-scoped TUN fd. ABI 1.6 добавляет whole-client export `qeli_client_run`, JNI
run/stats bindings и capability `NATIVE_DATA_PLANE`; Kotlin остаётся platform/UI adapter и не
является packet reader на активном пути. 17-й JNI export — handle-free UDP first-flight
diagnostic: credential-free профиль использует тот же Rust PQ ClientHello/fragment/QUIC/obfs
builder, что рабочий transport, и останавливается на первом ответе сервера.

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
2. проверяют exact Rust 1.97.0; дополнительно desktop — Zig 0.13.0, Android — NDK
   26.3.11579264 и cargo-ndk 4.1.2; остальные фактические версии линкеров записываются;
3. полностью синхронизируют локальный Rust source на соответствующую лабу;
4. дважды собирают `--locked` с `CARGO_INCREMENTAL=0`, `panic=unwind`, remap исходного пути
   и разными чистыми `CARGO_TARGET_DIR` (`a`/`b`);
5. требуют byte-identical SHA256 для A/B и полный export gate (6 Reality + 20 client;
   Android дополнительно 17 JNI);
6. только после этого атомарно заменяют canonical/consumed копии и создают
   `native-libs/reproducibility/{desktop,android}.json`.

Раньше desktop-скрипт не синхронизировал локальный source и не забирал результат: он мог
собрать случайно оставшееся `/opt/qeli-src`, а затем позволить записать текущий digest против
чужих бинарников. Теперь `provenance.py --update` проверяет обе A/B-evidence, финальные файлы,
source digest и закреплённые версии и отказывается менять [PROVENANCE](PROVENANCE), если хотя
бы одно условие нарушено. После **обоих** lab-скриптов:

```
bash native-libs/verify.sh --update
python native-libs/provenance.py --update
```

APK после native gate собирается `scripts/rebuild_apk.py`: он использует уже проверенные
`jniLibs/*.so`, синхронизирует Kotlin, собирает и забирает APK, не затирая native cores.

### wintun.dll
Сторонняя, скачивается с https://www.wintun.net (WireGuard). Не пересобираем.
