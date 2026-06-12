# Порт qeli-клиента на Keenetic (dual-arch: mipsel + aarch64)

Статус: **Фаза 1 в работе** (код-скелет применён, ждёт лаб-сборки). Цель — гонять
существующий Linux-клиент `qeli` на роутерах Keenetic под Entware, **сразу под обе
арки** модельного ряда: MIPS (mipsel) и ARM (aarch64). Без написания нового
нативного клиента — переиспользуем демон.

## 1. Вывод по осуществимости

Keenetic — это Linux. Полноценный `qeli client` уже Linux-only (TUN через
`/dev/net/tun` + `ioctl(TUNSETIFF)`), так что на роутер ставится тот же демон,
кросс-собранный под CPU роутера.

Единственный жёсткий блокер — **`ring`** (через `rustls`): у него нет MIPS-бэкенда.
Но `ring`/`rustls`/`rcgen` используются **только на серверной стороне**
(`protocol/realtls/server.rs`, `server/mod.rs`, `server/reality.rs`) плюс в
тестах/доках. Клиентский путь, включая `reality-tls`, **рукописный на RustCrypto**
(`realtls/{client,stream,sansio,keyschedule,record,clienthello}.rs`) — чистый Rust,
портируется на любую арку. Значит **client-only сборка без `ring` собирается** после
фич-рефактора (ниже), одинаково под mipsel и aarch64.

## 2. Целевая матрица

| Target | Покрывает | Класс Rust | Крипто на железе |
|---|---|---|---|
| `aarch64-unknown-linux-musl` | новые WiFi6 (Cortex-A53: Hopper, Peak/Filogic MT7981) | tier-1/2, std из rustup | ARMv8 crypto-ext → AES-GCM быстрый, `reality-tls` ок |
| `mipsel-unknown-linux-musl` | основной парк (MT7621/MT7628: Giga/Ultra/Viva/...) | **tier-3**, нужен `-Zbuild-std` | софт ChaCha20 → `obfs`/`fake-tls`/`plain` |
| *(опц.)* `mips-unknown-linux-musl` (BE) | редкие модели на Realtek | tier-3 | как mipsel |

Оба основных таргета — **статический musl** (один бинарь в `/opt/bin`). Big-endian
по умолчанию НЕ собираем.

> Перед фиксацией тулчейнов снять с устройств `opkg print-architecture` (точная
> ABI-строка, особенно mipsel: o32/float) и `cat /proc/cpuinfo` (FPU/crypto-ext).

## 3. Единый код под обе арки (Фаза 1)

Принцип: **архитектурно-специфичного Rust-кода ноль**. Разница уходит в (а) фичи
Cargo и (б) тулчейн/рантайм. Идентичный по поведению бинарь под любой target.

### 3.1 Фич-флаги (Cargo.toml)

`rustls/tokio-rustls/rcgen/axum/tower/qrcode` → `optional = true`, включаются только
фичей `server`. Введены:

```toml
[features]
default    = ["server", "client"]   # обычная серверная сборка — как раньше
server     = ["dep:rustls", "dep:tokio-rustls", "dep:rcgen", "dep:axum", "dep:tower", "dep:qrcode"]
client     = []
# Отдельный standalone-бинарь клиента (роутеры/Keenetic). ВЫКЛ по умолчанию,
# чтобы серверные/CI/FFI-сборки оставались байт-идентичными прежним.
client-bin = ["client"]
```

`default` сохраняет `server`+`client` → `cargo build` без флагов компилирует ровно
то же, что и до правок (server + web + realtls::server + FFI-cdylib для
Android/Win/Mac не затронуты).

### 3.2 Гейтинг модулей

- `lib.rs`: `client`/`tun` → `feature="client"`; `server`/`web`/`transport` →
  `feature="server"` (плюс существующий `target_os="linux"`).
- `protocol/realtls/mod.rs`: `pub mod server` → `#[cfg(feature="server")]`.
  Клиентские подмодули (`client/stream/sansio/keyschedule/record/clienthello/ffi`)
  остаются всегда (нужны и Linux-клиенту, и FFI win/mac). Ссылки на `realtls::server`
  вне server-модулей есть только в `#[cfg(test)]` — сборка client-only их не
  компилирует, а `cargo test` идёт с дефолтными фичами (server вкл).

### 3.3 portable-atomic (нужен только 32-бит mipsel)

На 32-бит mipsel нет 64-битных атомиков (`target_has_atomic="64"` = false) →
`std::sync::atomic::AtomicU64` отсутствует, и код без правок **не компилируется**.
`AtomicU64` в проде используется только в `client/mod.rs` (счётчики статы/`last_rx`;
в `server/{handler,udp_handler}.rs` — но это server-only, в client-сборку не входит).

Решение: зависимость `portable-atomic = "1"` и в `client/mod.rs`
`use portable_atomic::AtomicU64;` вместо std. На aarch64/x86_64 маппится на нативную
инструкцию (цена ноль), на mipsel — lock-fallback. Один путь кода для обеих арок.
`tokio` свои внутренние `AtomicU64` уже шими́т сам (`loom/std/atomic_u64.rs`).

### 3.4 Точка входа

Новый бинарь `src/client_main.rs` (только подкоманда client), `required-features
= ["client-bin"]`. Существующий `main.rs` **не трогаем**: бинарь `qeli`
помечается `required-features = ["server","client"]`, поэтому client-only сборка его
пропускает. Так default-сборка никогда не компилирует новый файл — нулевой риск для
рабочих сборок.

Команда Keenetic-сборки:
```sh
cargo build --release --bin qeli-client \
  --no-default-features --features client-bin --target <TARGET>
```
`--no-default-features` гасит `server` → `rustls/ring/axum/...` не компилируются.

## 4. Тулчейны (на лабе .10) — обе арки через zig ✅

Линкер/cc для обеих арок — **zig 0.13** (уже стоит на .10) через `cargo-zigbuild`.
OpenWrt SDK НЕ понадобился. Канонический скрипт — `scripts/build_keenetic.py`
(idempotent-сетап nightly+rust-src+aarch64-target+cargo-zigbuild, сборка обеих арок,
strip, пулл в `release/keenetic/`). Разведка тулчейна — `scripts/keenetic_toolchain_probe.py`.

### aarch64 (stable, std из rustup) → ~2.3 МБ, static ARM aarch64
```sh
rustup target add aarch64-unknown-linux-musl
cargo zigbuild --release --bin qeli-client \
  --no-default-features --features client-bin --target aarch64-unknown-linux-musl
```

### mipsel (tier-3: nightly + build-std) → ~3.3 МБ, static-pie MIPS32r2 LE
```sh
rustup toolchain install nightly -c rust-src
# Rust компилит mipsel в soft-float, а zig линкует mips как fpxx → конфликт float-ABI.
# Принуждаем линковку к soft-float (бинарь не трогает FPU — идёт на любом mips):
RUSTFLAGS='-C link-arg=-msoft-float' cargo +nightly zigbuild \
  -Z build-std=std,panic_abort --release --bin qeli-client \
  --no-default-features --features client-bin --target mipsel-unknown-linux-musl
```

### Gotchas, всплывшие при кросс-сборке (оба арк-специфичны — видны ТОЛЬКО тут, не на x86)
- **TUNSETIFF** (`tun/iface.rs`): тип запроса `ioctl` — `c_ulong` на glibc, но `c_int`
  на musl (кастуем `as _`); на MIPS другая кодировка `_IOW` → значение `0x800454ca`,
  а не `0x400454ca` (выбор через `cfg(target_arch="mips")`). Иначе ioctl упал бы в
  рантайме на живом Кинетике, хотя на x86 всё «зелено».
- **float-ABI mipsel**: `-msoft-float` на линковке (см. выше).

### CI
- В `ci.yml` добавить обе цели в build-матрицу клиентов (гейт, чтобы кросс-сборка под
  обе арки не отвалилась незаметно).

## 5. Рантайм на роутере (одинаково для обеих арок)

📖 **Пошаговый деплой с командами и проверкой туннеля — [KEENETIC-DEPLOY.md](KEENETIC-DEPLOY.md).**
Ниже — обзор, полный гайд там.

1. **Entware** установлен (opkg, `/opt`). Бинарь → `/opt/bin/qeli-client`.
2. `opkg install ip-full iptables` — клиент шеллит в `ip addr/route/link/tuntap`
   (`tun/iface.rs`, `client/route.rs`); busybox-`ip` Keenetic'а урезан (нет `tuntap`).
3. **`/dev/net/tun`**: должен быть (включить VPN-компонент KeeneticOS — WireGuard/
   OpenVPN — он тянет tun-модуль). Проверка: `ls -l /dev/net/tun`.
4. Конфиг `/opt/etc/qeli/client.conf` (секция `[qeli]`), импорт из `qeli://`-ссылки.
5. **device-id на персистентный путь**: по умолчанию `/var/lib/qeli/device-id`, на
   роутере `/var` часто tmpfs (теряется при ребуте → сервер каждый раз видит «новое
   устройство», тратит слот). В init-скрипте задать
   `QELI_DEVICE_ID_FILE=/opt/etc/qeli/device-id` (env-override уже есть в коде).
6. **DNS — не трогать resolv.conf роутера**: `dns.mode = off`/`manual` в конфиге
   (`client/dns.rs::setup_dns_for_interface` делает early-return при `mode != tunnel`).
   DNS LAN-клиентов — через штатный dnsmasq/ndnsproxy Keenetic.
7. Автозапуск: `/opt/etc/init.d/S99qeli` (start/stop), от root. Авто-reconnect и
   устойчивость к смене IP/линка в клиенте уже есть.

## 6. Режим шлюза — роутер как VPN для всего LAN

Клиент спроектирован как endpoint и **NAT сам не ставит**. Для заворота LAN:

```sh
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o vpn0 -j MASQUERADE
iptables -A FORWARD -i br0 -o vpn0 -j ACCEPT
iptables -A FORWARD -i vpn0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

Два под-режима маршрутизации:
- **Full-tunnel**: весь трафик LAN в туннель. Клиент уже умеет ставить default route
  через tun + bypass-маршрут до сервера (`client/route.rs`, `add_default_gateway`/
  `full-tunnel`). Включается в `[routing]`.
- **Селективный (по доменам/IP)**: `ipset` + `iptables` + dnsmasq-роутера (паттерн как
  у kvas/antizapret на Keenetic). Гибче и дружелюбнее к скорости.

> ⚠️ Самая капризная часть: взаимодействие с собственным firewall/NAT KeeneticOS
> зависит от модели и версии прошивки — проверять на живом устройстве.

## 7. Производительность и выбор wire-режима

| | mipsel (MT7621 ~880МГц, без AES-NI) | aarch64 (A53 + crypto-ext) |
|---|---|---|
| Рекоменд. режим | `obfs`/`fake-tls`/`plain` (ChaCha20) | можно `reality-tls` |
| Ожидаемый потолок | десятки Мбит | сотни Мбит |
| `reality-tls` | очень медленно (двойной AEAD, <~20 Мбит) | приемлемо |

Выбор режима — это конфиг на устройстве, **не разный бинарь**.

## 8. Риски

- **mipsel-сборка** — основной техриск (tier-3 + `-Zbuild-std` + ABI-match + atomics).
  На aarch64 этого нет.
- **Перф на MIPS** — потолок десятки Мбит (софт-крипто). Для канала до ~50–100 Мбит
  ок, для гигабита нет.
- **Интеграция с NAT/firewall KeeneticOS** — непредсказуема, зависит от модели/прошивки.
- **Нет нативной интеграции в веб-морду KeeneticOS** — это сторонний Entware-демон
  (SSH/init-скрипт). Полноценный KeeneticOS-компонент требует SDK Keenetic — вне реализма.

## 9. Чек-лист

**Фаза 1 — код-скелет + лаб-верификация ✅ PASS (2026-06-11):**
- [x] Cargo.toml: server-депы → optional; фичи `server`/`client`/`client-bin`
- [x] lib.rs: модули под фичи
- [x] protocol/realtls/mod.rs: `server` под `feature="server"`
- [x] client/mod.rs: `AtomicU64` → `portable_atomic`
- [x] src/client_main.rs: standalone-клиент
- [x] **верификация на .10** (`scripts/keenetic_verify.py`): дефолтная `cargo build --release`
  = OK (не сломана); `cargo build --bin qeli-client --no-default-features --features
  client-bin` = OK (без rustls/axum/rcgen в графе); client-bin `clippy -D warnings` = OK;
  `cargo tree -i ring` → «did not match any packages» (**ring отсутствует**); бинарь = ELF x86-64.

**Фаза 1.5 — config-ключи для роутера ✅ (2026-06-11):**
- [x] `[qeli]` парсер: `gateway=true` (→ full-tunnel) и `dns=off` (→ не трогать резолвер
  роутера) + эмит в `to_ini_string` + тест (`config/client.rs`); в qeli://-ссылку НЕ входят.

**Фаза 2 — тулчейны и кросс-сборка ✅ PASS (2026-06-11):**
- [x] aarch64-musl: `rustup target add` + `cargo zigbuild` → static ARM aarch64, 2.3 МБ
- [x] mipsel-musl: nightly + `-Zbuild-std` + zig + `-msoft-float` → static-pie MIPS32r2, 3.3 МБ
- [x] `scripts/build_keenetic.py` (обе арки, idempotent-сетап, пулл в `release/keenetic/`)
- [x] арк-баги исправлены: TUNSETIFF (тип+значение per-arch), float-ABI (soft-float)
- [ ] CI-матрица (обе цели в `ci.yml`)

**Фаза 3 — рантайн/деплой ✅ шаблоны готовы (2026-06-11), нужна проверка на устройстве:**
- [x] `release/keenetic/install-keenetic.sh` (детект арки → бинарь, `ip-full`/`iptables`, tun-проба)
- [x] `release/keenetic/S99qeli` (Entware init + NAT/forward для шлюза + `QELI_DEVICE_ID_FILE`)
- [x] `release/keenetic/client.conf.example` (`gateway`/`dns`) + `README.md`
- [ ] **проверка на живом Кинетике** (нет устройства): арку, `/dev/net/tun`, имена интерфейсов,
  взаимодействие с firewall/NAT KeeneticOS

**Фаза 4 — e2e и замеры (нужно устройство):**
- [ ] туннель против прод-сервера, ping/speedtest с LAN-клиента (mips + arm)
- [ ] подбор wire-режима под железо
