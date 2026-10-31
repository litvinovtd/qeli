# Установка клиента qeli на OpenWrt

Русский · [English](../../eng/manuals/OPENWRT-INSTALL.md)

> **0.8.3 / issue #205:** обновляйте бинарник **и** init-скрипт вместе. Служба
> передаёт физический путь `/var` с добавлением `/lib/qeli` как `STATE_DIRECTORY`;
> на стандартном OpenWrt это прежний `/tmp/lib/qeli`. Init не меняет права
> небезопасного каталога и не присваивает его себе. При ручном запуске нужно то же
> окружение: [хранилище состояния и восстановление](OPERATIONS.md#восстановление-физических-маршрутов-клиента).
> Управляемые маршруты требуют поддержки `SO_NETNS_COOKIE` ядром даже при `dns=off`.

> **Объём аудита 0.8.2.** Физические роутеры исключены из согласованного аудита.
> SDK и изолированные проверки lifecycle не заменяют тесты вашей прошивки.
> Используйте артефакт точного опубликованного тега, проверьте архитектуру,
> поддержку TUN и имена firewall/интерфейсов. [Границы аудита](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

Два способа установки: **A) готовый бинарник** с ручной установкой и зависимостями
opkg или **B) сборка из исходников** как feed-пакета `.ipk`. В обоих случаях
используются одинаковая конфигурация UCI/LuCI и служба procd.

## 0. Требования на роутере

```sh
opkg update
opkg install kmod-tun ip-full iptables ip6tables ca-bundle
ls -l /dev/net/tun        # must exist (kmod-tun provides it)
```

- **Место:** ELF клиента 0.8.2 занимает 8.93 МиБ (aarch64), 9.07 МиБ (armv7),
  9.66 МиБ (x86_64) или 10.87 МиБ (mipsel). Дополнительно нужны зависимости,
  предыдущий бинарник и место для подготовки замены. Размер ELF не равен полному
  бюджету установки. При небольшой flash используйте **extroot** или USB/`/opt` overlay.
- **Режим по CPU:** маломощные **mipsel** (MT7621/7628) → `fake-tls` / `obfs` /
  `plain` (ChaCha20). `reality-tls` с двойным AEAD разумен только для **aarch64**.

## A. Готовый бинарник

1. Определите архитектуру (`opkg print-architecture` / `uname -m`), загрузите
   соответствующий `qeli-client-openwrt-<arch>` из **GitHub Releases**: aarch64,
   x86_64, mipsel или armv7, static musl. Скопируйте бинарник на роутер.

   > `qeli-openwrt/build/build_openwrt.py` — внутренний инструмент сопровождающего:
   > он собирает на частном стенде по SSH. Используйте релизный бинарник или SDK
   > из раздела B. Старый пример копировал `qeli-openwrt/dist/`, но это локальный
   > gitignored-каталог, отсутствующий в свежем checkout и способный содержать
   > старую сборку: при 0.7.14 там оставались бинарники 0.7.13. Берите файл из
   > загруженного релиза. У сопровождающего набор версии хранится в явном
   > `release/dist/v<version>/`. Исторический аудит: 2026-08-01, §7.

```sh
   # from your PC, from wherever you saved the download:
   scp qeli-client-openwrt-aarch64 root@192.168.1.1:/usr/bin/qeli-client
   # and the integration files, from a checkout of this repo:
   scp qeli-openwrt/files/qeli.init   root@192.168.1.1:/etc/init.d/qeli
   scp qeli-openwrt/files/qeli.config root@192.168.1.1:/etc/config/qeli
   scp qeli-openwrt/files/qeli.firewall.uci-defaults root@192.168.1.1:/etc/uci-defaults/99-qeli-firewall
   ```

2. На роутере задайте права и один раз примените defaults firewall zone:

```sh
   chmod 755 /usr/bin/qeli-client /etc/init.d/qeli /etc/uci-defaults/99-qeli-firewall
   chmod 600 /etc/config/qeli
   sh /etc/uci-defaults/99-qeli-firewall      # creates the `qeli` fw zone (or runs on next boot)
   ```

3. Перейдите к разделу **3. Настройка**.

## B. Из исходников: feed-пакет и .ipk

На сборочном хосте используйте **OpenWrt SDK той же версии и target, что прошивка**,
с закреплёнными feeds; границы проверки SDK приведены ниже.

```sh
# 1. Add the rust + luci feeds (rust is needed to compile the client).
./scripts/feeds update -a && ./scripts/feeds install -a

# 2. Drop the package into the tree (symlink or copy this dir).
mkdir -p package/qeli
cp /path/to/qeli-openwrt/Makefile /path/to/qeli-openwrt/verify-source.sh package/qeli/
cp -r /path/to/qeli-openwrt/files package/qeli/files
cp -r /path/to/qeli-openwrt/luci-app-qeli package/luci-app-qeli

# 3. Select and build.
make menuconfig        # Network → VPN → <*> qeli ;  LuCI → Applications → luci-app-qeli
make package/qeli/compile V=s -j1
make package/luci-app-qeli/compile V=s -j1

# 4. The .ipk lands in bin/packages/<arch>/…  — install on the router:
# Use the actual output names; SDK24.10.4 uses <ver>-r<release>.
opkg install ./qeli_<ver>-r1_<arch>.ipk ./luci-app-qeli_<ver>-r1_all.ipk
```

> **Где Cargo.toml?** Пакет сам загружает весь репозиторий через
> `PKG_SOURCE_PROTO:=git`, а Cargo-проект находится в `qeli/Cargo.toml`.
> Сборка переходит туда автоматически. В `package/qeli/` нужны только Makefile,
> сборочный `verify-source.sh` и `files/`; crate берётся из Git, не из локальной
> рабочей копии. Для изменённого crate укажите свой fork в
> `PKG_SOURCE_URL`/`PKG_SOURCE_VERSION` или локальное зеркало для `PKG_SOURCE_PROTO`.

`opkg install` устанавливает `kmod-tun`/`ip-full`/`iptables` и запускает firewall
uci-default автоматически.

## 3. Настройка

Получите параметры подключения из серверной ссылки, а ключ — на сервере:

```sh
# on the SERVER:
qeli add-client router1 --link --host vpn.example.com   # prints a qeli:// link
qeli show-identity                                       # prints the public key to pin
```

Несекретные параметры задаются через **UCI** или LuCI → Services → qeli VPN.
Учётные данные — доступные только для записи секреты в tmpfs на время загрузки;
они намеренно не сохраняются в UCI/flash.

```sh
uci set qeli.main.server='vpn.example.com:443'
uci set qeli.main.user='router1'
printf '%s\n' '<password>' | /etc/init.d/qeli set_secret pass
uci set qeli.main.key='<64-hex server identity>'   # zero/empty = TOFU
uci set qeli.main.bind_static='1'                  # keep on with a real key (drop to 0 for TOFU)
uci set qeli.main.mode='fake-tls'
uci set qeli.main.sni='www.cloudflare.com'
uci set qeli.main.gateway='1'                      # 1 = route the WHOLE LAN through the tunnel
uci set qeli.main.dns='off'                        # leave the router's resolver alone
uci set qeli.main.enabled='1'
uci commit qeli
```

`gateway = 1` делает роутер **full-tunnel шлюзом**: зона firewall `qeli` выполняет
NAT LAN через туннель. `gateway = 0` — split tunnel: только подсеть туннеля и
маршруты, полученные от сервера.

## 4. Запуск

```sh
/etc/init.d/qeli enable        # start on boot
/etc/init.d/qeli start
/etc/init.d/qeli status

logread -e qeli                # watch for "Auth OK"
ip addr show qeli0             # the tun should have an address
ip route                       # full-tunnel: 0.0.0.0/1 + 128.0.0.0/1 via qeli0
```

При full tunnel проверьте выход с клиента LAN: публичный IP должен стать адресом сервера.

```sh
# from a LAN PC:
curl -s https://api.ipify.org ; echo      # == server IP when gateway=1
```

## 5. Диагностика

| Симптом | Проверка |
|---|---|
| `/dev/net/tun missing` | `opkg install kmod-tun` |
| Зависание handshake на **LTE/4G WAN** | UDP-фрагментация 0.7.4 уже устраняет известную причину; проверьте соответствие `proto`/`mode` серверу |
| Ошибка `Auth` | Несовпадение `user`/`pass`/`key`; проверьте `qeli show-identity` на сервере |
| LAN видит туннель, но не интернет | `uci show firewall \| grep qeli`: нужны `name 'qeli'`, `masq '1'`, forwarding `lan → qeli`; `fw4 reload` |
| Циклические reconnect | Синхронизация времени `ntpd`, причина отключения в серверном логе |
| Нарушен DNS роутера | `dns='off'`: клиент не меняет `resolv.conf`, которым управляет dnsmasq |

Логи: `logread -e qeli`. Подробность:
`uci set qeli.main.log_level='debug'; /etc/init.d/qeli restart`.

`log_time_format` задаёт время в строках клиента: `none`, `datetime`, `rfc3339`,
`time`, `epoch`. По умолчанию `none`: procd передаёт stderr в syslog, который уже
добавляет время. Иное значение даст двойные метки в `logread`. `rfc3339` полезен
при отправке логов с роутера и сопоставлении UTC с сервером.

## Ошибки конфигурации и службы: разработка 0.8.2

Перед status controls сохраните поля через Save & Apply. Connect/Disconnect ждут
UCI commit/confirmation перед сменой службы; Restart использует ту же очередь
страницы. Apply может применить и другие staged UCI-пакеты. Ошибка службы
показывается, но не отменяет уже сохранённое намерение автозапуска.

Init публикует полный tmpfs INI с правами 0600 атомарным rename. Обычный отказ
render сохраняет прежний файл; MTU — 0 (auto) или 576..16602. Ошибка изменения,
commit или reload firewall останавливает startup и оставляет root-only tmpfs
pending marker для следующей попытки. Успешный no-op не перезагружает firewall.
Частичные UCI-изменения автоматически не откатываются. Исправьте причину и
перезапустите qeli. Shell/JavaScript fixtures не квалифицируют это на роутере:
историческая аппаратная проверка публичной 0.8.0 не распространяется на новые
исходники. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

Status polling читает видимый init UCI через ограниченный `service_status` RPC,
сохраняет несохранённые правки формы и показывает unknown при ошибке чтения.
Cross-build helpers отклоняют ошибки target, подготовки и передачи. Каждый
запуск загружает текущий checkout в новый частный каталог. Атомарная передача
со сверкой SHA256/ELF не квалифицирует полный ABI или runtime роутера.
Development-тесты выполняют закреплённые OpenWrt 24.10/25.12 ucode/fs на Linux;
native 24.10 rpcd/ubus/UCI/session ACL проверены в частном chroot. Проверки
non-PID1 procd и установки SDK-пакета в OpenWrt userspace описаны ниже.
Firmware runtime остаётся неквалифицированным, USER_EXCLUDED.

Первичные firewall defaults создают именованные секции, принадлежащие пакету;
существующая qeli zone сохраняется. Ошибка UCI create/commit или live reload
оставляет `/var/run/qeli/firewall-install-pending` и блокирует start. Исправьте
ошибку, успешно повторите `sh /etc/uci-defaults/99-qeli-firewall`, затем start.
Удаление marker не заменяет ремонт. Retry завершает секции без дублирования
devices/forwarding, но не откатывает частичные изменения. Marker находится в
tmpfs и не гарантирует восстановление после reboot.

Каждый helper создаёт частный каталог 0700
`/var/tmp/qeli-router-keenetic-XXXXXX` или `/var/tmp/qeli-router-openwrt-XXXXXX`,
загружает checkout и использует собственный target. `--sync` сохранён для
совместимости: загрузка выполняется и без него. Прежние `/opt/qeli-src` и общий
backup Cargo.toml не используются; ограничение manifest до rlib касается только
частной копии. Ошибка загрузки/закрытия оставляет `.router-sync-incomplete` и
останавливает запуск; повтор получает новый checkout. Каталоги сохраняются для
диагностики: после завершения удаляйте только проверенный напечатанный owned path.
Автоудаления нет. Cargo: `--locked`, `--jobs1`, без incremental cache. Установленные
toolchains и download cache Cargo могут оставаться общими между запусками.

Перед атомарной публикацией тот же SHA256-bound snapshot должен быть little-endian
ELF нужного class/machine с file-backed executable entry, без PT_INTERP/DT_NEEDED;
ARMv7 обязан объявлять EABI5 hard-float. Отказ сохраняет прежний локальный бинарник,
даже при совпадении с remote cache. Это не доказательство musl identity, CPU ISA,
полного MIPS float ABI, воспроизводимости или firmware runtime. Общая политика
router helpers: Rust 1.97.0, nightly-2026-06-10 для MIPS, Zig 0.13.0,
cargo-zigbuild 0.23.0. Неверные версии отклоняются; отсутствующие именованные
компоненты устанавливаются без смены default Rust. Ambient/encoded Rust flags
не меняют рецепт, MIPS soft-float задан явно, compiler overrides очищены,
wrappers отключены. Global Cargo config, PATH, общие installations и upload races
не дают hermetic/reproducible гарантии. SDK использует свой Rust feed/toolchain.
[Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

SDK-пакет требует Cargo.lock и проверяет client-only graph через
`cargo metadata --locked` до `cargo install --locked --jobs1`. Отсутствующий или
устаревший lock останавливает установку. Это не заменяет source SHA и
PKG_MIRROR_HASH при release cut и само по себе не проверяет настоящий SDK-пакет.

Удаление секретов сообщает filesystem failure и через CLI, и через LuCI;
отсутствующий файл — успешный no-op. Удаление не останавливает текущий VPN и не
стирает уже загруженные credentials: изменение применяет restart. При неудачном
commit legacy UCI migration сохраняет `/var/run/qeli/secret-migration-pending`
и повторяется на start даже при уже удалённых staged options. Исправьте ошибку
storage/UCI и повторите start. Гарантии reboot-транзакции или стирания старых
flash blocks нет; мигрированные credentials следует сменить.
Ошибка UCI load или несколько qeli firewall zones блокируют подготовку start.
Стандартные rc.common hooks возвращают ошибки подготовки/cleanup и передачи
ubus service submission. Ошибка stop cleanup/delete submission блокирует
следующий start в том же restart/reload. Недоступный procd/service socket —
ошибка команды; восстановите supervisor и повторите. Даже успешная submission
не подтверждает initialization, cleanup или связь VPN.

Повторный start сравнивает отрендеренный INI и volatile password через procd:
изменение заменяет процесс, совпадение сохраняет PID. Запись секрета сама по себе
не применяет его. Ошибка подготовки не удаляет работающий instance, render
failure сохраняет INI. Это не откатывает firewall/UCI и не подтверждает VPN.
`restart`/`reload` запрашивают явный restart.

Init renderer заключает строки в кавычки и экранирует двойные кавычки по общему
INI-парсеру. Кавычки, обратные слеши и значимые крайние пробелы в usernames и
volatile obfs keys сохраняются. В UCI/LuCI/stdin secret command вводите raw
значения без дополнительного INI escaping. ASCII controls для секретов запрещены,
из обычных UCI-значений удаляются. Экранирование не делает некорректный endpoint,
logging mode или другую настройку валидной: итог проверяет клиент.

Secret RPC использует фиксированные init-команды и передаёт credentials только
через stdin, как проверено с OpenWrt 24.10/25.12 ucode. Допустимы 1..4096 UTF-8
байт, без ASCII C0/DEL; считаются байты, не символы. В LuCI не добавляйте shell/INI
escaping. Configured требует читаемый regular file этого размера в физическом
runtime directory. Empty/oversize files, directories, FIFOs и symlinks не подходят.
Linked runtime directories и non-regular/linked destinations отклоняют запись.
Очистка также отклоняет linked runtime directory, чтобы не удалять чужие файлы;
отсутствующий каталог — no-op. Исправьте неожиданный filesystem object и повторите;
не считайте failed write применёнными credentials. Host-тесты покрывают реальные
ucode/fs и native 24.10 rpcd/ubus/UCI/session ACL в частном chroot. Другие тесты
проверяют официальный 24.10.4 x86 procd и rc.common с inert client: start/stop/reload,
respawn, autostart links и transport errors. Procd работает non-PID1; это не
проверка VPN cleanup/connectivity, SDK installation, HTTP serving, boot или
firmware. Замена путей администратором между проверкой и публикацией вне гарантии.

LuCI-пакет явно требует luci-base, rpcd-mod-ucode и ucode-mod-fs вместе с qeli:
без fs RPC object не зарегистрируется. Оба secret fields до RPC проверяют ASCII
controls, UTF-8 byte limit и Unicode. Ubus C-string transport не поддерживает NUL:
внешние RPC producers должны отклонить его до сериализации, иначе значение может
усечься до обработчика Qeli. Используйте валидный текст без control bytes.
LuCI session staging отделён от init-visible configuration до commit; глобальный
CLI UCI staging администратора — другой context, иногда видимый init до commit.
Перед service controls выполняйте Save & Apply.

### Проверка SDK-пакета

Используйте SDK версии/target вашей прошивки с pinned feeds. Аудит 7 октября
использовал официальный x86/64 SDK 24.10.4: реальные package metadata, IPv6 Kconfig,
LuCI IPK compilation/minification — PASS. Частный default-n fixture проверил
IPv4-only dependency branch; stock SDK фиксирует IPV6=y. Пакет сохраняет virtual
iptables providers и запрашивает ip6tables только при IPV6. LuCI использует
LUCI_MAINTAINER/LUCI_URL, как требует luci.mk.

Pinned Rust feed — 1.89.0; глобального rust-version в Cargo.toml нет. Срез F358
client-bin прошёл GNU check и musl compile/link с stock Rust 1.89.0, SDK GCC 13.3
и экспортированным SDK Build/Compile macro/profile. Свежий ELF прошёл CLI/INI
inspection в официальном rootfs 24.10.4. Использованы upstream prebuilt std;
это не квалификация SDK Rust bootstrap, source-download/release-cut pipeline,
других targets, VPN или firmware. Standalone helpers сохраняют Rust 1.97.0 и
свой объём проверки.

Recipe переводит только частный SDK Cargo.toml в rlib до metadata/install.
Допустимы каноническая декларация трёх типов и уже существующий rlib; неизвестная
декларация останавливает Cargo. Лишние cdylib/staticlib не собираются и не
устанавливаются; manifest/native ABI в репозитории не меняется. На release cut
проверяйте source tag/commit, PKG_SOURCE_DATE, source/mirror hashes. Имя Source
берите из реальных metadata: SDK 24.10.4 создаёт `.tar.zst`, не обязательно
`.tar.xz`. См. package/qeli/check FIXUP=1 в recipe. Recursive-dependency diagnostics
считайте отказом даже при make exit 0.

`scripts/test_openwrt_sdk.py` содержит три SDK и три реальные IPK-проверки.
SdkTests запускайте только в подготовленном owned SDK с `.qeli-audit-sdk`:
они временно меняют и восстанавливают .config/Config-build.in.
QELI_OPENWRT_LUCI_IPK выбирает IPK для IpkTests, включая 14 прежних LuCI fixtures
на minified JS. Пакет установленного роутера не читается. Offline opkg проверен
в официальном rootfs с настоящими signed dependencies: nft/legacy providers,
install/upgrade/remove, сохранение изменённого UCI и режимов 0600, ранние отказы.
Первичный empty-root FAIL сохранён; live postinst/fw4/procd не квалифицирован.
Используйте offline `/target` внутри owned chroot, а не offline-root `/`.
Шесть real-Cargo SDK macro tests в `scripts/test_openwrt_compile.py` требуют
явных owned compiler/template fixtures и не запускаются на роутере.
[Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Границы HTTP/session аудита

Реальный OpenWrt 24.10.4 uhttpd JSON-RPC bridge проверен на Linux namespace
loopback с native rpcd/ucode/UCI и SDK-built LuCI IPK. Шесть integration methods:
login, reader/writer permissions, unauthorized requests, secrets, закрытый набор
service verbs, session UCI apply/confirm, отказ session-ID impersonation,
revocation/idle expiry, static JS и malformed requests. Ограниченным rpcd users
нужен соответствующий read/write luci-base ACL дополнительно к luci-app-qeli:
framework даёт UCI RPC, Qeli — только scope qeli config/object. Обращение к сессии
обновляет idle expiry; Qeli ACL не менялся.

Требуются root в частных mount **и** network namespaces, loopback up,
QELI_OPENWRT_ROOTFS_TEMPLATE, QELI_OPENWRT_RPCD_TEMPLATE, QELI_OPENWRT_LUCI_IPK;
`scripts/test_openwrt_http.py` запускайте только в owned lab. Authentication bypass
нет. Service verbs используют inert adapter: live VPN, browser login/DOM, TLS и
общая cookie/CORS/CSRF policy LuCI не квалифицированы. Firmware исключён.
[Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Компилятор и промежуточная сборка: разработка 0.8.2

Общий helper получает rustc выбранного pin через `rustup which --toolchain ... rustc`,
проверяет executable и явно передаёт Cargo. CARGO_TARGET_DIR и CARGO_BUILD_BUILD_DIR
указывают в target owned run: обычные build.rustc/build.build-dir и ambient build-dir
не должны перенаправить эти входы. Router CI следует той же политике.
Linux gate `keenetic_verify.py` использует Rust 1.97.0 с его Clippy, не default host;
отсутствие compiler resolution останавливает Cargo. Wrapper/encoded flags — по
общей политике.

Это ограниченная изоляция окружения, не полностью hermetic build. Cargo home/ancestor
configuration, forced environment, profile/source/linker overrides, PATH/shared
registry/tool caches и clean independent Qeli A/B требуют своей квалификации.
Семь real-Cargo methods используют Linux fixtures без dependencies; они не
квалифицируют новый Qeli cross build, Zig, SDK Rust или router ABI/runtime.
[Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

Следующее изменение runtime generation F361 имеет свежие GNU Rust 1.97 unit/check,
production Clippy/fmt. Предыдущая SDK 1.89/musl квалификация относится к F358,
а не этому последующему изменению. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Release profile standalone helper: разработка 0.8.2

`scripts/router_toolchain.py` явно передаёт дочернему Cargo пять полей release:
lto=fat, codegen-units=1, opt-level=3, strip=true, panic=abort. Standalone helpers
OpenWrt/Keenetic и Linux host gate переопределяют ambient значения этих полей,
включая FFI panic=unwind, Cargo home и ancestor config. Router CI получает тот же
набор через `python3 scripts/router_toolchain.py --print-release-profile` из корня.
FFI сохраняет отдельную unwind policy, SDK feed profiles не меняются.

Проверены реальные GNU mini-crates и pinned Zig x86_64-musl mini-probe, не новый
полный Qeli/cross/firmware build. Остальные profile keys, forced child env,
source/linker/PATH/caches и clean Qeli A/B пока изолированы не полностью.

Helper также remap-ит частный source root в `/usr/src/qeli` для `file!()`/panic
diagnostics; реальные пути config не меняются. F365 проверил две независимые
полные x86_64-musl сборки Qeli с fresh target/Zig caches и одинаковыми offline
registry copies: byte-identical ELF, help/version и INI metadata — PASS. Это
заменяет прежнее A/B NOT_RUN только для этого target/recipe; остальные targets,
SDK/CI path policy и произвольные окружения остаются отдельными проверками.
См. Q31.

### Обновление: standalone A/B и preflight, 7 октября 2026

Q31-V006 завершает independent full A/B aarch64, armv7 и mipsel: каждая пара
byte-identical. С sealed input-matched парой F365 x86_64 все четыре standalone
targets имеют ограниченное A/B evidence. Шесть новых ELF также прошли static
admission и QEMU help/version/INI. Это заменяет прежнее NOT_RUN других targets,
но не квалифицирует firmware, router networking или полный SDK release pipeline.

`python scripts/release_preflight.py <branch>` запускает optional 32-bit lab gate 2
при заданном QELI_LAB_PASS. До SSH отклоняются dirty source/recipe inputs; exact
bytes замораживаются из одного committed `qeli/` Git archive и собираются в частном
checkout общим pinned/locked one-job recipe. Проверяются fetched SHA256 и static
ELF, SSH закрывается при успехе/ошибке. QELI_LAB_SRC устарел. Публикации нет,
checkout сохраняется для анализа. Helper может установить отсутствующие named
tools. Полный live preflight/CI dispatch, SDK bootstrap/source-pin/mirror release-cut
остаются отдельными проверками.

## Допуск OpenWrt release source: разработка 0.8.2

Gate 3 `scripts/release_preflight.py` требует committed участвующие inputs,
одну literal `:=` декларацию на source/version/hash variable, полный immutable
commit SHA и тот же committed `qeli/` tree, что candidate. Branch/tag, короткий ID,
повторные/qualified/eval/define/undefine metadata, отсутствующий/неверный Cargo
`[package].version`, dirty inputs и Git errors дают отказ. Git запускается из
корня с timeout 30 секунд. Более старый commit с тем же crate tree допустим:
запись pin сама создаёт ещё один commit, точное равенство HEAD не требуется.

Перед preflight задайте QELI_OPENWRT_SOURCE_ARCHIVE — локальный **SDK-generated
Source archive**. Имя берите из package metadata, создавайте/проверяйте через
SDK download/check recipe и коммитьте соответствующие pin/hash. Gate 3 сверяет
SHA256 с PKG_MIRROR_HASH; отсутствующий, пустой, nonregular, linked, несовпадающий
или наблюдаемо меняющийся файл отклоняется. Download, extraction и публикации
нет. Синтаксически правильного hash уже недостаточно. Проверяется mirror integrity,
но не реконструируется SDK generation/Rust bootstrap, произвольный Make/environment
или privileged replacement после последнего наблюдения. Development pin/hash
не меняются; release-cut квалифицируется отдельно. Нужен Python 3.11+ для TOML.

25 real temporary-Git/local-file methods прошли Linux uid/gid 65534, включая
четыре прежних fail-open и FIFO/link refusal. Обычный CI выполняет 24 и явно
пропускает только opt-in historical-baseline; lab с baseline выполняет все 25.
Также прошли 18 CI и 15 router release methods. Checksum fixtures не являются
новыми SDK-generated release archives; запуск релиза или Actions не заявляется.

## Проверка SDK archive до prepare/compile: разработка 0.8.2

Настоящий SDK 24.10.4 Git fallback способен вернуть 0 и распаковать source при
неверном PKG_MIRROR_HASH; обычный download даже не обязан вывести CHECK warning.
Поэтому build-only `verify-source.sh` вызывается в Hooks/Prepare/Pre и при входе
в Build/Compile до Cargo/projection. Копируйте его рядом с Makefile, как выше;
на роутер он не устанавливается. Missing/empty/nonregular/linked archive,
malformed/nonmatching hash и hash-tool failure блокируют build. Явные SDK developer
overlays допустимы, но не mirror-qualified. Privileged mutation после проверки
и произвольные Make overrides вне защиты.

Для релиза закрепите immutable source, выполните download, SDK check FIXUP=1,
независимо проверьте Source archive/hash и задайте QELI_OPENWRT_SOURCE_ARCHIVE.
Аудит использовал `make -C package/qeli TOPDIR=/absolute/sdk download CHECK=1
FIXUP=1 -j1`: SDK check/fixup без host build. Development pin/hash меняются
только при настоящем release cut.

SDK дважды создал одинаковый archive из private fixture commit с точно тем же
qeli tree, что candidate. Prepare отвергает bad hash до unpack, valid prepare
сохраняет tree. GNU make экспортирует реальный Compile macro, inert Cargo seam
подтверждает 0 вызовов при bad hash и 2 при valid. SDK archive проходит source
gate. Девять shell methods прошли dash/ash без root, 25 source methods — PASS.
Это закрывает scoped archive/prepare admission, не полный bootstrap, новую
компиляцию/установку клиента, Actions или firmware.

## Maintainer 32-bit preflight helper: разработка 0.8.2

Live Gate2 собрал ARMv7/MIPS release из текущего committed qeli tree по pinned
Zig/Rust recipe со скачанным SHA256 и static ELF. 32 реальных QEMU CLI/INI
inspection прошли без root на cortex-a7/24Kc. Это дополняет SDK 1.89 scope;
данные две сборки — maintainer Zig, не SDK Rust bootstrap.
Весь preflight/Actions и production release-cut pin/hash остаются отдельными.
QEMU inspection не квалифицирует router VPN/TUN/firewall/firmware. Raw evidence
сохранён, временные build/emulation roots удалены; опубликованные артефакты и
production pin/hash не менялись.

## Стабильный source во время preflight

Запускайте `python scripts/release_preflight.py <release-branch>` из чистой
committed working tree, включая non-ignored untracked inputs. Preflight печатает
admitted commit и сверяет между gates и после certification. Не коммитьте, не
редактируйте и не переключайте ветку во время работы: drift даёт FAIL и
останавливает следующие gates. Optional lab snapshot/report должен содержать
тот же commit. Обычные gate failures накапливаются; certification timeout 120
секунд также даёт отказ. Ignored caches и изменение, целиком отменённое внутри
gate, вне boundary guard. Preflight не блокирует Git и не разрешает публикацию
после дальнейших правок. Optional lab gate не заменяет SDK build, source pin/archive
generation и успешный CI точного commit.

## Реальная интеграция SDK client package, 8 октября 2026

Для x86/64 OpenWrt 24.10.4 получено scoped source-to-IPK evidence: private Git
fixture с exact current qeli tree, SDK-generated/admitted archive, prepare,
real client-only Cargo build, GCC 13.3 musl link, package install/dependency
check/strip и IPK generation. Nested make выявил broken sed anchor; Compile
проверяет точную accepted crate declaration до projection и использует команду,
переживающую SDK expansion. Шесть real-Cargo boundary cases — PASS.

Свежий IPK прошёл семь offline opkg install/upgrade/remove/corruption cases
с настоящими rootfs/dependency packages и девять client executions в isolated
OpenWrt userspace. Прошли nft и legacy providers; forced dependencies и фиктивных
installed records не было. r2 — upgrade fixture. Firmware и VPN не проверялись.
Использованы private official prebuilt Rust/std 1.89.0 и copied registry через
direct SDK entry. Rust bootstrap, cold/hermetic compilation, другие targets,
production pin/hash cut и текущий успешный Actions/preflight не квалифицированы.
Production pin/hash не менялись. Для release build нужен полный SDK dependency
graph; audit bootstrap shortcut не является release certification.
[Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Текущая standalone 32-bit проверка, 8 октября

После publication-lock change committed source пересобран Gate2 для ARMv7/MIPS.
Оба ELF/SHA и 32 QEMU CLI/INI cases прошли cortex-a7/24Kc uid 65534. Ещё 14 executions
проверяют exact production publication-lock/budget modules с той же standalone
release policy. В этом объёме регрессии нет. Это не full cfg(test), firmware/VPN,
SDK bootstrap или новое clean A/B. Прежний four-target A/B сохраняет исходные
дату/source. [Артефакты и границы Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Ошибка загрузки Rust feed LLVM: SDK 24.10.4, 14 октября 2026

Pinned packages feed f1470815f41f использует Rust 1.89.0 и
`--set=llvm.download-ci-llvm=true`. Изолированный Host/Compile собрал bootstrap,
затем получил HTTP 404 для pinned CI rust-dev artifact. Компиляция Qeli не
началась. Повтор download или правки INI/DNS/firewall Qeli зависимость не исправят.

Для полного source toolchain build в private SDK/feed замените только
`--set=llvm.download-ci-llvm=true` на `--set=llvm.download-ci-llvm=false` в
`feeds/packages/lang/rust/Makefile`, сохранив host/target flags и source version/hash.
Очистите собственное build state Rust host package и повторите configure:
одного generated bootstrap.toml недостаточно, Host/Configure может его перезаписать.
Это выбирает bundled LLVM source вместо недоступного CI binary, требует ресурсов
и отдельных Host/Compile/Host/Install и Qeli SDK проверок. Поздний qualified
Clang-host результат описан ниже; pin/hash и явную конфигурацию сохраняйте.
Прежний qualified SDK/IPK использовал official prebuilt Rust/std 1.89: это package
integration, не cold bootstrap. [Отказ и cleanup](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Ранняя ограниченная source-LLVM попытка, 14 октября 2026

Единственная private-feed правка `download-ci-llvm=false` прошла prepare/configure,
bootstrap compilation и вошла в C++ LLVM. Последний Ninja indicator — 548/3710;
owned time guard остановил попытку. LLVM/rustc/dist/Host/Install и cold SDK/IPK
тогда оставались неквалифицированными. Исходный CI 404 сохранён отдельно.
Это подтверждает configured bypass, не полный toolchain. Production feed не
менялся. [Результат и очистка](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Последующая Clang-попытка: лимит места, 14 октября 2026

Private Clang 19 GNU host дошёл до LLVM 3340/3710 и остановился при 1003.2 МиБ
свободного места, ниже порога 1024 МиБ. Rust stage2/dist и Host/Install не
завершились; cold SDK/opkg не запускался. Pinned Rust source/feed и musl target
compiler/linker сохранены, host cc/cxx и jobs=1 заданы явно. На этом этапе
source fallback ещё не квалифицирован.
Owned root/unit удалены после проверки архива; локально оставлен evidence archive
142834 байта. Перед retry нужен значительно больший запас диска.
[Rust compiler guide рекомендует 30GB+](https://rustc-dev-guide.rust-lang.org/building/prerequisites.html):
это общая рекомендация, не измеренный минимум данного pinned dist build.
[Clang disk failure](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Точная GNU-host Clang конфигурация квалифицированного варианта

Ниже конфигурация x86_64 GNU build host и x86_64 musl target проверенного source
bootstrap. Другие hosts, firmware и architectures требуют отдельных проверок.
Используйте private SDK/feed с pinned Rust source version/hash; установите
существующий аргумент llvm.download-ci-llvm=false, выполните Host/Prepare и
Host/Configure. В resolved `rustc-1.89.0-src` редактируйте существующий generated
config.toml или bootstrap.toml, не создавайте второй config. Проверенные host
executables: `/usr/bin/clang`, `/usr/bin/clang++`, оба Clang 19.
Добавьте/измените только поля **в существующих секциях**, не заменяйте весь config:

```toml
[build]
jobs = 1

[target.x86_64-unknown-linux-gnu]
cc = "/usr/bin/clang"
cxx = "/usr/bin/clang++"
```

Остальные поля, GNU build/host triples, target list и весь
`[target.x86_64-unknown-linux-musl]` сохраняются. Musl target использует SDK
`x86_64-openwrt-linux-musl-gcc`/`g++` и gcc linker: host Clang не заменяет target
tools. Host/Configure способен пересоздать config; после него сверяйте effective
configuration повторно. До Qeli package проверьте LLVM CMake compiler IDs/paths,
Host/Compile и Host/Install, установленный Rust/Cargo 1.89 и musl std. Intermediate
compiler или сообщение Dist не подтверждают полный результат.

Кампания 15 октября завершила LLVM/Rust Host/Compile и Host/Install: это
квалификация compiler configuration, ещё не Qeli SDK package. Следующий consumer
отказал на defconfig: external PATH начинался с staging_dir/host/bin и prerequisite
checks находили собственные canonical symlinks. Входите в top-level SDK с external
tools в PATH, например private `deps/usr/bin:/usr/bin:/bin`, очистите inherited
ORIG_PATH и дайте OpenWrt добавить generated tools самостоятельно. Не обходите
это через FORCE=1. Старая consumer cleanup удалила установленный compiler: логи
сохранены, бинарники повторно использовать нельзя. См. датированный Q31.

### Квалифицированный Clang-host source bootstrap, 2026-10-15

Поздняя private SDK кампания завершила LLVM source, Rust 1.89 stage2/dist,
Host/Install, обычный package/qeli/compile graph, семь opkg и девять userspace/CLI/INI
cases. Pin Rust source/feed и musl compiler/linker сохранены. Кроме
download-ci-llvm=false выбраны installed Clang 19 для GNU host cc/cxx и jobs=1
после Host/Configure в существующих build/host sections; повторный Configure
может их пересоздать. Результат одного controlled host не обещает общие
минимальные ресурсы.

Direct host-* goals и root graph используют разные Rust install stamps — host
и hostpkg. R8 создал IPK, но вскрыл замаскированный upstream Host/Install failure
после dist autoremove и post-check refusal. Продолжение сверило весь installed
prefix с qualified source-built backup, явно перенесло только cache metadata
в root graph namespace, затем квалифицировало normal graph reuse и тот же IPK.
Исторический R9 refusal на .built_check timestamp сохраняется; R10 принимает
нормальную metadata mutation со сверкой contents/tool identity. Это explicit cache
handoff, не чистый first-bootstrap-to-root-graph. Failures сохранены. В будущих
bootstrap/consumer используйте согласованный SDK graph namespace; одного make
exit недостаточно для вывода об установке.

Chroot проверки требуют PATH=/usr/sbin:/usr/bin:/sbin:/bin. Lab systemd manager
имел merged-/usr PATH без /bin: opkg ложно сообщал malformed IPK и timeout.
Negative/positive probe того же IPK локализовал причину. R13 изменил только child
environment и прошёл семь opkg и девять CLI cases; host PATH/devices/procfs не менялись.

Оба owned compiler/runtime roots с большими caches архивированы и удалены после
проверки evidence. CI 404, GCC OOM и bounded partial результаты сохраняют даты.
Public source pin/hosted release qualification остаются открытыми; физический
роутер USER_EXCLUDED. [Qualified compiler и SDK](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).
