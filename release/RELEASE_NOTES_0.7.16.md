# qeli 0.7.16 (beta, release candidate) — reconnect recovery, strict framing and fail-closed lifecycle

> ⚠️ **Prepared locally — not published.** The Linux server binary and Debian package were refreshed
> after the latest panel changes and are covered by `SHA256SUMS`. The Windows and macOS artifacts
> still predate the latest desktop-only commits and must be rebuilt before this candidate is
> published. No GitHub release or tag has been created. The production all-modes lifecycle matrix
> still requires a separately authorised maintenance window.
>
> ⚠️ **Локальный кандидат обновлён — релиз не опубликован.** Linux-бинарник сервера и Debian-пакет
> пересобраны после последних изменений панели и покрыты `SHA256SUMS`. Артефакты Windows и macOS
> пока созданы до последних desktop-изменений и должны быть пересобраны перед публикацией кандидата.
> GitHub release и tag не создавались. Production all-modes lifecycle matrix требует отдельно
> согласованного окна обслуживания.

**Language · Язык:** [English](#english) · [Русский](#русский) ·
[Release readiness](#release-readiness--готовность-релиза)

This document describes the fixes made after `v0.7.15` in the `0.7.16` development line. The
canonical itemised history is [CHANGELOG.md](../CHANGELOG.md); these notes explain the user and
operator impact without presenting unfinished artifacts as a published release.

---

## English

### Before upgrading

- There is no new configuration-format migration, but validation is stricter. Run
  `qeli check-config` on the final server configuration and every enabled client/profile before
  replacing a working installation.
- Fix invalid `allowed_networks`, out-of-range route metrics, unreachable REALITY targets,
  conflicting TUN names and Quick Start bind collisions. The previous code could accept or hide
  some of these states; `0.7.16` deliberately refuses them.
- The current inner data plane is IPv4-only. IPv6 DNS resolvers and an IPv6-literal `PUBLIC_HOST`
  are now rejected explicitly instead of generating a client profile that cannot work.
- Validate a backup before relying on it. Restore now requires the active server config and its
  referenced users database, rejects unsafe hooks/symlinks/type changes, and will not call a
  restore exact while leaving extra nested live files behind.
- Logging out of the panel revokes every currently issued panel session. Other browsers and panel
  processes will have to authenticate again.
- Rolling upgrades from the historical qeli QUIC-masking spelling remain accepted. New peers emit
  the strict Initial form; malformed, truncated or tailed records that older builds tolerated are
  now rejected.

### Connection recovery and mobile roaming

- A reconnect intentionally requested after sleep or a physical network change no longer counts
  as a failed connection. The exponential delay therefore stays clear instead of growing to 32
  seconds merely because a user wakes the phone repeatedly.
- Android compares the physical-network signature before cycling a healthy tunnel. During a real
  handover it can select a validated carrier even while the system temporarily reports the VPN
  itself as active, and it advances the baseline only after reconnecting to that carrier.
- A late platform acknowledgement from an already retired generation is normal. One stale event
  or handler exception no longer kills the Android/iOS dispatcher and poisons every subsequent
  connection until the service is restarted.
- Physical DNS recovery on Android uses a bounded two-worker, per-network pool. One resolver stuck
  on an old network cannot block the replacement carrier, while repeated network flaps cannot
  create an unbounded thread or request queue.
- Terminal background failures remain observable even when the event queue is full. A late ACK
  cannot revive a failed generation, and an unusable one-slot event queue is rejected up front.

### Packet path, MTU and loss diagnostics

- Downlink pools are sized from the negotiated MTU plus protocol headroom instead of reserving the
  64 KiB protocol maximum for every ordinary packet. Android, iOS and the Windows packet path now
  retain enough slots to absorb a TUN-writer stall without manufacturing an `internal_drops`
  storm. A genuinely larger record can still grow its individual buffer.
- Internal drops are split into pool exhaustion, queue full, oversize, unsupported packet and TUN
  write failures. Previously invisible `EAGAIN`/`ENOBUFS` failures now reach Linux CLI diagnostics.
- A failed TUN queue duplication or partial packet write is fatal to that writer and is surfaced;
  a truncated IP packet is no longer reported as successfully delivered.

### Fail-closed host lifecycle

- Linux DNS ownership is recorded per interface before changing systemd-resolved. Failed reverts
  remain retryable, stale recovery leaves live foreign interfaces alone, and legacy
  `/etc/resolv.conf` state is restored only after its last verified owner exits.
- Gateway NAT and exit-node setup fails if IPv4 forwarding cannot be enabled. Partial sysctl and
  firewall work is rolled back, cleanup errors remain visible, and incompatible gateway/exit-node
  combinations are rejected before traffic starts.
- The Linux kill switch uses instance-specific chains, rolls back partial installation, refreshes
  server-IP allowances without opening egress, and is removed only after routes, NAT and forwarding
  have been cleaned. Failed inspection is no longer confused with an absent rule.
- Route ownership survives a failed deletion so cleanup can be retried. Qeli refuses to delete or
  attach an existing TUN whose ownership cannot be proven, and preflight detects shared TUN names
  even when one conflicting profile is disabled.
- Concurrent first starts converge on one durable device ID, identity key, TOFU pin and panel
  session key. Corrupt or locked state is preserved and reported instead of being silently replaced
  by fresh trust material.
- `auth.password_command` must exit successfully, and the effective credential length is checked
  for password-file and command sources as well as inline passwords. Passwords and obfuscation keys
  are zeroized when every cloned reconnect/bonding configuration owner is dropped.

### Windows and macOS

- A desktop tunnel generation cannot start while its predecessor may still own TUN, socket, route
  or firewall state. Start, DNS, network-plan, kill-switch and teardown errors reach the service and
  UI instead of being flattened into a false `Disconnected` state.
- The platform boundary rejects an empty or wrong-generation `NetworkPlan`, an unsupported DNS
  endpoint, and a native ownership mode without the corresponding TUN/Wintun/packet descriptor.
- The macOS kill switch is isolated in a PF anchor instead of replacing the global ruleset. It
  distinguishes a live owner from crash residue, serialises PF operations, rolls back partial
  engage, and permits port 53 only to the system's configured resolvers rather than to any host.
- Elevated Windows native extraction uses a non-inheriting directory writable only by
  Administrators and SYSTEM. Both privileged services refuse a new tunnel when stale kill-switch
  recovery has not been proven successful.
- The desktop editor keeps supported INI fields that are not represented by a form control. It
  preserves unresolved invalid/unknown-key evidence, clears only the marker for a field the user
  actually fixed, and refuses a malformed supplied pinned key instead of silently enabling TOFU.

### Server, panel, users and backup

- A profile generation closes task admission and joins every child before removing TUN/NAT state.
  An old supervisor cannot unregister a replacement generation with the same name. The control
  socket is bound before the data plane and a lost control task is a worker failure, not a hidden
  detached condition.
- Client subprocess shutdown has a bounded wait, kill and reap path. Process handles are retained
  when teardown fails so a later cleanup attempt does not lose the only way to reap the child.
- Usage accounting fails closed on a corrupt file. Reload keeps the last good diagnostic snapshot;
  reset and periodic flush are serialised, and failed persistence restores the in-memory counters.
- Authenticated panel logout persists and atomically advances the global session generation. A
  durability failure is reported instead of claiming success. Concurrent key creation converges
  under a sidecar lock, private files are mode `0600`, and unreadable revocation state never falls
  back to generation zero.
- User/group destination ACLs are validated in the configuration layer for panel, inline, file and
  restored inputs. An explicitly configured but malformed ACL cannot become unrestricted. Route
  metrics must be integral `u32`, and user mutations validate a complete clone before publication.
- Preflight recognises typed Linux routes such as `blackhole`, `unreachable` and `prohibit` and does
  not let a disabled qeli profile hide a collision with a physical interface or route.
- Backup/restore validates the complete staged configuration and dependency graph before publish.
  The active path must stay below `/etc/qeli`; referenced users files must be present and valid;
  unknown `.conf` content, unsafe hooks, symlinks, staged/live type mismatches and inexact nested
  state are rejected.
- Quick Start checks the existing profile's effective saved port and transport, not the current UI
  card defaults. Relaunching the same mode is allowed; a real collision with another profile is not.
- IPv6 DNS resolvers are rejected in both client configuration and server push, and the installer
  refuses an IPv6-literal `PUBLIC_HOST` while the inner data plane remains IPv4-only.
- The client round-trip fixture now pins `server`, `dns_servers` and every runtime key, preventing a
  parser option from being added without coverage for its persisted representation.
- `install-polkit` and `set-service-user` validate service-unit and account names before using them
  in paths or generated policy, write rules/drop-ins atomically with explicit permissions, and
  check `chmod`, `chown` and `systemctl daemon-reload` results. Returning from root to the qeli
  account repairs `/etc/qeli` ownership before removing the last working root override.
- The panel shows the current server hostname beside its version, and its UDP badges now distinguish
  queue capacity from socket-buffer occupancy. Administrative access is detected with a real
  `pkcheck` request instead of trying to read system polkit rules that are normally inaccessible to
  the unprivileged service account; missing helpers and indeterminate results are not presented as
  a confirmed denial.
- Panel profile deletion must first stop the client and remove its primary file; auxiliary
  log/status cleanup failures are returned as warnings. Notification serialization and web TLS
  directory-creation errors can no longer produce an empty/partial file or a falsely successful
  startup.

### Framing, encapsulation and wire compatibility

- The native FFI rejects a null pointer with a positive length. A stream ending halfway through a
  TLS record produces `UnexpectedEof`, never a clean end-of-stream.
- Rust, retained C# and Swift decoders require an AEAD record to consume the supplied packet
  exactly. A valid authenticated prefix followed by unauthenticated bytes is rejected, and an
  in-place destination is cleared on every decode failure.
- UDP handshake records are length- and overflow-checked before PQ/TLS key-schedule work. Truncated
  ChangeCipherSpec, Certificate, Finished or NewSessionTicket data cannot advance an offset beyond
  the datagram.
- TCP/sans-IO handshakes also require the expected ChangeCipherSpec and NewSessionTicket instead of
  swallowing read failures. Certificate generation, TLS 1.3 configuration and ticket-provider
  failures return from REALITY setup instead of panicking; IPv6 decoy endpoints use the common
  host/port formatter.
- New QUIC-masking packets emit the exact qeli Initial form (`0xC3`). Parsing validates version 1,
  the four-byte DCID, empty SCID and token, declared Length, four-byte packet number, exact short
  flags and complete datagram consumption. Only the exact historical `0xE3` form is accepted for a
  rolling upgrade; arbitrary packet types, huge/truncated varints and trailing bytes are rejected.
- Server mode selection uses the same full structural parser instead of a prefix test. Rust, C# and
  Swift consume common generated fixtures for packet decode, QUIC, fragmentation, replay windows,
  PRP nonces and HKDF domains.
- Documentation now states the actual boundary: this is QUIC-shaped masking, not a full QUIC
  implementation. Initial AEAD, QUIC header protection, CRYPTO frames and 1200-byte Initial padding
  are not implemented.

### Build and release hygiene

- The deliberate-cycle symbol is available on every target, fixing the Android core E0425 hidden
  by stale prebuilt libraries. Android libraries were rebuilt at that point with unchanged exports;
  all native cores still require one final rebuild from the release commit.
- The hardening changes again pass Rust formatting and lint compilation. A raw-descriptor teardown
  test waits for real destruction and is serialised so another test cannot reuse the same fd number
  and create a false failure.
- Keenetic helpers resolve files from their own checkout instead of a developer-specific absolute
  path, native recipe tests cover that rule, and helper failures retain a non-zero exit status.
- Temporary round-trip snippets were removed from `release/` so they cannot be mistaken for final
  release inputs. Version `0.7.16` and platform build numbers are synchronised across the source
  tree.
- Version checking now includes the signed macOS per-app extension, and IPv4/DNS diagnostics take
  their version from `CARGO_PKG_VERSION` rather than a hard-coded previous release.
- After the late panel changes, `qeli-linux-amd64` and `qeli_0.7.16_amd64.deb` were rebuilt from
  source commit `4ee837b`; the complete lab gate passed, including 633 library tests, formatting,
  Clippy, fuzz/conformance checks, cargo-deny and the portable glibc 2.28 ABI check.

---

## Русский

### Перед обновлением

- Нового перехода формата конфигурации нет, но проверки стали строже. Перед заменой работающей
  установки выполните `qeli check-config` для финального серверного конфига и всех включённых
  клиентов/профилей.
- Исправьте невалидные `allowed_networks`, выходящие за `u32` метрики маршрутов, недостижимые
  REALITY targets, совпадающие TUN names и коллизии bind в Quick Start. `0.7.16` намеренно
  отказывается запускать состояния, которые прежний код мог принять или скрыть.
- Текущий внутренний data plane поддерживает только IPv4. IPv6 DNS resolver и IPv6 literal в
  `PUBLIC_HOST` теперь явно отклоняются вместо генерации неработоспособного профиля клиента.
- Проверьте backup до того, как считать его аварийной копией. Restore требует active server config
  и указанную им базу пользователей, отклоняет небезопасные hooks, symlink и смену типа объекта,
  а exact restore больше не оставляет молча лишние вложенные live-файлы.
- Logout панели отзывает все выданные panel sessions. На других устройствах и в других процессах
  панели потребуется войти повторно.
- Rolling upgrade со старой qeli-формой QUIC masking поддерживается. Новые peers отправляют строгий
  Initial; malformed, truncated и содержащие хвост records, которые ранее могли пройти, теперь
  отклоняются.

### Восстановление соединения и roaming

- Намеренный reconnect после сна или смены физической сети больше не считается сетевой ошибкой и
  не разгоняет backoff до 32 секунд при каждом пробуждении телефона.
- Android сравнивает сигнатуру физического пути и не перезапускает здоровый tunnel на обычном
  screen-off. При реальном handover он находит валидированную carrier-сеть, даже когда система
  временно считает активным собственный VPN, и обновляет baseline только после reconnect.
- Поздний platform ACK от уже завершённой generation является ожидаемым исходом гонки. Один stale
  event или exception больше не убивает Android/iOS dispatcher до перезапуска сервиса.
- Физический DNS Android работает через ограниченный пул из двух workers на разные сети: зависший
  resolver старой сети не блокирует новую, а network flap не создаёт бесконечную очередь потоков.
- Терминальная runtime-ошибка остаётся видимой при заполненной очереди событий; поздний ACK не
  оживляет упавшую generation, а заведомо непригодная однослотовая очередь отклоняется заранее.

### Packet path, MTU и диагностика потерь

- Downlink-пулы рассчитываются по согласованному MTU с протокольным запасом, а не по максимуму
  64 КиБ на каждый обычный пакет. Android, iOS и Windows packet path сохраняют достаточно слотов
  при кратком stall TUN writer, а реально большой record при необходимости расширяет свой buffer.
- `internal_drops` разделён на pool exhaustion, queue full, oversize, unsupported packet и TUN
  write. Ранее невидимые `EAGAIN`/`ENOBUFS` публикуются в Linux CLI diagnostics.
- Ошибка дублирования очереди TUN и частичная запись пакета больше не считаются успехом и
  останавливают writer с диагностируемой причиной.

### Fail-closed lifecycle хоста

- Linux DNS записывает per-interface ownership до изменения systemd-resolved, сохраняет маркер при
  неудачном revert, не трогает живой чужой интерфейс и восстанавливает legacy `resolv.conf` только
  после выхода последнего подтверждённого владельца.
- Gateway NAT и exit node не стартуют без реально включённого IPv4 forwarding; частичные sysctl и
  firewall изменения откатываются, ошибки cleanup не скрываются, несовместимая комбинация
  gateway/exit-node отклоняется.
- Linux kill switch использует цепочки отдельного экземпляра, откатывает частичный engage,
  безопасно обновляет server-IP allows и снимается только после маршрутов, NAT и forwarding.
- Неудачно удалённый маршрут остаётся в журнале владения для повтора. Qeli не удаляет и не
  присоединяет существующий TUN без доказанного владельца и заранее находит совпадающие TUN names.
- Конкурентный первый запуск сходится к одному device ID, identity key, TOFU pin и session key.
  Повреждённое или заблокированное состояние сохраняется и выдаёт ошибку, а не заменяется молча.
- `auth.password_command` обязан завершиться успешно; длина фактического credential проверяется и
  для password-file/command, а не только для inline password. Password и obfuscation key обнуляются
  после Drop каждого клона конфигурации, использовавшегося reconnect/bonding.

### Windows и macOS

- Новая desktop generation не стартует, пока предыдущая может владеть TUN/socket/routes/firewall.
  Ошибки start, DNS, NetworkPlan, kill switch и teardown доходят до службы и UI вместо ложного
  `Disconnected`.
- Проверяется непустой plan, его generation, поддерживаемость DNS endpoint и наличие descriptor,
  соответствующего заявленному native TUN/Wintun/packet ownership.
- macOS kill switch живёт в отдельном PF anchor, различает активного владельца и crash residue,
  сериализует операции и разрешает port 53 только к системным resolver вместо `to any`.
- Elevated Windows extraction использует каталог без наследования с записью только для
  Administrators/SYSTEM. Привилегированный service не запускает tunnel при недоказанном recovery.
- Desktop editor сохраняет не показанные формой INI-поля и не «отмывает» неизвестные/ошибочные
  ключи. Исправленное поле освобождается от marker, а malformed pinned key не включает TOFU молча.

### Сервер, панель, пользователи и backup

- Profile generation запрещает новые задачи и join-ит дочерние до удаления TUN/NAT. Старый
  supervisor не удаляет replacement с тем же именем. Control socket связывается до data plane, а
  исчезновение control task завершает worker с ошибкой.
- Client subprocess получает timeout, kill и обязательный reap; handle не теряется при ошибке
  teardown и остаётся доступным для следующей попытки cleanup.
- Usage accounting не заменяет повреждённый файл пустыми квотами. Reload хранит последний хороший
  snapshot, reset и flush сериализованы, а неудачная запись откатывает in-memory counters.
- Аутентифицированный logout сохраняет и атомарно повышает общую session generation; ошибка
  долговременной записи возвращается вместо ложного успеха. Конкурентное создание key сходится под
  sidecar lock, приватные файлы имеют `0600`, нечитаемый revoke-state не превращается в разрешающую
  generation `0`.
- Destination ACL пользователей/групп проверяется одинаково для panel, inline, file и restore.
  Полностью ошибочный настроенный список не становится unrestricted; metric обязан быть `u32`, а
  mutation валидирует полный clone до публикации.
- Preflight понимает typed routes (`blackhole`, `unreachable`, `prohibit`) и не позволяет
  отключённому qeli-профилю скрыть конфликт с физическим интерфейсом или route.
- Backup/restore валидирует staged config и зависимости до publish: active path остаётся в
  `/etc/qeli`, users file присутствует и корректен, неизвестный `.conf`, hooks, symlink, type
  mismatch и неточный nested restore отклоняются.
- Quick Start проверяет сохранённые effective port/transport существующего профиля, а не defaults
  карточки. Повтор своего режима разрешён, настоящий конфликт с другим профилем — нет.
- IPv6 DNS resolver отклоняется и в client config, и в server push; installer не принимает IPv6
  literal `PUBLIC_HOST`, пока внутренний data plane остаётся IPv4-only.
- Round-trip fixture клиента фиксирует `server`, `dns_servers` и все runtime keys, чтобы новый parser
  key нельзя было добавить без теста его сохраняемого представления.
- `install-polkit` и `set-service-user` валидируют unit/account до использования в path/policy,
  атомарно пишут rule/drop-in с явными правами и проверяют `chmod`, `chown` и
  `systemctl daemon-reload`. При возврате с root владение `/etc/qeli` исправляется до удаления
  последнего рабочего root override.
- Панель показывает hostname текущего сервера рядом с версией, а UDP-индикаторы теперь явно
  различают ёмкость очереди и заполнение сокетного буфера. Административный доступ проверяется
  реальным запросом `pkcheck`, а не чтением системных polkit rules, обычно недоступных сервисному
  пользователю; отсутствие helper или неопределённый результат не показываются как подтверждённый
  запрет.
- Удаление client-профиля через panel сначала обязано остановить процесс и удалить основной файл;
  сбой очистки log/status возвращается warning. Ошибки сериализации notification config и создания
  каталога web TLS больше не выглядят успешной записью или запуском.

### Фрейминг, инкапсуляция и wire-совместимость

- Native FFI отклоняет null pointer с положительной длиной. EOF внутри TLS record является
  `UnexpectedEof`, а не корректным завершением потока.
- Rust, retained C# и Swift требуют точного полного потребления AEAD record. Корректный
  аутентифицированный префикс с неаутентифицированным хвостом отклоняется; in-place destination
  очищается при любой ошибке decode.
- UDP handshake проверяет record length и overflow до PQ/TLS key schedule; truncated
  ChangeCipherSpec, Certificate, Finished и NewSessionTicket не выводят offset за datagram.
- TCP/sans-IO handshake также требует ожидаемые ChangeCipherSpec и NewSessionTicket. Ошибки
  certificate generation, TLS 1.3 и session ticketer возвращаются из REALITY setup вместо panic;
  IPv6 decoy endpoint собирается общим host/port helper.
- Новый QUIC masking отправляет точный Initial `0xC3`. Parser проверяет version 1, DCID 4 bytes,
  пустые SCID/token, Length, packet number 4 bytes, short flags и полное потребление datagram.
  Для rolling upgrade принимается только точная legacy-форма `0xE3`; произвольный type, битый
  varint и trailing bytes отклоняются.
- Сервер выбирает режим тем же полным structural parser, а не проверкой префикса. Общие fixtures
  синхронизируют Rust, C# и Swift для packet decode, QUIC, fragmentation, replay, PRP nonce и HKDF.
- Документация больше не выдаёт masking за полный QUIC: Initial AEAD, header protection, CRYPTO
  frames и padding Initial до 1200 bytes не реализованы.

### Сборка и release hygiene

- `DELIBERATE_CYCLE` определён на всех targets, что устранило Android E0425. Android libraries были
  пересобраны на этом этапе без изменения exports, но финальная release-сборка всех cores всё равно
  выполняется из конечного release commit.
- После hardening восстановлены Rust build/format/lints. Teardown test ждёт реального Drop и
  выполняется последовательно, исключая ложную ошибку от повторного номера raw fd.
- Keenetic helpers определяют checkout от своего script path, native recipe tests проверяют это, а
  ошибка helper сохраняет ненулевой exit code.
- Временные round-trip snippets удалены из `release/`, версии и build numbers синхронизированы во
  всём дереве исходников.
- Version gate охватывает подписанное macOS per-app extension, а IPv4/DNS diagnostics получают
  номер из `CARGO_PKG_VERSION` вместо hardcode предыдущего релиза.
- После поздних изменений панели `qeli-linux-amd64` и `qeli_0.7.16_amd64.deb` пересобраны из
  commit `4ee837b`; полный lab gate прошёл, включая 633 library tests, formatting, Clippy,
  fuzz/conformance, cargo-deny и ABI-проверку portable-сборки с glibc 2.28.

---

## Release readiness · Готовность релиза

The local candidate passed the documentation/version/configuration gates, GitHub CI, native
provenance checks and the complete release preflight. All first-party native cores were produced by
independent byte-identical A/B builds. Rust tests and the portable glibc 2.28 Debian build passed on
the lab; Android unit tests, signed Release assembly, Windows/macOS Release builds and desktop
self-tests passed. OpenWrt built all four shipped architectures, Keenetic built both shipped
architectures, and the matching aarch64/mipsel outputs are byte-identical. The OpenWrt 23.05.5 SDK
accepted the pinned source tarball and its real mirror hash.

The Linux server binary and Debian package in the candidate now include the late panel commits.
The Windows and macOS files still need a new application build for the later desktop-only commits;
the candidate must not be published as a complete release until those files are refreshed.

Локальный кандидат прошёл gates документации/версий/конфигурации, GitHub CI, проверку native
provenance и полный release preflight. Все first-party native cores получены двумя независимыми
побайтно совпавшими A/B-сборками. На лаборатории прошли Rust tests и portable Debian build с
glibc 2.28; прошли Android unit tests и подписанная Release-сборка, Windows/macOS Release build и
desktop self-tests. OpenWrt собран для четырёх публикуемых архитектур, Keenetic — для двух;
соответствующие aarch64/mipsel файлы побайтно совпадают. SDK OpenWrt 23.05.5 принял закреплённый
source tarball и его настоящий mirror hash.

Linux-бинарник сервера и Debian-пакет в кандидате уже содержат поздние изменения панели. Файлы
Windows и macOS ещё требуют новой сборки приложений после последних desktop-коммитов; до их
обновления кандидат нельзя публиковать как полный релиз.

The production all-modes and Android roaming/sleep lifecycle matrix was not rerun while preparing
this local candidate because it temporarily changes the production profile set and restarts the
service. Run it only in an explicitly authorised maintenance window. GitHub publication, the
`v0.7.16` tag and any merge to `main` have not been performed.

Production all-modes и Android roaming/sleep lifecycle matrix при подготовке локального кандидата
не запускались: проверка временно меняет набор production profiles и перезапускает сервис. Её
следует выполнять только в отдельно согласованное окно обслуживания. Публикация в GitHub, tag
`v0.7.16` и изменения ветки `main` не выполнялись.

---

## Artifacts · Артефакты

Every publishable payload is covered by the accompanying `SHA256SUMS` file.
Каждый публикуемый файл покрыт прилагаемым `SHA256SUMS`.

| Artifact | Size | SHA-256 (first 16) |
|---|---:|---|
| `qeli-android-0.7.16.apk` | 8.4 MB | `b374f4513a77ef7d` |
| `qeli-linux-amd64` | 10.5 MB | `99e268ee5513d922` |
| `qeli_0.7.16_amd64.deb` | 3.4 MB | `74e0702c5816b196` |
| `Qeli-macOS-universal.zip` | 59.3 MB | `8ffe9f18eeb3df9c` |
| `QeliWin-net-required.exe` | 11.3 MB | `9f8accea20d69f77` |
| `QeliWin-standalone.exe` | 74.6 MB | `d097b8b53ccfd21f` |
| `qeli-client-keenetic-aarch64` | 2.9 MB | `dc5bda121e379597` |
| `qeli-client-keenetic-mipsel` | 4.2 MB | `6018ee4e599172d2` |
| `qeli-client-openwrt-aarch64` | 2.9 MB | `dc5bda121e379597` |
| `qeli-client-openwrt-armv7` | 3.0 MB | `9b8cc2b5a347f2e9` |
| `qeli-client-openwrt-mipsel` | 4.2 MB | `6018ee4e599172d2` |
| `qeli-client-openwrt-x86_64` | 3.5 MB | `a963c10b16d91d5f` |
| `qeli-openwrt-files.tar.gz` | 10.4 KB | `4dde1739886d826f` |
| `install-keenetic.sh` | 1.8 KB | `87f1a656d4ff358f` |
| `WinDivert-LICENSE.txt` | 61.3 KB | `c00a04bf0dcca8f7` |
| `WinDivert-NOTICE.txt` | 0.3 KB | `8018c935ccc84a54` |

The Keenetic/OpenWrt aarch64 pair and the Keenetic/OpenWrt mipsel pair are intentionally
byte-identical. Полностью совпадающие хеши этих пар являются ожидаемым результатом.

### Install · Установка

See the [README](https://github.com/litvinovtd/qeli/blob/main/README.md) for complete instructions.
Полные инструкции находятся в [README](https://github.com/litvinovtd/qeli/blob/main/README.md).

- Linux DEB: `sudo dpkg -i qeli_0.7.16_amd64.deb`
- Verify downloads · Проверить файлы: `sha256sum -c SHA256SUMS`
- Android is signed with the existing project key and is intended to install over 0.7.15.
- Android подписан существующим ключом проекта и предназначен для установки поверх 0.7.15.
