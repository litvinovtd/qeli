# qeli 0.8.0 (beta) — IPv6, session roaming and a new packet data plane

> ⚠️ **Beta — may be unstable.** The **1.0** line will be the first stable one.
>
> ⚠️ **Бета — возможна нестабильность.** Стабильной станет линейка **1.0**.

**Release candidate prepared · Кандидат подготовлен:** 2026-09-01

**Language · Язык:** [English](#english) · [Русский](#русский) ·
[Artifacts](#artifacts--артефакты)

This document describes the fundamental changes since `v0.7.16`. The canonical itemised history,
including smaller fixes, is available in [CHANGELOG.md](../CHANGELOG.md).

---

## English

qeli 0.8.0 is not a collection of isolated fixes. It changes the foundation on which transports,
sessions and routes are built: IPv6 becomes a first-class network family, a VPN session can survive
a change of physical path, and encrypted record formation is no longer tied one-to-one to IP packet
boundaries. Reality transport also moves to a genuine TLS 1.3 and HTTP/2 carrier.

### Why 0.8.0 instead of 0.7.17

A `0.7.17` version would imply another compatible patch within the same operating model. This
release introduces a new capability-negotiated data plane, a new session/path lifecycle, dual-stack
server configuration and a new native-core ABI. These are platform-wide capabilities shared by the
server, mobile and desktop applications, router clients and the administration layer—not local bug
fixes in one component.

The release remains `0.8.0`, rather than `1.0`, because qeli is still in beta and the rollout is
designed to preserve mixed-version operation. Legacy clients can continue through negotiated
fallback or reconnect, existing profiles are not silently rewritten, and the new recordizer and
roaming policies can be introduced gradually. The minor-version bump signals a substantial new
architecture while the compatibility controls keep it short of a deliberately breaking major
release.

### IPv6 becomes a first-class network layer

IPv6 is no longer treated as an optional address attached to an IPv4-oriented tunnel. It now
participates in configuration validation, address allocation, route ownership, DNS, PMTU discovery,
fail-closed decisions and platform path changes on the same terms as IPv4.

- New server templates are dual-stack. Every profile receives an IPv4 pool and a separate IPv6 ULA
  `/64`, with NAT44 and NAT66 support and DNS listeners for both address families.
- The installer checks for a real IPv6 default route, a usable WAN interface, a public GUA and
  `ip6tables` NAT support. When the host is suitable, it generates a random RFC 4193 Global ID and a
  unique ULA `/48`; when it is not, installation safely falls back to IPv4-only operation.
- Existing configurations are intentionally left unchanged. IPv6 is enabled through an explicit
  migration, including the tunnel address family, IPv6 pool, NAT66/routing and DNS listener. This
  prevents an upgrade from unexpectedly taking ownership of IPv6 traffic.
- Route-family mismatches and unsafe path updates fail closed. The same IPv4/IPv6 contract is used by
  Linux, Windows, macOS, Android, iOS and router clients.

The result is a real dual-stack VPN path rather than IPv6 traffic being leaked, ignored or handled by
platform-specific exceptions. See the [IPv6 guide](../docs/eng/manuals/IPV6.md) for deployment and
migration details.

### Roaming separates the session from the connection

Previously, changing Wi-Fi, mobile data, NAT mapping or another uplink normally meant losing the
carrier and establishing a new VPN session. In 0.8.0 the authenticated session has its own lifetime
and can move to a new network path without being equated with one TCP connection or UDP tuple.

- Roaming is negotiated by the shared Rust core for ordinary TCP and all UDP camouflage modes.
  Clients expose `off`, `auto` and `required` policies; `required` rejects an incomplete peer or
  platform contract before credentials and full authentication are sent.
- TCP uses make-before-break with a two-phase path commit. The old carrier stays active until the new
  path is established, applied by the platform and acknowledged. An ambiguous post-commit state is
  terminated and recovered by a clean reconnect rather than left as a traffic black hole.
- UDP migration uses authenticated epochs and a bounded pre-commit queue. It accepts NAT rebinding
  and reordered traffic while rejecting stale paths and unbounded buffering.
- Break-before-make carrier loss is now covered as well: when an interface disappears before the
  platform reports its replacement, the UDP session keeps its authenticated generation for one
  bounded 15-second recovery window, requests an immediate path refresh where supported and drops
  uplink packets instead of building an unbounded queue. A valid candidate is committed into the
  existing session; expiry falls back to a clean reconnect. TCP also distinguishes a rejected
  pre-commit request from an actually issued commit, preserving rollback-safe recovery.
- Android and iOS feed physical-network changes into the same generation state machine used by the
  desktop platforms. If a platform or native core cannot prove that a path switch succeeded, qeli
  falls back to reconnect instead of reporting a migration that did not happen.

Newly generated server profiles enable roaming with bounded limits and clients default to
`roaming = auto`. Existing profiles keep roaming disabled when `roaming.enabled` is absent, so the
feature is never activated silently. The full state and compatibility contract is documented in the
[roaming plan](../docs/eng/plans/ROAMING.md).

### Recordizer changes traffic morphology across transports

`PACKET_MUX_V1`, referred to as the recordizer, adds a negotiated layer between TUN packets and the
selected TCP or UDP carrier. It removes the observable structural rule that one incoming IP packet
must produce one qeli encrypted record.

The recordizer can batch several packets into one record, emit partial or full records, and split a
large packet across several encrypted records before reconstructing it at the peer. Batching and
reassembly are strictly bounded. The outer transport remains unchanged, so the same mechanism works
across all supported TCP and UDP camouflage modes rather than being a feature of one carrier.

Recordizer parameters are authenticated and supplied by the server during negotiation; no new
client secret or qeli-link field is needed. The rollout policies are:

- `off` — retain the legacy packet-to-record mapping;
- `prefer` — use `PACKET_MUX_V1` when both peers support it and preserve rolling compatibility;
- `required` — reject peers without the new data plane after the fleet has been upgraded.

Shipped profiles use `prefer`. Recordization reduces a transport-independent packet-boundary
fingerprint, but it is not presented as making traffic undetectable.

### Reality/TLS is rebuilt around a genuine HTTP/2 carrier

The `reality-tls` mode now uses an actual TLS 1.3 connection with ALPN `h2`, standard HTTP/2 framing
and one long-lived bidirectional POST stream. Random short batching is performed within real H2
frames, while qeli PacketCodec AEAD remains as the authenticated payload layer. The redundant inner
fake-TLS handshake and framing are removed.
The wire stack is now **TCP → REALITY TLS 1.3 → genuine HTTP/2 →
private qeli stream**; there is no second simulated TLS protocol inside the real one.

This matters operationally as well as on the wire: the qeli heartbeat is unnecessary for this
carrier, traffic shaping can operate on genuine H2 frames, and the transport has one clear framing
model instead of nested imitations. A 0.8.0 server still accepts the legacy Reality carrier, but the
new client is H2-only and does not downgrade. Therefore the server must be upgraded first. Reality/H2
also requires transparent TCP pass-through to qeli; TLS termination, H2 conversion or HTTP routing
by an intermediate reverse proxy breaks authentication.

#### How to migrate and enable it

The genuine H2 carrier is selected automatically by `mode = reality-tls`; there is no separate H2
switch. To migrate an existing deployment:

1. **Preserve the current credentials.** Back up the server profile, qeli identity key and
   `short_ids`. Do not rotate them as part of this upgrade unless all client profiles will be reissued.
2. **Update the server binary first.** The 0.8.0 server accepts both the legacy Reality carrier and
   the new H2 carrier. The restart interrupts active sessions, but old clients can reconnect while the staged client rollout continues.
3. **Normalize the server profile.** Use TCP, `obf.mode = reality-tls`,
   `obf.tls.reality_proxy.enabled = true` and `obf.tls.reality_proxy.real_tls = true`. Keep one real DNS name consistent in
   `obf.tls.server_name`, `obf.tls.reality_proxy.target` and the client `sni`; preserve the existing `short_ids`.
   Disable heartbeat and per-packet padding, enable traffic shaping, and remove retired
   `obf.http2_masking.*` keys.
4. **Check the path and clocks.** Port 443 must reach qeli through transparent TCP pass-through, and
   client/server time must remain within ±120 seconds when Reality short IDs are used.
5. **Restart and test the server before clients.** Confirm that an old client still reaches `AUTH OK`,
   then update every client application/native core. Client profiles keep `proto = tcp`,
   `mode = reality-tls` and their existing `key`, `sni` and `reality_sid` values.
6. **Verify the new carrier.** The client log should contain
   `REALITY-TLS carrier: genuine HTTP/2 stream`, followed by `AUTH OK` and bidirectional traffic.
   With debug logging enabled, the server also records `REALITY: genuine HTTP/2 carrier established`.

Bare `fake-tls` is a different mode and does not become Reality/H2 automatically. Keep it on a
separate legacy profile or port if it is still required.

### What this gives qeli

Together, these changes move qeli from a tunnel whose lifetime and packet shape are largely defined
by one connection into a unified cross-platform transport system. The server and every client family
now share the same model of address families, session generations, path migration and encrypted
record formation.

In practical terms, this gives qeli:

- **real dual-stack operation** — IPv4 and IPv6 follow one validated routing and fail-closed policy,
  reducing the risk of IPv6 bypasses and platform-specific behaviour;
- **continuity while the network changes** — an authenticated session can survive switching between
  Wi-Fi, mobile data, NAT mappings and other uplinks, reducing visible interruptions and repeated full
  reconnects;
- **transport-independent traffic morphology** — recordization removes the fixed relationship
  between an IP packet and an encrypted record across all supported carriers, rather than improving
  only one camouflage mode;
- **one implementation of critical behaviour** — the shared Rust core keeps roaming, PMTU, path
  ownership and compatibility decisions consistent across desktop, mobile and router clients;
- **a controlled evolution path** — capability negotiation, `prefer` policies and fail-closed
  `required` modes allow new protocol behaviour to be deployed server-first without cutting off the
  existing fleet;
- **a foundation for future transports** — new carriers can reuse the same session, routing and
  recordization layers instead of implementing their own platform-specific data plane.

For users, the visible result is a more stable connection during movement between networks, correct
IPv6 tunnelling and more consistent behaviour across devices. For operators, it is predictable
rollout, explicit compatibility controls and aggregate transport/roaming health in the panel without
exposing session identifiers, proofs or secrets.

Supporting application work exposes these capabilities safely: profile editors understand roaming
policy, while Windows per-app routing preserves direct traffic outside selected processes. Routing,
PMTU handling, configuration validation and recovery were strengthened around the new architecture;
detailed individual changes remain in the changelog.

### Upgrade order

1. Upgrade the server and run `qeli check-config` before restarting it.
2. Keep `obf.recordizer.policy = prefer` during a mixed-version rollout. Reconnect clients so the
   authenticated capability negotiation is repeated.
3. Migrate existing profiles to IPv6 explicitly only after validating host IPv6 and NAT66 support.
4. Update applications and native cores, then test IPv4, IPv6 and network switching on the platforms
   used by the deployment.
5. Enable `roaming = required` or recordizer `required` only after every required peer and platform is
   known to support the complete contract.

For all configuration fields see the [configuration reference](../docs/eng/manuals/CONFIG.md) and
[transport-core reference](../docs/eng/reference/TRANSPORT-CORE.md).

### Release verification

The 2026-09-01 candidate was rebuilt after the break-before-make fix in Rust/native source commit
`f2dbe7fe`. It passed the Rust workspace, CLI/configuration, dependency-policy, jemalloc and portable
Linux/DEB gates. Native cores were rebuilt for Android arm64-v8a/x86_64, Windows x64
and macOS universal2 and matched across independent A/B builds. The signed Android APK, both
Windows executables, the ad-hoc signed universal macOS bundle, four OpenWrt clients and two
Keenetic clients were then rebuilt from those inputs. The DEB contains the exact standalone Linux
binary, and every payload is covered by the candidate's `SHA256SUMS`.

This local candidate has not been published. Release publication still requires final preflight
for the committed source and a remote CI run covering that exact commit after it is pushed.
Machine-readable certification retains unavailable physical roaming/IPv6 cases as an explicit
advisory backlog; an executed failure remains blocking.

---

## Русский

qeli 0.8.0 — это не набор отдельных исправлений. В этой версии меняется основа, на которой построены
транспорты, сессии и маршрутизация: IPv6 становится полноценным семейством сети, VPN-сессия может
переживать смену физического пути, а формирование шифрованных записей больше не привязано один к
одному к границам IP-пакетов. Транспорт Reality также переведён на настоящий TLS 1.3 и HTTP/2.

### Почему 0.8.0, а не 0.7.17

Номер `0.7.17` означал бы очередное совместимое исправление в рамках прежней модели работы. Этот
релиз добавляет новый согласуемый data plane, новый жизненный цикл сессии и сетевого пути,
dual-stack-конфигурацию сервера и новую ABI нативного ядра. Это общие возможности всей платформы —
сервера, мобильных и настольных приложений, роутерных клиентов и панели, — а не локальные исправления
одного компонента.

При этом версия остаётся `0.8.0`, а не `1.0`: qeli всё ещё находится в бета-стадии, а обновление
спроектировано для смешанного парка версий. Старые клиенты продолжают работать через согласованный
fallback или переподключение, существующие профили не переписываются молча, recordizer и роуминг
можно включать поэтапно. Повышение минорной версии подчёркивает существенную смену архитектуры, а
механизмы совместимости не превращают её в намеренно ломающий major-релиз.

### IPv6 становится полноценным сетевым уровнем

IPv6 больше не рассматривается как необязательный адрес внутри IPv4-ориентированного туннеля. Теперь
он наравне с IPv4 участвует в проверке конфигурации, распределении адресов, владении маршрутами, DNS,
определении PMTU, fail-closed-решениях и смене пути на каждой платформе.

- Новые серверные шаблоны работают в dual-stack. Каждый профиль получает IPv4-пул и отдельную IPv6
  ULA-подсеть `/64`, поддержку NAT44 и NAT66, а также DNS-listener для обоих семейств адресов.
- Установщик проверяет реальный IPv6 default route, пригодный WAN-интерфейс, публичный GUA-адрес и
  поддержку NAT в `ip6tables`. На подходящем сервере он генерирует случайный RFC 4193 Global ID и
  уникальную ULA-сеть `/48`; если необходимых условий нет, установка безопасно остаётся IPv4-only.
- Существующие конфигурации намеренно не изменяются автоматически. IPv6 включается явной миграцией:
  задаются семейство адресов туннеля, IPv6-пул, NAT66/маршрутизация и DNS-listener. Поэтому обновление
  не начинает неожиданно перехватывать IPv6-трафик.
- Несовпадения семейств маршрутов и небезопасное обновление пути завершаются fail-closed. Linux,
  Windows, macOS, Android, iOS и роутерные клиенты используют один контракт IPv4/IPv6.

В результате qeli предоставляет настоящий dual-stack VPN-путь, а не пропускает IPv6 мимо туннеля и
не полагается на отдельные исключения каждой платформы. Порядок развёртывания и миграции описан в
[руководстве по IPv6](../docs/ru/manuals/IPV6.md).

### Роуминг отделяет сессию от соединения

Раньше смена Wi-Fi, мобильной сети, NAT mapping или другого uplink обычно означала потерю carrier и
создание новой VPN-сессии. В 0.8.0 аутентифицированная сессия имеет собственный жизненный цикл и может
переехать на новый сетевой путь, не будучи жёстко привязанной к одному TCP-соединению или UDP tuple.

- Роуминг согласуется общим Rust-ядром для обычного TCP и всех UDP camouflage modes. На клиенте есть
  политики `off`, `auto` и `required`; `required` отклоняет неполный контракт peer или платформы до
  отправки credentials и полной аутентификации.
- TCP использует make-before-break и двухфазную фиксацию пути. Старый carrier остаётся активным, пока
  новый путь не установлен, не применён платформой и не подтверждён. Неоднозначная post-commit ошибка
  завершает generation и запускает чистое переподключение, а не оставляет соединение в blackhole.
- Миграция UDP использует аутентифицированные epoch и ограниченную очередь до commit. Она корректно
  обрабатывает смену NAT mapping и переупорядочивание трафика, отклоняя устаревшие пути и не допуская
  неограниченного накопления данных.
- Учтена и потеря carrier по схеме break-before-make: если интерфейс исчез раньше, чем платформа
  сообщила замену, UDP-сессия сохраняет аутентифицированное поколение на одно ограниченное окно
  восстановления в 15 секунд, запрашивает немедленное обновление пути там, где это поддерживается,
  и отбрасывает исходящие пакеты вместо накопления неограниченной очереди. Валидный кандидат
  фиксируется в прежней сессии, а по истечении окна выполняется чистое переподключение. TCP теперь
  также отличает отклонённый запрос до commit от действительно отправленного commit.
- Android и iOS передают смену физической сети в ту же generation state machine, что используется на
  desktop-платформах. Если платформа или native core не может подтвердить успешную смену пути, qeli
  выполняет reconnect, а не сообщает о миграции, которой фактически не произошло.

Новые серверные профили включают роуминг с ограниченными лимитами, а клиенты по умолчанию используют
`roaming = auto`. В существующем профиле отсутствие `roaming.enabled` по-прежнему означает `false`,
поэтому функция не активируется молча. Полный контракт состояний и совместимости приведён в
[плане роуминга](../docs/ru/plans/ROAMING.md).

### Recordizer меняет морфологию трафика для всех транспортов

`PACKET_MUX_V1`, или recordizer, добавляет согласуемый слой между пакетами TUN и выбранным TCP- или
UDP-carrier. Он устраняет структурное правило, при котором один входящий IP-пакет обязательно
превращался ровно в одну шифрованную запись qeli.

Recordizer может объединить несколько пакетов в одну запись, формировать полные и частичные записи,
а также разделить большой пакет между несколькими шифрованными записями и восстановить его на другой
стороне. Batching и reassembly имеют строгие лимиты. Внешний транспорт при этом не меняется, поэтому
механизм одинаково работает во всех поддерживаемых TCP- и UDP-режимах маскировки, а не принадлежит
только одному carrier.

Параметры recordizer приходят от сервера внутри аутентифицированного согласования; новый секрет или
поле qeli-ссылки клиенту не требуется. Для поэтапного внедрения предусмотрены политики:

- `off` — сохранить прежнее соответствие пакетов и записей;
- `prefer` — использовать `PACKET_MUX_V1`, когда его поддерживают обе стороны, сохраняя rolling
  compatibility;
- `required` — отклонять peer без нового data plane после обновления всего парка.

Поставляемые профили используют `prefer`. Recordizer снижает транспортно-независимый fingerprint по
границам пакетов, но это не заявляется как полная неразличимость трафика.

### Reality/TLS переработан вокруг настоящего HTTP/2 carrier

Режим `reality-tls` теперь использует реальное TLS 1.3-соединение с ALPN `h2`, стандартный HTTP/2
framing и один долгоживущий двусторонний POST stream. Короткий случайный batching выполняется внутри
настоящих H2 frames, а PacketCodec AEAD qeli остаётся аутентифицированным слоем полезной нагрузки.
Лишние внутренние fake-TLS handshake и framing удалены.
Новый стек на проводе: **TCP → REALITY TLS 1.3 → настоящий HTTP/2 →
приватный поток qeli**; второго имитируемого TLS-протокола внутри настоящего TLS больше нет.

Это важно не только для вида трафика, но и для эксплуатации: собственный heartbeat qeli для этого
carrier больше не нужен, shaping работает с настоящими H2 frames, а вместо вложенных имитаций остаётся
одна понятная модель framing. Сервер 0.8.0 продолжает принимать прежний Reality carrier, однако новый
клиент работает только через H2 и не выполняет downgrade. Поэтому первым обязательно обновляется
сервер. Reality/H2 также требует прозрачного TCP pass-through до qeli: TLS termination, H2 conversion
или HTTP routing на промежуточном reverse proxy ломают аутентификацию.

#### Как перейти на новую реализацию и включить её

Настоящий H2 carrier включается автоматически через `mode = reality-tls`; отдельного H2-переключателя
нет. Для миграции существующей установки:

1. **Сохраните действующие credentials.** Сделайте резервную копию серверного профиля, identity key
   qeli и `short_ids`. Не меняйте их вместе с обновлением, если не готовы переиздать все профили.
2. **Сначала обновите серверный бинарник.** Сервер 0.8.0 принимает старый Reality carrier и новый H2.
   Рестарт прерывает активные сессии, но старые клиенты переподключаются и могут обновляться постепенно.
3. **Приведите серверный профиль к новой схеме.** Используйте TCP, `obf.mode = reality-tls`,
   `obf.tls.reality_proxy.enabled = true` и `obf.tls.reality_proxy.real_tls = true`. Одно реальное DNS-имя должно совпадать
   в `obf.tls.server_name`, `obf.tls.reality_proxy.target` и клиентском `sni`; сохраните прежние `short_ids`.
   Отключите heartbeat и per-packet padding, включите traffic shaping и удалите устаревшие ключи
   `obf.http2_masking.*`.
4. **Проверьте сетевой путь и время.** Порт 443 должен доходить до qeli через прозрачный TCP
   pass-through, а часы клиента и сервера при использовании Reality short ID — совпадать в пределах
   ±120 секунд.
5. **Перезапустите и сначала проверьте сервер.** Старый клиент должен по-прежнему получить `AUTH OK`.
   После этого обновите приложения и native core на всех клиентах. В клиентском профиле сохраняются
   `proto = tcp`, `mode = reality-tls` и прежние значения `key`, `sni`, `reality_sid`.
6. **Проверьте новый carrier по логам.** Клиент должен вывести
   `REALITY-TLS carrier: genuine HTTP/2 stream`, затем `AUTH OK` и двусторонний трафик.
   При debug-логировании сервер также пишет `REALITY: genuine HTTP/2 carrier established`.

Обычный `fake-tls` — отдельный режим и автоматически не превращается в Reality/H2. Если он ещё нужен,
оставьте его на отдельном legacy-профиле или порту.

### Что это даёт qeli

Вместе эти изменения превращают qeli из туннеля, жизненный цикл и форма трафика которого в основном
определялись одним соединением, в единую кроссплатформенную транспортную систему. Сервер и все
семейства клиентов теперь используют общую модель семейств адресов, поколений сессии, миграции пути
и формирования шифрованных записей.

На практике qeli получает:

- **настоящую dual-stack-работу** — IPv4 и IPv6 подчиняются одной проверяемой политике маршрутизации
  и fail-closed, что снижает риск обхода туннеля через IPv6 и различий между платформами;
- **непрерывность при смене сети** — аутентифицированная сессия может пережить переход между Wi-Fi,
  мобильной сетью, разными NAT mapping и другими uplink, сокращая заметные разрывы и повторные полные
  подключения;
- **независимую от транспорта морфологию трафика** — recordizer убирает фиксированную связь между
  IP-пакетом и шифрованной записью во всех поддерживаемых carrier, а не улучшает только один режим
  маскировки;
- **единую реализацию критической логики** — общее Rust-ядро одинаково управляет роумингом, PMTU,
  владением сетевым путём и совместимостью на настольных, мобильных и роутерных клиентах;
- **контролируемое развитие протокола** — согласование возможностей, политика `prefer` и fail-closed
  режим `required` позволяют сначала обновить сервер и постепенно внедрить новое поведение, не
  отключая существующий парк клиентов;
- **основу для следующих транспортов** — новые carrier смогут использовать готовые слои сессии,
  маршрутизации и recordizer вместо отдельного platform-specific data plane.

Для пользователя итогом становятся более стабильное соединение при переходах между сетями,
корректное туннелирование IPv6 и одинаковое поведение на разных устройствах. Для оператора —
предсказуемое поэтапное обновление, явное управление совместимостью и агрегированное состояние
транспорта/роуминга в панели без идентификаторов сессий, proof и секретов.

Сопутствующие изменения приложений безопасно открывают эти возможности: редакторы профилей понимают
политику роуминга, а Windows per-app сохраняет прямой трафик процессов вне выбранного списка.
Маршрутизация, PMTU, проверка конфигурации и восстановление усилены вокруг новой архитектуры; полный
перечень небольших изменений остаётся в changelog.

### Порядок обновления

1. Сначала обновите сервер и перед рестартом выполните `qeli check-config`.
2. Во время работы смешанного парка версий оставьте `obf.recordizer.policy = prefer`. Переподключите
   клиентов, чтобы аутентифицированное согласование возможностей выполнилось заново.
3. Переносите существующие профили на IPv6 только явно и после проверки IPv6/NAT66 на хосте.
4. Обновите приложения и native cores, затем проверьте IPv4, IPv6 и смену сети на используемых
   платформах.
5. Включайте `roaming = required` или recordizer `required` только после подтверждения полного
   контракта на всех обязательных peer и платформах.

Все параметры приведены в [справочнике конфигурации](../docs/ru/manuals/CONFIG.md) и
[описании transport core](../docs/ru/reference/TRANSPORT-CORE.md).

### Проверка релиза

Кандидат от 2026-09-01 полностью пересобран после исправления break-before-make в commit исходников
Rust/native `f2dbe7fe`. Он прошёл release gates Rust workspace, CLI/configuration suites, dependency
policy, jemalloc и portable Linux/DEB. Native cores пересобраны для Android arm64-v8a/x86_64,
Windows x64 и macOS universal2 и совпали в независимых A/B-сборках. После этого заново собраны
подписанный Android APK, оба Windows EXE, ad-hoc подписанный universal macOS bundle, четыре клиента
OpenWrt и два клиента Keenetic. DEB содержит в точности тот же бинарник, что и standalone Linux,
а каждый payload покрыт новым `SHA256SUMS` кандидата.

Этот локальный кандидат ещё не опубликован. Для публикации нужны финальный preflight на
закоммиченном дереве и удалённый CI для этого же commit после push. Машиночитаемая сертификация
сохраняет недоступные физические roaming/IPv6-проверки как явный неблокирующий backlog;
реально выполненная неуспешная проверка остаётся блокирующей.

---

## Artifacts · Артефакты

`release/dist/v0.8.0` contains the freshly rebuilt local candidate: 17 payloads plus
`SHA256SUMS`. The table identifies the exact files prepared on 2026-09-01. Каталог
`release/dist/v0.8.0` содержит заново собранный локальный кандидат: 17 payload-файлов и
`SHA256SUMS`. Таблица описывает точные файлы, подготовленные 2026-09-01.

| Artifact | Size | SHA-256 (first 16) |
|---|---:|---|
| `qeli-android-0.8.0.apk` | 9.8 MB | `c43f4831d3489dc7` |
| `qeli-linux-amd64` | 12.6 MB | `1c94e93bf5ecb377` |
| `qeli_0.8.0_amd64.deb` | 4.0 MB | `a40f77a3f335d5b2` |
| `Qeli-macOS-universal.zip` | 57.9 MB | `51ba8ac13ea5811d` |
| `QeliWin-net-required.exe` | 8.0 MB | `53e3398101368ad4` |
| `QeliWin-standalone.exe` | 72.7 MB | `28480f6f3d13f401` |
| `qeli-client-keenetic-aarch64` | 4.0 MB | `b02cff7569d6bfa8` |
| `qeli-client-keenetic-mipsel` | 5.7 MB | `1ee78b7f1ff98e8f` |
| `qeli-client-openwrt-aarch64` | 4.0 MB | `b02cff7569d6bfa8` |
| `qeli-client-openwrt-armv7` | 4.2 MB | `74a8e76a38d717fd` |
| `qeli-client-openwrt-mipsel` | 5.7 MB | `1ee78b7f1ff98e8f` |
| `qeli-client-openwrt-x86_64` | 4.7 MB | `499ffbcb55324c1b` |
| `qeli-openwrt-files.tar.gz` | 12.7 KB | `be63fc06eb73c91f` |
| `install-keenetic.sh` | 2.3 KB | `fa12354977d6a81e` |
| `Wintun-LICENSE.txt` | 5.3 KB | `9aaf948856ce8845` |
| `WinDivert-LICENSE.txt` | 61.3 KB | `c00a04bf0dcca8f7` |
| `WinDivert-NOTICE.txt` | 0.3 KB | `8018c935ccc84a54` |

The Keenetic/OpenWrt aarch64 pair and the Keenetic/OpenWrt mipsel pair are intentionally
byte-identical. Полностью совпадающие хеши этих пар являются ожидаемым результатом.

### Candidate handling · Работа с кандидатом

Do not publish the candidate until final preflight and remote CI pass for the source being released.
The payload rebuild and checksum regeneration are complete; no GitHub release has been created.
Не публиковать кандидат до успешных финального preflight и удалённого CI для выпускаемого дерева.
Пересборка payload-файлов и обновление контрольных сумм завершены; GitHub Release не создавался.
