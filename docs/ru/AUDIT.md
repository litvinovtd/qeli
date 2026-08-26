# qeli — модель безопасности и состояние
<!-- normative-sync: security-ipv6-v1 -->

Документ описывает **текущую** криптографию, аутентификацию и обфускацию qeli, а
также честный список того, что защищено и что нет. Прошлые аудиты (с открытыми
пунктами A1/UDP/C2 и т.п.) устарели — перечисленные ниже проблемы закрыты или
переосмыслены.

> **Примечание carrier 0.8.0.** Текущий `reality-tls` терминирует REALITY TLS 1.3,
> согласует ALPN `h2` и несёт raw private qeli records через один настоящий долгоживущий HTTP/2
> POST. PacketCodec AEAD остаётся defence-in-depth; прежнего второго fake-TLS handshake/framing нет.

## Криптографическое ядро

| Элемент | Реализация |
|---|---|
| Обмен ключами | X25519 (эфемерный per-session), `x25519-dalek`; во всех режимах кроме `plain` — PQ-гибрид **X25519MLKEM768** (ML-KEM-768, `ml-kem`, ключи данных = `HKDF(x25519 ‖ mlkem)`, `derive_keys_hybrid`). `plain` — классический X25519. Секреты с `zeroize` |
| AEAD | ChaCha20-Poly1305 (`chacha20poly1305`) на дата-плоскости qeli; в `reality-tls` внешний TLS 1.3 — AES-128/256-GCM (`aes-gcm`/rustls-ring) |
| Вывод ключей | HKDF-SHA256, раздельные ключи `server→client` / `client→server` (в `reality-tls` для `TLS_AES_256_GCM` — SHA-384) |
| Пароли | Argon2id (`argon2` 0.5.3), профиль **зафиксирован в коде** — `crypto::password_hasher()` строит `Params::new(19456, 2, 1, None)` (m=19456 KiB, t=2, p=1 — рекомендация OWASP), поэтому обновление крейта не изменит его молча. ПРОВЕРКА намеренно использует `Argon2::default()`: параметры существующего хеша берутся из его собственной PHC-строки, а не из наших — именно это позволяет старым хешам проверяться после смены параметров |
| Anti-replay | 2048-битное скользящее окно по счётчику в `protocol::packet` (размер как у WireGuard, с 0.7.1); отдельный replay-cache захваченного REALITY-ClientHello (анти-replay активного пробинга) |
| Идентичность сервера | Долговременный X25519-ключ **на каждый профиль** в `/etc/qeli/identity/<name>.key` (0600) |

## Рукопожатие и аутентификация (порядок важен)

1. **Carrier-specific обмен.** `fake-tls` использует TLS-shaped ClientHello и X25519 key_share.
   `reality-tls` сначала аутентифицирует REALITY TLS 1.3 и устанавливает настоящий H2;
   приватный qeli handshake и hybrid X25519MLKEM768 затем идут внутри этого carrier.
2. **Channel binding.** В auth_proof подмешивается `transcript_hash =
   SHA256(ClientHello‖ServerHello‖Cert‖Finished)`. Подмена любого сообщения
   в канале ломает proof (защита от split-handshake MITM).
3. **Аутентификация сервера → клиента.** Сервер доказывает владение
   static-ключом: `HKDF(static_shared ‖ ephemeral_shared ‖ transcript)`. Клиент
   проверяет proof и сверяет static-ключ с **запиненным** (`auth.server_public_key`).
   **Это происходит ДО отправки кред** — MITM не может перехватить пароль.
4. **Аутентификация клиента → сервера.** Клиент шлёт (в AEAD-канале)
   `[client_key_proof(32)] [username:password]`; пароль проверяется Argon2id.
5. **Передача данных.** Каждый IP-пакет → AEAD → (опц. паддинг) → запись.

**Варианты шага 1 по wire-режиму** (шаги 2–5 — channel-binding, взаимная
аутентификация, дата-плоскость — одинаковы во всех режимах; меняется только
внешняя обёртка):
- `plain` — без TLS-мимикрии: голый обмен 32-байтными X25519-ключами, записи
  `[len][nonce][ct]` (TCP-only).
- `fake-tls` / `obfs` / `reality` — псевдо-TLS-1.3 ClientHello (см. выше).
- `reality-tls` — browser-shaped TLS 1.3 ClientHello с REALITY-токеном. Сервер опознаёт токен,
  терминирует TLS, согласует ALPN `h2` и принимает один двунаправленный HTTP/2 POST с private
  qeli stream и случайным batching. `handrolled=true` одалживает цепочку target и зеркалит JA3S;
  неавторизованные подключения мостятся на target. Это снижает известные tells, но не означает
  универсальный behavioral-паритет с Xray/браузером.

## Что реализовано для защиты

- **Пиннинг ключа сервера** (`auth.server_public_key` на клиенте). При
  несовпадении — `SERVER KEY MISMATCH`, соединение рвётся.
- **`auth.require_client_key_proof`** (сервер): клиент обязан доказать знание
  запиненного ключа, иначе отказ. Дополнительно: в этом режиме сервер **не
  передаёт** свой static-ключ — он скрыт от сканеров.
- **Авторизация по профилям** (`users.profiles`): юзер одного интерфейса не
  подключится к другому даже с верным паролем.
- **Brute-force**: жёсткий lockout **только по source IP**; по username — адаптивный
  tarpit БЕЗ блокировки, чтобы перебором имени нельзя было заблокировать чужую учётку
  (L1). Окно/порог/блок настраиваются.
- **UDP анти-амплификация**: клиентский initial добивается до ≥1200 байт, сервер
  режет мелкие initial — нельзя использовать сервер как рефлектор.
- **Web-админка**: HTML-страницы аутентифицируются **подписанной сессионной cookie**
  `qeli_session` (HMAC-SHA256, ключ = HKDF(секрет подписи, соль = хеш пароля админа,
  info = поколение сессий); TTL — `web.session_ttl_secs`, клампится 30 сутками).
  По УМОЛЧАНИЮ (`web.persist_session_key = true`) секрет подписи персистится в файл
  0600, поэтому сессии ПЕРЕЖИВАЮТ рестарт; `false` даёт per-process секрет, при
  котором рестарт разлогинивает всех (H-4). `POST /api/logout` инкрементирует
  поколение сессий, что отзывает все ранее выданные токены. Cookie выдаёт
  `POST /api/login` после проверки пароля Argon2id. Страницы **намеренно не
  учитывают** HTTP Basic: иначе Argon2 крутился бы на каждый GET без rate-limit'а.
  Basic остаётся для API/`curl`-пути и идёт через rate-limited `AuthGuard`.
  Плюс same-origin CSRF на мутирующих запросах и path-whitelist для записи
  конфигов/чтения логов.
- **Crash-safe DNS**: восстановление `/etc/resolv.conf` (включая симлинк) с
  персистентным бэкапом и само-лечением при старте.

## Обфускация (wire-режимы)

| Режим | Что на проводе | Против чего |
|---|---|---|
| `plain` (TCP) | без обфускации: голый обмен X25519 + записи `[len][nonce][ct]` | ничего (доверенные сети); самый дешёвый по CPU |
| `fake-tls` (TCP/UDP, деф) | псевдо-TLS-1.3 рукопожатие + Application-Data записи; GREASE, рандом порядок расширений, PQ-key_share | пассивный/сигнатурный DPI |
| `obfs` (TCP) | весь поток XOR ChaCha20-keystream (общий PSK); старт замаскирован под WebSocket Upgrade (printable HTTP) | DPI, ловящий *известные* протоколы (fake-TLS/JA3) + энтропийный «fully encrypted» детект (GFW/ТСПУ) |
| `reality` (TCP) | «свой» ClientHello опознаётся **криптографически** (токен в `session_id`); «чужой»/пробер **проксируется на реальный `target:443`** | активный пробинг (`openssl s_client` видит настоящий сайт) |
| `reality-tls` (TCP) | **настоящий** TLS 1.3 + один genuine H2 streaming POST со случайным batching; с `handrolled` — одолженный серт target'а + зеркалированная форма JA3S | удаляет legacy inner fake-TLS/record-boundary tells и снижает известные probe/fingerprint признаки; универсальной гарантии неотличимости нет |
| QUIC-masking (UDP) | датаграммы под QUIC v1 заголовком (поверх `fake-tls`) | DPI, ждущий QUIC/HTTP3 |

Дополнительно: паддинг (probability/randomize), нормализация длины, fragmentation
рукопожатия, зависящий от режима idle-heartbeat с jitter (принудительно off в Reality/H2), **nonce через 96-битную перестановку
Фейстеля** (на проводе нет инкрементного счётчика — частый отпечаток самописных VPN).

## Что qeli НЕ защищает (честно)

- **fake-TLS — не настоящий TLS.** В режиме `fake-tls` сертификат — псевдо-DER
  заглушка. Против **активного** пробинга нужен REALITY: `reality` (proxy) мостит
  чужих на реальный сайт, а **`reality-tls`** использует настоящий TLS 1.3 + genuine H2
  и с **cert-borrowing** (`handrolled=true`) отдаёт клиенту захваченную цепочку
  серта target'а и зеркалит форму JA3S (не полный паритет с Xray/браузером; см. CONFIG.md/DPI-AUDIT.md). Без
  REALITY `fake-tls`/`obfs` рассчитаны на пассивный DPI.
- **Post-quantum** — гибрид **X25519MLKEM768** теперь рабочий KEX **внутреннего**
  qeli-туннеля во ВСЕХ режимах кроме `plain` (`fake-tls`/`obfs`/`reality-tls`/UDP):
  настоящий ML-KEM-768 encaps/decaps, ключи данных = `HKDF(x25519_shared ‖ mlkem_shared)`
  (`derive_keys_hybrid`). Сервер ТРЕБУЕТ X25519MLKEM768-долю для не-`plain` (нет тихого
  даунгрейда; домен-сепарация солью). Managed-клиенты (C#/Kotlin) берут ML-KEM из ядра
  через C-ABI/JNI (BouncyCastle ML-KEM не содержит). Защита от harvest-now-decrypt-later
  независимо от обёртки.
- **`obfs`-keystream** ограничен 256 ГиБ на направление на сессию — при
  превышении соединение fail-safe реконнектится (без повторного использования
  keystream).
- **TOFU по умолчанию.** Если клиент не запинил ключ и сервер не требует
  `require_client_key_proof`, первый коннект принимается без проверки
  (печатается ключ-кандидат). Для жёсткой защиты включайте `require_client_key_proof`.
- Код **не проходил внешний аудит** и не имеет публичной CVE-истории.

## Формат конфигурации

Единый **flat-INI** для сервера, клиента и базы юзеров (TOML/JSON выпилены
полностью). Юзеры — секции `[user:<name>]`/`[group:<name>]`. Минимальный
клиентский конфиг — секция `[qeli]`, она же разворачивается из `qeli://`-ссылки
(QR-импорт). Подробности — `docs/CONFIG.md`.

## Транспорт auth-ответа

После успешного логина сервер шлёт (в AEAD-канале) самоописательный keyed-JSON
`OK:{client_ip, server_ip, dns, dns_port, routes:[…], obfuscation:{…}}` — каждый
параметр под своим ключом, что исключает рассогласование полей. Pushed-DNS не
отправляется, когда внутритуннельный DNS-прокси выключен (иначе клиент получал
мёртвый резолвер).
Это внутренний payload протокола, а не пользовательский JSON-конфиг или файл.

## IPv6, TAP, NetworkPlan v2 и DATA_FRAG

- **Согласование возможностей.** Внутренний IPv6, NetworkPlan v2 и UDP DATA_FRAG_V1
  включаются только через аутентифицированные capability bits. Режим `required` обязан
  отказывать, если peer или platform adapter не подтверждает весь требуемый контракт.
- **Изоляция семейств.** Outer IPv4/IPv6 выбирает только путь до сервера и не определяет
  внутренний режим. В full-tunnel отсутствующее внутреннее семейство блокируется fail-closed;
  выход напрямую разрешают только явные `allow_ipv4_leak`/`allow_ipv6_leak`, по умолчанию false.
- **TUN и TAP.** TUN принимает только валидные IPv4/IPv6 пакеты. TAP остаётся локальным
  Ethernet-framing adapter поверх L3 qeli: пропускаются IPv4/IPv6, локально обслуживаются
  необходимые ARP/NDP/Router Solicitation, а VLAN/STP/LLDP и произвольные EtherType не
  превращают туннель в прозрачный L2-мост.
- **Фрагментация.** DATA_FRAG отделяет внутренний MTU от внешнего UDP budget. Фрагменты
  принимаются только после capability negotiation и аутентификации, имеют строгие лимиты
  размера/числа/времени reassembly и отдельный MAC-derived контекст; это ограничивает
  memory/CPU amplification, но reassembly остаётся fuzz- и soak-поверхностью.
- **PMTU.** IPv6 не фрагментируется маршрутизатором: ICMPv6 Packet Too Big и живой UDP
  probe критичны. Ложные/запоздалые ответы не должны повышать бюджет другого path epoch;
  при неопределённости используется консервативный budget либо соединение отклоняется.

## Качество кода

- Юнит-тестов **сотни, и число растёт** (`cargo test --workspace`); release-gate 0.7.16
  сообщил 635 library-тестов плюс 8 CLI/config-тестов. Это датированный снимок — источником
  истины остаётся текущий лог job `build-test` в CI. Покрыто: crypto
  round-trip, **2048-битное replay-окно** на сервере и клиенте, PRP-биективность,
  channel-binding симуляция, keyed auth-OK round-trip, qeli://-link round-trip,
  IpPool/RateLimiter/FailedAuthTracker, INI round-trip, obfs roundtrip TCP +
  per-datagram UDP, plain raw-фрейминг + TCP-only guard, REALITY token seal/open,
  realtls handshake-interop с rustls (оба cipher-suite + PQ-гибрид), cert-borrowing,
  NewSessionTicket, авторизация по профилям, QR-рендер.
- Сборка `cargo build --release` чистая, **0 warning'ов**; дерево
  rustfmt/clippy-нормализовано.
- CI в 0.7.16: `.github/workflows/ci.yml` — четырнадцать top-level job'ов. Актуальный состав всегда в самом
  файле (список тут неизбежно устареет), поэтому по смыслу: сверка хешей закоммиченных
  нативных ядер (`native-libs`), сборка + весь набор тестов (`build-test`), настоящая
  сборка/установка Debian-пакета (`deb-package`), lint установщиков (`shellcheck`), формат и
  clippy `-D warnings` (`lint`), проверки документации и синхронности версий (`docs` →
  `scripts/check_docs.py` + `scripts/sync_version.py`), `cargo audit` по базе RUSTSEC
  (`security-audit`, в файле помечен `# HARD GATE`), компиляция клиентов Android /
  Windows / macOS / iOS и кросс-сборка под роутер (`keenetic-cross`), а также fuzz —
  короткий smoke на push и длинный прогон по расписанию. Ни у одного job нет
  `continue-on-error: true`; `fuzz-smoke` намеренно остаётся hard gate даже с nightly
  toolchain. Отдельный workflow `.github/workflows/dco.yml` требует
  `Signed-off-by` в каждом коммите PR. Локальный прогон полного гейта —
  `scripts/lab_sync_build.py` (sync → build → test → clippy на лабе).
