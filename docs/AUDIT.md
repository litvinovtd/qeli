# qeli — модель безопасности и состояние

Документ описывает **текущую** криптографию, аутентификацию и обфускацию qeli, а
также честный список того, что защищено и что нет. Прошлые аудиты (с открытыми
пунктами A1/UDP/C2 и т.п.) устарели — перечисленные ниже проблемы закрыты или
переосмыслены.

## Криптографическое ядро

| Элемент | Реализация |
|---|---|
| Обмен ключами | X25519 (эфемерный per-session), `x25519-dalek`; в `reality-tls` — PQ-гибрид **X25519MLKEM768** (ML-KEM-768, `ml-kem`, общий секрет `ML-KEM ‖ X25519`). Секреты с `zeroize` |
| AEAD | ChaCha20-Poly1305 (`chacha20poly1305`) на дата-плоскости qeli; в `reality-tls` внешний TLS 1.3 — AES-128/256-GCM (`aes-gcm`/rustls-ring) |
| Вывод ключей | HKDF-SHA256, раздельные ключи `server→client` / `client→server` (в `reality-tls` для `TLS_AES_256_GCM` — SHA-384) |
| Пароли | Argon2id (`argon2`), параметры m=16384,t=2,p=1 |
| Anti-replay | 64-битное скользящее окно по счётчику в `protocol::packet`; отдельный replay-cache захваченного REALITY-ClientHello (анти-replay активного пробинга) |
| Идентичность сервера | Долговременный X25519-ключ **на каждый профиль** в `/etc/qeli/identity/<name>.key` (0600) |

## Рукопожатие и аутентификация (порядок важен)

1. **Эфемерный обмен.** Клиент шлёт fake-TLS ClientHello (с GREASE и
   рандомизированным порядком расширений → JA3 меняется per-connection),
   сервер — ServerHello/Certificate/Finished. Общий секрет — X25519 из key_share.
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
- `reality-tls` — **настоящий** браузерный (Chrome JA4) TLS 1.3 ClientHello с
  REALITY-токеном в `session_id` = `HKDF(X25519(eph, reality_pub) ‖ short_id)`.
  Сервер криптографически опознаёт «своего» (открывает токен приватником профиля,
  сверяет с `short_ids`), терминирует настоящий TLS 1.3 (rustls **или** hand-rolled)
  и несёт qeli-туннель ВНУТРИ него; KEX — PQ-гибрид X25519MLKEM768. «Чужой»/пробер
  прозрачно проксируется на реальный `target:443`. С `handrolled=true` сервер
  **одалживает настоящую цепочку серта target'а** (cert-borrowing, авто-refresh 12ч)
  и зеркалит его JA3S/ServerHello — паритет с Xray-REALITY.

## Что реализовано для защиты

- **Пиннинг ключа сервера** (`auth.server_public_key` на клиенте). При
  несовпадении — `SERVER KEY MISMATCH`, соединение рвётся.
- **`auth.require_client_key_proof`** (сервер): клиент обязан доказать знание
  запиненного ключа, иначе отказ. Дополнительно: в этом режиме сервер **не
  передаёт** свой static-ключ — он скрыт от сканеров.
- **Авторизация по профилям** (`users.profiles`): юзер одного интерфейса не
  подключится к другому даже с верным паролем.
- **Brute-force**: lockout по **связке user+IP** (окно/порог/блок настраиваются).
- **UDP анти-амплификация**: клиентский initial добивается до ≥1200 байт, сервер
  режет мелкие initial — нельзя использовать сервер как рефлектор.
- **Web-админка**: Basic-Auth с Argon2id, same-origin CSRF на мутирующих запросах,
  path-whitelist для записи конфигов/чтения логов.
- **Crash-safe DNS**: восстановление `/etc/resolv.conf` (включая симлинк) с
  персистентным бэкапом и само-лечением при старте.

## Обфускация (wire-режимы)

| Режим | Что на проводе | Против чего |
|---|---|---|
| `plain` (TCP) | без обфускации: голый обмен X25519 + записи `[len][nonce][ct]` | ничего (доверенные сети); самый дешёвый по CPU |
| `fake-tls` (TCP/UDP, деф) | псевдо-TLS-1.3 рукопожатие + Application-Data записи; GREASE, рандом порядок расширений, PQ-key_share | пассивный/сигнатурный DPI |
| `obfs` (TCP) | весь поток XOR ChaCha20-keystream (общий PSK); старт замаскирован под WebSocket Upgrade (printable HTTP) | DPI, ловящий *известные* протоколы (fake-TLS/JA3) + энтропийный «fully encrypted» детект (GFW/ТСПУ) |
| `reality` (TCP) | «свой» ClientHello опознаётся **криптографически** (токен в `session_id`); «чужой»/пробер **проксируется на реальный `target:443`** | активный пробинг (`openssl s_client` видит настоящий сайт) |
| `reality-tls` (TCP) | **настоящий** TLS 1.3 (Chrome JA4) несёт туннель внутри; с `handrolled` — одолженный реальный серт target'а + зеркалированный JA3S | активный пробинг + JA3/JA4 + энтропийный DPI (на проводе неотличимо от HTTPS) |
| QUIC-masking (UDP) | датаграммы под QUIC v1 заголовком (поверх `fake-tls`) | DPI, ждущий QUIC/HTTP3 |

Дополнительно: паддинг (probability/randomize), нормализация длины, fragmentation
рукопожатия, idle-heartbeat с джиттером, **nonce через 96-битную перестановку
Фейстеля** (на проводе нет инкрементного счётчика — частый отпечаток самописных VPN).

## Что qeli НЕ защищает (честно)

- **fake-TLS — не настоящий TLS.** В режиме `fake-tls` сертификат — псевдо-DER
  заглушка. Против **активного** пробинга нужен REALITY: `reality` (proxy) мостит
  чужих на реальный сайт, а **`reality-tls`** несёт туннель внутри настоящего TLS 1.3
  и с **cert-borrowing** (`handrolled=true`) отдаёт клиенту настоящую захваченную
  цепочку серта target'а (паритет с Xray-REALITY; см. CONFIG.md/DPI-AUDIT.md). Без
  REALITY `fake-tls`/`obfs` рассчитаны на пассивный DPI.
- **Post-quantum** — гибрид **X25519MLKEM768** реализован в `reality-tls` (настоящий
  ML-KEM-768 encaps/decaps, общий секрет `ML-KEM ‖ X25519`); в `fake-tls` PQ-key_share
  присутствует в ClientHello (закрывает телл «нет PQ»), но рабочий KEX там — X25519.
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

## Качество кода

- Юнит-тесты: **161** (crypto round-trip, **64-битное replay-окно** на сервере и
  клиенте, PRP-биективность, channel-binding симуляция, keyed auth-OK round-trip,
  qeli://-link round-trip, IpPool/RateLimiter/FailedAuthTracker, INI round-trip,
  obfs roundtrip TCP + per-datagram UDP, plain raw-фрейминг + TCP-only guard,
  REALITY token seal/open, realtls handshake-interop с rustls (оба cipher-suite +
  PQ-гибрид), cert-borrowing, NewSessionTicket, авторизация по профилям, QR-рендер).
- Сборка `cargo build --release` чистая, **0 warning'ов**; дерево
  rustfmt/clippy-нормализовано.
- CI: `.github/workflows/ci.yml` — **два hard-гейта** (блокируют merge): build+test
  (`cargo test --all`) и lint (`cargo fmt --check` + `cargo clippy --all-targets -- -D
  warnings`); **+ три soft-гейта**: компиляция клиентов Android (gradle) / Windows /
  macOS (dotnet). Локальный прогон полного гейта — `scripts/lab_sync_build.py`
  (sync → build → test → clippy на лабе).
