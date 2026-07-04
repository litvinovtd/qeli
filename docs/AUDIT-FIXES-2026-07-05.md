# План устранения находок аудита 2026-07-05

Трекинг-документ по итогам детального аудита QELI (6 зон). Полный отчёт и пофайловые
находки — в истории сессии / памяти проекта (`project_qeli_audit_2026-07-05`).

**Статусы:** ⬜ не начато · 🔧 в работе · 🧪 код готов, ждёт верификации · ✅ сделано+проверено · 🚫 не фиксим (by design).
**Верификация:** Rust локально не собирается (нет cargo на dev-машине) → `cargo test --all` + clippy + fmt на лабе **.10**; C# — `dotnet build`; Python — запуск; shell/доки/конфиги — инспекция + прогон на сервере.
**Workflow:** ветка `fix/client-crash-sni` (пре-релиз, НЕ main); wire-затрагивающее — прогон на лабе .10/.11.

Легенда усилий: S <1ч · M несколько часов · L день+.

---

## Фаза 0 — Быстрые безопасные победы

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 0.1 | ⬜→лаб | argon2-хэши в API — `skip_serializing` (+ маскировать raw). Отложено на лаб-пасс: Rust не собрать локально, а `UserEntry` сериализуется и в TOML (нюанс) → нужен `cargo test` round-trip | `config/users.rs:29`, `config/server.rs:468`, `web/api/config.rs` | S |
| 0.2 | ✅ | Прод-пароль вынесен в `~/.config/qeli/creds.sh` (вне OneDrive); `lab_env.sh`→загрузчик без секретов. **ROTATE QELI_PROD_PASS** (был в облаке) | `scripts/lab_env.sh` (local) | S |
| 0.3 | ✅ | 5 скриптов → OBSOLETE-guard (exit 1), проверено `bash -n`+прогон | `deploy-server.sh` +4 | S |
| 0.4 | ✅ | download→review→run вместо `curl \| bash` | `docs/README.md` | S |
| 0.5 | ✅ | `nftables`→`iptables` | `qeli/config/client.conf:67` | S |
| 0.6 | ✅ | `cur_jem` определена; python парсится (untracked, локально) | `scripts/deploy_prod_jemalloc.py:66` | S |
| 0.7 | ✅ | `RedactUser`/`redactUser` (first+last); C# собран (0 ошибок), Kotlin — инспекция | `VpnTunnelBase.cs`, `QeliService.kt` | S |

---

## Фаза 1 — Устойчивость к отказам (Т1+Т2) — **критично**

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 1.1 | ⬜ | КРИТ: `PacketTooLarge`/framing-desync рвёт TCP-цикл — разделить fatal/recoverable | `client/mod.rs:526`, `server/handler.rs:700` | M |
| 1.2 | ⬜ | КРИТ: `read_tls_record` не cancellation-safe (корень рассинхрона) | `protocol/packet.rs` + `client/mod.rs:~898` | L |
| 1.3 | ⬜ | КРИТ: UDP-GRO суперпакет не разбивается — `setsockopt UDP_GRO off` + итерация записей | `protocol/obfs.rs:633`, `server/udp_handler.rs:438` | M/L |
| 1.4 | ⬜ | ВЫС: `encrypt_packet` тихая truncation `as u16` — guard | `protocol/packet.rs:230` | S |
| 1.5 | ⬜ | ВЫС: `panic!`/`expect` в realtls/reality → `Result` | `realtls/record.rs:29`, `crypto/reality.rs:73` | M |
| 1.6 | ⬜ | НИЗ: DHCP/DNS recv-loop падает на `?` → log+continue | `server/dhcp.rs:133`, `server/dns.rs:34` | S |
| 1.7 | ⬜ | СРЕД: accept/recv busy-spin на EMFILE → backoff | `server/mod.rs:~1862`, `udp_handler.rs:181` | S |

---

## Фаза 2 — Утечки ресурсов и фантомные сессии (Т3+Т4) — **критично**

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 2.1 | ⬜ | КРИТ: утечка IP при session-cap eviction — `pool.release` | `server/handler.rs:302-313` | M |
| 2.2 | ⬜ | СРЕД: UDP-reaper без `session_id`-guard сносит живую сессию | `server/udp_handler.rs:336-353` | M |
| 2.3 | ⬜ | СРЕД: DHCP двойной release/утечка IP | `server/dhcp.rs:340-358` | M |
| 2.4 | ⬜ | ВЫС: утечка REALITY-хендла (single-stream) | `VpnTunnelBase.cs:476`, `QeliService.kt:1078` | M |
| 2.5 | ⬜ | ВЫС: утечка REALITY-хендла при провале bonded-JOIN | `VpnTunnelBase.cs:1198`, `QeliService.kt:1688` | S |
| 2.6 | ⬜ | ВЫС: TUN/TAP writer игнорирует ошибку `write` | `server/mod.rs:1737-1748` | M |
| 2.7 | ⬜ | НИЗ: `process::exit(0)` пропускает flush usage | `server/mod.rs:910` | S |
| 2.8 | ⬜ | НИЗ: блокирующий `SyncSender::send` в async | `server/mod.rs:1757` | M |

---

## Фаза 3 — Крипто и утечки по краям

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 3.1 | ⬜ | ВЫС: IPv6-утечка kill-switch без `ip6tables` | `client/killswitch.rs:206-218` | M |
| 3.2 | ⬜ | СРЕД: REALITY session_id без anti-replay-кэша | `crypto/reality.rs:84-106` | M |
| 3.3 | ⬜ | СРЕД: `short_id_from_hex` молча обнуляет мусор | `crypto/reality.rs:48-59` | S |
| 3.4 | ⬜ | ВЫС: DNS-метаданные при full-tunnel + `dns=off` — warn | `client/mod.rs:1811`, `client/dns.rs:47` | S |
| 3.5 | ⬜ | СРЕД: TOFU `known_hosts` окно прав 0644 | `client/mod.rs:2662` | S |
| 3.6 | ⬜ | СРЕД: хуки — warn на world-writable скрипт | `hooks.rs:26-37` | S |

---

## Фаза 4 — Веб-панель

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 4.1 | ⬜ | СРЕД: явный `DefaultBodyLimit` для `/api/restore` | `web/api/backup.rs:106` / роутер | S |
| 4.2 | ⬜ | СРЕД: пороги брутфорса без UI | `web/api/status.rs:225`, `blocked.html` | M |
| 4.3 | ⬜ | НИЗ: web-настройки без UI + смена пароля админа | `config/server.rs:457`, config-страница | M |
| 4.4 | ⬜ | НИЗ: мёртвый код `is_authed`/`check_auth`/Basic | `web/auth.rs:49,194` | S |
| 4.5 | ⬜ | НИЗ: `secure_cookie` авто под reverse-proxy | `web/api/login.rs:92,117` | S |
| 4.6 | ⬜ | НИЗ: мелочи (ttl-кламп, username-валидация, logs-filter, trusted_proxies warn) | `auth.rs:116`, `users.rs:139`, `logs.rs:54`, `mod.rs:251` | S |

---

## Фаза 5 — Паритет клиентов

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 5.1 | ⬜ | СРЕД: баг выбора профиля macOS (`ItemsSource`→`Id`) + персист выбора | `qeli-mac/MainWindow.axaml.cs:616` | M |
| 5.2 | ⬜ | СРЕД: macOS не валидирует pushed-CIDR | `qeli-mac/NetworkConfigurator.cs:208` | S |
| 5.3 | ⬜ | НИЗ: `ExcludeRoutes` парсится, не применяется (решить) | `VpnConfig.cs:86`, `Config.kt:42` | M/S |
| 5.4 | ⬜ | НИЗ: Android `parse()` без ветки `qeli://` | `Config.kt:199` | S |
| 5.5 | ⬜ | НИЗ: детект «сервис работает» macOS + utun-инвариант | `axaml.cs:269`, `UtunDevice.cs:117` | S |

---

## Фаза 6 — Долг «объявлено, но не подключено»

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 6.1 | ⬜ | СРЕД: поля-призраки `ClientConfig` (реализовать в INI или удалить) | `config/client.rs` | M |
| 6.2 | ⬜ | НИЗ: `logging.rotation` / `web.update_check` не парсятся | `config/mod.rs:132`, `server.rs:522` | M |

---

## Фаза 7 — DoS-грани и тесты

**Сначала проверить:** sweep протухших `udp_frag`; CSP `connect-src` vs update-check; padding `min>pad_cap`.

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 7.1 | ⬜ | СРЕД: junk-WS без лимита control-фреймов/таймаута | `protocol/obfs.rs:575` | M |
| 7.2 | ⬜ | СРЕД: `flow_hash` на IP-фрагментах | `protocol/mod.rs:32` | S |
| 7.3 | ⬜ | СРЕД: `Shaper::stealth_pace` дрейф rate-cap | `protocol/shaper.rs:95` | S |
| 7.4 | ⬜ | Тесты: fuzz udp_frag/obfs/quic/reality + интеграционный хендшейк | `qeli/fuzz`, `qeli/tests` | L |

---

## Не фиксим (осознанно)

- 🚫 CSRF loopback на любом порту — by design (коммит `b1ed0c4` + тумблер `web.csrf`); описать остаточный риск в `PANEL.md`.
- 🚫 Хуки `post_up` RCE — документированная модель (как systemd ExecStart).
- 🚫 Kill-switch DNS port 53→any в окне реконнекта — согласованный компромисс (задокументировать).
- 🚫 `panic = "abort"` в release — оставить; убираем сами паники (Фазы 1–2).
- 🚫 CSP `unsafe-inline/eval` (Alpine.js) — бэклог (нужен Alpine CSP-build).

---

## Журнал выполнения

- 2026-07-05: план создан; начата Фаза 0.
- 2026-07-05: Фаза 0 — 6/7 сделано и проверено локально (0.2–0.7), закоммичено 4 логических
  коммита (0.3/0.4/0.5/0.7) на `fix/client-crash-sni`; 0.2/0.6 — локальные untracked-правки.
  0.1 отложено на лаб-пасс (Rust). Ваши незакоммиченные правки (`web.csrf` и доки) не тронуты.
  **Открытое действие оператора: сменить `QELI_PROD_PASS`.**
