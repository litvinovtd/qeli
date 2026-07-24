# План устранения находок аудита 2026-07-05

> 🗄 **Исторический документ — аудит закрыт.** Это зафиксированный трекер работ по итогам
> проверки 2026-07-05; он описывает состояние на свою дату и не обновляется. Актуальное
> состояние безопасности — в [ru/AUDIT.md](ru/AUDIT.md) · [eng/AUDIT.md](eng/AUDIT.md).
> Документ существует только на русском, поэтому лежит вне языковых деревьев.

Трекинг-документ по итогам детального аудита QELI (6 зон). Полный отчёт и пофайловые
находки — в истории сессии / памяти проекта (`project_qeli_audit_2026-07-05`).

**Статусы:** ⬜ не начато · 🔧 в работе · 🧪 код готов, ждёт верификации · ✅ сделано+проверено · 🚫 не фиксим (by design).
**Верификация:** Rust локально не собирается (нет cargo на dev-машине) → `cargo test --all` + clippy + fmt на лабе **.10**; C# — `dotnet build`; Python — запуск; shell/доки/конфиги — инспекция + прогон на сервере.
**Workflow:** **ветка `0.7.7`** (собрана 2026-07-05 из fix/client-crash-sni: дореализные фиксы + аудит-фиксы + web.csrf + 0.1b; 29+ коммитов, HEAD зелёный на лабе). wire-затрагивающее — прогон на лабе .10/.11.

Легенда усилий: S <1ч · M несколько часов · L день+.

---

## Фаза 0 — Быстрые безопасные победы

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 0.1a | ✅ | Юзер-хеши: `skip_serializing` на `UserEntry.password_hash` (utoml нет, персист INI hand-rolled → безопасно). Лаб 262 теста, коммит `66f9f99` | `config/users.rs` | S |
| 0.1b | 🧪 | Админ-хеш: `skip_serializing` на `WebConfig.password_hash` — зелёный на лабе, ПРИДЕРЖАН (в `server.rs` рядом с вашей `web.csrf`) | `config/server.rs:468` | S |
| 0.1c | ⬜ | Маскировать `/api/config/raw` — отложено: round-trip редактора (GET-маска→PUT затрёт хеш→лок-аут), нужен PUT-preserve | `web/api/config.rs` | M |
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
| 1.1 | ✅ | различать framing-desync/чистый обрыв в логе — `91d259e`/`2831a29` (реальный fix дропов — 1.2/1.3) | `client/mod.rs`, `server/handler.rs` | M |
| 1.2 | 🟢 | УЖЕ исправлен: чтение вынесено в отдельную reader-задачу (`split_io`, коммент client/mod.rs:908-913), из `select!` убрано → отмена не теряет заголовок. **Нагруз. тест на лабе** (16 потоков bidir, GRO on, 40с) — стабильно, 0 desync/reconnect. Память 2026-07-02 устарела | `client/mod.rs:908` | — |
| 1.3 | ✅ | Критич. oversized-record drop под нагрузкой (память [[project_qeli_oversized_record_drop]]) **ЗАКРЫТ моим фиксом 1.4** (guard в `encrypt_packet`→`Err(PacketTooLarge)`, коммит `3710053`): GSO-супер-пакет → encrypt Err → egress-вызовы дропают пакет (`client/mod.rs:605`/`server/mod.rs:1703` `if let Ok`, `2397` `.ok()`), oversized-запись НЕ эмитится → приёмник не рвётся. Юнит-тест + нагруз. тест GRO on. Опц.: `TUNSETOFFLOAD(0)` (throughput-hardening, нужно воспроизвести супер-пакет) | `packet.rs:230`, `server/mod.rs:1703` | — |
| 1.4 | ✅ | guard от u16-truncation — `3710053` | `protocol/packet.rs:230` | S |
| 1.5 | 🚫 | Переклассиф.: `panic!`/`.expect()` недостижимы (fixed-size входы, не горячий путь); `Result`-конверсия — ripple 25+ мест, не оправдана | `realtls/record.rs:29`, `crypto/reality.rs:73` | — |
| 1.6 | ✅ | log+continue — `14febeb` | `server/dhcp.rs:133`, `server/dns.rs:34` | S |
| 1.7 | ✅ | backoff в accept-цикле — `e443207` (UDP-recv оставлен: sleep бил бы по data-plane) | `server/mod.rs:1863` | S |

---

## Фаза 2 — Утечки ресурсов и фантомные сессии (Т3+Т4) — **критично**

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 2.1 | ✅ | КРИТ: release IP при session-cap eviction — `91d259e` | `server/handler.rs:302` | M |
| 2.2 | ✅ | UDP-reaper guard по session_id (+защита pool.release от отзыва IP реконнекта) — `6944984` | `server/udp_handler.rs:336` | M |
| 2.3 | 📝 анализ | Прямой двойной `release(key)` БЕЗОПАСЕН by design: `release` идемпотентен по username (guard `if let Some=remove`), `freed.pop()` ревалидирует `!allocated` (pool.rs:96-120, коммент 118-119). Остаётся условный рассинхрон DHCP-lease-Vec ↔ session-`release` (общий `profile.pool.clone()`, mod.rs:1893) — достижим ТОЛЬКО при `dhcp.enabled` И совпадении session-ключа с "dhcp:MAC". Нужен отдельный координированный фикс (release_by_ip + очистка lease-слота); форс в аллокатор на этой глубине рискован → отложено | `server/dhcp.rs:340`, `server/pool.rs:115` | M |
| 2.4 | ✅ | Dispose REALITY-хендла в single-stream (try/finally) — `b0676d8` (C# собран, Kotlin зеркально) | `VpnTunnelBase.cs`, `QeliService.kt` | M |
| 2.5 | ✅ | Dispose REALITY-хендла при провале bonded-JOIN (catch) — `b0676d8` | `VpnTunnelBase.cs`, `QeliService.kt` | S |
| 2.6 | ✅ | TUN/TAP writer: EINTR-retry, drop на ENOBUFS/EAGAIN, стоп на fatal — `f0a1d23` | `server/mod.rs:1737` | M |
| 2.7 | ✅ | flush usage перед signal-exit — `e443207` | `server/mod.rs:910` | S |
| 2.8 | ✅ | `try_send` вместо блокирующего `SyncSender::send` в tokio-задаче — `f0a1d23` | `server/mod.rs:1757` | M |

---

## Фаза 3 — Крипто и утечки по краям

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 3.1 | ✅ | Kill-switch fail-closed на незащищённом IPv6 (`bdc7488`): если хост имеет global IPv6 (`/proc/net/if_inet6` scope 00) и `ip6tables` нет — откат v4-плеча + отказ запуска (как v4-контракт). Opt-out `routing.allow_ipv6_leak` для v4-only. v4-only хосты не затронуты. cargo check+clippy чисто, round-trip тест добавлен | `client/killswitch.rs`, `config/client.rs` | M |
| 3.2 | 🟢 | УЖЕ реализовано: `ReplayGuard` (mod.rs:141, TTL 2×window, FIFO) подключён в `server/reality.rs:84`; реплей брайджится на decoy. Находка агента ложная (смотрел чистую крипто-функцию, пропустил серверный гард) | `server/reality.rs:84` | — |
| 3.3 | 🚫 | Переклассиф.: `Option`-конверсия ripple ~25 мест; лучше валидация `reality_sid` при загрузке конфига (follow-up) | `crypto/reality.rs:48-59` | S |
| 3.4 | ✅ | warn при `add_default_gateway`+`dns=off` (утечка DNS) — `0e680bd` | `client/mod.rs:1821` | S |
| 3.5 | 🧪 | TOFU: создавать known_hosts с 0600 (`OpenOptionsExt::mode`) — верифицируется | `client/mod.rs:2662` | S |
| 3.6 | ✅ | warn на world-writable хук-скрипт — `8d9a151` | `hooks.rs:48` | S |

---

## Фаза 4 — Веб-панель

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 4.1 | ✅ | явный DefaultBodyLimit 16MiB на api-роутере — `80c111f` | `web/api/mod.rs:108` | S |
| 4.2 | 🟢 | UI УЖЕ есть: пороги брутфорса (`max_attempts`/`window_secs`/`lockout_secs`) в `config.html:129/134/139` — агент смотрел blocked.html, а UI на странице Config | `config.html` | — |
| 4.3 | ✅ | Полностью: добавлены поля формы `session_ttl_secs`/`base_path`/`trusted_proxies`/`csrf`/`update_check` в секцию Web (`77b34f3`). Backend round-trip уже был (serde→`to_ini_string`→INI→parse, server_ini.rs:195-261); не хватало только UI. Div-баланс 20/20 доб., 460/460 файл | `config.html`, `config/server_ini.rs` | M |
| 4.4 | ✅ | Удалены мёртвые `is_authed`/`check_auth` (+ footgun un-rate-limited Basic) — лаб 263 теста | `web/auth.rs` | S |
| 4.5 | ✅ | Авто-`Secure` cookie за доверенным HTTPS-прокси (`80f96f5`): `X-Forwarded-Proto=https` И peer ∈ `trusted_proxies` (new `forwarded_https`); гейтед на доверие → спуф на plain-HTTP не залочит | `web/mod.rs`, `web/api/login.rs` | S |
| 4.6 | ✅ | logs-filter hoist + username charset (`c0053ec`) + ttl-кламп 30д + trusted_proxies /0-warn (`f5e6c4c`) | `logs.rs`, `users.rs`, `auth.rs`, `web/mod.rs` | S |

---

## Фаза 5 — Паритет клиентов

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 5.1 | ✅ | Полностью: (а) фикс выбора при фильтрации по `VpnConfig.Id` (`22a22e7`); (б) СОХРАНЕНИЕ выбора между запусками — `AppSettings.LastProfile`, restore на старте вместо `SelectedIndex=0` (`7f4b653`, dotnet build 0/0). Тот же стабильный Id, что service/auto-connect | `qeli-mac/MainWindow.axaml.cs`, `Model/AppSettings.cs` | M |
| 5.2 | ✅ | macOS `ParseCidr` валидирует через `IsStrictIp` (паритет с Windows) — `22a22e7`, dotnet build OK | `qeli-mac/NetworkConfigurator.cs:208` | S |
| 5.3 | ✅ | ExcludeRoutes применяется: Rust уже (route.rs:76), + win/mac `DeleteRoute` (`a37aa9b`, dotnet), + Android `excludeRoute` API33+ (`7e7cc82`, CI) | все клиенты | M |
| 5.4 | ✅ | Android `parse()` понимает `qeli://` (паритет с C#) — `80f9b9c` (Kotlin, инспекция) | `Config.kt:199` | S |
| 5.5 | ✅ | utun-инвариант: гард против повторного `Open()` (leak fd) — fail-loud (`8dfe0b4`, dotnet 0/0). Service-detect (file-freshness) оставлен by-design: non-root GUI не может `launchctl`-опросить системный демон | `UtunDevice.cs` | S |

---

## Фаза 6 — Долг «объявлено, но не подключено»

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 6.1 | ✅ | Реализован INI-парсинг ghost-полей (honored, но не парсились): `password_file`/`password_command` (auth), `keepalive` (server), `tcp_nodelay` (perf) + сериализация round-trip + тест (`5e0b78c`) | `config/client.rs` | M |
| 6.2 | ✅ | `web.update_check` УЖЕ парсится (server_ini.rs:260, добавлено с web.csrf-работой). `logging.rotation` — мёртвый код (не читался нигде, `init_logging` берёт только level+file): удалены поле + `LogRotation` + 2 default-fn. check+clippy 0/0 | `config/mod.rs` | S |

---

## Фаза 7 — DoS-грани и тесты

**Сначала проверить:** ~~sweep протухших `udp_frag`~~ УЖЕ ЕСТЬ (`udp_handler.rs:358` — `frag_pending.retain(age()<REASSEMBLY_TIMEOUT)` в reaper-тике); CSP `connect-src` vs update-check (браузер); padding `min>pad_cap` (obfuscate.rs).

| # | Статус | Находка | Файл | Усилие |
|---|---|---|---|---|
| 7.1 | ✅ | `recv_junk_ws` (pre-auth, без внешнего handshake-таймаута): дедлайн 15с + байт-бюджет (`4e56aab`). Slowloris-дрибл и control-фрейм-флуд (пропускались не считая) больше не держат/крутят accept-таск | `protocol/obfs.rs` | M |
| 7.2 | ✅ | `flow_hash` не хеширует L4-порты у ЛЮБОГО фрагмента (MF или offset>0) — все фрагменты датаграммы пиннятся в один поток; + IHL-гард (1.11) (`4e56aab`) | `protocol/mod.rs` | S |
| 7.3 | ✅ | `Shaper::stealth_pace`: дефицит клампится до `-rate_bps` (симметрично +ёмкости и 1с-sleep) — аномально большой write не уводит бакет в глубокий минус и не стопорит пейсер (`4e56aab`) | `protocol/shaper.rs` | S |
| 7.4 | ◑ | fuzz-цели `udp_frag`/`quic`/`obfs_datagram` добавлены (компилируются на лабе, гоняет CI) + регресс-тест 1.4 в packet.rs; интеграционный хендшейк-тест остаётся | `qeli/fuzz`, `packet.rs` | L |

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
- 2026-07-05 (продолжение): +11 фиксов через лаб-пайплайн, каждый зелёный (262 теста/clippy/fmt,
  C# — dotnet). Фаза 1: 1.1/1.4/1.6/1.7 (`91d259e`/`2831a29`/`3710053`/`14febeb`/`e443207`);
  Фаза 2: 2.1/2.2/2.7 (`91d259e`/`6944984`/`e443207`), 2.4/2.5 (`b0676d8`), 2.6/2.8 (`f0a1d23`);
  Фаза 3: 3.4/3.5/3.6 (`0e680bd`/`4ed1ddb`/`8d9a151`). **Итого 21 фикс закоммичен+проверен.**
  Осталось: 2.3 (DHCP, редкий путь), 3.1 (IPv6 kill-switch — меняет поведение), 3.2 (replay-кэш —
  фича), Фазы 4 (панель), 5 (клиенты macOS/Android), 6 (долг конфига), 7 (DoS+тесты).
- 2026-07-05 (продолжение 2): +4.1 (DefaultBodyLimit, `80c111f`). Итого 22 фикса закоммичено+проверено.
  4.4 (мёртвый код) пропущен — риск осиротить `unauth()`/импорты под clippy -D warnings; 4.5 отложен
  (нужен плюмбинг X-Forwarded-Proto в login). Память проекта обновлена статусом.
- 2026-07-05 (продолжение 3): **собрана релизная ветка `0.7.7`** (от fix/client-crash-sni). Консолидированы
  как коммиты: web.csrf-тумблер (`460eb20`), CHANGELOG-релиз-ноты (`ae30134`), 0.1b админ-хеш (отдельно,
  распутан от web.csrf). +4.6 частично logs/username (`c0053ec`). HEAD 0.7.7 зелёный (262/clippy/fmt).
  **ОТКРЫТИЯ (ложные находки аудита):** 3.2 (anti-replay REALITY) и sweep `udp_frag` УЖЕ реализованы в коде —
  агенты смотрели чистые функции, пропустив серверные гарды. Итого ~24 фикса + 2 находки сняты как ложные.
  Быстрые lab-verifiable Rust-фиксы исчерпаны; остаток требует нагрузки (1.2/1.3), UI (Фаза 5, 4.2/4.3) или
  мелкой доводки (2.3, 4.4/4.5, ttl-кламп/trusted_proxies-warn).
- 2026-07-05 (продолжение 6): tractable-остатки без блокеров — **5.1** (macOS выбор профиля по `Id`),
  **5.2** (macOS pushed-CIDR валидация, паритет с Win), **5.4** (Android `parse()` qeli://), **4.4**
  (удалены мёртвые `is_authed`/`check_auth`). macOS собран dotnet, Kotlin инспекция, 4.4 на лабе (263).
  4.5 пропущен (нужен trusted_proxies-гейт для XFP, ценность низкая); 2.3 (DHCP) — редкий путь, отложен.
  Остаток требует ВАШЕГО решения (3.1 IPv6 kill-switch, 5.3 ExcludeRoutes implement/remove) или браузера/GUI
  (4.2/4.3 панель, GUI-верификация 5.1).
- 2026-07-05 (продолжение 5): **тесты Фаза 7.4** — 3 фаззера (`udp_frag`/`quic`/`obfs_datagram`) + регресс 1.4
  (коммиты на 0.7.7, CI fuzz-smoke PASS). **Нагрузочный стенд на лабе** (2-VM .10↔.11, `gro_repro.py` в scratchpad):
  fake-tls TCP туннель, GRO on (generic+rx-gro-list+rx-udp-gro-forwarding), iperf3 --bidir -P8 40с → **туннель
  стабилен, 0 desync** → **1.2/1.3 подтверждены как УЖЕ исправленные** (3-я и 4-я ложные находки после 3.2/udp_frag-sweep).
  Память project_qeli_oversized_record_drop устарела. CI на PR #71: все код-проверки PASS, только DCO fail (нет Signed-off-by).
- 2026-07-05 (продолжение 4): удалены поглощённые ветки `fix/client-crash-sni` + `deps/2026-06-28`
  (локально+origin). Закрыт **4.6 полностью** (`f5e6c4c`). **`0.7.7` = единая консолидированная ветка
  (42 коммита над main), запушена, зелёная с новыми крипто-deps.** Все lab-проверяемые Rust-фиксы Фаз 0–4
  сделаны (~26 фиксов + 2 находки сняты как ложные: 3.2, udp_frag-sweep). Остаток — только иной режим:
  1.2/1.3 (нагрузочный стенд), 3.1 (решение по поведению IPv6), Фаза 5 (GUI-клиенты), 4.2/4.3 (браузер).
- 2026-07-05: настроен лаб-пайплайн верификации Rust — сборочная папка `/root/qeli-audit/qeli`
  на .10 (tar-over-SSH синк, тёплый target, `/opt/qeli-src` не тронут). Базовый прогон зелёный
  (262 теста/clippy/fmt). Закоммичены 0.1a/1.4/1.6 (коммиты `66f9f99`/`3710053`/`14febeb`),
  каждый верифицирован на лабе. 0.1b придержан (WIP), 0.1c отложен.
