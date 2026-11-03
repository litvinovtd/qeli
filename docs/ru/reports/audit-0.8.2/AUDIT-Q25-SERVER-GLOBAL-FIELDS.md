# D07: глобальные поля серверного INI

1 октября 2026. Проверены 34 фиксированных ключа: 7 в [auth], 4 в [logging] и 23 в [web]. Пользователи и группы, динамические ключи и 116 фиксированных профильных полей сюда не входят. Основа перечисления — [генератор fixture](../../../../scripts/gen_roundtrip_fixture.py) и [полный round-trip тест](../../../../qeli/src/config/server_ini.rs); команда python scripts/gen_roundtrip_fixture.py --check прошла на текущем дереве (163 имени ключей, три динамических семейства).

| Поля | Валидация | Фактическое применение | Граница применения |
|---|---|---|---|
| auth.users_file | Доверие пути и загрузка эффективной базы пользователей | Supervisor, worker и панель читают выбранный файл | Полный рестарт при смене пути |
| auth.require_client_key_proof, auth.bind_static_to_session | Общая проверка конфига | Проверка доказательства ключа и связывание ключей сессии в handshake | Перезапуск worker |
| auth.brute_force.enabled, max_attempts, window_secs, lockout_secs | BruteForceConfig::validate | Трекер VPN-аутентификации worker | SIGHUP после панельной правки |
| logging.level, file, time_format | INI и доверие файла вывода | Ранний init_logging и форматирование временной метки | Полный рестарт |
| logging.format | INI round-trip | Намеренно не применяется: совместимость, только обычные строки | Изменение не требует рестарта |
| web.enabled, bind, port, base_path | WebConfig::validate_active | Listener и маршрутизатор панели | Полный рестарт |
| web.tls, tls_cert, tls_key | Валидация путей, размера и PEM-пары | HTTPS listener | Полный рестарт |
| web.persist_session_key | Проверка конфигурации | Источник ключа подписи сессий | Полный рестарт |
| web.username, password_hash, insecure_no_auth | Argon2 и обязательный допуск включённой панели | Login и auth guard читают live_web | Live reload |
| web.secure_cookie, session_ttl_secs | WebConfig::validate_active | Login выдаёт cookie и ограничивает срок токена | Live reload |
| web.allowed_ips, trusted_proxies | Проверка IP/CIDR | Request middleware читает live_web | Live reload |
| web.public_host, allowed_origins, csrf | Проверка host/origin | CSRF и ссылки панели | Live reload |
| web.brute_force.enabled, max_attempts, window_secs, lockout_secs | BruteForceConfig::validate | Панельный FailedAuthTracker | Live reload |
| web.update_check | Булево значение INI | Status API передаёт opt-in браузеру | Читается с диска при запросе |

Форма, сырой INI и Quick Start используют общую серверную валидацию до публикации. После записи [reload_web_settings](../../../../qeli/src/server/mod.rs) обновляет живые поля [web], оставляя поля listener/router из startup-снимка; [needs_full_restart_for_config](../../../../qeli/src/web/api/config.rs) и предупреждения SIGHUP учитывают startup-only поля. Прямые обращения к startup state.config.web в web runtime относятся к bind, port, tls и base_path. Отдельный status API читает update_check из текущего INI. Для UI JSON-вывод логов отключён: logging.format=json сохраняется как legacy-значение, но не обещает JSON-логи.

Это сверка статических потребителей и уже пройденных адресных регрессий, не новый end-to-end прогон каждого из 34 ключей. D07 остаётся открытым для 116 профильных полей, смешанных сценариев импорта/рестарта и гонки с внешним редактором, не использующим lock-файл.

Продолжение 2 октября: [Q25-F209 в реестре](../../plans/AUDIT-DEBT.md) закрывает смешанные API save/INI/history/Quick Start/archive/restart проверки D07 и фиксирует обязательный sidecar lock внешнего писателя. Исторические числа выше не являются новым прогоном. Сетевые комбинации и итоговая сертификация остаются D10/D15.
