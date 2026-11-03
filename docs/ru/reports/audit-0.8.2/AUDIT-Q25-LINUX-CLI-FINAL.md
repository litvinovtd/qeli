# Q25: Linux CLI и восстановление сети — итог

<!-- normative-sync: audit-q25-linux-cli-final-v1 -->

**DONE/PASS. Общий план: 25/37 (67,6%), осталось 12; далее Q26.** 4 октября 2026.
[Evidence](../../../../release/certification/evidence/q25-cli-20261004.json).

Два подтверждённых дефекта [F216/F217](AUDIT-Q25-CLI-BOOTSTRAP.md) исправлены: обе точки запуска и `check-config --client` используют ограниченное чтение INI, клиентское логирование проходит общий строгий парсер и проверку доверия snapshot; обычный файловый лог открывается через общий helper, который отклоняет FIFO. Удалены отдельный standalone-парсер и дубли открывания sink. Мануал обновлён. Конфиги только INI; служебный JSON API сохранён. Общий data plane, wire, ключи конфигурации и C/JNI ABI не менялись.

| Слой | Разбор и подтверждение |
|---|---|
| Входы/feature gates | `qeli client`, `qeli-client`, `check-config --client`, shared parser/config_source, раннее логирование; Linux-only wiring, обе реальные сборки и all-target Clippy. Мёртвый частичный parser удалён; других подтверждённых мёртвых production-реализаций в текущем проходе не найдено. |
| Контракт INI/файлов | 7 новых unit-регрессий; 12 baseline FAIL; 26 final CLI сценариев / 68 checks PASS. FIFO INI/log sink, граница 262144 байта, unknown/malformed, права и symlink, mixed-case, missing/directory, nonzero error exit и append. |
| Маршруты/DNS/firewall/TUN | 348 compilation inputs совпадают; изменены/добавлены только 4 файла bootstrap/entry points. Общий `client/mod.rs` Q24 сохранён как точный префикс; 71 сетевой input unchanged. Применимость закрытых Q14/Q17–Q24 и D01–D05/D09/D10/D13 сверена по исходникам. |
| Отказы/конкуренция/recovery | Прежние 152 mixed-firewall ячейки / 136 crash-recovery, namespace/TUN identity, leases, joined hooks/writers, 15-секундные setup/cleanup бюджеты и честный terminal status сохраняют исходные даты и границы. Это не новый полный прогон. Свежий lib-набор в private NET/mount/PID: 2414 PASS, 60 ignored. |
| Настоящая интеграция | Исправленный debug daemon прошёл TCP IPv4 full и dual-stack UDP split: 2 сценария / 32 checks PASS, реальный AUTH/TUN/маршрутизация/остановка и cleanup. Полные private/host snapshots совпали. Полная dedicated leak matrix/100-cycle soak не повторялись; aggregate_leak_passed=false у subset не переименован в PASS. |
| Сборочный контракт | 4 fresh independent native A/B пары PASS и побайтно равны Q24; все canonical/consumer копии, 14 SHA256SUMS и provenance проверены. Поэтому прежние 22 Windows ABI и 23 actual Android JNI проверки применимы к тем же байтам; нового запуска эмулятора не заявляется. |

Финальные build, CLI, desktop/Android A/B и connected wrappers прошли строгое сравнение host state без исключения firewall-правил. Первые FAIL сохранены: сторонняя `vpn-nat` меняет три legacy-правила при циклическом рестарте `vpn-obfuscated`; текущий журнал установил источник. Рабочий Qeli сохранил PID и бинарник. Эти сторонние службы не исправлялись и не останавливались.

Private Android SDK временно архивирован для места под сборки. Проверены все payload SHA до удаления expanded copy и после восстановления; SHA/size/mtime всех файлов и обоих AVD сохранены. Удалены только проверенный inactive private Cargo cache и временный архив; исходники, CLI-кандидаты и raw failures сохранены.

Сохраняются принятый D06 WAN identity остаток и безопасные ручные границы recovery для legacy DNS/persistent TUN/потерянного sysctl witness. Изменение выбранного WAN требует остановки профиля и подтверждения cleanup. Произвольные действия root не сертифицированы. Router/Mac/iOS/Windows VM network runtime исключён пользователем; отсутствие такого runtime не названо PASS. Новый peak benchmark, полный release preflight, push/deploy не выполнялись. Артефакты: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q25-cli-20261004/`.
