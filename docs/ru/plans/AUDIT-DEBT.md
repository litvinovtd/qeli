# Техдолг начатых аудитов

> Ранее снятые с публикации замеры разработки 0.8.2 и их сравнения сохраняются локально для аудита и не возвращаются в качестве бенчмарка релиза. Новые датированные [снимки Linux](../reports/LINUX-LAB-0.8.2-2026-10-17.md) и [результаты N04](../reports/TUN-N04-0.8.2-2026-10-19.md) включены в документацию отдельно: каждый сохраняет идентификатор проверенного ELF, методику и границы применимости. Они не описывают все платформы или любой последующий бинарник; статусы инженерных проверок сами по себе не являются бенчмарком.

<!-- normative-sync: audit-debt-v144 -->

**19 октября, N04 — итоговая квалификация комплекта:** после исправления Linux UDP
reader устранена следующая межпоточная граница: транспортный цикл `qeli client` /
`qeli-client` и I/O-драйвер используют `current_thread`. Сервер и `_worker`
сохраняют `multi_thread`; политика native FFI не менялась. Default очереди — 1000.

Готовый Linux ELF `e4cb6e05…`, квалифицированный в `dev` на
[`9ab788e5`](https://github.com/litvinovtd/qeli/commit/9ab788e5d5e7aaddb3d82220bb6ebdb9da8cacd2),
прошёл **20 обязательных runtime-пунктов / 409 проверок** и **7 нагрузочных окон**
FakeTLS/QUIC, включая отдельное минутное QUIC950. При очередях клиента/сервера
1000/1000 во всех семи окнах получено **0 TUN drops на обоих концах**.
В минутном окне: 949,76 Мбит/с и 0,00267535% сквозных UDP-потерь; ноль TUN drops
не означает отсутствие всех потерь. [Результаты готового ELF](../../../release/certification/evidence/n04-cli-packaged-udp-20261019.json)
отделены от [диагностических A/B и их границ](../reports/TUN-N04-0.8.2-2026-10-19.md).
Прежние остаточные drops первого reader-fix и отдельные проверки очереди 2000
сохранены как результаты своих ELF; default не повышен, loaded RTT не квалифицирован.

Native A/B, provenance, SDK source, 16 файлов поставки,
[CI 20/20](https://github.com/litvinovtd/qeli/actions/runs/39232066191) точного
`9ab788e5` и release preflight прошли проверку. Идентичности и применимость
фиксирует [квалификация релиза](../../../release/certification/0.8.2.json).
Изменение одних только документов не означает повторного исполнения этих тестов;
новая редакция проходит отдельные проверки документации, CI и preflight.
Прежний объём 37/37, принятые неисправленные API34 ENONET / D06,
исходные FAIL и исключённые стенды сохранены. Комплект остаётся в черновике;
публикация релиза не выполнялась.

Исходная сверка полного аудита: 15 октября 2026. Полный аудит завершён в согласованном объёме: 37/37 (100%). Q29 закрыт по явному решению пользователя с документированным ограничением generic/null DnsResolver API34; исходный ENONET остаётся FAIL, исправление не заявляется. Первоначальные 15 групп обязательств: 14 DONE и D06 ACCEPTED_LIMITATION; прежние границы платформенного покрытия сохранены. Исторические OPEN и счётчики ниже относятся к указанным датам. [Решение и границы Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md).

`ACCEPTED_LIMITATION` означает явное решение пользователя оставить известный остаток;
это не исправление и не PASS. `DONE` допустим только после исправления/обоснования и нужной проверки. `BLOCKED`
обозначает недоступную внешнюю предпосылку, а не успех. Стенд Linux и Android-эмулятор
пользователь предоставил 24 сентября; старое ограничение «нет Linux» больше не действует.
Подключение к двум Linux VM подтверждено; работающий сервер и его файлы не заменялись.

[Полный план](FULL-SYSTEM-AUDIT.md) · [Общее конфигурационное ядро](CLIENT-CONFIG-CORE.md)

**Исторический снимок, 7 октября:** 14/15 DONE, D06 ACCEPTED_LIMITATION.
D11/D15 закрыты для текущего пакета после новых A/B, exports/signatures,
14 SHA-записей, provenance, Windows/Android ABI и managed checks, Linux
2417 library/12 CLI units, строгого Clippy и debug client/daemon builds.
[Текущая сверка](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md) сохраняет исходные
ошибки подготовки и границы прежних измерений. Восемь согласованных старых
каталогов удалены после повторной проверки backup/identity/guards; оба
локальных архива сохранены. Q29 SIGKILL/ENONET, Q30 callback drain/Apple
и Q31 SDK/release pipeline остаются незавершёнными частями полного аудита,
а не PASS. Полный план: 28/37, девять разделов впереди. Новые изменения
исходников/рецептов могут снова сделать native evidence устаревшим.
Обновление 8 октября, [Q32](../reports/audit-0.8.2/AUDIT-Q32-METRICS.md):2424 library PASS,
60 прежних ignored, строгий Clippy/daemon PASS и36namespace PASS при PID42;
Windows ABI22/Android JNI23 проверяют новые бинарники. Final native A/B и
provenance указаны в evidence этого пакета; managed sources/ABI declarations
не менялись, прежние12CLI и платформенные ограничения сохраняют свой scope.
Пакет [Q32 metrics](../reports/audit-0.8.2/AUDIT-Q32-METRICS.md) отдельно обновляет native
evidence после серверной правки; итоговая квалификация и её пределы приведены
в отчёте, без повторного объявления закрытыми Q29/Q30/Q31.
Исторические OPEN ниже не требуют повторять закрытые неизменённые проверки.

| ID | Разделы | Статус | Долг | Критерий закрытия / текущее свидетельство |
|---|---|---|---|---|
| D01 | 14/17/18/25 | DONE | Ошибки NAT и старого поколения | Точные спецификации правил до изменения firewall; retry и итоговая ошибка; запрет restart после неполной очистки; возврат IPv4 forwarding. Unit/cross, 18 native и 8 worker E2E PASS; baseline IPv4 leak воспроизведён. [Отчёт](../reports/audit-0.8.2/AUDIT-Q14-RETAINED-CLEANUP.md). |
| D02 | 14/25 | DONE | Внутренние границы sysctl | Lock/I/O/context, trusted directory, namespace fd pins, исходный per-interface fd/witness и network_cookie v4 проверены. 1995 Linux + 32 privileged + 8 lifecycle и SIGKILL/mismatch worker E2E PASS. Потерянный interface witness сохраняется для ручного recovery; общий persistent firewall/DNS/routes остаётся D04. [Отчёт](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-GENERATION.md). |
| D03 | 22/25 | DONE | Самостоятельный kill-switch | Закреплённый namespace, сохранённый владелец точных семейств, fail-closed reconnect и безопасная смена адреса. 11 portable + 2 native регрессии, реальные счётчики IPv4/IPv6 и 2 отказа baseline. [Отчёт](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-IDENTITY.md). |
| D04 | 14/19/22/25 | DONE | Восстановление после crash | Persistent server firewall, DNS v2, kill-switch и physical routes проверены; legacy global DNS, persistent TUN и потерянный sysctl witness имеют явные безопасные ручные границы. [Клиентская mixed матрица](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-MIXED-FIREWALL.md): 152/152 ячейки, 136 crash/recovery; [серверная](../reports/audit-0.8.2/AUDIT-Q14-MIXED-FIREWALL.md): 16/16, 476 checks повторно PASS. Дополнительный multiprofile/public-policy reload закрыт D10/Q25-F213; накопление состояния — D13. Произвольные политики и root rewrites не сертифицированы. |
| D05 | 05/14/25 | DONE | Срок всей операции и блокировки | Panel preflight/health/backup, DNS/NSS, resolver-файлы, startup INI/identity, TOFU/status writers и сетевые workers проверены. В пакете A ниже закрыта композиция команд: 15 секунд NetworkPlan и отдельные общие 15 секунд cleanup через Drop и terminal firewall. Сверены Linux early-Drop/внутренние waits; файловая подготовка hooks/backup закрыта продолжением ниже; штатные server startup/final cleanup и profile teardown вынесены в присоединяемые потоки; TUN/NAT и DNS firewall setup профиля теперь также в присоединяемых потоках; NDP bind теперь также выполняется в worker с регистрацией AsyncFd в исходном runtime; установка до готовности всех listeners получила общий бюджет 120 секунд; повторный допуск после отмены закрыт [Q25-F130](../reports/audit-0.8.2/AUDIT-Q25-SERVER-FORCED-DROP-LEASE.md); async join при forced Drop закрыт Q25-F206 ниже; общий CLI shutdown и параллельный drain уведомлений закрыты Q25-F208 ниже: 45 секунд worker, аварийный exit 124, восстановление, 136 unit и 8 lifecycle PASS. Библиотечные и kernel-границы обоснованы. [Серверная установка](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-WORKER.md), [DNS firewall](../reports/audit-0.8.2/AUDIT-Q25-SERVER-DNS-SETUP-WORKER.md), [NDP bind](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NDP-BIND-WORKER.md), [готовность и бюджет](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-BUDGET.md). Произвольные kernel/fs I/O и forced join не прерываются. [Серверная очистка](../reports/audit-0.8.2/AUDIT-Q25-SERVER-CLEANUP-WORKER.md). [Worker ownership](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md). |
| D06 | 15/21/22/23/25 | ACCEPTED_LIMITATION | Контекст внешних сетевых ресурсов | Multi-IP UDP endpoint, WAN presence/ECMP/auto-detection, NAT44/NAT66 off-WAN guard, DNS/bus/sysfs/attach/process context и поздние IPv4/IPv6 проверены; Q25-F214: 73 portable + 23 privileged, Q25-F215: 4 mixed cells/204 packet checks PASS. [Q25-A125](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md) остаётся известным P2: selector по имени и client monitor не обеспечивают непрерывную identity. Прототип DEVMAP: 156 checks, не production fix. 3 октября пользователь отменил его внедрение и соответствующую переделку monitor. Перед заменой выбранного WAN остановить профиль и подтвердить cleanup. Остаток принят как ограничение, не PASS; решение и откат приведены в конце реестра. |
| D07 | 01/05/09/11 | DONE | Серверный конфиг в runtime | Таблица field → parse/validate/runtime/serialize; malformed/oversized input; check-config/startup/SIGHUP/HTTP save/Quick Start с сохранением действующего состояния при отказе. [Q25-F137](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SIGHUP-AUTH.md) закрывает частичное обновление VPN-auth при неверном профиле или users.conf: 1 адресный async-тест с двумя отказами и успешным применением. [Q25-F138](../reports/audit-0.8.2/AUDIT-Q25-SERVER-INI-SIZE.md) вводит общий предел серверного INI 16 МиБ для worker, CLI, панели и restore; 16 loader + 33 editor + 1 backup тест, строгий Clippy и CLI отказ проверены. [Q25-F139](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WEB-LIVE.md) согласует startup-only web-поля и живой CSRF, применяет панельный BF при обычном сохранении и сохраняет lockout при неизменных порогах. [Q25-F140](../reports/audit-0.8.2/AUDIT-Q25-SERVER-INI-PERMISSIONS.md) переводит пять панельных записей INI на приватную атомарную публикацию `0600`; 34 теста редактора, строгий Clippy и проверка mode `0644` → `0600` прошли. [Q25-F141](../reports/audit-0.8.2/AUDIT-Q25-SERVER-CHECK-CONFIG-PARITY.md) согласует отсутствие users.conf и all-disabled для CLI, панели и старта. [Q25-F142](../reports/audit-0.8.2/AUDIT-Q25-SERVER-IDENTITY-NAME.md) запрещает path traversal через имя профиля в default identity-ключе. [Q25-F143](../reports/audit-0.8.2/AUDIT-Q25-SERVER-IDENTITY-TRUST.md) привязывает произвольный identity_key и ранний logging.file к доверию того же файлового снимка. [Q25-F144](../reports/audit-0.8.2/AUDIT-Q25-SERVER-USERS-PATH-TRUST.md) закрывает перенаправление нестандартного users_file из недоверенного INI. [Q25-F145](../reports/audit-0.8.2/AUDIT-Q25-SERVER-USERS-SIGHUP-RESTART.md) сохраняет ту же границу на SIGHUP и рестарте, требует полный restart при смене users_file. [Q25-F146](../reports/audit-0.8.2/AUDIT-Q25-SERVER-CONCURRENT-WRITES.md) сериализует панель, CLI и restore по одному sidecar lock и сохраняет lock-inode при exact restore. [Q25-F147](../reports/audit-0.8.2/AUDIT-Q25-SERVER-TLS-PEM.md) ограничивает чтение TLS PEM и сохраняет уцелевший файл автопары. [Q25-F148](../reports/audit-0.8.2/AUDIT-Q25-SERVER-TLS-CHECK-CONFIG.md) сверяет существующую TLS-пару в check-config без записи. [Q25-F149](../reports/audit-0.8.2/AUDIT-Q25-SERVER-TLS-PATH-TRUST.md) связывает явные TLS-пути с доверенным INI-снимком, разрешает Let's Encrypt в панели и исключает TLS выключенной панели из backup. [Q25-F150](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PANEL-SNAPSHOT-TRUST.md) закрывает панельный обход доверия через identity, Share и users после ручной правки INI. [Q25-F151](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PANEL-SAVE-TRUST.md) запрещает повышение доверия к недоверенному INI через все сохранения панели, историю и архивные команды. [Q25-F152](../reports/audit-0.8.2/AUDIT-Q25-SERVER-FIELD-MATRIX-LOGGING.md) сверяет 150 фиксированных INI-ключей на parse/serialize и требует полный рестарт для трёх действующих logging-полей. [Q25-F153](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WEB-AUTH-SAVE.md) запрещает сохранять включённую панель без пароля и без явного insecure_no_auth в обоих редакторах и restore. [Q25-F154](../reports/audit-0.8.2/AUDIT-Q25-SERVER-QUICKSTART-BF-SAVE.md) распространяет эту проверку на Quick Start и API политики блокировок, валидирует полный BF-кандидат перед SIGHUP и показывает ошибки чтения INI/отложенный reload. [Q25-F155](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SIGHUP-RESTART-HINTS.md) устраняет ложные предупреждения о выключенных профилях и сообщает о неприменённых SIGHUP изменениях действующих профилей, двух auth-флагов и трёх logging-полей. [Q25-F156](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WEB-HASH-VALIDATION.md) проверяет непустой хеш администратора при check-config/старте и сохраняет действующий login при ошибочном live reload. [Q25-F157](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WEB-RELOAD-RESULT.md) отличает запись INI от успешного применения панели и исключает частичную смену lockout-политики при отмене reload. [Q25-F158](../reports/audit-0.8.2/AUDIT-Q25-SERVER-BLOCKED-LIVE.md) синхронизирует панельную BF-политику с live web-снимком, показывает расхождение сохранённого и действующего и убирает ложный отказ для выключенной панели без пароля. [Q25-F159](../reports/audit-0.8.2/AUDIT-Q25-SERVER-INI-ORDER.md) стабилизирует порядок групп, IPv4/IPv6-резерваций и метаданных при записи INI. Пакет 2026-10-01: общий валидатор отвергает пустой набор профилей, а полный рестарт проверяет авторизацию панели и существующую PEM-пару до остановки службы; 74 теста и строгий Clippy на `.11` прошли (2 namespace-теста пропущены). Второй пакет синхронизирует `check-config`/старт с панельным отказом без пароля при `web.enabled = true`; 152 серверных/панельных теста и строгий Clippy на `.11` прошли (2 namespace-теста пропущены). Следующий пакет требует `expected_revision` для Quick Start, формы, INI и restore; старые API-скрипты обновлены, 37 тестов редактора, форматирование и строгий Clippy на `.11` прошли. [Глобальная матрица](../reports/audit-0.8.2/AUDIT-Q25-SERVER-GLOBAL-FIELDS.md) сверяет parse/validate/runtime/apply для 34 ключей auth/web/logging; генератор fixture подтверждает 163 имени и три динамических семейства. [Базовая профильная матрица](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PROFILE-FOUNDATION.md) прослеживает 63 записи вне obf.* и исправляет скрытое ограничение явного tun.queues до 256. [Матрица obf.*](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PROFILE-OBF.md) прослеживает остальные 59 ключей и исправляет источник SNI в REALITY share-ссылках. [Q25-F160](../reports/audit-0.8.2/AUDIT-Q25-SERVER-BLOCKED-REVISION.md) требует ревизию INI и для редактора политики блокировок. [Q25-F161](../reports/audit-0.8.2/AUDIT-Q25-SERVER-ARCHIVE-SCAN.md) закрывает молчаливый пропуск ошибок перечисления при архивном restore. [Q25-F162](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NOTIFY-INI.md) убирает JSON-миграцию уведомлений и ограничивает чтение/запись notify.ini. [Q25-F163](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NOTIFY-REVISION.md) защищает сохранение notify.ini от устаревшей вкладки. Q25-F209 ниже закрывает смешанные save/reload/import: 201 unit, 4 privileged исполнения и 44 runtime проверки PASS; внешний writer без общего lock исключён из поддерживаемого протокола с объяснением в мануале. [Q25-F190](../reports/audit-0.8.2/AUDIT-Q25-SERVER-INI-HISTORY.md) устраняет молчаливые ошибки списка и ротации истории INI; Windows rustfmt и 1551 portable-тест PASS, адресные серверные тесты и смешанный Linux runtime повторно проверены в Q25-F209. |
| D08 | 02/24/27 | DONE | Общие клиентские конфиги | Проверить весь контракт 81+3 полей, INI/import/URI/QR/form/store/reconnect через реальные адаптеры; fuzz/budget и конкурентное редактирование. [Q25-F164](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-PROFILE-REVISION.md) защищает панельный INI от перезаписи другой вкладкой, ручной правки и повторного импорта имени; [Q25-F165](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-PROFILE-BOUNDS.md) ограничивает autostart/status и сериализует Connect/Delete с сохранением. [Q25-F166](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-DELETE-REVISION.md) требует ревизию до Delete и показывает необходимость переподключения после Save работающего клиента. [Q25-F167](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-FILE-IMPORT.md) закрывает преобразование байтов файлового импорта Android в текст без потери неверного UTF-8 и хвоста INI. [Q25-F168](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-CONFIG-FILES.md) объединяет строгое ограниченное чтение файлового INI в Windows/macOS CLI. [Q25-F169](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-UI-INI-INPUT.md) убирает предварительное обрезание текстового INI в UI Windows/macOS/Android/iOS. [Q25-F170](../reports/audit-0.8.2/AUDIT-Q25-MOBILE-CONFIG-BUDGET.md) выравнивает ранние пределы Android/iOS файла и хранилища с 256 КиБ общего ядра. [Q25-F171](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-UTF8.md) запрещает молчаливую замену неверного UTF-8 при загрузке Windows/macOS profile store. [Q25-F172](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-RECOVERY.md) исключает перезапись неперенесённого повреждённого store и ложную порчу при сбое миграции. [Q25-F173](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-PROFILE-TRANSACTIONS.md) сохраняет предложенный список до изменения desktop UI и оставляет видимое состояние прежним при ошибке записи. [Q25-F174](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-PROFILE-TRANSACTIONS.md) переносит Android-мутации, backup restore и legacy migration на проверяемый commit до обновления UI или удаления plaintext. [Q25-F175](../reports/audit-0.8.2/AUDIT-Q25-MOBILE-STORE-LOAD-FAILURE.md) блокирует обычную перезапись Android/iOS store после отказа чтения и разрешает явный restore backup. [Q25-F176](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-STORE-DECODING.md) отвергает повреждённую структуру Android store и неверный UTF-8 без замены credentials. [Q25-F177](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-PROFILE-UI-REVISION.md) отвергает устаревшие Android/desktop UI-операции и сообщает о необходимости переподключения Android после правки активного INI. [Q25-F178](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-CONCURRENCY.md) защищает desktop profile store от устаревшей записи и карантина между экземплярами. [Q25-F179](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-STORE-VERSION.md) запрещает устаревшие записи между Android Activity и restore. [Q25-F180](../reports/audit-0.8.2/AUDIT-Q25-IOS-EMPTY-ARCHIVE.md) запрещает превращение пустого iOS store в шаблон до валидации. [Q25-F181](../reports/audit-0.8.2/AUDIT-Q25-IOS-ACTIVE-PROFILE-RECONNECT.md) сообщает iOS о ручном переподключении после правки активного INI. [Q25-F182](../reports/audit-0.8.2/AUDIT-Q25-IOS-PROFILE-SNAPSHOT.md) отвергает устаревшие iOS Edit/Delete внутри приложения. [Q25-F183](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-BOUNDS.md) ограничивает desktop store и macOS .bak 16 МиБ до чтения/хеширования/записи. [Q25-F184](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-LOCK-WAIT.md) ждёт краткую desktop-конкуренцию за sidecar lock с пределом одна секунда. [Q25-F185](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-STRUCTURE.md) отвергает null-корень и null-строки desktop store при сохранении настоящего пустого массива. [Q25-F186](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-ACTIVE-INDEX.md) отвергает неверный индекс активного профиля Android во всех трёх путях и ограничивает прямое чтение сервисом. [Q25-F187](../reports/audit-0.8.2/AUDIT-Q25-IOS-ACTIVE-INDEX.md) отвергает неверный индекс при iOS restore, ожидая XCTest на Mac/Xcode. [Q25-F188](../reports/audit-0.8.2/AUDIT-Q25-MOBILE-STORE-BOUNDS.md) ограничивает Android encrypted store и backup до декодирования/криптографии, отвергает неверный UTF-8 и фиксирует отдельные бюджеты переносимого backup и внутреннего desktop store. [Q25-F189](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-PROFILE-IDENTITY.md) мигрирует отсутствующий Id в смешанном desktop store и отвергает явные пустые/дублирующиеся Id при чтении и записи. [Q25-F191](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-STORE-NULL-FIELDS.md) отвергает null в обязательных полях и коллекциях desktop-профилей при загрузке и записи; conformance и обе desktop-сборки PASS. [Q25-F192](../reports/audit-0.8.2/AUDIT-Q25-DESKTOP-SETTINGS-STORE.md) объединяет файловое хранение настроек Windows/macOS, ограничивает чтение и запись 1 МиБ и сохраняет повреждённый оригинал до fallback; семь файловых conformance-кейсов и обе сборки PASS. [Q25-F193](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-APPS-INI.md) исправляет расположение apps_mode/apps при редактировании профиля с секцией logging; 167 JVM-тестов и debug APK PASS. [Q25-F194](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-SHARE-PASSWORD.md) запрещает выдачу ссылки без переносимого inline-пароля; 52 интеграционных теста общего редактора PASS на Windows. [Q25-F195](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-SHARE-UI.md) показывает этот отказ в UI Windows/macOS/iOS; desktop-сборки PASS, iOS XCTest ожидает стенд. [Q25-F196](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-SHARE-PARITY.md) согласует тесты Android/.NET/iOS для импорта ссылки без пароля и отказа повторного экспорта; 167 Android JVM-тестов и .NET conformance PASS со свежей debug host DLL. [Q25-F197](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-INI-MATRIX.md) закрепляет все 84 поля схемы через runtime и 1000 детерминированных мутаций INI с повторным импортом; 54 теста редактора PASS. Q25-F210 ниже закрывает доступный остаток: внешний writer имеет явную неподдерживаемую границу, iOS provider теперь read-only; 511 .NET, 167 JVM и 12 Android instrumentation PASS. Прежний VPN/reconnect E2E сопоставлен с D12; Apple runtime SKIPPED по решению пользователя, не PASS. [Q25-F198](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-URI-BUDGET.md) ограничивает прямой импорт URI через панель 256 КиБ до разбора query; 1552 переносимых и 54 интеграционных теста PASS. |
| D09 | 14/15/25/32/33 | DONE | Linux lifecycle и системные отказы | [Итоговая сверка](../reports/audit-0.8.2/AUDIT-Q25-LINUX-LIFECYCLE-CLOSURE.md): на исходном `4eaf551a` 2175 Linux unit, 8 control, 15 hook-process и 8/8 реальных worker lifecycle PASS; сохранены exit/SHA и сетевые снимки до/после. Ранее 48 privileged и реальные DNS/route/firewall матрицы применимы к неизменённым путям. Полные install/upgrade и сетевые сочетания остаются D11/D10, общий shutdown — D05. |
| D10 | 17/18/19/21/22/23 | DONE | Сетевая интеграционная матрица | Поддерживаемый Linux-контракт закрыт Q25-F211/F212/F213 ниже: 118 четырёхпрофильных IPv6/DNS checks, 8 NDP packet cells/248 checks, 4 mixed IPv4/IPv6 backend с public zone/policy firewalld reload/restart/416 checks и 19 адресных тестов PASS. Чужие ресурсы восстановлены; crash/recovery — D04, TCP/UDP multiprofile SIGKILL/churn — D13. Произвольные root rewrites/автоматическая смена backend не сертифицированы. [Evidence](../../../release/certification/evidence/firewalld-profiles-20261002.json). |
| D11 | 00/24/27/34 | DONE | Актуальные native cores и provenance | [Q25-F202](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md): чистый исходник `27db1a22`, единый digest, независимые A/B release-сборки Windows x64, macOS universal2, Android arm64/x86_64 с совпадающими SHA; ABI/exports, 14 manifest-копий и provenance PASS. Windows selftest 143/0, Android APK содержит проверенные библиотеки. После Q25-F204 [повторная A/B сборка](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md#обновление-после-q25-f204-1-октября-2026): source digest `d39a3343`, четыре ABI 1.16 библиотеки, 14/14 SHA-пар и provenance PASS; Windows selftest 143/143, Android JVM 167/167 и новый APK с точными `.so`. Mac app/runtime исключены в D12 по решению пользователя.  Текущий пакет 7 октября: см. сверку native/Linux выше. |
| D12 | 24/25/27/34 | DONE | Платформенное подтверждение в доступном объёме | [Q25-F203](../reports/audit-0.8.2/AUDIT-Q25-ANDROID-NETWORK-IDENTITY.md): Android 0.8.2 APK/JNI, 167 JVM, 11 instrumentation, двусторонний ICMP, WebView HTTP 200 с VPN-адреса, reconnect и Wi-Fi toggle PASS. Физический inner-source локализован в системном Private DNS `netd`; серверный антиспуфинг сохранился. Windows VM, Mac/Xcode/iOS и router runtime **SKIPPED по решению пользователя**, не PASS. После нового native A/B и APK [instrumentation 11/11](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md#обновление-после-q25-f204-1-октября-2026) повторена; полный VPN-трафик этого нового APK не повторялся. Physical Android/LTE/Doze/always-on и release APK остаются полным аудитом раздела 29, не сертифицированы этим пунктом. |
| D13 | 14/19/22/25 | DONE | Удержание ресурсов под нагрузкой | [Q25-F204](../reports/audit-0.8.2/AUDIT-Q25-WORKER-RESOURCE-CHURN.md): 8/8 worker TCP/UDP × IPv6-mode, 80 reload, fd/socket/tasks Δ=0; точный release SHA `a526c03b` дал 100 TCP handover (16/16), 100 UDP QUIC handover (17/17), 3 UDP адаптера ×20 (по 17/17), без смены сессии/процессов/TUN и с восстановлением sysctl lease. Два одновременно работающих TCP/UDP профиля: 14/14 stop/reload/SIGKILL/recovery, fd/socket/tasks 26/11/7→26/11/7, сеть/journal после stop восстановлены. Пиковый RSS измерен выборочно; недоступные платформенные runtime не сертифицированы. |
| D14 | 00/34 | DONE | Исторический итоговый прогон и certification | Инженерные проверки зафиксированы для снимка `a526c03b`: автоматическая certification 20/20, сетевые проверки и восстановление состояния стенда. [Методика и статус измерений](../reports/BENCHMARK.md). Численные замеры 0.8.2 сняты с публикации и не служат публичным сравнением версий. Физические advisory не являются PASS; при изменении исходников требуется новая проверка применимости evidence. |
| D15 | Все начатые разделы | DONE | Итоговое согласование | [Q25-F200](../reports/audit-0.8.2/AUDIT-Q25-DOC-PARITY.md)/[Q25-F201](../reports/audit-0.8.2/AUDIT-Q25-PATCH-RECONCILIATION.md): docs и 625 архивных патчей сверены. Финал 3 октября: native A/B/ABI/provenance, Windows 143; 164 adapter + 288 Rust SHA неизменны; release `09af8fb0`, Linux 2257 unit, fmt/Clippy, 18/327 runtime, 100 TCP + 100 QUIC/33 checks, 45,02 с shutdown/recovery, certification 20/20 automated. [Evidence](../../../release/certification/evidence/final-candidate-20261003.json). 21 physical advisory не PASS; D06 принят как ограничение.  Текущий пакет 7 октября: см. сверку native/Linux выше. |

Историческое состояние реестра на 3 октября: **14/15 DONE, D06 ACCEPTED_LIMITATION**.
Урегулированы **15/15 групп (100%)**: 14 закрыты по evidence, остаток D06
снят пользователем с обязательной реализации. Q25-A125 не исправлен: перед
заменой выбранного WAN остановить профиль и подтвердить cleanup. На тот момент был завершён
реестр техдолга; оставшиеся разделы полного аудита проверены позднее. Текущий итог приведён в начале документа.
Исторические числа ниже остаются результатами прежних снимков.

## Завершение техдолга: порядок с 25 сентября

По запросу пользователя работа ведётся пакетами, с проверками по риску изменения.
Опорный проверенный снимок — `a8aba986`: 1584 host, 71 config, 2157 Linux,
48 privileged, 8 lifecycle, 38 native cases и 2 recovery; см.
[TOFU worker](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md). Это результаты указанного
снимка, а не автоматический PASS для будущих изменений.

| Пакет | Группы | Конкретный остаток и условие завершения |
|---|---|---|
| A. Запуск, остановка и системный контекст | D05/D06/D09 | Одним проходом разобрать startup `config_source::load`/metadata/canonicalize, составной бюджет NetworkPlan/cleanup и оставшиеся ранние Drop; закрыть таблицу WAN/resolved/attach/dynamic IPv6. Для каждого пути зафиксировать результат: исправлен и проверен, уже покрыт ссылкой или обоснованное ограничение. Завершить адресными Linux-проверками затронутых границ. |
| B. Конфиги и оставшаяся сетевая совместимость | D07/D08/D10 | Завершить серверную field → parse/validate/runtime/serialize таблицу и клиентский контракт 81+3; покрыть save/reload/import, malformed input и конкурентное редактирование. Выполнить только незакрытые сочетания IPv6/NDP, DNS, multiprofile и firewall; известные исправления включать в один пакет. |
| C. Сборки, Android и ресурсы | D11/D12/D13 | На согласованном чистом commit пересобрать изменённые cores, проверить A/B/ABI/provenance и Android. Один ограниченный прогон churn/reconnect/fault с заранее записанными циклами и критериями роста fd/tasks/threads/RSS/сетевых объектов. Платформенные SKIPPED сохраняются. |
| D. Итоговый прогон и измерения | D14/D15 | Один общий регрессионный прогон итогового кандидата, актуальный benchmark и сверка пакетов/документации. Каждое обязательство получает evidence либо явный нерешённый остаток; непроверенное не объявляется закрытым. |

Пакеты задают последовательность завершения, а не обещание четырёх запусков или срок
в календарных днях. Исправления и короткие проверки выполняются внутри пакета;
переход к следующему не требует нового разрешения пользователя.

### Выбор проверок

- На каждое изменение — тест воспроизведённого дефекта, затронутые тесты модуля и
  необходимая сборка. Docs-only — только docs/link/diff checks, без Rust и лабы.
- Связанные исправления проверяются одним набором. Полный Linux/host набор выполняется
  на границе пакета; полная feature/platform матрица — на итоговом кандидате либо
  раньше при изменении cfg/features/ABI/зависимостей.
- Новые реальные fault/cancel/crash сценарии обязательны при изменении владения
  сетью, ключами или сохраняемым состоянием. Проверять неизменённые транспортные и
  firewall-матрицы после каждого локального исправления не требуется.
- Воспроизведение на старом бинарнике выполняется один раз. Сохранённый baseline
  используется повторно с его SHA; его повтор нужен только при изменении самого
  сценария, предпосылок или обнаруженной неоднозначности.
- Старое evidence переиспользуется только после сверки затронутого кода/зависимостей
  и условий стенда, с указанием исходного SHA и причины применимости. Сборка нового
  бинарника сама по себе не обнуляет все независимые проверки. Финальный кандидат
  всё равно проходит общий прогон.
- Независимые сборки и тесты запускаются параллельно; изменяющие одни и те же
  исходники, target или сетевые ресурсы — последовательно. Успешный прогон без
  последующего релевантного изменения не повторяется.

### Границы и отчётность

Существующие обязательства D01–D15 сохраняются. Новые некритичные улучшения и
неподтверждённые гипотезы записываются в очередь дальнейшего полного аудита и не
расширяют текущий пакет. Подтверждённый дефект безопасности, потери данных/трафика
или основного рабочего сценария включается в пакет с конкретным воспроизводителем.

Непрерываемый системный вызов и принудительный Drop требуют описания поддерживаемой
границы и поведения владельца; сами по себе они не запускают новый цикл аудита.
Обычное зависание, потеря ошибки или оставленная без владельца мутация остаются
обязательными дефектами. Пункт нельзя закрыть простым переименованием в ограничение.

Одна запись результата пакета в этом реестре; отдельный отчёт на каждую небольшую
правку не требуется. Логи, команды и хеши сохраняются машинно, в итоговом тексте —
изменение поведения, закрытые критерии и конечный остаток. Показатель 4/15 относится
к целиком закрытым группам; он не используется как оценка времени или выполненной
работы. Статусы меняются только по результату, не вследствие перестройки плана.

Начальная сверка пакета A на `a8aba986`: `config_source` уже отвергает специальные
файлы через NONBLOCK + fstat и сверяет один открытый снимок. Повторный аудит этих
свойств не нужен без их изменения. Открыты синхронный вызов загрузчика до регистрации
сигналов, отсутствие общего лимита размера в самом загрузчике и startup metadata/
canonicalize. Это конкретные точки проверки; отдельные DNS/route/gateway/kill-switch
бюджеты и joined workers уже имеют evidence. Осталось проверить их композицию и
ранние пути выхода, а не повторять все предыдущие сценарии.

Изменение privileged-ресурса сторонним root между проверкой и записью не обещает
атомарной защиты; это предел интерфейса ОС, а не автоматически новый функциональный
дефект. Однако потеря identity, ошибка команды и неопределённый исход должны сохранять
сведения для восстановления и не давать ложный успешный результат.

### Пакет A — проверенный результат запуска, 25 сентября

Закрыта стартовая часть D05/D09: обработчики stop установлены до чтения INI,
клиентский предел 256 КиБ применяется до чтения/выделения содержимого; загрузка,
capability probes и hook canonicalize выполняются в joined worker. Предупреждение
о правах использует тот же открытый снимок. Stop дожидается принятой операции;
поздняя ошибка не скрывается, credential-команда и подключение не начинаются.

Адресные проверки: 12 host + 32 Linux tests (15 config source, 8 lifecycle,
9 prepared worker), Linux Clippy и standalone client build. На frozen baseline
`a8aba986` воспроизведены блокировка runtime, выход по SIGTERM до обработчика и чтение
oversized-файла. Три исправленных startup-сценария и TCP/UDP startup → post_up → stop
прошли в отдельных NET/mount/PID namespaces; маршруты и operator firewall сохранены.
Первый stop-сценарий ошибочно использовал `pass_cmd`: отказ строгого парсера сохранён,
исправленная фикстура с `password_command` проверена повторно. Регрессия сохранена в
[scripts/audit_client_startup.py](../../../scripts/audit_client_startup.py) и
[test shim](../../../scripts/audit_client_startup_shim.c). Команды, manifests, SHA и логи:
`audit-debt-20260924/batch-a-startup/` в каталоге артефактов `qeli`.

Переиспользован сервер `a8aba986` (SHA256 `c53dec6b…83c97`) и неизменённая teardown-фикстура;
серверная логика этого изменения не касается. Общие прошлые матрицы не объявляются
новым прогоном. D05/D06/D09 пока IN_PROGRESS: остались составной бюджет NetworkPlan/
cleanup, таблица системного контекста и ранние Drop. Установленная граница: невозможно
безопасно оборвать произвольный kernel/filesystem I/O; принудительный Drop сохраняет join.
Это ограничение не закрывает оставшуюся задачу общего командного бюджета.

**Общий командный бюджет (продолжение пакета A).** TUN/gateway/routes/DNS настройки
делят 15 секунд. Rollback/cleanup получает отдельный общий срок; deadline сохраняется
через pump join, worker threads, fallback Drop и terminal firewall cleanup. Ошибки
остаются sticky, а новая попытка после завершения прежних владельцев получает новый бюджет.
Имена владельцев, namespace guards и условие снятия kill-switch не ослаблены.

Проверены 1594 host-теста, 471 адресный Linux-тест и 18 privileged; Linux Clippy,
client-only и server-only builds. В восьми native baseline/fixed сценариях TCP/UDP
последовательные задержки 9+9 секунд на старом `efc9f949` давали 19–20 секунд операции.
Исправленный setup прерывает команды к общему сроку и завершает rollback примерно за
15,9 секунды от первого маркера; cleanup — примерно за 14,8 секунды от маркера первой
мутации (его бюджет начался раньше). Setup оставляет чистую сеть, ошибка cleanup
сохраняет DROP обеих семей и `failed`; чужие правила/routes не изменены. Четыре обычных
TCP/UDP clean/fault shutdown и два явных recovery также PASS. Сценарий:
[audit_network_budget.py](../../../scripts/audit_network_budget.py). Evidence:
`audit-debt-20260924/batch-a-budget/`, source manifest 359 файлов, driver SHA256
`ef126a15…934a4f7`. Сервер `a8aba986` переиспользован; его runtime не объявляется новой сборкой.

Отдельная проверка restart после **timeout gateway** подтвердила границу D02:
утраченный per-interface sysctl witness запрещает автоматическое завершение очистки.
Первое ожидание автоматического recovery дало 2 FAIL и сохранено в `ab3`; это не PASS
восстановления. Проверяется сохранение исходной записи, отсутствие TUN/routes и DROP
обеих семей; ручная процедура — [§6.64](../manuals/TROUBLESHOOTING.md#664-потерян-исходный-sysctl-интерфейса).
Успешные два recovery выше относятся к прежнему route-fault сценарию без утраты witness.

Командная композиция закрыта в этих границах; жёсткий timeout произвольного kernel I/O
не обещается. D05 остаётся IN_PROGRESS до конечной сверки ранних Drop и остальных
внутренних ожиданий; D06 — до проверок ниже. Общий итог групп не изменён: 4/15 DONE.

Сверка D06 с текущим кодом (без заявления новых runtime PASS):

| Граница | Существующее свидетельство / остаток |
|---|---|
| resolved / system bus | GUID/unique owner/network/PID context уже проверены в [resolver context](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONTEXT.md); DNS-маркеры v2 и crash — D04. |
| procfs / sysfs | Namespace pins, cookie и sysctl witness — D02/D04. IPv6 module-disabled читается ограниченно и строго; это не гарантия отсутствия IPv6 в будущем. |
| TUN attach / имена | [Attach](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md), lease и route/TUN identity имеют отдельные проверки. `dev_attach` читает `tun_flags` из `/sys/class/net`, который может остаться от прежнего network namespace. [Netlink-снимок ядра](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c) не содержит всех `TUN_FEATURES`, а первый `TUNSETIFF` может их переписать; простой перенос на netlink небезопасен. [Q25-F123](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH-CONTEXT.md) добавляет native same-name/different-netns проверку и отклоняет доказанное расхождение `ifindex` до `TUNSETIFF`. Совпадение индексов не доказывает общий namespace; до namespace-aware чтения полного набора флагов эта комбинация не сертифицирована. |
| Физический WAN | `gateway/wan.rs` возвращает имя из маршрута, firewall сохраняет selector имени. [Q25-F120](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IPV6-ROAM.md) повторно проверяет IPv6 default route после rule batch при roaming COMMIT. [Q25-F124](../reports/audit-0.8.2/AUDIT-Q25-EXIT-POLICY-ROUTING.md) воспроизводит off-WAN выход без NAT при policy routing и добавляет fail-closed DROP до установки MARK/NAT, а также lockdown на время cleanup. [Q25-A125](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md) подтвердил: смена на другое имя блокируется, но новое устройство со старым именем наследует MARK/NAT без refresh. [Q25-F126](../reports/audit-0.8.2/AUDIT-Q25-WAN-METRIC.md) выбирает default route с минимальной метрикой; отдельную смену exit WAN без VPN COMMIT теперь обрабатывает монитор [Q25-F127](../reports/audit-0.8.2/AUDIT-Q25-EXIT-WAN-MONITOR.md), проверенный на TCP/UDP вместе с cleanup. До identity-bound backend rename/reuse активного WAN не поддерживается; перенос и mixed-backend packet/recovery остаются D06/D10. [Q25-F128](../reports/audit-0.8.2/AUDIT-Q25-EXIT-SELF-WAN.md) запрещает выбирать собственный exit-TUN как WAN до установки правил. [Q25-F129](../reports/audit-0.8.2/AUDIT-Q25-WAN-ECMP.md) отклоняет ECMP и равноприоритетные default routes на разных WAN вместо одного адресного hash bucket; клиентский IPv6 gateway также отказывает до изменения forwarding/RA. |
| DNS / carrier globals | DNS per-link; process-global carrier/cycle защищён одним run_client на процесс до terminal cleanup. Forced Drop закрывает повторный допуск до перезапуска процесса; проверка ниже. |
| Динамический IPv4 | [Q25-F122](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV4.md) запрещает допуск без `iptables` по пустому текущему списку default route; поздний маршрут не обходит отсутствующий firewall. Другие WAN/route сценарии остаются D06/D10. |
| Динамический IPv6 | [Q25-F121](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-DYNAMIC-IPV6.md) запрещает незащищённый допуск по пустому текущему списку адресов; поздний IPv6 не обходит отсутствующий firewall. Реальная сетевая матрица появления адреса и прочие динамические пути остаются D06/D10. |

**Допуск Linux runtime и сверка ранних выходов (продолжение пакета A).** Устранено
пересечение process-global carrier/cycle state при двух `run_client`: второй вызов
отвергается до конфигурации/сигналов, допуск удерживается до завершения cleanup и
итогового writer. Возвращённая ошибка допускает следующий запуск с обычными проверками
ресурсов. Forced Drop всей future закрывает допуск до перезапуска процесса: вложенные
TaskGroup не гарантируют async join при Drop. Это явная граница отмены, а не заявление
успешной сетевой очистки. [Контракт](../manuals/OPERATIONS.md#один-linux-клиент-на-процесс).

На исходном entry point `b307c913` проверка отказа до чтения отсутствующего INI дала
ожидаемый FAIL: старый вызов дошёл до открытия файла при занятом process gate.
Исправленный entry point и проверки simultaneous admission, terminal ownership,
отмены с работающим ребёнком и panic прошли: 7 host + 85 Linux tests, Linux Clippy.
Три privileged-теста неизменённых namespace workers оставлены ignored в этом адресном
прогоне; новый privileged PASS не заявляется. Окончательные команды/коды/manifest: `audit-debt-20260925/batch-a-instance/`.

Сверка ранних путей Linux-клиента с текущим кодом и прежним evidence:

| Путь / ожидание | Результат и граница |
|---|---|
| Startup/NetworkPlan до adoption | `network_task::Job::Drop` отклоняет результат и присоединяет исходный поток; частичный guard откатывает на нём же. [Network worker](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-TASK.md), startup и бюджет выше. |
| Pump-start / частичный план | При отказе writer reader останавливается и присоединяется; непринятый `(pump, guard)` уничтожается в этом порядке. [Pump start](../reports/audit-0.8.2/AUDIT-Q25-PUMP-START.md). |
| Установленный TUN / обычная ошибка | `TunGuard::shutdown` ждёт DNS → pump → routes/gateway; fallback Drop удерживает TUN fd и общий cleanup deadline. [Teardown](../reports/audit-0.8.2/AUDIT-Q25-TUN-TEARDOWN.md), бюджет выше. |
| TCP/H2/UDP дочерние задачи | Обычные выходы выполняют TaskGroup finish до terminal cleanup; Drop только закрывает admission/запрашивает abort. Forced cancellation всего run_client теперь запрещает повторный запуск в процессе. [TCP](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md), [H2](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md), [UDP](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md). |
| TOFU/status / файловый I/O | finish ждёт worker; fallback Drop синхронно join. Sender/queue mutex не удерживается во время файловой операции. [TOFU](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md), [status](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md). |
| Внутренние locks / ожидания | Carrier/core/diagnostic state меняется под короткими mutex без await; очереди writer освобождают mutex перед внешним I/O. TunWorkers удерживает join lock до всех потоков специально, чтобы отмена не оставляла fd без владельца. [TUN workers](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md). Непрерываемые kernel/fs I/O и forced join остаются описанной границей, не обещанием 15-секундного process exit. |

Это закрывает сверку перечисленных Linux early-Drop путей и process-global допуска.
На этом этапе D05/D06/D09 не закрывались: файловая подготовка hooks и backup
требовала runtime воспроизведения. Она закрывается следующим продолжением пакета ниже;
серверные setup/cleanup ещё требуют проверки.
WAN/dynamic IPv6 остаются в D06; никакие новые платформенные или сетевые packet PASS не заявляются.

**Файловый I/O hooks и backup (продолжение пакета A).** Подтверждены и исправлены
блокировки executor при записи/удалении hook context и чтении активного INI для backup.
Hooks владеют подготовкой, command runtime и cleanup в одном присоединяемом потоке;
отмена до запуска не выполняет команду, отмена работающего shell ждёт terminate/reap
до удаления context. Backup preflight выполняется в существующем blocking worker с
config lease; отмена HTTP-запроса не освобождает её раньше операции. Общий загрузчик
отвергает FIFO и проверяет стабильность исходного файла. Права исполнения hooks и
форматы INI/API не менялись.

Проверки: **37 host + 77 Linux tests, 8 native-сценариев PASS**, Linux Clippy и отдельные
client/server builds. Воспроизводитель задерживает настоящий write/unlink/read на 2 секунды:
исходные обработчики `0645a8b0` дают 0/0/2 heartbeat тика (3 ожидаемых FAIL), исправленные —
178/178/179. Отмена подготовки не создаёт marker запуска; отмена работающего hook подтверждает
reap/отсутствие процесса и удаление context. Отменённый backup удерживает config lease,
сохраняет конфиг и даёт 178 тиков. Backup → overlay/exact restore и отказ неполного rollback
snapshot проверены в приватных NET/mount/PID namespace и tmpfs `/etc/qeli`, `/tmp`.
Shim: [audit_hook_backup_io_shim.c](../../../scripts/audit_hook_backup_io_shim.c).
Логи/команды/manifest 362 исходных файлов:
`audit-debt-20260925/batch-a-file-io/`; fixed test binary SHA256 `208e91b7…500bba`.
Baseline — исходные обработчики с новым тестовым harness, не старый выпущенный бинарник.

Этот остаток hooks/backup закрыт; D05 целиком остаётся IN_PROGRESS. Сверка server-кода
уточнила следующий пакет: `run_worker` вызывает `nat::cleanup_all` синхронно;
`run_profile_generation` выполняет TUN/NAT setup, а штатный `run_profile` вызывает
`drop(ProfileTeardown)` с NAT cleanup/worker joins на async-пути. Компонентные сроки NAT
уже проверены; scheduler isolation и составной срок профиля ещё требуют проверки.
Непрерываемые kernel/fs вызовы и forced join не объявляются жёстко ограниченными таймером.
D06 WAN/dynamic IPv6 и остальные группы сохраняются; итог **4/15 DONE**.

### Q25-F115 — серверная очистка вне async executor

Синхронные `nat::cleanup_all`, штатный `ProfileTeardown::drop`, итоговые
NAT sweep/ownership check и `usage.flush` выполняются в присоединяемых потоках.
Отмена ожидающего async-кода ждёт рабочий поток, поэтому network namespace lease и
профильные ресурсы не освобождаются до завершения принятой очистки. Порядок
остановки дочерних задач, удаления регистрационной записи, NAT и TUN сохранён;
ошибка worker входит в `Outcome`. [Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-CLEANUP-WORKER.md).

На host: 1602 теста PASS, 1 заранее ignored; Linux cross-check и all-targets Clippy
PASS. В лабе `.11` 10 адресных Linux-тестов и восемь реальных TCP/UDP ×
`off`/`manual`/`route`/`nat66` lifecycle-сценариев и 2 bind-failure/rollback/retry сценария PASS в частных пространствах
NET/mount/PID. Точный manifest/логи: `audit-debt-20260925/server-cleanup-phase/`.
D05 остаётся IN_PROGRESS: синхронная TUN/NAT setup, аварийный Drop, составной
срок профиля и непрерываемые системные вызовы ещё требуют отдельного решения.
Итого по реестру **4/15 DONE**.

### Q25-F116 — установка TUN/NAT серверного профиля вне executor

Создание и настройка TUN выполняются в первом присоединяемом worker: до
передачи результата непостоянный TUN принадлежит его исходным fd. После принятия
очередей `ProfileTeardown` владеет ими, и только затем отдельный worker запускает
NAT/IPv6 setup. Отмена ожидания присоединяет выполняющийся поток перед Drop
внешнего guard. [Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-WORKER.md).

1603 host-теста PASS, 1 заранее ignored; 11 адресных Linux-тестов, Linux
all-targets Clippy и реальные 8 штатных + 2 bind-failure/retry сценария в
приватных пространствах `.11` PASS. Снимок/логи:
`audit-debt-20260925/server-setup-phase/`. D05 остаётся IN_PROGRESS: DNS INPUT
firewall, NDP bind, аварийный Drop и составной срок всех операций не закрыты.
Реестр: **4/15 DONE**.

### Q25-F117 — DNS firewall серверного профиля вне executor

Обе установки DNS INPUT/REDIRECT выполняются на присоединяемом worker.
Отменённое ожидание закрывает канал принятия; непринятый `DnsInputLease`
уничтожается в исходном namespace до Drop внешнего guard. Принятый lease
передаётся `ProfileTeardown`. [Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-DNS-SETUP-WORKER.md).

1603 host-теста PASS, 1 заранее ignored; 11/11 Linux адресных тестов,
22/22 recovery/ownership/SIGKILL checks, 4/4 TCP/UDP × IPv6 `manual`/`route`
DNS сценария в приватных пространствах `.11` PASS. Логи и manifest:
`audit-debt-20260925/server-dns-setup-phase/`. D05 остаётся IN_PROGRESS:
NDP bind, аварийный Drop и общий срок установки открыты. Реестр: **4/15 DONE**.

### Q25-F118 — NDP bind вне executor

`AF_PACKET` bind и socket-local multicast выполняются в присоединяемом
worker; после принятия `OwnedFd` регистрируется как `AsyncFd` в исходном
Tokio runtime. Отмена закрывает непринятый fd до уничтожения внешнего guard.
[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NDP-BIND-WORKER.md).

В `.11`: 5 NDP unit, 1 privileged namespace, 8 lifecycle и 22 recovery checks
PASS; Linux Clippy для library/binary и rustfmt PASS. Исходник и логи:
`audit-debt-20260925/server-ndp-bind-phase/`. D05 остаётся IN_PROGRESS:
общий срок, принудительный Drop и непредсказуемые kernel/fs I/O.
Реестр: **4/15 DONE**.

### Q25-F119 — общий срок server setup и готовность всех listeners

120-секундный бюджет действует от начала поколения до подтверждения bind
основного и всех дополнительных listeners; после готовности профиль служит
без этого таймера. UDP сообщает готовность после всей группы SO_REUSEPORT.
Ошибки bind передаются только установке, не маскируются под ошибку cleanup.
[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SETUP-BUDGET.md).

На `.11`: 2 новых + 11 worker-тестов, 8 lifecycle, 4 occupied-bind
rollback/retry/stop и 22 recovery checks PASS; Linux Clippy library/binary,
rustfmt и docs checks PASS. Первый отказ и исправленный прогон сохранены в
`audit-debt-20260925/server-setup-budget-phase/`. D05 остаётся IN_PROGRESS:
forced Drop, общий срок shutdown и непрерываемый kernel/fs I/O.
Реестр: **4/15 DONE**.

### D09 — итоговая Linux lifecycle сверка, 25 сентября

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-LINUX-LIFECYCLE-CLOSURE.md) связывает текущий полный
Linux-набор (2175 PASS), 8 control и 15 hook-process тестов с восемью реальными
worker-сценариями. У каждого сохранены raw-снимки firewall/routes/links/forwarding
до и после, бинарный и сценарный SHA, stdout и exit. Первый дополнительный
снимок ложно сработал на пустые builtin таблицы xtables-nft; исходные дампы
сохранены, правило сравнения исправлено. Первый полный набор упал с EMFILE при
nofile=1024 на тесте 512 TCP-соединений; неизменённый код прошёл при nofile=4096.
Предыдущие privileged/DNS/route/crash прогоны сверены с неизменёнными путями.
**D09 DONE; реестр: 5/15 DONE (33,3%), 8 IN_PROGRESS, 2 TODO.**
Установка/обновление и systemd runtime остаются отдельными пунктами полного аудита
и D11; D05/D06/D10 не меняют статус.

### Q25-F130 — допуск server worker после отмены

После первой сетевой мутации forced Drop или неподтверждённый terminal result
удерживает network-namespace lease до выхода процесса. Ранний отказ и успешная
штатная остановка освобождают его; новый worker не допускается поверх
незавершённого поколения. [Отчёт и проверки](../reports/audit-0.8.2/AUDIT-Q25-SERVER-FORCED-DROP-LEASE.md).
Это частичное закрытие D05: async join дочерних задач при forced Drop и общий
срок shutdown остаются открытыми. Реестр: **5/15 DONE**.

### Q25-F131 — наличие WAN при серверной установке

Выбранный IPv4 NAT или управляемый IPv6 uplink теперь проверяется через ioctl
в network namespace worker до включения forwarding и добавления правил.
[Отчёт и 1 unit + 8 штатных + 2 отрицательных Linux-прогона](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WAN-PRESENCE.md).
Открыты повторное использование имени активного WAN, атомарная привязка правил
к устройству и mixed-backend recovery. D06 остаётся IN_PROGRESS; реестр **5/15 DONE**.

### Q25-F132 — неоднозначный auto-WAN на сервере

Общий с клиентом парсер default routes обнаруживает ECMP и равную лучшую метрику
разных WAN. Серверный auto-режим отказывает до forwarding и новых правил;
[отчёт: 11 parser + 1 WAN unit, 8 обычных и 2 отрицательных Linux-сценария](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WAN-ECMP.md).
Явный WAN, отдельные policy routes и runtime-смена остаются D06/D10;
реестр **5/15 DONE**.

### Q25-F133 — сборка клиентского ядра без roaming feature

Монитор exit WAN работает на Linux независимо от experimental-roaming, но имя
TUN в TCP и UDP объявлялось только под этим feature. Сборка client-only
падала с двумя E0425; область объявления расширена до Linux.
[Отчёт, baseline FAIL и исправленные feature-сборки](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-ONLY-BUILD.md).
Клиентский router binary собран и запущен с --help; платформенный runtime
и provenance остаются D11/D12. Реестр **5/15 DONE**.

### Q25-F134 — NAT66 только через выбранный WAN

При разрешающем хостовом FORWARD прежний пакет из TUN мог выйти через другой
WAN без MASQUERADE. Обязательный per-profile DROP ставится до разрешений и
охватывает весь TUN. [Отчёт: 16 NAT tests, Clippy/build, packet baseline/fixed,
1 реальный worker с точной очисткой](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NAT66-EGRESS.md).
IPv4 NAT44 и server-side LAN требуют отдельного решения контракта; повторное
использование WAN-имени и mixed backend остаются D06/D10. Реестр **5/15 DONE**.

### Q25-F135 — NAT auto-WAN без списка default routes

NAT44/NAT66 больше не переходят к одному `route get` при ошибке или отсутствии
пригодного списка default routes: это был обход отказа от ECMP. [Отчёт:
18 NAT tests, 2/2 baseline startup и 2/2 fixed refusal до сетевых мутаций](../reports/audit-0.8.2/AUDIT-Q25-SERVER-AUTO-WAN-FAILURE.md).
Пакетный опыт отдельно подтвердил незакрытую NAT44 off-WAN утечку и нужный
LAN-путь, который безусловный DROP также блокирует. Контракт LAN-исключений,
явный `eth0`, runtime WAN identity и mixed backend остаются D06/D10;
реестр **5/15 DONE**.

### Q25-F136 — NAT44 вне выбранного WAN и приватные сети

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-NAT44-EGRESS.md): обязательный guard
отсекает не-RFC1918 трафик из TUN на чужом интерфейсе до разрешений хоста,
не меняя firewall-политику RFC1918 LAN. Пакетный прогон на nft/legacy
подтверждает DROP, LAN без NAT и MASQUERADE на выбранном WAN; реальный
worker проверяет установку и точную очистку. RFC1918 off-WAN, LAN вне
RFC1918, policy WAN и смена идентичности интерфейса остаются D06/D10;
реестр **5/15 DONE**.

### Q25-F137 — SIGHUP применяет VPN-auth только после общей проверки

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-SIGHUP-AUTH.md): сначала
`validate_profiles` и загрузка эффективной базы пользователей, затем
обновление пользователей и brute-force порогов. Ошибка любого источника
оставляет обе живые части прежними. Прямой async-тест охватил неверный
`tun.mtu`, повреждённый `users.conf` и успешное применение; D07 остаётся
**IN_PROGRESS** до полной матрицы путей и size bounds. Реестр **5/15 DONE**.

### Q25-F138 — единый предел серверного INI

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-INI-SIZE.md): worker, CLI и панель
отказывают в чтении server INI свыше 16 МиБ; форма, raw INI, Quick Start,
настройки brute-force и restore не публикуют сверхлимитный результат.
При ошибке чтения активного файла редактор не подставляет стартовую копию.
16 loader + 33 editor + 1 backup тест, строгий Clippy и фактический
`check-config` на 16 МиБ + 1 байт прошли. D07 остаётся **IN_PROGRESS**;
реестр **5/15 DONE**.

### Q25-F139 — согласованное живое состояние панели

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-WEB-LIVE.md): при сохранении нового
`web.port`/`bind`/TLS текущий listener и проверки CSRF остаются на стартовых
значениях до полного рестарта. Изменение `[web] brute_force` через общую форму
или INI применяет новые пороги сразу; прежний lockout сохраняется при
неизменной политике. Прямой async-тест и строгий Clippy прошли. D07 остаётся
**IN_PROGRESS**; реестр **5/15 DONE**.

### Q25-F140 — права активного серверного INI после сохранения панели

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-INI-PERMISSIONS.md): все пять путей
панельной записи публикуют серверный INI с режимом `0600` независимо от
старых прав. Прямой Linux-тест с исходным `0644`, 34 теста редактора и строгий
Clippy прошли. D07 остаётся **IN_PROGRESS**; реестр **5/15 DONE**.

### Q25-F141 — одинаковый допуск серверного INI

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-CHECK-CONFIG-PARITY.md): baseline на
лабе `.11` выявил расхождение `check-config` с runtime при отсутствующем
`users.conf` и ложный `OK` при всех выключенных профилях. CLI, supervisor,
worker и панель используют согласованные правила; адресный unit-тест, CLI и
startup-проверки, строгий Clippy прошли. D07 остаётся **IN_PROGRESS**; реестр
**5/15 DONE**.

### Q25-F142 — имя профиля и default identity-путь

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-IDENTITY-NAME.md): baseline `check-config`
принял `[profile:../escape]`, что вывело бы путь приватного ключа из
`/etc/qeli/identity`. Парсер, панель и прямые key-helper'ы теперь отвергают
разделители пути. Два unit-теста, серверный INI-аудит, строгий Clippy и CLI
пара на лабе `.11` прошли. D07 остаётся **IN_PROGRESS**; реестр **5/15 DONE**.

### Q25-F143 — доверие к файловым путям из INI

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-IDENTITY-TRUST.md): недоверенный
`server.conf` больше не выбирает произвольный `identity_key` для startup и
CLI-команд, а ранний логгер не открывает указанный им `logging.file`. Baseline
mode `0666`, адресные unit-тесты и CLI-матрица проверены на лабе `.11`.
Остальные файловые поля остаются D07; реестр **5/15 DONE**.

### Q25-F144 — доверие к пути users-файла

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-USERS-PATH-TRUST.md): нестандартный
`auth.users_file` из недоверенного INI больше не достигает записывающих
CLI-команд, панели или control socket. `check-config` и оба startup-пути
проверяют тот же снимок до создания состояния. Адресный тест, CLI-матрица
и строгий Clippy проверены на лабе `.11`. D07 остаётся **IN_PROGRESS**;
реестр **5/15 DONE**.

### Q25-F145 — применение users_file после сохранения

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-USERS-SIGHUP-RESTART.md): SIGHUP не
подменяет путь users-файла и не принимает нестандартный путь из недоверенного
INI; при отказе сохраняет живое auth-состояние. Панель и restart API требуют
полного рестарта для смены users-файла и session-key source. Адресные тесты и
строгий Clippy на лабе `.11`; реестр **5/15 DONE**, D07 **IN_PROGRESS**.

### Q25-F146 — конкурентная запись серверного INI

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-CONCURRENT-WRITES.md): панель, `set-web-password`
и restore используют общий sidecar lock; `exact` restore сохраняет активные
lock-файлы и не публикует архивные. Проверка конкурентных писателей, тесты
редактора и backup, CLI-отказ при занятом lock и строгий Clippy на лабе `.11`.
Ручные SSH-редакторы остаются за пределом advisory lock; реестр **5/15 DONE**,
D07 **IN_PROGRESS**.

### Q25-F147 — загрузка TLS PEM панели

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-TLS-PEM.md): регулярный PEM читается с пределом 4 МиБ, FIFO отвергается без ожидания, уцелевший файл автопары не заменяется. Пять тестов, форматирование и строгий Clippy прошли на лабе .11. Сверка check-config и доверия к TLS-путям остаётся D07; реестр **5/15 DONE**, D07 **IN_PROGRESS**.

### Q25-F148 — TLS-файлы в check-config

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-TLS-CHECK-CONFIG.md): CLI проверяет существующую PEM-пару тем же загрузчиком, что и HTTPS-панель, без создания автопары. Восемь тестов, строгий Clippy и CLI-отказ на повреждённом сертификате прошли на лабе `.11`. Доверие к явным TLS-путям остаётся D07; реестр **5/15 DONE**.

### Q25-F149 — доверие к TLS-путям и панельное сохранение

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-TLS-PATH-TRUST.md): явная пара активной HTTPS-панели требует доверенного INI-снимка в CLI, supervisor и worker; Form и INI панели принимают `/etc/letsencrypt`; backup не требует TLS-файлы выключенной панели. Адресные тесты, CLI-матрица и строгий Clippy проверены на `.11`. Реестр **5/15 DONE**, D07 **IN_PROGRESS**.

### Q25-F150 — доверие к текущему INI в панельных API

[Отчёт](../reports/audit-0.8.2/AUDIT-Q25-SERVER-PANEL-SNAPSHOT-TRUST.md): identity list/rotate, Share и users получают пути только из ограниченного INI-снимка с проверкой доверия того же inode; restart preflight сверяет TLS. Четыре адресных теста и строгий Clippy прошли на `.11`. Реестр **5/15 DONE**, D07 **IN_PROGRESS**.

## Источники

- [AUDIT-Q01-SERVER-INI](../reports/audit-0.8.2/AUDIT-Q01-SERVER-INI.md)
- [AUDIT-Q02-CLIENT-PARSERS](../reports/audit-0.8.2/AUDIT-Q02-CLIENT-PARSERS.md)
- [AUDIT-Q05-PREFLIGHT](../reports/audit-0.8.2/AUDIT-Q05-PREFLIGHT.md)
- [AUDIT-Q14-CONTROL](../reports/audit-0.8.2/AUDIT-Q14-CONTROL.md)
- [AUDIT-Q14-DNS-OWNERSHIP](../reports/audit-0.8.2/AUDIT-Q14-DNS-OWNERSHIP.md)
- [AUDIT-Q14-H2-TASKS](../reports/audit-0.8.2/AUDIT-Q14-H2-TASKS.md)
- [AUDIT-Q14-HOOKS](../reports/audit-0.8.2/AUDIT-Q14-HOOKS.md)
- [AUDIT-Q14-IPV6-PARTIAL-ACQUIRE](../reports/audit-0.8.2/AUDIT-Q14-IPV6-PARTIAL-ACQUIRE.md)
- [AUDIT-Q14-NAT-CLEANUP](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP.md)
- [AUDIT-Q14-NAT-COMMANDS](../reports/audit-0.8.2/AUDIT-Q14-NAT-COMMANDS.md)
- [AUDIT-Q14-OWNED-SHUTDOWN](../reports/audit-0.8.2/AUDIT-Q14-OWNED-SHUTDOWN.md)
- [AUDIT-Q14-PROFILE-SHUTDOWN](../reports/audit-0.8.2/AUDIT-Q14-PROFILE-SHUTDOWN.md)
- [AUDIT-Q14-Q15-WORKER-USAGE](../reports/audit-0.8.2/AUDIT-Q14-Q15-WORKER-USAGE.md)
- [AUDIT-Q14-Q19-LIFECYCLE](../reports/audit-0.8.2/AUDIT-Q14-Q19-LIFECYCLE.md)
- [AUDIT-Q14-Q25-FIREWALL-CHECKS](../reports/audit-0.8.2/AUDIT-Q14-Q25-FIREWALL-CHECKS.md)
- [AUDIT-Q14-Q32-NOTIFICATIONS](../reports/audit-0.8.2/AUDIT-Q14-Q32-NOTIFICATIONS.md)
- [AUDIT-Q14-Q33-CONFIG-TRUST](../reports/audit-0.8.2/AUDIT-Q14-Q33-CONFIG-TRUST.md)
- [AUDIT-Q14-SUPERVISOR](../reports/audit-0.8.2/AUDIT-Q14-SUPERVISOR.md)
- [AUDIT-Q14-SYSCTL-RECOVERY](../reports/audit-0.8.2/AUDIT-Q14-SYSCTL-RECOVERY.md)
- [AUDIT-Q19-DNS-CACHE](../reports/audit-0.8.2/AUDIT-Q19-DNS-CACHE.md)
- [AUDIT-Q19-DNS-EDNS](../reports/audit-0.8.2/AUDIT-Q19-DNS-EDNS.md)
- [AUDIT-Q19-DNS-PROXY](../reports/audit-0.8.2/AUDIT-Q19-DNS-PROXY.md)
- [AUDIT-Q19-Q22-NETWORK-PLAN](../reports/audit-0.8.2/AUDIT-Q19-Q22-NETWORK-PLAN.md)
- [AUDIT-Q25-CLIENT-COMMANDS](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-COMMANDS.md)
- [AUDIT-Q25-CLIENT-NAMESPACE](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-NAMESPACE.md)
- [AUDIT-Q25-CORE-LIFECYCLE](../reports/audit-0.8.2/AUDIT-Q25-CORE-LIFECYCLE.md)
- [AUDIT-Q25-CREDENTIAL-COMMANDS](../reports/audit-0.8.2/AUDIT-Q25-CREDENTIAL-COMMANDS.md)
- [AUDIT-Q25-DNS-LEASES](../reports/audit-0.8.2/AUDIT-Q25-DNS-LEASES.md)
- [AUDIT-Q25-DNS-RECOVERY](../reports/audit-0.8.2/AUDIT-Q25-DNS-RECOVERY.md)
- [AUDIT-Q25-EXIT-OWNERSHIP](../reports/audit-0.8.2/AUDIT-Q25-EXIT-OWNERSHIP.md)
- [AUDIT-Q25-GATEWAY-IDENTITY](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-IDENTITY.md)
- [AUDIT-Q25-GATEWAY-ROLLBACK](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-ROLLBACK.md)
- [AUDIT-Q25-GATEWAY-WAN](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-WAN.md)
- [AUDIT-Q25-H2-TASKS](../reports/audit-0.8.2/AUDIT-Q25-H2-TASKS.md)
- [AUDIT-Q25-KILL-SWITCH-LIFETIME](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-LIFETIME.md)
- [AUDIT-Q25-NETWORK-CLEANUP](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-CLEANUP.md)
- [AUDIT-Q25-PASSWORD-FILES](../reports/audit-0.8.2/AUDIT-Q25-PASSWORD-FILES.md)
- [AUDIT-Q25-PATH-MONITOR](../reports/audit-0.8.2/AUDIT-Q25-PATH-MONITOR.md)
- [AUDIT-Q25-ROUTE-IDENTITY](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-IDENTITY.md)
- [AUDIT-Q25-ROUTE-OUTCOME](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OUTCOME.md)
- [AUDIT-Q25-ROUTE-OWNERSHIP](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-OWNERSHIP.md)
- [AUDIT-Q25-ROUTE-PENDING](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-PENDING.md)
- [AUDIT-Q25-ROUTE-POSTCONDITIONS](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-POSTCONDITIONS.md)
- [AUDIT-Q25-ROUTE-SCOPE](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-SCOPE.md)
- [AUDIT-Q25-SETUP-FLUSH](../reports/audit-0.8.2/AUDIT-Q25-SETUP-FLUSH.md)
- [AUDIT-Q25-SETUP-IDENTITY](../reports/audit-0.8.2/AUDIT-Q25-SETUP-IDENTITY.md)
- [AUDIT-Q25-SYSCTL-NAMESPACE](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-NAMESPACE.md)
- [AUDIT-Q25-SYSCTL-OWNER-EVIDENCE](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-OWNER-EVIDENCE.md)
- [AUDIT-Q25-SYSTEM-COMMANDS](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-COMMANDS.md)
- [AUDIT-Q25-TCP-TASKS](../reports/audit-0.8.2/AUDIT-Q25-TCP-TASKS.md)
- [AUDIT-Q25-TUN-ADMISSION](../reports/audit-0.8.2/AUDIT-Q25-TUN-ADMISSION.md)
- [AUDIT-Q25-TUN-ATTACH](../reports/audit-0.8.2/AUDIT-Q25-TUN-ATTACH.md)
- [AUDIT-Q25-TUN-CLEANUP](../reports/audit-0.8.2/AUDIT-Q25-TUN-CLEANUP.md)
- [AUDIT-Q25-TUN-LIFETIME](../reports/audit-0.8.2/AUDIT-Q25-TUN-LIFETIME.md)
- [AUDIT-Q25-TUN-WORKERS](../reports/audit-0.8.2/AUDIT-Q25-TUN-WORKERS.md)
- [AUDIT-Q25-TUNNEL-ROUTES](../reports/audit-0.8.2/AUDIT-Q25-TUNNEL-ROUTES.md)
- [AUDIT-Q25-UDP-TASKS](../reports/audit-0.8.2/AUDIT-Q25-UDP-TASKS.md)

D02/D05: [чтение sysctl-журнала и lock waits](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-JOURNAL-IO.md) исправлены в описанных границах; остальные критерии строк остаются открыты.

D03: [kill-switch namespace / reconnect](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-IDENTITY.md).

D02/D06: [namespace-aware link observation](../reports/audit-0.8.2/AUDIT-Q25-LINK-OBSERVATION.md).

D05: [async preflight и время жизни транзакции панели](../reports/audit-0.8.2/AUDIT-Q05-PANEL-TRANSACTIONS.md). Бюджет backup/restore закрыт следующим этапом; остальные сетевые последовательности открыты.

Обновление D05/D09: [бюджет backup/restore и полнота снимка](../reports/audit-0.8.2/AUDIT-Q05-ARCHIVE-BUDGET.md). Остальные сетевые последовательности и filesystem fault E2E остаются открытыми.

D02: [guard внутренних границ sysctl](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-CONTEXT-IO.md); durable namespace identity и исходный интерфейс ещё открыты; parent trust закрыт последующим этапом.

D02/D05/D09: [атомарная запись состояния](../reports/audit-0.8.2/AUDIT-Q25-ATOMIC-STATE.md) очищает частичные временные файлы и синхронизирует каталог на Unix; реальные partial-write/fsync fault probes PASS. Остальные критерии этих групп остаются открыты.

D02/D05/D09: [каталог состояния и целостность lock](../reports/audit-0.8.2/AUDIT-Q25-STATE-DIRECTORY.md). Parent trust закрыт в описанных границах; durable namespace identity и исходное поколение интерфейса остаются D02. Группы целиком ещё не закрыты.

D08/D11/D12: [Android JNI и emulator runtime](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-RUNTIME.md): исправлены cwd/API flag cargo-ndk, удалён устаревший JSON-config harness; 154 JVM + 6 instrumentation PASS. Свежий dev x86_64 APK проверен по SHA. Release A/B, полный конфигурационный/runtime контракт и остальные платформы открыты.

D02: [удержание namespace](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-PIN.md) открытыми fd действует от admission до конца транзакции; 1922 Linux + 29 privileged + 8 worker E2E PASS. Между транзакциями и после crash durable generation остаётся открытым, как и исходное поколение интерфейса.

D02: [Q25-F083 — исходный sysctl интерфейса](../reports/audit-0.8.2/AUDIT-Q25-SYSCTL-TARGET.md): journal v3 удерживает fd и отказывает при потере свидетельства; 3 дефекта baseline воспроизведены, 5 дополнительных worker E2E PASS. Опасное восстановление по имени и потеря original закрыты. Для global journal durable namespace generation после crash остаётся открытым; автоматическое per-interface crash recovery не обещается.

D05: [Q25-F084 — общий срок DNS](../reports/audit-0.8.2/AUDIT-Q25-DNS-BUDGET.md): dns/domain делят 15 секунд от admission, частичный lease сохраняется для отдельного rollback. 3 новые Linux-регрессии PASS. NAT/routes/kill-switch и остальные lock waits остаются открытыми.

D05/D09: [Q05-F008 — async health probes](../reports/audit-0.8.2/AUDIT-Q05-HEALTH-PROBES.md): Status/Transport health не блокируют executor ожиданием `--version`; четыре общих async-слота, deadline включает очередь. 8 новых обычных + 1 privileged HTTP-router тест PASS; 2 контрольных возврата старого поведения дают ожидаемый FAIL. Общие сроки сетевых мутаций и полный HTTP/systemd/fault охват остаются открытыми.

D05/D09: [Q25-F085 — общий срок очистки kill-switch](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-BUDGET.md): 15 секунд включают operation mutex и обе семьи; частичный результат сохраняет owner для нового verified retry. 5 регрессий PASS, 2 контрольных FAIL старого поведения. Engage/refresh рассмотрены следующими фазами ниже; NAT/routes/gateway и прочие lock waits ещё открыты.

D05/D09: [Q25-F086/F087 — refresh kill-switch](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REFRESH.md): общий срок admission/команд учитывает resolver; unknown не разрешает вставку. 6 новых регрессий и 5 повторных cleanup PASS; 3 контрольных FAIL прежнего поведения. DNS/NSS остаётся синхронным; engage закрыт следующей фазой ниже в части командного срока, NAT/routes/gateway и прочие ожидания открыты.

D05/D09: [Q25-F088/F089 — установка и откат kill-switch](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-SETUP.md): общий срок установки 15 секунд и отдельный общий срок отката 15 секунд; неполный откат нельзя принять флагами разрешения утечки. 8 новых регрессий PASS; 2 контрольных FAIL, затем 8 setup + 6 refresh + 5 cleanup PASS. Полный снимок: 1962 Linux + 30 privileged + 8 worker E2E PASS. Командные сроки engage/refresh/disengage закрыты в описанных границах; синхронный DNS/NSS, NAT/routes/gateway, прочие ожидания и полные D04/D05/D09 остаются открытыми.

D05/D09: [Q14-F034 — общий срок очистки NAT](../reports/audit-0.8.2/AUDIT-Q14-NAT-CLEANUP-BUDGET.md): profile/startup/final cleanup делят по 15 секунд между очередью, IPv4/IPv6, точными правилами и retired DNS UDP/TCP. Поздние ответы не дают успеха, неподтверждённые записи сохраняются. 8 новых Linux-регрессий PASS; 4 контрольных FAIL, затем 8 регрессий + 1 privileged exact-rule PASS. Полный снимок: 1970 Linux + 30 privileged + 8 worker E2E PASS. Открыты NAT setup/rollback, admission DNS lease в Drop/setup, routes/gateway, внутренние sysctl/I/O и полные D04/D05/D09.

D05/D09: [Q14-F035 — сроки и retirement DNS INPUT lease](../reports/audit-0.8.2/AUDIT-Q14-DNS-INPUT-BUDGET.md): setup и cleanup получают по 15 секунд с очередью/UDP/TCP; отдельный откат после setup, неблокирующая отметка завершения и сохранение pending evidence. 4 новые переносимые + 7 Linux + 1 privileged регрессии PASS; 5 контрольных отказов, затем 20 domain + 7 DNS + 8 NAT + 2 native PASS. Полный снимок: 1981 Linux + 31 privileged + 8 worker E2E PASS. NAT setup/rollback, DNS REDIRECT, routes/gateway, внутренние sysctl/I/O и полные D04/D05/D09 остаются открытыми.

D05/D09: [Q14-F036 — установка NAT/forwarding и DNS REDIRECT](../reports/audit-0.8.2/AUDIT-Q14-NAT-SETUP-BUDGET.md): общие сроки setup и точного rollback; 10 новых регрессий, 7 контрольных отказов, 1991 Linux + 31 privileged + 8 E2E PASS. Client routes/gateway, scheduler isolation и полный D05 остаются открытыми.

D02 закрыт: [Q25-F090 — поколение namespace и журнал v4](../reports/audit-0.8.2/AUDIT-Q25-NAMESPACE-GENERATION.md). D04/D05 и остальные критерии сохраняются. Проверки Windows VM, Mac/iOS и роутера исключены из текущего объёма по решению пользователя; они не объявляются PASS.

D09/D10: [17/17 Linux packet matrix PASS](../reports/audit-0.8.2/AUDIT-Q34-LINUX-MATRIX.md). D13: 100 TCP handover сохранили сессию/fd, но RSS превысил критерий; FAIL сохранён, долг открыт.

D05/D09: [Q25-F091 — общий срок gateway/exit-node](../reports/audit-0.8.2/AUDIT-Q25-GATEWAY-BUDGET.md): 6 регрессий, 6 контрольных FAIL, 107 restored gateway и полный Linux 2001 + 32 privileged + 8 E2E PASS. Route-последовательности, внутренние locks/I/O и scheduler isolation остаются открыты.

D13: [release TCP/UDP по 100 handover](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md): 30/30 утверждений PASS, прирост RSS в прежнем лимите 32 MiB; debug FAIL сохранён. Полный ресурсный/fault охват и итоговый снимок ещё открыты.

D05/D09: [Q25-F092 — общий срок route-транзакций](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-BUDGET.md): 8 регрессий, 6 контрольных FAIL, 196 восстановленных route tests и полный Linux 2009 + 32 privileged + 8 E2E PASS. Executor isolation и внутренний I/O остаются открыты.

D06/D09: [Q25-F093 — строгая проверка resolver-конфига](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONFIG.md): 3 новых теста, 2 контрольных FAIL, 18 восстановленных DNS, полный Linux 2012 + 32 privileged + 8 E2E PASS. Отдельно подтверждена cross-netns мутация через общую D-Bus-шину; bus/service identity ещё требует исправления.

D06/D09/D10: [Q25-F094/F095 — контекст resolved/D-Bus и DNS-порт](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-CONTEXT.md): direct unique-owner вызовы с AUTH GUID, 2023 Linux + 33 privileged + 8 E2E, 17/17 packet matrix (301 assertion), 4 контрольных FAIL и restored 29 DNS + 1 privileged PASS. Реальные resolved/custom port/чужие netns и PID namespace проверены. Предыдущий пункт о незакрытом bus/service identity закрыт в описанных границах; остальные критерии D06 и D10 открыты.

D04/D06/D09: [Q14-F037 — worker network lease](../reports/audit-0.8.2/AUDIT-Q14-WORKER-NETWORK-LEASE.md): исправлен обход через разные control/state пути; baseline удалял 9 правил работающего worker. 2027 Linux + 34 privileged + 8 lifecycle и 22 crash/admission/recovery проверки PASS. D04 IN_PROGRESS: persistent exact firewall/routes и mixed nft остаются открытыми.

D04/D09/D10: [Q14-F038 — persistent server firewall](../reports/audit-0.8.2/AUDIT-Q14-FIREWALL-JOURNAL.md): точные NAT/routing/DNS INPUT/REDIRECT спецификации записываются до изменения, восстанавливаются после SIGKILL и удаления профиля без listing. Backend/namespace/file errors останавливают startup, evidence сохраняется. 2044 Linux + 35 privileged + 8 lifecycle; 27 recovery checks; 17/17 cases, 301 assertions PASS. D04 остаётся IN_PROGRESS: клиентские route/DNS/kill-switch и полная mixed nft/firewalld матрица открыты.

D04/D06/D09: [Q25-F096/F097 — DNS state v2](../reports/audit-0.8.2/AUDIT-Q25-DNS-MARKER-STORAGE.md): доверенный закреплённый каталог, проверка файлов и SO_NETNS_COOKIE; v1 сохраняется без автоматической миграции. 3 файловых дефекта воспроизведены на baseline. 2055 Linux + 37 privileged + 8 lifecycle; 17/17 cases, 323 assertions PASS. Остаются client route/kill-switch recovery, legacy global DNS, live persistent TUN, mixed nft/firewalld и накопление sidecar-файлов; D04 IN_PROGRESS.

D04/D09/D10: [Q25-F098 — kill-switch после crash](../reports/audit-0.8.2/AUDIT-Q25-KILL-SWITCH-REBUILD.md): временные точные DROP guards сохраняют прежний барьер при setup/rollback и повторном SIGKILL. Baseline реального клиента пропускал 14 IPv4 + 13 IPv6 UDP-проб; fixed — 0. 2057 Linux + 39 privileged + 8 lifecycle; 14 runtime checks; 17/17 cases, 339 assertions PASS. D04 IN_PROGRESS: routes, legacy global DNS/persistent TUN и полная mixed firewall матрица открыты.

D04/D09: [Q25-F099 — атрибуты владения маршрутом](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-ATTRIBUTES.md): пригодность чужого маршрута отделена от delete/replace authority; неявные protocol/metric/source и дополнительные атрибуты проверяются. Baseline удалял 10 операторских замен на ядре и static bypass настоящего клиента. 2068 Linux + 40 privileged + 8 lifecycle; 17/17 cases, 384 assertions PASS. На этом этапе persistent client route journal ещё не был реализован; продолжение Q25-F100 ниже. D04 IN_PROGRESS.

D04/D09: [Q25-F100 — постоянный журнал физических маршрутов](../reports/audit-0.8.2/AUDIT-Q25-ROUTE-JOURNAL.md): durable intent/confirmed ownership, boot/cookie/TUN scope, общая блокировка и terminal roaming при I/O ошибке. Baseline оставлял bypass/blackhole после SIGKILL → reconnect → stop (3 FAIL). 2087 Linux + 43 privileged + 8 lifecycle; 17/17 cases, 489 assertions PASS. Client physical route recovery закрыт в описанных пределах; legacy global DNS, live persistent TUN и mixed firewall остаются D04 IN_PROGRESS.

D04/D05/D09: [Q25-F101 — legacy global DNS](../reports/audit-0.8.2/AUDIT-Q25-LEGACY-DNS.md): unsafe автоматический replay и PID refcount удалены; снимок/holders требуют ручного восстановления без чтения содержимого и ожидания lock. Baseline изменял resolver в 4 сценариях; новый контракт 47/47 PASS. 2078 Linux + 43 privileged + 8 lifecycle; 17/17 cases, 489 assertions PASS. Старое глобальное восстановление закрыто безопасным отказом; D04 IN_PROGRESS — live persistent TUN и mixed firewall остаются.

D04/D09: [persistent TUN/TAP после SIGKILL](../reports/audit-0.8.2/AUDIT-Q25-PERSISTENT-TUN.md): подтверждён безопасный отказ без изменения интерфейса/routes/DNS/firewall и восстановление после ручного удаления проверенного остатка. 17/17 строк, 506 основных утверждений; 17 persistent-сценариев с 199 подробными проверками PASS. Новый дефект не обнаружен, Rust не изменён. Эта часть D04 закрыта в описанных пределах; D04 IN_PROGRESS — полная mixed firewall матрица остаётся.

D04/D09/D10: [серверный mixed nft/legacy/firewalld recovery](../reports/audit-0.8.2/AUDIT-Q14-MIXED-FIREWALL.md): 16/16 сценариев, 476 проверок PASS. Реальная смена backend каждого семейства, native nft parse errors, firewalld reload, partial cleanup и ручное восстановление проверены. Неопределённое отсутствие сохраняет журнал; потерянный WAN sysctl witness остаётся ручной границей D02. Rust не изменён. D04 IN_PROGRESS: mixed firewall packet/recovery для клиентского kill-switch/DNS/routes ещё требуется.

D04 закрыт: [Q25-F102 и клиентская mixed firewall матрица](../reports/audit-0.8.2/AUDIT-Q25-CLIENT-MIXED-FIREWALL.md): 152/152 сетевые ячейки, 136 SIGKILL/recovery, 4880 основных утверждений и 3224 вложенных проверок PASS. Все 4352 прямых UDP-попыток при защите заблокированы; 2624 разрешённых проб получили ответ. Общий распознаватель исправлен для точного legacy advisory; серверные 16/16, 476 checks повторно PASS. Ручные границы persistent TUN/sysctl/legacy DNS сохранены. **Итого техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.** Это не завершение разделов полного аудита; D05/D06 и D09/D10/D13 остаются открытыми.

D05/D09: [Q25-F103 — общий DNS/NSS и остановка](../reports/audit-0.8.2/AUDIT-Q25-SYSTEM-RESOLVER.md): четыре незавершённых вызова, deadline с очередью, сохранение слота после отмены и отсутствие ожидания blocking pool при shutdown. 4 baseline отказа и 4 fixed PASS; 38/38 hostname cells, 34 crash/recovery, 1220 основных и 806 вложенных checks PASS. 1537 host + 71 config; 2089 Linux + 44 privileged + 8 lifecycle PASS. D05 остаётся IN_PROGRESS: scheduler isolation сетевых мутаций, внутренние locks/I/O и цельный NetworkPlan/shutdown. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F104 — resolver-файлы до firewall](../reports/audit-0.8.2/AUDIT-Q25-RESOLVER-FILES.md): один ограниченный снимок, общий reader/parser со stub, точный keyword, комментарии и сохранение scope. 7 baseline/fixed пар; 2 старых зависания, все 7 fixed очищены. 38/38 cells, 34 crash/recovery, 1220 основных и 806 вложенных checks PASS. 1544 host + 71 config; 2098 Linux + 44 privileged + 8 lifecycle PASS. D05 остаётся IN_PROGRESS: сетевые мутации, внутренние locks/I/O и общий NetworkPlan/shutdown. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F105 — применение NetworkPlan вне async-потока](../reports/audit-0.8.2/AUDIT-Q25-NETWORK-TASK.md): отдельный поток сохраняет ownership и исходный NET/mount-контекст до принятия результата или завершения отката; native ACK использует async sleep. 7 новых переносимых + 1 Linux + 1 privileged регрессия; контрольный синхронный helper FAIL, исправленный PASS. Реальные TCP/UDP × TUN-create/ip-up: 4/4 PASS с отзывчивым однопоточным runtime, ожиданием отката и точным восстановлением сети. 38/38 cells, 34 crash/recovery, 1220 основных и 806 вложенных checks; 1551 host + 71 config; 2106 Linux + 45 privileged + 8 lifecycle PASS. D05 остаётся IN_PROGRESS: штатная очистка активного туннеля, kill-switch mutations, locks/I/O/диагностика и общий NetworkPlan/shutdown deadline. Принудительный Drop может блокировать поток до join. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F106 — штатная очистка установленного туннеля](../reports/audit-0.8.2/AUDIT-Q25-TUN-TEARDOWN.md): общий TCP/UDP TunGuard shutdown сохраняет DNS → pump join → routes/forwarding и выполняет сетевую очистку в одном присоединяемом потоке. Worker failures входят в sticky Failures. 5 новых переносимых + 1 privileged тест; baseline TCP/UDP дали 0 heartbeat тиков при задержке cleanup, fixed — 7–8. 4/4 fixed сценария и 2/2 повторных явных запуска после отказа PASS; kill-switch при ошибке сохранён. 38/38 cells, 34 crash/recovery, 1220 основных и 806 вложенных checks; 1556 host + 71 config; 2111 Linux + 46 privileged + 8 lifecycle PASS. D05 остаётся IN_PROGRESS: ранние error/Drop-пути, kill-switch mutations, locks/I/O/диагностика и общий NetworkPlan/shutdown deadline. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F107/F108 — firewall workers и сохранение DROP](../reports/audit-0.8.2/AUDIT-Q25-FIREWALL-TASK.md): setup/refresh и все шесть терминальных cleanup-путей ждут владеющий worker; неподтверждённый unhook запрещает очистку цепочки. 8 новых регрессий, 8 baseline + 12 fixed runtime-сценариев; baseline пропустил 6 UDP-проб после отказа cleanup, fixed — 0. 38/38 cells, 34 crash/recovery, 1220 основных + 806 вложенных checks; 1564 host + 71 config; 2119 Linux + 46 privileged + 8 lifecycle PASS. Исходный wildcard UDP recovery FAIL сохранён: повтор с явным bind прошёл, multi-IP wildcard остаётся D06/D10. D05 открыт: startup recovery, ранний Drop, locks/I/O/диагностика, общий срок. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D06/D09/D10: [Q15-F002 — адрес ответа UDP wildcard](../reports/audit-0.8.2/AUDIT-Q15-UDP-LOCAL-ADDRESS.md): pktinfo сохраняется от receive до immutable reply/roaming/PMTU path. Baseline — второй IPv4 адрес не подключается, 96 wrong-source replies; fixed — 8/8 подключений IPv4/IPv6 × plain/obfs, 256/256 inner UDP echoes и исходный refresh-fault recovery PASS. 6 новых Linux + 1 privileged регрессия; 1564 host + 71 config; 2125 Linux + 47 privileged + 8 lifecycle; 38/38 cells, 34 crash/recovery, 1220 + 806 checks PASS. Wildcard defect закрыт в границах отчёта, полные D06/D10 и D05 открыты. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F111 — последовательный writer диагностики](../reports/audit-0.8.2/AUDIT-Q25-STATUS-WRITER.md): один поток, один ожидающий снимок, join итоговой записи; файловый I/O вне async-потока. 5 новых portable + 1 privileged тест; 2 baseline + 4 fixed fsync-сценария, 2 baseline + 4 fixed TCP/UDP teardown и 2 recovery PASS. 1569 host + 71 config; 2133 Linux + 48 privileged + 8 lifecycle PASS. D05 открыт: остальные locks/I/O, ранний Drop и общий deadline. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F112/F113 — файлы идентичности](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-FILES.md): ID загружается один раз в joined worker, временный ID стабилен при reconnect; TOFU ограничен 1 MiB, повреждение/конфликт пинов запрещает новое доверие, запись атомарна. 15 новых тестов; 8 baseline + 8 fixed identity cases, 6 teardown cases и 2 recovery PASS. 1575 host + 71 config; 2148 Linux + 48 privileged + 8 lifecycle PASS. D05 открыт: синхронный TOFU, другие startup I/O/Drop и общий deadline. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

D05/D09: [Q25-F114 — TOFU worker](../reports/audit-0.8.2/AUDIT-Q25-IDENTITY-WORKER.md): файлы доверия обрабатываются в одном присоединяемом потоке; отмена и timeout не оставляют запись без владельца, поздний отказ сохраняется до terminal result. 9 portable regressions; 16 worker cases + 16 файловых + 6 teardown и 2 recovery PASS. 1584 host + 71 config; 2157 Linux + 48 privileged + 8 lifecycle PASS. Общий deadline и другие startup I/O/Drop остаются D05. **Техдолг: 4/15 DONE (26,7%), 9 IN_PROGRESS, 2 TODO.**

### Q25-F205 — остановка клиентов панели, 1 октября 2026

Закрыт конкретный остаток D05: остановка outbound-клиентов больше не суммирует
по пять секунд на профиль. Все принадлежащие менеджеру процессы получают SIGTERM
параллельно и делят исходный пятисекундный grace, включая ожидание реестра.
С первого запроса shutdown закрывается Connect/autostart; повторный или отменённый
waiter не обновляет deadline. Принудительный kill, ошибочный exit и отказ signal/wait
сохраняются в terminal result supervisor вместе с ошибкой основного worker.

Disconnect сохраняет исходный Child до reaping даже при отмене HTTP-ожидания.
Профильный lock запрещает замену ещё очищающегося процесса; проверки статуса других
профилей не ждут его завершения. Shutdown не оставляет detached task-владельцев,
наблюдённые ошибки переживают отмену waiter. Пять новых процессных регрессий и
существующий autostart: **6/6**; связанные supervisor **19/19**, shutdown **10/10**,
profile tasks **19/19**, всего **54 PASS**. Rustfmt PASS. Clippy Rust 1.97 прошёл
с `-D warnings -A clippy::useless_conversion`; без исключения он отказал на двух
неизменённых переносимых UDP-конверсиях. Логи обоих исходов сохранены.

[Машинное evidence](../../../release/certification/evidence/client-shutdown-20261001.json)
содержит 287 SHA проверенных Rust-файлов, SHA test-бинарника, выводы и хеши raw.
Рабочий PID 845, listener 443 и release SHA `a526c03b` лабы сохранились.
Проверка использует настоящие дочерние процессы без сетевых мутаций; новый release
VPN/E2E и benchmark не запускались. Исходная последовательность подтверждена
сверкой production-кода; старый release-бинарник для этой находки не запускался.

D05 остаётся IN_PROGRESS: async join перед освобождением ресурсов при forced Drop
и общий wall-clock срок всего worker/supervisor shutdown. Пять секунд относятся
только к grace outbound-клиентов; kernel reaping/fs I/O не обещают прерываемость.
D11/D14 evidence и **9/15** выше относятся к проверенному кандидату `62c84fc4`.
После этой серверной правки native source digest и release tree изменились;
старый provenance/certificate не сертифицирует новый HEAD. Обновление сборочных
свидетельств и certification входит в финальную сборку пакета D15, а не в
повторный прогон неизменённых transport/firewall матриц после каждой правки.

### Q25-F206 — ресурсы профиля при принудительной отмене, 2 октября 2026

Закрыт остаток D05 по порядку async join/host cleanup. Прежний Drop запрашивал
отмену задач и сразу освобождал TUN/DNS/NAT, хотя дочерняя задача ещё могла
выполнять свой деструктор. Теперь ProfileScope передаёт worker одновременно
ресурсы поколения и присоединяемые наборы задач. Worker дожидается их завершения
до удаления ресурсов, общей NAT-очистки и итоговых hooks. Отменённое ожидание
возвращает всё поколение в ту же очередь; фоновой задачи без владельца нет.
Принудительная отмена сохраняется как ошибка terminal result даже после успешной
очистки. Если уничтожена сама future worker, незавершённые ресурсы и network lease
удерживаются до выхода процесса; новый in-process worker не допускается.

Регрессия с настоящими TUN и DNS INPUT правилами задерживает дочерний Drop.
Контроль вызывает неизменённый production-деструктор ProfileTeardown напрямую:
**ожидаемый FAIL**, ресурсы удаляются преждевременно. Это контроль прежнего порядка
на том же test-бинарнике, не запуск старого release. Исправленный guard:
**1/1 PASS**, включая отмену первого drain, удержание ресурсов и повторный join.
Обычные teardown **13/13**, profile tasks **19/19**, shutdown **10/10**,
supervisor **19/19**, panel clients **6/6**, всего **67 unit PASS**.
Текущий debug-бинарник проходит **8/8** live worker TCP/UDP × off/manual/route/nat66
с reload, отказом второго worker, SIGTERM и восстановлением сетевого состояния.
Полные снимки внешнего хоста совпадают; рабочий listener 443/PID 845 сохранён.

[Машинное evidence](../../../release/certification/evidence/deferred-profile-20261001.json):
287 сверенных SHA Rust-файлов, SHA test/debug-бинарников, команды, результаты,
raw-хеши и снимки хоста. Rustfmt PASS; Clippy Rust 1.97 PASS с прежним исключением
двух переносимых UDP-конверсий: `-D warnings -A clippy::useless_conversion`.
Первый compile отказал из-за mutability, первая команда build — из-за пути драйвера;
исправленные прогоны успешны, исходные логи сохранены.

**D05 остаётся IN_PROGRESS только по общему бюджету остановки в заявленных границах**:
этот fix не вводит единый wall-clock deadline и не прерывает kernel/fs I/O.
Исторические **9/15 DONE (60%)** и D11/D14 относятся к кандидату `62c84fc4`;
новый HEAD требует финального обновления native/provenance/certification в D15.

### Q25-F207 — совместная остановка worker и клиентов панели, 2 октября 2026

Устранена последовательная композиция supervisor: раньше остановка outbound-клиентов
начиналась только после возврата supervise, потенциально через 60 секунд после сигнала.
До этого Connect/autostart оставались разрешены; клиентский grace затем добавлялся
к ожиданию worker. Теперь обработка SIGTERM/SIGINT синхронно закрывает допуск клиентов
до SIGTERM worker. Один координатор опрашивает оба принадлежащих supervisor ожидания
параллельно и возвращает оба результата; новых detached задач нет. Завершение supervise
без отдельного stop-сигнала также запускает очистку клиентов. Отмена coordinator
сохраняет прежние guards и исходный deadline менеджера; ошибки обоих путей не теряются.

Целевые shutdown **13/13**, panel clients **7/7**, supervisor **19/19**,
notifications **8/8**: всего **47 PASS**, включая четыре новые регрессии.
В live-проверке настоящие supervisor/worker/client запускаются в отдельных
NET/mount/PID namespaces. Сохранённый debug-бинарник Q25-F206 воспроизводит
последовательное ожидание: при восьмисекундном post_down клиент ещё жив через
6,20 секунды, общий stop занимает 13,24 секунды. Новый debug-бинарник собирает
клиента через 5,02 секунды, пока worker ещё выполняет hook; весь stop — 8,25 секунды.
Оба supervisor возвращают ожидаемый exit 1: TCP-peer намеренно не отвечает на
handshake, клиент получает принудительный kill, очистка его VPN этим не подтверждена.
Это контроль задержки/reaping и ошибочного результата, не успешный VPN handshake.

В обоих случаях worker TUN/tagged NAT удалены, forwarding возвращён к исходному
значению; все дочерние процессы собраны. Полные снимки внешнего хоста совпадают,
listener 443/PID 845 и рабочий release SHA сохранены. Rustfmt PASS; Clippy Rust 1.97
PASS с прежним `-D warnings -A clippy::useless_conversion`. В evidence сохранены
SHA 287 исходников, обоих debug-бинарников и test-бинарника, исходные compile/fixture
отказы и исправленные прогоны. Полные transport/benchmark матрицы не повторялись.

Проверки и точные SHA приведены в
[машинном evidence](../../../release/certification/evidence/stop-composition-20261002.json).
Это исправление композиции существующих grace, а не новый общий deadline worker.
Ожидание уведомлений, async joins, blocking host cleanup и kernel reaping сохраняют
описанные ограничения. **D05 остаётся IN_PROGRESS**; итоговое обновление native сборок
и release certification после серверных изменений остаётся D15. Исторические
**9/15 DONE (60%)** относятся к проверенному кандидату `62c84fc4`.

### Q25-F208 — общий CLI shutdown и уведомления, 2 октября 2026

Закрыт последний критерий D05 в заявленных границах. CLI worker включает независимый
от Tokio системный таймер **45 секунд** при первом наблюдаемом stop/fatal-событии,
до stop-диагностики. Он остаётся активным через control handlers, services, profile/
deferred joins, NAT/sysctl, hooks, запись counters, control socket и итоговый журнал.
Повторный arm не продлевает срок; отмена владеющей future не отменяет активный таймер.
Штатная очистка снимает таймер и присоединяет его поток. Позднее завершение не может
выиграть гонку у уже истёкшего срока.

По истечении worker закрывает запуск новых команд, останавливает группы принадлежащих
ему ещё не собранных команд и выполняет `_exit(124)` без Rust Drop, логгера и C atexit.
Spawn/reap/групповой kill используют один реестр, чтобы не сигналить повторно
использованному PGID. Supervisor классифицирует 124 как ошибку срока с неподтверждённой
очисткой. Нормально отделённые фоновые службы с закрытыми pipe сохраняют старый контракт.
Уведомления worker и supervisor закрывают приём и делят свой исходный 10-секундный grace
с момента stop; drain идёт параллельно остальной очистке. Supervisor сохраняет 60 секунд
для worker и пять для клиентов, одновременно опрашивая все принадлежащие ему ожидания.

**136 адресных unit PASS**: process budget 6, notifications 9, supervisor 20,
shutdown 13, teardown 13, profile tasks 19, hook process 15, credential supplier 13,
system commands 21, panel clients 7. Восемь новых регрессий включают реальные дочерние
процессы с остановленным Tokio executor, отменой владельца таймера и выходом 124.
Это адресный набор, не новый прогон всех 2317 unit.

В изолированных NET/mount/PID namespaces сохранённый Q25-F207 debug-бинарник
остаётся жив через 48 секунд stop при задержке metadata одного post_down на 60 секунд.
Его завершает только тестовый контроллер. Новый worker выходит сам через 45 секунд
с кодом 124; другой post_down начинает shell+sleep после 35-секундной подготовки.
Контроллер собирает владельца группы и sleep с SIGKILL и проверяет отсутствие всех
наблюдавшихся участников в `/proc`. TUN/tagged NAT удалены, незавершённый sysctl-журнал
остаётся; следующий обычный worker восстанавливает forwarding и штатно выходит 0.
Чужое INPUT-правило, маршруты и остальные настройки сохранены. **8/8** обычных
TCP/UDP × off/manual/route/nat66 lifecycle с reload/отказом второго worker/stop PASS.
Полные снимки внешнего хоста совпадают; рабочие listener/PID/release SHA сохранены.

[Evidence](../../../release/certification/evidence/worker-budget-20261002.json) содержит
288 SHA сверенных Rust-файлов, test/debug SHA, команды, исходный Clippy-отказ и исправление,
первый fixture-отказ и исправление проверки сбора дочернего shell. Внешний shell мог
сам собрать script-shell до собственной смерти; ожидать его повторный wait-status было
ошибкой теста. Исправленная проверка требует SIGKILL для владельца группы и sleep,
а также исчезновения каждого наблюдавшегося PID. Rustfmt, docs 9/9 и diff PASS;
Clippy 1.97 PASS с прежним `-D warnings -A clippy::useless_conversion`.

Ограничение обосновано: это граница CLI-процесса после наблюдаемого stop, не абсолютная
гарантия от доставки сигнала ОС. Подготовка до shutdown, библиотечный `run_worker`,
произвольные kernel exit/reaping и зависший spawn под реестром не получают безопасного
прерывания; библиотечная отмена сохраняет ресурсы/namespace quarantine. При отказе ядра
таймер не обещает точного wall-clock. Прикладной блокирующий fs-worker и работающая
группа hook проверены настоящим process exit и recovery. Эти ограничения не выдаются
за PASS произвольных kernel failures. **D05 DONE; реестр: 10/15 DONE (66,7%),
5 IN_PROGRESS**. Финальное обновление native/provenance/certification остаётся D15;
исторический certificate кандидата `62c84fc4` не сертифицирует текущий HEAD.

### Q25-F209 — смешанный жизненный цикл конфигурации, 2 октября 2026

Закрыт остаток D07 после глобальной и профильных матриц. Новый воспроизводимый
[стенд](../../../scripts/audit_panel_config_lifecycle.py) проверяет настоящую HTTP-панель,
supervisor и TCP/UDP worker в частных NET/mount/PID namespaces. Rust-код не менялся:
нового дефекта в этих сценариях не обнаружено. Генератор повторно подтвердил
163 имени парсера, три динамических семейства и актуальность fixture из 165 записей;
это покрытие парсера, а не 165 отдельных сетевых E2E.

**201 адресный unit-тест PASS**: server 78, INI 22, config_source 16, panel config 38,
control 7, backup 32, status 4, preflight 4. Все три привилегированных backup-теста
из обычного ignored-набора отдельно выполнены в изоляции: exact/overlay roundtrip,
отказ rollback при нечитаемом файле, ownership при медленном backup I/O; последний
проверен также с отменой — **4 исполнения PASS**. Первые ошибочные фильтры
`server::web::api::*` дали пустые выборки и не засчитаны: исправленный запуск
`web::api::*` требует ненулевой выборки у каждой группы.

**44/44 HTTP/runtime проверки PASS**: отказ неверного INI/формы/privileged hook;
обязательные ревизии, устаревшая вкладка и ровно один победитель одновременной записи;
ожидание внешнего процесса с общим lock и сохранение его байтов при конфликте;
разделение live web, сохранённого профиля и startup-only web; отказ restart без
остановки здорового worker; явный restart с новым TCP bind; Quick Start/check-config/
history rollback; неверный архив и exact restore с сохранением lock inode и identity;
смена пароля и отзыв старой cookie без restart; нормальный stop с восстановлением
forwarding, TUN и чужих firewall-правил. Identity сохранилась после всех операций.
Первый промежуточный прогон имел 43 проверки; итоговый добавляет сквозную сверку
identity и выдаёт PASS только после завершения всего сценария.

[Мануал панели](../manuals/PANEL.md#server-config-writers-v1) фиксирует границу:
каждый совместный внешний writer должен брать canonical `<config>.lock` через flock
от чтения до публикации. Ревизия и повторная проверка ловят завершённую ручную правку
и изменение во время подготовки, но произвольную root-запись без lock между последней
проверкой и rename невозможно сделать атомарно согласованной. Этот сценарий исключён
из поддерживаемого протокола с объяснением; ему не присвоен PASS. Для такого редактора
нужно остановить Qeli, завершить конкурирующие panel/CLI записи, проверить INI и запустить.

Все 288 Rust-входов и SHA debug/test сопоставлены с предыдущим точным build evidence;
новая сборка, Clippy и полная benchmark-матрица здесь не запускались. Внешние снимки
лабы `.11` до/после обоих наборов совпали, работающий release и listener 443/PID 845
сохранены, `.10` не затронут. Точные команды, SHA, результаты и raw manifest:
[машинное evidence](../../../release/certification/evidence/config-mixed-20261002.json).
Сетевые сочетания остаются D10, окончательная native/certificate сверка — D15;
это не новая сертификация HEAD и не завершение всего 37-шагового аудита.
**D07 DONE; реестр: 11/15 DONE (73,3%), 4 IN_PROGRESS — D06/D08/D10/D15.**

### Q25-F210 — владельцы клиентского store и итог D08, 2 октября 2026

Закрыт D08 в доступном объёме с сохранением согласованного исключения D12.
Матрица Q25-F197 покрывает 84 поля общего INI-редактора и 1000 детерминированных
мутаций. Её Rust-код не менялся; новый coverage-guided fuzzing не заявляется.
Остаток внешней записи обоснован протоколом ниже; автоматический reconnect и
смена Wi-Fi подтверждены прежним Android VPN E2E Q25-F203, а не новым прогоном.
Недоступные Mac/iOS/Windows VM/router проверки остаются **SKIPPED по решению
пользователя**, не PASS; полный мобильный lifecycle/выпуск остаются полным аудитом.

Найден и устранён второй writer iOS: `ProfileStore.load()` при отсутствии архива
сохранял шаблон из PacketTunnel так же, как из приложения. При первой записи
расширение могло опубликовать шаблон поверх профилей приложения. Теперь создание
отсутствующего store разрешает явно только начальный AppModel; PacketTunnel и
обычный load — read-only и дают ошибку при отсутствии архива. Чтение существующего
ciphertext больше не создаёт отсутствующий master key: ключ и зашифрованный оригинал
сохраняются, приложение предлагает восстановить backup. Добавлены две XCTest-регрессии
и EN/RU сообщения. XCTest и iOS-сборка **не запускались**: Apple-стенд исключён;
проверены call sites, порядок guards и отсутствие write/key-create в ветке reader.
Один `@StateObject AppModel` обслуживает WindowGroup, мутации идут через MainActor;
PacketTunnel читает, виджеты не получают профили или ключи. Второй app-owned writer
профилей среди этих процессов отсутствует; атомарность UserDefaults между любыми
произвольными внешними процессами этим не обещается.

Новая desktop conformance-регрессия запускает **два отдельных OS-процесса**:
оба читают исходную версию, один выигрывает публикацию, второй отказывается;
байты победителя и `.bak` сохранены, новый reader может писать после выхода обоих.
Весь .NET selftest: **511 PASS, 0 FAIL** на точной Windows DLL SHA `653522e6`.
Начальный запуск с build artifacts вне дерева не нашёл boundary corpus и дал
один FAIL; исправленный запуск из обычного project output исполнил corpus,
включая 19 дополнительных проверок. Исходный отказ сохранён, не засчитан PASS.

Android: **167 JVM, 0 failures/errors/skipped**, debug и androidTest APK собраны.
**12/12 instrumentation PASS** на Android 14/API 34 x86_64 AVD, включая новую
связку настоящий INI → упакованный JNI → AES-GCM/Keystore → повторное чтение после
правки порта → отказ устаревшей записи. Это хранение/адаптер, не новый VPN handshake
и не тест UI-редактора во время активного VPN. Обе `.so` внутри APK совпадают с
committed A/B библиотеками; native не пересобирался, окончательное обновление — D15.
Read-only AVD завершён без сохранения; хеши userdata и полный внешний host snapshot
совпали, working release/listener 443/PID 845 сохранены; `.10` не затронут.

Поддерживаемая запись: desktop экземпляры используют общий ProfileStoreFile,
sidecar и наблюдённую ревизию; Android Activities — общий процесс/SharedPreferences
и encrypted version; iOS — единственный writer приложения. Редактировать INI следует
через приложение/import, не вручную менять зашифрованный store. Произвольный внешний
writer, обходящий эту координацию, не поддерживается: hash/revision не закрывает
промежуток последней проверки и rename. При обслуживании store нужно завершить всех
писателей и пользоваться штатным восстановлением. Изменение сохранённого активного
INI не переписывает уже работающую сессию; после сообщения приложения требуется
явное переподключение. Прежний E2E reconnect не засчитан новым выполнением этого пакета.

[Проверки и SHA](../../../release/certification/evidence/client-store-20261002.json).
**D08 DONE; реестр: 12/15 DONE (80%), 3 IN_PROGRESS — D06/D10/D15.** Это не завершение
всего аудита, не iOS runtime PASS и не сертификат текущего HEAD.

### Q25-F211 — совместная IPv6/DNS/NDP матрица, 2 октября 2026

Добавлен воспроизводимый [изолированный runtime-сценарий](../../../scripts/audit_worker_ipv6_multiprofile.py):
четыре настоящих dual-stack профиля `off/manual/route/nat66`, два TCP и два UDP,
общий WAN, отдельные DNS listeners и обязательные NDP responders у `manual`/`route`.
На настоящих **iptables-nft и iptables-legacy — по 59 проверок, всего 118 PASS**.
Проверены DROP режима off, отсутствие IPv6-правил manual, source-preserving route,
MASQUERADE и off-WAN guard nat66, приоритет защитных DROP, общие forwarding/RA leases,
отказ неверного SIGHUP и сохранение сетевого поколения при правильном reload.

На каждом backend выполнено **32 DNS-запроса** четырёх профилей: IPv4/IPv6 × UDP/TCP ×
A/AAAA. Upstream получил только восемь запросов: кеш общий между frontend-транспортами
одного профиля и независим между профилями. Отдельный `manual` дал ещё два IPv6 DNS
ответа при исходном `forwarding=0` и неизменном RA/IPv6 firewall. DNS проверялся с
самого сервера: это настоящий proxy/listener, но не трафик через VPN и не packet-proof
INPUT/перенаправления порта 53 с TUN. Два NDP responder действительно привязались;
ответы upstream NS/NA для адресов активных сессий этим пакетом не подтверждены.

Для отсутствующего `ndp_proxy_interface` в режиме required профиль не допускает
клиентов и не выполняет post_up. Worker остаётся живым и повторяет запуск профиля:
обязательный NDP не означает остановку других профилей. После SIGTERM сравниваются
точные чужие правила и политики, маршруты, link flags (включая ALLMULTI), sysctl,
удаление control socket и sysctl journal. Четырёхпрофильный stop, manual-only stop и
stop после NDP-отказа восстановили исходное состояние на обоих backend.

Три промежуточных отказа теста сохранены и не засчитаны PASS: первые два сравнивали
с baseline без ещё не созданных пустых nat/mangle таблиц; чтение nft через `-S` их
не создаёт. Теперь перед снимком создаётся/удаляется пустая тестовая цепочка.
Третий ошибочно ожидал завершения worker вместо штатного retry отклонённого профиля.
Изменений production Rust не потребовалось. 288 local/remote SHA и debug SHA совпали
с точным предыдущим build evidence; повторных build/Clippy/benchmark здесь нет.
Внешние host snapshots всех четырёх прогонов совпали, работающий release/listener
сохранён, `.10` не затронут. [Команды, SHA и raw manifest](../../../release/certification/evidence/ipv6-multiprofile-20261002.json).

**D10 остаётся IN_PROGRESS:** нужны upstream NDP packet tests для активных/неактивных
leases, оставшиеся mixed firewall/firewalld и lifecycle сочетания. Смена/идентичность
WAN остаётся D06, окончательная native/certificate сверка — D15.
**Реестр: 12/15 DONE (80%), 3 IN_PROGRESS — D06/D10/D15.** Это доля групп техдолга,
а не готовность всего 37-шагового аудита.

### Q25-F212 — NDP за активные сессии и подсети, 2 октября 2026

Закрыта пакетная NDP-часть D10 для `required` в режимах `route` и `manual`:
**8/8 ячеек `route/manual × TCP/UDP × nft/legacy`, по 31 проверке, всего 248 PASS**.
Новый [сценарий](../../../scripts/audit_ndp_session_packet.py) запускает настоящий worker
и CLI-клиент с аутентификацией в отдельных client/router/server namespaces. Upstream
считает pool и delegated prefix on-link, поэтому доставляет запросы NS на WAN сервера;
подмена SessionMap или симуляция ответов firewall не используется.

Выполнено **128 packet probes, 384 Ethernet NS**. Для каждой ячейки kernel NDP на
WAN служит положительным контролем. До подключения нет NA за зарезервированный
`/128` и `client_subnet`; после handshake есть правильные proxy NA за оба адреса,
нет ответа за свободный pool-адрес и чужой префикс. Проверяются Ethernet MAC,
IPv6 source/destination, hop limit, ICMPv6 checksum, target и TLLA, Solicited/Override
flags. DAD получает all-nodes NA без этих двух flags; неправильные hop limit,
checksum и DAD с SLLA отвергаются. Сохранены hex всех отправленных NS и полученных NA.

Внешний router реально достигает ping-ом назначенного адреса и адреса за клиентом
из `client_subnet` через зашифрованный VPN; NAT66 отсутствует. При нормальной
остановке клиента тест дожидается удаления сессии из control registry (для UDP
учитывает idle expiry/maintenance), затем новые NS больше не получают NA за lease
или delegated prefix. Kernel route подсети удалён. Повторный handshake возвращает
ownership и ответы обоих адресов. После stop worker перестаёт отвечать; точные чужие
firewall rules/policies, маршруты, link flags и IPv6 sysctl восстановлены, control
socket/sysctl journal удалены. В `manual` forwarding и разрешающие правила заранее
заданы администратором и сохранены; Qeli не получает их ownership.

Исправлена неточность [IPv6-мануала](../manuals/IPV6.md): остановка клиентского
процесса не всегда означает немедленное исчезновение серверной сессии. Пока UDP
сессия живёт до idle/liveness timeout/cleanup или действует roaming grace, NDP может
отвечать за её адрес. Проверять прекращение ответов следует после удаления/revoke
сессии; старый upstream neighbor cache отдельно не доказывает новый ответ responder.

Два промежуточных fixture-отказа не засчитаны PASS: check-config правильно отклонил
тестовые interval=1000ms с default jitter=5000ms; затем исходный snapshot был взят
до завершения WAN link-local DAD. Подготовка задаёт jitter=0 и ждёт готовности
исходного link-local адреса, строгое сравнение состояния сохранено. Production Rust
не менялся. 288 local/remote SHA и debug SHA совпали с точным прежним build evidence;
повторных build/Clippy/benchmark нет. Внешние host snapshots всех трёх прогонов совпали,
работающий release/listener сохранён; `.10` не затронут.
[Результаты, команды, SHA и raw manifest](../../../release/certification/evidence/ndp-packets-20261002.json).

Это не новый пакетный тест `/0`, rate saturation, VLAN, admin revoke/смены активного
владельца или SIGKILL NDP. Сочетания нескольких профилей с mixed firewall/firewalld
reload/политиками остаются D10; WAN identity — D06, окончательная certification — D15.
**Реестр: 12/15 DONE (80%), D06/D10/D15 IN_PROGRESS.** NDP packet lifecycle проверен,
но весь D10 и полный 37-шаговый аудит этим не закрыты.

### Q25-F213 — multiprofile, mixed backend и политики firewalld, 2 октября 2026

Закрыт оставшийся интеграционный компонент D10: **4/4 сочетания IPv4/IPv6
nft/nft, nft/legacy, legacy/nft, legacy/legacy, по 104 проверки — 416 PASS**.
[Четырёхпрофильный сценарий](../../../scripts/audit_worker_ipv6_multiprofile.py)
расширен [изолированным firewalld fixture](../../../scripts/audit_firewalld_profiles.py).
Запускаются настоящие `off/manual/route/nat66` TCP/UDP профили, NDP required для
manual/route, firewalld 2.3.1 с public zone и политикой public → HOST priority -500.
Используются настоящие xtables multicall binaries, отдельно выбранные для IPv4/IPv6;
ответы команд и правила не подменяются. Сверены SHA 17 исходных Debian packages.

Внешний veth-peer проверяет разрешённый UDP 49000 и запрещённый политикой 49001:
**96 packet probes, 288 datagrams, 168 подтверждённых echo replies**; 120 запрещённых
посылок не получили ответа в окне 250ms каждая. При удалении rich DROP порт 49001
действительно открывается, после возврата закрывается для IPv4 и IPv6. Проверены
firewalld reload при активных профилях, после их stop и после restart; сохраняются
точные собственные и чужие правила. У нового поколения допускается перестановка
независимых профилей при сохранении порядка внутри каждого profile/table/chain и
обязательного DROP перед ACCEPT. Reload того же поколения сравнивает полный снимок.

По 42 DNS-ответа в ячейке: исходные 32 IPv4/IPv6 × UDP/TCP × A/AAAA, четыре после
смены политики, четыре после restart и два manual-only; всего **168**. Кеш профилей
независим, смена политики сохраняет кеш. Неверный SIGHUP сохраняет действующее
состояние, правильный не меняет сетевое поколение. Manual-only сохраняет исходные
администраторские forwarding/RA и IPv6 firewall; отсутствующий обязательный NDP
interface запрещает admission/post_up, worker retry остаётся штатным. Все четыре
stop возвращают правила обоих backend, native nft, маршруты, sysctl/link flags,
control socket и journal к baseline.

Адресный набор: **18 portable PASS и один отдельно выполненный privileged PASS**
на точном test-binary SHA. Проверены разрешённые IPv6/NDP сочетания, INI round-trip,
выбор interface, ownership leases/подсетей/session state, malformed NS/DAD/NA,
rate bound и namespace bind; фильтр `ndp` также выбрал несколько endpoint-тестов.
Первый неверный путь native-теста обнаружен при listing до исполнения и не засчитан.
Два ранних runtime-отказа были ошибками fixture: INPUT DROP мешал IPv6 ND;
затем baseline содержал синтетические iptables-save headers без шести пустых native
nft hooks. Подготовка разрешает ICMPv6 только на контрольном veth и создаёт/удаляет
временное правило до снимка. Строгое сравнение сохранено, production Rust не менялся.
288 local/remote source SHA и debug/test artifacts сверены; прежнее build evidence
применимо. Повторных build/Clippy/benchmark нет. Внешние host snapshots финального и
ранних запусков совпали; работающие release/service сохранены, `.10` не затронут.
[Команды, SHA, результаты, исходные отказы и raw manifest](../../../release/certification/evidence/firewalld-profiles-20261002.json).

Закрытие D10 опирается на следующие независимые свидетельства:

| Критерий | Подтверждение |
|---|---|
| off/manual/route/nat66, DNS/NDP, rollback/stop | Q25-F211: 118 checks; этот пакет повторяет композицию на четырёх mixed backend |
| Активные/неактивные NDP leases и delegated prefix, реальный VPN | Q25-F212: 8 packet cells/248 checks; адресные NDP тесты этого пакета |
| Чужие ресурсы и mixed crash/recovery | D04: серверная 16-cell/476-check и клиентская 152-cell матрицы |
| Одновременные TCP/UDP, reload/stop/SIGKILL/recovery, churn | D13: 14 multiprofile lifecycle checks и прежний same-SHA churn |
| Несколько IPv6 профилей с firewalld reload/политикой | Этот пакет: 4 mixed cells/416 checks, реальные положительные и отрицательные policy probes |

Границы проверки сохранены: DNS здесь приходит с сервера на настоящий proxy port,
а контрольный firewall-трафик — на отдельный echo listener. Это не новый packet test
VPN forwarding через все public zones/policies или TUN INPUT/port-53. Произвольные
root rewrites, автоматическая миграция backend и все возможные firewall-политики не
поддерживаются этим доказательством; Qeli сохраняет чужие запреты, администратор
обеспечивает разрешения своей topology. `/0` и rate bounds покрыты unit, но новые
packet saturation/VLAN/admin-revoke/SIGKILL NDP не выполнялись. Физическая сеть
провайдера и исключённые пользователем платформы не объявлены PASS.

**D10 DONE в указанном Linux-объёме. Реестр: 13/15 DONE (86,7%), 2 IN_PROGRESS —
D06 и D15.** WAN identity/runtime route changes и финальная native/certificate
сверка остаются открытыми. Это доля групп техдолга, не готовность полного 37-шагового
аудита. Следующий пакет — оставшаяся таблица внешнего сетевого контекста D06.

### Q25-F214 — внешний сетевой контекст и поздние адреса, 2 октября 2026

Выполнен единый адресный пакет D06 на точном текущем test-binary:
**73 обычных + 23 привилегированных исполнения PASS**. Новый
[runner](../../../scripts/audit_external_context.py) использует существующие Rust
регрессии и реальную независимую установку xtables backend для IPv4/IPv6.
Production Rust не менялся; сборка, Clippy, полный benchmark и native refresh
не повторялись. Все 288 local/remote source SHA и test/release SHA сверены с
[точным build evidence](../../../release/certification/evidence/config-mixed-20261002.json).

На **4/4 парах nft/nft, nft/legacy, legacy/nft, legacy/legacy** выполнены три native
сценария: поздний IPv4 default route, поздний глобальный IPv6 вместе с default route,
refresh/cleanup/restart при переходе в чужой network namespace. Всего **12 native
исполнений**, из них восемь динамических адресных. В адресных тестах защита ставится
до появления маршрута/адреса; затем настоящий ICMP увеличивает счётчик DROP в уже
установленном kill-switch. Namespace-сценарий сохраняет чужой sentinel и не допускает
сетевую мутацию в другом контексте. Это packet counter proof, а не успешный/неуспешный
ответ внешнего приёмника: на dummy WAN такого приёмника нет.

Остальной набор выполнен один раз: 11 WAN-discovery, 23 exit-policy, 11 resolver
context, 18 attach policy, 3 terminal writer, 5 process admission и 2 interface
portable теста; восемь настоящих TUN ioctl и три native context-теста. Проверены
missing/borrowed/multiqueue TUN, fd cleanup после rename/replacement, чужой namespace
и same-name/different-index sysfs отказ; interface MAC/index и TAP/hooks используют
текущий namespace. Resolver отказывает в другой сети до мутации. Process admission
удерживается до terminal completion, запрещает overlap до чтения конфига и остаётся
закрытым после forced Drop. Обычные фильтры временно пропускают три native fixture:
два затем исполнены отдельно; child с настоящим resolved здесь не запускался и
не засчитан PASS. Его прежние packet/PID/bus проверки сохраняют отдельное evidence.

| Граница D06 | Результат сверки и действующий контракт |
|---|---|
| DNS / D-Bus / procfs | Context guards повторно PASS; настоящий resolved, AUTH GUID/unique owner, PID/network и marker recovery — прежние Q25-F094/F095/F096/F097. Нужны поддерживаемые общий network/PID контекст и доверенный resolver; текущий пакет не повторяет service fixture. |
| sysfs / сведения link | Native interface/TAP/hooks PASS без remount sysfs; sysctl namespace pins/cookie/witness закрыты D02. Наблюдение не является атомарной защитой от внешнего root. |
| TUN attach / имя / features | 18 policy + 8 native PASS. Внешний менеджер удерживает устройство/формат стабильным. `dev_attach` требует sysfs текущего namespace; одинаковый числовой ifindex разных namespace не доказывает identity. Эта неподдерживаемая комбинация не объявлена исправленной. |
| DNS/carrier globals | 3 writer + 5 admission PASS; один Linux run_client на процесс до cleanup, forced Drop требует restart процесса. Независимые клиенты — отдельные процессы. |
| Поздний IPv4/IPv6 | 8/8 native исполнений на четырёх mixed backend PASS; прежние отказы без firewall Q25-F121/F122 остаются применимыми. DHCP/RA daemon rollout и все динамические маршруты этим не сертифицированы. |
| Клиентский default WAN | 11 discovery + 23 exit-policy модели PASS; настоящий TCP/UDP monitor ранее проверен Q25-F127. Новый mixed packet monitor здесь не запускался. |
| Серверный WAN / identity / policy routes | Q25-F131–F136 сохраняют присутствие, ECMP/ошибки auto и NAT44/NAT66 off-WAN guards. Смена выбранного устройства с сохранением имени не защищена непрерывной identity; server runtime route/policy композиция остаётся остатком D06. |

Все изменения тестов происходят в частных NET/mount/PID namespaces; native Rust
тесты дополнительно создают одноразовые thread namespaces. Полный внешний snapshot
firewall обоих backend/nft, маршрутов, адресов, listener, resolver и именованных
namespace до/после совпал. Работающий release/service сохранён, `.10` не затронут.
[Команды, точные selectors/counts, SHA и raw manifest](../../../release/certification/evidence/external-context-20261002.json).

**D06 остаётся IN_PROGRESS**, но пробел mixed-backend поздних адресов/маршрутов закрыт,
а DNS/sysfs/attach/process-global пункты больше не требуют повторения общего набора.
Дальше — WAN identity, серверная runtime-смена маршрутов и уточнение policy/RFC1918
контракта с пакетными проверками. Неподдерживаемые привилегированные подмены не
переименованы в исправления. **Реестр: 13/15 DONE (86,7%), D06/D15 IN_PROGRESS**.

### Q25-F215 — серверные default/policy routes и LAN, 2 октября 2026

Закрыта документированная серверная часть D06 по runtime-маршрутам и адресным
планам: **4/4 пары nft/nft, nft/legacy, legacy/nft, legacy/legacy, по 51 проверке,
всего 204 PASS**. Новый [packet runner](../../../scripts/audit_server_route_policy.py)
запускает настоящий worker с одновременными dual-stack TCP NAT44/NAT66 и IPv6-only
UDP route профилями, двумя настоящими аутентифицированными клиентами, двумя WAN
и отдельной LAN. Правила ставит сам Qeli; SessionMap и сетевые ответы не подменяются.

В каждой ячейке получатели наблюдают IPv4/IPv6 source после дешифрования, пересылки
и NAT. Выполнено **116 packet probes, 348 UDP datagrams, 252 валидных echo replies**.
Из посылок 276 прошли путь через реальный VPN; 72 — прямые положительные контроли
приёмников. 96 посылок ожидаемо не получили ответа в окне 350ms каждая. Для 84 из
них отдельно подтверждён рост именно Qeli off-WAN DROP (28 проверок, delta=3 в
каждой); остальные 12 блокирует администраторский `FORWARD DROP`.

| Состояние | Наблюдаемое поведение |
|---|---|
| Выбран WAN A | NAT44/NAT66 имеют адрес WAN A; route сохраняет IPv6-адрес клиента |
| RFC1918 LAN вне WAN | 10/8, 172.16/12, 192.168/16 достигаются без NAT под администраторским ACCEPT |
| CGNAT/публичная LAN вне WAN | 100.64.0.1 и 192.0.2.1 блокируются NAT44 guard; прямые контроли подтверждают живых приёмников |
| IPv6 LAN вне WAN | NAT66 блокирует, route достигает с исходным адресом |
| Администратор FORWARD DROP | RFC1918 LAN закрывается; выбранный WAN остаётся доступен через собственное разрешение Qeli |
| Default A → B | NAT44/NAT66 не переносят поколение правил и блокируют off-WAN; route следует B без NAT |
| Source policy table100 → A при default B | NAT возвращается через A; отдельный route-клиент продолжает B |
| Default возвращён A | NAT и route работают через A без reconnect |
| Source policy → B при default A | NAT44/NAT66 блокируются своими guards; peer B проверен положительным контролем |

После удаления policy rules и возврата маршрутов точный живой снимок совпадает:
firewall обоих семейств/backend и native nft, IPv4/IPv6 route tables и RPDB, link
flags и sysctl. По логам каждого из восьми клиентских процессов — ровно одна попытка
подключения и одна успешная AUTH за весь финальный сценарий. После штатного stop
клиентов и worker восстанавливается исходный снимок, control socket/sysctl journal
удалены. Полный внешний host snapshot лабы совпал до/после; рабочие release/service
сохранены, `.10` не затронут.

Мануал уточнён: серверный auto-WAN выбирается при установке профиля и не означает
автоматический перенос NAT на новый default route. Для нового выбранного WAN нужен
restart профиля либо администраторский маршрут к прежнему WAN. Клиентский exit-node
monitor — другая функция. RFC1918 исключение NAT44 не включает CGNAT/публичную LAN.
Первый fixture-отказ сохранён: IPv6-only клиент ошибочно получил IPv4 include и
правильно отказал после AUTH; список маршрутов исправлен. Промежуточные 160 PASS
r2 сохранены отдельно: финальный r3 добавил контроли, DROP counters и точную RPDB
сверку; они не суммируются с 204. Production Rust не менялся; 288 local/remote SHA,
debug/release SHA совпали с точным build evidence. Новых build/Clippy/benchmark нет.
[Команды, результаты, SHA, отказы и raw manifest](../../../release/certification/evidence/server-route-policy-20261002.json).

Это четыре выбранные topology/backend ячейки при сохранении устройств, а не все
возможные policy tables, obfuscation или физические сети. Delegated client_subnet
имеет отдельное route/NDP evidence; он не проходил этот NAT packet сценарий.
Повторного firewalld daemon прогона нет: его public-policy/multiprofile доказательство
сохранено в Q25-F213. IPv4 forward_private/manual runtime здесь не повторяются.

**D06 IN_PROGRESS:** непрерывная identity выбранного WAN при rename/delete/recreate
[Q25-A125](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md) не исправлена; клиентский monitor
WAN требует отдельной сверки этого остатка. Текущий пакет не превращает ограничение
по имени в identity-защиту. **Реестр: 13/15 DONE (86,7%), D06/D15 IN_PROGRESS**.

### Q25-A125 continuation — выбор WAN identity guard, 2 октября 2026

Квалифицированы kernel кандидаты на четырёх mixed backend: **168 проверок ожидаемых
результатов**, 88 probes / 264 datagrams / 168 echo replies / 96 блокировок. Это
синтетические exit-shaped правила, без worker/VPN и без production fix. Native
ifindex selector пропускает новый WAN с прежними index/name/MAC. Per-device devgroup
token блокирует такую замену, но его установка выключает чужой group0 DROP; root
может перенести token на новое устройство. Поэтому простой переход на ifindex или
скрытая смена device group отклонены как готовое решение.

[Отчёт и конкретные требования реализации](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md)
и [полное evidence](../../../release/certification/evidence/wan-identity-candidates-20261002.json).
Клиентский monitor сверён по текущему исходнику: только имена в ExitWanSnapshot,
сравнение раз в 5 секунд; его прежний Q25-F127 закрывает смену имени, а не identity.
Нового monitor E2E, реального firewalld или crash/group recovery в пакете нет.
Внешние firewall/routes/link groups/RPDB и набор kernel modules сохранены.

**D06 IN_PROGRESS:** остаётся kernel guard с явным контрактом владения, shared lease,
журналом и packet/recovery проверками. Остальные компоненты D06 уже имеют evidence;
общие наборы повторять до изменения кода не требуется. **13/15 DONE (86,7%)**;
D15 — финальная сборка/сертификация после production исправления.

### Q25-A125 continuation — выбран DEVMAP guard, 3 октября 2026

Рабочий прототип сохраняет routing/NAT и блокирует замену WAN: frozen DEVMAP
удаляет запись при unregister; socket-filter в mangle/POSTROUTING сравнивает
фактический out index. Проверены и другой index при живом переименованном исходном
WAN, и повтор name/index/MAC после удаления, pin/reopen и запрет refill.
**4/4 mixed cells, 156 проверок, 72 probes / 216 sends / 168 replies / 48 DROP**.
Две отдельные setpriv проверки показывают отказ со stock unit capabilities и
работу после добавления CAP_BPF при заранее подготовленном bpffs.

[Точный механизм, ограничения и интеграция](../reports/audit-0.8.2/AUDIT-Q25-WAN-NAME-REUSE.md) ·
[evidence](../../../release/certification/evidence/wan-devmap-20261003.json).
Это synthetic veth proof, не Qeli worker/TUN, SIGKILL или systemd startup. Внешние
сетевые snapshots совпали; xt_bpf был автозагружен один раз и оставлен загруженным.
Rust, действующие unit/service и `.10` не менялись.

**D06 IN_PROGRESS:** реализация выбранного guard в общем Rust helper, trusted pins /
persistent journal / bootstrap / service capabilities / client monitor, затем
целевые реальные VPN/multiprofile/conntrack/policy/recovery проверки. Продолжать
общий поиск identity кандидатов не требуется. **13/15 DONE (86,7%)**, D15 после
конечного production кандидата.

### Решение по Q25-A125 — 3 октября 2026

Пользователь отменил внедрение BPF: «это не столько необходимая защита, если не
получается реализовать хрен с ним». Прототип работал; production интеграция ещё не
была завершена. Решение относится к усложнению рабочей системы, а не к отрицанию
воспроизведённой проблемы. Q25-A125 остаётся известным P2: правила выбирают WAN
по имени; повтор этого имени другим устройством может снова разрешить NAT.

**D06 ACCEPTED_LIMITATION:** остальные компоненты имеют приведённое выше evidence;
непрерывная identity и соответствующая переделка client monitor сняты с
обязательной реализации по решению пользователя. [Эксплуатационный контракт](../manuals/OPERATIONS.md):
перед rename/delete/recreate выбранного WAN остановить профиль, подтвердить
очистку, затем изменить интерфейс и запустить профиль заново. Смена default route
с сохранением устройств имеет отдельные успешные проверки.

Незавершённые Rust helper/server journal изменения сохранены только в архиве
черновика вне репозитория и убраны из рабочего и lab source tree. CAP_BPF, bpffs
bootstrap и service unit не применены: изменение прав было отклонено автоматической
проверкой до выполнения, затем сама доработка отменена пользователем. Рабочий
release SHA `a526c03b` и сервис .11 (MainPID 777) сохранены. `.10` не затронут.
Начатая сборка черновика не считается PASS; её test artifacts не сертифицированы.
[Машинная запись решения и отката](../../../release/certification/evidence/wan-identity-disposition-20261003.json).

**Остался D15:** единый финальный кандидат, native/provenance/build/benchmark
сверка с точным source/artifact SHA и применимость ранее полученного evidence.
Не требуется внедрять BPF или повторять поиск WAN identity кандидатов.

### Итоговый native checkpoint D15 — 3 октября

Новые A/B и ABI для четырёх native-библиотек прошли; байты совпали с прежними,
provenance обновлён на digest `1bcee8e9…`. Windows read-only selftest 143/143 PASS.
Сверка 164 adapter + 288 Rust input SHA сохраняет применимость прежних D08
результатов; семь Linux-отчётов совпадают по всем 288 Rust-файлам. На .10
сторонний vpn-nat меняет три legacy-правила: host wrapper FAILED сохранён и
объяснён журналом; A/B reproducibility от этого не зависит. [Подробности](../reports/audit-0.8.2/AUDIT-Q25-NATIVE-REBUILD.md).
D15 остаётся IN_PROGRESS до свежих Linux release/runtime/soak/benchmark и
certification; 13/15 DONE + D06 ACCEPTED_LIMITATION не меняются.

### Итоговое закрытие D15 — 3 октября

Финальный кандидат проверен, benchmark и automated certification обновлены.
Ошибки обвязки сохранены: пропущенные compile-time conformance fixtures и
SSH NOFILE 1024 для 512 пар TCP-сокетов. После полного архива inputs и
process-local лимита 4096: 2257 PASS, 0 failed, 60 штатно ignored. Лимит
рабочего сервиса 65536 и PID не менялись. Soak: fd/socket counts стабильны,
выборочный RSS в пределах 32 МиБ на 100 циклах; бесконечный прогон не заявлен.
Старые отчёты остаются историческими. Неизменённые модули переиспользуются
по SHA с исходными границами. Общий набор не повторяется без релевантного
изменения. Полный release preflight/публикация и physical exclusions не PASS.

**8 октября, F384:** [usage Q32](../reports/audit-0.8.2/AUDIT-Q32-USAGE.md) различает ошибку до публикации и неподтверждённую сохранность после rename. Baseline memory700/file0 воспроизведён, исправленный harness16/uid65534,2426library (60ignored),strictClippy/daemon,A-B four cores,WindowsABI22/AndroidJNI23 PASS; подробности в evidence. Исходное host firewall расхождение и неуспешные подготовительные прогоны сохранены. Агрегат остаётся14/15 DONE плюсD06 ACCEPTED_LIMITATION.

**8 октября, F385–F388:** [Q32: I/O логов и trace](../reports/audit-0.8.2/AUDIT-Q32-LOGS-TRACE.md) квалифицирован: три baseline-ошибки, harness11/UID65534, настоящие сигнальные выгрузки,2434 library (60ignored), строгийClippy/daemon,118 групп Node VM и четыре nativeA/B/WindowsABI22/AndroidJNI23 PASS. Логи неудач/исправление входов и первоначальный legacy firewall drift сохранены; пределы источников/входов/host/платформ — в evidence. Итого14/15 DONE плюсD06 ACCEPTED_LIMITATION; Q32 и другие незавершённые разделы полного аудита остаются открыты.

**8 октября, F389–F394:** [INI уведомлений и доставка](../reports/audit-0.8.2/AUDIT-Q32-NOTIFICATIONS.md): доверие перед чтением/сохранением, полная ограниченная HTTP-строка и успех только 2xx, query/fragment, консервативная проверка специальных адресов, сброс кеша после записи и проверка записи симлинка. Воспроизведены три старых helper-ошибки и две ошибки кеша настоящей библиотеки; шесть helper tests, 12 изолированных HTTP-проверок и cache trust/recovery проверяют исправления. Финальные library/native результаты и guards — в machine evidence. Q32 и Q29/Q30/Q31 открыты; всего 28/37, осталось девять; старый долг14 DONE плюс принятое D06.

**8 октября, Q32 завершён:** пять критериев сверены для metrics/usage/logs/trace/notifications и неизменных roaming observations; финальные2439 library, strictClippy/daemon, реальные HTTP12/cache, native A/B/ABI22/JNI23 и docs/provenance PASS. Сравнения16 сохраняют область прежнего выполнения; границы physical/TLS/Telegram/browser документированы. План29/37(78,4%),осталось восемь;Q29/Q30/Q31 и D06 сохранены.

**8октября,F395:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): отдельный core/hook publication-lock закрывает гонку между проверкой и командой без deadlock lifecycle/startup. Три ожидаемых FAIL старого hook; четыре Rust/shell случая и196 прежних methods на каждой dash/ash без skips,2444 Linux(60прежних ignored),strictClippy/client PASS. Native refresh/ABI и raw guards записаны в scoped packet evidence. Смешанный комплект/admin writes, последовательный NDM/power loss, исключённая прошивка и полный SDK/release pipeline вне закрытия;Q31 остаётся3/5IN_PROGRESS. Общий29/37(78.4%),8осталось;старый долг14DONE+D06ACCEPTED;Q29/Q30 сохранены.

**8 October,F396:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): whole preflight requires one clean commit between gates; three old mixed-commit false-PASS cases reproduced.12 whole-program methods,56 Linux related methods uid65534 without skips PASS; Windows78PASS/3pre-existing skips. Snapshot/report identity and120-second certification timeout qualified; optional lab build and production pin/hash unchanged. Current native inputs/artifacts unchanged, SHA/provenance retained; owned Python fixture removed after verified backup. Full SDK/bootstrap/release-cut/successful Actions/preflight remain OPEN; Q31 remains3/5,full29/37(78.4%),8remain;old debt14DONE+D06ACCEPTED,Q29/Q30/exclusions retained.

**8 October,F397–F398:** [Q31 CI diagnostics](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): macOS CI output matches guarded per-app-arm64 leaf; old command fails,11 Windows/12 Linux path cases PASS (Windows symlink unavailable). iOS exit-node known-key fixture now uses valid gateway=false shared split mode; seven actual configuration-ABI checks PASS. Swift XCTest/Keychain status(-34018) runtime remains OPEN; old native CI failure reconciled to current PASS provenance, not new Actions success. Source/runtime exclusions and all plan/debt counts retained.

**8 October,F399/Q31-V010:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): actual SDK nested make broke sed before Cargo; exact admission plus dollar-free substitution fixes it. Official24.10.4 x86/64 Git download/hash/prepare, Rust1.89 prebuilt client compile/link, SDK install/dependency/strip/IPK PASS.6 real-Cargo,7 offline opkg and9 fresh SDK-client OpenWrt userspace cases PASS without skips. Stock toolchain tables repaired a fixture packaging prerequisite; no dependency bypass. Initial rootfs prep/autoremove backup-selection failures retained. SHA-verified backup and guarded own-root cleanup; service unchanged, native14SHA/provenance PASS. Upstream Rust bootstrap/cold-hermetic build, production source-cut and successful current Actions/preflight remain OPEN; firmware USER_EXCLUDED. Q31 remains3/5, full29/37(78.4%),8remain; old debt14DONE+D06accepted,Q29/Q30 retained. No push/deploy/release.

**8 October,Q31-V011:** [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md): previous32-bit builds predated F395; current6c2225cd ARMv7/MIPS full client builds/SHA/static ELF PASS,318exact transferred inputs.32QEMU CLI/INI and14exact production PublicationLock/budget release behavior checks PASS on cortex-a7/24Kc uid65534. No new product regression/ABI/source change;14nativeSHA/provenance PASS. .11 rustup inventory auto-installed a missing named nightly; only that own addition removed with guards/default preserved,probe compiled sequentially on .10. Verified backups,three own roots cleaned,unrelated old root/services retained. Old four-target A/B keeps original source/date;no cfg(test)/firmware/fullVPN/SDK bootstrap/source-cut/current CI success claim. Q31 remains3/5;29/37(78.4%),8remain;Q29/Q30/D06/exclusions retained. No push/deploy/release.

**8 октября,F400–F403:** [Q33 Docker entrypoint](../reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md): четыре старые ошибки воспроизведены на dash/ash; исправлены пустой argv, явный CLI-config и новые файлы0600 без перезаписи.34 сценария/46 chroot-запусков PASS без skips; проверены конкурентные creators и copy/link failures. Docker image/daemon, Debian updater/install и полный Q33 OPEN. Bootstrap Rust SDK Q31 отложен: измерены2GB RAM/~9GB диска, ниже рекомендации upstream8GB/30GB; compiler FAIL/PASS не заявляется.29/37(78.4%),осталось восемь; exclusions сохранены.

**8 октября,F404–F411:** [Q33 updater](../reports/audit-0.8.2/AUDIT-Q33-SERVER-UPDATER.md): исправлены invalid local input, admission пакета, CRLF/cleanup, блокировка транзакции, точная install/downgrade identity, restart/PID health и legacy-кэш.14 старых регрессионных сценариев FAIL;21 итоговый метод/24 запуска updater+1 installer PASS с настоящим dpkg. Точная команда CI, ShellCheck и guarded cleanup PASS; production maintainer scripts/systemd/VPN/Docker OPEN. Q33 IN_PROGRESS;29/37(78.4%),осталось восемь; старый долг14DONE+D06accepted, Q29/Q30/Q31/exclusions сохранены. Без push/deploy/release.

**8 октября,F412–F416:** [Q33 Debian lifecycle](../reports/audit-0.8.2/AUDIT-Q33-DEBIAN-LIFECYCLE.md): исправлены private no-replace users creation, pre-unpack state guards, service-user/debconf failures, отказ удаления при stop failure и adduser dependency.10 baseline methods/12 ожидаемых ошибок;16 итоговых методов/24 настоящих lifecycle dpkg-вызова PASS, точная команда CI/lint PASS. Production make/scripts с инертным бинарником/зависимостями и account/debconf/systemctl seams; полный installer/daemon/Docker OPEN. Собственный каталог SHA-backed-up/guarded-cleaned; service777/845 сохранён. Q33IN_PROGRESS,29/37(78.4%),осталось восемь; старый долг14DONE+D06accepted,Q29/Q30/Q31/exclusions сохранены. Без push/deploy/release.

**8 октября,F417–F421:** [Q33 from-binary](../reports/audit-0.8.2/AUDIT-Q33-BINARY-INSTALLER.md): исправлены copy-failure propagation, exclusive source/full staging, state/users, signal exit и remote architecture/metadata/required attestation.14 baseline methods19 ожидаемых ошибок;18 итоговых методов23 запуска(21prefix+2earlywhole) PASS, точная CI-команда/updater21 regressions/lint PASS. HTTP/account/systemctl/qeli/gh seams явные; full installation/VPN/OIDC PASS не заявлен. Полный installer dependencies/publication/tuning/health и Docker OPEN. Собственный каталог backed-up/guarded-cleaned; service777/845 сохранён. Q33IN_PROGRESS,29/37(78.4%),осталось8; старый долг14DONE+D06accepted,Q29/Q30/Q31/exclusions сохранены. Без push/deploy/release.

**8 октября,F422–F426:** [Q33 допуск installer](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-ADMISSION.md): conditional/rechecked зависимости, qeli/arch/version metadata, exact installed state, required gh и удаление мёртвой URL-ветки QELI_DEB.12 baseline methods14 ошибок;18 final methods22 calls(20helpers+2earlywhole) PASS; точная CI/binary18/updater21 regressions/lint PASS. Recipe38/native14 SHA+provenance PASS. Full positive installer/publication/tuning/health/disconnected host/Docker OPEN. Собственный root backed-up/guarded-cleaned;777/845 сохранены. Q33IN_PROGRESS;29/37DONE78.4%,осталось8; Q31 3/5 и все historical open/excluded/accepted пункты сохранены. Без push/deploy/release.

**8 октября,F427–F431:** [Q33 секреты/web-config](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-SECRETS.md): исправлены unsafe secret targets, private rename/kept-link copy, staged summary/pending-password recovery, atomic web rewrite/owner600, unique backups и retained-user notice.14 baseline methods15 ожидаемых assertions; итог21 methods22 запуска(20helpers+1earlywhole+1positivewhole с seams) PASS. Точная CI/admission18/binary18/updater21 regressions/lint/recipes38/native14 PASS. Настоящие CLI/parser/identity/users/panel/kernel/service/VPN/Docker и initial config transaction OPEN; automatic rollback/durability/race-pinned-dir не заявлены. Оба root backed-up/guarded-cleaned;777/845 сохранены. Q33IN_PROGRESS,29/37DONE78.4%,осталось8; Q31 3/5 и historical open/excluded/accepted пункты сохранены. Без push/deploy/release.

**8 октября,F432–F436:** [Q33 preflight/подготовленный INI](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CONFIG.md): explicit host/panel/boolean до изменений; auto-host до config/identity; ровно один profile header/явные awk errors; полный private INI stage через CLI/web/final validation, root helper после проверки, backup/rename publication. Baseline17methods22expected assertions; исправлено21method28whole(3positive/25refusals), точная CI21/28,78regressions/lint/recipes38/native14/docs9(676Markdown) PASS. Filesystem настоящий; CLI/systemctl/kernel seams, actual parser/auth/daemon/VPN/Docker OPEN. Config сохранён до commit; users/identity/links/tuning/bin/deps/drop-in могут измениться, restart-after-publish не откатывается, прежний root override OPEN. Собственный .11 root backed-up/cleaned;777/845 сохранены. Q33IN_PROGRESS,Q31 3/5,29/37DONE78.4%,осталось8,historical OPEN/USER_EXCLUDED/D06ACCEPTED сохранены. Без push/deploy/release.

**8 октября,F437–F438:** [Настоящий CLI/version](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CLI.md): --version для старого binary, строгие fixture argv и unique stage-lock cleanup. Version baseline2fail→2PASS; realCLI initial4lockfail→5PASS, повторCI2+5;99regressions/lint/recipes38/native14/docs9(678Markdown)PASS. Genuine debug artifact85ea/SHA37a6 reused для неизменённых CLI/parser/trust paths;4laterclient/notify различия — не fullcurrentRust/releaseABI qualification. Настоящие три profile keys/Argon2/users/panel/INI/link/custom-dropin flows;systemctl/daemon/kernel/preflight-ip seams,VPN/Docker/default-unit-rootrevertOPEN. Package CI добавлен,Actions не исполнялся. Own root backed-up/cleaned,777/845 сохранены. Raw334files41695825bytesSEALED. Q33IN_PROGRESS,Q31 3/5,29/37DONE78.4%осталось8,history/exclusions/D06accepted сохранены;без push/deploy/release.

**8 октября,F439–F441:** [Пользователь службы/ownership](../reports/audit-0.8.2/AUDIT-Q33-SERVICE-USER.md): сохранены права client-links/backups, каталог квитанций root0700; real state validation и сохранение existing override при ошибке исправления; installer явно применяет default qeli после проверки. Baseline ownership2/CLI3 failures;fixed2+10 и117regressions PASS;CI2+10+2,lint3scripts,Rustbin5/Clippy/fmt PASS. Current CLI пересобран0e01;native A/B evidence обновлено. Real systemd/startup/kernel/VPN/Docker остаются OPEN;Q33 IN_PROGRESS,29/37DONE78.4%,осталось8. Исторический долг/exclusions сохранены;только локальный dev.

**8 октября, F442–F444 / Q33-F045–F047:** [Systemd](../reports/audit-0.8.2/AUDIT-Q33-SYSTEMD.md): стабильный снимок nft без смешивания diagnostics; управляемый SIGHUP supervisor с сохранением panel lockouts; ограниченные filesystem capabilities root. Current CLI a36d/SHA6161 собран Rust1.97 offline/locked; bin5 + SIGHUP4 + supervisor23 + Clippy PASS; installer/CLI129 + точная локальная CI14 + lint PASS. Настоящий manager257 sandbox/reload/restart/root-qeli/invalid-INI recovery проверен в собственном network namespace; запрет root config trust сохранён. Native A/B/ABI и sealed evidence — в отчёте. Закрыт этот manager gate, а не весь Q33: настоящий package/update rollback pipeline, VPN traffic и Docker image runtime остаются OPEN. Q33 IN_PROGRESS,29/37 DONE(78.4%),осталось8; история/exclusions/deferred пункты сохранены; без push/deploy/release.

**8 октября:** [DEB/update/remove](../reports/audit-0.8.2/AUDIT-Q33-PACKAGE-MANAGER.md): настоящий portable release/jemalloc и production package; реальные apt/dpkg/debconf/CLI/systemd с частной DB и явным unit mapping, финальные 24 PASS. Успешное обновление, package rollback после неисправного unit и повреждённого ELF, exact configured DB, сохранение bytes/UID/mode config/users/identity/receipts/backups, remove/purge. Три fixture FAIL сохранены; audit helpers исправлены, продукт не изменён. Закрыт этот scoped gate; whole binary/kernel installer, release VPN roundtrip, Docker и Actions OPEN. Q33 IN_PROGRESS; 29/37 DONE (78.4%), осталось 8; предыдущие статусы/исключения сохранены.

**8 октября:** release VPN и package→systemd→VPN: [Q33 DEB](../reports/audit-0.8.2/AUDIT-Q33-PACKAGE-MANAGER.md). Матрица extracted production release ELF:18 сценариев/376 PASS (TCP/UDP, outer/inner4/6, split, leak, TAP, DNS, MTU, legacy0.7.16). Реальный pinned H-1 client через пакетную службу:36 PASS, fresh/upgrade/оба rollback, exact TUN route и clean stop. Исходный fixture trust FAIL сохранён, show-identity выполняется от qeli. Продукт/native не менялись; стенд восстановлен, roots SHA-archived/guard-cleaned. Release data-plane и package/service/VPN gate закрыты; full binary/kernel installer и Docker/Actions остаются OPEN. Q33 IN_PROGRESS;29/37 DONE78.4%,осталось8; прежние ограничения сохранены.

**8 октября,F445 / Q33-F048:** [Полный installer/kernel](../reports/audit-0.8.2/AUDIT-Q33-INSTALLER-CONFIG.md): подтверждён и исправлен ложный sysctl success; private per-run snapshots/prior files/restore instructions, readback и early tuning path guards. Full QELI_BIN+QELI_SRC и production QELI_DEB: по24 PASS с actual manager/CLI/Argon2/MSS/pinned VPN; probing0→1→0 и persistent files restoration. Linux136 regressions без skips/lint PASS, CI tuning добавлен. Первые FAIL сохранены; root777/845/network/kernel не менялись. Full positive installer и partial kernel recovery gate закрыты, глобальная запись10keys/BBR load/reboot/пустой OS bootstrap не заявлены; Docker/Actions и прежние ограничения остаются OPEN. Q33IN_PROGRESS29/37DONE78.4%,осталось8; без push/deploy/release.

**8 октября,F446–F448:** [Docker runtime](../reports/audit-0.8.2/AUDIT-Q33-DOCKER-ENTRYPOINT.md): branch latest publication исправлена, Cargo --locked, четыре destructive/status-ignoring legacy harness удалены. Настоящий Docker image/runtime26PASS: pinned H1 VPN fresh/recreate/known-image rollback, root0600/readonly volumes, protected-login readiness, сохранение bytes/UID/mode, шесть exit0 без OOM/SIGKILL. Harness FAIL сохранены; host snapshots/профили AppArmor/PID777-845 восстановлены, own root SHA-backed-up/guard-cleaned. Runtime gate закрыт; compiler multiarch/registry/currentActions и итоговая command/hook сверка Q33 OPEN.29/37DONE78.4%,осталось8; исторический долг14DONE+D06accepted/exclusions сохранены; локальный dev без push/deploy/release.

**8 октября,F449/Q33-F052:** [Итоговая сверка Q33](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md): исправлен обход защиты hook-файла при restore через `..`, кавычки и symlink aliases; literal variables/globs в неизвестном top-level managed entry отклоняются. Точный старый collector на Linux ожидаемо FAIL;14 targeted production helper/gate checks PASS. Полная серверная/native квалификация PASS:CLI5/backup49/IO2/Clippy, freshA-B/14SHA/provenance/WindowsABI22. Retained hook snapshot SOURCE REVIEW OPEN;Q33IN_PROGRESS; общий29/37DONE78.4%,8осталось. Прежние runtime gates переиспользуются только в неизменённой части; Q29/Q30/Q31/USER_EXCLUDED/D06ACCEPTED сохраняются. Без push/deploy/release.

**8 октября,F450/Q33-F053:** [Q33 завершён](../reports/audit-0.8.2/AUDIT-Q33-COMPLETION.md): actual baseline два HTTP restore исполняют заменённый harmless marker; фикс хранит hooks startup/последующих worker до завершения supervisor и запрещает exact deletion. Fixed8+later10 runtime, CLI5/backup50/lifecycle1/post_down3/privateIO2/Clippy PASS; свежая native/ABI квалификация и raw seal приведены в отчёте. Q33 5/5 DONE;30/37(81,1%),7осталось. Исторические ограничения Q29/Q30/Q31/Q34/D06 сохраняются; без push/deploy/release.

**Q34 dependency packet,8 октября:** [F451–F454](../reports/audit-0.8.2/AUDIT-Q34-DEPENDENCY-POLICY.md) закрыты в пределах Rust dependency policy/PEM migration/formatter gate с реальными negative/positive checks. Старые14DONE и D06accepted сохранены; полный Q34/current Actions и согласованные Q29/Q30/Q31/платформенные ограничения остаются отдельными критериями. Не создаёт нового списка D-пунктов и не закрывает непроверенные release payloads.

**8 October, F455–F459 / Q34-F009–F013:** [Client supply chain](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): two npm advisories fixed with byte-identical CSS; official Gradle checksum qualified by real positive/corrupt-wrapper checks; NuGet all/transitive/low audit errors and explicit advisory source, actual vulnerable/unavailable-source refusals; WinDivert official archive match/signature/hash/notices positive+4negative PASS. Three Release managed builds, required conformance, Windows selftest and local codec benchmark PASS. braces advisory remains OPEN (no published patch); SDK/locks/other graphs/currentCI/release coverage pending. Native inputs/copies14SHA unchanged; no lab changes. Q34 IN_PROGRESS,30/37DONE81.1%,7remain; established Q29/Q30/Q31/D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F460–F462/Q34-F014–F016:** [SDK/locks](../reports/audit-0.8.2/AUDIT-Q34-SDK-LOCKS.md): exact official SHA512-qualifiedSDK10.0.401/runtime10.0.12;CIglobal-json-file/build_appcwd corrected;35reviewed perRID/config/tools/Linux/singlefile locks with root/referenced missinglock guard.18Windowsgenerate-lockedpairs/7builds/conformance/adapters/codec and exact2Windows+2MacpublishPASS;realoldSDK/drift/hash/missingrefusalsPASS;Linux12graphs24restore/builds2MacpublishPASS,ownedSHAarchive/proc-mountguardcleanup/service745901preserved. Native/CSS/protectedfiles unchanged;standaloneinvokerselftest only,normalrequireAdministrator740 retained. Android locks/remainingpackages/currentCI/sourcecut and bracesOPEN remain;Q34IN_PROGRESS30-37DONE81.1percent7remain;historical debt/Q29Q30Q31D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F463–F465/Q34-F017–F019:** [Android dependencies](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-DEPENDENCIES.md): strict transitive project/early-plugin locks, three real lockfiles, SHA256 artifacts+metadata and missing-policy guards. 747 independent HTTPS files match; Windows/macOS AAPT2 checksum admission only. Actual debug/defaultR8/debug-release instrumentation assemblies, locked/offline/lint and fresh201productionJNI JVM PASS; five real default-mode refusals PASS. Initial partial-lock, harness Metaspace and alias404 trials retained; separate lint/in-process Kotlin/oneworker privateVM overrides. SHA-backup/proc-mountguard owned cleanup,777845 preserved; nativee3fb/14SHA/protected unchanged. No device VPN/currentJava17CI/otherOS builds claimed. Q34IN_PROGRESS30-37DONE81.1percent7remain;braces/packages-licenses/currentCI/sourcecut-release and historicalQ29Q30Q31D06/exclusions preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 октября,F466–F468/Q34-F020–F022:** [Maven security](../reports/audit-0.8.2/AUDIT-Q34-MAVEN-SECURITY.md): shared early-plugin/project security versions, KGP2.4.21/Netty4.1.137/BC1.85 and remaining targeted fixes; all318 locked package/version records freshOSV0affected (initial326/19affected/50distinctadvisories). CI Maven fail-closed gate8fixtures/actualJDOMnegative-positive PASS; wrong-password test now AEADBadTagException, nullable reflection checked. Java17 officialSHA private qualification: debug/defaultR8/debug-release instrumentation assemblies/201JVMproductionJNI/lint0errors53warnings/offline-strict PASS;2actualoffline policy/driftrefusals+restoredpositive.104freshHTTPS checksums/626exactinheritedsealed records,obsolete admission removed. First unit compileFAIL and harness/API diagnostics preserved. SHA32720631byte backup/proc-mountguardcleanup777845 preserved; nativee3fb/14SHA/protectedfiles unchanged. License metadata318 obtained, actualNOTICE/native copyleft/source-cut/device runtime/currentActions remain OPEN; freshestCI37765333335 is anotherSHAf84a78d9. Q34IN_PROGRESS30-37DONE81.1percent7remain;F459braces/Q29SIGKILLFAIL-ENONET/Q30/Q31/D06accepted/exclusions unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 октября,F469/Q34-F023:** [Android licenses/NOTICE packaging](../reports/audit-0.8.2/AUDIT-Q34-ANDROID-NOTICES.md): per-variant canonical project AGPL/MPL,Apache2,Maven runtime inventory,original archive identities and preserved JAR/AAR/nested notices; dedicated original-archive ArtifactView,identical variant visit deduplication. Independent extraction current-checksum-admitted63archives/44AAR/24resources PASS;76license declarations inherited sealed review. CI APK index/hash/coordinate/origin gate12negative fixtures. APK qualification/evidence in linked report; native dependency/upstream-source notices,matching source publication/signatures/currentActions/fullrelease remain OPEN. Native e3fb/protected files unchanged; no new nativeAB/JVM/deviceVPN claim. Q34IN_PROGRESS30/37DONE81.1percent7remain; historical Q29/Q30/Q31/F459/D06/exclusions unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October, F470/Q34-F024:** [Common Cargo legal resources](../reports/audit-0.8.2/AUDIT-Q34-NATIVE-NOTICES.md): 235 checksum-locked packages,458 upstream resources, six exact-VCS supplements; one common bundle and packaging/CI checks. Actual qualification and limitations in linked report. Rust std/toolchain/.NET/upstream-source notices, source publication, OpenWrt immutable source cut and current Actions remain OPEN. Q34 IN_PROGRESS;30/37 DONE81.1percent7remain;historical Q29/Q30/Q31/F459/D06/USER_EXCLUDED unchanged. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F471–F472/Q34-F025–F026:** [Managed notices and Inter font](../reports/audit-0.8.2/AUDIT-Q34-MANAGED-NOTICES.md):67 actual SDK-content-hash/official-catalog checked NuGet/runtime packages,187 shared resources; original upstream bytes and separate SIL OFL1.1/copyright for6 exact embedded fonts.35-lock/globalSDK/runtime binding,offline generator/checker,desktop/CI/app gates.19fixtures/final-source regeneration/four actual publishes/published negative/restored and shell gates PASS; scope and raw qualification in report. Toolchain notices,MicroCom exact source binding/sourcepublication/OpenWrt cut/finalActions/release OPEN. Nativee3fb/14SHA/protected unchanged,labs untouched;no new nativeAB/JVM/device claim. Q34 IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED preserved. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**8 October,F473/Q34-F027:** [Toolchain runtime/stdlib notices](../reports/audit-0.8.2/AUDIT-Q34-TOOLCHAIN-NOTICES.md):65 original reviewed Rust/Zig/NDK/GCC-MinGW resources,69 embedded files;533 common native files. Offline policy/version/SHA binding,Gradle source InputFile,common CI and all packaging paths. Qualification and exact scope in report. Source publication,old GCC minor linkage/NDK whole archive/OpenWrt immutable source cut/final Actions-signatures-release remain OPEN. Nativee3fb/14SHA/protected preserved;Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED retained. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F474–F477/Q34-F028–F031:** [Release publication gates](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md):actual tag/clean-source/exact-commit CI admission beforebuild,shared Rust pin,Docker reviewed base digests/common notices,extractedDEB notices gate,allworkflow CI filters.86methods/baselineactualGit/CLI/YAMLparse PASS;official metadata and401/currentCIabsence limits in report. Fullsourcepublication/OpenWrt immutablecut/wholeDockerbuild/currentActions/signatures/release OPEN;nativee3fb/14SHA/protected unchanged,labs untouched. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F478–F479/Q34-F032–F033:** [Attestation/checksums](../reports/audit-0.8.2/AUDIT-Q34-ATTESTATION-CHECKSUMS.md): removed unsupported build provenance for downloaded foreign assets; only actual CI-built DEB remains a subject. Atomic SHA256SUMS publication with consumer-compatible filename/regular-file admission and retained old manifest on failure. Linux11 no-skips/real GNU verify/baseline defect PASS;Windows7+4POSIXskips,release18,recipes38,YAML parse PASS (67distinct methods). SHA-backed-up/guard-cleaned own Python fixture;777845/service/network/native14SHA/protected unchanged. No Docker/native rebuild or hosted signing. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29/Q30/Q31/F459/D06/USER_EXCLUDED preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F480/Q34-F034:** [Full Docker build](../reports/audit-0.8.2/AUDIT-Q34-DOCKER-BUILD.md): tag/Cargo/exact-commitCI gate before publication tools/login,fullref/history/actionsread;actual classifier mismatch baseline/refusal and64focusedmethods/YAML PASS. Full fresh amd64 defaultfatLTO/jemalloc pinnedRust/Debian build826.546s/no binaryoverride,exact533image notices/CLI/dependencies and26pinnedVPN/recreation/invalidimage rollback checks PASS. Originalhost restored,own image/source/fixtures archiveSHA-qualified before guarded cleanup;public cache/tools exclusion explicit. Harness refusals/profile restoration retained;explicitunconfined runtime is not defaultAppArmor qualification. Multiarch/currentActions/signatures/sourcepublication remainOPEN;Q34IN_PROGRESS30/37DONE81.1percent7remain;native14SHA/protected/historicalQ29Q30Q31F459D06exclusions preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F481/Q34-F035:** [Immutable Docker inputs](../reports/audit-0.8.2/AUDIT-Q34-DOCKER-INPUTS.md): reviewed frontend digest matches previous whole build;fresh registry index/manifest/config SHA checked. Single signed Debian/security snapshot20261008T000000Z,live sources removed,source-scoped expiry only,archive authentication preserved. Actual SHA-pinned amd64 Debian rootfs APT3signatures/62new150total packages/13commands/check/repeat and4signature negatives PASS;66focused methods/2priorrecipe refusals. SHA-backed-up full installedrootfs/guardedcleanup/original777845/network/profiles preserved;initial harness failures retained. No fresh wholeimage/compiler/ARM/hostedActions/release;remaining Q34/historical limits preserved. Q34IN_PROGRESS30/37DONE81.1percent7remain.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F482/Q34-F036:** [OpenWrt source Git flags](../reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-FLAGS.md): actualGit10hidden-input false-PASS reproduced on exactprior gate;scoped ls-files refuses assume-unchanged/skip-worktree on5inputs before pin/hash. Unrelatedflags keep existingboundary.37methodsPASS(25source/12preflight),3existingPOSIX-oldbaseline skips unchanged;sourcecut actualpin/tree mismatch OPEN,pin/hash/SDK untouched. Docs/native14/protected unchanged scope,no lab/network/newcompiler/runtime. Q34IN_PROGRESS30/37DONE81.1percent7remain;historical Q29/Q30/Q31/F459/D06/exclusions preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F483/Q34-F037:** [OpenWrt exact local source cut](../reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-CUT.md): stalepin/actual qelitree baseline refused;exact full local dev f4b80a9 pinned,actualSDK24.10.4 download+prepare and second emptyDL/differentURL samearchiveSHA PASS. All 3131 trackedfiles match originalcommit incllicenses/notices;no syntheticcommit. PublicURL unchanged,actualGitHubHTTP422 means publication prerequisite OPEN. Sourcegate/native14/protected/doc checks and scoped evidence in report;no newcompiler/bootstrap/IPK/router/nativeAB/hostedCI claims. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q29SIGKILLFAIL-ENONET/Q30/Q31/F459braces/D06accepted/USER_EXCLUDED preserved.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F484/Q34-F038:** [Fuzz CI inventory](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-INVENTORY.md): actualCargo15targets butoldsmoke/nightly11 omitcontrol_v2/quic_envelope/realtls_client/websocket_frame. Sharedmanifesthelper drives bothconsumers,earlymetadatafailure blocks instead ofemptysmoke;nightlydynamicneeds/output matrix.69localmethodsPASS+10repeatLinuxunits+10actualCI Bash scenarios with controlledcargo receipts inclbaselinegap,15calls/early23failure/malformed/missing/outputpreservation/new16thtarget/externalsymlink refusal. ActualRust/libFuzzer/hostedActions and pinnedfuzztools remainseparate OPEN;no core/native/tree changes,previousOpenWrtcut retainsqelitree. SHA-backed-up fullownedfixture/procmountguards/service777845 preserved. Q34IN_PROGRESS30/37DONE81.1percent7remain;Q35TODO andhistoricalQ29/Q30/Q31/F459/D06/exclusions retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F485–F486/Q34-F039–F040:** [Воспроизводимый fuzz CI](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-TOOLCHAIN.md): фиксированы nightly/cargo-fuzz и отдельный146-package lock; locked-fetch/offline/SHA и отдельный strict audit. Все15 настоящих ASan targets:85 930 590 выполнений,без crash artifacts;72 Windows+13 Linux regression methods и реальные missing/stale/drift отказы PASS. Exact SDK source recut/prepare3140files/second emptyDL identicalSHA PASS;pin/hash обновлены. Scope и сохранённые ошибки обвязки в отчёте. Q34 IN_PROGRESS30/37DONE81,1%,7осталось;Q35 TODO и прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 October,F487/Q34-F041:** [Fuzz Actions context correction](../reports/audit-0.8.2/AUDIT-Q34-FUZZ-TOOLCHAIN.md): official SHA-qualified actionlint1.7.12 reproduces two invalid job-env references introduced in previous patch;export single pinned RUSTUP_TOOLCHAIN through GITHUB_ENV instead. Final semantic lint13 regressions/exact Bash export PASS. Previous real85,930,590-case ASan smoke recipe/environment unchanged,not rerun;sealed history preserved. Q34IN_PROGRESS30/37DONE81.1%,7remain;Q35TODO/hostedCI/historical limits retained.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F488/Q34-F042:** [Постоянный Actions lint](../reports/audit-0.8.2/AUDIT-Q34-WORKFLOW-LINT.md): новый CI gate проверяет все .yml/.yaml официальным SHA-закреплённым actionlint1.7.12. Все четыре baseline workflow уже корректны; закрыт пробел постоянного контроля. На каждой из Windows/Linux:11 unit+8 реальных сценариев PASS, включая отказ ошибочного env/нового yaml/подменённого бинарника. Временная .11 сохранена и удалена,777/845 сохранены. Ядро/native/source cut неизменны; hosted CI и остальные границы в отчёте. Q34 IN_PROGRESS;30/37 DONE81.1%,7 остаются. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F489/Q34-F043:** [MicroCom source binding](../reports/audit-0.8.2/AUDIT-Q34-SOURCE-BINDING.md): совместимый pin0.11.2 сохраняет52 API и указывает тот же exact commit в DLL/nuspec; full76-file upstream SHA проверен, publisher-only исключение удалено.24 настоящих Windows/Linux graph pairs, baseline/fixed COM consumer12 assertions,187-file bundle regeneration, builds/publishes/conformance PASS. Более новые API-несовместимые кандидаты не применены. Границы и cleanup evidence в отчёте; native/qeli tree неизменны. Q34IN_PROGRESS30/37DONE81.1%,7remain. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F490/Q34-F044:** [Docker latest](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): воспроизведён откат latest старым стабильным тегом; отдельный числовой допуск максимальной версии и общая concurrency group. 16 Windows +16 Linux методов, 59 связанных Windows методов и официальный lint четырёх workflow PASS. Входы/логи восстановлены, собственный Linux-каталог удалён, служба777/845 сохранена. Границы Git-tag inventory/очереди/старых refs и прочие обязательства в отчёте. Q34 IN_PROGRESS;30/37 DONE81,1%,7 остаются. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F491/Q34-F045:** [APK-builder](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): убраны глобальный SIGKILL GradleDaemon и удаление общего cache-журнала; import-safe main и finally закрывают SSH/SFTP при отказах.63 Windows/Linux метода и официальный lint4workflow PASS; отдельный PID/mount probe воспроизводит baseline SIGKILL, исправленная оркестрация сохраняет чужой процесс/cache. Evidence восстановлен, own root удалён, служба777/845 сохранена. Нового APK нет; общий source workspace/ожидаемый release-signer и прежние ограничения остаются открытыми. Q34 IN_PROGRESS;30/37 DONE81,1%,7 остаются.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F492/Q34-F046:** [Приватная APK-сборка](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): полный committed snapshot вместо общих source directories/фильтра расширений; locks/legal/Java/conformance сохранены, собственные Cargo/Gradle/output paths. Реальный APK/JVM и SHA-отказ мутации отдельного root PASS;71 Windows+22 Linux методов,lint/docs PASS. APK/исходники восстановлены,2 own roots удалены,служба777/845 сохранена. Offline/SDK/ENOSPC отказы и границы release/runtime в отчёте;Q34IN_PROGRESS30/37DONE81,1%,7remain; прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F493/Q34-F047:** [Явный APK для E2E](../reports/audit-0.8.2/AUDIT-Q34-CLIENT-SUPPLY.md): четыре installer-сценария требуют source/size/SHA/native-bound BUILD.json; приватная передача,remoteSHA/ADB status и ранний отказ перед canonical server restoration.89Windows+18Linux методов,5real transfer/refusal cases с контролируемымADB,lint/docs PASS; own inputs восстановлены/очищены,служба777/845 сохранена. Настоящий emulator/VPN/release runtime не запускался. Q34IN_PROGRESS30/37DONE81,1%,7remain; прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F494/Q34-F048:** [Единый release source admission](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): preflight/certification/tag запрещают скрывающие Git-флаги; certification закрепляет commit и повторно проверяет источник. Совместимость новых certification evidence сохранена.165Windows+33Linux методов PASS,own fixture удалён,служба .11 сохранена;без CI dispatch/Rust/APK rebuild. Q34IN_PROGRESS30/37DONE81,1%,7remain;прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября,F495/Q34-F049:** [Certification actual publisher](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): confirmed PASS при failed обязательном кейсе; оба release workflows теперь требуют --require-certification до DEB build/Docker login.132Windows+41Linux методов и semantic workflow lint PASS; own SHA fixture очищён,служба .11 сохранена. Без current Actions/OIDC/publication/Rust/APK rebuild.Q34IN_PROGRESS30/37DONE81,1%,7remain; historical limits сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F496/Q34-F050:** [Отказ упаковки без подписанта](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): подтверждённый unsigned archive/Done; build_app.sh теперь отказывает до native/publish и сохраняет прежние outputs. 57 Windows +8 Linux методов, Bash syntax и workflow lint PASS. Подписанты контролируемые; actual Mac signature/runtime не проверены. Own Linux fixture очищён, служба сохранена; удалена только SDK-копия с полной сверкой сохранённого ZIP. Q34 IN_PROGRESS,30/37 DONE81,1%,7remain; прочие ограничения сохранены. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**9 октября, F497–F498/Q34-F051–F052:** [Universal2 и retired resign](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): устранён arm64 fallback при lipo failure/missing Intel; проверяется полный Mach-O graph и каждый output. Удалён неиспользуемый unchecked SSH-resign helper.58Windows/11Linux методов включая2actualLLVM PASS, workflow lint/docs PASS. Synthetic headers, без full payload/signature/Mac runtime; служба сохранена, own root очищён.Q34IN_PROGRESS30/37DONE81,1%,7remain; прежние ограничения сохранены.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября, F499–F500/Q34-F053–F054:** [Входы и ресурсы упаковщика](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): закрытие SSH/SFTP на всех путях, отдельные workspace, safe TAR/core до SSH и 4 upload SHA gates.72 Windows/23 Linux методов +3 actual main trials PASS; повреждение сохраняет прежний ZIP. Controlled signer/synthetic headers, без Mac/signature PASS.48 own lab files очищены, service сохранён. NuGet/HTTP дубликаты удалены по SHA, archives/SEALED сохранены. Q34 IN_PROGRESS;30/37 DONE81,1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября, F501/Q34-F055:** [Compiler CI pins](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): устранён implicit stable в7jobs, compiler1.97.0 совпадает с reviewed policy; остальные matrix/nightly choices сохранены. Actual YAML/exactaction default proof,65methods/actionlint4/docs PASS. Source qualification без hosted Actions/rebuild; native/qeli execution inherited. Q34IN_PROGRESS30/37DONE81,1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F502–F503/Q34-F056–F057:** [Событие и охват CI](../reports/audit-0.8.2/AUDIT-Q34-PUBLICATION-GATES.md): release gate требует push event/exact SHA; green PR merge не заменяет source CI. Paths filters удалены, все root policy inputs запускают CI.132Windows/67Linux methods/actionlint4/docs PASS. Actual Git/controlled gh, не hosted Actions.25ownlabfiles очищены,service сохранён. Developer docs1.97/locked обновлены;F459 latest3.0.3/no patch OPEN.Q34IN_PROGRESS30/37DONE81,1%,7remain;LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.
**10 октября, F504–F505:** [Stability gate](../reports/BENCHMARK.md): исправлены ложный PASS по неполным/округлённым/некорректным замерам и host-wide cleanup. 89Windows/19Linux methods,4workflow lint и real read-only .11 refusal PASS; service777/845/CLI75bc сохранены. Нет нового throughput/soak или завершения Q34/Q35/Q36. 30/37DONE81,1%,7остается. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10октября,F506–F507:** [Soak admission](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md): нулевой цикл TCP и downgraded endurance labels воспроизведены; общий decimal validator до сетевых действий, smoke/full markers и minimum10k/1k только для full endurance wrapper. Обязательный bounded100 сохранён.28Linux/57Windows methods,4workflow lint PASS; без новогоVPNsoak/native rebuild. Q34/Q35IN_PROGRESS,30/37DONE81,1%,7остаётся.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F508/Q35-F005:** [Изоляция runner](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
закрыта конкурирующая очистка TCP/UDP namespaces и общий family-switch hosts.
7 реальных kernel +35 Linux script methods PASS; SIGINT/TERM/KILL удаляют потомков,
соседние процессы/настройки сохраняются. Только живые NAT-счётчики нормализованы
в структурном сравнении, raw сохранён. Новый VPN-soak не заявляется;
Q34/Q35IN_PROGRESS,30/37DONE81,1%,7остаётся.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F509/Q35-F006:** [Короткие control sockets и матрица отказов](../reports/audit-0.8.2/AUDIT-Q34-RELEASE-SOAK.md):
реальный SUN_LEN при длинном TMPDIR исправлен private /run path; все consumers
TCP/UDP/bonding/secondary перенесены.14case executions/320assertions,
7liveconcurrent snapshots,35Linuxscript+7kernelmethods PASS; первый family
FAIL и ошибка TCP-only наблюдателя сохранены. Общий Q35 IN_PROGRESS,
30/37DONE81,1%,7остаётся.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября, Q35 fuzz фрагментов:** [отчёт](../reports/audit-0.8.2/AUDIT-Q35-FRAGMENT-FUZZ.md): усилены два target, 246 813 настоящих ASan запусков PASS; исходные ошибки тестовой обвязки сохранены. Q35 IN_PROGRESS, 30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября, Q35 длительный roaming:** [отчёт](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md): два одновременных реальных VPN-прогона TCP/UDP по 900 циклов; 1835,9 с подтверждённой совместной активности, 368 полных снимков, пороги ресурсов PASS. Исходные и итоговые снимки хоста сохранены, own root очищен по SHA. Это локальная квалификация, полный release endurance/8 ч остаётся открытым. Q35 IN_PROGRESS;30/37 DONE,7 остаются. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F511/Q35-F009:** [Клиентский INI/qeli:// fuzz](../reports/audit-0.8.2/AUDIT-Q35-CLIENT-CONFIG-FUZZ.md): инварианты стабильной сериализации;18 494 ASan запуска PASS,701 итоговый corpus,723 SHA-файла evidence; первый локальный отказ сборщика сохранён. Own root очищен,служба/хост сохранены. Полный Q35 остаётся открытым,30/37 DONE. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**10 октября,F512/Q35-F010:** [Ложный PASS release-soak](../reports/audit-0.8.2/AUDIT-Q35-RELEASE-ADMISSION.md): пустые дочерние сценарии ранее давали PASS за0,064с; теперь обязательны восемь проверенных результатов, финальные счётчики10k/10k+3×1k и28800с.7Linux/Bash проверок PASS; own root удалён,служба сохранена. Фактический8ч прогон ещё открыт,Q35IN_PROGRESS30/37DONE.LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

**12 октября, перенос проверенного кандидата:** [wire pool и фактические результаты](../reports/BENCHMARK.md): при переносе 916 входов совпали с проверенной сборкой; затем только два явно проверенных изменения пробелов/переносов в одном файле для rustfmt, логика прежняя. Четыре строгих feature-профиля, 8+1 тестов PASS. 24 минутных AUTH-прогона / 34644 аутентификаций, пик RSS 336320 КиБ при прежнем лимите 524288; 20+4 составной результат, исходный отказ бюджета файлов и host differences сохранены. 12 новых native сессий /48 функциональных окон IPv4 TCP/UDP P1/P4. Исходники и CI warning gate перенесены. [Q35 endurance](../reports/audit-0.8.2/AUDIT-Q35-LONG-SOAK.md): пять ресурсных сценариев завершены, upload 6,8627%>5% FAIL, межсерверный этап NOT_RUN. Android: 23 JNI +2 packaged INI теста подтверждены на прежнем x86_64 native; исходные harness/signature/wlan0 отказы сохранены, полный VPN runtime не заявляется. Q30 DONE в согласованном объёме; итог31/37 (83,8%), остаются Q29/Q31/Q34/Q35/Q36/Q37. Native refresh, hosted CI, performance/cross-node и оставшиеся критерии этих шести разделов открыты. `NO_PUSH_DEPLOY_RELEASE`.

<!-- normative-sync: current-pool-native-20261012 -->

### 12 октября: платформенные библиотеки после исправления пула

[Результаты сборок и runtime-проверок](../../../release/certification/evidence/current-pool-native-20261012.json).
Для исходников `c0aad62a` выполнены две независимые сборки каждой из четырёх
библиотек: Android arm64/x86_64, Windows x64 и macOS universal2. Пары A/B
побайтно совпали, обе копии каждого артефакта обновлены; provenance и SHA256
проверены. На Android проверены точные 55 экспортов каждой ABI, на Windows
и в каждой архитектуре macOS — 33 C-экспорта. На Windows выполнены 22 C ABI
проверки; на Android API34 x86_64 — 23 JNI проверки и 2 теста INI из нового APK.

Новые instrumented Release/test APK и обычный unsigned Release содержат
актуальные обе Android ABI. Проверки R8 и упаковки прошли. Результаты 201 JVM
теста и lint переиспользованы после точного сравнения 679 входных файлов
с уже проверенным исправленным вариантом; это не новое выполнение JVM-тестов
через свежую native-библиотеку. Исходный отказ проверки wlan0 сохранён;
новый стенд дождался carrier (LOWER_UP/state UP) и завершения запуска интерфейса и прошёл строгую проверку
неизменности сетевого состояния. Исходный AVD, SDK и рабочие сервисы сохранены,
созданные для прогонов каталоги и временный swap удалены.

Исходный desktop worker FAIL сохранён: финальная проверка обнаружила только
пустой `.intentionally-empty-file.o`; все 327 входов совпали. Артефакты,
API и C ABI подтверждены из полного SHA-проверенного архива без пересборки.
На .10 сохранён host gate FAIL по iptables4/legacy4; рабочие сервисы и их
бинарные файлы остались прежними. Это не полный PASS состояния хоста.

Итог плана остаётся 31/37 (83,8%); открыты Q29/Q31/Q34/Q35/Q36/Q37.
Эти результаты закрывают обновление native-артефактов после правки пула.
Полный Android VPN data plane, пределы нагрузки, причина TCP-асимметрии,
upload-регрессия Q35 и межсерверный этап остаются вне данного PASS.
Физические Mac/Xcode/iOS, роутер и Windows VM исключены пользователем.
Полный релиз и hosted CI не подтверждены. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: отдельная проверка performance и cross-node

<!-- normative-sync: q35-bounded-performance-crossnode-20261012 -->

[Квалифицированные результаты](../../../release/certification/evidence/q35-bounded-performance-crossnode-20261012.json).
На .11 выполнены четыре заранее объявленные независимые проверки: performance
и cross-node для прежнего CLI `35da83fd` и актуального CLI `52511ceb` с исправлением
пула. Оба performance-прогона сохранили прежние три повтора по 20 секунд,
порог 5%, лимит 2 CPU и проверку upload/download/совокупного CPU. Скорости
перепроверены по исходным receiver-строкам iperf3 для каждого режима и направления,
медианы пересчитаны независимо. Ни один замер не исключён и не заменён повтором.

| Бинарник | Upload off / required, Мбит/с | Снижение upload | Download off / required, Мбит/с | CPU off / required, % | Performance: проваленные критерии | Cross-node |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| Прежний CLI | 515 / 518 | -0.5825% | 626 / 620 | 159.921 / 160.140 | PASS: — | 28 PASS / 0 FAIL |
| CLI с исправлением пула | 515 / 538 | -4.4660% | 615 / 624 | 160.560 / 163.601 | PASS: — | 28 PASS / 0 FAIL |

Cross-node здесь означает два независимых серверных процесса и реестра
в разных network namespaces на одной VM. Проверены отказ JOIN с чужим locator,
потеря основного carrier, переход клиента к полной AUTH, новый адрес и работа
туннеля второго процесса. Это не переключение между физическими серверами.

Исходный 13-часовой release gate остаётся FAIL: 6,8627% снижения upload при
лимите 5%. Сравнение off/required на одном бинарнике не является измерением
регрессии между версиями. Причина старого провала не установлена; эти новые
проверки не доказывают влияние правки пула или фоновой нагрузки. Пять завершённых
ресурсных сценариев не повторялись и принадлежат прежнему SHA. Полный 8-часовой
release gate на актуальном CLI этим пакетом не подтверждён.

Каждый вход и сохранённый файл проверен по SHA; наблюдаемые процессы работали
в private mount/net/PID namespaces. Службы, их PID/start ticks/бинарники и staged
CLI сохранены. Созданный каталог, удалённый архив и transient unit очищены.
Полное структурное сравнение всех backend хоста прошло.
Q35 остаётся IN_PROGRESS; итог плана 31/37 (83,8%), шесть разделов открыты.
Полный релиз и hosted CI не подтверждены. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: 20 Linux-критериев на CLI с исправлением пула

<!-- normative-sync: current-pool-linux-certification-20261012 -->

[Новые результаты и привязка к исходникам](../../../release/certification/evidence/current-pool-linux-matrix-20261012.json).
На .11 заново выполнены все обязательные автоматические Linux-сценарии на
CLI `52511ceb`: 19 самостоятельных запусков, 409 успешных утверждений,
без отказов; двадцатый критерий отсутствия утечек выведен из реальных проб
14 full/split случаев. Длительность — 595.0 с. Старые результаты
другого бинарника и даты их выполнения не переписаны.

Проверены 12 сочетаний outer/inner IPv4/IPv6 и TCP/UDP fake-TLS/UDP QUIC,
два dual-stack split tunnel, TAP с локальными NDP/RA, настоящие systemd-resolved
и DNS через IPv4/IPv6/принудительный TCP, DATA_FRAG/PMTU на MTU 1280 и ICMPv6 PTB,
совместимость с Qeli 0.7.16 в обоих направлениях, 100 переключений TCP и 100 QUIC.
Для каждого случая проверены команды, исходные журналы, итоговые утверждения,
SHA, отдельные mount/net/PID namespaces и нужные функциональные отметки.

Повторная компиляция не выполнялась: из 916 входов существующей квалифицированной
сборки совпали 915; в buffer_pool.rs заново проверены только две прежние явные
замены пробелов/переносов, без изменения логики, строк и комментариев.
Все 453 входа тестовой обвязки совпали. SHA ELF и legacy-клиента закреплены.
DNS-инструменты, зависимости и учётная запись уже присутствовали на .11;
установка или изменение службы не потребовались.

Все сохранённые файлы проверены по SHA. Структурные снимки всех backend хоста
до/после/после очистки совпали. Production PID/start ticks/бинарники, staged CLI,
DNS-инструменты, зависимости и passwd/group сохранены. Созданный каталог,
удалённый архив и transient unit удалены. Сертификат Linux связан с новым
результатом и проверенной применимостью последующих изменений только документации;
первоначальный source/time/raw этого запуска остаётся отдельным неизменным фактом.

Это закрывает устаревшую привязку 20 Linux-критериев после изменения пула.
Короткий 100+100 soak не заменяет восьмичасовой Q35 release gate.
Старый Q35 performance FAIL, Android SIGKILL/ENONET, полный Android VPN data plane,
hosted CI и остальные открытые критерии остаются за пределами этого PASS.
План: 31/37 (83,8%), Q29/Q31/Q34/Q35/Q36/Q37 открыты. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: порядок performance-замеров Q35

<!-- normative-sync: q35-performance-order-20261012 -->

[Исходные результаты и независимая проверка](../../../release/certification/evidence/q35-performance-order-20261012.json).
На .11 выполнены четыре заранее зафиксированных замера на прежнем CLI
`35da83fd`, в порядке off → required → required → off. В каждом режиме
остались три повтора по 20 секунд и прежний порог 5%; CPUQuota — 200%.
Все четыре функциональных сценария прошли (44 утверждений).
Это диагностические сравнения порядка, а не новый общий release gate.

| Order | Policy | Upload Mbps | Download Mbps | CPU % | Host steal % |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | off | 511 | 633 | 159.861 | 0.004 |
| 2 | required | 513 | 635 | 159.519 | 0.008 |
| 3 | required | 527 | 630 | 161.851 | 0.008 |
| 4 | off | 524 | 632 | 161.849 | 0.004 |

- off-first / required-second: upload -0.3914%, download -0.3160%; gates {"upload": true, "download": true, "cpu": true}; PASS.
- off-last / required-third: upload -0.5725%, download 0.3165%; gates {"upload": true, "download": true, "cpu": true}; PASS.

Из receiver-строк iperf3 независимо проверены все 24 результата; медианы и
оба сравнения пересчитаны. Наблюдение сохранило CPU steal, PSI, memory и cgroup
с доступными исходными счётчиками; новые результаты не заменяют старый отказ.
В private sysfs нет смонтированного cgroup filesystem: все cgroup-наблюдения
пусты. Throttling квоты и события memory cgroup этим прогоном не измерены.
Файлы и входы проверены по SHA, private namespaces подтверждены,
host gate до/после/после очистки PASS. Рабочие службы и staged CLI сохранены;
собственный каталог, удалённый архив и transient unit удалены.

В исходном 13-часовом прогоне оба performance-режима использовали новые пары
процессов; их PID/start ticks не пересекаются с ресурсным префиксом по 9395
снимкам. Performance helper не менялся. Поэтому FAIL 6,8627% не доказывает
замедление той же долгоживущей VPN-сессии. Старый сборщик не сохранял host CPU
steal/PSI/cgroup telemetry, и новый короткий тест не восстанавливает те условия.
Даже различие прямого и обратного порядка не устанавливает причину старого FAIL.
Порог не изменён; причина NOT_ESTABLISHED, оригинальный отказ сохранён.
Ресурсный 13-часовой префикс не повторяли.

Q35 IN_PROGRESS; полный 8-часовой gate на текущем CLI не подтверждён.
План остаётся 31/37 (83,8%), шесть разделов открыты. `NO_PUSH_DEPLOY_RELEASE`.

### 12 октября: Q37 завершён по пяти критериям

<!-- normative-sync: q37-five-criteria-closure-20261012 -->

[Матрица критериев и проверяемые доказательства](../../../release/certification/evidence/q37-closure-20261012.json).

| Критерий | Основание закрытия |
| --- | --- |
| Review и мёртвый код | 297 Rust-модулей / 306 связей; 59 диагностик четырёх Linux-профилей, 73 проверенных подавления. Удалены 41 retired body и лишние прямые зависимости; внешние API, JNI/C/Swift и RAII сохранены. Последующие изменения покрыты актуальными строгими профилями и native A/B. |
| Штатные, граничные и негативные сценарии | Сверены 84 клиентских поля, 134 server defaults и 176 reader keys; реальные INI admissions и исходные отрицательные случаи сохранены. Текущие 8 schema/docs/generated-adapter методов PASS. |
| Отказы и конкуренция | Текущие 4 admission-метода и 2 метода безопасного импорта 24 сценариев PASS; 5 настоящих Linux CI-fixture методов применимы по точным неизменным SHA runner/test. Пустые/неполные/skipped/expected-failure наборы не получают PASS, отказ дочерней команды сохраняется. |
| Интеграция и целевая платформа | Актуальные четыре native A/B, exports/provenance, 22 Windows C ABI, 23 Android JNI и 2 packaged INI; свежие 20 Linux-критериев / 409 проверок. Исключённые пользователем физические платформы не объявлены проверенными. |
| Исправления, повторная проверка и evidence | Исходные отказы F001–F013 и maintenance сохранены; 915/916 входов текущей CLI совпадают, единственный форматный delta отдельно доказан. Все текущие provenance/docs/version/source gates PASS; owned cleanup и исторические host FAIL сохранены. |

Финальная адресная проверка: 14 методов, без failures/errors/skips; provenance,
документация, версия и строгий Linux-сертификат прошли. Исходная обвязка ожидала
один import method вместо двух: сохранён её отказ по счётчику, оба реально
выполненных PASS квалифицированы из исходного лога без повторного запуска.
Прежние полные Rust suites, 149 Linux fixtures, native/JNI и сетевые прогоны
сохраняют исходные даты и SHA; новым выполнением они не названы.

Q37 закрывает документацию, достижимость, подключение и допуск тестов, а также
проверенную интеграцию изменённой обвязки. Полный Android VPN data plane,
SIGKILL recovery/ENONET относятся к Q29; hosted CI и выпуск — к Q34;
SDK/bootstrap — Q31; старый performance FAIL и полный endurance — Q35;
причина TCP-асимметрии и пределы нагрузки — Q36. Они остаются открытыми,
но не дублируются как неопределённый остаток Q37. Не утверждается, что все
возможные исполнения или все публичные API доказаны семантически достижимыми.

**Q37 DONE в согласованном объёме. Итог: 32/37 (86,5%), осталось 5 разделов:**
Q29/Q31/Q34/Q35/Q36. Полный аудит и релиз ещё не завершены.
Сетевые прогоны и большие сборки в этом пакете не повторялись;
новые кэши компиляции не создавались. `NO_PUSH_DEPLOY_RELEASE`.

<!-- q31-current-portable-20261012 -->

**12 октября, Q31-V013:** текущие ARM/MIPS и SDK client-only compile/packaging подтверждены; исправлены0664 права лицензий и устаревшие SDK/opkg assertions.54 scoped методов PASS,533 license files проверены. Сам ELF не менялся при исправленной установке/перепаковке. Own roots удалены, около3,6GiB освобождено, исходные сервисы сохранены. [Полный scope и остаток](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md). Q31:3/5 IN_PROGRESS; bootstrap resource-deferred, physical router USER_EXCLUDED. Полный32/37 (86,5%),5 открытых разделов.

<!-- q29-publication-contract-20261012 -->

Разобрана граница APPLIED/CONNECTED: первые sampled сокеты после APPLIED начаты до CONNECTED;8 отказов в окне и80/80 post-CONNECTED PASS в каждом из двух сохранённых прогонов. Вопрос трактовки закрыт, исходный FAIL_POST_PLAN_BLOCKING сохранён. Helper уже проверяет post-CONNECTED;6 методов PASS. Новые runtime/builds не выполнялись. SIGKILL/DNS compatibility FAIL и Q29 IN_PROGRESS сохраняются. [Q29](../reports/audit-0.8.2/AUDIT-Q29-ANDROID-CURRENT-VPN.md).32/37(86.5%),5 open.NO_PUSH_DEPLOY_RELEASE.
