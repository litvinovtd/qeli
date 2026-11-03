# Q06: пользователи и отзыв доступа — завершение

Дата: 3 октября 2026. **Q06: PASS; четыре пакета завершены.**

Исправления проверены на изолированном Linux release `fa6d2e9457575b63315a7e5fbcc3e342b448849814c0ebe7e9e98549ca8ce0cc`.
**Последняя квалификация — четвёртый пакет ниже: 387 Q06 checks.**
Конфигурации остаются INI. JSON используется только как служебное тело HTTP/control API.

## Подтверждённые ошибки и исправления

| ID | Ошибка | Итог |
| --- | --- | --- |
| Q06-F001 | Scalar/array/null вместо тела объекта снимали bandwidth/quota/expiry; неверные типы enabled/password/bandwidth принимались с успехом. Неверный profile в live bandwidth выбирал все профили. | Общая проверка объекта и строгие типы до hashing, блокировок и записи. Ошибочный запрос сохраняет точные прежние байты users INI. |
| Q06-F002 | Удаление файлового override возвращало inline-пользователя или прежнюю группу из server.conf. | Удаление любой записи, также определённой inline, отклоняется до мутации. Для пользователя доступно Disable; определения inline удаляются в server.conf. |
| Q06-F003 | Неверный тип route.gateway превращался в отсутствующий next hop. | Nullable строка проверяется строго; отсутствующее/null/пустое значение по-прежнему допустимо. |
| Q06-F004 | Delete, enabled=false через Edit и запрет профиля меняли базу, сохраняя рабочие TCP/UDP-сессии. | После успешного SIGHUP права применяются к открытым сессиям через существующий admission/kick/lease teardown. Sweep также перепроверяет текущие права, включая сессию, зарегистрированную после первоначального сканирования. |
| Q06-F005 | После сохранения bandwidth панель посылала второй persist-командный writer; он заменял явный burst_mbps CLI-дефолтом. | Панель сохраняет INI один раз; reload применяет эффективный limit_mbps к существующим сессиям, включая наследование от группы. |

До исправления реальный пакетный прогон воспроизвёл шесть продолжающих работать туннелей:
TCP и UDP × Edit disabled / Delete / profile restriction. Проверяется и список сессий,
и ICMP через клиентский TUN. Приватное INPUT DROP исключает ложный успех через внешний
интерфейс после исчезновения TUN. Disable отдельным endpoint и quota/expiry имели собственные проверки.

## Проверки

- 119 реальных HTTP/API checks PASS: строгие тела/типы, массивы ACL, предел u32, missing group,
  маршруты и семейства gateway, inline/file precedence, статические адреса и коллизии,
  очистка optional fields, quota/expiry, сохранение пароля и лимитов, share/QR.
- 57 checks PASS на реальных Linux TCP/UDP-клиентах: 12 сценариев отзыва доступа,
  fixed IP, group bandwidth 2 → 3 Mbps на живой сессии, expiry и seeded exhausted quota.
  Quota использует приватный usage sidecar с известным счётчиком, а не новый гигабайтный benchmark.
- 293 HTTP checks Q04 и 75 transaction checks Q05 PASS на том же новом release.
- 2263 Linux unit tests PASS, 60 ignored; pinned full/minimal Clippy и rustfmt PASS;
  116 JS-групп редакторов и panel checks PASS.
- Linux release matrix: 18 сценариев / 327 assertions PASS, host_restored=true.
  Свежий soak 100 TCP + 100 QUIC / 33 checks PASS; свежие desktop/Android native A/B,
  SHA256SUMS и provenance PASS. Все четыре клиентские библиотеки побайтно совпали с Q04.

API Users подтверждает сохранение и постановку reload в очередь. Это не синхронная
квитанция готовности авторизации worker. Стенд ждёт появления пользователя в read-only
worker control перед первой авторизацией, чтобы не смешивать проверку revoke с startup
race и brute-force lockout. Исторические ошибки обвязки сохранены отдельно от канонических результатов.

## Границы после первого пакета

Q06 ещё не закрыт: остаются UsersDb filesystem/lock/crash и конкурентные писатели,
актуальность inline auth в worker control, изменения live ACL/group restrictions,
несколько устройств и замена опасных legacy fixtures. `test_user_reload.py` и
`test_l3_user_limits.py` не запускались: они управляют общими службами/фиксированными путями.
`burst_mbps` сохраняется как legacy поле; отдельное burst enforcement data plane не подтверждено.
Новый benchmark и physical qualification не заявляются. Mac, роутер и Windows VM исключены пользователем.

Все новые сетевые проверки работают внутри NET/mount/PID namespaces. Рабочий qeli.service,
его PID/время запуска и бинарник сохранены; источник и все compilation inputs захешированы.
[План](../../plans/FULL-SYSTEM-AUDIT.md#06-пользователи-группы-и-выдача-доступа).

На desktop-стенде `.10` за время native-сборки появились три legacy firewall/NAT rules;
`host_restored=false` сохранён в raw evidence. PID/start и рабочий executable не менялись.
Источник изменений не установлен, firewall не восстанавливался. Это отклонение стенда
не выдано за PASS неизменности сети; desktop здесь подтверждает только A/B-артефакты.

[Итоговые свидетельства](../../../../release/certification/evidence/q06-users-access-20261003.json).

## Второй пакет: INI-хранилище и inline auth после SIGHUP

**PASS; общий Q06 остаётся IN_PROGRESS.** Новая сборка `dda3c71f6c51e356d3a123f853f64073570ac17ac9c1a21b805f79141ef91e78`.

**Q06-F006:** worker принимал новую базу при SIGHUP, но четыре persist-команды контрольного
сокета объединяли users.conf со стартовыми inline users/groups. Реальный baseline
воспроизвёл восстановление удалённого inline-аккаунта через enable-user и невозможность
отключить добавленный после reload аккаунт через disable-user. Исправление хранит
последнюю принятую auth-конфигурацию; её read lease удерживается до завершения
INI-транзакции и обновления live users. Reload меняет auth и базу под тем же порядком
блокировок. enable-user, disable-user, set-limit и set-bandwidth покрыты регрессией.

- Новый users-storage: 23 checks PASS. Восемь параллельных create без потерь; два
  независимых редактирования одного аккаунта сохраняют оба поля. Повреждённые INI
  (unknown key, плохое число, невалидный UTF-8), read-only storage и отказ rename
  сохраняют прежние байты; последующее штатное сохранение работает.
- API 119 и TCP/UDP live 57 повторно прошли на этой сборке: всего 199 Q06 checks.
- 2264 Linux units, 60 ignored; full/minimal Clippy, rustfmt PASS. Свежие 18/327
  release matrix и 100 TCP + 100 QUIC / 33 soak PASS.
- Свежие native A/B и ABI/provenance PASS; библиотеки побайтно прежние. На .11 сеть и служба сохранены. На .10 raw host_restored=false: первый снимок
  default iptables-save отличается от последующего, тогда как явные legacy/nft
  снимки и остальные поля неизменны. Повторные read-only запросы воспроизвели
  непоследовательность default dump; добавление новых правил в этом прогоне не
  доказано. Источник прежнего отклонения .10 остаётся не установленным.

Файловый пункт ещё не закрыт: нужны ENOSPC/EACCES, lock timeout, crash/durability
и семантика ошибки после опубликованной записи. Также остаются live ACL/groups,
несколько устройств и legacy burst. Наличие этих проверок не означает закрытие Q06.
[Свидетельства второго пакета](../../../../release/certification/evidence/q06-users-storage-20261003.json).

## Третий пакет: live-права и отказы публикации INI

**PASS; общий Q06 остаётся IN_PROGRESS.** Release `25a052afd351324b9fc2924035aac7cb998155d54ff6865a19a6448b99367e5c`.

Пять дефектов подтверждены на прежнем release: 12 отрицательных live checks и два
файловых отказа. Все соответствующие случаи проходят после исправления.

| ID | Ошибка | Исправление |
| --- | --- | --- |
| Q06-F007 | Сужение собственного или группового ACL оставляло прежние права сессии. | Изменение эффективных пакетных разрешений отзывает сессию. Порядок и дубли правил не влияют; собственный ACL перекрывает группу. |
| Q06-F008 | Удалённые client_subnets продолжали разрешать источник и удерживали iroute. | Отзыв через admission освобождает ingress, lease и маршруты старой сессии. |
| Q06-F009 | Снижение max_sessions не уменьшало число активных устройств. | На каждом профиле остаются самые новые устройства в пределах эффективного лимита; teardown проверяет session_id и не захватывает заменившую сессию. |
| Q06-F010 | Занятый users lock удерживал запрос без предела. | FileLock ограничен пятью секундами; отказ происходит до чтения/публикации кандидата. |
| Q06-F011 | После rename и отказа directory fsync ответ ложно обещал change NOT applied. | Типизированная ошибка публикации; API/control перечитывают INI. API запрашивает worker reload и отдельно сообщает published/reload_requested, сохраняя ok=false. |

315 Q06 checks PASS: 72 storage/durability, 67 policy, 119 API и 57 live.
Реальные TCP/UDP-пакеты проверяют ACL, делегированный source и три устройства;
снижение собственного/группового cap оставляет самое новое. Эквивалентный ACL и
изменение группы при собственном ACL сохраняют соединение. Проверены все восемь
API mutation paths и четыре control writers при fsync-отказе, readback worker,
реальные ENOSPC/EACCES, восстановление записи и crash до/после rename.

2265 Linux units PASS, 60 ignored; full/minimal Clippy и rustfmt PASS.
Свежие 18/327 release matrix, 100 TCP + 100 QUIC / 33 soak и 27 Q05 config-crash
checks PASS. Native A/B, ABI и provenance проверены заново; библиотеки обновлены
в canonical и клиентских копиях. Сеть, PID/start и рабочие binaries обеих лаб
сохранены. Прежнее отклонение firewall .10 остаётся исторически не атрибутированным.

Legacy test_user_reload.py/test_l3_user_limits.py теперь запускают только
изолированные пакеты с обязательными binary/SHA/output. Они не останавливают
общие службы. Новый L3 driver проверяет live metadata и cap, не заявляя throughput
benchmark. CONFIG/PANEL описывают burst_mbps как сохраняемое поле совместимости
без отдельного enforcement; прежнее обещание burst-запаса в CONFIG исправлено.

Файловые отказы и конкурентные writers закрыты в плане Q06. Остаются измерение
bandwidth, дополнительные admission-сценарии same-device/fixed-IP/profile и
отображение legacy burst в панели. Physical qualification и новый benchmark
не заявляются.

[Свидетельства третьего пакета](../../../../release/certification/evidence/q06-users-policy-durability-20261003.json).

## Четвёртый пакет: admission, bandwidth и завершение Q06

**PASS; Q06 завершён.** Финальный release `fa6d2e9457575b63315a7e5fbcc3e342b448849814c0ebe7e9e98549ca8ce0cc`.

| ID | Подтверждённая проблема | Исправление |
| --- | --- | --- |
| Q06-F012 | Замена same-device, fixed-IP или вытеснение по max_sessions закрывали транспорт без терминальной причины; автоматические reconnect повторно вытесняли победителя. TCP и UDP имели разные реализации. | Общий admission helper выбирает уникальных владельцев и самые старые устройства, доставляет `session_superseded` при ещё действующем владении, затем освобождает маршруты, carrier и lease. Modern management клиент прекращает retry; один бюджет 4 секунды на весь пакет. Legacy без ACK также отзывается по deadline, но может reconnect. |
| Q06-F013 | Панель показывала нулевой собственный bandwidth как отсутствие ограничения, игнорируя группу; legacy burst выглядел действующим контролем. | Отображается эффективный собственный/групповой cap, 0 наследует группу. Burst read-only с явной пометкой отсутствия enforcement; прежнее значение сохраняется при edit/save. |
| Q06-F014 | Share password reset после rename и отказа directory fsync не перечитывал опубликованный INI и не запрашивал reload. | Девятый API writer использует общий published-write recovery после освобождения DB lock; повторная выдача ссылки использует уже сохранённые credentials без нового reset. |

Финальная сборка: **387 Q06 checks PASS** — admission 35, bandwidth 33,
durability 76, policy 67, API 119, live 57. Проверены TCP/UDP same-device,
static IPv4, cap=1, устойчивость победителя 10 секунд, освобождение адреса,
два профиля, selective revoke и удаление пользователя во всех профилях.
Промежуточный TCP-only фикс не прошёл cap/UDP проверки и заменён общим helper.
Повторное использование source IP в admission fixture имеет отдельный повышенный
pre-auth budget; production rate limit не менялся.

Bandwidth измерен реальным iperf3 через TCP/UDP, по два параллельных потока,
3 секунды после 1 секунды warmup; upload/download имеют отдельные buckets.
Group=2 даёт 1.77–2.10 Mbps, own=1 — 0.92–1.05 Mbps; group=3 не перекрывает
own=1, own=0 наследует 3 (2.80 Mbps), group=0 возвращает unlimited.
Unlimited headroom превышает 5 Mbps; допуск cap 0.4–1.35 используется для короткого
функционального измерения. Это проверка enforcement, а не release benchmark.
Legacy burst=99 сохранён и не добавляет отдельного burst-запаса.

2265 Linux units PASS / 60 ignored, full/minimal Clippy и rustfmt PASS;
118 JS-групп и static panel PASS. Свежие 18 сценариев / 327 assertions,
aggregate leak и 100 TCP + 100 QUIC / 33 soak checks PASS на точном release fa6d2e9457575b63315a7e5fbcc3e342b448849814c0ebe7e9e98549ca8ce0cc.
Все четыре native cores прошли свежие A/B, ABI/provenance и побайтно совпали
с предыдущим пакетом; клиентские copies согласованы. CONFIG/PANEL и план RU/ENG
синхронизированы. Совместные службы и working binaries не заменялись.

На .11 полный снимок сети и служба сохранены. На .10 SDK A/B PASS,
но default IPv4 firewall dump отличается; повторные read-only снимки тоже дали
расхождения default/legacy dumps. Финальный SDK run сохранил nft, explicit legacy,
остальные поля, PID/start и deployed binary. Полный network-preservation PASS .10
не заявляется; прежнее отклонение firewall исторически не атрибутировано, правила
не удалялись и не восстанавливались. Это ограничение доказательства, не новый
подтверждённый defect Qeli. Завершённые debug binaries архивированы losslessly
с проверкой fa6d2e9457575b63315a7e5fbcc3e342b448849814c0ebe7e9e98549ca8ce0cc для освобождения места. Physical qualification не заявляется.

Все пять критериев Q06 закрыты в принятой области; следующих долгов Q06 нет.
Далее Q07: backup/restore/history с отдельной проверкой архивов и транзакций.

[Итоговые свидетельства](../../../../release/certification/evidence/q06-users-access-complete-20261003.json).
