# Q31: управление LuCI, публикация INI и ошибки firewall

<!-- normative-sync: q31-openwrt-controls-v50 -->

**Актуальный итог 15 октября: DONE в согласованном объёме; критерии и границы — в итоговом разделе ниже.**

**Актуальный checkpoint, 2026-10-15:** полный source LLVM/Rust bootstrap через Clang19 и следующий штатный SDK/IPK/opkg прогон квалифицированы. Q31 остаётся 3/5 IN_PROGRESS: public source pin и hosted release qualification открыты; physical router USER_EXCLUDED. Полный аудит34/37 (91,9%). Ранние результаты ниже сохраняют исходные даты и отказы.


6 октября 2026. Исправления продукта F307–F309 и сверка теста F310. Q31 переведён
из TODO в IN_PROGRESS; ни полный критерий, ни роутерный runtime не закрыты.
Всего28/37(75.7%),осталось9. Q29 SIGKILL FAIL/auto-null ENONET, исключённые Apple
запуски и callback-drain OPEN Q30, D06 ACCEPTED_LIMITATION сохранены.

## F307: команда службы выполнялась раньше применения UCI

Connect/Disconnect записывали `enabled` через `uci.save()`, вызывали службу и лишь
затем запускали модальное применение. Изменения UCI в сессии отличаются от
применённого конфига, который читает root init. Поэтому Connect отключённого
профиля мог ничего не сделать, а параллельные кнопки перемешивали старый start
и новый stop. Модальный помощник не предоставляет ожидаемый барьер commit.

Три кнопки теперь используют общую очередь Promise. Connect/Disconnect сохраняют
и ждут commit/подтверждение `uci.apply()` перед enable/start либо stop/disable.
Ошибка save/apply останавливает дальнейшие команды; следующий запрос после
ошибки работает. Restart ждёт очередь. Гарантия относится к одной открытой
странице, не к другим вкладкам/RPC-клиентам или сохранению формы. Ошибка службы
после commit не откатывает сохранённое намерение автозапуска и возвращается UI.
Как и прежнее применение, UCI apply может применить другие staged-пакеты.
Несохранённые поля формы сначала требуют Save & Apply.

Поведение сверено с первичными исходниками LuCI:
[UCI save/apply](https://openwrt.github.io/luci/jsapi/uci.js.html) и
[модальный changes.apply](https://openwrt.github.io/luci/jsapi/ui.js.html).
Семь Node-тестов выполняют настоящий модуль с управляемыми UCI/RPC Promise:
порядок commit, отключение, ошибки save/apply, восстановление очереди,
пересечение трёх команд, ошибка enable и неизвестная команда. Настоящие rpcd/procd
эти тесты не запускают.

## F308: ошибки синхронизации firewall скрывались

Live init игнорировал ошибки delete/add-list/set/commit/reload. Одного проброса
ошибки недостаточно: следующий запуск может увидеть staged-значения UCI и
ошибочно пропустить commit/reload. Перед изменениями теперь создаётся root-only
маркер tmpfs `firewall-pending`. Он сохраняется при ошибке и удаляется после
успешного commit/reload. Повторный запуск сверяет текущий желаемый dev и повторяет
незавершённые операции. Чистый no-op не делает commit/reload. Ошибка не допускает
создания procd instance; ошибка создания каталога состояния тоже возвращается.
Тесты не вызывали существующую службу firewall.

Это не транзакция с rollback: частично staged-изменения могут остаться до повтора,
другие администраторы и независимые init-процессы не блокируются. Одноразовые
install defaults и настоящий жизненный цикл fw4 остаются следующей частью Q31.

## F309: неполный INI заменял прежний конфиг

Генерация обнуляла живой файл и скрывала ранние ошибки записи. Некорректный MTU
из UCI мог исчезать вместо отказа, а выход за диапазон доходил до ядра. Теперь
создаётся соседний0600-файл tmpfs, записи проверяются, результат публикуется
атомарным rename. Обычная ошибка удаляет временный файл и сохраняет прежний INI.
MTU допускает десятичный0(auto) либо576..16602, как ядро/LuCI. Убийство процесса
может оставить0600-временный файл до reboot; уборка после SIGKILL и конкурентный
жизненный цикл не квалифицированы.

Пользовательские значения выводятся printf с фиксированным форматом. Обратные
слеши остаются буквальными; C0/DEL удаляются из несекретных INI-значений. CLI
секреты также отклоняют DEL, согласованно с rpcd. Исходный BusyBox уже сохранял
буквальные слеши: воспроизведённая escape-инъекция на OpenWrt не заявляется.
Printf также устраняет интерпретацию echo на других shell, например dash.
Пароль остаётся отдельным0600-файлом tmpfs; JSON-конфиги не добавлены.

Десять Python-тестов вызывают настоящие init-функции с mock UCI/firewall в новом
временном каталоге. BusyBox ash и dash PASS: генерация/DNS/router guard, безопасный
вывод значений, malformed/граничный MTU, ранняя ошибка записи/публикации,
секрет ровно4096байт и неверные секреты, no-op миграции, no-op firewall, пять
путей ошибки/повтора mutation/reload, namespace устройства. Ошибки исходного
BusyBox сохранены отдельно. Настоящий UCI parser OpenWrt, stdin RPC-секретов и
сетевой firewall этими тестами не подменяются. /etc, работающие службы, TUN и
management route не менялись; тесты выполнялись только в отдельном `/var/tmp`
каталоге лабы .11.

## F310: устаревшая проверка Android сломала gate рецептов

Набор37 тестов ожидал старую nullable-цепочку имени пользователя. Уже в базовом
коммите Android один раз захватывает `activeConfig`, проверяет stopping/null/
current core под monitor службы, затем логирует `logValue(config.username)`.
Перед исправлением тест и продукт совпадали с базовым коммитом: сбой появился
раньше Q31. Assertion обновлён на текущий захват/санитайзер; код Android не менялся.
Все37 тестов PASS. Это проверка исходника, не runtime-тест логирования и не новый
фикс Android.

## Границы и оставшаяся работа

Первично разобраны init renderer/live firewall sync, кнопки LuCI, ACL/rpcd транспорт
секретов, package defaults и точки входа роутерных сборок. ACL по-прежнему
ограничивает запись UCI пакетом qeli и собственными командами; service list доступен
только для чтения. RPC-секреты передаются stdin, не argv. Дополнительного удаления
кода этот пакет не обосновал; полный review/dead-code остаётся открытым.

Далее: ошибки install/upgrade и rollback, кэш UI-статуса/несохранённая форма,
межпроцессные гонки секретов/службы, ошибки/provenance build-helper и доступные
cross-build проверки. Артефакты сейчас не пересобирались; реализация Rust/native/
Android/Apple/Windows клиентов не менялась. Реальные роутерные WAN renewal/reboot,
память/throughput и сетевой runtime USER_EXCLUDED; cross-build не будет называться
квалификацией устройства.

Документация/bindings/diff проверяются вместе с fixtures. Исторические статусы,
артефакты, даты и acceptance_basis Linux-кейсов сохранены; source digest обновлён
только с отдельным ограниченным supplement этого изменения.

Raw packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-controls-20261006.
Evidence: release/certification/evidence/q31-openwrt-controls-20261006.json.

## F311: ошибки подготовки и восстановления manifest обходили cleanup

Команды toolchain скрывали ошибки rustup через tail/true; exit Zig тоже игнорировался.
Оба скрипта теперь проверяют каждую команду и inventory cargo-zigbuild0.23.0. Nightly/
rust-src готовятся только для выбранного MIPS; другим аркам лишний nightly не ставится.
Cargo использует --locked. Неизвестная архитектура, лишний аргумент и неизвестный флаг
отклоняются до SSH: опечатка больше не запускает все сборки. Rolling nightly/stable
этим не закреплены; reproducibility, ABI и текущая поддержка MIPS не квалифицированы.

Всё время жизни подключения теперь покрыто finally-close. Backup прерванной сборки
восстанавливается до --sync: поздний restore больше не заменяет новый загруженный
Cargo.toml прежней версией. После успешного ограничения crate-type manifest
восстанавливается; даже ошибка восстановления не пропускает закрытие соединения.
SFTP закрывается при сбое put/inventory; ошибки cleanup/mkdir пробрасываются,
Cargo.toml/Cargo.lock обязательны. Sync ещё не атомарный и не точный: удалённые
remote modules, .cargo/config.toml, параллельная работа в общем checkout и полная
source provenance остаются OPEN.

## F312: ошибка скачивания не мешала KEENETIC_BUILD PASS

Keenetic pull проглатывал IOError, оставляя результат сборки0. Исходный main
воспроизведён с отказом скачивания: exit0 и PASS. Ошибка подготовки также оставляла
SSH открытым, а ошибки toolchain не возвращались вызывающему коду. Исправленный
main даёт1 при отказе скачивания, закрывает соединение и отклоняет ошибку подготовки.
Оба скрипта используют общий проверяемый атомарный transfer native_lab: SHA256
получается по strict SSH, скачанные байты проверяются до замены файла. Пустой digest
отклоняется до скачивания/публикации. Ошибка чтения, несовпадающий payload и пустой
артефакт сохраняют прежний локальный файл. Ошибка одной арки отмечается, остальные
выбранные арки продолжают работу. Это идентичность передачи, не ELF/ABI/device/
reproducibility attestation. Реальные бинарники не собирались и не публиковались.

Четырнадцать исполняемых Python-тестов загружают оба настоящих скрипта с mock
SSH/SFTP/toolchain: CLI, ошибки toolchain/pin, non-MIPS, manifest/sync order, cleanup,
ошибки отдельных арок, публикация проверенных артефактов и --locked команды. PASS;
воспроизведения исходных ошибок сохранены отдельно. Mock не выдаётся за настоящую
успешную установку toolchain.

## F313: повторный LuCI load читал прежний enabled из кэша

uci.load кэширует пакет: повторный опрос не видел внешних изменений, а unload
уничтожил бы staged-правки формы. Новый read-only service_status RPC вызывает
status_enabled собственного init. Команда читает root UCI, используемый запуском
службы, а не браузерный/сессионный кэш формы. Root CLI deltas могут быть видимы до
commit: это init-visible намерение, а не строгое чтение только применённого файла.
Опрос не делает load/unload формы. Exit0/1 означают enabled/disabled; ошибка load,
отсутствующая служба или неверный RPC дают unknown с явным сообщением. Read ACL
разрешает только service_status; управление и запись секретов остаются write ACL.
Liveness процесса по-прежнему берётся из procd и не означает аутентифицированную
сетевую связность.

Девять LuCI caller fixtures и один status/ACL adapter fixture PASS. Последний
разбирает совместимый adapter в JavaScript с mock system/fs, не интерпретатором
ucode; реальные ucode/rpcd и rc.common dispatch NOT_RUN. Новый init-status case
вместе с прежними сценариями даёт11 тестов для каждого BusyBox ash/dash: оба PASS
в отдельном каталоге .11. Первичные источники:
[кэш LuCI](https://openwrt.github.io/luci/jsapi/uci.js.html),
[exit-коды ucode system](https://ucode-lang.org/module-core.html).

Текущий пакет F311–F313: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-router-build-failures-20261006.
Evidence: release/certification/evidence/q31-router-build-failures-20261006.json.
Прежний packet/seal не менялся. Install defaults/upgrade rollback, полный source
review, гонки секретов/службы и настоящие доступные cross-build остаются OPEN.
Следующая проверка установки должна разобрать прерванное создание и ошибки reload;
одноразовый defaults ещё не квалифицирован тестами live sync. Q31 IN_PROGRESS,
всего28/37(75.7%),осталось9.


## F314: прерванные firewall defaults выдавали успешную установку

Скрипт первой установки игнорировал ошибки отдельных UCI-команд и reload, затем
выходил с0. Если успело появиться лишь имя зоны qeli, следующий запуск видел его и
пропускал восстановление. Baseline fixtures воспроизводят exit0 после ошибок
commit/reload/input: зона не сохраняется при отказе commit, reload не повторяется,
ошибка input оставляет неполную зону. Это shell/UCI model, не настоящие libuci/fw4.

Теперь проверяются load, каждая мутация, commit и reload работающей службы. Перед
изменением создаётся0600 pending marker в0700 tmpfs-каталоге; зона и forwarding
имеют фиксированные package-owned имена. Повтор завершает только собственные
секции, заменяя device list без дубликатов. Существующая зона администратора
сохраняется; collision зарезервированного имени, чужое pending ownership, несколько
зон qeli и неправильный device останавливают мутации. Подготовка образа без службы
firewall допустима. Пока существует firewall-install-pending, init запрещает live
sync/start и указывает повторить /etc/uci-defaults/99-qeli-firewall.

Это восстановление установки, не автоматический rollback или interprocess
transaction. Root CLI staged deltas, конкуренция, process death и reboot моделью не
квалифицированы. Tmpfs marker не переживает boot; частичные изменения требуют
устранить причину ошибки и повторить defaults. Девять новых installation cases и12
init cases PASS отдельно в BusyBox ash и dash на .11. Пути и службы перенаправлены
в temporary fixtures; настоящие /etc/firewall/службы не менялись.

## F315: --sync оставлял удалённые исходники и старый Cargo config

Оба helper удаляли только src/bin, остальные файлы загружались поверх старых.
Удалённый локально модуль оставался на сервере, .cargo/config.toml не обновлялся.
Оба baseline helper воспроизводят эти stale inputs. Общий router_source вызывает
существующий native_lab sync: заменить src/.cargo, загрузить текущие config/assets/
исходники/Cargo.toml/Cargo.lock, сохранить target cache. Обязательные локальные
входы проверяются до первого изменения удалённого checkout.

0600 .router-sync-incomplete появляется до замены и удаляется только после всех
uploads и успешного SFTP close. Оба helper проверяют его до toolchain/build, включая
следующий запуск без --sync. Ошибки open/transfer/close/remote command сохраняют
marker; успешный --sync восстанавливает управляемые входы. Семь real-shell/filesystem
adapter tests PASS в Linux temporary roots,14 router helper fault tests и12
неизменённых shared native-lab tests PASS. Повтор удаляет stale inputs, сохраняет
кэш; отсутствие локальных файлов не вызывает remote commands. Старый hardcoded
cleanup воспроизводится ограниченным адаптером, без изменений настоящего /opt.

Замена не атомарна и не имеет cross-process lock. Без --sync старый checkout без
marker по-прежнему используется намеренно. Конкурирующие процессы, изменяемый
локальный snapshot, полная provenance, воспроизводимость, ELF/ABI и свежая настоящая
cross-build не подтверждены. Текущий Cargo config scope: один .cargo/config.toml.
Первый baseline attempt с отсутствующим Paramiko в Linux fixture сохранён как FAIL;
source-only импорт исправлен lab stub с запретом соединения, пакеты не устанавливались.

Пакет F314–F315: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-install-source-sync-20261006.
Evidence: release/certification/evidence/q31-install-source-sync-20261006.json.
Также PASS37 native recipe checks,10 Node caller/adapter cases, docs/bindings/diff.
Настоящие libuci/fw4/procd/ucode/rpcd/package install и cross-build NOT_RUN; router
runtime USER_EXCLUDED. Старые seals/runtime statuses/artifacts/dates/acceptance_basis
сохранены. Полные upgrade/rollback, lifecycle/secret races между процессами, широкий
review и настоящая build qualification OPEN. Q31 IN_PROGRESS,28/37(75.7%),9 осталось.

## F316–F318: ошибки удаления, миграции и загрузки UCI

clear_secrets сообщал успех после ошибки rm. RPC clear_secret игнорировал null,
возвращаемый fs.unlink при ошибке, и всегда выдавал result=true. CLI теперь
передаёт отказ, включая частичное удаление all; отсутствующий файл удаляется
идемпотентно. RPC проверяет два буквальных имени, делегирует init owner и выдаёт
result=false при ненулевом/неправильном результате команды. Compatible Node fixture
воспроизводит ложный успех с documented null; настоящий ucode не исполняется.
[Первичный контракт fs.unlink](https://ucode-lang.org/module-fs.html#unlink).
Удаление сохранённого файла не останавливает работающий VPN и не стирает уже
загруженные клиентом/отрендеренным obfs-конфигом копии; смена применяется restart.

Legacy migration удаляла staged UCI options до commit. После отказа commit повтор
видел отсутствие опций и возвращал0, хотя старые секреты оставались на постоянном
хранилище. Теперь0600 secret-migration-pending создаётся до staged delete и
сохраняется при отказе. Повтор делает commit даже без staged legacy options;
ошибка удаления marker сохраняет намерение повторить. Значение читается один раз,
непустой текущий runtime secret сохраняется, копирование идёт до удаления; пустые
legacy values также очищаются. Проверены copy/marker/delete/commit/remove failures.
Marker tmpfs: crash/reboot transaction и secure flash erase не подтверждены.
После миграции нужно сменить старые credentials, как было указано ранее.

Оба config_load qeli при старте, загрузка firewall и восстановление qeli context
теперь явно запрещают admission при отказе. Несколько зон qeli отвергаются до
мутации вместо выбора последней. Валидное отсутствие зоны допустимо по-прежнему.
Baseline model probes в обоих interpreter воспроизводят ложный успех clear/load/
ambiguous zone и сохранение persistent credentials после migration retry.

## F319: rc.common скрывал ошибку callback от сервисной команды

Сверка сохранённого [upstream rc.common](https://raw.githubusercontent.com/openwrt/openwrt/master/package/base-files/files/etc/rc.common)
показала: rc_procd вызывает callback, закрывает сервисное сообщение, а start/stop
затем вызывают optional hooks; иначе callback result теряется. Сохранённый dispatcher
с fixture-only lib/functions/procd adapters воспроизводит callback failure при CLI
exit0. Для отделения этого дефекта использован промежуточный F316–F318 source до
hooks, сохранённый отдельно от Git baseline.

Init owner теперь удерживает preparation/cleanup status и возвращает его через
стандартные service_started/service_stopped hooks. После ошибки stop cleanup
запрос procd_kill сохраняется, но последующая подготовка start внутри того же
restart/reload запрещается. Валидный disabled start успешен. Это callback results,
не проверка ubus publication/delete failure, daemon acceptance, native join или
VPN connectivity. flock/admission настоящей procd library только source-reviewed;
собственный механизм блокировок не добавлялся.

Пять saved-dispatcher cases,23 init и9 installation cases дают37 PASS отдельно в
BusyBox ash/dash на .11. Snapshot зафиксирован bytes/hash; тестам нужен явный путь
QELI_OPENWRT_RC_COMMON_FIXTURE, без него skip. Пути/adapters temporary-only: реальные
/etc/firewall/rc.d/daemons не менялись. Два hook cases и9 предшествующих init cases
новые.11 Node fixtures PASS, включая новый compatible RPC clear case. Также PASS
37 native recipes, docs/bindings/diff.

Пакет F316–F319: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-secrets-upgrade-20261006.
Evidence: release/certification/evidence/q31-secrets-upgrade-20261006.json.
Настоящие libuci/fw4/procd/ucode/rpcd/opkg и cross-build NOT_RUN; router USER_EXCLUDED.
Полные package upgrade/rollback, interprocess/daemon failure/lifecycle, широкий
review и build provenance OPEN. Предыдущие seals/runtime statuses/artifacts/dates/
acceptance_basis и Q29/Q30/D06 observations сохранены. Q31 IN_PROGRESS,28/37(75.7%),9 осталось.

## F320: установщик Keenetic искал старые артефакты и скрывал отказ зависимостей

Build helper публикует qeli-client-keenetic-aarch64/mipsel, а установщик искал
только qeli-client-aarch64/mipsel: canonical-only bundle не устанавливался.
Обязательный opkg install ip-full/iptables имел ||true, поэтому после отказа
подготовки установщик публиковал клиент и сообщал готовность. Оба поведения
воспроизведены на исходном Git source с изолированными command models. Инструкции
теперь указывают canonical artifacts и --sync; старые ручные имена поддерживаются
как fallback, canonical имеет приоритет.

До dependency changes проверяются непустые binary/init/new-config inputs. Ошибки
обязательных update/install передаются вызывающему, проверяется наличие ip/iptables;
отказ необязательного ip6tables даёт явное предупреждение. Копии binary/init/config
готовятся до публикации; обычные temporary files убираются при выходе, каждый файл
публикуется sibling rename. Existing INI content сохранён, mode ограничен0600,
credential directory0700. Copy/preparation failure сохраняет старые binary/init.
Publication failure может оставить частичный bundle: несколько rename не являются
транзакцией; нужно устранить ошибку и повторить установку. Автоматический restart,
concurrent-installer lock, fsync/power-loss и настоящие architecture/ELF/opkg проверки
не заявляются.

Одиннадцать installer cases: canonical/legacy names, обе архитектуры выбора,
existing config, required/optional dependency errors, missing command, incomplete
bundle/unsupported arch, copy failure и publication retry. Артефакты — маленькие
fixture files, VPN binary не запускается. Первый baseline attempt использовал
ambient PATH и завершился harness FAIL, запись сохранена. В final fixtures PATH
ограничен для обоих source; lab inventory подтверждает отсутствие настоящего opkg.

## F321: OpkgTun игнорировал ошибки ndm и смешивал чтения NetworkPlan

Каждая ndmc mutation продолжалась после отказа, затем выполнялся save и выводилось
interface up. Original-source model injection воспроизводит exit0/up/save после
неудачного ip global. Теперь проверяются все L3/configuration-save mutations;
отказ возвращается вызывающему, выводится retry required, ложный up не печатается.
Перед первой mutation создаётся pending checkpoint0600, который удаляется только
после успешного save. При повторе незавершённого apply address-only no-op обходится,
даже если ndm уже показывает matching connected addresses. Ошибки создания/удаления
checkpoint не дают сообщить completion; это не cross-process lock или fsync transaction.
Ранее успешные изменения ndm не откатываются автоматически: устранить причину,
повторить hook или manual registration, проверяя результат каждой команды.
Отсутствующий interface/plan по-прежнему даёт0 с диагностикой ожидания, без up.

Interface marker теперь требует opkgtun + непустой только десятичный suffix,
максимум15 символов. Старый glob принимал opkgtun0garbage, что доходило до ndm в
модели. Неправильный marker не вызывает ndm commands. Это исправление локальной
грамматики, не доказанный server-to-ndm exploit. План читается одним снимком, все
IPv4/IPv6/MTU извлекаются из него. Принудительная замена после первого чтения
воспроизвела old IPv4 из A при IPv6/MTU из B; corrected команды используют только A.
Это не сериализация concurrent stop, не generation ownership и не второй полный
клиентский parser NetworkPlan.

Девять hook cases: dual-stack apply, все девять mutation failures/connected retry,
ошибки создания/удаления checkpoint, invalid marker,
missing plan/interface, existing address no-op и forced replacement. Старые optimistic
address/status idempotence, MTU-only updates, process ownership/join, legacy NAT/sysctl
recovery и wan.d concurrency OPEN. Настоящие ndmc error/status output, event recursion,
ndm rollback и firmware compatibility не квалифицированы. Настоящие network/proc/sys/
службы роутера не менялись.

Пакет F320–F321: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-install-hook-20261006.
Evidence: release/certification/evidence/q31-keenetic-install-hook-20261006.json.
20 cases на BusyBox ash/dash PASS в .11 temporary roots с подставными /opt/PATH/
opkg/ndmc. Также PASS37 native recipes/docs/bindings/diff; native implementation,
OpenWrt adapters и build helpers неизменны. Настоящие opkg/ndm/cross-build NOT_RUN;
routers USER_EXCLUDED. Предыдущие seals/runtime statuses/artifacts/dates/acceptance_basis
и Q29/Q30/D06 observations сохранены. Q31 IN_PROGRESS,28/37(75.7%),9 осталось.

## F322: снимок forwarding и ошибка восстановления теряли состояние для повтора

Оба init-шаблона Keenetic записывали непроверенный снимок прямо в конечный файл.
Ошибка чтения sysctl могла превратиться в пустое сохранённое значение, а функция
сохранения всё равно возвращала успех. Ошибка запроса WAN-маршрута скрывалась
pipeline. Восстановление игнорировало ошибки записи и удаляло checkpoint даже при
незавершённой очистке. Сравнение старого и исправленного кода воспроизводит эти
случаи на моделях. Проверка ошибки чтения вызывает функцию сохранения отдельно:
старый nat_up впоследствии падал на записи, уже успев создать некорректный снимок.

Теперь оба шаблона проверяют чтение, допустимые значения sysctl и результат запроса
WAN, затем публикуют checkpoint0600 переименованием соседнего временного файла.
Читаются только согласованные семейства: IPv4-only plan не требует IPv6 sysctl/WAN
query, IPv6-only plan не требует IPv4 sysctl/iptables. Checkpoint version2 хранит исходные
значения, имена TUN/LAN и семейства и RA, отмеченные до изменения. Применение отклоняет
состояние для других интерфейсов. Восстановление проверяет сохранённые поля, меняет
только отмеченные семейства и проверяет чтение/запись. После ошибки checkpoint
остаётся для повтора; удаляется только после успешного восстановления. Значения,
изменённые с установленных шаблоном1/2 на другие, сохраняются; изменения администратором
на те же значения отличить невозможно. Это не межпроцессная блокировка, fsync/
power-loss transaction или владение глобальными kernel sysctl.

## F323: legacy-очистка удаляла правила администратора и скрывала отказы

Старые правила не имели тега владельца: nat_up использовал совпадающее правило
администратора, а nat_down удалял его. Ошибки firewall игнорировались, после чего
сохранённое состояние могло удалиться. Смена GATEWAY/OPKGTUN полностью пропускала
восстановление. Original-source модели воспроизводят удаление совпадающих admin
rules, ложное завершение после ошибки delete/check, оставшийся checkpoint после
смены режима и переход restart к start после незавершённого восстановления.

Новые правила получают comment qeli-keenetic-legacy. Проверяемые add/delete helpers
отличают модельный check status1 (правило отсутствует) от более высоких кодов ошибки;
ошибки add/delete возвращаются вызывающему. Удаляются только правила с тегом для
отмеченных семейств и сохранённых интерфейсов. Checkpoint определяет необходимость
восстановления даже после смены GATEWAY/OPKGTUN/TUN/LAN; без него правила не удаляются.
После частичной очистки состояние сохраняется для повтора. Start отклоняет неудачное
восстановление до очистки плана и запуска; stop/restart передают отказ очистки.
Новому legacy-режиму требуется iptables comment capability; настоящие Entware/kernel
и особенности кодов ошибки NOT_RUN.

Versionless/unknown старый checkpoint блокирует автоматическую очистку и сохраняется
для ручной сверки. Перед заменой работающего legacy-шаблона остановить его старым
скриптом и проверить правила/sysctl. Если checkpoint остался, сохранить исходные
значения и установить владельца старых правил перед ручным восстановлением.
Не удалять состояние как автоматическую миграцию: новый код намеренно не угадывает
владельца старых нетегированных правил. На реальном роутере такая миграция не проводилась.

По22 изолированных state cases на каждый шаблон (44 новых): capture/publication,
WAN failure, family/interface admission, journal failures, точное совпадение admin
rules, повторное применение, check/add/delete/missing-command failures и retry,
ошибки чтения/записи восстановления, corrupt/old checkpoints, смена режима и gating
start/stop/restart через настоящий dispatcher шаблона. Вместе с20 предыдущими cases
установщика/хука64 теста на BusyBox ash/dash PASS. Общие блоки функций обоих шаблонов
сверены на идентичность. Proc/sys заменены файлами, firewall/ip — модели, все возможные
сигналы перехвачены. Настоящие процесс клиента, kernel forwarding/firewall и служба
роутера не запускались. Начальные fixture TUN expectation FAIL и reproduction-scope
assertion FAIL сохранены с объяснениями; финальное сравнение использует одинаковую
исправленную изоляцию для обоих исходников. Native recipes37/docs/bindings/diff PASS.

Пакет F322–F323: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-forwarding-state-20261006.
Evidence: release/certification/evidence/q31-keenetic-forwarding-state-20261006.json.
Настоящие router/iptables/comment module/sysctl runtime и cross-build NOT_RUN;
router USER_EXCLUDED. PID identity, TERM/join ordering, мгновенный отказ запуска,
INI/core semantic parity, OpkgTun idempotence/concurrency и широкий build/source
review остаются OPEN. Предыдущие runtime statuses/artifacts/dates/acceptance_basis
и Q29/Q30/D06 observations сохранены. Q31 IN_PROGRESS,28/37(75.7%),9 осталось.

## F324: PID-файл мог направить сигнал чужому процессу или группе

Оба init-шаблона доверяли cat(PIDFILE) и kill -0/kill без проверки процесса. Старый
скрипт принимал и завершал специально созданный sleep victim по устаревшему PID.
Неверный PID0 доходил до попытки группового сигнала; в этом сравнении kill всегда
перехватывался, групповой сигнал не посылался.

Новый приватный PID record содержит десятичный PID и время старта из Linux proc в
тиках. Перед приёмом процесса/сигналом проверяются оба значения, точный формат,
положительный не-системный PID и executable identity. Суффикс deleted после замены
бинарника допускается для исходного процесса. Start ticks отличают повторно выданный
PID в пределах одной загрузки; пробелы/скобки в comm не ломают stat parser. Corrupt/legacy single-PID records,
чужой executable и неверные ticks блокируют start/stop и сохраняют состояние для
сверки. Status:0 live,3 stopped,4 unverified. Это best-effort shell/proc checks:
окно между проверкой и kill не закрыто атомарно через pidfd. Interprocess locking,
PID namespace/reboot identity и настоящий router proc/readlink не квалифицированы;
атомарная защита PID identity не заявляется.

PID публикуется файлом0600 через соседний временный файл и rename. При отказе
известный запущенный процесс завершается с ожиданием, если identity подтверждена.
Если termination/publication не закончены, pending record остаётся, start/stop
отказывают до ручной сверки. Установщик теперь отклоняет существующий PID/pending
record до зависимостей/замены файлов: сначала остановить установленный шаблон и
проверить завершение. Старый single-PID формат автоматически не мигрирует. Ошибка
proc-read после запуска может оставить неполный pending record и напечатанный PID;
не удалять его и не запускать новую генерацию вслепую.

## F325: после TERM сеть очищалась до выхода, ошибка запуска выглядела успехом

Старый stop выполнял compatibility cleanup до TERM, сразу удалял PID/plan и TUN без
ожидания. EXIT native helper с задержкой видел уже удалённые файлы; игнорируемый TERM
давал успешный stop и забытое состояние. Старый core-managed start сообщал успех при
мгновенном выходе executable или PID path, являющемся каталогом. Старый unwind после
NAT failure также очищал до выхода helper. Безопасное original/current сравнение
воспроизводит каждый случай.

Теперь оба шаблона требуют executable/config/readlink, проверяют каталоги, восстанавливают
старое compatibility state, готовят/публикуют record и проверяют post-exec liveness.
Это process admission, не подтверждение authenticated NetworkPlan readiness для
core-managed/OpkgTun старта. TERM адресуется проверенному процессу с ожиданием выхода
до15 итераций по одной секунде. Matching zombie считается завершившимся: это наблюдение
выхода, не waitpid reaping процесса, созданного другой оболочкой. Signal/identity/
timeout failure сохраняет PID/plan/marker и пропускает network cleanup; restart не
запускает новый клиент. После выхода выполняется compatibility recovery, затем
проверяемое удаление plan/markers/PID. Ошибки startup plan/NAT/marker проходят через
тот же joined stop. PID-removal/cleanup failure допускает повтор.

Шаблон больше не выполняет ip link del: временем жизни TUN управляют kernel/core/ndm,
нельзя вслепую удалять persistent или повторно используемый интерфейс. Это не новое
подтверждение настоящего Qeli thread drain, kill-switch lifetime или connectivity.
Точные wall-clock deadlines, SIGKILL/power loss, одновременно работающий wan.d handler
и все service/admin операции под межпроцессной блокировкой остаются OPEN.

Linux native test executable: process-fixture.c в raw packet, однократная сборка cc
с сохранённым hash; release-бинарник Qeli не пересобирался.43 native-process cases
(21 base,22 OpkgTun),44 state-file models и21 installer/hook cases: всего108 на
BusyBox ash/dash PASS;44 новых, включая installer upgrade gate. Helper публикует
подставной plan, задерживает выход или игнорирует TERM. Уникальный per-test executable
и отдельно созданные sleep children ограничивают цели сигналов/очистки. Network
callbacks подменены; настоящий kernel network/firewall/router service не менялся.
Polling сокращён до3*50ms (startup50ms, plan timeout2 polls): проверяет control flow,
не production15-second duration. Старые state fixtures теперь моделируют proc и
имеют executable/readlink, чтобы проверять stale-recovery admission с новым форматом.
Сохранён начальный original-source harness assertion FAIL: выбор первого nat_up
добавлял новый lifecycle code. Исправленный воспроизводитель добавляет только
последние fixture callbacks, оставляя старую реализацию. Invalid/group PID scenario
всегда моделирует сигналы, не посылает групповой сигнал.
Native recipes37/docs/bindings/diff PASS; настоящий router/core-OS integration NOT_RUN.

Пакет F324–F325: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-process-lifecycle-20261006.
Evidence: release/certification/evidence/q31-keenetic-process-lifecycle-20261006.json.
INI/core semantic parity, OpkgTun idempotence/generation/concurrency, packaging и
широкий source/build ABI/provenance остаются OPEN. Предыдущие runtime statuses/artifacts/
dates/acceptance_basis и Q29/Q30/D06 observations сохранены. Router USER_EXCLUDED;
Q31 IN_PROGRESS,28/37(75.7%),9 осталось.

## F326: OpkgTun пропускал изменение MTU и незавершённую настройку

Connected и совпадение подстроки адреса не подтверждали полное применение плана.
Сравнение старого/нового исходника воспроизводит пропуск изменения MTU, принятие
IPv4 .20 вместо .2 и строк с подстановками регулярного выражения, IPv6 ::20 вместо
::2, а также тихий выход без текущего плана. Совпавшие адреса сами по себе не
подтверждают успешные global/MSS/security/save.

Теперь для пропуска команд нужна приватная запись qeli.opkgtun.applied с точным
именем интерфейса и полным снимком плана. Файл0600 публикуется через соседний
временный файл и rename после всех успешных команд и save. Нет записи или план
изменился — настройка повторяется. Изменение только MTU применяется, следующее
событие при совпадении становится no-op. Connected и адреса сравниваются буквально,
проверяется код show. Пустой план не допускает no-op. Ошибка публикации записи или
удаления pending сохраняет повторную попытку и не сообщает успех. Stop удаляет
запись после завершения клиента.

Запись подтверждает выполненные команды, а не поколение клиента, блокировку или
чтение всех параметров ndm. Внешние изменения MTU/MSS/security, устаревший обработчик
после stop, удаление семейства адресов, эквивалентная запись IPv6 и формат/события
реальной прошивки остаются непроверенными. Команды удаления адресов для прошивки
не придумываются. Согласованность одного снимка сохранена; он не обязательно
последний при параллельном обновлении плана.

## F327: завершение между чтением proc stat и executable принималось за смену владельца

После stat живой процесс может стать zombie до readlink(exe): proc ещё существует,
а executable уже недоступен. Старый код возвращал unverified вместо exited и
сохранял состояние после успешного завершения. Детерминированный тест удерживает
zombie собственного прямого дочернего процесса до waitpid и воспроизводит ошибку
обоих init-шаблонов. Отдельно проверен отказ сигналить живой процесс с недоступным exe.

При отказе чтения exe оба шаблона повторно читают stat и принимают Z/X только при
совпадении start ticks. Живой, недоступный, заменённый или непроверенный процесс
по-прежнему отвергается; исчезнувший proc считается завершённым. Общая гонка между
проверкой и сигналом этим не закрывается, pidfd-защита не заявляется.

Итог:120 проверок на каждом BusyBox ash/dash PASS:43 прежних native-process плюс
четыре новых race/live-exe,44 модели состояния,12 installer,17 hook. Восемь hook
тестов новые. Семь методов сравнения hook воспроизводят восемь старых assertion
failures с subtests; новая версия PASS. Детерминированная старая гонка FAIL дважды,
исправление и unreadable-live PASS в обеих оболочках. Первый dash suite FAIL сохранён,
точная причина в том прогоне не инструментировалась. Первый orphan diagnostic не
воспроизвёл гонку из-за reaping PID1; квалификация прямого child записана отдельно.
Native recipes37/docs/bindings/diff PASS. Команды/файлы и network callbacks — модели;
реальны только собственные Linux helper processes. Helper unchanged от F324/F325,
Qeli/router binary не пересобирались. Router USER_EXCLUDED, cross-build NOT_RUN.

Пакет F326–F327: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-opkgtun-receipt-20261006.
Evidence: release/certification/evidence/q31-keenetic-opkgtun-receipt-20261006.json.
INI/core parity, поколения/параллелизм OpkgTun и остальная package/build/source
проверка OPEN. Q29 FAIL/ENONET, Q30 skips/drain OPEN и D06 сохранены.
Q31 IN_PROGRESS; общий итог28/37(75.7%),осталось9.

## F328: скрипт проверки сборки останавливал сервисы и использовал общий исходный каталог

keenetic_verify.py безусловно останавливал qeli-server и выполнял pkill -9 qeli,
хотя компиляция и проверка зависимостей не требуют менять работающие сервисы.
Отдельная additive-синхронизация сохраняла удалённые модули и старую Cargo config.
Модели старого pipeline воспроизводят сервисные команды; настоящий file-adapter
в собственном временном каталоге подтверждает stale inputs. Старые сервисные и
компиляторные команды на действующей лабе не выполнялись.

Новая проверка создаёт отдельный0700 mktemp checkout в /var/tmp на каждый запуск,
проверяет путь, задаёт CARGO_TARGET_DIR внутри него и использует общий
router_source/native_lab. Проверки incomplete-sync marker и завершения SFTP
переиспользованы; отдельный sync или INI parser не добавляется. Сервисы не
останавливаются, не убиваются и не перезапускаются. Сборки используют --locked и
одну compiler job, серверный release требует jemalloc; клиент сохраняет client-only
features. Каталог сохраняется для разбора; после использования его нужно удалить.
Общий source/target каталог для параллельных запусков не используется. Pinning
toolchain и полный provenance роутерного артефакта остаются OPEN.

## F329: ошибки проверки могли давать exit0, а текст ошибки подтверждал отсутствие ring

Старый main печатал FAIL, но возвращал None: после отказа сборки скрипт выходил0.
Ненулевой reverse dependency query с текстом did-not-match принимался за отсутствие
ring; отказ поиска артефакта игнорировался. При sync exception SSH не закрывался.
Управляемые старые прогоны подтверждают ложный PASS и exit0 после failed summary.

Каждый этап теперь проверяет exit status. Требуется успешный прямой граф normal/
build dependencies: пакет ring, пустой/чужой root и текст ошибки отвергаются.
Dev-only зависимости исключены. Обязательны nonempty/executable, readelf ELF magic
и проверенный SHA256 артефакта. SSH закрывается в finally после успеха и ошибки,
включая sync failure. Нет credentials — exit2; verification/connect/close failure
— exit1; полный успех — exit0.

19 новых gate-тестов PASS на Windows/Linux: отказ каждой команды, sync/readiness/
hash/metadata/close и отсутствие операций над сервисами.7 shared-sync тестов
используют настоящие shell/files с временным SFTP adapter в Linux и PASS. Настоящий
установленный Cargo выполняет offline-графы локальных fixture crates: client
normal/build исключает dev-only ring, положительный server-граф содержит ring и
отвергается. Компилятор, загрузка зависимостей, настоящий Qeli host/cross build,
артефакт клиента и прошивка этим не квалифицируются.37 recipes/docs/bindings/diff
PASS. Исторические результаты11 июня остаются историческими и не подтверждают
текущий исходник.

Пакет F328–F329: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-verification-gate-20261006.
Evidence: release/certification/evidence/q31-keenetic-verification-gate-20261006.json.
INI/core gateway parity, поколения/параллелизм OpkgTun, packaging и остальная
source/build ABI/provenance проверка OPEN. Q29 FAIL/ENONET,Q30 skips/drain OPEN,D06
сохранены. Router USER_EXCLUDED; Q31 IN_PROGRESS,28/37(75.7%),осталось9.

Первый native-recipe FAIL сохранён: прежняя проверка литерала server_build= в
исходнике не совпала с динамическим выводом этапа. Теперь recipe требует именованную
locked server-команду, а execution test проверяет фактический server_build=OK после
успеха. Итоговые recipes PASS; product-команда ради старого assertion не ослаблялась.

## F330: отдельный INI-парсер init расходился с ядром

Оба шаблона содержали awk parser и собственный список true/yes/1. Корректные
кавычки, регистр/BOM и on, принимаемые каноническим клиентским parser, считались
false в wrapper. Сравнение старого/нового кода воспроизводит лишний legacy NAT/
forwarding для quoted gateway_nat, uppercase key и forward=on.

Оба shell-парсера удалены. qeli-client --print-gateway-owner использует существующие
ограниченный config_source loader и строгий общий INI parser; печатает только core
или legacy до logging initialization и запуска клиента. Секреты конфига не
сериализуются, hooks/device identity/TOFU/TUN/network setup не выполняются. API
включён только для Linux AND client-bin. За пределами добавленного блока client/
mod.rs совпадает с baseline. Cargo/native FFI recipes/default features и остальные
native implementations неизменны; новый FFI ABI не вводится.

## F331: exit-node и ошибки определения владельца допускали legacy LAN NAT

Раньше core_manages_gateway проверял только gateway_nat/forward. Допустимый
exit_node=true дополнительно включал противоположный legacy LAN masquerade. Теперь
это core ownership наравне с gateway_nat/forward. Все flags false/отсутствуют —
legacy fallback сохранён. Invalid/duplicate/conflicting config, ненулевой exit
query, unknown/empty/multiline reply запрещают start до запуска и восстановления
сети. Неизвестный владелец не допускает nat_up. Один проверенный pre-launch ответ
сохранён для решений wrapper; GATEWAY=no и активный OpkgTun не требуют legacy
query. Stop recovery не зависит от нынешних INI flags; saved-state rules неизменны.

Standalone binary и шаблон нужно обновлять вместе. Без новой команды binary
отклоняет gateway startup, а не возвращается к старому shell parser. Query —
снимок config, не authentication readiness и не владение работающим поколением.
Процесс затем повторно читает path: параллельная замена config между inspection/
start и параллельные service/wan.d операции остаются OPEN. Atomic config-generation
lock не заявляется.

Свежие Rust1.97.0 offline/locked/jobs1 host client-bin debug build,8 binary unit,
pinned formatter и strict Clippy PASS.155 проверок на каждом BusyBox ash/dash
PASS:47 owned native-helper process,44 state model,12 installer,17 hook,19 verifier,
16 новых owner tests.22 subcases настоящего inspector/INI admission на оболочку
для обоих шаблонов.16 original/current records на оболочку воспроизводят три
syntax mismatches и exit-node legacy ownership. Только new-source query использует
настоящий host inspector; old-source решение — исходный awk. Firewall/proc/sys/
network/service callbacks остаются моделями. C helper моделирует metadata reply
без parser; настоящий core parsing проверен Rust-тестами и host inspector. State
fixture исправлен для допуска metadata query: stale-recovery assertions достигают
recovery, а не раннего unsupported-command failure. Оба final suite перепроверены.
37 recipes/docs/bindings/diff PASS. Windows rustfmt не найден, до компиляции
использован pinned formatter лабы. Qeli release/cross-build, настоящий router/
firmware networking и native FFI artifacts не пересобирались; исторические
статусы/даты сохранены.

Пакет F330–F331: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-core-gateway-20261006.
Evidence: release/certification/evidence/q31-keenetic-core-gateway-20261006.json.
Core gateway INI decision parity теперь scoped PASS. Config/generation concurrency,
OpkgTun ownership, packaging и остальная source/build ABI/provenance проверка OPEN.
Q29 FAIL/ENONET,Q30 skips/drain OPEN,D06 сохранены; router USER_EXCLUDED.
Q31 IN_PROGRESS;28/37(75.7%),осталось9.

## F332: init, wan.d и установка выполнялись параллельно

Два hook могли смешать команды ndm и публикацию pending/receipt. Stop удалял marker
и план, пока уже запущенный hook продолжал настройку по старому снимку и заново
создавал служебные файлы. Для start/stop/restart и установки общей блокировки не было.

Теперь все три точки входа используют одну библиотеку lifecycle.sh. Атомарный mkdir
/var/run/qeli.lifecycle.lock допускает одну операцию; конкурент возвращает ошибку
до сетевой настройки, работы службы или публикации и требует повтора. Init держит
lock весь restart и внутреннюю очистку. Hook повторно проверяет marker под lock.
Installer использует библиотеку из комплекта, готовит установленную копию0600 и
публикует её перед бинарником/init. Старые скрипты lock не соблюдают: обновлять
библиотеку, соответствующие init и hook вместе после остановки/сверки старого клиента.

Обычный выход и HUP/INT/TERM освобождают lock. После SIGKILL каталог остаётся для
ручной сверки: автоматического удаления по PID/возрасту и убийства процессов нет.
Lock находится во временном /var/run роутера, а не в постоянном /opt. Убедившись,
что init/hook/installer-владельца больше нет, удалять только пустой каталог через
rmdir, сохраняя PID/plan/forwarding/pending, затем повторять штатную операцию.
Занятые hook-события не стоят в очереди: нужен следующий event или ручной повтор.
Зависший ndmc может удерживать lock; новый firmware timeout здесь не квалифицирован.

## F333: смена плана ядром допускала ложный complete receipt

Hook сравнивает captured marker/целый план перед каждой проверяемой командой L3/save
и после save перед публикацией receipt. Обнаруженная замена прерывает обработку и
сохраняет pending для повтора. Snapshot-тест теперь проверяет отказ от старого плана
и применение нового вместо подтверждения устаревшего результата. Ядро не участвует
в shell-lock: замена после последней проверки, ABA с одинаковыми байтами, привязка
к аутентифицированному поколению и удаление семейства остаются OPEN. Выполненные
команды не откатываются; атомарность всей настройки не заявляется.

## F334: mv в каталог выдавал ложный успех установки

mv source destination-directory успешно помещает временный basename внутрь
каталога. Installer отвергает directory targets бинарника/init/config/helper до
работы с зависимостями. Ошибка подготовки/публикации библиотеки сохраняет старые
binary/init и убирает временный sibling; rollback всего комплекта остаётся OPEN.

Восемь новых lifecycle-методов (оба init внутри одного метода) и два installer-метода:
165 тестов на каждом BusyBox ash/dash —47 owned native-process,44 state models,
14 installer,17 hook,19 verifier,16 owner и8 lifecycle. Настоящие owned shell-процессы
с барьерами воспроизводят три baseline-отказа на каждом shell: перемешивание hook,
stop во время hook и смену плана при save. Исходный installer также проваливает
новый directory admission assertion. Исправленные suites PASS. Network/ndm/opkg/
sysctl — модели команд/файлов. Байты C helper и host debug inspector совпадают с
F330/F331; Rust/core/native implementations, ABI/artifacts/recipes неизменны:
новая Rust/FFI/release/cross-сборка не заявляется.37 recipes/docs/bindings/diff PASS.
Настоящий router runtime USER_EXCLUDED.

Packet F332–F334: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-lifecycle-lock-20261006.
Evidence: release/certification/evidence/q31-keenetic-lifecycle-lock-20261006.json.
Общее исключение cooperating shell-операций и отказ при обнаруженной смене плана —
scoped PASS; core/config generations, firmware ordering, packaging/cross ABI/source
provenance и широкий review OPEN. Q29 FAIL/ENONET,Q30 skips/drain OPEN,D06 сохранены.
Q31 IN_PROGRESS;28/37(75.7%),осталось9.

Первый directory baseline дал также две ошибки фикстуры: успешная старая установка повлияла на следующие targets. Raw logs сохранены и не квалифицируют эти targets. Отдельные свежие фикстуры воспроизводят ложный старый успех для binary/init/config и отказ нового кода: шесть old/current records на shell PASS. Код продукта и входы финального165-suite для этого сравнения не менялись.

## F335: общий checkout и backup manifest загрязняли сборки роутеров

Без --sync оба helper использовали старый /opt/qeli-src. Успешная сборка могла
содержать прежние исходники; параллельные запуски изменяли/восстанавливали один
Cargo.toml и делили target. Теперь каждый запуск создаёт проверенный приватный
mktemp-каталог0700, всегда загружает текущие управляемые входы, проверяет завершение
sync и ограничивает только свою копию до rlib. Общие backup/restore удалены.
CARGO_TARGET_DIR принадлежит запуску; CARGO_INCREMENTAL=0 и --jobs1 ограничивают
конкурентность компилятора внутри него. --sync совместим, но необязателен.
Напечатанный каталог сохраняется для диагностики и требует проверенной очистки
после завершения; старые checkout не меняются. Toolchain и download cache Cargo
могут быть общими; конкурентная установка toolchain и локальные изменения файлов
во время upload пока не квалифицированы.

## F336: совпадение SHA допускало несовместимый бинарник и даже не-ELF

Проверенный hash доставки не подтверждал архитектуру или статическую компоновку.
Оба helper используют router_artifact.py: один снимок SFTP читается, транспорт
закрывается, SHA сверяется, проверяется тот же снимок, затем существующий owner
публикует его атомарно. Отказ сохраняет прежний бинарник; совпавший локальный hash
не обходит проверку. Gate проверяет границы headers/segments, little endian,
разрядность/машину target и исполняемую точку входа, запрещает PT_INTERP/DT_NEEDED,
проверяет EABI5 hard-float ARMv7. ET_EXEC/static PIE разрешены; расширенный формат
program headers отвергается. Это metadata admission, а не доказательство musl,
CPU ISA, полного float ABI MIPS, работы kernel/firmware или полной валидности ELF.

## F337: SDK install не обеспечивал graph из сохранённого lockfile

Пакет OpenWrt требует Cargo.lock и проверяет client-only graph через cargo metadata
--locked до cargo install --locked --jobs1. Реальный fixture показал: install
--locked --path сам по себе допускал отсутствующий/устаревший lockfile для локальной
path dependency. Guard отвергает оба случая до публикации. Загрузок зависимостей
не было. Source SHA/mirror hash остаются этапами release-cut. Пустые SDK include
stubs только позволяют GNU make развернуть настоящий Build/Compile; полноценная
SDK/package/cross сборка этим не подтверждается.

На .11 PASS45 router tests:15 helper failure/admission,16 ELF/snapshot,7 private
checkout,7 sync. Три POSIX метода выполняют реальные операции над собственными
каталогами/manifest; compiler/SSH helper проверяются моделями с test-only Paramiko
stub, запрещающим SSH, поскольку Paramiko в лабе отсутствует.20 old/current записей
воспроизводят допуск старого source и неверного ELF с совпадающим SHA в обоих
helper. Пять реальных offline GNU make/Cargo tiny-crate случаев: старый код
принимает missing/stale lock, новый отвергает их и принимает valid lock. Настоящий
маленький x86_64 glibc-static ELF проходит metadata gate; прежний неизменённый GNU
debug Qeli ELF отвергается по PT_INTERP. Это не свежая router Qeli/musl cross сборка
и не выполнение на firmware. Начальные import/fixture-assumption FAIL сохранены
и не квалифицируют результат.37 recipe tests, docs/bindings/diff PASS.

Пакет F335–F337: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-router-build-isolation-20261006.
Evidence: release/certification/evidence/q31-router-build-isolation-20261006.json.
Rust/core/native compile inputs, библиотеки, существующие router binaries и их
историческая квалификация неизменны. Новые Qeli/FFI/release/cross build, фиксация
toolchain/reproducibility и полный ABI не заявляются. Core/config generation,
ABA, last-check replacement, порядок firmware и whole-bundle rollback OPEN.
Q29 FAIL/ENONET,Q30 exclusions/drainOPEN,D06 сохранены. Q31 IN_PROGRESS;
28/37(75.7%),9 осталось; целый checklist-пункт Q31 не закрыт.

Основание metadata: [ELF program headers](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.pheader.html),
[Arm ELF32 ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst),
[Cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html).

## F338: default Rust, плавающий nightly и непроверенный Zig меняли сборку

Оба helper отдельно настраивали toolchain. Обычные сборки использовали default
Cargo/Rust, MIPS — +nightly; любая версия Zig только печаталась. Свежий read-only
inventory подтверждает default Rust1.96 в обеих лабах, тогда как pinned native
recipes используют1.97.0. router_toolchain.py теперь владеет aliases targets,
настройкой и build commands обоих helper: Rust1.97.0, nightly-2026-06-10 для MIPS,
Zig0.13.0, cargo-zigbuild0.23.0. Дата nightly взята из существующего manifest .10
(compiler commit датирован June9); latest-nightly не выбирается.

Неверный Zig отвергается до установки. Именованные Rust pins/версии, target std и
nightly rust-src проверяются после успешных installer; отсутствие результата
останавливает setup. Inventory cargo-zigbuild и версия его top-level executable
должны совпадать. Install использует explicit Rust и один job; default не меняется.
Удалены мёртвые checked/feature definitions helper и дублирующие OpenWrt build_std
data/argument. У architecture/toolchain/flags теперь один owner.

## F339: внешние encoded/compiler flags перекрывали recipe

CARGO_ENCODED_RUSTFLAGS имеет приоритет над RUSTFLAGS, в том числе прежним MIPS
soft-float assignment. Общая команда Qeli удаляет encoded flags, RUSTC,
CARGO_BUILD_RUSTC и CARGO_BUILD_RUSTFLAGS, задаёт свои RUSTFLAGS (пустые для обычных
targets, явный MIPS linker soft-float), отключает Rust wrappers и использует pin,
приватный target/noincremental/jobs1. Это ограниченный фикс ambient overrides,
а не полная очистка всех Cargo profile/config/PATH/cache inputs.

PASS52 Linux router tests:12 helper,10 shared policy,16 ELF,7 source,7 checkout.
Четыре дублирующих setup test methods заменены одним delegation method и10 общими
semantic failure methods; покрытие перенесено.12 old/current model записей
воспроизводят допуск неверного Zig и unpinned/unisolated команды в обоих helper.
Реальный offline tiny host Cargo/Rust fixture выполняет старый/новый prefix:
старый применяет encoded cfg с default Rust1.96, новый не применяет cfg и выбирает
Rust1.97. Это не cargo-zigbuild/musl/cross/MIPS/nightly/Qeli сборка.37 recipes,
docs/bindings/diff PASS. На .10 только read-only inventory; выполнение на .11.
Global tools/defaults/service/network/установленные бинарники не менялись.

Начальный draft использовал cargo +pin zigbuild --version, который реальный tool
отвергает; итоговая проверка — cargo-zigbuild --version. Временное удаление BIN в
незакоммиченном коде обнаружили helper tests, оно исправлено. Test-only import context также выгружал policy module и нарушал identity
comparison mock; pre-import исправил harness. Начальные FAIL сохранены и не
квалифицируют успех; проверки точного итогового source повторены.
Pinning не доказывает hermeticity, полный ABI/ISA, независимую A/B reproducibility
или router runtime. Shared tool installation/cache, global config/PATH/upload races
остаются. Реальный router USER_EXCLUDED; SDK Rust feed/source/mirror release-cut
проверяются отдельно. Core/native/Rust implementation inputs/artifacts неизменны.

Пакет F338–F339: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-router-toolchain-policy-20261006.
Evidence: release/certification/evidence/q31-router-toolchain-policy-20261006.json.
Generation/ABA/last-check/firmware/whole-bundle rollback OPEN. Q29 FAIL/ENONET,
Q30 exclusions/drainOPEN,D06 сохранены. Q31 IN_PROGRESS;28/37(75.7%),9 осталось;
целый checklist-пункт не закрыт.
Основание политики: [rustup pins](https://rust-lang.github.io/rustup/concepts/toolchains.html),
[Cargo environment](https://doc.rust-lang.org/cargo/reference/environment-variables.html).

## F340: ошибка публикации оставляла смешанное поколение installer

Прежний installer отдельно заменял helper/binary/init. Ошибка последнего init
rename либо TERM после публикации binary оставляли новый executable/helper со
старым init. Теперь до публикации создаются backup старых файлов в тех же
каталогах с сохранением bytes/modes и recovery record0600. Rollback intent задаётся
до rename; неуспешный same-directory rename с сохранившимся source считается
неопубликованным. Обычная ошибка/обработанный сигнал восстанавливают изменённый
код в обратном порядке; отсутствовавшие прежде targets удаляются. Failed restore
сохраняет оставшиеся backup/install-pending вместо потери recovery evidence.

Общий qeli_install_ready проверяет retry, start обоих обновлённых init и активный
wan.d hook. Stop разрешён. Lock освобождается после обработанного rollback.
Pending record, включая dangling symlink, блокирует admission. Старые скрипты
требуют ручной остановки/проверки и не обязательно соблюдают guard: старый init,
восстановленный при частично неуспешном rollback, не считается защищённым.
Crash atomicity всего bundle не заявлена: SIGKILL/power loss требуют owner review
и manual recovery; fsync/automatic stale deletion нет. Существующий INI content
сохраняется; ужесточённый mode600 и новая опубликованная болванка могут остаться
после поздней ошибки. opkg/package changes и root/admin replacement вне code
rollback. Именованный backup мог уже быть использован успешным частичным restore;
проверяй комплект, не удаляй targets/marker вслепую.

## F341: linked/special targets обходили предположения об обычных файлах

Старая directory-проверка допускала symlink/FIFO. chmod600 client.conf проходил
по symlink и менял внешний файл; chmod700 linked config directory менял внешний
каталог. Теперь installed code/config targets — только regular или absent, без
symlink; /opt/etc/qeli не должен быть linked. Отказ до package updates. Root/admin
path races этим не закрываются.

PASS176 tests на каждом BusyBox ash/dash:47 owned native process,44 state,14
installer,17 hook,19 verifier,16 gateway owner,8 lifecycle и11 новых install
rollback/admission methods. Проверены каждый code rename, old/absent/new code,
restore/copy/marker failures, TERM после реального owned rename, regular/dangling
linked targets,FIFO,linked config directory и pending guards обоих init/hook.
Пять old/current сценариев дают10 записей на shell: init rename,TERM,config
symlink,directory symlink,failed restore. Воспроизведены старые mixed code/outside
chmod/отсутствующий recovery marker; новые restore/refusal/retained recovery PASS.

Начальные11-method suites FAIL только из-за fixture assertion: read-only opkg
print-architecture при отказе retry был посчитан как изменение зависимостей.
Теперь сравниваются mutating package calls; все176 повторены на каждом interpreter.
Исходные FAIL logs/inputs сохранены. State function fixtures явно source shared
library, все library paths отображены в owned root; настоящий /opt не используется.
Network/ndm/opkg/proc-sys — модели; выполняются настоящие owned shell/rename/signal/
native helper и существующий host inspector. Reused helper/inspector hashes равны
F330–F331; Rust/core/native inputs/artifacts/recipes неизменны.37 recipes,
docs/bindings/diff PASS; новая Qeli/FFI/release/cross сборка и router runtime не заявлены.

Пакет F340–F341: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-install-rollback-20261006.
Evidence: release/certification/evidence/q31-keenetic-install-rollback-20261006.json.
Ordinary executable-bundle failure recovery — scoped PASS. Power-loss transaction,
старые scripts/admin,core/config generation/ABA/last-check,firmware/full ABI и
cross-build qualification OPEN. Q29 FAIL/ENONET,Q30 exclusions/drainOPEN,D06 сохранены;
real router USER_EXCLUDED. Q31 IN_PROGRESS;28/37(75.7%),9 осталось;
целый checklist-пункт не закрыт.

## F342: UCI → INI менял буквальные строки перед общим парсером

Renderer записывал строковые значения без кавычек. Общий INI parser обрезает
крайние пробелы у bare values и снимает одну пару внешних кавычек с unescape
backslash-quote. Поэтому username, окружённый пробелами, или volatile obfs_key,
начинающийся и заканчивающийся кавычками, мог отличаться от заданного оператором.
Сохранение secret-файла само по себе не защищало последующую сериализацию ключа.
Это дефект преобразования данных; VPN handshake в этом пакете не запускался.

Единый ini_write теперь заключает строку в двойные кавычки и экранирует только
двойные кавычки, как serializer общего ядра. Bare backslash остаётся буквальным.
ini_kv сохраняет прежний пропуск отсутствующих необязательных значений; required
server/proto/password_file и logging используют тот же writer. ASCII control
characters по-прежнему удаляются до записи, bool/MTU остаются прежними.
UCI-текст не исполняется; набор параметров/формат конфигурации остаётся INI.

Четыре новые проверки дают40 round-trip операций: по13 вариантов для writer,
user и obfs_key плюс required/logging/control case. Сам файл config/format.rs
без изменения компилируется в отдельный GNU host inspector с существующим log
rlib; fixture подаёт сгенерированный INI через stdin и сверяет UTF-8 bytes из hex.
Это настоящий общий parser, не новая Python реализация. Старый Git init на том
же новом test source воспроизводит13 несовпадений в каждом shell. Текущий полный
набор41 =23 init +9 defaults +5 saved rc.common dispatcher +4 round-trip PASS
отдельно в BusyBox ash и dash. Файлы, функции init и Rust parser выполняются
в собственных temporary paths; UCI/procd/firewall остаются моделями. Saved
dispatcher snapshot/hash прежний, настоящие OpenWrt daemons не запускались.
Первый standalone compile отказал без log dependency; отказ сохранён, затем
подключён существующий GNU log rlib без изменения parser source.

11 LuCI Node fixtures,37 native recipes, docs/bindings/diff PASS. Core/native/
router build recipes и существующие артефакты не менялись; свежая сборка Qeli,
FFI/cross/firmware/ABI и сетевой obfs handshake не заявлены. Форматирование
значения проверено отдельно от его допустимости для ClientConfig.

Пакет: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-ini-roundtrip-20261006.
Evidence: release/certification/evidence/q31-openwrt-ini-roundtrip-20261006.json.
Q31 IN_PROGRESS,28/37(75.7%),9 осталось; целый checklist-пункт не закрыт.
Generation/ABA/last-check/firmware ordering и cross qualification остаются OPEN;
Q29 FAIL/ENONET,Q30 exclusions/drainOPEN,D06 сохранены, router USER_EXCLUDED.

## F343: wrapper не сверял dev и владельца L3 до запуска

Оба init templates использовали своё TUN для legacy firewall и marker OpkgTun,
но gateway inspection не проверял соответствие этому имени dev в INI. При
GATEWAY=no или активном OpkgTun inspection вообще пропускался. Поэтому неверный
dev/dev_attach мог запускать иной интерфейс или пытаться создать устройство,
которым должен владеть ndm; gateway flags могли включать дополнительного владельца.

Metadata CLI теперь принимает парные --expect-router-device и
--expect-router-attach только вместе с --print-gateway-owner. Общий bounded loader
и strict core parser одним чтением проверяют совпадение dev, device_type=tun и
dev_attach. Attached router требует gateway_nat/forward/exit_node выключенными,
поскольку ndm владеет L3/gateway. Старый metadata CLI без expectations сохраняет
свою прежнюю функцию; обновлённые templates требуют новый бинарник. Неизвестные
опции у старого binary дают отказ до launch, а не тихий unsafe fallback.

Оба templates делают этот query один раз до cleanup старого state, удаления
NetworkPlan/PID и создания процесса; даже GATEWAY=no не отменяет interface admission.
Shell INI parser не добавлен. Проверка не фиксирует snapshot для дальнейшего
запуска: изменение INI между inspection и startup, generation/ABA остаются OPEN.
Не меняй client.conf во время start/restart. При исправлении имени/режима согласуй
INI и template и повтори start; inspection сам не создаёт TUN и не запускает hooks.

Свежий GNU client-bin debug build Rust1.97.0,12 целевых unit tests (4 новых),
strict Clippy и fmt PASS. 184 shell tests на каждом BusyBox ash/dash PASS:
47 process +44 state +14 installer +17 hook +19 verifier +24 gateway owner
+8 lifecycle +11 rollback. Восемь новых shell методов добавляют34 actual
inspector cells; вместе с прежними22 это56, не сетевые подключения.
Тот же новый test source, старые Git template bodies и старый host inspector
дают20 false admission mismatches в восьми методах на каждом interpreter.

Первый полный прогон с прежним вспомогательным C-процессом завис: argc==4 не
распознал дополнительные CLI flags, metadata query перешёл в модельный lifetime.
Timeout не засчитан как полный результат; собственные helper/suite остановлены
после проверки exe hash/cwd, два своих temp roots очищены, финальный lookup пуст.
Отдельный C helper теперь распознаёт только прежние4 и новые8 аргументов;
его metadata reply остаётся моделью, процессные lifecycle проверки настоящие.
Исходник/hash старого и нового helper сохранены; прежний executable не менялся.
Без rustfmt в Windows PATH применён установленный pinned formatter на .11.

317 compile inputs и17 fixture Git files сверены с фактически переданными
байтами; только приватный Cargo.toml ограничен до rlib, исходный manifest сохранён.
37 native recipes, docs/bindings/diff PASS. Изменения Rust ограничены Linux
client-bin metadata admission/CLI; обычный data plane, FFI/JNI exports/config schema
не менялись. Прежние native/release/router artifacts сохранены; свежая сборка
FFI/release/cross/firmware или router ABI/runtime не заявлена. .10 не затронут,
.11 выполнял только собственные files/compiler/process fixtures.

Пакет: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-interface-admission-20261006.
Evidence: release/certification/evidence/q31-keenetic-interface-admission-20261006.json.
Q31 IN_PROGRESS,28/37(75.7%),9 осталось; целый checklist-пункт не закрыт.
Q29 FAIL/ENONET,Q30 exclusions/drainOPEN,D06 сохранены, router USER_EXCLUDED.

## F344–F346: реальная router cross-matrix и compile-регрессии

Прежние host/tiny-crate проверки не подтверждали сборку текущего Qeli на musl.
Все четыре настоящие release client-only сборки старого Git-снимка упали:
statfs.f_type у musl беззнаковый, а PROC_SUPER_MAGIC знаковый. На MIPS дополнительно
не существует std::sync::atomic::AtomicU64 для roaming RPF lease counter.
F344 сравнивает оба значения в lossless i128, сохраняя проверку regular procfs;
F345 использует уже имеющийся portable-atomic. Ширина64бит, Relaxed fetch_update,
checked_add и отказ при исчерпании lease IDs сохранены. Это изменение общего Linux
кода, а не только metadata CLI; новые FFI/native release artifacts не заявлены.

Повторные сборки всех четырёх targets PASS: locked/client-bin/jobs1, private
source/target0700, manifest только rlib. Rust1.97.0; MIPS nightly-2026-06-10,
Zig0.13.0/cargo-zigbuild0.23.0. Каждый полученный SHA-bound SFTP snapshot прошёл
общий ELF admission и readelf: little endian, нужные class/machine, executable
entry, без PT_INTERP/DT_NEEDED; ARM EABI5 hard-float. У MIPS readelf показывает
O32/MIPS32r2/soft-float. Это декларация ABI полученного файла, не проверка исполнения
на firmware, других ISA/ядрах или доказательство воспроизводимости A/B.

| Target | Bytes | SHA-256 |
|---|---:|---|
| aarch64-unknown-linux-musl | 4818040 | 60641ddcdb447c347240e173a341923d3eadc34b9f72fb30954fc4ff00327351 |
| x86_64-unknown-linux-musl | 5574984 | ec567377e46cd8a2ed629bccfb83318fba4e19bf26905df3f49ca77c254a5925 |
| mipsel-unknown-linux-musl | 6846056 | b365638cfc715086052b04ee6a3f5ad3e826077a858387bfc28d3f0d3c8faeaa |
| armv7-unknown-linux-musleabihf | 4981980 | ba223fb91a931aad1c631ae71b111f568cdcb8830a69ece684854e03c591910f |

На .11 GNU build/strict Clippy/fmt PASS;79 sysctl tests PASS,3 inherited ignored,
отдельно настоящий native descriptor recreation test PASS в private network
namespace. Static x86_64-musl executable выполняет24 gateway admission tests на
каждом BusyBox ash/dash без skips, включая56 actual metadata cells на interpreter.
Все52 router helper tests на Linux без skips,37 recipe checks/docs/bindings PASS.

F346 устраняет расхождение CI: четыре targets уже были в матрице, но использовали
плавающие stable/nightly. Теперь те же named pins, явный toolchain в Cargo/rustup,
один job, очищенные compiler overrides и общий static ELF gate вместо одного file.
Workflow разобран PyYAML6.0.3 из отдельного audit-каталога;16 rendered shell steps
прошли bash -n. Точный Python ELF step выполнен на четырёх настоящих binaries и
четырёх усечённых negative copies:8 ожидаемых результатов. GitHub Actions NOT_RUN.

Первый вариант inferred cast as _ не компилировался и сохранён как FAIL;
он заменён lossless преобразованием. Initial library-test harness не передал
conformance siblings; после загрузки12 Git fixtures правильный sysctl:: filter
выполнил79 tests. Два пустых фильтра явно NOT_RUN, не PASS. Windows router helpers
имели10 POSIX skips; квалифицированный итог взят из Linux прогона без пропусков.
317 compile inputs/8 gateway fixture inputs проверены на .10; два317-input source
layouts/12 conformance/16 helper inputs — на .11. Только private Cargo manifest
изменён на rlib. Реквизиты не сохраняются в reproduction scripts.

.10 выполнял собственную последовательную компиляцию и metadata/filesystem
fixtures; добавлены named nightly/rust-src и недостающие pinned std targets,
default toolchains и работающие сервисы не изменялись. .11 — собственная GNU
сборка и private namespace test. Repo binaries/deployment не заменялись.

Текущий остаток Q31 после этой матрицы:

| Область | Состояние |
|---|---|
| Реальная standalone cross-сборка четырёх targets/ELF | DONE в указанном scope |
| UCI/INI, shell lifecycle/rollback и LuCI | Scoped suites PASS; сохранены модельные границы |
| Настоящие ucode/fs, rpcd/ubus/UCI и session ACL | Scoped native PASS F347–F352 ниже; SDK Kconfig/LuCI packaging scoped PASS F353–F354; SDK packaging retained binary и offline opkg Q31-V003 scoped PASS; stock Rust1.89/x86 SDK macro compile/link F358 scoped PASS; bootstrap/release pipeline OPEN, procd non-PID1 lifecycle и HTTP/session API Q31-V002 проверены |
| Keenetic preflight→launch INI; core plan generation/ABA | F355/F361 scoped PASS; F362–F363: late receipt и counter reset при fresh OpkgTun init launch scoped PASS; writer/lock, direct launch и admin replacement OPEN |
| SIGKILL/power-loss installer recovery | Manual recovery; полная bundle transaction не подтверждена |
| Firmware WAN/reboot/DNS/firewall/RSS/throughput | USER_EXCLUDED; cross-build не device test |
| Hermetic shared caches/config/PATH и clean A/B | F356–F357 compiler/intermediate-directory и F364 пять standalone release fields scoped PASS; F365/Q31-V006 все четыре standalone Qeli A/B scoped PASS; полная hermetic policy OPEN |

Эта таблица актуализирует исторические cross-build NOT_RUN в предыдущих разделах;
их исходные evidence не переписаны. Пакет:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-router-cross-matrix-20261006.
Evidence: release/certification/evidence/q31-router-cross-matrix-20261006.json.
Q31 IN_PROGRESS;28/37(75.7%),9 осталось. Q29 SIGKILL FAIL/auto-null ENONET,
Q30 Apple exclusions/callback-drain OPEN и D06 ACCEPTED сохранены.

## F347–F349: настоящий ucode/fs и передача volatile secrets

На .11 собраны неизменённые upstream ucode и fs из двух pinned revisions,
используемых OpenWrt: 24.10 — 3f64c8089bf3ea4847c96b91df09fbfcaec19e1d;
25.12 — 85922056ef7abeace3cca3ab28bc1ac2d88e31b1. Это GNU host execution
настоящего интерпретатора и filesystem/process API, без rpcd/ubus daemon,
OpenWrt firmware, UCI/procd или package SDK. Их квалификация остаётся OPEN.

F347: массив аргументов fs.popen не поддерживается этими revisions: возвращает
null/EINVAL. После отдельного исправления regex обе версии всё ещё отказывали
записи pass/obfs_key. Теперь запускается одна из двух буквальных команд init;
секрет передаётся только через stdin. Caller-controlled name/value не входят
в shell text или argv. Короткая запись/неуспешный close дают RPC unknown error,
включая null вместо exit code; запись и close сравниваются строго.

F348: regex с JavaScript escapes \x00..\x1f/\x7f отвергался настоящим ucode
при проверке непустого секрета. Теперь каждый байт проверяется через ord:
C0 и DEL запрещены, длина 1..4096 байт, Unicode и буквальные метасимволы сохраняются.
JSON остаётся служебным RPC/test transport; формат конфигурации остаётся INI.

F349: mv считал каталог назначения контейнером, помещал туда .secret.* и
возвращал успех. linked runtime directory мог менять внешний mode/secret.
Init теперь отвергает linked/non-directory runtime leaf и linked/non-regular
secret target до публикации. Clear также отвергает linked runtime leaf,
чтобы не удалять внешние файлы; отсутствие runtime dir остаётся успешным no-op. Статус true только для читаемого regular файла
размером 1..4096 байт в нелинкованном каталоге. Пустой/oversize/каталог/FIFO/link
не показываются как настроенный секрет. Это стабильные файловые состояния;
root/admin replacement race между проверкой и rename не объявлена закрытой.

14 новых методов test_openwrt_ucode.py PASS без skips на обеих версиях и в
каждом BusyBox ash/dash: четыре сочетания. Проверены оба имени/точные bytes,
Unicode byte boundary, все 33 control bytes, invalid types/names, stdin injection
sentinel и отсутствие секрета в argv, child exit17/сохранение прежнего файла,
четыре неверных publication targets, пять неверных status targets, linked
runtime directory без записи/chmod, linked runtime clear refusal, clear filesystem failure и closed service
verbs/status. Service responses — exit-code adapters, не настоящий procd.
Полный OpenWrt набор55 (41 прежний +14 новых) PASS в ash/dash с ucode24.10,
saved hash-checked rc.common и прежним exact-source Rust INI inspector.
11 LuCI Node fixtures,37 recipes, docs/bindings/diff PASS.

Старый Git module с исправленным loader fixture даёт40 assertion failures
в11 методах на каждом из четырёх сочетаний. Intermediate regex-only fix
воспроизводит отдельный array-popen failure; первый fix выявил directory false
success. Три новых filesystem-status/runtime-link write/delete метода со старым init/status
дают7 независимых failures на каждой версии. Initial include() loader и
каскадные subtest cleanup errors являются harness errors, не дополнительными
дефектами продукта; исходные файлы/FAIL logs сохранены. Final subtests очищают
свои пути даже после assertion failure.

Build dependencies скачаны/распакованы только в private0700 root, без системной
установки: CMake3.31.6, json-c0.18 и recorded Debian library packages. Сборка
одним job, только ucode/fs; остальные modules выключены. Source archives,
commit/source/executable/shared-library SHA256, CMake config/runtime ldd и
входные Qeli bytes сохранены. Первые private CMake dependency failures сохранены.
.10 не изменялся; сервисы, /etc, firewall и сеть .11 не затронуты. Rust/native/
router artifacts/recipes не менялись; повторная Qeli/FFI/cross сборка не нужна
для этих shell/ucode правок и не заявлена.

Источники API и pins: [OpenWrt24.10 recipe](https://github.com/openwrt/openwrt/blob/openwrt-24.10/package/utils/ucode/Makefile),
[OpenWrt25.12 recipe](https://github.com/openwrt/openwrt/blob/openwrt-25.12/package/utils/ucode/Makefile),
[pinned fs.popen](https://github.com/jow-/ucode/blob/85922056ef7abeace3cca3ab28bc1ac2d88e31b1/lib/fs.c),
[ucode core API](https://ucode-lang.org/module-core.html).

Пакет: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-ucode-runtime-20261006.
Evidence: release/certification/evidence/q31-openwrt-ucode-runtime-20261006.json.
ucode/fs platform API проверен в указанном scope; daemon/SDK/firmware,
config preflight→launch generation/ABA и clean A/B остаются отдельно OPEN.
Q31 IN_PROGRESS;28/37(75.7%),9 осталось. Q29 SIGKILL FAIL/auto-null ENONET,
Q30 Apple exclusions/callback-drain OPEN и D06 ACCEPTED сохранены.

## F350–F351: package dependencies и настоящий RPC/UCI/ACL

F350: LuCI package объявлял только qeli/rpcd-mod-ucode, хотя использует UI
framework и импортирует fs. luci.mk переносит LUCI_DEPENDS в runtime DEPENDS,
а rpcd-mod-ucode тянет libucode, но не fs. На обычной LuCI установке недостающие
пакеты уже присутствуют и маскируют пробел. Теперь явно указаны luci-base и
ucode-mod-fs. Настоящий rpcd без fs.so не регистрирует luci.qeli; с модулем все
пять методов доступны. Полный SDK package resolver/install не запускался.

F351: форма отправляла секрет без собственной проверки. Native ubus CLI/JSON→blob
обрезает NUL и suffix до Qeli: left<NUL>right сохранялся как left с успехом.
Это неподдерживаемый input транспортного C-string API, который handler после
потери bytes уже не может обнаружить. Исправлен официальный caller: общий
validator формы и setSecret отвергает все C0/DEL до RPC, неверные типы,
больше4096 UTF-8 bytes и lone surrogates. Пустое поле оставляет прежний секрет;
Unicode/quotes/пробелы передаются буквально, ошибки хранения не скрываются.
Произвольные direct RPC callers обязаны сами исключать NUL до сериализации:
серверный отказ для уже потерянного NUL не заявлен. NUL probe сохранён как
UNSUPPORTED_NUL_INPUT_LOST_BEFORE_QELI, не как поддержанная запись секрета.

Собран pristine GNU host stack из OpenWrt24.10 recipes сохранённого commit
58584c6f2829a7e5d77376ab68aae3dcc4a392d8: libubox49056d17,ubus60e04048,
uci16ff0bad,rpcdbba95191 и ucode3f64c808. Полные SHA в evidence. CMake3.31.6,
json-c0.18 и существующие native runtime libraries; один compiler job. Только
private DESTDIR/sysroot, без системной установки. rpcd file/rpcsys/iwinfo modules
выключены; ucode plugin/fs настоящие. Новая отдельная ucode build имеет ZLIB OFF;
в прежнем F347 build ZLIB был default ON, но zlib target не строился и не использовался.
Это уточняет прежнее краткое описание выключенных modules; bytes прежних artifacts
не менялись. Первый install отказал на небuilt zlib, затем собрана независимая copy.
Первый rpcd compile отказал без private json-c include; исправлены только build flags.

Семь новых integration methods PASS без skips. Каждый запускает собственные
ubusd/rpcd в chroot с отдельным Unix socket и неизменёнными Qeli module/init/ACL,
настоящими OpenWrt functions.sh/uci.sh/libuci и owned config/runtime paths.
Проверены signature/type policy, exit2/9 и продолжение VM после ошибки,
оба secrets/точные bytes/4096byte Unicode/child17, filesystem/linked-leaf guards,
reader/writer ACL allow/deny для пяти методов и UCI qeli/firewall, session-specific
UCI set/commit и unknown при отсутствующем config. Дополнительно11 literal/control/
Unicode/injection values прошли real UCI→init renderer→прежний exact-source Rust
INI inspector; его SHA256 afc80db3… совпадает с F342, format.rs не менялся.
Service start/stop/enable verbs и logger — adapters; procd не квалифицирован.
Session.access decisions настоящие; HTTP/uhttpd authentication bridge не запускался.

Первый chroot fixture в /tmp(nodev) отказал при открытии собственных devices;
каталог перенесён в owned /var/tmp без remount. Initial global CLI staging
assertion был неверен: global UCI delta видна init, это не session-local LuCI staging.
Финальный тест делает реальные uci.set/commit через session SID; до commit статус
не меняется, после меняется. Initial NUL assertion уточнён после отдельного
transport probe. Эти setup/fixture assumptions не объявлены дополнительными
ошибками продукта. Исходные FAIL logs/inputs сохранены. Последующие tests и cleanup
PASS; собственных daemons/socket runtime roots не осталось. Host /etc, services,
network/firewall и .10 не изменялись.

14 Node fixtures PASS (3 новых):66 C0/DEL name/value cases, invalid types,
ASCII/Unicode byte boundaries, lone surrogates, exact literal values, blank/no-op
и storage failure. Старый JS на тех же новых tests воспроизводит отправку NUL
до проверки; первоначальный неполный baseline без qeli.uc исключён.37 recipes,
docs/bindings/diff PASS. Core/native/router build inputs и artifacts не менялись;
новая Qeli/FFI/cross сборка не заявлена. Сохранены pinned source archives,
CMake configs, template/runtime dependencies, executable/module SHA и Git byte proof.

Источники: [pinned rpcd package dependencies](https://github.com/openwrt/openwrt/blob/58584c6f2829a7e5d77376ab68aae3dcc4a392d8/package/system/rpcd/Makefile),
[LuCI runtime dependency mapping](https://github.com/openwrt/luci/blob/openwrt-24.10/luci.mk),
[pinned rpcd ucode dispatch](https://github.com/openwrt/rpcd/blob/bba95191ff2f22c9118a1ba1355b83afaa277ae3/ucode.c).
Пакет: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-rpcd-package-20261006.
Evidence: release/certification/evidence/q31-openwrt-rpcd-package-20261006.json.
Native RPC/UCI/session ACL часть проверена; procd/SDK/HTTP/firmware не заменены
этими tests. Config preflight/core generation/ABA и clean A/B остаются OPEN.
Q31 IN_PROGRESS;28/37(75.7%),9 осталось. Q29 SIGKILL FAIL/auto-null ENONET,
Q30 Apple exclusions/callback-drain OPEN и D06 ACCEPTED сохранены.

## F352: init скрывал ошибку отправки команды настоящему procd

На официальном OpenWrt24.10.4 x86/64 rootfs старый init возвращал exit0 для
start/stop/restart/reload при отсутствии service object procd, хотя ubus сообщал
Not found. При отсутствующем Unix socket ошибка также терялась. procd.sh после
ubus очищает JSON и восстанавливает namespace; rc.common вызывает результатные
hooks после этих операций. Прежние hooks сохраняли лишь ошибки подготовки и
удаления INI, поэтому LuCI мог показать успешную команду без доступного supervisor.

Init теперь локально наблюдает command ubus call service set/add/delete: передаёт
тот же массив аргументов без изменения и сохраняет фактический exit code.
Wrapper устанавливается из start_service/stop_service после загрузки procd.sh;
не зависит от переопределения внутренних функций библиотеки. service_started
возвращает ошибку подготовки либо отправки, service_stopped — ошибку удаления
INI либо отправки delete. Последняя сохраняется в QELI_STOP_RESULT: restart/reload
не допускает новый instance после failed stop. Другие ubus calls не меняют receipt.
Успех отправки не доказывает VPN connectivity, завершение cleanup или успешную
валидацию конфигурации самим клиентом; эти границы сохранены.

Скачан официальный rootfs.tar.gz24.10.4, SHA256
 e7f8ab84eef55c7eb23492de7b0517dbc23fbedaa4abbb680fe64720c309dc03.
В нём настоящий musl procd2024.12.22~42d39376-r1, ubusd/ubus/libuci,
BusyBox ash, rc.common/procd.sh/jshn. Все archive/runtime identities сохранены.
Каждый метод копирует rootfs в owned0700 chroot на .11 с собственным Unix socket.
Procd работает как обычный процесс, не PID1; штатная boot/reboot последовательность
не запускается. Host /etc, system services, network/firewall и .10 неизменны.

7 новых integration methods PASS без skips: настоящий start/command argv/env и
0600INI; stop с удалением rendered config и сохранением volatile secret;
restart/reload с новым PID и актуальным INI; SIGKILL owned child→реальный respawn;
disabled no-instance, enable/disable rc.d symlinks; missing secret/binary admission;
ошибки при missing procd и missing socket для четырёх verbs. Один метод проверяет
несколько состояний, не дополнительные checklist пункты. Client executable —
inert shell receipt с exec sleep; /dev/net/tun — только файл existence marker,
firewall UCI пустой и реального reload нет. Qeli data plane, cleanup NetworkPlan,
WAN/reboot, DNS/firewall и firmware boot не подтверждены этим запуском.

Старый Git init на тех же7 методах даёт8 assertion failures: обе недоступности
× четыре verbs. Первый6-method baseline с4 failures также сохранён. Полный
OpenWrt набор69 = прежние55 +7rpcd +7procd PASS отдельно в BusyBox ash/dash;
все optional runtime env заданы, skips нет. Прежние ucode24.10/fs GNU runtime,
rpcd/UCI template, saved rc.common fixture и exact-source INI inspector повторно
использованы с их прежними hashes. Procd tests всегда выполняют rootfs BusyBox,
а shell-dependent прежние fixtures — выбранный interpreter. Собственных процессов
и runtime roots после всех runs нет.14 Node/37recipes/docs/bindings/diff PASS.
Core/native/router Qeli sources/recipes/artifacts не менялись; повторная Rust/FFI/
cross сборка для shell fix не заявлена. SDK не запускался: read-only inventory .11
показал1.7GB free, поэтому в этом блоке использован малый rootfs вместо SDK251MB
с дальнейшей распаковкой/feed/build. Это оставшийся пункт, не технический PASS.

Источники: [официальный rootfs/hash](https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/),
[release procd recipe](https://github.com/openwrt/openwrt/blob/v24.10.4/package/system/procd/Makefile),
[pinned non-PID1 daemon](https://github.com/openwrt/procd/blob/42d3937654508b04da64969f9d764ac2ec411904/procd.c),
[release rc.common](https://github.com/openwrt/openwrt/blob/v24.10.4/package/base-files/files/etc/rc.common).
Пакет: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-procd-20261006.
Evidence: release/certification/evidence/q31-openwrt-procd-20261006.json.
Actual procd supervision API проверен в указанном scope; SDK/package installation,
HTTP, config preflight/core generation/ABA, clean A/B остаются OPEN; firmware
USER_EXCLUDED. Q31 IN_PROGRESS;28/37(75.7%),9 осталось. Q29 SIGKILL FAIL/auto-null
ENONET, Q30 Apple exclusions/callback-drain OPEN и D06 ACCEPTED сохранены.

## F353–F354: проверка настоящего SDK и пакета LuCI (7 октября)

F353: безусловная `+ip6tables` в рецепте Qeli создаёт recursive dependency
в настоящем SDK24.10.4 с его pinned feeds и альтернативными virtual providers.
Ошибки появляются для qeli и luci-app-qeli; `make defconfig` при этом может
вернуть0. Зависимость теперь `+IPV6:ip6tables`; virtual backend choice сохранён,
IPv6 provider требуется только при IPV6. Прямой `scripts/config/conf` и проверка
stderr обязательны: один exit code make не подтверждает корректный Kconfig.
Baseline с прежним рецептом воспроизводит цикл; conditional recipe его устраняет.

F354: luci.mk читает LUCI_MAINTAINER и LUCI_URL, а прежний PKG_MAINTAINER
не попадал в IPK. Старый реально собранный пакет указывал OpenWrt LuCI community
и URL общего LuCI. Исправлены обе переменные; новый control содержит Alexandr
и https://github.com/litvinovtd/qeli. Старый IPK сохранён; тот же контрольный тест
на нём FAIL, на новом PASS. Инструкция source hash больше не предполагает tar.xz:
этот SDK генерирует tar.zst; release-cut SHA/mirror hash остаётся обязательством.

Официальный x86/64 SDK24.10.4 скачан и сверён с release SHA256
229e871f734a2cee5ce3ad6a3e98d3836b0899bfdeaea4d9c2c5cc7b1fce1407.
Pinned LuCI75e41cba5160281b2d1dca922719efef29f7ffd8, packages Rust
f1470815f41fe199bfdafe9a91ad115bc2e91203 и base v24.10.4 сохранены с hashes.
Использован только нужный Rust feed recipe, без полного packages feed.
GNU awk установлен распаковкой скачанных deb в owned directory; host packages
не устанавливались. luCI host jsmin/po2lmo собраны штатным host-compile, затем
реальный LuCI compile -j1 создаёт IPK с минифицированным JS. Прямой package goal
не квалифицирует полный resolver, Rust bootstrap или сборку самого Qeli.

`scripts/test_openwrt_sdk.py`:3 SDK метода PASS без skips (реальная metadata,
stock IPV6=y, private Kconfig IPV6=n),3 IPK метода PASS без skips; packaged
minified JS проходит14 прежних LuCI сценариев. SDK скрывает IPV6 с default y,
поэтому первоначальный запрос n фактически давал y и не квалифицирует IPv4-only.
Последний n-test временно меняет только owned Config-build.in default, отключает
ALL/ALL_KMODS/ALL_NONSHARED, проверяет фактические символы и восстанавливает файлы.
Это private Kconfig branch coverage, не реальный IPv4-only firmware runtime.
IPK имеет четыре ожидаемых файла0644; RPC/ACL/menu bytes равны Git, JS меньше
исходника.37 native recipe/14 source LuCI/docs/bindings/diff checks PASS.

Попытка opkg install в пустой owned offline-root НЕ PASS: после исправления
fixture lock directory отсутствуют пять dependency packages; opkg отклоняет
candidate даже с force-depends/nodeps/add-arch. Начальные и последние logs
сохранены, temporary roots удалены. Fake installed dependency records не добавлялись.
Установка с настоящим resolver/зависимостями остаётся OPEN. Первые missing awk,
wrong feeds env, missing jsmin и неправильное ожидание IPV6=n сохранены как harness
FAIL, не product defects и не положительные результаты.

Прежний compiler cache только собственного завершённого Q31 Keenetic run на .11
сжат в target-cache.tar.zst; zstd/tar compare PASS, прежний qeli-client сохранён
отдельно с прежним SHA. Только после проверки удалён восстановимый target cache.
SDK, source feeds, IPK, inputs и logs сохранены. Нет процессов/temporary install
roots; host services/network/firewall и .10 не затронуты. Rust/core/native код,
ABI и опубликованные бинарники не менялись; новая Rust/FFI/cross сборка не заявлена.

Cargo.toml не объявляет rust-version. Rust1.89.0 в pinned SDK feed нельзя считать
несовместимым только потому, что предыдущая standalone recipe тестировалась
с1.97.0; первоначальная гипотеза о минимуме1.96 была неверной. Реальная совместимость
SDK Rust с Qeli, source pin/mirror release-cut и clean A/B остаются OPEN.
HTTP, preflight/core generation/ABA и administrator replacement races также OPEN;
firmware USER_EXCLUDED. Исторические41 certification cases и acceptance сохранены;
новое scoped supplement не заменяет их artifact/date/status.
Q31 IN_PROGRESS;28/37(75.7%),9 осталось. Q29 SIGKILL FAIL/auto-null ENONET,
Q30 Apple exclusions/callback-drain OPEN и D06 ACCEPTED сохранены.

Источники: [официальный SDK/hash](https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/),
[pinned LuCI package mapping](https://github.com/openwrt/luci/blob/75e41cba5160281b2d1dca922719efef29f7ffd8/luci.mk),
[pinned Rust recipe](https://github.com/openwrt/packages/blob/f1470815f41fe199bfdafe9a91ad115bc2e91203/lang/rust/Makefile).
Пакет: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-sdk-20261007.
Evidence: release/certification/evidence/q31-openwrt-sdk-20261007.json.

## Q31-V002: настоящий HTTP/session bridge (7 октября)

Закрыта прежняя HTTP API NOT_RUN граница в ограниченном scope: официальный
musl uhttpd2025.07.06~7e64e8ba-r4 и uhttpd_ubus.so из rootfs24.10.4 обращаются
к прежнему native GNU rpcd/ucode/fs/UCI runtime через private Unix socket.
Каждый тест выполняется внутри новых mount/net namespaces .11, HTTP слушает
только loopback этого namespace. Два owned chroot разделяют только socket directory
через private bind mount. Flag -a (authentication bypass) не используется.
Host /etc, services, network/firewall и .10 не менялись.

6 методов `scripts/test_openwrt_http.py` PASS без skips: anonymous/поддельная
сессия/неверный пароль; reader читает qeli и service status, но не secrets,
service mutations либо чужую UCI; writer передаёт пять закрытых service verbs
и literal Unicode/metacharacter secret через stdin, получает только boolean
secret status и очищает секрет; настоящие session UCI set→apply→confirm и
init-visible committed enabled; попытка вложить чужой ubus_rpc_session отвергается;
отзыв локальным session API и idle expiration запрещают дальнейший HTTP RPC;
HTTP выдаёт точные minified JS bytes предыдущего SDK IPK и восстанавливается
после malformed request. UCI firewall/rpcd write остаётся запрещённой.

Используются реальные packaged Qeli RPC/ACL/menu/JS из IPK предыдущего F353–F354,
а также настоящий неизменённый luci-base ACL. UCI transport methods поступают
из обязательного LuCI framework ACL; granular qeli config scope — из ACL Qeli.
Restricted login нуждается в read/write luci-base соответственно своей роли;
один luci-app-qeli не предоставляет framework UCI methods. API apply/confirm
соответствует LuCI; HTTP commit не подменяет его. Qeli ACL не расширен.
Начальный FAIL стенда без base ACL, polling продлевавший idle session,
неверное ожидание parse error и существующий receipt разрешённого чтения сохранены
и исправлены. Ошибка cleanup inventory принимала сохранённый runtime-template
за temporary root; он исключён по точному пути, не удалён. Нового дефекта продукта
не найдено; ложного baseline/product-regression утверждения нет.

Сверены все959 regular files/215 links official rootfs с прежним SHA-проверенным
архивом,28 regular/19 links GNU rpcd template и7 transferred Git inputs.
Нет owned процессов, mount/runtime roots после final run; все временные namespaces
завершены. uhttpd/plugin/ACL/status hashes и предыдущий IPK сохранены в пакете.
14 source LuCI/37 recipes/docs9/bindings/diff PASS. Rust/core/native/ABI/build
inputs и артефакты не менялись; прежние SDK/cross результаты сохраняют дату/scope.

Service verbs здесь идут в inert init adapter, не в работающий VPN/procd.
HTML login/DOM браузера, TLS/cookies/CORS/CSRF политика всего LuCI, OpenWrt PID1,
firmware и реальная VPN-сеть не квалифицированы этим HTTP API тестом.
Full SDK Rust build/resolver/install, source release-cut/compiler compatibility,
preflight/config/core generation/ABA и clean A/B остаются OPEN.
41 historic certification cases/acceptance сохранены; добавлено scoped supplement.
Q31 IN_PROGRESS;28/37(75.7%),9 осталось. Q29 SIGKILL FAIL/auto-null ENONET,
Q30 Apple exclusions/callback-drain OPEN и D06 ACCEPTED сохранены.

Источники: [release uhttpd recipe](https://github.com/openwrt/openwrt/blob/v24.10.4/package/network/services/uhttpd/Makefile),
[pinned HTTP/session bridge](https://github.com/openwrt/uhttpd/blob/7e64e8bad2415cec0a6d9770ec379db54273c7a7/ubus.c).
Пакет: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-http-20261007.
Evidence: release/certification/evidence/q31-openwrt-http-20261007.json.

## F355: Keenetic проверял и запускал разные версии INI (7 октября)

Оба шаблона проверяли редактируемый исходный INI, затем асинхронный процесс открывал
его снова. Настоящий сохранённый inspector ядра и собственный native process
воспроизвели атомарную замену сразу после проверки: оба baseline-варианта проверили
A, но запустили B (два subtest FAIL). Проверенные interface/gateway могли не совпасть
с конфигурацией запущенного клиента.

Общий lifecycle helper теперь публикует ограниченную приватную runtime-копию до
проверки; inspector и клиент получают /opt/var/run/qeli-launch/client.conf.
Владелец/mode сохраняются, доверие к командам не повышается. Source/runtime links
и nonregular targets запрещены; каталоги требуют root-owned0700. Installer проверяет
tools и владельца существующего config directory до package updates. Повторный start
работающего клиента сохраняет копию; restart перечитывает оригинал. Stop очищает
копию после подтверждённого join и network cleanup. Hook QELI_CONFIG_PATH указывает
на копию; мануалы описывают редактирование, recovery и изменившийся путь.
Новый shell INI parser, config format/schema или native ABI не вводились.

8 новых методов проверяют оба шаблона с настоящим preflight ядра и native process
identity: replacement, metadata, paths, bounded copy, publication failures, failed
join, repeated start/restart и отказы installer. Все192 Keenetic methods PASS без
skips в dash и BusyBox ash на .11. Первый полный прогон дал четыре fixture FAIL
на каждом shell: старые PID-publication tests ломали любой mv и попадали в новую
предшествующую публикацию конфига. Fault теперь ограничен PID destination;
новые tests отдельно проверяют отказ copy publication. Полный baseline7 methods
дал14failures/12errors из-за отсутствующих новых контрактов; это не26 product bugs.
Все initial/final logs сохранены.37recipes/14LuCI/docs9/bindings/diff PASS.

Inspector — прежний SHA-bound host binary:315/317 compile inputs точно совпадают
с текущим Git. Два позднейших portability edits (MIPS atomic fallback/procfs integer
cast) вне неизменённых CLI/parser/inspection; точные diff проверены. Свежая сборка
текущего core не заявляется. GCC -Werror сборка только у малого C receipt helper. Filesystem/network
commands остаются моделями; живой роутер/VPN/hook command execution не заявляются.
Product Rust/core/native/ABI/artifacts неизменны, прошлые cross results сохраняют
даты и scope. Cleanup собственных fixtures проверен; только приватные files/processes
.11, host services/network/firewall и .10 не затронуты. Старый model-only fixture6октября отдельно архивирован/сверен и удалён по точному пути; initial guard остановился без изменений, совпав с собственной командой verifier.

Закрыта замена редактируемого оригинала между Keenetic preflight и launch.
Root/admin replacement приватных runtime paths, core plan generation/ABA, OpenWrt
config generation, SIGKILL/power-loss transactions, полный SDK build/install/compiler
compatibility/source release-cut и clean A/B остаются OPEN. Firmware USER_EXCLUDED.
41 historic cases/acceptance сохранены; только scoped supplement.
Q31 IN_PROGRESS28/37(75.7%),9remain; Q29 SIGKILL FAIL/auto-null ENONET, Q30 Apple
exclusions/callback-drain OPEN и D06 ACCEPTED сохранены. Без push/deploy.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-keenetic-launch-config-20261007.
Evidence: release/certification/evidence/q31-keenetic-launch-config-20261007.json.

## F356–F357: Cargo config обходил pin компилятора и private intermediates (7 октября)

F356: cargo +pin фиксирует Cargo, но unset RUSTC/CARGO_BUILD_RUSTC позволял Cargo
выбирать другой executable через build.rustc. F357: одного CARGO_TARGET_DIR
недостаточно — build.build-dir/CARGO_BUILD_BUILD_DIR мог вынести intermediates
за пределы собственного target. Host gate также использовал default toolchain и
ambient flags. Оба router-варианта и захваченная настоящая команда client build
из host gate воспроизводят это реальным Cargo на маленьких private Linux probes:
compiler adapter из config меняет compiled receipt, config/environment перенаправляют
intermediates. Тот же финальный harness baseline4methods:9expected subtest FAIL,
без errors; это два дефекта, не девять независимых product bugs.

Общий router_toolchain находит и проверяет rustc выбранного pin до Cargo, явно
задаёт RUSTC и оба output directories. Оба maintainer helpers используют его;
keenetic_verify использует то же окружение и Rust1.97.0 для test/Clippy/graph.
Шаг router CI для четырёх targets выровнен. Failed/nonexecutable compiler lookup
останавливает Cargo. Прежние target-specific flags и MIPS nightly сохраняются.
Мануалы описывают named compiler/Clippy prerequisite и ограничения scope.
Project Rust/native/schema/ABI/published artifacts неизменны.

59 связанных router methods (7real-Cargo runtime, один новый host-prefix model)
и19 host-gate model methods PASS без skips на .11. Девять fixed compile/execute
receipts дают pinned вместо redirected; настоящий tiny test1PASS, Clippy -Dwarnings
и graph проходят при configured compiler trap. Это проверка выбора команд, не
собственные unit tests/dependency graph Qeli. Два failure guards покрывают все три
roots. Real rustc/cargo1.97.0/Clippy identity и SHA rustc сохранены. PyYAML6.0.3
разобрал настоящий CI;16rendered shell steps четырёх targets проходят bash -n.
37recipes/14LuCI/docs9/bindings/diff PASS. GitHub Actions, настоящий Zig и fresh
full Qeli/cross/SDK build не заявляются. На .11 свободно532MiB, RAM2GiB; probes
не требуют загрузки зависимостей.

Initial preparation остановилась до tests из-за отсутствующего local baseline
каталога; первый baseline8FAIL/1harnessERROR: tempfile выдал underscore, запрещённый
production root admission. Owned mktemp naming исправлено, все logs сохранены.
CRLF/Git mismatch одного test source сохранён, нормализован к canonical bytes;59-method suite повторён. 17transferred Git inputs финально проверены; probe processes/run roots отсутствуют,
CARGO_HOME только private. Host services/network/firewall/global config и .10
не затронуты.

Закрыты обычные build.rustc и config/environment intermediate-directory overrides
в этих командах. Полная hermetic Cargo home/ancestor configuration, forced env,
profile/source/linker/PATH/cache policy и независимые clean Qeli A/B OPEN.
Source release-cut/full SDK build/install/compiler compatibility, core plan
generation/ABA/admin replacement и SIGKILL/power-loss transactions OPEN;
firmware USER_EXCLUDED.41historic cases/acceptance сохранены; scoped supplement.
Q31 IN_PROGRESS28/37(75.7%),9remain; Q29 SIGKILL FAIL/ENONET, Q30 callback-drain
OPEN/Apple exclusions и D06 ACCEPTED сохранены. Без push/deploy.

Справочник: [Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html).
Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-router-cargo-20261007.
Evidence: release/certification/evidence/q31-router-cargo-20261007.json.

## Q31-V003: настоящая offline установка, обновление и удаление IPK (7 октября)

В официальном OpenWrt24.10.4 x86/64 rootfs на .11 выполнены7 интеграционных
сценариев настоящим opkg2024.10.16~38eccbb1-r1, все PASS без skips. Установка Qeli
и SDK LuCI IPK разрешает виртуальные iptables/ip6tables с реальными nft и legacy
провайдерами. Проверены точные payload bytes, root ownership, executable modes,
UCI0600 и запуск qeli-client --version. Нет force-depends или подставных installed
records: исходное состояние из официального rootfs,22 недостающих пакета скачаны
из соответствующих release core/base/kernel feeds. Все3 подписи индексов проверены
настоящим usign с release keys rootfs; каждый IPK SHA совпал с подписанным индексом.

Upgrade использует только audit fixture0.8.2-r2 с изменённым default comment,
упакованный настоящим SDK ipkg-build. Версия продукта не повышена. Изменённый UCI
сохраняется, новый default появляется в qeli-opkg; оба0600. Нетронутый default
заменяется. Удаление Qeli при установленном LuCI запрещено; после удаления LuCI
удаляются binary/init/defaults/RPC/ACL, изменённый UCI остаётся0600. Отказ без
зависимостей и truncated archive не меняют installed status/client payload.
Это ранние admission отказы, не доказательство атомарности при power loss.

SDK действительно выполняет Package/qeli/install и BuildPackage/ipkg packaging.
Audit overlay отключает source download/prepare/configure/Rust compile и подаёт
прежний SHA-проверенный standalone musl binary от6октября. Точные оригинальный
рецепт, overlay, артефакты и логи сохранены; исходный SDK рецепт восстановлен.
Новой сборки Qeli Rust внутри SDK нет; pin/mirror release-cut и SDK Rust1.89
compatibility остаются OPEN. Published artifacts, Rust/core/native/ABI неизменны.

Initial ошибки harness сохранены: незаполненный Download/default в packaging
overlay, повтор copytree поверх symlinks, пропущенный kmods feed, неверный lists_dir
и отсутствующий lock directory. Первый suite дал5PASS/1FAIL/1ERROR: несовпадение
текста ошибки и offline-root / нарушающий conffile lookup. Correct /target внутри
private chroot устранил ошибки; финальный suite7PASS. Первый r2 packager выдал
locale timestamp warning; fixture переупакован с LC_ALL=C и фиксированным epoch,
затем все7 tests повторены. Нового product bug не выявлено.

Все операции внутри собственных rootfs и mount/network/PID namespaces, без
подключения host proc/dev, загрузки модулей, запуска VPN или host служб. Offline
opkg не квалифицирует postinst/fw4/procd на живой firmware. WAN/reboot/DNS/firewall/
performance на физическом роутере USER_EXCLUDED. Полный SDK Rust build, core plan
generation/ABA/admin replacement и full hermetic clean Qeli A/B остаются OPEN.
Q31 IN_PROGRESS,28/37(75.7%),9remain; Q29 SIGKILL FAIL/auto-null ENONET,
Q30 callback-drain OPEN/Apple exclusions и D06 ACCEPTED сохранены.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-opkg-20261007.
Evidence: release/certification/evidence/q31-openwrt-opkg-20261007.json.
Upstream reference: [opkg conffile removal](https://lxr.openwrt.org/source/opkg-lede/libopkg/opkg_remove.c).

Сверены959 official rootfs files/215 links и6 transferred source inputs. Все317
входов прежней fixed musl сборки совпадают с текущим Git; обычная router derivation
crate-type=rlib сохраняет прежний scope. SDK strip меняет SHA binary: исходный
ec567377e46cd8a2ed629bccfb83318fba4e19bf26905df3f49ca77c254a5925, packaged
915b113abcb47ce37f40c79be70927b8d330217cb075ae161fc36ae9fffeac24. Оба сохранены.
37recipes/14LuCI/docs9/bindings PASS. Final owned processes/case/smoke/mount roots
отсутствуют; host services/network/firewall и .10 не затронуты. Без push/deploy.

## F358 / Q31-V004: SDK компилировал неиспользуемые FFI библиотеки (7 октября)

Выполнена новая проверка текущего client-bin настоящим Rust1.89.0 — версией pinned
SDK feed. GNU cargo check --locked --offline --release PASS. Полный musl cargo
install с GCC13.3.0 из официального SDK24.10.4 и фактически раскрытыми SDK flags/
profile PASS. Это prebuilt upstream rustc/std, не SDK bootstrap Rust из исходников.
Compiler, linker, locked dependencies и release source inputs зафиксированы.
На .10 использованы отдельные RUSTUP_HOME/CARGO_HOME/target, jobs1; global defaults
и cache не менялись. SDK GCC вместе с его bundled host loader/libs перенесён в
собственный каталог; оба архива проверены SHA/tar compare.

F358: baseline настоящий cargo install собирал rlib, cdylib и staticlib, хотя SDK
устанавливает только CLI. Оба лишних FFI outputs подтверждены в compiler argv и
артефактах. Build/Compile теперь проверяет lock и проецирует только private SDK
Cargo.toml на rlib; неизвестная декларация/отсутствующие inputs запрещают Cargo.
Исходный manifest проекта, Rust/core/schema/native ABI не менялись. Make $$
сохраняет regex anchor для sed. Оба production макроса раскрыты настоящим SDK,
сохранены точный вывод и явно указанные path substitutions для private compiler.
На маленьком настоящем Cargo/musl crate baseline даёт1 expected FAIL из-за .a/.so;
fixed5methods PASS без skips, включая existing rlib, unknown declaration и missing
lock/manifest. Полный текущий клиент затем повторно собран именно fixed macro,
без замены Compile на copy. Только rlib/rmeta, лишних FFI outputs нет; source
manifest после probe восстановлен. Кэш зависимостей использован повторно — это
не независимые clean A/B. SDK3 Kconfig/metadata methods PASS с fixed recipe.

Baseline и fixed ELF по9 actual executable cases PASS в official24.10.4 rootfs:
--version; legacy/core owner, BOM/quotes, attached TUN, wrong device/attach, TAP и
malformed INI refusals. Всего18 executions, не18 unit methods. Проверены ELF64/
x86-64 PIE, /lib/ld-musl-x86_64.so.1, libc.so/libgcc_s.so.1, BIND_NOW/RELRO и NX stack.
Mount/network/PID namespaces private, host proc/dev не подключались. VPN/TUN/
firewall не запускались; настоящая router firmware USER_EXCLUDED. ELF/projection/
inputs/logs сохранены; published binaries не заменялись. Никакой общей MSRV всех
features/платформ или SDK Rust bootstrap/source-download/target matrix не заявляется.

Cargo предупредил о locked der0.8.0: первичный RustCrypto changelog объясняет yank
исправлением minimal-versions CI. Lock не разблокирован; обновление dependency
stack относится к Q34. Это не подтверждение уязвимости и не compiler failure.
Первый standalone GCC запуск остановился без bundled SDK host libs; правильный
runtime перенесён перед сборкой, диагностика сохранена. Компилятор1.89 подтвердил
совместимость именно проверенного client-bin/x86 пути. Более новые helper1.97 и
MIPS nightly квалификации сохраняют прежние даты/scope.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-compiler-20261007.
Evidence: release/certification/evidence/q31-openwrt-compiler-20261007.json.
Первичный источник yank: [RustCrypto der changelog](https://github.com/RustCrypto/formats/blob/master/der/CHANGELOG.md).
Q31 IN_PROGRESS28/37(75.7%),9remain. Full SDK bootstrap/release pipeline, core plan
ABA/admin replacement и full hermetic Qeli A/B OPEN; Q29 SIGKILL FAIL/ENONET,
Q30 callback-drain OPEN/Apple exclusions и D06 ACCEPTED сохранены. Без push/deploy.

Итоговая сверка и очистка:364 входных файла crate из Git проверены до и после полной
сборки; сохранён перечень3228 файлов и ссылок инструментов компилятора/SDK. Оба
SDK-рецепта совпадают с текущим исходником.959 файлов и215 ссылок официального
rootfs сверены с архивом. Частные toolchain/cache/build-каталоги и runtime rootfs
удалены; процессов, mount-точек и compile-case-каталогов испытаний не осталось.
Глобальный перечень Rust toolchain не изменился. После очистки свободно:
.10=2588MiB,.11=467MiB.37 проверок рецептов,14 LuCI fixtures,9 проверок документации,
bindings и diff PASS. Сервисы, сеть и firewall хостов не изменялись.41 исторический
сертификационный случай сохранён; добавляется только дополнение с указанной областью.

## F359–F360: повторный start и отказ подготовки OpenWrt (7 октября)

F359: init атомарно обновлял client.conf, но передавал procd прежние command/path.
Повторный start с другим сервером или паролем возвращал успех, оставляя прежний
процесс с прежними данными. Теперь procd получает file-параметр для INI и файла
пароля. Штатное сравнение содержимого перезапускает instance при изменении данных;
повторная генерация тех же байтов сохраняет PID. Запись секрета сама по себе
не перезапускает VPN; применяется последующим start/restart/reload.

F360: rc.common закрывает и отправляет описание службы даже при ошибке
start_service. Пустой set удалял уже работающий instance после malformed MTU,
недопустимого dev или отсутствующего server. Обёртка ubus теперь запрещает
set/add при неуспешной подготовке и возвращает её ошибку. Намеренное отключение
профиля и stop/delete сохраняют штатное поведение.

На настоящих procd 2024.12.22~42d39376, ubus, UCI и rc.common из официального
OpenWrt 24.10.4: baseline даёт пять ожидаемых failures в трёх методах; исправленный
набор из 11 методов проходит без skips. Четыре новых метода проверяют смену INI,
смену пароля, idempotent start и сохранение процесса/INI при трёх отказах render.
Семь прежних методов охватывают stop/reload/respawn/autostart/ошибки транспорта.
Связанные 55 shell/renderer/dispatcher/ucode методов проходят на dash и BusyBox ash.
Retained INI inspector и ucode проверены по SHA; общий parser source совпадает
с текущим Git. Новая сборка Rust/FFI и обновление публикуемых бинарников не нужны.

Стенд использует отдельные mount/network/PID namespaces и собственную procfs
для корректной проверки PID; host proc/dev в chroot не монтируются. Клиент —
inert receipt/sleep adapter, TUN — маркер существования. Firewall и настоящий
VPN не запускаются; procd работает как non-PID1 daemon. Начальные ошибки CRLF,
несогласованной procfs/PID namespace и import path сохранены как ошибки подготовки,
а не ошибки продукта. Это не атомарная транзакция UCI/firewall/INI/core plan:
rollback после успешного render, core generation/ABA и admin replacement OPEN.

Механизм сверён с [исходником точной версии procd](https://github.com/openwrt/procd/blob/42d39376/service/instance.c).
Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-openwrt-config-generation-20261007.
Evidence: release/certification/evidence/q31-openwrt-config-generation-20261007.json.
Q31 IN_PROGRESS; 28/37 (75.7%), осталось 9. Q29 SIGKILL FAIL/auto-null ENONET,
Q30 callback-drain OPEN/Apple exclusions и D06 ACCEPTED сохранены. Без push/deploy.

Итог: 10 входных файлов и 4 retained артефакта проверены по SHA; 959 файлов/215 ссылок
rootfs повторно сверены, собственная template-копия удалена. Процессов, mount-точек
и runtime-каталогов испытаний не осталось. 37 recipe checks, 14 LuCI fixtures,
9 проверок документации, bindings и diff PASS. Исторические 41 case/acceptance
записи сохраняются; добавляется scoped supplement. .10 не использовался.

## F361: поколение runtime-файла сетевого плана (7 октября)

Ядро публиковало только адреса и MTU. Повторная аутентификация с теми же адресами
давала идентичные bytes: Keenetic мог принять прежний APPLIED receipt за текущий.
Переход A→B→A во время ndm apply/save также оставался невидимым сравнению файла.
Теперь Linux writer добавляет `generation=<NetworkPlan.generation>` после MTU,
сохраняя первую строку адреса и прежние именованные поля. Используется существующее
аутентифицированное поколение ядра; новых INI-параметров или JSON-конфигов нет.
Имеющиеся проверки полного файла в hook и APPLIED автоматически учитывают поле.

Это закрывает различение одинаковых адресов и ABA внутри монотонных поколений
одного адаптера. Счётчик не глобален: сброс адаптера/процесса, координация writer
с shell lock, смена после последней проверки, атомарность всей настройки ndm,
удаление прежних семей адресов и root/admin replacement остаются OPEN.
Старые runtime-файлы без generation продолжают читаться с прежними гарантиями.

На .10 Rust1.97 в приватных Cargo home/target с одним job и offline/locked:
derived baseline (те же formatter seam/tests, без единственной строки generation)
воспроизвёл 2 assertion FAIL и 1 PASS; fixed — 11 lifecycle unit tests PASS,
client-bin GNU check, production lib/bin Clippy `-D warnings` и fmt PASS.
Три новых unit methods покрывают legacy/IPv4, same-address reauth/ABA/u64 max
и dual-stack/IPv6-only. Baseline не выдаётся за неизменённый исходный файл.
376 Git/current compile inputs проверены до и после, приватная rlib-проекция
manifest восстановлена. Это не свежая FFI/SDK1.89/cross или published binary сборка.

На .11 — 194 Keenetic methods без skips на каждом dash/BusyBox ash (192 прежних
и 2 новых). Новые methods проверяют повторное применение тех же адресов с новым
generation и A→B→A при apply/save: отказ stale receipt, сохранение pending,
успешный retry нового поколения. ndmc моделируется; retained native helper и
metadata inspector используются только в прежних scoped ролях, inspected region
текущего ядра совпадает с источником retained binary. Это не firmware/VPN тест.
37 recipes,14 LuCI fixtures,9 docs checks,bindings и diff checks PASS.
Первоначально отсутствовавшие conformance inputs и запуск форматирования с
неверной edition сохранены как ошибки подготовки; final gate использует edition2021.
Собственные compile/cache каталоги .10 очищены после сохранения результатов.

Raw: `audit-debt-20260924/q31-plan-generation-20261007/`; seal, input SHA,
команды, времена и результаты включены в evidence. 41 historic cases/acceptance
сохранены. Q31 IN_PROGRESS; Q29 SIGKILL FAIL/auto-null ENONET, Q30 callback drain
OPEN/Apple exclusions и D06 ACCEPTED неизменны. Всего 28/37 (75.7%),9 осталось.

## F362–F363: поздний stale receipt и новое поколение процесса (7 октября)

F362: cached no-op проверял снимок плана до `ndmc show`, но не после него.
После последней проверки перед receipt, команды `mv APPLIED` и `rm PENDING`
тоже могли совпасть с независимой публикацией нового плана/marker. Hook возвращал
успех для прежнего состояния. Общая проверка теперь повторяет чтение marker/плана
перед no-op, после публикации receipt и после удаления pending. Наблюдаемая смена
возвращает отказ и сохраняет/восстанавливает pending для следующего события.
Файл старого receipt после `mv` может остаться; с pending он не разрешает no-op.
Это не откат уже выполненных ndm-команд и не очередь событий.

F363: новый start после выхода прежнего клиента удалял план, но сохранял APPLIED.
Локальный счётчик нового адаптера снова начинается с 1; одинаковые план/адреса
могли повторно использовать receipt прежнего процесса. OpkgTun init теперь
удаляет APPLIED перед новым launch, после успешной проверки INI/владельца и до
создания PID/процесса. Ошибка удаления запрещает launch. Start уже работающего
проверенного клиента сохраняет receipt; отказ preflight сохраняет recovery state.
Incomplete pending не удаляется этим шагом. Базовый init и Rust writer неизменны.

На .11 одинаковые 5 новых methods воспроизвели baseline8 assertion failures в
4 methods на каждом dash/BusyBox ash: show×plan/marker(2), mv/rm×plan/marker(4),
наследование receipt нового процесса(1), игнорирование ошибки очистки(1).
Preflight preservation — PASS уже в baseline. Fixed199 methods на каждом
interpreter без skips PASS (194 прежних +5 новых). Проверены успешный retry,
отсутствие ложного success log, повторный start без перезапуска живого native
helper и отказ запуска при directory receipt с сохранением canary/старого плана.
Процесс и /proc identity настоящие; ndmc/сеть — модели. Generation=1 после launch
публикуется fixture: C-helper проверяет process admission, не новый Rust handshake.
Retained metadata inspector использован только в ранее квалифицированной роли.
382 Git/current inputs и SHA2 retained artifacts сверены до/после; own process,
mount и temporary roots не остались. 37 recipes,14 LuCI,docs9,bindings/diff PASS.
Новых Rust/FFI/cross/SDK builds и firmware/VPN квалификации нет.

Counter reset закрыт в scoped протоколе нового launch обновлённого OpkgTun init.
Прямой запуск binary/замена адаптера вне этого протокола, writer/shell lock,
смена после самой последней проверки, atomic ndm и старые address families OPEN.
Общий shell lock нельзя просто брать в core writer: init удерживает его во время
start, а legacy ветка может ждать публикации плана. Без изменения этого протокола
получился бы цикл ожидания. Generation + bounded проверки не обещают синхронизации.
Raw: `audit-debt-20260924/q31-keenetic-receipt-20261007/`; source SHA, команды,
времена, baseline/fixed и seal в evidence. 41 historic cases/acceptance и34 прошлых
supplements сохранены. Q31 IN_PROGRESS,28/37(75.7%),9 осталось; Q29/Q30/D06 сохранены.

## F364: внешнее окружение меняло standalone release-профиль (7 октября)

Pinned Cargo/rustc и очищенный RUSTFLAGS не закрепляли profile.release. Переменные
из соседней FFI-сборки (например, CARGO_PROFILE_RELEASE_PANIC=unwind), Cargo home
и ancestor config могли изменить пять явно заданных полей qeli/Cargo.toml:
lto=fat,codegen-units=1,opt-level=3,strip=true,panic=abort. Получалась успешная
сборка с другим panic/оптимизацией/размером. Это воспроизведённая зависимость
сборки от окружения, а не найденный crash или новое измерение производительности.

Общий router_toolchain теперь передаёт эти пять CARGO_PROFILE_RELEASE_* значений
в дочерний Cargo. Обе standalone helper-сборки и Linux host gate используют его.
`--print-release-profile` выводит тот же набор для отдельного шага keenetic-cross
CI с working-directory=.; другие jobs, FFI unwind и SDK feed-профиль не изменены.
Новое сравнение с каноническим Cargo.toml проверяет совпадение exporter/helper/CI.
[Cargo документирует приоритет environment над config](https://doc.rust-lang.org/cargo/reference/config.html#environment-variables);
живые проверки ниже закрепляют результат для фактических инструментов лабы.

На .10 Rust1.97: одинаковый новый method проверяет12cells (Keenetic/OpenWrt/host ×
environment/Cargo home/owned ancestor/forced child env). Baseline9 assertion FAIL:
программа напечатала unwind|0 вместо abort|3; forced child env3cells уже PASS.
Fixed все12cells PASS; проверены пять фактических rustc flags. Вся real-Cargo suite
8methods без skips PASS (7 прежних +1 новый).72 router/host-gate methods на Linux
без skips PASS (53 helper +19 gate, включая новый manifest/export/CI contract).
Windows предварительно пропустил10 POSIX methods; эти же методы выполнены на Linux.

Дополнительно настоящий cargo-zigbuild0.23.0/Zig0.13.0/stock x86_64-musl std1.97
выполнил точную router_build_command в двух отдельных мини-crates без зависимостей:
baseline unwind|0; fixed abort|3 и пять compile flags PASS. Оба native static ELF
прошли общий target validator и реально запущены. Это маленькие probes, не Qeli,
не clean одинаковая A/B-пара и не новый четырёх-target/current-Qeli ABI build.
Каждый имеет собственные HOME/Cargo/target/Zig/XDG caches; они удалены после сохранения
ELF/логов. Pins, глобальные caches/defaults, сервисы, сеть и .11 не изменялись.
372 основной +1 supplemental Git/current inputs проверены; source/tools SHA и
command/result/timestamp в raw.37recipes/14LuCI/docs9/bindings/diff PASS.
CI exporter/placement проверены локально; новый GitHub Actions run не запускался.

Полная hermetic policy (другие profile keys, forced env, source/linker/PATH,
registry/tool caches), clean Qeli A/B, SDK bootstrap/source release-cut остаются OPEN.
Этот фикс квалифицирует пять явных standalone полей; он не обещает изоляцию всего Cargo.
Raw: `audit-debt-20260924/q31-router-release-profile-20261007/`; seal и scoped evidence.
41 historic cases/acceptance и35 прежних supplements сохранены. Q31 IN_PROGRESS,
28/37(75.7%),9 осталось; Q29 SIGKILL FAIL/auto-null ENONET,Q30 callback-drain OPEN/
Apple exclusions,D06 ACCEPTED неизменны. Published binaries не заменены.

## F365 / Q31-V005: независимые сборки зависели от временного пути исходников

Две полные сборки Qeli x86_64-musl выполняли точный общий standalone-рецепт с Rust
1.97.0, cargo-zigbuild0.23.0 и Zig0.13.0. У каждой были пустые target и Zig/XDG cache,
отдельные HOME/Cargo home и одинаковая offline-копия существующего registry.
Сборки шли последовательно, одним потоком. Все364 входа крейта совпадали и остались
неизменными; это сборка полного клиента, а не маленькой тестовой программы.

Обе baseline-сборки завершились успешно: статические ELF по5582856 байт, но96458
байт различались. В каждом были227 вхождений случайного mktemp-пути. Простая замена
строк не сделала файлы одинаковыми; исходный FAIL сохранён. Общий router/host helper
теперь передаёт `--remap-path-prefix=<owned root>=/usr/src/qeli`. Меняются записанные
в binary пути исходников, включая `file!()` и panic diagnostics; каталог не создаётся,
пути конфигов не меняются. MIPS soft-float сохранён. Канонические manifests,
Rust/core/FFI и SDK/CI recipes неизменны. Описание — в [rustc](https://doc.rust-lang.org/rustc/command-line-arguments.html#--remap-path-prefix-remap-source-names-in-output).

Один новый actual-Cargo метод воспроизвёл три baseline FAIL: Keenetic/OpenWrt/host.
Все9 исправленных actual-Cargo методов и72 Linux helper/gate методов PASS без skips.
Две новые полные исправленные сборки побайтно идентичны:5577864 байт, SHA256
`5132852d8b56ec588a503d52b4cc6cc4aa959d2c537e6ed47a2daa4518c2427b`.
Своих временных путей в ELF нет. Проверки ELF, help/version и24 INI metadata cases
на каждую пару PASS (48 baseline/fixed), без подключения. Проверены пять release
flags, отсутствие лишних FFI outputs и компиляция без готовых target-артефактов.
Предупреждения dependencies и deprecated linker optimization сохранены без подавления.
Глобальные registry/tools неизменны; временные каталоги удалены, своих процессов
и mounts не осталось. Опубликованные binaries не заменялись.

Подтверждён clean independent x86_64 standalone A/B с проверенной существующей
registry-копией. Другие ISA A/B, произвольная Cargo/config/linker/PATH/cache hermeticity,
SDK bootstrap/source release-cut и firmware runtime этим прогоном не подтверждены.
Firmware USER_EXCLUDED. Q31 IN_PROGRESS,28/37(75.7%); Q29 SIGKILL FAIL/auto-null ENONET,
Q30 callback-drain OPEN/Apple exclusions и D06 ACCEPTED сохранены.
Packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-router-clean-ab-20261007.
Evidence: release/certification/evidence/q31-router-clean-ab-20261007.json.

## Q31-V006: независимые полные сборки трёх оставшихся роутерных целей

Выполнены шесть новых полных сборок клиента Qeli: две независимые на каждую цель.
AArch64/ARMv7 используют Rust 1.97.0; MIPS — nightly-2026-06-10 и настоящий
`build-std=std,panic_abort`. Общий закреплённый standalone-рецепт, один job,
последовательный запуск, offline-копии одной проверенной registry. У каждой сборки
отдельные исходники, HOME/Cargo home, target и Zig/XDG/TMP caches.
Все 364 входа crate неизменны; временная rlib-проекция восстановлена.
Verbose logs подтверждают пять release-полей, remap путей, свежую компиляцию,
отсутствие лишних FFI outputs и приватных путей исходников в ELF.

| Цель | Размер каждого ELF | SHA256 обеих независимых сборок |
| --- | ---: | --- |
| aarch64-unknown-linux-musl | 4820920 | `6a0ae5622a9dd4ce58289e2ab0066d0d1600e1b6dec0269cf1199209452ea62a` |
| armv7-unknown-linux-musleabihf | 4984836 | `2a445c055db3ffc23f26e3adb59c8ecb8e9fe89ae6f74f251c8437530b3fe812` |
| mipsel-unknown-linux-musl | 6849048 | `591f593741b167832aa2bc7b06f9e3476ea336e8195246920915b0367ef4deb9` |

Все три пары побайтно идентичны и проходят общий static target-ELF admission.
Предыдущая пара x86_64 F365 используется после проверки всего seal из 74 файлов
и совпадения всех 380 входов текущего compiled packet с прежним fixed packet.
Тем самым independent A/B подтверждён для всех четырёх standalone-целей;
новый запуск x86_64 и полная Cargo hermeticity здесь не заявляются.

Каждый новый ELF выполнил help/version и 12 owner/interface INI metadata cases
в приватном QEMU user mode: 12 CLI-вызовов и 72 metadata cases PASS, без skips.
Три исполняемых файла QEMU 10.0.2 извлечены приватно из официального Debian security
пакета. До извлечения SHA архива размером 71008176 байт совпал с существующей
apt metadata:
`ac60ebf92f482731e6a89ff5428c805a74f3e66c062670b89c81d2f7512d6c38`.
Пакет, binfmt и системный emulator не устанавливались. Первая ссылка из устаревшей
main-repository metadata вернула 404; ошибка подготовки сохранена.
[QEMU user mode](https://www.qemu.org/docs/master/user/main.html) выполняет целевой
userspace через службы host kernel. CLI/parser-проверки не подтверждают роутерное
ядро, CPU-specific crypto, firmware, TUN, firewall или VPN-соединение.

Все шесть compiler roots удалены; своих работающих runner/process/mount не осталось.
Содержимое глобальных registry/toolchains/nightly-source неизменно. Собственные
исходники, ELF и tool evidence сохранены в пакете для инспекции. Build warnings
сохранены; новый full-cross Clippy и performance benchmark не заявляются.
Опубликованные binaries, Rust/core/ABI, manifests и lockfiles не менялись.

## F366–F367: release preflight обходил общую политику роутерной сборки

F366: старый source fingerprint удалял каждый CR-байт, в том числе из бинарных
шрифтов. Два разных реальных fixture-файла получили одинаковый fingerprint.
Dirty source inputs допускались с одним предупреждением. Оба дефекта воспроизведены
исполнением точного baseline function/gate AST с реальными binary fixtures и
явными SSH/subprocess-моделями; live-запуск старого preflight не заявляется.

F367: gate 2 собирал общий checkout через незакреплённые default Rust/rolling
nightly, без общего locked one-job рецепта, release fields, remap, rlib-проекции
и строгого ELF admission. Заданная лаба при отсутствии Paramiko могла тихо
пропускаться; моделируемая ошибка исполнения оставляла SSH незакрытым.
Baseline-команды, silent skip и отсутствие close сохранены.

Новый `router_release_gate.py` фиксирует один committed Git-архив `qeli/`, сохраняя
точные бинарные байты, и загружает его в собственный checkout через общие helpers.
Dirty source и участвующие recipe/helper inputs запрещены до SSH. Gate 2 использует
общие закреплённые toolchains/build command, rlib-проекцию и strict static target
ELF admission; SHA скачанного artifact обязан совпасть с удалённым SHA256.
Ошибка настроенной лабы проваливает preflight; SSH закрывается в `finally`.
`QELI_LAB_SRC` устарел. Gate 2 остаётся optional при отсутствии `QELI_LAB_PASS`.
Artifact не публикуется; приватный remote checkout сохраняется для инспекции.
Проверка tools следует действующему helper и может установить недостающие
закреплённые версии при запуске maintainer; в аудите этого не выполняли.

Финальные Linux-проверки: 15 уникальных gate methods с настоящими временными Git
репозиториями, binary CR/NUL, immutable snapshots и явными transport/ELF models;
72 существующих связанных метода PASS без skips. Все 750 финальных model inputs
проверены до/после исполнения. CI вызывает новые tests в native job; точная команда
также проверена локально. Первоначальные ошибки escaping fixture и дублирование
унаследованных methods исправлены до финального evidence. Шесть полных сборок
подтверждают общий compiler recipe; новая caller-обвязка проверена моделями,
а не полным live preflight/GitHub Actions dispatch.

Полный SDK Rust bootstrap, source-pin/mirror release-cut, произвольная env/Cargo/
linker/PATH/cache isolation и оставшийся source/dead-code review Q31 остаются OPEN.
Physical firmware USER_EXCLUDED. Q31 IN_PROGRESS; всего 28/37 (75.7%), девять
осталось. Q29 SIGKILL FAIL/auto-null ENONET, Q30 callback-drain OPEN/Apple exclusions
и D06 ACCEPTED сохранены. Без push/deploy.
Packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-router-cross-ab-20261007.
Evidence: release/certification/evidence/q31-router-cross-ab-20261007.json.

## F368–F369 / Q31-V007: SSH receive-window и диагностические соединения

Четыре точные baseline-реализации (`native_lab`, `lab_common`, Keenetic/OpenWrt
build helpers) читали stdout целиком перед stderr. Настоящая SSH-команда на .10,
записывающая сначала 3 МиБ stderr, затем 64 КиБ stdout, воспроизвела timeout
во всех четырёх случаях. Fixture ограничен внешним timeout; каналы после baseline
отказов закрывал test harness. Сервисы, firewall и сеть не менялись.

F368: общий `ssh_command.run_ssh_command` объединяет stderr в канал stdout через
Paramiko, передаёт EOF в неиспользуемый stdin, читает вывод перед exit status и
закрывает только command channel в `finally`. Удалены четыре отдельные реализации
последовательного drain; сохранены контракты whitespace, return tuple и exit code.
Вывод объединяется в порядке получения; отдельный порядок stdout затем stderr
больше не обещается. [Контракт Paramiko](https://docs.paramiko.org/en/stable/api/channel.html#paramiko.channel.Channel.set_combine_stderr).
Timeout остаётся operation timeout Paramiko; закрытие канала не доказывает
остановку удалённого процесса и не вводит общий wall-clock deadline.

F369: `connect_lab` закрывает созданный client при отказе подключения, сохраняя
исходную ошибку даже при ошибке close. Диагностический probe закрывает SSH в
`finally` и проверяет только установленные именованные pins. Rolling nightly и
default rustc/cargo proxies заменены guarded inventory/pinned executable queries.
Точные old AST models подтвердили отсутствие close при connect/probe failure;
скачивание старого rolling nightly и неверный пароль в лабе не выполнялись.

Исправленный код прошёл 16 настоящих SSH-проверок четырёх callers: pressure bytes
полностью сохранены, stdin EOF, nonzero exit, timeout и закрытие каждого канала.
После четырёх timeout соединение повторно использовано успешно. Все восемь
настоящих probe-команд прошли; toolchain/install inventory и tool hashes до/после
совпали. Linux: 35 native +90 router methods PASS без skips, включая семь новых
transport и три probe methods. Проверены все 764 model inputs до/после исполнения.
Локальные native contract78 (включая recipe37), release-gate15, docs9 и bindings
PASS. Windows-only запуск probe имел один ожидаемый POSIX skip; квалификация
берётся из Linux без skips. CI включает transport через native tests и probe
явной командой; новый GitHub Actions run не запускался.

## Итог source review Q31

Сверены 28 файлов роутерного среза: 21 production/declaration, три config examples
и четыре мануала. UCI/INI publication, volatile secrets/ACL/LuCI, procd lifecycle,
Keenetic PID/join/legacy recovery, OpkgTun plan/receipt, SDK package declarations,
standalone build/source/tool/artifact helpers и maintainer gates разобраны.
Общие transport/connect и recipe identity changes проверены отдельно.
Внешние rc.common/procd callbacks, rpcd methods, LuCI entry points и Make macros
сохранены; единичная текстовая ссылка не считалась признаком мёртвого кода.
Thin compatibility wrappers используются entry points/tests. Дополнительной
подтверждённой неиспользуемой production-реализации не обнаружено; отдельные SSH
реализации заменены общим helper. Source inventory/SHA/classification сохранены.
Критерий «Review и мёртвый код» закрыт в этом срезе; остальные четыре критерия Q31
сохраняют свои runtime/pipeline ограничения. Это не полный Q31 PASS.

Новый SSH helper включён в native recipe inputs и dirty admission release-gate.
Native provenance был STALE уже в исходном коммите и остаётся STALE: source/recipe
не соответствуют опубликованным cores. PROVENANCE, A/B evidence и binaries не
переписаны; полное обновление native A/B/provenance остаётся обязательством Q34
перед release. Текущий core/Rust/ABI, router compiler flags и artifacts неизменны;
новая Rust/cross сборка не заявляется. Certification manifest сохраняет 41 старый
case/acceptance и 38 прежних supplements; scoped evidence не означает green CI.
Своих pressure/model процессов и временных test roots не осталось; fixture/source
packet сохранён для инспекции. Полный SDK bootstrap/source release-cut, произвольная
hermetic policy, writer/lock/atomic ndm остаются OPEN; firmware USER_EXCLUDED.
Q31 IN_PROGRESS,28/37(75.7%),9осталось;Q29/Q30/D06 сохранены. Без push/deploy.
Packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q31-router-ssh-20261007.
Evidence: release/certification/evidence/q31-router-ssh-20261007.json.


## F370–F371: безопасный native preflight перед обновлением provenance

7 октября обновление native A/B заблокировано фактической ёмкостью лабы: на .10
около 2.3 GiB свободно, на .11 около 450 MiB при обязательных 8 GiB. Установленные
Rust1.97.0/targets, desktop Zig0.13.0/cargo-zigbuild0.23.0/GNUld2.44/rcodesign0.29.0
и Android NDK26.3.11579264/cargo-ndk4.1.2 прошли фактический inventory без установки.

F370: старый reset helper удалял pass A/B до проверки свободного места. Точная
baseline-функция на .10 удалила два маленьких контрольных файла, затем отказала
по диску. Исправленная функция на том же стенде отказала и сохранила оба файла.
Проверка ёмкости теперь выполняется на build root, если он существует, иначе на
существующем родителе `/var/tmp` до любых mkdir/rm; некорректный inventory также не допускает очистку. Это preflight,
не резервирование места и не гарантия против параллельного заполнения диска.

F371: source sync desktop/Android перенесён из общих `/opt/qeli-src` и
`/root/qeli-src` в отдельные `desktop-source`/`android-source` внутри собственных
native build roots. Все три Cargo-команды Windows/macOS/Android имеют `--jobs 1`
для серверов с 2 GiB памяти; OOM или предел RSS этим прогоном не доказывались.
Одновременные запуски одной группы пока не поддерживаются; общей hermetic policy
или нового global lock нет. Сервисы и глобальные инструменты не менялись.

36 native Linux methods PASS без skips; 80 локальных native methods PASS,
включая фактический capture трёх build-команд и отказ до очистки при bad inventory.
764 точных model inputs сверены до/после. Первоначальный Linux discover80 получил
20 ошибок отсутствующих нерелевантных входов расширенного GUI/recipe набора:
этот неполный model-прогон сохранён отдельно; Linux-квалификация ограничена
четырьмя полными native helper suites, полный80 проверен локально.

Старые собственные данные лабы сохранены в двух локальных архивах: 18 231 запись
на .10 и 138 114 записей на .11, плюс метаданные 918 неактивных socket-файлов.
Все обычные файлы/ссылки/FIFO сверены, remote contents до/после совпали;
распакованные потоки проверены на пароль без совпадений. Перед возможной очисткой
автоматическая проверка отклонила широкое удаление без отдельного одобрения точных
путей. Удаление не выполнялось. Архивирование и его результат отражены в raw packet;
неактивные Unix socket файлы учитываются метаданными, FIFO поддерживается tar.
До освобождения места и настоящих свежих A/B native provenance остаётся STALE,
release-блокер Q34 открыт. PROVENANCE/evidence/binaries не переписаны. Новая native
компиляция, экспортный gate, подпись или emulator runtime не заявляются.
Q31 IN_PROGRESS,28/37(75.7%),9осталось;Q29/Q30/D06 и platform exclusions сохранены.
Packet: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/native-refresh-20261007.
Evidence: release/certification/evidence/native-preflight-20261007.json.


## F372: допуск релиза по CI и сверка сценариев Q31 (7 октября)

Прежний первый release gate принимал успешный workflow, если локальный Git
завершался ошибкой и не возвращал коммит либо ответ CI содержал пустой `headSha`.
Оба ложных допуска воспроизведены на точном старом gate. Запрос `gh` также
наследовал каталог запуска команды вместо корня репозитория.

`release_ci_gate.py` сначала получает корректный локальный коммит, затем требует
корректный SHA CI, точное совпадение коммитов и завершённый успешный workflow.
Все Git/gh-команды выполняются из корня репозитория с ограничением времени.
Отсутствующие инструменты, ошибки команд, неверный JSON, неизвестный SHA,
устаревший CI и незавершённый/неуспешный workflow запрещают допуск. Имена failed
jobs сохраняются в диагностике; ошибка их получения не скрывает отказ и не
прерывает следующие gates. `release_preflight.py` подключён к общей функции,
dirty-recipe guard учитывает новый helper, а CI запускает его тесты отдельной
корректной командой unittest discovery. Инструкция архива использует имя из
metadata SDK; описание preflight исправлено на сравнение qeli/ subtree и
advisory-статус недоступных физических проверок.

Итог на `.11`: **77 router methods +18 CI-admission methods PASS, без пропусков**,
24 входных файла проверены по SHA. Router-набор включает настоящий POSIX source
replacement, изолированные checkout и небольшие проверки закреплённого
Rust/Cargo, а также модели отказов SSH/build/artifact; четыре полных клиента
заново не собирались. После последней правки диагностики повторены только
затронутые18 CI и15 release-gate methods. Рабочий qeli остался active/PID777.
Текущие native source/recipe digest и A/B evidence проходят provenance;
Rust, native-библиотеки, INI, router templates и опубликованные assets не менялись.

Настоящий read-only запуск всего preflight выполнен из родительского каталога.
Gate2 явно выключен без credentials; новой live cross-build здесь нет. Первый
запрос увидел старый неуспешный CI83c07f5c, последний — зелёный CIcde130e0.
Оба относятся к другому коммиту и отклонены. Gate3 также отклонил OpenWrt pin
dd0b7362 с другим qeli/ tree. Gate4 отклонил намеренно ещё незакоммиченное дерево
при этом предварительном запуске. Все gates дошли до общего verdict; release,
tag, dispatch Actions и push не выполнялись. Оба изменившихся наблюдения CI
сохранены в исходных логах.

Ошибки подготовки сохранены: первый baseline harness использовал null вместо
пустого SHA; первый локальный AST-тест выбрал strip() вместо run(); первая
Linux-загрузка пропустила lab_common; локальный snapshot wrapper выбрал неверную
кодировку. Промежуточная перекодировка комментариев workflow восстановлена из
точного baseline до итогового прогона входов. Это отдельно от product F372.

**Критерий штатных, граничных и негативных сценариев закрыт в доступном
платформенном объёме.** Он объединяет прежнюю evidence UCI/INI, ACL/HTTP, procd,
opkg install/upgrade/remove, SDK compile, четырёх target A/B/QEMU и Keenetic
lifecycle; даты, артефакты и ограничения этих результатов не переписываются.
Теперь в Q31 закрыты **2/5 критериев**, весь раздел остаётся IN_PROGRESS;
полный аудит28/37(75.7%),9 разделов остаются. Открыты full SDK Rust source
bootstrap/source-pin/mirror release-cut pipeline, configured live Gate2/Actions
end-to-end admission и описанные границы writer/lock, after-final-check,
atomic ndm/старых семейств адресов. Герметичность произвольной недоверенной
build environment не заявляется. Firmware runtime остаётся USER_EXCLUDED.
Q29 SIGKILL/auto-null ENONET, Q30 callback-drain/Apple exclusions и принятый D06
без изменений. Текущий долг14/15 DONE+D06 ACCEPTED; native/D11/D15 закрыты.

Raw packet: `audit-debt-20260924/q31-release-admission-20261007` (вне Git).
Машинная запись: `release/certification/evidence/q31-release-admission-20261007.json`.


## F373–F375: очистка адресов OpkgTun и сохранение ownership (7 октября)

F373: hook только добавлял адреса следующего плана. IPv6 допускает несколько
адресов, поэтому readdress или dual-stack→IPv4 сохраняли старый Qeli IPv6 в ndm
даже после нового успешного receipt. При исчезновении IPv4 сохранялся прежний
статический IPv4. F374: пустой pending не описывал частично применённый план;
обработка смены плана стирала payload, а новый launch и stop удаляли сохранённое
ownership, хотя ndm сохранял L3. F375: поиск токена мог разрешить cached IPv4 no-op,
если адрес встречался лишь в gateway/peer, а локальный адрес уже изменился.

До добавления нового адреса hook очищает устаревшие адреса из последнего
завершённого APPLIED и предыдущего частичного PENDING. Новый pending IF+plan
публикуется атомарно до новых L3-изменений. Ошибка cleanup/publication или
обнаруженная замена сохраняет retry intent и старый payload. Успешный save
по-прежнему предшествует APPLIED и удалению pending. IPv6 удаляется конкретной
командой с записанным адресом/prefix; отсутствие IPv4 разрешает сброс только при
совпадении с текущим локальным `address:`. Заменённый IPv4 и другие IPv6
сохраняются; peer не разрешает ни очистку, ни cached no-op. При смене интерфейса
удаляются лишь записанные адреса прежнего проверенного OpkgTun, без удаления
интерфейса/политик ndm. Ошибка show прежнего интерфейса сохраняет recovery,
а не трактуется как его отсутствие. Синтаксис сверён с официальным
[справочником Keenetic](https://docs.help.keenetic.com/cli/3.1/en/cli_manual_kn-1910_tr.pdf),
interface ip address и interface ipv6 address; это не проверка KeeneticOS5.

Новый launch сохраняет saved/partial ownership и принуждает к свежему apply через
создание/сохранение pending. Повторный start проверенного работающего процесса
сохраняет состояние. Stop сначала выполняет join, удаляет marker/current plan,
но оставляет адресные записи, поскольку ndm оставляет L3. Без marker wan.d
не применяет настройки. Linked/nonregular records запрещают свежий launch.
Старые пустые pending совместимы; потерянные записи не доказывают ownership и
требуют ручной сверки. Обе operational инструкции Keenetic обновлены.

Итог: **218 Keenetic methods PASS на каждом dash и BusyBox ash, без пропусков**:
настоящие собственные POSIX файлы/locks/processes и текущий неизменённый common-core
inspector; ndmc/firewall/sysctl моделируются. Добавлены14 stateful address
сценариев и два native stop/start/pending-path сценария. Точный старый hook
провалил регрессионный набор; точный старый init провалил обе ownership-проверки
на том же native helper. Первые214/217-method PASS и baseline failures сохранены.
Точная новая CI-команда на14 методов также прошла с uid/gid65534 без root-only
предположений; подключена к CI, Actions не запускались. Прежний C process fixture
пересобран с -Wall/-Wextra/-Werror; VPN/TUN/routes/firewall на host не применялись.
Служба осталась active/PID777; .10, текущие Rust/native/router artifacts и
установленные toolchains без изменений. Новых полных Rust/cross/native сборок
нет; current A/B provenance остаётся PASS.

**Критерий отказов и cooperative lifecycle concurrency закрыт:** он объединяет
прежнюю evidence init/hook/installer exclusion, process join, partial apply и retry.
В Q31 закрыты **3/5 критериев**, раздел IN_PROGRESS; весь аудит28/37(75.7%),
9 разделов остаются. В оставшейся интеграции не заявляются участие writer в
shell lock, смена после последней проверки, атомарность нескольких ndm-команд,
формат адресов firmware или роутерная сеть. Full SDK source bootstrap/source-pin/
mirror release-cut и configured live Gate2/Actions end-to-end ещё открыты.
Firmware остаётся USER_EXCLUDED; Q29 SIGKILL/auto-null ENONET, Q30 callback-drain/
Apple exclusions и принятый D06 без изменений. Долг14/15 DONE+D06 ACCEPTED;
непроверенного исправления в этом пакете не остаётся.

Raw packet: `audit-debt-20260924/q31-opkgtun-address-retirement-20261007` (вне Git).
Машинная запись: `release/certification/evidence/q31-opkgtun-address-retirement-20261007.json`.


## F376–F378: проверка исходников OpenWrt перед релизом (7 октября)

F376: прежний Gate3 принимал `HEAD`, ветку или тег вместо полного commit SHA,
а первое присваивание metadata могло скрывать последующее значение Makefile.
F377: отсутствие версии Cargo пропускало сравнение; версия читалась строковым
поиском вместо `[package]`, запросы Git не имели timeout и проверки типа объекта.
F378: корректная по форме строка SHA256 считалась достаточной без сверки байтов
SDK-архива. Точная прежняя реализация допускает четыре воспроизведённых случая:
HEAD, повторное присваивание, другой архив и отсутствующую версию пакета.

Общий `scripts/openwrt_source_gate.py` заменяет прежний встроенный блок Gate3.
Проверяются чистые участвующие пути, однозначные literal := metadata, полный SHA
именно commit-объекта и совпадение закреплённого `qeli/` tree с candidate.
Ветка/тег/сокращённый ID, define/undefine/eval с прямым повторным присваиванием,
невалидный Git/TOML и отсутствующая или наследуемая версия закрывают допуск.
Cargo читается из того же зафиксированного commit; Git queries ограничены30s.
Старый commit с идентичным crate tree допустим: равенство SHA самому HEAD
не требуется, иначе commit с новым значением pin был бы невозможен.

`QELI_OPENWRT_SOURCE_ARCHIVE` теперь обязателен для Gate3: путь к локальному
SDK-generated Source archive из package metadata. Сверяется реальный SHA256,
без download/extract; отсутствующий, пустой, nonregular, symlink или наблюдаемо
изменившийся файл, несовпадение и skip/placeholder блокируют релиз. На POSIX
O_NONBLOCK/O_NOFOLLOW и fstat открытого fd не дают зависнуть на FIFO и читать
подменённую ссылку; особый файл отвергается до hashing. Оба gate проверяют
наблюдаемые состояния, а не защищают от привилегированного изменения после
последней проверки. Произвольный Make/environment не интерпретируется; SDK
генерация содержимого архива и full Rust bootstrap не объявляются выполненными.

**25 source-gate методов PASS без skips на Linux uid/gid65534**: реальные
временные Git repositories, version/tree/pin faults, binary CR bytes, file integrity,
FIFO/link и observed mutation; четыре старых fail-open пути воспроизведены.
После добавления eval/undefine повторён только изменённый набор25. В точном
обычном CI запуске24 проверены и1 исторический baseline явно skipped, потому
что он включается отдельной переменной.18 CI admission и15 router release
методов PASS без skips.20 transferred input SHA совпадают до/после; реальные
SDK source archive generation/full compilation/Actions не запускались.
Первый Windows прогон:24 метода,1 symlink privilege error и1 POSIX skip;
fixture разделён, окончательный Linux прогон квалифицирует оба POSIX случая.
Финальный Windows:23 PASS и2 явных POSIX skips.
В рабочем development tree старый package pin остаётся ожидаемой причиной
отказа; pin/hash не менялись. Мануал OpenWrt и CI обновлены. Rust/native recipes,
публикуемые binaries и provenance unchanged/PASS. .11 qeli.service active/PID777
сохранён, .10 не использован; ни host network/firewall, ни tools не изменялись.

Q31 остаётся **3/5 criteria, IN_PROGRESS**, whole audit28/37(75.7%),9remain.
Source admission закрыт в проверенном объёме; full SDK bootstrap/release-cut,
configured Gate2/Actions integration и writer-lock/atomic ndm/firmware границы
остаются. USER_EXCLUDED firmware/Apple/WindowsVM, Q29SIGKILL/ENONET,
Q30callback-drain и D06ACCEPTED не меняются. Debt14/15DONE+D06ACCEPTED.

Raw packet: `audit-debt-20260924/q31-openwrt-source-gate-20261007` (outside Git).
Machine record: `release/certification/evidence/q31-openwrt-source-gate-20261007.json`.


## F379 / Q31-V008: реальная SDK генерация архива и проверка prepare/compile (7 октября)

Официальный SDK24.10.4 SHA229e871f… распакован в private каталог .11.
Использованы закреплённые Rust feed files и SHA-bound gawk/libsigsegv debs,
извлечённые приватно без host installation. Git fixture содержит точный committed
qeli/ tree26a0402e… и LICENSE. Его local URL/pin относятся к fixture, не к релизу.
Настоящие SDK rawgit/download/tar/zstd создали qeli-0.8.2.tar.zst,1541480bytes,
SHA49450a5b4803b8e2b657a49c5b4fdbb5c0373813275904ab9c1e689c52850b58.
Повторный download побайтно идентичен; tree распакованного qeli/ совпадает.
Настоящий CHECK=1/FIXUP=1 изменил hash только private recipe. Source gate прошёл
на committed fixture recipe с реальным SDK-generated архивом.

F379: SDK Git fallback/download и prepare возвращали0 при неверном mirror hash
и распаковывали исходники. CHECK может предупреждать; обычный download не обязан.
Прежний комментарий recipe о гарантированном отказе был ошибочным. Build-only
verify-source.sh теперь проверяет архив в Prepare/Pre и при входе в Compile,
до Cargo и rlib projection. Требуются regular/nonempty/nonlinked файл, literal
hash и успешный hash command. Явные SDK developer overlays сохраняются, но не
считаются mirror-qualified релизом. Инструкция копирования включает новый файл;
Package/install не переносит его на роутер. Privileged replacement после проверки
и произвольные Make overrides остаются вне этого ограничения.

Исправленный actual SDK prepare отказал до unpack при bad hash, а при правильном
сохранил exact source tree. Actual GNU-make-exported Compile macro с inert Cargo
показал: старый bad hash вызывает metadata/install; новый bad hash делает0calls
и сохраняет manifest; valid hash делает2calls. Это compile boundary, не новая
Rust-сборка.7 integration stages PASS;9 shell methods на каждом dash/ash и25source
methods PASS,все Linux методы uid65534/zero skips.7 final source/test/CI SHA
совпали до/после. Новый helper включён в dirty admission и CI; Actions не запущен.
Native provenance current/PASS; production source pin/hash не менялись.

Ошибки подготовки сохранены: отсутствующий SDK tmp для flock; ожидание обязательного
warning; неправильное имя fixture unpack-directory; CRLF shell upload с Windows.
Финальный LF helper и корректный source directory квалифицируют отказ/успех.
Auto-review отклонил расширение SDK0700 до0755 ради nonroot теста, действие не
выполнено. Использован отдельный новый0700 каталог владельца65534; SDK остался0700.
Нового запроса одобрения нет. Source archive generation/check/fixup/prepare теперь
scoped PASS. Full SDK Rust bootstrap, свежая полная compile/package/release cut/CI
и физическая прошивка ещё не квалифицированы. Нет publication/tag/push.

Q31 остаётся3/5criteria IN_PROGRESS; общий аудит28/37(75.7%),9remain; текущий
долг14/15DONE+D06ACCEPTED. Q29SIGKILL/ENONET, Q30callbackdrain/Apple exclusions,
firmware/WindowsVM exclusions и D06ACCEPTED сохранены. .10 только read-only
inventory; .11 qeli.serviceactivePID777 сохранён. Host network/firewall/default tools
не изменялись.

Перед очисткой сохранены и SHA-проверены fixture Git bundle, SDK package/config/feed overlay, private dependency packages и оба source archives; исходный официальный SDK archive сохранён в прежнем sealed packet. Удалены только созданные здесь SDK/deps/source/home/prepare/shim каталоги и дубликат официального архива после проверки отсутствия процессов/mounts. Raw logs и отдельный небольшой unit-inputs каталог сохранены; qeli.service active/PID777 не изменился.

Предкоммитная сверка отказала на различии CRLF Windows checkout и Git LF; затем все43 Linux метода повторно прошли на точных staged Git bytes,7 SHA совпали до/после. Исходные43 результатов и причина отказа сохранены.

Raw packet: `audit-debt-20260924/q31-sdk-source-integrity-20261007` (outside Git).
Machine record: `release/certification/evidence/q31-sdk-source-integrity-20261007.json`.

## Q31-V009: настоящий 32-битный release gate и запуск CLI под QEMU (7 октября)

Выполнен `verify_router_release` из текущего committed snapshot `0000ead0`,
через настоящий SSH/SFTP на .10. Это helper Gate2; весь `release_preflight.py`
и GitHub Actions этим запуском не квалифицируются. Кандидат имеет прежний
qeli/tree26a0402e; код продукта и рецепты не изменялись.

| Target | Компилятор | Release artifact SHA256 | Результат |
|---|---|---|---|
| armv7-unknown-linux-musleabihf | Rust1.97.0, Zig0.13.0/cargo-zigbuild0.23.0 | 373068ebb4c7e9361eeabe573b6c74ba7ee15d95c4248425bd266f2f6cfcef2e | PASS;4982148bytes,ELF32/ARM hard-float/static |
| mipsel-unknown-linux-musl | nightly-2026-06-10 с rust-src/build-std;тот же Zig | 41ba9a0b324b790c320daac4c65d5a8698d98b7f6c4936f753eda226a3b2bed7 | PASS;6846296bytes,ELF32/MIPS O32/static PIE |

Каждая сборка выполнялась последовательно, с locked dependencies/jobs1 и общим
release profile. Проверены скачанные байты/SHA/ELF.317 transferred compile inputs
совпали с Git archive; единственная предусмотренная derivation — private manifest
rlib projection. Отсутствующие package-only файлы вне sync build contract учтены
отдельно. Это свежие target directories с повторным использованием общих caches,
не independent clean A/B и не произвольная hermetic environment. В обеих сборках
сохранён warning линкера о deprecated optimization setting1.

Сохранённые артефакты реально запущены через QEMU10.0.13, ARM cortex-a7 и MIPS24Kc,
uid/gid65534:32/32 executions PASS,16 на архитектуру. Version/help, legacy/core
owner, BOM/quotes, attached router, device/attach/TAP mismatch, malformed/duplicate/
unknown INI, missing/nonregular config, неполная CLI expectation pair и неисполнение
post_up при инспекции. Проверен настоящий CLI/common parser в обоих ELF32 binaries;
VPN/TUN/networking/firewall/throughput через эмуляцию не запускались.

QEMU из [официального Debian package](https://packages.debian.org/trixie/amd64/qemu-user/download),
SHAca6ede739327a20ae5a3498230c8a3a9a072c586e131bc6bcc1201eb1725e336,
распакован privately: только два static emulators,без system install/binfmt changes.
Первый fetch по устаревшему APT index дал404; подготовительная ошибка сохранена,
новый официальный archive checksum проверен. Это не ошибка продукта.

Named tool inventories/hashes/default settings до/после идентичны; qeli PIDs745/901
и inactive qeli.service/MainPID0 на .10 сохранены. .11 не использовалась. Source
archive, оба клиента, emulators/package и logs сохранены локально с SHA; собственные
compile/emulation roots удалены после process/mount/identity guards. Host network
policy commands не выполнялись; whole-host firewall invariant без baseline не
заявляется. Native inputs/artifacts/provenance unchanged/current PASS.

Live Gate2 helper/32-bit CLI scope закрыт. Полный preflight/Actions/release-cut,
production source pin/hash и full SDK Rust source bootstrap, writer-lock/atomic ndm
и firmware остаются в прежней очереди. Q31 IN_PROGRESS3/5,28/37overall,9remain;
D06ACCEPTED,Q29SIGKILL/ENONET,Q30callbackdrain и USER_EXCLUDED платформы сохранены.
Нет новой непроверенной правки продукта, push/deploy/release не выполнялись.

Raw packet: `audit-debt-20260924/q31-live-release-gate-20261007`.
Machine record: `release/certification/evidence/q31-live-release-gate-20261007.json`.

## F395: согласованная публикация ядром и применение NDM на Keenetic (8 октября)

Повторные проверки поколения оставляли гонку между проверкой и командой:
ядро могло заменить `qeli.tunip` перед мутацией NDM. Следующая проверка обнаруживала
смену и оставляла pending, но не предотвращала уже выполненную устаревшую команду.
Общий lifecycle-lock для writer создал бы взаимное ожидание при старте: init
удерживает его, пока ждёт первый план.

Linux writer теперь захватывает `$QELI_TUNIP_FILE.publish-lock` через атомарный
mkdir только вокруг прежней атомарной записи. Ожидание расходует общий бюджет
NetworkPlan, не более 15 секунд. Согласованный хук берёт тот же каталог перед
повторным чтением готового плана и удерживает до завершения apply/save, receipt
и удаления pending. Создание attach-интерфейса и ожидание первого плана идут без
этой блокировки. Ядро освобождает её до post-up; shell cleanup освобождает обе
блокировки при штатном выходе и обработанных сигналах. Неизвестный/stale lock сохраняется.

Старый хук с точным новым Rust-компонентом блокировки и seam атомарного rename
воспроизвёл три ожидаемых FAIL из четырёх проверок. На dash и BusyBox ash все четыре
PASS: writer ждёт save/receipt; занятый writer запрещает NDM-команды; первый план
публикуется при удерживаемом lifecycle-lock; неизвестный владелец сохраняется.
Тело записи в этом fixture — seam, не полный VPN/NDM runtime. Пять тестов production
Rust-lock проверяют unwind, живого владельца, stale/file owner, истёкший общий бюджет
и сохранение неизвестного содержимого каталога. Все 2444 Linux library теста PASS,
60 прежних ignored; strict all-target Clippy и сборка настоящего Linux-клиента PASS.
196 прежних Keenetic methods и четыре новых проходят на каждой оболочке без skips
(400 выполнений), включая настоящий INI-инспектор и собственный native process
fixture. Одиннадцать сравнений Git-файлов и неизменный остаток клиентского модуля
согласуют прежние проверки atomic writer/durability, бюджета, ABI и build recipes.

Producer исходников: `17c5d382c529a896ddf78b7bb56d1e9b8e157bfa`, native digest
`efbe3f1c4f90784ad07a0cb1768b1494ba95debe7815dba6067ec1c74be3d858`;
318 точных Git/archive native inputs. Свежие A/B/export и Windows ABI/Android JNI,
хеши и границы записаны в
[q31-plan-publication evidence](../../../../release/certification/evidence/q31-plan-publication-20261008.json).
Raw: `audit-debt-20260924/q31-plan-publication-20261008` вне репозитория.

Сохранены результаты подготовки: предварительный shell-прогон имел 71 skip без
fixture и одно устаревшее ожидание отказа при смене до захвата lock. Новое ожидание
требует применения перечитанного текущего плана, отсутствия setter старого адреса,
точного receipt и одного save. Локальный cp1251 read упал до этой правки; первая
сборка inspector не указала обязательный client-bin; selector лога текущего прогона
исправлен собственными aliases без перезапуска компиляции; первоначальный selector
backup unit binary ожидал qeli вместо qeli_core и ничего не удалил. Завершённые
Linux-тесты и Clippy не повторялись. Снимки исходного сервиса/сети .11 совпали точно. На .10 три ранее наблюдавшиеся legacy FORWARD/MASQUERADE строки перешли из default firewall snapshot в legacy snapshot. Причина не установлена; из сравнения исключены только эти точные строки. Остальные сетевые снимки и записи исходных процессов/сервиса совпали. Native harness не выполнял мутаций сетевой политики; неизменность всего host firewall не заявляется. Первоначальная final-check проверка потребовала полного совпадения, отвергла этот drift и была приведена к уже документированному ограниченному guard.

Обновляй binary/helper/hook вместе. Смешанный старый комплект и записи администратора
не кооперируют. Команды NDM последовательны; ошибка сохраняет ownership для повтора,
а более новый опубликованный план требует следующего события wan.d. Полная атомарность
NDM, VPN handover, физическая прошивка и power-loss recovery не квалифицированы.
SIGKILL и release panic=abort могут оставлять lock с проверяемым ручным recovery.
Закрыта гонка согласованного writer/hook, весь Q31 остаётся открытым. Полный SDK
Rust bootstrap/build и release-cut/preflight/Actions OPEN; прежние standalone
cross/QEMU доказательства сохраняют исходную дату и snapshot.
Q31 остаётся3/5 IN_PROGRESS; общий аудит29/37(78.4%),8осталось. Состояния Q29/Q30/D06
и исключения платформ сохранены. Push/deploy/release не выполнялись.

## F396: preflight объединял проверки разных коммитов (8 октября)

Каждый gate отдельно читал HEAD. Checkout или коммит во время CI, долгой сборки
в лабе либо сертификации позволял объединить успешные результаты разных версий
и получить общий PASS. Старый целый скрипт воспроизведён с настоящими временными
Git-репозиториями и контролируемыми внешними gates: штатный контроль проходит,
три сценария смены коммита ошибочно проходят. Это проверка оркестрации, не новые
прогоны Actions, роутерной сборки или релизной сертификации.

До внешних запросов допускается один чистый committed working tree. Между каждым
gate и после сертификации проверяются тот же коммит и чистота; при изменении
следующие gates не запускаются. Snapshot и source_commit отчёта сборки обязаны
совпадать с исходным коммитом. Обычные независимые отказы gates суммируются.
Для процесса сертификации установлен timeout120секунд, ошибки запуска дают FAIL.
Импорт модуля больше не запускает preflight. Gate2 остаётся optional; production
OpenWrt pin/hash не менялись. Ignored caches и изменения, полностью сделанные и
откаченные внутри одного gate, вне этой проверки границ. Это не блокировка
privileged writers и не разрешение публиковать после последующих изменений.

12 методов полного скрипта покрывают clean/dirty/untracked/ignored inputs, три
момента смены коммита, промежуточную правку, накопление отказов, snapshot/report
mismatch, timeout и ошибку закрытия SSH. Windows:78PASS из81 методов; три старых
POSIX/opt-in source-gate skips. Linux:56 связанных orchestration/CI/router/
certification методов без пропусков,uid65534.328 staged Git Python-файлов сверены
до/после; приватный fixture удалён после SHA-сверенного backup и process/mount/path
guards. Первичная Windows-обвязка очистила PATH и остановилась на поиске Git;
окружение исправлено, содержательные проверки затем прошли. Rust/native source,
бинарники и SDK recipe не менялись; native SHA/provenance применимы. Новые тесты
включены в CI.

Настоящий read-only запуск всего preflight записан в scoped evidence: ожидается
отказ для unpublished/stale CI и development source pin; validator metadata
сертификации проверяется отдельно. Optional lab builds не повторялись: прежние
ARM/MIPS/QEMU evidence сохраняют исходные SHA и дату. Закрыт дефект смешанного
вердикта, но full SDK Rust bootstrap/build, production release-cut archive и
успешные актуальные Actions/preflight остаются OPEN. Лабы проверены только чтением
(около2GiB RAM и9GiB свободно каждая); bootstrap/capacity guarantee не заявлены.
Q31 остаётся3/5IN_PROGRESS; весь план29/37(78.4%),восемь осталось.
Q29/Q30, исключения пользователя и D06 сохранены.

Evidence: `release/certification/evidence/q31-preflight-identity-20261008.json`.

## F397–F398: разбор старого CI и исправление двух fixtures (8 октября)

Read-only GitHub diagnostics for run37598403060 at83c07f5c confirmed three failed
jobs. Its native-libs failure is old stale provenance; the current four cores and
provenance pass locally with the already qualified F395 source. This is not a new
successful Actions run. macos-build rejected its per-app-ci output leaf because
the production build permits only dist/per-app-arm64. CI now uses that permitted
leaf; the path fixture executes the exact production command against build.sh with
all build/remove tools mocked. Old CI command independently fails; fixed11 Windows
cases pass (symlink unavailable),12 Linux uid65534 cases pass without skips. This
fixture is also in the Linux CI job and does not require Xcode or weaken path guards.

The iOS known-key test supplied exit_node=true with the default full gateway,
contradicting shared split-routing validation. Its exit-node fixture now adds
supported gateway=false, which projects split mode; other known-key examples stay
unchanged. The actual shipped configuration ABI reproduces the old refusal and
accepts the corrected example plus five other keys (seven checks). Initial attempts
to write explicit routing keys were rejected by the native editor and discarded;
no unsupported INI syntax remains in the fixture. This proves common policy only,
not execution of Swift XCTest. iOS Keychain errors status(-34018) remain OPEN for
signed test-host/runtime qualification. Apple runtime exclusions are preserved;
no signing/entitlement bypass or failure-to-skip conversion was made.

Both private Python/path lab roots were removed after verified backups and guards.
The path backup's initial tar directory-mtime error was retained as a preparation
note; only backup was retried. Current native SHA/provenance remain valid; Rust,
SDK recipes, production pin/hash and client runtime code are unchanged. Q31/full
plan counts remain unchanged. A fresh successful Actions run is still required.

## F399 / Q31-V010: сборка исходников до IPK в настоящем SDK (8 октября)

Полный make target пакета, в отличие от прежнего отдельно экспортированного Compile,
повторно раскрывает команду через GNU make. Якорь sed терял разделитель, и сборка
останавливалась до Cargo с `unterminated s command`. Фактический baseline сохранён.
Теперь перед изменением проверяется точное допустимое объявление библиотеки,
подстановка не содержит dollar-anchor, а итоговая проверка точного rlib сохраняется.
Неизвестное объявление, суффикс и отсутствие Cargo.lock отклоняются до изменений/Cargo.
Проекция применяется только к приватному Cargo.toml SDK.

Официальный x86/64 SDK24.10.4 создал Git source archive из приватного immutable fixture
с точным деревом qeli bfa0cfc6b25f7c2ddd1a15799bcf75ecf80f38e8 (b68bf907).
URL/pin/hash изменены только в fixture; production-значения сохранены.
Настоящие download, проверка hash, prepare, client-only metadata/install Cargo,
musl link GCC13.3 SDK, install, проверка зависимостей, strip и упаковка IPK прошли.
Свежий IPK:2259448байт, SHA256
`f73c53d42de06b8cc885e7a9829bbf0bbb84c22abfdbcaa4a4169889883382fa`.
Внутри SDK-клиент и три точных production init/UCI/default файла.

Прямой вход make пакета использует приватные официальные prebuilt Rust/std1.89.0
и копию существующего registry. Upstream bootstrap компилятора Rust не выполнялся;
cold/hermetic build не подтверждён. На .11 работал один компилятор.
Первая упаковка отказала из-за отсутствующих libc/libgcc provides; штатный рецепт
package/toolchain SDK сформировал настоящие таблицы, после чего упаковка прошла.
libc предоставляет libgcc транзитивно; обход зависимостей и лишний +libgcc не добавлены.
ELF требует libc.so/libgcc_s.so.1 и использует OpenWrt musl interpreter.
Закрыт прежний разрыв между standalone ELF и SDK-упаковкой для этого source/target/
toolchain; другие архитектуры SDK и production release source-cut не подтверждены.

Без skips прошли6 real-Cargo тестов Compile, включая отказ без изменения файла с
суффиксом, и7 offline opkg методов в SHA-проверенном официальном rootfs24.10.4 с ранее
signature-admitted зависимостями: nft/legacy providers, отказ без зависимостей,
обновление изменённого/стандартного UCI, guard удаления/сохранение конфига и отказ
повреждённого обновления. r2 — явный fixture обновления, упакованный SDK, не релиз.
Поддельных installed records и force-depends нет.9 запусков свежего SDK-клиента
в приватных mount/net/PID namespaces проверили version, quoted/BOM INI,
legacy/core ownership, attached TUN и отказы неверного config/device/attach.
VPN и firewall хоста не запускались. Проверка подписей cached feeds имеет прежнюю
дату; свежая signature verification не заявлена. Сначала подготовка rootfs не
создала tmp/lock и задала неверный lists_dir option; после исправления повторены
только установочные/runtime-проверки.

Штатный autoremove SDK удалил подготовленные исходники после упаковки. Backup
исправлен: сохранены оригинальный source/archive, рецепты, логи, тесты, IPK, ELF и
tool identity; сверка уже удалённого подготовленного дерева не заявлена.
Локальная копия проверена по SHA. После process/mount/resolved-path guards удалён
только собственный root; исходные сервис PID777/worker845 сохранились.
Native source/artifacts неизменны,14SHA/provenance PASS. Не повторялись несвязанные
Rust matrix/native rebuild; push/deploy/release не выполнялись.

Evidence: `release/certification/evidence/q31-sdk-build-20261008.json`;
raw: `audit-debt-20260924/q31-sdk-build-20261008` вне репозитория.
SDK upstream Rust bootstrap, production release-cut archive и успешный актуальный
Actions/preflight остаются OPEN. Firmware — USER_EXCLUDED. Q31:3/5 IN_PROGRESS;
полный аудит29/37(78.4%),8осталось. Q29/Q30/D06 без изменения статуса.

## Q31-V011: актуальные ARMv7/MIPS после F395 (8 октября)

Клиенты Q31-V009 были собраны до новой production-блокировки F395. Тот же release
gate зафиксировал commit6c2225cd и собрал обе текущие client-only цели:
ARMv7 Rust1.97.0/Zig0.13.0 и MIPS nightly-2026-06-10/build-std/soft-float,
по одному компилятору на .10.318 переданных input совпадают с Git archive,
с учётом намеренной приватной rlib-проекции Cargo.toml.47 непереданных файлов
архива вне managed build contract; каждый src и три обязательных Cargo/config
input совпадают. Проверки SHA/static ELF прошли.

| Цель | Байты | SHA256 |
|---|---:|---|
| ARMv7 hard-float | 4996156 | `0d7f0d75b2e3bc99ebbef8d5fd89d4cabc56fdbf2d4412686efc7bfd183f9fea` |
| MIPS little-endian O32/static PIE | 6865260 | `943a484ad428e34c5256f2deff75281d19670d2f8ab13bb6bc95417e5f9e0905` |

Новые клиенты прошли32 CLI/INI запуска на cortex-a7/24Kc под прежними
SHA-admitted QEMU10.0.13, uid65534 на .11. VPN/TUN/firewall/binfmt не менялись.
Два небольших release-бинарника дополнительно компилируют точные committed
PublicationLock/operation_budget с настоящим log, без mocked imports.
По7 behavior-проверок на CPU (14 всего) прошли:0700/обычное освобождение,
ожидание живого владельца, сохранение stale canary/чужого файла, отказ при
истёкшем parent budget, сохранение непустого lock, восстановление вложенного
cleanup scope и thread-local budget. Это выполнение production-модулей в release,
не cfg(test) suite всего crate, FFI/handshake или firmware lifecycle.
panic=abort не подтверждает unwind/SIGKILL recovery. В выполненной области новых
product-регрессий не найдено.

При inventory на .11 вызов rustup component list неожиданно установил отсутствующий
named nightly. Zig/targets также отсутствовали, поэтому probe собран последовательно
на .10. Только созданный этим вызовом nightly удалён после exact-path/process guards;
байты default settings и исходные три toolchain сохранены. Подготовка не была read-only.
После SHA-проверенной копии source/binaries и process/mount/path guards удалены два
своих build root и один emulation root. Чужой прежний R8L058 сохранён.
Исходные PID745/901 на .10, PID777/845 на .11 и service state не изменились.

Rust/ABI/production scripts и packaged native artifacts неизменны;14nativeSHA/
provenance PASS. Native rebuild и несвязанные большие suites не повторялись.
Обновлена применимость текущих32-bit build/runtime результатов; прежнее clean A/B
четырёх целей сохраняет исходную дату/source и не объявлено новым прогоном.
Read-only CI по-прежнему возвращает failed37598403060 на83c07f5c, не текущей dev.
Upstream SDK Rust bootstrap, production source-cut и успешный актуальный Actions/
whole preflight остаются OPEN; firmware USER_EXCLUDED. Q31:3/5 IN_PROGRESS;
полный29/37(78.4%),8осталось; Q29/Q30/D06 сохранены. Без push/deploy/release.
Evidence: `release/certification/evidence/q31-current-32bit-20261008.json`;
raw: `audit-debt-20260924/q31-current-32bit-20261008` вне репозитория.

## Q31-V012: решение по ресурсам SDK bootstrap (8 октября)

Read-only inventory: обе VM имеют2020932KiB RAM, два CPU, ~9GiB свободного root-диска; отдельного диска сборки и активных компиляторов нет. [Рекомендации Rust upstream](https://rustc-dev-guide.rust-lang.org/building/prerequisites.html) —8GB RAM и30GB+ свободного диска, это явно не строгие требования. Закреплённый feed собирает compiler/std/cargo/dist Rust1.89; прежняя компиляция пакета prebuilt Rust не квалифицирует bootstrap. Компиляция bootstrap на этом стенде отложена; OOM/ENOSPC или compiler FAIL не выдумываются.

На .11 начата отдельная загрузка официального SDK и отменена после9437184 байт. SHA-admission/распаковка SDK, host/prepare, host/configure и compile не выполнялись. SSH launch timeout и отказ первого process-group guard — примечания подготовки; остановлена только точная собственная python/curl группа. Backup834257байт SHA256 `a40bc8dcf7fefbbd9386283e2582fe054da62a0a816cb89aad0796de16013981` скопирован и проверен; свой каталог удалён после path/process/fd/mount guards. PID777/worker845/service сохранены. Raw13файлов/1016634байт; manifest SHA256 `9c9b347eb444fe467fdbb6f46edad754408d61eee7f2fb197b2bdb770ba5ce6d`.

Полный bootstrap OPEN/capacity-deferred; release source-cut/current Actions также OPEN. Прежние package/32-bit PASS сохранены. Чтобы независимая работа не стояла, продолжены проверки entrypoint Q33. Q31 остаётся3/5 IN_PROGRESS, полный29/37(78.4%),восемь осталось; exclusions/Q29/Q30/D06 сохранены. Production pin/hash, Rust/native artifacts и сервисы не менялись; push/deploy/release отсутствуют.

<!-- q31-current-portable-20261012 -->
## Q31-V013: текущие ARM/MIPS, SDK-пакет и права лицензий (12 октября)

Старые SDK/32-bit artifacts не объявляются актуальными: изменились 38 ранее
переданных input, включая Cargo, клиент и buffer pool. Commit c52e0c15:
две новые client-only release-сборки ARMv7 Rust1.97/Zig0.13 и MIPS
nightly-2026-06-10/build-std/soft-float прошли SHA/static-ELF admission и
32 CLI/INI проверки QEMU10.0.13 на cortex-a7/24Kc под uid65534.
Переданные src/Cargo/config bytes сверены с immutable Git archive.
Прежние 14 production-module probes и A/B four-target результаты сохраняют
свои даты/source; полный VPN/firmware этим пакетом не проверялся.

Официальный SDK24.10.4 x86/64 с приватными официальными prebuilt Rust/std1.89
выполнил download/hash/prepare, Cargo client-only, GCC13.3 musl link,
install/dependency-check/strip/BuildPackage. Подготовленные исходники до
rlib-проекции побайтно проверены. Upstream bootstrap и cold/hermetic build
не заявлены. Production URL/pin/hash неизменны; private fixture изменяет
только URL/pin/hash. Полный SDK compile завершён до исправления Install ниже.

Найден и исправлен дефект упаковки: CP сохранял права исходного архива,
поэтому 533 файла лицензий устанавливались 0664. Рецепт нормализует файлы
0644 и каталоги0755. Выполнены настоящий обновлённый SDK Install macro и
ipkg-build с тем же ELF: все payload bytes и control поля прежние, права
лицензий исправлены. Повторной Rust-компиляции/full BuildPackage после
правки Install не было. Финальный IPK: 2712812 байт, SHA256
`1f6967bc996695976d906c50034c4180128db025e089d3a5a8a17b2787c0b39a`.

Тесты перестали зависеть от даты SDK-каталога, сохранив /var/tmp и marker
guards. Строгий список payload дополнен независимым inventory исходных
лицензий: точные имена/bytes,0644/0755 и root owner; неизвестные файлы
по-прежнему отвергаются. Удаление проверяет отсутствие файлов/ссылок;
стандартные пустые каталоги opkg разрешены. Свежие6 real-Cargo методов,
7 opkg методов (nft/legacy, upgrade/remove/dependency/corrupt refusal) и
9 CLI/INI запусков OpenWrt userspace PASS без skips; всего54 метода в
этом scoped пакете вместе с QEMU. Дополнительно25 Windows source-admission
методов и2 Linux POSIX метода PASS; historical opt-in baseline не повторён.

Исходные отказы сохранены: HOME/Zig и SDK/tmp/flock в подготовке, датированный
guard, старый four-file assertion,0664 modes и слишком строгий empty-dir
assertion. Последние проверки используют точные текущие тесты без private
root projections. Компиляция ограничена одним job, MemoryMax1400M,
MemorySwapMax512M, CPUQuota150%. Собственные roots удалены после backup/SHA/
process/fd/mount/path guards: освобождено около3,6GiB. PID/commands/service
state исходных Qeli сохранены; новые большие кеши на Windows не создавались.

Q31 остаётся3/5 IN_PROGRESS: bootstrap resource-deferred; public release cut/
hosted CI относятся к Q34, physical router USER_EXCLUDED. Всего32/37 (86,5%);
Q29/Q31/Q34/Q35/Q36 открыты. Evidence:
`release/certification/evidence/q31-current-portable-20261012.json`.
NO_PUSH_DEPLOY_RELEASE.

## Q31-V014: актуальные ARMv7/MIPS после Q36-F030 (14 октября)

Собраны два новых client-only release-бинарника из commit `d26c78df4cf1556046332b5a7744208a15c00e06`, включая исправление bonded pool. Приватные source/registry/target, offline Cargo и jobs1; общий закреплённый router recipe: ARMv7 Rust1.97/Zig0.13, MIPS nightly-2026-06-10/build-std/soft-float, fat LTO/codegen1/opt3/strip/panic=abort. Старые target artifacts не переиспользованы; новые toolchain не устанавливались. Перед компиляцией все907 файлов сверены с Git; единственная разрешённая проекция Cargo — crate-type rlib.

Оба SHA/static ELF прошли независимую проверку: little-endian32-bit executable с корректной entry point, без внешнего interpreter/shared-library dependencies. QEMU10.0.13 cortex-a7/24Kc под uid65534 выполнил32 CLI/INI случая: версия/help, BOM/case/quoted values, legacy/core ownership, device/attach, отрицательные TAP/duplicate/unknown/malformed/missing/nonregular и отсутствие исполнения hook-canary. Это исполнение новых бинарников, не перенос результатов12октября. Полный VPN/TUN/network runtime на ARM/MIPS, A/B четырёх архитектур и physical firmware не проверялись.

Сохранены подготовительные отказы: local root-directory guard; read-only admission принял текст собственной Python-команды за cargo; первая bounded unit остановилась на неполном import closure ELF-валидатора до Rust. Её source/cache/unit архивированы и удалены, сервисы сохранены. В исправленном r2 импорт полного closure проверен до копирования registry; первая настоящая компиляция обеих целей прошла. Никаких повторов успешных Rust-сборок ради зелёного статуса.

Логи, исходники и бинарники сохранены с SHA; текущий root/registry/target/QEMU/unit удалены после archive/cookie/process/fd/mount guards. Host/firewall/routes/resolver, production PID/start/exe/argv и passwd/group/Rustup settings сохранены. Для QEMU собственному parent разрешён только traversal group65534, leaf0700/uid65534; host binfmt не менялся. Исходные архивы сохранены, больших Windows-кешей нет.

Закрыт долг актуальных standalone32-bit compile/CLI после F030. Предыдущий SDK1.89/IPK/opkg пакет сохраняет source/date и не квалифицирует это изменение ядра; его актуальная сборка остаётся отдельно. MIPS build-std не означает полный host Rust compiler bootstrap OpenWrt SDK. Bootstrap resource-deferred, physical router USER_EXCLUDED, public cut/hosted CI отдельны. Q31 IN_PROGRESS;33/37(89,2%),NO_PUSH_DEPLOY_RELEASE.

## Q31-V015: актуальный SDK/IPK после Q36-F030 (14 октября)

Исходники `2061407d12983a61ba958e2b88adcf660e94d3bc` собраны в штатном OpenWrt SDK 24.10.4 x86/64: Download/hash/Prepare, Cargo client-only, musl link через GCC 13.3, Install, dependency-check, strip и BuildPackage. Использован приватный официальный Rust/std 1.89. Проверены 321 точных src/Cargo/config входов до проекции rlib. Синтетический Git fixture содержит точное дерево `qeli/`, но не является исходным полным release commit; производственный source-cut от 14 октября проверен отдельно.

Получен IPK `eb3886d8c449f425726e5ee4cc232af1e4a45e2194dc2970ee6c4741c04120fc` (2711950 байт). Встроенный ELF x86_64 с `/lib/ld-musl-x86_64.so.1` совпал с исполнявшимся снимком. Все 533 Rust notices совпали по именам и байтам; проверены права 0644/0755 и владелец root.

Семь реальных opkg-сценариев PASS: установка с nft/legacy providers, отказ при отсутствии dependencies, обновление изменённого/неизменённого UCI, отказ при повреждённом пакете без изменения payload, удаление с dependency guard и сохранением UCI. Использованы настоящие rootfs и dependency packages, без force-depends. R2 — только upgrade-фикстура с тем же ELF. Девять CLI/INI-сценариев этого SDK-бинарника в OpenWrt userspace PASS: версия, legacy/core ownership, BOM/кавычки, attached device и четыре отрицательных случая. Шесть неизменённых Compile-boundary тестов не повторены; ARM/MIPS V014 остаются отдельным доказательством.

Первичный collector отказал после успешной сборки: искал IPK в `bin/packages` вместо `bin/targets`. Пакет восстановлен из SHA-проверенного архива без повторной компиляции. Два следующих runtime-прогона через systemd service завершились тайм-аутами; их исходные FAIL и журналы сохранены. Контрольные запуски подтвердили, что тот же opkg/IPK проходит через ограниченный systemd scope. Причина зависания внутри service-контекста не установлена; смена locale, PID namespace и NOFILE её не устранила.

Исправлен `scripts/test_openwrt_opkg.py`: `unshare --kill-child=KILL` завершает дочерний процесс при смерти родителя, а TimeoutExpired сохраняет частичный stdout/stderr. Этот helper прошёл все семь opkg-сценариев и отдельный реальный тайм-аут 0,3 секунды: оба потока сохранены, оставшихся процессов в chroot нет. Assertions сценариев не менялись. Все 50 файлов замыкания Linux-матрицы имеют прежние SHA; этот helper в него не входит. Ранее полученные Linux20 результаты не переименованы в новые прогоны.

SDK-сборка ограничена jobs=1, runtime=2100 секунд и собственным disk budget 6 GiB. Успешный runtime scope ограничен 600 секундами, MemoryMax=1400 MiB, SwapMax=512 MiB и CPUQuota=150%. SDK-архив 257 MB переиспользован. Собственные build/toolchain/registry/target/rootfs/cache/unit очищены после архивирования и проверок; состояние хоста и production сохранено. Исходные архивы остались. Приватный SDK download source archive отдельно не сохранился до очистки: его SHA записан, подготовленные input, compile logs и IPK сохранены и сверены; повторная проверка байтов этого архива не заявлена. Производственный source-cut имеет отдельный сохранённый архив.

Долг актуального SDK/IPK/opkg после F030 закрыт. Полный feed Host/Compile Rust ещё не выполнен: recipe скачивает готовый LLVM, но собирает rustc/std/cargo/dist. Prebuilt Rust не доказывает compiler bootstrap или cold dependency graph. Physical router USER_EXCLUDED; public pin, hosted CI и полный release gate остаются отдельно. Q31 IN_PROGRESS; 33/37 (89,2%), NO_PUSH_DEPLOY_RELEASE.

## 14 октября: штатная подготовка Rust feed и проверка конфигурации хоста

Проверен полный каталог `lang/rust` из packages commit `f1470815f41fe199bfdafe9a91ad115bc2e91203`, закреплённого внутри SDK 24.10.4: шесть файлов, включая Config.in, rust-host-build.mk и патч статического xz2. Каждый файл сверён по Git blob SHA и SHA256. Прежняя трёхфайловая копия имела правильный Makefile/версию 1.89.0, но не содержала полный feed; она не доказывала bootstrap.

На изолированной .11 выполнены настоящие прямые target `host-prepare` и `host-configure`, оба exit0. Патч применился к src/bootstrap/Cargo.toml. GNU_HOST_NAME/HOST_OS/HOST_ARCH вычислены теми же командами, что в SDK include/toplevel.mk; конфигурация проверена отдельно: build/host x86_64-unknown-linux-gnu, targets GNU+musl, profile dist, channel stable, download-ci-llvm=true. LLVM/Rust compiler не компилировались и LLVM artifact в этой проверке не скачивался.

Поток официального архива Rust проверен по SHA `0b9d55610d8270e06c44f459d1e2b7918a5e673809c592abed9b9c600e33d95a`: 267487572 сжатых байта, 3154771958 байт обычных файлов, 269551 tar entries; архив/дерево при измерении не сохранялись. Полный частный каталог подготовки занял около 4,70 GiB apparent bytes. Лимиты: 5 GiB файлов, резерв 1 GiB свободного диска, 768 MiB RAM, 256 MiB swap, один CPU, 25 минут. Каталог, SDK, исходники, cache, unit и remote archive удалены; рабочие сервисы, firewall, маршруты, resolver, аккаунты и staged binary сохранены. Малые исходники конфигуратора и логи остаются в доказательствах.

Предыдущие результаты сохранены: неправильный target host/prepare остановился до подготовки; лимит 4 GiB остановил распаковку без compiler/OOM/ENOSPC FAIL; затем exit0 configure был отклонён независимой проверкой из-за host triple -unknown-linux- при обходе toplevel exports. Эти результаты не превращены в PASS.

Подготовка полного feed и корректность его конфигурации проверены. Host/Compile/Host/Install Rust, stage2 dist и cold dependency graph остаются NOT_RUN; размеры будущей компиляции не выводятся из размера подготовки. Новых Qeli/native/IPK/VPN прогонов нет. Q31 IN_PROGRESS; 33/37 (89,2%), NO_PUSH_DEPLOY_RELEASE. Evidence: `release/certification/evidence/q31-host-configure-20261014.json`.

## 14 октября: холодный Host/Compile выполнен и локализован отказ LLVM

Впервые выполнен настоящий Host/Compile закреплённого Rust1.89 feed из SDK24.10.4 на изолированной .10. Execution source a94feb891c17, шесть файлов feed из f1470815f41f и официальный Rust source SHA прежние. Host/Prepare и Host/Configure exit0; build/host GNU, target GNU+musl, profile dist, stable и download-ci-llvm=true проверены. Makefile/patch не изменялись. Только build.jobs=1 добавлен в bootstrap.toml; исходный и изменённый TOML совпадают по всем прочим полям.

Начальные Rust/std/Cargo1.88 скачаны из официального источника по версии src/stage0. Реальная компиляция bootstrap и build_helper завершилась dev profile за79с. Готовый Rust1.89 не подставлялся. Затем штатный downloader четыре раза получил HTTP404 для [LLVM CI artifact](https://ci-artifacts.rust-lang.org/rustc-builds/29483883eed69d5fb4db01964cdf2af4d86e9cb2/rust-dev-1.89.0-x86_64-unknown-linux-gnu.tar.xz); Host/Compile отказал. Отказ означает недоступность этого адреса в момент проверки, а не доказанное удаление артефакта или ошибку Qeli. Stage1/stage2 rustc, dist и Host/Install не выполнены; original FAIL сохранён.

Рабочее время246,32с; итог systemd Result=exit-code, ExecMainStatus=1. Disk/time guards не срабатывали; отдельного OOM-результата нет. Лимиты1152MiB RAM/512MiB swap/один CPU/25мин/7GiB собственного каталога и минимум1GiB свободного диска. MemoryPeak1210777600байт, SwapPeak359653376байт сохранены как фактические значения. После отказа удалены6226200078байт собственного SDK/source/stage0/cache/build, root/archive/unit отсутствуют. Полный host gate, аккаунты и staged binary прежние. Локальный evidence archive55195байт; большого cache на Windows не добавлено. Первый launcher отказал локально из-за переноса пути до подключения; причина исправлена, затем generator побайтно воспроизвёл реально запущенные scripts без повторного remote workload.

Квалифицированы завершённые prerequisites и стадия отказа; полного compiler PASS нет. Следующий исходный путь — отключить download-ci-llvm в частной копии feed и собирать bundled LLVM из исходников. Он требует отдельной проверки ресурсов, компиляции/установки и итогового SDK/IPK; здесь не выполнен. Произвольный новый LLVM binary/URL вместо закреплённого не принят. Уже проверенный SDK/IPK с официальным prebuilt Rust1.89 сохраняет прежний scope и не становится cold graph PASS. [Инструкция и границы обхода](../../manuals/OPENWRT-INSTALL.md).

Q31 IN_PROGRESS,33/37(89,2%); physical router USER_EXCLUDED и public pin/hosted CI остаются отдельно. Evidence: `release/certification/evidence/q31-cold-bootstrap-20261014.json`; packet q31-cold-bootstrap-20261014. NO_PUSH_DEPLOY_RELEASE.

## 14 октября: обход LLVM CI404 проверен на реальной сборке исходников

Execution source f3b61e7618a1. В частной копии закреплённого feed изменён ровно один аргумент: --set=llvm.download-ci-llvm=true → false. Исходные и изменённые Makefile сохранены с SHA; все прочие байты и остальные пять файлов прежние. Отдельный build.jobs=1 сохраняет все прочие поля generated TOML. Rust1.89 source/version/hash, build/host GNU и target GNU+musl прежние; нового LLVM binary или готового Rust1.89 не подставляли.

Prepare/configure и реальная компиляция bootstrap прошли. Недоступный CI URL не запрашивался; CMake сформировал граф LLVM из bundled source, Ninja начал компиляцию C++ LLVMSupport/LLVMCore. Последний индикатор 548/3710 сохранён из raw; это не готовый LLVM/rustc. 1 CMakeCache и SHA/число build statements в графе сохранены. Configuration/переход к source compilation подтверждены, original4HTTP404 сохранён отдельно.

Попытка остановлена своим ограничителем time; факты: 1275.32s, last Ninja indicator 548/3710, guard time; owned bytes at guard 6512947857, free bytes 2058006528. Это контролируемый частичный прогон, не новый product regression. Full Host/Compile/Host/Install, stage2/dist и cold Qeli dependency graph не квалифицированы. Из ограниченного окна не выводится точная потребность полного build в RAM/диске/времени. Далее нужен длительный source-LLVM/compiler прогон с подходящим бюджетом и итоговая проверка SDK/IPK; одинаковый CI404 retry больше не требуется.

Все 6512968313 байт SDK/source/stage0/cache/build удалены после проверки архива; root/archive/unit отсутствуют. Full host gate, аккаунты, staged binary сохранены. Локальный evidence archive 77371 байт, большого compiler cache на Windows нет. В рабочем проекте изменена только документация; override применён только к собственному SDK, производственный feed не переписан. Q31 IN_PROGRESS,33/37(89,2%),NO_PUSH_DEPLOY_RELEASE. Evidence: `release/certification/evidence/q31-source-llvm-20261014.json`.

## 14 октября: длительная source-LLVM сборка остановлена cgroup OOM

Execution source 4eb79632105b. Продолженный bootstrap в той же копии SDK дошёл до операции LLVM 1690/3710. Это индекс операции Ninja, а не процент готовности Rust. Журнал ядра подтвердил CONSTRAINT_MEMCG в собственном unit: убит llvm-tblgen. MemoryPeak достиг лимита 1152 МиБ (1207959552 байт); MemorySwapPeak 536682496 байт при лимите swap 512 МиБ. Исчерпаны ограничения частной cgroup; отказ не является результатом компиляции Qeli. Точная потребность полного bootstrap в ресурсах ещё не измерена. Повторять тот же бюджет нельзя.

Worker был прерван до итогового finally: result.json сохранил промежуточный статус VALIDATED_SOURCE_COMPILER_RESUME_STARTING. Итог устанавливается по systemd Result=oom-kill, журналу ядра и сохранённым логам, а не по этому промежуточному статусу. Full Host/Compile/Host/Install, stage2/dist и холодный граф SDK не прошли. Подготовленный следующий этап отказался запускаться; новых SDK/IPK/runtime прогонов нет. Предыдущие configuration и prebuilt-SDK результаты сохраняют свой исходный scope.

После проверки SHA и полного inventory архива удалены 6858519526 байт собственного cache/root; unit и remote archive отсутствуют. Host/firewall/routes/resolver, аккаунты и staged CLI сохранены. Локально сохранён evidence archive 79253 байта, без большого compiler cache. Свободно 9288957952 байта на .10. Другой стенд .11 также имеет около 2 ГБ RAM и меньше свободного диска; перенос сам по себе не подтверждает достаточность ресурсов. Следующий source bootstrap требует отдельно обоснованного бюджета либо явно квалифицированного иного решения. Q31 IN_PROGRESS; 33/37 (89,2%), NO_PUSH_DEPLOY_RELEASE.

Evidence: `release/certification/evidence/q31-long-compiler-oom-20261014.json`.

## 14 октября: второй OOM после увеличения частного swap-бюджета

Execution source 66cf9a2d5d40. Отдельная попытка полного source-LLVM bootstrap использовала прежние RAM 1152 МиБ, jobs=1 и CPUQuota=100%, но swap-лимит cgroup увеличен с 512 до 1024 МиБ. Настройки host swap не менялись. Одна private recipe-поправка `llvm.download-ci-llvm=false` сохранена; prebuilt Rust 1.89 не подставлялся.

LLVM дошёл до операции Ninja 1929/3710; это не процент готовности Rust. В 11:58:05 +03:00 журнал ядра подтвердил CONSTRAINT_MEMCG в собственном unit, убив `cc1plus`. Это другое узкое место после прежнего `llvm-tblgen`. MemoryPeak=1211572224 байта, MemoryMax=1207959552; swap peak достиг лимита 1073741824 байта. Небольшое превышение memory peak не меняет исход `Result=oom-kill`.

Worker снова прерван до итогового finally, поэтому его промежуточный `STOCK_PREPARE_CONFIGURE_PASS_COMPILER_ATTEMPT_STARTING` не является результатом сборки. Archive SHA/inventory, systemd и kernel подтверждают отказ. Подготовленный SDK consumer корректно отказался запускаться: новых SDK/IPK/runtime проверок нет. Stage2/dist/HostInstall и cold source-built SDK всё ещё не квалифицированы. Ранее проверенные сборки с готовым Rust сохраняют свой отдельный scope.

Удалены 7040038732 байта собственного root/cache, remote archive и unit отсутствуют; host/firewall/routes/resolver, аккаунты и staged CLI сохранены. Локально осталось 79620 байт evidence archive, а не гигабайты compiler cache. Третью попытку с близким бюджетом не запускаем: имеющийся стенд не подтвердил достаточность ресурсов полного bootstrap. Q31 остаётся IN_PROGRESS; 33/37 (89,2%), NO_PUSH_DEPLOY_RELEASE.

Evidence: `release/certification/evidence/q31-second-oom-20261014.json`.

## 14 октября: Clang, остановка по дисковому порогу

После двух сохранённых GCC OOM проверен другой вариант: только GNU host cc/cxx изменены на Clang19 и jobs=1 в собственном bootstrap.toml; musl compiler/linker и остальные поля сохранены. Фактические CMake compiler IDs и пути подтверждены; LLVM взят из официальных исходников Rust1.89, feed/source hashes сохранены.

Последняя начатая операция Ninja — 3340/3710, линковка llvm-ar. Через 11472 секунд Host/Compile контроллер остановил сборку: свободно 1003.2 МиБ при пороге 1024 МиБ. Учтённый объём собственных файлов 7341742206 байт ещё не достиг лимита 8 ГиБ. Фактические cgroup peaks: RAM 1154.5 МиБ, swap 747.2 МиБ. Зафиксирован дисковый отказ; полного результата LLVM, Rust stage2/dist и Host/Install нет. Следующий SDK/IPK/opkg прогон не запускался.

Архив 142834 байт сверён по SHA и полному inventory; удалено 7513146208 байт собственных файлов и собственный unit. Host/account/staged identities сохранены. [Evidence](../../../../release/certification/evidence/q31-clang-disk-floor-20261014.json). Q31 IN_PROGRESS; 34/37 (91,9%), NO_PUSH_DEPLOY_RELEASE. Нужен другой запас диска перед следующим полным bootstrap; повтор с тем же ресурсным пределом не квалифицирован.

## 15 октября: source compiler PASS, SDK остановился на defconfig

Полная Clang19 source-сборка LLVM20.1.7/Rust1.89 завершила Host/Compile за 18519 секунд и Host/Install за 5,38 секунды. Проверены реальные LLVM CMake compiler IDs/paths, установленный Rust/Cargo и musl std. GNU host Clang, jobs=1, musl tools/linker и остальные поля сохранены в указанной границе. Это закрывает проверку самого source compiler, но не холодного графа Qeli SDK.

Следующий consumer завершился отказом за 12,16 секунды на `make defconfig`, до компиляции Qeli. Причина в нашем audit harness: внешний PATH начинался с SDK staging_dir/host/bin; OpenWrt сохранял его как ORIG_PATH, и проверка находила собственные canonical symlinks вместо исходных утилит. Неизменённый macro SDK воспроизводит отказ для bash/cp/grep/python3 с прежним PATH и проходит с внешним PATH. FORCE не применялся.

Дополнительная ошибка harness: безусловная очистка consumer удалила исправный установленный compiler SDK (около 2,8 ГБ). Исходные результаты, архивы и логи сохранены; сам toolchain не доступен для повтора. Новый consumer должен сохранять compiler до отдельного решения об очистке. SDK package/IPK/opkg/userspace этой source-built попыткой не проверены. Предыдущие результаты с готовым Rust сохраняют свой отдельный scope.

[Evidence](../../../../release/certification/evidence/q31-source-compiler-sdk-failure-20261015.json). Host/firewall/routes/resolver, аккаунты и staged CLI сохранены. Q31 IN_PROGRESS; 34/37 (91,9%); NO_PUSH_DEPLOY_RELEASE.

## 2026-10-15: полный source bootstrap через Clang и штатный SDK

После двух сохранённых GCC OOM выполнен другой вариант: в собственном bootstrap.toml изменены только GNU host cc/cxx на установленный Clang19 и jobs=1; musl compiler/linker и остальные поля сохранены. Фактический CMake cache и compiler IDs подтверждены. Официальный Rust1.89 source SHA и SDK feed pin сохранены; LLVM собран из исходников вместо недоступного CI artifact. Host/Compile, stage2/dist и Host/Install завершились; установленный rustc1.89 GNU host проверен. Лимиты: RAM1400/swap1536 МиБ и CPU100%/одна задача. Это один успешный вариант на данном стенде; прежние OOM остаются историческими.

Промежуточный R5 остановился до сборки Qeli: make -q вернул1 из-за обязательного double-colon cache check, а не из-за необходимости bootstrap. R6 не стартовал из-за изменённого времени SDK tmp после проверки guard; содержимое и инструменты совпали. R7 выявил конфликт guard с первым MAKEFILE_LIST в проверках OpenWrt. Исправленный guard отдельно прошёл5 проверок, включая настоящий defconfig; после восстановления собственной копии R8 применил этот рекурсивный HostCompile guard: штатные dependency checks сохранены, повторный bootstrap запрещён. Исходные отказы сохранены.

Следующий штатный package/qeli/compile использовал этот установленный source toolchain; PATH/sysroot/musl libraries, SHA инструментов и всей установленной копии Rust сверены с source-qualified backup. R8 реально собрал IPK, но его постпроверка отказала из-за второго install stamp; в исходном логе также сохранён проглоченный внешним Rust feed отказ повторного Host/Install из удалённого dist. R9 сохранил отказ на штатном обновлении .built_check; R10 учитывает это проверяемое обновление. В продолжении явно импортированы только метаданные этой проверенной установки из host в hostpkg namespace, после чего штатный граф прошёл без повторной установки/bootstrap и сохранил точный SHA уже собранного IPK. Это продолжение с квалифицированным cache handoff, а не чистый первый проход bootstrap-to-root graph. Исходный R8 FAIL не переименован в PASS. R10 отдельно сохранил runtime import error до первого теста; R11 исправил только импорт PurePosixPath из стандартного pathlib и выполнил реальные runtime-проверки. Зависимости загружены по Cargo.lock установленным source Cargo/Rust в собственный registry. R11/R12 сохранили отказы opkg из-за PATH systemd без /bin и /sbin; отдельная проба на том же IPK воспроизвела отказ с manager PATH и корректный разбор с PATH OpenWrt. R13 выполнил runtime в отдельном unit без make/Rust/Cargo, с явным PATH=/usr/sbin:/usr/bin:/sbin:/bin. Все7 opkg и9 CLI сценариев прошли за12 секунд. Установка /dev/null или procfs не потребовалась; ресурсные ограничения не вызывали отказ. Новый IPK 85c7b94498e438f0b598d03d2fbb9b4a0a7bc699c1b56a46ff70127865998574 и ELF 865c7118dd34927963b32a51d1f8efcec3c42eed483caf8c9a336aa1f5fa04a7 прошли7 настоящих opkg и9 userspace/CLI/INI сценариев. Использован точный исходный archive commit ee2b74aafb2a57a2613541223c5522908cb71f71; его product tree совпадает с текущим 8c50631e7c253ab6cacd0056098ecad83f393487. Это сохранённый архив с подтверждённой применимостью.

Архивы и их inventory, этапы, исходные результаты, host/account/staged identities и очистка обоих собственных roots/unit сверены. Все большие SDK/compiler caches удалены; сохранены evidence archives. [Evidence](../../../../release/certification/evidence/q31-clean-lab-source-sdk-20261015.json). Закрыт локальный source compiler/cold SDK долг. Public source pin/hosted release qualification остаются открыты; physical router USER_EXCLUDED. Q31 IN_PROGRESS;34/37(91,9%),NO_PUSH_DEPLOY_RELEASE.


## 15 октября: завершение Q31 в согласованном объёме

**Q31 DONE.** Публичный source pin `099258dc3719161154c7978347a017a8d90aba75`
доступен и входит в историю `dev`. Два штатных SDK download/prepare дали
одинаковый архив `c04a743e…`; feed закрепляет его полный SHA256. После
обновления rustls заново выполнены Compile/Install/BuildPackage, семь opkg
и девять CLI/INI-сценариев. IPK `adcbb4c6…` содержит актуальное дерево
`qeli/`, musl ELF и все 533 лицензионных файла с проверенными правами.

Полная source-сборка LLVM20/Rust1.89 и последующий квалифицированный cache
handoff сохраняют прежние evidence. Это не переименование исходного R8 FAIL
в успешный чистый bootstrap-to-SDK проход. Новый consumer использовал
отдельный официальный Rust1.89; повторной сборки компилятора не было.
Текущий CI `9fa0903a…` подтвердил все четыре router cross-build и остальные
обязательные jobs. Очистка собственных ресурсов и сохранение хостов проверены.

| Критерий | Результат |
| --- | --- |
| Review и мёртвый код | Завершённый review 28 файлов и последующие адресные исправления |
| Штатные, граничные и негативные сценарии | ucode/rpcd/UCI/procd, INI, cross-target и opkg evidence PASS |
| Отказы и конкуренция | Baseline-отказы, generation/owner/ABA, rollback и cleanup проверены |
| Интеграция и целевая платформа | Source compiler/cache handoff, актуальный SDK/IPK и hosted cross-build PASS; физический router USER_EXCLUDED |
| Исправления, повторная проверка и evidence | Публичные source pin/archive, текущий CI и проверенные receipts |

[Итоговое evidence](../../../../release/certification/evidence/q31-q34-dev-closure-20261015.json)
сопоставляет все пять критериев. Физические роутеры не объявлены проверенными.
Исторические OPEN выше относятся к указанным датам; актуальный итог —
36/37 разделов (97,3%), открыт Q29 с generic/null DnsResolver API34.
