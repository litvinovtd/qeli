# Q29: Android — хранилище, редактор профиля, backup и Release

<!-- normative-sync: q29-android-storage-package-v2 -->

**5 октября 2026: этап PASS; Q29 IN_PROGRESS. План 28/37 (75,7%), осталось 9 разделов.**

| Находка | Исправление |
|---|---|
| F273 | `specialUse` объявлял неизвестное manifest-свойство вместо `android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE`. Исправлено имя и добавлено описание назначения. PackageManager на API34 подтверждает свойство, privacy/permission и типы сервиса. Старый APK воспроизводит NameNotFoundException; это не доказательство отказа startForeground на всех ОС. |
| F274 | Ошибка чтения старой Tink-базы прерывала open: Activity не получала version и не могла явно восстановить backup. Частичные keysets могли выглядеть пустым хранилищем. Теперь version доступна, обычные чтение/запись блокируются, backup restore явно разрешает замену через CAS. Старое encrypted state сохраняется; неполная миграция не запускает plaintext/default save. Ошибка удаления уже проверенной legacy-копии не блокирует пригодный новый store. |
| F275 | `BigInteger.intValueExact()` требует API31, а minSdk28. Заменён на точный `BigDecimal.intValueExact()` с API1: дробь/overflow по-прежнему отвергаются. Release lint больше не имеет NewApi error. Старый вызов подтверждён исходником и первым lint-прогоном; runtime Android9–11 не заявлен. |
| F276 | Одного allowBackup=false недостаточно для всех OEM D2D-переносов. Добавлены явные исключения девяти credential/device-protected доменов для cloud/device-transfer и fullBackupContent=false для старых ОС. Проверены packaged XML и manifest; физический OEM/cloud/D2D backup не исполнен. Пользовательский экспорт backup через UI остаётся доступным. |

Удалены пять недостижимых веток SDK<26/<28 в boot/tile/widget/Activity. minSdk остаётся28; дополнительные значения INI не вводились. JSON archive/journal — внутренние контейнеры, JSON-конфиг по-прежнему отвергается ядром.

## Проверки и evidence

- **167 JVM PASS, 0 failures/errors/skips**, production host ConfigCore JNI. Сборки debug/androidTest, unsigned Release с R8/resource shrinking и lintRelease завершены. Lint: **0 errors,55 warnings**, без baseline/suppression новых ошибок. Сохранена классификация предупреждений: версии зависимостей, UI/layout/plurals, legacy attributes и намеренный host-JNI override. AAB language splits не проверены; текущая дистрибуция APK.
- **18/18 debug instrumentation PASS** на временном Android14/API34 x86_64 AVD. Пять новых cases: platform specialUse property, private service/types, cloud/D2D resource contract, unreadable/partial legacy recovery; ещё один новый case проверяет потерю Keystore key. Это **6 новых tests** против прежних12. Проверены exact ciphertext preservation, обычный write/editor refusal, explicit restore, stale restore rejection и reopen; реальные JNI INI round-trip/reject JSON и TUN split/full/dual establish повторены.
- Baseline старого production APK: **3 tests,2 ожидаемых FAIL**, service privacy/type case PASS. Исходники продукта в baseline не изменены; добавлены только проверки.
- Первое полное выполнение:16 PASS, TUN case отказал из-за отсутствующего ACTIVATE_VPN в обвязке. Результат сохранён; исправлена подготовка временного AVD, затем18 PASS. Две ошибки компиляции новых тестов (nullable SDK return и попытка чтения скрытого ApplicationInfo field), offline lint-cache failure и NewApi lint failure также сохранены; они не объявлены регрессиями продукта.
- Debug test APK против minified Release не является квалифицированным Release test variant: падение сохранено и диагностируется отдельно от production UI smoke. Не заявляются3 Release instrumentation PASS.
- Native digest/14 actual artifact hashes и183 предыдущих managed/Swift inputs/7 DLLs неизменны; прежние1248 .NET checks не повторялись и не называются свежим Android результатом. APK содержат точные исходные JNI.so; Rust/native AB пересборка не требовалась.

R8 production UI smoke: **PASS на Android14/API34 x86_64: штатная launcher Activity, холодный запуск, процесс жив и не debuggable, без fatal-ошибок logcat. При первом запуске открывается системный запрос исключения из оптимизации батареи. Проверен запуск приложения, а не полный сценарий взаимодействия с Activity или VPN-трафик.**. Release-fixture подписан только debug test key для временного AVD; это не production signing и не опубликованный APK.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-20261005.
Evidence: release/certification/evidence/q29-android-storage-package-20261005.json.

## Эксплуатация и остаток Q29

Если legacy-профили не читаются, не удаляйте app data/старые encrypted preferences автоматически. Возобновить миграцию после временного отказа можно перезапуском процесса; при потере ключа нужен пригодный ранее экспортированный backup. Восстановление выполняется через существующее подтверждение UI и отказывает устаревшему снимку. Без backup утраченный device-bound key не восстанавливается. Системный перенос encrypted prefs не переносит ключ Keystore; явный экспорт/импорт backup — поддержанный путь.

Только отдельные read-only AVD sessions; исходные userdata SHA/mtime/size сохранены. Работающий qeli.service, host routes/firewall/resolver и .10 не изменялись. Push/deploy не выполнялись; основная ветка сохраняет пользовательский WIP.

Остаток Q29: полноценные connect/reconnect/cancel/revoke/process-death/always-on/lockdown/Doze, JNI/TUN generation/protect races и трафик TCP/UDP; Release lifecycle, старые Android API, arm64/физический LTE, дополнительные backup/миграционные ошибки. Сетевые Android результаты D12 остаются историческими, не заменяют эти проверки. Полный раздел пока не закрыт.

Контракты: [specialUse property](https://developer.android.com/reference/android/content/pm/ServiceInfo), [BigDecimal exact/API1](https://developer.android.com/reference/java/math/BigDecimal), [BigInteger exact/API31](https://developer.android.com/reference/java/math/BigInteger), [Android backup/D2D](https://developer.android.com/identity/data/autobackup).

Диагностика тестового варианта Release: NoClassDefFoundError для kotlin.jvm.internal.Intrinsics в AndroidJUnitRunner/MonitoringInstrumentation. Debug-тестовый APK зависит от классов неминифицированного приложения; штатная production Activity запускается без instrumentation. Этот результат не считается PASS instrumentation Release или дефектом запуска клиента.

## 6 октября: F284–F285 — редактор профиля и экспорт архива

| Находка | Исправление |
| --- | --- |
| F284 | Ошибка чтения store выходила из обработчика Activity; null output stream мог сообщать успех, KDF и запись provider выполнялись на UI-потоке. Ошибка чтения теперь отображается без замены ciphertext. Шифрование и write/close выполняются на Dispatchers.IO; успех сообщается после завершения, null/write/close дают ошибку. Временный массив результата очищается. |
| F285 | Save во время перечисления мог стереть список приложений; сохранение после загрузки удаляло недоступные пакеты; смена режима оставляла устаревшее состояние checkbox. Save выключен до публикации строк, отсутствующие пакеты остаются строками с package name, доступность checkbox зависит от текущего режима. Закрытие отменяет enumeration job; permission lookup отдельного пакета выдерживает его параллельное удаление. |

Строка с package name сохраняется, пока пользователь явно не снимет выбор. Пустой выбор
по-прежнему нормализуется в существующий режим всех приложений; INI keys/default не меняются.
Служебный JSON архива остаётся контейнером профилей; конфигурации остаются INI.

### Свежие проверки и границы

- **188 JVM PASS, шесть новых exporter cases**: точный UTF-8/close/очистка temporary bytes,
  encrypted round-trip и неверный пароль, null sink, отказ write, отказ close,
  превышение UTF-8 бюджета до открытия sink. Lint: **0 errors,54 warnings**.
  Свежие debug/androidTest и обычный R8/resource-shrunk Release собираются.
- **Один исправленный test APK: старый продукт 5 тестов/4 ожидаемых FAIL,
  исправленный 5 PASS**. Настоящие Activity, PackageManager и Keystore проверяют ранний
  Save, сохранение отсутствующего пакета, смену режима во время загрузки, экспорт из
  нечитаемого encrypted store и точные plaintext/encrypted архивы в реальные private
  `file:` destinations. Dialog roots инспектируются тестовым reflection на Android14/API34
  x86_64. Сторонний SAF/cloud provider и UI latency benchmark не проверены. IO placement
  подтверждён source review; JVM sink-проверки отказов перечислены выше.
- Первый baseline дал 3 FAIL/2 PASS: один тест читал профиль до выполнения отложенного
  Android Save listener. Результат, исходный тест и APK сохранены как диагностика обвязки.
  Ранний PASS отсутствующего пакета не квалифицирован. Ожидание idle подтверждает четыре
  отказа; положительный экспорт проходит на обеих версиях продукта.
- Release TCP, независимый анализ пакетов и итоговый cleanup квалифицируются точными
  результатами ниже. Debug profile suite не создаёт VPN payload. Matching Release
  instrumentation в этом пакете не запускалась.
- Native/server/service/managed inputs неизменны. Прежние UDP/QUIC и service результаты
  сохраняют свою область. Standalone Java Release probe использован повторно. Source proof:
  306 Android inputs (три новых, два существующих изменены),23 auxiliary (один изменён),
  пять неизменных regression inputs,14 native hashes,семь managed artifacts и восемь APK,
  включая два первых диагностических артефакта. Выполнены15 helper checks и6 CLI guards
  отклонения недопустимых режимов расширенного lab runner.

Raw: C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q29-android-profile-ui-20261006.
Evidence: release/certification/evidence/q29-android-profile-ui-20261006.json.

Q29 остаётся IN_PROGRESS,28/37(75,7%). SIGKILL auto-redelivery FAIL и generic auto/null
DnsResolver ENONET остаются открыты: этот UI/storage fix не устанавливает их причину и
не принимает их. Границы API/OEM/arm64/physical покрытия, пользовательские skips и D06 неизменны.

Первая попытка исправленного продукта: пять тестов PASS, итог runner FAIL из-за старого
traffic guard, ожидавшего TCP/UDP receipts от profile-only suite. Диагностика сохранена;
теперь suite требует нулевые echo receipts и проходит Android cleanup. Исполненные helpers
baseline/первого debug закреплены за сохранённой версией до guard-fix; итоговые debug/Release
inputs закреплены отдельно. Product APK не менялся.

### Квалифицированный итог runtime

Обычный production R8 Release TCP **PASS**: настоящий UI import INI и OS lockdown,два
перехода Wi-Fi→Cellular→Wi-Fi,12 полных IPv4/IPv6 TCP/UDP ответов отдельному UID с точным
SHA приёмника и независимой реконструкцией помеченных пакетов. Native планы/auth
обновляются после каждого TCP перехода, PID/TUN сохраняются. Проанализированы288 socket
проб,48 после остановки заблокированы;physical new requests0,capture drops0 в проверенных
окнах. Потери на границе handover/force-stop сохранены: это не288 успешных ответов.
Profile-only debug **5/5 PASS**,нулевые VPN receipts.

Пять попыток (два старых baseline,первый fixed debug с устаревшим traffic guard обвязки,
квалифицированный debug,Release) сохранили baseline хоста/службы и SHA/mtime/size исходного
userdata AVD,восстановили namespace addresses и штатно завершили private server. Итоговые
успешные прогоны дополнительно подтверждают отсутствие Android Qeli service/TUN/fatal
exception. .10 не затрагивался. Новая native матрица и повтор UDP/QUIC не нужны;push/deploy нет.
