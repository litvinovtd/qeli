# Q29: инструментированный Release runner

<!-- normative-sync: q29-android-release-runner-v1 -->

5 октября 2026. **7/7 сетевых instrumentation tests PASS** на изолированном
API34 x86_64 AVD сервера .11. Q29 остаётся IN_PROGRESS; план 28/37 (75,7%).

Причина отказа runner — приложение и test APK разделяют библиотеки, но R8 может
удалить API приложения, используемые только runner. Matching test mapping сохраняет
переименования, а не удалённые определения. Сохранение только трёх методов Trace
открыло следующий отказ `kotlin.LazyKt`. Генерация всех pre-R8 references устранила
пропуски, но выявила `IllegalAccessError`: R8 перенёс Kotlin-наследника в другой
пакет, оставив package-private родителя недоступным. Обе неуспешные пары APK,
сопоставленные mapping, runtime-логи и восстановление стенда сохранены.

Исправление применяется только с `-PqeliTestBuildType=release`. Генератор выводит
точные ABI keep rules из скомпилированных тестов и двух resolved classpaths;
`allowaccessmodification` разрешает R8 расширять доступ к родителям. Default
production Release использует прежние правила. Тестовый Release остаётся R8/minified,
resource shrinking включён, приложение non-debuggable, подпись лабораторная.
Это отдельный тестовый вариант; его PASS не переименовывает исторические отказы
обычного production APK. Предыдущая проверка production UI остаётся отдельным свидетельством.

Проверки:

- pre-R8 inference: 9 564 target и 832 source classes, 11 известных platform-stub
  diagnostics; неизвестные unresolved references отвергаются. `--check` PASS.
- DEX: Trace beginSection/endSection/forceEnableAppTracing присутствуют с нужными
  сигнатурами; недоступных superclass нет. Предыдущий APK даёт ожидаемый FAIL для
  Kotlin-наследования; первоначальный production APK — FAIL для Trace.
- TCP/UDP/QUIC × split/full: 6 сценариев с off-pool IPv4/IPv6 TCP/UDP и системным
  DNS; 72 echo receipts, 12 A/AAAA DNS-ответов через TUN. Первый пакет без preflight
  этим прогоном не квалифицирован.
- Седьмой сценарий: full kill-switch отказывается стартовать без Android lockdown.
- Cleanup PASS всех трёх runtime attempts: server exit 0, namespace restored,
  readonly AVD userdata и host/service/firewall/routes без изменений. .10 не затронут.

Новые build/DEX/runtime проверки исполнены; прежние 172 JVM/lint и JNI/managed
проверки используются по неизменности соответствующих inputs, не названы свежими.
API28/29, arm64/OEM runtime не исполнялись. SIGKILL recovery FAIL, auto/null
DnsResolver ENONET, Private DNS, остальные per-app и долгие lifecycle/flapping
пункты остаются открытыми. USER_SKIPPED и ограничение D06 не меняются.

Инструкция регенерации и запуска — [Android README](../../../../qeli-android/README.md).
Evidence: `release/certification/evidence/q29-android-release-runner-20261005.json`.
Raw: `audit-debt-20260924/q29-android-release-runner-20261005` (вне Git), включая
все неуспешные кандидаты, APK SHA, mapping, captures и source proof.
