# Q34: безопасность Maven-графов Android

<!-- normative-sync: q34-maven-security-v1 -->

8 октября 2026. F466–F468 / Q34-F020–F022 исправлены в описанном объёме. Q34 остаётся IN_PROGRESS; полный аудит 30/37 DONE (81,1%), 7 разделов остаются. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Находки и изменения

| Находка | Исправление |
|---|---|
| F466 / Q34-F020 | В исходных 326 Maven package/version записях OSV нашёл 19 затронутых записей и 50 различных advisories. Включаемый в APK releaseRuntimeClasspath не содержал совпадений; уязвимы инструменты сборки, плагин Kotlin и UTP. Единый gradle/security-versions.properties применяется до загрузки плагинов и ко всем project configurations; обновлены Kotlin Gradle Plugin2.4.21, Netty4.1.137.Final, BC1.85, Commons Lang3.18.0, jose4j0.9.6, JDOM2.0.6.1 и HttpClient4.5.14. Все три Gradle lockfile и checksum policy обновлены настоящим Gradle. |
| F467 / Q34-F021 | CI проверял RustSec, но не известные уязвимости Android Maven-графов. Новый audit_android_dependencies.py охватывает все три lockfile и проверяет соответствие security pins. OSV errors/неполные ответы/циклическая пагинация вызывают отказ; build-only advisory также блокирует gate. В security-audit добавлены fixtures и отдельный gate с явным working-directory корня репозитория. |
| F468 / Q34-F022 | Тест wrongPassphraseFails принимал любую Exception и делал всегда истинный assert: AssertionError не является Exception. Kotlin2.4 отвергает эту проверку. Теперь проверяется именно AEADBadTagException. В reflection instrumentation fixture явно проверяется nullable enumConstants; предупреждение нового компилятора устранено без ослабления проверки. |

Обновление KGP выполняется через поддерживаемый AGP buildscript classpath; standalone Kotlin Android plugin не применяется. AGP9.2.1 и Gradle9.7.1 сохранены. Kotlin stdlib приложения действительно обновлён до2.4.21; утверждать неизменность всех APK-зависимостей было бы неверно. VPN-конфиги остаются INI; Gradle properties/locks/XML описывают сборку.

## Проверки и границы

- Итоговый production OSV gate: **318 пакетов,0 затронутых**. Реальный build-only JDOM fixture2.0.6 отклонён (exit1),2.0.6.1 принят (exit0).8 unit fixtures проверяют полноту, пагинацию, network failure и drift; import gate PASS.
- **730 checksum records**:104 новых/изменённых сверены свежим независимым HTTPS stream SHA;626 неизменённых точных coordinate/artifact/SHA наследуют sealed review предыдущего пакета. Это не730 новых загрузок. Удалены obsolete admission records; двух Windows/macOS AAPT2 classifier касается только неизменённый inherited checksum, без новых OS builds.
- Изолированная официальная Temurin Java17.0.20.1+1, опубликованный SHA256 `3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e`; системная Java не менялась. Поддерживается JVM target17; Gradle9.7.1 patch находится выше опубликованного KGP2.4.20 fully-supported ceiling9.7.0, реальная квалификация этой комбинации приведена здесь, полный Gradle10 не заявлен.
- Debug/default unsigned R8/debug и release instrumentation APK, lintRelease, штатные offline/strict сборки без write-флагов PASS. **201 JVM test,failures/errors/skipped0** с production host ConfigCore JNI из неизменённого sealed пакета (SHA6b6d956f); новый Rust rebuild не заявлен. Lint0errors/0fatal/53warnings; прежние deprecation diagnostics сохранены.
- Два реальных Gradle offline отказа: missing security policy и KGP pin/lock drift; restored positive PASS. Drift включает отказ uncached2.4.20 и missing locked2.4.21 modules, не является изолированным complete-cache solver тестом. Все прогоны в отдельной копии, policy восстановлена.
- Отдельный обычный unsigned R8 APK сохранён до переключения testBuildType: SHA `e475123c15d7c8b5f4bf798e44a2328cf468624ae9f7fa35ac202131a4badb6f`. Собранные instrumentation APK не устанавливались; Android device/VPN runtime этим пакетом не подтверждён.
- Архив32720631bytes SHA `7cd085fdf16cdbfc164c01cd92537ba896200171e109607da2288caba2610286`: qualified Android/conformance sources, APKs, reports/mapping/tests/logs и reused host JNI. Публичные пересоздаваемые SDK/JDK/Gradle caches не дублируются; Java archive и checksum review сохранены в raw packet. Downloaded SHA проверен до proc/cwd/exe/root/fd/mount guarded cleanup. .11 Qeli777/845 и installed CLI75bc сохранены; .10 не менялся. Related local native12/release11 tests PASS.


До исправления нового Kotlin первый прогон собрал debug/default unsigned R8/debug instrumentation APK, затем остановился на всегда истинном assert в unit test. FAIL сохранён; повтор выполнен после точного исправления теста. Первичные Unicode/working-directory draft-ошибки CI, недоступность Adoptium API, license API404/503 и ошибочное предположение harness о наличии всех POM в Gradle metadata и первоначальная SyntaxError подстановки negative harness сохранены отдельно. Это не замена неуспешных попыток успешными.

## Лицензии и текущий CI

Получены license metadata всех318 итоговых пакетов. 23 исходных ошибки deps.dev и одно отсутствующее license поле дополнены официальными POM: SHA сверены с build verification там, где POM входит в неё; иначе отдельно фиксируются HTTPS origin и hash без заявления Gradle admission. Material1.14.0 Apache2.0 подтверждён LICENSE официального тега. Все76 Maven записей releaseRuntimeClasspath заявляют Apache2.0. Это инвентаризация, а не закрытие packaging NOTICE/native copyleft/source-cut: Android wrapper MPL2.0 и Rust core AGPL3.0 проверяются отдельно. Non-standard labels в build tooling требуют проверки текстов. Проверка фактической комплектации лицензий APK и source admission остаётся OPEN. В собранных app APK обнаружены четыре AndroidX META-INF LICENSE, но native AGPL/MPL тексты не обнаружены по именам entries; это конкретный следующий packaging review.

Свежий [CI37765333335](https://github.com/litvinovtd/qeli/actions/runs/37765333335) от8октября проверял SHAf84a78d9, не текущие изменения. Android build отказал на удалённом SDK package tools; security-audit — на старых rustls0.23.43/rustls-pemfile/der. Локальное дерево уже содержит platform-tools, rustls0.23.45, удаление pemfile и der0.8.1. Зелёные jobs старого SHA не подтверждают текущий source-cut. Новый workflow не запускался; exact-source Actions/release admission остаются OPEN.

`q34-maven-review-20261008`: SEALED 824 files / 245841311 bytes; manifest SHA256 `1bf34d5f422e52d1c66d6c66ac1f3b123e93c134b310813612268e0b67bca3ce`.

Сохраняются Q29 SIGKILL FAIL/ENONET, Q30 Apple/callback OPEN, Q31 capacity/source-cut/currentActions, F459/braces OPEN, D06 ACCEPTED_LIMITATION и USER_EXCLUDED Mac/iOS/router/Windows network VM. Старые14 debt DONE не переименованы. Native source e3fb и14 native/copies SHA, CHANGELOG/users/CSS неизменны; новый release native A/B и device VPN runtime этим пакетом не заявлены.

Источники: [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/), [AGP built-in Kotlin upgrade](https://developer.android.com/build/releases/agp-9-0-0-release-notes#runtime-dependency-on-kotlin-gradle-plugin), [Kotlin/AGP/R8](https://developer.android.com/build/kotlin-support), [Kotlin cache advisory](https://github.com/advisories/GHSA-r937-wjx7-w2jp), [deps.dev API](https://docs.deps.dev/api/v3/), [Material LICENSE](https://github.com/material-components/material-components-android/blob/1.14.0/LICENSE).


Последующая проверка закрывает отсутствие текстов лицензий проекта и перенос найденных Maven NOTICE в APK: [F469/Q34-F023](AUDIT-Q34-ANDROID-NOTICES.md). Проверки сторонних native notices, upstream source notices и source publication остаются OPEN.
