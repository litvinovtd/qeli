# Q34: лицензии проекта и Maven NOTICE в Android APK

<!-- normative-sync: q34-android-notices-v1 -->

## Находка и исправление

**F469 / Q34-F023:** в предыдущем обычном R8 APK найдены четыре AndroidX
META-INF LICENSE; тексты AGPL ядра и MPL Android-клиента отсутствовали.
Наличие LICENSE в репозитории не проверяло их попадание в приложение.

Каждый вариант теперь генерирует `assets/licenses/`: канонические AGPL/MPL,
Apache 2.0, проверенный Maven runtime-реестр, идентификаторы исходных архивов
и LICENSE/LICENCE/NOTICE/COPYING/COPYRIGHT из JAR/AAR и вложенных `classes.jar`/
`libs/*.jar`. Индекс сохраняет исходные координаты/пути и SHA256; одинаковые
имена NOTICE разных зависимостей не перезаписываются. Варианты имеют отдельные
output directories; новые/удалённые координаты или версии требуют review.

Выбор исходных архивов использует отдельный [Gradle ArtifactView](https://docs.gradle.org/current/userguide/artifact_views.html)
и совместимость только для собственного типа потребителя. Повторные visits
одного component/physical archive через разные variants объединяются; реальные
конфликты имён отклоняются. Legacy resolvedConfiguration API не используется.

CI после сборки обоих APK проверяет канонические тексты, Maven-реестр, индекс,
хэши, привязку origin/path и отсутствие дубликатов/неиндексированных файлов.
[Обслуживание](../../../../qeli-android/README.md), [карта лицензий](../../../../LICENSING.md).

## Проверки

- Частный официальный Temurin17.0.20.1+1 проверен по опубликованному SHA256 `3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e`; системный Java не менялся. Gradle9.7.1/AGP9.2.1/KGP2.4.21 и locks/checksum policy прежние.
- Обычная strict сборка debug и unsigned release с R8 без write-флагов PASS (313.14 s). Release lintVital PASS; полный lintRelease и JVM-тесты в этом пакете повторно не запускались.
- Независимый Python extraction проверил оба generated outputs:63 исходных архивов,44AAR,24 ресурса; каждый архив сверён с committed Gradle SHA256 и ресурс с origin/SHA. Generated debug/release assets совпадают.
- В обоих реальных APK проверены29 индексируемых assets:AGPL/MPL/Apache/MAVEN/ARTIFACTS +24 upstream resources. Debug SHA `61faba3a75efaa465043c0fb1a9491de1d8fe3264b16f1e2ccfc90a0e66626eb`, release SHA `c99a5de06098916ea97c75680449923deb15ee5ad68a17c3b0e68e7ada4c03c1`; размеры 28587166/10582903 bytes. Повторная локальная проверка APK из SHA-проверенного архива PASS.
- **12 негативных fixtures**, **2 реальных offline Gradle отказа** (unreviewed coordinate/duplicate inventory), restored positive и побайтное совпадение regenerated assets PASS. **4 реальных APK отказа** при удалении AGPL либо одного сохранённого ресурса в каждом варианте.
- 698 Markdown/9 docs checks PASS; новые CI steps имеют explicit root working-directory (локальная текстовая проверка, не YAML parser/full workflow). Native sourcee3fb/14 artifact hashes/canonical core license parity/protected CSS/CHANGELOG/users unchanged.
- Recoverable source/APK/generated-assets/log/report archive 24370725 bytes, SHA `55fca2447631bfe3f188041ba58256ed43d202033f2efd819c6e8089b25d7e82`; публичные пересоздаваемые SDK/JDK/Maven caches не дублируются. Локальный SHA предшествует proc/cwd/exe/root/fd/mount guarded cleanup; результаты очистки фиксируются отдельно.

Первичные отказы на duplicate variant records, попытка legacy resolution,
диагностический прогон, missing offline cache и XML namespace в независимом
harness и unavailable optional PyYAML в локальном orchestration сохранены. Это не успешные проверки продукта; итоговые прогоны ниже
выполнены после исправлений. Утверждение о причине отказа уточнено по диагностике:
первичный duplicate filename вызван повторными visits, а не доказанной потерей
NOTICE стандартным ArtifactCollection.

## Границы

Реестр 76 Maven-координат наследует ранее sealed review деклараций лицензий;
это не 76 новых запросов upstream. Независимая сверка касается 63 оригинальных
JAR/AAR, закреплённых текущими Gradle checksum, и 24 найденных ресурсов.
Отсутствие NOTICE в бинарном архиве не доказывает его отсутствие в исходниках.
Проверка сторонних notices Rust-ядра, upstream source notices, source publication,
подписей, current-source Actions и полного release admission остаётся OPEN.
Наличие AGPL/MPL в APK не меняет лицензии каталогов и не закрывает эти пункты.

Native core и Rust-код не менялись; новая native A/B-сборка, JVM/device/VPN runtime
не заявляются. Предыдущие JVM201/lint53 — inherited evidence. Q34 IN_PROGRESS;
полный план 30/37 DONE (81,1%), осталось7. Исторические Q29 SIGKILL FAIL/ENONET,
Q30/Q31, F459, D06 ACCEPTED_LIMITATION и USER_EXCLUDED сохранены.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-android-notices-20261008`: SEALED 93 files / 29234394 bytes; manifest SHA256 `0566db24ab52066b5cc339764eef4d65345e23ff37ff03703237b8afcde86db6`.


Очистка собственного build root и remote backup выполнена после проверки локального SHA и proc/mount guards. .11 Qeli777/845,CLI75bc/serviceactive и .10 Qeli745/901,CLIca0a сохранены.
