# Q34: общий комплект Cargo legal resources

<!-- normative-sync: q34-native-notices-v1 -->

## F470 / Q34-F024: находка и исправление

Клиентские и серверные пакеты не имели общего комплекта лицензионных ресурсов
Cargo-зависимостей. `cargo deny` проверяет допустимые лицензии графа, но не
подтверждает попадание их текстов в распространяемые файлы.

Добавлен один `qeli/third-party-notices/rust/`: 235 registry-пакетов закреплённого
Cargo.lock, 458 upstream ресурсов, 464 файла вместе с индексами и AGPL ядра,
2544405 bytes. Полный lockfile включает server/build/test/other-target зависимости;
это сознательный superset, не перечень linkage каждого клиентского бинаря.
SPDX expressions из опубликованных Cargo.toml и исходные байты сохранены.
LICENSE/NOTICE/COPYING/COPYRIGHT/UNLICENSE/AUTHORS, LICENSES и license-file
собираются offline; SHA архивов сверяются с Cargo.lock.

Три опубликованных subcrate не содержат LICENSE: для asn1-rs-impl, defmt-parser
и jni-sys-macros добавлены шесть текстов с VCS-коммитов из их crate metadata.
`r-efi` содержит лицензию и copyright в [AUTHORS](https://github.com/r-efi/r-efi/blob/7e1b0322d31d625f81a5656096330934f9cd835d/AUTHORS);
этот оригинальный файл сохранён из SHA-проверенного архива.

`scripts/native_licenses.py` генерирует только в новый каталог; validator
блокирует stale Cargo.lock, checksum/version/source drift, потерю/добавление
файлов, дубли и unsafe paths. Git attributes сохраняют upstream bytes.
CI проверяет общий комплект. Android Gradle дополнительно проверяет lock binding,
индекс/SHA и включает комплект в variant assets; APK checker сравнивает все bytes.
Windows/macOS сохраняют visible publish sidecars и MPL клиента; iOS получает folder
resource. Debian/OpenWrt install рецепты и Keenetic ZIP используют тот же комплект.
Процедура обновления и пути упаковки: [LICENSING](../../../../LICENSING.md).

## Проверки

- 235 официальных `.crate` архивов / 35756092 bytes: все SHA совпадают с Cargo.lock. Независимая прямая tar-распаковка сверила все458 ресурсов; шесть supplements сверены с точными VCS-коммитами и upstream Git blob.
- 17 native bundle и14 APK policy fixtures PASS. Комплект и детерминированный ZIP проверены; новая сборка роутерного ядра не заявляется.
- Четыре реальные publish-сборки PASS: оба Windows-варианта и macOS osx-arm64/osx-x64. В каждом464 точных файла и MPL клиента. macOS publish выполнен на Windows, Apple runtime исключён. CLI проверил все четыре каталога; два реальных удаления/повреждения ресурса отклонены, восстановление PASS.
- Настоящий Debian package/extraction и фактическое тело OpenWrt install-рецепта PASS:464 идентичных файла. Использованы /bin/true ELF fixtures, без установки, полной SDK или Qeli release-сборки.
- Strict debug/default unsigned R8 APK PASS (326.05 s), lintVital PASS. В каждом493 индексируемых assets, включая весь общий комплект464 файлов. Debug SHA `d3eac85fcee3b3780d9e304ccb52934a6e3b4f21182fa94b0b8ad1ead0d80c1e` (29793867 bytes), release SHA `50341f617e836db18f3d890159907bfa24029bbd2bc56e1609627197dbc9d0d0` (11691588 bytes). Локальная проверка APK из SHA-проверенного архива также PASS.
- Два реальных offline Gradle отказа (stale binding/повреждённый resource), восстановление и побайтное совпадение assets PASS. Восемь реальных APK отказов при удалении core/Maven/native resource/native index PASS.
- Восстановимый архив source/APK/generated assets/logs/reports: 27830087 bytes, SHA `58519cc3f5d77ae4e2b4c72cfb78faa4dfb4e42640d5d25780259729ea7afeb9`. Локальный SHA предшествует proc/cwd/exe/root/fd/mount guarded очистке собственного .11 root/backup. .11 процессы777/845 и active service; .10 процессы745/901 и installed CLI сохранены.
- 700 Markdown /9 docs checks PASS. Первичные ошибки integration harness (existing attributes/CI indentation) и Gradle DSL shadowed java import исправлены, результаты FAIL сохранены отдельно. Итоговая сборка использует явный Files import. CI-команды проверены текстово; запуск Actions/YAML parser не заявляется. Полные lintRelease/JVM/device проверки для изменения упаковки не повторялись.

## Границы и дальнейшие шаги

Это проверка сохранения найденных upstream ресурсов, а не полной юридической
квалификации. Rust std/toolchain, отсутствующие в архивах upstream source notices,
.NET notices, matching source publication, подписи и current-source Actions
остаются OPEN. Для OpenWrt остаётся обязательным обновление/квалификация immutable
source cut с новым комплектом: host install fixture не подтверждает старый mirror
или полноценную SDK-сборку. iOS/Xcode и physical router runtime USER_EXCLUDED.

Native Rust исходники/recipe и все 14 artifact SHA неизменны (e3fb04a8…); новая
native A/B, JVM suite или device VPN проверка не заявляется. Исторические Q29
SIGKILL FAIL/ENONET, Q30/Q31, F459 braces, D06 ACCEPTED_LIMITATION сохранены.
Q34 IN_PROGRESS; полный план 30/37 DONE (81,1%), осталось7.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-native-notices-20261008`: SEALED 837 files / 74001463 bytes; manifest SHA256 `5b8d9e61cf51e25dcf6b2c58530171aa519749e809d5ac0d905f22596a3bb3a1`.
