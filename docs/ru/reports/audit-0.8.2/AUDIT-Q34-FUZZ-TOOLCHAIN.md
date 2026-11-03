# Q34: воспроизводимый fuzz CI и полный ASan smoke

<!-- normative-sync: q34-fuzz-toolchain-v2 -->

Дата: 9 октября 2026.

## Исправления F485–F486 / Q34-F039–F040

CI устанавливал плавающие nightly и cargo-fuzz. Самостоятельный пакет qeli/fuzz
не имел Cargo.lock: основной lockfile не фиксировал его граф. README описывал
10 из 15 целей. Теперь оба CI задания используют nightly-2026-06-10 и
cargo-fuzz0.13.2; RUSTUP_TOOLCHAIN фиксирует также внутренние вызовы Cargo/rustc.
Отдельный lock содержит146 пакетов:142 совпадают с основным графом по
name/version/source/checksum, ещё arbitrary1.5.0,jobserver0.1.35,libfuzzer-sys0.4.13
и сам qeli-fuzz. Основной lock и исходники shipping core не изменены.

cargo-fuzz0.13.2 не поддерживает --locked для build/run. CI требует файл,
выполняет Cargo fetch --locked, затем build/run offline и проверяет SHA256
lockfile перед каждым smoke target и после задания, включая отказ harness.
Missing/stale lock не становится автоматическим успешным обновлением.
Security CI отдельно выполняет cargo audit --deny warnings --file fuzz/Cargo.lock.
README содержит все15 целей, точные инструменты и тот же контракт запуска.

## Настоящие проверки

Лаба .11: приватная установка dated nightly, один compile job, Cargo cache и
Rustup home внутри собственного root. Compiler rustc1.98.0-nightly beae78130
(2026-06-09),cargo-fuzz0.13.2: побайтная копия прежнего установленного инструмента
SHA92e6980f76db9e77f62b6cfd8e74fe47d672f9d7ee59789f238a6fe563e4c29b.
Новая сборка cargo-fuzz из опубликованного install recipe не заявлена.

Все15 настоящих harnesses собраны default ASan recipe за250.4 секунды, без
rlib/profile/compiler overrides. Исполнен точный smoke Bash из текущего workflow:
30 секунд бюджета на каждую цель,85 930 590 выполнений,15 завершений по31 секунде,
никаких crash artifacts. Пиковый сообщённый RSS687MiB включает ASan quarantine;
это не расход памяти обычного клиента. Для каждого исполненного бинарника
сохранены SHA256 и readelf ASan runtime symbols. Запуск был без исходного corpus;
сгенерированный corpus сохранён. Scope: короткий smoke, не600s nightly и не
доказательство отсутствия всех ошибок.47 warnings core при отключённых shipping
features сохранены; из этих предупреждений не делается вывод о мёртвом коде.

Настоящие отказы: отсутствие lockfile в preflight rc1, несовместимое точечное
изменение aes-gcm с Cargo --locked rc101, изменённый SHA lock rc1. После каждого
отказа исходники восстановлены, положительная проверка повторена. Свежий
cargo-audit0.22.2:146 пакетов,1295 RustSec advisories,DB commit550efd3d587a29b2e2c2b21b17a440da4fede999;
0 vulnerabilities/0 warnings.72 Windows regression methods и13 Linux methods PASS.
Настоящий YAML разобран SHA-qualified private PyYAML; hosted Actions не исполнены.

Первый private rustup install установил compiler, но дал rc1 на self-update из
изолированного Cargo home: сохранён, повторён с --no-self-update. Первое runtime
upload остановилось до запуска из-за отсутствующего .github/workflows каталога;
ошибка обвязки сохранена. Ошибки локальной кодировки/разбора статистики сохранены
в диагностике; исходные UTF-8 строки восстановлены, итоговый diff проверен.

## OpenWrt и границы

Новый fuzz lock/README меняют qeli tree, поэтому прежний source cut не переиспользован.
Exact Git commit746e09cce08b4ffa07f5128427feec99aafcdb98 экспортирован настоящим SDK24.10.4:
download/prepare PASS,все3140 tracked files совпали. Второй пустой DL_DIR с другим
приватным URL дал тот же archive SHA256
9b4b2450c5d8d79cb5e559546dab00e1308e9c0c3646af48431634b91eb1df07.
Production pin/mirror hash обновлены; source gate PASS. SDK subset побайтно
сохранён из прежнего official-SHA-qualified projection, неиспользуемые LLVM/cmake/
headers/static libs исключены. Компиляция SDK/IPK и публичное скачивание нового
локального commit не заявлены; публикация остаётся отдельным prerequisite.

Уникальные outputs,15 бинарников,corpus,точные Git/SDK inputs и ошибки сохраняются
в SHA-проверенном recovery archive; регенерируемые compiler/Cargo/build/SDK caches
исключаются явно с manifest/checksum/source-pack anchors. Собственный lab root
удаляется только после локальной проверки archive members и process/mount guards.
MainPID777/845,active service и CLI SHA75bc сохранены; .10 не использовалась.
Native digest e3fb,14 artifact SHA и protected files неизменны.

Q34 IN_PROGRESS;30/37DONE81,1%,7 осталось. Q35 TODO;full fuzz/concurrency/DoS/soak,
current hosted CI/signatures/release остаются открыты. Q29 SIGKILL FAIL/ENONET,
Q30/Q31,F459 braces,D06 ACCEPTED_LIMITATION и USER_EXCLUDED сохранены.
LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-fuzz-toolchain-20261009`: SEALED 154 files / 358276286 bytes; manifest SHA256 `eb1dd886685937f9a311420ab44d8b0d59bfcd4825e642cc945d816af3f27b60`.

## Последующая проверка Actions: F487 / Q34-F041

Финальный semantic review выявил внесённую этим патчем ошибку: env context недоступен в job-level env. Первичная проверка YAML её не обнаружила; hosted CI тогда не запускался. Официальный SHA-qualified actionlint1.7.12 воспроизвёл два отказа baseline. В исправленном workflow RUSTUP_TOOLCHAIN передаётся отдельным шагом через GITHUB_ENV после установки compiler. Final actionlint rc0,13 regression methods и точный Bash export с LF PASS. Smoke Bash,lock,compiler/tool versions и эффективное окружение настоящего lab прогона не изменились; повторное исполнение85 930 590 случаев не заявляется. Предыдущий sealed packet сохранён; исправление и ограничения зафиксированы отдельным evidence supplement. Это исправление собственного CI patch, не новая найденная ошибка parser.

[Допустимые контексты GitHub](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts) и [GITHUB_ENV](https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-an-environment-variable).

Context correction evidence: `q34-fuzz-context-20261009`;SEALED 33 files;manifest SHA256 `a62231996d1d5eb1a0889cfde3ea4cd65f1121514ecf056cb17fa2282735c3c9`.
