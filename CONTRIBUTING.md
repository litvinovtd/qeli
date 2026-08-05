# Contributing to qeli

[Русская версия ниже](#участие-в-qeli)

Thank you for your interest in qeli. Contributions are accepted through pull requests.

## How to prepare and open a pull request

### 1. Start from `dev`

`dev` is the only target branch for development. `main` contains the released state of
the project. A PR opened directly against `main` will be asked to retarget and rebase
onto `dev`.

Create a fork, then start a dedicated branch from the current `upstream/dev`:

```bash
git clone https://github.com/YOUR_GITHUB_LOGIN/qeli.git
cd qeli
git remote add upstream https://github.com/litvinovtd/qeli.git
git fetch upstream
git switch -c feature/short-name upstream/dev
```

Do not prepare a PR directly on your fork's `main` or `dev`. One branch should address
one related task; submit unrelated fixes as separate PRs.

### 2. Make reviewable commits

- Split the work into logical commits. Code, tests, documentation, and packaging changes
  should be independently reviewable and reversible where practical.
- Do not commit local build output, temporary files, secrets, real server configurations,
  or keys.
- Sign off **every** commit under the DCO with `git commit -s`.
- Before pushing, synchronize your branch with the current `dev`:

```bash
git fetch upstream
git rebase upstream/dev
git push --force-with-lease origin feature/short-name
```

Use `--force-with-lease`, not an unconditional `--force`: it refuses to overwrite remote
work if the branch has unexpectedly changed.

If you forgot the DCO sign-off, fix the last commit with:

```bash
git commit --amend -s --no-edit
```

For several commits, use `git rebase --signoff`. The DCO workflow currently reports
missing sign-offs as an advisory warning, but every commit is still expected to carry a
`Signed-off-by` line and the maintainer may ask you to repair the PR history.

### 3. Include what is needed to review the change

A PR should include the implementation and tests or conformance vectors for new behavior
and bug fixes.

Changes to `CHANGELOG.md` and user documentation are **optional for the PR author**. You
may include them, but if they are absent, the maintainer will add the required release
notes and documentation before publishing a release. If you choose to update them:

- add the changelog entry under the current development version; its source of truth is
  `qeli/Cargo.toml` (0.7.15 at the time of writing);
- document user-visible behavior in both Russian and English;
- add new INI keys and current examples to both `CONFIG.md` files.

For third-party DLLs, drivers, libraries, and other binaries, you must provide the exact
version and source, SHA-256/provenance, license, and third-party notice. Unverified binaries
or binaries built from an unknown source state are not accepted.

Do not create a tag or GitHub Release, and do not publish release artifacts from a PR. The
maintainer performs the final release build and publication after the changes are accepted.

### 4. Test before opening the PR

Run the checks for every affected platform. The complete local gate is:

```bash
scripts/ci-check.sh
```

Platform-specific commands are listed later in this guide and in
`.github/workflows/ci.yml`. In the PR description, list the commands you actually ran and
their results. If a check requires special hardware, administrator privileges, or the lab
and you could not run it, say so explicitly; do not mark it as completed.

### 5. Open the PR against `dev`

Select these values when creating the PR:

- **base repository:** `litvinovtd/qeli`;
- **base branch:** `dev`;
- **compare branch:** the task branch in your fork.

The PR description should explain:

1. what changed and which problem it solves;
2. how the solution works and which components it affects;
3. how it was tested, including commands, scenarios, and results;
4. known limitations, compatibility risks, and review questions;
5. screenshots for visible UI changes.

Check that the diff contains no accidental files and that every checked test-plan item was
actually completed. For a first-time contributor, GitHub Actions may initially show
`action_required`. This means that the workflow is waiting for maintainer approval; it does
not mean that the tests have already failed.

After review feedback, update the same branch, rerun the relevant checks, and reply briefly
to each point. A PR is ready to merge when conflicts with `dev` are resolved and required
checks are green. Documentation and the changelog can be completed separately before the
release when needed.

---

# Участие в qeli

[English version above](#contributing-to-qeli)

Спасибо за интерес к проекту! Вклады принимаются через pull request.

## Как подготовить и открыть pull request

### 1. Начинайте от `dev`

`dev` — единственная целевая ветка для разработки. `main` содержит выпущенное
состояние проекта: PR, открытый напрямую в `main`, будет предложено перенаправить и
перебазировать на `dev`.

Создайте форк, затем начните отдельную ветку от актуального `upstream/dev`:

```bash
git clone https://github.com/YOUR_GITHUB_LOGIN/qeli.git
cd qeli
git remote add upstream https://github.com/litvinovtd/qeli.git
git fetch upstream
git switch -c feature/short-name upstream/dev
```

Не вносите работу для PR прямо в `main` или `dev` своего форка. Одна ветка должна
решать одну связанную задачу; несвязанные исправления оформляйте отдельными PR.

### 2. Делайте проверяемые коммиты

- Разбивайте работу на логические коммиты: отдельные изменения кода, тестов,
  документации или упаковки можно проверить и при необходимости откатить независимо.
- Не добавляйте в коммит результаты локальной сборки, временные файлы, секреты,
  конфиги реальных серверов и ключи.
- Подписывайте **каждый** коммит по DCO с помощью `git commit -s`; подробности — ниже.
- Перед отправкой синхронизируйтесь с актуальным `dev`:

```bash
git fetch upstream
git rebase upstream/dev
git push --force-with-lease origin feature/short-name
```

Используйте именно `--force-with-lease`, а не безусловный `--force`: он не перезапишет
чужую работу, если удалённая ветка неожиданно изменилась.

### 3. Приложите всё необходимое для проверки изменения

PR должен включать реализацию и тесты или conformance-векторы для нового поведения
и исправленной ошибки.

Изменения `CHANGELOG.md` и пользовательской документации **не обязательны для автора
PR**. Их можно добавить по желанию; если их нет, мейнтейнер внесёт необходимые записи
перед выпуском релиза. Если вы всё же обновляете документацию:

- добавляйте запись в `CHANGELOG.md` в секцию текущей разрабатываемой версии; источник
  версии — `qeli/Cargo.toml` (на момент написания это 0.7.15);
- пользовательские изменения описывайте одновременно на русском и английском;
- новые INI-ключи добавляйте в оба файла `CONFIG.md` вместе с актуальными примерами.

Для сторонних DLL, драйверов, библиотек и других бинарников обязательно укажите точную
версию и источник, SHA-256/provenance, лицензию и third-party notice. Непроверенные или
собранные из неизвестного исходного состояния бинарники не принимаются.

Не создавайте тег, GitHub Release и не публикуйте релизные артефакты из PR. Финальную
сборку и публикацию релиза выполняет мейнтейнер после принятия изменений.

### 4. Проверьте работу до открытия PR

Запустите проверки для затронутых платформ; полный локальный гейт:

```bash
scripts/ci-check.sh
```

Команды по отдельным платформам перечислены ниже и в `.github/workflows/ci.yml`.
В описании PR укажите реально выполненные команды и результаты. Если проверку нельзя
было выполнить без специального устройства, прав администратора или лаборатории —
так и напишите; не отмечайте её выполненной.

### 5. Откройте PR в `dev`

При создании PR выберите:

- **base repository:** `litvinovtd/qeli`;
- **base branch:** `dev`;
- **compare branch:** ветка задачи в вашем форке.

Описание PR должно содержать:

1. что изменено и какую проблему это решает;
2. как устроено решение и какие компоненты оно затрагивает;
3. как изменение проверялось — команды, сценарии и результат;
4. известные ограничения, риски совместимости и вопросы для ревью;
5. скриншоты для заметных изменений интерфейса.

Убедитесь, что diff не содержит случайных файлов, а все пункты test plan действительно
выполнены. У новых контрибуторов GitHub Actions может сначала показать
`action_required`: это означает, что запуск workflow ждёт разрешения мейнтейнера, а не
что тесты уже упали.

После замечаний ревьюера внесите исправления в ту же ветку, повторите проверки и
коротко ответьте по каждому пункту. PR готов к слиянию, когда конфликты с `dev`
устранены и обязательные проверки зелёные. Документацию и CHANGELOG при необходимости
можно дополнить отдельно перед релизом.

## Лицензия вклада (inbound = outbound)

Отправляя вклад, вы соглашаетесь, что он лицензируется на условиях лицензии того
каталога, в который вносится (см. [LICENSING.md](LICENSING.md)):
- `qeli/` (ядро/сервер) → **AGPL-3.0-only**;
- `qeli-android/`, `qeli-win/`, `qeli-mac/`, `qeli-ios/` → **MPL-2.0**.

**CLA / передача авторских прав не требуются.** Вы сохраняете авторство; код входит
под той же открытой лицензией, что и каталог («inbound = outbound»).

## Developer Certificate of Origin (DCO)

Вместо CLA мы используем **DCO** — лёгкое подтверждение, что вы имеете право прислать
этот код. Каждый коммит должен содержать строку `Signed-off-by`:

```
git commit -s -m "ваше сообщение"
```

Это добавляет в конец сообщения коммита:

```
Signed-off-by: Ваше Имя <your.email@example.com>
```

Имя/email должны быть настоящими (`git config user.name` / `user.email`) и совпадать
с автором коммита. Если забыли `-s` — поправьте последний коммит:
`git commit --amend -s --no-edit` (для нескольких — `git rebase --signoff`).
CI сообщает о пропущенных подписях проверкой DCO. Сейчас она advisory и выводит warning,
но подпись ожидается в каждом коммите, и мейнтейнер может попросить исправить историю PR.

### Текст DCO 1.1

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Разработка

### Тулчейн и системные пререквизиты

- **Rust stable.** Заведомо рабочая версия — **rustc 1.96.0** (на ней собирается лаба);
  CI берёт актуальный `stable`. `rust-version` (MSRV) в `qeli/Cargo.toml` не объявлен,
  так что «older stable» не гарантирован — если собираете на более старом тулчейне и
  что-то не компилируется, обновитесь, прежде чем заводить issue.
- **Nightly** нужен только для двух вещей: fuzz-харнесов (`cargo +nightly fuzz`) и
  кросс-сборки под mipsel (tier-3, `-Zbuild-std`). Для обычной работы не требуется.
- **Сборка `.deb`** (`qeli/debian/Makefile`) — Debian/Ubuntu-хост и **`dpkg-deb`**.
  Для публикуемых пакетов цель одна — **`make deb-portable`**, а ей нужны **`zig`** и
  **`cargo-zigbuild`** в `PATH`: они прибивают ABI glibc к 2.28, иначе бинарь
  собирается против glibc хоста и падает на Ubuntu 22.04 с `GLIBC_2.39 not found`
  (так уехали 0.7.8–0.7.11). `make deb` — только для локального использования.
- **Клиенты**: .NET SDK (Windows/macOS), Android SDK + Gradle, Xcode + XcodeGen (iOS).
  Точные версии — в `.github/workflows/ci.yml`, он же источник истины.

### Команды

- Сервер/ядро (Linux), в `qeli/`: `cargo build --release --features jemalloc` +
  `cargo test --workspace` + `cargo clippy --all-targets -- -D warnings`.
  **`--features jemalloc` для СЕРВЕРНОГО бинаря обязателен**: без него RSS воркера
  упирается в ~180 МБ под churn'ом хендшейков (glibc держит освобождённые арены)
  вместо ~40–60 МБ с jemalloc — см.
  [GETTING-STARTED](docs/ru/GETTING-STARTED.md). Клиентской сборке фича не нужна,
  а `qeli/debian/Makefile` включает её сам (`CARGO_FEATURES`).
- Клиенты: см. `.github/workflows/ci.yml` (Android gradle, Windows/macOS `dotnet`).
- Документация — начните с карты: [docs/ru/index.md](docs/ru/index.md) · [docs/eng/index.md](docs/eng/index.md).
- **Правили доки или добавляли ключ конфигурации?** Прогоните `python3 scripts/check_docs.py`
  (это же делает CI). Скрипт проверяет: нет битых ссылок, нет страниц-сирот вне индекса,
  наборы файлов `docs/ru` и `docs/eng` совпадают, каждый INI-ключ, который сервер реально
  эмитит, описан в `CONFIG.md` на **обоих** языках, каждый упомянутый в бэктиках файл
  исходников существует, в GitHub-ссылках не осталось незаполненного `<owner>`, и в
  `CHANGELOG.md` есть секция под разрабатываемую версию.
  Новый документ нужно добавить в оба языковых дерева и в `index.md`.
- **Бампите версию?** Не правьте 22 файла руками — `python3 scripts/sync_version.py --write`.
  Источников истины два и они намеренно разные: **разрабатываемая** версия берётся из
  `qeli/Cargo.toml` (идёт в сборочные файлы и обзорные `README.md`), **выпущенная** — из
  новейшего тега `v*` (идёт в баннер «документация описывает X» в десяти документах).
  Без `--write` скрипт только проверяет и ничего не пишет; это же делает CI.
- Всё локально одной командой: `scripts/ci-check.sh` (доки + сборка + тесты + clippy).
- Перед PR: убедитесь, что сборка/тесты/линт зелёные и каждый коммит подписан (`-s`).
