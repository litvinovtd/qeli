# Contributing to qeli

Спасибо за интерес к проекту! Вклады принимаются через pull request.

## Лицензия вклада (inbound = outbound)

Отправляя вклад, вы соглашаетесь, что он лицензируется на условиях лицензии того
каталога, в который вносится (см. [LICENSING.md](LICENSING.md)):
- `qeli/` (ядро/сервер) → **AGPL-3.0-only**;
- `qeli-android/`, `qeli-win/`, `qeli-mac/` → **MPL-2.0**.

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
PR без подписи во всех коммитах не пройдёт проверку DCO в CI.

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

- Сервер/ядро (Linux): `cargo build --release` + `cargo test --all` + `cargo clippy --all-targets -- -D warnings` в `qeli/`.
- Клиенты: см. `.github/workflows/ci.yml` (Android gradle, Windows/macOS `dotnet`).
- Документация — начните с карты: [docs/ru/index.md](docs/ru/index.md) · [docs/eng/index.md](docs/eng/index.md).
- **Правили доки или добавляли ключ конфигурации?** Прогоните `python3 scripts/check_docs.py`
  (это же делает CI). Скрипт проверяет: нет битых ссылок, нет страниц-сирот вне индекса,
  наборы файлов `docs/ru` и `docs/eng` совпадают, каждый INI-ключ, который сервер реально
  эмитит, описан в `CONFIG.md` на **обоих** языках, каждый упомянутый в бэктиках файл
  исходников существует, и версия везде одна (источник истины — `qeli/Cargo.toml`; с ней
  сверяются сборка Android, обзорные `README.md` и `CHANGELOG.md`).
  Новый документ нужно добавить в оба языковых дерева и в `index.md`.
- Всё локально одной командой: `scripts/ci-check.sh` (доки + сборка + тесты + clippy).
- Перед PR: убедитесь, что сборка/тесты/линт зелёные и каждый коммит подписан (`-s`).
