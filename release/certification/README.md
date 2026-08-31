# Release certification evidence

`<version>.json` is the machine-readable release checklist used by
`scripts/release_certification.py` and `scripts/release_preflight.py`. Automated Linux cases are
release-blocking. Physical-device rows remain an explicit qualification backlog: `pending`,
`blocked`, `deferred`, or `not_available` is reported but does not block a release when the required
hardware is unavailable. A physical `failed` result is still fatal, because a known regression is
not the same thing as an unavailable test. A physical `passed` result must identify the exact
candidate artifact and retain evidence just like an automated result.

Print the source digest with:

```console
python scripts/release_certification.py --print-source-digest
```

The command deliberately fails while required automated cases are pending, but still prints the
value. For every successful case copy that digest, the SHA-256 of the exact tested binary/package,
an RFC 3339 timestamp, a precise environment description, and a retained evidence path or URL. Do
not mark a source-only build as a physical result. A later committed change outside this directory
changes the source digest and invalidates all prior results.

Automated statuses are `pending`, `passed`, `failed`, or `blocked`; only `passed` satisfies
preflight. Physical rows additionally accept `deferred` and `not_available`. The authoritative case
lists live in the validator, so deleting a row cannot hide either a required automated gate or the
advisory qualification backlog. Additional exploratory cases are allowed.

## По-русски

`<версия>.json` — машиночитаемая матрица выпуска. Автоматические Linux-сценарии обязательны.
Физические проверки остаются видимым qualification backlog, но статусы `pending`, `blocked`,
`deferred` и `not_available` не блокируют релиз при отсутствии нужного оборудования. Явный
`failed` остаётся фатальным, а `passed` требует точной привязки к артефакту и evidence.
Для каждого успешного теста сохраняются digest исходного дерева, SHA-256 реально проверенного
APK/EXE/архива/бинарника, время, точное окружение и ссылка на логи. После любого коммита вне этого
каталога digest меняется, поэтому старые результаты нельзя случайно использовать для нового
кандидата.
