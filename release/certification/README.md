# Release certification evidence

`<version>.json` is the machine-readable release checklist used by
`scripts/release_certification.py` and `scripts/release_preflight.py`. CI proves source-level
correctness; this file additionally proves that exact candidate artifacts passed the IPv6 and
roaming matrix on real operating systems and devices.

Print the source digest with:

```console
python scripts/release_certification.py --print-source-digest
```

The command deliberately fails while cases are pending, but still prints the value. For every
successful case copy that digest, the SHA-256 of the exact tested binary/package, an RFC 3339
timestamp, a precise environment description, and a retained evidence path or URL. Do not mark a
source-only build as a physical result. A later committed change outside this directory changes
the source digest and invalidates all prior results.

Statuses are `pending`, `passed`, `failed`, or `blocked`. Only `passed` satisfies preflight.
The authoritative required-case list lives in the validator, so deleting a JSON row cannot hide an
unfinished test. Additional exploratory cases are allowed.

## По-русски

`<версия>.json` — обязательная машиночитаемая матрица выпуска. Для каждого успешного теста
сохраняются digest исходного дерева, SHA-256 реально проверенного APK/EXE/архива/бинарника,
время, точное окружение и ссылка на логи. `pending`, `failed` и `blocked` не разрешают релиз.
После любого коммита вне этого каталога digest меняется, поэтому старые результаты нельзя
случайно использовать для нового кандидата.
