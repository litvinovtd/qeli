# Q34: происхождение артефактов и атомарные checksums

<!-- normative-sync: q34-attestation-checksums-v1 -->

Дата: 9 октября 2026.

## F478 / Q34-F032: downloaded bytes не являются результатом Linux build

Linux release job собирал и проверял один DEB, затем скачивал остальные release
assets и вызывал для них `actions/attest-build-provenance` с `dist/*`. Имя шага
«publication evidence only» не изменяет predicate. Точная upstream action
`96278af6caaf10aea03fd8d33a09a777ca52d62f` безусловно вызывает генератор build
provenance и передаёт этот predicate в signer. При наличии других assets workflow
создавал для них необоснованное свидетельство сборки. Baseline YAML содержит два
build attestation шага, final — только один с exact `steps.assets.outputs.subject`,
который задаётся именем actual CI-built DEB. Удалены чужая аттестация и мёртвый
presence detector. SHA256SUMS всех скачанных assets сохраняется; их build
provenance должен приходить из настоящих platform builds. Старые опубликованные
аттестации не удалялись; hosted OIDC/signature/verification не выполнялись.
[Точная upstream action](https://github.com/actions/attest-build-provenance/blob/96278af6caaf10aea03fd8d33a09a777ca52d62f/action.yml).

## F479 / Q34-F033: checksum admission и сохранение предыдущего manifest

Прежний generator принимал имя с пробелом или переводом строки, мог выдавать
успех с manifest, несовместимым с updater/installer, а CR проверял после записи.
На Windows реальный baseline CLI с `bad asset.deb` заменил прежний manifest и
вернул0; whitespace consumer видит только `bad`. На Linux actual newline basename
также вернул0, но GNU `sha256sum -c` отклонил manifest. Теперь admission принимает
имена `[A-Za-z0-9][A-Za-z0-9._+-]*`, regular files; nested directories пропускаются.
Symlinks, включая SHA256SUMS, и special files отклоняются до чтения/публикации.
После admission/hash всех inputs файл пишется во временный regular file в том же
каталоге и публикуется `os.replace`. Ошибки чтения и замены сохраняют прежние байты;
временный файл удаляется. Формат deterministic sorted, ASCII/LF, bare basename.
Это генератор для собственного release staging; concurrent hostile replacement
или изменение assets после генерации этой партией не квалифицировались.

## Проверки

- Linux11 checksum methods PASS без skips: real CLI/exact sorted hashes, invalid/newline names, asset/output symlinks, FIFO без зависания, empty/missing path, hash/replace failure и сохранение предыдущего manifest. GNU verifier на final two-file output PASS.
- Windows7 checksum PASS и4 POSIX skips; эти четыре реально выполнены на Linux. Release18 и existing native recipe38 methods PASS на Windows. Всего67 разных методов, без суммирования повторов Windows/Linux.
- Actual SHA-qualified PyYAML6.0.3 разобрал три workflow; подтверждены exact DEB subject, baseline foreign wildcard и присутствие новой suite в CI. Parser исходники сверены с прежним official SHA-qualified archive; GitHub expressions/Actions не выполнялись.
- На .11 изменялся только собственный Python fixture root. Recoverable archive скачан и SHA-проверен до /proc/mount-guarded удаления. Исходные PID777/845, service/CLI SHA и сетевые snapshots совпали до/после. Docker/native/SDK/APK/daemon не пересобирались.
- Docs, source scope, protected файлы,14 native SHA и unchanged native digest/evidence проверяются в raw packet. Прежние common bundle payload qualifications наследуются, новая упаковка не заявляется.

Q34 остаётся IN_PROGRESS, общий план30/37 DONE81,1%, осталось7. Matching third-party
source publication, OpenWrt immutable source cut, whole Docker/current Actions/
signatures/full release остаются OPEN. Q29 SIGKILL FAIL/ENONET, Q30/Q31, F459 braces,
D06 ACCEPTED_LIMITATION и USER_EXCLUDED не изменены. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-attestation-checksums-20261009`: SEALED 54 files / 1417911 bytes; manifest SHA256 `eac43f5804f6d55b789e2e3afbf87db459cdf18325fee1056a920febd94f77a9`.
