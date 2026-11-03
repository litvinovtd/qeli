# Q34: точный локальный source cut OpenWrt

<!-- normative-sync: q34-openwrt-source-cut-v2 -->

Дата: 9 октября 2026.

## F483 / Q34-F037

Прежний pin dd0b736276b9ad5b89d117abd1bfe324210f3b26 содержал другой qeli tree.
Production source gate ожидаемо отклонял его. Рецепт теперь ссылается на точный
полный локальный dev commit f4b80a9a3052e9ec12c640036928d543f931dafa и SHA256 d6c112641de77b446d3a32a702221b247556b873c11f648087aebb57d3b209c5
настоящего SDK-архива qeli-0.8.2.tar.zst. Commit не создавался заново: полный
исходный commit/tree перенесён Git pack, отсутствующие родители обозначены
shallow boundary. Все 3131 tracked files после SDK prepare совпали с Git,
включая исходники, лицензии и notices. Native digest и 14 артефактов неизменны.

Официальный OpenWrt24.10.4 SDK проверен по SHA256
229e871f734a2cee5ce3ad6a3e98d3836b0899bfdeaea4d9c2c5cc7b1fce1407.
Его metadata/scripts/host tools перенесены без изменения байтов; неиспользуемые
целевой toolchain/build trees исключены. Частные gawk/dependency extraction и
pinned Rust feed/config использованы для download/prepare без установки в host.
Это проверка исходного архива; компилятор, Cargo, bootstrap и IPK не запускались.
[Официальные checksum](https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/sha256sums).

## Проверки и границы

Два настоящих SDK download, разные собственные Git file URLs, пустые DL_DIR:
одинаковые 26381218 байт и SHA256. Первый Git download при PKG_SOURCE_MIRROR=0 не проверял старый hash;
это не допуск к prepare. Измеренный hash затем успешно проверил
production verify-source.sh в SDK prepare. Второй download использовал
новый hash в рецепте; байты независимо сверены после создания архива.
SDK source archive не подменялся git archive или вручную созданным tar.

Public URL остался https://github.com/litvinovtd/qeli.git. Read-only запрос
GitHub для f4b80a9a3052e9ec12c640036928d543f931dafa вернул HTTP422 No commit found; опубликованный dev
был 83c07f5c31178c67a005f20f59975e14528ab73a. Перед использованием публичного
feed необходимо опубликовать точный pinned commit. Source cut закрыт локально;
public clone/наличие revision и current Actions остаются OPEN. Более поздняя
правка qeli tree требует нового cut/hash. Версия пакета остаётся 0.8.2.

75 методов PASS:25source gate,12whole-preflight,38recipe. Три прежних
source-suite skips (POSIX symlink/FIFO и opt-in baseline) сохранены. Настоящий
gate на committed production recipe принял реальный SDK archive и отклонил
изменённый/отсутствующий архив. Начальный стенд не имел sdk/tmp: исходный FAIL66
сохранён, создан только свой каталог. Два SSH launch-channel timeout10s
сохранены как диагностика controller; jobs продолжились и успешно завершились,
повторно не запускались. Rust/compiler/runtime tests не подменены этими fixtures.

Лаба .11: только собственный временный root, jobs1, без изменений рабочих
сервисов, системных packages/firewall/sysctl. Исходные service/PID/hash проверены
после работы; recovery/archive и guarded cleanup приведены в raw evidence.
Лаба .10 не использовалась. Credential supplied through stdin only; raw and decoded archive credential scan PASS.

Общий план: Q34 IN_PROGRESS; 30/37 DONE (81,1%), 7 осталось. Q29 SIGKILL
FAIL/ENONET, Q30/Q31, F459 braces OPEN, D06 ACCEPTED_LIMITATION и USER_EXCLUDED
сохранены. Новые compiler/native A/B, platform/runtime/hostedCI/signatures/release
не заявлены. LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-openwrt-source-cut-20261009`: SEALED 81 files / 261832009 bytes; manifest SHA256 `3e57c16820e13a9177f2e8339779d50d09f41573357ae6eed5e6bfa21b8aaa98`.


## 12 октября: актуальный source cut после изменений ядра

Предыдущий production pin `746e09cce08b4ffa07f5128427feec99aafcdb98`
не соответствует текущему дереву `qeli/`; настоящий source gate сохранил
ожидаемый отказ. Рецепт обновлён на точный существующий commit `c71e4803cd086add92c066dd48a64af1fdb9dec0`
и SHA256 `2843576ae0eac173c95bb1f222d9459ef402ea992a0c43ff496e1e1f52ed8137` настоящего SDK-архива `qeli-0.8.2.tar.zst`
(28029607 байт). Public URL и версия 0.8.2 сохранены; Build/Compile и Install
не изменялись. Сам commit не пересоздавался: перенесены полный исходный commit
и все его tree/blob objects, shallow boundary только обозначает отсутствующих родителей.

Два штатных SDK24.10.4 download из пустых DL_DIR и разных собственных Git URLs
получили одинаковые байты. SDK prepare проверил новый hash до распаковки.
Все 3272 tracked files, включая LICENSE/notices, сверены с Git; локальная
независимая проверка повторно сверила каждый blob и symlink target. SDK download.pl
побайтно совпал с ранее SHA-квалифицированным официальным SDK. Использован тот же
проверенный SDK projection без нового локального дубликата. Rust/Cargo/bootstrap,
полный BuildPackage, IPK и сетевые router-тесты не запускались.

Настоящий gate на committed production recipe принял новый SDK-архив,
отклонил изменённые байты, отсутствующий argument и отсутствующий файл.
25 source-admission методов PASS; три прежних Windows skips (POSIX symlink/FIFO,
opt-in old baseline) сохранены и не названы PASS. Это не whole release preflight.

Read-only GitHub вернул HTTP422 для `c71e4803cd086add92c066dd48a64af1fdb9dec0`; public dev —
`83c07f5c31178c67a005f20f59975e14528ab73a`, push CI для exact pin отсутствует.
Перед публичным использованием feed необходимо опубликовать точный commit
и получить CI на конечной ревизии релиза. Архив содержит полное дерево pinned
commit; последующая правка recipe/docs вне `qeli/` не выдаётся за это дерево.
Локальная source-admission сравнивает именно `qeli/`, версию и фактический hash.

Лаба .11: один собственный root, jobs1, MemoryMax1400M, MemorySwapMax512M,
CPUQuota150%, общий runtime limit900s. Исходные PID777/845, service/start timestamp,
все firewall backends, routes/resolver сохранены. Результаты/архив скопированы
и проверены по SHA; root удалён после проверки inode/path/process/fd/mount.
SDK build caches удалены; .10 не использовалась. Исходный отказ старого pin сохранён; компиляция и большой benchmark не повторялись.

[Машиночитаемое evidence](../../../../release/certification/evidence/q34-current-source-cut-20261012.json).
Q34 IN_PROGRESS: current public cut/publication, hosted CI, full release gate
и F459 остаются открыты. Q29/Q31/Q35/Q36 также открыты. Всего32/37 (86,5%).
NO_PUSH_DEPLOY_RELEASE.

## 14 октября: локальный срез после исправления ядра

Закреплён исходный commit `ee2b74aafb2a57a2613541223c5522908cb71f71` и SHA256 настоящего SDK-архива `6c82f2162ba9b4939c8d40393a157d5483ccdc6796e41706f0ec2672ee95fb16` (28375941 байт). Старый pin не содержал Q36-F030: настоящий source gate отклонил несовпадающее `qeli/` до запуска. Два штатных SDK24.10.4 download из пустых кешей и разных приватных Git URLs дали одинаковые байты; prepare проверил hash, все 3348 tracked files сверены с исходным Git, включая лицензии и ссылки. Commit не синтезирован и не переписан; shallow mirror содержит все исходные tree/blob objects.

В рецепте изменены только pin, hash и дата проверки; версия, public URL, Compile/Install прежние. Четыре проверки committed source gate охватывают успешный допуск, изменённый архив, отсутствие аргумента и файла. Неизменённые unit suites и Linux-матрица не повторялись. Последующая применимость текущих 20 Linux-критериев касается только recipe metadata и Markdown, исходные execution SHA/даты/артефакт сохранены.

Собственный SDK root/cache/unit и удалённый recovery-архив очищены после SHA/process/fd/mount/inode guards; сервисы и состояние хоста сохранены. Ранее проверенная SDK-проекция переиспользована без локальной копии, исходные архивы сохранены. Нет нового compiler/bootstrap/BuildPackage/IPK/32-bit runtime. Прежние ARM/MIPS/IPK результаты остаются на своём исходнике; изменения ядра ими не квалифицированы. Локальный долг source-cut закрыт; public pin/hosted CI/full release gate и bootstrap остаются открыты. Q34 IN_PROGRESS,33/37 (89,2%),NO_PUSH_DEPLOY_RELEASE.
