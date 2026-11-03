# Q34: точный источник MicroCom.Runtime

<!-- normative-sync: q34-source-binding-v1 -->

9 октября 2026. F489 / Q34-F043 закрыт в пределах publisher source binding,
совместимости используемого API и обновления dependency graphs/notices.

## Изменение

MicroCom.Runtime 0.11.0 в Avalonia-графе не указывал исходный commit ни в nuspec,
ни в AssemblyInformationalVersion. Поэтому его MIT supplement ранее имел честную,
но менее точную привязку `publisher-declaration`.

Mac-проект явно закрепляет совместимый MicroCom.Runtime 0.11.2. Официальный пакет
указывает `a83e5a26aa68adaa6001338e2cee2411dd380d1f` в nuspec и в informational
version DLL. Полное upstream-дерево из 76 файлов сверено с Git blob SHA; LICENSE
теперь берётся именно из этого commit. Старое специальное publisher-only
исключение удалено из общего генератора. Обновлены все 24 Mac lockfile-графа
и общий managed bundle; прочие пакеты и legal resources побайтно прежние.

Это подтверждает согласованную декларацию издателя и доступность точного дерева
исходников. Независимая побайтно воспроизводимая сборка upstream DLL и проверка
доверия/отзыва сертификата NuGet этим результатом не заявляются.

## Почему версия 0.11.2

Проверены официальные пакеты 0.11.2–0.11.6. В 0.11.2 сохранены все 52 прежние
public/protected type/method API-записи и dispatch flags. У 0.11.3/0.11.4 отсутствует
прежний virtual `Dispose(bool)`, у 0.11.5/0.11.6 также отсутствует прежний
`AddMethod(Delegate)`. Это основание отказать слепому обновлению; оно не доказывает,
что конкретный интерфейс Qeli падает на каждой более новой версии. Несовместимые
кандидаты не применялись к проекту. Pin и комментарий фиксируют необходимость
повторной проверки API при следующем обновлении.

## Проверки

- Официальный NuGet catalog: размер и SHA512 архива 0.11.2 совпадают. Архив SHA256 `8e56d08570b33d3ec25087081dcab878a6bd07c63e9b76d028665331c48f3da6`.
- Windows и Linux: по 12 графов, в каждом настоящий generate/locked restore. Старый Windows lockfile после добавления pin реально отклонён. Сравнение всех 24 JSON-графов подтверждает изменение только записи MicroCom.
- Один consumer собран против старой DLL. На Windows с каждой старой/новой DLL проходят 12 interop-утверждений: unmanaged vtable, retained delegate, virtual Dispose, явное владение ссылками, disposed pointer и регистрация IUnknown. Тот же consumer с новой DLL проходит на Linux. Finalizer, Cocoa/GUI и VPN runtime здесь не проверялись.
- Закреплённый SDK10.0.401 реально проверил cryptographic signature integrity/contentHash всех 67 admitted пакетов. 66 неизменных официальных archive admissions наследуются; новый MicroCom проверен свежим catalog. Две генерации дают одинаковые 187 файлов/48 supplements/6 fonts. Старый bundle реально отклонён.
- 21 unit-тест генератора, включая два новых негативных контракта packaged commit/удалённого исключения, и 38 native recipe fixtures PASS. Настоящий Debug/tools build, две Release Mac-упаковки и Windows-упаковка PASS; Mac-публикации содержат точную DLL0.11.2, все три — точный общий legal bundle. Shared conformance PASS. Linux-host managed Release build PASS. Это сборки/упаковки на доступных хостах, без Mac/Xcode/signing.

Уникальные managed outputs и SHA-инвентарь полных локальных публикаций сохранены.
Собственный .11 стенд использовал частные SDK/NuGet roots. Recovery archive SHA
и все его члены проверены; восстанавливаемые official SDK/NuGet caches исключены
с точными URL/hash/contentHash receipts. Первая очистка штатно отказала из-за
живого сборочного процесса; он завершился самостоятельно. После повторной
проверки сохраняемых файлов и process/fd/mount guards удалены только собственный
root и удалённая копия backup. PID777/845, active service и установленный Qeli
сохранены. .10 не использовалась. Промежуточные отказы подготовки доказательств
сохранены отдельно; они не названы продуктовыми ошибками.

## Границы

Ядро, native inputs/14 artifact SHA, защищённые CSS/templates и `qeli` tree
не менялись. Прежняя native qualification и SDK source cut сохранены; source gate
проверен без новой SDK/Rust сборки. Q34 IN_PROGRESS; полный план30/37 DONE81.1%,
7 остаются. F459 braces по-прежнему OPEN; текущий exact-SHA hosted CI, source
publication, signatures/release, Q29 SIGKILL FAIL/ENONET, Q30/Q31, Q35,
D06 ACCEPTED_LIMITATION и USER_EXCLUDED сохранены. LOCAL_DEV_COMMIT;NO_PUSH_DEPLOY_RELEASE.

Источники: [пакет 0.11.2](https://www.nuget.org/packages/MicroCom.Runtime/0.11.2),
[точный upstream commit](https://github.com/kekekeks/MicroCom/tree/a83e5a26aa68adaa6001338e2cee2411dd380d1f).

Evidence: `q34-source-binding-20261009`; SEALED 894 files; manifest SHA256 `33a0f411c87fb281574d846f1629fabe96ecaf36904d5d7a8028acfc2d6192db`.
21 managed legal and38 recipe tests PASS;724 tracked Markdown/all9 documentation checks PASS.
