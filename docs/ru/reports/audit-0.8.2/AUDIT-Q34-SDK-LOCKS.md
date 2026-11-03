# Q34: SDK .NET и фиксация зависимостей

<!-- normative-sync: q34-sdk-locks-v1 -->

8 октября 2026. F460–F462 / Q34-F014–F016 закрыты в указанном ниже объёме. Q34 IN_PROGRESS:30/37 DONE (81.1%),осталось7. F459/braces OPEN и прежние platform/runtime/CI ограничения сохранены. Без push, deployment и release.

## Находки и изменения

| Находка | Изменение |
|---|---|
| F460 / Q34-F014 | CI выбирал плавающий .NET10.0.x; локальный SDK10.0.300 отставал от официального текущего. Корневой global.json задаёт проверенный stable10.0.401, rollForward=disable, allowPrerelease=false; оба setup-dotnet job читают этот файл. Собственные Windows/Linux SDK скачаны с проверкой официального SHA512 до распаковки. Standalone содержит Microsoft.NETCore.App и WindowsDesktop.App10.0.12. Глобально установленные SDK не заменялись. |
| F461 / Q34-F015 | NuGet-графы не имели committed locks. Корневые props/targets включают locked restore и выбирают35 reviewed lockfiles по RID, Mac Debug/Release, tools, Linux-host Skia и single-file packaging. Версии пакетов прежние. Отсутствующий lock, включая ProjectReference, останавливает обычный restore; обновление графа требует явного -p:QeliUpdateDependencyLocks=true --force-evaluate. |
| F462 / Q34-F016 | build_app.sh задавал абсолютный project, но сохранял cwd вызывающей стороны; SDK мог выбираться вне global.json репозитория. Скрипт переходит в свой checkout до dotnet. Настоящий скрипт из внешнего cwd подтвердил правильный каталог и SDK10.0.401; mock останавливает первый publish, без packaging/removal/signing. |

Поведение NuGet установлено реальными отказами: restore -r задаёт RuntimeIdentifiers, build/publish -r использует RuntimeIdentifier; portable lock не подходит следующему RID. Проба с общим RuntimeIdentifiers тоже отклоняется: restore -r заменяет список. Один --locked-mode создаёт отсутствующий lock. Single-file publish добавляет Microsoft.NET.ILLink.Tasks10.0.12 даже без trimming и требует отдельного графа у приложения и shared-проекта. Первые trial-логи и их семь неполных locks сохранены; итоговые артефакты —35 файлов.

Состав35 файлов:24 графа Mac (2конфигурации × 3RID × tools on/off × Linux/non-Linux host),5 shared,4 conformance и2 Windows. Формат конфигов продукта не менялся: global.json и package lock JSON — метаданные инструментов сборки .NET, VPN-профили остаются INI-only. При обновлении SDK нужно пересоздать/проверить затронутые implicit SDK-package locks, publish и audit gates. Хеши пакетов получены настоящим NuGet restore, не написаны вручную.

## Реальные проверки

Windows:18 пар generate/locked restore,7 managed builds (Windows Debug/Release, Mac Release/Debug-tools и оба RID, conformance), Windows adapters и обязательный полный shared conformance PASS. Codec benchmark1400bytes/20000iterations:264.690ms,100.883MiB/s; локальный conformance gate, не пропускная способность VPN и не статистически доказанное изменение относительно прошлого прогона. Отказы старого SDK, dependency drift NU1004, content-hash drift NU1403, отсутствующего root/referenced lock QELI1001 PASS; отсутствующий lock не пересоздаётся.

Обе точные Windows CI publish-команды PASS, third-party notices прежние. Standalone selftest PASS с RunAsInvoker только у дочернего процесса и собственным каталогом bundle extraction. Обычный прямой запуск exe отклонён WinError740: прежний requireAdministrator manifest сохранён. Это не проверка elevated startup, драйверов/filter либо Windows network VM. Отдельная unbundled runtime-инвентаризация подтверждает оба встроенных framework10.0.12. Обе self-contained macOS publish-архитектуры собраны на Windows; исполнения Mac, app signing и system extension проверки нет.

Linux .10: официальный собственный SDK10.0.401, jobs1/process count1;12 Linux-host графов и24 настоящих restore-проверки PASS. Release/Debug-tools managed builds и обе self-contained macOS публикации PASS. SHA финального targets привязан к Linux backup proof. Это не physical Mac runtime. На .10 сохранены installed CLI SHAca0ab9e9, исходные745/901 и inactive-сервис. На .11 read-only inventory подтвердил777/845 и installed CLI75bc593e; Android/emulator не менялись. Глобальные SDK, apt, firewall, службы и системные лимиты не изменялись.

Payload, полные source/fixtures и логи сохранены в recoverable собственных архивах; Linux-архив скачан и SHA-проверен до удаления своего root через guards proc cwd/exe/root/fd и mounts. Локальный scratch сохранён. Rust/native digest прежний: e3fb04a80fc8c2e7334fa5187dacb497ca47b2a79954fcddae45b5d5a533052c;14nativeSHA/copies и предыдущее A/B остаются валидны. Новая native-сборка и переименование старого runtime в current не заявляются. CHANGELOG,users.html и embedded CSS побайтно прежние.

`q34-sdk-locks-20261008`: SEALED 213 files / 967780741 bytes; manifest SHA256 `9cdb5f98a0a52e305471e68dfb74dcecb411211887722f4a39ddf0e9fa7cd18e`.

## Сборка и оставшаяся работа

Нужен полный checkout и SDK из global.json. [Windows build](../../../../qeli-win/README.md) и [Mac build](../../../../qeli-mac/README.md) описывают policy-файлы и явное обновление. В отдельную копию нужно переносить все четыре корневых файла политики и нужные locks. Проверены portable, поддерживаемые RID и существующие options; новые custom configurations/RID либо trim/AOT требуют собственного reviewed-графа. Удаление lock не является способом обновления пакета. --no-restore использует ранее resolved assets и не подтверждает свежий dependency audit.

Android dependency locking/checksum verification, остальные package/license/current exact-SHA Actions/release admission остаются отдельной работой Q34. braces GHSA-vfj7-8cjw-p6xm OPEN: опубликованной правки нет. Полный аудит30/37DONE81.1%,осталось7; old14debtDONE+D06accepted; Q29SIGKILLFAIL/ENONET,Q30Apple/callbackOPEN,Q31capacity/source-cut/currentActions и USER_EXCLUDED Mac/iOS/router/Windows network VM сохранены. Новый remote Actions здесь не запускался.

Официальные источники: [SDK/runtime release metadata](https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json), [SDK selection](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json), [NuGet locked restore](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies).
