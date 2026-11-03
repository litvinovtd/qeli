# Q27: Windows-хранилища и служебный профиль — этап PASS

5 октября 2026. База `e981c8c5`; Windows, .NET SDK 10.0.300.
Полный Q27 остаётся **IN_PROGRESS**; итог плана — **26/37 (70,3%)**, 11 разделов осталось.

<!-- normative-sync: audit-q27-windows-storage-v1 -->

## Подтверждённые дефекты

| Находка | Воспроизведение и исправление |
|---|---|
| Q27-F222: backup не использовался | Windows сохранял предыдущую зашифрованную генерацию в `.bak`, но при повреждении последней переносил её в quarantine и открывал пустой список. Теперь после успешного quarantine восстанавливается структурно корректный backup, затем атомарно публикуется DPAPI CurrentUser archive. Legacy backup проходит прежнюю миграцию. Ошибка восстановления при записи передаётся вызывающему коду. Stale-revision guard и sidecar lock сохранены. |
| Q27-F223: несогласованные лимиты службы | SaveProfile мог опубликовать blob больше 4 МиБ, который LoadProfile затем отвергал. Писатель проверяет как plaintext, так и итоговый DPAPI blob с envelope до публикации. Reader проверяет лимит на каждом блоке, вместо одного начального Length и неограниченного CopyTo. Status ограничен 64 КиБ, intent — 16 байт; сообщение status ограничено 2048 символами. Это граница локального защищённого storage, не найденная удалённая атака. |
| Q27-F224: тихая подмена UTF-8 и null | Encoding.UTF8 заменял некорректные байты в аутентифицированном профиле; служебная десериализация принимала обязательные поля с null. Strict UTF-8 и общий ProfileStorePayload.Validate отвергают их до UI/native использования. Только криптографическая ошибка выбирает legacy; System-политика по-прежнему запрещает plaintext. |

DPAPI codec вынесен в path-scoped WindowsProfileArchive, который использует тот же
production ProfileStoreFile. Тесты не открывают настоящий APPDATA и ProgramData.
Временные decrypted/serialized byte arrays обнуляются в finally; immutable managed
strings и внутренние буферы сериализатора не обещаются полностью стираемыми.

ServiceStatus теперь читается после тех же проверок каталога, владельца/DACL и
reparse points, что и другие service files, с одним handle, допускающим atomic rename.
Это hardening согласованности доверия; живое нарушение ACL на установленной службе
не воспроизводилось. Служба и автозапуск используют protected executable paths;
owned DLL extraction failure запрещает fallback. Эти existing guards проверены
доступными selftests и review, без установки/изменения службы.

## Проверки

- **184/184 Windows selftest PASS**, 0 FAIL/SKIP; 41 новая проверка:
  21 archive + 20 service storage. Настоящие DPAPI CurrentUser/LocalMachine;
  corruption/backup/legacy/ID/strict UTF-8/null, stale writer, blocked quarantine и
  blocked migration, точные 4 МиБ, envelope overhead, growth stream и status/intent caps.
- **543/543 shared conformance PASS**, обязательные fixtures включены, 0 FAIL/SKIP.
  Общая structural validation сохраняет прежнее поведение архивов.
- Release builds Windows/shared/Mac — 0 warnings/errors. Mac — compile-only на Windows,
  его Keychain/daemon/runtime не запускались.
- Изолированная адаптация прежних production Load/Save/decoder/reader воспроизводит
  **5/5 ожидаемых FAIL**: backup, encrypted UTF-8, required null, writer limit,
  streaming limit. Path и System identity заменены тестовыми аргументами; исходные
  тела сохранены. Streaming control использует поток с initial Length=1 и ростом;
  это не доказательство гонки обычного Windows file handle, открытого без FileShare.Write.
- Пиннинг двух Wintun 0.14.1 DLL: hash, Authenticode signer/thumbprint и обе лицензии PASS.
  Первая попытка script заблокирована локальной execution policy; повторный запуск
  использовал process-only ExecutionPolicy Bypass, системная policy не менялась.
- RU/EN docs, panel, generated bindings, diff и native provenance/checksums проверены.
  Rust/native inputs не изменены; новый native A/B, Linux network matrix и benchmark
  не запускались.

Raw: `audit-debt-20260924/q27-windows-store-20261005` в общем workspace;
машиночитаемое evidence: `release/certification/evidence/q27-windows-storage-20261005.json`.
Первые три baseline harness failures (desktop reference/import/native DLL resolution)
сохранены отдельно; только r4 воспроизводит production regressions, exit 1.

## Что остаётся в Q27

GUI service/profile transitions, autostart/SCM error reporting и остальные драйверные
адаптеры требуют завершения review и доступных fault checks. Windows VM network,
sleep/wake и boot service runtime — **SKIPPED по решению пользователя**, не PASS.
Selftest загружает Wintun DLL, но не подтверждает установленный драйвер, реальные
routes/DNS/firewall или VPN-подключение. Работающие сервисы, native binaries и лаба
не изменялись; push/deploy не выполнялись. Конфиги — INI, внутренний JSON DTO/storage
остаётся разрешённым служебным обменом.
