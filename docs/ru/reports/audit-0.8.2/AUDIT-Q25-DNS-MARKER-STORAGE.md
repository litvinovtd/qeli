# Q25 — DNS-маркеры: доверенный каталог и поколение namespace

<!-- normative-sync: audit-q25-dns-marker-storage-v1 -->

24 сентября 2026. База `668139dd`. Частичное закрытие D04/D06/D09.

## Q25-F096, P2 — DNS lease доверял небезопасным файлам состояния

Создание lease проходило по обычному пути каталога, а чтение маркера проверяло тип,
число hardlink и размер, но не владельца, права и стабильность снимка. На исходном коде
три регрессии воспроизвели приём каталога-symlink, каталога с правами 0777 и маркера
0666. В последнем случае recovery вызвал проверку индекса и удалил недоверенную запись.
Это подтверждает нарушение доверия к evidence; произвольная DNS-мутация этим тестом
не доказана, поскольку startup и прежде не делал revert живого индекса по маркеру.

DNS использует общий `state_storage`: проход по компонентам без symlink, проверку
владельцев/прав и открытый descriptor каталога до конца lease или recovery-прохода.
Операции обращаются к этому descriptor; переименование каталога и замена старого пути
не переводят cleanup на другой inode. Marker read ограничен 2048 байт, читает и
проверяет один fd. Symlink/FIFO/hardlink, чужой владелец и group/world write запрещены.
Стабильный `.lock` проверяется до и после неблокирующего flock; создание сохраняет
0600 и владельца допущенного service-каталога. Перед resolver callback права каталога
проверяются повторно. Удаление маркера завершается directory fsync; его отказ явно
сообщает о неопределённой долговечности уже выполненного удаления.

## Q25-F097, P2 — inode namespace не различает поколения после crash

Формат v1 содержал boot ID и device/inode namespace, но не kernel generation. При
повторном использовании inode startup мог принять чужой маркер за собственный и
удалить его по отсутствующему индексу. Теперь v2 включает ненулевой `SO_NETNS_COOKIE`
в содержимое и имя `dns-link-v2-<boot>-<netns-device>-<netns-inode>-<cookie>-<ifindex>.state`.
При несовпадении scope проверка индекса и retirement не выполняются; cleanup также
сравнивает cookie. На пути runtime recovery namespace закреплён fd и проверяется до
и после запроса индекса. Managed DNS требует доступного SO_NETNS_COOKIE; inode-only
fallback отсутствует.

Старые `dns-link-v1-*` сохраняются с предупреждением без автоматической миграции.
Совпадение прежних boot/device/inode/ifindex блокирует новый lease до ручного разбора.
Старые `dns-resolvectl-*` также не усыновляются. При обновлении штатно остановите
старый клиент; после аварии применяйте процедуру §6.50 TROUBLESHOOTING. Сохранённый
маркер любого поколения сам по себе не даёт права сбросить DNS живого интерфейса.

## Проверки

- **1506 host + 71 config; 9 feature/cross/lint checks PASS**.
- **2055 Linux + 37 privileged + 8 worker lifecycle PASS**.
- 5 новых portable, 6 Linux и 2 privileged регрессии: cookie, v1, небезопасные права/
  владельцы, подмена каталога и наследование uid/0600. Последний тест проверяет inode
  ownership при root-создании в service-каталоге, не запуск клиента под другим uid.
- Исходный код с тремя новыми файловыми тестами: **3 ожидаемых FAIL**, test exit 101;
  wrapper exit 0 подтверждает ожидаемое воспроизведение. Исходники после опыта восстановлены.
- Packet matrix: **17/17 cases, 323 assertions PASS**. DNS4/DNS6 используют настоящий resolved/D-Bus;
  дополнительный `QELI_DNS_CRASH_CHECK=1` проверяет SIGKILL, исчезновение TUN и link DNS,
  сохранность marker, restart, восстановление stub-запроса, сохранность v1 и чужого cookie.
  Чужой cookie подставлен в валидную fixture с тем же inode; реальный reuse nsfs inode
  не форсировался. Проверки не утверждают наличие защиты трафика в окне restart.

Source snapshot: 334 files, archive SHA256 `f72ded338327d3c7edda62ee0c82bb8283b113e0d5919f60b6fb6b7f27eed74a`.
Worker SHA256: `88af383f121304b8e3b7d40b89e62ff22088aa624004ccfbc25b76f8ed8782b2`.
Baseline test binary SHA256: `956c5f39fbb8110b2be8db36d03edf8648f282ec1c9de26c8cac00d329b6d0b5`.
Evidence: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/dns-marker-phase/`,
`dns-marker-baseline.log`, `dns-marker-final-v1.log`, `lifecycle-dns-marker/`,
`packet-matrix-dns-marker-v1/`.
Linux Rust 1.97; host Rust 1.98; existing Clippy allowance `chunks_exact_to_as_chunks`.

## Границы

Per-link DNS-маркеры остаются в `/var/lib/qeli`; `STATE_DIRECTORY` их не переносит.
Это внутреннее recovery state; пользовательские конфиги остаются INI. ABI/wire не менялись.
Стабильные lock-файлы намеренно остаются: не удаляйте их при работающих владельцах.
Учёт их накопления относится к D13. Старое глобальное восстановление `dns-backup.json`
и holder-файлы этим изменением не переработаны; process-global DNS остаётся D06.
Непрерываемый filesystem I/O не получил жёсткого deadline. Привилегированный сторонний
writer между проверкой и действием остаётся ограничением. Для внешнего persistent TUN
с живым индексом startup сохраняет evidence и требует проверки администратора.

D04 остаётся IN_PROGRESS: route/kill-switch recovery, перечисленные DNS-границы и полная
mixed nft/firewalld матрица ещё не закрыты. `.10` не изменялся; проверки выполнены на `.11`.
Windows VM/Mac/iOS/router runtime остаются SKIPPED по решению пользователя.

[Реестр](../../plans/AUDIT-DEBT.md) · [Восстановление DNS](../../manuals/TROUBLESHOOTING.md)

Продолжение: [Q25-F101](AUDIT-Q25-LEGACY-DNS.md) закрывает legacy global DNS безопасным отказом от автоматического replay и ручной миграцией. Старый snapshot не доказывает владение текущим resolver; автоматический restore/refcount и его тестовые реализации удалены. Исторические результаты выше относятся к прежнему поведению.
