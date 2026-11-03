# Q25 — сведения об интерфейсе в текущем namespace

<!-- normative-sync: audit-q25-link-observation-v1 -->

Дата: 24 сентября 2026. База: `0f4434bf`. Частичное закрытие D02/D06
[реестра техдолга](../../plans/AUDIT-DEBT.md); обе группы ещё имеют незакрытые критерии.

## Q25-F076, P2 — унаследованный sysfs не равен текущему network namespace

Процесс может войти в новый network namespace, сохранив mount sysfs прежнего namespace.
NDP proxy сочетал ifindex из текущего ядра с типом/MAC из унаследованного mount.
Корректный `required` proxy не запускался, если имени в sysfs не было, либо мог получить
чужой MAC при совпадении имён. Такая же проблема была у чтения MAC TAP и ifindex lifecycle
hooks. Панель могла выбрать уже занятое имя, а sysctl-проверка отсутствия — счесть живой
интерфейс исчезнувшим при удалении свидетельств восстановления.

`network_interface.rs` теперь задаёт общую границу получения индекса и параметров Ethernet.
Используется управляющий socket с CLOEXEC и платформенный ifreq/ioctl из libc.
SIOCGIFINDEX и SIOCGIFHWADDR обращаются к namespace сокета; повторный запрос индекса
обнаруживает обычную подмену имени во время наблюдения. Некорректные имена отклоняются,
только ENODEV означает отсутствие; ошибки прав/сокета не считаются отсутствием. NDP
сохраняет проверки Ethernet/unicast. TAP, hooks, sysctl и выбор имени панелью используют
общую границу; прежний TUN-helper индекса реэкспортирует её. Дублирующие sysfs MAC-парсеры удалены.

Worker lifecycle runner теперь намеренно сохраняет унаследованный sysfs, чтобы remount
не скрывал регрессию. Он по-прежнему создаёт отдельные network/mount/PID namespace,
изолируя конфигурацию, firewall и изменения sysctl.

## Проверки

- База `0f4434bf` с регрессионными фикстурами вызывающего кода: **2 ожидаемых FAIL**.
  NDP не может прочитать тип нового link через чужой sysfs; чтение MAC TAP также
  возвращает ENOENT, хотя интерфейс существует в ядре. Это реальные отказы Linux.
- Исправленный Linux-снимок: **1887 обычных + 25 привилегированных тестов PASS**. Пять новых
  native-сценариев покрывают общий запрос, NDP bind, TAP/hooks, наличие интерфейса для sysctl
  и выбор имени панелью. Два обычных теста отклоняют некорректные имена и MAC не-Ethernet link.
- Все **8 worker lifecycle E2E PASS** с унаследованным sysfs: TCP/UDP × off/manual/route/nat66,
  включая обязательный NDP в manual. Прежние проверки изоляции и очистки сохранены.
- Host **1437 unit + 71 config integration PASS**; все девять feature/cross/lint-команд PASS.
  Существующий Clippy compatibility allowance не расширялся. Новое предупреждение unused
  field в client-only удалено; прежние посторонние feature-only предупреждения остаются.
- RU/EN документация: 228 Markdown-файлов, все девять documentation gates PASS.

Свидетельства: `C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/network-view-phase/`,
`network-view-compare.log`, `network-view-final.log`, `lifecycle-network-final/` и сохранённый
manifest исходников. Перед переходом с baseline на исправленный исходник сравнение
явно очищает только артефакты пакета Qeli внутри изолированного Cargo target.
SHA256 финального Linux worker: `77017068e66802e88f45fc3ae42d2c548aeb1899a5ef137c4b90d0d2423f8fb0`.

## Что ещё открыто

Это наблюдение не является устойчивой identity исходного интерфейса или атомарной
арендой против последующих привилегированных rename/delete/recreate. Восстановление
per-link sysctl после reuse имени, смена WAN после захвата, dynamic IPv6, resolved/bus,
DNS/carrier globals и доверие к директории журнала остаются открытыми. `dev_attach`
по-прежнему читает флаги TUN через sysfs: работа attach с чужим mount здесь не сертифицирована.
Доставка NDP-пакетов и полная матрица сетевых backend остаются D10; успешный bind её не заменяет.
Поля INI/API/ABI не добавлялись. Актуальные native GUI-пакеты и бенчмарк здесь не создавались.

[Операционные инструкции](../../manuals/TROUBLESHOOTING.md).
