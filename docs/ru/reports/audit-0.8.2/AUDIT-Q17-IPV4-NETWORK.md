# Q17: IPv4 NAT, forwarding и sysctl

<!-- normative-sync: audit-q17-network-v1 -->

**DONE/PASS. План: 17/37 (45,9%), осталось 20.** 4 октября 2026.
Код ядра: `1342edbd9cd5d16af3d35161684f0bec3999a8ca`.
Linux SHA256: `eb2b90bf1bc60c985190d65560ef205a4769212ffcaf9169048c371b31ad5932`.
[Evidence](../../../../release/certification/evidence/q17-network-20261004.json).

## Результат разбора

Новых подтверждённых функциональных дефектов в движке NAT/gateway/sysctl не найдено.
Проверены NAT44 и RFC1918/off-WAN guard, MASQUERADE только для пула, forward_private,
порядок межпрофильных DROP/permit, MSS и ошибки backend. Владение точными правилами
регистрируется до изменения; неудачная очистка сохраняет записи для повторной попытки.
Setup и rollback/cleanup имеют отдельные общие бюджеты по 15 секунд. Ядерные файловые
I/O не становятся принудительно прерываемыми от проверки срока.

Gateway разобран по TUN-поколению, семье, подсети и списку ранее использованных WAN:
чужой или неподтверждённый owner не допускается, cleanup не выбирает цели по новому
конфигу. Проверены порядок kill-switch, guard при частичном exit setup, независимые
семьи cleanup и release sysctl. Общий журнал sysctl сохраняет original до записи,
сверяет PID/start-time, namespace cookie и исходный interface witness, подтверждает
запись readback и не перезаписывает изменённое администратором значение при restore.
Мёртвые production helpers не подтверждены; рабочие compatibility/recovery пути сохранены.

## Q17-F001, P2: небезопасная старая обвязка gateway

Старый test_gateway_nat.py копировал исполняемый файл в лабу, завершал процессы по
substring конфига, удалял правила по substring tag и общий known_hosts. Ошибки команд
не всегда влияли на итог. Он заменён запуском с обязательными binary SHA, output и
read-only package directory, свежими NET/mount/PID и собственными каталогами состояния.
Ошибки и host-state mismatch завершают проверку неуспешно. Рабочие службы не заменяются.
Проверки доверия клиентских hooks остаются отдельной областью Q32; новый runner их
не выдаёт за выполненные. Общая packet fixture расширена опцией --ipv4-gateway.

## Подтверждения

| Проверка | Результат и основание |
|---|---|
| Текущий Linux-код | 2374 unit PASS, 60 ignored из Q16; среди них 319 NAT/cleanup/journal/sysctl/gateway. Это сохранённый прогон, не новый запуск. |
| Актуальный кандидат | 4 свежих изолированных сценария, 228 checks PASS: route-policy и три pairwise gateway backend-сочетания. |
| Gateway LAN | Настоящий LAN peer, MASQUERADE в TUN и далее WAN, приватная сеть сервера; explicit permits при DROP policy, MSS правила, forwarding readback. |
| forward_private | Реальный IPv4 UDP-туннель сохраняет source 10.87.0.2; транзит работает при FORWARD DROP. |
| Stop | Gateway восстанавливает foreign rules, routes, ip_forward и rp_filter; остановленный gateway больше не пересылает LAN. Worker восстанавливает сеть и удаляет socket/journal. |
| Прежняя матрица | 204 packet checks на четырёх backend и 416 firewalld multiprofile checks сохранены с исходными SHA/датами; 979 raw-файлов сверены. |

51 исходник NAT/gateway/sysctl и общих адаптеров совпадает с evidence 2 октября.
Изменённые с тех пор auth/protocol/server inputs не объявлены прежним снимком:
их покрывают актуальная Q16-квалификация и свежие packet-прогоны. Namespace/target
native crash/cookie evidence используется только в его области; общий storage/cookie
рефакторинг проверен отдельно. Все ignored tests не объявляются запущенными.

Две ошибки подготовки новой fixture сохранены: отсутствующий обратный маршрут нового
IPv4-пула и сравнение времени/счётчиков iptables-save. После исправления финальные
сценарии PASS. Raw before/after сохранены полностью; сравнение исключает только
время/счётчики, сохраняет policies, selectors и порядок правил.

## Воспроизведение и границы

scripts/test_gateway_nat.py требует --qeli, --sha256, --output и --package; backend
задаются --ipv4/--ipv6. Пароль читается только из QELI_LAB_PASS. Артефакты:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q17-network-20261004.

Q25-A125 остаётся принятым ограничением: перед rename/delete/recreate WAN нужно
остановить профиль и подтвердить cleanup, затем изменить interface и запустить снова.
BPF не внедряется. Gateway/exit registry находится в памяти: clean stop подтверждён,
новый автоматический replay gateway NAT после SIGKILL не заявляется. Потерянный
sysctl interface witness требует подтверждённого ручного recovery. Произвольные
root rewrites и автоматическая смена backend не сертифицированы.

Свежая gateway матрица pairwise: nft/legacy, legacy/nft, nft/nft. UDP payload передан
через настоящий TCP/UDP carrier; это не новый TCP MSS или throughput-бенчмарк.
MSS правила подтверждены, старое PMTU evidence сохраняет собственную область.
Rust/ABI/native-библиотеки не изменены, поэтому сборка Q16 не повторялась.
Mac/router/Windows VM runtime исключены пользователем. Рабочие службы и файлы
исполнения сохранены. Следующий раздел — Q18: IPv6/NDP.
