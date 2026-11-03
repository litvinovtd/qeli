# Q21: TUN/TAP, IP и MTU/PMTU

<!-- normative-sync: audit-q21-final-v1 -->

**DONE/PASS. План: 21/37 (56,8%), осталось 16.** 4 октября 2026.
[Evidence](../../../../release/certification/evidence/q21-packets-20261004.json).
Linux candidate: `36a0e491f9437773b73b3e29f9c7ab0b7f624142e782dd78777f0c6168e6cef1`.

## Результат и слои

Новых ошибок production-кода в этом проходе не подтверждено. Семь новых
граничных тестов и захват реального carrier закрывают пробелы проверки.
Ядро и входные файлы native-сборки не изменились после квалификации Q20.

| Слой | Проверенный контракт и evidence |
|---|---|
| Создание TUN | Первый multiqueue-дескриптор создаёт интерфейс эксклюзивно. Дополнительные очереди привязаны к его фактическому имени/index; attach не создаёт незаметно замену. Неизвестные flags и VNET_HDR отклоняются. Текущий полный набор ядра содержит 28 open/admission-проверок. |
| Владение и namespace | Исходные fd удерживаются до завершения workers и очистки сети; их закрытие не удаляет чужую persistent-замену с тем же именем. Удерживаемый namespace и identity fd не позволяют lookup хоста разрешить другой link. Сохранены восемь выполненных ранее privileged Linux-тестов с исходными ELF/датой: production-файлы совпадают, изменение синтаксиса C-string в одном тесте доказано эквивалентным. |
| Адреса AUTH | Прежние TUN host-prefix проверки сохраняют область matrix evidence. Свежий настоящий TAP получает IPv4 /24 и IPv6 /64 через AUTH, передаёт трафик обеих семей и удаляется при clean stop. Это native Linux, не установленное мобильное приложение. |
| TAP control | ARP/NDP отвечают только в поддерживаемой области владения адресом/prefix. На DAD proxy не отвечает. RA: router lifetime=0, PIO L=1/A=0; автоматического default-router/SLAAC нет. Unit-тесты проверяют EtherType/length mismatch, padding, multicast MAC mapping, ARP/NDP/RS и DAD; реальные NDP/RA и checksum проходят отдельный probe. |
| IP metadata | Объявленная длина IPv4/IPv6 должна совпадать с L3 record. IHL/flags/fragment bounds IPv4 и extension chain/alignment IPv6 ограничены. У nonfirst fragment не появляются выдуманные transport ports. Этот parser не заменяет полный ingress checksum/firewall: source ownership и IP stack хоста проверяются отдельно. |
| ICMP и IPv4 fragmentation | Для DF формируется ограниченный Fragmentation Needed; non-DF делится по выровненным offsets с сохранением ID, payload и нужных copied options. IPv6 PTB укладывается в 1280 байт и объявляет MTU не ниже 1280. Невалидные endpoints и рекурсия ICMP errors отклоняются. Sweep из 17 сочетаний проверяет MTU, offsets/MF и точное восстановление payload. |
| Зашифрованный DATA_FRAG | HMAC проверяется до выделения состояния. На peer: максимум 64 fragments, 32 records, 512 KiB buffered payload; encrypted record не более 16645 байт. Overlap/gap, несогласованные metadata и конфликтующие duplicates отклоняются; reorder собирается точно. Новые тесты проверяют count/byte exhaustion и освобождение ресурса, поток неверных MAC, верхние границы и повторное использование record ID. |
| Handshake fragments и PMTU | Старый control-reassembler остаётся отдельным ограниченным wire format. Shared vectors, shape/size parser и wrapper budgets проходят тесты. PMTU ACK сверяет новый случайный 128-bit token и точный размер; reverse certification также сверяет peer/path epoch. Новый путь начинает с консервативного budget. Полный набор ядра сохраняет проверки неверного/устаревшего пути и concurrent egress. |
| Мёртвый код | Рассмотренные helpers используются реальными packet/TAP/transport путями. Два unused-item warning в маленьком audit crate возникают из-за отсутствия всего клиента и не указывают на production dead code. Квалифицированный полный all-target Clippy остаётся чистым. |

## Выполненные проверки

- **61 packet test PASS**, включая семь новых свойств. В приватный небольшой
  offline Cargo crate импортированы реальные production-модули IP/ICMP,
  DATA_FRAG/control fragments/TAP. Нужные constants извлечены из исходников
  дословно; все входы совпадают с текущим Linux build inventory. Детерминированный
  corpus из 8192 buffers проверяет untrusted metadata; это не новый ASan или
  длительный fuzz campaign.
- **70 проверок PASS в трёх итоговых Linux-сценариях**: MTU/PMTU/PTB 38,
  IPv6 TAP/NDP/RA 15, dual-stack TAP 17. При auto внутренние 1400 байт проходят
  outer MTU 1280 через DATA_FRAG; при explicit inner MTU 1280 oversized downlink
  получает реальный PTB, после уменьшения до объявленного размера связь работает.
- Два реальных carrier PCAP разобраны независимо от observer: есть оба
  направления, нет IPv4 MF/nonzero-offset fragments и пакетов выше link MTU
  1280. Это дополняет application logs; сохранённый захват содержит encrypted
  carrier-трафик приватных namespaces.
- **Три portable TAP-probe test PASS.** Прежние **2383 full Linux unit PASS/60
  ignored**, strict Clippy, release и четыре native A/B использованы после сверки
  всех 347 build inputs. Их не запускали заново и не выдали за свежие execution.
  Native provenance по-прежнему совпадает.

Оба сервиса лабы, активные executable hashes и рабочий source-tree release
сохранены. Сетевые прогоны восстановили адреса, routes, firewall, resolver,
listeners и named namespaces. Нового benchmark и замены рабочих бинарников нет.

## Принятые границы

TAP — L3 facade; полноценный Ethernet/VLAN bridge и IPv6 jumbograms не
поддерживаются. Новых config values нет; конфиги остаются INI.

Carrier PMTU ACK обрабатывается до PacketCodec decryption. Случайный challenge
защищает от слепой подделки, но не скрывается от наблюдателя на пути. Kernel ICMP
PMTU reduction и враждебный путь могут нарушить доступность. Общая неуязвимость
к spoofed PTB и новый raw ICMP ingress filter не заявляются. Генерация ICMP,
malformed probe parser, stale-path rejection и настоящий малый MTU проверены
на соответствующих слоях.

DATA_FRAG timeout — пять секунд от первого приёма, проверка выполняется при
последующих push. Idle entries могут остаться до следующего push/teardown,
не выходя за фиксированные caps. Повторное использование record ID допустимо;
после сборки обязательны authenticated counter и replay checks PacketCodec.

PCAP относится к проверенному outer IPv4 UDP QUIC, а не любому Internet path.
Прежние platform/backend rows сохраняют реальные даты и artifacts. Исключённые
пользователем Mac, router и Windows VM runtime, 60 ignored tests и принятое
ограничение Q25-A125 для WAN same-name replacement сохраняют свою область.

Далее: **Q22 transport core, FFI/JNI и память**.
