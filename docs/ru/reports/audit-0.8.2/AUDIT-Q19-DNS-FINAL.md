# Q19: серверный и клиентский DNS

<!-- normative-sync: audit-q19-final-v1 -->

**DONE/PASS. План: 19/37 (51,4%), осталось 18.** 4 октября 2026.
Кандидат Linux: `4c70a6595b6f5a9a9b2809c7975f12212895347fdabc9e05d4135f5a69a8a2f3`.
Production Rust не изменялся после Q18; это новый прогон DNS на том же бинарном SHA.
[Evidence](../../../../release/certification/evidence/q19-dns-20261004.json).

## Результат разбора

Новых подтверждённых production-дефектов DNS не найдено. Закрыт **Q19-V001** —
пробел runtime-проверки: прежняя tunnel DNS fixture посылала только UDP-запросы и
имела UDP-only upstream. Теперь она проверяет TCP listeners, TC → TCP retry и
принудительный TCP upstream через настоящий VPN. Это расширение тестов, не новая
настройка продукта. Конфиги остаются INI; служебные JSON API/evidence сохраняются.

| Слой | Разобранный контракт |
|---|---|
| Конфиг | UDP/TCP upstream; неизвестный протокол, в том числе TLS/DoT, отвергается. Не более 16 upstream, 10000 cache/blocklist entries, timeout до 300 секунд. IPv4/IPv6 listeners и listener port независимы от IPv4 NAT. |
| DNS wire | Ограниченный name/RR walker; backward compression pointers, expanded name ≤255, framing/RDATA для распространённых типов; malformed packets и multiple questions не идут в обычный кеш. QR/txid/question/upstream socket должны совпадать. |
| Upstream | Новый случайный txid для unsigned exchange; общий query deadline делится между upstream. UDP TC/exact buffer fill вызывает TCP retry с оставшимся сроком. TCP connect/write/prefix/body имеют общий deadline. Ошибки/неполный TCP answer допускают следующий upstream. |
| Кеш | Ключ включает query без txid; ответ восстанавливает txid и уменьшает TTL. Минимальный TTL всех RR, отрицательный SOA bound, high-bit TTL=0. До 16 MiB query+response payload на профиль плюс предел entries; expired/pressure eviction сохраняет учёт. |
| EDNS/подписи | OPT/TLV проверяется; BADVERS/FORMERR/NXDOMAIN/TC сохраняют корректную metadata. Nonempty options и TSIG/SIG(0) обходят обычный кеш. Подписанный oversized UDP answer отбрасывается; нужен TCP/достаточный EDNS размер. DNSSEC signatures не проверяются самим proxy. |
| Listener lifecycle | До admission bind обоих UDP/TCP сокетов; до spawn берётся permit. По 512 UDP tasks/TCP connections на listener; persistent TCP читает отдельные length-prefixed frames. Idle/body/write ограничены сроками; ProfileTasks владеет задачами и их отменой. |
| Client NetworkPlan | Приоритет config/push/fallback общий для клиентов; DNS host routes защищены от exclusions и в full, и в split. Ошибка DNS apply не получает ACK/Connected. Linux умеет custom port через SetLinkDNSEx; mobile/desktop adapters отвергают неподдерживаемый port вместо молчаливой потери. |
| Linux resolver | Только проверенный stub/resolved; per-link ifindex и исходный TUN descriptor, namespace cookie, bus AUTH GUID/GetId и unique service owner. Lease сохраняется до первой записи; setup/cleanup имеют отдельные общие сроки по 15 секунд. Legacy global resolv.conf snapshots сохраняются для администратора, автоматически не восстанавливаются. |
| NSS/файлы | Четыре read-only resolver workers; timeout/cancel не освобождает slot до завершения libc/NSS. Resolver files: regular file ≤64 KiB, стабильный descriptor stamp, до 64 адресов, NUL/invalid/scoped entries не расширяют firewall allowances. |

Мёртвые production helpers не подтверждены. Test-only wrappers отделены cfg(test);
compatibility/recovery пути нужны для fail-closed отказа и сохранения старых markers.
Android VpnService применяет канонический DNS до успешного NetworkPlan ACK. Windows
учитывает частично применённые семьи; macOS использует журнал physical-service DNS.
Их реальная OS/device квалификация сохраняет отдельную область, не подменяется Linux.

## Проверки

**105 свежих checks PASS:** три сценария dual-stack full TCP tunnel — UDP IPv4 upstream,
UDP IPv6 upstream, forced TCP IPv6 upstream. В каждом реальные systemd-resolved stub,
A/AAAA на tunnel DNS по обеим семьям, downstream TCP, stop/reconnect, SIGKILL и markers.
В двух UDP upstream случаях log подтверждает по два TC и два TCP retry. В forced TCP
случае все 13 upstream exchanges — TCP и ни одного UDP. Полный host snapshot восстановлен.

Q18 full Linux run сохранён: **2376 unit PASS, 60 ignored**, в том числе 52 resolver,
7 listener, 23 client DNS, 37 DNS lease, 7 legacy DNS и 16 system-resolver tests.
Это сохранённый прогон того же production source, не повторный запуск. Q18 Clippy,
release и четыре native A/B target сохранены; provenance соответствует текущим inputs.
Изменение трёх runtime fixtures не требует повторной Rust/native сборки.

Q18 four-profile matrix дополнительно покрывает DNS UDP/TCP A/AAAA на IPv4/IPv6,
custom listener ports и manual/off/route/nat66 coexistence. Для отказов NSS, FIFO/slow/
oversized/drift/scoped resolver files и service/PID/network mismatch сохранены
предыдущие результаты с исходными SHA/датами. Сверены 32 неизменённых релевантных
исходника, 61 raw file и 9 архивов. Более старые manifests совпадают лишь по части
общих зависимостей; их изменённые/отсутствующие entries записаны отдельно, не выданы
за точную квалификацию всего текущего дерева. Текущую композицию подтверждают Linux
unit и свежий real resolved/tunnel/SIGKILL прогон. Baseline FAIL из старых repro сохранены.

Локально: 3 DNS helper и 8 matrix contract tests PASS, docs/panel/certification PASS.
Воспроизведение: scripts/audit_release_matrix_lab.py с --cases linux.dns.ipv4-ipv6,
обязательными candidate path/SHA и новым output; пароль из QELI_LAB_PASS. Raw:
C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260924/q19-dns-20261004.

## Границы

Прогон использует настоящее ядро Linux, private NET/mount/PID и настоящий resolved.
Это не новый Android installed-app или physical Wi-Fi/cellular DNS leak тест.
[Предыдущий Android runtime](AUDIT-Q25-ANDROID-NETWORK-IDENTITY.md) сохраняет свой APK,
дату и Private DNS socket caveat. Mac/router/Windows VM runtime исключён пользователем;
полный Android/desktop аудит остаётся в соответствующих разделах плана.

NSS нельзя принудительно остановить: четыре застрявших вызова удерживают четыре slot
и новые lookup отказывают по deadline. Проверка контекста не атомарна против arbitrary
root service move. DNS proxy не выполняет полную DNSSEC/RRset coherence validation;
unknown RDATA остаётся opaque, EDNS options bypass cache снижает hit rate. Нет нового
бенчмарка или обещания throughput. Q25-A125 WAN replacement limitation сохранена;
60 ignored tests не объявлены глобально выполненными. Далее Q20 DHCP/leases.
