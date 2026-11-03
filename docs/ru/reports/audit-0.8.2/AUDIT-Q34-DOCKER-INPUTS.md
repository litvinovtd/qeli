# Q34: неизменяемые Docker frontend и APT inputs

<!-- normative-sync: q34-docker-inputs-v1 -->

Дата: 9 октября 2026.

## F481 / Q34-F035

При одинаковом source commit Dockerfile загружал изменяемый frontend
`docker/dockerfile:1`, а runtime packages получал из текущих Debian mirrors.
Два регрессионных теста отказали на точном прежнем Dockerfile. Теперь frontend
закреплён по SHA256, а единственные APT sources — Debian и Debian-security snapshot
`20261008T000000Z`. Перед COPY политики удаляются inherited `.list`/`.sources`.
Все три suites — bookworm, bookworm-updates и bookworm-security — используют один
срез времени. Политика поставляется из `release/docker/debian.sources`.

Frontend digest `4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e`
совпадает с frontend предыдущей полной amd64 сборки. Свежие official registry
index, amd64 manifest и config проверены по SHA; index содержит amd64, arm64 и
arm/v7. Это проверка идентичности, а не новая execution квалификация frontend.
[Docker frontend documentation](https://docs.docker.com/build/buildkit/frontend/).

Snapshot доступен как APT repository. HTTP нужен для bootstrap slim image без CA;
подписи и package hashes обязательны, `Signed-By` указывает Debian archive keyring.
Отключена только проверка срока исторических metadata в этих двух source stanzas,
без `trusted=yes`, allow-unauthenticated или глобального insecure bypass.
Фиксация даты фиксирует security updates: дату необходимо обновлять явно с
повторной проверкой. [Debian snapshot](https://snapshot.debian.org/).

## Реальная проверка APT

Official Debian base index, amd64 manifest, config и единственный rootfs layer
проверены по digest pinned image. В отдельном chroot/mount/PID namespace на .11
использованы точные base bytes, очистка sources и COPY новой политики; host APT
не запускался. Ограничение — 512 MiB и один CPU, без Docker daemon.

APT 2.6.1 проверил подписи трёх независимо загруженных InRelease. Actual update
и install всех 13 runtime packages завершились: 62 новых packages, итоговый
inventory — 150. Проверены 13 команд, apt-get check и повторная simulation с
нулевыми установками/обновлениями. Все три полученных APT InRelease побайтно
совпадают с независимой HTTPS загрузкой official snapshot. Один package остаётся
not upgraded: это scoped runtime install, не full-upgrade или vulnerability audit.

Три изменённых подписанных тела отклонены gpgv; actual APT file repository
с подменённым InRelease отказан с BADSIG и exit100. Эта проверка не зависит
от сетевого сервера. Все 66 связанных методов проходят: 21 release-tag/workflow,
7 Docker ref, 38 native recipe. Два новых метода выявляют прежние незакреплённые
inputs и проходят с окончательным source.

## Сохранение стенда и границы

Original service PID777/845, installed CLI SHA, network/firewall/resolver и
AppArmor snapshots совпали. Own unit остановлена. Full installed rootfs, sources,
fixtures и logs сохранены в recoverable archive; локальный SHA и критические
файлы проверены до удаления только own root/archive с /proc/mount guards.
Public base layer сохранён отдельно и исключён из дублирующего backup; proc/dev
mounts временные. Установка host packages и загрузка AppArmor profile отсутствуют.

Initial harness failures сохранены: CRLF shell, collected transient unit,
отсутствующий /dev/null в повторной отрицательной fixture и повторное создание
каталога. Первый backup verifier также ожидал regular file вместо штатного
symlink ip; цепочка symlink и SHA настоящего target проверены. Исправлена только
собственная обвязка; failures не переписаны в PASS.

Нет новой полной Docker compiler/image сборки, ARM installation, VPN runtime,
A/B reproducibility или hosted Actions/signing/publication. Предыдущая сборка
остаётся доказательством своего source/date; новая политика квалифицирована
реальным amd64 APT и source contracts. Native digest и 14 artifact SHA неизменны.
Matching third-party source, OpenWrt SDK source cut, MicroCom exact source,
F459 braces и остальные ранее открытые границы остаются OPEN.
Q34 IN_PROGRESS, 30/37 DONE (81,1%), 7 осталось. Q29 SIGKILL FAIL/ENONET,
Q30/Q31, D06 ACCEPTED_LIMITATION и USER_EXCLUDED сохранены.
LOCAL_DEV_COMMIT; NO_PUSH_DEPLOY_RELEASE.

## Evidence

`q34-docker-inputs-20261009`: SEALED 92 files / 101517131 bytes; manifest SHA256 `52fc5c0767d1b726f2127eb18c491eb2de3fe48d97b62748a7bab1cf8e9d0e9e`.
