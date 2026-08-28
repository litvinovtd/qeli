#!/usr/bin/env python3
"""Build static RU/EN pages, SEO metadata, breadcrumbs and sitemap for qeli.ru."""

from __future__ import annotations

import html as html_lib
import json
import re
from html.parser import HTMLParser
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SITE = REPO / "site"
BASE = "https://qeli.ru"
UPDATED = "2026-08-27"
HEADER_START = "<!-- shared-header:start -->"
HEADER_END = "<!-- shared-header:end -->"
FOOTER_START = "<!-- shared-footer:start -->"
FOOTER_END = "<!-- shared-footer:end -->"
BREAD_START = "<!-- breadcrumbs:start -->"
BREAD_END = "<!-- breadcrumbs:end -->"


PAGES = {
    "/": {
        "title": "meta.title", "desc": "meta.desc", "label": ("Главная", "Home"),
        "crumbs": [], "schema": "home",
    },
    "/tech/": {
        "title": "meta.titleTech", "desc": "meta.descTech", "label": ("Технологии", "Technology"),
        "crumbs": [], "schema": "TechArticle",
    },
    "/install/": {
        "title": "meta.titleGuide", "desc": "meta.descGuide", "label": ("Установка", "Installation"),
        "crumbs": [], "schema": "HowTo",
        "steps": [
            ("Подготовить Linux-сервер", "Prepare a Linux server"),
            ("Установить Qeli", "Install Qeli"),
            ("Проверить конфигурацию и службу", "Validate the configuration and service"),
            ("Получить ключ сервера", "Get the server identity key"),
            ("Создать пользователя", "Create a user"),
            ("Импортировать qeli:// на клиенте", "Import qeli:// on a client"),
        ],
    },
    "/install/debian/": {
        "title": "installDebian.metaTitle", "desc": "installDebian.metaDesc", "label": ("Debian VPS", "Debian VPS"),
        "crumbs": [("/install/", "Установка", "Installation")], "schema": "HowTo",
        "steps": [
            ("Подготовить Debian VPS", "Prepare a Debian VPS"),
            ("Скачать и проверить установщик", "Download and review the installer"),
            ("Запустить установку", "Run the installation"),
            ("Проверить systemd и ссылки qeli://", "Verify systemd and qeli:// links"),
        ],
    },
    "/install/docker/": {
        "title": "installDocker.metaTitle", "desc": "installDocker.metaDesc", "label": ("Docker", "Docker"),
        "crumbs": [("/install/", "Установка", "Installation")], "schema": "HowTo",
        "steps": [
            ("Проверить Docker и TUN", "Check Docker and TUN"),
            ("Загрузить образ и Compose-файл", "Pull the image and get the Compose file"),
            ("Запустить серверный контейнер", "Start the server container"),
            ("Создать пользователя и проверить журнал", "Create a user and verify the logs"),
        ],
    },
    "/install/mikrotik/": {
        "title": "installMikrotik.metaTitle", "desc": "installMikrotik.metaDesc", "label": ("MikroTik", "MikroTik"),
        "crumbs": [("/install/", "Установка", "Installation")], "schema": "HowTo",
        "steps": [
            ("Проверить архитектуру RouterOS", "Check the RouterOS architecture"),
            ("Включить контейнерный режим", "Enable container mode"),
            ("Добавить veth, mounts и контейнер", "Add the veth, mounts and container"),
            ("Настроить маршруты и проверить TUN", "Configure routes and check TUN"),
        ],
    },
    "/install/clients/": {
        "title": "installClients.metaTitle", "desc": "installClients.metaDesc", "label": ("Клиенты", "Clients"),
        "crumbs": [("/install/", "Установка", "Installation")], "schema": "HowTo",
        "steps": [
            ("Выбрать официальный файл", "Choose the official file"),
            ("Проверить SHA-256", "Verify SHA-256"),
            ("Установить приложение", "Install the application"),
            ("Импортировать qeli:// и проверить подключение", "Import qeli:// and test the connection"),
        ],
    },
    "/docs/": {
        "title": "docsHub.metaTitle", "desc": "docsHub.metaDesc", "label": ("Документация", "Documentation"),
        "crumbs": [], "schema": "CollectionPage",
    },
    "/docs/config/": {
        "title": "docsConfig.metaTitle", "desc": "docsConfig.metaDesc", "label": ("Конфигурация", "Configuration"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/docs/scenarios/": {
        "title": "docsScenarios.metaTitle", "desc": "docsScenarios.metaDesc", "label": ("Готовые сценарии", "Ready-made scenarios"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/docs/networking/": {
        "title": "docsLearning.metaTitle", "desc": "docsLearning.metaDesc", "label": ("Сетевые основы", "Networking basics"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/docs/transports/": {
        "title": "docsTransport.metaTitle", "desc": "docsTransport.metaDesc", "label": ("Транспортные режимы", "Transport modes"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/docs/routing/": {
        "title": "docsRouting.metaTitle", "desc": "docsRouting.metaDesc", "label": ("Маршрутизация", "Routing"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/docs/exit-node/": {
        "title": "docsExit.metaTitle", "desc": "docsExit.metaDesc", "label": ("Exit node", "Exit node"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/docs/per-app/": {
        "title": "docsPerApp.metaTitle", "desc": "docsPerApp.metaDesc", "label": ("Маршрутизация приложений", "Per-app routing"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/docs/external-tun/": {
        "title": "docsTun.metaTitle", "desc": "docsTun.metaDesc", "label": ("Внешний TUN", "External TUN"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/docs/troubleshooting/": {
        "title": "docsTrouble.metaTitle", "desc": "docsTrouble.metaDesc", "label": ("Диагностика", "Troubleshooting"),
        "crumbs": [("/docs/", "Документация", "Documentation")], "schema": "TechArticle",
    },
    "/changelog/": {
        "title": "changelog.metaTitle", "desc": "changelog.metaDesc", "label": ("История версий", "Changelog"),
        "crumbs": [], "schema": "CollectionPage",
    },
    "/support/": {
        "title": "support.title", "desc": "support.desc", "label": ("Поддержать разработку", "Support development"),
        "crumbs": [], "schema": "WebPage",
    },
    "/privacy/": {
        "title": "privacy.title", "desc": "privacy.desc", "label": ("Конфиденциальность", "Privacy"),
        "crumbs": [], "schema": "WebPage",
    },
}


VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

# Some code examples intentionally keep comments outside data-i18n nodes so the
# commands remain easy to copy. Translate those literal fragments while producing
# the static English tree.
RAW_ENGLISH = {
    "# пользователь, под которым подключается exit-клиент": "# user used by the exit client",
    "# обычный пользователь-потребитель; route=0/0 здесь не нужен": "# regular consumer user; route=0/0 is not needed here",
    "# должно совпадать с префиксом tunnel pool на сервере": "# must match the server tunnel-pool prefix",
    "# split-tunnel: только TUN-пул, server-push и include": "# split tunnel: TUN pool, server push and include only",
    "# full-tunnel: весь остальной трафик тоже через Qeli": "# full tunnel: route all remaining traffic through Qeli too",
    "# нужно для выхода full-tunnel в интернет": "# required for full-tunnel internet egress",
    "# WAN определяется автоматически; при необходимости задайте явно": "# WAN is detected automatically; set it explicitly when needed",
    "# получат все пользователи профиля": "# sent to every user of the profile",
    "# получит только этот пользователь": "# sent to this user only",
    " или префикс ": " or prefix ",
    "# сеть находится ЗА branch-a: входящий iroute на сервере": "# network behind branch-a: inbound iroute on the server",
    "# сам branch-a может ходить только сюда": "# branch-a itself may access only this destination",
    "server.conf + client.conf шлюза": "server.conf + gateway client.conf",
    "# сервер, [profile:main]": "# server, [profile:main]",
    "# каждый Linux-шлюз, [qeli]": "# each Linux gateway, [qeli]",
    "+ уникальные TUN/pool": "+ unique TUN/pool",
    "+ ручной выбор": "+ manual selection",
    ", режим DNS клиента": ", client DNS mode",
    " или <code>allowed_origins</code>": " or <code>allowed_origins</code>",
    ", trusted proxy, срез префикса": ", trusted proxy, prefix stripping",
    "# key клиента должен совпасть с профилем, к которому он подключается": "# the client key must match the profile it connects to",
    "# добавьте:": "# add:",
    "# 1. скачать скрипт": "# 1. download the script",
    "# 2. прочитать его — и только потом запускать от root": "# 2. review it, then run it as root",
    "# готовый мульти-arch образ из GHCR (собирать не нужно):": "# prebuilt multi-arch image from GHCR (no build required):",
    "# имя, на которое ссылается compose": "# name referenced by Compose",
    "# либо собрать самому: docker buildx build -f release/docker/Dockerfile -t qeli:latest --load .": "# or build it: docker buildx build -f release/docker/Dockerfile -t qeli:latest --load .",
    "# скачать compose-файл (или склонировать репозиторий):": "# download the Compose file (or clone the repository):",
    "# запуск сервера:": "# start the server:",
    "# Linux / macOS: SHA256SUMS и нужный файл должны лежать рядом": "# Linux / macOS: keep SHA256SUMS next to the downloaded file",
    "# Windows PowerShell: сравните результат со строкой в SHA256SUMS": "# Windows PowerShell: compare the result with SHA256SUMS",
    "# зафиксировать именно опубликованную версию": "# pin the published version",
    "# jemalloc используется серверной релизной сборкой и удерживает RSS под churn": "# release server builds use jemalloc to keep RSS stable under churn",
    "# служба, пользователь и каталоги — при установке из .deb это делает пакет,": "# the .deb creates the service, user and directories;",
    "# при ручной сборке создайте их сами:": "# create them yourself for a manual build:",
    "# разрешить непривилегированной панели перезапускать только qeli.service": "# allow the unprivileged panel to restart qeli.service only",
    "# reality-tls и H-1 требуют настоящий закреплённый ключ клиента;": "# reality-tls and H-1 require a real pinned client key;",
    "# true дополнительно отклоняет непиненных клиентов до AUTH и не раскрывает": "# true also rejects unpinned clients before AUTH and does not expose",
    "# identity-ключ сетевому сканеру.": "# the identity key to a network scanner.",
    "# reality-tls использует параметры reality_proxy ниже": "# reality-tls uses the reality_proxy settings below",
    "# выпуск клиентов в интернет": "# client internet egress",
    "# резолвер в туннеле": "# resolver inside the tunnel",
    "# reality-tls: туннель внутри настоящего TLS 1.3": "# reality-tls: tunnel inside real TLS 1.3",
    "# server_name должен совпадать с target — именно он попадёт в ссылку qeli://": "# server_name must match target and is included in the qeli:// link",
    "# чей сертификат заимствуем": "# certificate source",
    "# токен клиента (reality_sid)": "# client token (reality_sid)",
    "# настоящий TLS (handrolled по умолч.)": "# real TLS (handrolled by default)",
    "# смотреть логи": "# follow logs",
    "# либо вручную для проверки (foreground):": "# or run manually in the foreground:",
    "# → в поле key у клиента": "# → client key field",
    "# сгенерирован, печатается один раз": "# generated and printed once",
    "# свой пароль без утечки в argv и историю shell:": "# provide a password without leaking it into argv or shell history:",
    "# применить новых пользователей (без разрыва активных сессий)": "# apply new users without dropping active sessions",
    "# добавляет qeli add-client alice": "# added by qeli add-client alice",
    "# одновременных устройств (0 = без лимита)": "# simultaneous devices (0 = unlimited)",
    "# фиксированный IP в туннеле (из pool.cidr)": "# fixed tunnel IP (from pool.cidr)",
    "# доступ только к этим профилям": "# access to these profiles only",
    "# куда можно ходить (ACL); пусто = без ограничений": "# allowed destinations (ACL); empty = unrestricted",
    "# лимит скорости, Мбит/с (0 = без лимита)": "# speed limit in Mbit/s (0 = unlimited)",
    "# наследовать лимиты из [group:premium]": "# inherit limits from [group:premium]",
    "# доп. маршрут этому пользователю": "# additional route for this user",
    "# только для старого пользователя без password_enc: пароль будет заменён": "# legacy user without password_enc only: the password will be replaced",
    "# ключ из show-identity": "# key from show-identity",
    "# short_id из профиля сервера": "# short_id from the server profile",
    "# как у reality-цели": "# must match the REALITY target",
    "# локальные опции (в ссылку qeli:// не входят).": "# local options (not carried in qeli://).",
    "# ВАЖНО: комментарий — только отдельной строкой. Всё, что стоит после «=»,": "# IMPORTANT: put comments on separate lines. Everything after '='",
    "# попадает в значение целиком, вместе с «# ...».": "# becomes part of the value, including '# ...'.",
    "# авто-подбор MTU (важно на LTE/CGNAT); &gt;0 = вручную": "# automatic MTU selection (important on LTE/CGNAT); &gt;0 = manual",
    "# полный туннель; false = split-tunnel": "# full tunnel; false = split tunnel",
    "# заворачивать и приватные подсети сервера": "# also route the server's private subnets",
    "# эти подсети — мимо туннеля": "# bypass the tunnel for these subnets",
    "# блокировать выход, пока туннель не поднят (Linux)": "# block egress until the tunnel is up (Linux)",
    "# держать адаптер и маршруты между реконнектами (Win/macOS)": "# keep the adapter and routes between reconnects (Windows/macOS)",
    "# авто-подключение при старте панели/супервизора": "# auto-connect when the panel/supervisor starts",
    "# настоящий TLS 1.3 — TCP :443": "# real TLS 1.3 — TCP :443",
    "# TLS-подобный хендшейк — TCP :8443": "# TLS-shaped handshake — TCP :8443",
    "# ChaCha20-обфускация — TCP :8444": "# ChaCha20 obfuscation — TCP :8444",
    "= смените-меня": "= change-me",
    "# fake-tls + QUIC поверх UDP — UDP :8449": "# fake-tls + QUIC over UDP — UDP :8449",
    "# MASQUERADE клиентов в интернет": "# masquerade clients for internet egress",
    "# полный туннель включается НА КЛИЕНТЕ: по умолчанию gateway = false (split-tunnel)": "# full tunnel is enabled ON THE CLIENT; gateway = false (split tunnel) by default",
    "# опционально: не выпускать трафик мимо туннеля, пока он не поднят (Linux)": "# optional: block traffic outside the tunnel until it is up (Linux)",
    "# маршрутизация без подмены исходных адресов": "# routing without source-address translation",
    "# подсеть за сервером": "# subnet behind the server",
    "# LAN ЗА этим клиентом — аналог iroute в OpenVPN (ключевая строка)": "# LAN BEHIND this client — the OpenVPN iroute equivalent (key line)",
    "# фиксированный IP в туннеле — удобно, но не обязательно": "# fixed tunnel IP — convenient but optional",
    "# site-to-site идёт БЕЗ NAT — реальные адреса сохраняются": "# site-to-site runs WITHOUT NAT, preserving real addresses",
    "# транзит туннель ↔ сети, без MASQUERADE": "# tunnel ↔ network forwarding without MASQUERADE",
    "# обратный маршрут к сети за сервером — пушится клиентам": "# return route to the server-side LAN, pushed to clients",
    "/etc/qeli/client.conf · шлюз площадки A": "/etc/qeli/client.conf · site A gateway",
    "# ip_forward + FORWARD ACCEPT + MSS-clamp, но БЕЗ MASQUERADE —": "# ip_forward + FORWARD ACCEPT + MSS clamp, but WITHOUT MASQUERADE —",
    "# реальные адреса LAN сохраняются": "# real LAN addresses are preserved",
    "# без полного выхода в интернет": "# no full-tunnel internet egress",
    "# только рабочие подсети": "# work subnets only",
    "# split-tunnel — значение по умолчанию: в туннель идут только выданные маршруты": "# split tunnel is the default: only assigned routes use the tunnel",
    "# при желании увести отдельные подсети мимо туннеля": "# optionally bypass the tunnel for selected subnets",
    "# username и password_hash добавит qeli set-web-password": "# qeli set-web-password adds username and password_hash",
    "# затем откройте https://127.0.0.1:8080": "# then open https://127.0.0.1:8080",
    'alt="Приложение Qeli — активное VPN-подключение"': 'alt="Qeli app — active VPN connection"',
    'alt="QR · ЮMoney"': 'alt="QR · YooMoney"',
    'aria-label="Разделы документа"': 'aria-label="Document sections"',
}


class StaticTranslator(HTMLParser):
    def __init__(self, dictionary: dict, lang: str):
        super().__init__(convert_charrefs=False)
        self.dictionary = dictionary
        self.lang = lang
        self.out: list[str] = []
        self.skip_depth = 0
        self.missing: set[str] = set()

    def translated(self, key: str) -> str | None:
        entry = self.dictionary.get(key)
        if not entry:
            self.missing.add(key)
            return None
        return entry.get(self.lang, entry.get("ru"))

    def with_suffix(self, raw: str, attrs: list[tuple[str, str | None]]) -> str:
        amap = dict(attrs)
        if "data-suffix-ru" not in amap:
            return raw
        suffix = amap.get(f"data-suffix-{self.lang}") or amap.get("data-suffix-ru") or ""
        suffix_attr = html_lib.escape(suffix, quote=True)
        if re.search(r"\sdata-suffix=", raw):
            return re.sub(r'(\sdata-suffix=")[^"]*(")', rf'\g<1>{suffix_attr}\2', raw)
        return raw[:-1] + f' data-suffix="{suffix_attr}">'

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.skip_depth:
            if tag.lower() not in VOID:
                self.skip_depth += 1
            return
        raw = self.with_suffix(self.get_starttag_text(), attrs)
        amap = dict(attrs)
        key = amap.get("data-i18n") or amap.get("data-i18n-html")
        if key:
            value = self.translated(key)
            if value is not None:
                self.out.append(raw)
                self.out.append(value)
                if tag.lower() not in VOID:
                    self.skip_depth = 1
                return
        self.out.append(raw)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if not self.skip_depth:
            self.out.append(self.with_suffix(self.get_starttag_text(), attrs))

    def handle_endtag(self, tag: str) -> None:
        if self.skip_depth:
            self.skip_depth -= 1
            if self.skip_depth == 0:
                self.out.append(f"</{tag}>")
            return
        self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self.skip_depth:
            self.out.append(data)

    def handle_entityref(self, name: str) -> None:
        if not self.skip_depth:
            self.out.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if not self.skip_depth:
            self.out.append(f"&#{name};")

    def handle_comment(self, data: str) -> None:
        if not self.skip_depth:
            self.out.append(f"<!--{data}-->")

    def handle_decl(self, decl: str) -> None:
        if not self.skip_depth:
            self.out.append(f"<!{decl}>")

    def handle_pi(self, data: str) -> None:
        if not self.skip_depth:
            self.out.append(f"<?{data}>")

    def unknown_decl(self, data: str) -> None:
        if not self.skip_depth:
            self.out.append(f"<![{data}]>")


def source_file(url_path: str) -> Path:
    return SITE / "index.html" if url_path == "/" else SITE / url_path.strip("/") / "index.html"


def localized_path(url_path: str, lang: str) -> str:
    if lang == "ru":
        return url_path
    return "/en/" if url_path == "/" else "/en" + url_path


def replace_shared(html: str, start: str, end: str, placeholder: str, content: str) -> str:
    block = f"{start}\n{content.strip()}\n{end}"
    pattern = re.escape(start) + r".*?" + re.escape(end)
    if re.search(pattern, html, flags=re.S):
        return re.sub(pattern, lambda _: block, html, flags=re.S)
    if placeholder not in html:
        raise ValueError(f"missing shared component placeholder: {placeholder}")
    return html.replace(placeholder, block, 1)


def strip_generated(html: str) -> str:
    html = re.sub(
        re.escape(BREAD_START) + r".*?" + re.escape(BREAD_END) + r"\s*",
        "", html, flags=re.S,
    )
    html = re.sub(
        r'<script\s+type="application/ld\+json">.*?</script>\s*',
        "", html, flags=re.S | re.I,
    )
    html = re.sub(
        r'<script[^>]+src="/js/(?:components|i18n)\.js"[^>]*></script>\s*',
        "", html, flags=re.I,
    )
    return html


def translate(html: str, dictionary: dict, lang: str) -> tuple[str, set[str]]:
    parser = StaticTranslator(dictionary, lang)
    parser.feed(html)
    parser.close()
    return "".join(parser.out), parser.missing


def replace_meta(html: str, attr: str, name: str, value: str) -> str:
    escaped = html_lib.escape(value, quote=True)
    pattern = rf'(<meta\s+{attr}="{re.escape(name)}"\s+content=")[^"]*("\s*/?>)'
    return re.sub(pattern, rf"\g<1>{escaped}\2", html, count=1, flags=re.I)


def set_head(html: str, title: str, desc: str, url_path: str, lang: str) -> str:
    target_path = localized_path(url_path, lang)
    url = BASE + target_path
    ru_url = BASE + url_path
    en_url = BASE + localized_path(url_path, "en")
    html = re.sub(r'<html\s+lang="[^"]*"', f'<html lang="{lang}"', html, count=1, flags=re.I)
    html = re.sub(r"<title>.*?</title>", f"<title>{html_lib.escape(title)}</title>", html, count=1, flags=re.S | re.I)
    html = replace_meta(html, "name", "description", desc)
    html = replace_meta(html, "property", "og:title", title)
    html = replace_meta(html, "property", "og:description", desc)
    html = replace_meta(html, "property", "og:url", url)
    html = replace_meta(html, "property", "og:locale", "en_US" if lang == "en" else "ru_RU")
    html = replace_meta(html, "property", "og:locale:alternate", "ru_RU" if lang == "en" else "en_US")
    html = re.sub(
        r'(?m)^[ \t]*<link\s+rel="(?:canonical|alternate)"[^\n]*\r?\n?',
        "", html,
    )
    links = (
        f'<link rel="canonical" href="{url}">\n'
        f'<link rel="alternate" hreflang="ru" href="{ru_url}">\n'
        f'<link rel="alternate" hreflang="en" href="{en_url}">\n'
        f'<link rel="alternate" hreflang="x-default" href="{ru_url}">\n'
    )
    marker = '<link rel="icon"'
    if marker not in html:
        raise ValueError(f"missing icon marker in {url_path}")
    return html.replace(marker, links + marker, 1)


def rewrite_english_links(html: str) -> str:
    public_roots = ("/tech/", "/install/", "/docs/", "/changelog/", "/support/", "/privacy/")

    def repl(match: re.Match[str]) -> str:
        href = match.group(1)
        if href.startswith("/en/") or href.startswith("//"):
            return match.group(0)
        if href == "/" or href.startswith("/#") or href.startswith(public_roots):
            return f'href="/en{href}"'
        return match.group(0)

    return re.sub(r'href="([^"]+)"', repl, html)


def translate_literal_english(html: str) -> str:
    for source, translated in RAW_ENGLISH.items():
        html = html.replace(source, translated)
    return html


def set_language_links(html: str, url_path: str, lang: str) -> str:
    ru_path = url_path
    en_path = localized_path(url_path, "en")
    ru_cls = ' class="is-active"' if lang == "ru" else ""
    en_cls = ' class="is-active"' if lang == "en" else ""
    ru_current = ' aria-current="page"' if lang == "ru" else ""
    en_current = ' aria-current="page"' if lang == "en" else ""
    html = re.sub(
        r'<a[^>]*data-lang-link="ru"[^>]*>RU</a>',
        f'<a href="{ru_path}"{ru_cls} data-lang-link="ru" hreflang="ru" lang="ru"{ru_current}>RU</a>',
        html,
    )
    html = re.sub(
        r'<a[^>]*data-lang-link="en"[^>]*>EN</a>',
        f'<a href="{en_path}"{en_cls} data-lang-link="en" hreflang="en" lang="en"{en_current}>EN</a>',
        html,
    )
    html = html.replace('aria-label="Установка Qeli"', 'aria-label="Qeli installation"' if lang == "en" else 'aria-label="Установка Qeli"')
    html = html.replace('aria-label="Документация"', 'aria-label="Documentation"' if lang == "en" else 'aria-label="Документация"')
    return html


def breadcrumb_items(url_path: str, meta: dict, lang: str) -> list[tuple[str, str]]:
    index = 1 if lang == "en" else 0
    items = [(localized_path("/", lang), "Home" if lang == "en" else "Главная")]
    for path, ru_label, en_label in meta.get("crumbs", []):
        items.append((localized_path(path, lang), en_label if lang == "en" else ru_label))
    items.append((localized_path(url_path, lang), meta["label"][index]))
    return items


def breadcrumb_html(url_path: str, meta: dict, lang: str) -> str:
    if url_path == "/":
        return ""
    items = breadcrumb_items(url_path, meta, lang)
    li = []
    for pos, (path, label) in enumerate(items, 1):
        safe = html_lib.escape(label)
        if pos == len(items):
            li.append(f'<li><span aria-current="page">{safe}</span></li>')
        else:
            li.append(f'<li><a href="{path}">{safe}</a></li>')
    aria = "Breadcrumbs" if lang == "en" else "Хлебные крошки"
    return (
        f"{BREAD_START}\n"
        f'<nav class="breadcrumbs" aria-label="{aria}"><div class="container">'
        f'<ol class="breadcrumbs__list">{"".join(li)}</ol></div></nav>\n'
        f"{BREAD_END}\n"
    )


def schema_json(url_path: str, meta: dict, lang: str, title: str, desc: str) -> str:
    path = localized_path(url_path, lang)
    url = BASE + path
    if meta["schema"] == "home":
        graph = [
            {
                "@type": "WebSite", "@id": f"{url}#website", "url": url, "name": "Qeli",
                "description": desc, "inLanguage": lang,
            },
            {
                "@type": "SoftwareApplication", "@id": f"{url}#software", "name": "Qeli",
                "applicationCategory": "SecurityApplication", "operatingSystem": "Linux, Windows, macOS, Android",
                "softwareVersion": "0.7.16", "description": desc,
                "url": url, "downloadUrl": "https://github.com/litvinovtd/qeli/releases/tag/v0.7.16",
                "codeRepository": "https://github.com/litvinovtd/qeli", "license": "https://www.gnu.org/licenses/agpl-3.0.html",
                "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
                "author": {"@type": "Organization", "name": "Qeli", "url": "https://github.com/litvinovtd/qeli"},
            },
        ]
    else:
        crumbs = []
        for pos, (item_path, label) in enumerate(breadcrumb_items(url_path, meta, lang), 1):
            crumbs.append({"@type": "ListItem", "position": pos, "name": label, "item": BASE + item_path})
        primary = {
            "@type": meta["schema"], "@id": f"{url}#primary", "url": url,
            "name": title, "description": desc, "inLanguage": lang,
            "isPartOf": {"@id": BASE + localized_path("/", lang) + "#website"},
        }
        if meta["schema"] == "TechArticle":
            primary["headline"] = title
            primary["author"] = {"@type": "Organization", "name": "Qeli"}
            primary["publisher"] = {"@type": "Organization", "name": "Qeli"}
        if meta["schema"] == "HowTo":
            index = 1 if lang == "en" else 0
            primary["step"] = [
                {"@type": "HowToStep", "position": pos, "name": step[index]}
                for pos, step in enumerate(meta.get("steps", []), 1)
            ]
        graph = [
            {"@type": "BreadcrumbList", "@id": f"{url}#breadcrumbs", "itemListElement": crumbs},
            primary,
        ]
    payload = {"@context": "https://schema.org", "@graph": graph}
    return '<script type="application/ld+json">\n' + json.dumps(payload, ensure_ascii=False, indent=2) + "\n</script>\n"


def insert_generated(html: str, url_path: str, meta: dict, lang: str, title: str, desc: str) -> str:
    bread = breadcrumb_html(url_path, meta, lang)
    if bread:
        html = html.replace("<main>", "<main>\n" + bread, 1)
    schema = schema_json(url_path, meta, lang, title, desc)
    marker = "</head>"
    return html.replace(marker, schema + marker, 1)


def build_sitemap() -> None:
    rows = []
    for path in PAGES:
        ru = BASE + path
        en = BASE + localized_path(path, "en")
        alternates = (
            f'    <xhtml:link rel="alternate" hreflang="ru" href="{ru}" />\n'
            f'    <xhtml:link rel="alternate" hreflang="en" href="{en}" />\n'
            f'    <xhtml:link rel="alternate" hreflang="x-default" href="{ru}" />\n'
        )
        for loc in (ru, en):
            rows.append(f"  <url>\n    <loc>{loc}</loc>\n    <lastmod>{UPDATED}</lastmod>\n{alternates}  </url>")
    sitemap = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n'
        '        xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        + "\n".join(rows) + "\n</urlset>\n"
    )
    (SITE / "sitemap.xml").write_text(sitemap, encoding="utf-8", newline="\n")


def main() -> None:
    dictionary = json.loads((SITE / "assets" / "i18n.json").read_text(encoding="utf-8"))
    header = (SITE / "inc" / "header.html").read_text(encoding="utf-8")
    footer = (SITE / "inc" / "footer.html").read_text(encoding="utf-8")
    missing: set[str] = set()

    for url_path, meta in PAGES.items():
        source = source_file(url_path)
        if not source.exists():
            raise FileNotFoundError(f"missing page source: {source}")
        raw = source.read_text(encoding="utf-8")
        raw = replace_shared(raw, HEADER_START, HEADER_END, '<div id="header-placeholder"></div>', header)
        raw = replace_shared(raw, FOOTER_START, FOOTER_END, '<div id="footer-placeholder"></div>', footer)
        raw = strip_generated(raw)

        for lang in ("ru", "en"):
            page, page_missing = translate(raw, dictionary, lang)
            missing.update(page_missing)
            title = dictionary[meta["title"]].get(lang, dictionary[meta["title"]]["ru"])
            desc = dictionary[meta["desc"]].get(lang, dictionary[meta["desc"]]["ru"])
            page = set_head(page, title, desc, url_path, lang)
            if lang == "en":
                page = translate_literal_english(page)
                page = rewrite_english_links(page)
            page = set_language_links(page, url_path, lang)
            page = insert_generated(page, url_path, meta, lang, title, desc)
            destination = source if lang == "ru" else SITE / localized_path(url_path, "en").strip("/") / "index.html"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(page, encoding="utf-8", newline="\n")

    if missing:
        raise KeyError("missing i18n keys: " + ", ".join(sorted(missing)))
    build_sitemap()
    print(f"Built {len(PAGES)} RU pages, {len(PAGES)} EN pages and sitemap.xml")


if __name__ == "__main__":
    main()
