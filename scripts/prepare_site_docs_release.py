#!/usr/bin/env python3
"""Prepare the private site's active docs; never publish or rewrite historical data.

Run --write --build before deployment, then run without --write to check. The
publishedVersion, changelog, performance data and dated report files stay intact.
"""
from __future__ import annotations

import argparse
import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
ACTIVE_KEYS = ("docs", "guide.", "install", "clients.", "meta.", "release.")
HISTORICAL = re.compile(r"(?:^|[-_\s.])(changelog|clog|history|historical|archive|reports?|benchmarks?|perf|performance|compare|results)(?:$|[-_\s.])", re.I)
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


def replace_version(text: str, old: set[str], target: str) -> str:
    for value in sorted(old):
        text = re.sub(r"(?<![0-9.])" + re.escape(value) + r"(?![0-9]|\.[0-9])", target, text)
    return text


def rewrite_active_html(text: str, old: set[str], target: str) -> str:
    """Rewrite active fragments, preserving inline historical blocks byte-for-byte."""
    class HistoryRanges(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.offsets = [0]
            for line in text.splitlines(keepends=True):
                self.offsets.append(self.offsets[-1] + len(line))
            self.stack = []
            self.spans = []

        def position(self):
            line, column = self.getpos()
            return self.offsets[line - 1] + column

        def historical(self, tag, attrs):
            values = dict(attrs)
            labels = [values.get(key) or "" for key in ("id", "class", "data-i18n", "data-i18n-html")]
            return (tag in {"script", "style"}
                    or any(HISTORICAL.search(value) for value in labels)
                    or any(re.match(r"(?:release\d|v\d{3,}(?:$|[-_])|v?\d+\.\d+\.\d+$)", value) for value in labels)
                    or bool(re.search(r"/(reports?|benchmarks?|archive)/", values.get("href") or "", re.I)))

        def handle_starttag(self, tag, attrs):
            start = self.position()
            protected = self.historical(tag, attrs)
            if tag not in VOID_TAGS:
                self.stack.append((tag, start, protected))
            elif protected:
                self.spans.append((start, start + len(self.get_starttag_text())))

        def handle_startendtag(self, tag, attrs):
            if self.historical(tag, attrs):
                self.spans.append((self.position(), self.position() + len(self.get_starttag_text())))

        def handle_endtag(self, tag):
            index = next((i for i in range(len(self.stack) - 1, -1, -1) if self.stack[i][0] == tag), None)
            if index is not None:
                end = text.index(">", self.position()) + 1
                for _, start, protected in self.stack[index:]:
                    if protected:
                        self.spans.append((start, end))
                del self.stack[index:]

    ranges = HistoryRanges()
    ranges.feed(text)
    ranges.close()
    if any(protected for _, _, protected in ranges.stack):
        raise ValueError("unclosed protected historical HTML block")
    result, cursor = [], 0
    for start, end in sorted(ranges.spans):
        if end <= cursor:
            continue
        result.append(replace_version(text[cursor:start], old, target))
        result.append(text[max(cursor, start):end])
        cursor = end
    result.append(replace_version(text[cursor:], old, target))
    return "".join(result)


def json_text(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def plan(site: Path, version: str) -> dict[Path, str]:
    if not VERSION.fullmatch(version):
        raise ValueError("version must be numeric X.Y.Z")
    site = site.resolve(strict=True)
    config_path = site / "assets/site.json"
    dictionary_path = site / "assets/i18n.json"
    for path in (config_path, dictionary_path):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(site):
            raise ValueError(f"expected a regular private site input: {path}")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    dictionary = json.loads(dictionary_path.read_text(encoding="utf-8"))
    published = config["publishedVersion"]
    old = {config["version"], published} - {version}
    if any(not isinstance(v, str) or not VERSION.fullmatch(v) for v in old):
        raise ValueError("invalid current/published site version")
    protected = {key: copy.deepcopy(config[key]) for key in ("publishedVersion", "changelog", "perf", "compare") if key in config}
    config.update(version=version, versionNav=f"{version} beta · candidate",
                  versionFooterRu=f"{version} (кандидат)", versionFooterEn=f"{version} (candidate)",
                  versionJsonLd=version, developmentVersion=version, documentationStatus="candidate")
    # These labels describe the candidate, not an invented publication date.
    config["dateLabel"] = "Подготовка выпуска"
    config["dateLabelEn"] = "Release preparation"
    for key, entry in dictionary.items():
        if key.startswith(ACTIVE_KEYS) and isinstance(entry, dict):
            for language, value in entry.items():
                if isinstance(value, str):
                    entry[language] = rewrite_active_html(value, old, version)
    overrides = {
        "release.badge": {"ru": f"{version} · подготовка", "en": f"{version} · candidate"},
        "guide.previewLink": {"ru": f"Статус выпуска {version} →", "en": f"{version} release status →"},
        "installDocker.runP": {
            "ru": f"После публикации тега <code>v{version}</code> команды ниже собирают контейнер из этого тега, независимо от GHCR <code>latest</code>. До публикации используйте проверенный исходный commit кандидата. Сборка создаётся для архитектуры хоста; для роутера задайте целевую платформу.",
            "en": f"After tag <code>v{version}</code> is published, the commands below build from that tag independently of GHCR <code>latest</code>. Before publication use the reviewed candidate source commit. The image targets the host architecture; specify the target platform for routers.",
        },
        "installClients.chooseP": {
            "ru": f"Комплект {version}: Windows GUI — <code>QeliWin-standalone.exe</code> или <code>QeliWin-net-required.exe</code>; Windows CLI — архив <code>qeli-cli-windows-x64-standalone.zip</code> или <code>qeli-cli-windows-x64-net-required.zip</code> (распакуйте целиком). macOS 15+ — отдельный архив arm64 или x86_64. Android — <code>qeli-android-{version}.apk</code>. Linux amd64/arm64 — соответствующий бинарник или <code>qeli_{version}_amd64.deb</code>/<code>qeli_{version}_arm64.deb</code>. Для OpenWrt/Keenetic выбирайте свою архитектуру. Готовой iOS-сборки нет. Доступность файлов проверяйте в GitHub Releases.",
            "en": f"The {version} distribution: Windows GUI — <code>QeliWin-standalone.exe</code> or <code>QeliWin-net-required.exe</code>; Windows CLI — <code>qeli-cli-windows-x64-standalone.zip</code> or <code>qeli-cli-windows-x64-net-required.zip</code> (extract the whole archive). macOS 15+ — separate arm64 or x86_64 archive. Android — <code>qeli-android-{version}.apk</code>. Linux amd64/arm64 — matching binary or <code>qeli_{version}_amd64.deb</code>/<code>qeli_{version}_arm64.deb</code>. Select the matching OpenWrt/Keenetic architecture. No iOS build is published. Check GitHub Releases for available files.",
        },
    }
    for key, value in overrides.items():
        if key not in dictionary:
            raise ValueError(f"missing active site dictionary key: {key}")
        dictionary[key].update(value)
    preview = dictionary["guide.previewP"]
    preview["ru"] = re.sub(r"^.*?выпущена как beta\.", f"Руководство подготовлено для {version}; доступность пакетов проверяйте в GitHub Releases.", preview["ru"])
    preview["en"] = re.sub(r"^.*?is released as a beta\.", f"This guide targets {version}; check GitHub Releases for available packages.", preview["en"])
    # State the changed batching default without relabelling old benchmark results.
    if version == "0.8.4":
        for language, text in {
            "ru": "В 0.8.4 дефолт — prefer + batch.mode=opportunistic: ожидания новых пакетов ради batching нет. Параметры delay применяются только при явном batch.mode=timed. Явные off/required/timed при обновлении сохраняются.",
            "en": "In 0.8.4 the default is prefer + batch.mode=opportunistic: batching does not wait for new packets. Delay settings apply only with explicit batch.mode=timed. Upgrades preserve explicit off/required/timed settings.",
        }.items():
            body = dictionary["docsRecordizer.body"][language]
            body = re.sub(r'<div data-release-defaults="084".*?</div>\s*', '', body, flags=re.S)
            dictionary["docsRecordizer.body"][language] = f'<div data-release-defaults="084" class="doc-callout">{text}</div>\n' + body
    assert all(config[key] == value for key, value in protected.items())
    result = {config_path: json_text(config), dictionary_path: json_text(dictionary)}
    # Only active pages and shared chrome: no reports, benchmarks or changelog bodies.
    pages = [site / "index.html", site / "en/index.html", site / "inc/header.html", site / "inc/footer.html"]
    for folder in ("docs", "install", "en/docs", "en/install"):
        pages.extend((site / folder).rglob("index.html"))
    for path in sorted(set(pages)):
        if set(path.relative_to(site).parts) & {"reports", "benchmarks", "archive", "history", "changelog"}:
            continue
        if not path.is_file():
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(site):
            raise ValueError(f"site page escapes its root: {path}")
        text = path.read_text(encoding="utf-8")
        text = rewrite_active_html(text, old, version)
        # The builder's older literal dictionary need not know the new tag comment.
        if path.relative_to(site).parts[0] == "en":
            text = text.replace(f"# получить исходники опубликованной версии {version}:", f"# get the {version} sources after tag publication:")
        if path.name == "index.html":
            text = re.sub(r'<!-- release-docs-status:start -->.*?<!-- release-docs-status:end -->\s*', '', text, flags=re.S)
            english = path.relative_to(site).parts[0] == "en"
            message = (f"Documentation for the {version} candidate. Check GitHub Releases for publication and file availability; Docker tags require a successful image publication."
                       if english else f"Документация кандидата {version}. Статус публикации и доступность файлов смотрите в GitHub Releases; Docker-теги доступны после успешной публикации образа.")
            note = f'\n<!-- release-docs-status:start --><p class="doc-callout" role="note">{message}</p><!-- release-docs-status:end -->\n'
            text, count = re.subn(r'(<main\b[^>]*>)\s*', lambda m: m[1] + note, text, count=1)
            if count != 1:
                raise ValueError(f"expected exactly one main element: {path}")
        result[path] = text
    return {path: value for path, value in result.items() if path.read_text(encoding="utf-8") != value}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--site-root", type=Path, default=ROOT / "site")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--build", action="store_true", help="rebuild local RU/EN pages; requires --write and the repository's private site")
    args = parser.parse_args()
    if args.build and (not args.write or args.site_root.resolve() != (ROOT / "site").resolve()):
        parser.error("--build requires --write and the repository's private site")
    changes = plan(args.site_root, args.version)
    for path, value in changes.items():
        print(("update " if args.write else "stale  ") + str(path.relative_to(args.site_root.resolve())))
        if args.write:
            path.write_text(value, encoding="utf-8", newline="\n")
    if args.build:
        subprocess.run([sys.executable, str(ROOT / "scripts/build_site_static.py")], check=True)
        # Restore the explicit candidate notice after the normal template generation.
        for path, value in plan(args.site_root, args.version).items():
            path.write_text(value, encoding="utf-8", newline="\n")
    return 0 if args.write or not changes else 1


if __name__ == "__main__":
    raise SystemExit(main())
