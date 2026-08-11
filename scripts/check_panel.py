#!/usr/bin/env python3
"""Static quality gate for the embedded web panel.

Run from the repository root::

    python3 scripts/check_panel.py

The panel has no bundler/runtime test harness, so regressions previously entered as plain HTML:
unstyled native selects, keyboard-inaccessible clickable divs, duplicate dictionary entries and
new JS-bound strings that never reached the DOM translator. This check deliberately uses only the
standard library so it runs in every release/CI environment.
"""

from __future__ import annotations

import ast
import re
import sys
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "qeli" / "src" / "web" / "templates"
I18N = ROOT / "qeli" / "src" / "web" / "assets" / "i18n.js"

failures: list[str] = []


def fail(path: Path, line: int, message: str) -> None:
    failures.append(f"{path.relative_to(ROOT)}:{line}: {message}")


STRING_KEY = re.compile(r"^\s*(['\"])((?:\\.|.)*?)\1\s*:", re.MULTILINE)
TRANSLATE_CALL = re.compile(r"\bqeliT(?:f)?\(\s*(['\"])((?:\\.|.)*?)\1", re.DOTALL)


def decode_js_string(quote: str, body: str) -> str:
    try:
        return ast.literal_eval(f"{quote}{body}{quote}")
    except (SyntaxError, ValueError):
        return body.replace(r"\n", "\n").replace(r"\'", "'").replace(r'\"', '"')


i18n_text = I18N.read_text(encoding="utf-8")
dictionary_entries = [decode_js_string(match.group(1), match.group(2)) for match in STRING_KEY.finditer(i18n_text)]
dictionary = set(dictionary_entries)

for key, count in Counter(dictionary_entries).items():
    if count > 1:
        fail(I18N, 1, f"duplicate RU dictionary key ({count} copies): {key!r}")


def line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def technical_label(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    # Symbols and protocol/config values are intentionally language-neutral.
    if not any(character.isalpha() for character in stripped):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_.:/+×-]+", stripped))


def technical_placeholder(value: str) -> bool:
    # Single tokens and examples containing config/network punctuation should not be translated.
    # Human instructions such as "Search profiles" or "auto from the link" must be.
    return " " not in value or bool(re.search(r"[/:=\[\]{}<>$0-9]", value))


class TemplateAudit(HTMLParser):
    def __init__(self, path: Path, source: str) -> None:
        super().__init__(convert_charrefs=True)
        self.path = path
        self.source = source
        self.control_stack: list[tuple[str, dict[str, str | None], int]] = []

    @property
    def line(self) -> int:
        return self.getpos()[0]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        classes = set((data.get("class") or "").split())
        input_type = (data.get("type") or "text").lower()

        # login.html is a standalone, fully styled page with its own scoped input/select CSS.
        bespoke_login = self.path.name == "login.html"
        if not bespoke_login:
            if tag == "select" and "inp" not in classes:
                fail(self.path, self.line, "select must use the shared .inp control")
            if tag == "input" and input_type in {"text", "password", "search", "number", "email", "url", "tel"} and "inp" not in classes:
                fail(self.path, self.line, f"{input_type} input must use the shared .inp control")
            if tag == "textarea" and not ({"inp", "code-editor"} & classes):
                fail(self.path, self.line, "textarea must use .inp or .code-editor")

        for attr in ("title", "aria-label"):
            value = data.get(attr)
            if value and not attr.startswith(":") and not value.startswith(("qeliT(", "ev.")):
                if value not in dictionary and not technical_label(value):
                    fail(self.path, self.line, f"{attr} has no RU translation: {value!r}")
        placeholder = data.get("placeholder")
        if placeholder and not technical_placeholder(placeholder) and placeholder not in dictionary:
            fail(self.path, self.line, f"placeholder has no RU translation: {placeholder!r}")

        click = data.get("@click") or data.get("x-on:click")
        if tag == "div" and click:
            allowed = bool(
                {"toggle-wrap", "modal", "modal-bg"} & classes
                or data.get("role") in {"button", "switch", "dialog"}
                or data.get("@click.self")
                or "sidebarOpen" in click
            )
            if not allowed:
                fail(self.path, self.line, "clickable div must be a shared toggle, modal, or keyboard-operable role")

        if tag in {"button", "option"}:
            self.control_stack.append((tag, data, self.line))

    def handle_data(self, data: str) -> None:
        if not self.control_stack:
            return
        tag, attrs, start_line = self.control_stack[-1]
        text = " ".join(data.split())
        if not text or attrs.get("data-i18n-skip") is not None or attrs.get("x-text") is not None:
            return
        # An option without value submits its visible text as the configuration value. The
        # runtime translator intentionally leaves those protocol enum tokens untouched.
        if tag == "option" and "value" not in attrs:
            return
        if text not in dictionary and not technical_label(text):
            fail(self.path, start_line, f"{tag} text has no RU translation: {text!r}")

    def handle_endtag(self, tag: str) -> None:
        if self.control_stack and self.control_stack[-1][0] == tag:
            self.control_stack.pop()


template_paths = sorted(TEMPLATES.glob("*.html"))
if not template_paths:
    raise SystemExit("panel templates not found; refusing to pass an unchecked tree")

for path in template_paths:
    source = path.read_text(encoding="utf-8")
    for match in TRANSLATE_CALL.finditer(source):
        key = decode_js_string(match.group(1), match.group(2))
        if key not in dictionary:
            fail(path, line_at(source, match.start()), f"qeliT/qeliTf literal has no RU translation: {key!r}")
    parser = TemplateAudit(path, source)
    try:
        parser.feed(source)
    except Exception as error:  # fail closed on malformed input/parser surprises
        fail(path, parser.line, f"HTML audit failed: {error}")

if failures:
    print("panel checks FAILED:")
    for item in failures:
        print(f"  - {item}")
    raise SystemExit(1)

print(f"panel checks OK: {len(template_paths)} templates, {len(dictionary)} RU strings")
