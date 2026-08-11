#!/usr/bin/env python3
"""Capture/compare the complete panel matrix (RU/EN × dark/light × desktop/mobile).

This is an opt-in integration test because it needs a running, seeded qeli panel. It never
starts or modifies the server. Credentials are read from flags or environment and are not
written to filenames, screenshots or logs.

Dependencies (test workstation/lab only)::

    pip install playwright pillow
    playwright install chromium

Example::

    QELI_PANEL_URL=https://panel.example.test \
    QELI_PANEL_USER=admin QELI_PANEL_PASSWORD=... \
      python scripts/panel_visual_regression.py

Pass ``--update-baselines`` only after reviewing the images in ``--output``. Baselines are
kept out of this first code-only foundation; the first approved seeded run creates them.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGES = ("", "transport", "quickstart", "users", "config", "client", "logs", "blocked", "notifications")
VIEWPORTS = {
    "desktop": {"width": 1440, "height": 1000},
    "mobile": {"width": 390, "height": 844},
}


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.environ.get("QELI_PANEL_URL", ""))
    parser.add_argument("--username", default=os.environ.get("QELI_PANEL_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("QELI_PANEL_PASSWORD", ""))
    parser.add_argument("--output", type=Path, default=ROOT / "target" / "panel-visual-current")
    parser.add_argument("--baselines", type=Path, default=ROOT / "qeli" / "tests" / "panel-baselines")
    parser.add_argument("--update-baselines", action="store_true")
    parser.add_argument("--max-changed-ratio", type=float, default=0.005)
    return parser.parse_args()


def safe_name(page: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", page.lower()).strip("-") or "dashboard"


def changed_ratio(actual: Path, baseline: Path) -> float:
    from PIL import Image, ImageChops

    with Image.open(actual).convert("RGBA") as current, Image.open(baseline).convert("RGBA") as expected:
        if current.size != expected.size:
            return 1.0
        histogram = ImageChops.difference(current, expected).convert("L").histogram()
        changed = sum(histogram[1:])
        return changed / max(1, current.width * current.height)


def main() -> int:
    options = args()
    if not options.base_url or not options.password:
        print("set QELI_PANEL_URL and QELI_PANEL_PASSWORD (or pass matching flags)", file=sys.stderr)
        return 2
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is missing; install it in the lab test environment", file=sys.stderr)
        return 2
    try:
        import PIL  # noqa: F401
    except ImportError:
        print("Pillow is missing; install it in the lab test environment", file=sys.stderr)
        return 2

    base = options.base_url.rstrip("/") + "/"
    options.output.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        for viewport_name, viewport in VIEWPORTS.items():
            for language in ("en", "ru"):
                for theme in ("dark", "light"):
                    context = browser.new_context(viewport=viewport, device_scale_factor=1)
                    context.add_init_script(
                        f"localStorage.setItem('qeli_lang', {json.dumps(language)});"
                        f"localStorage.setItem('qeli_theme', {json.dumps(theme)});"
                    )
                    page = context.new_page()
                    page.goto(base + "login", wait_until="networkidle")
                    if page.locator("#loginForm").count():
                        page.locator("#username").fill(options.username)
                        page.locator("#password").fill(options.password)
                        page.locator("#loginForm").press("Enter")
                        page.wait_for_url(lambda url: not url.path.endswith("/login"), timeout=15_000)

                    for route in PAGES:
                        page.goto(base + route, wait_until="networkidle")
                        page.add_style_tag(
                            content="""
                              *,*::before,*::after{animation-duration:0s!important;transition-duration:0s!important;caret-color:transparent!important}
                              [data-visual-dynamic]{visibility:hidden!important}
                            """
                        )
                        page.wait_for_timeout(300)
                        name = f"{safe_name(route)}--{language}--{theme}--{viewport_name}.png"
                        actual = options.output / name
                        page.screenshot(path=str(actual), full_page=True)
                        baseline = options.baselines / name
                        if options.update_baselines:
                            baseline.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(actual, baseline)
                        elif not baseline.exists():
                            failures.append(f"missing baseline: {baseline.relative_to(ROOT)}")
                        else:
                            ratio = changed_ratio(actual, baseline)
                            if ratio > options.max_changed_ratio:
                                failures.append(
                                    f"{name}: {ratio:.2%} pixels changed (limit {options.max_changed_ratio:.2%})"
                                )
                    context.close()
        browser.close()

    if failures:
        print("panel visual regression FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        print(f"current screenshots: {options.output}")
        return 1
    print(f"panel visual regression OK: {len(PAGES) * len(VIEWPORTS) * 4} screenshots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
