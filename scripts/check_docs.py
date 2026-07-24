#!/usr/bin/env python3
"""Docs-as-code checks. Run from the repo root:  python scripts/check_docs.py

Guards the documentation structure so it cannot silently rot:

  1. links     — every relative Markdown link resolves to a real file
  2. index     — every document under docs/<lang>/ is reachable from that
                 language's index.md (no orphaned pages)
  3. parity    — docs/ru and docs/eng contain the SAME set of files
                 (this is what let `streams` exist in eng but not ru)
  4. config    — every INI key the server actually emits (server_ini.rs) is
                 mentioned in CONFIG.md, in BOTH languages
  5. source    — every source file a doc names in backticks still exists
                 (frozen records — archive/, CHANGELOG — are out of scope)
  6. version   — one version everywhere: qeli/Cargo.toml is the source of truth,
                 and the Android build, both overview READMEs and CHANGELOG.md
                 must agree with it

Exit code 0 = all good, 1 = something to fix. Intended for CI and pre-release.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LANGS = ("ru", "eng")

# Keys the server emits but that are deliberately NOT part of the user-facing
# configuration reference (internal/derived). Keep this list short and justified.
CONFIG_KEY_ALLOWLIST: set[str] = set()

failures: list[str] = []


def fail(check: str, msg: str) -> None:
    failures.append(f"[{check}] {msg}")


def tracked_markdown() -> list[Path]:
    """Markdown files git knows about — tracked PLUS new-but-not-ignored ones.

    Including untracked files matters: a freshly written page must be checked
    before it is committed, not after. Ignored paths (node_modules, build output)
    stay out because --exclude-standard honours .gitignore.
    """
    names: set[str] = set()
    for args in (["git", "ls-files", "*.md"],
                 ["git", "ls-files", "--others", "--exclude-standard", "*.md"]):
        out = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
        names.update(line for line in out.stdout.splitlines() if line.strip())
    files = [ROOT / n for n in sorted(names)]
    return [f for f in files if f.exists() and "node_modules" not in f.parts]


LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def check_links(files: list[Path]) -> None:
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            fail("links", f"cannot read {f.relative_to(ROOT)}: {e}")
            continue
        for target in LINK_RE.findall(text):
            t = target.strip()
            if t.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path = (f.parent / t.split("#", 1)[0]).resolve()
            if not path.exists():
                fail("links", f"{f.relative_to(ROOT)} -> {t}")


def check_index_coverage() -> None:
    for lang in LANGS:
        d = ROOT / "docs" / lang
        index = d / "index.md"
        if not index.exists():
            fail("index", f"docs/{lang}/index.md is missing")
            continue
        body = index.read_text(encoding="utf-8", errors="replace")
        for doc in sorted(d.glob("*.md")):
            if doc.name == "index.md":
                continue
            if f"({doc.name})" not in body:
                fail("index", f"docs/{lang}/{doc.name} is not linked from index.md")
        archive = d / "archive"
        if archive.is_dir():
            arch_readme = archive / "README.md"
            arch_body = (
                arch_readme.read_text(encoding="utf-8", errors="replace")
                if arch_readme.exists()
                else ""
            )
            for doc in sorted(archive.glob("*.md")):
                if doc.name == "README.md":
                    continue
                if f"({doc.name})" not in arch_body and f"(archive/{doc.name})" not in body:
                    fail("index", f"docs/{lang}/archive/{doc.name} is not linked anywhere")


def check_parity() -> None:
    sets = {}
    for lang in LANGS:
        d = ROOT / "docs" / lang
        sets[lang] = {p.relative_to(d).as_posix() for p in d.rglob("*.md")}
    only_ru = sets["ru"] - sets["eng"]
    only_eng = sets["eng"] - sets["ru"]
    for name in sorted(only_ru):
        fail("parity", f"docs/ru/{name} has no docs/eng counterpart")
    for name in sorted(only_eng):
        fail("parity", f"docs/eng/{name} has no docs/ru counterpart")


KEY_RE = re.compile(r'put(?:_str|_list)?\(\s*&mut\s+\w+\s*,\s*"([^"]+)"')


def _documented(body: str, key: str) -> bool:
    """Is `key` covered by the reference?

    CONFIG.md legitimately uses a compact pair notation for sibling keys —
    ``| `obf.fragmentation.min_chunk_size` / `max_chunk_size` |`` — where the second
    key omits the shared prefix. Accept that, but only when the SAME line also
    carries the parent prefix, so a stray mention of a generic word like `enabled`
    never counts as documentation.
    """
    if key in body:
        return True
    parent, _, last = key.rpartition(".")
    if not parent:
        return False
    return any(last in line and parent in line for line in body.splitlines())


def check_config_keys() -> None:
    src = ROOT / "qeli" / "src" / "config" / "server_ini.rs"
    if not src.exists():
        fail("config", f"{src.relative_to(ROOT)} not found — cannot verify key coverage")
        return
    keys = set(KEY_RE.findall(src.read_text(encoding="utf-8", errors="replace")))
    keys -= CONFIG_KEY_ALLOWLIST
    if not keys:
        fail("config", "no INI keys extracted — the extractor pattern probably drifted")
        return
    for lang in LANGS:
        cfg = ROOT / "docs" / lang / "CONFIG.md"
        if not cfg.exists():
            fail("config", f"docs/{lang}/CONFIG.md is missing")
            continue
        body = cfg.read_text(encoding="utf-8", errors="replace")
        missing = sorted(k for k in keys if not _documented(body, k))
        for k in missing:
            fail("config", f"key '{k}' is emitted by the server but absent from docs/{lang}/CONFIG.md")


# A source file named in backticks, e.g. `qeli/src/config/server_ini.rs`. Docs point at
# code constantly; when the code moves, nothing tells the reader the pointer went stale.
SRC_REF_RE = re.compile(
    r"`((?:qeli|qeli-[a-z]+|scripts|release|site)/[A-Za-z0-9_./-]+"
    r"\.(?:rs|cs|kt|swift|py|sh|toml|conf|yml|yaml|kts))`"
)

# Frozen records name paths as they were AT THE TIME — rewriting them would falsify the
# record, so they are out of scope for this check rather than exceptions to fix.
SRC_REF_SKIP = ("archive/", "CHANGELOG.md", "AUDIT-FIXES-")


def check_source_refs(files: list[Path]) -> None:
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        if any(s in rel for s in SRC_REF_SKIP):
            continue
        for ref in SRC_REF_RE.findall(f.read_text(encoding="utf-8", errors="replace")):
            # `qeli-android/.../QeliService.kt` — deliberate elision, not a real path.
            if "/.../" in ref:
                continue
            if not (ROOT / ref).exists():
                fail("source", f"{rel} points at `{ref}`, which does not exist")


CARGO_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.M)
ANDROID_VERSION_RE = re.compile(r'versionName\s*=\s*"([^"]+)"')


def check_version() -> None:
    """One version across all components (see the CHANGELOG header) — and the docs
    must state it. The overview README claimed 0.7.11 while the crate was already
    0.7.12, which is exactly what this catches."""
    cargo = ROOT / "qeli" / "Cargo.toml"
    if not cargo.exists():
        fail("version", "qeli/Cargo.toml not found")
        return
    m = CARGO_VERSION_RE.search(cargo.read_text(encoding="utf-8", errors="replace"))
    if not m:
        fail("version", "no [package] version in qeli/Cargo.toml")
        return
    version = m.group(1)

    gradle = ROOT / "qeli-android" / "app" / "build.gradle.kts"
    if gradle.exists():
        am = ANDROID_VERSION_RE.search(gradle.read_text(encoding="utf-8", errors="replace"))
        if am and am.group(1) != version:
            fail("version", f"Android versionName {am.group(1)} != crate version {version}")

    for lang in LANGS:
        readme = ROOT / "docs" / lang / "README.md"
        if readme.exists() and version not in readme.read_text(encoding="utf-8", errors="replace"):
            fail("version", f"docs/{lang}/README.md does not state the current version {version}")

    changelog = ROOT / "CHANGELOG.md"
    if changelog.exists() and f"[{version}]" not in changelog.read_text(
        encoding="utf-8", errors="replace"
    ):
        fail("version", f"CHANGELOG.md has no section for {version}")


def main() -> int:
    files = tracked_markdown()
    print(f"checking {len(files)} tracked Markdown files…")
    check_links(files)
    check_index_coverage()
    check_parity()
    check_config_keys()
    check_source_refs(files)
    check_version()

    if not failures:
        print(
            "OK — links, index coverage, ru/eng parity, config-key coverage, "
            "source references and version consistency all pass."
        )
        return 0
    by_check: dict[str, int] = {}
    for f in failures:
        by_check[f.split("]")[0][1:]] = by_check.get(f.split("]")[0][1:], 0) + 1
    print(f"\n{len(failures)} problem(s):\n")
    for f in failures:
        print("  " + f)
    print("\nsummary: " + ", ".join(f"{k}={v}" for k, v in sorted(by_check.items())))
    return 1


if __name__ == "__main__":
    sys.exit(main())
