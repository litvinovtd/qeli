#!/usr/bin/env python3
"""Docs-as-code checks. Run from the repo root:  python scripts/check_docs.py

Guards the documentation structure so it cannot silently rot:

  1. links     — every relative Markdown link resolves to a real file; release-note
                 repository links are absolute and pinned to their release tag
  2. index     — every document under docs/<lang>/ is reachable from that
                 language's index.md (no orphaned pages)
  3. parity    — docs/ru and docs/eng contain the SAME set of files
                 (this is what let `streams` exist in eng but not ru)
  4. config    — every INI key the server actually emits (server_ini.rs) AND
                 every key the client actually reads from `[qeli]`
                 (client.rs::from_ini) is mentioned in CONFIG.md, in BOTH
                 languages. Runtime-built keys (`pool.reservation.<user>`) are
                 checked by their literal prefix
  5. source    — tracked docs only name source files tracked by Git
                 (frozen records — archive/, CHANGELOG — are out of scope)
  6. placeholder — no GitHub URL left with `<owner>` unfilled; these hide in
                 fenced code blocks where check 1 never looks
  7. version   — CHANGELOG.md names the next public release and it is not older
                 than the development build. Every other version string is owned
                 by scripts/sync_version.py
  8. anchors   — active docs do not pin source links to refactor-fragile #L numbers
  9. sync      — safety-sensitive RU/EN pairs carry the same normative revision

Every semantic check fails closed when its extractor or marker drifts.

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
        try:
            out = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
        except OSError as e:
            raise SystemExit(f"cannot run git ({e}) — refusing to report success on an unchecked tree")
        # Fail CLOSED. Swallowing a git error left the file list empty, and an empty
        # list makes every per-file check pass vacuously: the script printed
        # "checking 0 tracked Markdown files ... OK" and exited 0, i.e. a green gate
        # that verified nothing. A gate that cannot see the tree must not pass it.
        if out.returncode != 0:
            raise SystemExit(
                f"git {' '.join(args[1:])} failed (exit {out.returncode}): "
                f"{out.stderr.strip() or 'no stderr'}"
            )
        names.update(line for line in out.stdout.splitlines() if line.strip())
    files = [ROOT / n for n in sorted(names)]
    files = [f for f in files if f.exists() and "node_modules" not in f.parts]
    if not files:
        raise SystemExit("no Markdown files found — the tree looks wrong; refusing to pass")
    return files


LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
RELEASE_NOTES_FILE_RE = re.compile(r"RELEASE_NOTES_(\d+\.\d+\.\d+)\.md")


# Fenced blocks and inline code spans, in that order. Link syntax inside either is
# LITERAL TEXT in every Markdown renderer, so scanning it for links produces false
# failures — e.g. a Rust/Swift type written as `[UInt8](raw)` in prose was reported as a
# broken link to a file named "raw". Strip them before looking for links.
# (Audit 2026-07-27, Z6.)
CODE_SPAN_RE = re.compile(r"```.*?```|``.*?``|`[^`\n]*`", re.DOTALL)


def strip_code(text: str) -> str:
    """Blank out fenced blocks and inline code, preserving newlines so line numbers hold."""
    return CODE_SPAN_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def check_links(files: list[Path]) -> None:
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            fail("links", f"cannot read {f.relative_to(ROOT)}: {e}")
            continue
        text = strip_code(text)
        release_match = (
            RELEASE_NOTES_FILE_RE.fullmatch(f.name)
            if f.parent == ROOT / "release"
            else None
        )
        for target in LINK_RE.findall(text):
            t = target.strip()
            if t.startswith(("http://", "https://", "mailto:", "#")):
                if release_match and t.startswith(
                    "https://github.com/litvinovtd/qeli/blob/"
                ):
                    expected = (
                        "https://github.com/litvinovtd/qeli/blob/"
                        f"v{release_match.group(1)}/"
                    )
                    if not t.startswith(expected):
                        fail(
                            "links",
                            f"{f.relative_to(ROOT)} -> {t} is not pinned to "
                            f"v{release_match.group(1)}",
                        )
                continue
            if release_match:
                fail(
                    "links",
                    f"{f.relative_to(ROOT)} -> {t}: GitHub Release bodies require "
                    "an absolute repository URL pinned to the release tag",
                )
                continue
            path = (f.parent / t.split("#", 1)[0]).resolve()
            if not path.exists():
                fail("links", f"{f.relative_to(ROOT)} -> {t}")


def check_index_coverage() -> None:
    allowed_roots = {"manuals", "reference", "plans", "reports", "archive"}
    for lang in LANGS:
        d = ROOT / "docs" / lang
        index = d / "index.md"
        if not index.exists():
            fail("index", f"docs/{lang}/index.md is missing")
            continue
        body = strip_code(index.read_text(encoding="utf-8", errors="replace"))
        linked: set[str] = set()
        for raw_target in LINK_RE.findall(body):
            target = raw_target.strip()
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (index.parent / target).resolve()
            try:
                linked.add(resolved.relative_to(d.resolve()).as_posix())
            except ValueError:
                continue

        for doc in sorted(d.rglob("*.md")):
            rel = doc.relative_to(d)
            rel_posix = rel.as_posix()
            if rel_posix == "index.md":
                continue
            if len(rel.parts) == 1 and rel_posix != "README.md":
                fail(
                    "index",
                    f"docs/{lang}/{rel_posix} is uncategorized; move it under "
                    "manuals/, reference/, plans/, reports/ or archive/",
                )
            elif len(rel.parts) > 1 and rel.parts[0] not in allowed_roots:
                fail("index", f"docs/{lang}/{rel_posix} uses an unknown document category")
            if rel_posix not in linked:
                fail("index", f"docs/{lang}/{rel_posix} is not linked from index.md")


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

# Keys whose tail is built at runtime:
#   put_str(&mut s, &format!("pool.reservation.{}", name), ip)
#   put_str(&mut s, &format!("metadata.{}", k), v)
# KEY_RE only sees string literals, so these were invisible to the gate. The literal
# stem is the documentable part (`pool.reservation.<user>`), so capture it and require
# the reference to name it.
PREFIX_KEY_RE = re.compile(
    r'put(?:_str|_list)?\(\s*&mut\s+\w+\s*,\s*&format!\(\s*"([A-Za-z0-9_.]*?)\.?\{'
)

# The server extractor above reads the WRITER (`put*()` in server_ini.rs), which by
# construction only ever sees SERVER keys. The client's `[qeli]` section is parsed by a
# READER in client.rs, so its ~39 keys (`server`, `proto`, `exit_node`,
# `password_command`, `allow_unpinned_tofu`, …) sat outside the gate entirely — which is
# how the site could document `exclude_routes` for a parser that only ever reads
# `exclude`, with nothing to catch it. Slice `from_ini` rather than the whole file: `q`
# is the `[qeli]` section handle only inside that function.
CLIENT_FN_START = "pub fn from_ini"
CLIENT_FN_END = "pub fn to_link"
CLIENT_KEY_RE = re.compile(
    r'\bq\s*\.\s*(?:get|get_or|str_or|bool_or|parse_or|list)\(\s*"([^"]+)"'
)


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


def _client_keys() -> set[str]:
    """Keys the client reads out of the `[qeli]` section, from client.rs::from_ini.

    Fails CLOSED like the rest of this script: if the function markers moved or the
    accessor pattern drifted, an empty result would silently pass every key, so say so
    instead."""
    src = ROOT / "qeli" / "src" / "config" / "client.rs"
    if not src.exists():
        fail("config", f"{src.relative_to(ROOT)} not found — cannot verify client key coverage")
        return set()
    text = src.read_text(encoding="utf-8", errors="replace")
    start = text.find(CLIENT_FN_START)
    end = text.find(CLIENT_FN_END, start + 1) if start != -1 else -1
    if start == -1 or end == -1:
        fail(
            "config",
            f"cannot locate '{CLIENT_FN_START}'..'{CLIENT_FN_END}' in client.rs — "
            "the client key extractor needs updating",
        )
        return set()
    keys = set(CLIENT_KEY_RE.findall(text[start:end])) - CONFIG_KEY_ALLOWLIST
    if not keys:
        fail("config", "no client [qeli] keys extracted — the extractor pattern probably drifted")
    return keys


def check_config_keys() -> None:
    src = ROOT / "qeli" / "src" / "config" / "server_ini.rs"
    if not src.exists():
        fail("config", f"{src.relative_to(ROOT)} not found — cannot verify key coverage")
        return
    src_text = src.read_text(encoding="utf-8", errors="replace")
    keys = set(KEY_RE.findall(src_text)) - CONFIG_KEY_ALLOWLIST
    if not keys:
        fail("config", "no INI keys extracted — the extractor pattern probably drifted")
        return
    # `pool.reservation.<user>` etc. — the stem is what the reference can document.
    prefixes = {p for p in PREFIX_KEY_RE.findall(src_text) if p}
    client_keys = _client_keys()

    for lang in LANGS:
        cfg = ROOT / "docs" / lang / "manuals" / "CONFIG.md"
        if not cfg.exists():
            fail("config", f"docs/{lang}/manuals/CONFIG.md is missing")
            continue
        body = cfg.read_text(encoding="utf-8", errors="replace")
        for k in sorted(k for k in keys if not _documented(body, k)):
            fail("config", f"key '{k}' is emitted by the server but absent from docs/{lang}/manuals/CONFIG.md")
        for p in sorted(p for p in prefixes if f"{p}." not in body):
            fail(
                "config",
                f"dynamic key prefix '{p}.<…>' is emitted by the server but absent "
                f"from docs/{lang}/manuals/CONFIG.md",
            )
        # Client keys are short, generic words (`key`, `mode`, `dev`, `user`) that a bare
        # substring search would find anywhere in a 1300-line reference, making the check
        # vacuous. Require the key as a backticked token — which is how CONFIG.md's
        # `[qeli]` reference table writes them anyway.
        for k in sorted(k for k in client_keys if f"`{k}`" not in body):
            fail(
                "config",
                f"client key '[qeli] {k}' is read by client.rs but absent "
                f"from docs/{lang}/manuals/CONFIG.md",
            )


# A GitHub URL whose OWNER slot is still a `<placeholder>`. The repo owner is a constant,
# so such a URL is an unfilled template, not something the reader substitutes — and it sits
# in a fenced code block, where the Markdown link check never looks. Deliberate redactions
# (YOUR_PROD_HOST) and reader-supplied values (<bind>, <port>) are a different thing and
# stay out of this pattern: it only fires on the owner position.
PLACEHOLDER_URL_RE = re.compile(r"(?:raw\.)?github(?:usercontent)?\.com/<[^>]+>")


def check_placeholder_urls(files: list[Path]) -> None:
    for f in files:
        for m in PLACEHOLDER_URL_RE.findall(f.read_text(encoding="utf-8", errors="replace")):
            fail(
                "placeholder",
                f"{f.relative_to(ROOT).as_posix()} has an unfilled repo owner in `{m}`",
            )


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
    try:
        proc = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=False
        )
    except OSError as e:
        raise SystemExit(
            f"cannot run git ({e}) — refusing to validate source references against "
            "an unknown committed tree"
        )
    if proc.returncode != 0:
        raise SystemExit(
            "git ls-files failed while validating source references "
            f"(exit {proc.returncode}): {proc.stderr.strip() or 'no stderr'}"
        )
    tracked = {line.strip() for line in proc.stdout.splitlines() if line.strip()}

    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        if any(s in rel for s in SRC_REF_SKIP):
            continue
        for ref in SRC_REF_RE.findall(f.read_text(encoding="utf-8", errors="replace")):
            # `qeli-android/.../QeliService.kt` — deliberate elision, not a real path.
            if "/.../" in ref:
                continue
            source_exists = (ROOT / ref).exists()
            if ref not in tracked and (rel in tracked or not source_exists):
                state = (
                    "missing from the tracked Git tree"
                    if rel in tracked
                    else "does not exist"
                )
                fail("source", f"{rel} points at `{ref}`, which {state}")


SOURCE_LINE_ANCHOR_RE = re.compile(
    r"(?:"
    r"\]\([^)]*\.(?:rs|cs|kt|swift)#L\d+(?:-L\d+)?\)"
    r"|"
    r"\[(?:[^\]\r\n]*\.(?:rs|cs|kt|swift):\d+(?:-\d+)?|:\d+(?:-\d+)?)\]"
    r"\([^)]*\.(?:rs|cs|kt|swift)\)"
    r")"
)


def check_source_line_anchors(files: list[Path]) -> None:
    """Active docs link to symbols/files, never to refactor-fragile line numbers."""
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        if any(s in rel for s in SRC_REF_SKIP):
            continue
        body = f.read_text(encoding="utf-8", errors="replace")
        if SOURCE_LINE_ANCHOR_RE.search(body):
            fail("anchors", f"{rel} contains a refactor-fragile source line anchor")


NORMATIVE_SYNC_DOCS = (
    "plans/ROAMING.md",
    "reports/AUDIT.md",
    "reference/THREAT-MODEL.md",
)
NORMATIVE_SYNC_RE = re.compile(r"<!--\s*normative-sync:\s*([a-z0-9._-]+)\s*-->")


def check_normative_sync() -> None:
    """Safety-sensitive RU/EN pairs must declare the same review revision."""
    for name in NORMATIVE_SYNC_DOCS:
        revisions: dict[str, str] = {}
        for lang in LANGS:
            path = ROOT / "docs" / lang / name
            if not path.exists():
                continue
            matches = NORMATIVE_SYNC_RE.findall(path.read_text(encoding="utf-8"))
            if len(matches) != 1:
                fail("sync", f"docs/{lang}/{name} must contain exactly one normative-sync marker")
                continue
            revisions[lang] = matches[0]
        if len(revisions) == len(LANGS) and len(set(revisions.values())) != 1:
            fail("sync", f"{name} RU/EN revisions differ: {revisions}")


CARGO_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.M)


def check_version() -> None:
    """The CHANGELOG must identify the next public release.

    A development build number need not become a public release number: the
    0.7.17 development tree is intentionally scheduled as 0.8.0. Every other
    version string in the repo (build files, overview READMEs, documentation
    status banners) is owned by
    `scripts/sync_version.py`, which can also stamp them. Checking them here too
    would be a second, weaker implementation of the same rule."""
    cargo = ROOT / "qeli" / "Cargo.toml"
    if not cargo.exists():
        fail("version", "qeli/Cargo.toml not found")
        return
    m = CARGO_VERSION_RE.search(cargo.read_text(encoding="utf-8", errors="replace"))
    if not m:
        fail("version", "no [package] version in qeli/Cargo.toml")
        return
    version = m.group(1)

    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        fail("version", "CHANGELOG.md not found")
        return
    body = changelog.read_text(encoding="utf-8", errors="replace")
    planned_match = re.search(
        r"^## \[([0-9]+\.[0-9]+\.[0-9]+)\]\s+[—-]\s+не выпущен\s*$",
        body,
        re.M | re.I,
    )
    if not planned_match:
        fail("version", "CHANGELOG.md has no numeric unreleased release heading")
        return
    planned = planned_match.group(1)
    try:
        dev_tuple = tuple(int(part) for part in version.split("."))
        planned_tuple = tuple(int(part) for part in planned.split("."))
    except ValueError:
        fail("version", f"development/planned version is not numeric SemVer: {version}/{planned}")
        return
    if len(dev_tuple) != 3 or len(planned_tuple) != 3:
        fail("version", f"development/planned version is not three-part SemVer: {version}/{planned}")
    elif planned_tuple < dev_tuple:
        fail("version", f"planned release {planned} is older than development build {version}")


def main() -> int:
    files = tracked_markdown()
    print(f"checking {len(files)} tracked Markdown files…")
    check_links(files)
    check_index_coverage()
    check_parity()
    check_config_keys()
    check_source_refs(files)
    check_placeholder_urls(files)
    check_source_line_anchors(files)
    check_normative_sync()
    check_version()

    if not failures:
        print(
            "OK — all 9 checks pass (links, index, parity, config keys "
            "[server + client + prefixes], sources, placeholders, anchors, sync, version)."
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
