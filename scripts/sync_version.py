#!/usr/bin/env python3
"""Keep every version string in the repo in sync. Run from anywhere:

    python3 scripts/sync_version.py            # check only (CI / pre-release)
    python3 scripts/sync_version.py --write     # stamp the versions into every file

There are THREE versions in this repo and they are deliberately different:

  * the DEVELOPMENT version — what the tree currently builds. Source of truth:
    `qeli/Cargo.toml`. It is mirrored into the platform build files plus the two overview
    READMEs ("Rust 2021, version X").
  * the PLANNED version — the next public release. Source of truth: the first
    unreleased CHANGELOG heading. A development build may intentionally retain
    an older version number; for example the 0.7.17 development tree is released
    directly as 0.8.0, without a public 0.7.17 release.
  * the RELEASED version — the newest published package. Source of truth: the
    newest `v*` git tag. It is shown as the latest published release in the
    ten-document status banner and owns released download/attestation commands.

Bumping by hand means editing many files, which is how docs once ended up claiming
0.7.11 while the crate was already 0.7.12. Markdown on GitHub has no variable
substitution, so the only way to templatise this is to stamp at commit time —
which is what `--write` does.

Exit code 0 = everything agrees, 1 = something drifted (or was rewritten).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (path, regex with ONE capturing group around the version, human label).
# Each regex must match exactly the occurrences that carry the version — a group
# that is too greedy would rewrite unrelated strings, so they are anchored on the
# surrounding key rather than on the bare number.
DEV_TARGETS: list[tuple[str, str, str]] = [
    ("qeli/Cargo.lock", r'(?s)(?<=\[\[package\]\]\nname = "qeli"\nversion = ")([^"]+)', "crate lock"),
    ("qeli-android/app/build.gradle.kts", r'versionName\s*=\s*"([^"]+)"', "Android versionName"),
    ("qeli-mac/Info.plist.in", r"(?<=<key>CFBundleVersion</key>\n    <string>)([^<]+)", "macOS CFBundleVersion"),
    ("qeli-mac/Info.plist.in", r"(?<=<key>CFBundleShortVersionString</key>\n    <string>)([^<]+)", "macOS CFBundleShortVersionString"),
    ("qeli-mac/QeliMac/QeliMac.csproj", r"<Version>([^<]+)</Version>", "macOS csproj"),
    (
        "qeli-mac/per-app/project.yml",
        r"MARKETING_VERSION:\s*(\S+)",
        "macOS per-app MARKETING_VERSION",
    ),
    ("qeli-win/QeliWin/QeliWin.csproj", r"<Version>([^<]+)</Version>", "Windows csproj"),
    ("qeli-shared/QeliShared/QeliShared.csproj", r"<Version>([^<]+)</Version>", "shared csproj"),
    # iOS keeps both numbers in project.yml; the plists only reference the variables.
    ("qeli-ios/project.yml", r"MARKETING_VERSION:\s*(\S+)", "iOS MARKETING_VERSION"),
    # …and AppConstants carries a FALLBACK used when the bundle has no version (unit tests, a
    # stripped host). It is a literal, so it drifts silently: it read 0.7.13 while project.yml
    # said 0.7.14, and this script reported everything in sync because it never looked here.
    # (Audit 2026-07-31, §12.)
    (
        "qeli-ios/QeliCore/AppConstants.swift",
        r'fallbackVersion = "([^"]+)"',
        "iOS fallback version",
    ),
    ("qeli-openwrt/Makefile", r"PKG_VERSION:=(\S+)", "OpenWrt package"),
    ("qeli-openwrt/luci-app-qeli/Makefile", r"PKG_VERSION:=(\S+)", "LuCI package"),
    ("qeli/debian/control", r"^Version: (\S+)", "deb control"),
    ("docs/ru/README.md", r"Rust 2021, версия (\S+) \(бета\)", "overview README (ru)"),
    ("docs/eng/README.md", r"Rust 2021, version (\S+) \(beta\)", "overview README (eng)"),
]

# The Win32 side-by-side manifest carries the SAME development version, but the
# assemblyIdentity schema demands FOUR fields (X.Y.Z.B) — it cannot hold the 3-part
# string every other file uses, which is why it was never added to DEV_TARGETS above.
# The result was a file nothing checked: it sat at 0.7.11.0 while the whole tree said
# 0.7.13 and this very gate reported "everything agrees". (Audit 2026-07-27, G4)
WIN_MANIFEST_TARGETS: list[tuple[str, str, str]] = [
    ("qeli-win/QeliWin/app.manifest", r'<assemblyIdentity version="([^"]+)"', "Windows app.manifest"),
]

# The signed macOS per-app extension uses a numeric CFBundleVersion derived from SemVer.
# 0.7.15 -> 715, 0.7.16 -> 716, and 1.0.0 -> 10000.
MAC_PER_APP_BUILD_TARGETS: list[tuple[str, str, str]] = [
    (
        "qeli-mac/per-app/project.yml",
        r"CURRENT_PROJECT_VERSION:\s*(\S+)",
        "macOS per-app build number",
    ),
]

# The documentation status banner. It names the development tree, planned public
# release, and latest published package independently. Collapsing these values was
# the reason unreleased IPv6 material looked as if it belonged to stable 0.7.16.
BANNER_DOCS = ("CONFIG", "GETTING-STARTED", "PANEL", "TROUBLESHOOTING", "OPERATIONS")
BANNER_RE = {
    "ru": {
        "dev": r"текущая ветка разработки \*\*([^*]+)\*\*",
        "planned": r"планируемый full-IPv6 релиз \*\*([^*]+)\*\*",
        "released": r"последний опубликованный релиз \*\*([^*]+)\*\*",
    },
    "eng": {
        "dev": r"current development tree \*\*([^*]+)\*\*",
        "planned": r"planned full-IPv6 release \*\*([^*]+)\*\*",
        "released": r"latest published release \*\*([^*]+)\*\*",
    },
}

# Commands that fetch or verify a released package must track the same release as the docs
# banner. Checking only the banner let a 0.7.14 guide keep installing/attesting 0.7.13.
RELEASE_ARTIFACT_TARGETS: list[tuple[str, str, str]] = [
    (
        "docs/eng/GETTING-STARTED.md",
        r"releases/download/v([0-9]+\.[0-9]+\.[0-9]+)/",
        "release download URL (eng)",
    ),
    (
        "docs/ru/GETTING-STARTED.md",
        r"releases/download/v([0-9]+\.[0-9]+\.[0-9]+)/",
        "release download URL (ru)",
    ),
    (
        "docs/eng/GETTING-STARTED.md",
        r"qeli_([0-9]+\.[0-9]+\.[0-9]+)_amd64\.deb",
        "release package commands (eng)",
    ),
    (
        "docs/ru/GETTING-STARTED.md",
        r"qeli_([0-9]+\.[0-9]+\.[0-9]+)_amd64\.deb",
        "release package commands (ru)",
    ),
    (
        "docs/eng/OPERATIONS.md",
        r"qeli_([0-9]+\.[0-9]+\.[0-9]+)_amd64\.deb",
        "release attestation command (eng)",
    ),
    (
        "docs/ru/OPERATIONS.md",
        r"qeli_([0-9]+\.[0-9]+\.[0-9]+)_amd64\.deb",
        "release attestation command (ru)",
    ),
]

problems: list[str] = []


def released_version() -> str | None:
    """Newest `v*` tag, without the `v`. Tags are what a release actually is."""
    out = subprocess.run(
        ["git", "tag", "--sort=-v:refname", "--list", "v*"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    tags = [t.strip() for t in out.stdout.splitlines() if t.strip()]
    return tags[0].lstrip("v") if tags else None


def dev_version() -> str | None:
    m = re.search(
        r'^version\s*=\s*"([^"]+)"',
        (ROOT / "qeli" / "Cargo.toml").read_text(encoding="utf-8"),
        re.M,
    )
    return m.group(1) if m else None


def planned_version() -> str | None:
    """First unreleased CHANGELOG heading, without brackets."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        r"^## \[([0-9]+\.[0-9]+\.[0-9]+)\]\s+[—-]\s+не выпущен\s*$",
        text,
        re.M | re.I,
    )
    return match.group(1) if match else None


def tagged_file(version: str, path: str) -> str | None:
    """Read one tracked file from a release tag without checking it out."""
    out = subprocess.run(
        ["git", "show", f"v{version}:{path}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout if out.returncode == 0 else None


def apply(targets: list[tuple[str, str, str]], want: str, write: bool) -> None:
    """Check (or rewrite) every occurrence the regexes select."""
    for rel, pattern, label in targets:
        path = ROOT / rel
        if not path.exists():
            problems.append(f"{rel}: missing — cannot carry the version ({label})")
            continue
        # Normalise line endings for matching (patterns embed plain \n), but remember
        # what the file actually uses so --write can put them back byte-for-byte.
        raw = path.read_bytes()
        newline = "\r\n" if b"\r\n" in raw else "\n"
        text = raw.decode("utf-8").replace("\r\n", "\n")
        found = re.findall(pattern, text, re.M)
        if not found:
            # A silently unmatched pattern is worse than a mismatch: it would let a
            # file drift forever while the script reports success.
            problems.append(f"{rel}: pattern for {label} matched nothing — it needs updating")
            continue
        stale = [v for v in found if v != want]
        if not stale:
            continue
        if write:
            # Replace ONLY the captured group, keeping the syntax around it. A plain
            # re.sub(pattern, want, ...) substitutes the whole match, which turns
            # `versionName = "0.7.13"` into a bare `0.7.13` and breaks the build file.
            def swap(m: re.Match[str]) -> str:
                whole, base = m.group(0), m.start()
                return whole[: m.start(1) - base] + want + whole[m.end(1) - base :]

            new = re.sub(pattern, swap, text, flags=re.M)
            with open(path, "w", encoding="utf-8", newline=newline) as fh:
                fh.write(new)
            print(f"  stamped {want:>8}  {rel}  ({label}, was {', '.join(sorted(set(stale)))})")
        else:
            problems.append(f"{rel}: {label} is {', '.join(sorted(set(stale)))}, expected {want}")


def apply_release_artifacts(write: bool) -> None:
    """Keep every package command equal to the banner in its own document.

    The banner may legitimately name either the latest tag or the version currently being
    cut. Accepting both values independently for package commands would still allow a 0.7.14
    banner to point at a nonexistent 0.7.15 artifact, so the relationship is checked directly.
    """
    for target in RELEASE_ARTIFACT_TARGETS:
        rel = target[0]
        lang = "ru" if rel.startswith("docs/ru/") else "eng"
        path = ROOT / rel
        if not path.exists():
            # apply() reports the missing artifact target; avoid a duplicate diagnostic here.
            apply([target], "<missing-banner>", write)
            continue
        text = path.read_text(encoding="utf-8")
        banner = re.search(BANNER_RE[lang]["released"], text, re.M)
        if banner is None:
            problems.append(f"{rel}: cannot match release artifacts to a missing docs banner")
            continue
        apply([target], banner.group(1), write)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="rewrite the files instead of only checking")
    ap.add_argument(
        "--releasing", action="store_true",
        help="stamp the published-release field with the planned release instead of the "
             "newest tag — use just before tagging, after qeli/Cargo.toml has been bumped "
             "to the planned version",
    )
    args = ap.parse_args()

    dev = dev_version()
    planned = planned_version()
    rel = released_version()
    if not dev:
        print("cannot read the version from qeli/Cargo.toml", file=sys.stderr)
        return 1
    if not rel:
        print("no v* git tag found — cannot tell which version is released", file=sys.stderr)
        return 1
    if not planned:
        print("cannot read the planned release from CHANGELOG.md", file=sys.stderr)
        return 1
    print(
        f"development version {dev} (qeli/Cargo.toml) · "
        f"planned release {planned} (CHANGELOG.md) · "
        f"released version {rel} (newest v* tag)"
    )
    if args.releasing and dev != planned:
        print(
            f"refusing release mode: development binaries still identify as {dev}, "
            f"but the planned public release is {planned}; bump qeli/Cargo.toml to "
            f"{planned} and run --write --releasing again",
            file=sys.stderr,
        )
        return 1
    if args.write:
        print("writing:")

    apply(DEV_TARGETS, dev, args.write)
    # Same version, four-field form (the fourth field is the manifest build number and
    # is not used by anything here, so it stays 0). See WIN_MANIFEST_TARGETS.
    apply(WIN_MANIFEST_TARGETS, f"{dev}.0", args.write)

    semver = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", dev)
    if semver:
        major, minor, patch = (int(part) for part in semver.groups())
        mac_per_app_build = str(major * 10000 + minor * 100 + patch)
        apply(MAC_PER_APP_BUILD_TARGETS, mac_per_app_build, args.write)
    else:
        problems.append(f"development version {dev!r} is not three-part numeric SemVer")

    planned_semver = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", planned)
    if planned_semver and semver:
        if tuple(map(int, planned_semver.groups())) < tuple(map(int, semver.groups())):
            problems.append(
                f"planned release {planned} is older than development version {dev}"
            )
    else:
        problems.append(f"planned release {planned!r} is not three-part numeric SemVer")

    # Build numbers are monotonic counters, not a function of the version, so they are
    # not derived from Cargo.toml. But iOS and Android have always been released as a
    # pair (both 715 at 0.7.12), and iOS is the one that gets forgotten because nothing
    # ships from it — so Android's counter is the source and iOS must match it.
    gradle = ROOT / "qeli-android" / "app" / "build.gradle.kts"
    if gradle.exists():
        vc = re.search(r"versionCode\s*=\s*(\d+)", gradle.read_text(encoding="utf-8"))
        if vc:
            # Keeping Android and iOS equal is insufficient: both counters must also remain
            # strictly above the package already published by the latest release tag.
            android_build = int(vc.group(1))
            released_gradle = tagged_file(rel, "qeli-android/app/build.gradle.kts")
            released_vc = (
                re.search(r"versionCode\s*=\s*(\d+)", released_gradle)
                if released_gradle is not None
                else None
            )
            minimum_build: int | None = None
            if released_vc is None:
                problems.append(
                    f"v{rel}: cannot read Android versionCode from the latest release tag"
                )
            else:
                released_build = int(released_vc.group(1))
                minimum_build = released_build + int(dev != rel)
            if minimum_build is not None and android_build < minimum_build:
                if args.write:
                    next_build = str(minimum_build)
                    apply(
                        [
                            (
                                "qeli-android/app/build.gradle.kts",
                                r"versionCode\s*=\s*(\d+)",
                                "Android monotonic versionCode",
                            )
                        ],
                        next_build,
                        True,
                    )
                    android_build = int(next_build)
                else:
                    relation = "greater than" if dev != rel else "at least"
                    problems.append(
                        "qeli-android/app/build.gradle.kts: versionCode "
                        f"{android_build} must be {relation} released v{rel} build "
                        f"{released_vc.group(1)}"
                    )
            apply(
                [
                    ("qeli-ios/project.yml", r"CURRENT_PROJECT_VERSION:\s*(\S+)", "iOS build number"),
                    # The literal fallback next to fallbackVersion, for the same reason: it is
                    # used when the bundle has none and drifts silently otherwise.
                    (
                        "qeli-ios/QeliCore/AppConstants.swift",
                        r'fallbackBuild = "([^"]+)"',
                        "iOS fallback build",
                    ),
                ],
                str(android_build),
                args.write,
            )
    def banners(field: str) -> list[tuple[str, str, str]]:
        return [
            (
                f"docs/{lang}/{doc}.md",
                BANNER_RE[lang][field],
                f"docs banner {field} ({lang})",
            )
            for lang in ("ru", "eng")
            for doc in BANNER_DOCS
        ]

    # Immediately before tagging, the "latest published release" field and package
    # commands are intentionally staged to the release being cut. At all other times
    # they remain tied to the newest existing tag.
    apply(banners("dev"), dev, args.write)
    apply(banners("planned"), planned, args.write)
    apply(banners("released"), planned if args.releasing else rel, args.write)
    apply_release_artifacts(args.write)

    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print("  " + p)
        print("\nRun `python3 scripts/sync_version.py --write` to stamp them.")
        return 1
    print("OK — every version string agrees with its source of truth.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
