"""Validate Docker release refs before login/build/push; branches publish SHA only."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SEMVER = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def classify(ref_type, ref_name):
    if ref_type == "branch":
        if not ref_name:
            raise ValueError("empty branch ref")
        return {"release_tag": "false", "stable_release": "false"}
    if ref_type != "tag":
        raise ValueError("Docker publication requires a branch or tag")
    match = SEMVER.fullmatch(ref_name)
    if not match or (match[4] and any(part.isdecimal() and len(part) > 1 and part[0] == "0" for part in match[4].split("."))):
        raise ValueError("Docker release tag must be vMAJOR.MINOR.PATCH with valid SemVer suffixes")
    return {"release_tag": "true", "stable_release": str(match[4] is None).lower()}


def publication_outputs(root, ref_type, ref_name):
    outputs = classify(ref_type, ref_name)
    outputs["latest_release"] = "false"
    if outputs["stable_release"] != "true":
        return outputs

    def git(*args):
        result = subprocess.run(["git", *args], cwd=root, capture_output=True,
                                text=True, encoding="utf8", errors="strict", timeout=30)
        if result.returncode:
            raise ValueError(result.stderr.strip() or "Docker release tag inventory failed")
        return result.stdout.strip()

    if git("rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("Docker latest selection requires complete Git history and tags")
    tags = git("for-each-ref", "--format=%(refname:strip=2)", "refs/tags").splitlines()
    if ref_name not in tags:
        raise ValueError("Docker publication tag is missing from the Git inventory")
    candidate = tuple(int(part) for part in SEMVER.fullmatch(ref_name).group(1, 2, 3))
    for tag in tags:
        try:
            stable = classify("tag", tag)["stable_release"] == "true"
        except ValueError:
            continue  # Unrelated/invalid tags cannot define the stable release channel.
        if stable and tuple(int(part) for part in SEMVER.fullmatch(tag).group(1, 2, 3)) > candidate:
            return outputs
    outputs["latest_release"] = "true"
    return outputs


def published_stable_release(repository, tag):
    """A numeric tag alone cannot promote a GitHub beta/draft to latest."""
    if not repository:
        return False
    result = subprocess.run(
        ["gh", "release", "view", tag, "--repo", repository,
         "--json", "tagName,isDraft,isPrerelease"],
        capture_output=True, text=True, encoding="utf8", errors="strict", timeout=30)
    if result.returncode:
        # Tags may arrive before a release exists. Publish their version/SHA
        # images, but do not infer permission to change the stable channel.
        print("Docker latest withheld: published stable release not confirmed", file=sys.stderr)
        return False
    release = json.loads(result.stdout)
    return (release.get("tagName") == tag and release.get("isDraft") is False
            and release.get("isPrerelease") is False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--require-published-stable", action="store_true",
                        help="allow latest only for a published stable GitHub release")
    args = parser.parse_args(argv)
    try:
        outputs = publication_outputs(args.repo, os.environ["GITHUB_REF_TYPE"], os.environ["GITHUB_REF_NAME"])
        if (args.require_published_stable and outputs["latest_release"] == "true"
                and not published_stable_release(os.environ.get("GITHUB_REPOSITORY"),
                                                 os.environ["GITHUB_REF_NAME"])):
            outputs["latest_release"] = "false"
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf8", newline="\n") as stream:
            for key, value in outputs.items():
                stream.write(f"{key}={value}\n")
        return 0
    except (KeyError, OSError, ValueError, AttributeError, subprocess.SubprocessError) as error:
        print(f"Docker publication refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
