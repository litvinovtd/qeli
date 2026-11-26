"""Admit one published Beta whose immutable tag predates the guide-only fix."""
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from release_source import source_identity

REPO = "litvinovtd/qeli"
TAG = "v0.8.5"
VERSION = "0.8.5"
SOURCE = "c316e26af7a1811271a50decb4c60fd547cd0975"
TAG_OBJECT = "be718bca39dc7f4b30fd01b7513f597bb33d241f"
RELEASE_ID = 459305616
CI_WORKFLOW = 290889678
QUALIFYING_RUN = 45802621756
ROOT = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(root, *args):
    result = subprocess.run(args, cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=45)
    if result.returncode:
        raise ValueError((result.stdout + result.stderr).strip() or f"{args[0]} failed")
    return result.stdout.strip()


def github(root, endpoint):
    return json.loads(command(root, "gh", "api", f"repos/{REPO}/{endpoint}"))


def require_unpublished_version():
    registry = "https://ghcr.io"
    query = urlencode({"scope": f"repository:{REPO}:pull", "service": "ghcr.io"})
    with urlopen(f"{registry}/token?{query}", timeout=15) as response:
        token = json.load(response)["token"]
    request = Request(f"{registry}/v2/{REPO}/manifests/{VERSION}", method="HEAD", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json",
    })
    try:
        with urlopen(request, timeout=15):
            raise ValueError("version already exists in GHCR; refusing to overwrite")
    except HTTPError as error:
        if error.code != 404:
            raise


def check_jobs(payload, *, docs_failure):
    jobs = payload["jobs"]
    require(len(jobs) == payload["total_count"] and bool(jobs), "CI jobs missing or truncated")
    require(all(j["head_sha"] == SOURCE and j["status"] == "completed" for j in jobs),
            "CI jobs not complete on the release commit")
    bad = [j for j in jobs if j["conclusion"] not in ("success", "skipped")]
    require(len(bad) == int(docs_failure), "CI has unexpected failed jobs")
    if bad:
        job = bad[0]
        require(job["name"] == "docs" and job["conclusion"] == "failure", "CI failed outside docs")
        require([(s["name"], s["conclusion"]) for s in job["steps"]
                 if s["conclusion"] not in ("success", "skipped")] == [("version consistency", "failure")],
                "docs failed outside the version consistency check")
    else:
        require(any(j["name"] == "docs" and j["conclusion"] == "success" for j in jobs),
                "qualifying CI did not pass docs")


def admit(root, env):
    require((env.get("GITHUB_REPOSITORY"), env.get("GITHUB_EVENT_NAME"), env.get("GITHUB_REF")) ==
            (REPO, "workflow_dispatch", "refs/heads/dev"), "recovery requires manual dispatch on upstream dev")
    workflow_source = source_identity(root)
    require(workflow_source == env.get("GITHUB_SHA"), "workflow checkout drifted")
    target = f"refs/tags/{TAG}"
    require(command(root, "git", "rev-parse", target, f"{target}^{{commit}}").splitlines() == [TAG_OBJECT, SOURCE],
            "published tag is not the approved annotated tag/commit")
    command(root, "git", "merge-base", "--is-ancestor", SOURCE, workflow_source)
    release = github(root, f"releases/{RELEASE_ID}")
    require(release["tag_name"] == TAG and release["target_commitish"] == SOURCE and
            release["draft"] is False and release["prerelease"] is True and bool(release["published_at"]),
            "release is not the approved published Beta")

    # Ordinary tag publishes still require the newest exact CI. This recovery
    # separately rechecks the corrected guides, the green pre-tag CI on the very
    # same release commit, and every later CI on that commit for unrelated failures.
    print(command(root, sys.executable, "-B", "scripts/sync_version.py", "--releasing"), flush=True)
    runs = github(root, f"actions/workflows/{CI_WORKFLOW}/runs?head_sha={SOURCE}&per_page=100")
    require(len(runs["workflow_runs"]) == runs["total_count"], "CI runs missing or truncated")
    qualified = [r for r in runs["workflow_runs"] if r["id"] == QUALIFYING_RUN]
    require(len(qualified) == 1, "qualified CI run missing")
    for run in runs["workflow_runs"]:
        cid = run["id"]
        require(run["head_sha"] == SOURCE and run["workflow_id"] == CI_WORKFLOW and run["status"] == "completed",
                f"CI {cid} is not completed on the exact release commit")
        if cid == QUALIFYING_RUN:
            require((run["event"], run["head_branch"], run["conclusion"]) == ("push", "dev", "success"),
                    "pre-tag qualification is not a successful dev push CI")
        require(run["conclusion"] in ("success", "failure"), f"CI {cid} has unexpected result")
        check_jobs(github(root, f"actions/runs/{cid}/jobs?filter=latest&per_page=100"),
                   docs_failure=run["conclusion"] == "failure")
        print(f"CI {cid}: {run['conclusion']} (exact {SOURCE})", flush=True)

    require(source_identity(root) == workflow_source, "workflow checkout changed during checks")
    require_unpublished_version()
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"source={SOURCE}\nversion={VERSION}\n")


if __name__ == "__main__":
    try:
        admit(ROOT, os.environ)
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        sys.exit(f"Docker Beta recovery refused: {exc}")
