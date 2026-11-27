"""Reconcile Docker latest with the highest eligible, attested GitHub release."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from docker_publish_ref import SEMVER, classify

REPO = "litvinovtd/qeli"
REGISTRY = "https://ghcr.io"
IMAGE = f"ghcr.io/{REPO}"
SIGNER = f"{REPO}/.github/workflows/docker-publish.yml"
REQUIRED_PLATFORMS = {("linux", "amd64", ""), ("linux", "arm64", ""), ("linux", "arm", "v7")}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ACCEPT = ("application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
          "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
# v0.8.5 is an immutable exception: the verified recovery was signed by the
# dev workflow, while its build context and OCI revision were the release tag.
RECOVERED = ("v0.8.5", "c316e26af7a1811271a50decb4c60fd547cd0975",
             "sha256:06b3a38bd731dce58224a99fa4fb2050d6941f6cdbf199428374d4d6cc60a7e3")
RECOVERY_WORKFLOW_SHA = "99dac49783d409194718ffad31ea3c69c8b84cc6"


def semver_key(tag):
    classify("tag", tag)
    parsed = SEMVER.fullmatch(tag)
    pre = parsed[4]
    return (tuple(int(parsed[i]) for i in (1, 2, 3)), pre is None, tuple(
        (0, int(part)) if part.isdecimal() else (1, part) for part in pre.split(".") if part
    ) if pre else ())


def latest_release(rows):
    """Drafts never count. Once a stable release exists, it owns the channel."""
    candidates = []
    for row in rows:
        if row["draft"] is True or not row["published_at"]:
            continue
        if row["draft"] is not False or type(row["prerelease"]) is not bool:
            raise ValueError("invalid GitHub release record")
        tag = row["tag_name"]
        key = semver_key(tag)
        # A suffix such as -rc.1 is not stable, even if the UI flag is wrong.
        stable = not row["prerelease"] and key[1]
        candidates.append((stable, key, tag))
    if not candidates:
        return None
    best = max(candidates)
    if sum(row[:2] == best[:2] for row in candidates) != 1:
        raise ValueError("multiple releases share the newest SemVer precedence")
    return best[2]


def command(*args, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    if result.returncode:
        raise ValueError((result.stderr or result.stdout).strip() or f"{args[0]} failed")
    return result.stdout.strip()


def published_latest():
    pages = json.loads(command("gh", "api", "--paginate", "--slurp", f"repos/{REPO}/releases?per_page=100"))
    if not isinstance(pages, list) or not pages or not all(isinstance(page, list) for page in pages):
        raise ValueError("invalid GitHub release inventory")
    return latest_release(row for page in pages for row in page)


class Registry:
    def __init__(self):
        query = urlencode({"scope": f"repository:{REPO}:pull", "service": "ghcr.io"})
        with urlopen(f"{REGISTRY}/token?{query}", timeout=20) as response:
            self.token = json.load(response)["token"]

    def get(self, kind, ref, *, missing=False):
        request = Request(f"{REGISTRY}/v2/{REPO}/{kind}/{ref}", headers={
            "Authorization": f"Bearer {self.token}", "Accept": ACCEPT, "User-Agent": "qeli-latest-publisher",
        })
        try:
            with urlopen(request, timeout=20) as response:
                body = response.read(1048577)
                header = response.headers.get("Docker-Content-Digest")
        except HTTPError as error:
            if missing and error.code == 404:
                return None, None
            raise
        computed = "sha256:" + hashlib.sha256(body).hexdigest()
        expected = ref if DIGEST.fullmatch(ref) else header
        if len(body) > 1048576 or computed != expected:
            raise ValueError("unverified or oversized OCI metadata")
        return computed, json.loads(body)


def verify_platforms(registry, index, commit, version):
    seen = set()
    for descriptor in index["manifests"]:
        platform = descriptor["platform"]
        system, arch = platform["os"], platform["architecture"]
        if (system, arch) == ("unknown", "unknown"):
            if descriptor.get("annotations", {}).get("vnd.docker.reference.type") != "attestation-manifest":
                raise ValueError("unexpected unknown OCI platform")
            continue
        key = (system, arch, platform.get("variant", "") if arch == "arm" else "")
        if key not in REQUIRED_PLATFORMS or key in seen:
            raise ValueError(f"unexpected/duplicate OCI platform {key}")
        seen.add(key)
        _, manifest = registry.get("manifests", descriptor["digest"])
        _, config = registry.get("blobs", manifest["config"]["digest"])
        labels = config["config"]["Labels"]
        if ((config["os"], config["architecture"]) != (system, arch) or
                labels.get("org.opencontainers.image.revision") != commit or
                labels.get("org.opencontainers.image.version") != version):
            raise ValueError(f"OCI config does not match release {version}/{commit} on {key}")
    if seen != REQUIRED_PLATFORMS:
        raise ValueError("missing required OCI platform")


def attestation_identity(tag, source, digest):
    if (tag, source, digest) == RECOVERED:
        return "refs/heads/dev", RECOVERY_WORKFLOW_SHA
    return f"refs/tags/{tag}", source


def promote(requested, build_digest, mode):
    chosen = published_latest()
    if not chosen or (mode == "manual" and requested and chosen != requested):
        print(f"latest unchanged: eligible release is {chosen!r}, not {requested!r}")
        if mode == "manual":
            raise ValueError("no matching published release")
        return

    release_ref = f"refs/tags/{chosen}"
    source = command("git", "rev-parse", "--verify", release_ref + "^{commit}")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("invalid exact release commit")
    version = tomllib.loads(command("git", "show", f"{source}:qeli/Cargo.toml"))["package"]["version"]
    if chosen != "v" + version or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", version):
        raise ValueError("release tag and Docker version must identify the same published package")

    registry = Registry()
    own_build = mode == "build" and requested == chosen
    can_defer = mode != "manual" and not own_build
    digest, index = registry.get("manifests", version, missing=can_defer)
    if not digest:
        print(f"latest unchanged: {version} is not built yet; its tag build will reconcile after smoke and attestation")
        return
    if own_build and build_digest != digest:
        raise ValueError("version tag does not match the just-verified build digest")
    verify_platforms(registry, index, source, version)
    ref, signed_source = attestation_identity(chosen, source, digest)
    try:
        command("gh", "attestation", "verify", f"oci://{IMAGE}@{digest}", "--repo", REPO,
                "--signer-workflow", SIGNER, "--source-ref", ref, "--source-digest", signed_source, timeout=90)
    except ValueError as error:
        if not can_defer:
            raise
        print(f"latest unchanged: {version} is not attested yet; its tag build will reconcile: {error}")
        return
    print(f"Verified signed image {version} {digest} on all three platforms (source {source})", flush=True)

    # Selection is checked again after the remote signature verification. All
    # promotion jobs in this workflow also share one concurrency group.
    if published_latest() != chosen or registry.get("manifests", version)[0] != digest:
        raise ValueError("publication inputs changed; refusing to move latest")
    old, _ = registry.get("manifests", "latest", missing=True)
    if old != digest:
        command("docker", "buildx", "imagetools", "create", "--tag", f"{IMAGE}:latest", f"{IMAGE}@{digest}")
    actual, _ = registry.get("manifests", "latest")
    if actual != digest:
        raise ValueError("GHCR latest does not match the verified digest")
    print(f"latest: {old} -> {actual} ({version})", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default="")
    parser.add_argument("--digest", default="")
    parser.add_argument("--mode", choices=("manual", "release", "build"), required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_REPOSITORY") != REPO:
        sys.exit("Docker latest promotion requires the upstream repository")
    if args.tag:
        semver_key(args.tag)
    if args.mode == "build" and (not args.tag or not DIGEST.fullmatch(args.digest)):
        sys.exit("build reconciliation requires the release tag and verified digest")
    try:
        promote(args.tag, args.digest, args.mode)
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Docker latest promotion refused: {error}")


if __name__ == "__main__":
    main()
