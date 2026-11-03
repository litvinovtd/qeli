#!/usr/bin/env python3
"""Audit every locked Android Maven graph against OSV; errors fail closed."""
from __future__ import annotations

import argparse
import datetime
import json
import sys
import urllib.request
from pathlib import Path

LOCKS = ("buildscript-gradle.lockfile", "app/buildscript-gradle.lockfile", "app/gradle.lockfile")
API = "https://api.osv.dev/v1/querybatch"


def inventory(android: Path) -> list[dict]:
    rows = {}
    for name in LOCKS:
        text = (android / name).read_text(encoding="utf-8")
        for line in text.splitlines():
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coordinate, separator, configurations = line.partition("=")
            fields = coordinate.split(":")
            if not separator or len(fields) != 3 or not all(fields) or not configurations:
                raise ValueError(f"Malformed lock entry in {name}: {line}")
            group, artifact, version = fields
            if "+" in version or version.startswith("latest.") or version.endswith("-SNAPSHOT"):
                raise ValueError(f"Non-release version in {name}: {coordinate}")
            key = (group + ":" + artifact, version)
            row = rows.setdefault(key, {"name": key[0], "version": version, "uses": []})
            row["uses"].append({"lock": name, "configurations": configurations.split(",")})
    if not rows:
        raise ValueError("No Maven dependencies found in Android locks")
    return [rows[key] for key in sorted(rows)]


def check_security_pins(android: Path, rows: list[dict]) -> None:
    pins = {}
    for line in (android / "gradle/security-versions.properties").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, version = line.partition("=")
        if not separator or key.count("/") != 1 or not version or key in pins:
            raise ValueError(f"Malformed or duplicate security pin: {line}")
        pins[key] = version
    if not pins:
        raise ValueError("Empty Android security version policy")
    found = set()
    for row in rows:
        key = row["name"].replace(":", "/")
        if key in pins:
            found.add(key)
            if row["version"] != pins[key]:
                raise ValueError(f"Security pin drift: {row['name']} {row['version']} != {pins[key]}")
    if set(pins) != found:
        raise ValueError("Security pins absent from locks: " + ", ".join(sorted(set(pins) - found)))


def request(payload: dict) -> dict:
    req = urllib.request.Request(API, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json", "User-Agent": "Qeli Maven audit"})
    with urllib.request.urlopen(req, timeout=45) as response:
        body = response.read(8 * 1024 * 1024 + 1)
    if len(body) > 8 * 1024 * 1024:
        raise ValueError("OSV response exceeds 8 MiB")
    return json.loads(body)


def results(response: dict, count: int) -> list[dict]:
    values = response.get("results") if isinstance(response, dict) else None
    if not isinstance(values, list) or len(values) != count:
        raise ValueError("Incomplete OSV batch response")
    for value in values:
        if not isinstance(value, dict) or "error" in value:
            raise ValueError("Invalid OSV result")
        vulns = value.get("vulns", [])
        if not isinstance(vulns, list) or any(not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"] for v in vulns):
            raise ValueError("Invalid OSV advisory list")
        if "next_page_token" in value and (not isinstance(value["next_page_token"], str) or not value["next_page_token"]):
            raise ValueError("Invalid OSV page token")
    return values


def audit(rows: list[dict], query=request) -> dict:
    audited = []
    for offset in range(0, len(rows), 100):
        batch = rows[offset:offset + 100]
        queries = [{"package": {"ecosystem": "Maven", "name": row["name"]}, "version": row["version"]} for row in batch]
        for row, payload, value in zip(batch, queries, results(query({"queries": queries}), len(batch))):
            advisories = {v["id"] for v in value.get("vulns", [])}
            tokens = set()
            while token := value.get("next_page_token"):
                if token in tokens or len(tokens) >= 100:
                    raise ValueError("OSV pagination loop or excessive pages")
                tokens.add(token)
                value = results(query({"queries": [{**payload, "page_token": token}]}), 1)[0]
                advisories.update(v["id"] for v in value.get("vulns", []))
            audited.append({**row, "advisories": sorted(advisories)})
    return {"queried_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "packages": len(audited), "affected_packages": sum(bool(row["advisories"]) for row in audited),
            "rows": audited}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--android", type=Path, default=Path(__file__).resolve().parents[1] / "qeli-android")
    args = parser.parse_args()
    try:
        rows = inventory(args.android)
        check_security_pins(args.android, rows)
        report = audit(rows)
        print(json.dumps(report, indent=2))
        return 1 if report["affected_packages"] else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Android Maven audit failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
