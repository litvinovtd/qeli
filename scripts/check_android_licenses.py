#!/usr/bin/env python3
"""Check the project/Maven legal assets in a built Android APK.

This packaging check verifies the common Cargo.lock legal superset as well as
Maven resources. It does not certify per-binary linkage, toolchain notices,
matching source publication, signing, or all legal requirements of a release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

from native_licenses import check_bundle

PREFIX = 'assets/licenses/'
MAX_ASSET = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
COORDINATE = re.compile(r'[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.+-]+')


def check_apk(apk: Path, repository: Path) -> dict:
    canonical = {
        'AGPL-3.0.txt': repository / 'LICENSE',
        'MPL-2.0.txt': repository / 'qeli-android/LICENSE',
        'Apache-2.0.txt': repository / 'qeli-android/gradle/licenses/Apache-2.0.txt',
        'MAVEN.tsv': repository / 'qeli-android/gradle/licenses/maven-runtime.tsv',
    }
    native_report = check_bundle(repository)
    native = repository / 'qeli/third-party-notices/rust'
    canonical.update({'native-rust/' + path.relative_to(native).as_posix(): path for path in native.rglob('*') if path.is_file()})
    expected = {name: source.read_bytes().replace(b'\r\n', b'\n') for name, source in canonical.items()}
    for name, source in canonical.items():
        if name.startswith('native-rust/'):
            expected[name] = source.read_bytes()
    lines = expected['MAVEN.tsv'].decode('utf-8').splitlines()
    if not lines or lines[0] != 'coordinate\tlicense\treview':
        raise ValueError('Invalid reviewed Maven inventory')
    coordinates = set()
    for line in lines[1:]:
        fields = line.split('\t')
        if len(fields) != 3 or not COORDINATE.fullmatch(fields[0]) or fields[1] != 'Apache-2.0' or not fields[2].startswith('https://'):
            raise ValueError('Unreviewed or malformed Maven license row')
        if fields[0] in coordinates:
            raise ValueError('Duplicate reviewed coordinate')
        coordinates.add(fields[0])
    if not coordinates:
        raise ValueError('Empty reviewed inventory')
    with zipfile.ZipFile(apk) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) > 100000 or len(names) != len(set(names)):
            raise ValueError('Duplicate or oversized APK entry list')
        legal = {entry.filename[len(PREFIX):]: entry for entry in entries if entry.filename.startswith(PREFIX) and not entry.is_dir()}
        if 'INDEX.tsv' not in legal:
            raise ValueError('Missing legal asset index')
        if sum(entry.file_size for entry in legal.values()) > MAX_TOTAL:
            raise ValueError('Oversized legal assets')

        def read(name: str) -> bytes:
            entry = legal.get(name)
            if entry is None:
                raise ValueError(f'Missing legal asset: {name}')
            if entry.file_size > MAX_ASSET:
                raise ValueError(f'Oversized legal asset: {name}')
            with archive.open(entry) as stream:
                result = stream.read(MAX_ASSET + 1)
            if not result or len(result) > MAX_ASSET:
                raise ValueError(f'Empty or oversized legal asset: {name}')
            return result

        for name, data in expected.items():
            if read(name) != data:
                raise ValueError(f'Canonical text/inventory drift: {name}')
        artifacts = read('ARTIFACTS.tsv').decode('utf-8').splitlines()
        if not artifacts or artifacts[0] != 'coordinate\tartifact\tsha256':
            raise ValueError('Invalid original archive inventory')
        artifact_keys = set()
        for line in artifacts[1:]:
            fields = line.split('\t')
            if (len(fields) != 3 or fields[0] not in coordinates
                    or not re.fullmatch(r'[A-Za-z0-9_.+-]+\.(jar|aar)', fields[1])
                    or not re.fullmatch(r'[0-9a-f]{64}', fields[2])):
                raise ValueError('Invalid/unreviewed original archive identity')
            key = (fields[0], fields[1])
            if key in artifact_keys:
                raise ValueError('Duplicate original archive identity')
            artifact_keys.add(key)
        if not artifact_keys:
            raise ValueError('Empty original archive inventory')
        index = read('INDEX.tsv').decode('utf-8').splitlines()
        if not index or index[0] != 'sha256\tpath\torigin':
            raise ValueError('Invalid legal index header')
        seen = set()
        notices = []
        for line in index[1:]:
            fields = line.split('\t')
            if len(fields) != 3:
                raise ValueError('Malformed legal index row')
            digest, name, origin = fields
            parts = PurePosixPath(name).parts
            if (not re.fullmatch(r'[0-9a-f]{64}', digest) or not parts or name.startswith('/') or '\\' in name
                    or '..' in parts or name != '/'.join(parts) or any(ord(c) < 32 for c in name + origin)):
                raise ValueError('Unsafe legal index row')
            if name == 'INDEX.tsv' or name in seen:
                raise ValueError('Duplicate/self-referencing legal index row')
            seen.add(name)
            if hashlib.sha256(read(name)).hexdigest() != digest:
                raise ValueError(f'Legal asset checksum mismatch: {name}')
            if name not in canonical and name != 'ARTIFACTS.tsv':
                if len(parts) != 5 or parts[0] != 'maven' or ':'.join(parts[1:4]) not in coordinates:
                    raise ValueError('Unreviewed legal asset coordinate')
                coordinate = ':'.join(parts[1:4])
                if not origin.startswith(coordinate + '!') or not origin[len(coordinate) + 1:]:
                    raise ValueError('Missing embedded notice origin')
                original = origin[len(coordinate) + 1:]
                if parts[4] != hashlib.sha256(original.encode('utf-8')).hexdigest() + '.txt':
                    raise ValueError('Embedded notice origin/path mismatch')
                notices.append({'coordinate': coordinate, 'origin': original, 'sha256': digest})
        if seen != set(legal) - {'INDEX.tsv'} or not (set(canonical) | {'ARTIFACTS.tsv'}).issubset(seen):
            raise ValueError('Unindexed or missing legal assets')
    return {'status': 'PASS', 'apk_sha256': hashlib.sha256(apk.read_bytes()).hexdigest(),
            'reviewed_maven_coordinates': len(coordinates), 'indexed_assets': len(seen), 'original_archives': len(artifact_keys),
            'embedded_notices': notices,
            'native_bundle': native_report,
            'scope': 'Project, Maven and reviewed native Cargo/toolchain legal resource packaging; per-binary linkage/source/signature admission remains separate'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        result = check_apk(args.apk, args.repo)
    except (OSError, ValueError, KeyError, UnicodeError, zipfile.BadZipFile, RuntimeError) as error:
        print(f'Android legal assets: FAIL: {error}', file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2) + '\n'
    if args.report:
        args.report.write_text(text, encoding='utf-8', newline='\n')
    print(text, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
