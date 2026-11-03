#!/usr/bin/env python3
"""Generate/check the exact Cargo.lock superset of upstream legal resources.

Generation is offline: provide checksum-matching .crate archives and reviewed
exact-VCS supplements. Output must be a new directory. Checking needs no Cargo.
This does not certify per-binary linkage, Rust std/toolchain notices, source
publication, or complete release licensing.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
import tarfile
import tomllib
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
HASH = re.compile(r'[0-9a-f]{64}')
COMPONENT = re.compile(r'[A-Za-z0-9_.+-]+')
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
HEADERS = {'PACKAGES.tsv': 'name\tversion\tlicense\tarchive_sha256\tarchive_url',
           'INDEX.tsv': 'sha256\tpath\torigin',
           'SUPPLEMENTS.tsv': 'name\tversion\tvcs_commit\tupstream_path\turl\tsha256'}
SCOPE = ("Cargo.lock superset: includes client, server, target-specific, build and test dependencies.\n"
         "Presence here does not imply linkage into every packaged binary.\n"
         "Upstream legal resources are preserved byte for byte; license expressions are not rewritten.\n"
         "Reviewed toolchain notices are retained in the optional policy-bound toolchains layer.\nMatching source publication and per-binary runtime linkage require separate review.\n")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(name: str) -> str:
    parts = PurePosixPath(name).parts
    if (not name or name.startswith('/') or '\\' in name or ':' in name
            or not parts or '..' in parts or name != '/'.join(parts)
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError(f'Unsafe resource path: {name!r}')
    return name


def cell(value: str) -> str:
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Empty/control character in inventory field')
    return value


def lock_packages(repository: Path) -> dict:
    data = tomllib.loads((repository / 'qeli/Cargo.lock').read_text(encoding='utf-8'))
    result = {}
    for package in data['package']:
        if 'source' not in package:
            if package['name'] != 'qeli':
                raise ValueError('Unexpected local Cargo package')
            continue
        if package['source'] != REGISTRY:
            raise ValueError('Unreviewed Cargo source')
        name, version = package['name'], package['version']
        if not COMPONENT.fullmatch(name) or not COMPONENT.fullmatch(version) or not HASH.fullmatch(package.get('checksum', '')):
            raise ValueError('Invalid locked archive identity')
        key = (name, version)
        if key in result:
            raise ValueError('Duplicate locked package')
        result[key] = package['checksum']
    if not result:
        raise ValueError('Empty Cargo inventory')
    return result


def legal_path(name: str, declared: str | None) -> bool:
    parts = PurePosixPath(name).parts
    return (name == declared or bool(re.fullmatch(r'(?i)(licen[cs]e|notice|copying|copyright|unlicense|authors?)([._-].*)?', parts[-1]))
            or any(part.lower() in ('licenses', 'licences') for part in parts[:-1]))


def archive_url(name: str, version: str) -> str:
    return f'https://static.crates.io/crates/{name}/{name}-{version}.crate'


def rows(data: bytes, header: str, fields: int) -> list:
    lines = data.decode('utf-8').splitlines()
    if not lines or lines[0] != header:
        raise ValueError('Invalid inventory header')
    result = []
    for line in lines[1:]:
        values = line.split('\t')
        if len(values) != fields:
            raise ValueError('Invalid inventory row')
        result.append([cell(value) for value in values])
    return result


def check_bundle(repository: Path, bundle: Path | None = None) -> dict:
    bundle = bundle or repository / 'qeli/third-party-notices/rust'
    if bundle.is_symlink():
        raise ValueError('Symlink native legal bundle root')
    actual = {}
    for path in bundle.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in legal bundle')
        if path.is_file():
            name = safe_path(path.relative_to(bundle).as_posix())
            if path.stat().st_size > MAX_FILE:
                raise ValueError('Oversized legal resource')
            actual[name] = path.read_bytes()
    if not actual or sum(map(len, actual.values())) > MAX_TOTAL or any(not data for data in actual.values()):
        raise ValueError('Empty/oversized legal bundle')
    # The toolchain layer is mandatory when its reviewed source policy exists.
    # Minimal standalone Cargo fixtures without that policy remain supported.
    toolchain_report = None
    if (repository / 'qeli/third-party-notices/toolchain-sources.tsv').exists() or any(name.startswith('toolchains/') for name in actual):
        from toolchain_licenses import check_bundle as check_toolchains
        toolchain_report = check_toolchains(repository, bundle / 'toolchains')
    locked = lock_packages(repository)
    expected_binding = ('cargo_lock_lf_sha256=' + sha((repository / 'qeli/Cargo.lock').read_bytes().replace(b'\r\n', b'\n')) + '\nscope=full-cargo-lock\n').encode()
    if actual.get('BINDING.properties') != expected_binding:
        raise ValueError('Cargo.lock binding drift')
    if actual.get('Qeli-AGPL-3.0.txt') != (repository / 'LICENSE').read_bytes().replace(b'\r\n', b'\n'):
        raise ValueError('Qeli license drift')
    if actual.get('SCOPE.txt') != SCOPE.encode():
        raise ValueError('Scope statement drift')
    packages = {}
    for name, version, license_expression, checksum, url in rows(actual['PACKAGES.tsv'], HEADERS['PACKAGES.tsv'], 5):
        key = (name, version)
        if key in packages or locked.get(key) != checksum or url != archive_url(name, version):
            raise ValueError('Locked package inventory drift')
        packages[key] = license_expression
    if set(packages) != set(locked):
        raise ValueError('Missing/extra Cargo package')
    supplements = {}
    for name, version, commit, original, url, checksum in rows(actual['SUPPLEMENTS.tsv'], HEADERS['SUPPLEMENTS.tsv'], 6):
        key = (name, version)
        safe_path(original)
        if (key not in packages or not re.fullmatch(r'[0-9a-f]{40}', commit) or not HASH.fullmatch(checksum)
                or not url.startswith('https://raw.githubusercontent.com/') or f'/{commit}/{original}' not in url):
            raise ValueError('Invalid exact-VCS supplement')
        identity = (key, url)
        if identity in supplements:
            raise ValueError('Duplicate supplement')
        supplements[identity] = checksum
    seen, counts, used_supplements = set(), dict.fromkeys(locked, 0), set()
    canonical = {'PACKAGES.tsv', 'SUPPLEMENTS.tsv', 'BINDING.properties', 'SCOPE.txt', 'Qeli-AGPL-3.0.txt'}
    for checksum, name, origin in rows(actual['INDEX.tsv'], HEADERS['INDEX.tsv'], 3):
        safe_path(name)
        if name == 'INDEX.tsv' or name in seen or not HASH.fullmatch(checksum) or sha(actual.get(name, b'')) != checksum:
            raise ValueError('Duplicate/missing/checksum mismatch in legal index')
        seen.add(name)
        if name in canonical:
            if origin != 'qeli!' + name:
                raise ValueError('Invalid project resource origin')
            continue
        if name.startswith('toolchains/'):
            if toolchain_report is None or origin != 'toolchains!' + name.removeprefix('toolchains/'):
                raise ValueError('Unreviewed toolchain legal origin')
            continue
        parts = PurePosixPath(name).parts
        if len(parts) != 4 or parts[0] != 'files' or (parts[1], parts[2]) not in locked:
            raise ValueError('Unreviewed legal resource')
        key = (parts[1], parts[2])
        prefix = archive_url(*key) + '!'
        if origin.startswith(prefix):
            original = safe_path(origin[len(prefix):])
        else:
            identity = (key, origin)
            if supplements.get(identity) != checksum:
                raise ValueError('Unreviewed upstream supplement origin')
            used_supplements.add(identity)
            original = origin
        if parts[3] != sha(original.encode()) + '.txt':
            raise ValueError('Resource origin/path mismatch')
        counts[key] += 1
    if seen != set(actual) - {'INDEX.tsv'} or not canonical.issubset(seen) or any(count == 0 for count in counts.values()) or used_supplements != set(supplements):
        raise ValueError('Incomplete/unindexed legal resources')
    return {'status': 'PASS', 'locked_packages': len(locked), 'resources': sum(counts.values()),
            'indexed_files': len(seen), 'bytes': sum(map(len, actual.values())), 'supplements': len(supplements),
            'toolchains': toolchain_report,
            'scope': 'Full Cargo.lock superset; not per-binary linkage or complete release licensing'}


def generate(repository: Path, archives: Path, supplements_dir: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError('Generate into a new directory; review replacement separately')
    locked = lock_packages(repository)
    receipts = json.loads((supplements_dir / 'receipts.json').read_text(encoding='utf-8'))
    if receipts.get('schema') != 1:
        raise ValueError('Invalid supplement receipt schema')
    payloads, origins, packages, supplements, used = {}, {}, [], [], set()
    def save(name: str, data: bytes, origin: str):
        safe_path(name); cell(origin)
        if name in payloads or not data or len(data) > MAX_FILE:
            raise ValueError('Duplicate/empty/oversized legal resource')
        payloads[name], origins[name] = data, origin
    for (name, version), checksum in sorted(locked.items()):
        archive = archives / f'{name}-{version}.crate'
        if archive.stat().st_size > 64 * 1024 * 1024 or sha(archive.read_bytes()) != checksum:
            raise ValueError('Archive checksum mismatch')
        with tarfile.open(archive) as source:
            members = {}
            for count, member in enumerate(source):
                if count >= 100000 or not member.name.startswith(name + '-' + version + '/'):
                    raise ValueError('Invalid crate archive layout')
                relative = member.name[len(name + '-' + version + '/'):]
                if not relative and member.isdir():
                    continue
                safe_path(relative)
                if relative in members:
                    raise ValueError('Duplicate crate archive member')
                members[relative] = member
            def read(path: str) -> bytes:
                member = members[path]
                if not member.isfile() or member.size > MAX_FILE:
                    raise ValueError('Nonregular/oversized crate metadata or legal resource')
                return source.extractfile(member).read(MAX_FILE + 1)
            manifest = tomllib.loads(read('Cargo.toml').decode('utf-8'))['package']
            if (manifest['name'], manifest['version']) != (name, version):
                raise ValueError('Archive manifest identity mismatch')
            expression = manifest.get('license') or 'SEE-LICENSE-FILE'
            declared = manifest.get('license-file')
            if declared:
                safe_path(declared)
                if declared not in members:
                    raise ValueError('Missing declared license file')
            packages.append([name, version, cell(expression), checksum, archive_url(name, version)])
            found = 0
            for path in sorted(members):
                if legal_path(path, declared):
                    save(f'files/{name}/{version}/{sha(path.encode())}.txt', read(path), archive_url(name, version) + '!' + path)
                    found += 1
            relevant = [(i, row) for i, row in enumerate(receipts['rows']) if (row['name'], row['version']) == (name, version)]
            for i, row in relevant:
                vcs = json.loads(read('.cargo_vcs_info.json').decode())['git']
                commit = row['vcs_commit']; original = safe_path(row['upstream_path'])
                repo = manifest['repository'].removesuffix('.git').removeprefix('https://github.com/')
                if vcs.get('dirty') or vcs['sha1'] != commit or row['url'] != f'https://raw.githubusercontent.com/{repo}/{commit}/{original}':
                    raise ValueError('Supplement does not match published crate VCS')
                data = (supplements_dir / safe_path(row['payload'])).read_bytes()
                if sha(data) != row['sha256']:
                    raise ValueError('Supplement checksum mismatch')
                save(f'files/{name}/{version}/{sha(row["url"].encode())}.txt', data, row['url'])
                supplements.append([name, version, commit, original, row['url'], row['sha256']]);used.add(i);found += 1
            if not found:
                raise ValueError(f'No legal resources for {name} {version}; review exact upstream sources')
    if used != set(range(len(receipts['rows']))):
        raise ValueError('Unused/unknown supplement')
    for filename, table in [('PACKAGES.tsv', packages), ('SUPPLEMENTS.tsv', supplements)]:
        save(filename, (HEADERS[filename] + '\n' + ''.join('\t'.join(row) + '\n' for row in table)).encode(), 'qeli!' + filename)
    save('BINDING.properties', ('cargo_lock_lf_sha256=' + sha((repository / 'qeli/Cargo.lock').read_bytes().replace(b'\r\n', b'\n')) + '\nscope=full-cargo-lock\n').encode(), 'qeli!BINDING.properties')
    save('SCOPE.txt', SCOPE.encode(), 'qeli!SCOPE.txt')
    save('Qeli-AGPL-3.0.txt', (repository / 'LICENSE').read_bytes().replace(b'\r\n', b'\n'), 'qeli!Qeli-AGPL-3.0.txt')
    if (repository / 'qeli/third-party-notices/toolchain-sources.tsv').exists():
        from toolchain_licenses import check_bundle as check_toolchains, BUNDLE as TOOLCHAIN_BUNDLE
        source = repository / TOOLCHAIN_BUNDLE
        check_toolchains(repository, source)
        for file in sorted(path for path in source.rglob('*') if path.is_file()):
            name = file.relative_to(source).as_posix()
            save('toolchains/' + name, file.read_bytes(), 'toolchains!' + name)
    payloads['INDEX.tsv'] = (HEADERS['INDEX.tsv'] + '\n' + ''.join(f'{sha(payloads[name])}\t{name}\t{origins[name]}\n' for name in sorted(payloads))).encode()
    output.mkdir(parents=True)
    for name, data in payloads.items():
        path = output / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
    return check_bundle(repository, output)


def export_bundle_zip(repository: Path, destination: Path) -> dict:
    """Export a deterministic sidecar for standalone router executables."""
    report = check_bundle(repository)
    bundle = repository / 'qeli/third-party-notices/rust'
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='qeli-legal-', dir=destination.parent) as temporary:
        output = Path(temporary) / 'legal.zip'
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(path for path in bundle.rglob('*') if path.is_file()):
                name = file.relative_to(bundle).as_posix()
                entry = zipfile.ZipInfo('rust/' + name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = 0o100644 << 16
                archive.writestr(entry, file.read_bytes())
        with zipfile.ZipFile(output) as archive:
            for file in bundle.rglob('*'):
                if file.is_file() and archive.read('rust/' + file.relative_to(bundle).as_posix()) != file.read_bytes():
                    raise ValueError('Router legal ZIP byte drift')
        digest = sha(output.read_bytes())
        output.replace(destination)
    return dict(report, zip_sha256=digest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--archives', type=Path)
    parser.add_argument('--supplements', type=Path)
    args = parser.parse_args()
    try:
        if args.archives:
            if not args.supplements or not args.bundle:
                parser.error('Generation requires --archives, --supplements and a new --bundle directory')
            result = generate(args.repo, args.archives, args.supplements, args.bundle)
        else:
            result = check_bundle(args.repo, args.bundle)
    except (OSError, ValueError, KeyError, UnicodeError, tarfile.TarError) as error:
        print(f'Native legal bundle: FAIL: {error}', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
