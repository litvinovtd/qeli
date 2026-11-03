#!/usr/bin/env python3
"""Check/generate reviewed native toolchain legal resources (not VPN config).

All original member paths/bytes are preserved, including Rust HTML and its
companion license directory. This is a conservative source-resource superset, not per-binary
linkage, matching source publication or complete legal release qualification.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import stat
from pathlib import Path
from urllib.parse import urlsplit
from native_licenses import sha, safe_path, rows, HASH, MAX_FILE, MAX_TOTAL
from native_repro import DEFAULT_RUST_TOOLCHAIN, DEFAULT_ZIG_VERSION, DEFAULT_ANDROID_NDK
from router_toolchain import ROUTER_NIGHTLY

POLICY = 'qeli/third-party-notices/toolchain-sources.tsv'
BUNDLE = 'qeli/third-party-notices/rust/toolchains'
HEADER = 'component\tversion\tsource_url\tarchive_verification\tarchive_sha256\tmember\tsha256'
COMPONENT = re.compile(r'[a-z0-9_.+-]+')
SCOPE = ('Reviewed native-toolchain runtime/stdlib legal resources, preserved byte for byte.\n'
         'Includes extra targets/build notices; presence is not a per-binary linkage declaration.\n'
         'Rust COPYRIGHT-library plus license pool, Zig runtime/libc/unwind, NDK, GCC/MinGW resources.\n'
         'NDK qualification covers HTTPS ZIP range members/CRC, not the whole archive hash.\n'
         'GCC14.2/MinGW12 match observed lab source versions; old native metadata does not pin GCC minor.\n'
         'Rust1.89 covers the reviewed OpenWrt SDK compatibility fixture, not a published SDK source cut.\n'
         'Matching source, downstream patches, dynamic system libraries and release admission remain separate.\n')


def required_components():
    return {('rust', DEFAULT_RUST_TOOLCHAIN), ('rust', ROUTER_NIGHTLY), ('rust', '1.89.0'),
            ('zig', DEFAULT_ZIG_VERSION), ('android-ndk', DEFAULT_ANDROID_NDK),
            ('gcc-runtime', '14.2.0'), ('mingw-w64', '12.0.0')}


def catalog(repo):
    data = (repo / POLICY).read_bytes().replace(b'\r\n', b'\n')
    records, seen, components = [], set(), set()
    for component, version, source, verification, archive_sha, member, digest in rows(data, HEADER, 7):
        if not COMPONENT.fullmatch(component) or not COMPONENT.fullmatch(version):
            raise ValueError('Unsafe toolchain component/version')
        safe_path(member)
        key = (component, version); name = safe_path(f'files/{component}/{version}/{member}')
        if name in seen or key not in required_components() or not HASH.fullmatch(digest):
            raise ValueError('Duplicate/unreviewed toolchain identity')
        parsed = urlsplit(source)
        if parsed.scheme != 'https' or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError('Unsafe toolchain source URL')
        if component in ('rust', 'zig'):
            domain = 'static.rust-lang.org' if component == 'rust' else 'ziglang.org'
            if parsed.netloc != domain or not parsed.path.endswith('.tar.xz') or verification != 'full-archive-sha256' or not HASH.fullmatch(archive_sha):
                raise ValueError('Invalid Rust/Zig archive provenance')
        elif component == 'android-ndk':
            if source != 'https://dl.google.com/android/repository/android-ndk-r26d-linux.zip' or verification != 'official-https-zip-member-range-crc' or archive_sha != 'not-whole-archive-verified':
                raise ValueError('Invalid NDK member provenance')
        else:
            repository = 'gcc-mirror/gcc' if component == 'gcc-runtime' else 'mingw-w64/mingw-w64'
            if (not re.fullmatch(re.escape('https://raw.githubusercontent.com/' + repository + '/') + '[0-9a-f]{40}/' + re.escape(member), source)
                    or verification != 'exact-git-blob' or archive_sha != 'not-archive-source'):
                raise ValueError('Invalid GCC/MinGW exact-VCS provenance')
        seen.add(name); components.add(key)
        records.append({'path': name, 'source': source, 'member': member, 'sha256': digest})
    if components != required_components():
        raise ValueError('Missing pinned toolchain legal component')
    # Retain essential std-library copyright/license anchors, not just a generic MIT file.
    for component, version in components:
        if component == 'rust':
            for name in ('LICENSE-APACHE', 'LICENSE-MIT', 'rustc/share/doc/rust/COPYRIGHT-library.html'):
                if f'files/rust/{version}/{name}' not in seen:
                    raise ValueError('Missing Rust standard-library copyright/license resource')
    binding = {'schema': 1, 'source_inventory_lf_sha256': sha(data),
               'rust': DEFAULT_RUST_TOOLCHAIN, 'router_nightly': ROUTER_NIGHTLY,
               'zig': DEFAULT_ZIG_VERSION, 'android_ndk': DEFAULT_ANDROID_NDK}
    return data, records, (json.dumps(binding, sort_keys=True, indent=2) + '\n').encode()


def check_bundle(repo, bundle=None):
    bundle = bundle or repo / BUNDLE
    if bundle.is_symlink():
        raise ValueError('Symlink toolchain bundle root')
    source_inventory, records, binding = catalog(repo)
    expected = {r['path']: (r['sha256'], r['source'] + '!' + r['member']) for r in records}
    canonical = {'SOURCES.tsv': source_inventory, 'BINDING.json': binding, 'SCOPE.txt': SCOPE.encode()}
    expected.update({name: (sha(data), 'qeli-toolchains!' + name) for name, data in canonical.items()})
    actual = {}
    for path in bundle.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink toolchain resource')
        if path.is_file():
            name = safe_path(path.relative_to(bundle).as_posix())
            if path.stat().st_size > MAX_FILE:
                raise ValueError('Oversized toolchain legal resource')
            actual[name] = path.read_bytes()
    if set(actual) != set(expected) | {'INDEX.tsv'}:
        raise ValueError('Missing/extra toolchain resource')
    if any(not data for data in actual.values()) or sum(map(len, actual.values())) > MAX_TOTAL:
        raise ValueError('Empty/oversized toolchain bundle')
    for name, data in canonical.items():
        if actual[name] != data:
            raise ValueError('Toolchain source/version binding drift')
    indexed = {}
    for digest, name, origin in rows(actual['INDEX.tsv'], 'sha256\tpath\torigin', 3):
        safe_path(name)
        if name in indexed or expected.get(name) != (digest, origin) or sha(actual.get(name, b'')) != digest:
            raise ValueError('Toolchain index/source/checksum mismatch')
        indexed[name] = (digest, origin)
    if indexed != expected:
        raise ValueError('Incomplete toolchain resource index')
    return {'status': 'PASS', 'components': len(required_components()), 'resources': len(records),
            'files': len(actual), 'bytes': sum(map(len, actual.values()))}


def generate(repo, resources, output):
    if output.exists():
        raise ValueError('Generate into a new toolchain directory')
    inventory, records, binding = catalog(repo)
    payloads = {'SOURCES.tsv': inventory, 'BINDING.json': binding, 'SCOPE.txt': SCOPE.encode()}
    origins = {name: 'qeli-toolchains!' + name for name in payloads}
    for record in records:
        file = resources / (record['sha256'] + '.txt')
        if file.is_symlink() or not stat.S_ISREG(file.stat().st_mode) or file.stat().st_size > MAX_FILE:
            raise ValueError('Nonregular/oversized reviewed toolchain payload')
        data = file.read_bytes()
        if not data or sha(data) != record['sha256']:
            raise ValueError('Reviewed toolchain payload checksum mismatch')
        payloads[record['path']] = data
        origins[record['path']] = record['source'] + '!' + record['member']
    if sum(map(len, payloads.values())) > MAX_TOTAL:
        raise ValueError('Oversized toolchain bundle')
    payloads['INDEX.tsv'] = ('sha256\tpath\torigin\n' + ''.join(f'{sha(payloads[name])}\t{name}\t{origins[name]}\n' for name in sorted(payloads))).encode()
    output.mkdir(parents=True)
    for name, data in payloads.items():
        file = output / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(data)
    return check_bundle(repo, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--resources', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.resources or args.output:
            if not args.resources or not args.output:
                raise ValueError('Generation requires resources and new output')
            result = generate(args.repo, args.resources, args.output)
        else:
            result = check_bundle(args.repo, args.bundle)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, UnicodeError) as error:
        parser.exit(1, f'Toolchain legal bundle rejected: {error}\n')


if __name__ == '__main__': main()
