#!/usr/bin/env python3
"""Offline NuGet legal-resource inventory/checker; JSON here is build metadata.

Generation uses the pinned SDK's NuGet API (signature integrity/content hash),
not a raw signed-nupkg SHA512 or cached .nupkg.metadata. Certificate trust and
revocation, matching source publication and per-binary linkage are separate.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import re
import struct
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape
from native_licenses import sha, safe_path, cell, rows, HASH, MAX_FILE, MAX_TOTAL

COMPONENT = re.compile(r'[a-z0-9_.+-]+')
LEGAL = re.compile(r'(?i)(^|[._ -])(licen[cs]es?|notices?|copying|copyright|unlicense|authors?|ofl)([._ -]|$)')
PACKAGE_HEADER = 'id\tversion\tlicense_kind\tlicense_value\tcontent_hash\tarchive_sha256\tarchive_url'
SUPPLEMENT_HEADER = 'id\tversion\trepository\tcommit\tupstream_path\turl\tsha256\tbinding'
SCOPE = ('All reviewed desktop NuGet lock graphs plus reviewed default publish runtime packs.\n'
         'Includes debug, tools, Linux and other-RID packages; not a per-binary linkage claim.\n'
         'Archive and upstream text bytes are preserved; embedded font names are decoded UTF-16BE.\n'
         'MicroCom.Runtime uses the packaged VCS commit for its upstream MIT supplement.\n'
         'SDK overrides, trust/revocation, other toolchain notices and source publication need separate review.\n')
RUNTIME = 'qeli-shared/third-party-notices/nuget-runtime.tsv'
BUNDLE = 'qeli-shared/third-party-notices/dotnet'


def content_hash(value):
    cell(value)
    if len(base64.b64decode(value, validate=True)) != 64:
        raise ValueError('Invalid NuGet content hash')
    return value


def inventory(repo):
    packages, locks = {}, {}
    for root in ('qeli-win', 'qeli-mac', 'qeli-shared'):
        for path in sorted((repo / root).rglob('packages*.lock.json')):
            relative = path.relative_to(repo)
            if any(part in ('obj', 'bin') for part in relative.parts):
                continue
            locks[relative.as_posix()] = sha(path.read_bytes().replace(b'\r\n', b'\n'))
            lock = json.loads(path.read_bytes())
            if lock.get('version') != 1:
                raise ValueError('Unsupported NuGet lock schema')
            for graph in lock['dependencies'].values():
                for name, dependency in graph.items():
                    if dependency['type'].lower() == 'project':
                        continue
                    key = (name.lower(), dependency['resolved'].lower())
                    digest = content_hash(dependency['contentHash'])
                    if not all(COMPONENT.fullmatch(v) for v in key) or packages.get(key, digest) != digest:
                        raise ValueError('Conflicting/invalid NuGet identity')
                    packages[key] = digest
    if not locks or not packages:
        raise ValueError('Empty managed lock inventory')
    runtime = (repo / RUNTIME).read_bytes().replace(b'\r\n', b'\n')
    runtime_keys = set()
    for name, version, digest in rows(runtime, 'id\tversion\tcontent_hash', 3):
        key = (name, version)
        if (not all(COMPONENT.fullmatch(v) for v in key) or key in runtime_keys
                or packages.get(key, digest) != digest):
            raise ValueError('Duplicate/conflicting runtime identity')
        runtime_keys.add(key)
        packages[key] = content_hash(digest)
    if not runtime_keys:
        raise ValueError('Empty reviewed runtime inventory')
    binding = {'schema': 1, 'global_json_lf_sha256': sha((repo / 'global.json').read_bytes().replace(b'\r\n', b'\n')),
               'runtime_inventory_lf_sha256': sha(runtime), 'lock_files': locks}
    return packages, (json.dumps(binding, sort_keys=True, indent=2) + '\n').encode()


def url(key):
    name, version = key
    return f'https://api.nuget.org/v3-flatcontainer/{name}/{version}/{name}.{version}.nupkg'


def metadata(data):
    root = ET.fromstring(data)
    elements = {e.tag.rsplit('}', 1)[-1]: e for e in root.iter()}
    key = (elements['id'].text.lower(), elements['version'].text.lower())
    license_node = elements.get('license')
    if license_node is None or not license_node.text:
        raise ValueError('Missing explicit NuGet license declaration')
    kind, value = cell(license_node.get('type', '')), cell(license_node.text)
    if kind not in ('expression', 'file'):
        raise ValueError('Unsupported NuGet license declaration')
    repository = elements.get('repository')
    return key, kind, value, (dict(repository.attrib) if repository is not None else {})


def sdk_hashes(repo, dotnet, paths):
    version = json.loads((repo / 'global.json').read_bytes())['sdk']['version']
    def run(args, cwd):
        result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding='utf-8', timeout=180)
        if result.returncode:
            raise ValueError('NuGet SDK helper failed:\n' + result.stdout + result.stderr)
        return result.stdout
    dotnet = str(dotnet.resolve())
    if run([dotnet, '--version'], repo).strip() != version:
        raise ValueError('NuGet helper requires exact global.json SDK')
    candidates = []
    for line in run([dotnet, '--list-sdks'], repo).splitlines():
        match = re.fullmatch(re.escape(version) + r' \[(.+)\]', line)
        if match:
            candidates.append(Path(match[1]) / version)
    if len(candidates) != 1:
        raise ValueError('Cannot locate pinned SDK assemblies')
    with tempfile.TemporaryDirectory(prefix='qeli-nuget-hash-') as directory:
        temp = Path(directory)
        refs = ''
        for name in ('NuGet.Packaging', 'NuGet.Common', 'NuGet.Frameworks', 'NuGet.Versioning', 'System.Security.Cryptography.Pkcs'):
            assembly = candidates[0] / (name + '.dll')
            if not assembly.is_file():
                raise ValueError('Missing SDK NuGet assembly')
            refs += f'<Reference Include="{name}"><HintPath>{escape(str(assembly))}</HintPath></Reference>'
        (temp / 'PackageHash.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup><ItemGroup>' + refs + '</ItemGroup></Project>', encoding='utf-8')
        (temp / 'Program.cs').write_bytes((repo / 'scripts/nuget_content_hash.cs').read_bytes())
        (temp / 'global.json').write_bytes((repo / 'global.json').read_bytes())
        (temp / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>', encoding='utf-8')
        (temp / 'inputs.txt').write_text(''.join(cell(str(path.resolve())) + '\n' for path in paths), encoding='utf-8')
        run([dotnet, 'build', 'PackageHash.csproj', '-c', 'Release', '--disable-build-servers', '-m:1'], temp)
        output = run([dotnet, str(temp / 'bin/Release/net10.0/PackageHash.dll'), str(temp / 'inputs.txt')], temp)
        records = [json.loads(line) for line in output.splitlines()]
        if len(records) != len(paths) or [Path(r['path']) for r in records] != [p.resolve() for p in paths]:
            raise ValueError('NuGet helper result mismatch')
        return records


def font_names(data):
    count = struct.unpack_from('>H', data, 4)[0]
    table = None
    for i in range(count):
        tag, _, offset, length = struct.unpack_from('>4sIII', data, 12 + i * 16)
        if tag == b'name':
            table = data[offset:offset + length]
    if table is None:
        raise ValueError('Font has no name table')
    _, count, strings = struct.unpack_from('>HHH', table)
    result = []
    for i in range(count):
        platform, encoding, language, name_id, length, offset = struct.unpack_from('>6H', table, 6 + i * 12)
        if platform == 3 and name_id in (0, 5, 13, 14):
            payload = table[strings + offset:strings + offset + length]
            if len(payload) != length:
                raise ValueError('Truncated font name')
            result.append({'platform': platform, 'encoding': encoding, 'language': language, 'id': name_id, 'text': cell(payload.decode('utf-16-be'))})
    if {r['id'] for r in result} != {0, 5, 13, 14}:
        raise ValueError('Missing font legal/version names')
    return result


def font_notice(proof):
    lines = ['Embedded Inter font name records (UTF-16BE decoded to UTF-8):']
    for record in proof['rows']:
        safe_path(record['path']); cell(record['url'])
        if not HASH.fullmatch(record['sha256']) or not re.fullmatch('[0-9a-f]{40}', record['git_blob']):
            raise ValueError('Invalid font source identity')
        lines += [record['path'], 'sha256=' + record['sha256'], record['url']]
        names = record['names']
        if {r['id'] for r in names} != {0, 5, 13, 14}:
            raise ValueError('Incomplete font legal names')
        lines += [f"name_id={r['id']} platform={r['platform']} encoding={r['encoding']} language={r['language']}: {cell(r['text'])}" for r in names]
    return ('\n'.join(lines) + '\n').encode()


def supplement_allowed(key, repo_meta, record, font_proof):
    repository, commit, path = record['repository'], record['commit'], safe_path(record['upstream_path'])
    expected_url = f'https://raw.githubusercontent.com/{repository}/{commit}/{path}'
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch('[0-9a-f]{40}', commit) or record['url'] != expected_url:
        return False
    published_repo = repo_meta.get('url', '').removesuffix('/').removesuffix('.git').lower()
    if record['binding'] == 'nuspec-vcs':
        return published_repo == ('https://github.com/' + repository).lower() and repo_meta.get('commit') == commit
    if record['binding'] == 'embedded-font-version-git-0a5106e0b':
        return (key[0] == 'avalonia.fonts.inter' and repository == 'rsms/inter' and path == 'LICENSE.txt'
                and commit.startswith('0a5106e0b') and font_proof and all(any(r['id'] == 5 and 'git-0a5106e0b' in r['text'] for r in font['names']) for font in font_proof['rows']))
    return False


def check_bundle(repo, bundle=None):
    bundle = bundle or repo / BUNDLE
    if bundle.is_symlink():
        raise ValueError('Symlink managed bundle root')
    files = {}
    for path in bundle.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in managed bundle')
        if path.is_file():
            name = safe_path(path.relative_to(bundle).as_posix())
            if path.stat().st_size > MAX_FILE:
                raise ValueError('Oversized managed resource')
            files[name] = path.read_bytes()
    if not files or sum(map(len, files.values())) > MAX_TOTAL or any(not data for data in files.values()):
        raise ValueError('Empty/oversized managed bundle')
    locked, binding = inventory(repo)
    if files.get('BINDING.json') != binding or files.get('SCOPE.txt') != SCOPE.encode():
        raise ValueError('Managed lock/SDK/runtime binding drift')
    packages = {}
    for name, version, kind, value, digest, archive_sha, archive_url in rows(files['PACKAGES.tsv'], PACKAGE_HEADER, 7):
        key = (name, version)
        if key in packages or locked.get(key) != digest or not HASH.fullmatch(archive_sha) or archive_url != url(key):
            raise ValueError('NuGet package inventory drift')
        packages[key] = (kind, value)
    if set(packages) != set(locked):
        raise ValueError('Missing/extra NuGet package')
    indexed = {}
    for digest, name, origin in rows(files['INDEX.tsv'], 'sha256\tpath\torigin', 3):
        safe_path(name)
        if name == 'INDEX.tsv' or name in indexed or not HASH.fullmatch(digest) or sha(files.get(name, b'')) != digest:
            raise ValueError('Duplicate/missing/checksum mismatch in managed index')
        indexed[name] = origin
    if set(files) != set(indexed) | {'INDEX.tsv'}:
        raise ValueError('Unindexed managed resource')
    canonical = {'PACKAGES.tsv', 'SUPPLEMENTS.tsv', 'BINDING.json', 'SCOPE.txt', 'FONTS.json'}
    for name in canonical:
        if indexed.get(name) != 'qeli!' + name:
            raise ValueError('Invalid managed metadata origin')
    font_proof = json.loads(files['FONTS.json'])
    if font_proof.get('schema') != 1 or not isinstance(font_proof.get('rows'), list):
        raise ValueError('Invalid font metadata')
    supplements, used = {}, set()
    for name, version, repository, commit, original, source_url, digest, binding_kind in rows(files['SUPPLEMENTS.tsv'], SUPPLEMENT_HEADER, 8):
        key = (name, version)
        identity = (key, source_url)
        if key not in packages or identity in supplements or not HASH.fullmatch(digest):
            raise ValueError('Invalid/duplicate managed supplement')
        supplements[identity] = {'repository': repository, 'commit': commit, 'upstream_path': original, 'url': source_url, 'sha256': digest, 'binding': binding_kind}
    metadata_map, legal_counts, license_paths = {}, dict.fromkeys(locked, 0), {}
    for name, origin in indexed.items():
        if name in canonical:
            continue
        parts = name.split('/')
        if len(parts) != 4 or parts[0] != 'files' or (parts[1], parts[2]) not in packages or parts[3] != sha(origin.encode()) + '.txt':
            raise ValueError('Invalid managed resource path')
        key = (parts[1], parts[2]); prefix = url(key) + '!'
        if origin.startswith(prefix):
            original = safe_path(origin[len(prefix):])
            if original.lower().endswith('.nuspec'):
                ident, kind, value, repo_meta = metadata(files[name])
                if key in metadata_map or ident != key or packages[key] != (kind, value):
                    raise ValueError('NuGet nuspec identity/license drift')
                metadata_map[key] = repo_meta
            elif LEGAL.search(original.split('/')[-1]) or (packages[key][0] == 'file' and original == packages[key][1]):
                legal_counts[key] += 1
                license_paths.setdefault(key, set()).add(original)
            else:
                raise ValueError('Not a declared/legal archive resource')
        elif origin == 'qeli-font-names!Inter':
            if key[0] != 'avalonia.fonts.inter' or not font_proof['rows'] or files[name] != font_notice(font_proof):
                raise ValueError('Embedded font notice drift')
            legal_counts[key] += 1
        else:
            identity = (key, origin)
            if identity not in supplements or supplements[identity]['sha256'] != sha(files[name]):
                raise ValueError('Unreviewed managed supplement origin')
            used.add(identity); legal_counts[key] += 1
    if set(metadata_map) != set(packages) or set(supplements) != used or not all(legal_counts.values()):
        raise ValueError('Missing metadata/legal resource/supplement')
    for key, (kind, value) in packages.items():
        if kind == 'file' and value not in license_paths.get(key, set()):
            raise ValueError('Missing declared NuGet license file')
    for (key, _), record in supplements.items():
        if not supplement_allowed(key, metadata_map[key], record, font_proof):
            raise ValueError('Supplement VCS/publisher/font binding mismatch')
    font_keys = [key for key in packages if key[0] == 'avalonia.fonts.inter']
    if font_keys:
        expected_fonts = {f'src/Avalonia.Fonts.Inter/Assets/Inter-{name}.ttf' for name in ('Bold', 'Light', 'Medium', 'Regular', 'SemiBold', 'Thin')}
        if len(font_keys) != 1 or {r['path'] for r in font_proof['rows']} != expected_fonts or len(font_proof['rows']) != 6:
            raise ValueError('Missing/duplicate embedded Inter font source')
        key = font_keys[0]; commit = metadata_map[key].get('commit', '')
        for record in font_proof['rows']:
            if record['url'] != f'https://raw.githubusercontent.com/AvaloniaUI/Avalonia/{commit}/{record["path"]}':
                raise ValueError('Inter package/font VCS mismatch')
        if not any(k == key and r['binding'] == 'embedded-font-version-git-0a5106e0b' for (k, _), r in supplements.items()):
            raise ValueError('Missing embedded Inter OFL text')
        origin = 'qeli-font-names!Inter'
        if indexed.get(f'files/{key[0]}/{key[1]}/{sha(origin.encode())}.txt') != origin:
            raise ValueError('Missing embedded Inter name records')
    elif font_proof['rows']:
        raise ValueError('Unlinked font metadata')
    return {'status': 'PASS', 'packages': len(packages), 'files': len(files), 'bytes': sum(map(len, files.values())), 'supplements': len(supplements), 'fonts': len(font_proof['rows'])}


def generate(repo, admissions, upstream, output, dotnet):
    if output.exists():
        raise ValueError('Output must be a new directory')
    locked, binding = inventory(repo)
    admitted = {}
    for name, version, digest, archive_sha, path in rows(admissions.read_bytes(), 'id\tversion\tcontent_hash\tarchive_sha256\tpath', 5):
        key = (name, version)
        if key in admitted or locked.get(key) != digest or not HASH.fullmatch(archive_sha):
            raise ValueError('Admission inventory mismatch')
        admitted[key] = (digest, archive_sha, Path(path))
    if set(admitted) != set(locked):
        raise ValueError('Admission must cover exact managed superset')
    keys = sorted(admitted)
    records = sdk_hashes(repo, dotnet, [admitted[key][2] for key in keys])
    files, origins, package_rows, supplement_rows = {}, {}, [], []
    def add(key, data, origin):
        if not data or len(data) > MAX_FILE:
            raise ValueError('Empty/oversized managed resource')
        name = f'files/{key[0]}/{key[1]}/{sha(origin.encode())}.txt'
        if name in files:
            raise ValueError('Duplicate managed resource origin')
        files[name], origins[name] = data, origin
    receipts = json.loads((upstream / 'receipts.json').read_bytes())
    if receipts.get('schema') != 1:
        raise ValueError('Invalid supplements schema')
    receipt_urls = [r['url'] for r in receipts['rows']]
    if len(set(receipt_urls)) != len(receipt_urls):
        raise ValueError('Duplicate supplement receipt')
    used_receipts = set()
    font_proof = {'schema': 1, 'rows': []}
    if any(k[0] == 'avalonia.fonts.inter' for k in locked):
        proof = json.loads((upstream / 'inter-font-proof.json').read_bytes())
        if proof.get('status') != 'PASS':
            raise ValueError('Font extraction proof is not PASS')
        font_proof['rows'] = [{k: row[k] for k in ('path', 'url', 'sha256', 'git_blob', 'names')} for row in proof['rows']]
    for key, actual in zip(keys, records):
        digest, archive_sha, archive = admitted[key]
        if actual['contentHash'] != digest or actual['archiveSha256'] != archive_sha:
            raise ValueError('Actual NuGet content hash/archive checksum mismatch')
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist(); names = [safe_path(i.filename.rstrip('/')) for i in infos]
            if len(set(names)) != len(names):
                raise ValueError('Duplicate NuGet zip entry')
            nuspecs = [i for i in infos if i.filename.lower().endswith('.nuspec')]
            if len(nuspecs) != 1 or nuspecs[0].file_size > MAX_FILE:
                raise ValueError('Missing/ambiguous/oversized nuspec')
            data = z.read(nuspecs[0]); ident, kind, value, repo_meta = metadata(data)
            if ident != key:
                raise ValueError('NuGet archive identity mismatch')
            package_rows.append([*key, kind, value, digest, archive_sha, url(key)])
            add(key, data, url(key) + '!' + nuspecs[0].filename)
            for info in infos:
                name = info.filename
                if name.endswith('/') or name.lower().endswith('.nuspec'):
                    continue
                if (LEGAL.search(name.split('/')[-1]) or (kind == 'file' and name == value)):
                    if info.file_size > MAX_FILE:
                        raise ValueError('Oversized NuGet legal resource')
                    add(key, z.read(info), url(key) + '!' + name)
            for record in receipts['rows']:
                if supplement_allowed(key, repo_meta, record, font_proof):
                    data = (upstream / safe_path(record['payload'])).read_bytes()
                    if sha(data) != record['sha256']:
                        raise ValueError('Supplement checksum mismatch')
                    add(key, data, record['url'])
                    used_receipts.add(record['url'])
                    supplement_rows.append([*key, *[record[k] for k in ('repository', 'commit', 'upstream_path', 'url', 'sha256', 'binding')]])
            if key[0] == 'avalonia.fonts.inter':
                dlls = [i for i in infos if i.filename.startswith('lib/') and i.filename.endswith('/Avalonia.Fonts.Inter.dll')]
                if not dlls:
                    raise ValueError('Missing embedded Inter assemblies')
                assemblies = [z.read(i) for i in dlls]
                for record in font_proof['rows']:
                    data = (upstream / Path(record['path']).name).read_bytes()
                    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                    if sha(data) != record['sha256'] or blob != record['git_blob'] or font_names(data) != record['names'] or not all(data in dll for dll in assemblies):
                        raise ValueError('Embedded Inter byte/name proof mismatch')
                add(key, font_notice(font_proof), 'qeli-font-names!Inter')
    if set(receipt_urls) != used_receipts:
        raise ValueError('Unbound/unreviewed supplement receipt')
    def tsv(header, values):
        return ('\n'.join([header] + ['\t'.join(cell(v) for v in row) for row in sorted(values)]) + '\n').encode()
    files.update({'BINDING.json': binding, 'SCOPE.txt': SCOPE.encode(), 'PACKAGES.tsv': tsv(PACKAGE_HEADER, package_rows),
                  'SUPPLEMENTS.tsv': tsv(SUPPLEMENT_HEADER, supplement_rows), 'FONTS.json': (json.dumps(font_proof, sort_keys=True, indent=2) + '\n').encode()})
    for name in ('BINDING.json', 'SCOPE.txt', 'PACKAGES.tsv', 'SUPPLEMENTS.tsv', 'FONTS.json'):
        origins[name] = 'qeli!' + name
    files['INDEX.tsv'] = tsv('sha256\tpath\torigin', [[sha(data), name, origins[name]] for name, data in files.items()])
    if sum(map(len, files.values())) > MAX_TOTAL:
        raise ValueError('Oversized managed bundle')
    output.mkdir(parents=True)
    for name, data in files.items():
        target = output / safe_path(name); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    return check_bundle(repo, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--admissions', type=Path)
    parser.add_argument('--upstream', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--dotnet', type=Path)
    args = parser.parse_args()
    try:
        if any((args.admissions, args.upstream, args.output, args.dotnet)):
            if not all((args.admissions, args.upstream, args.output, args.dotnet)):
                raise ValueError('Generation requires admissions, upstream, output and exact dotnet SDK')
            result = generate(args.repo, args.admissions, args.upstream, args.output, args.dotnet)
        else:
            result = check_bundle(args.repo, args.bundle)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, ET.ParseError, struct.error, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'Managed legal bundle rejected: {error}\n')


if __name__ == '__main__':
    main()
