"""Archive an already verified Windows CLI publication, including its runtime DLLs.

Called by build-cli.ps1 only after native/parser/original-license admission. This
does not publish a release or qualify an arbitrary DLL as a release native core.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import stat
import zipfile


REQUIRED = ('qeli-cli.exe', 'qeli-cli.dll', 'qeli-cli.deps.json',
            'qeli-cli.runtimeconfig.json', 'QeliWindowsRuntime.dll', 'QeliShared.dll')
ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ASSETS = ROOT / 'qeli-win/cli-package'
ARCHIVE_REQUIRED = tuple('bin/' + name for name in REQUIRED) + (
    'qeli-cli.cmd', 'README.md', 'examples/client.ini.example',
    'docs/WINDOWS-CLI.ru.md', 'docs/WINDOWS-CLI.en.md')


def validate_runtime(config: bytes, names: set[str], standalone: bool) -> None:
    runtime = json.loads(config)['runtimeOptions']
    frameworks = runtime.get('frameworks', []) + runtime.get('includedFrameworks', [])
    if 'framework' in runtime:
        frameworks.append(runtime['framework'])
    if not frameworks or any(f['name'] != 'Microsoft.NETCore.App' for f in frameworks):
        raise ValueError('CLI must use the console runtime, not WindowsDesktop')
    if standalone != bool(runtime.get('includedFrameworks')):
        raise ValueError('Runtime configuration does not match package variant')
    if standalone and not {'coreclr.dll', 'hostfxr.dll'} <= names:
        raise ValueError('Standalone runtime missing')


def verify_cli_archive(path: Path, standalone: bool) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len({name.casefold() for name in names}) or archive.testzip() is not None:
            raise ValueError('Corrupt or duplicate CLI archive members')
        if any(name.startswith(('/', '\\')) or '\\' in name or ':' in name or
               any(part in ('', '.', '..') for part in name.split('/')) for name in names):
            raise ValueError('Unsafe CLI archive path')
        if any(stat.S_ISLNK(info.external_attr >> 16) for info in archive.infolist()):
            raise ValueError('Linked CLI archive member refused')
        if not set(ARCHIVE_REQUIRED) <= set(names):
            raise ValueError('CLI archive is missing required launch/runtime/documentation files')
        if {name for name in names if '/' not in name} != {'qeli-cli.cmd', 'README.md'}:
            raise ValueError('CLI root must contain only launcher and README')
        if any('/' in name and name.split('/')[0] not in ('bin', 'docs', 'examples') for name in names):
            raise ValueError('Unexpected CLI archive directory')
        validate_runtime(archive.read('bin/qeli-cli.runtimeconfig.json'),
                         {name[4:] for name in names if name.startswith('bin/')}, standalone)


def documentation(variant: str, version: str) -> dict[str, bytes]:
    readme = (PACKAGE_ASSETS / 'README.md.in').read_text(encoding='utf8')
    values = {
        'VERSION': version, 'VARIANT': variant,
        'RUNTIME_RU': ('Нужен .NET 10 Runtime (не WPF/Desktop Runtime).'
                       if variant == 'net-required' else 'Runtime .NET включён; отдельная установка не нужна.'),
        'RUNTIME_EN': ('Requires .NET 10 Runtime, not Desktop Runtime.'
                       if variant == 'net-required' else 'Includes the .NET runtime; no separate installation needed.'),
    }
    for key, value in values.items():
        readme = readme.replace('@' + key + '@', value)
    if re.search(r'@[A-Z_]+@', readme):
        raise ValueError('Unexpanded CLI README placeholder')
    launcher = (PACKAGE_ASSETS / 'qeli-cli.cmd').read_text(encoding='ascii')
    result = {
        'README.md': readme.encode('utf8'),
        'qeli-cli.cmd': launcher.replace('\n', '\r\n').encode('ascii'),
        'examples/client.ini.example': (PACKAGE_ASSETS / 'examples/client.ini.example').read_bytes(),
    }
    for lang, other in (('ru', 'eng'), ('eng', 'ru')):
        body = (ROOT / f'docs/{lang}/manuals/WINDOWS-CLI.md').read_text(encoding='utf8')
        suffix = 'en' if lang == 'eng' else 'ru'
        other_suffix = 'en' if other == 'eng' else 'ru'
        body = body.replace(f'../../{other}/manuals/WINDOWS-CLI.md', f'WINDOWS-CLI.{other_suffix}.md')
        result[f'docs/WINDOWS-CLI.{suffix}.md'] = body.encode('utf8')
    return result


def linked(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def package(source: Path, output: Path, variant: str, version: str, epoch: int) -> None:
    if variant not in ('net-required', 'standalone') or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid CLI package variant/version')
    if linked(source) or not source.is_dir():
        raise ValueError('Publication must be a real directory')
    source = source.resolve()
    output = output.absolute()
    if output.exists() or output.is_symlink() or source in output.parents:
        raise ValueError('Output must be new and outside the publication')
    files = []
    for path in sorted(source.rglob('*')):
        if linked(path):
            raise ValueError('Linked publication member refused')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('Non-file publication member refused')
        if path.suffix.lower() in ('.ini', '.conf', '.log', '.key', '.pfx', '.pem'):
            raise ValueError('Configuration/secret/log must not enter a CLI package')
        if path.suffix.lower() != '.pdb':
            files.append(path)
    names = {p.relative_to(source).as_posix() for p in files}
    if not set(REQUIRED) <= names:
        raise ValueError('Incomplete CLI publication: runtime/entry assemblies missing')
    validate_runtime((source / 'qeli-cli.runtimeconfig.json').read_bytes(), names, variant == 'standalone')
    date = datetime.fromtimestamp(max(epoch, 315532800), timezone.utc).timetuple()[:6]
    if {'README.txt', 'README.md'} & names:
        raise ValueError('Reserved package README already exists')
    extra = documentation(variant, version)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in [(f'bin/{p.relative_to(source).as_posix()}', p.read_bytes()) for p in files] + list(extra.items()):
            info = zipfile.ZipInfo(name, date)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != {'bin/' + name for name in names} | set(extra):
            raise ValueError('Archive verification failed')
        for path in files:
            if archive.read('bin/' + path.relative_to(source).as_posix()) != path.read_bytes():
                raise ValueError('Archived publication bytes changed')
    verify_cli_archive(output, variant == 'standalone')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--variant', required=True, choices=('net-required', 'standalone'))
    parser.add_argument('--version', required=True)
    parser.add_argument('--epoch', required=True, type=int)
    args = parser.parse_args()
    package(args.source, args.output, args.variant, args.version, args.epoch)
    print('CLI archive verified:', args.output)


if __name__ == '__main__':
    main()
