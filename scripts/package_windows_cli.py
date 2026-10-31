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
    runtime = json.loads((source / 'qeli-cli.runtimeconfig.json').read_bytes())['runtimeOptions']
    frameworks = runtime.get('frameworks', []) + runtime.get('includedFrameworks', [])
    if 'framework' in runtime:
        frameworks.append(runtime['framework'])
    if not frameworks or any(f['name'] != 'Microsoft.NETCore.App' for f in frameworks):
        raise ValueError('CLI must use the console runtime, not WindowsDesktop')
    if (variant == 'standalone') != bool(runtime.get('includedFrameworks')):
        raise ValueError('Runtime configuration does not match package variant')
    if variant == 'standalone' and not {'coreclr.dll', 'hostfxr.dll'} <= names:
        raise ValueError('Standalone runtime files missing')
    date = datetime.fromtimestamp(max(epoch, 315532800), timezone.utc).timetuple()[:6]
    readme = (f'Qeli Windows CLI {version} ({variant}, win-x64)\n\n'
              'Extract the ENTIRE archive to a new directory. Do not copy only the EXE.\n'
              + ('Requires .NET 10 Runtime (not Desktop Runtime).\n' if variant == 'net-required'
                 else 'Contains the .NET runtime; no separate runtime installation required.\n')
              + 'qeli-cli.exe --help\nqeli-cli.exe version --json\n'
              'qeli-cli.exe config validate --config "C:\\VPN\\client.ini"\n'
              'qeli-cli.exe run --config "C:\\VPN\\client.ini"\n\n'
              'run/service control require Administrator. Help/version/config validation do not.\n'
              'Install the service only from a trusted location such as C:\\Program Files\\QeliCli.\n'
              'Manual: https://github.com/litvinovtd/qeli/blob/v' + version
              + '/docs/eng/manuals/WINDOWS-CLI.md\n'
              'Licenses: qeli-cli.exe licenses --export NEW_DIRECTORY\n').encode('utf8')
    if 'README.txt' in names:
        raise ValueError('Reserved package README already exists')
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in [(p.relative_to(source).as_posix(), p.read_bytes()) for p in files] + [('README.txt', readme)]:
            info = zipfile.ZipInfo(name, date)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != names | {'README.txt'}:
            raise ValueError('Archive verification failed')
        for path in files:
            if archive.read(path.relative_to(source).as_posix()) != path.read_bytes():
                raise ValueError('Archived publication bytes changed')


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
