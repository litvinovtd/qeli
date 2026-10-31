"""Fail closed on an incomplete or mixed local release distribution; no publication."""
from __future__ import annotations
import argparse
from pathlib import Path
import re
import zipfile

from gen_checksums import sha256
from linux_release import verify_assets
from package_windows_cli import REQUIRED


def expected_assets(version: str) -> set[str]:
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Expected a numeric three-part release version')
    if tuple(map(int,version.split('.'))) < (0,8,4):
        raise ValueError('This complete ARM64/console release contract starts with 0.8.4')
    names = {'SHA256SUMS', 'install-keenetic.sh', f'qeli-android-{version}.apk',
        'qeli-keenetic-files.tar.gz', 'qeli-openwrt-files.tar.gz',
        'Qeli-macos-arm64.tar.gz', 'Qeli-macos-x86_64.tar.gz',
        'QeliWin-net-required.exe', 'QeliWin-standalone.exe'}
    for arch in ('amd64', 'arm64'):
        names.update((f'qeli-linux-{arch}', f'qeli_{version}_{arch}.deb'))
    for arch in ('aarch64','armv7','mipsel','x86_64'):
        names.add('qeli-client-openwrt-'+arch)
    for arch in ('aarch64','mipsel'):
        names.add('qeli-client-keenetic-'+arch)
    for variant in ('net-required','standalone'):
        names.add('qeli-cli-windows-x64-'+variant+'.zip')
    return names


def verify_cli_archive(path: Path, standalone: bool) -> None:
    with zipfile.ZipFile(path) as archive:
        names=archive.namelist()
        if len(names)!=len(set(names)) or archive.testzip() is not None:
            raise ValueError('Corrupt or duplicate CLI archive members')
        if not set(REQUIRED) | {'README.txt'} <= set(names):
            raise ValueError('CLI archive is missing required runtime/entry files')
        if any(name.startswith(('/', '\\')) or '\\' in name or ':' in name or
               any(part in ('', '.', '..') for part in name.split('/')) for name in names):
            raise ValueError('Unsafe CLI archive path')
        if standalone and not {'coreclr.dll','hostfxr.dll'} <= set(names):
            raise ValueError('Standalone console runtime missing')


def verify(directory: Path, version: str) -> None:
    expected=expected_assets(version)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Release directory missing or linked')
    files=list(directory.iterdir())
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise ValueError('Only regular release files are allowed')
    actual={p.name for p in files}
    if actual!=expected:
        raise ValueError(f'Release assets differ: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}')
    verify_assets(directory)
    manifest=''.join(f'{sha256(directory/name)}  {name}\n' for name in sorted(expected-{'SHA256SUMS'}))
    if (directory/'SHA256SUMS').read_bytes()!=manifest.encode('ascii'):
        raise ValueError('SHA256SUMS does not match the exact release file set and bytes')
    for variant in ('net-required','standalone'):
        verify_cli_archive(directory/('qeli-cli-windows-x64-'+variant+'.zip'),variant=='standalone')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',required=True,type=Path)
    parser.add_argument('--version',required=True)
    args=parser.parse_args()
    verify(args.directory,args.version)
    print('Complete local release assets: PASS',args.version,len(expected_assets(args.version)))
