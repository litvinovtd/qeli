#!/usr/bin/env python3
"""Validate original resource bytes inside a shipped single-file EXE, without executing it."""
import argparse
import base64
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

from embedded_licenses import expected_files


def bundled_assembly(pe, assembly_name="QeliWin.dll"):
    signature = bytes.fromhex('8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae')
    if pe[:2] != b'MZ' or pe.count(signature) != 1:
        raise ValueError('Not one .NET single-file PE bundle')
    pos = pe.index(signature)
    cursor = struct.unpack_from('<q', pe, pos - 8)[0]
    if cursor <= 0 or cursor > len(pe) - 12:
        raise ValueError('Invalid bundle header offset')
    major, minor, count = struct.unpack_from('<IIi', pe, cursor)
    cursor += 12
    if (major, minor) != (6, 0) or not 0 < count < 4096:
        raise ValueError('Unsupported .NET bundle format')

    def string():
        nonlocal cursor
        size = 0
        for shift in range(0, 35, 7):
            byte = pe[cursor]; cursor += 1
            size |= (byte & 127) << shift
            if not byte & 128: break
        else: raise ValueError('Invalid bundle string')
        if size >= 4096 or cursor + size > len(pe): raise ValueError('Invalid bundle string size')
        value = pe[cursor:cursor + size].decode('utf8'); cursor += size
        return value

    string()
    cursor += 40
    seen = set()
    result = None
    for _ in range(count):
        offset, size, compressed, kind = struct.unpack_from('<qqqB', pe, cursor)
        cursor += 25
        name = string()
        if name in seen or name.startswith('/') or '\\' in name or ':' in name or any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('Unsafe/duplicate bundle entry')
        seen.add(name)
        if offset < 0 or not 0 <= size < 128 * 1024 ** 2 or compressed < 0 or offset + (compressed or size) > len(pe):
            raise ValueError('Invalid bundle payload size')
        if name == assembly_name:
            if kind != 1: raise ValueError('Wrong candidate assembly kind')
            raw = pe[offset:offset + (compressed or size)]
            if compressed:
                decoder = zlib.decompressobj(-15)
                raw = decoder.decompress(raw, size + 1)
                if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
                    raise ValueError('Invalid compressed candidate assembly')
            if len(raw) != size: raise ValueError('Candidate assembly size mismatch')
            result = raw
    if result is None: raise ValueError(assembly_name + ' missing from EXE')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    candidate = parser.add_mutually_exclusive_group(required=True)
    candidate.add_argument('--exe', type=Path)
    candidate.add_argument('--directory', type=Path)
    parser.add_argument('--entry-assembly', choices=('QeliWin.dll','qeli-cli.dll'), default='QeliWin.dll')
    parser.add_argument('--native-core', type=Path, help='Explicit dev/CI core; default is the canonical qualified Windows core')
    parser.add_argument('--reader', required=True, type=Path)
    parser.add_argument('--dotnet', default='dotnet')
    args = parser.parse_args()
    if args.exe:
        payload = args.exe.read_bytes()
        raw = bundled_assembly(payload, args.entry_assembly)
        runtime = bundled_assembly(payload, 'QeliWindowsRuntime.dll')
    else:
        if args.directory.is_symlink() or not args.directory.is_dir():
            raise ValueError('Candidate directory must be a real directory')
        paths = [args.directory / args.entry_assembly, args.directory / 'QeliWindowsRuntime.dll']
        if any(p.is_symlink() or not p.is_file() for p in paths):
            raise ValueError('Candidate managed assemblies are missing or linked')
        raw, runtime = (p.read_bytes() for p in paths)
    native = (args.native_core or args.repo / 'qeli-win/QeliWin/native/qeli.dll').read_bytes()
    if runtime.count(native) != 1: raise ValueError('Runtime does not contain the exact supplied native core')
    with tempfile.TemporaryDirectory(prefix='qeli-legal-inspect-') as directory:
        assembly = Path(directory) / 'QeliWin.dll'; assembly.write_bytes(raw)
        output = subprocess.check_output([args.dotnet, 'exec', str(args.reader), str(assembly)], timeout=60)
    actual = {name: base64.b64decode(value, validate=True) for name, value in json.loads(output).items()}
    expected = expected_files(args.repo, windows=True)
    if actual != expected:
        raise ValueError('EXE legal resources missing, changed, or extra')
    print(f'Windows licenses: PASS ({len(actual)} exact original resources; exact supplied native core embedded)')


if __name__ == '__main__':
    main()
