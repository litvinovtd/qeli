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


def bundled_assembly(pe):
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
        if name == 'QeliWin.dll':
            if kind != 1: raise ValueError('Wrong candidate assembly kind')
            raw = pe[offset:offset + (compressed or size)]
            if compressed:
                decoder = zlib.decompressobj(-15)
                raw = decoder.decompress(raw, size + 1)
                if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
                    raise ValueError('Invalid compressed candidate assembly')
            if len(raw) != size: raise ValueError('Candidate assembly size mismatch')
            result = raw
    if result is None: raise ValueError('QeliWin.dll missing from EXE')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--exe', required=True, type=Path)
    parser.add_argument('--reader', required=True, type=Path)
    parser.add_argument('--dotnet', default='dotnet')
    args = parser.parse_args()
    raw = bundled_assembly(args.exe.read_bytes())
    native = (args.repo / 'qeli-win/QeliWin/native/qeli.dll').read_bytes()
    if raw.count(native) != 1: raise ValueError('EXE does not contain the exact qualified native core')
    with tempfile.TemporaryDirectory(prefix='qeli-legal-inspect-') as directory:
        assembly = Path(directory) / 'QeliWin.dll'; assembly.write_bytes(raw)
        output = subprocess.check_output([args.dotnet, 'exec', str(args.reader), str(assembly)], timeout=60)
    actual = {name: base64.b64decode(value, validate=True) for name, value in json.loads(output).items()}
    expected = expected_files(args.repo, windows=True)
    if actual != expected:
        raise ValueError('EXE legal resources missing, changed, or extra')
    print(f'Single-file EXE licenses: PASS ({len(actual)} exact original resources; qualified native core embedded)')


if __name__ == '__main__':
    main()
