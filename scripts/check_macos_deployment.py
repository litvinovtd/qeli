"""Validate the supported macOS floor and every bundled Mach-O deployment target."""
import argparse
from pathlib import Path
import plistlib
import struct

from macho_repro import macho_slices, _load_commands

SUPPORTED_MINIMUM = (15, 0, 0)
MAGICS = {b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
          b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
          b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


def version(text):
    parts = text.split('.')
    if not 1 <= len(parts) <= 3 or any(not p.isascii() or not p.isdecimal() for p in parts):
        raise ValueError('invalid macOS deployment version')
    return tuple(map(int, parts)) + (0,) * (3 - len(parts))


def declared_minimum(plist):
    minimum = version(plistlib.loads(plist)['LSMinimumSystemVersion'])
    if minimum < SUPPORTED_MINIMUM:
        raise ValueError('macOS minimum must be at least 15.0 for the supported .NET 10 distribution')
    return minimum


def check_binary(data, minimum):
    for part in macho_slices(data):
        endian = _load_commands(data, part)[0]  # validates all command/slice bounds first
        count = struct.unpack_from(endian + 'I', data, part.offset + 16)[0]
        cursor = part.offset + 32
        targets = []
        for _ in range(count):
            command, size = struct.unpack_from(endian + 'II', data, cursor)
            if command == 0x32:  # LC_BUILD_VERSION
                if size < 24 or struct.unpack_from(endian + 'I', data, cursor + 8)[0] != 1:
                    raise ValueError('invalid/non-macOS LC_BUILD_VERSION')
                targets.append(struct.unpack_from(endian + 'I', data, cursor + 12)[0])
            elif command == 0x24:  # LC_VERSION_MIN_MACOSX
                if size < 16:
                    raise ValueError('invalid LC_VERSION_MIN_MACOSX')
                targets.append(struct.unpack_from(endian + 'I', data, cursor + 8)[0])
            cursor += size
        if len(targets) != 1:
            raise ValueError('missing or ambiguous macOS deployment target')
        target = targets[0]
        required = (target >> 16, target >> 8 & 255, target & 255)
        if required > minimum:
            raise ValueError(f'Mach-O requires {required}, above Info.plist minimum {minimum}')


def check_bundle(app):
    app = Path(app)
    minimum = declared_minimum((app / 'Contents/Info.plist').read_bytes())
    count = 0
    for path in (app / 'Contents/MacOS').rglob('*'):
        if path.is_file():
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic in MAGICS:
                check_binary(path.read_bytes(), minimum)
                count += 1
    if not count:
        raise ValueError('no Mach-O files in app bundle')
    return count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app', type=Path)
    args = parser.parse_args()
    print(f'macOS deployment: PASS ({check_bundle(args.app)} Mach-O files)')
