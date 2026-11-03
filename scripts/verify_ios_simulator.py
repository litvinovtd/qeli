#!/usr/bin/env python3
"""Check the built simulator host signature and embedded Keychain declaration.

This is not device/IPA release admission. Real Keychain unit tests still run
after this check; unsigned or wrongly signed hosts must not qualify them.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import plistlib
import struct
import subprocess
import sys

from macho_repro import macho_slices
from verify_ios_ipa import KEYCHAIN_GROUP_KEY, _string_list


def embedded_entitlements(data: bytes) -> list[dict]:
    """Read __TEXT,__entitlements from every 64-bit iOS Simulator slice.

    Xcode puts simulated entitlements in the executable, separately from the
    macOS code-signature entitlements. Real Keychain tests remain mandatory.
    """
    values = []
    for part in macho_slices(data):
        start, end = part.offset, part.offset + part.size
        if part.size < 32 or data[start:start+4] != b'\xcf\xfa\xed\xfe':
            raise ValueError('64-bit little-endian simulator Mach-O required')
        filetype, count, length = struct.unpack_from('<III', data, start+12)
        commands_end = start+32+length
        if filetype != 2 or count > 1024 or commands_end > end:
            raise ValueError('invalid executable Mach-O load commands')
        cursor, platform, payload = start+32, None, None
        for _ in range(count):
            if cursor+8 > commands_end:
                raise ValueError('truncated Mach-O load command')
            command, size = struct.unpack_from('<II', data, cursor)
            if size < 8 or cursor+size > commands_end:
                raise ValueError('invalid Mach-O load command size')
            if command == 0x32:  # LC_BUILD_VERSION
                if size < 24 or platform is not None:
                    raise ValueError('invalid/duplicate Mach-O platform')
                platform = struct.unpack_from('<I', data, cursor+8)[0]
            if command == 0x19:  # LC_SEGMENT_64
                if size < 72:
                    raise ValueError('truncated Mach-O segment')
                sections = struct.unpack_from('<I', data, cursor+64)[0]
                if size != 72+80*sections:
                    raise ValueError('invalid Mach-O section table')
                segment = data[cursor+8:cursor+24].rstrip(b'\0')
                for index in range(sections):
                    section = cursor+72+80*index
                    if (data[section:section+16].rstrip(b'\0') != b'__entitlements'
                            or data[section+16:section+32].rstrip(b'\0') != b'__TEXT'):
                        continue
                    length = struct.unpack_from('<Q', data, section+40)[0]
                    offset = start+struct.unpack_from('<I', data, section+48)[0]
                    if (segment != b'__TEXT' or payload is not None or not 0 < length <= 1024*1024
                            or offset < commands_end or offset+length > end):
                        raise ValueError('invalid/duplicate embedded simulator entitlements')
                    payload = data[offset:offset+length]
            cursor += size
        if cursor != commands_end or platform != 7 or payload is None:
            raise ValueError('iOS Simulator platform and embedded entitlements required')
        value = plistlib.loads(payload)
        if not isinstance(value, dict):
            raise ValueError('embedded entitlements must be a dictionary')
        values.append(value)
    return values


def validate_host(bundle: Path) -> list[str]:
    if sys.platform != "darwin":
        return ["simulator signature verification requires macOS codesign"]
    try:
        if bundle.is_symlink() or not bundle.is_dir():
            return ["simulator host must be a real app directory"]
        info_path = bundle / "Info.plist"
        if info_path.is_symlink() or not info_path.is_file():
            return ["simulator host Info.plist is missing or not a regular file"]
        info = plistlib.loads(info_path.read_bytes())
        if not isinstance(info, dict) or info.get("CFBundlePackageType") != "APPL":
            return ["simulator host is not an application bundle"]
        group = info.get("QeliKeychainAccessGroup")
        if not isinstance(group, str) or not group or "$(" in group:
            return ["simulator host Keychain access group is missing or unresolved"]
        name = info.get('CFBundleExecutable')
        if not isinstance(name, str) or not name or name in ('.', '..') or '/' in name or '\\' in name:
            return ['simulator host executable name is missing or invalid']
        executable = bundle / name
        if executable.is_symlink() or not executable.is_file() or executable.stat().st_size > 256*1024*1024:
            return ['simulator host executable must be a bounded regular file']
        verified = subprocess.run(
            ["codesign", "--verify", "--strict", str(bundle)],
            capture_output=True, timeout=30,
        )
        if verified.returncode:
            return ["simulator host code signature verification failed"]
        for entitlements in embedded_entitlements(executable.read_bytes()):
            actual = _string_list(entitlements.get(KEYCHAIN_GROUP_KEY))
            if group not in actual:
                return [f'simulator embedded Keychain group differs: expected={group!r}, embedded={actual!r}']
    except (OSError, ValueError, struct.error, plistlib.InvalidFileException, subprocess.TimeoutExpired) as error:
        return [f"cannot verify simulator host: {error}"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    args = parser.parse_args(argv)
    errors = validate_host(args.app)
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    if errors:
        return 1
    print("PASS: simulator host signature and embedded shared-Keychain declaration verified; runtime tests still required")
    return 0


if __name__ == "__main__":
    sys.exit(main())
