#!/usr/bin/env python3
"""Fail-closed admission of portable Linux amd64/arm64 releases (no execution).

The ELF must require at most glibc 2.28 and carry the allocator tag emitted only
by the jemalloc binary build. This is build-regression detection, not a signature
or a defence against a malicious producer. No objdump/host glibc is required.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import tarfile

GLIBC_MAX = (2, 28)
ALLOCATOR_TAG = b"qeli-allocator-v1:jemalloc\0"
MAX_BINARY = 128 * 1024 * 1024
ARCH_MACHINES = {"amd64": 62, "arm64": 183}


def verify_elf(blob: bytes, arch: str | None = None) -> dict:
    def fail(message):
        raise ValueError("Linux release refused: " + message)

    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(blob):
            fail("truncated ELF structure")
        return struct.unpack_from(fmt, blob, offset)

    def region(offset, size):
        if offset < 0 or size < 0 or offset + size > len(blob):
            fail("ELF section outside file")
        return blob[offset:offset + size]

    def string(table, offset):
        if offset >= len(table) or table.find(b"\0", offset) < 0:
            fail("invalid ELF string")
        try:
            return table[offset:table.index(b"\0", offset)].decode("ascii")
        except UnicodeError:
            fail("non-ASCII ELF metadata")

    if not 64 <= len(blob) <= MAX_BINARY or blob[:7] != b"\x7fELF\x02\x01\x01":
        fail("expected ELF64 little-endian executable")
    kind, machine, version = unpack("<HHI", 16)
    if kind not in (2, 3) or machine not in ARCH_MACHINES.values() or version != 1:
        fail("expected Linux amd64/arm64 executable")
    actual_arch = next(name for name, value in ARCH_MACHINES.items() if value == machine)
    if arch is not None and arch != actual_arch:
        fail(f"ELF architecture is {actual_arch}, expected {arch}")
    shoff, = unpack("<Q", 40)
    entry_size, count, name_index = unpack("<HHH", 58)
    if entry_size != 64 or not 0 < name_index < count or count > 4096:
        fail("missing/unsupported ELF section table")
    region(shoff, entry_size * count)
    headers = [unpack("<IIQQQQIIQQ", shoff + i * entry_size) for i in range(count)]
    names_header = headers[name_index]
    names = region(names_header[4], names_header[5])
    sections = {}
    for header in headers:
        name = string(names, header[0])
        if name in sections:
            fail("duplicate ELF section name")
        sections[name] = header
    tag = sections.get(".qeli.alloc")
    if tag is None or tag[1] != 1 or not tag[2] & 2 or region(tag[4], tag[5]) != ALLOCATOR_TAG:
        fail("missing jemalloc allocator tag; rebuild the server with --features jemalloc")
    verneed = sections.get(".gnu.version_r")
    if verneed is None or verneed[1] != 0x6ffffffe or not verneed[5]:
        fail("missing glibc symbol version requirements")
    if verneed[6] >= count or headers[verneed[6]][1] != 3:
        fail("invalid version string table")
    strings_header = headers[verneed[6]]
    strings = region(strings_header[4], strings_header[5])
    start, length = verneed[4:6]
    region(start, length)
    position, versions = 0, set()
    while True:
        if position + 16 > length:
            fail("truncated version requirement")
        version, auxiliary_count, file, aux, nxt = unpack("<HHIII", start + position)
        if version != 1 or not auxiliary_count or auxiliary_count > 4096 or aux < 16:
            fail("invalid version requirement")
        string(strings, file)
        offset = position + aux
        for index in range(auxiliary_count):
            if offset + 16 > length:
                fail("truncated symbol version")
            _, _, _, name, next_aux = unpack("<IHHII", start + offset)
            value = string(strings, name)
            if value.startswith("GLIBC_"):
                if re.fullmatch(r"GLIBC_[0-9]+(?:\.[0-9]+)+", value) is None:
                    fail("unsupported glibc ABI requirement " + value)
                versions.add(tuple(map(int, value[6:].split("."))))
            if index + 1 < auxiliary_count and next_aux < 16:
                fail("invalid symbol version chain")
            offset += next_aux
        if not nxt:
            break
        if nxt < 16:
            fail("invalid version requirement chain")
        position += nxt
    if not versions:
        fail("no glibc requirements found")
    maximum = max(versions)
    if maximum > GLIBC_MAX:
        fail("requires glibc " + ".".join(map(str, maximum)) + "; maximum is 2.28; use make -C qeli/debian binary-portable")
    return dict(sha256=hashlib.sha256(blob).hexdigest(), bytes=len(blob), arch=actual_arch,
                max_glibc=".".join(map(str, maximum)), allocator="jemalloc")


def verify_binary(path: Path, arch: str | None = None) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BINARY:
        raise ValueError("Linux release binary must be a regular bounded file")
    filename = re.fullmatch(r"qeli-linux-(amd64|arm64)", path.name)
    if filename:
        if arch is not None and arch != filename[1]:
            raise ValueError("binary filename and expected architecture disagree")
        arch = filename[1]
    return verify_elf(path.read_bytes(), arch)


def verify_deb(path: Path, arch: str | None = None) -> dict:
    """Inspect the packaged executable without extracting or installing anything."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BINARY:
        raise ValueError("Linux release package must be a regular bounded file")
    blob = path.read_bytes()
    if not blob.startswith(b"!<arch>\n"):
        raise ValueError("invalid .deb archive")
    offset, data_members, control_members, deb_versions = 8, [], [], []
    while offset < len(blob):
        header = blob[offset:offset + 60]
        if len(header) != 60 or header[-2:] != b"`\n":
            raise ValueError("invalid .deb member header")
        try:
            name = header[:16].decode("ascii").strip().rstrip("/")
            size = int(header[48:58])
        except (UnicodeError, ValueError) as error:
            raise ValueError("invalid .deb member") from error
        offset += 60
        if size < 0 or offset + size > len(blob):
            raise ValueError("truncated .deb member")
        if name.startswith("data.tar"):
            data_members.append(blob[offset:offset + size])
        elif name.startswith("control.tar"):
            control_members.append(blob[offset:offset + size])
        elif name == "debian-binary":
            deb_versions.append(blob[offset:offset + size])
        offset += size + size % 2
    if offset != len(blob) or len(data_members) != 1 or len(control_members) != 1 or deb_versions != [b"2.0\n"]:
        raise ValueError("expected .deb 2.0 with one control and one data archive")
    try:
        with tarfile.open(fileobj=io.BytesIO(control_members[0]), mode="r:*") as archive:
            controls = [m for m in archive if m.name in ("./control", "control")]
            if len(controls) != 1 or not controls[0].isfile() or not 0 < controls[0].size < 128 * 1024:
                raise ValueError("expected one regular .deb control file")
            control = archive.extractfile(controls[0]).read().decode("utf-8")
            architectures = re.findall(r"^Architecture: ([^\r\n]+)$", control, re.M)
            if len(architectures) != 1 or architectures[0] not in ARCH_MACHINES:
                raise ValueError("unsupported/missing .deb Architecture")
            package_arch = architectures[0]
            if arch is not None and package_arch != arch:
                raise ValueError(f"package architecture is {package_arch}, expected {arch}")
            filename = re.fullmatch(r"qeli_[A-Za-z0-9.+~-]+_(amd64|arm64)\.deb", path.name)
            if filename and filename[1] != package_arch:
                raise ValueError(".deb filename and control Architecture disagree")
        with tarfile.open(fileobj=io.BytesIO(data_members[0]), mode="r:*") as archive:
            binaries = [m for m in archive if m.name in ("./usr/bin/qeli", "usr/bin/qeli")]
            if len(binaries) != 1 or not binaries[0].isfile() or not 0 < binaries[0].size <= MAX_BINARY:
                raise ValueError("expected one regular usr/bin/qeli in .deb")
            stream = archive.extractfile(binaries[0])
            return verify_elf(stream.read(MAX_BINARY + 1), package_arch)
    except (tarfile.TarError, EOFError, UnicodeError) as error:
        raise ValueError("invalid/unsupported .deb data archive (release packages use xz)") from error


def verify_assets(directory: Path) -> list[dict]:
    results = []
    for path in sorted(directory.iterdir()):
        raw = re.fullmatch(r"qeli-linux-(amd64|arm64)", path.name)
        package = re.fullmatch(r"qeli_[A-Za-z0-9.+~-]+_(amd64|arm64)\.deb", path.name)
        if raw:
            results.append(dict(name=path.name, **verify_binary(path, raw[1])))
        elif package:
            results.append(dict(name=path.name, **verify_deb(path, package[1])))
    for arch in ARCH_MACHINES:
        if len({row["sha256"] for row in results if row["arch"] == arch}) > 1:
            raise ValueError(f"Linux {arch} release binary and .deb payload are different builds")
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--binary", type=Path)
    group.add_argument("--deb", type=Path)
    group.add_argument("--assets", type=Path)
    parser.add_argument("--arch", choices=tuple(ARCH_MACHINES), help="Require this ELF/package architecture")
    args = parser.parse_args(argv)
    if args.assets and args.arch:
        parser.error("--assets checks both architectures; do not combine it with --arch")
    try:
        result = (verify_assets(args.assets) if args.assets else
                  verify_binary(args.binary, args.arch) if args.binary else verify_deb(args.deb, args.arch))
        print(json.dumps(dict(status="PASS", result=result), sort_keys=True))
        return 0
    except (OSError, ValueError, struct.error) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
