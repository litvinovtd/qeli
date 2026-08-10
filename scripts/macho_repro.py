#!/usr/bin/env python3
"""Normalize reproducibility-only Mach-O metadata before ad-hoc signing.

Zig 0.13 writes a random LC_UUID into every Mach-O slice. The arm64 UUID is covered by
its ad-hoc signature, so two otherwise identical builds differ in both places. Its x86_64
Mach-O linker can also leave one invalid, non-deterministic indirect-symbol index in the
``__DATA_CONST,__got`` section. This tool replaces only such an out-of-range GOT index with
Mach-O's standard ``INDIRECT_SYMBOL_LOCAL`` marker, derives an RFC-4122-shaped UUID from the
slice with UUID/signature bytes zeroed, and writes the UUID in place. Any invalid indirect
entry outside ``__got`` is rejected. The caller must ad-hoc-sign the result again; the old
signature blob stays structurally valid so the signer can replace it.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
S_NON_LAZY_SYMBOL_POINTERS = 0x6
SECTION_TYPE = 0xFF
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000


@dataclass(frozen=True)
class Slice:
    offset: int
    size: int


@dataclass(frozen=True)
class IndirectSection:
    segment: str
    section: str
    section_type: int
    first_index: int
    entry_count: int


def macho_slices(data: bytes | bytearray) -> list[Slice]:
    if len(data) < 4:
        raise ValueError("file is too small for Mach-O")
    magic = bytes(data[:4])
    fat_formats = {
        b"\xca\xfe\xba\xbe": (">", "IIIII"),
        b"\xbe\xba\xfe\xca": ("<", "IIIII"),
        b"\xca\xfe\xba\xbf": (">", "IIQQII"),
        b"\xbf\xba\xfe\xca": ("<", "IIQQII"),
    }
    if magic not in fat_formats:
        return [Slice(0, len(data))]
    endian, arch_format = fat_formats[magic]
    if len(data) < 8:
        raise ValueError("truncated Mach-O fat header")
    count = struct.unpack_from(f"{endian}I", data, 4)[0]
    entry_size = struct.calcsize(f"{endian}{arch_format}")
    if count == 0 or 8 + count * entry_size > len(data):
        raise ValueError("invalid Mach-O fat architecture table")
    slices = []
    for index in range(count):
        fields = struct.unpack_from(
            f"{endian}{arch_format}", data, 8 + index * entry_size
        )
        offset, size = fields[2], fields[3]
        if size == 0 or offset + size > len(data):
            raise ValueError("Mach-O fat slice escapes file")
        slices.append(Slice(offset, size))
    return slices


def _load_commands(
    data: bytes | bytearray, slice_info: Slice
) -> tuple[
    str,
    list[tuple[int, int]],
    list[tuple[int, int]],
    tuple[int, int, int] | None,
    list[IndirectSection],
]:
    start, size = slice_info.offset, slice_info.size
    magic = bytes(data[start : start + 4])
    magics = {
        b"\xce\xfa\xed\xfe": ("<", 28),
        b"\xfe\xed\xfa\xce": (">", 28),
        b"\xcf\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xcf": (">", 32),
    }
    if magic not in magics:
        raise ValueError(f"unsupported Mach-O slice magic at offset {start}")
    endian, header_size = magics[magic]
    if size < header_size:
        raise ValueError("truncated Mach-O header")
    command_count, command_bytes = struct.unpack_from(f"{endian}II", data, start + 16)
    cursor = start + header_size
    commands_end = cursor + command_bytes
    if commands_end > start + size:
        raise ValueError("Mach-O load commands escape slice")
    uuid_ranges = []
    signature_ranges = []
    symbol_count: int | None = None
    indirect_table: tuple[int, int] | None = None
    indirect_sections = []
    for _index in range(command_count):
        if cursor + 8 > commands_end:
            raise ValueError("truncated Mach-O load command")
        command, command_size = struct.unpack_from(f"{endian}II", data, cursor)
        if command_size < 8 or cursor + command_size > commands_end:
            raise ValueError("invalid Mach-O load command size")
        if command == LC_UUID:
            if command_size != 24:
                raise ValueError("invalid LC_UUID size")
            uuid_ranges.append((cursor + 8, 16))
        elif command == LC_CODE_SIGNATURE:
            if command_size < 16:
                raise ValueError("invalid LC_CODE_SIGNATURE size")
            data_offset, data_size = struct.unpack_from(f"{endian}II", data, cursor + 8)
            if data_size == 0 or data_offset + data_size > size:
                raise ValueError("code signature escapes Mach-O slice")
            signature_ranges.append((start + data_offset, data_size))
        elif command == LC_SYMTAB:
            if command_size != 24:
                raise ValueError("invalid LC_SYMTAB size")
            symbol_count = struct.unpack_from(f"{endian}I", data, cursor + 12)[0]
        elif command == LC_DYSYMTAB:
            if command_size != 80:
                raise ValueError("invalid LC_DYSYMTAB size")
            indirect_offset, indirect_count = struct.unpack_from(
                f"{endian}II", data, cursor + 56
            )
            if indirect_offset + indirect_count * 4 > size:
                raise ValueError("indirect-symbol table escapes Mach-O slice")
            indirect_table = (start + indirect_offset, indirect_count)
        elif command in (LC_SEGMENT, LC_SEGMENT_64):
            is_64 = command == LC_SEGMENT_64
            expected_header = 72 if is_64 else 56
            section_size = 80 if is_64 else 68
            if command_size < expected_header:
                raise ValueError("truncated Mach-O segment command")
            segment = bytes(data[cursor + 8 : cursor + 24]).split(b"\0", 1)[0].decode(
                "ascii", errors="replace"
            )
            section_count = struct.unpack_from(
                f"{endian}I", data, cursor + (64 if is_64 else 48)
            )[0]
            if command_size != expected_header + section_count * section_size:
                raise ValueError("invalid Mach-O segment section table")
            for section_index in range(section_count):
                section_cursor = cursor + expected_header + section_index * section_size
                section = bytes(data[section_cursor : section_cursor + 16]).split(
                    b"\0", 1
                )[0].decode("ascii", errors="replace")
                if is_64:
                    section_bytes = struct.unpack_from(
                        f"{endian}Q", data, section_cursor + 40
                    )[0]
                    flags, first_index, stride = struct.unpack_from(
                        f"{endian}III", data, section_cursor + 64
                    )
                    pointer_width = 8
                else:
                    section_bytes = struct.unpack_from(
                        f"{endian}I", data, section_cursor + 36
                    )[0]
                    flags, first_index, stride = struct.unpack_from(
                        f"{endian}III", data, section_cursor + 56
                    )
                    pointer_width = 4
                section_type = flags & SECTION_TYPE
                if section_type == S_NON_LAZY_SYMBOL_POINTERS:
                    if section_bytes % pointer_width:
                        raise ValueError("indirect-pointer section has a partial entry")
                    indirect_sections.append(
                        IndirectSection(
                            segment,
                            section,
                            section_type,
                            first_index,
                            section_bytes // pointer_width,
                        )
                    )
        cursor += command_size
    if cursor != commands_end:
        raise ValueError("Mach-O load-command size mismatch")
    if len(uuid_ranges) != 1:
        raise ValueError(f"expected exactly one LC_UUID, found {len(uuid_ranges)}")
    if (symbol_count is None) != (indirect_table is None):
        raise ValueError("Mach-O has only one of LC_SYMTAB/LC_DYSYMTAB")
    indirect = None
    if symbol_count is not None and indirect_table is not None:
        indirect = (indirect_table[0], indirect_table[1], symbol_count)
    return endian, uuid_ranges, signature_ranges, indirect, indirect_sections


def _normalize_invalid_got_indices(
    data: bytearray,
    endian: str,
    indirect: tuple[int, int, int] | None,
    sections: list[IndirectSection],
) -> int:
    if indirect is None:
        return 0
    table_offset, table_count, symbol_count = indirect
    replacements = 0
    for section in sections:
        if section.first_index + section.entry_count > table_count:
            raise ValueError("indirect section escapes LC_DYSYMTAB")
        for index in range(section.first_index, section.first_index + section.entry_count):
            entry_offset = table_offset + index * 4
            value = struct.unpack_from(f"{endian}I", data, entry_offset)[0]
            if value < symbol_count or value in (
                INDIRECT_SYMBOL_LOCAL,
                INDIRECT_SYMBOL_ABS,
                INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS,
            ):
                continue
            if (section.segment, section.section) != ("__DATA_CONST", "__got"):
                raise ValueError(
                    "invalid indirect-symbol index outside __DATA_CONST,__got: "
                    f"{section.segment},{section.section}[{index}]={value}"
                )
            struct.pack_into(f"{endian}I", data, entry_offset, INDIRECT_SYMBOL_LOCAL)
            replacements += 1
    if replacements > 1:
        raise ValueError(f"expected at most one invalid Zig GOT index, found {replacements}")
    return replacements


def normalize_bytes(data: bytes) -> tuple[bytes, list[str]]:
    output = bytearray(data)
    normalized_uuids = []
    for slice_info in macho_slices(output):
        endian, uuid_ranges, signature_ranges, indirect, sections = _load_commands(
            output, slice_info
        )
        _normalize_invalid_got_indices(output, endian, indirect, sections)
        canonical = bytearray(output[slice_info.offset : slice_info.offset + slice_info.size])
        for absolute, length in uuid_ranges + signature_ranges:
            local = absolute - slice_info.offset
            canonical[local : local + length] = b"\0" * length
        value = bytearray(hashlib.sha256(canonical).digest()[:16])
        value[6] = (value[6] & 0x0F) | 0x50
        value[8] = (value[8] & 0x3F) | 0x80
        for absolute, length in uuid_ranges:
            output[absolute : absolute + length] = value
        normalized_uuids.append(value.hex())
    return bytes(output), normalized_uuids


def normalize_file(path: str | os.PathLike[str]) -> list[str]:
    destination = Path(path)
    original_mode = destination.stat().st_mode
    normalized, uuids = normalize_bytes(destination.read_bytes())
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=destination.parent, delete=False) as stream:
            stream.write(normalized)
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.chmod(temporary, original_mode)
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return uuids


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: macho_repro.py <Mach-O>", file=sys.stderr)
        return 2
    try:
        uuids = normalize_file(sys.argv[1])
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("normalized Mach-O UUIDs: " + ", ".join(uuids))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
