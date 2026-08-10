#!/usr/bin/env python3

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import macho_repro


def thin_macho(uuid: bytes, signature: bytes) -> bytes:
    header_size = 32
    uuid_command = struct.pack("<II16s", macho_repro.LC_UUID, 24, uuid)
    signature_offset = header_size + 24 + 16
    signature_command = struct.pack(
        "<IIII", macho_repro.LC_CODE_SIGNATURE, 16, signature_offset, len(signature)
    )
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x01000007,
        3,
        6,
        2,
        len(uuid_command) + len(signature_command),
        0,
        0,
    )
    return header + uuid_command + signature_command + signature


def fat_macho(first: bytes, second: bytes) -> bytes:
    first_offset = 48
    second_offset = first_offset + len(first)
    header = struct.pack(
        ">IIiiIIIiiIII",
        0xCAFEBABE,
        2,
        0x01000007,
        3,
        first_offset,
        len(first),
        0,
        0x0100000C,
        0,
        second_offset,
        len(second),
        0,
    )
    return header + first + second


def thin_macho_with_got(uuid: bytes, signature: bytes, indirect_index: int) -> bytes:
    header_size = 32
    segment_size = 72 + 80
    command_bytes = segment_size + 24 + 80 + 24 + 16
    got_offset = header_size + command_bytes
    symbol_offset = got_offset + 8
    indirect_offset = symbol_offset + 32
    signature_offset = indirect_offset + 4
    total_size = signature_offset + len(signature)
    segment = struct.pack(
        "<II16sQQQQiiII",
        macho_repro.LC_SEGMENT_64,
        segment_size,
        b"__DATA_CONST",
        0,
        4096,
        0,
        total_size,
        3,
        3,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__got",
        b"__DATA_CONST",
        0,
        8,
        got_offset,
        3,
        0,
        0,
        macho_repro.S_NON_LAZY_SYMBOL_POINTERS,
        0,
        0,
        0,
    )
    symtab = struct.pack(
        "<IIIIII", macho_repro.LC_SYMTAB, 24, symbol_offset, 2, 0, 0
    )
    dysymtab_fields = [0] * 18
    dysymtab_fields[12] = indirect_offset
    dysymtab_fields[13] = 1
    dysymtab = struct.pack("<" + "I" * 20, macho_repro.LC_DYSYMTAB, 80, *dysymtab_fields)
    uuid_command = struct.pack("<II16s", macho_repro.LC_UUID, 24, uuid)
    signature_command = struct.pack(
        "<IIII", macho_repro.LC_CODE_SIGNATURE, 16, signature_offset, len(signature)
    )
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x01000007,
        3,
        6,
        5,
        command_bytes,
        0,
        0,
    )
    return (
        header
        + segment
        + section
        + symtab
        + dysymtab
        + uuid_command
        + signature_command
        + b"\0" * 8
        + b"\0" * 32
        + struct.pack("<I", indirect_index)
        + signature
    )


class MachoReproTests(unittest.TestCase):
    def test_random_uuid_and_signature_normalize_to_identical_bytes(self):
        first = thin_macho(b"a" * 16, b"signature-a")
        second = thin_macho(b"b" * 16, b"signature-b")
        normalized_a, uuids_a = macho_repro.normalize_bytes(first)
        normalized_b, uuids_b = macho_repro.normalize_bytes(second)
        self.assertEqual(uuids_a, uuids_b)
        self.assertNotEqual(uuids_a, ["00" * 16])
        self.assertNotEqual(normalized_a, normalized_b)  # old valid signatures are retained

    def test_both_fat_slices_are_normalized(self):
        first = fat_macho(
            thin_macho(b"a" * 16, b"signature-a"),
            thin_macho(b"b" * 16, b"signature-b"),
        )
        second = fat_macho(
            thin_macho(b"c" * 16, b"signature-c"),
            thin_macho(b"d" * 16, b"signature-d"),
        )
        normalized_a, uuids_a = macho_repro.normalize_bytes(first)
        normalized_b, uuids_b = macho_repro.normalize_bytes(second)
        self.assertEqual(uuids_a, uuids_b)
        self.assertEqual(len(uuids_a), 2)
        self.assertNotEqual(normalized_a, normalized_b)

    def test_missing_uuid_is_rejected(self):
        data = struct.pack("<IiiIIIII", 0xFEEDFACF, 1, 1, 6, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "exactly one LC_UUID"):
            macho_repro.normalize_bytes(data)

    def test_invalid_zig_got_index_is_canonicalized(self):
        first = thin_macho_with_got(b"a" * 16, b"same-signature", 21919)
        second = thin_macho_with_got(b"b" * 16, b"same-signature", 21876)
        normalized_a, uuids_a = macho_repro.normalize_bytes(first)
        normalized_b, uuids_b = macho_repro.normalize_bytes(second)
        self.assertEqual(normalized_a, normalized_b)
        self.assertEqual(uuids_a, uuids_b)
        indirect_offset = len(normalized_a) - len(b"same-signature") - 4
        self.assertEqual(
            struct.unpack_from("<I", normalized_a, indirect_offset)[0],
            macho_repro.INDIRECT_SYMBOL_LOCAL,
        )


if __name__ == "__main__":
    unittest.main()
