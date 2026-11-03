"""Actual Mach-O load-command fixtures, without Apple tools or a compiler."""
import plistlib
import struct
import tempfile
from pathlib import Path
import unittest

from check_macos_deployment import check_binary, check_bundle, declared_minimum


def thin(minimum, legacy=False):
    if legacy:
        command = struct.pack('<IIII', 0x24, 16, minimum, minimum)
    else:
        command = struct.pack('<IIIIII', 0x32, 24, 1, minimum, minimum, 0)
    uuid = struct.pack('<II', 0x1b, 24) + bytes(16)
    return struct.pack('<IIIIIIII', 0xfeedfacf, 0x100000c, 0, 2, 2, len(command) + len(uuid), 0, 0) + command + uuid


class DeploymentTests(unittest.TestCase):
    def test_old_plist_floor_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'at least 15'):
            declared_minimum(plistlib.dumps({'LSMinimumSystemVersion': '11.0'}))

    def test_later_runtime_is_refused_for_advertised_floor(self):
        with self.assertRaisesRegex(ValueError, 'above Info.plist'):
            check_binary(thin(16 << 16), (15, 0, 0))

    def test_supported_floor_accepts_older_runtime_targets(self):
        for legacy in (False, True):
            check_binary(thin(12 << 16, legacy), (15, 0, 0))

    def test_second_fat_slice_cannot_require_a_newer_os(self):
        a, b = thin(12 << 16), thin(16 << 16)
        header = struct.pack('>II', 0xcafebabe, 2)
        header += struct.pack('>IIIII', 0x100000c, 0, 48, len(a), 0)
        header += struct.pack('>IIIII', 0x1000007, 0, 48 + len(a), len(b), 0)
        with self.assertRaisesRegex(ValueError, 'above Info.plist'):
            check_binary(header + a + b, (15, 0, 0))

    def test_truncated_load_commands_are_refused(self):
        with self.assertRaises(ValueError):
            check_binary(thin(12 << 16)[:-1], (15, 0, 0))

    def test_missing_target_is_refused(self):
        data = bytearray(thin(12 << 16))
        struct.pack_into('<I', data, 32, 0x80000000)
        with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
            check_binary(data, (15, 0, 0))

    def test_bundle_checks_runtime_libraries_not_only_apphost(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory)
            macos = app / 'Contents/MacOS'
            macos.mkdir(parents=True)
            (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'LSMinimumSystemVersion': '15.0'}))
            (macos / 'QeliMac').write_bytes(thin(12 << 16))
            (macos / 'libcoreclr.dylib').write_bytes(thin(16 << 16))
            with self.assertRaisesRegex(ValueError, 'above Info.plist'):
                check_bundle(app)
            (macos / 'libcoreclr.dylib').write_bytes(thin(12 << 16))
            self.assertEqual(check_bundle(app), 2)


if __name__ == '__main__':
    unittest.main()
