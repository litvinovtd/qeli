"""Portable admission checks; mock codesign, never claim actual Apple qualification."""
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_ios_simulator as gate


def image(entitlements, platform=7):
    payload = plistlib.dumps(entitlements)
    offset = 32+152+24
    header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 2, 176, 0, 0)
    segment = struct.pack('<II16sQQQQiiII', 0x19, 152, b'__TEXT', 0, offset+len(payload),
                          0, offset+len(payload), 5, 5, 1, 0)
    section = struct.pack('<16s16sQQ8I', b'__entitlements', b'__TEXT', offset, len(payload),
                          offset, 0, 0, 0, 0, 0, 0, 0)
    build = struct.pack('<6I', 0x32, 24, platform, 0, 0, 0)
    return header+segment+section+build+payload


class SimulatorHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = Path(self.tmp.name) / "Qeli.app"
        self.app.mkdir()
        self.group = "FAKETEAMID.ru.qeli.app.shared"
        self.info = {"CFBundlePackageType": "APPL", "QeliKeychainAccessGroup": self.group,
                     "CFBundleExecutable": "Qeli"}
        self.write_info()

    def write_info(self):
        (self.app / "Info.plist").write_bytes(plistlib.dumps(self.info))

    def check(self, entitlements=None, verify_exit=0, executable=None):
        if entitlements is None:
            entitlements = {"keychain-access-groups": [self.group]}
        (self.app / 'Qeli').write_bytes(image(entitlements) if executable is None else executable)
        with patch.object(gate.sys, "platform", "darwin"), patch.object(gate.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], verify_exit, b"", b"")
            errors = gate.validate_host(self.app)
        return errors, run.call_args_list

    def test_signature_and_embedded_simulator_declaration_both_required(self):
        errors, calls = self.check()
        self.assertEqual(errors, [])
        self.assertEqual(calls[0].args[0], ["codesign", "--verify", "--strict", str(self.app)])
        self.assertEqual(len(calls), 1)  # Simulator groups are not macOS signature entitlements.
        self.assertTrue(all(c.kwargs["timeout"] == 30 for c in calls))

    def test_signature_failure_refuses_before_reading_entitlements(self):
        errors, calls = self.check(verify_exit=1)
        self.assertTrue(errors)
        self.assertEqual(len(calls), 1)

    def test_valid_signature_cannot_admit_bare_plist(self):
        self.assertTrue(self.check(executable=plistlib.dumps({'keychain-access-groups':[self.group]}))[0])

    def test_missing_foreign_and_scalar_groups_refused(self):
        for entitlements in [{}, {"keychain-access-groups": ["foreign"]},
                             {"keychain-access-groups": self.group},
                             {"keychain-access-groups": [self.group, 1]}]:
            with self.subTest(entitlements=entitlements):
                self.assertTrue(self.check(entitlements)[0])

    def test_invalid_host_metadata_refuses_before_codesign(self):
        for value in ["", "$(QELI_KEYCHAIN_GROUP)", None, 1]:
            with self.subTest(group=value):
                self.info["QeliKeychainAccessGroup"] = value
                if value is None:
                    self.info.pop("QeliKeychainAccessGroup")
                self.write_info()
                errors, calls = self.check()
                self.assertTrue(errors)
                self.assertFalse(calls)

    def test_extension_cannot_be_used_as_the_test_host(self):
        self.info["CFBundlePackageType"] = "XPC!"
        self.write_info()
        errors, calls = self.check()
        self.assertTrue(errors)
        self.assertFalse(calls)

    def test_missing_or_malformed_plist_refused(self):
        path = self.app / "Info.plist"
        path.unlink()
        self.assertTrue(self.check()[0])
        path.write_bytes(b"not a plist")
        self.assertTrue(self.check()[0])
        path.write_bytes(plistlib.dumps(["not a dictionary"]))
        self.assertTrue(self.check()[0])

    def test_codesign_timeout_and_launch_failure_refused(self):
        (self.app / 'Qeli').write_bytes(image({'keychain-access-groups':[self.group]}))
        for error in [subprocess.TimeoutExpired("codesign", 30), FileNotFoundError("codesign")]:
            with patch.object(gate.sys, "platform", "darwin"), patch.object(gate.subprocess, "run", side_effect=error):
                self.assertTrue(gate.validate_host(self.app))

    def test_device_binary_is_not_a_simulator_declaration(self):
        self.assertTrue(self.check(executable=image({'keychain-access-groups':[self.group]}, platform=2))[0])

    def test_empty_or_malformed_executable_refused(self):
        for output in [b"", b"<?xml version='1.0'?><plist>broken</plist>", plistlib.dumps([self.group])]:
            self.assertTrue(self.check(executable=output)[0])

    def test_executable_name_cannot_escape_bundle(self):
        for name in ('', '../Qeli', '/tmp/Qeli', 'a\\Qeli', '..', None):
            self.info['CFBundleExecutable'] = name
            if name is None:
                self.info.pop('CFBundleExecutable')
            self.write_info()
            self.assertTrue(self.check()[0])

    def test_truncated_commands_and_escaping_section_refused(self):
        valid = image({'keychain-access-groups':[self.group]})
        invalid = [valid[:16], valid[:40], valid[:100], valid[:-1]]
        for offset, value in ((20, 0xffffffff), (36, 0), (32+72+48, 0xffffffff), (32+72+40, 0)):
            data = bytearray(valid)
            struct.pack_into('<I', data, offset, value)
            invalid.append(bytes(data))
        for data in invalid:
            with self.subTest(size=len(data)):
                self.assertTrue(self.check(executable=data)[0])

    def test_every_universal_slice_requires_matching_group(self):
        one = image({'keychain-access-groups':[self.group]})
        two = image({'keychain-access-groups':['foreign']})
        header = struct.pack('>II', 0xcafebabe, 2)
        header += struct.pack('>5I', 0x100000c, 0, 48, len(one), 0)
        header += struct.pack('>5I', 0x1000007, 0, 48+len(one), len(two), 0)
        self.assertTrue(self.check(executable=header+one+two)[0])
        header = bytearray(header)
        struct.pack_into('>I', header, 40, len(one))
        self.assertFalse(self.check(executable=header+one+one)[0])

    def test_non_apple_host_cannot_report_signature_pass(self):
        with patch.object(gate.sys, "platform", "linux"), patch.object(gate.subprocess, "run") as run:
            self.assertTrue(gate.validate_host(self.app))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
