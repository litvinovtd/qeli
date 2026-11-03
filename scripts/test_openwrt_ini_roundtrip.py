"""Render through the actual OpenWrt init and parse with the exact shared Rust INI.
Requires QELI_OPENWRT_INI_INSPECTOR compiled from config/format.rs in an owned lab.
No real UCI/procd/firewall or service changes.
"""
import os
import shutil
import subprocess
import unittest
import test_openwrt_init as init_fixture

SHELL = init_fixture.SHELL

INSPECTOR = os.environ.get("QELI_OPENWRT_INI_INSPECTOR", "")
VALUES = (' user ', '"user"', 'a\\"b', 'tail\\', 'x#;=y', 'a"b"c',
          '  ', '\u00a0user\u00a0', 'русский 日本語', "'single'",
          '$(touch NEVER) '+chr(96)+'id'+chr(96)+' $HOME', '\\\\"double\\\\"', 'simple')

@unittest.skipUnless(INSPECTOR and shutil.which(SHELL[0]),
                     "requires exact shared Rust INI inspector and POSIX shell")
class OpenWrtIniRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.fixture = init_fixture.OpenWrtInitTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        if os.environ.get("QELI_OPENWRT_INI_INIT_FIXTURE"):
            self.fixture.env["QELI_TEST_INIT"] = os.environ["QELI_OPENWRT_INI_INIT_FIXTURE"]

    def parse(self):
        result = subprocess.run([INSPECTOR], input=self.fixture.config(),
                                text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        pairs = {}
        for row in result.stdout.splitlines():
            section, key, encoded = row.split("\t", 2)
            pairs[section, key] = bytes.fromhex(encoded).decode("utf-8")
        return pairs

    def test_ini_writer_preserves_quotes_backslashes_whitespace_and_unicode(self):
        for value in VALUES:
            with self.subTest(value=value):
                result = self.fixture.run_shell('printf "[qeli]\\n" > "$CONF"; ini_kv user "$QELI_TEST_VALUE"', VALUE=value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.parse()["qeli", "user"], value)

    def test_render_preserves_user_without_command_expansion_or_key_injection(self):
        for value in VALUES:
            with self.subTest(value=value):
                result = self.fixture.run_shell("render_conf", user=value)
                self.assertEqual(result.returncode, 0, result.stderr)
                parsed = self.parse()
                self.assertEqual(parsed["qeli", "user"], value)
                self.assertNotIn(("qeli", "post_up"), parsed)
                self.assertFalse((self.fixture.root/"NEVER").exists())

    def test_render_obfs_secret_has_same_bytes_as_volatile_file(self):
        for value in VALUES:
            with self.subTest(value=value):
                (self.fixture.root/"run/obfs-key").write_text(value, encoding="utf-8")
                result = self.fixture.run_shell("render_conf", mode="obfs")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.parse()["qeli", "obfs_key"], value)
                self.assertEqual((self.fixture.root/"run/client.conf").stat().st_mode & 0o777, 0o600)

    def test_required_fields_logging_and_control_stripping_use_same_writer(self):
        result = self.fixture.run_shell("render_conf", server=' endpoint"\\:443 ',
                                       proto="tcp", log_level=' info"\\ ',
                                       log_time_format=' none"\\ ',
                                       user='a\npost_up=bad\x7fb')
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = self.parse()
        self.assertEqual(parsed["qeli", "server"], ' endpoint"\\:443 ')
        self.assertEqual(parsed["qeli", "proto"], "tcp")
        self.assertEqual(parsed["logging", "level"], ' info"\\ ')
        self.assertEqual(parsed["logging", "time_format"], ' none"\\ ')
        self.assertEqual(parsed["qeli", "user"], 'apost_up=badb')
        self.assertEqual(parsed["qeli", "password_file"], str(self.fixture.root/"run/password"))
        self.assertNotIn(("qeli", "post_up"), parsed)

if __name__ == "__main__":
    unittest.main()
