#!/usr/bin/env python3
"""Version discovery must support the long-standing --version CLI interface."""
import unittest
import test_binary_installer as binary
import test_server_updater as updater

class PayloadVersionTests(binary.BinaryTests):
    def test_legacy_binary_default_payload_tag(self):
        self.online();self.env.pop('QELI_SRC',None)
        p=self.run_installer();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('/releases/tags/v0.8.2',(self.root/'records/curl.log').read_text())
        self.assertEqual((self.root/'usr/bin/qeli').read_bytes(),(self.root/'fixtures/new-qeli').read_bytes())

class UpdaterVersionTests(updater.UpdaterTests):
    def test_legacy_cli_installed_version_fallback(self):
        (self.root/'var/lib/dpkg/status').write_text('')
        p=self.run_update();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('Installed version: 0.8.1',p.stdout)

def load_tests(loader, tests, pattern):
    # The borrowed suites have their own CI steps; run only these two new cases.
    return unittest.TestSuite([PayloadVersionTests('test_legacy_binary_default_payload_tag'),UpdaterVersionTests('test_legacy_cli_installed_version_fallback')])

if __name__=='__main__':unittest.main(verbosity=2)
