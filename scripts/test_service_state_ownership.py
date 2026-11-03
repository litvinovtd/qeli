#!/usr/bin/env python3
"""Installer and packaged postinst ownership, actual filesystem with CLI seams."""
import unittest
import test_binary_installer as binary
import test_debian_lifecycle as debian

class InstallerOwnershipTests(binary.BinaryTests):
    def test_binary_install_keeps_receipts_and_backups_private(self):
        receipt=self.root/'etc/qeli/client-links/INSTALL-PENDING-fixture';receipt.write_text('private');receipt.chmod(0o600)
        backup=self.root/'etc/qeli/server.conf.bak-fixture';backup.write_text('backup');backup.chmod(0o600)
        p=self.run_installer();self.assertEqual(p.returncode,0,p.stderr)
        for file in [receipt,backup]:self.assertEqual(file.stat().st_uid,0);self.assertEqual(file.stat().st_mode&0o777,0o600)
        links=receipt.parent;self.assertEqual(links.stat().st_uid,0);self.assertEqual(links.stat().st_mode&0o777,0o700)
        self.assertEqual((self.root/'etc/qeli/users.conf').stat().st_uid,234)

class DebianOwnershipTests(debian.DebianTests):
    def test_package_install_keeps_receipts_and_backups_private(self):
        receipt=self.root/'etc/qeli/client-links/INSTALL-PENDING-fixture';receipt.write_text('private');receipt.chmod(0o600)
        backup=self.root/'etc/qeli/server.conf.bak-fixture';backup.write_text('backup');backup.chmod(0o600)
        p=self.install();self.assertEqual(p.returncode,0,p.stderr)
        for file in [receipt,backup]:self.assertEqual(file.stat().st_uid,0);self.assertEqual(file.stat().st_mode&0o777,0o600)
        links=receipt.parent;self.assertEqual(links.stat().st_uid,0);self.assertEqual(links.stat().st_mode&0o777,0o700)
        self.assertEqual((self.root/'etc/qeli/users.conf').stat().st_uid,234)

def load_tests(loader, tests, pattern):
    return unittest.TestSuite([InstallerOwnershipTests('test_binary_install_keeps_receipts_and_backups_private'),DebianOwnershipTests('test_package_install_keeps_receipts_and_backups_private')])

if __name__=='__main__':unittest.main(verbosity=2)
