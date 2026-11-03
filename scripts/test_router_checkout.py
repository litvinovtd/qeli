"""Isolation admission models plus real private POSIX checkout/restriction operations."""
import os
from pathlib import Path
import re
import shutil
import unittest
from unittest.mock import Mock,patch
import router_source
from test_router_source import LocalClient

class RouterCheckoutTests(unittest.TestCase):
    def test_invalid_kind_never_runs_command(self):
        c=Mock()
        for kind in ('','../bad','keenetic;bad','other'):
            with self.assertRaises(ValueError):router_source.create_router_checkout(c,kind)
        c.exec_command.assert_not_called()

    def test_invalid_mktemp_output_never_admits_or_syncs_path(self):
        for output in ('/opt/qeli-src','/','/var/tmp/qeli-router-keenetic-ABC123\n/opt/bad',
                       '/var/tmp/qeli-router-keenetic-ABC123;touch bad',
                       '/var/tmp/qeli-router-openwrt-ABC123','/var/tmp/qeli-router-keenetic-ABC'):
            connection=Mock();connection.checked.return_value=output
            with self.subTest(output=output),patch.object(router_source,'LabConnection',return_value=connection):
                with self.assertRaises(RuntimeError):router_source.create_router_checkout(Mock(),'keenetic')
            self.assertEqual(connection.checked.call_count,1)

    def test_allocation_and_directory_check_failures_propagate(self):
        for stage in (0,1):
            connection=Mock()
            connection.checked.side_effect=[RuntimeError('allocation')] if stage==0 else ['/var/tmp/qeli-router-openwrt-ABC123',RuntimeError('directory')]
            with self.subTest(stage=stage),patch.object(router_source,'LabConnection',return_value=connection):
                with self.assertRaises(RuntimeError):router_source.create_router_checkout(Mock(),'openwrt')

    def test_restriction_refuses_shared_relative_and_invalid_roots(self):
        c=Mock()
        for root in ('/opt/qeli-src','relative','/var/tmp/qeli-router-keenetic-ABC123/../bad',
                     '/var/tmp/qeli-router-bad-ABC123'):
            with self.assertRaises(ValueError):router_source.restrict_router_crate_types(c,root)
        c.exec_command.assert_not_called()

    @unittest.skipUnless(os.name=='posix','requires isolated real POSIX shell')
    def test_two_fresh_private_roots_per_kind_do_not_share_targets(self):
        c=LocalClient()
        for kind in ('keenetic','openwrt'):
            first=self.allocate(c,kind);second=self.allocate(c,kind)
            self.assertNotEqual(first,second)
            self.assertEqual(first.stat().st_mode&0o777,0o700)
            (first/'target').mkdir();(first/'target/stale').write_text('previous')
            self.assertFalse((second/'target').exists())
            self.assertEqual((first/'target/stale').read_text(),'previous')

    def allocate(self,c,kind):
        p=Path(router_source.create_router_checkout(c,kind))
        def cleanup():
            absolute=p.resolve()
            if re.fullmatch(r'/var/tmp/qeli-router-(keenetic|openwrt)-[A-Za-z0-9]{6}',str(absolute)) is None:
                raise RuntimeError('refusing cleanup outside owned checkout')
            shutil.rmtree(absolute)
        self.addCleanup(cleanup)
        return p

    @unittest.skipUnless(os.name=='posix','requires isolated real POSIX shell')
    def test_only_owned_uploaded_manifest_is_restricted_without_backup(self):
        c=LocalClient();first=self.allocate(c,'keenetic');second=self.allocate(c,'openwrt')
        text='[lib]\ncrate-type = ["rlib", "cdylib", "staticlib"]\n'
        for p in (first,second):(p/'Cargo.toml').write_text(text)
        router_source.restrict_router_crate_types(c,str(first))
        self.assertEqual((first/'Cargo.toml').read_text(),'[lib]\ncrate-type = ["rlib"]\n')
        self.assertEqual((second/'Cargo.toml').read_text(),text)
        self.assertFalse((first/'Cargo.toml.router-backup').exists())

    @unittest.skipUnless(os.name=='posix','requires isolated real POSIX shell')
    def test_unrecognized_manifest_cannot_claim_restriction(self):
        c=LocalClient();root=self.allocate(c,'openwrt')
        (root/'Cargo.toml').write_text('[lib]\ncrate-type = ["cdylib"]\n')
        with self.assertRaises(RuntimeError):router_source.restrict_router_crate_types(c,str(root))
        self.assertEqual((root/'Cargo.toml').read_text(),'[lib]\ncrate-type = ["cdylib"]\n')

if __name__=='__main__':unittest.main()
