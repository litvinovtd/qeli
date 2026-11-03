#!/usr/bin/env python3
"""Actual Qeli CLI integration in disposable Linux chroots; daemon/kernel are seams.

Set QELI_AUDIT_BINARY to an explicitly provenance-checked Linux binary. No download
or Rust build is performed; missing binary is a skip, never runtime qualification.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
import test_installer_secrets as fixture

BINARY = Path(os.environ.get('QELI_AUDIT_BINARY', '/nonexistent-qeli-audit-binary'))
RECORDS = os.environ.get('QELI_REAL_CLI_RECORDS')

@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0 and BINARY.is_file(), 'Linux root and explicit QELI_AUDIT_BINARY required')
class RealCliTests(unittest.TestCase):
    stub = fixture.SecretTests.__dict__['stub']
    tearDownClass = fixture.SecretTests.__dict__['tearDownClass']

    @classmethod
    def setUpClass(cls):
        fixture.SecretTests.setUpClass.__func__(cls)
        (cls.base / 'usr/local/bin/qeli').unlink()
        shutil.copy2(BINARY, cls.base / 'fixtures/new-qeli')
        (cls.base / 'fixtures/new-qeli').chmod(0o755)
        for lib in re.findall(r'(/[^\s]+)', subprocess.run(['ldd', str(BINARY)], capture_output=True, text=True).stdout):
            p=cls.base / lib.lstrip('/');p.parent.mkdir(parents=True, exist_ok=True);shutil.copy2(lib,p)

    def setUp(self):
        fixture.SecretTests.setUp(self)
        (self.root / 'etc/qeli/server.conf').unlink()
        (self.root / 'etc/qeli/users.conf').unlink()
        (self.root / 'etc/qeli/identity/default.key').unlink()
        self.env['QELI_RUN_AS']='root'

    def run_cli(self, *args, input=None):
        return subprocess.run([self.chroot,str(self.root),'/usr/bin/qeli',*args],env=self.env,input=input,capture_output=True,text=True,timeout=30)

    def install(self, profile):
        self.env['QELI_PROFILE']=profile
        p=subprocess.run([self.chroot,str(self.root),'/bin/bash','/installer.sh','vpn.example'],env=self.env,capture_output=True,text=True,timeout=60)
        if RECORDS:
            r=Path(RECORDS)/self.id().split('.')[-1];r.mkdir(parents=True,exist_ok=True)
            (r/'installer.log').write_text(p.stdout+p.stderr)
            for file in (self.root/'etc/qeli').rglob('*'):
                if file.is_file():
                    dst=r/file.relative_to(self.root/'etc/qeli');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(file,dst)
            (r/'returncode').write_text(str(p.returncode))
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        self.assertFalse(list((self.root/'etc/qeli').glob('*.qeli-*')))
        conf=self.root/'etc/qeli/server.conf';self.assertEqual(conf.stat().st_mode&0o777,0o600);self.assertEqual(conf.stat().st_uid,234)
        users=(self.root/'etc/qeli/users.conf').read_text();self.assertEqual(users.count('[user:phone'),5);self.assertEqual(users.count('$argon2'),5)
        text=conf.read_text();self.assertIn('[profile:'+profile+']',text);self.assertEqual(text.count('[profile:'),1);self.assertIn('$argon2',text)
        self.assertEqual(self.run_cli('check-config','--config','/etc/qeli/server.conf').returncode,0)
        summary=(self.root/'etc/qeli/client-links/CONNECTION-STRINGS.txt').read_text();self.assertEqual(summary.count('qeli://'),5)
        self.assertFalse(list((self.root/'etc/qeli/client-links').glob('INSTALL-PENDING-*')))
        return text

    def test_actual_udp_installer(self): self.install('udp-quic')
    def test_actual_fake_tls_installer(self): self.install('fake-tls')
    def test_actual_reality_installer(self): self.install('reality-tls')

    def test_actual_invalid_stage_refuses_without_changing_live(self):
        self.install('udp-quic');live=self.root/'etc/qeli/server.conf';old=live.read_bytes();stage=live.with_name('server.conf.qeli-invalid')
        stage.write_text(live.read_text().replace('bind.port = 443','bind.port = invalid'))
        p=self.run_cli('check-config','--config','/etc/qeli/server.conf.qeli-invalid');self.assertNotEqual(p.returncode,0,p.stdout+p.stderr);self.assertEqual(live.read_bytes(),old)
        stage.unlink()

    def test_actual_custom_service_override_and_revert(self):
        shutil.copy2(BINARY,self.root/'usr/bin/qeli');(self.root/'usr/bin/qeli').chmod(0o755)
        for user in ['root','qeli']:
            p=self.run_cli('set-service-user',user,'--unit','audit-fixture.service');self.assertEqual(p.returncode,0,p.stderr)
            path=self.root/'etc/systemd/system/audit-fixture.service.d/run-as.conf'
            if user=='root':
                self.assertIn('User=root',path.read_text());self.assertIn('CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER',path.read_text());self.assertIn('AmbientCapabilities=\n',path.read_text())
            else:self.assertFalse(path.exists())
        self.assertNotIn('restart', (self.root/'records/systemctl.log').read_text())

    def copy_binary(self):
        shutil.copy2(BINARY,self.root/'usr/bin/qeli');(self.root/'usr/bin/qeli').chmod(0o755)

    def root_override(self):
        for name, line in [('passwd', 'qeli:x:234:234::/var/lib/qeli:/usr/sbin/nologin'), ('group', 'qeli:x:234:')]:
            path=self.root/'etc'/name
            if not any(row.startswith('qeli:') for row in path.read_text().splitlines()):
                with path.open('a') as stream:stream.write(line+'\n')
        self.copy_binary();p=self.run_cli('set-service-user','root');self.assertEqual(p.returncode,0,p.stderr)
        return self.root/'etc/systemd/system/qeli.service.d/run-as.conf'

    def test_default_service_revert_keeps_admin_data_private(self):
        dropin=self.root_override();links=self.root/'etc/qeli/client-links';links.chmod(0o700)
        receipt=links/'INSTALL-PENDING-fixture';receipt.write_text('private password');receipt.chmod(0o600)
        backup=self.root/'etc/qeli/server.conf.bak-fixture';backup.write_text('private backup');backup.chmod(0o600)
        users=self.root/'etc/qeli/users.conf';users.write_text('daemon data');users.chmod(0o600)
        p=self.run_cli('set-service-user','qeli');self.assertEqual(p.returncode,0,p.stderr)
        self.assertFalse(dropin.exists());self.assertEqual(users.stat().st_uid,234)
        for file in [receipt,backup]:self.assertEqual(file.stat().st_uid,0);self.assertEqual(file.stat().st_mode&0o777,0o600)
        self.assertEqual(links.stat().st_uid,0);self.assertEqual(links.stat().st_mode&0o777,0o700)
        p=subprocess.run([self.chroot,'--userspec=234:234',str(self.root),'/bin/bash','-c','test -r /etc/qeli/client-links/INSTALL-PENDING-fixture'],capture_output=True)
        self.assertNotEqual(p.returncode,0)

    def test_default_service_refuses_linked_state_and_keeps_override(self):
        dropin=self.root_override();state=self.root/'etc/qeli';state.rename(self.root/'saved-state');state.symlink_to('/outside')
        witness=self.root/'outside/witness';witness.write_text('outside');before=witness.stat().st_uid
        p=self.run_cli('set-service-user','qeli');self.assertNotEqual(p.returncode,0,p.stdout+p.stderr)
        self.assertTrue(dropin.exists());self.assertEqual(witness.stat().st_uid,before)

    def test_default_service_chown_failure_keeps_override(self):
        dropin=self.root_override();fault=self.root/'usr/local/bin/chown'
        fault.write_text('#!/bin/bash\nexit 42\n');fault.chmod(0o755)
        p=self.run_cli('set-service-user','qeli');self.assertNotEqual(p.returncode,0,p.stdout+p.stderr);self.assertTrue(dropin.exists())

    def test_default_service_nonroot_refusal(self):
        dropin=self.root_override();before=dropin.read_bytes()
        p=subprocess.run([self.chroot,'--userspec=234:234',str(self.root),'/usr/bin/qeli','set-service-user','qeli'],env=self.env,capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertEqual(dropin.read_bytes(),before)

    def test_forced_installer_default_removes_prior_root_override(self):
        self.install('udp-quic');dropin=self.root/'etc/systemd/system/qeli.service.d/run-as.conf';self.assertTrue(dropin.exists())
        links=self.root/'etc/qeli/client-links';before={p.name:(p.read_bytes(),p.stat().st_uid,p.stat().st_mode&0o777) for p in links.iterdir() if p.is_file() and p.name!='CONNECTION-STRINGS.txt'}
        self.env.update(QELI_RUN_AS='qeli',QELI_FORCE_RECONFIG='1')
        p=subprocess.run([self.chroot,str(self.root),'/bin/bash','/installer.sh','vpn.example'],env=self.env,capture_output=True,text=True,timeout=60)
        if RECORDS:
            record=Path(RECORDS)/self.id().split('.')[-1];(record/'forced-installer.log').write_text(p.stdout+p.stderr)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr);self.assertFalse(dropin.exists())
        self.assertEqual((self.root/'etc/qeli/server.conf').stat().st_uid,234)
        self.assertEqual(self.run_cli('check-config','--config','/etc/qeli/server.conf').returncode,0)
        for name,metadata in before.items():
            file=links/name;self.assertEqual((file.read_bytes(),file.stat().st_uid,file.stat().st_mode&0o777),metadata)
        self.assertEqual(links.stat().st_uid,0);self.assertEqual(links.stat().st_mode&0o777,0o700)

if __name__=='__main__':unittest.main(verbosity=2)
