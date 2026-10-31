#!/usr/bin/env python3
"""Q33 installer dependency and package admission stage in Linux chroots.

Exact production prefix/functions plus early whole-program refusal; genuine dpkg
and package status. apt/HTTP/account/systemctl/gh are explicit seams, not a full
installer or end-to-end service qualification.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

import test_binary_installer as binary_fixture


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Linux root/chroot required')
class AdmissionTests(unittest.TestCase):
    stub = binary_fixture.BinaryTests.__dict__['stub']
    setUp = binary_fixture.BinaryTests.setUp
    tearDownClass = binary_fixture.BinaryTests.__dict__['tearDownClass']

    @classmethod
    def setUpClass(cls):
        binary_fixture.BinaryTests.setUpClass.__func__(cls)
        cls.stub('ip', 'exit 0')
        cls.stub('apt-get', r'''printf '%s\n' "$*" >> /records/apt.log
mode="$(< /records/mode)";last="${!#}"
if [[ "$1" == update ]]; then [[ "$mode" != update_fail ]]; exit; fi
if [[ "$last" == *.deb ]]; then
 [[ "$mode" != install_refused && "$mode" != repair_false ]] || exit 1
 [[ "$mode" != apt_false && "$mode" != old_version ]] || exit 0
 exec /usr/bin/dpkg -i "$last"
fi
[[ "$mode" != deps_fail ]] || exit 1
if [[ "$mode" == restore_deps ]]; then
 /usr/bin/cp /fixtures/ip /usr/local/bin/ip
fi
if [[ "$mode" == restore_sysctl ]]; then
 /usr/bin/cp /fixtures/sysctl /usr/local/bin/sysctl
fi
exit 0''')
        cls.stub('dpkg', r'''if [[ "$1" == -i && "$(< /records/mode)" == repair_false ]]; then exit 1; fi
exec /usr/bin/dpkg "$@"''')
        shutil.copy2(cls.base / 'usr/local/bin/ip', cls.base / 'fixtures/ip')
        shutil.copy2(cls.base / 'usr/local/bin/sysctl', cls.base / 'fixtures/sysctl')
        (cls.base / 'etc/ssl/certs').mkdir(parents=True)
        (cls.base / 'etc/ssl/certs/ca-certificates.crt').write_text('fixture CA availability only\n')
        stage = Path(cls.workspace.name) / 'broken-dependency'; (stage / 'DEBIAN').mkdir(parents=True)
        (stage / 'DEBIAN/control').write_text('Package: qeli\nVersion: 0.8.3\nArchitecture: amd64\nDepends: qeli-fixture-missing\nMaintainer: Audit <audit@localhost>\nDescription: inert missing-dependency fixture\n')
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', str(stage), str(cls.base / 'fixtures/qeli_broken.deb')], check=True, capture_output=True)
        record = os.environ.get('QELI_BINARY_FIXTURE_RECORDS')
        if record: shutil.copy2(cls.base / 'fixtures/qeli_broken.deb', Path(record) / 'qeli_broken.deb')

    def run_installer(self, command='from_source_install', whole=False):
        if os.environ.get('QELI_ADMISSION_BASELINE') == '1' and not whole:
            source = (self.root / 'installer.sh').read_text()
            if '_ensure_installer_deps' in command:
                a = source.index('log "Installing dependencies"'); b = source.index('# ── 2.', a)
                command = command.replace('_ensure_installer_deps', source[a:b])
            if command.startswith('_install_verified_deb '):
                package = command.split(' ', 1)[1]
                a = source.index('DEB_ARCH="$(dpkg-deb -f "$TMP_DEB" Architecture', source.index('# ── 3.'))
                b = source.index('fi   # end obtain+install', a)
                command = 'TMP_DEB=' + package + '; CLEANUP_DEB=0; HOST_DEB_ARCH="$(dpkg --print-architecture)";\n' + source[a:b] + '\ncommand -v qeli >/dev/null || die "qeli is not on PATH after install."'
        return binary_fixture.BinaryTests.run_installer(self, command, whole)

    def mode(self, value): (self.root / 'records/mode').write_text(value)

    def deps(self):
        return self.run_installer('PUBLIC_HOST=vpn.example; _ensure_installer_deps')

    def install(self, name='qeli_0.8.2_amd64.deb'):
        return self.run_installer('_install_verified_deb /fixtures/' + name)

    def status(self):
        return subprocess.run([self.chroot, str(self.root), '/usr/bin/dpkg-query', '-W', '-f=${Status} ${Version} ${Architecture}', 'qeli'], capture_output=True, text=True).stdout

    def test_local_binary_dependencies_skip_apt_and_http(self):
        (self.root / 'usr/local/bin/curl').unlink(); (self.root / 'usr/bin/jq').unlink()
        p = self.deps(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse((self.root / 'records/apt.log').exists())

    def test_local_deb_dependencies_skip_apt_and_http(self):
        self.env.pop('QELI_BIN'); self.env['QELI_DEB'] = '/fixtures/qeli_0.8.2_amd64.deb'
        (self.root / 'usr/local/bin/curl').unlink(); (self.root / 'usr/bin/jq').unlink()
        p = self.deps(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse((self.root / 'records/apt.log').exists())

    def test_available_online_dependencies_skip_apt(self):
        self.env.pop('QELI_SRC'); p = self.deps(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse((self.root / 'records/apt.log').exists())

    def test_missing_dependency_installed_once_and_rechecked(self):
        (self.root / 'usr/local/bin/ip').unlink(); self.mode('restore_deps')
        p = self.deps(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((self.root / 'records/apt.log').read_text().splitlines(), ['update -y', 'install -y --no-install-recommends iproute2'])

    def test_missing_sysctl_installs_procps_and_rechecks(self):
        (self.root/'usr/local/bin/sysctl').unlink();self.mode('restore_sysctl')
        p=self.deps();self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual((self.root/'records/apt.log').read_text().splitlines(),
                         ['update -y','install -y --no-install-recommends procps'])

    def test_failed_index_refuses_before_package_publish(self):
        (self.root / 'usr/local/bin/ip').unlink(); self.mode('update_fail')
        (self.root / 'etc/qeli/server.conf').unlink()
        p = self.run_installer(whole=True); self.assertNotEqual(p.returncode, 0)
        self.assertIn('index refresh failed', p.stderr)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)
        self.assertEqual((self.root / 'records/apt.log').read_text().splitlines(), ['update -y'])

    def test_failed_dependency_install_refuses(self):
        (self.root / 'usr/local/bin/ip').unlink(); self.mode('deps_fail')
        p = self.deps(); self.assertNotEqual(p.returncode, 0); self.assertIn('dependency installation failed', p.stderr)

    def test_false_success_cannot_hide_missing_command(self):
        (self.root / 'usr/local/bin/ip').unlink()
        p = self.deps(); self.assertNotEqual(p.returncode, 0); self.assertIn('required dependency command', p.stderr)

    def test_online_missing_jq_refuses_after_false_apt_success(self):
        self.env.pop('QELI_SRC'); (self.root / 'usr/bin/jq').unlink()
        p = self.deps(); self.assertNotEqual(p.returncode, 0)
        self.assertIn('jq', (self.root / 'records/apt.log').read_text())

    def test_online_missing_ca_bundle_refuses(self):
        self.env.pop('QELI_SRC'); (self.root / 'etc/ssl/certs/ca-certificates.crt').unlink()
        p = self.deps(); self.assertNotEqual(p.returncode, 0); self.assertIn('CA certificate bundle', p.stderr)
        self.assertIn('ca-certificates', (self.root / 'records/apt.log').read_text())

    def test_local_package_real_dpkg_admitted(self):
        p = self.install(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.status(), 'install ok installed 0.8.2 amd64')
        self.assertNotIn('update', (self.root / 'records/apt.log').read_text())

    def test_all_architecture_real_dpkg_admitted(self):
        p = self.install('qeli_0.8.2_all.deb'); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.status(), 'install ok installed 0.8.2 all')

    def test_wrong_package_arch_and_corrupt_refuse_before_apt(self):
        (self.root / 'fixtures/corrupt.deb').write_text('not a Debian package')
        for name in ['other_0.8.2_amd64.deb', 'qeli_0.8.2_arm64.deb', 'corrupt.deb']:
            with self.subTest(package=name):
                p = self.install(name); self.assertNotEqual(p.returncode, 0)
                self.assertFalse((self.root / 'records/apt.log').exists())
                self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)

    def test_whole_wrong_local_package_refuses_before_dependencies(self):
        self.env.pop('QELI_BIN'); self.env['QELI_DEB'] = '/fixtures/other_0.8.2_amd64.deb'
        (self.root / 'etc/qeli/server.conf').unlink()
        p = self.run_installer(whole=True); self.assertNotEqual(p.returncode, 0)
        self.assertIn('Package=qeli', p.stderr); self.assertFalse((self.root / 'records/apt.log').exists())

    def test_false_apt_success_not_installed_refused(self):
        self.mode('apt_false'); p = self.install(); self.assertNotEqual(p.returncode, 0)
        self.assertIn('did not configure', p.stderr)

    def test_wrong_installed_version_refused(self):
        p = subprocess.run([self.chroot, str(self.root), '/usr/bin/dpkg', '-i', '/fixtures/qeli_0.8.1-1_amd64.deb'], capture_output=True); self.assertEqual(p.returncode, 0)
        self.mode('old_version'); p = self.install(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.status(), 'install ok installed 0.8.1-1 amd64')

    def test_repair_false_success_refused(self):
        self.mode('repair_false'); p = self.install(); self.assertNotEqual(p.returncode, 0)
        self.assertIn('did not configure', p.stderr); self.assertIn(' -f', (self.root / 'records/apt.log').read_text())

    def test_unconfigured_real_package_refused(self):
        p = self.install('qeli_broken.deb'); self.assertNotEqual(p.returncode, 0)
        self.assertIn('did not configure', p.stderr)
        self.assertEqual(self.status(), 'install ok unpacked 0.8.3 amd64')

    def test_required_attestation_missing_failed_success(self):
        self.env['QELI_VERIFY_ATTESTATION'] = '1'
        p = self.install(); self.assertNotEqual(p.returncode, 0); self.assertFalse((self.root / 'records/apt.log').exists())
        gh = self.root / 'usr/local/bin/gh'; gh.write_text('#!/bin/bash\nexit 1\n'); gh.chmod(0o755)
        p = self.install(); self.assertNotEqual(p.returncode, 0); self.assertFalse((self.root / 'records/apt.log').exists())
        gh.write_text('#!/bin/bash\nprintf "%s\\n" "$*" > /records/gh-argv\n')
        p = self.install(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((self.root / 'records/gh-argv').read_text().strip(), 'attestation verify /fixtures/qeli_0.8.2_amd64.deb --repo litvinovtd/qeli')


if __name__ == '__main__':
    unittest.main(verbosity=2)
