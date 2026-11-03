"""Actual offline opkg tests on an explicitly marked, private Linux rootfs.
QELI_OPENWRT_OPKG_ROOTFS requires prepared genuine packages/dependencies.
No forced dependencies, simulated installed records or VPN startup.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_openwrt_sdk import ipk_contents

TEMPLATE = os.environ.get('QELI_OPENWRT_OPKG_ROOTFS', '')
SOURCE = Path(__file__).resolve().parents[1]


@unittest.skipUnless(TEMPLATE and os.name == 'posix', 'requires owned Linux OpenWrt fixture')
class OpkgTests(unittest.TestCase):
    def setUp(self):
        template = Path(TEMPLATE).resolve()
        self.assertEqual(template.parent.parent, Path('/var/tmp'))
        self.assertTrue(template.parent.name.startswith(('qeli-q31-openwrt-opkg-', 'qeli-sdk-')))
        self.assertEqual(template.name, 'rootfs-template')
        self.assertEqual((template/'.qeli-opkg-audit').read_text().strip(),
                         'qeli-openwrt-opkg-fixture-v1')
        self.assertEqual(os.geteuid(), 0)
        self.run = template.parent
        self.wrapper = Path(tempfile.mkdtemp(prefix='opkg-case-', dir=self.run))
        self.addCleanup(shutil.rmtree, self.wrapper)
        shutil.copytree(template, self.wrapper, symlinks=True, dirs_exist_ok=True)
        self.root = self.wrapper/'target'
        shutil.copytree(template, self.root, symlinks=True)
        self.step = 0
        self.groups = json.loads((self.run/'dependency-groups.json').read_text())
        self.deps = json.loads((self.run/'dependencies.json').read_text())

    def command(self, *args, success=True, target=False):
        self.step += 1
        log = self.run/'logs'/f'{self.id().split(".")[-1]}-{self.step}.log'
        # The host may use a merged /usr PATH (for example under systemd),
        # while the OpenWrt rootfs keeps busybox utilities in /bin and /sbin.
        env = dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin')
        try:
            result = subprocess.run(['unshare', '--mount', '--net', '--pid', '--fork',
                                     '--kill-child=KILL',
                                     'chroot', str(self.root if target else self.wrapper), *args],
                                    env=env, capture_output=True, timeout=40)
        except subprocess.TimeoutExpired as error:
            log.write_bytes((error.stdout or b'') + (error.stderr or b''))
            raise
        log.write_bytes(result.stdout+result.stderr)
        if success:
            self.assertEqual(result.returncode, 0, log.read_text(errors='replace'))
        else:
            self.assertNotEqual(result.returncode, 0, log.read_text(errors='replace'))
        return result

    def opkg(self, *args, success=True):
        return self.command('/bin/opkg', '--offline-root', '/target', '--conf',
                            '/fixtures/opkg.conf', *args, success=success)

    def status(self):
        result = {}
        for block in (self.root/'usr/lib/opkg/status').read_text().split('\n\n'):
            fields = dict(line.split(': ', 1) for line in block.splitlines()
                          if ': ' in line and not line.startswith(' '))
            if 'Package' in fields: result[fields['Package']] = fields
        return result

    def install(self, backend='nft'):
        archives = ['/fixtures/cache/'+Path(self.deps[n]['Filename']).name for n in self.groups[backend]]
        self.opkg('install', *archives, '/fixtures/qeli.ipk', '/fixtures/luci.ipk')
        installed = self.status()
        for name in ['qeli', 'luci-app-qeli', *self.groups[backend]]:
            self.assertIn('installed', installed[name]['Status'], name)
        self.assertFalse(any('qeli' in p.name for p in (self.root/'etc/rc.d').iterdir()))

    def verify_payload(self):
        control, payload = ipk_contents(self.root/'fixtures/qeli.ipk')
        modes = {'usr/bin/qeli-client': 0o755, 'etc/init.d/qeli': 0o755,
                 'etc/config/qeli': 0o600, 'etc/uci-defaults/99-qeli-firewall': 0o755}
        notices = SOURCE/'qeli/third-party-notices/rust'
        expected_notices = {}
        for source in sorted(notices.rglob('*')):
            self.assertFalse(source.is_symlink(), source)
            if source.is_file():
                name = 'usr/share/licenses/qeli/rust/'+source.relative_to(notices).as_posix()
                expected_notices[name] = source.read_bytes()
        self.assertIn('usr/share/licenses/qeli/rust/INDEX.tsv', expected_notices)
        self.assertIn('usr/share/licenses/qeli/rust/BINDING.properties', expected_notices)
        modes.update({name: 0o644 for name in expected_notices})
        self.assertEqual(set(payload), set(modes))
        self.assertEqual(control['Version'], '0.8.2-r1')
        self.assertEqual(set(control['Depends'].split(', ')),
                         {'libc', 'kmod-tun', 'ip-full', 'iptables', 'ip6tables', 'ca-bundle'})
        for name, mode in modes.items():
            p = self.root/name
            self.assertEqual(p.read_bytes(), payload[name][0], name)
            self.assertEqual(p.stat().st_mode & 0o777, mode, name)
            self.assertEqual(p.stat().st_uid, 0, name)
        for name, expected in expected_notices.items():
            self.assertEqual(payload[name][0], expected, name)
        installed_notices = self.root/'usr/share/licenses/qeli/rust'
        for directory in [installed_notices, *installed_notices.rglob('*')]:
            if directory.is_dir():
                self.assertFalse(directory.is_symlink(), directory)
                self.assertEqual(directory.stat().st_mode & 0o777, 0o755, directory)
                self.assertEqual(directory.stat().st_uid, 0, directory)
        for source, target in [('qeli.init', 'etc/init.d/qeli'), ('qeli.config', 'etc/config/qeli'),
                               ('qeli.firewall.uci-defaults', 'etc/uci-defaults/99-qeli-firewall')]:
            self.assertEqual((SOURCE/'qeli-openwrt/files'/source).read_bytes(), (self.root/target).read_bytes())
        _, payload = ipk_contents(self.root/'fixtures/luci.ipk')
        for name, (data, mode) in payload.items():
            self.assertEqual((self.root/name).read_bytes(), data, name)
            self.assertEqual((self.root/name).stat().st_mode & 0o777, mode, name)
        self.assertEqual(self.command('/usr/bin/qeli-client', '--version', target=True).stdout.strip(), b'qeli-client 0.8.2')

    def test_install_with_real_nft_providers(self):
        self.install('nft')
        self.verify_payload()

    def test_install_with_real_legacy_providers(self):
        self.install('legacy')
        self.verify_payload()

    def test_missing_dependencies_reject_installation(self):
        status = (self.root/'usr/lib/opkg/status').read_bytes()
        result = self.opkg('install', '/fixtures/qeli.ipk', success=False)
        self.assertIn(b'cannot find dependency kmod-tun', result.stderr)
        self.assertEqual((self.root/'usr/lib/opkg/status').read_bytes(), status)
        self.assertFalse((self.root/'usr/bin/qeli-client').exists())

    def test_upgrade_preserves_modified_uci(self):
        self.install()
        p = self.root/'etc/config/qeli'
        edited = p.read_bytes()+b'\n# operator-owned value\n'
        p.write_bytes(edited)
        self.opkg('install', '/fixtures/qeli-upgrade.ipk')
        self.assertEqual(p.read_bytes(), edited)
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        _, payload = ipk_contents(self.root/'fixtures/qeli-upgrade.ipk')
        self.assertEqual((self.root/'etc/config/qeli-opkg').read_bytes(), payload['etc/config/qeli'][0])
        self.assertEqual((self.root/'etc/config/qeli-opkg').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.status()['qeli']['Version'], '0.8.2-r2')

    def test_upgrade_replaces_unmodified_default(self):
        self.install()
        self.opkg('install', '/fixtures/qeli-upgrade.ipk')
        _, payload = ipk_contents(self.root/'fixtures/qeli-upgrade.ipk')
        self.assertEqual((self.root/'etc/config/qeli').read_bytes(), payload['etc/config/qeli'][0])
        self.assertEqual((self.root/'etc/config/qeli').stat().st_mode & 0o777, 0o600)

    def test_removal_dependency_guard_and_modified_uci_retention(self):
        self.install()
        p = self.root/'etc/config/qeli'
        edited = p.read_bytes()+b'\n# retained operator config\n'
        p.write_bytes(edited)
        self.opkg('remove', 'qeli', success=False)
        self.assertTrue((self.root/'usr/bin/qeli-client').is_file())
        self.opkg('remove', 'luci-app-qeli')
        self.opkg('remove', 'qeli')
        self.assertEqual(p.read_bytes(), edited)
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        for name in ['usr/bin/qeli-client', 'etc/init.d/qeli', 'etc/uci-defaults/99-qeli-firewall',
                     'usr/share/rpcd/ucode/qeli.uc', 'usr/share/rpcd/acl.d/luci-app-qeli.json']:
            self.assertFalse((self.root/name).exists(), name)
        notices = self.root/'usr/share/licenses/qeli/rust'
        if notices.exists():
            # opkg may retain empty directories; no package file may remain.
            self.assertFalse(notices.is_symlink())
            for path in notices.rglob('*'):
                self.assertFalse(path.is_symlink(), path)
                self.assertTrue(path.is_dir(), path)
        self.assertNotIn('installed', self.status().get('qeli', {}).get('Status', ''))

    def test_corrupt_upgrade_rejected_before_payload_change(self):
        self.install()
        status = (self.root/'usr/lib/opkg/status').read_bytes()
        binary = hashlib.sha256((self.root/'usr/bin/qeli-client').read_bytes()).hexdigest()
        data = (self.root/'fixtures/qeli-upgrade.ipk').read_bytes()
        (self.root/'fixtures/broken.ipk').write_bytes(data[:32])
        self.opkg('install', '/fixtures/broken.ipk', success=False)
        self.assertEqual((self.root/'usr/lib/opkg/status').read_bytes(), status)
        self.assertEqual(hashlib.sha256((self.root/'usr/bin/qeli-client').read_bytes()).hexdigest(), binary)


if __name__ == '__main__':
    unittest.main()
