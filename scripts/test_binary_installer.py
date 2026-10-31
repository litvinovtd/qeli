#!/usr/bin/env python3
"""Q33 binary installer prefix/functions and early whole-program refusals.

Real Bash/coreutils/dpkg extraction; account creation, HTTP, installed qeli and
systemctl are explicit seams. The complete installation/VPN is not qualified.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

import test_server_updater as updater_fixture

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('QELI_BINARY_INSTALLER_SOURCE', ROOT / 'install-qeli-server.sh'))
PAYLOAD = Path(os.environ.get('QELI_BINARY_PAYLOAD_SOURCE', ROOT))


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Linux root/chroot required')
class BinaryTests(unittest.TestCase):
    stub = classmethod(updater_fixture.UpdaterTests.stub.__func__)

    @classmethod
    def setUpClass(cls):
        updater_fixture.UpdaterTests.setUpClass.__func__(cls)
        for program in ['chown', 'chmod', 'mkdir', 'cat', 'ln', 'getent', 'tr', 'openssl']:
            src = Path(shutil.which(program)); shutil.copy2(src, cls.base / 'usr/bin' / program)
            libs = subprocess.run(['ldd', str(src)], capture_output=True, text=True).stdout
            for lib in re.findall(r'(/[^\s]+)', libs):
                dest = cls.base / lib.lstrip('/'); dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(lib, dest)
        for n in ['var/log/qeli', 'lib/systemd/system', 'etc/polkit-1/rules.d', 'outside', 'checkout/qeli/config', 'checkout/qeli/debian']:
            (cls.base / n).mkdir(parents=True, exist_ok=True)
        cls.inputs = [(f'qeli/config/{n}.conf', f'etc/qeli/{n}.conf.example') for n in
                      ['server', 'server-multiprofile', 'server-ipv6', 'server-maxobf', 'users', 'client', 'client-reality', 'client-maxobf']]
        cls.inputs += [('qeli/debian/qeli.service', 'lib/systemd/system/qeli.service'),
                       ('qeli/debian/49-qeli.rules', 'etc/polkit-1/rules.d/49-qeli.rules')]
        for src, _ in cls.inputs:
            (cls.base / 'checkout' / src).write_bytes((PAYLOAD / src).read_bytes())
        source = SOURCE.read_bytes(); marker = b'# Must run as root.'; assert source.count(marker) == 1
        cls.prefix = source[:source.index(marker)]
        (cls.base / 'prefix.sh').write_bytes(cls.prefix)
        (cls.base / 'installer.sh').write_bytes(source)
        binary = cls.base / 'fixtures/new-qeli'
        binary.write_text('#!/bin/bash\n[[ "$1" != --version ]] || { echo "qeli 0.8.2"; exit 0; };exit 1\n'); binary.chmod(0o755)
        cls.stub('adduser', "printf 'qeli:x:234:234:qeli:/nonexistent:/bin/false\\n' >> /etc/passwd\nprintf 'qeli:x:234:\\n' >> /etc/group")
        cls.stub('useradd', 'exit 1')
        cls.stub('setcap', 'exit 0')
        cls.stub('sysctl', 'exit 0')
        cls.stub('systemctl', 'printf "%s\\n" "$*" >> /records/systemctl.log')
        cls.stub('iptables', 'exit 0')
        cls.stub('ip6tables', 'exit 1')
        cls.stub('install', '''printf '%s\\n' "$*" >> /records/install.log
if [[ "$(< /records/mode)" == copy_fail && "$*" == */checkout/* ]]; then exit 1; fi
exec /usr/bin/install "$@"''')
        cls.stub('curl', '''printf '%s\\n' "$*" >> /records/curl.log
out='';while [[ "$#" -gt 0 ]]; do case "$1" in -o) out="$2";shift 2 ;; *) url="$1";shift ;; esac;done
case "$url" in
 */releases/tags/*) while IFS= read -r line; do printf '%s\\n' "$line";done < /fixtures/releases.json ;;
 */SHA256SUMS) /usr/bin/cp /fixtures/SHA256SUMS "$out" ;;
 *.deb) /usr/bin/cp "/fixtures/${url##*/}" "$out" ;;
 *) exit 22 ;;
esac''')
        for name, arch in [('qeli', 'amd64'), ('qeli', 'arm64'), ('other', 'amd64')]:
            stage = Path(cls.workspace.name) / ('payload-' + name + '-' + arch)
            (stage / 'DEBIAN').mkdir(parents=True)
            (stage / 'DEBIAN/control').write_text(f'Package: {name}\nVersion: 0.8.2\nArchitecture: {arch}\nMaintainer: Audit <audit@localhost>\nDescription: inert installer payload\n')
            for src, dest in cls.inputs:
                path = stage / dest; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes((PAYLOAD / src).read_bytes())
            p = cls.base / 'fixtures' / f'{name}_0.8.2_{arch}.deb'
            subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', str(stage), str(p)], check=True, capture_output=True)
        record = os.environ.get('QELI_BINARY_FIXTURE_RECORDS')
        if record:
            shutil.copytree(cls.base / 'fixtures', Path(record), dirs_exist_ok=True)
            (Path(record) / 'prefix.sh').write_bytes(cls.prefix)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.root = Path(self.workspace.name) / self.id().split('.')[-1]
        shutil.copytree(self.base, self.root, symlinks=True)
        old = self.root / 'usr/bin/qeli'; old.write_text('#!/bin/bash\necho "qeli 0.8.1"\n'); old.chmod(0o755)
        self.old = old.read_bytes()
        self.env = dict(os.environ, PATH='/usr/local/bin:/usr/bin:/bin', LC_ALL='C', TMPDIR='/tmp')
        for key in list(self.env):
            if key.startswith('QELI_'): self.env.pop(key)
        self.env.update(QELI_BIN='/fixtures/new-qeli', QELI_SRC='/checkout', QELI_PROFILE='udp-quic', QELI_PORT='443')

    def run_installer(self, command='from_source_install', whole=False):
        args = ['/bin/bash', '/installer.sh', 'vpn.example'] if whole else ['/bin/bash', '-c', '. /prefix.sh; ' + command]
        p = subprocess.run([self.chroot, str(self.root), *args], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertFalse(list((self.root / 'tmp').iterdir()), p.stderr)
        self.assertFalse(list((self.root / 'etc/qeli').glob('*.qeli-*')), p.stderr)
        record = os.environ.get('QELI_BINARY_OPERATION_RECORDS')
        if record:
            with Path(record).open('a', encoding='utf8') as f:
                f.write(json.dumps({'method': self.id(), 'whole': whole, 'command': command, 'returncode': p.returncode}) + '\n')
        return p

    def online(self, mixed=False, wrong=False, mismatch=False):
        self.env.pop('QELI_SRC', None)
        names = ['qeli_0.8.2_arm64.deb', 'qeli_0.8.2_amd64.deb'] if mixed else ['qeli_0.8.2_amd64.deb']
        if wrong: shutil.copy2(self.root / 'fixtures/other_0.8.2_amd64.deb', self.root / 'fixtures/qeli_0.8.2_amd64.deb')
        assets = [{'name': n, 'browser_download_url': 'https://fixture/' + n} for n in names]
        assets.append({'name': 'SHA256SUMS', 'browser_download_url': 'https://fixture/SHA256SUMS'})
        (self.root / 'fixtures/releases.json').write_text(json.dumps({'assets': assets}) + '\n')
        (self.root / 'fixtures/SHA256SUMS').write_bytes(''.join(('0' * 64 if mismatch else hashlib.sha256((self.root / 'fixtures' / n).read_bytes()).hexdigest()) + '  ' + n + '\r\n' for n in names).encode())

    def test_local_layout_and_state_preserved(self):
        state = {p.relative_to(self.root): p.read_bytes() for p in (self.root / 'etc/qeli').rglob('*') if p.is_file()}
        p = self.run_installer(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), (self.root / 'fixtures/new-qeli').read_bytes())
        self.assertEqual((self.root / 'usr/bin/qeli').stat().st_uid, 0)
        for src, dest in self.inputs: self.assertEqual((self.root / dest).read_bytes(), (self.root / 'checkout' / src).read_bytes())
        for path, data in state.items(): self.assertEqual((self.root / path).read_bytes(), data)
        self.assertEqual((self.root / 'lib/systemd/system/qeli.service').stat().st_mode & 0o777, 0o644)
        self.assertFalse((self.root / 'records/curl.log').exists())

    def test_fresh_users_empty_private(self):
        (self.root / 'etc/qeli/users.conf').unlink()
        p = self.run_installer(); self.assertEqual(p.returncode, 0, p.stderr)
        users = self.root / 'etc/qeli/users.conf'; self.assertEqual(users.read_bytes(), b'')
        self.assertEqual(users.stat().st_mode & 0o777, 0o600); self.assertEqual(users.stat().st_uid, 234)

    def test_pkg_copy_failure_is_not_success(self):
        (self.root / 'records/mode').write_text('copy_fail')
        p = self.run_installer('if _pkg_file qeli/config/server.conf etc/qeli/server.conf.example /outside/copied; then echo FALSE_SUCCESS; fi')
        self.assertNotIn('FALSE_SUCCESS', p.stdout)
        self.assertFalse((self.root / 'outside/copied').exists())

    def test_explicit_partial_source_does_not_download(self):
        self.online(); self.env['QELI_SRC'] = '/checkout'
        (self.root / 'checkout/qeli/config/server.conf').unlink()
        p = self.run_installer('if _pkg_file qeli/config/server.conf etc/qeli/server.conf.example /outside/copied; then echo FALSE_SUCCESS; fi')
        self.assertNotIn('FALSE_SUCCESS', p.stdout); self.assertFalse((self.root / 'records/curl.log').exists())

    def test_staging_failure_preserves_binary(self):
        (self.root / 'records/mode').write_text('copy_fail')
        p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)
        self.assertFalse((self.root / 'lib/systemd/system/qeli.service').exists())

    def test_missing_rule_refuses_before_publish(self):
        self.online(); self.env['QELI_SRC'] = '/checkout'
        (self.root / 'checkout/qeli/debian/49-qeli.rules').unlink()
        p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)
        self.assertFalse((self.root / 'records/curl.log').exists())

    def test_dangling_users_refuses_before_publish(self):
        users = self.root / 'etc/qeli/users.conf'; users.unlink(); users.symlink_to('/outside/created')
        p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.root / 'outside/created').exists())
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)

    def test_state_root_links_refuse_before_publish(self):
        for state in ['etc/qeli', 'var/log/qeli', 'var/lib/qeli', 'etc/qeli/identity', 'etc/qeli/client-links']:
            with self.subTest(state=state):
                saved = self.root / (state.replace('/', '-') + '-saved'); (self.root / state).rename(saved)
                (self.root / state).symlink_to('/outside', target_is_directory=True)
                try:
                    p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
                    self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)
                finally:
                    (self.root / state).unlink(); saved.rename(self.root / state)
                    (self.root / 'usr/bin/qeli').write_bytes(self.old)

    def test_invalid_binary_refuses_before_dependencies(self):
        (self.root / 'etc/qeli/server.conf').unlink(); self.env['QELI_BIN'] = '/fixtures/missing'
        p = self.run_installer(whole=True); self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.root / 'records/apt.log').exists())

    def test_whole_dangling_config_refuses_before_dependencies(self):
        conf = self.root / 'etc/qeli/server.conf'; conf.unlink(); conf.symlink_to('/outside/generated')
        p = self.run_installer(whole=True); self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.root / 'records/apt.log').exists())
        self.assertFalse((self.root / 'outside/generated').exists())

    def test_signal_stops_execution_and_cleans_owned_temp(self):
        for name, expected in [('TERM', 143), ('INT', 130)]:
            with self.subTest(signal=name):
                marker = self.root / 'records/continued'; marker.unlink(missing_ok=True)
                p = self.run_installer('tmp="$(mktemp)"; QELI_TMP_PATHS+=("$tmp"); kill -' + name + ' $$; : > /records/continued')
                self.assertEqual(p.returncode, expected); self.assertFalse(marker.exists())

    def test_remote_host_architecture_selected(self):
        self.online(mixed=True)
        p = self.run_installer(); self.assertEqual(p.returncode, 0, p.stderr)
        calls = (self.root / 'records/curl.log').read_text()
        self.assertIn('https://fixture/qeli_0.8.2_amd64.deb', calls)
        self.assertNotIn('https://fixture/qeli_0.8.2_arm64.deb', calls)

    def test_remote_wrong_package_refused(self):
        self.online(wrong=True)
        p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)

    def test_remote_fresh_install_uses_supplied_version(self):
        self.online(); (self.root / 'usr/bin/qeli').unlink()
        p = self.run_installer(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('/releases/tags/v0.8.2', (self.root / 'records/curl.log').read_text())

    def test_remote_checksum_failure_preserves_binary_and_cleans(self):
        self.online(mismatch=True)
        p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)

    def test_required_attestation_without_gh_refuses(self):
        self.online(); self.env['QELI_VERIFY_ATTESTATION'] = '1'
        p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)

    def test_failed_attestation_refuses(self):
        self.online(); self.env['QELI_VERIFY_ATTESTATION'] = '1'
        gh = self.root / 'usr/local/bin/gh'; gh.write_text('#!/bin/bash\nexit 1\n'); gh.chmod(0o755)
        p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)

    def test_successful_attestation_command_admits(self):
        self.online(); self.env['QELI_VERIFY_ATTESTATION'] = '1'
        gh = self.root / 'usr/local/bin/gh'
        gh.write_text('#!/bin/bash\nprintf "%s\\n" "$*" > /records/gh-argv\n'); gh.chmod(0o755)
        p = self.run_installer(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('attestation verify', (self.root / 'records/gh-argv').read_text())
        self.assertIn('--repo litvinovtd/qeli', (self.root / 'records/gh-argv').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
