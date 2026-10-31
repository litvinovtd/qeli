#!/usr/bin/env python3
"""Execute packaged production Debian scripts via real make/dpkg in private chroots.

qeli CLI, account creation, debconf and systemctl are explicit seams. Dependency
packages are inert fixtures; this does not test a production daemon or apt resolver.
"""
import os
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

import test_server_updater as updater_fixture

ROOT = Path(__file__).resolve().parents[1]
DEBIAN = Path(os.environ.get('QELI_DEBIAN_SOURCE', ROOT / 'qeli/debian'))
CONFIG = Path(os.environ.get('QELI_DEBIAN_CONFIG_SOURCE', ROOT / 'qeli/config'))


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Linux root/chroot required')
class DebianTests(unittest.TestCase):
    stub = classmethod(updater_fixture.UpdaterTests.stub.__func__)

    @classmethod
    def setUpClass(cls):
        updater_fixture.UpdaterTests.setUpClass.__func__(cls)
        for program in ['chown', 'chmod', 'mkdir', 'cat', 'ln', 'getent']:
            src = Path(shutil.which(program))
            shutil.copy2(src, cls.base / 'usr/bin' / program)
            libs = subprocess.run(['ldd', str(src)], capture_output=True, text=True).stdout
            for lib in re.findall(r'(/[^\s]+)', libs):
                dest = cls.base / lib.lstrip('/')
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(lib, dest)
        for folder in ['var/log/qeli', 'usr/share/debconf', 'etc/systemd/system', 'outside']:
            (cls.base / folder).mkdir(parents=True, exist_ok=True)
        (cls.base / 'records/mode').write_text('normal')
        (cls.base / 'records/answer').write_text('qeli')
        (cls.base / 'usr/share/debconf/confmodule').write_text('''RET=root
db_get() { RET="$(cat /records/answer)"; [ ! -e /records/db-fail ]; }
db_input() { printf '%s\\n' "$*" >> /records/debconf-input; }
db_go() { return 0; }
''')
        cls.stub('adduser', '''printf '%s\\n' "$*" >> /records/adduser
printf 'qeli:x:234:234:qeli:/nonexistent:/bin/false\\n' >> /etc/passwd
printf 'qeli:x:234:\\n' >> /etc/group
''')
        cls.stub('setcap', "printf '%s\\n' \"$*\" >> /records/setcap")
        # Real packaged UDP helper, isolated sysctl backend (never the host kernel).
        cls.stub('sysctl', '''case "$1" in
 -n) cat /records/"$2" ;;
 -w) printf '%s\\n' "${2#*=}" > /records/"${2%%=*}" ;;
 *) exit 2 ;;
esac''')
        for key in ('net.core.rmem_max','net.core.wmem_max'):
            (cls.base/'records'/key).write_text('212992\n')
        cls.stub('systemctl', '''printf '%s\\n' "$*" >> /records/systemctl.log
[ "$1" != stop ] || [ "$(cat /records/mode)" != stop_fail ]
''')
        source = Path(cls.workspace.name) / 'src/qeli'
        shutil.copytree(DEBIAN, source / 'debian')
        # Explicit private-fixture seam: this suite packages an inert shell CLI,
        # not a deployable ELF. Production stage/check-abi has no bypass option.
        # Actual ELF acceptance/rejection is covered by test_linux_release and CI.
        makefile = source / 'debian/Makefile'
        text = makefile.read_text()
        begin, end = text.index('check-abi:\n'), text.index('# -Zxz')
        assert 'linux_release.py --binary' in text[begin:end]
        text = text[:begin] + 'check-abi:\n\t@test -x "$(BINARY)"\n\n' + text[end:]
        packaged_gate = '\tpython3 ../../scripts/linux_release.py --deb "$(DEB_DIR).deb" --arch $(ARCH)\n'
        assert text.count(packaged_gate) == 1
        makefile.write_text(text.replace(packaged_gate, ''))
        shutil.copytree(CONFIG, source / 'config')
        # Exercise the real packaging gate and ship its actual legal bundle.
        # deb-prebuilt invokes scripts/native_licenses.py from the source root.
        shutil.copytree(ROOT / 'scripts', source.parent / 'scripts',
                        ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT / 'qeli/third-party-notices', source / 'third-party-notices')
        shutil.copy2(ROOT / 'qeli/Cargo.lock', source / 'Cargo.lock')
        shutil.copy2(ROOT / 'LICENSE', source.parent / 'LICENSE')
        binary = source / 'inert-qeli'
        binary.write_text('''#!/bin/bash
printf '%s\\n' "$*" >> /records/qeli-command
[ "$(cat /records/mode)" != set_user_fail ] || exit 1
if [ "$1" = set-service-user ]; then
 if [ "$2" = root ]; then
  mkdir -p /etc/systemd/system/qeli.service.d
  printf '[Service]\\nUser=root\\nGroup=root\\n' > /etc/systemd/system/qeli.service.d/run-as.conf
 else rm -f /etc/systemd/system/qeli.service.d/run-as.conf; fi
fi
''')
        binary.chmod(0o755)
        cls.packages = {}
        cls.arch = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
        control = (source / 'debian/control').read_text()
        for version in ['0.8.2', '0.8.1']:
            (source / 'debian/control').write_text(re.sub(r'^Version: .*$', 'Version: ' + version, control, flags=re.M))
            p = subprocess.run(['make', '-C', str(source / 'debian'), 'deb-prebuilt', 'BINARY=' + str(binary)],
                               capture_output=True, text=True, timeout=30)
            assert p.returncode == 0, p.stdout + p.stderr
            package = cls.base / 'fixtures' / f'production-{version}.deb'
            shutil.copy2(source / 'debian' / f'qeli_{version}_{cls.arch}.deb', package)
            cls.packages[version] = package.name
        # Admit the production dependency expression with explicit inert packages,
        # without --force-depends. These qualify maintainer scripts, not dependencies.
        deps = []
        for name in ['adduser', 'libc6', 'libgcc-s1', 'iptables', 'iproute2', 'procps', 'libcap2-bin', 'debconf']:
            stage = Path(cls.workspace.name) / ('dep-' + name)
            (stage / 'DEBIAN').mkdir(parents=True)
            (stage / 'DEBIAN/control').write_text(f'Package: {name}\nVersion: 99\nArchitecture: all\nMaintainer: Audit <audit@localhost>\nDescription: inert dependency seam\n')
            package = cls.base / 'fixtures' / f'dep-{name}.deb'
            subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', str(stage), str(package)],
                           check=True, capture_output=True)
            deps.append('/fixtures/' + package.name)
        p = cls.command(cls.base, ['dpkg', '-i', *deps])
        assert p.returncode == 0, p.stdout + p.stderr
        record = os.environ.get('QELI_DEBIAN_FIXTURE_RECORDS')
        if record:
            shutil.copytree(cls.base / 'fixtures', Path(record), dirs_exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    @classmethod
    def command(cls, root, args):
        p = subprocess.run([cls.chroot, str(root), '/bin/bash', '-c', 'umask 022; exec "$@"', 'fixture', *args],
                              env=dict(os.environ, PATH='/usr/local/bin:/usr/bin:/bin', LC_ALL='C', TMPDIR='/tmp', DEBIAN_FRONTEND='noninteractive'),
                              capture_output=True, text=True, timeout=8)
        record = os.environ.get('QELI_DEBIAN_OPERATION_RECORDS')
        if record:
            with Path(record).open('a', encoding='utf8') as f:
                f.write(json.dumps({'argv': args, 'returncode': p.returncode}) + '\n')
        return p

    def setUp(self):
        self.root = Path(self.workspace.name) / self.id().split('.')[-1]
        shutil.copytree(self.base, self.root, symlinks=True)
        (self.root / 'run/systemd/system').mkdir(parents=True)

    def install(self, version='0.8.2'):
        return self.command(self.root, ['dpkg', '-i', '/fixtures/' + self.packages[version]])

    def snapshot(self):
        return {n: (self.root / 'etc/qeli' / n).read_bytes()
                for n in ['server.conf', 'users.conf', 'identity/default.key', 'client-links/phone.txt']}

    def status(self):
        return self.command(self.root, ['dpkg-query', '-W', '-f=${Status} ${Version}', 'qeli']).stdout

    def test_fresh_users_private(self):
        (self.root / 'etc/qeli/users.conf').unlink()
        p = self.install()
        self.assertEqual(p.returncode, 0, p.stderr)
        users = self.root / 'etc/qeli/users.conf'
        self.assertEqual(users.read_bytes(), b'')
        self.assertEqual(users.stat().st_mode & 0o777, 0o600)
        self.assertEqual(users.stat().st_uid, 234)
        self.assertFalse(list((self.root / 'etc/qeli').glob('*.qeli-*')))

    def test_install_preserves_state(self):
        before = self.snapshot()
        p = self.install()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.status(), 'install ok installed 0.8.2')

    def test_udp_limits_delivered_and_verified_on_install_and_upgrade(self):
        before=self.snapshot()
        first=self.install('0.8.1')
        self.assertEqual(first.returncode,0,first.stderr)
        for key in ('net.core.rmem_max','net.core.wmem_max'):
            self.assertEqual((self.root/'records'/key).read_text(),'16777216\n')
            # Simulate an older installation's lower ceiling before upgrading.
            (self.root/'records'/key).write_text('212992\n')
        upgraded=self.install()
        self.assertEqual(upgraded.returncode,0,upgraded.stderr)
        self.assertEqual(upgraded.stdout.count('limit verified'),2)
        self.assertEqual(before,self.snapshot())
        self.assertTrue(os.access(self.root/'usr/lib/qeli/udp-buffer-limits',os.X_OK))
        policy=self.root/'usr/lib/sysctl.d/60-qeli-udp-buffers.conf'
        self.assertTrue(policy.is_file())
        for key in ('net.core.rmem_max','net.core.wmem_max'):
            self.assertEqual((self.root/'records'/key).read_text(),'16777216\n')
            self.assertIn(key+' = 16777216',policy.read_text())

    def test_dangling_users_refused_without_target(self):
        users = self.root / 'etc/qeli/users.conf'
        users.unlink(); users.symlink_to('/outside/created')
        p = self.install()
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.root / 'outside/created').exists())
        self.assertFalse((self.root / 'usr/bin/qeli').exists())

    def test_users_link_refused_preserving_target(self):
        users = self.root / 'etc/qeli/users.conf'
        users.unlink(); users.symlink_to('/outside/existing')
        target = self.root / 'outside/existing'; target.write_text('outside')
        p = self.install()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(target.read_text(), 'outside')
        self.assertEqual(target.stat().st_uid, 0)

    def test_users_fifo_refused(self):
        users = self.root / 'etc/qeli/users.conf'; users.unlink(); os.mkfifo(users)
        self.assertNotEqual(self.install().returncode, 0)

    def test_state_root_links_refused_before_unpack(self):
        for state in ['etc/qeli', 'var/log/qeli', 'var/lib/qeli']:
            with self.subTest(state=state):
                saved = self.root / (state.replace('/', '-') + '-saved')
                (self.root / state).rename(saved)
                (self.root / state).symlink_to('/outside', target_is_directory=True)
                marker = self.root / 'outside/keep'; marker.write_text('keep')
                p = self.install()
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(marker.stat().st_uid, 0)
                self.assertFalse((self.root / 'outside/users.conf').exists())
                (self.root / state).unlink(); saved.rename(self.root / state)

    def test_active_service_user_failure_not_configured(self):
        (self.root / 'records/mode').write_text('set_user_fail')
        p = self.install()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('half-configured', self.status())
        self.assertNotIn('configured successfully', p.stdout)
        (self.root / 'records/mode').write_text('normal')
        self.assertEqual(self.command(self.root, ['dpkg', '--configure', 'qeli']).returncode, 0)
        self.assertEqual(self.status(), 'install ok installed 0.8.2')

    def test_invalid_debconf_user_refused(self):
        (self.root / 'records/answer').write_text('surprise')
        self.assertNotEqual(self.install().returncode, 0)
        self.assertFalse((self.root / 'records/qeli-command').exists())

    def test_failed_debconf_lookup_defaults_qeli(self):
        (self.root / 'records/answer').write_text('root')
        (self.root / 'records/db-fail').touch()
        p = self.install()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('set-service-user qeli', (self.root / 'records/qeli-command').read_text())

    def test_nonbooted_service_user_failure_warns(self):
        (self.root / 'run/systemd/system').rmdir()
        (self.root / 'records/mode').write_text('set_user_fail')
        p = self.install()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('service-user application not confirmed', p.stderr)
        self.assertNotIn('Service runs as:', p.stdout)

    def test_upgrade_reapplies_selected_user_preserves_state(self):
        before = self.snapshot()
        self.assertEqual(self.install('0.8.1').returncode, 0)
        (self.root / 'records/answer').write_text('root')
        p = self.install()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.status(), 'install ok installed 0.8.2')
        self.assertEqual(before, self.snapshot())
        self.assertIn('User=root', (self.root / 'etc/systemd/system/qeli.service.d/run-as.conf').read_text())
        self.assertNotIn('stop qeli', (self.root / 'records/systemctl.log').read_text())

    def test_remove_preserves_state_and_stops_service(self):
        self.assertEqual(self.install().returncode, 0)
        before = self.snapshot()
        p = self.command(self.root, ['dpkg', '--remove', 'qeli'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse((self.root / 'usr/bin/qeli').exists())
        self.assertEqual(before, self.snapshot())
        commands = (self.root / 'records/systemctl.log').read_text()
        self.assertIn('stop qeli', commands); self.assertIn('disable qeli', commands)

    def test_purge_preserves_unmanaged_secrets(self):
        self.assertEqual(self.install().returncode, 0)
        before = self.snapshot()
        p = self.command(self.root, ['dpkg', '--purge', 'qeli'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.root / 'etc/qeli/server.conf.example').exists())

    def test_active_stop_failure_blocks_remove(self):
        self.assertEqual(self.install().returncode, 0)
        (self.root / 'records/mode').write_text('stop_fail')
        p = self.command(self.root, ['dpkg', '--remove', 'qeli'])
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue((self.root / 'usr/bin/qeli').exists())
        self.assertIn('refusing to remove', p.stderr)

    def test_nonbooted_stop_failure_allows_remove(self):
        self.assertEqual(self.install().returncode, 0)
        (self.root / 'run/systemd/system').rmdir()
        (self.root / 'records/mode').write_text('stop_fail')
        p = self.command(self.root, ['dpkg', '--remove', 'qeli'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse((self.root / 'usr/bin/qeli').exists())

    def test_package_control_and_payload(self):
        p = self.command(self.root, ['dpkg-deb', '-f', '/fixtures/' + self.packages['0.8.2'], 'Depends'])
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('adduser', p.stdout)
        p = self.install(); self.assertEqual(p.returncode, 0, p.stderr)
        for name in ['preinst', 'postinst', 'prerm', 'config']:
            self.assertTrue((self.root / ('var/lib/dpkg/info/qeli.' + name)).is_file())
        self.assertTrue((self.root / 'lib/systemd/system/qeli.service').is_file())
        self.assertTrue((self.root / 'etc/polkit-1/rules.d/49-qeli.rules').is_file())


if __name__ == '__main__':
    unittest.main(verbosity=2)
