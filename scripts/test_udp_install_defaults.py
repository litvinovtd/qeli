"""UDP install/upgrade defaults: source guards plus real shell in private chroots.

The chroot tests mock sysctl: they never write the build VM's kernel settings.
They qualify the shipped helper, not a production installation or reboot.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
FLOOR = 16777216


class DefaultSourceTests(unittest.TestCase):
    def test_package_install_and_upgrade_share_verified_helper(self):
        post = (ROOT/'qeli/debian/postinst').read_text()
        self.assertRegex(post, r'configure\)[\s\S]+if ! /usr/lib/qeli/udp-buffer-limits; then')
        updater = (ROOT/'update-qeli-server.sh').read_text()
        self.assertIn('apt-get install', updater)
        make = (ROOT/'qeli/debian/Makefile').read_text()
        for name in ('udp-buffer-limits', '60-qeli-udp-buffers.conf'):
            self.assertIn('install -m', make)
            self.assertIn(name, make)
        self.assertIn('procps', (ROOT/'qeli/debian/control').read_text())
        installer=(ROOT/'install-qeli-server.sh').read_text()
        self.assertIn('for cmd in iptables ip openssl sysctl;',installer)
        self.assertIn('sysctl) pkg=procps',installer)

    def test_persistent_and_full_installer_ceilings_cover_auto_cap(self):
        persistent = (ROOT/'qeli/debian/60-qeli-udp-buffers.conf').read_text()
        installer = (ROOT/'install-qeli-server.sh').read_text()
        for key in ('net.core.rmem_max', 'net.core.wmem_max'):
            self.assertRegex(persistent, re.escape(key)+r'\s*=\s*16777216')
            self.assertIn(key+'=16777216', installer)
        self.assertNotIn('rmem_default', persistent)
        self.assertNotIn('wmem_default', persistent)
        self.assertIn('const AUTO_MAX_RECV_BYTES: u32 = 16 * 1024 * 1024;',
                      (ROOT/'qeli/src/transport_core/udp_buffer.rs').read_text())

    def test_shipped_profiles_explicitly_prefer_opportunistic_and_udp_auto(self):
        paths = list((ROOT/'qeli/config').glob('server*.conf'))
        paths.append(ROOT/'release/reality-tls/server-reality.conf')
        count = 0
        for path in paths:
            for block in re.split(r'(?m)^\[', path.read_text()):
                if not block.startswith('profile:'):
                    continue
                count += 1
                self.assertEqual(len(re.findall(r'(?m)^obf.recordizer.policy\s*=\s*prefer\s*$', block)), 1, path)
                self.assertEqual(len(re.findall(r'(?m)^obf.recordizer.batch.mode\s*=\s*opportunistic\s*$', block)), 1, path)
                self.assertNotRegex(block, r'(?m)^perf.udp.recv_buffer_size\s*=')
        self.assertEqual(count, 14)

    def test_clients_do_not_pin_auto_or_invent_recordizer_keys(self):
        for path in (ROOT/'qeli/config').glob('client*.conf'):
            text = path.read_text()
            self.assertNotRegex(text, r'(?m)^(?:obf.recordizer\.|recv_buffer_size\s*=)')


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Linux root/chroot required')
class HelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_binary_installer as fixture
        cls.fixture = fixture.BinaryTests
        cls.stub = classmethod(fixture.BinaryTests.stub.__func__)
        cls.fixture.setUpClass.__func__(cls)
        cls.fixture.stub.__func__(cls, 'sysctl', r'''case "$1" in
 -n) [[ "$(< /records/mode)" != unread ]] || exit 1
     cat /records/"$2" ;;
 -w) printf '%s\n' "$2" >> /records/writes
     [[ "$(< /records/mode)" != denied ]] || exit 1
     [[ "$(< /records/mode)" != mismatch ]] || exit 0
     printf '%s\n' "${2#*=}" > /records/"${2%%=*}" ;;
 *) exit 2 ;;
esac''')
        p = cls.base/'helper.sh'
        p.write_bytes((ROOT/'qeli/debian/udp-buffer-limits').read_bytes())
        p.chmod(0o755)
        dest=cls.base/'usr/lib/qeli'
        dest.mkdir(parents=True,exist_ok=True)
        (dest/'udp-buffer-limits').write_bytes(p.read_bytes())
        (dest/'udp-buffer-limits').chmod(0o755)
        conf=cls.base/'usr/share/debconf'
        conf.mkdir(parents=True,exist_ok=True)
        (conf/'confmodule').write_text('db_get() { RET=qeli; return 0; }\n')
        (cls.base/'postinst.sh').write_bytes((ROOT/'qeli/debian/postinst').read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.fixture.tearDownClass.__func__(cls)

    def setUp(self):
        self.fixture.setUp(self)
        (self.root/'records/mode').write_text('ok')
        for key in ('net.core.rmem_max', 'net.core.wmem_max'):
            (self.root/'records'/key).write_text('212992\n')

    def run_helper(self):
        return subprocess.run([self.chroot, str(self.root), '/bin/bash', '/helper.sh'],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_fresh_install_and_repeated_upgrade_are_idempotent(self):
        for _ in range(2):
            result = self.run_helper()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.count('limit verified'), 2)
        self.assertEqual(len((self.root/'records/writes').read_text().splitlines()), 2)
        for key in ('net.core.rmem_max', 'net.core.wmem_max'):
            self.assertEqual(int((self.root/'records'/key).read_text()), FLOOR)

    def test_actual_postinst_fresh_and_upgrade_preserve_configuration(self):
        config=self.root/'etc/qeli/server.conf'
        before=config.read_bytes()
        for previous_version in ('', '0.8.3'):
            result=subprocess.run([self.chroot,str(self.root),'/bin/bash','/postinst.sh',
                                   'configure',previous_version],env=self.env,
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.count('limit verified'),2)
            self.assertEqual(config.read_bytes(),before)
        self.assertEqual(len((self.root/'records/writes').read_text().splitlines()),2)

    def test_higher_administrator_values_are_not_lowered(self):
        for key in ('net.core.rmem_max', 'net.core.wmem_max'):
            (self.root/'records'/key).write_text('67108864\n')
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root/'records/writes').exists())

    def test_refused_write_is_not_success(self):
        (self.root/'records/mode').write_text('denied')
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('limit verified', result.stdout)

    def test_successful_command_with_insufficient_readback_is_not_success(self):
        (self.root/'records/mode').write_text('mismatch')
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('readback insufficient', result.stderr)

    def test_unreadable_previous_value_is_not_written(self):
        (self.root/'records/mode').write_text('unread')
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'records/writes').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
