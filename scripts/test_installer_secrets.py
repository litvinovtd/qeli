#!/usr/bin/env python3
"""Q33 secret/config publication stages in genuine Linux chroot filesystems.

The CLI, accounts, HTTP and systemctl are seams; no real users/identity/VPN or full
positive installer is qualified. Baseline uses exact old secret/backup blocks.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

import test_binary_installer as binary_fixture


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Linux root/chroot required')
class SecretTests(unittest.TestCase):
    stub = binary_fixture.BinaryTests.__dict__['stub']
    setUp = binary_fixture.BinaryTests.setUp
    tearDownClass = binary_fixture.BinaryTests.__dict__['tearDownClass']

    @classmethod
    def setUpClass(cls):
        binary_fixture.BinaryTests.setUpClass.__func__(cls)
        for program in ['mv', 'seq']:
            src = Path(shutil.which(program)); shutil.copy2(src, cls.base / 'usr/bin' / program)
            for lib in re.findall(r'(/[^\s]+)', subprocess.run(['ldd', str(src)], capture_output=True, text=True).stdout):
                dest = cls.base / lib.lstrip('/'); dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(lib, dest)
        cls.stub('qeli', r'''printf '%s\n' "$*" >> /records/qeli-argv
config=/etc/qeli/server.conf;args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
 [[ "${args[i]}" != --config ]] || config="${args[i+1]}"
done
case "$1" in
 --version) printf 'qeli 0.8.2\n';exit 0 ;;
 show-identity) /usr/bin/mkdir -p /etc/qeli/identity;printf fixture-key > /etc/qeli/identity/default.key;printf 'udp-quic fixture-key\n';exit 0 ;;
 set-web-password) : > "$config.lock";IFS= read -r password || true;/usr/bin/sed -i 's/^enabled = false$/enabled = true/' "$config";exit 0 ;;
 check-config) [[ -s "$config" ]] && /usr/bin/grep -q '^\[profile:' "$config";exit ;;
 set-service-user) exit 0 ;;
 add-client) ;;
 *) exit 1 ;;
esac
u="$2";IFS= read -r password || true
printf '%s|%s\n' "$u" "$password" >> /records/passwords
mode="$(< /records/mode)"
[[ "$u" != phone3 || "$mode" != fail_before ]] || exit 42
printf '[user:%s]\npassword_hash = fixture-only\n' "$u" >> /etc/qeli/users.conf
[[ "$u" != phone3 || "$mode" != fail_after ]] || exit 42
[[ "$u" != phone3 || "$mode" != missing_link ]] || exit 0
printf 'qeli://fixture-%s\n' "$u"''')
        for program in ['ip', 'sysctl', 'modprobe']: cls.stub(program, 'exit 0')
        cls.stub('mv', r'''printf '%s\n' "$*" >> /records/mv-argv
mode="$(< /records/mode)"
[[ "$mode" != mv_fail ]] || exit 42
[[ "$mode" != summary_fail || "${!#}" != */CONNECTION-STRINGS.txt ]] || exit 42
[[ "$mode" != link_fail || "${!#}" != */phone1.qeli ]] || exit 42
exec /usr/bin/mv "$@"''')
        cls.stub('awk', r'''if [[ "$(< /records/mode)" == awk_fail ]]; then printf partial;exit 42;fi
exec /usr/bin/awk "$@"''')
        cls.stub('cat', r'''if [[ "$(< /records/mode)" == cat_fail ]]; then printf partial;exit 42;fi
exec /usr/bin/cat "$@"''')

    def run_installer(self, command='from_source_install', whole=False):
        if os.environ.get('QELI_SECRETS_BASELINE') == '1' and not whole:
            source = (self.root / 'installer.sh').read_text()
            if '_create_client_links' in command:
                a = source.index('mkdir -p "$LINKS_DIR"; chmod 700 "$LINKS_DIR"', source.index('# ── 7.'))
                b = source.index('# ── 8. OS tuning', a)
                command = command.replace('_create_client_links', source[a:b])
            if '_backup_private_file' in command:
                a = source.index('  CONF_BAK="${CONF}.bak-${RUN_STAMP}"')
                b = source.index('  echo "  previous config backed up', a)
                command = command.replace('_backup_private_file "$CONF"', source[a:b] + 'printf "%s\\n" "$CONF_BAK"')
        return binary_fixture.BinaryTests.run_installer(self, command, whole)

    def mode(self, value): (self.root / 'records/mode').write_text(value)

    def links(self):
        return self.run_installer('PROFILE=udp-quic; PUBLIC_AUTHORITY_HOST=vpn.example; _create_client_links')

    def summary(self): return self.root / 'etc/qeli/client-links/CONNECTION-STRINGS.txt'

    def journal(self):
        found = list((self.root / 'etc/qeli/client-links').glob('INSTALL-PENDING-*'))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(found[0].stat().st_uid, 0)
        return found[0].read_text()

    def assert_private(self, path):
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_uid, 0)

    def test_success_all_passwords_links_and_permissions(self):
        p = self.links(); self.assertEqual(p.returncode, 0, p.stderr)
        pairs = (self.root / 'records/passwords').read_text().splitlines(); self.assertEqual(len(pairs), 5)
        text = self.summary().read_text(); self.assert_private(self.summary())
        calls = (self.root / 'records/qeli-argv').read_text()
        for pair in pairs:
            user, password = pair.split('|'); self.assertIn('pass: ' + password, text)
            self.assertNotIn(password, calls); self.assertIn('--password-stdin', calls)
            link = self.root / 'etc/qeli/client-links' / (user + '.qeli')
            self.assertEqual(link.read_text(), 'qeli://fixture-' + user + '\n'); self.assert_private(link)
        self.assertFalse(list(self.summary().parent.glob('INSTALL-PENDING-*')))

    def test_existing_users_kept_and_no_false_reality_claim(self):
        self.summary().write_text('old credentials\n'); (self.root / 'etc/qeli/users.conf').write_text('[user:phone1]\npassword_hash = old\n')
        link = self.summary().parent / 'phone1.qeli'; link.write_text('old link\n')
        p = self.links(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(link.read_text(), 'old link\n'); self.assert_private(link)
        self.assertNotIn('phone1', (self.root / 'records/passwords').read_text())
        self.assertNotIn('minted a new REALITY', self.summary().read_text())
        backup = list(self.summary().parent.glob('CONNECTION-STRINGS.txt.bak-*')); self.assertEqual(len(backup), 1)
        self.assertEqual(backup[0].read_text(), 'old credentials\n'); self.assert_private(backup[0])

    def test_summary_regular_and_dangling_links_refuse_without_writes(self):
        for dangling in [False, True]:
            with self.subTest(dangling=dangling):
                out = self.root / 'outside/summary'; out.write_text('outside witness')
                if dangling: out.unlink()
                self.summary().symlink_to('/outside/summary')
                try:
                    p = self.links(); self.assertNotEqual(p.returncode, 0)
                    self.assertFalse((self.root / 'records/qeli-argv').exists())
                    if dangling: self.assertFalse(out.exists())
                    else: self.assertEqual(out.read_text(), 'outside witness')
                finally: self.summary().unlink()

    def test_generated_link_refuses_before_any_user_is_added(self):
        out = self.root / 'outside/phone'; out.write_text('outside witness')
        link = self.summary().parent / 'phone5.qeli'; link.symlink_to('/outside/phone')
        p = self.links(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(out.read_text(), 'outside witness'); self.assertFalse((self.root / 'records/qeli-argv').exists())

    def test_unrelated_link_does_not_change_external_mode(self):
        out = self.root / 'outside/unrelated'; out.write_text('witness'); out.chmod(0o644)
        (self.summary().parent / 'unrelated-link').symlink_to('/outside/unrelated')
        p = self.links(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(out.stat().st_mode & 0o777, 0o644); self.assertEqual(out.read_text(), 'witness')

    def test_failed_third_user_keeps_old_summary_and_recoverable_passwords(self):
        self.summary().write_text('old credentials\n'); self.mode('fail_before')
        p = self.links(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.summary().read_text(), 'old credentials\n')
        journal = self.journal()
        for row in (self.root / 'records/passwords').read_text().splitlines():
            user, password = row.split('|'); self.assertIn('user: ' + user, journal); self.assertIn('pass: ' + password, journal)
        self.assertNotIn('[user:phone3]', (self.root / 'etc/qeli/users.conf').read_text())

    def test_cli_failure_after_append_recovers_committed_user_password(self):
        self.mode('fail_after'); p = self.links(); self.assertNotEqual(p.returncode, 0)
        self.assertIn('[user:phone3]', (self.root / 'etc/qeli/users.conf').read_text())
        user, password = (self.root / 'records/passwords').read_text().splitlines()[-1].split('|')
        self.assertIn('user: ' + user, self.journal()); self.assertIn('pass: ' + password, self.journal())
        self.assertFalse(self.summary().exists())

    def test_cli_missing_link_retains_password_and_old_summary(self):
        self.summary().write_text('old credentials\n'); self.mode('missing_link')
        p = self.links(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.summary().read_text(), 'old credentials\n'); self.assertIn('user: phone3', self.journal())

    def test_link_publish_failure_keeps_old_link_summary_and_journal(self):
        self.summary().write_text('old credentials\n'); link = self.summary().parent / 'phone1.qeli'; link.write_text('old link\n'); self.mode('link_fail')
        p = self.links(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(link.read_text(), 'old link\n'); self.assertEqual(self.summary().read_text(), 'old credentials\n')
        self.assertIn('link: qeli://fixture-phone1', self.journal())

    def test_summary_publish_failure_keeps_old_summary_and_all_passwords(self):
        self.summary().write_text('old credentials\n'); self.mode('summary_fail')
        p = self.links(); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.summary().read_text(), 'old credentials\n')
        journal = self.journal()
        for row in (self.root / 'records/passwords').read_text().splitlines(): self.assertIn('pass: ' + row.split('|')[1], journal)
        self.assertEqual(len((self.root / 'records/passwords').read_text().splitlines()), 5)

    def test_summary_hardlink_does_not_modify_external_inode(self):
        out = self.root / 'outside/summary'; out.write_text('external credentials'); self.summary().hardlink_to(out)
        p = self.links(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(out.read_text(), 'external credentials'); self.assertNotEqual(out.stat().st_ino, self.summary().stat().st_ino)

    def test_private_write_failure_keeps_old_bytes_and_cleans_temp(self):
        path = self.root / 'etc/qeli/client-links/write-test'; path.write_text('old bytes'); self.mode('cat_fail')
        p = self.run_installer('_write_private_file /etc/qeli/client-links/write-test <<< replacement'); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(path.read_text(), 'old bytes'); self.assertFalse(list(path.parent.glob('*.qeli-*')))

    def test_web_rewrite_preserves_owner_private_mode_and_sections(self):
        conf = self.root / 'etc/qeli/server.conf'; conf.write_text('[web]\ntls = false\n# tls = true\n[profile:udp-quic]\nbind.port = 443\n'); os.chown(conf, 234, 234); conf.chmod(0o640)
        p = self.run_installer('_conf_web_set tls true; _conf_web_set public_host vpn.example'); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(conf.stat().st_uid, 234); self.assertEqual(conf.stat().st_gid, 234); self.assertEqual(conf.stat().st_mode & 0o777, 0o600)
        text = conf.read_text(); self.assertEqual(text.count('tls = true'), 1); self.assertIn('[profile:udp-quic]\nbind.port = 443', text)

    def test_web_awk_failure_keeps_original_and_cleans_temp(self):
        conf = self.root / 'etc/qeli/server.conf'; old = conf.read_bytes(); self.mode('awk_fail')
        p = self.run_installer('_conf_web_set tls true'); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(conf.read_bytes(), old); self.assertFalse(list(conf.parent.glob('*.qeli-*')))

    def test_web_publish_failure_keeps_original_and_cleans_temp(self):
        conf = self.root / 'etc/qeli/server.conf'; old = conf.read_bytes(); self.mode('mv_fail')
        p = self.run_installer('_conf_web_set tls true'); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(conf.read_bytes(), old); self.assertFalse(list(conf.parent.glob('*.qeli-*')))

    def test_web_hardlink_does_not_mutate_external_config(self):
        conf = self.root / 'etc/qeli/server.conf'; out = self.root / 'outside/config'; out.hardlink_to(conf); old = out.read_bytes()
        p = self.run_installer('_conf_web_set tls true'); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(out.read_bytes(), old); self.assertNotEqual(out.stat().st_ino, conf.stat().st_ino)

    def test_web_dangling_link_refuses_without_external_creation(self):
        conf = self.root / 'etc/qeli/server.conf'; conf.unlink(); conf.symlink_to('/outside/web-config')
        p = self.run_installer('_conf_web_set tls true'); self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.root / 'outside/web-config').exists())

    def test_same_stamp_backups_unique_private_and_preserve_both_versions(self):
        conf = self.root / 'etc/qeli/server.conf'; conf.write_text('first version')
        command = 'RUN_STAMP=fixed; _backup_private_file "$CONF"; printf second > "$CONF"; _backup_private_file "$CONF"'
        p = self.run_installer(command); self.assertEqual(p.returncode, 0, p.stderr)
        backups = list(conf.parent.glob('server.conf.bak-fixed*')); self.assertEqual(len(backups), 2)
        self.assertEqual({x.read_text() for x in backups}, {'first version', 'second'})
        for backup in backups: self.assert_private(backup)

    def test_whole_summary_link_refuses_before_dependencies_or_config_mutation(self):
        conf = self.root / 'etc/qeli/server.conf'; old = conf.read_bytes(); self.env['QELI_FORCE_RECONFIG'] = '1'
        out = self.root / 'outside/summary'; out.write_text('witness'); self.summary().symlink_to('/outside/summary')
        p = self.run_installer(whole=True); self.assertNotEqual(p.returncode, 0)
        self.assertEqual(conf.read_bytes(), old); self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)
        self.assertFalse((self.root / 'records/apt.log').exists()); self.assertEqual(out.read_text(), 'witness')


    def test_whole_local_udp_control_flow_to_done(self):
        (self.root / 'etc/qeli/server.conf').unlink(); (self.root / 'etc/qeli/users.conf').write_text('')
        p = self.run_installer(whole=True); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('Done', p.stdout); self.assertFalse((self.root / 'records/apt.log').exists())
        config = self.root / 'etc/qeli/server.conf'; text = config.read_text()
        self.assertEqual(re.findall(r'^\[profile:([^]]+)\]', text, re.M), ['udp-quic'])
        self.assertIn('tun.ip_mode = ipv4', text); self.assertIn('tls = true', text); self.assertIn('bind = 127.0.0.1', text)
        self.assertEqual(config.stat().st_uid, 234); self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len((self.root / 'records/passwords').read_text().splitlines()), 5); self.assert_private(self.summary())
        self.assertFalse(list(self.summary().parent.glob('INSTALL-PENDING-*')))
        calls = (self.root / 'records/qeli-argv').read_text(); self.assertIn('check-config --config /etc/qeli/server.conf', calls)
        self.assertIn('restart qeli', (self.root / 'records/systemctl.log').read_text())


    def test_kept_link_hardlink_private_copy_preserves_external_bytes_and_mode(self):
        (self.root / 'etc/qeli/users.conf').write_text('[user:phone1]\npassword_hash = old\n')
        out = self.root / 'outside/kept-link'; out.write_text('old link\n'); out.chmod(0o644)
        link = self.summary().parent / 'phone1.qeli'; link.hardlink_to(out)
        p = self.links(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(link.read_bytes(), out.read_bytes()); self.assert_private(link)
        self.assertEqual(out.stat().st_mode & 0o777, 0o644); self.assertNotEqual(out.stat().st_ino, link.stat().st_ino)


if __name__ == '__main__':
    unittest.main(verbosity=2)
