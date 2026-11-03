#!/usr/bin/env python3
"""Q33 preflight/staged config publication, exact whole installer in Linux chroots.

CLI/account/systemctl/HTTP/kernel are explicit seams. Real filesystem and shell
fault handling, not actual crypto/parser/VPN qualification.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import test_installer_secrets as secret_fixture


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Linux root/chroot required')
class ConfigTests(unittest.TestCase):
    stub = secret_fixture.SecretTests.__dict__['stub']
    tearDownClass = secret_fixture.SecretTests.__dict__['tearDownClass']

    @classmethod
    def setUpClass(cls):
        secret_fixture.SecretTests.setUpClass.__func__(cls)
        cli = cls.base / 'usr/local/bin/qeli'; text = cli.read_text()
        text = text.replace('case "$1" in', '''mode="$(< /records/mode)"
case "$1" in''')
        text = text.replace(' show-identity) ', ' show-identity) [[ "$mode" != identity_fail ]] || exit 42; ')
        text = text.replace(' check-config) ', ' check-config) [[ "$mode" != validate_fail ]] || exit 42; ')
        text = text.replace(' set-service-user) exit 0', ' set-service-user) [[ "$mode" != service_user_fail ]] || exit 42;exit 0')
        cli.write_text(text)
        cls.stub('awk', r'''mode="$(< /records/mode)"
if [[ "$*" == *server-multiprofile.conf.example && ( "$mode" == globals_fail || ( "$mode" == profile_fail && "$1" == -v ) ) ]]; then printf partial;exit 42;fi
exec /usr/bin/awk "$@"''')
        cls.stub('sed', r'''if [[ "$(< /records/mode)" == sed_fail && "$1" == -i && "$*" == *server.conf* ]]; then exit 42;fi
exec /usr/bin/sed "$@"''')
        cls.stub('openssl', r'''if [[ "$(< /records/mode)" == random_fail && "$*" == 'rand -hex 8' ]]; then exit 42;fi
exec /usr/bin/openssl "$@"''')
        cls.stub('install', r'''printf '%s\n' "$*" >> /records/install.log
if [[ "$(< /records/mode)" == backup_fail && "${!#}" == *.bak-* ]]; then exit 42;fi
exec /usr/bin/install "$@"''')
        cls.stub('mv', r'''printf '%s\n' "$*" >> /records/mv-argv
if [[ "$(< /records/mode)" == config_publish_fail && "${!#}" == /etc/qeli/server.conf ]]; then exit 42;fi
exec /usr/bin/mv "$@"''')
        cls.stub('curl', r'''printf '%s\n' "$*" >> /records/curl.log
case "$(< /records/mode)" in autodetect_bad) printf 'evil|host' ;; autodetect_empty) exit 22 ;; *) printf '203.0.113.4\n' ;; esac''')
        (cls.base / 'etc/ssl/certs').mkdir(parents=True)
        (cls.base / 'etc/ssl/certs/ca-certificates.crt').write_text('fixture CA availability\n')

    def setUp(self):
        secret_fixture.SecretTests.setUp(self)
        self.env['QELI_FORCE_RECONFIG'] = '1'
        self.before = (self.root / 'etc/qeli/server.conf').read_bytes()

    def mode(self, value): (self.root / 'records/mode').write_text(value)

    def run_installer(self, host='vpn.example'):
        p = subprocess.run([self.chroot, str(self.root), '/bin/bash', '/installer.sh', host], env=self.env, capture_output=True, text=True, timeout=15)
        record = os.environ.get('QELI_CONFIG_OPERATION_RECORDS')
        if record:
            with Path(record).open('a', encoding='utf8') as f:
                f.write(json.dumps({'method': self.id(), 'whole': True, 'host': host, 'mode': (self.root / 'records/mode').read_text(), 'returncode': p.returncode}) + '\n')
        self.assertFalse(list((self.root / 'tmp').iterdir()), p.stderr)
        self.assertFalse(list((self.root / 'etc/qeli').glob('*.qeli-*')), p.stderr)
        return p

    def unchanged(self, p):
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual((self.root / 'etc/qeli/server.conf').read_bytes(), self.before)
        calls = self.root / 'records/systemctl.log'
        if calls.exists(): self.assertNotIn('restart qeli', calls.read_text())

    def early(self, p):
        self.unchanged(p)
        self.assertEqual((self.root / 'usr/bin/qeli').read_bytes(), self.old)
        self.assertFalse((self.root / 'records/apt.log').exists())
        self.assertFalse((self.root / 'records/qeli-argv').exists())
        self.assertFalse((self.root / 'records/install.log').exists())

    def test_invalid_explicit_host_refuses_before_mutation(self):
        for host in ['evil|host', '-example', 'a' * 254]:
            with self.subTest(host=host): self.early(self.run_installer(host))

    def test_invalid_panel_options_refuse_before_mutation(self):
        for public, allowed in [('1', ''), ('1', 'bad address'), ('1', 'a|b'), ('2', '203.0.113.4')]:
            with self.subTest(public=public, allowed=allowed):
                self.env.update(QELI_PANEL_PUBLIC=public, QELI_PANEL_ALLOWED_IPS=allowed)
                self.early(self.run_installer())

    def test_boolean_optins_reject_typos_before_mutation(self):
        for flag in ['QELI_FORCE_RECONFIG', 'QELI_VERIFY_ATTESTATION', 'QELI_ALLOW_UNVERIFIED']:
            with self.subTest(flag=flag):
                saved = self.env.get(flag); self.env[flag] = 'oops'
                try:
                    p = self.run_installer(); self.early(p); self.assertIn(flag + ' must be 0 or 1', p.stderr)
                finally:
                    if saved is None: self.env.pop(flag)
                    else: self.env[flag] = saved

    def test_bad_autodetection_does_not_change_config_or_generate_identity(self):
        self.mode('autodetect_bad'); self.unchanged(self.run_installer(''))
        self.assertFalse((self.root / 'records/qeli-argv').exists())

    def test_empty_autodetection_does_not_change_config_or_generate_identity(self):
        self.mode('autodetect_empty'); self.unchanged(self.run_installer(''))
        self.assertFalse((self.root / 'records/qeli-argv').exists())

    def test_valid_autodetection_commits_config(self):
        p = self.run_installer(''); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('public_host = 203.0.113.4', (self.root / 'etc/qeli/server.conf').read_text())

    def alter_example(self, duplicate=False):
        p = self.root / 'checkout/qeli/config/server-multiprofile.conf'; text = p.read_text()
        if duplicate: text += '\n[profile:udp-quic]\nbind.port = 1234\n'
        else:
            a = text.index('[profile:udp-quic]'); b = text.find('\n[profile:', a + 1)
            text = text[:a] + (text[b:] if b != -1 else '')
        p.write_text(text)

    def test_missing_selected_profile_refuses_without_config_mutation(self):
        self.alter_example(); self.unchanged(self.run_installer())
        self.assertFalse((self.root / 'records/qeli-argv').exists())

    def test_duplicate_selected_profile_refuses_without_config_mutation(self):
        self.alter_example(duplicate=True); self.unchanged(self.run_installer())
        self.assertFalse((self.root / 'records/qeli-argv').exists())

    def test_global_awk_failure_keeps_live_config(self):
        self.mode('globals_fail'); self.unchanged(self.run_installer())

    def test_profile_awk_failure_keeps_live_config(self):
        self.mode('profile_fail'); self.unchanged(self.run_installer())

    def test_sed_failure_keeps_live_config(self):
        self.mode('sed_fail'); self.unchanged(self.run_installer())

    def test_reality_random_failure_keeps_live_config(self):
        self.env['QELI_PROFILE'] = 'reality-tls'; self.mode('random_fail'); self.unchanged(self.run_installer())

    def test_identity_failure_keeps_live_config(self):
        self.mode('identity_fail'); self.unchanged(self.run_installer())

    def test_partial_users_failure_keeps_live_config_and_password_journal(self):
        self.mode('fail_after'); self.unchanged(self.run_installer())
        self.assertIn('[user:phone3]', (self.root / 'etc/qeli/users.conf').read_text())
        self.assertEqual(len(list((self.root / 'etc/qeli/client-links').glob('INSTALL-PENDING-*'))), 1)

    def test_final_validation_refuses_before_root_override_and_commit(self):
        self.env['QELI_RUN_AS'] = 'root'; self.mode('validate_fail'); self.unchanged(self.run_installer())
        self.assertNotIn('set-service-user', (self.root / 'records/qeli-argv').read_text())

    def test_failed_backup_prevents_commit_and_restart(self):
        self.mode('backup_fail'); self.unchanged(self.run_installer())

    def test_failed_config_publish_preserves_live_config(self):
        self.mode('config_publish_fail'); self.unchanged(self.run_installer())

    def test_fresh_invalid_config_does_not_publish_empty_or_partial_file(self):
        (self.root / 'etc/qeli/server.conf').unlink(); self.mode('validate_fail')
        p = self.run_installer(); self.assertNotEqual(p.returncode, 0)
        self.assertFalse((self.root / 'etc/qeli/server.conf').exists())
        self.assertNotIn('restart qeli', (self.root / 'records/systemctl.log').read_text())

    def test_new_tcp_profiles_explicitly_leave_buffers_to_linux(self):
        for profile in ('fake-tls','reality-tls'):
            with self.subTest(profile=profile):
                self.env['QELI_PROFILE']=profile
                p=self.run_installer();self.assertEqual(p.returncode,0,p.stderr)
                text=(self.root/'etc/qeli/server.conf').read_text()
                self.assertIn('[profile:'+profile+']',text)
                self.assertIn('perf.tcp.send_buffer_size = 0',text)
                self.assertIn('perf.tcp.recv_buffer_size = 0',text)

    def test_old_packaged_example_gets_missing_tcp_defaults_in_selected_profile_only(self):
        self.env['QELI_PROFILE']='fake-tls'
        example=self.root/'checkout/qeli/config/server-multiprofile.conf'
        example.write_text('\n'.join(line for line in example.read_text().splitlines()
            if not line.startswith(('perf.tcp.send_buffer_size','perf.tcp.recv_buffer_size')))+'\n')
        p=self.run_installer();self.assertEqual(p.returncode,0,p.stderr)
        text=(self.root/'etc/qeli/server.conf').read_text()
        profile=text.split('[profile:fake-tls]',1)[1].split('\n[',1)[0]
        self.assertEqual(text.count('perf.tcp.send_buffer_size = 0'),1)
        self.assertEqual(text.count('perf.tcp.recv_buffer_size = 0'),1)
        self.assertIn('perf.tcp.send_buffer_size = 0',profile)
        self.assertIn('perf.tcp.recv_buffer_size = 0',profile)

    def test_explicit_example_tcp_override_is_preserved(self):
        self.env['QELI_PROFILE']='fake-tls'
        example=self.root/'checkout/qeli/config/server-multiprofile.conf'
        example.write_text(example.read_text().replace('perf.tcp.send_buffer_size = 0',
            'perf.tcp.send_buffer_size = 524288').replace('perf.tcp.recv_buffer_size = 0',
            'perf.tcp.recv_buffer_size = 1048576'))
        p=self.run_installer();self.assertEqual(p.returncode,0,p.stderr)
        text=(self.root/'etc/qeli/server.conf').read_text()
        self.assertEqual(text.count('perf.tcp.send_buffer_size = 524288'),1)
        self.assertEqual(text.count('perf.tcp.recv_buffer_size = 1048576'),1)
        self.assertNotIn('perf.tcp.send_buffer_size = 0',text)
        self.assertNotIn('perf.tcp.recv_buffer_size = 0',text)

    def test_missing_recv_default_preserves_explicit_send_and_ignores_other_profiles(self):
        self.env['QELI_PROFILE']='fake-tls'
        example=self.root/'checkout/qeli/config/server-multiprofile.conf'
        text=example.read_text()
        start=text.index('[profile:fake-tls]');end=text.index('[profile:',start+1)
        selected=text[start:end].replace('perf.tcp.recv_buffer_size = 0\n','').replace(
            'perf.tcp.send_buffer_size = 0','  perf.tcp.send_buffer_size = 524288')
        example.write_text(text[:start]+selected+text[end:])
        p=self.run_installer();self.assertEqual(p.returncode,0,p.stderr)
        text=(self.root/'etc/qeli/server.conf').read_text()
        self.assertEqual(text.count('perf.tcp.send_buffer_size = 524288'),1)
        self.assertEqual(text.count('perf.tcp.recv_buffer_size = 0'),1)
        self.assertNotIn('perf.tcp.send_buffer_size = 0',text)

    def test_new_udp_profile_does_not_receive_tcp_buffer_keys(self):
        self.env['QELI_PROFILE']='udp-quic'
        p=self.run_installer();self.assertEqual(p.returncode,0,p.stderr)
        text=(self.root/'etc/qeli/server.conf').read_text()
        self.assertNotIn('perf.tcp.send_buffer_size',text)
        self.assertNotIn('perf.tcp.recv_buffer_size',text)

    def test_existing_manual_tcp_buffers_are_not_migrated_by_first_installer(self):
        self.env.pop('QELI_FORCE_RECONFIG')
        config=self.root/'etc/qeli/server.conf'
        self.before=b'[profile:manual]\nperf.tcp.send_buffer_size = 524288\nperf.tcp.recv_buffer_size = 1048576\n'
        config.write_bytes(self.before)
        p=self.run_installer()
        self.assertNotEqual(p.returncode,0,p.stderr)
        self.assertEqual(config.read_bytes(),self.before)
        self.assertFalse((self.root/'records/qeli-argv').exists())

    def test_successful_forced_config_breaks_hardlink_and_preserves_backup(self):
        conf = self.root / 'etc/qeli/server.conf'; out = self.root / 'outside/config'; out.hardlink_to(conf)
        p = self.run_installer(); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(out.read_bytes(), self.before); self.assertNotEqual(out.stat().st_ino, conf.stat().st_ino)
        backups = list(conf.parent.glob('server.conf.bak-*')); self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.before); self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(conf.stat().st_uid, 234); self.assertEqual(conf.stat().st_mode & 0o777, 0o600)
        args = (self.root / 'records/qeli-argv').read_text(); self.assertIn('--config /etc/qeli/server.conf.qeli-', args)
        self.assertIn('restart qeli', (self.root / 'records/systemctl.log').read_text())

    def test_public_ipv6_endpoint_and_panel_control_flow(self):
        self.env.update(QELI_PANEL_PUBLIC='1', QELI_PANEL_ALLOWED_IPS='203.0.113.4,2001:db8::/64')
        p = self.run_installer('2001:db8::1'); self.assertEqual(p.returncode, 0, p.stderr)
        text = (self.root / 'etc/qeli/server.conf').read_text(); self.assertIn('bind = ::', text)
        self.assertIn('listen = [::]:443', text); self.assertIn('allowed_ips = 203.0.113.4,2001:db8::/64', text)
        self.assertIn('--host [2001:db8::1]:443', (self.root / 'records/qeli-argv').read_text())

    def test_service_user_failure_after_validation_preserves_live_config(self):
        self.env['QELI_RUN_AS'] = 'root'; self.mode('service_user_fail'); self.unchanged(self.run_installer())
        args = (self.root / 'records/qeli-argv').read_text(); self.assertLess(args.index('check-config'), args.index('set-service-user root'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
