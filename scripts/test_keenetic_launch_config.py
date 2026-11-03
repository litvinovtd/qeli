"""Owned native process/real core preflight; filesystem and network control models.
Requires root Linux, the recorded C process fixture and current actual inspector.
Both templates are exercised per method; baseline overrides only their bundle.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import shlex
import shutil
import unittest
import test_keenetic_process as processes
from test_keenetic_templates import ROOT

INSPECTOR = Path(os.environ.get('QELI_GATEWAY_INSPECTOR', '/nonexistent-qeli-inspector'))
BASELINE = os.environ.get('QELI_LAUNCH_BASELINE', '')

@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0 and
                    INSPECTOR.is_file() and processes.NATIVE.is_file(),
                    'requires owned root Linux native fixture/current core inspector')
class LaunchConfigTests(unittest.TestCase):
    @contextmanager
    def fixture(self, attached):
        cls = processes.KeeneticOpkgTunProcessTests if attached else processes.KeeneticBaseProcessTests
        f = cls('test_start_private_identity_and_repeated_start')
        try:
            f.setUp()
            if BASELINE:
                source = Path(BASELINE) / f.TEMPLATE
                f.copy_template(source, f.script)
                helper = f.opt / 'etc/qeli/lifecycle.sh'
                helper.write_text((Path(BASELINE) / 'release/keenetic/lifecycle.sh').read_text().replace(
                    '/opt/', str(f.opt)+'/').replace('/var/run/qeli.lifecycle.lock',
                    str(f.opt/'var/run/qeli.lifecycle.lock')))
                text = f.script.read_text().replace('[ "$waited" -lt 15 ]','[ "$waited" -lt 3 ]')
                head, dispatch = text.rsplit('case "$1" in', 1)
                f.script.write_text(head + '\nnat_up() { return 0; }\n'
                    + 'nat_down() { printf "CLEANUP\\n" >> "$QELI_HELPER_EVENTS"; return 0; }\n'
                    + 'case "$1" in' + dispatch)
            dev = 'opkgtun0' if attached else 'vpn0'
            f.conf.write_text('[qeli]\nserver=192.0.2.1:443\nmode=plain\nbind_static=false\n'
                'user=fixture\npass=canary-password\ngateway=false\n'
                + 'dev='+dev+'\ndev_attach='+str(attached).lower()+'\n'
                + 'gateway_nat='+str(not attached).lower()+'\n')
            f.conf.chmod(0o600)
            f.env.update(QELI_HELPER_REAL_INSPECTOR=str(INSPECTOR),
                QELI_HELPER_QUERY_COPY=str(f.root/'query.ini'), QELI_HELPER_QUERY_PATH=str(f.root/'query.path'),
                QELI_HELPER_CONFIG_COPY=str(f.root/'opened.ini'), QELI_HELPER_CONFIG_PATH=str(f.root/'opened.path'))
            f.launch_dir = f.opt/'var/run/qeli-launch'
            f.launch_conf = f.launch_dir/'client.conf'
            yield f
        finally:
            f.doCleanups()

    def test_installer_refuses_unowned_directory_or_missing_snapshot_tools_before_dependencies(self):
        for attached in [False, True]:
            for fault in ['owner', 'stat', 'cp', 'mktemp']:
                with self.subTest(attached=attached, fault=fault), self.fixture(attached) as f:
                    f.seed_installed()
                    if fault == 'owner':os.chown(f.conf.parent, 65534, 65534)
                    else:(f.bin/fault).unlink()
                    result = f.installer()
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(f.installed('bin/qeli-client').read_text(), 'old binary')
                    self.assertEqual(f.installed('etc/init.d/S99qeli').read_text(), 'old init')
                    self.assertNotIn('opkg update', f.calls())
                    self.assertFalse(any(c.startswith('opkg install ') for c in f.calls()))
                    self.assertEqual(f.helper_pids(), set())

    def test_atomic_original_replacement_after_actual_preflight_cannot_change_launch(self):
        for attached in [False, True]:
            with self.subTest(attached=attached), self.fixture(attached) as f:
                before = f.conf.read_bytes()
                replacement = '[qeli]\ndev=vpn1\ngateway_nat=false\nuser=replaced\n'
                # Native fixture rotates the original immediately after actual core inspection.
                f.env.update(QELI_HELPER_ROTATE_CONFIG=str(f.conf), QELI_HELPER_ROTATE_TEXT=replacement)
                pid = f.start()
                self.assertEqual((f.root/'query.ini').read_bytes(), before)
                self.assertEqual((f.root/'opened.ini').read_bytes(), before)
                self.assertEqual(f.conf.read_text(), replacement)
                self.assertEqual((f.root/'query.path').read_text(), (f.root/'opened.path').read_text())
                self.assertNotEqual((f.root/'opened.path').read_text().strip(), str(f.conf))
                self.assertEqual(f.launch_dir.stat().st_mode & 0o777, 0o700)
                self.assertEqual(f.launch_conf.stat().st_mode & 0o777, 0o600)
                self.assertEqual(f.service('stop').returncode, 0)
                f.assert_joined(pid)
                self.assertFalse(f.launch_conf.exists())
                self.assertEqual(f.conf.read_text(), replacement)

    def test_snapshot_preserves_mode_and_owner_without_promoting_command_trust(self):
        for attached in [False, True]:
            for mode, uid in [(0o644, 0), (0o666, 0), (0o600, 65534)]:
                with self.subTest(attached=attached, mode=mode, uid=uid), self.fixture(attached) as f:
                    f.conf.chmod(mode);os.chown(f.conf, uid, 65534 if uid else 0)
                    pid = f.start()
                    self.assertEqual(f.launch_conf.read_bytes(), f.conf.read_bytes())
                    self.assertEqual(f.launch_conf.stat().st_uid, uid)
                    self.assertEqual(f.launch_conf.stat().st_mode & 0o777, mode)
                    self.assertEqual(f.launch_dir.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(f.service('stop').returncode, 0);f.assert_joined(pid)

    def test_unsafe_source_and_runtime_paths_are_refused_without_external_changes(self):
        for attached in [False, True]:
            for kind in ['source-link', 'parent-mode', 'runtime-link', 'runtime-mode', 'target-link', 'target-dir']:
                with self.subTest(attached=attached, kind=kind), self.fixture(attached) as f:
                    outside = f.root/'outside';outside.mkdir(mode=0o755)
                    external = outside/'client.conf';external.write_text('external-sentinel');external.chmod(0o640)
                    if kind == 'source-link':f.conf.unlink();f.conf.symlink_to(external)
                    elif kind == 'parent-mode':f.conf.parent.chmod(0o755)
                    elif kind == 'runtime-link':f.launch_dir.symlink_to(outside, target_is_directory=True)
                    else:
                        f.launch_dir.mkdir(mode=0o755 if kind == 'runtime-mode' else 0o700)
                        if kind == 'target-link':f.launch_conf.symlink_to(external)
                        elif kind == 'target-dir':f.launch_conf.mkdir()
                    self.assertNotEqual(f.service('start').returncode, 0)
                    self.assertEqual(external.read_text(), 'external-sentinel')
                    self.assertEqual(external.stat().st_mode & 0o777, 0o640)
                    self.assertEqual(outside.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(f.helper_pids(), set())

    def test_copy_publication_failure_preserves_previous_snapshot_and_plan(self):
        for attached in [False, True]:
            for command in ['cp', 'mv']:
                with self.subTest(attached=attached, command=command), self.fixture(attached) as f:
                    f.launch_dir.mkdir(mode=0o700);f.launch_conf.write_text('old-snapshot')
                    f.plan.write_text('retained-plan')
                    f.write_command(command, 'exit 17')
                    self.assertNotEqual(f.service('start').returncode, 0)
                    self.assertEqual(f.launch_conf.read_text(), 'old-snapshot')
                    self.assertEqual(f.plan.read_text(), 'retained-plan')
                    self.assertFalse(list(f.launch_dir.glob('.client.conf.*')))
                    self.assertEqual(f.helper_pids(), set())

    def test_failed_join_retains_snapshot_until_verified_stop_retry(self):
        for attached in [False, True]:
            with self.subTest(attached=attached), self.fixture(attached) as f:
                pid = f.start(QELI_HELPER_MODE='ignore');before = f.launch_conf.read_bytes()
                self.assertNotEqual(f.service('stop').returncode, 0)
                self.assertEqual(f.launch_conf.read_bytes(), before)
                self.assertTrue(f.pidfile.exists());self.assertTrue(processes.running(pid))
                os.kill(pid, 9)
                self.assertEqual(f.service('stop').returncode, 0)
                self.assertFalse(f.launch_conf.exists())

    def test_large_copy_is_bounded_before_parser_or_launch(self):
        for attached in [False, True]:
            with self.subTest(attached=attached), self.fixture(attached) as f:
                f.conf.write_bytes(b'x' * (4 * 1024 * 1024))
                self.assertNotEqual(f.service('start').returncode, 0)
                self.assertFalse(f.launch_conf.exists())
                self.assertFalse(list(f.launch_dir.glob('.client.conf.*')))
                self.assertEqual(f.helper_pids(), set())

    def test_active_start_keeps_snapshot_and_restart_admits_updated_original(self):
        for attached in [False, True]:
            with self.subTest(attached=attached), self.fixture(attached) as f:
                before = f.conf.read_bytes();pid = f.start()
                updated = before.replace(b'user=fixture', b'user=updated')
                f.conf.write_bytes(updated)
                self.assertEqual(f.service('start').returncode, 0)
                self.assertEqual(f.launch_conf.read_bytes(), before)
                self.assertEqual(f.service('restart').returncode, 0)
                self.assertNotEqual(f.pidfile.read_text().split()[0], str(pid))
                self.assertEqual(f.launch_conf.read_bytes(), updated)
                self.assertEqual((f.root/'opened.ini').read_bytes(), updated)
                self.assertEqual(f.service('stop').returncode, 0)


if __name__ == '__main__':
    unittest.main()
