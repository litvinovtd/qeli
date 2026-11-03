#!/usr/bin/env python3
"""Execute the production Docker entrypoint in disposable Linux chroots.

Requires root, coreutils, dash, and optionally QELI_ENTRYPOINT_ASH_ROOT containing
an extracted OpenWrt rootfs. This checks shell/filesystem behavior with a recording
qeli executable; it does not qualify the Docker image, VPN or daemon networking.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = Path(os.environ.get('QELI_ENTRYPOINT_SOURCE', ROOT / 'release/docker/entrypoint.sh'))


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Linux root/chroot required')
class EntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chroot = shutil.which('chroot')
        assert cls.chroot, 'chroot required'
        cls.workspace = tempfile.TemporaryDirectory(prefix='qeli-entrypoint-tests-')
        cls.base = Path(cls.workspace.name) / 'base'
        cls.base.mkdir()
        cls.shells = ['/bin/dash']
        ash_root = os.environ.get('QELI_ENTRYPOINT_ASH_ROOT')
        if ash_root:
            shutil.copytree(ash_root, cls.base, dirs_exist_ok=True, symlinks=True)
            assert (cls.base / 'bin/ash').exists(), 'rootfs must contain ash'
            cls.shells.append('/bin/ash')
        selected = os.environ.get('QELI_ENTRYPOINT_TEST_SHELL')
        if selected:
            assert selected in cls.shells, 'requested shell unavailable'
            cls.shells = [selected]
        for program in ['/bin/dash', *['/usr/bin/' + n for n in
                                     ['cat', 'cp', 'ln', 'mkdir', 'mktemp', 'rm', 'dirname', 'grep']]]:
            dest = cls.base / program.lstrip('/')
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Replace rootfs busybox symlinks, keeping its ash and musl libraries.
            if dest.is_symlink():
                dest.unlink()
            shutil.copy2(program, dest)
            libs = subprocess.check_output(['ldd', program], text=True)
            for lib in re.findall(r'(/[^\s]+)', libs):
                target = cls.base / lib.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_symlink():
                    target.unlink()
                shutil.copy2(lib, target)
        for name in ['etc/qeli', 'usr/share/qeli', 'usr/local/bin', 'tmp', 'dev', 'records']:
            (cls.base / name).mkdir(parents=True, exist_ok=True)
        (cls.base / 'dev/null').touch()  # no actual devices or proc/sys mounted
        for role in ['server', 'client']:
            (cls.base / f'usr/share/qeli/{role}.conf.example').write_text(f'[qeli]\nrole = {role}\n')
        (cls.base / 'entrypoint.sh').write_bytes(ENTRYPOINT.read_bytes())
        recorder = cls.base / 'usr/local/bin/qeli'
        recorder.write_text('#!/bin/dash\nprintf "%s\\n" "$@" > /records/argv\n')
        recorder.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def cases(self):
        for shell in self.shells:
            with tempfile.TemporaryDirectory(dir=self.workspace.name) as work:
                root = Path(work) / 'root'
                shutil.copytree(self.base, root, symlinks=True)
                yield shell, root

    def run_entry(self, root, shell, args=(), config=None):
        env = dict(os.environ, PATH='/usr/local/bin:/usr/bin:/bin', LC_ALL='C')
        env.pop('QELI_CONFIG', None)
        if config is not None:
            env['QELI_CONFIG'] = config
        p = subprocess.run([self.chroot, str(root), shell, '/entrypoint.sh', *args],
                           env=env, capture_output=True, text=True, timeout=5)
        argv = (root / 'records/argv').read_text().splitlines() if (root / 'records/argv').exists() else None
        self.assertFalse(list(root.rglob('*.qeli-*')), p.stderr)
        return p, argv

    def test_default_without_arguments(self):
        for shell, root in self.cases():
            p, argv = self.run_entry(root, shell)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(argv, ['server', '--config', '/etc/qeli/server.conf'])

    def test_explicit_path_is_used_once(self):
        for shell, root in self.cases():
            p, argv = self.run_entry(root, shell, ['client', '--config', '/custom/path with space.conf'], '/ignored.conf')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(argv, ['client', '--config', '/custom/path with space.conf'])
            self.assertTrue((root / 'custom/path with space.conf').is_file())
            self.assertFalse((root / 'ignored.conf').exists())
            self.assertFalse((root / 'etc/qeli/client.conf').exists())
            self.assertFalse((root / 'etc/qeli/users.conf').exists())

    def test_equal_and_short_config_forms(self):
        for shell, root in self.cases():
            for args in [['client', '--config=/one.conf'], ['client', '-c', '/two.conf'], ['client', '-c/three.conf']]:
                p, argv = self.run_entry(root, shell, args)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(argv, args)

    def test_environment_path(self):
        for shell, root in self.cases():
            p, argv = self.run_entry(root, shell, ['client'], '/env/path.conf')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(argv, ['client', '--config', '/env/path.conf'])
            self.assertTrue((root / 'env/path.conf').is_file())

    def test_option_only_invocation(self):
        for shell, root in self.cases():
            p, argv = self.run_entry(root, shell, ['--config', '/option.conf'])
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(argv, ['server', '--config', '/option.conf'])

    def test_secrets_created_owner_only(self):
        for shell, root in self.cases():
            p, _ = self.run_entry(root, shell, ['server'])
            self.assertEqual(p.returncode, 0, p.stderr)
            for name in ['server.conf', 'users.conf']:
                self.assertEqual((root / 'etc/qeli' / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / 'etc/qeli/users.conf').read_bytes(), b'')

    def test_existing_configuration_and_users_preserved(self):
        for shell, root in self.cases():
            for name in ['server.conf', 'users.conf']:
                p = root / 'etc/qeli' / name
                p.write_text('operator state\n')
                p.chmod(0o640)
            p, _ = self.run_entry(root, shell, ['server'])
            self.assertEqual(p.returncode, 0, p.stderr)
            for name in ['server.conf', 'users.conf']:
                p = root / 'etc/qeli' / name
                self.assertEqual(p.read_text(), 'operator state\n')
                self.assertEqual(p.stat().st_mode & 0o777, 0o640)

    def test_help_does_not_seed(self):
        for shell, root in self.cases():
            p, argv = self.run_entry(root, shell, ['client', '--help'])
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(argv, ['client', '--help'])
            self.assertFalse(list((root / 'etc/qeli').iterdir()))

    def test_missing_or_duplicate_path_refuses_before_write(self):
        for shell, root in self.cases():
            for args in [['server', '-c'], ['server', '--config='], ['server', '-c', '/a', '--config=/b']]:
                p, argv = self.run_entry(root, shell, args)
                self.assertNotEqual(p.returncode, 0)
                self.assertIsNone(argv)
                self.assertFalse(list((root / 'etc/qeli').iterdir()))

    def test_dangling_users_link_preserves_target(self):
        for shell, root in self.cases():
            (root / 'etc/qeli/users.conf').symlink_to('/records/canary')
            p, argv = self.run_entry(root, shell, ['server'])
            self.assertNotEqual(p.returncode, 0)
            self.assertIsNone(argv)
            self.assertFalse((root / 'records/canary').exists())
            self.assertTrue((root / 'etc/qeli/users.conf').is_symlink())

    def test_config_link_and_fifo_refuse(self):
        for shell, root in self.cases():
            path = root / 'etc/qeli/client.conf'
            (root / 'records/canary').write_text('preserved')
            path.symlink_to('/records/canary')
            p, argv = self.run_entry(root, shell, ['client'])
            self.assertNotEqual(p.returncode, 0)
            self.assertIsNone(argv)
            self.assertEqual((root / 'records/canary').read_text(), 'preserved')
            path.unlink()
            os.mkfifo(path)
            p, argv = self.run_entry(root, shell, ['client'])
            self.assertNotEqual(p.returncode, 0)
            self.assertIsNone(argv)

    def wrapper(self, root, program, body):
        path = root / 'usr/local/bin' / program
        path.write_text('#!/bin/dash\n' + body + '\n')
        path.chmod(0o755)

    def test_concurrent_regular_creator_preserved(self):
        for shell, root in self.cases():
            self.wrapper(root, 'ln', 'printf "concurrent state\\n" > "$4"\nexec /usr/bin/ln "$@"')
            p, _ = self.run_entry(root, shell, ['client'])
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual((root / 'etc/qeli/client.conf').read_text(), 'concurrent state\n')

    def test_concurrent_symlink_refuses_without_truncation(self):
        for shell, root in self.cases():
            self.wrapper(root, 'ln', '/usr/bin/ln -s /records/canary "$4"\nexec /usr/bin/ln "$@"')
            p, argv = self.run_entry(root, shell, ['client'])
            self.assertNotEqual(p.returncode, 0)
            self.assertIsNone(argv)
            self.assertFalse((root / 'records/canary').exists())
            self.assertTrue((root / 'etc/qeli/client.conf').is_symlink())

    def test_concurrent_directory_refuses_without_nested_file(self):
        for shell, root in self.cases():
            self.wrapper(root, 'ln', '/usr/bin/mkdir "$4"\nexec /usr/bin/ln "$@"')
            p, argv = self.run_entry(root, shell, ['client'])
            self.assertNotEqual(p.returncode, 0)
            self.assertIsNone(argv)
            self.assertTrue((root / 'etc/qeli/client.conf').is_dir())
            self.assertFalse(list((root / 'etc/qeli/client.conf').iterdir()))

    def test_copy_failure_leaves_no_partial_final_file(self):
        for shell, root in self.cases():
            self.wrapper(root, 'cat', 'printf "partial"\nexit 1')
            p, argv = self.run_entry(root, shell, ['client'])
            self.assertNotEqual(p.returncode, 0)
            self.assertIsNone(argv)
            self.assertFalse((root / 'etc/qeli/client.conf').exists())

    def test_link_failure_leaves_no_partial_final_file(self):
        for shell, root in self.cases():
            self.wrapper(root, 'ln', 'exit 1')
            p, argv = self.run_entry(root, shell, ['client'])
            self.assertNotEqual(p.returncode, 0)
            self.assertIsNone(argv)
            self.assertFalse((root / 'etc/qeli/client.conf').exists())

    def test_config_path_is_data(self):
        for shell, root in self.cases():
            name = "/etc/qeli/a'; touch injected; '.conf"
            p, argv = self.run_entry(root, shell, ['client', '--config', name])
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(argv, ['client', '--config', name])
            self.assertTrue((root / name.lstrip('/')).exists())
            self.assertFalse((root / 'injected').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
