"""Real console protocol checks; no VPN connection, SCM or network mutation."""
import json
import os
from pathlib import Path
import struct
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'Windows command-shell contract')
class WindowsCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exe = Path(os.environ.get('QELI_CLI_EXE', ROOT / 'qeli-win/QeliCli/bin/Release/net10.0-windows/win-x64/qeli-cli.exe'))
        if not cls.exe.is_file():
            if os.environ.get('QELI_CLI_REQUIRED') == '1':
                raise AssertionError('Build the Windows CLI before running its required smoke tests')
            raise unittest.SkipTest('Windows CLI not built')
        cls.cmd = str(Path(os.environ['SystemRoot']) / 'System32/cmd.exe')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='qeli-cli-shell-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'профиль с пробелами.ini'
        self.config.write_text('[qeli]\nserver = 192.0.2.1:443\nproto = tcp\nuser = fixture\npass = cli-canary-secret\nmode = fake-tls\n', encoding='utf-8-sig')

    def run_cli(self, args, code=0, payload=None):
        result = subprocess.run(args, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        out = result.stdout.decode('utf-8-sig')
        err = result.stderr.decode('utf-8-sig')
        self.assertEqual(result.returncode, code, out + err)
        self.assertNotIn('cli-canary-secret', out + err)
        envelope = json.loads(out)
        self.assertEqual(envelope['schema_version'], 1)
        self.assertEqual(envelope['ok'], code == 0)
        self.assertEqual(err, '')
        return envelope

    def test_console_pe_and_non_elevating_manifest(self):
        data = self.exe.read_bytes()
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        self.assertEqual(data[pe:pe+4], b'PE\0\0')
        self.assertEqual(struct.unpack_from('<H', data, pe+4)[0], 0x8664)
        self.assertEqual(struct.unpack_from('<H', data, pe+24+68)[0], 3)
        self.assertIn(b'asInvoker', data)

    def test_no_desktop_framework_required(self):
        config = json.loads(self.exe.with_suffix('.runtimeconfig.json').read_bytes())['runtimeOptions']
        framework = config.get('framework')
        if framework:
            self.assertEqual(framework['name'], 'Microsoft.NETCore.App')
        for row in config.get('frameworks', []) + config.get('includedFrameworks', []):
            self.assertNotIn('WindowsDesktop', row['name'])

    def test_native_version(self):
        self.run_cli([str(self.exe), 'version', '--json'])

    def test_ini_bom_unicode_path(self):
        self.run_cli([str(self.exe), 'config', 'validate', '--config', str(self.config), '--json'])

    def test_ini_redirected_stdin(self):
        self.run_cli([str(self.exe), 'config', 'validate', '--config', '-', '--json'], payload=self.config.read_bytes())

    def test_missing_config_exit_code(self):
        self.run_cli([str(self.exe), 'config', 'validate', '--config', str(self.root / 'missing.ini'), '--json'], 3)

    def test_unknown_secret_option_does_not_echo_value(self):
        self.run_cli([str(self.exe), 'connect', '--config', str(self.config), '--pass=cli-canary-secret', '--json'], 2)

    def test_cmd_version(self):
        # Supply CMD's command string directly: list2cmdline uses backslash quoting,
        # which has different semantics from CMD's outer /s /c quote pair.
        self.run_cli(f'"{self.cmd}" /d /s /c ""{self.exe}" version --json"')

    def test_cmd_stdin(self):
        self.run_cli(f'"{self.cmd}" /d /s /c ""{self.exe}" config validate --config - --json < "{self.config}""')

    def test_batch_errorlevel(self):
        batch = self.root / 'check.cmd'
        batch.write_text('@echo off\r\n"' + str(self.exe) + '" config validate --config missing.ini --json\r\nexit /b %errorlevel%\r\n', encoding='utf-8')
        self.run_cli([self.cmd, '/d', '/c', str(batch)], 3)

    def test_powershell_51_and_7(self):
        shells = [Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe',
                  Path(shutil.which('pwsh') or str(Path(os.environ['ProgramFiles']) / 'PowerShell/7/pwsh.exe'))]
        for shell in shells:
            with self.subTest(shell=shell):
                self.assertTrue(shell.is_file(), f'Required shell missing: {shell}')
                version = subprocess.check_output([str(shell), '-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.Major'], timeout=15)
                self.assertEqual(int(version.strip()), 7 if shell.name.lower() == 'pwsh.exe' else 5)
                for command, code in [('version --json', 0), ('config validate --config missing.ini --json', 3)]:
                    script = "& '" + str(self.exe).replace("'", "''") + "' " + command + '; exit $LASTEXITCODE'
                    self.run_cli([str(shell), '-NoProfile', '-NonInteractive', '-Command', script], code)


if __name__ == '__main__':
    unittest.main()
