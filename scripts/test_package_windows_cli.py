import json
import re
from pathlib import Path
import tempfile
import unittest
import zipfile

from package_windows_cli import REQUIRED, ARCHIVE_REQUIRED, ROOT, package, verify_cli_archive


class CliPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'publication'
        self.source.mkdir()
        self.output = self.root / 'qeli-cli.zip'
        for name in REQUIRED:
            (self.source / name).write_bytes(b'fixture-original')
        self.runtime(False)

    def runtime(self, standalone):
        key = 'includedFrameworks' if standalone else 'frameworks'
        (self.source / 'qeli-cli.runtimeconfig.json').write_text(json.dumps({
            'runtimeOptions': {key: [{'name': 'Microsoft.NETCore.App', 'version': '10.0.12'}]}}))
        if standalone:
            for name in ('coreclr.dll', 'hostfxr.dll'):
                (self.source / name).write_bytes(b'runtime-original')

    def pack(self, variant='net-required', output=None):
        package(self.source, output or self.output, variant, '0.8.4', 1793447894)

    def test_complete_reproducible_publication_and_no_pdb(self):
        (self.source / 'private.pdb').write_bytes(b'debug paths')
        self.pack()
        second = self.root / 'second.zip'
        self.pack(output=second)
        self.assertEqual(self.output.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(set(archive.namelist()), set(ARCHIVE_REQUIRED))
            self.assertEqual(archive.read('bin/QeliWindowsRuntime.dll'), b'fixture-original')
            self.assertIn(b'ENTIRE archive', archive.read('README.md'))
            self.assertEqual({name for name in archive.namelist() if '/' not in name}, {'qeli-cli.cmd', 'README.md'})
            launcher = archive.read('qeli-cli.cmd')
            self.assertIn(b'"%~dp0bin\\qeli-cli.exe" %*\r\n', launcher)
            self.assertNotIn(b'\n', launcher.replace(b'\r\n', b''))
            self.assertIn(b'DisableDelayedExpansion', launcher)
            self.assertNotIn(b'cd ', launcher.lower())
            readme = archive.read('README.md').decode('utf8')
            self.assertIn('0.8.4 (net-required', readme)
            self.assertIn('service install', readme)
            self.assertIn('licenses --export', readme)
            self.assertNotIn('@VERSION@', readme)
            self.assertIn(b'WINDOWS-CLI.en.md', archive.read('docs/WINDOWS-CLI.ru.md'))
            self.assertIn(b'WINDOWS-CLI.ru.md', archive.read('docs/WINDOWS-CLI.en.md'))
            self.assertIn(b'REPLACE_WITH_YOUR_PASSWORD', archive.read('examples/client.ini.example'))

    def test_manual_examples_match_the_packaged_tree(self):
        for lang in ('ru', 'eng'):
            text = (ROOT / f'docs/{lang}/manuals/WINDOWS-CLI.md').read_text(encoding='utf8')
            self.assertIn('bin\\qeli-cli.exe', text)
            self.assertIn('qeli-cli.cmd', text)
            for kind, body in re.findall(r'```(cmd|bat|powershell)\n(.*?)```', text, re.S):
                self.assertNotRegex(body, r'(?m)^\s*(?:&\s+\.\\)?qeli-cli\.exe\b')
                if kind == 'bat':
                    self.assertNotRegex(body, r'(?m)^qeli-cli\.cmd\b')
                    self.assertIn('call qeli-cli.cmd', body)

    def test_standalone_contains_runtime(self):
        self.runtime(True)
        self.pack('standalone')
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.read('bin/coreclr.dll'), b'runtime-original')
            self.assertIn(b'Includes the .NET runtime', archive.read('README.md'))

    def test_nested_runtime_bytes_and_paths_preserved(self):
        nested = self.source / 'runtimes/win-x64/native/component.dll'
        nested.parent.mkdir(parents=True)
        nested.write_bytes(b'nested-runtime')
        self.pack()
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.read('bin/runtimes/win-x64/native/component.dll'), b'nested-runtime')

    def test_flat_package_and_extra_root_dll_are_refused(self):
        with zipfile.ZipFile(self.output, 'w') as archive:
            for name in REQUIRED:
                archive.writestr(name, b'flat')
        with self.assertRaisesRegex(ValueError, 'missing'):
            verify_cli_archive(self.output, False)
        self.output.unlink()
        self.pack()
        with zipfile.ZipFile(self.output, 'a') as archive:
            archive.writestr('unexpected.dll', b'not-in-bin')
        with self.assertRaisesRegex(ValueError, 'root'):
            verify_cli_archive(self.output, False)

    def test_windows_case_collision_is_refused(self):
        self.pack()
        with zipfile.ZipFile(self.output, 'a') as archive:
            archive.writestr('bin/QELI-CLI.DLL', b'duplicate-case')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            verify_cli_archive(self.output, False)

    def test_missing_assembly_refused(self):
        (self.source / 'QeliWindowsRuntime.dll').unlink()
        with self.assertRaises(ValueError): self.pack()
        self.assertFalse(self.output.exists())

    def test_missing_standalone_runtime_refused(self):
        self.runtime(True)
        (self.source / 'hostfxr.dll').unlink()
        with self.assertRaises(ValueError): self.pack('standalone')

    def test_variant_mismatch_refused(self):
        with self.assertRaises(ValueError): self.pack('standalone')

    def test_no_desktop_dependency(self):
        config = {'runtimeOptions': {'framework': {'name': 'Microsoft.WindowsDesktop.App'}}}
        (self.source / 'qeli-cli.runtimeconfig.json').write_text(json.dumps(config))
        with self.assertRaises(ValueError): self.pack()

    def test_existing_output_preserved(self):
        self.output.write_bytes(b'keep')
        with self.assertRaises(ValueError): self.pack()
        self.assertEqual(self.output.read_bytes(), b'keep')

    def test_secrets_and_in_tree_output_refused(self):
        with self.assertRaises(ValueError): self.pack(output=self.source / 'nested.zip')
        (self.source / 'client.ini').write_text('pass=canary')
        with self.assertRaises(ValueError): self.pack()


if __name__ == '__main__':
    unittest.main()
