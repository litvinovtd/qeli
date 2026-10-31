import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from package_windows_cli import REQUIRED, package


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
            self.assertEqual(set(archive.namelist()), set(REQUIRED) | {'README.txt'})
            self.assertEqual(archive.read('QeliWindowsRuntime.dll'), b'fixture-original')
            self.assertIn(b'ENTIRE archive', archive.read('README.txt'))

    def test_standalone_contains_runtime(self):
        self.runtime(True)
        self.pack('standalone')
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.read('coreclr.dll'), b'runtime-original')

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
