from pathlib import Path
import json
import tempfile
import unittest
import zipfile

from release_assets import expected_assets, verify, verify_cli_archive
from package_windows_cli import ARCHIVE_REQUIRED


class ReleaseAssetTests(unittest.TestCase):
    def cli(self, path, standalone=False, extra=()):
        with zipfile.ZipFile(path,'w') as archive:
            for name in (*ARCHIVE_REQUIRED, *extra):
                if name == 'bin/qeli-cli.runtimeconfig.json':
                    key = 'includedFrameworks' if standalone else 'framework'
                    value = {'name':'Microsoft.NETCore.App','version':'10.0.12'}
                    archive.writestr(name,json.dumps({'runtimeOptions':{key:[value] if standalone else value}}))
                else:
                    archive.writestr(name,b'fixture')

    def test_084_requires_both_linux_architectures_and_console_variants(self):
        names=expected_assets('0.8.4')
        self.assertEqual(len(names),21)
        for arch in ('amd64','arm64'):
            self.assertIn('qeli-linux-'+arch,names)
            self.assertIn('qeli_0.8.4_'+arch+'.deb',names)
        for variant in ('net-required','standalone'):
            self.assertIn('qeli-cli-windows-x64-'+variant+'.zip',names)
        self.assertNotIn('qeli-native-legal.zip',names)

    def test_version_is_not_a_path(self):
        for value in ('../0.8.4','0.8.4/','v0.8.4','latest','0.8.3'):
            with self.assertRaises(ValueError):expected_assets(value)

    def test_incomplete_directory_refused_before_binary_checks(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError,'missing='):verify(Path(root),'0.8.4')

    def test_cli_members_and_runtime_required(self):
        with tempfile.TemporaryDirectory() as root:
            archive=Path(root)/'console.zip'
            self.cli(archive)
            verify_cli_archive(archive,False)
            self.cli(archive,True)
            with self.assertRaisesRegex(ValueError,'runtime missing'):verify_cli_archive(archive,True)

    def test_cli_traversal_refused(self):
        with tempfile.TemporaryDirectory() as root:
            archive=Path(root)/'console.zip'
            self.cli(archive,extra=('../evil.dll',))
            with self.assertRaisesRegex(ValueError,'Unsafe'):verify_cli_archive(archive,False)


if __name__=='__main__':unittest.main()
