from pathlib import Path
import tempfile
import unittest
import zipfile

from release_assets import REQUIRED, expected_assets, verify, verify_cli_archive


class ReleaseAssetTests(unittest.TestCase):
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
            with zipfile.ZipFile(archive,'w') as out:
                for name in (*REQUIRED,'README.txt'):out.writestr(name,b'fixture')
            verify_cli_archive(archive,False)
            with self.assertRaisesRegex(ValueError,'runtime missing'):verify_cli_archive(archive,True)

    def test_cli_traversal_refused(self):
        with tempfile.TemporaryDirectory() as root:
            archive=Path(root)/'console.zip'
            with zipfile.ZipFile(archive,'w') as out:
                for name in (*REQUIRED,'README.txt','../evil.dll'):out.writestr(name,b'fixture')
            with self.assertRaisesRegex(ValueError,'Unsafe'):verify_cli_archive(archive,False)


if __name__=='__main__':unittest.main()
