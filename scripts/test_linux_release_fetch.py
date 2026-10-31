"""Invalid lab artifacts must not overwrite an already qualified local candidate."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from test_linux_release import elf_fixture, deb_fixture


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.binary=self.root/'qeli-linux-amd64';self.package=self.root/'qeli_0.8.4_amd64.deb'
        self.binary.write_bytes(b'previous binary');self.package.write_bytes(b'previous package')
        spec=importlib.util.spec_from_file_location('qeli_fetch_fixture',Path(__file__).with_name('fetch_binary.py'))
        self.module=importlib.util.module_from_spec(spec)
        with patch.dict('sys.modules',{'lab_common':types.SimpleNamespace(LAB_SRV='fixture',connect=lambda _:None)}):
            spec.loader.exec_module(self.module)
        self.artifacts={'/binary':self.binary,'/package':self.package}

    def execute(self,binary,package,arch='amd64'):
        payloads={'/binary':binary,'/package':package}
        class Session:
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def stat(self,path):return types.SimpleNamespace(st_size=len(payloads[path]))
            def get(self,path,local):Path(local).write_bytes(payloads[path])
        class Client:
            def open_sftp(self):return Session()
            def close(self):pass
        with patch.object(self.module,'connect',return_value=Client()),patch.object(self.module,'artifact_paths',return_value=self.artifacts),contextlib.redirect_stdout(io.StringIO()):
            return self.module.main(['--arch',arch])

    def assert_preserved(self):
        self.assertEqual(self.binary.read_bytes(),b'previous binary')
        self.assertEqual(self.package.read_bytes(),b'previous package')

    def test_validated_matching_downloads_replace_both_files(self):
        binary=elf_fixture();package=deb_fixture(binary)
        self.assertEqual(self.execute(binary,package),0)
        self.assertEqual(self.binary.read_bytes(),binary);self.assertEqual(self.package.read_bytes(),package)

    def test_native_glibc_build_refused_before_any_destination_write(self):
        with self.assertRaises(ValueError):self.execute(elf_fixture('GLIBC_2.39'),deb_fixture(elf_fixture()))
        self.assert_preserved()

    def test_bad_second_download_does_not_replace_good_first_download(self):
        with self.assertRaises(ValueError):self.execute(elf_fixture(),b'corrupt package')
        self.assert_preserved()

    def test_mismatched_packaged_binary_preserves_previous_files(self):
        with self.assertRaisesRegex(ValueError,'different builds'):
            self.execute(elf_fixture(),deb_fixture(elf_fixture('GLIBC_2.17')))
        self.assert_preserved()

    def test_arm64_download_and_wrong_architecture_refusal(self):
        self.binary=self.root/'qeli-linux-arm64';self.package=self.root/'qeli_0.8.4_arm64.deb'
        self.artifacts={'/binary':self.binary,'/package':self.package}
        self.binary.write_bytes(b'previous binary');self.package.write_bytes(b'previous package')
        with self.assertRaises(ValueError):self.execute(elf_fixture(),deb_fixture(elf_fixture()),'arm64')
        self.assert_preserved()
        blob=elf_fixture(machine=183)
        self.assertEqual(self.execute(blob,deb_fixture(blob),'arm64'),0)
        self.assertEqual(self.binary.read_bytes(),blob)

    def test_arm64_remote_paths_do_not_point_at_x86_build(self):
        paths=self.module.artifact_paths('arm64')
        self.assertTrue(any('aarch64-unknown-linux-gnu' in remote for remote in paths))
        self.assertTrue(all('amd64' not in str(local) for local in paths.values()))


if __name__=='__main__':unittest.main()
