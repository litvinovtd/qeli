"""Exercise checksum publication and retained-manifest behavior using real files."""
from pathlib import Path
import contextlib
import hashlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import gen_checksums as checksums
from test_linux_release import deb_fixture, elf_fixture


class ChecksumTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "SHA256SUMS"
    def run_cli(self):
        return subprocess.run([sys.executable, "-B", checksums.__file__, str(self.root)], capture_output=True)
    def preserved(self):
        self.assertEqual(self.output.read_bytes(), b"old manifest\n")
        self.assertEqual(list(self.root.glob(".qeli-checksums-*")), [])
    def test_real_cli_sorted_lf_exact_hashes_and_nested_directory(self):
        package=deb_fixture(elf_fixture())
        (self.root / "qeli_0.8.2_amd64.deb").write_bytes(package)
        (self.root / "QeliWin-0.8.2+win.zip").write_bytes(b"desktop")
        (self.root / "nested").mkdir(); (self.root / "nested/ignore").write_bytes(b"nested")
        self.output.write_bytes(b"old manifest\n")
        proc = self.run_cli(); self.assertEqual(proc.returncode, 0, proc.stderr)
        expected = b"".join(hashlib.sha256(data).hexdigest().encode()+b"  "+name.encode()+b"\n" for name,data in [("QeliWin-0.8.2+win.zip",b"desktop"),("qeli_0.8.2_amd64.deb",package)])
        self.assertEqual(self.output.read_bytes(), expected)
    def test_real_cli_invalid_space_name_preserves_previous_manifest(self):
        self.output.write_bytes(b"old manifest\n"); (self.root / "bad asset.deb").write_bytes(b"package")
        proc = self.run_cli(); self.assertEqual(proc.returncode, 1); self.preserved()
    def test_bad_linux_binary_or_package_never_gets_release_checksums(self):
        for name in ['qeli-linux-amd64','qeli_0.8.4_amd64.deb','qeli-linux-arm64','qeli_0.8.4_arm64.deb']:
            with self.subTest(name=name):
                path=self.root/name;path.write_bytes(b'incompatible artifact')
                self.output.write_bytes(b'old manifest\n')
                self.assertEqual(self.run_cli().returncode,1);self.preserved();path.unlink()
    def test_two_architecture_release_gets_checksums(self):
        for arch,machine in [('amd64',62),('arm64',183)]:
            blob=elf_fixture(machine=machine)
            (self.root/('qeli-linux-'+arch)).write_bytes(blob)
            (self.root/f'qeli_0.8.4_{arch}.deb').write_bytes(deb_fixture(blob))
        self.assertEqual(self.run_cli().returncode,0)
        self.assertEqual(len(self.output.read_text().splitlines()),4)
    def test_checksum_delimiters_and_control_names_are_not_admitted(self):
        for name in ["bad asset.deb", "bad\nasset", "bad\rasset", "bad\tasset", "bad\\asset", "*asset", ".hidden", "asset\x7f", "asset\u00a0zip", "не-asset"]:
            with self.subTest(name=name):self.assertIsNone(checksums.ASSET_NAME.fullmatch(name))
    def test_empty_inputs_preserve_manifest(self):
        self.output.write_bytes(b"old manifest\n")
        self.assertEqual(self.run_cli().returncode, 1); self.preserved()
    def test_missing_directory_returns_two(self):
        with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(checksums.main([str(self.root/'missing')]), 2)
    def test_hash_io_failure_preserves_previous_manifest(self):
        self.output.write_bytes(b"old manifest\n"); (self.root / "qeli.deb").write_bytes(b"package")
        with patch.object(checksums, "sha256", side_effect=OSError("unreadable asset")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(checksums.main([str(self.root)]), 1)
        self.preserved()
    def test_atomic_replace_failure_preserves_manifest_and_removes_temp(self):
        self.output.write_bytes(b"old manifest\n"); (self.root / "qeli.deb").write_bytes(b"package")
        with patch.object(checksums.os, "replace", side_effect=OSError("publication denied")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(checksums.main([str(self.root)]), 1)
        self.preserved()
    @unittest.skipUnless(os.name == "posix", "POSIX file names and symlinks qualified on Linux")
    def test_actual_linux_newline_name_preserves_manifest(self):
        self.output.write_bytes(b"old manifest\n"); (self.root / "bad\nasset").write_bytes(b"package")
        self.assertEqual(self.run_cli().returncode, 1); self.preserved()
    @unittest.skipUnless(os.name == "posix", "POSIX symlinks qualified on Linux")
    def test_actual_asset_symlink_refused(self):
        outside = self.root / "nested"; outside.mkdir(); (outside/"asset").write_bytes(b"package")
        (self.root/"qeli.deb").symlink_to(outside/"asset")
        self.output.write_bytes(b"old manifest\n")
        self.assertEqual(self.run_cli().returncode, 1); self.preserved()
    @unittest.skipUnless(os.name == "posix", "POSIX symlinks qualified on Linux")
    def test_actual_output_symlink_keeps_external_target(self):
        (self.root/"qeli.deb").write_bytes(b"package"); outside = self.root/"nested"; outside.mkdir()
        target=outside/"manifest"; target.write_bytes(b"old manifest\n"); self.output.symlink_to(target)
        self.assertEqual(self.run_cli().returncode, 1); self.assertTrue(self.output.is_symlink()); self.preserved()
    @unittest.skipUnless(os.name == "posix", "POSIX special file qualified on Linux")
    def test_fifo_refused_without_blocking(self):
        os.mkfifo(self.root/"qeli.deb"); self.output.write_bytes(b"old manifest\n")
        proc=subprocess.run([sys.executable,"-B",checksums.__file__,str(self.root)],capture_output=True,timeout=5)
        self.assertEqual(proc.returncode,1);self.preserved()


if __name__ == "__main__":unittest.main()
