"""Actual POSIX build-time archive verifier; no SDK/compiler required."""
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
SHELL=shlex.split(os.environ.get("QELI_ROUTER_TEST_SHELL","sh"))


@unittest.skipUnless(os.name=="posix", "requires POSIX shell")
class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="qeli-sdk-archive-")
        self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.archive=self.root/"source.tar.zst";self.archive.write_bytes(b"archive fixture\x00\r\n\x80")
        self.digest=hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.tool=self.root/"mkhash"
        self.tool.write_text("#!"+sys.executable+"\nimport hashlib,sys\nfrom pathlib import Path\n"
                             "Path(__file__).with_suffix('.called').touch()\n"
                             "print(hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest())\n")
        self.tool.chmod(0o700)

    def run_guard(self, archive=None, digest=None, mode="", tool=None):
        return subprocess.run(SHELL+[str(ROOT/"qeli-openwrt/verify-source.sh"),
            str(self.archive if archive is None else archive),self.digest if digest is None else digest,
            str(self.tool if tool is None else tool),mode],capture_output=True,text=True,timeout=10)

    def test_correct_hash_and_binary_CR_bytes_pass(self):
        self.assertEqual(self.run_guard().returncode,0)

    def test_wrong_or_invalid_hash_refuses(self):
        for digest in ("0"*64,"skip","",self.digest.upper(),"a"*63,"$(echo)"):
            with self.subTest(digest=digest):self.assertNotEqual(self.run_guard(digest=digest).returncode,0)

    def test_missing_empty_directory_and_fifo_refuse_before_hash(self):
        self.assertNotEqual(self.run_guard(archive=self.root/"absent").returncode,0)
        self.assertNotEqual(self.run_guard(archive=self.root).returncode,0)
        self.archive.write_bytes(b"");self.assertNotEqual(self.run_guard().returncode,0)
        fifo=self.root/"fifo";os.mkfifo(fifo)
        self.assertNotEqual(self.run_guard(archive=fifo).returncode,0)
        self.assertFalse(self.tool.with_suffix('.called').exists())

    def test_link_archive_refuses(self):
        link=self.root/"link";link.symlink_to(self.archive)
        self.assertNotEqual(self.run_guard(archive=link).returncode,0)
        self.assertFalse(self.tool.with_suffix('.called').exists())

    def test_matching_hash_with_failed_command_still_refuses(self):
        self.tool.write_text('#!/bin/sh\nprintf "%s\\n" '+shlex.quote(self.digest)+'\nexit 19\n')
        self.assertNotEqual(self.run_guard().returncode,0)

    def test_missing_hash_executable_refuses(self):
        self.assertNotEqual(self.run_guard(tool=self.root/"missing-tool").returncode,0)

    def test_explicit_sdk_developer_overlay_skips_mirror_only(self):
        self.assertEqual(self.run_guard(archive=self.root/"absent",digest="skip",mode="local source").returncode,0)
        self.assertFalse(self.tool.with_suffix('.called').exists())

    def test_literal_metacharacter_paths_do_not_execute(self):
        other=self.root/"archive [x] $(touch FOREIGN)";other.write_bytes(self.archive.read_bytes())
        before=set(self.root.iterdir());self.assertEqual(self.run_guard(archive=other).returncode,0)
        self.assertFalse((self.root/"FOREIGN").exists())
        self.assertEqual(set(self.root.iterdir())-before,{self.tool.with_suffix('.called')})

    def test_hash_check_preserves_source_bytes(self):
        before=self.archive.read_bytes();self.assertEqual(self.run_guard().returncode,0)
        self.assertEqual(self.archive.read_bytes(),before)


if __name__=="__main__":unittest.main()
