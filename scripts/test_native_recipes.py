#!/usr/bin/env python3

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build_native_libs_p4 as desktop
import build_mac_universal as macpack


class NativeRecipeTests(unittest.TestCase):
    def test_macos_install_name_does_not_contain_build_pass_path(self):
        flags = desktop.macos_rust_flags()
        self.assertIn("-install_name,@rpath/libqeli.dylib", flags)
        self.assertNotIn("-no_uuid", flags)
        self.assertNotIn("desktop-a", flags)
        self.assertNotIn("desktop-b", flags)

    def test_independent_artifacts_still_have_distinct_storage(self):
        first = desktop.artifact_path("a", desktop.MAC_TARGET, "libqeli.dylib")
        second = desktop.artifact_path("b", desktop.MAC_TARGET, "libqeli.dylib")
        self.assertNotEqual(first, second)

    def test_rcodesign_textual_error_is_not_accepted_with_zero_exit(self):
        class FakeClient:
            def checked(self, _command, _label):
                return "normalized"

            def run(self, _command):
                return "Error: invalid signature", 0

        with self.assertRaisesRegex(RuntimeError, "rcodesign sign failed"):
            desktop.normalize_and_sign_macos(FakeClient(), "/tmp/libqeli.dylib", "a")

    def test_apk_rebuild_uses_strict_shared_lab_connection(self):
        source = (Path(__file__).parent / "rebuild_apk.py").read_text(encoding="utf-8")
        self.assertIn("from native_lab import connect_lab", source)
        self.assertIn("apksigner} verify", source)
        self.assertIn("pull_verified_artifact", source)
        self.assertIn("shutil.copy2(cur, prev)", source)
        self.assertNotIn("os.replace(cur, prev)", source)
        self.assertNotIn("AutoAddPolicy", source)

    def test_macos_packaging_uses_checked_shared_lab_connection(self):
        source = (Path(__file__).parent / "build_mac_universal.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("from native_lab import connect_lab", source)
        self.assertIn("print-signature-info", source)
        self.assertIn("pull_verified_artifact", source)
        self.assertNotIn("AutoAddPolicy", source)

    def test_macos_packaging_batches_signing_and_accepts_adhoc_runtime_flag(self):
        self.assertIn("print-signature-info", macpack.REMOTE_SIGN_PY)
        self.assertIn('"CodeSignatureFlags(ADHOC"', macpack.REMOTE_SIGN_PY)
        source = Path(macpack.__file__).read_text(encoding="utf-8")
        self.assertIn("python3 sign_app.py", source)
        self.assertIn("remote_sha256(c, cached) != expected", source)

    def test_android_e2e_uses_current_abi_strict_ssh_and_exact_restore(self):
        source = (Path(__file__).parent / "e2e_final.py").read_text(encoding="utf-8")
        self.assertIn("from lab_common import LAB_CLI, LAB_SRV, connect", source)
        self.assertIn("Shared native transport active: ABI 0x10009", source)
        self.assertIn("original_server_bytes", source)
        self.assertNotIn("AutoAddPolicy", source)


if __name__ == "__main__":
    unittest.main()
