#!/usr/bin/env python3

import os
import subprocess
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
        self.assertIn("Shared native transport active: ABI 0x1000a", source)
        self.assertIn("original_server_bytes", source)
        self.assertNotIn("AutoAddPolicy", source)

    def test_installer_rejects_ipv6_until_all_clients_support_it(self):
        source = (Path(__file__).parent.parent / "install-qeli-server.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("clients support IPv4 server endpoints only", source)

    def test_lab_gate_syncs_integration_tests_and_their_release_fixture(self):
        source = (Path(__file__).parent / "lab_sync_build.py").read_text(encoding="utf-8")
        self.assertIn('"tests"', source)
        self.assertIn('"release", "reality-tls", "server-reality.conf"', source)
        self.assertIn('"/opt/release/reality-tls/server-reality.conf"', source)

    def test_native_client_recipes_do_not_enable_the_server_stack(self):
        recipes = [
            Path(desktop.__file__),
            Path(__file__).parent / "build_android_so_11.py",
            Path(__file__).parent / "build_so_aes.py",
            Path(__file__).parent.parent / "qeli-mac" / "build_dylib.sh",
        ]
        for recipe in recipes:
            source = recipe.read_text(encoding="utf-8")
            self.assertIn(
                "--no-default-features",
                source,
                f"{recipe.name} must build only the shared client transport",
            )

    def test_keenetic_recipes_resolve_the_current_checkout(self):
        for name in ("build_keenetic.py", "keenetic_verify.py"):
            source = (Path(__file__).parent / name).read_text(encoding="utf-8")
            self.assertIn("Path(__file__).resolve().parents[1]", source, name)
            self.assertNotIn(r"C:\Users\litvi", source, name)

    def test_retired_root_ssh_scenarios_exit_before_network_or_mutation(self):
        root = Path(__file__).parent.parent
        retired = [
            "scripts/add-dpd-config.py",
            "scripts/add-hash-command.py",
            "scripts/add-hash-command-v2.py",
            "scripts/capture-handshake.py",
            "scripts/create-multi-interface-config.py",
            "scripts/create-multi-interface-server.py",
            "scripts/deploy-and-build.py",
            "scripts/deploy-and-build-final.py",
            "scripts/deploy_audit_fixes.py",
            "scripts/deploy_prod_0712.py",
            "scripts/deploy_prod_073.py",
            "scripts/deploy_prod_dev0711.py",
            "scripts/deploy_to_server.py",
            "scripts/generate-hash.py",
            "scripts/generate-hash-v2.py",
            "scripts/gen-hash-rust.py",
            "scripts/implement-dpd-client.py",
            "scripts/implement-dpd-server.py",
            "scripts/install-argon2.py",
            "scripts/rebuild-and-test.py",
            "scripts/rebuild-both.py",
            "scripts/setup-client.py",
            "scripts/setup-multi-interface.py",
            "scripts/sync-config-and-rebuild.py",
            "scripts/update-client-binary.py",
            "scripts/update-server-dpd-config.py",
            "scripts/verify-dpd-file.py",
        ]
        retired += [
            str(path.relative_to(root)).replace("\\", "/")
            for path in (root / "test").iterdir()
            if path.suffix == ".py"
        ]
        for relative in retired:
            source = (root / relative).read_text(encoding="utf-8")
            guard = source.find("raise SystemExit")
            dangerous = min(
                (pos for marker in ("paramiko", "ssh.connect", "exec_command", "subprocess")
                 if (pos := source.find(marker)) >= 0),
                default=len(source),
            )
            self.assertGreaterEqual(guard, 0, f"{relative} has no retirement guard")
            self.assertLess(guard, dangerous, f"{relative} can act before its retirement guard")

        for path in (root / "test").glob("*.sh"):
            source = path.read_text(encoding="utf-8")
            self.assertIn("RETIRED:", source, path.name)
            dangerous = min(
                (pos for marker in ("ssh ", "scp ", "systemctl")
                 if (pos := source.find(marker)) >= 0),
                default=len(source),
            )
            self.assertLess(source.find("exit 1"), dangerous, path.name)

    def test_tracked_python_scenarios_never_silently_trust_a_new_ssh_host(self):
        root = Path(__file__).resolve().parents[1]
        tracked = subprocess.run(
            ["git", "ls-files", "scripts/*.py", "scripts/**/*.py"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        for relative in tracked:
            path = root / relative
            if path.resolve() == Path(__file__).resolve():
                continue  # assertions below name the forbidden policy but never execute SSH
            if path.name == "ssh_hostkey.py":
                continue  # the one explicit QELI_LAB_TRUST_NEW_HOST opt-in lives here
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("AutoAddPolicy", source, str(path))


if __name__ == "__main__":
    unittest.main()
