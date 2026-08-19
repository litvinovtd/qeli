#!/usr/bin/env python3

import os
import subprocess
import sys
import tempfile
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

    def test_installer_selects_and_verifies_the_host_deb_architecture(self):
        source = (Path(__file__).parent.parent / "install-qeli-server.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('HOST_DEB_ARCH="$(dpkg --print-architecture)"', source)
        self.assertIn('endswith("_" + $arch + ".deb")', source)
        self.assertIn('dpkg-deb -f "$TMP_DEB" Architecture', source)
        self.assertIn('"$HOST_DEB_ARCH"|all', source)

    def test_release_checksum_is_lf_only_and_installer_handles_crlf_defensively(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            asset_dir = Path(tmp)
            (asset_dir / "qeli.deb").write_bytes(b"release payload")
            subprocess.run(
                [sys.executable, str(root / "scripts/gen_checksums.py"), str(asset_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            sums = (asset_dir / "SHA256SUMS").read_bytes()
            self.assertIn(b"  qeli.deb\n", sums)
            self.assertNotIn(b"\r", sums)

        installer = (root / "install-qeli-server.sh").read_text(encoding="utf-8")
        self.assertIn('sub(/\\r$/, "", $2)', installer)
        self.assertEqual(installer.count("_checksum_for \"$"), 2)

        workflow = (root / ".github/workflows/release-attest.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("grep -q $'\\r' SHA256SUMS", workflow)

    def test_installer_strictly_validates_the_final_mutated_config_before_restart(self):
        source = (Path(__file__).parent.parent / "install-qeli-server.sh").read_text(
            encoding="utf-8"
        )
        validation = source.index('qeli check-config --config "$CONF"')
        restart = source.index("systemctl restart qeli")
        self.assertLess(validation, restart)
        self.assertIn("final configuration validation failed", source)

    def test_config_matrix_uses_strict_server_client_and_users_validation(self):
        source = (Path(__file__).parent / "config_functest.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('CFG.glob("server*.conf")', source)
        self.assertIn('CFG.glob("client*.conf")', source)
        self.assertIn("check-config --client", source)
        self.assertIn('users_remote = "/tmp/pv-users.conf"', source)
        self.assertNotIn("timeout 3", source)
        self.assertNotIn("pkill -9 -x qeli", source)
        self.assertIn("SERVER_PID", source)
        self.assertIn("client_active_units", source)
        self.assertIn("nohup setsid", source)
        self.assertIn(r'kill -TERM -- \"-$p\"', source)
        self.assertIn(r'kill -KILL -- \"-$p\"', source)
        self.assertIn(r'readlink -f \"/proc/$p/exe\"', source)
        self.assertIn(r'[ \"$pgid\" = \"$p\" ]', source)

        main_source = (Path(__file__).parent.parent / "qeli/src/main.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("server::load_users_db(&cfg).map_err", main_source)
        self.assertNotIn("valid empty first install", main_source)

        multiprofile = (Path(__file__).parent / "pool2_multiprofile.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("client_active_units", multiprofile)
        self.assertIn("nohup setsid", multiprofile)
        self.assertIn(r'kill -TERM -- \"-$p\"', multiprofile)
        self.assertIn(r'kill -KILL -- \"-$p\"', multiprofile)
        self.assertIn(r'readlink -f \"/proc/$p/exe\"', multiprofile)
        self.assertIn(r'[ \"$pgid\" = \"$p\" ]', multiprofile)

    def test_linux_matrix_uses_the_configured_management_route_end_to_end(self):
        source = (Path(__file__).parent / "e2e_linux_prod_matrix.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('MGMT_IP_ROUTE = "ip -6 route"', source)
        self.assertIn("f\"{MGMT_IP_ROUTE} show {shlex.quote(MGMT_ROUTE_PREFIX)}\"", source)
        self.assertIn("f\"{MGMT_IP_ROUTE} add {MGMT_ROUTE_COMMAND}\"", source)
        self.assertIn("f\"{MGMT_IP_ROUTE} del {MGMT_ROUTE_COMMAND}", source)

    def test_active_release_scenarios_are_checkout_and_tool_path_neutral(self):
        root = Path(__file__).resolve().parents[1]
        forbidden_checkout = "C:" + "\\Users\\" + "litvi"
        for recipe in (root / "scripts").glob("*.py"):
            source = recipe.read_text(encoding="utf-8")
            self.assertNotIn(forbidden_checkout, source, str(recipe.relative_to(root)))
        android = (root / "scripts/e2e_android_prod_lifecycle.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('os.environ.get("QELI_ADB"', android)
        self.assertIn("command -v {quoted}", android)
        self.assertNotIn('shutil.which("adb")', android)

    def test_installer_e2e_fails_closed_on_any_red_case(self):
        source = (Path(__file__).parent / "pool0b_installer_full.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('and A["panel"]', source)
        self.assertIn('and A["panel_bind"]', source)
        self.assertIn('and A["version"]', source)
        self.assertIn('if passed != len(results):', source)
        self.assertIn('raise RuntimeError("one or more installer scenarios failed")', source)
        self.assertIn("def dns_resolves", source)
        self.assertNotIn("| head -1 || echo FAIL", source)

    def test_android_native_recipe_requires_the_cancellable_probe_exports(self):
        source = (Path(__file__).parent / "build_android_so_11.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('jni.strip() != "19"', source)

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
            self.assertNotIn("C:" + "\\Users\\" + "litvi", source, name)

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
            "scripts/gen_reality_link.py",
            "scripts/gen_share_link.py",
            "scripts/gen-hash-rust.py",
            "scripts/implement-dpd-client.py",
            "scripts/implement-dpd-server.py",
            "scripts/install-argon2.py",
            "scripts/rebuild-and-test.py",
            "scripts/rebuild-both.py",
            "scripts/setup-client.py",
            "scripts/setup_reality_tls.py",
            "scripts/setup-multi-interface.py",
            "scripts/sync-config-and-rebuild.py",
            "scripts/update-client-binary.py",
            "scripts/update-server-dpd-config.py",
            "scripts/verify-dpd-file.py",
            "scripts/finish_deploy.py",
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
            [
                "git",
                "-c",
                f"safe.directory={root.as_posix()}",
                "ls-files",
                "scripts/*.py",
                "scripts/**/*.py",
            ],
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
