#!/usr/bin/env python3

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import native_lab
import native_repro


class FakeSftp:
    def __init__(self, files=None):
        self.files = files or {}
        self.puts = []

    def open(self, path, _mode):
        return io.BytesIO(self.files[path])

    def put(self, local, remote):
        self.puts.append((Path(local).name, remote))


class FakeConnection:
    def __init__(self, output=""):
        self.commands = []
        self.output = output

    def checked(self, command, label, timeout=2400):
        self.commands.append((command, label, timeout))
        return self.output


class NativeLabTests(unittest.TestCase):
    def test_pull_verifies_before_replacing_all_copies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = b"native-core"
            sftp = FakeSftp({"/remote/core": data})
            size, digest, changes = native_lab.pull_verified_artifact(
                sftp,
                "/remote/core",
                native_repro.sha256_bytes(data),
                root,
                ("canonical/core", "consumer/core"),
            )
            self.assertEqual(size, len(data))
            self.assertEqual(digest, native_repro.sha256_bytes(data))
            self.assertEqual(changes, [("canonical/core", True), ("consumer/core", True)])
            self.assertEqual((root / "canonical/core").read_bytes(), data)
            self.assertEqual((root / "consumer/core").read_bytes(), data)

    def test_pull_hash_mismatch_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "changed after verification"):
                native_lab.pull_verified_artifact(
                    FakeSftp({"/remote/core": b"wrong"}),
                    "/remote/core",
                    "0" * 64,
                    root,
                    ("canonical/core",),
                )
            self.assertFalse((root / "canonical/core").exists())

    def test_pull_skips_transfer_when_every_local_copy_already_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = b"already-present-native-core"
            for relative in ("canonical/core", "consumer/core"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            size, digest, changes = native_lab.pull_verified_artifact(
                FakeSftp(),
                "/remote/core",
                native_repro.sha256_bytes(data),
                root,
                ("canonical/core", "consumer/core"),
            )
            self.assertEqual(size, len(data))
            self.assertEqual(digest, native_repro.sha256_bytes(data))
            self.assertEqual(
                changes, [("canonical/core", False), ("consumer/core", False)]
            )

    def test_pull_rejects_destination_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = b"native-core"
            with self.assertRaisesRegex(ValueError, "escapes repository"):
                native_lab.pull_verified_artifact(
                    FakeSftp({"/remote/core": data}),
                    "/remote/core",
                    native_repro.sha256_bytes(data),
                    temporary,
                    ("../outside",),
                )

    def test_source_sync_is_deterministic_and_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src" / "nested").mkdir(parents=True)
            (root / "src" / "z.rs").write_text("z")
            (root / "src" / "a.rs").write_text("a")
            (root / "src" / "nested" / "b.rs").write_text("b")
            (root / "src" / "asset.css").write_text("asset")
            (root / "Cargo.toml").write_text("manifest")
            (root / "Cargo.lock").write_text("lock")
            connection = FakeConnection()
            sftp = FakeSftp()
            count = native_lab.sync_qeli_source(
                connection, sftp, root, "/opt/qeli-src"
            )
            self.assertEqual(count, 4)
            self.assertIn("rm -rf /opt/qeli-src/src", connection.commands[0][0])
            self.assertEqual(
                [remote for _local, remote in sftp.puts],
                [
                    "/opt/qeli-src/src/a.rs",
                    "/opt/qeli-src/src/asset.css",
                    "/opt/qeli-src/src/z.rs",
                    "/opt/qeli-src/src/nested/b.rs",
                    "/opt/qeli-src/Cargo.toml",
                    "/opt/qeli-src/Cargo.lock",
                ],
            )

    def test_source_sync_rejects_broad_remote_root(self):
        with self.assertRaisesRegex(ValueError, "unsafe remote source root"):
            native_lab.sync_qeli_source(FakeConnection(), FakeSftp(), ".", "/")

    def test_cargo_package_version_comes_from_installed_inventory(self):
        connection = FakeConnection("cargo-zigbuild v0.20.1:")
        self.assertEqual(
            native_lab.installed_cargo_package(connection, "cargo-zigbuild"),
            "cargo-zigbuild v0.20.1:",
        )
        self.assertIn("cargo install --list", connection.commands[0][0])
        self.assertEqual(
            native_lab.cargo_package_version(
                "cargo-zigbuild v0.20.1:", "cargo-zigbuild"
            ),
            "0.20.1",
        )

    def test_cargo_package_version_rejects_ambiguous_inventory(self):
        with self.assertRaisesRegex(RuntimeError, "invalid cargo-ndk inventory"):
            native_lab.cargo_package_version("cargo-ndk latest", "cargo-ndk")

    def test_rust_target_preflight_is_idempotent_when_installed(self):
        connection = FakeConnection("x86_64-pc-windows-gnu\n")
        result = native_lab.ensure_rust_targets(
            connection, "1.97.0", ("x86_64-pc-windows-gnu",)
        )
        self.assertEqual(result, "x86_64-pc-windows-gnu")
        self.assertEqual(len(connection.commands), 1)

    def test_repro_cleanup_is_scoped_to_exact_tmp_roots(self):
        connection = FakeConnection("disk")
        self.assertEqual(native_lab.reset_repro_group(connection, "desktop"), "disk")
        command = connection.commands[0][0]
        self.assertIn("/tmp/qeli-native-repro/desktop-a", command)
        self.assertIn("/tmp/qeli-native-repro/desktop-b", command)
        self.assertNotIn("/opt/qeli-src/target", command)

    def test_repro_cleanup_rejects_path_syntax(self):
        with self.assertRaisesRegex(ValueError, "invalid reproducibility group"):
            native_lab.reset_repro_group(FakeConnection(), "../desktop")


if __name__ == "__main__":
    unittest.main()
