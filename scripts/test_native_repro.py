#!/usr/bin/env python3

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import native_repro


class NativeReproTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "qeli" / "src").mkdir(parents=True)
        (self.root / "qeli" / "src" / "lib.rs").write_text("pub fn qeli() {}\n")
        (self.root / "qeli" / "Cargo.toml").write_text("[package]\nname='qeli'\n")
        (self.root / "qeli" / "Cargo.lock").write_text("version = 4\n")
        for paths in native_repro.EVIDENCE_SPECS.values():
            for relative in paths:
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
                consumed = self.root / native_repro.CONSUMED_COPIES[relative]
                consumed.parent.mkdir(parents=True, exist_ok=True)
                consumed.write_bytes(relative.encode())
        self.identity = {
            "source_digest": native_repro.source_digest(self.root),
            "source_commit": "1" * 40,
            "source_dirty": False,
            "source_date_epoch": 1_700_000_000,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def hashes(self, group):
        return {
            relative: (
                native_repro.sha256_file(self.root / relative),
                native_repro.sha256_file(self.root / relative),
            )
            for relative in native_repro.EVIDENCE_SPECS[group]
        }

    @staticmethod
    def toolchain(group):
        common = {
            "rust_toolchain": native_repro.DEFAULT_RUST_TOOLCHAIN,
            "rustc": "rustc 1.97.0 (fixture)",
            "cargo": "cargo 1.97.0 (fixture)",
        }
        if group == "desktop":
            return {
                **common,
                "zig": native_repro.DEFAULT_ZIG_VERSION,
                "cargo_zigbuild": "cargo-zigbuild 0.20.1",
                "mingw_linker": "GNU ld fixture",
            }
        return {
            **common,
            "android_ndk": native_repro.DEFAULT_ANDROID_NDK,
            "cargo_ndk_version": native_repro.DEFAULT_CARGO_NDK_VERSION,
            "cargo_ndk": "cargo-ndk 4.1.2",
        }

    def write_all(self):
        for group in native_repro.EVIDENCE_SPECS:
            native_repro.write_evidence(
                self.root,
                group,
                self.identity,
                self.toolchain(group),
                self.hashes(group),
            )

    def test_complete_evidence_validates(self):
        self.write_all()
        self.assertEqual(
            native_repro.validate_evidence(self.root, self.identity["source_digest"]), []
        )

    def test_tampered_final_artifact_is_rejected(self):
        self.write_all()
        target = self.root / native_repro.EVIDENCE_SPECS["desktop"][0]
        target.write_bytes(b"tampered")
        errors = native_repro.validate_evidence(self.root, self.identity["source_digest"])
        self.assertTrue(any("evidence does not match" in error for error in errors))

    def test_tampered_consumed_copy_is_rejected(self):
        self.write_all()
        canonical = native_repro.EVIDENCE_SPECS["android"][0]
        target = self.root / native_repro.CONSUMED_COPIES[canonical]
        target.write_bytes(b"tampered")
        errors = native_repro.validate_evidence(self.root, self.identity["source_digest"])
        self.assertTrue(any("consumed artifact differs" in error for error in errors))

    def test_mismatched_independent_builds_cannot_be_recorded(self):
        hashes = self.hashes("desktop")
        relative = native_repro.EVIDENCE_SPECS["desktop"][0]
        hashes[relative] = ("0" * 64, "1" * 64)
        with self.assertRaisesRegex(RuntimeError, "independent build hashes differ"):
            native_repro.write_evidence(
                self.root,
                "desktop",
                self.identity,
                self.toolchain("desktop"),
                hashes,
            )

    def test_unpinned_toolchain_cannot_be_recorded(self):
        toolchain = self.toolchain("desktop")
        toolchain["zig"] = "0.14.0"
        with self.assertRaisesRegex(RuntimeError, "Zig is not pinned"):
            native_repro.write_evidence(
                self.root,
                "desktop",
                self.identity,
                toolchain,
                self.hashes("desktop"),
            )

    def test_wrong_source_digest_is_rejected(self):
        self.write_all()
        errors = native_repro.validate_evidence(self.root, "f" * 64)
        self.assertTrue(any("source digest" in error for error in errors))

    def test_atomic_binary_replace(self):
        target = self.root / "artifact.bin"
        target.write_bytes(b"old")
        native_repro.atomic_write_bytes(target, b"new")
        self.assertEqual(target.read_bytes(), b"new")

    def test_non_object_evidence_is_rejected_cleanly(self):
        self.write_all()
        evidence = self.root / "native-libs" / "reproducibility" / "desktop.json"
        evidence.write_text("[]\n")
        errors = native_repro.validate_evidence(
            self.root, self.identity["source_digest"]
        )
        self.assertTrue(any("root must be an object" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
