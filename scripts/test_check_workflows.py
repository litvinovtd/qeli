"""Failure admission tests; real Actions semantics are checked by the CI gate."""
import contextlib
import hashlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import check_workflows as gate


class WorkflowGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / ".github/workflows"
        self.directory.mkdir(parents=True)
        (self.directory / "first.yml").write_text("name: First", encoding="utf8")
        self.payload = b"fixture executable; never executed"
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("actionlint.exe", self.payload)
        self.archive = stream.getvalue()
        self.pin = {"archive": "fixture.zip", "archive_sha256": hashlib.sha256(self.archive).hexdigest(),
                    "binary": "actionlint.exe", "binary_sha256": hashlib.sha256(self.payload).hexdigest()}

    def invoke(self, *args):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return gate.main(["--root", str(self.root), *args])

    def test_new_yaml_and_yml_are_included(self):
        (self.directory / "new.yaml").write_text("name: Added", encoding="utf8")
        self.assertEqual([p.name for p in gate.workflows(self.root)], ["first.yml", "new.yaml"])

    def test_missing_or_empty_inventory_refuses_before_network(self):
        (self.directory / "first.yml").unlink()
        with patch.object(gate.urllib.request, "urlopen") as download:
            self.assertEqual(self.invoke("--install-dir", str(self.root / "tool")), 1)
            self.directory.rmdir()
            self.assertEqual(self.invoke("--install-dir", str(self.root / "tool")), 1)
            download.assert_not_called()

    def test_workflow_directory_named_yaml_is_rejected(self):
        (self.directory / "fake.yaml").mkdir()
        with self.assertRaises(ValueError):
            gate.workflows(self.root)

    def test_unsupported_platform_is_rejected(self):
        with patch.object(gate.platform, "system", return_value="Unknown"):
            with self.assertRaises(ValueError):
                gate.selected_pin()

    def test_valid_archive_installs_and_reuses_without_network(self):
        destination = self.root / "tools with spaces"
        with patch.object(gate.urllib.request, "urlopen", return_value=io.BytesIO(self.archive)) as download:
            tool = gate.install(destination, self.pin)
            self.assertEqual(tool.read_bytes(), self.payload)
            self.assertEqual(gate.install(destination, self.pin), tool)
            download.assert_called_once()

    def test_corrupt_archive_is_rejected_before_parsing(self):
        with patch.object(gate.urllib.request, "urlopen", return_value=io.BytesIO(b"corrupt")), \
                patch.object(gate.zipfile, "ZipFile") as parse:
            with self.assertRaisesRegex(ValueError, "archive"):
                gate.install(self.root / "tool", self.pin)
            parse.assert_not_called()
            self.assertFalse((self.root / "tool/actionlint.exe").exists())

    def test_wrong_extracted_binary_is_rejected(self):
        pin = dict(self.pin, binary_sha256="0" * 64)
        with patch.object(gate.urllib.request, "urlopen", return_value=io.BytesIO(self.archive)):
            with self.assertRaisesRegex(ValueError, "extracted binary"):
                gate.install(self.root / "tool", pin)
            self.assertEqual(list((self.root / "tool").iterdir()), [])

    def test_unknown_cached_binary_is_not_overwritten_or_executed(self):
        tool = self.root / "actionlint.exe"
        tool.write_bytes(b"different release")
        with patch.object(gate, "selected_pin", return_value=self.pin), \
                patch.object(gate.urllib.request, "urlopen") as download, \
                patch.object(gate.subprocess, "run") as run:
            self.assertEqual(self.invoke("--install-dir", str(self.root)), 1)
            download.assert_not_called()
            run.assert_not_called()
            self.assertEqual(tool.read_bytes(), b"different release")

    def test_failed_atomic_install_removes_temporary_file(self):
        with patch.object(gate.urllib.request, "urlopen", return_value=io.BytesIO(self.archive)), \
                patch.object(gate.os, "replace", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                gate.install(self.root / "tool", self.pin)
            self.assertEqual(list((self.root / "tool").iterdir()), [])

    def test_network_failure_is_failure(self):
        with patch.object(gate, "selected_pin", return_value=self.pin), \
                patch.object(gate.urllib.request, "urlopen", side_effect=OSError("offline")):
            self.assertEqual(self.invoke("--install-dir", str(self.root / "tool")), 1)

    def test_nonzero_lint_and_timeout_are_failures(self):
        tool = self.root / "actionlint.exe"
        tool.write_bytes(self.payload)
        with patch.object(gate, "selected_pin", return_value=self.pin):
            with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
                self.assertEqual(self.invoke("--actionlint", str(tool)), 1)
                self.assertEqual(run.call_args.args[0], [str(tool.resolve()), "-shellcheck=", "-pyflakes=",
                                                         str((self.directory / "first.yml").resolve())])
            with patch.object(gate.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 120)):
                self.assertEqual(self.invoke("--actionlint", str(tool)), 1)


if __name__ == "__main__":
    unittest.main()
