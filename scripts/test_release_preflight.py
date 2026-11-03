"""Whole preflight orchestration with real Git and controlled external gates.
These tests do not dispatch CI, build router clients or validate an SDK package.
"""
import ast
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import native_lab
import openwrt_source_gate
import release_ci_gate
import router_release_gate


class PreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="qeli-preflight-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "source").write_text("original")
        self.git("init", "--quiet")
        self.git("add", "source")
        self.commit("first")
        self.first = self.git("rev-parse", "HEAD").strip()
        self.commit("second", "--allow-empty")
        self.second = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "--quiet", "--detach", self.first)

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.autocrlf=false", *args],
                                       cwd=self.root, text=True).strip()

    def commit(self, message, *args):
        self.git("-c", "user.name=Audit Fixture", "-c", "user.email=audit@localhost",
                 "commit", "--quiet", "-m", message, *args)

    def execute(self, change=None, phase="ci", credential="", errors=None, cert_error=None,
                snapshot_commit=None, report_commit=None, close_error=None):
        events = []
        def event(name):
            events.append(name)
            if name == phase and change:
                change()
        def ci(*args):
            event("ci")
            return (errors or {}).get("ci", [])
        def source(*args):
            event("source")
            return (errors or {}).get("source", [])
        def verify(*args, **kwargs):
            event("lab")
            return {"source_commit": report_commit or self.first,
                    "remote_root": "/var/tmp/fixture", "archive_sha256": "0" * 64,
                    "results": [{"arch": arch, "status": "PASS", "artifact_sha256": "1" * 64}
                                for arch in ("armv7", "mipsel")]}
        real_run = subprocess.run
        def command(args, **kwargs):
            if len(args) > 1 and str(args[1]).endswith("release_certification.py"):
                event("certification")
                self.assertEqual(Path(kwargs["cwd"]), self.root)
                if cert_error:
                    raise cert_error
                if not os.environ.get("QELI_PREFLIGHT_BASELINE"):
                    self.assertEqual(kwargs.get("timeout"), 120)
                return subprocess.CompletedProcess(args, 1 if (errors or {}).get("certification") else 0,
                                                   "controlled evidence", "")
            return real_run(args, **kwargs)
        connection = Mock()
        connection.close.side_effect = close_error
        connect = Mock(return_value=connection)
        path = Path(os.environ.get("QELI_PREFLIGHT_BASELINE", Path(__file__).with_name("release_preflight.py")))
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        # Override only repository selection in the baseline script. All gate
        # ordering and verdict logic execute from the unmodified implementation.
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "ROOT" for t in node.targets):
                node.value = ast.Constant(str(self.root))
        tree.body = [node for node in tree.body if not (isinstance(node, ast.Expr)
                     and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                     and node.value.func.attr == "reconfigure")]
        ast.fix_missing_locations(tree)
        namespace = {"__file__": str(path), "__name__": "audit_fixture"}
        output = io.StringIO()
        with patch.dict(os.environ, {"QELI_LAB_PASS": credential}, clear=False), \
             patch.object(release_ci_gate, "check_release_ci", side_effect=ci), \
             patch.object(openwrt_source_gate, "check_openwrt_source", side_effect=source), \
             patch.object(native_lab, "connect_lab", connect), \
             patch.object(router_release_gate, "verify_router_release", side_effect=verify), \
             patch.object(router_release_gate, "committed_crate_archive", return_value=(snapshot_commit or self.first, b"fixture")), \
             patch.object(subprocess, "run", side_effect=command), \
             patch.object(__import__("sys"), "argv", [str(path), "dev"]), \
             contextlib.redirect_stdout(output):
            try:
                exec(compile(tree, str(path), "exec"), namespace)
                result = namespace["main"](["dev"], self.root) if "main" in namespace else 0
            except SystemExit as error:
                result = error.code
        return result, output.getvalue(), events, connect, connection

    def test_unchanged_clean_source_and_optional_lab_skip_pass(self):
        rc, text, events, connect, _ = self.execute()
        self.assertEqual(rc, 0, text)
        self.assertEqual(events, ["ci", "source", "certification"])
        connect.assert_not_called()

    def test_commit_change_after_ci_refuses_before_other_gates(self):
        rc, text, events, _, _ = self.execute(change=lambda: self.git("checkout", "--quiet", self.second))
        self.assertEqual(rc, 1, text)
        self.assertNotIn("PASS — safe to release", text)
        self.assertEqual(events, ["ci"])

    def test_commit_change_during_lab_closes_and_refuses(self):
        rc, text, events, _, connection = self.execute(credential="fixture-only", phase="lab",
            change=lambda: self.git("checkout", "--quiet", self.second))
        self.assertEqual(rc, 1, text)
        self.assertEqual(events, ["ci", "lab"])
        connection.close.assert_called_once()

    def test_commit_change_during_certification_cannot_pass(self):
        rc, text, _, _, _ = self.execute(phase="certification",
            change=lambda: self.git("checkout", "--quiet", self.second))
        self.assertEqual(rc, 1, text)
        self.assertNotIn("PASS — safe to release", text)

    def test_tracked_edit_after_source_gate_refuses_before_certification(self):
        rc, text, events, _, _ = self.execute(phase="source",
            change=lambda: (self.root / "source").write_text("modified"))
        self.assertEqual(rc, 1, text)
        self.assertEqual(events, ["ci", "source"])

    def test_initial_dirty_or_untracked_input_refuses_before_external_queries(self):
        for name in ("source", "untracked-helper.py"):
            with self.subTest(name=name):
                target = self.root / name
                target.write_text("changed")
                rc, text, events, connect, _ = self.execute(credential="fixture-only")
                self.assertEqual(rc, 1, text)
                self.assertEqual(events, [])
                connect.assert_not_called()
                if name == "source":target.write_text("original")
                else:target.unlink()

    def test_ignored_cache_does_not_dirty_source(self):
        (self.root / ".gitignore").write_text("cache/\n")
        self.git("add", ".gitignore")
        self.commit("ignore cache")
        (self.root / "cache").mkdir()
        (self.root / "cache/object").write_text("cache")
        rc, text, _, _, _ = self.execute()
        self.assertEqual(rc, 0, text)

    def test_independent_gate_failures_accumulate(self):
        rc, text, events, _, _ = self.execute(errors={"ci": ["CI refused"],
                                             "source": ["archive refused"], "certification": True})
        self.assertEqual(rc, 1, text)
        self.assertIn("CI refused", text)
        self.assertIn("archive refused", text)
        self.assertIn("certification is incomplete", text)
        self.assertEqual(events, ["ci", "source", "certification"])

    def test_snapshot_mismatch_refuses_before_connecting(self):
        rc, text, _, connect, _ = self.execute(credential="fixture-only", snapshot_commit=self.second)
        self.assertEqual(rc, 1, text)
        connect.assert_not_called()

    def test_report_mismatch_closes_and_fails(self):
        rc, text, _, _, connection = self.execute(credential="fixture-only", report_commit=self.second)
        self.assertEqual(rc, 1, text)
        connection.close.assert_called_once()

    def test_certification_timeout_or_missing_interpreter_is_failed_verdict(self):
        for error in (subprocess.TimeoutExpired("certification", 120), FileNotFoundError("interpreter")):
            with self.subTest(error=type(error).__name__):
                rc, text, _, _, _ = self.execute(cert_error=error)
                self.assertEqual(rc, 1, text)
                self.assertIn("certification execution failed", text)

    def test_configured_lab_and_close_failure_remain_release_blocking(self):
        rc, text, events, connect, connection = self.execute(credential="fixture-only", close_error=OSError("close fault"))
        self.assertEqual(rc, 1, text)
        self.assertEqual(events, ["ci", "lab", "source", "certification"])
        connect.assert_called_once()
        connection.close.assert_called_once()


    def test_hidden_flags_refuse_before_external_queries(self):
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                self.git("update-index", "--" + flag, "--", "source")
                try:
                    (self.root / "source").write_text("hidden edit")
                    self.assertEqual(self.git("status", "--porcelain"), "")
                    rc, text, events, connect, _ = self.execute(credential="fixture-only")
                    self.assertEqual(rc, 1, text)
                    self.assertIn("assume-unchanged/skip-worktree", text)
                    self.assertEqual(events, [])
                    connect.assert_not_called()
                finally:
                    self.git("update-index", "--no-" + flag, "--", "source")
                    (self.root / "source").write_text("original")

    def test_flags_added_during_ci_refuse_before_other_gates(self):
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                try:
                    rc, text, events, _, _ = self.execute(
                        change=lambda: self.git("update-index", "--" + flag, "--", "source"))
                    self.assertEqual(rc, 1, text)
                    self.assertEqual(events, ["ci"])
                finally:
                    self.git("update-index", "--no-" + flag, "--", "source")

    def test_flags_added_during_certification_prevent_pass(self):
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                try:
                    rc, text, _, _, _ = self.execute(phase="certification",
                        change=lambda: self.git("update-index", "--" + flag, "--", "source"))
                    self.assertEqual(rc, 1, text)
                    self.assertNotIn("PASS — safe to release", text)
                finally:
                    self.git("update-index", "--no-" + flag, "--", "source")


if __name__ == "__main__":
    unittest.main()
