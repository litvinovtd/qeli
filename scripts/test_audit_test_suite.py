"""A missing CI connection, skipped test or empty suite must not qualify the audit."""
import ast
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import audit_test_suite as gate

ROOT = Path(__file__).resolve().parents[1]


class AuditSuiteTests(unittest.TestCase):
    def test_workflow_connects_every_group_and_its_admission_guard(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for group in gate.SUITES:
            self.assertIn(f"python3 -B scripts/audit_test_suite.py --group {group}", workflow)
        self.assertIn("test_audit_test_suite.py", workflow)

    def test_registry_has_only_existing_test_modules_with_no_duplicates(self):
        modules = [module for group in gate.SUITES.values() for module in group]
        self.assertEqual(len(modules), len(set(modules)))
        for module in modules:
            path = ROOT / "scripts" / (module + ".py")
            tree = ast.parse(path.read_text(encoding="utf-8"))
            self.assertTrue(any(isinstance(node, ast.FunctionDef)
                                and node.name.startswith("test_") for node in ast.walk(tree)), module)

    def test_incomplete_empty_skipped_expected_failure_or_error_never_pass(self):
        result = unittest.TestResult()
        self.assertFalse(gate.qualified(result, 0))
        result.testsRun = 2
        self.assertTrue(gate.qualified(result, 2))
        self.assertFalse(gate.qualified(result, 3))
        for field in ("skipped", "expectedFailures", "failures", "errors"):
            result = unittest.TestResult()
            result.testsRun = 2
            setattr(result, field, [("fixture", "reason")])
            self.assertFalse(gate.qualified(result, 2), field)

    def test_unknown_group_refuses_before_loading_any_module(self):
        with patch.object(gate.unittest.defaultTestLoader, "loadTestsFromNames") as load:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    gate.main(["--group", "test_panel_route_dns"])
            self.assertEqual(error.exception.code, 2)
            load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
