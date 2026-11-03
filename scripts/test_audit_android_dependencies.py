import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import audit_android_dependencies as policy


class AndroidDependenciesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.android = Path(self.tmp.name)
        for name in policy.LOCKS:
            path = self.android / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# Gradle lock\nempty=classpath\n")
        (self.android / policy.LOCKS[0]).write_text("g:a:1.0=classpath\n")
        (self.android / policy.LOCKS[2]).write_text("g:a:1.0=debugCompileClasspath\ng:b:2.0=releaseRuntimeClasspath\n")
        (self.android / "gradle").mkdir()
        (self.android / "gradle/security-versions.properties").write_text("g/a=1.0\n")

    def test_plugin_and_application_uses_are_merged(self):
        rows = policy.inventory(self.android)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(rows[0]["uses"]), 2)
        policy.check_security_pins(self.android, rows)

    def test_missing_and_malformed_locks_fail(self):
        path = self.android / policy.LOCKS[0]
        for text in ("invalid", "g:a:=classpath", "g:a:1.+ =classpath"):
            path.write_text(text)
            with self.assertRaises(ValueError): policy.inventory(self.android)
        path.unlink()
        with self.assertRaises(OSError): policy.inventory(self.android)

    def test_security_policy_drift_duplicate_and_unused_pins_fail(self):
        path = self.android / "gradle/security-versions.properties"
        for text in ("g/a=0.9", "g/a=1.0\ng/a=1.0", "g/c=1.0", ""):
            path.write_text(text)
            with self.assertRaises(ValueError): policy.check_security_pins(self.android, policy.inventory(self.android))

    def test_paginated_build_tool_advisory_blocks_report(self):
        rows = policy.inventory(self.android)
        calls = []
        def query(payload):
            calls.append(payload)
            if len(calls) == 1:return {"results": [{"next_page_token": "page1"}, {}]}
            return {"results": [{"vulns": [{"id": "GHSA-fixture"}]}]}
        result = policy.audit(rows, query)
        self.assertEqual(result["affected_packages"], 1)
        self.assertEqual(calls[1]["queries"][0]["page_token"], "page1")
        self.assertEqual(result["rows"][0]["advisories"], ["GHSA-fixture"])

    def test_partial_malformed_or_error_response_fails(self):
        rows = policy.inventory(self.android)
        for value in ({}, {"results": [{}]}, {"results": [{}, {"error": "unavailable"}]},
                      {"results": [{"vulns": [{}]}, {}]}, {"results": [{"next_page_token": 42}, {}]}):
            with self.assertRaises(ValueError):policy.audit(rows, lambda _: value)

    def test_pagination_loop_fails(self):
        with self.assertRaises(ValueError):
            policy.audit(policy.inventory(self.android)[:1], lambda _: {"results": [{"next_page_token": "loop"}]})

    def test_batches_cover_every_record(self):
        rows = [{"name": f"g:a{i}", "version": "1", "uses": []} for i in range(201)]
        batches = []
        def query(payload):
            batches.append(len(payload["queries"]))
            return {"results": [{} for _ in payload["queries"]]}
        self.assertEqual(policy.audit(rows, query)["packages"], 201)
        self.assertEqual(batches, [100, 100, 1])

    def test_network_failure_is_not_an_empty_pass(self):
        with patch.object(policy, "inventory", return_value=[]), patch.object(policy, "check_security_pins"), \
             patch.object(policy, "audit", side_effect=OSError("fixture outage")), \
             patch("sys.argv", ["audit_android_dependencies.py"]):
            self.assertEqual(policy.main(), 2)


if __name__ == "__main__":
    unittest.main()
