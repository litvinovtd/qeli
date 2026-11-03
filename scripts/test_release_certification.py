import copy
import unittest
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import release_certification as certification


DIGEST = "a" * 64
ARTIFACT = "b" * 64


def complete_manifest():
    document = {
        "schema_version": 1,
        "release_version": "0.8.0",
        "source_digest": DIGEST,
        "cases": [
            {
                "id": case_id,
                "kind": kind,
                "status": "passed",
                "source_digest": DIGEST,
                "artifact_sha256": ARTIFACT,
                "executed_at": "2026-08-31T12:00:00+03:00",
                "environment": "test fixture",
                "evidence": "release/certification/evidence/test.json",
            }
            for case_id, kind in certification.REQUIRED_CASES.items()
        ],
    }
    document["cases"].extend(
        {"id": case_id, "kind": kind, "status": "pending"}
        for case_id, kind in certification.ADVISORY_CASES.items()
    )
    return document


class ReleaseCertificationTest(unittest.TestCase):
    def validate(self, document):
        return certification.validate_manifest(
            document,
            expected_version="0.8.0",
            expected_source_digest=DIGEST,
        )

    def test_complete_manifest_passes(self):
        self.assertEqual(self.validate(complete_manifest()), [])

    def test_missing_case_fails_closed(self):
        document = complete_manifest()
        missing = document["cases"].pop(0)["id"]
        self.assertTrue(any(missing in error for error in self.validate(document)))

    def test_pending_case_blocks_without_demanding_fake_evidence(self):
        document = complete_manifest()
        document["cases"][0] = {
            "id": document["cases"][0]["id"],
            "kind": document["cases"][0]["kind"],
            "status": "pending",
        }
        errors = self.validate(document)
        self.assertEqual(len(errors), 1)
        self.assertIn("expected 'passed'", errors[0])

    def test_pending_physical_case_is_advisory(self):
        document = complete_manifest()
        self.assertEqual(self.validate(document), [])
        self.assertEqual(
            certification.advisory_statuses(document),
            {"pending": len(certification.ADVISORY_CASES)},
        )

    def test_unavailable_physical_case_is_advisory(self):
        document = complete_manifest()
        physical = document["cases"][len(certification.REQUIRED_CASES)]
        physical["status"] = "not_available"
        self.assertEqual(self.validate(document), [])

    def test_failed_physical_case_blocks_known_regression(self):
        document = complete_manifest()
        physical = document["cases"][len(certification.REQUIRED_CASES)]
        physical["status"] = "failed"
        errors = self.validate(document)
        self.assertEqual(len(errors), 1)
        self.assertIn("physical qualification failed", errors[0])

    def test_passed_physical_case_requires_exact_evidence(self):
        document = complete_manifest()
        physical = document["cases"][len(certification.REQUIRED_CASES)]
        physical["status"] = "passed"
        errors = self.validate(document)
        self.assertTrue(any("different source tree" in error for error in errors))
        self.assertTrue(any("artifact_sha256" in error for error in errors))
        self.assertTrue(any("executed_at" in error for error in errors))
        self.assertTrue(any("environment" in error for error in errors))
        self.assertTrue(any("evidence" in error for error in errors))

    def test_missing_advisory_row_is_a_schema_error(self):
        document = complete_manifest()
        advisory_id = next(iter(certification.ADVISORY_CASES))
        document["cases"] = [
            case for case in document["cases"] if case["id"] != advisory_id
        ]
        self.assertTrue(
            any(
                f"missing advisory case {advisory_id}" in error
                for error in self.validate(document)
            )
        )

    def test_stale_source_and_artifact_are_rejected(self):
        document = complete_manifest()
        document["source_digest"] = "c" * 64
        document["cases"][0]["source_digest"] = "c" * 64
        document["cases"][0]["artifact_sha256"] = "not-a-sha"
        errors = self.validate(document)
        self.assertTrue(any("source_digest" in error for error in errors))
        self.assertTrue(any("different source tree" in error for error in errors))
        self.assertTrue(any("artifact_sha256" in error for error in errors))

    def test_duplicate_case_cannot_shadow_a_failure(self):
        document = complete_manifest()
        document["cases"].append(copy.deepcopy(document["cases"][0]))
        self.assertTrue(any("duplicate case id" in error for error in self.validate(document)))

    def test_timestamp_requires_timezone(self):
        document = complete_manifest()
        document["cases"][0]["executed_at"] = "2026-08-31T12:00:00"
        self.assertTrue(any("RFC 3339" in error for error in self.validate(document)))


class RepositorySourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="qeli-cert-source-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "source").write_text("original")
        (self.root / ".gitignore").write_text("cache/\n")
        (self.root / "release/certification").mkdir(parents=True)
        (self.root / "release/certification/receipt").write_text("receipt")
        self.git("init", "--quiet")
        self.git("add", ".")
        self.commit("first")
        self.first = self.git("rev-parse", "HEAD")
        self.commit("second", "--allow-empty")
        self.second = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "--detach", self.first)

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.autocrlf=false", *args],
                                       cwd=self.root, text=True).strip()

    def commit(self, message, *args):
        self.git("-c", "user.name=Audit Fixture", "-c", "user.email=audit@localhost",
                 "commit", "--quiet", "-m", message, *args)

    def digest(self):
        return certification.repository_source_digest(self.root)

    def test_clean_digest_ignores_only_certification_tree_and_caches(self):
        expected = self.digest()
        (self.root / "cache").mkdir()
        (self.root / "cache/object").write_text("ignored cache")
        (self.root / "release/certification/new-evidence.json").write_text("{}")
        self.assertEqual(self.digest(), expected)
        self.git("add", "release/certification")
        self.commit("evidence")
        self.assertEqual(self.digest(), expected)

    def test_hidden_flags_refuse_even_without_worktree_edit(self):
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                self.git("update-index", "--" + flag, "--", "source")
                try:
                    with self.assertRaisesRegex(certification.CertificationError, "assume-unchanged/skip-worktree"):
                        self.digest()
                finally:
                    self.git("update-index", "--no-" + flag, "--", "source")

    def test_hidden_edits_cannot_reuse_committed_digest(self):
        for path in ("source", "release/certification/receipt"):
            original = (self.root / path).read_text()
            for flag in ("assume-unchanged", "skip-worktree"):
                with self.subTest(path=path, flag=flag):
                    self.git("update-index", "--" + flag, "--", path)
                    try:
                        (self.root / path).write_text("hidden edit")
                        self.assertEqual(self.git("status", "--porcelain"), "")
                        with self.assertRaises(certification.CertificationError):
                            self.digest()
                    finally:
                        self.git("update-index", "--no-" + flag, "--", path)
                        (self.root / path).write_text(original)

    def test_untracked_source_and_tracked_evidence_edits_refuse(self):
        for path in ("new-helper.py", "release/certification/receipt"):
            target = self.root / path
            original = target.read_text() if target.exists() else None
            try:
                target.write_text("changed")
                with self.assertRaises(certification.CertificationError):
                    self.digest()
            finally:
                if original is None:target.unlink()
                else:target.write_text(original)

    def test_head_change_during_tree_query_refuses(self):
        real_run = subprocess.run
        def command(args, **kwargs):
            result = real_run(args, **kwargs)
            if args[1] == "ls-tree":
                self.assertEqual(args[-1], self.first)
                self.git("checkout", "--quiet", self.second)
            return result
        with patch.object(subprocess, "run", side_effect=command):
            with self.assertRaisesRegex(certification.CertificationError, "changed during certification"):
                self.digest()

    def test_flags_added_during_tree_query_refuse(self):
        real_run = subprocess.run
        for flag in ("assume-unchanged", "skip-worktree"):
            def command(args, **kwargs):
                result = real_run(args, **kwargs)
                if args[1] == "ls-tree":
                    self.git("update-index", "--" + flag, "--", "source")
                return result
            try:
                with patch.object(subprocess, "run", side_effect=command):
                    with self.assertRaises(certification.CertificationError):
                        self.digest()
            finally:
                self.git("update-index", "--no-" + flag, "--", "source")

    def test_git_failures_are_certification_refusals(self):
        real_run = subprocess.run
        for query in ("rev-parse", "ls-files", "status", "ls-tree"):
            for failure in ("missing", "timeout", "nonzero"):
                with self.subTest(query=query, failure=failure):
                    def command(args, **kwargs):
                        if args[1] == query:
                            if failure == "missing":raise FileNotFoundError("git")
                            if failure == "timeout":raise subprocess.TimeoutExpired(args, 30)
                            return subprocess.CompletedProcess(args, 7, b"", b"query refused") if not kwargs.get("text") else subprocess.CompletedProcess(args, 7, "", "query refused")
                        return real_run(args, **kwargs)
                    with patch.object(subprocess, "run", side_effect=command):
                        with self.assertRaises(certification.CertificationError):
                            self.digest()


if __name__ == "__main__":
    unittest.main()
