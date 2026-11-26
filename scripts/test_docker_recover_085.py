"""A recovery must not excuse any failure outside the known guide-only check."""
import unittest
from unittest.mock import patch

import docker_recover_085 as recovery


def job(name, conclusion="success", step="version consistency", **override):
    return {"name": name, "conclusion": conclusion, "status": "completed", "head_sha": recovery.SOURCE,
            "steps": [{"name": step, "conclusion": conclusion}], **override}


def payload(*jobs):
    return {"jobs": list(jobs), "total_count": len(jobs)}


class RecoveryTests(unittest.TestCase):
    def test_green_exact_ci_and_known_docs_only_failure(self):
        recovery.check_jobs(payload(job("docs"), job("test")), docs_failure=False)
        recovery.check_jobs(payload(job("docs", "failure"), job("test")), docs_failure=True)

    def test_wrong_step_additional_failure_and_stale_job_fail_closed(self):
        for fixture in (payload(job("docs", "failure", "tests")),
                        payload(job("docs", "failure"), job("test", "failure")),
                        payload(job("test", "failure")),
                        payload(job("docs", "failure"), job("test", "cancelled")),
                        payload(job("docs", "failure"), job("test", head_sha="0" * 40))):
            with self.subTest(fixture=fixture), self.assertRaises(ValueError):
                recovery.check_jobs(fixture, docs_failure=True)

    def test_missing_required_docs_or_truncated_results_fail_closed(self):
        for fixture in (payload(job("docs", "skipped")), {"jobs": [job("docs")], "total_count": 2}):
            with self.subTest(fixture=fixture), self.assertRaises(ValueError):
                recovery.check_jobs(fixture, docs_failure=False)

    def test_wrong_ref_does_not_query_repository(self):
        with patch.object(recovery, "source_identity") as source:
            with self.assertRaisesRegex(ValueError, "upstream dev"):
                recovery.admit("fixture", {"GITHUB_REPOSITORY": recovery.REPO, "GITHUB_EVENT_NAME": "workflow_dispatch",
                                           "GITHUB_REF": "refs/heads/main"})
            source.assert_not_called()


if __name__ == "__main__":
    unittest.main()
