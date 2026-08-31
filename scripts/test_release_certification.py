import copy
import unittest

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


if __name__ == "__main__":
    unittest.main()
