"""Release-channel selection and promotion without network access or Docker."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import docker_latest as latest


def rel(tag, *, beta=True, draft=False, published="2026-11-26T11:16:48Z"):
    return {"tag_name": f"v{tag}", "draft": draft, "prerelease": beta, "published_at": published}


class PolicyTests(unittest.TestCase):
    def test_beta_bootstrap_ignores_drafts_unpublished_and_list_order(self):
        self.assertEqual(latest.latest_release([
            rel("0.8.6", draft=True), rel("0.8.10"), rel("0.8.11", published=None), rel("0.8.9"),
            rel("0.8.8", beta=False, draft=True),
        ]), "v0.8.10")

    def test_only_stable_after_first_published_stable_even_if_beta_is_newer(self):
        self.assertEqual(latest.latest_release([
            rel("1.9.0"), rel("1.2.0", beta=False), rel("1.3.0-rc.2", beta=False), rel("1.2.1", beta=False),
        ]), "v1.2.1")

    def test_semver_prerelease_numeric_order(self):
        self.assertEqual(latest.latest_release([rel("1.2.0-rc.9"), rel("1.2.0-rc.10")]), "v1.2.0-rc.10")

    def test_no_eligible_release_and_ambiguous_precedence(self):
        self.assertIsNone(latest.latest_release([rel("1.0.0", draft=True)]))
        with self.assertRaisesRegex(ValueError, "precedence"):
            latest.latest_release([rel("1.0.0+build1"), rel("1.0.0+build2")])

    def test_085_recovery_requires_all_three_exact_identifiers(self):
        tag, source, digest = latest.RECOVERED
        self.assertEqual(latest.attestation_identity(tag, source, digest), ("refs/heads/dev", latest.RECOVERY_WORKFLOW_SHA))
        self.assertEqual(latest.attestation_identity(tag, source, "sha256:"+"f"*64), ("refs/tags/v0.8.5", source))


class PromotionTests(unittest.TestCase):
    def checks(self, *, releases=None, digest=None, attestation_failure=False, missing=False, request="v0.8.5", mode="manual"):
        version, source, known = latest.RECOVERED
        target = digest or known
        calls = []

        def run(*args, **kwargs):
            calls.append(args)
            if args[0] == "git":
                return source if args[1] == "rev-parse" else '[package]\nversion="0.8.5"'
            if args[:3] == ("gh", "attestation", "verify") and attestation_failure:
                raise ValueError("invalid signature")
            return ""

        registry = {
            ("manifests", "0.8.5"): (None, None) if missing else (target, {}),
            ("manifests", "latest"): ("sha256:"+"a"*64, {}),
        }

        def manifest(kind, key, *, missing=False):
            if any(c[0] == "docker" and c[3] == "create" for c in calls) and key == "latest":
                return target, {}
            return registry[kind, key]

        failure = None
        with contextlib.redirect_stdout(io.StringIO()), \
             patch.object(latest, "published_latest", side_effect=releases or [version, version]), \
             patch.object(latest, "command", side_effect=run), \
             patch.object(latest, "Registry") as factory, \
             patch.object(latest, "verify_platforms") as platforms:
            factory.return_value.get.side_effect = manifest
            try:
                latest.promote(request, known if mode == "build" else "", mode)
            except ValueError as exc:
                failure = str(exc)
        return failure, calls, platforms

    def test_manual_retags_only_exact_index_without_building(self):
        failure, calls, platforms = self.checks()
        self.assertIsNone(failure)
        platforms.assert_called_once()
        writes = [c for c in calls if c[0] == "docker"]
        self.assertEqual(writes, [("docker", "buildx", "imagetools", "create", "--tag", latest.IMAGE+":latest",
                                   latest.IMAGE+"@"+latest.RECOVERED[2])])
        self.assertLess(next(i for i,c in enumerate(calls) if c[0] == "gh"), calls.index(writes[0]))

    def test_unsigned_changed_or_mismatched_build_never_moves_latest(self):
        for options, expected in (({"attestation_failure":True}, "signature"),
                                  ({"releases":["v0.8.5", "v0.8.6"]}, "changed"),
                                  ({"mode":"build", "digest":"sha256:"+"b"*64}, "build digest"),
                                  ({"releases":["v0.8.6"]}, "no matching")):
            with self.subTest(options=options):
                failure, calls, _ = self.checks(**options)
                self.assertIn(expected, failure)
                self.assertFalse(any(c[0] == "docker" for c in calls))

    def test_release_event_can_arrive_before_tag_image_exists(self):
        failure, calls, platforms = self.checks(mode="release", missing=True)
        self.assertIsNone(failure)
        platforms.assert_not_called()
        self.assertFalse(any(c[0] == "docker" for c in calls))

    def test_release_event_defers_an_image_whose_signature_is_not_ready(self):
        failure, calls, platforms = self.checks(mode="release", attestation_failure=True)
        self.assertIsNone(failure)
        platforms.assert_called_once()
        self.assertFalse(any(c[0] == "docker" for c in calls))

    def test_older_release_event_still_reconciles_the_latest_eligible_image(self):
        failure, calls, _ = self.checks(request="v0.8.4", mode="release")
        self.assertIsNone(failure)
        self.assertTrue(any(c[0] == "docker" and c[-1].endswith(latest.RECOVERED[2]) for c in calls))

    def test_workflow_skips_publisher_in_promotion_mode_and_separates_credentials(self):
        path = Path(__file__).resolve().parents[1]/".github/workflows/docker-publish.yml"
        workflow = path.read_text(encoding="utf-8")
        self.assertIn("github.event_name != 'release' && !inputs.latest_only", workflow)
        self.assertIn("needs.publish.result == 'success' && github.ref_type == 'tag'", workflow)
        promotion = workflow.split("\n  latest:\n", 1)[1]
        self.assertNotIn("docker/build-push-action", promotion)
        self.assertNotIn("id-token: write", promotion)
        self.assertIn("scripts/docker_latest.py", promotion)


if __name__ == "__main__":
    unittest.main()
