"""Exercise publication ref policy and the real workflow contract without pushing."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch
import unittest
from docker_publish_ref import classify, publication_outputs, published_stable_release

ROOT = Path(__file__).resolve().parent.parent


class RefTests(unittest.TestCase):
    def test_manual_branches_never_publish_latest(self):
        for branch in ["dev", "main", "v1.2.3", "release/1.2", "codex/fix"]:
            self.assertEqual(classify("branch", branch), {"release_tag": "false", "stable_release": "false"})

    def test_stable_tags_allow_latest(self):
        for tag in ["v0.8.2", "v1.2.3", "v10.20.30", "v1.2.3+build-42"]:
            self.assertEqual(classify("tag", tag), {"release_tag": "true", "stable_release": "true"})

    def test_prereleases_never_publish_latest(self):
        for tag in ["v1.2.3-rc1", "v1.2.3-rc.1", "v1.2.3-0", "v1.2.3-rc+build"]:
            self.assertEqual(classify("tag", tag), {"release_tag": "true", "stable_release": "false"})

    def test_invalid_tags_refuse_publication(self):
        for tag in ["vtest", "1.2.3", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2.3-01", "v1.2.3-", "v1.2.3+", "v1.2.3\n", "v1.2.3;echo bad"]:
            with self.assertRaises(ValueError):
                classify("tag", tag)

    def test_unexpected_refs_refuse(self):
        for kind, name in [("pull", "1"), ("", "dev"), ("branch", "")]:
            with self.assertRaises(ValueError):
                classify(kind, name)

    def test_real_cli_appends_outputs_and_refuses_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "outputs"
            output.write_text("existing=value\n")
            env = {**os.environ, "GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "dev", "GITHUB_OUTPUT": str(output)}
            p = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/docker_publish_ref.py")], env=env, capture_output=True)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(output.read_text(), "existing=value\nrelease_tag=false\nstable_release=false\nlatest_release=false\n")
            before = output.read_bytes()
            env.update(GITHUB_REF_TYPE="tag", GITHUB_REF_NAME="vmalformed")
            p = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/docker_publish_ref.py")], env=env, capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(output.read_bytes(), before)

    def test_workflow_guards_and_branch_fallback(self):
        workflow = (ROOT / ".github/workflows/docker-publish.yml").read_text(encoding="utf8")
        self.assertLess(workflow.index("python3 -B scripts/docker_publish_ref.py"), workflow.index("docker/login-action@"))
        self.assertIn("flavor: latest=false", workflow)
        self.assertIn("type=semver,pattern={{version}},enable=${{ steps.ref.outputs.release_tag }}", workflow)
        self.assertIn("type=sha,format=long", workflow)
        self.assertIn("type=raw,value=latest,enable=${{ steps.ref.outputs.latest_release }}", workflow)
        self.assertNotIn("!contains(github.ref_name, '-')", workflow)
        self.assertIn("concurrency:\n  group: docker-publish\n  cancel-in-progress: false", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("scripts/docker_publish_ref.py --require-published-stable", workflow)

    def test_release_workflow_preserves_prerelease_candidate_assets(self):
        workflow = (ROOT / ".github/workflows/release-attest.yml").read_text(encoding="utf8")
        self.assertIn("if: github.event_name == 'workflow_dispatch' || github.event.release.prerelease == false", workflow)
        self.assertLess(workflow.index("github.event.release.prerelease == false"),
                        workflow.index("runs-on: ubuntu-latest"))

    def test_numeric_beta_draft_and_missing_release_never_promote_latest(self):
        import json
        from types import SimpleNamespace
        for draft, prerelease, expected in [(False, True, False), (True, False, False),
                                            (True, True, False), (False, False, True)]:
            response = SimpleNamespace(returncode=0, stdout=json.dumps(
                dict(tagName="v0.8.2", isDraft=draft, isPrerelease=prerelease)))
            with patch("docker_publish_ref.subprocess.run", return_value=response):
                self.assertEqual(published_stable_release("owner/repo", "v0.8.2"), expected)
        with patch("docker_publish_ref.subprocess.run", return_value=SimpleNamespace(returncode=1)):
            self.assertFalse(published_stable_release("owner/repo", "v0.8.2"))
        for record in [{}, {"tagName": "v0.8.1", "isDraft": False, "isPrerelease": False}]:
            with patch("docker_publish_ref.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(record))):
                self.assertFalse(published_stable_release("owner/repo", "v0.8.2"))
        with patch("docker_publish_ref.subprocess.run", side_effect=AssertionError("missing repo queried")):
            self.assertFalse(published_stable_release(None, "v0.8.2"))


class LatestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--quiet", "--allow-empty", "-m", "fixture")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def tags(self, *tags):
        for tag in tags:
            self.git("tag", tag)

    def test_old_stable_cannot_downgrade_latest(self):
        self.tags("v0.8.2", "v0.9.0")
        # Baseline admits the old tag to latest; the publication decision must not.
        self.assertEqual(classify("tag", "v0.8.2")["stable_release"], "true")
        result = publication_outputs(self.root, "tag", "v0.8.2")
        self.assertEqual(result, {"release_tag": "true", "stable_release": "true", "latest_release": "false"})
        self.assertEqual(publication_outputs(self.root, "tag", "v0.9.0")["latest_release"], "true")

    def test_numeric_order_not_lexical_or_creation_order(self):
        self.tags("v10.0.0", "v2.99.99", "v10.0.2", "v10.0.10", "v9.99.99", "v10.1.0")
        for tag in ["v2.99.99", "v9.99.99", "v10.0.10", "v10.0.2"]:
            self.assertEqual(publication_outputs(self.root, "tag", tag)["latest_release"], "false")
        self.assertEqual(publication_outputs(self.root, "tag", "v10.1.0")["latest_release"], "true")

    def test_prereleases_and_unrelated_tags_do_not_block_stable(self):
        self.tags("v1.2.3", "v99.0.0-rc.1", "v100.0.0-01", "vtest", "backup")
        self.assertEqual(publication_outputs(self.root, "tag", "v1.2.3")["latest_release"], "true")

    def test_build_metadata_has_equal_precedence(self):
        self.tags("v1.2.3", "v1.2.3+build-42")
        for tag in ["v1.2.3", "v1.2.3+build-42"]:
            self.assertEqual(publication_outputs(self.root, "tag", tag)["latest_release"], "true")

    def test_branch_and_prerelease_do_not_need_git_inventory(self):
        with patch("docker_publish_ref.subprocess.run", side_effect=AssertionError("unexpected Git query")):
            for kind, name in [("branch", "dev"), ("tag", "v1.2.3-rc.1")]:
                self.assertEqual(publication_outputs(self.root, kind, name)["latest_release"], "false")

    def test_missing_tag_or_repository_refuse(self):
        self.tags("v1.2.3")
        with self.assertRaisesRegex(ValueError, "missing"):
            publication_outputs(self.root, "tag", "v1.2.4")
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaises(ValueError):
                publication_outputs(Path(outside), "tag", "v1.2.3")

    def test_shallow_repository_refuses(self):
        self.tags("v1.2.3")
        clone = self.root / "shallow"
        subprocess.run(["git", "clone", "--quiet", "--depth=1", self.root.as_uri(), str(clone)], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "complete Git history"):
            publication_outputs(clone, "tag", "v1.2.3")

    def test_git_failure_and_timeout_preserve_cli_output(self):
        output = self.root / "outputs"
        output.write_bytes(b"existing=value\n")
        env = {**os.environ, "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.2.3", "GITHUB_OUTPUT": str(output)}
        with patch.dict(os.environ, env):
            for error in [OSError("Git missing"), subprocess.TimeoutExpired("git", 30)]:
                with patch("docker_publish_ref.subprocess.run", side_effect=error):
                    from docker_publish_ref import main
                    self.assertEqual(main(["--repo", str(self.root)]), 1)
                self.assertEqual(output.read_bytes(), b"existing=value\n")

    def test_real_cli_old_new_and_missing_tags(self):
        self.tags("v1.2.3", "v1.3.0")
        output = self.root / "outputs"
        for tag, expected in [("v1.2.3", "false"), ("v1.3.0", "true")]:
            output.write_bytes(b"existing=value\n")
            env = {**os.environ, "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": tag, "GITHUB_OUTPUT": str(output)}
            command = [sys.executable, "-B", str(ROOT / "scripts/docker_publish_ref.py"), "--repo", str(self.root)]
            result = subprocess.run(command, env=env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), f"existing=value\nrelease_tag=true\nstable_release=true\nlatest_release={expected}\n".encode())
        before = output.read_bytes()
        env["GITHUB_REF_NAME"] = "v1.4.0"
        self.assertNotEqual(subprocess.run(command, env=env, capture_output=True).returncode, 0)
        self.assertEqual(output.read_bytes(), before)

    def test_cli_withholds_latest_for_numeric_github_prerelease(self):
        self.tags("v0.8.2")
        output = self.root / "outputs"
        env = {**os.environ, "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v0.8.2",
               "GITHUB_REPOSITORY": "owner/repo", "GITHUB_OUTPUT": str(output)}
        from docker_publish_ref import main
        for confirmed, expected in [(False, "false"), (True, "true")]:
            output.write_bytes(b"existing=value\n")
            with patch.dict(os.environ, env), patch("docker_publish_ref.published_stable_release", return_value=confirmed) as check:
                self.assertEqual(main(["--repo", str(self.root), "--require-published-stable"]), 0)
                check.assert_called_once_with("owner/repo", "v0.8.2")
            self.assertIn(f"latest_release={expected}\n", output.read_text())


if __name__ == "__main__":
    unittest.main()
