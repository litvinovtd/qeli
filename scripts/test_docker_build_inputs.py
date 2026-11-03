"""Regression checks for legal resources needed at Docker compile time (issue 200)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent


class DockerBuildInputTests(unittest.TestCase):
    def test_embedded_licenses_are_copied_before_compilation(self):
        recipe = (ROOT / "release/docker/Dockerfile").read_text(encoding="utf8")
        build = recipe.split(" AS build\n", 1)[1].split("# ---- runtime stage", 1)[0]
        self.assertIn("COPY qeli/third-party-notices/rust ./third-party-notices/rust", build)
        self.assertLess(build.index("COPY qeli/third-party-notices/rust"),
                        build.index("cargo build --locked --release --features jemalloc --bin qeli"))

    def test_runtime_legal_resources_are_still_distributed(self):
        recipe = (ROOT / "release/docker/Dockerfile").read_text(encoding="utf8")
        runtime = recipe.split("# ---- runtime stage", 1)[1]
        self.assertIn("COPY qeli/third-party-notices/rust /usr/share/doc/qeli/licenses/rust", runtime)

    def test_shared_workflow_does_not_pin_the_recovery_release(self):
        workflow = (ROOT / ".github/workflows/docker-publish.yml").read_text(encoding="utf8")
        self.assertIn("ref: ${{ github.ref }}", workflow)
        self.assertIn("tags: ['v*']", workflow)
        self.assertNotIn("de477ecc2a4376d1f471d056d748f14f937d7956", workflow)
        self.assertNotIn("ghcr.io/litvinovtd/qeli:0.8.2", workflow)

    def test_platform_checks_use_child_manifests(self):
        workflow = (ROOT / ".github/workflows/docker-publish.yml").read_text(encoding="utf8")
        self.assertIn('platform_image="$IMAGE@$child"', workflow)
        self.assertIn('assert len(matches)==1', workflow)
        self.assertNotIn('--entrypoint /usr/local/bin/qeli "$IMAGE@$DIGEST"', workflow)

    def test_latest_is_promoted_only_after_checks_and_attestation(self):
        workflow = (ROOT / ".github/workflows/docker-publish.yml").read_text(encoding="utf8")
        self.assertIn("tags: ${{ steps.version_tags.outputs.tags }}", workflow)
        self.assertIn("grep -v ':latest$'", workflow)
        checks = workflow.index("name: Run exact published image on all three architectures")
        attest = workflow.index("- uses: actions/attest-build-provenance@")
        promote = workflow.index("name: Promote verified latest")
        self.assertLess(checks, attest)
        self.assertLess(attest, promote)
        self.assertIn("if: steps.ref.outputs.latest_release == 'true'", workflow[promote:])


if __name__ == "__main__":
    unittest.main()
