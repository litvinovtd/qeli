"""Guide targets must survive release tagging without claiming publication."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sync_version as version


class GuideReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root_patch = patch.object(version, 'ROOT', self.root)
        self.root_patch.start(); self.addCleanup(self.root_patch.stop)
        self.problem_patch = patch.object(version, 'problems', [])
        self.problem_patch.start(); self.addCleanup(self.problem_patch.stop)

    def guides(self, target='0.8.2', package=None, legacy=False, ambiguous=False):
        package = package or target
        for language in ('ru', 'eng'):
            label = ('последний опубликованный релиз' if legacy else 'версия пакетов в этом руководстве') if language == 'ru' else (
                'latest published release' if legacy else 'package version covered by this guide')
            for name in version.BANNER_DOCS:
                path = self.root / f'docs/{language}/manuals/{name}.md'
                path.parent.mkdir(parents=True, exist_ok=True)
                text = f'> {label} **{target}**.\n'
                if ambiguous:
                    extra = 'последний опубликованный релиз' if language == 'ru' else 'latest published release'
                    text += f'> {extra} **0.8.1**.\n'
                text += f'https://github.com/litvinovtd/qeli/releases/download/v{package}/qeli_{package}_amd64.deb\n'
                path.write_text(text, encoding='utf8')

    def test_prepared_target_passes_before_and_after_tag(self):
        self.guides()
        for public in ('0.8.1', '0.8.2'):
            version.problems.clear()
            version.apply_documented_releases(public, '0.8.2', False, False)
            version.apply_release_artifacts(False)
            self.assertEqual(version.problems, [])

    def test_existing_public_target_remains_valid_during_next_development(self):
        self.guides('0.8.1')
        version.apply_documented_releases('0.8.1', '0.8.2', False, False)
        self.assertEqual(version.problems, [])

    def test_stale_and_unplanned_targets_are_rejected(self):
        for target in ('0.8.0', '0.9.0'):
            self.guides(target); version.problems.clear()
            version.apply_documented_releases('0.8.1', '0.8.2', False, False)
            self.assertEqual(len(version.problems), 10)

    def test_legacy_published_banner_cannot_claim_unpublished_release(self):
        self.guides(legacy=True)
        version.apply_documented_releases('0.8.1', '0.8.2', False, False)
        self.assertEqual(len(version.problems), 10)

    def test_releasing_stamps_guide_and_package_commands_together(self):
        self.guides('0.8.1')
        with contextlib.redirect_stdout(io.StringIO()):
            version.apply_documented_releases('0.8.1', '0.8.2', True, True)
            version.apply_release_artifacts(True)
        version.apply_documented_releases('0.8.1', '0.8.2', False, True)
        version.apply_release_artifacts(False)
        self.assertEqual(version.problems, [])

    def test_package_commands_cannot_disagree_with_guide(self):
        self.guides(package='0.8.1')
        version.apply_release_artifacts(False)
        self.assertEqual(len(version.problems), 6)

    def test_ambiguous_banner_is_rejected(self):
        self.guides(ambiguous=True)
        version.apply_documented_releases('0.8.1', '0.8.2', False, False)
        self.assertEqual(len(version.problems), 10)


if __name__ == '__main__':
    unittest.main()
