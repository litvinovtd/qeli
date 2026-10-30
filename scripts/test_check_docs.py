"""Documentation navigation must reject missing fragments without rejecting real ones."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_docs


class MarkdownAnchorTests(unittest.TestCase):
    def test_unicode_inline_code_and_duplicate_headings(self):
        text = '# IPv6: `manual`\n## Настройка DNS\n## Настройка DNS\n'
        self.assertEqual(check_docs.markdown_anchors(text),
                         {'ipv6-manual', 'настройка-dns', 'настройка-dns-1'})

    def test_fences_are_not_headings_and_html_anchors_work(self):
        text = '```md\n# Fake\n<a id="fake">\n```\n`<a id="inline-fake">`\n<a id="manual"></a>\nTitle\n=====\n'
        self.assertEqual(check_docs.markdown_anchors(text), {'manual', 'title'})

    def test_explicit_id_does_not_consume_heading_duplicate_suffix(self):
        text = '<a id="manual"></a>\n# Manual\n# Manual\n'
        self.assertEqual(check_docs.markdown_anchors(text), {'manual', 'manual-1'})

    def test_missing_and_valid_local_fragments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            page = root / 'page.md'
            target = root / 'target.md'
            target.write_text('# Проверка DNS\n', encoding='utf8')
            page.write_text('# Here\n[valid](target.md#%D0%BF%D1%80%D0%BE%D0%B2%D0%B5%D1%80%D0%BA%D0%B0-dns)\n'
                            '[self](#here)\n[broken](target.md#removed)\n', encoding='utf8')
            with patch.object(check_docs, 'ROOT', root), patch.object(check_docs, 'failures', []):
                check_docs.check_links([page])
                self.assertEqual(len(check_docs.failures), 1)
                self.assertIn('target.md#removed: missing Markdown anchor', check_docs.failures[0])

    def test_release_body_can_link_to_its_own_heading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'release').mkdir()
            page = root / 'release' / 'RELEASE_NOTES_0.8.2.md'
            page.write_text('# English\n[English](#english)\n', encoding='utf8')
            with patch.object(check_docs, 'ROOT', root), patch.object(check_docs, 'failures', []):
                check_docs.check_links([page])
                self.assertEqual(check_docs.failures, [])


class CatalogNavigationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.docs = self.root / 'docs/ru'

    def write(self, name, text):
        path = self.docs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def coverage_failures(self):
        with patch.object(check_docs, 'ROOT', self.root), \
             patch.object(check_docs, 'LANGS', ('ru',)), \
             patch.object(check_docs, 'failures', []):
            check_docs.check_index_coverage()
            return list(check_docs.failures)

    def test_nested_catalog_covers_audit_without_flat_index_list(self):
        self.write('index.md', '[Audit](reports/audit-0.8.2/README.md)\n')
        self.write('reports/audit-0.8.2/README.md', '[Report](AUDIT-Q01.md)\n')
        self.write('reports/audit-0.8.2/AUDIT-Q01.md', '# Q01\n')
        self.assertEqual([], self.coverage_failures())

    def test_scenario_catalog_covers_guide_and_previous_manual_address(self):
        self.write('index.md', '[Use cases](scenarios/README.md)\n')
        self.write('scenarios/README.md', '[Chain](CHAINED-SERVERS.md)\n'
                   '[Old address](../manuals/CHAINED-SERVERS.md)\n')
        self.write('scenarios/CHAINED-SERVERS.md', '# Chain\n')
        self.write('manuals/CHAINED-SERVERS.md',
                   '[Moved](../scenarios/CHAINED-SERVERS.md)\n')
        self.assertEqual([], self.coverage_failures())

    def test_orphan_scenario_and_unknown_category_still_fail(self):
        self.write('index.md', '[Use cases](scenarios/README.md)\n'
                   '[Unknown](unknown/page.md)\n')
        self.write('scenarios/README.md', '# Use cases\n')
        self.write('scenarios/orphan.md', '# Not linked\n')
        self.write('unknown/page.md', '# Unknown category\n')
        failures = self.coverage_failures()
        self.assertEqual(2, len(failures))
        self.assertTrue(any('scenarios/orphan.md is not reachable' in f for f in failures))
        self.assertTrue(any('unknown/page.md uses an unknown document category' in f for f in failures))

    def test_orphan_in_linked_catalog_is_still_rejected(self):
        self.write('index.md', '[Audit](reports/audit/README.md)\n')
        self.write('reports/audit/README.md', '# Audit\n')
        self.write('reports/audit/orphan.md', '# Missing from catalog\n')
        failures = self.coverage_failures()
        self.assertEqual(1, len(failures))
        self.assertIn('reports/audit/orphan.md', failures[0])

    def test_unlinked_catalog_does_not_make_its_documents_reachable(self):
        self.write('index.md', '# Index\n')
        self.write('reports/audit/README.md', '[Report](report.md)\n')
        self.write('reports/audit/report.md', '# Report\n')
        self.assertEqual(2, len(self.coverage_failures()))

    def test_catalog_cycles_terminate(self):
        self.write('index.md', '[Audit](reports/audit/README.md)\n')
        self.write('reports/audit/README.md', '[Back](../../index.md)\n[Report](report.md)\n')
        self.write('reports/audit/report.md', '# Report\n')
        self.assertEqual([], self.coverage_failures())

    def test_ordinary_article_is_not_an_implicit_catalog(self):
        self.write('index.md', '[Article](reports/article.md)\n')
        self.write('reports/article.md', '[Hidden](hidden.md)\n')
        self.write('reports/hidden.md', '# Hidden\n')
        self.assertIn('reports/hidden.md', self.coverage_failures()[0])

    def test_code_and_external_links_do_not_cover_documents(self):
        self.write('index.md', '[Audit](reports/audit/README.md)\n')
        self.write('reports/audit/README.md',
                   '```md\n[Example](hidden.md)\n```\n'
                   '`[Inline](hidden.md)`\n[External](https://example.com/hidden.md)\n')
        self.write('reports/audit/hidden.md', '# Hidden\n')
        self.assertEqual(1, len(self.coverage_failures()))

    def test_catalog_cannot_escape_language_tree(self):
        index = self.write('index.md', '[Outside](../eng/README.md)\n')
        outside = self.root / 'docs/eng/README.md'
        outside.parent.mkdir(parents=True)
        outside.write_text('[Hidden](../ru/reports/hidden.md)\n', encoding='utf-8')
        self.write('reports/hidden.md', '# Hidden\n')
        self.assertEqual(set(), check_docs.catalog_linked_documents(index, self.docs))
        self.assertEqual(1, len(self.coverage_failures()))

    def test_directory_and_nested_index_catalogs(self):
        self.write('index.md', '[Audit](reports/audit/)\n')
        self.write('reports/audit/README.md', '[Group](group/index.md)\n')
        self.write('reports/audit/group/index.md', '[Report](report.md#details)\n')
        self.write('reports/audit/group/report.md', '# Details\n')
        self.assertEqual([], self.coverage_failures())

    def test_repository_report_sections_do_not_expand_audit_catalog(self):
        root = Path(__file__).resolve().parents[1]
        for lang, audits, reports in [('ru', '## Аудиты', '## Отчёты'),
                                      ('eng', '## Audits', '## Reports')]:
            text = (root / f'docs/{lang}/index.md').read_text(encoding='utf-8')
            section = text.split(reports, 1)[1].split('\n## ', 1)[0]
            self.assertNotIn('AUDIT-Q', section)
            self.assertNotIn('reports/audit-0.8.2/', section)
            self.assertIn(audits, text)
            self.assertEqual(1, text.count('reports/audit-0.8.2/README.md'))


if __name__ == '__main__':
    unittest.main()
