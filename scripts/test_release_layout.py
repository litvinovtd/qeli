"""Local release/data layout regressions; no lab access or builds."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseLayoutTests(unittest.TestCase):
    def test_release_root_contains_only_release_notes(self):
        files = [p for p in (ROOT / 'release').iterdir() if p.is_file()]
        self.assertTrue(files)
        for path in files:
            self.assertRegex(path.name, r'^RELEASE_NOTES_\d+\.\d+\.\d+\.md$')

    def test_packaging_and_certification_directories_remain(self):
        for name in ['docker', 'keenetic', 'reality-tls', 'certification']:
            self.assertTrue((ROOT / 'release' / name).is_dir(), name)

    def test_shared_data_is_grouped_by_type(self):
        for name in ['benchmarks', 'audits', 'validation']:
            self.assertTrue(any((ROOT / 'docs/data' / name).glob('*.json')), name)

    def test_080_benchmark_and_snapshots_remain_available(self):
        for lang in ['ru', 'eng']:
            self.assertTrue((ROOT / f'docs/{lang}/reports/benchmarks/'
                             'vpn_protocol_benchmark_repeat_2026-09-01.md').is_file())
        self.assertEqual(5, len(list((ROOT / 'docs/data/benchmarks').glob('benchmark_v0.8.0_*.json'))))

    def test_roundtrip_fixture_is_a_test_input(self):
        self.assertTrue((ROOT / 'test/fixtures/roundtrip_fixture_server.ini').is_file())
        generator = (ROOT / 'scripts/gen_roundtrip_fixture.py').read_text(encoding='utf-8')
        self.assertIn('"test/fixtures/roundtrip_fixture_server.ini"', generator)
        self.assertNotIn('release/roundtrip_fixture_server.ini', generator)

    def test_current_benchmark_docs_do_not_use_old_flat_data_paths(self):
        old = re.compile(r'release/(?:benchmark_|ab_|reality_tls_5x_|stability_)[^\s`)]*')
        for lang in ['ru', 'eng']:
            text = (ROOT / f'docs/{lang}/reports/BENCHMARK.md').read_text(encoding='utf-8')
            self.assertIsNone(old.search(text), lang)

    def test_versioned_result_path_creates_data_directory_and_avoids_overwrite(self):
        # Execute only this stdlib-only function, not the SSH/lab module.
        tree = ast.parse((ROOT / 'scripts/lab_hygiene.py').read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == 'versioned_result_path')
        module = ast.Module(body=[node], type_ignores=[])
        with tempfile.TemporaryDirectory() as temporary:
            fake_script = Path(temporary) / 'scripts/lab_hygiene.py'
            namespace = {'__file__': str(fake_script)}
            exec(compile(module, str(fake_script), 'exec'), namespace)
            path = Path(namespace['versioned_result_path']('qeli 0.8.2', 'features'))
            self.assertEqual(Path(temporary) / 'docs/data/benchmarks', path.parent)
            self.assertTrue(path.parent.is_dir())
            path.write_text('{}', encoding='utf-8')
            repeated = Path(namespace['versioned_result_path']('qeli 0.8.2', 'features'))
            self.assertNotEqual(path, repeated)
            self.assertTrue(repeated.stem.endswith('_run2'))

    def test_writers_do_not_regenerate_flat_release_results(self):
        for name in ['benchmark.py', 'reality_tls_repeat.py', 'lab_hygiene.py']:
            text = (ROOT / 'scripts' / name).read_text(encoding='utf-8')
            self.assertIn('"docs", "data", "benchmarks"', text, name)
            self.assertNotIn('"..", "release")', text, name)
        stability = (ROOT / 'scripts/stability_gate.py').read_text(encoding='utf-8')
        self.assertIn('docs/data/benchmarks/stability_gate_last.json', stability)
        fetch = (ROOT / 'scripts/fetch_binary.py').read_text(encoding='utf-8')
        self.assertIn('"release" / "dist" / f"v{VERSION}"', fetch)


if __name__ == '__main__':
    unittest.main()
