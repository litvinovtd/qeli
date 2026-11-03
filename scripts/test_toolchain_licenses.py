from __future__ import annotations
import json
import tempfile
import unittest
import shutil
from pathlib import Path
import toolchain_licenses as legal

ROOT = Path(__file__).resolve().parent.parent


class ToolchainLicenseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(); cls.resources = Path(cls.shared.name)
        _, records, _ = legal.catalog(ROOT)
        for record in records:
            (cls.resources / (record['sha256'] + '.txt')).write_bytes((ROOT / legal.BUNDLE / record['path']).read_bytes())
    @classmethod
    def tearDownClass(cls): cls.shared.cleanup()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'; self.policy = self.repo / legal.POLICY
        self.policy.parent.mkdir(parents=True); self.policy.write_bytes((ROOT / legal.POLICY).read_bytes())
        self.bundle = self.repo / legal.BUNDLE
    def generate(self, output=None): return legal.generate(self.repo, self.resources, output or self.bundle)
    def reindex(self):
        file = self.bundle / 'INDEX.tsv'; lines = file.read_text(encoding='utf-8').splitlines()
        file.write_text(lines[0] + '\n' + ''.join(legal.sha((self.bundle / n).read_bytes()) + '\t' + n + '\t' + o + '\n' for _, n, o in (line.split('\t') for line in lines[1:])), encoding='utf-8')
    def rust_copyright(self): return self.bundle / ('files/rust/' + legal.DEFAULT_RUST_TOOLCHAIN + '/rustc/share/doc/rust/COPYRIGHT-library.html')
    def test_original_bytes_and_relative_paths(self):
        result = self.generate(); self.assertEqual(result['resources'], 65)
        for record in legal.catalog(self.repo)[1]:
            self.assertEqual((self.bundle / record['path']).read_bytes(), (self.resources / (record['sha256'] + '.txt')).read_bytes())
        self.assertTrue((self.rust_copyright().parent / 'licenses/MIT.txt').is_file())
    def test_deterministic_generation(self):
        self.generate(); other = Path(self.temp.name) / 'other'; self.generate(other)
        self.assertEqual({p.relative_to(self.bundle).as_posix(): p.read_bytes() for p in self.bundle.rglob('*') if p.is_file()}, {p.relative_to(other).as_posix(): p.read_bytes() for p in other.rglob('*') if p.is_file()})
    def test_existing_output_refused(self):
        self.generate()
        with self.assertRaisesRegex(ValueError, 'new toolchain'): self.generate()
    def test_missing_std_copyright(self):
        self.generate(); self.rust_copyright().unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'): legal.check_bundle(self.repo)
    def test_corrupt_source_resource_even_with_reindexed_bundle(self):
        self.generate(); self.rust_copyright().write_bytes(b'bad'); self.reindex()
        with self.assertRaisesRegex(ValueError, 'source/checksum'): legal.check_bundle(self.repo)
    def test_extra_resource(self):
        self.generate(); (self.bundle / 'extra.txt').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'extra'): legal.check_bundle(self.repo)
    def test_duplicate_index(self):
        self.generate(); index = self.bundle / 'INDEX.tsv'; index.write_bytes(index.read_bytes() + index.read_bytes().splitlines()[1] + b'\n')
        with self.assertRaisesRegex(ValueError, 'index/source'): legal.check_bundle(self.repo)
    def test_inventory_byte_binding_drift(self):
        self.generate(); lines = self.policy.read_text(encoding='utf-8').splitlines(); self.policy.write_text('\n'.join([lines[0], *reversed(lines[1:])]) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'binding'): legal.check_bundle(self.repo)
    def test_missing_policy(self):
        self.generate(); self.policy.unlink()
        with self.assertRaises(OSError): legal.check_bundle(self.repo)
    def test_missing_version_component(self):
        lines = self.policy.read_text(encoding='utf-8').splitlines(); self.policy.write_text('\n'.join(l for l in lines if not l.startswith('zig\t')) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'Missing pinned'): self.generate()
    def test_std_library_cannot_be_replaced_by_generic_mit_only(self):
        self.policy.write_text('\n'.join(l for l in self.policy.read_text(encoding='utf-8').splitlines() if 'COPYRIGHT-library.html' not in l) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'standard-library'): self.generate()
    def test_traversal_member(self):
        self.policy.write_bytes(self.policy.read_bytes().replace(b'\tLICENSE-APACHE\t', b'\t../LICENSE-APACHE\t', 1))
        with self.assertRaisesRegex(ValueError, 'Unsafe'): self.generate()
    def test_untrusted_source_domain(self):
        self.policy.write_bytes(self.policy.read_bytes().replace(b'static.rust-lang.org', b'example.com'))
        with self.assertRaisesRegex(ValueError, 'provenance'): self.generate()
    def test_duplicate_catalog_resource(self):
        self.policy.write_bytes(self.policy.read_bytes() + self.policy.read_bytes().splitlines()[1] + b'\n')
        with self.assertRaisesRegex(ValueError, 'Duplicate'): self.generate()
    def test_false_ndk_whole_archive_claim_refused(self):
        self.policy.write_bytes(self.policy.read_bytes().replace(b'not-whole-archive-verified', b'0' * 64))
        with self.assertRaisesRegex(ValueError, 'NDK'): self.generate()
    def test_branch_instead_of_exact_git_commit_refused(self):
        lines = self.policy.read_text(encoding='utf-8').splitlines()
        for i, line in enumerate(lines):
            if line.startswith('gcc-runtime\t'):
                values = line.split('\t'); values[2] = values[2].replace(values[2].split('/')[5], 'main'); lines[i] = '\t'.join(values)
        self.policy.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'exact-VCS'): self.generate()


if __name__ == '__main__': unittest.main()
