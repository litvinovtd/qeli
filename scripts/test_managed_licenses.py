from __future__ import annotations
import base64
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import managed_licenses as legal


class ManagedLicensesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.repo = self.root / 'repo'
        for name in ('qeli-win', 'qeli-mac', 'qeli-shared'):
            (self.repo / name).mkdir(parents=True)
        self.digest = base64.b64encode(b'x' * 64).decode()
        self.lock = self.repo / 'qeli-win/packages.win-x64.lock.json'
        self.lock.write_text(json.dumps({'version': 1, 'dependencies': {'net10.0': {'Demo': {'type': 'Direct', 'resolved': '1.0.0', 'contentHash': self.digest}}}}), encoding='utf-8')
        self.sdk = self.repo / 'global.json'; self.sdk.write_text('{"sdk":{"version":"10.0.401"}}', encoding='utf-8')
        self.runtime = self.repo / legal.RUNTIME; self.runtime.parent.mkdir(parents=True)
        self.runtime.write_text('id\tversion\tcontent_hash\ndemo\t1.0.0\t' + self.digest + '\n', encoding='utf-8')
        self.archive = self.root / 'demo.nupkg'; self.upstream = self.root / 'upstream'; self.upstream.mkdir()
        self.receipts = self.upstream / 'receipts.json'; self.receipts.write_text('{"schema":1,"rows":[]}', encoding='utf-8')
        self.bundle = self.repo / legal.BUNDLE; self.admissions = self.root / 'admissions.tsv'
        self.write_archive()
    def write_archive(self, extra=None, kind='expression', value='MIT'):
        nuspec = f'<package><metadata><id>Demo</id><version>1.0.0</version><license type="{kind}">{value}</license><repository url="https://github.com/example/demo" commit="{"1"*40}" /></metadata></package>'.encode()
        with zipfile.ZipFile(self.archive, 'w') as z:
            z.writestr('demo.nuspec', nuspec)
            z.writestr('THIRD-PARTY-NOTICES.txt', b'upstream copyright\r\n')
            z.writestr('LICENSE.txt', b'MIT full text\r\n')
            for name, data in (extra or {}).items(): z.writestr(name, data)
        self.archive_sha = legal.sha(self.archive.read_bytes())
        self.admissions.write_text('id\tversion\tcontent_hash\tarchive_sha256\tpath\ndemo\t1.0.0\t' + self.digest + '\t' + self.archive_sha + '\t' + str(self.archive) + '\n', encoding='utf-8')
    def generate(self, output=None, actual=None):
        proof = actual or [{'path': str(self.archive), 'signed': True, 'contentHash': self.digest, 'archiveSha256': legal.sha(self.archive.read_bytes())}]
        with patch.object(legal, 'sdk_hashes', return_value=proof):
            return legal.generate(self.repo, self.admissions, self.upstream, output or self.bundle, self.root / 'dotnet')
    def resource(self, origin='LICENSE.txt'):
        return self.bundle / ('files/demo/1.0.0/' + legal.sha((legal.url(('demo', '1.0.0')) + '!' + origin).encode()) + '.txt')
    def reindex(self):
        file = self.bundle / 'INDEX.tsv'
        rows = legal.rows(file.read_bytes(), 'sha256\tpath\torigin', 3)
        file.write_text('sha256\tpath\torigin\n' + ''.join(legal.sha((self.bundle / name).read_bytes()) + '\t' + name + '\t' + origin + '\n' for _, name, origin in rows), encoding='utf-8')
    def test_original_bytes_and_third_party_notice(self):
        self.assertEqual(self.generate()['packages'], 1)
        self.assertEqual(self.resource().read_bytes(), b'MIT full text\r\n')
        self.assertEqual(self.resource('THIRD-PARTY-NOTICES.txt').read_bytes(), b'upstream copyright\r\n')
    def test_generation_is_deterministic(self):
        self.generate(); other = self.root / 'second'; self.generate(other)
        self.assertEqual({p.relative_to(self.bundle).as_posix(): p.read_bytes() for p in self.bundle.rglob('*') if p.is_file()}, {p.relative_to(other).as_posix(): p.read_bytes() for p in other.rglob('*') if p.is_file()})
    def test_refuses_existing_output(self):
        self.generate()
        with self.assertRaisesRegex(ValueError, 'new directory'): self.generate()
    def test_corrupt_archive_refused_by_actual_sdk_result(self):
        with self.archive.open('ab') as stream: stream.write(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'checksum'): self.generate()
    def test_official_content_hash_mismatch(self):
        with self.assertRaisesRegex(ValueError, 'content hash'):
            self.generate(actual=[{'contentHash': 'wrong', 'archiveSha256': self.archive_sha}])
    def test_sdk_binding_drift(self):
        self.generate(); self.sdk.write_text('{"sdk":{"version":"10.0.402"}}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'binding'): legal.check_bundle(self.repo)
    def test_lock_binding_drift(self):
        self.generate(); self.lock.write_bytes(self.lock.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'binding'): legal.check_bundle(self.repo)
    def test_added_graph_requires_regeneration(self):
        self.generate(); (self.repo / 'qeli-mac/packages.new.lock.json').write_bytes(self.lock.read_bytes())
        with self.assertRaisesRegex(ValueError, 'binding'): legal.check_bundle(self.repo)
    def test_runtime_binding_drift(self):
        self.generate(); self.runtime.write_bytes(self.runtime.read_bytes().replace(b'1.0.0', b'1.0.1'))
        with self.assertRaisesRegex(ValueError, 'binding'): legal.check_bundle(self.repo)
    def test_missing_published_file(self):
        self.generate(); self.resource().unlink()
        with self.assertRaisesRegex(ValueError, 'missing/checksum'): legal.check_bundle(self.repo)
    def test_corrupt_published_file(self):
        self.generate(); self.resource().write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'checksum'): legal.check_bundle(self.repo)
    def test_extra_published_file(self):
        self.generate(); (self.bundle / 'stray.txt').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'Unindexed'): legal.check_bundle(self.repo)
    def test_duplicate_index_row(self):
        self.generate(); index = self.bundle / 'INDEX.tsv'; lines = index.read_bytes().splitlines()
        index.write_bytes(index.read_bytes() + lines[1] + b'\n')
        with self.assertRaisesRegex(ValueError, 'Duplicate'): legal.check_bundle(self.repo)
    def test_nuspec_identity_even_with_reindexed_payload(self):
        self.generate(); p = self.resource('demo.nuspec'); p.write_bytes(p.read_bytes().replace(b'<id>Demo</id>', b'<id>Other</id>')); self.reindex()
        with self.assertRaisesRegex(ValueError, 'nuspec'): legal.check_bundle(self.repo)
    def test_declared_file_must_exist(self):
        self.write_archive(kind='file', value='missing.txt')
        with self.assertRaisesRegex(ValueError, 'declared NuGet license'): self.generate()
    def test_traversal_archive_rejected(self):
        self.write_archive({'../LICENSE.txt': b'unsafe'})
        with self.assertRaisesRegex(ValueError, 'Unsafe'): self.generate()
    def test_exact_vcs_supplement(self):
        data = b'Exact upstream\r\n'; (self.upstream / 'supplement.txt').write_bytes(data)
        record = {'repository': 'example/demo', 'commit': '1' * 40, 'upstream_path': 'COPYING', 'url': 'https://raw.githubusercontent.com/example/demo/' + '1' * 40 + '/COPYING', 'sha256': legal.sha(data), 'payload': 'supplement.txt', 'binding': 'nuspec-vcs'}
        self.receipts.write_text(json.dumps({'schema': 1, 'rows': [record]}), encoding='utf-8')
        self.assertEqual(self.generate()['supplements'], 1)
    def test_unbound_supplement_cannot_be_silently_skipped(self):
        self.receipts.write_text(json.dumps({'schema': 1, 'rows': [{'repository': 'other/demo', 'commit': '1' * 40, 'upstream_path': 'LICENSE', 'url': 'https://raw.githubusercontent.com/other/demo/' + '1' * 40 + '/LICENSE', 'binding': 'nuspec-vcs'}]}), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'Unbound'): self.generate()
    def test_microcom_supplement_requires_packaged_vcs_commit(self):
        commit = 'a83e5a26aa68adaa6001338e2cee2411dd380d1f'
        record = {'repository': 'kekekeks/MicroCom', 'commit': commit, 'upstream_path': 'LICENSE',
                  'url': f'https://raw.githubusercontent.com/kekekeks/MicroCom/{commit}/LICENSE',
                  'binding': 'nuspec-vcs'}
        metadata = {'url': 'https://github.com/kekekeks/MicroCom', 'commit': commit}
        self.assertTrue(legal.supplement_allowed(('microcom.runtime', '0.11.2'), metadata, record, {}))
        self.assertFalse(legal.supplement_allowed(('microcom.runtime', '0.11.2'), {'url': metadata['url']}, record, {}))
        self.assertFalse(legal.supplement_allowed(('microcom.runtime', '0.11.2'), dict(metadata, commit='0'*40), record, {}))

    def test_old_publisher_only_exception_is_removed(self):
        record = {'repository': 'kekekeks/MicroCom', 'commit': '4b8a38f773c109bad558ee3713d9f16d80776e42',
                  'upstream_path': 'LICENSE', 'binding': 'publisher-declaration; no nuspec-vcs commit'}
        record['url'] = f"https://raw.githubusercontent.com/{record['repository']}/{record['commit']}/LICENSE"
        self.assertFalse(legal.supplement_allowed(('microcom.runtime', '0.11.0'), {}, record, {}))

    def test_fake_font_metadata_rejected(self):
        self.generate(); (self.bundle / 'FONTS.json').write_text('{"schema":1,"rows":[{}]}', encoding='utf-8'); self.reindex()
        with self.assertRaisesRegex(ValueError, 'Unlinked'): legal.check_bundle(self.repo)


if __name__ == '__main__': unittest.main()
