from __future__ import annotations

import hashlib
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from check_android_licenses import check_apk


class AndroidLicenseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        texts = {'AGPL-3.0.txt': ('LICENSE', b'core\n'), 'MPL-2.0.txt': ('qeli-android/LICENSE', b'client\n'),
                 'Apache-2.0.txt': ('qeli-android/gradle/licenses/Apache-2.0.txt', b'apache\n'),
                 'MAVEN.tsv': ('qeli-android/gradle/licenses/maven-runtime.tsv',
                               b'coordinate\tlicense\treview\ng:a:1\tApache-2.0\thttps://example.org/source\n')}
        self.assets = {}
        self.origins = {}
        for name, (source, data) in texts.items():
            file = self.repo / source
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
            self.assets[name] = data
            self.origins[name] = name
        from test_native_licenses import fixture
        from native_licenses import generate
        repo, archives, receipts, bundle = fixture(self.repo / 'native-fixture')
        # The two fixtures use the same canonical core text.
        generate(repo, archives, receipts, bundle)
        import shutil
        shutil.copytree(repo / 'qeli', self.repo / 'qeli')
        for file in bundle.rglob('*'):
            if file.is_file():
                name = 'native-rust/' + file.relative_to(bundle).as_posix()
                self.assets[name] = file.read_bytes()
                self.origins[name] = 'native-rust!' + name.removeprefix('native-rust/')
        self.assets['ARTIFACTS.tsv'] = b'coordinate\tartifact\tsha256\ng:a:1\ta-1.aar\t' + b'0' * 64 + b'\n'
        self.origins['ARTIFACTS.tsv'] = 'original archive identities'
        original = 'classes.jar!META-INF/NOTICE.txt'
        notice = 'maven/g/a/1/' + hashlib.sha256(original.encode()).hexdigest() + '.txt'
        self.assets[notice] = b'upstream attribution\n'
        self.origins[notice] = 'g:a:1!' + original
        self.notice = notice
        self.apk = self.repo / 'app.apk'

    def write(self, *, omitted=(), altered=None, extra=None, index=None, duplicate=None):
        lines = ['sha256\tpath\torigin'] + [hashlib.sha256(data).hexdigest() + '\t' + name + '\t' + self.origins[name]
                                               for name, data in self.assets.items()]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.apk, 'w') as archive:
                archive.writestr('assets/licenses/INDEX.tsv', index or '\n'.join(lines) + '\n')
                for name, data in self.assets.items():
                    if name not in omitted:
                        archive.writestr('assets/licenses/' + name, (altered or {}).get(name, data))
                for name, data in (extra or {}).items():
                    archive.writestr('assets/licenses/' + name, data)
                if duplicate:
                    archive.writestr('assets/licenses/' + duplicate, self.assets[duplicate])

    def test_complete_assets_and_embedded_notice(self):
        self.write()
        result = check_apk(self.apk, self.repo)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['reviewed_maven_coordinates'], 1)
        self.assertEqual(result['embedded_notices'][0]['origin'], 'classes.jar!META-INF/NOTICE.txt')

    def test_missing_native_resource(self):
        name = next(name for name in self.assets if name.startswith('native-rust/files/'))
        self.write(omitted=[name])
        with self.assertRaisesRegex(ValueError, 'Missing legal asset'): check_apk(self.apk, self.repo)

    def test_native_resource_byte_drift(self):
        name = next(name for name in self.assets if name.startswith('native-rust/files/'))
        self.write(altered={name: b'tampered'})
        with self.assertRaisesRegex(ValueError, 'Canonical text/inventory drift'): check_apk(self.apk, self.repo)

    def test_missing_core_license(self):
        self.write(omitted=['AGPL-3.0.txt'])
        with self.assertRaisesRegex(ValueError, 'Missing legal asset'): check_apk(self.apk, self.repo)

    def test_missing_embedded_notice(self):
        self.write(omitted=[self.notice])
        with self.assertRaisesRegex(ValueError, 'Missing legal asset'): check_apk(self.apk, self.repo)

    def test_notice_hash_drift(self):
        self.write(altered={self.notice: b'tampered'})
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'): check_apk(self.apk, self.repo)

    def test_canonical_license_drift(self):
        self.write(altered={'MPL-2.0.txt': b'old license'})
        with self.assertRaisesRegex(ValueError, 'Canonical text/inventory drift'): check_apk(self.apk, self.repo)

    def test_duplicate_zip_entry(self):
        self.write(duplicate='AGPL-3.0.txt')
        with self.assertRaisesRegex(ValueError, 'Duplicate'): check_apk(self.apk, self.repo)

    def test_unindexed_notice(self):
        self.write(extra={'unexpected.txt': b'notice'})
        with self.assertRaisesRegex(ValueError, 'Unindexed'): check_apk(self.apk, self.repo)

    def test_index_traversal(self):
        self.write(index='sha256\tpath\torigin\n' + '0' * 64 + '\t../escape.txt\tupstream\n')
        with self.assertRaisesRegex(ValueError, 'Unsafe'): check_apk(self.apk, self.repo)

    def test_origin_path_binding(self):
        self.origins[self.notice] = 'g:a:1!another-notice.txt'
        self.write()
        with self.assertRaisesRegex(ValueError, 'origin/path mismatch'): check_apk(self.apk, self.repo)

    def test_inventory_drift(self):
        file = self.repo / 'qeli-android/gradle/licenses/maven-runtime.tsv'
        self.write()
        file.write_bytes(file.read_bytes().replace(b'g:a:1', b'g:a:2'))
        with self.assertRaisesRegex(ValueError, 'Canonical text/inventory drift'): check_apk(self.apk, self.repo)

    def test_unreviewed_license(self):
        file = self.repo / 'qeli-android/gradle/licenses/maven-runtime.tsv'
        file.write_bytes(file.read_bytes().replace(b'Apache-2.0', b'unknown'))
        self.write()
        with self.assertRaisesRegex(ValueError, 'Unreviewed'): check_apk(self.apk, self.repo)

    def test_oversized_notice(self):
        from check_android_licenses import MAX_ASSET
        self.write(altered={self.notice: b'x' * (MAX_ASSET + 1)})
        with self.assertRaisesRegex(ValueError, 'Oversized'): check_apk(self.apk, self.repo)


if __name__ == '__main__':
    unittest.main()
