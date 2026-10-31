import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import embedded_licenses
from license_lz4 import compress, decompress
from check_windows_embedded_licenses import bundled_assembly


ROOT = Path(__file__).resolve().parents[1]


class EmbeddedLicenseTests(unittest.TestCase):
    def test_committed_catalogue_matches_verified_original_inventory(self):
        actual = (ROOT / 'qeli/src/embedded_license_files.rs').read_text('utf8')
        self.assertEqual(actual, embedded_licenses.rust_catalogue(ROOT))
        self.assertEqual((ROOT / 'qeli/src/embedded_licenses.lz4').read_bytes(), embedded_licenses.rust_resources(ROOT)[1])

    def test_storage_codec_round_trip_boundaries_and_repetition(self):
        for data in (b'', b'a', bytes(range(256)), b'a' * 70000,
                     bytes(range(256)) * 300, b'original\r\n\xff' * 7000):
            packed = compress(data)
            self.assertEqual(compress(data), packed)
            self.assertEqual(decompress(packed, len(data)), data)
            with self.assertRaises(ValueError):
                decompress(packed, len(data) + 1)

    def test_storage_codec_rejects_malformed_data(self):
        for data in (b'\xf0', b'\x30a', b'\x00\x00\x00', b'\x00\x01\x00'):
            with self.assertRaises(ValueError):
                decompress(data, 10)

    def test_catalogue_order_is_explicit_across_host_path_flavours(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(embedded_licenses, 'check_bundle'):
            root = Path(directory)
            bundle = root / 'qeli/third-party-notices/rust'
            for name in ('B.txt', 'a/Z.txt', 'a/b.txt'):
                file = bundle / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'original')
            catalogue = embedded_licenses.rust_catalogue(root)
            names = ['rust/a/b.txt', 'rust/a/Z.txt', 'rust/B.txt']
            positions = [catalogue.index('"' + name + '"') for name in names]
            self.assertEqual(positions, sorted(positions))

    def test_export_verifier_keeps_exact_bytes_and_rejects_changes(self):
        expected = {'rust/license.txt': b'original\r\n\xff', 'rust/INDEX.tsv': b'index\n'}
        with tempfile.TemporaryDirectory() as directory, patch.object(embedded_licenses, 'expected_files', return_value=expected):
            root = Path(directory)
            for name, data in expected.items():
                file = root / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(data)
            self.assertEqual(embedded_licenses.verify_export(ROOT, root), 2)
            (root / 'rust/license.txt').write_bytes(b'normalized\n')
            with self.assertRaisesRegex(ValueError, 'changed='): embedded_licenses.verify_export(ROOT, root)
            (root / 'rust/license.txt').write_bytes(expected['rust/license.txt'])
            (root / 'extra').write_text('extra')
            with self.assertRaisesRegex(ValueError, 'extra='): embedded_licenses.verify_export(ROOT, root)
            (root / 'extra').unlink(); (root / 'rust/license.txt').unlink()
            with self.assertRaisesRegex(ValueError, 'missing='): embedded_licenses.verify_export(ROOT, root)

    def test_native_and_windows_original_inventories_include_licenses(self):
        native = embedded_licenses.expected_files(ROOT)
        windows = embedded_licenses.expected_files(ROOT, windows=True)
        self.assertGreater(len(native), 400)
        self.assertTrue(native.keys() <= windows.keys())
        for name, data in native.items(): self.assertEqual(data, windows[name])
        self.assertIn('drivers/Wintun-LICENSE.txt', windows)
        self.assertIn('drivers/WinDivert-LICENSE.txt', windows)
        self.assertIn('Qeli-MPL-2.0.txt', windows)

    def test_single_file_inspector_refuses_non_bundles(self):
        for data in (b'', b'MZ' + b'\0' * 4096):
            with self.assertRaises(ValueError): bundled_assembly(data)

    def test_cli_is_separate_from_network_startup(self):
        program = (ROOT / 'qeli-win/QeliWin/Program.cs').read_text('utf8')
        self.assertLess(program.index('EmbeddedLicenses.Run('), program.index('KillSwitch.Sweep('))
        main = (ROOT / 'qeli/src/main.rs').read_text('utf8')
        client = (ROOT / 'qeli/src/client_main.rs').read_text('utf8')
        self.assertLess(main.index('embedded_licenses::run('), main.index('qeli::logging::init('))
        self.assertLess(client.index('embedded_licenses::run('), client.index('peek_logging('))
        self.assertNotIn('mod embedded_licenses', (ROOT / 'qeli/src/lib.rs').read_text('utf8'))


if __name__ == '__main__': unittest.main()
