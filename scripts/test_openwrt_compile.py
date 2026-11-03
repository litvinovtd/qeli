"""Actual SDK Build/Compile macro with tiny real-Cargo musl fixtures.
Explicit QELI_OPENWRT_COMPILE_TEMPLATE and QELI_OPENWRT_COMPILER_ROOT are required.
The template is exported from the owned SDK, with owned host tool paths substituted.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

TEMPLATE = os.environ.get('QELI_OPENWRT_COMPILE_TEMPLATE', '')
RUN = os.environ.get('QELI_OPENWRT_COMPILER_ROOT', '')


@unittest.skipUnless(TEMPLATE and RUN and os.name == 'posix', 'requires owned SDK compiler fixture')
class CompileTests(unittest.TestCase):
    def setUp(self):
        self.run = Path(RUN).resolve()
        self.assertEqual(self.run.parent, Path("/var/tmp"))
        self.assertTrue(self.run.name.startswith(("qeli-q31-openwrt-compiler-", "qeli-sdk-")))
        self.assertEqual((self.run/'.qeli-compiler-audit').read_text().strip(), 'qeli-sdk-compiler-fixture-v1')
        self.root = Path(tempfile.mkdtemp(prefix='compile-case-', dir=self.run))
        self.addCleanup(shutil.rmtree, self.root)
        self.crate = self.root/'source/qeli'
        (self.crate/'src').mkdir(parents=True)
        self.manifest = self.crate/'Cargo.toml'
        self.manifest.write_text('[package]\nname="qeli-sdk-probe"\nversion="0.1.0"\nedition="2021"\n'
            '[features]\nclient-bin=[]\n[lib]\nname="qeli_probe"\n'
            'crate-type = ["rlib", "cdylib", "staticlib"]\n'
            '[[bin]]\nname="qeli-client"\npath="src/main.rs"\n')
        (self.crate/'src/lib.rs').write_text('pub fn receipt() -> u32 { 42 }\n')
        (self.crate/'src/main.rs').write_text('fn main() { println!("{}", qeli_probe::receipt()); }\n')
        self.tools = self.run/'rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin'
        self.bin = self.root/'bin'
        self.bin.mkdir()
        wrapper = self.bin/'cargo'
        wrapper.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$QELI_CARGO_RECEIPT"\n'
                           'exec "$QELI_REAL_CARGO" "$@"\n')
        wrapper.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.bin)+':'+str(self.tools)+':'+os.environ['PATH'],
            RUSTUP_HOME=str(self.run/'rustup'), CARGO_HOME=str(self.run/'cargo'),
            RUSTC=str(self.tools/'rustc'), RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='',
            CARGO_TARGET_DIR=str(self.root/'target'), CARGO_BUILD_BUILD_DIR=str(self.root/'target'),
            CARGO_INCREMENTAL='0', QELI_REAL_CARGO=str(self.tools/'cargo'),
            QELI_CARGO_RECEIPT=str(self.root/'cargo-calls'), LC_ALL='C')
        self.env.pop('CARGO_ENCODED_RUSTFLAGS', None)
        p = subprocess.run([str(self.tools/'cargo'), 'generate-lockfile', '--offline'],
                           cwd=self.crate, env=self.env, capture_output=True, timeout=20)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.script = Path(TEMPLATE).read_text().lstrip().removeprefix('+')
        self.assertIn('__QELI_SOURCE__', self.script)
        self.assertIn('__QELI_INSTALL__', self.script)
        self.script = self.script.replace('__QELI_SOURCE__', str(self.root/'source')).replace(
            '__QELI_INSTALL__', str(self.root/'install'))

    def compile(self, success):
        p = subprocess.run(['bash', '-c', self.script], cwd=self.run, env=self.env,
                           capture_output=True, timeout=60)
        (self.run/'logs'/f'{self.id().split(".")[-1]}.log').write_bytes(p.stdout+p.stderr)
        self.assertEqual(p.returncode == 0, success, (p.stdout+p.stderr).decode())
        return p

    def no_cargo(self):
        self.assertFalse((self.root/'cargo-calls').exists())

    def only_rlib(self):
        self.assertTrue((self.root/'install/usr/bin/qeli-client').is_file())
        outputs = list((self.root/'target').rglob('libqeli_probe*'))
        self.assertTrue(any(p.suffix == '.rlib' for p in outputs))
        self.assertFalse(any(p.suffix in ['.a', '.so'] for p in outputs), [p.name for p in outputs])
        self.assertEqual((self.root/'cargo-calls').read_text().splitlines(), ['metadata', 'install'])

    def test_default_manifest_builds_only_rlib_and_client(self):
        self.compile(True)
        self.only_rlib()

    def test_existing_rlib_manifest_builds_client(self):
        self.manifest.write_text(self.manifest.read_text().replace(
            '["rlib", "cdylib", "staticlib"]', '["rlib"]'))
        self.compile(True)
        self.only_rlib()

    def test_unknown_library_declaration_refuses_before_cargo(self):
        self.manifest.write_text(self.manifest.read_text().replace(
            '["rlib", "cdylib", "staticlib"]', '["rlib", "cdylib"]'))
        before = self.manifest.read_bytes()
        self.compile(False)
        self.no_cargo()
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_commented_or_suffixed_declaration_refuses_without_projection(self):
        self.manifest.write_text(self.manifest.read_text().replace(
            '["rlib", "cdylib", "staticlib"]', '["rlib", "cdylib", "staticlib"] # unsupported declaration'))
        before = self.manifest.read_bytes()
        self.compile(False)
        self.no_cargo()
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_missing_lock_refuses_before_projection(self):
        (self.crate/'Cargo.lock').unlink()
        before = self.manifest.read_bytes()
        self.compile(False)
        self.no_cargo()
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_missing_manifest_refuses_before_cargo(self):
        self.manifest.unlink()
        self.compile(False)
        self.no_cargo()


if __name__ == '__main__':
    unittest.main()
