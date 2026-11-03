'''Exercise universal assembly with real files and controlled lipo, plus opt-in LLVM fixtures.'''
import ast
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get('QELI_MAC_UNIVERSAL_SOURCE', Path(__file__).with_name('build_mac_universal.py')))
ARM_MAGIC = b'\xcf\xfa\xed\xfe'
FAT_MAGIC = b'\xca\xfe\xba\xbe'

def assembler():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8-sig'))
    source = next(node.value.value for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'REMOTE_PY' for t in node.targets))
    if '\ndef assemble(' not in source:
        # Adapt only the old fixed workspace/tool assignments to the owned fixture.
        source = source.replace('RDIR="/root/mac-build"', 'RDIR=root').replace('LIPO="/usr/bin/llvm-lipo-19"', 'LIPO=lipo')
        source = 'def assemble(root, lipo):\n' + textwrap.indent(source, '    ')
    namespace = {'__name__': 'qeli_assembly_fixture'}
    exec(compile(source, str(SOURCE) + ':REMOTE_PY', 'exec'), namespace)
    return namespace['assemble']

class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qeli-universal-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.arm = self.root / 'osx-arm64'; self.arm.mkdir()
        self.x64 = self.root / 'osx-x64'; self.x64.mkdir()
        self.write(self.arm / 'QeliMac', ['arm64'])
        self.write(self.x64 / 'QeliMac', ['x86_64'])
        self.write(self.arm / 'libqeli.dylib', ['arm64', 'x86_64'])
        self.write(self.x64 / 'libqeli.dylib', ['arm64', 'x86_64'])
        (self.arm / 'resource.txt').write_bytes(b'resource')
        self.marker = self.root / 'Qeli.app/old'
        self.marker.parent.mkdir(); self.marker.write_bytes(b'old bundle')
        self.failure = False; self.thin_output = False; self.calls = []
        self.assemble = assembler()

    def write(self, path, arches):
        path.write_bytes((FAT_MAGIC if len(arches) > 1 else ARM_MAGIC) + b'\n' + ' '.join(arches).encode())

    def run_tool(self, args, **kwargs):
        self.calls.append(args)
        rc = 0; output = b''
        if Path(args[0]).name == 'file':
            f = Path(args[-1])
            if f.exists() and f.read_bytes()[:4] in (ARM_MAGIC, FAT_MAGIC):
                output = b'Mach-O ' + (b'universal binary' if f.read_bytes()[:4] == FAT_MAGIC else b'64-bit')
        elif args[0] == 'fixture-lipo':
            if args[1] == '-archs':
                output = Path(args[2]).read_bytes().split(b'\n', 1)[1]
            elif args[1] == '-create':
                rc = 7 if self.failure else 0
                if not rc:
                    self.write(Path(args[-1]), ['arm64'] if self.thin_output else ['arm64', 'x86_64'])
            else:
                raise AssertionError(args)
        else:
            raise AssertionError(args)
        if rc and kwargs.get('check'):
            raise subprocess.CalledProcessError(rc, args, output=output, stderr=b'controlled lipo failure')
        if kwargs.get('text'):
            output = output.decode()
        return subprocess.CompletedProcess(args, rc, output, '' if kwargs.get('text') else b'')

    def invoke(self):
        with patch('subprocess.run', side_effect=self.run_tool):
            return self.assemble(str(self.root), 'fixture-lipo')

    def test_merges_paired_thin_binary_and_preserves_fat_core(self):
        native = (self.arm / 'libqeli.dylib').read_bytes()
        self.invoke()
        self.assertEqual((self.root / 'Qeli.app/Contents/MacOS/QeliMac').read_bytes()[:4], FAT_MAGIC)
        self.assertEqual((self.root / 'Qeli.app/Contents/MacOS/libqeli.dylib').read_bytes(), native)
        self.assertEqual((self.root / 'Qeli.app/Contents/MacOS/resource.txt').read_bytes(), b'resource')

    def test_already_universal_apphost_is_copied(self):
        self.write(self.arm / 'QeliMac', ['arm64', 'x86_64'])
        expected = (self.arm / 'QeliMac').read_bytes()
        self.invoke()
        self.assertEqual((self.root / 'Qeli.app/Contents/MacOS/QeliMac').read_bytes(), expected)
        self.assertFalse(any('-create' in c for c in self.calls))

    def test_legal_sidecars_are_resources_not_nested_code(self):
        for folder in (self.arm, self.x64):
            notice = folder / 'Legal/NativeRust/example/0.1.2/LICENSE'
            notice.parent.mkdir(parents=True)
            notice.write_bytes(b'license text')
        self.invoke()
        contents = self.root / 'Qeli.app/Contents'
        self.assertFalse((contents / 'MacOS/Legal').exists())
        self.assertEqual((contents / 'Resources/Legal/NativeRust/example/0.1.2/LICENSE').read_bytes(),
                         b'license text')

    def test_missing_x64_partner_refuses_before_output_replacement(self):
        (self.x64 / 'QeliMac').unlink()
        with self.assertRaises(Exception): self.invoke()
        self.assertEqual(self.marker.read_bytes(), b'old bundle')

    def test_rid_specific_managed_dll_is_refused_before_output_replacement(self):
        for folder, machine in ((self.arm, 0xaa64), (self.x64, 0x8664)):
            payload = bytearray(128)
            payload[:2] = b'MZ'
            struct.pack_into('<I', payload, 0x3c, 64)
            payload[64:68] = b'PE\x00\x00'
            struct.pack_into('<H', payload, 68, machine)
            (folder / 'QeliMac.dll').write_bytes(payload)
        with self.assertRaisesRegex(RuntimeError, 'architecture-specific .NET payload'):
            self.invoke()
        self.assertEqual(self.marker.read_bytes(), b'old bundle')

    def test_rid_specific_dependency_graph_is_refused_before_output_replacement(self):
        (self.arm / 'QeliMac.deps.json').write_text('{"runtimeTarget":"osx-arm64"}')
        (self.x64 / 'QeliMac.deps.json').write_text('{"runtimeTarget":"osx-x64"}')
        with self.assertRaisesRegex(RuntimeError, 'architecture-specific .NET payload'):
            self.invoke()
        self.assertEqual(self.marker.read_bytes(), b'old bundle')

    def test_missing_managed_partner_is_refused_in_either_inventory(self):
        for folder in (self.arm, self.x64):
            with self.subTest(folder=folder.name):
                path = folder / 'OnlyOne.dll'
                path.write_bytes(b'managed')
                try:
                    with self.assertRaisesRegex(RuntimeError, 'architecture-specific .NET payload'):
                        self.invoke()
                    self.assertEqual(self.marker.read_bytes(), b'old bundle')
                finally:
                    path.unlink()

    def test_identical_portable_managed_payload_can_be_copied(self):
        for folder in (self.arm, self.x64):
            (folder / 'Portable.dll').write_bytes(b'portable IL fixture')
            (folder / 'QeliMac.deps.json').write_bytes(b'{"portable":true}')
        self.invoke()
        self.assertEqual((self.root / 'Qeli.app/Contents/MacOS/Portable.dll').read_bytes(),
                         b'portable IL fixture')

    def test_lipo_failure_is_not_replaced_with_arm64(self):
        self.failure = True
        with self.assertRaises(Exception): self.invoke()
        self.assertFalse((self.root / 'Qeli.app/Contents/MacOS/QeliMac').exists())

    def test_successful_lipo_with_thin_output_is_refused(self):
        self.thin_output = True
        with self.assertRaises(Exception): self.invoke()

    def test_native_core_must_already_be_universal(self):
        self.write(self.arm / 'libqeli.dylib', ['arm64'])
        with self.assertRaises(Exception): self.invoke()
        self.assertEqual(self.marker.read_bytes(), b'old bundle')

    def test_missing_required_native_core_is_refused(self):
        (self.arm / 'libqeli.dylib').unlink()
        with self.assertRaises(Exception): self.invoke()
        self.assertEqual(self.marker.read_bytes(), b'old bundle')

    def test_x64_only_macho_is_not_silently_omitted(self):
        self.write(self.x64 / 'IntelOnly.dylib', ['x86_64'])
        with self.assertRaises(Exception): self.invoke()
        self.assertEqual(self.marker.read_bytes(), b'old bundle')

    def test_fat_file_without_x64_slice_is_refused(self):
        self.write(self.arm / 'QeliMac', ['arm64', 'armv7'])
        with self.assertRaises(Exception): self.invoke()
        self.assertEqual(self.marker.read_bytes(), b'old bundle')


if __name__ == '__main__':
    unittest.main()
