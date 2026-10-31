"""Portable release admission regressions; no execution of candidate binaries."""
import contextlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

import linux_release as gate


def elf_fixture(version='GLIBC_2.28', tag=gate.ALLOCATOR_TAG, tag_section='.qeli.alloc', machine=62):
    names = b'\0.shstrtab\0.dynstr\0.gnu.version_r\0'+tag_section.encode()+b'\0'
    strings = b'\0libc.so.6\0'+version.encode()+b'\0'
    need = struct.pack('<HHIII',1,1,1,16,0)+struct.pack('<IHHII',0,0,2,11,0)
    blobs = [b'', names, strings, need, tag]
    labels = ['', '.shstrtab', '.dynstr', '.gnu.version_r', tag_section]
    data = bytearray(64);data[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI',data,16,3,machine,1)
    headers = []
    for index, body in enumerate(blobs):
        offset=len(data);data.extend(body)
        headers.append((names.index(labels[index].encode()+b'\0') if index else 0,
                        [0,3,3,0x6ffffffe,1][index],2 if index==4 else 0,0,offset,len(body),2 if index==3 else 0,0,1,0))
    shoff=len(data)
    for row in headers:data.extend(struct.pack('<IIQQQQIIQQ',*row))
    struct.pack_into('<Q',data,40,shoff);struct.pack_into('<HHH',data,58,64,5,1)
    return bytes(data)


def deb_fixture(binary, arch=None):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:xz') as archive:
        item=tarfile.TarInfo('./usr/bin/qeli');item.size=len(binary);item.mode=0o755
        archive.addfile(item,io.BytesIO(binary))
    data=output.getvalue()
    arch=arch or ('arm64' if len(binary)>20 and struct.unpack_from('<H',binary,18)[0]==183 else 'amd64')
    control=f'Package: qeli\nVersion: 0.8.4\nArchitecture: {arch}\n'.encode()
    metadata=io.BytesIO()
    with tarfile.open(fileobj=metadata,mode='w:xz') as archive:
        item=tarfile.TarInfo('./control');item.size=len(control);archive.addfile(item,io.BytesIO(control))
    def member(name,body):
        header=f"{name+'/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode()
        return header+body+(b'\n' if len(body)%2 else b'')
    return b'!<arch>\n'+member('debian-binary',b'2.0\n')+member('control.tar.xz',metadata.getvalue())+member('data.tar.xz',data)


class LinuxReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_accepts_glibc_floor_and_jemalloc(self):
        result=gate.verify_elf(elf_fixture())
        self.assertEqual(result['max_glibc'],'2.28');self.assertEqual(result['allocator'],'jemalloc')

    def test_all_versions_above_floor_rejected_even_with_allocator(self):
        for value in ['GLIBC_2.29','GLIBC_2.34','GLIBC_2.39','GLIBC_2.100','GLIBC_PRIVATE','GLIBC_ABI_DT_RELR']:
            with self.subTest(value=value),self.assertRaises(ValueError):gate.verify_elf(elf_fixture(value))

    def test_lower_glibc_is_compatible(self):
        self.assertEqual(gate.verify_elf(elf_fixture('GLIBC_2.17'))['max_glibc'],'2.17')

    def test_text_license_or_rodata_is_not_allocator_proof(self):
        for tag,section in [(b'glibc malloc','.qeli.alloc'),(gate.ALLOCATOR_TAG,'.rodata'),(b'','.qeli.alloc')]:
            with self.subTest(section=section,tag=tag),self.assertRaises(ValueError):gate.verify_elf(elf_fixture(tag=tag,tag_section=section))

    def test_missing_version_requirements_rejected(self):
        with self.assertRaisesRegex(ValueError,'no glibc'):gate.verify_elf(elf_fixture('GCC_4.2.0'))

    def test_wrong_arch_format_and_truncation_fail_closed(self):
        for blob in [b'',b'#!/bin/sh\n',b'jemalloc GLIBC_2.28',elf_fixture(machine=40),elf_fixture()[:-20]]:
            with self.subTest(size=len(blob)),self.assertRaises(ValueError):gate.verify_elf(blob)

    def test_out_of_bounds_section_fails(self):
        blob=bytearray(elf_fixture());struct.pack_into('<Q',blob,40,len(blob)+1)
        with self.assertRaises(ValueError):gate.verify_elf(bytes(blob))

    def test_invalid_version_chain_fails(self):
        blob=bytearray(elf_fixture());offset=blob.index(struct.pack('<HHIII',1,1,1,16,0))
        struct.pack_into('<I',blob,offset+12,1)
        with self.assertRaises(ValueError):gate.verify_elf(bytes(blob))

    def test_deb_payload_is_checked_without_extraction(self):
        path=self.root/'qeli_0.8.4_amd64.deb';path.write_bytes(deb_fixture(elf_fixture()))
        self.assertEqual(gate.verify_deb(path)['allocator'],'jemalloc')
        path.write_bytes(deb_fixture(elf_fixture('GLIBC_2.39')))
        with self.assertRaisesRegex(ValueError,'2.39'):gate.verify_deb(path)

    def test_invalid_and_truncated_deb_rejected(self):
        path=self.root/'bad.deb'
        for blob in [b'package',b'!<arch>\n',deb_fixture(elf_fixture())[:-1]]:
            path.write_bytes(blob)
            with self.assertRaises(ValueError):gate.verify_deb(path)

    def test_assets_require_same_binary_and_package_payload(self):
        (self.root/'qeli-linux-amd64').write_bytes(elf_fixture())
        package=self.root/'qeli_0.8.4_amd64.deb';package.write_bytes(deb_fixture(elf_fixture()))
        self.assertEqual(len(gate.verify_assets(self.root)),2)
        package.write_bytes(deb_fixture(elf_fixture('GLIBC_2.17')))
        with self.assertRaisesRegex(ValueError,'different builds'):gate.verify_assets(self.root)

    def test_real_cli_rejects_non_elf_with_nonzero_exit(self):
        path=self.root/'qeli';path.write_bytes(b'fake')
        result=subprocess.run([sys.executable,gate.__file__,'--binary',str(path)],capture_output=True)
        self.assertEqual(result.returncode,1)

    def test_cli_accepts_real_file_and_reports_hash(self):
        path=self.root/'qeli';path.write_bytes(elf_fixture())
        with contextlib.redirect_stdout(io.StringIO()) as output:self.assertEqual(gate.main(['--binary',str(path)]),0)
        self.assertEqual(json.loads(output.getvalue())['result']['allocator'],'jemalloc')

    def test_missing_input_returns_failure(self):
        with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(gate.main(['--binary',str(self.root/'missing')]),1)

    def test_shipping_routes_use_shared_gate(self):
        root=Path(__file__).resolve().parents[1]
        make=(root/'qeli/debian/Makefile').read_text()
        self.assertIn('deb: deb-portable',make);self.assertIn('stage: check-abi',make)
        self.assertIn('override GLIBC_ABI := 2.28',make)
        self.assertIn('override ZIG_TARGET := $(RUST_TARGET).2.28',make)
        self.assertIn('override RUST_TARGET := aarch64-unknown-linux-gnu',make)
        self.assertNotIn('cargo build --locked --release',make)
        self.assertIn('linux_release.py --binary',make)
        self.assertIn('linux_release.py --deb "$(DEB_DIR).deb"',make)
        for name in ['.github/workflows/ci.yml','.github/workflows/release-attest.yml']:
            self.assertIn('linux_release.py --', (root/name).read_text())

    def test_arm64_has_same_abi_and_allocator_requirements(self):
        self.assertEqual(gate.verify_elf(elf_fixture(machine=183),'arm64')['arch'],'arm64')
        for version in ['GLIBC_2.29','GLIBC_2.39']:
            with self.subTest(version=version),self.assertRaises(ValueError):gate.verify_elf(elf_fixture(version,machine=183),'arm64')
        with self.assertRaises(ValueError):gate.verify_elf(elf_fixture(machine=183,tag=b'glibc malloc'),'arm64')

    def test_expected_architecture_cannot_be_satisfied_by_renaming_binary(self):
        for machine,expected in [(62,'arm64'),(183,'amd64')]:
            with self.subTest(expected=expected),self.assertRaises(ValueError):gate.verify_elf(elf_fixture(machine=machine),expected)

    def test_named_binary_is_checked_even_without_explicit_arch(self):
        path=self.root/'qeli-linux-arm64';path.write_bytes(elf_fixture())
        with self.assertRaisesRegex(ValueError,'architecture'):gate.verify_binary(path)
        path.write_bytes(elf_fixture(machine=183))
        self.assertEqual(gate.verify_binary(path)['arch'],'arm64')
        with self.assertRaisesRegex(ValueError,'architecture'):gate.verify_binary(path,'amd64')

    def test_arm64_deb_control_filename_and_elf_must_agree(self):
        path=self.root/'qeli_0.8.4_arm64.deb'
        path.write_bytes(deb_fixture(elf_fixture(machine=183)))
        self.assertEqual(gate.verify_deb(path,'arm64')['arch'],'arm64')
        for binary,arch in [(elf_fixture(),'arm64'),(elf_fixture(machine=183),'amd64')]:
            path.write_bytes(deb_fixture(binary,arch))
            with self.subTest(arch=arch),self.assertRaises(ValueError):gate.verify_deb(path)

    def test_both_architectures_coexist_but_each_pair_must_match(self):
        for arch,machine in [('amd64',62),('arm64',183)]:
            blob=elf_fixture(machine=machine)
            (self.root/('qeli-linux-'+arch)).write_bytes(blob)
            (self.root/f'qeli_0.8.4_{arch}.deb').write_bytes(deb_fixture(blob))
        self.assertEqual(len(gate.verify_assets(self.root)),4)
        (self.root/'qeli-linux-arm64').write_bytes(elf_fixture())
        with self.assertRaisesRegex(ValueError,'architecture'):gate.verify_assets(self.root)

    def test_same_architecture_different_arm64_payloads_rejected(self):
        (self.root/'qeli-linux-arm64').write_bytes(elf_fixture(machine=183))
        (self.root/'qeli_0.8.4_arm64.deb').write_bytes(deb_fixture(elf_fixture('GLIBC_2.17',machine=183)))
        with self.assertRaisesRegex(ValueError,'different builds'):gate.verify_assets(self.root)

    def test_ci_and_publisher_include_both_native_architectures(self):
        root=Path(__file__).resolve().parents[1]
        ci=(root/'.github/workflows/ci.yml').read_text().split('  deb-package:',1)[1].split('  shellcheck:',1)[0]
        release=(root/'.github/workflows/release-attest.yml').read_text()
        for source in [ci,release]:
            self.assertIn('arch: amd64',source);self.assertIn('arch: arm64',source)
            self.assertIn('runner: ubuntu-24.04-arm',source)
            self.assertIn('ARCH=${{ matrix.arch }}',source)
        self.assertIn('qeli-linux-${{ matrix.arch }}',ci)
        self.assertIn('qeli-candidate-linux-${{ matrix.arch }}-',ci)
        publisher=release.split('  publish-linux:',1)[1]
        self.assertIn('needs: linux-package',publisher)
        self.assertIn('for arch in amd64 arm64',publisher)
        self.assertIn('--name "qeli-linux-built-$arch"',publisher)
        self.assertEqual(release.count('gh release upload'),1)


if __name__=='__main__':unittest.main()
