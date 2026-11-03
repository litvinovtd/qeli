"""Router metadata tests; generated ELF fixtures are not firmware/runtime qualification."""
import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
import router_artifact as artifact
from native_repro import sha256_bytes


def elf_fixture(target='aarch64-unknown-linux-musl', kind=2, extra=0):
    cls, machine = artifact.TARGET_ELF[target]
    fmt = '<16sHHIQQQIHHHHHH' if cls == 2 else '<16sHHIIIIIHHHHHH'
    phfmt = '<IIQQQQQQ' if cls == 2 else '<IIIIIIII'
    hsize, psize = struct.calcsize(fmt), struct.calcsize(phfmt)
    count = 1 + bool(extra)
    offset = hsize + psize*count
    ident = b'\x7fELF' + bytes((cls, 1, 1, 0)) + bytes(8)
    flags = 0x05000400 if 'armv7' in target else 0
    body = struct.pack('<qQ' if cls == 2 else '<iI', 0, 0) if extra == 2 else b'\x90'
    size = offset+len(body)
    header = struct.pack(fmt, ident, kind, machine, 1, 0x10000+offset, hsize,
                         0, flags, hsize, psize, count, 0, 0, 0)
    def ph(ptype, at, filesz, perms):
        if cls == 2:
            return struct.pack(phfmt, ptype, perms, at, 0x10000+at, 0, filesz, filesz, 1)
        return struct.pack(phfmt, ptype, at, 0x10000+at, 0, filesz, filesz, perms, 1)
    return header+ph(1, 0, size, 5)+(ph(extra, offset, len(body), 4) if extra else b'')+body


class RouterElfTests(unittest.TestCase):
    def test_all_targets_accept_static_exec_and_static_pie(self):
        for target in artifact.TARGET_ELF:
            for kind in (2, 3):
                with self.subTest(target=target, kind=kind):
                    self.assertEqual(artifact.validate_router_elf(elf_fixture(target, kind), target)['type'], kind)

    def test_unknown_target_nonelf_and_short_headers_fail(self):
        with self.assertRaises(ValueError):artifact.validate_router_elf(b'', 'unknown')
        for data in (b'', b'fixture ELF', b'\x7fELF', elf_fixture()[:40]):
            with self.subTest(length=len(data)), self.assertRaises(RuntimeError):
                artifact.validate_router_elf(data, 'aarch64-unknown-linux-musl')

    def test_target_machine_class_byte_order_and_version_fail(self):
        for at, value in ((4,1),(5,2),(6,2),(7,255),(18,62),(20,0),(16,1)):
            b=bytearray(elf_fixture());b[at]=value
            with self.subTest(at=at), self.assertRaises(RuntimeError):
                artifact.validate_router_elf(b, 'aarch64-unknown-linux-musl')

    def test_wrong_arch_binary_is_rejected_even_with_valid_sha(self):
        data=elf_fixture('x86_64-unknown-linux-musl')
        with self.assertRaisesRegex(RuntimeError,'machine'):
            artifact.validate_router_elf(data,'aarch64-unknown-linux-musl')

    def test_program_header_bounds_and_size_fail(self):
        for at, fmt, value in ((32,'Q',10000),(54,'H',55),(56,'H',0),(56,'H',0xffff)):
            b=bytearray(elf_fixture());struct.pack_into('<'+fmt,b,at,value)
            with self.subTest(at=at,value=value), self.assertRaises(RuntimeError):
                artifact.validate_router_elf(b,'aarch64-unknown-linux-musl')

    def test_segment_bounds_memory_and_executable_entry_fail(self):
        for at, value in ((64+8,10000),(64+32,10000),(64+40,0),(24,0)):
            b=bytearray(elf_fixture());struct.pack_into('<Q',b,at,value)
            with self.subTest(at=at), self.assertRaises(RuntimeError):
                artifact.validate_router_elf(b,'aarch64-unknown-linux-musl')
        b=bytearray(elf_fixture());struct.pack_into('<I',b,64+4,4)
        with self.assertRaisesRegex(RuntimeError,'entry'):
            artifact.validate_router_elf(b,'aarch64-unknown-linux-musl')

    def test_external_interpreter_is_rejected(self):
        for target in artifact.TARGET_ELF:
            with self.subTest(target=target), self.assertRaisesRegex(RuntimeError,'interpreter'):
                artifact.validate_router_elf(elf_fixture(target,extra=3),target)

    def test_no_dependency_static_dynamic_table_passes(self):
        for target in artifact.TARGET_ELF:
            artifact.validate_router_elf(elf_fixture(target,kind=3,extra=2),target)

    def test_needed_unterminated_and_partial_dynamic_tables_fail(self):
        for tag in (1,2):
            b=bytearray(elf_fixture(extra=2));struct.pack_into('<q',b,len(b)-16,tag)
            with self.subTest(tag=tag), self.assertRaises(RuntimeError):
                artifact.validate_router_elf(b,'aarch64-unknown-linux-musl')
        b=bytearray(elf_fixture(extra=2));struct.pack_into('<Q',b,64+56+32,15)
        with self.assertRaisesRegex(RuntimeError,'dynamic'):
            artifact.validate_router_elf(b,'aarch64-unknown-linux-musl')

    def test_arm_hard_float_flags_are_required(self):
        for flags in (0,0x400,0x05000200,0x05000600):
            b=bytearray(elf_fixture('armv7-unknown-linux-musleabihf'));struct.pack_into('<I',b,36,flags)
            with self.subTest(flags=flags), self.assertRaisesRegex(RuntimeError,'hard-float'):
                artifact.validate_router_elf(b,'armv7-unknown-linux-musleabihf')


class RouterPullTests(unittest.TestCase):
    def perform(self,data,digest=None,close_error=False,read_error=False,cached=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);dest=root/'out';dest.write_bytes(data if cached else b'previous')
            sf=Mock();sf.open.side_effect=IOError('read failed') if read_error else lambda *a:io.BytesIO(data)
            if close_error:sf.close.side_effect=IOError('close failed')
            client=Mock();client.open_sftp.return_value=sf
            with patch.object(artifact,'remote_sha256',return_value=digest or sha256_bytes(data)),contextlib.redirect_stdout(io.StringIO()):
                try:
                    result=artifact.pull_router_artifact(client,'/owned/ELF','aarch64-unknown-linux-musl',root,'out')
                except Exception as error:
                    return error,dest.read_bytes(),sf
                return result,dest.read_bytes(),sf

    def test_valid_snapshot_is_published_and_sftp_read_once(self):
        data=elf_fixture();result,published,sf=self.perform(data)
        self.assertEqual(result,(len(data),sha256_bytes(data)));self.assertEqual(published,data)
        sf.open.assert_called_once();sf.close.assert_called_once()

    def test_checksum_mismatch_retains_previous_and_cached_copy(self):
        for cached in (False,True):
            result,published,sf=self.perform(elf_fixture(),digest='a'*64,cached=cached)
            self.assertIsInstance(result,RuntimeError)
            self.assertEqual(published,elf_fixture() if cached else b'previous');sf.close.assert_called_once()

    def test_wrong_elf_valid_hash_never_replaces_previous(self):
        for data in (b'fixture ELF',elf_fixture('x86_64-unknown-linux-musl')):
            result,published,sf=self.perform(data)
            self.assertIsInstance(result,RuntimeError);self.assertEqual(published,b'previous');sf.close.assert_called_once()

    def test_sftp_read_and_close_failures_never_publish(self):
        for kwargs in ({'read_error':True},{'close_error':True}):
            result,published,sf=self.perform(elf_fixture(),**kwargs)
            self.assertIsInstance(result,IOError);self.assertEqual(published,b'previous');sf.close.assert_called_once()

    def test_valid_cached_copy_still_validates_one_remote_snapshot(self):
        result,published,sf=self.perform(elf_fixture(),cached=True)
        self.assertIsInstance(result,tuple);self.assertEqual(published,elf_fixture())
        sf.open.assert_called_once()

    def test_snapshot_admits_only_exact_path_and_read_mode(self):
        snapshot=artifact._VerifiedSnapshot('/owned',b'bytes')
        for path,mode in (('/other','rb'),('/owned','wb')):
            with self.assertRaises(ValueError):snapshot.open(path,mode)

if __name__=='__main__':unittest.main()
