"""CPU checks are target-specific and a failed disassembler never qualifies."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import linux_release_cpu as cpu
from test_linux_release import elf_fixture


class CpuTests(unittest.TestCase):
    def test_native_and_cross_objdump_selection(self):
        self.assertEqual(cpu.default_objdump('arm64','aarch64'),'objdump')
        self.assertEqual(cpu.default_objdump('arm64','x86_64'),'aarch64-linux-gnu-objdump')
        self.assertEqual(cpu.default_objdump('amd64','aarch64'),'x86_64-linux-gnu-objdump')

    def test_architecture_specific_crypto_and_cpu_probe(self):
        for arch,aes,probe in [('amd64','aesenc %xmm0,%xmm1','cpuid'),('arm64','aese v0.16b,v1.16b','bl <getauxval@plt>')]:
            with self.subTest(arch=arch):
                with self.assertRaises(ValueError):cpu.inspect_disassembly(['1000: '+aes],arch)
                self.assertEqual(cpu.inspect_disassembly(['1000: '+aes,'1004: '+probe],arch)['aes_instructions'],1)
                self.assertEqual(cpu.inspect_disassembly(['1000: ret'],arch)['aes_instructions'],0)

    def test_failed_or_missing_objdump_returns_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'qeli';binary.write_bytes(elf_fixture(machine=183))
            args=['--arch','arm64','--binary',str(binary)]
            for error in [FileNotFoundError('objdump'),subprocess.TimeoutExpired('objdump',120)]:
                with patch.object(cpu.subprocess,'run',side_effect=error),contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cpu.main(args),1)
            with patch.object(cpu.subprocess,'run',return_value=types.SimpleNamespace(returncode=17,stderr='bad architecture')),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cpu.main(args),1)

    def test_empty_success_output_is_not_a_cpu_baseline_pass(self):
        for arch in ['amd64','arm64']:
            with self.subTest(arch=arch),self.assertRaises(ValueError):cpu.inspect_disassembly(['file format elf64'],arch)


if __name__=='__main__':unittest.main()
