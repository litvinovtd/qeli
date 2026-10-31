#!/usr/bin/env python3
"""Architecture-specific CPU-baseline heuristic, complementing ELF ABI admission.

Like the former x86 awk check, this is not a proof of every runtime CPU path.
AES instructions require retained CPU detection: CPUID on amd64, HWCAP/getauxval
on Linux arm64. Tool errors fail closed; cross builds need a matching objdump.
"""
import argparse
import platform
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from linux_release import ARCH_MACHINES, verify_binary


def default_objdump(arch, host=None):
    host = platform.machine().lower() if host is None else host.lower()
    native = (arch == "amd64" and host in ("x86_64", "amd64")) or (arch == "arm64" and host in ("aarch64", "arm64"))
    return "objdump" if native else {"amd64": "x86_64-linux-gnu-objdump", "arm64": "aarch64-linux-gnu-objdump"}[arch]


def inspect_disassembly(lines, arch):
    aes = re.compile(r"\b(?:aesenc|aesenclast|aesdec|aesdeclast|aeskeygenassist|aesimc)\b" if arch == "amd64" else r"\b(?:aese|aesd|aesmc|aesimc)\b")
    detection = re.compile(r"\bcpuid\b" if arch == "amd64" else r"\bgetauxval\b")
    count, probes, instructions = 0, 0, 0
    for line in lines:
        instructions += bool(re.match(r"\s*[0-9a-fA-F]+:", line))
        count += bool(aes.search(line))
        probes += bool(detection.search(line))
    if not instructions:
        raise ValueError("objdump produced no disassembled instructions")
    if count and not probes:
        raise ValueError(f"{arch}: AES instructions with no retained CPU detection; remove forced CPU/crypto target features")
    return dict(arch=arch, aes_instructions=count, cpu_probe_references=probes)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--arch", required=True, choices=tuple(ARCH_MACHINES))
    parser.add_argument("--objdump", help="Cross objdump or llvm-objdump executable")
    args = parser.parse_args(argv)
    try:
        verify_binary(args.binary, args.arch)
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
            result = subprocess.run([args.objdump or default_objdump(args.arch), "-d", str(args.binary)],
                                    stdout=output, stderr=subprocess.PIPE, text=True, timeout=120)
            if result.returncode:
                raise ValueError("objdump failed: " + result.stderr[-1000:])
            output.seek(0)
            print(inspect_disassembly(output, args.arch))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
