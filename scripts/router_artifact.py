"""Shared router ELF admission and verified pull; firmware/toolchain ABI is separate."""
import io
import struct
from native_lab import LabConnection, remote_sha256, pull_verified_artifact
from native_repro import sha256_bytes

TARGET_ELF = {
    'aarch64-unknown-linux-musl': (2, 183),
    'x86_64-unknown-linux-musl': (2, 62),
    'mipsel-unknown-linux-musl': (1, 8),
    'armv7-unknown-linux-musleabihf': (1, 40),
}

def validate_router_elf(data, target):
    """Require a bounded little-endian executable for the selected static target."""
    if target not in TARGET_ELF:
        raise ValueError(f'unsupported router target: {target!r}')
    elf_class, machine = TARGET_ELF[target]
    if len(data) < 16 or data[:4] != b'\x7fELF':
        raise RuntimeError('router artifact is not ELF')
    if data[4:7] != bytes((elf_class, 1, 1)) or data[7] not in (0, 3):
        raise RuntimeError('router ELF class/endianness/version/OSABI mismatch')
    header_format = '<16sHHIQQQIHHHHHH' if elf_class == 2 else '<16sHHIIIIIHHHHHH'
    header_size = struct.calcsize(header_format)
    if len(data) < header_size:
        raise RuntimeError('truncated router ELF header')
    header = struct.unpack_from(header_format, data)
    _, kind, found_machine, version, entry, phoff, _, flags, ehsize, phsize, phnum, _, _, _ = header
    if kind not in (2, 3) or found_machine != machine or version != 1 or ehsize != header_size:
        raise RuntimeError('router ELF executable type/machine/header mismatch')
    if target == 'armv7-unknown-linux-musleabihf' and (flags >> 24 != 5 or not flags & 0x400 or flags & 0x200):
        raise RuntimeError('router ARM ELF does not declare hard-float ABI')
    program_format = '<IIQQQQQQ' if elf_class == 2 else '<IIIIIIII'
    if phsize != struct.calcsize(program_format) or not 0 < phnum < 0xffff:
        raise RuntimeError('unsupported router ELF program-header layout')
    if phoff < header_size or phoff + phsize*phnum > len(data):
        raise RuntimeError('truncated router ELF program-header table')
    executable_entry = False
    for index in range(phnum):
        program = struct.unpack_from(program_format, data, phoff + index*phsize)
        if elf_class == 2:
            ptype, pflags, offset, vaddr, _, filesz, memsz, _ = program
        else:
            ptype, offset, vaddr, _, filesz, memsz, pflags, _ = program
        if offset + filesz > len(data) or (ptype == 1 and filesz > memsz):
            raise RuntimeError('truncated/inconsistent router ELF segment')
        if ptype == 3:
            raise RuntimeError('router ELF requires an external interpreter')
        if ptype == 1 and pflags & 1 and vaddr <= entry < vaddr + filesz:
            executable_entry = True
        if ptype == 2:
            dynamic_format = '<qQ' if elf_class == 2 else '<iI'
            size = struct.calcsize(dynamic_format)
            if filesz % size:
                raise RuntimeError('truncated router ELF dynamic table')
            terminated = False
            for position in range(offset, offset+filesz, size):
                tag, _ = struct.unpack_from(dynamic_format, data, position)
                if tag == 0:
                    terminated = True
                    break
                if tag == 1:
                    raise RuntimeError('router ELF requires a shared library')
            if not terminated:
                raise RuntimeError('unterminated router ELF dynamic table')
    if not executable_entry:
        raise RuntimeError('router ELF has no file-backed executable entry')
    return {'class': elf_class, 'machine': machine, 'type': kind,
            'endianness': 'little', 'external_interpreter': False, 'needed_libraries': False}


class _VerifiedSnapshot:
    def __init__(self, path, data):
        self.path, self.data = path, data

    def open(self, path, mode):
        if path != self.path or mode != 'rb':
            raise ValueError('unexpected router snapshot read')
        return io.BytesIO(self.data)


def pull_router_artifact(client, remote, target, repo_root, destination):
    """Validate the same SHA-bound snapshot published by the existing atomic owner."""
    digest = remote_sha256(LabConnection(client), remote)
    sftp = client.open_sftp()
    try:
        with sftp.open(remote, 'rb') as stream:
            data = stream.read()
    finally:
        sftp.close()
    if sha256_bytes(data) != digest:
        raise RuntimeError('router SFTP payload changed after SHA verification')
    metadata = validate_router_elf(data, target)
    size, actual, _ = pull_verified_artifact(
        _VerifiedSnapshot(remote, data), remote, digest, repo_root, [destination])
    print(f'router ELF admitted: {metadata}')
    return size, actual
