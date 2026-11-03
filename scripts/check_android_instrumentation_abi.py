#!/usr/bin/env python3
"""Verify runner Trace ABI and cross-package superclass access in packaged DEX.

Run after assembleRelease/assembleReleaseAndroidTest. R8 can remove application
library APIs referenced only by the separate test APK; a successful build alone
is insufficient. This check reads the actual packaged DEX, not source or mapping.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

TRACE = 'Landroidx/tracing/Trace;'
REQUIRED = {('beginSection', '(Ljava/lang/String;)V'),
            ('endSection', '()V'), ('forceEnableAppTracing', '()V')}


def dex_trace(data):
    assert data[:4] == b'dex\n' and len(data) >= 112
    def u32(at):return struct.unpack_from('<I', data, at)[0]
    assert u32(40) == 0x12345678
    def uleb(at):
        value = shift = 0
        while True:
            byte = data[at];at += 1;value |= (byte & 127) << shift
            if byte < 128:return value, at
            shift += 7
            assert shift <= 28
    strings = []
    for i in range(u32(56)):
        at = u32(u32(60) + i * 4);_, at = uleb(at)
        strings.append(data[at:data.index(b'\0', at)].decode('utf-8', errors='replace'))
    types = [strings[u32(u32(68) + i * 4)] for i in range(u32(64))]
    protos = []
    for i in range(u32(72)):
        at = u32(76) + i * 12;parameters = u32(at + 8)
        params = '' if not parameters else ''.join(types[struct.unpack_from('<H', data, parameters + 4 + j * 2)[0]] for j in range(u32(parameters)))
        protos.append('(' + params + ')' + types[u32(at + 4)])
    methods = []
    for i in range(u32(88)):
        owner, proto, name = struct.unpack_from('<HHI', data, u32(92) + i * 8)
        methods.append((types[owner], strings[name], protos[proto]))
    definitions = {};hierarchy = {}
    for i in range(u32(96)):
        at = u32(100) + i * 32
        superclass = u32(at + 8)
        hierarchy[types[u32(at)]] = (u32(at + 4), None if superclass == 0xffffffff else types[superclass])
        if types[u32(at)] != TRACE:continue
        encoded = u32(at + 24)
        if not encoded:continue
        counts = []
        for _ in range(4):value, encoded = uleb(encoded);counts.append(value)
        for count in counts[:2]:
            for _ in range(count):_, encoded = uleb(encoded);_, encoded = uleb(encoded)
        for count in counts[2:]:
            index = 0
            for _ in range(count):
                delta, encoded = uleb(encoded);index += delta
                access, encoded = uleb(encoded);code, encoded = uleb(encoded)
                _, name, signature = methods[index]
                definitions[(name, signature)] = bool(access & 1 and access & 8 and code)
    return definitions, {(name, signature) for owner, name, signature in methods if owner == TRACE}, hierarchy


def apk_trace(path):
    definitions = {};references = set();hierarchy = {}
    with zipfile.ZipFile(path) as apk:
        for name in apk.namelist():
            if name.startswith('classes') and name.endswith('.dex'):
                defined, referenced, classes = dex_trace(apk.read(name))
                if hierarchy.keys() & classes.keys():raise ValueError('Duplicate packaged DEX class')
                definitions.update(defined);references.update(referenced);hierarchy.update(classes)
    return definitions, references, hierarchy


def check(app, test):
    definitions, _, hierarchy = apk_trace(app)
    _, references, _ = apk_trace(test)
    missing = sorted(method for method in REQUIRED if not definitions.get(method))
    assert REQUIRED <= references, 'instrumentation no longer exercises the expected Trace ABI'
    inaccessible = [dict(child=child, parent=parent) for child, (_, parent) in sorted(hierarchy.items())
                    if parent in hierarchy and not hierarchy[parent][0] & 1
                    and child.rpartition('/')[0] != parent.rpartition('/')[0]]
    return dict(status='FAIL_PACKAGED_ABI' if missing or inaccessible else 'PASS',
                inaccessible_superclasses=inaccessible,
                missing=[name + signature for name, signature in missing],
                tested=[name + signature for name, signature in sorted(REQUIRED)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--test', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = check(args.app, args.test)
    text = json.dumps(result, indent=2) + '\n'
    if args.output:args.output.write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':raise SystemExit(main())