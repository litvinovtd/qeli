#!/usr/bin/env python3
"""Independently check Rust-generated HKDF wire vectors with Python's stdlib HMAC."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path

SCHEMES = {
    'classic': (b'qeli-key-derivation-v1', ('shared_secret',)),
    'hybrid': (b'qeli-key-derivation-v2-hybrid', ('x25519_shared', 'mlkem_shared')),
    'bound': (b'qeli-key-derivation-v1-static-bound', ('ee', 'es')),
    'hybrid-bound': (b'qeli-key-derivation-v2-hybrid-static-bound', ('x25519_shared', 'mlkem_shared', 'es')),
}

def expand(ikm, salt, label):
    prk = hmac.digest(salt, ikm, 'sha256')
    # Every directional key is exactly one SHA-256 HKDF-Expand block.
    return hmac.digest(prk, label + b'\x01', 'sha256')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, default=Path(__file__).resolve().parent.parent/'conformance/hkdf.json')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    raw = args.fixture.read_bytes()
    fixture = json.loads(raw)
    checks = []
    covered = set()
    for case in fixture['cases']:
        salt, fields = SCHEMES[case['scheme']]
        covered.add(case['scheme'])
        parts = [bytes.fromhex(case['inputs'][field]) for field in fields]
        assert all(len(part) == 32 for part in parts)
        ikm = b''.join(parts)
        outputs = []
        for direction in ['server_to_client', 'client_to_server']:
            label = direction.replace('_', '-').encode() + b'-enc-key'
            actual = expand(ikm, salt, label)
            assert actual.hex() == case['expect'][direction], (case['name'], direction)
            checks.append(case['name'] + ':' + direction)
            outputs.append(actual)
        assert outputs[0] != outputs[1]
        altered = bytes([ikm[0] ^ 1]) + ikm[1:]
        assert expand(altered, salt, b'server-to-client-enc-key') != outputs[0]
        checks.append(case['name'] + ':direction/input separation')
        if len(parts) > 1 and len(set(parts)) > 1:
            assert expand(b''.join(reversed(parts)), salt, b'server-to-client-enc-key') != outputs[0]
            checks.append(case['name'] + ':input order')
    assert covered == set(SCHEMES), 'all four wire schemes must be covered'
    result = dict(status='PASS', fixture_sha256=hashlib.sha256(raw).hexdigest(), cases=len(fixture['cases']), checks_passed=len(checks), checks=checks, implementation='Python stdlib HMAC-SHA256; no Rust generator or crypto helper calls', scope='Wire derivation consistency and separation checks, not independent primitive/security certification')
    if args.output:
        args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print('PASS independent HKDF crosscheck:', result['cases'], 'vectors,', result['checks_passed'], 'checks')

if __name__ == '__main__':
    main()
