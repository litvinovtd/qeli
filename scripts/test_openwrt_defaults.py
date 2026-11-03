"""Execute package defaults with isolated paths and a fault-injectable UCI model.
This exercises shell control flow, not libuci, fw4 or rc.common integration.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELL = shlex.split(os.environ.get('QELI_OPENWRT_TEST_SHELL', '/bin/sh'))
UCI = r'''
import json, os, sys
from pathlib import Path
root = Path(os.environ['QELI_DEFAULTS_ROOT'])
args = sys.argv[1:]
if args[0] == '-q': args = args[1:]
verb, key = args[0], args[1] if len(args) > 1 else ''
state = json.loads((root / 'stage').read_text())
if verb == 'zones':
    print(' '.join(k for k,v in state.items() if v.get('type') == 'zone')); sys.exit(0)
if verb == 'load': sys.exit(19 if os.environ.get('QELI_FAIL') == 'load' else 0)
if verb == 'get':
    if key == 'qeli.main.dev': print(os.environ.get('QELI_DEV', 'qeli0')); sys.exit(0)
    bits = key.split('.')
    value = state.get(bits[1], {}).get('type' if len(bits) == 2 else bits[2])
    if value is None: sys.exit(1)
    print(' '.join(value) if isinstance(value, list) else value); sys.exit(0)
with (root / 'calls').open('a') as stream: stream.write(verb + ' ' + key + '\n')
fail = os.environ.get('QELI_FAIL', '')
if fail in (verb, key.split('=')[0]) and fail and not (root / 'failed-once').exists():
    (root / 'failed-once').touch(); sys.exit(17)
if verb == 'add':
    name = 'cfg' + str(len(state))
    state[name] = {'type': args[2]}
    (root / 'stage').write_text(json.dumps(state)); print(name); sys.exit(0)
if verb == 'commit':
    (root / 'disk').write_text(json.dumps(state)); sys.exit(0)
bits = key.split('=')[0].split('.')
section = state.setdefault(bits[1], {})
option = 'type' if len(bits) == 2 else bits[2]
if verb == 'delete': section.pop(option, None)
elif verb == 'add_list': section.setdefault(option, []).append(key.split('=',1)[1])
elif verb == 'set': section[option] = key.split('=',1)[1]
else: sys.exit(2)
(root / 'stage').write_text(json.dumps(state))
'''

@unittest.skipUnless(shutil.which(SHELL[0]), 'requires POSIX shell (Linux lab)')
class OpenWrtDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qeli-defaults-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'; self.bin.mkdir()
        for filename, body in {
            'uci': '#!' + sys.executable + '\n' + UCI,
            'logger': '#!/bin/sh\nexit 0\n',
        }.items():
            p = self.bin / filename; p.write_text(body); p.chmod(0o700)
        functions = self.root / 'functions.sh'
        functions.write_text('config_load() { uci load "$1"; }\n'
            'config_foreach() { for section in $(uci zones); do "$1" "$section"; done; }\n')
        firewall = self.root / 'firewall'
        firewall.write_text('#!/bin/sh\nprintf "reload\n" >> "$QELI_DEFAULTS_ROOT/calls"\n'
            'if [ "$QELI_FAIL" = reload ] && [ ! -f "$QELI_DEFAULTS_ROOT/failed-once" ]; then\n'
            'touch "$QELI_DEFAULTS_ROOT/failed-once"; exit 17; fi\nexit 0\n')
        firewall.chmod(0o700)
        source = (ROOT / 'qeli-openwrt/files/qeli.firewall.uci-defaults').read_text()
        source = source.replace('. /lib/functions.sh', '. ' + shlex.quote(str(functions)))
        source = source.replace('RUNDIR=/var/run/qeli', 'RUNDIR=' + shlex.quote(str(self.root / 'run')))
        source = source.replace('FIREWALL_INIT=/etc/init.d/firewall', 'FIREWALL_INIT=' + shlex.quote(str(firewall)))
        self.script = self.root / 'defaults'; self.script.write_text(source)
        self.env = dict(os.environ, QELI_DEFAULTS_ROOT=str(self.root),
            PATH=str(self.bin) + os.pathsep + os.environ['PATH'])
        self.seed({})

    def seed(self, state):
        for name in ('stage', 'disk'): (self.root / name).write_text(json.dumps(state))

    def run_defaults(self, **env):
        return subprocess.run(SHELL + [str(self.script)], env=dict(self.env, **env),
            capture_output=True, text=True, timeout=20)

    def state(self, name='stage'): return json.loads((self.root / name).read_text())
    def calls(self):
        p = self.root / 'calls'; return p.read_text() if p.exists() else ''
    def pending(self): return self.root / 'run/firewall-install-pending'
    def assert_complete(self):
        state = self.state('disk')
        self.assertEqual(set(state), {'qeli_package_zone', 'qeli_package_lan'})
        self.assertEqual(state['qeli_package_zone'], dict(type='zone', name='qeli', input='REJECT',
            output='ACCEPT', forward='REJECT', masq='1', masq6='1', mtu_fix='1', device=['qeli0']))
        self.assertEqual(state['qeli_package_lan'], dict(type='forwarding', src='lan', dest='qeli'))
        self.assertFalse(self.pending().exists())

    def test_fresh_install_and_second_run_do_not_duplicate_or_reload(self):
        result = self.run_defaults(); self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_complete(); calls = self.calls()
        self.assertEqual(self.run_defaults().returncode, 0)
        self.assertEqual(self.calls(), calls)

    def test_existing_administrator_zone_is_preserved(self):
        state = {'admin': dict(type='zone', name='qeli', input='ACCEPT', masq='0', device=['qeli9'])}
        self.seed(state)
        self.assertEqual(self.run_defaults().returncode, 0)
        self.assertEqual(self.state(), state); self.assertEqual(self.calls(), '')

    def test_each_mutation_commit_reload_failure_retains_marker_and_repairs(self):
        for failure in ('set', 'firewall.qeli_package_zone.input', 'add_list',
                        'firewall.qeli_package_lan.dest', 'commit', 'reload'):
            with self.subTest(failure=failure):
                self.seed({})
                for name in ('failed-once', 'calls'): (self.root / name).unlink(missing_ok=True)
                result = self.run_defaults(QELI_FAIL=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.pending().exists())
                self.assertEqual(self.pending().stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.pending().parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(self.run_defaults(QELI_FAIL=failure).returncode, 0)
                self.assert_complete()

    def test_delete_failure_after_reload_failure_is_not_ignored(self):
        self.assertNotEqual(self.run_defaults(QELI_FAIL='reload').returncode, 0)
        (self.root / 'failed-once').unlink()
        self.assertNotEqual(self.run_defaults(QELI_FAIL='delete').returncode, 0)
        self.assertTrue(self.pending().exists())
        self.assertEqual(self.run_defaults().returncode, 0); self.assert_complete()

    def test_partial_owned_sections_are_completed(self):
        self.seed({'qeli_package_zone': dict(type='zone', name='qeli', device=['old','qeli0'])})
        self.pending().parent.mkdir(); self.pending().touch(mode=0o600)
        self.assertEqual(self.run_defaults().returncode, 0); self.assert_complete()

    def test_reserved_collision_and_foreign_pending_sections_are_preserved(self):
        for pending, state in ((False, {'qeli_package_zone': dict(type='zone', name='custom')}),
                               (False, {'qeli_package_lan': dict(type='forwarding', dest='wan')}),
                               (True, {'admin': dict(type='zone', name='qeli')}),
                               (True, {'qeli_package_zone': dict(type='redirect')})):
            with self.subTest(pending=pending, state=state):
                self.seed(state); self.pending().unlink(missing_ok=True)
                if pending:
                    self.pending().parent.mkdir(exist_ok=True); self.pending().touch()
                self.assertNotEqual(self.run_defaults().returncode, 0)
                self.assertEqual(self.state(), state); self.assertEqual(self.calls(), '')

    def test_multiple_zones_invalid_device_and_config_load_fail_before_writes(self):
        for dev in ('eth0', 'qeli012345678901234', 'qeli;bad', 'qeli\npost_up=x'):
            self.assertNotEqual(self.run_defaults(QELI_DEV=dev).returncode, 0)
            self.assertEqual(self.calls(), '')
        self.assertNotEqual(self.run_defaults(QELI_FAIL='load').returncode, 0)
        self.seed({'a': dict(type='zone', name='qeli'), 'b': dict(type='zone', name='qeli')})
        self.assertNotEqual(self.run_defaults().returncode, 0); self.assertEqual(self.calls(), '')

    def test_marker_creation_failure_precedes_any_uci_mutation(self):
        (self.root / 'run').write_text('not a directory')
        self.assertNotEqual(self.run_defaults().returncode, 0); self.assertEqual(self.calls(), '')

    def test_image_preparation_without_firewall_service_can_complete(self):
        (self.root / 'firewall').unlink()
        self.assertEqual(self.run_defaults().returncode, 0); self.assert_complete()
        self.assertNotIn('reload', self.calls())

if __name__ == '__main__': unittest.main()
