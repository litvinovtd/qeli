"""Run a saved upstream rc.common dispatcher with fixture-only UCI/procd adapters.
Provide QELI_OPENWRT_RC_COMMON_FIXTURE; the recorded upstream snapshot hash is required.
No actual rpcd/procd/firewall/rc.d or /etc changes. Tests without the snapshot skip.
"""
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELL = shlex.split(os.environ.get('QELI_OPENWRT_TEST_SHELL', '/bin/sh'))
SNAPSHOT = os.environ.get('QELI_OPENWRT_RC_COMMON_FIXTURE', '')
EXPECTED_SHA256 = 'dd8ae95c78d10cccf78cb487874f163ace4c1ee14dace05fe28393b19ba639e4'
FUNCTIONS = r'''
logger() { :; }
config_load() {
    qeli_fixture_loads=$((${qeli_fixture_loads:-0} + 1))
    printf 'load:%s\n' "$1" >> "$QELI_FIXTURE_ROOT/calls"
    [ "$qeli_fixture_loads" != "$QELI_FIXTURE_LOAD_FAILURE" ]
}
config_get_bool() { export "$1=${QELI_FIXTURE_ENABLED:-0}"; }
uci() { return 1; }
list_contains() { case " $ALL_COMMANDS " in *" $2 "*) return 0 ;; *) return 1 ;; esac; }
'''
PROCD = r'''
procd_lock() { :; }
procd_open_service() { printf 'open\n' >> "$QELI_FIXTURE_ROOT/calls"; }
procd_close_service() { printf 'close\n' >> "$QELI_FIXTURE_ROOT/calls"; }
procd_kill() { printf 'kill\n' >> "$QELI_FIXTURE_ROOT/calls"; }
'''

@unittest.skipUnless(SNAPSHOT and shutil.which(SHELL[0]), 'requires saved rc.common snapshot and POSIX shell')
class OpenWrtDispatchTests(unittest.TestCase):
    def setUp(self):
        data = Path(SNAPSHOT).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), EXPECTED_SHA256)
        self.temp = tempfile.TemporaryDirectory(prefix='qeli-rc-dispatch-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        functions = self.root/'lib/functions.sh';functions.parent.mkdir()
        functions.write_text(FUNCTIONS)
        folder = self.root/'lib/functions';folder.mkdir()
        (folder/'service.sh').write_text('')
        (folder/'procd.sh').write_text(PROCD)
        self.rc = self.root/'rc.common';self.rc.write_bytes(data)
        (self.root/'run').mkdir()
        source = (ROOT/'qeli-openwrt/files/qeli.init').read_text()
        source = source.replace('RUNDIR=/var/run/qeli', 'RUNDIR='+shlex.quote(str(self.root/'run')))
        self.init = self.root/'qeli';self.init.write_text(source)
        self.env = dict(os.environ, IPKG_INSTROOT=str(self.root), QELI_FIXTURE_ROOT=str(self.root),
            QELI_FIXTURE_ENABLED='0', QELI_FIXTURE_LOAD_FAILURE='never')

    def invoke(self, action, *args, **env):
        return subprocess.run(SHELL+[str(self.rc),str(self.init),action,*args], env=dict(self.env,**env),
            capture_output=True,text=True,timeout=15)
    def calls(self):
        p=self.root/'calls';return p.read_text().splitlines() if p.exists() else []

    def test_extra_status_uses_actual_dispatch_and_exit_codes(self):
        self.assertEqual(self.invoke('status_enabled',QELI_FIXTURE_ENABLED='1').returncode,0)
        self.assertEqual(self.invoke('status_enabled').returncode,1)
        self.assertEqual(self.invoke('status_enabled',QELI_FIXTURE_LOAD_FAILURE='1').returncode,2)

    def test_start_preserves_first_and_second_load_failure_through_close(self):
        for phase in ('1','2'):
            with self.subTest(phase=phase):
                result=self.invoke('start',QELI_FIXTURE_LOAD_FAILURE=phase)
                self.assertNotEqual(result.returncode,0,result.stderr)
                self.assertEqual(self.calls()[-1],'close')

    def test_valid_disabled_start_succeeds_through_hook(self):
        self.assertEqual(self.invoke('start').returncode,0)
        self.assertEqual(self.calls(),['open','load:qeli','load:qeli','close'])

    def test_failed_stop_cleanup_and_extra_clear_report_failure(self):
        (self.root/'run/client.conf').mkdir()
        result=self.invoke('stop');self.assertNotEqual(result.returncode,0)
        self.assertIn('kill',self.calls())
        (self.root/'run/password').mkdir()
        self.assertNotEqual(self.invoke('clear_secrets','pass').returncode,0)

    def test_restart_and_reload_do_not_admit_start_after_failed_stop_cleanup(self):
        (self.root/'run/client.conf').mkdir()
        for action in ('restart','reload'):
            with self.subTest(action=action):
                result=self.invoke(action);self.assertNotEqual(result.returncode,0)
                self.assertNotIn('load:qeli',self.calls())
                self.assertIn('kill',self.calls())

if __name__ == '__main__': unittest.main()
