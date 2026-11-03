"""Actual ucode/fs RPC module + real init secret CLI in private files.
No rpcd daemon, ubus, /etc changes, service/firewall or network mutations.
Run with QELI_UCODE_EXECUTABLE and QELI_UCODE_LIBDIR for a built pinned ucode.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UCODE = os.environ.get('QELI_UCODE_EXECUTABLE', '')
LIBDIR = os.environ.get('QELI_UCODE_LIBDIR', '')
SHELL = shlex.split(os.environ.get('QELI_OPENWRT_TEST_SHELL', '/bin/dash'))
MODULE = ROOT / 'qeli-openwrt/luci-app-qeli/root/usr/share/rpcd/ucode/qeli.uc'

@unittest.skipUnless(os.name == 'posix' and UCODE and Path(UCODE).is_file(),
                     'requires actual pinned Linux ucode and fs module')
class UcodeRpcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qeli-ucode-rpc-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / 'run'
        self.run.mkdir(mode=0o700)
        self.init = self.root / 'init-cli'
        self.module = self.root / 'qeli.uc'
        # Only production absolute paths are mapped into this disposable fixture.
        source = MODULE.read_text().replace('/etc/init.d/qeli', str(self.init))
        source = source.replace("const RUNDIR = '/var/run/qeli';",
                                "const RUNDIR = '" + str(self.run) + "';")
        self.module.write_text(source)
        self.driver = self.root / 'driver.uc'
        self.driver.write_text("""import * as fs from 'fs';
global.UBUS_STATUS_INVALID_ARGUMENT = 2;
global.UBUS_STATUS_UNKNOWN_ERROR = 9;
const methods = loadfile(getenv('QELI_TEST_MODULE'), { raw_mode: true })()['luci.qeli'];
const request = json(fs.stdin.read('all'));
print(methods[request.method].call({ args: request.args }), '\n');
""")
        wrapper = r"""
. "$QELI_TEST_INIT"
RUNDIR="$QELI_TEST_ROOT/run"
PASS_FILE="$RUNDIR/password"
OBFS_KEY_FILE="$RUNDIR/obfs-key"
logger() { :; }
printf '%s\n' "$@" > "$QELI_TEST_ROOT/argv"
cat "/proc/$PPID/cmdline" > "$QELI_TEST_ROOT/parent-argv"
[ "${QELI_TEST_CHILD_FAIL:-0}" = 0 ] || exit "$QELI_TEST_CHILD_FAIL"
case "$1" in
    set_secret) shift; set_secret "$@" ;;
    clear_secrets) shift; clear_secrets "$@" ;;
    status_enabled) exit "${QELI_TEST_STATUS:-0}" ;;
    start|stop|restart|enable|disable) exit "${QELI_TEST_STATUS:-0}" ;;
    *) exit 17 ;;
esac
"""
        self.init.write_text('#!' + ' '.join(SHELL) + '\n' + wrapper)
        self.init.chmod(0o700)
        self.env = dict(os.environ, QELI_TEST_ROOT=str(self.root),
                        QELI_TEST_INIT=str(ROOT / 'qeli-openwrt/files/qeli.init'),
                        QELI_TEST_MODULE=str(self.module))
    def call(self, method, args=None, **env):
        return subprocess.run([UCODE, '-L', LIBDIR + '/*.so', str(self.driver)],
            input=json.dumps({'method':method, 'args':args or {}}, ensure_ascii=False),
            text=True, capture_output=True, env=dict(self.env, **env), timeout=10)
    def result(self, process):
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        return json.loads(process.stdout)
    def write(self, name, value, **env):
        return self.call('set_secret', {'name':name, 'value':value}, **env)
    def test_both_secret_names_publish_exact_private_bytes(self):
        for name, filename in [('pass','password'),('obfs_key','obfs-key')]:
            value='  quote" slash\\ dollar$ backtick` unicode-Ж😀 ; $(false)  '
            with self.subTest(name=name):
                process=self.write(name,value)
                self.assertEqual(self.result(process),{'result':True})
                path=self.run/filename
                self.assertEqual(path.read_bytes(),value.encode())
                self.assertEqual(path.stat().st_mode & 0o777,0o600)
                self.assertEqual(self.run.stat().st_mode & 0o777,0o700)
                self.assertEqual((self.root/'argv').read_text().splitlines(),['set_secret',name])
                self.assertNotIn(value.encode(),(self.root/'parent-argv').read_bytes())
                self.assertNotIn(value,process.stdout+process.stderr)
    def test_byte_limit_ascii_and_unicode(self):
        for value,accepted in [('a'*4096,True),('é'*2048,True),('a'*4097,False),('é'*2049,False)]:
            with self.subTest(bytes=len(value.encode())):
                path=self.run/'password';path.write_text('previous')
                process=self.write('pass',value)
                if accepted:
                    self.assertEqual(self.result(process),{'result':True})
                    self.assertEqual(path.read_bytes(),value.encode())
                else:
                    self.assertEqual(process.returncode,2,process.stdout+process.stderr)
                    self.assertEqual(path.read_text(),'previous')
    def test_every_ascii_control_is_rejected_before_child_launch(self):
        for code in [*range(32),127]:
            with self.subTest(code=code):
                receipt=self.root/'argv';receipt.unlink(missing_ok=True)
                process=self.write('pass','left'+chr(code)+'right')
                self.assertEqual(process.returncode,2,process.stdout+process.stderr)
                self.assertFalse(receipt.exists())
                self.assertFalse((self.run/'password').exists())
    def test_invalid_types_empty_and_names_do_not_launch(self):
        for value in ['',None,1,True,[],{}]:
            self.assertEqual(self.write('pass',value).returncode,2)
        for name in ['','unknown','pass; touch sentinel','__proto__']:
            self.assertEqual(self.write(name,'fixture').returncode,2)
        self.assertFalse((self.root/'argv').exists())
    def test_stdin_metacharacters_do_not_execute_shell_fragments(self):
        sentinel=self.root/'injected'
        value='$(touch '+str(sentinel)+'); `touch '+str(sentinel)+'`'
        self.assertEqual(self.result(self.write('pass',value)),{'result':True})
        self.assertEqual((self.run/'password').read_text(),value)
        self.assertFalse(sentinel.exists())
    def test_child_failure_preserves_previous_secret(self):
        path=self.run/'password';path.write_text('previous')
        process=self.write('pass','new-fixture',QELI_TEST_CHILD_FAIL='17')
        self.assertEqual(process.returncode,9,process.stdout+process.stderr)
        self.assertEqual(path.read_text(),'previous')
    def test_non_regular_publication_target_cannot_report_success(self):
        outside=self.root/'outside';outside.write_text('previous')
        for kind in ['directory','symlink','dangling','fifo']:
            with self.subTest(kind=kind):
                path=self.run/'password'
                if kind=='directory':path.mkdir()
                elif kind=='symlink':path.symlink_to(outside)
                elif kind=='dangling':path.symlink_to(self.root/'missing')
                else:os.mkfifo(path)
                try:
                    process=self.write('pass','new-fixture')
                    self.assertEqual(process.returncode,9,process.stdout+process.stderr)
                    self.assertEqual(outside.read_text(),'previous')
                    if kind=='directory':self.assertEqual(list(path.iterdir()),[])
                finally:
                    if kind=='directory':
                        for child in path.iterdir():child.unlink()
                        path.rmdir()
                    else:path.unlink()

    def test_secret_status_reads_actual_files(self):
        self.assertEqual(self.result(self.call('secret_status')),{'pass':False,'obfs_key':False})
        (self.run/'password').write_text('fixture')
        self.assertEqual(self.result(self.call('secret_status')),{'pass':True,'obfs_key':False})
    def test_secret_status_rejects_empty_oversize_and_non_regular_files(self):
        outside=self.root/'outside';outside.write_text('fixture')
        for kind in ['empty','oversize','directory','symlink','fifo']:
            with self.subTest(kind=kind):
                path=self.run/'password'
                if kind=='empty':path.touch()
                elif kind=='oversize':path.write_text('a'*4097)
                elif kind=='directory':path.mkdir()
                elif kind=='symlink':path.symlink_to(outside)
                else:os.mkfifo(path)
                try:
                    self.assertFalse(self.result(self.call('secret_status'))['pass'])
                finally:
                    if kind=='directory':path.rmdir()
                    else:path.unlink()
    def test_linked_runtime_directory_is_rejected_without_chmod_or_write(self):
        outside=self.root/'outside-dir';outside.mkdir(mode=0o755)
        (outside/'password').write_text('previous')
        self.run.rmdir();self.run.symlink_to(outside,target_is_directory=True)
        process=self.write('pass','new-fixture')
        self.assertEqual(process.returncode,9,process.stdout+process.stderr)
        self.assertEqual((outside/'password').read_text(),'previous')
        self.assertEqual(outside.stat().st_mode & 0o777,0o755)
        self.assertFalse(self.result(self.call('secret_status'))['pass'])
    def test_clear_rejects_linked_runtime_directory_and_preserves_external_files(self):
        outside=self.root/'outside-dir';outside.mkdir(mode=0o755)
        for filename in ['password','obfs-key']:(outside/filename).write_text('previous')
        self.run.rmdir();self.run.symlink_to(outside,target_is_directory=True)
        for name in ['pass','obfs_key']:
            result=self.result(self.call('clear_secret',{'name':name}))
            self.assertFalse(result['result'])
            self.assertNotEqual(result['code'],0)
        process=subprocess.run(SHELL+[str(self.init),'clear_secrets','all'],
            capture_output=True,text=True,env=self.env,timeout=10)
        self.assertNotEqual(process.returncode,0,process.stdout+process.stderr)
        for filename in ['password','obfs-key']:
            self.assertEqual((outside/filename).read_text(),'previous')
        self.assertEqual(outside.stat().st_mode & 0o777,0o755)
    def test_clear_secret_success_and_actual_filesystem_failure(self):
        for name,filename in [('pass','password'),('obfs_key','obfs-key')]:
            path=self.run/filename;path.write_text('fixture')
            self.assertEqual(self.result(self.call('clear_secret',{'name':name})),{'result':True,'code':0})
            self.assertFalse(path.exists());path.mkdir()
            result=self.result(self.call('clear_secret',{'name':name}))
            self.assertFalse(result['result']);self.assertNotEqual(result['code'],0)
        self.assertEqual(self.call('clear_secret',{'name':'unknown'}).returncode,2)
    def test_service_status_preserves_error_as_unknown(self):
        for code,wanted in [(0,True),(1,False),(2,None)]:
            self.assertEqual(self.result(self.call('service_status',QELI_TEST_STATUS=str(code))),{'enabled':wanted})
    def test_closed_service_actions_and_failure_result(self):
        for action in ['start','stop','restart','enable','disable']:
            self.assertEqual(self.result(self.call('service_action',{'action':action})),{'result':True,'code':0})
        self.assertEqual(self.result(self.call('service_action',{'action':'start'},QELI_TEST_STATUS='17')),{'result':False,'code':17})
        for action in ['','reload','start; touch sentinel','__proto__']:
            (self.root/'argv').unlink(missing_ok=True)
            self.assertEqual(self.call('service_action',{'action':action}).returncode,2)
            self.assertFalse((self.root/'argv').exists())

if __name__ == '__main__':
    unittest.main()
