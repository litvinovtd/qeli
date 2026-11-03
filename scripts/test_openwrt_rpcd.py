"""Actual pinned rpcd/ubusd/UCI in a private chroot, never host /etc or sockets.
Requires a root Linux lab and QELI_OPENWRT_RPCD_TEMPLATE with built runtime files.
Only service verbs are adapters; ucode dispatch, errors, fs, UCI and session ACLs
are real. Template/source identities must be captured by the lab evidence runner.
"""
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = os.environ.get('QELI_OPENWRT_RPCD_TEMPLATE', '')
CHROOT = shutil.which('chroot')
INSPECTOR = os.environ.get('QELI_OPENWRT_INI_INSPECTOR', '')
MODULE = 'qeli-openwrt/luci-app-qeli/root/usr/share/rpcd/ucode/qeli.uc'
ACL = 'qeli-openwrt/luci-app-qeli/root/usr/share/rpcd/acl.d/luci-app-qeli.json'

@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid') and
                    os.geteuid() == 0 and CHROOT and TEMPLATE and
                    Path(TEMPLATE).is_dir(), 'requires owned Linux rpcd runtime/chroot')
class RpcdIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='runtime-', dir=Path(TEMPLATE).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.jail = self.root / 'jail'
        shutil.copytree(TEMPLATE, self.jail, symlinks=True)
        for name,minor in [('null',3),('urandom',9)]:
            os.mknod(self.jail/'dev'/name, stat.S_IFCHR | 0o600, os.makedev(1,minor))
        self.run = self.jail/'var/run/qeli'
        self.run.mkdir(mode=0o700)
        self.fixture = self.jail/'fixture'
        self.fixture.mkdir()
        (self.fixture/'qeli.init').write_bytes((ROOT/'qeli-openwrt/files/qeli.init').read_bytes())
        (self.jail/'usr/share/rpcd/ucode/qeli.uc').write_bytes((ROOT/MODULE).read_bytes())
        (self.jail/'usr/share/rpcd/acl.d/luci-app-qeli.json').write_bytes((ROOT/ACL).read_bytes())
        (self.jail/'etc/config/qeli').write_bytes((ROOT/'qeli-openwrt/files/qeli.config').read_bytes())
        wrapper = r"""#!/bin/sh
. /lib/functions.sh
. /fixture/qeli.init
logger() { :; }
printf '%s\n' "$@" > /fixture/argv
if [ -f /fixture/fail-code ]; then exit "$(cat /fixture/fail-code)"; fi
verb="$1"; shift
case "$verb" in
    set_secret|clear_secrets|status_enabled) "$verb" "$@" ;;
    start|stop|restart|enable|disable) exit 0 ;;
    *) exit 17 ;;
esac
"""
        self.init = self.jail/'etc/init.d/qeli'
        self.init.write_text(wrapper);self.init.chmod(0o700)
        self.processes = []
        self.logs = []
        self.addCleanup(self.stop)
        self.bus = self.launch('/usr/sbin/ubusd','-s','/var/run/ubus.sock')
        for _ in range(50):
            if (self.jail/'var/run/ubus.sock').exists():break
            self.assertIsNone(self.bus.poll(), self.log_text())
            time.sleep(0.02)
        self.assertTrue((self.jail/'var/run/ubus.sock').exists(),self.log_text())
        self.start_rpcd()
    def log_text(self):
        return '\n'.join(p.read_text(errors='replace') for p in self.root.glob('daemon-*.log'))
    def launch(self, *args):
        p=self.root/('daemon-'+str(len(self.logs))+'.log')
        log=p.open('wb');self.logs.append(log)
        process=subprocess.Popen([CHROOT,str(self.jail),*args],stdout=log,stderr=log,
            env={'PATH':'/usr/bin:/usr/sbin:/bin:/sbin','LC_ALL':'C'},start_new_session=True)
        self.processes.append(process)
        return process
    def stop(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        for log in self.logs:log.close()
    def start_rpcd(self, require_qeli=True):
        self.rpcd=self.launch('/usr/sbin/rpcd','-s','/var/run/ubus.sock','-t','5')
        wanted='luci.qeli' if require_qeli else 'session'
        for _ in range(50):
            result=self.command('/usr/bin/ubus','-s','/var/run/ubus.sock','list')
            if wanted in result.stdout.splitlines():return
            self.assertIsNone(self.rpcd.poll(),self.log_text())
            time.sleep(0.02)
        self.fail('rpcd did not register '+wanted+'\n'+self.log_text())
    def command(self, *args):
        return subprocess.run([CHROOT,str(self.jail),*args],capture_output=True,
            text=True,timeout=10,env={'PATH':'/usr/bin:/usr/sbin:/bin:/sbin','LC_ALL':'C'})
    def call(self, method, args=None, object_name='luci.qeli'):
        return self.command('/usr/bin/ubus','-s','/var/run/ubus.sock','call',
            object_name,method,json.dumps(args or {},ensure_ascii=False))
    def result(self, process):
        self.assertEqual(process.returncode,0,process.stdout+process.stderr+self.log_text())
        return json.loads(process.stdout.strip() or 'null')
    def test_missing_fs_module_prevents_registration(self):
        self.rpcd.terminate();self.rpcd.wait(timeout=3)
        (self.jail/'usr/lib/ucode/fs.so').unlink()
        self.start_rpcd(require_qeli=False)
        result=self.command('/usr/bin/ubus','-s','/var/run/ubus.sock','list')
        self.assertNotIn('luci.qeli',result.stdout.splitlines())
        self.assertIn('Unable to resolve',self.log_text())
        self.assertIsNone(self.rpcd.poll())
    def test_real_signature_and_invalid_requests_do_not_poison_vm(self):
        result=self.command('/usr/bin/ubus','-s','/var/run/ubus.sock','-v','list','luci.qeli')
        self.assertEqual(result.returncode,0,result.stderr)
        for name in ['set_secret','clear_secret','secret_status','service_action','service_status']:
            self.assertIn('"'+name+'"',result.stdout)
        for method,args in [('set_secret',{}),('set_secret',{'name':'pass','value':True}),
                            ('set_secret',{'name':'pass','value':'a\nkey=b'}),
                            ('clear_secret',{'name':'unknown'}),
                            ('service_action',{'action':'restart; touch /fixture/injected'})]:
            with self.subTest(method=method,args=args):
                result=self.call(method,args)
                self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn('Invalid argument',result.stderr)
                self.assertIsNone(self.rpcd.poll())
                self.assertEqual(self.result(self.call('secret_status')),{'pass':False,'obfs_key':False})
        self.assertFalse((self.fixture/'injected').exists())
    def test_actual_secret_stdin_bytes_limits_and_child_failure(self):
        for name,filename in [('pass','password'),('obfs_key','obfs-key')]:
            value='  "quoted" \\ Unicode-Ж😀 $(touch /fixture/injected) `false`  '
            self.assertEqual(self.result(self.call('set_secret',{'name':name,'value':value})),{'result':True})
            path=self.run/filename
            self.assertEqual(path.read_bytes(),value.encode())
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual((self.fixture/'argv').read_text().splitlines(),['set_secret',name])
        self.assertFalse((self.fixture/'injected').exists())
        self.assertEqual(self.result(self.call('set_secret',{'name':'pass','value':'é'*2048})),{'result':True})
        for value in ['a'*4097,'é'*2049,'x\x7fy']:
            self.assertNotEqual(self.call('set_secret',{'name':'pass','value':value}).returncode,0)
            self.assertEqual((self.run/'password').read_bytes(),('é'*2048).encode())
        (self.fixture/'fail-code').write_text('17')
        result=self.call('set_secret',{'name':'pass','value':'new-fixture'})
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Unknown error',result.stderr)
        self.assertEqual((self.run/'password').read_bytes(),('é'*2048).encode())
        (self.fixture/'fail-code').unlink()
        self.assertEqual(self.result(self.call('secret_status')),{'pass':True,'obfs_key':True})
    def test_actual_file_status_clear_error_and_linked_runtime(self):
        (self.run/'password').mkdir()
        self.assertFalse(self.result(self.call('secret_status'))['pass'])
        result=self.result(self.call('clear_secret',{'name':'pass'}))
        self.assertFalse(result['result']);self.assertNotEqual(result['code'],0)
        (self.run/'password').rmdir()
        outside=self.jail/'fixture/outside';outside.mkdir(mode=0o755)
        (outside/'password').write_text('previous')
        self.run.rmdir();self.run.symlink_to('/fixture/outside',target_is_directory=True)
        self.assertFalse(self.result(self.call('secret_status'))['pass'])
        result=self.result(self.call('clear_secret',{'name':'pass'}))
        self.assertFalse(result['result'])
        self.assertNotEqual(self.call('set_secret',{'name':'pass','value':'new'}).returncode,0)
        self.assertEqual((outside/'password').read_text(),'previous')
        self.assertEqual(outside.stat().st_mode & 0o777,0o755)
    def test_status_uses_actual_uci_session_staging_and_commit(self):
        self.configure_login()
        sid=self.login('writer')
        self.assertEqual(self.result(self.call('service_status')),{'enabled':False})
        self.result(self.call('set',{'ubus_rpc_session':sid,'config':'qeli',
            'section':'main','values':{'enabled':'1'}},'uci'))
        self.assertEqual(self.result(self.call('service_status')),{'enabled':False})
        self.result(self.call('commit',{'ubus_rpc_session':sid,'config':'qeli'},'uci'))
        self.assertEqual(self.result(self.call('service_status')),{'enabled':True})
        (self.jail/'etc/config/qeli').unlink()
        self.assertEqual(self.result(self.call('service_status')),{'enabled':None})
    @unittest.skipUnless(INSPECTOR and Path(INSPECTOR).is_file(), 'requires exact shared INI inspector')
    def test_real_uci_renderer_and_shared_ini_preserve_literal_values(self):
        self.configure_login();sid=self.login('writer')
        (self.run/'password').write_text('fixture')
        values=[' user ','"user"','a\\"b','tail\\','x#;=y','  ','русский 日本語',
                "'single'",'$(touch /fixture/injected) `id` $HOME','simple',
                'left\npost_up=bad\x7fend']
        for value in values:
            with self.subTest(value=value):
                self.result(self.call('set',{'ubus_rpc_session':sid,'config':'qeli',
                    'section':'main','values':{'server':'vpn.example:443','user':value}},'uci'))
                self.result(self.call('commit',{'ubus_rpc_session':sid,'config':'qeli'},'uci'))
                process=self.command('/bin/sh','-c',
                    '. /lib/functions.sh; . /fixture/qeli.init; logger() { :; }; config_load qeli && render_conf')
                self.assertEqual(process.returncode,0,process.stderr)
                parsed=subprocess.run([INSPECTOR],input=(self.run/'client.conf').read_text(),
                    capture_output=True,text=True,timeout=5)
                self.assertEqual(parsed.returncode,0,parsed.stderr)
                pairs={}
                for row in parsed.stdout.splitlines():
                    section,key,encoded=row.split('\t',2)
                    pairs[section,key]=bytes.fromhex(encoded).decode()
                expected=''.join(c for c in value if ord(c)>=32 and ord(c)!=127)
                self.assertEqual(pairs['qeli','user'],expected)
                self.assertEqual(pairs['qeli','server'],'vpn.example:443')
                self.assertNotIn(('qeli','post_up'),pairs)
                self.assertFalse((self.fixture/'injected').exists())
    def login(self,user):
        return self.result(self.call('login',{'username':user,'password':'fixture-password'},
            'session'))['ubus_rpc_session']
    def configure_login(self):
        library=ctypes.CDLL(ctypes.util.find_library('crypt'))
        library.crypt.argtypes=[ctypes.c_char_p,ctypes.c_char_p];library.crypt.restype=ctypes.c_char_p
        hashed=library.crypt(b'fixture-password',b'$6$qeli-audit$').decode()
        self.assertTrue(hashed.startswith('$6$'))
        config=''
        for user,permissions in [('reader',['read']),('writer',['read','write'])]:
            config += "config login\n option username '"+user+"'\n option password '"+hashed+"'\n"
            for permission in permissions:config += " list "+permission+" 'luci-app-qeli'\n"
        (self.jail/'etc/config/rpcd').write_text(config)
    def test_real_session_acl_reader_writer_and_denials(self):
        self.configure_login()
        for user in ['reader','writer']:
            sid=self.login(user)
            for method,allowed in [('service_status',True),('service_action',user=='writer'),
                                  ('secret_status',user=='writer'),('set_secret',user=='writer'),
                                  ('clear_secret',user=='writer'),('not_a_qeli_method',False)]:
                with self.subTest(user=user,method=method):
                    result=self.result(self.call('access',{'ubus_rpc_session':sid,'scope':'ubus',
                        'object':'luci.qeli','function':method},'session'))
                    self.assertEqual(result,{'access':allowed})
            for permission,allowed in [('read',True),('write',user=='writer')]:
                result=self.result(self.call('access',{'ubus_rpc_session':sid,'scope':'uci',
                    'object':'qeli','function':permission},'session'))
                self.assertEqual(result,{'access':allowed})
            result=self.result(self.call('access',{'ubus_rpc_session':sid,'scope':'uci',
                'object':'firewall','function':'write'},'session'))
            self.assertEqual(result,{'access':False})

if __name__ == '__main__':
    unittest.main()
