"""Native router CLI + real OpenWrt secret wrapper, private files only.
Run as root on Linux with QELI_ROUTER_CLIENT pointing to the built client.
"""
import json,os,subprocess,tempfile,unittest
from pathlib import Path
BIN=Path(os.environ.get('QELI_ROUTER_CLIENT','/nonexistent-router-client'))
ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0 and BIN.is_file(),'requires root Linux native router client')
class RouterCliTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='qeli-router-cli-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
    def cli(self,*args,input=None):
        return subprocess.run([str(BIN),'router',*map(str,args)],input=input,text=True,capture_output=True,timeout=15)
    def test_both_platforms_leave_external_ownership_by_default(self):
        for platform,device in [('openwrt','qeli0'),('keenetic','vpn0')]:
            p=json.loads(self.cli('example','--platform',platform).stdout)
            self.assertEqual(p['components'],{'routing':'external','firewall':'external'})
            self.assertEqual(p['device'],device);self.assertIsNone(p['router_policy'])
    def test_invalid_candidate_does_not_replace_owned_manifest(self):
        runtime=self.root/'run';runtime.mkdir(mode=0o700)
        output=self.root/'router.json';config=self.root/'client.conf'
        config.write_text('[qeli]\nserver=192.0.2.1:444\nmode=plain\nuser=fixture\npass=fixture\ndev=qeli0\ndns=off\ngateway=true\n');config.chmod(0o600)
        def render(p,routing='external'):
            return self.cli('render','--output',output,'--runtime',runtime,'--client-config',config,'--routing',routing,'--firewall','external','--bootstrap',input=json.dumps(p))
        self.assertEqual(render({}).returncode,0)
        before=output.read_bytes()
        p={'uplinks':[{'device':'wan-test','probes':['1.1.1.1']}],'server_addresses':['192.0.2.1'],'offload_disabled':True,'health':{'tunnel_probes':['1.0.0.1']}}
        failed=render(p,'client')
        self.assertNotEqual(failed.returncode,0);self.assertIn('gateway=false',failed.stderr)
        self.assertEqual(output.read_bytes(),before)
    def test_cannot_adopt_unowned_policy_or_follow_secret_symlink(self):
        runtime=self.root/'run';runtime.mkdir(mode=0o700)
        output=self.root/'router.json';output.write_text('original');output.chmod(0o600)
        result=self.cli('render','--output',output,'--runtime',runtime,'--client-config',self.root/'unused','--routing','external','--firewall','external','--bootstrap',input='{}')
        self.assertNotEqual(result.returncode,0);self.assertEqual(output.read_text(),'original')
        secret=self.root/'secrets';secret.mkdir(mode=0o700);(secret/'password').symlink_to(output)
        self.assertNotEqual(self.cli('store-secret','--directory',secret,'--name','pass',input='replacement\n').returncode,0)
        self.assertEqual(output.read_text(),'original')
    def test_openwrt_persistence_is_explicit_and_ram_clear_keeps_retained_copy(self):
        run=self.root/'run';run.mkdir(mode=0o700)
        script=ROOT/'qeli-openwrt/files/qeli.init'
        # Production shell functions, with only UCI values and absolute paths adapted.
        head='''. "$QELI_INIT"
RUNDIR="$QELI_CASE/run"; STATEDIR="$QELI_CASE/state"
PASS_FILE="$RUNDIR/password"; OBFS_KEY_FILE="$RUNDIR/obfs-key"
BIN="$QELI_ROUTER_CLIENT"
config_load(){ :; }; config_get_bool(){ export "$1=$QELI_RETAIN"; }
'''
        env=dict(os.environ,QELI_INIT=str(script),QELI_CASE=str(self.root),QELI_ROUTER_CLIENT=str(BIN))
        def shell(body,retain='0'):
            return subprocess.run(['/bin/sh','-c',head+body],env=dict(env,QELI_RETAIN=retain),text=True,capture_output=True,timeout=15)
        p=shell("printf 'fixture-ram\\n' | set_secret pass")
        self.assertEqual(p.returncode,0,p.stderr);self.assertFalse((self.root/'state/secrets').exists())
        p=shell("printf 'fixture-retained\\n' | set_secret pass",'1')
        self.assertEqual(p.returncode,0,p.stderr)
        retained=self.root/'state/secrets/password'
        self.assertEqual(retained.read_text(),'fixture-retained');self.assertEqual(retained.stat().st_mode&0o777,0o600)
        p=shell('clear_secrets')
        self.assertEqual(p.returncode,0,p.stderr);self.assertFalse((run/'password').exists());self.assertTrue(retained.exists())
        p=shell('forget_retained_secrets')
        self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(retained.exists())
if __name__=='__main__':unittest.main()
