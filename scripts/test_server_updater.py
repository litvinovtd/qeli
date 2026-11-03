#!/usr/bin/env python3
"""Q33 updater transactions with genuine fixture .deb packages/dpkg in Linux chroots.

apt, HTTP, systemctl and sleep are explicit seams; no real daemon/repository or
production maintainer script is executed. Run as root inside private namespaces.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

if sys.platform == 'linux':
    import fcntl

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('QELI_UPDATER_SOURCE', ROOT / 'update-qeli-server.sh'))
INSTALLER = Path(os.environ.get('QELI_INSTALLER_SOURCE', ROOT / 'install-qeli-server.sh'))

@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root/chroot required')
class UpdaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix='qeli-updater-tests-')
        cls.base = Path(cls.workspace.name)/'base';cls.base.mkdir()
        cls.chroot = shutil.which('chroot');assert cls.chroot
        for program in ['bash','id','date','awk','sed','sort','head','tail','grep','find','xargs','cut','cp','rm','install','stat','dirname','basename','mktemp','sha256sum','flock','dpkg','dpkg-deb','dpkg-query','jq','tar','diff','ldconfig','start-stop-daemon','dpkg-split']:
            source = Path(shutil.which(program));dest=cls.base/'usr/bin'/program;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
            for lib in re.findall(r'(/[^\s]+)',subprocess.run(['ldd',str(source)],capture_output=True,text=True).stdout):
                target=cls.base/lib.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(lib,target)
        (cls.base/'bin').mkdir();(cls.base/'bin/bash').symlink_to('../usr/bin/bash');(cls.base/'bin/sh').symlink_to('bash')
        for name in ['tmp','run','etc/qeli/identity','etc/qeli/client-links','var/lib/dpkg/info','var/lib/dpkg/updates','var/lib/dpkg/triggers','var/lib/qeli','var/cache/qeli','usr/local/bin','records','fixtures','dev']:(cls.base/name).mkdir(parents=True,exist_ok=True)
        (cls.base/'var/lib/dpkg/status').touch();(cls.base/'dev/null').touch();(cls.base/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\n');(cls.base/'etc/group').write_text('root:x:0:\n');(cls.base/'var/cache/qeli').chmod(0o700)
        (cls.base/'update.sh').write_bytes(SOURCE.read_bytes());(cls.base/'install.sh').write_bytes(INSTALLER.read_bytes())
        for version,arch,name in [('0.8.1','amd64','qeli'),('0.8.1-1','amd64','qeli'),('0.8.2','amd64','qeli'),('0.8.2','arm64','qeli'),('0.8.2','all','qeli'),('0.8.2','amd64','other')]:
            staging=Path(cls.workspace.name)/f'{name}-{version}-{arch}';(staging/'DEBIAN').mkdir(parents=True);(staging/'usr/bin').mkdir(parents=True)
            (staging/'DEBIAN/control').write_text(f'Package: {name}\nVersion: {version}\nArchitecture: {arch}\nMaintainer: Audit <audit@localhost>\nDescription: inert Q33 fixture\n')
            binary=staging/'usr/bin'/name;binary.write_text('#!/bin/bash\n[[ \"$1\" == --version ]] || exit 2\nprintf "qeli '+version.split('-')[0]+'\\n"\n');binary.chmod(0o755)
            subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','--build',str(staging),str(cls.base/'fixtures'/f'{name}_{version}_{arch}.deb')],check=True,capture_output=True)
        record_dir = os.environ.get('QELI_UPDATER_FIXTURE_RECORDS')
        if record_dir:
            record = Path(record_dir);record.mkdir(parents=True,exist_ok=True)
            rows=[]
            for package in (cls.base/'fixtures').glob('*.deb'):
                shutil.copy2(package,record/package.name)
                rows.append({'path':package.name,'size':package.stat().st_size,'sha256':hashlib.sha256(package.read_bytes()).hexdigest()})
            (record/'packages.json').write_text(json.dumps(rows,indent=2))
        for name in ['server.conf','users.conf','identity/default.key','client-links/phone.txt']:(cls.base/'etc/qeli'/name).write_text('preserve '+name+'\n')
        cls.stub('apt-get',r'''printf '%s\n' "$*" >> /records/apt.log
mode="$(< /records/mode)";last="${!#}"
if [[ "$*" == *--allow-downgrades* ]]; then
 [[ "$mode" != rollback_false ]] || exit 0
 [[ "$mode" != rollback_fail ]] || exit 1
elif [[ "$last" == *.deb && "$mode" == install_refused ]]; then exit 1
fi
if [[ "$last" == *.deb ]]; then exec /usr/bin/dpkg -i "$last"; fi
exit 0''')
        cls.stub('dpkg',r'''if [[ "$1" == -i && "$(< /records/mode)" == install_refused ]]; then exit 1; fi
exec /usr/bin/dpkg "$@"''')
        cls.stub('systemctl',r'''printf '%s\n' "$*" >> /records/systemctl.log
mode="$(< /records/mode)";version="$(/usr/bin/qeli --version)"
case "$1" in
 restart) [[ "$mode" != restart_fail || "$version" != 'qeli 0.8.2' ]] ;;
 show)
  [[ "$mode" != empty_pid ]] || exit 0
  if [[ "$mode" == rollback_flaps && "$version" == 'qeli 0.8.1' ]]; then
   n=0;[[ ! -f /records/pid-count ]] || n="$(< /records/pid-count)";n=$((n+1));printf '%s' "$n" > /records/pid-count;echo "$((100+n))"
  else echo 123;fi ;;
 is-active) [[ "$mode" != crash_new && "$mode" != rollback_false && "$mode" != rollback_fail && "$mode" != rollback_flaps ]] || [[ "$version" != 'qeli 0.8.2' ]] ;;
 *) exit 0 ;;
esac''')
        cls.stub('sleep','exit 0')
        cls.stub('curl',r'''printf '%s\n' "$*" >> /records/curl.log
out='';while [[ "$#" -gt 0 ]]; do case "$1" in -o) out="$2";shift 2 ;; *) url="$1";shift ;; esac;done
case "$url" in
 */releases) /usr/bin/cp /fixtures/releases.json /dev/stdout ;;
 */SHA256SUMS) /usr/bin/cp /fixtures/SHA256SUMS "$out" ;;
 *.deb)
  if [[ "$(< /records/mode)" == download_failure ]]; then printf partial > "$out";exit 22;fi
  /usr/bin/cp "/fixtures/${url##*/}" "$out" ;;
 *) exit 22 ;;
esac'''.replace('/usr/bin/cp /fixtures/releases.json /dev/stdout','while IFS= read -r line; do printf "%s\\n" "$line";done < /fixtures/releases.json'))
        (cls.base/'records/mode').write_text('normal')

    @classmethod
    def stub(cls,name,text):
        p=cls.base/'usr/local/bin'/name;p.write_text('#!/bin/bash\n'+text+'\n');p.chmod(0o755)

    @classmethod
    def tearDownClass(cls):cls.workspace.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=self.workspace.name);self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)/'root';shutil.copytree(self.base,self.root,symlinks=True)
        self.env=dict(os.environ,PATH='/usr/local/bin:/usr/bin:/bin',LC_ALL='C',QELI_DEB='/fixtures/qeli_0.8.2_amd64.deb',TMPDIR='/tmp')
        for key in list(self.env):
            if key.startswith('QELI_') and key!='QELI_DEB':self.env.pop(key)
        self.old='0.8.1';self.install_old(self.old)
        self.snap={p.relative_to(self.root).as_posix():p.read_bytes() for p in (self.root/'etc/qeli').rglob('*') if p.is_file()}

    def install_old(self,version):
        self.old=version;p=subprocess.run([self.chroot,str(self.root),'/usr/bin/dpkg','-i',f'/fixtures/qeli_{version}_amd64.deb'],capture_output=True,text=True);assert p.returncode==0,p.stderr
        shutil.copy2(self.root/f'fixtures/qeli_{version}_amd64.deb',self.root/f'var/cache/qeli/qeli_{version}_amd64.deb')

    def mode(self,name):(self.root/'records/mode').write_text(name)

    def run_update(self,installer=False):
        p=subprocess.run([self.chroot,str(self.root),'/bin/bash','/install.sh' if installer else '/update.sh'],env=self.env,capture_output=True,text=True,timeout=10)
        for name,data in self.snap.items():self.assertEqual((self.root/name).read_bytes(),data,name)
        return p

    def version(self):return subprocess.check_output([self.chroot,str(self.root),'/usr/bin/dpkg-query','-W','-f=${Version}','qeli'],text=True)
    def binary_version(self):return subprocess.check_output([self.chroot,str(self.root),'/usr/bin/qeli','--version'],text=True).strip()

    def online(self,with_sums=True,crlf=False):
        self.env.pop('QELI_DEB',None);assets=[{'name':f'qeli_0.8.2_{arch}.deb','browser_download_url':f'https://fixture/qeli_0.8.2_{arch}.deb'} for arch in ['arm64','amd64']]
        if crlf:assets=assets[1:]
        if with_sums:assets.append({'name':'SHA256SUMS','browser_download_url':'https://fixture/SHA256SUMS'})
        (self.root/'fixtures/releases.json').write_text(json.dumps([{'tag_name':'v0.8.2','draft':False,'assets':assets}])+'\n')
        sums=''.join(hashlib.sha256((self.root/'fixtures'/a['name']).read_bytes()).hexdigest()+'  '+a['name']+('\r\n' if crlf else '\n') for a in assets if a['name'].endswith('.deb'))
        (self.root/'fixtures/SHA256SUMS').write_bytes(sums.encode())

    def test_local_success_preserves_state_and_caches(self):
        p=self.run_update();self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.version(),'0.8.2');self.assertEqual((self.root/'var/cache/qeli/qeli_0.8.2_amd64.deb').stat().st_mode&0o777,0o600)

    def test_local_update_needs_no_curl(self):
        (self.root/'usr/local/bin/curl').unlink()
        p=self.run_update();self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.version(),'0.8.2')

    def test_required_attestation_without_gh_refuses(self):
        self.online();self.env['QELI_VERIFY_ATTESTATION']='1';p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertIn('gh',p.stderr);self.assertFalse((self.root/'records/apt.log').exists());self.assertFalse(list((self.root/'tmp').iterdir()))

    def test_restart_failure_rolls_back_package(self):
        self.mode('restart_fail');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertEqual(self.version(),self.old);self.assertIn('rolled back',p.stderr)

    def test_install_refusal_is_not_success(self):
        self.mode('install_refused');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertEqual(self.version(),self.old);self.assertNotIn('Done —',p.stdout)

    def test_missing_local_file_refuses_before_download(self):
        self.online(False);self.env['QELI_DEB']='/fixtures/absent.deb';p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertFalse((self.root/'records/curl.log').exists());self.assertEqual(self.version(),self.old)

    def test_installer_missing_local_file_refuses_early(self):
        self.env['QELI_DEB']='/fixtures/absent.deb';p=self.run_update(True);self.assertNotEqual(p.returncode,0);self.assertIn('QELI_DEB',p.stderr);self.assertFalse((self.root/'records/apt.log').exists())

    def test_online_selects_host_architecture(self):
        self.online();p=self.run_update();self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.version(),'0.8.2');self.assertNotIn('arm64.deb',(self.root/'records/apt.log').read_text())

    def test_checksum_crlf(self):
        self.online(crlf=True);p=self.run_update();self.assertEqual(p.returncode,0,p.stderr)

    def test_checksum_mismatch_refuses(self):
        self.online();(self.root/'fixtures/SHA256SUMS').write_text('0'*64+'  qeli_0.8.2_amd64.deb\n');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertEqual(self.version(),self.old);self.assertFalse((self.root/'records/apt.log').exists());self.assertFalse(list((self.root/'tmp').iterdir()))

    def test_download_failure_cleans_owned_files(self):
        self.online();self.mode('download_failure');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertFalse(list((self.root/'tmp').iterdir()));self.assertEqual(self.version(),self.old)

    def test_legacy_cache_is_not_imported_or_deleted(self):
        legacy=self.root/'var/lib/qeli/packages';legacy.mkdir();p=legacy/'legacy.deb';p.write_bytes(b'untrusted');p.chmod(0o666);out=self.run_update();self.assertEqual(out.returncode,0,out.stderr);self.assertTrue(p.exists());self.assertFalse((self.root/'var/cache/qeli/legacy.deb').exists())

    def test_empty_pid_cannot_pass_health(self):
        self.mode('empty_pid');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertNotIn('Done —',p.stdout)

    def test_crash_new_rolls_back_package(self):
        self.mode('crash_new');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertEqual(self.version(),self.old);self.assertIn('rolled back',p.stderr)

    def test_rollback_false_success_falls_back_to_binary(self):
        self.mode('rollback_false');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertEqual(self.binary_version(),'qeli 0.8.1');self.assertEqual(self.version(),'0.8.2');self.assertIn('only the BINARY',p.stderr)

    def test_rollback_crash_loop_is_not_recovery(self):
        self.mode('rollback_flaps');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertEqual(self.version(),self.old);self.assertIn('is DOWN',p.stderr)

    def test_debian_revision_rollback_uses_package_version(self):
        self.install_old('0.8.1-1');self.mode('crash_new');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertEqual(self.version(),'0.8.1-1')

    def test_wrong_name_architecture_and_corruption_refuse(self):
        for package in ['other_0.8.2_amd64.deb','qeli_0.8.2_arm64.deb','corrupt.deb']:
            if package=='corrupt.deb':(self.root/'fixtures/corrupt.deb').write_text('not a deb')
            self.env['QELI_DEB']='/fixtures/'+package;p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertEqual(self.version(),self.old);self.assertFalse((self.root/'records/apt.log').exists())

    def test_architecture_all_is_admitted(self):
        self.env['QELI_DEB']='/fixtures/qeli_0.8.2_all.deb';p=self.run_update();self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(self.version(),'0.8.2')

    def test_lock_excludes_second_transaction(self):
        folder=self.root/'run/qeli-updater';folder.mkdir(mode=0o700)
        with (folder/'lock').open('w') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertIn('in progress',p.stderr);self.assertEqual(self.version(),self.old);self.assertFalse((self.root/'records/apt.log').exists())
        p=self.run_update();self.assertEqual(p.returncode,0,p.stderr)

    def test_lock_link_and_cache_link_refuse(self):
        folder=self.root/'run/qeli-updater';folder.mkdir(mode=0o700);(folder/'lock').symlink_to('/records/canary');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertFalse((self.root/'records/canary').exists())
        (folder/'lock').unlink();cache=self.root/'var/cache/qeli';shutil.rmtree(cache);cache.symlink_to('/records');p=self.run_update();self.assertNotEqual(p.returncode,0);self.assertFalse((self.root/'records/apt.log').exists())

if __name__=='__main__':unittest.main(verbosity=2)
