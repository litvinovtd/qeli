#!/usr/bin/env python3
"""Q33 real apt/dpkg plus a real manager, using owned filesystem and unit mapping.

Remote entrypoint: root, private mount+NET namespace, verified package/updater,
precreated owned unit link and network namespace. No HTTP or package dependency
bootstrap: dependency status is copied from the lab, qeli is removed from that copy.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--vpn', action='store_true', help='connect a real pinned client across update and rollback')
    parser.add_argument('--installer', choices=['binary','deb'])
    parser.add_argument('--writable-mtu', action='store_true', help='allow only the namespaced tcp_mtu_probing key for actual partial apply/restore')
    args = parser.parse_args()
    work = args.root.resolve()
    assert work == args.root and work.parent == Path('/var/tmp')
    assert re.fullmatch(r'qeli-q33-pkg-[0-9]+', args.unit)
    unit = args.unit + '.service'
    root = work / 'root'
    root.mkdir()
    result = {'status': 'IN_PROGRESS', 'checks': [], 'commands': []}
    client = None
    client_namespace = args.unit + '-client'
    client_network_created = False
    client_log = None
    destination = '10.9.2.1' if args.installer else '10.77.1.1'

    def save():
        (work / 'results.json').write_text(json.dumps(result, indent=2))

    def run(argv, label, timeout=120, required=True):
        process = subprocess.run(argv, capture_output=True, timeout=timeout)
        text = (process.stdout + process.stderr).decode(errors='replace')
        result['commands'].append({'label': label, 'argv': argv, 'rc': process.returncode, 'output': text})
        save()
        if required:
            assert process.returncode == 0, (label, process.returncode, text[-3000:])
        return process.returncode, text

    def check(label, ok, detail=None):
        result['checks'].append({'name': label, 'status': 'PASS' if ok else 'FAIL', 'detail': detail})
        save()
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        assert ok, (label, detail)

    def copy_file(source, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    def executable(source, name=None):
        source = Path(source)
        copy_file(source, root / 'usr/bin' / (name or source.name))
        output = subprocess.run(['ldd', str(source)], capture_output=True, text=True).stdout
        for library in re.findall(r'(/[^\s]+)', output):
            copy_file(library, root / library.lstrip('/'))

    def chroot(argv, label, required=True):
        env = ['/usr/bin/env', 'PATH=/usr/local/bin:/usr/bin:/bin', 'LC_ALL=C',
               'DEBIAN_FRONTEND=noninteractive', 'SYSTEMD_IGNORE_CHROOT=1']
        return run(['chroot', str(root), *env, *argv], label, required=required)

    def prop(key):
        return run(['systemctl', 'show', unit, '-p', key, '--value'], key)[1].strip()

    def ready():
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            pid = prop('MainPID')
            if pid != '0':
                _, text = run(['nsenter', '-t', pid, '-n', '--', 'ss', '-lnt'], 'real unit listeners', required=False)
                if ':443 ' in text and (':'+('8080' if args.installer else '24990')+' ') in text:
                    return pid
            time.sleep(.25)
        raise AssertionError('owned packaged service not ready')

    def stop_client(required=True):
        nonlocal client, client_log
        if client is None:
            return
        try:
            if client.poll() is None:
                _, output = run(['ip','netns','pids',client_namespace], 'owned client PID inventory')
                for pid in output.split():
                    try:
                        if (Path('/proc')/pid/'exe').resolve() == work/'release-binary':
                            os.kill(int(pid), signal.SIGTERM)
                    except (OSError, ProcessLookupError):
                        pass
                client.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(client.pid, signal.SIGKILL)
            client.wait(timeout=10)
            result['forced_client_cleanup'] = True
            save()
            if required:
                raise AssertionError('owned VPN client did not stop cleanly')
        finally:
            client = None
            if client_log is not None:
                client_log.close();client_log = None

    def vpn_roundtrip(label):
        nonlocal client, client_log
        stop_client()
        script = """set -eu
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /var/lib
mount -t tmpfs tmpfs /var/log
mkdir -p /var/lib/qeli /var/log/qeli
exec "$1" client -c "$2"
"""
        client_log = (work/('client-'+label+'.log')).open('wb')
        argv = ['ip','netns','exec',client_namespace,'unshare','--mount','--pid','--fork',
                '--kill-child=KILL','--mount-proc','bash','-c',script,'q33-client',
                str(work/'release-binary'),str(work/'client.conf')]
        client = subprocess.Popen(argv,stdout=client_log,stderr=subprocess.STDOUT,start_new_session=True)
        deadline = time.monotonic()+30
        ok = False
        while time.monotonic()<deadline and client.poll() is None:
            rc, _ = run(['ip','-n',client_namespace,'link','show','q33pcvpn'], 'actual client TUN '+label, required=False)
            if rc == 0:
                rc, output = run(['ip','netns','exec',client_namespace,'ping','-c','3','-W','2',destination],
                                 'real inner tunnel roundtrip '+label,required=False)
                if rc == 0:
                    ok = True
                    break
            time.sleep(.25)
        check('packaged systemd service carries authenticated VPN traffic '+label,ok)
        _, routes = run(['ip','-n',client_namespace,'route','get',destination],'inner route proof '+label)
        check('inner destination uses actual client TUN '+label,'dev q33pcvpn' in routes)
        stop_client()
        rc, _ = run(['ip','-n',client_namespace,'link','show','q33pcvpn'],'client clean stop '+label,required=False)
        check('client clean stop removes TUN '+label,rc!=0 and not result.get('forced_client_cleanup'))

    def state_snapshot():
        paths = ['server.conf', 'users.conf', 'identity/fixture.key',
                 'client-links/INSTALL-PENDING-fixture', 'server.conf.bak-fixture']
        return {name: {'sha256': hashlib.sha256((root/'etc/qeli'/name).read_bytes()).hexdigest(),
                       'uid': (root/'etc/qeli'/name).stat().st_uid,
                       'mode': stat.S_IMODE((root/'etc/qeli'/name).stat().st_mode)} for name in paths}

    try:
        run(['mount', '--make-rprivate', '/'], 'private mount propagation')
        for program in ['bash','env','id','date','awk','sed','sort','head','tail','grep','find','xargs',
                        'cut','cp','rm','install','stat','dirname','basename','mktemp','sha256sum','flock',
                        'dpkg','dpkg-deb','dpkg-query','tar','diff','ldconfig','start-stop-daemon',
                        'dpkg-split','chown','chmod','mkdir','cat','ln','getent','setcap','sleep',
                        'apt-get','perl','readlink','test','setpriv']:
            executable(shutil.which(program))
        executable('/usr/bin/systemctl', 'systemctl.real')
        output = subprocess.run(['ldd', str(work/'release-binary')], capture_output=True, text=True).stdout
        for library in re.findall(r'(/[^\s]+)', output):
            copy_file(library, root/library.lstrip('/'))
        for folder in ['usr/share/debconf','usr/share/dpkg','usr/share/perl5/Debconf','usr/share/perl5/Dpkg']:
            shutil.copytree('/'+folder, root/folder)
        for parent in ['/usr/share/perl','/usr/lib/x86_64-linux-gnu/perl','/usr/lib/x86_64-linux-gnu/perl-base']:
            if Path(parent).is_dir():
                shutil.copytree(parent, root/parent.lstrip('/'))
        shutil.copytree('/usr/lib/apt', root/'usr/lib/apt')
        for path in Path('/usr/lib/apt/methods').iterdir():
            if path.is_file():
                output = subprocess.run(['ldd', str(path)], capture_output=True, text=True).stdout
                for library in re.findall(r'(/[^\s]+)', output):
                    copy_file(library, root/library.lstrip('/'))
        for name in ['tmp','run/systemd/system','run/qeli-audit-unit','run/qeli-audit-dropin','etc/qeli',
                     'etc/systemd/system','var/lib/dpkg/info','var/lib/dpkg/updates','var/lib/dpkg/triggers',
                     'var/cache/debconf','var/cache/qeli','var/cache/apt/archives/partial','var/log/apt',
                     'var/lib/apt/lists/partial','etc/apt/sources.list.d','etc/apt/apt.conf.d','etc/apt/preferences.d','usr/local/bin','fixtures','dev','proc']:
            (root/name).mkdir(parents=True, exist_ok=True)
        (root/'bin').mkdir()
        for name in ['sh','bash']:
            (root/'bin'/name).symlink_to('../usr/bin/bash')
        for name, number in [('null',3),('zero',5),('random',8),('urandom',9)]:
            os.mknod(root/'dev'/name, stat.S_IFCHR | 0o666, os.makedev(1,number))
        for name in ['passwd','group']:
            rows=[line for line in Path('/etc/'+name).read_text().splitlines() if line.split(':')[0] in ['root','qeli','_apt']]
            (root/'etc'/name).write_text('\n'.join(rows)+'\n')
        (root/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
        copy_file('/etc/debconf.conf', root/'etc/debconf.conf')
        records=Path('/var/lib/dpkg/status').read_text().split('\n\n')
        records=[entry for entry in records if not re.search(r'^Package: qeli$', entry, re.M)]
        (root/'var/lib/dpkg/status').write_text('\n\n'.join(records)+'\n\n')
        for filelist in Path('/var/lib/dpkg/info').glob('*.list'):
            if filelist.name != 'qeli.list':
                copy_file(filelist, root/'var/lib/dpkg/info'/filelist.name)
        (root/'etc/apt/sources.list').touch()
        (root/'etc/apt/apt.conf').write_text('APT::Get::List-Cleanup "false"; Acquire::Retries "0"; Dpkg::Use-Pty "0";\n')
        (root/'var/cache/qeli').chmod(0o700)
        # Bind only the manager socket and this test's exact owned unit/drop-in directories.
        (root/'run/systemd/private').touch()
        run(['mount','--bind','/run/systemd/private',str(root/'run/systemd/private')], 'real manager socket')
        for source, target in [(work/'unit-map',root/'run/qeli-audit-unit'),
                               (Path('/run/systemd/system')/(unit+'.d'),root/'run/qeli-audit-dropin')]:
            run(['mount','--bind',str(source),str(target)], 'owned manager paths')
        run(['mount','--bind','/proc',str(root/'proc')], 'read-only process inspection')
        run(['mount','-o','remount,bind,ro',str(root/'proc')], 'protect proc')
        wrapper = r'''#!/bin/bash
set -euo pipefail
render() {
 [ -f /lib/systemd/system/qeli.service ] || return 0
 awk -v name='UNITNAME' -v net='/run/netns/UNITNAME' -v binary='ROOTFS/usr/bin/qeli' -v conf='ROOTFS/etc/qeli' '
 /^StateDirectory=|^RuntimeDirectory=|^LogsDirectory=/ {sub(/=qeli$/, "="name)}
 /^\[Install\]/ {print "NetworkNamespacePath="net; print "BindReadOnlyPaths="binary":/usr/bin/qeli"; print "BindPaths="conf":/etc/qeli"; print "Environment=QELI_CONTROL_SOCKET=/run/"name"/control.sock"; print ""}
 {print}
 ' /lib/systemd/system/qeli.service > /run/qeli-audit-unit/UNITNAME.service.tmp
 mv /run/qeli-audit-unit/UNITNAME.service.tmp /run/qeli-audit-unit/UNITNAME.service
 if [ -f /etc/systemd/system/qeli.service.d/run-as.conf ] && [ ! -L /etc/systemd/system/qeli.service.d/run-as.conf ]; then
  cp /etc/systemd/system/qeli.service.d/run-as.conf /run/qeli-audit-dropin/run-as.conf
 else rm -f /run/qeli-audit-dropin/run-as.conf; fi
}
case "${1:-}" in
 daemon-reload) [ "$#" = 1 ] || exit 93; render ;;
 start|stop|restart|show|is-active|status|enable|disable)
  args=();found=no
  for arg in "$@"; do
   case "$arg" in qeli|qeli.service) args+=('UNITNAME.service'); found=yes ;; *) args+=("$arg") ;; esac
  done
  [ "$found" = yes ] || exit 94
  grep -Fx 'NetworkNamespacePath=/run/netns/UNITNAME' /run/qeli-audit-unit/UNITNAME.service >/dev/null
  grep -Fx 'BindReadOnlyPaths=ROOTFS/usr/bin/qeli:/usr/bin/qeli' /run/qeli-audit-unit/UNITNAME.service >/dev/null
  grep -Fx 'BindPaths=ROOTFS/etc/qeli:/etc/qeli' /run/qeli-audit-unit/UNITNAME.service >/dev/null
  case "$1" in enable|disable) args+=(--runtime) ;; esac
  set -- "${args[@]}"
  ;;
 *) echo "unapproved manager operation" >&2;exit 95 ;;
esac
exec /usr/bin/systemctl.real "$@"
'''.replace('UNITNAME',args.unit).replace('ROOTFS',str(root))
        # Wrapper is a name/path adapter; it runs the genuine manager client and never fabricates health.
        if args.installer:
            wrapper=wrapper.replace('print "Environment=QELI_CONTROL_SOCKET', 'print "BindPaths=ROOTSTATE:/var/lib/qeli"; print "Environment=QELI_CONTROL_SOCKET').replace('ROOTSTATE',str(root/'var/lib/qeli'))
        (root/'usr/bin/systemctl').write_text(wrapper)
        (root/'usr/bin/systemctl').chmod(0o755)
        executable(shutil.which('mv'))
        copy_file(work/'update-qeli-server.sh',root/'update.sh')
        if args.installer:
            from audit_installer_manager_case import qualify
            qualify(args, work, root, run, check, executable, copy_file, chroot, prop, ready, vpn_roundtrip)
            result['status']='PASS';save()
            return 0
        for revision in [1,2,3,4]:
            stage=work/('package-'+str(revision))
            run(['dpkg-deb','-R',str(work/'qeli_0.8.2_amd64.deb'),str(stage)], 'extract production package')
            control=stage/'DEBIAN/control'
            control.write_text(re.sub(r'^Version: .*$', 'Version: 0.8.2-'+str(revision),control.read_text(),flags=re.M))
            if revision==3:
                service=stage/'lib/systemd/system/qeli.service'
                service.write_text(service.read_text().replace('ExecStart=/usr/bin/qeli server --config /etc/qeli/server.conf','ExecStart=/usr/bin/qeli intentional-audit-startup-failure'))
            if revision==4:
                (stage/'usr/bin/qeli').write_bytes(b'not an ELF audit fault\n')
            package=root/'fixtures'/('qeli_0.8.2-'+str(revision)+'_amd64.deb')
            run(['dpkg-deb','--root-owner-group','-Zxz','--build',str(stage),str(package)], 'build revision/fault package',timeout=180)
        chroot(['/usr/bin/dpkg','-i','/fixtures/qeli_0.8.2-1_amd64.deb'],'fresh production maintainer scripts')
        check('fresh package configured by actual dpkg',chroot(['dpkg-query','-W','-f=${Status} ${Version}','qeli'],'fresh status')[1]=='install ok installed 0.8.2-1')
        (root/'etc/qeli/server.conf').write_text('''[auth]
users_file = /etc/qeli/users.conf
[web]
enabled = true
bind = 127.0.0.1
port = 24990
tls = false
secure_cookie = false
base_path = /audit
[profile:fixture]
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = q33pkg
identity_key = /etc/qeli/identity/fixture.key
tun.address = 10.77.1.1
pool.cidr = 10.77.1.0/24
routing.forward_private = false
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = fake-tls
''')
        (root/'etc/qeli/server.conf').chmod(0o600)
        chroot(['qeli','set-web-password','--password','synthetic-package-panel-password','--config','/etc/qeli/server.conf'],'real panel password')
        chroot(['qeli','add-client','audit-package-user','--password','synthetic-package-user-password','--config','/etc/qeli/server.conf'],'real user persistence')
        links=root/'etc/qeli/client-links';links.mkdir(exist_ok=True);links.chmod(0o700)
        for path in [links/'INSTALL-PENDING-fixture',root/'etc/qeli/server.conf.bak-fixture']:
            path.write_text('synthetic administrator receipt\n');path.chmod(0o600)
        chroot(['qeli','set-service-user','qeli'],'real ownership/default run-as')
        chroot(['systemctl','start','qeli'],'real fresh package startup')
        pid=ready();check('fresh package supervisor and worker ready',pid!='0')
        if args.vpn:
            run(['ip','netns','add',client_namespace],'create own isolated peer namespace')
            client_network_created = True
            for argv in [
                ['ip','-n',args.unit,'link','add','q33pv','type','veth','peer','name','q33pc'],
                ['ip','-n',args.unit,'link','set','q33pc','netns',client_namespace],
                ['ip','-n',args.unit,'addr','add','10.88.0.1/24','dev','q33pv'],
                ['ip','-n',args.unit,'link','set','q33pv','up'],
                ['ip','-n',client_namespace,'link','set','lo','up'],
                ['ip','-n',client_namespace,'addr','add','10.88.0.2/24','dev','q33pc'],
                ['ip','-n',client_namespace,'link','set','q33pc','up'],
                ['ip','-n',client_namespace,'route','add','default','via','10.88.0.1']]:
                run(argv,'owned peer carrier')
            _, identity = chroot(['setpriv','--reuid=qeli','--regid=qeli','--init-groups','qeli','show-identity','--config','/etc/qeli/server.conf'],'actual packaged server key')
            keys = re.findall(r'\b[0-9a-f]{64}\b',identity);assert len(keys)==1
            conf = '[qeli]\nserver = 10.88.0.1:443\nproto = tcp\nuser = audit-package-user\npass = synthetic-package-user-password\nkey = '+keys[0]+'\nmode = fake-tls\ndev = q33pcvpn\ngateway = true\ndns = off\nkill_switch = false\n[logging]\nlevel = info\n'
            (work/'client.conf').write_text(conf);(work/'client.conf').chmod(0o600)
            (work/'release-binary').chmod(0o755)
            vpn_roundtrip('fresh')
        baseline=state_snapshot();result['preserved_state']=baseline;save()
        shutil.copy2(root/'fixtures/qeli_0.8.2-1_amd64.deb',root/'var/cache/qeli/qeli_0.8.2-1_amd64.deb')
        (root/'var/cache/qeli/qeli_0.8.2-1_amd64.deb').chmod(0o600)
        for revision in [2,3,4]:
            rc,output=chroot(['env','QELI_DEB=/fixtures/qeli_0.8.2-'+str(revision)+'_amd64.deb','bash','/update.sh','--force'],'real updater revision'+str(revision),required=False)
            check('updater exit reflects revision'+str(revision),rc==(0 if revision==2 else 1),output[-1800:])
            current=chroot(['dpkg-query','-W','-f=${Status} ${Version}','qeli'],'installed state after revision'+str(revision))[1]
            check('exact package revision installed/recovered '+str(revision),current=='install ok installed 0.8.2-2',current)
            nextpid=ready();check('real service restarted/recovered '+str(revision),nextpid!=pid);pid=nextpid
            check('state bytes/owner/mode preserved '+str(revision),state_snapshot()==baseline)
            if revision!=2:
                check('failure reported as rollback '+str(revision),'rolled back' in output and '== Done ' not in output)
            check('real installed ELF restored '+str(revision),hashlib.sha256((root/'usr/bin/qeli').read_bytes()).hexdigest()==hashlib.sha256((work/'release-binary').read_bytes()).hexdigest())
            if args.vpn:
                vpn_roundtrip('revision'+str(revision))
        cache=root/'var/cache/qeli/qeli_0.8.2-2_amd64.deb'
        check('rollback cache private and exact package',cache.stat().st_uid==0 and stat.S_IMODE(cache.stat().st_mode)==0o600 and hashlib.sha256(cache.read_bytes()).digest()==hashlib.sha256((root/'fixtures/qeli_0.8.2-2_amd64.deb').read_bytes()).digest())
        chroot(['apt-get','remove','-y','qeli'],'real package remove')
        check('prerm stops actual owned service',prop('MainPID')=='0')
        check('remove preserves operator state',state_snapshot()==baseline)
        chroot(['dpkg','--purge','qeli'],'real package purge')
        check('purge preserves operator state',state_snapshot()==baseline)
        check('purge removes packaged examples',not(root/'etc/qeli/server.conf.example').exists())
        result['status']='PASS';save()
    except BaseException:
        import traceback
        result['status']='FAIL';result['error']=traceback.format_exc();save();raise
    finally:
        stop_client(required=False)
        if client_network_created or (args.installer and (Path('/run/netns')/client_namespace).exists()):
            run(['ip','netns','delete',client_namespace],'remove only owned peer namespace')
        run(['systemctl','stop',unit],'stop only owned service',required=False)
        result['owned_main_pid_after_stop']=prop('MainPID')
        save()
    return 0


if __name__=='__main__':
    raise SystemExit(main())
