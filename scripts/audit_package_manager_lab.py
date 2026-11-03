#!/usr/bin/env python3
"""Run the Q33 package/manager fixture on a lab, without replacing its installation."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import shlex
import subprocess
import sys
import traceback
from native_lab import connect_lab
from audit_release_matrix_lab import snapshot

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--package-sha256',required=True)
    parser.add_argument('--binary-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--host',default='10.66.116.11')
    parser.add_argument('--reuse-owned-inputs')
    parser.add_argument('--vpn',action='store_true',help='qualify actual client traffic through owned packaged service')
    parser.add_argument('--installer', choices=['binary','deb'], help='run the complete one-shot installer instead of updater cases')
    parser.add_argument('--writable-mtu', action='store_true', help='allow only the namespaced tcp_mtu_probing key for actual partial apply/restore')
    sys.stdout.reconfigure(errors="backslashreplace")
    args=parser.parse_args()
    if args.writable_mtu and not args.installer:
        parser.error('writable-mtu requires the verified installer NET gate')
    for path,sha in [(args.package,args.package_sha256),(args.binary,args.binary_sha256)]:
        if hashlib.sha256(path.read_bytes()).hexdigest()!=sha:
            parser.error('explicit artifact hash mismatch')
    if args.reuse_owned_inputs and not __import__('re').fullmatch(r'/var/tmp/qeli-q33-pkg-[0-9]+',args.reuse_owned_inputs):
        parser.error('reuse source must be a prior owned package fixture')
    args.output.mkdir(parents=True,exist_ok=False)
    out=args.output
    name='qeli-q33-pkg-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S%f')
    remote='/var/tmp/'+name
    unit=name+'.service'
    unitfile='/run/systemd/system/'+unit
    dropin=unitfile+'.d'
    client=connect_lab(args.host,'root',sys.stdin.readline().strip())
    result={'status':'IN_PROGRESS','remote':remote,'unit':unit,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'package_sha256':args.package_sha256,'binary_sha256':args.binary_sha256,'commands':[]}
    created=False
    network=False
    mapped=False

    def save():
        (out/'outer-results.json').write_text(json.dumps(result,indent=2))

    def run(argv,label,timeout=30,required=True):
        command=shlex.join(argv)
        text,rc=client.run(command,timeout)
        result['commands'].append({'label':label,'argv':argv,'rc':rc,'output':text})
        save()
        if required:
            assert rc==0,(label,rc,text[-3000:])
        return text,rc

    try:
        result['host_before']=snapshot(client)
        for key,argv in [('service',['systemctl','show','qeli','-p','MainPID','-p','ExecMainStartTimestampMonotonic','-p','ActiveState']),('binary',['sha256sum','/usr/bin/qeli'])]:
            result[key+'_before']=run(argv,key+' before')[0]
        run(['test','!','-e',remote],'fresh own root')
        run(['mkdir','-m','755',remote],'create owned package root');created=True
        run(['mkdir',remote+'/unit-map',dropin],'fresh owned manager directories')
        mapped=True
        run(['test','!','-e',unitfile],'fresh own unit')
        run(['ln','-s',remote+'/unit-map/'+unit,unitfile],'map only own unit')
        run(['ip','netns','add',name],'owned service namespace');network=True
        for command in [['link','set','lo','up'],['link','add','wan0','type','dummy'],['link','set','wan0','up'],['addr','add','192.0.2.1/24','dev','wan0'],['route','add','default','dev','wan0']]:
            run(['ip','-n',name,*command],'owned service network')
        inputs={}
        sources=[(args.package,'qeli_0.8.2_amd64.deb'),(args.binary,'release-binary'),(ROOT/'update-qeli-server.sh','update-qeli-server.sh'),(ROOT/'scripts/audit_package_manager_fixture.py','fixture.py')]
        if args.installer:
            archive=out/'installer-payload.tar'
            subprocess.run(['git','archive','--format=tar','--output='+str(archive.resolve()),'HEAD','qeli/config','qeli/debian'],cwd=ROOT,check=True)
            sources += [(ROOT/'install-qeli-server.sh','install-qeli-server.sh'),(ROOT/'scripts/audit_installer_manager_case.py','audit_installer_manager_case.py'),(archive,'installer-payload.tar')]
            result['kernel_before']=run(['sysctl','net.ipv4.tcp_mtu_probing','net.ipv4.tcp_congestion_control','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem','net.core.rmem_max','net.core.wmem_max'],'host tuning before')[0]
        with client.open_sftp() as sftp:
            for source,target in sources:
                if args.reuse_owned_inputs and target in ['qeli_0.8.2_amd64.deb','release-binary']:
                    prior=args.reuse_owned_inputs+'/'+target
                    run(['test','!','-L',prior],'reuse nonlinked input')
                    assert run(['sha256sum',prior],'reuse prior input SHA')[0].split()[0]==hashlib.sha256(source.read_bytes()).hexdigest()
                    run(['cp','--',prior,remote+'/'+target],'copy only prior owned input')
                else:
                    sftp.put(str(source),remote+'/'+target)
                sha=hashlib.sha256(source.read_bytes()).hexdigest()
                assert run(['sha256sum',remote+'/'+target],'input SHA '+target)[0].split()[0]==sha
                inputs[target]=sha
        (out/'inputs.json').write_text(json.dumps(inputs,indent=2))
        text,rc=run(['timeout','--signal=TERM','--kill-after=20','600',*(['nsenter','--net=/run/netns/'+name,'unshare','--mount'] if args.installer else ['unshare','--mount','--net']),'python3','-u','-B',remote+'/fixture.py','--root',remote,'--unit',name,*(['--vpn'] if args.vpn else []),*(['--installer',args.installer] if args.installer else []),*(['--writable-mtu'] if args.writable_mtu else [])],'actual apt/dpkg manager fixture',timeout=650,required=False)
        (out/'driver.log').write_text(text,encoding='utf8')
        print(text[-12000:],flush=True)
        with client.open_sftp() as sftp:
            sftp.get(remote+'/results.json',str(out/'results.json'))
        assert rc==0 and json.loads((out/'results.json').read_text())['status']=='PASS'
        result['status']='PASS'
    except BaseException:
        result['status']='FAIL';result['error']=traceback.format_exc();save();raise
    finally:
        try:
            if mapped:
                result['journal']=run(['journalctl','-u',unit,'--no-pager','-n','150'],'owned package journal',required=False)[0]
                run(['systemctl','stop',unit],'stop own package unit',required=False)
                pid=run(['systemctl','show',unit,'--value','-p','MainPID'],'own stopped PID')[0].strip()
                assert pid=='0',pid
                code="from pathlib import Path; u=Path("+repr(unitfile)+"); d=Path("+repr(dropin)+"); assert u.parent==d.parent==Path('/run/systemd/system') and u.name=="+repr(unit)+";\nif u.is_symlink():\n assert str(u.readlink())=="+repr(remote+'/unit-map/'+unit)+";u.unlink()\nif d.exists():\n assert not d.is_symlink();\n for p in d.iterdir():\n  assert p.name=='run-as.conf' and p.is_file() and not p.is_symlink();p.unlink()\n d.rmdir()"
                run(['python3','-B','-c',code],'remove only own manager mapping')
                run(['systemctl','daemon-reload'],'unload own manager mapping')
            if network:
                run(['ip','netns','delete',name],'remove own namespace')
            if created:
                for parent,dest in [('/var/lib','manager-state'),('/var/log','manager-logs')]:
                    code="from pathlib import Path;p=Path("+repr(parent+'/'+name)+"); d=Path("+repr(remote+'/'+dest)+");\nif p.exists():\n assert p.parent==Path("+repr(parent)+") and not p.is_symlink() and not d.exists();p.rename(d)"
                    run(['python3','-B','-c',code],'retain owned manager '+parent)
            result['host_after']=snapshot(client)
            for key,argv in [('service',['systemctl','show','qeli','-p','MainPID','-p','ExecMainStartTimestampMonotonic','-p','ActiveState']),('binary',['sha256sum','/usr/bin/qeli'])]:
                result[key+'_after']=run(argv,key+' after')[0]
            if args.installer:
                result['kernel_after']=run(['sysctl','net.ipv4.tcp_mtu_probing','net.ipv4.tcp_congestion_control','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem','net.core.rmem_max','net.core.wmem_max'],'host tuning after')[0]
                assert result['kernel_before']==result['kernel_after'],'host kernel tuning changed'
            result['host_restored']=result['host_before']==result['host_after'] and all(result[key+'_before']==result[key+'_after'] for key in ['service','binary'])
            save()
            assert result['host_restored'],'host snapshot changed'
        finally:
            client.close()
    print('PASS actual apt/dpkg/manager fixture; owned retained root '+remote,flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
