#!/usr/bin/env python3
"""Complete one-shot installer with actual CLI, crypto, firewall and mapped manager.

Only the manager name/filesystem adapter and dependency/account seed are fixtures.
Kernel /proc writes are refused; no host modules are present in the chroot.
"""
from pathlib import Path
import hashlib
import os
import re
import shutil
import stat
import tarfile
from urllib.parse import urlparse, parse_qs, unquote


def qualify(args, work, root, run, check, executable, copy_file, chroot, prop, ready, vpn):
    check('installer runs in exactly its owned service NET namespace',
          os.stat('/proc/self/ns/net').st_ino == os.stat('/run/netns/'+args.unit).st_ino)
    check('installer NET namespace differs from host PID1',
          os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino)
    for program in ['tr','openssl','ip','iptables','ip6tables','iptables-save','iptables-restore',
                    'ip6tables-save','ip6tables-restore','sysctl','modprobe','adduser','useradd',
                    'uname','tee','cmp','wc','seq']:
        executable(shutil.which(program))
    plugin=Path('/usr/lib/x86_64-linux-gnu/xtables')
    assert plugin.is_dir()
    for path in plugin.iterdir():
        if path.is_file():
            copy_file(path, root/path.as_posix().lstrip('/'))
    for name in ['etc/sysctl.d','etc/modules-load.d','var/lib/qeli','var/log/qeli','source']:
        (root/name).mkdir(parents=True,exist_ok=True)
    with tarfile.open(work/'installer-payload.tar') as archive:
        archive.extractall(root/'source',filter='data')
    copy_file(work/'install-qeli-server.sh',root/'installer.sh')
    copy_file(work/'release-binary',root/'fixtures/new-qeli')
    copy_file(work/'qeli_0.8.2_amd64.deb',root/'fixtures/original.deb')
    (root/'fixtures/new-qeli').chmod(0o755)
    if args.writable_mtu:
        run(['sysctl','-w','net.ipv4.tcp_mtu_probing=0'],'seed only owned NET MTU value')
        run(['mount','--bind','/proc/sys/net/ipv4/tcp_mtu_probing',str(root/'proc/sys/net/ipv4/tcp_mtu_probing')],'allow one per-NET kernel key')
        for file in ['etc/sysctl.d/99-qeli-perf.conf','etc/modules-load.d/qeli-bbr.conf']:
            (root/file).write_text('# administrator prior '+file+'\n');(root/file).chmod(0o644)
    setup=['QELI_PROFILE=fake-tls']
    if args.installer=='binary':
        setup += ['QELI_BIN=/fixtures/new-qeli','QELI_SRC=/source']
    else:
        setup += ['QELI_DEB=/fixtures/original.deb']
    rc, text = chroot(['env',*setup,'bash','/installer.sh','10.88.0.1'],
                     'complete actual one-shot '+args.installer,required=False)
    (work/'installer.log').write_text(text)
    check('complete installer exits successfully and reports Done',rc==0 and '== Done' in text,text[-3500:])
    check('installed exact qualified production ELF',
          hashlib.sha256((root/'usr/bin/qeli').read_bytes()).digest()==hashlib.sha256((work/'release-binary').read_bytes()).digest())
    uid=int(next(row for row in (root/'etc/passwd').read_text().splitlines() if row.startswith('qeli:')).split(':')[2])
    conf=root/'etc/qeli/server.conf'
    data=conf.read_text()
    check('only selected profile and private service-owned INI',
          re.findall(r'^\[profile:([^]]+)\]',data,re.M)==['fake-tls'] and
          conf.stat().st_uid==uid and stat.S_IMODE(conf.stat().st_mode)==0o600)
    check('panel enabled only over loopback HTTPS',
          re.search(r'^tls = true$',data,re.M) and re.search(r'^bind = 127.0.0.1$',data,re.M))
    users=(root/'etc/qeli/users.conf').read_text()
    check('all five users persisted by real Argon2 CLI',
          re.findall(r'^\[user:([^]]+)\]',users,re.M)==['phone'+str(i) for i in range(1,6)] and users.count('$argon2id$')==5)
    links=root/'etc/qeli/client-links'
    check('credential directory and six files are root private',links.stat().st_uid==0 and
          stat.S_IMODE(links.stat().st_mode)==0o700 and all((links/name).stat().st_uid==0 and
          stat.S_IMODE((links/name).stat().st_mode)==0o600 for name in
          ['phone'+str(i)+'.qeli' for i in range(1,6)]+['CONNECTION-STRINGS.txt']))
    check('successful install retires pending credential journal',not list(links.glob('INSTALL-PENDING-*')))
    pid=ready()
    check('real manager starts default service user',pid!='0' and prop('User')=='qeli')
    _, firewall=run(['iptables-save','-t','mangle'],'actual owned NET MSS rules')
    check('actual installer adds both IPv4 MSS directions',
          '-A PREROUTING -p tcp -m tcp --dport 443' in firewall and
          '-A OUTPUT -p tcp -m tcp --sport 443' in firewall and firewall.count('--set-mss 1240')==2,firewall)
    peer=args.unit+'-client'
    run(['ip','netns','add',peer],'owned installer client namespace')
    for argv in [
        ['ip','-n',args.unit,'link','add','q33pv','type','veth','peer','name','q33pc'],
        ['ip','-n',args.unit,'link','set','q33pc','netns',peer],
        ['ip','-n',args.unit,'addr','add','10.88.0.1/24','dev','q33pv'],
        ['ip','-n',args.unit,'link','set','q33pv','up'],
        ['ip','-n',peer,'link','set','lo','up'],
        ['ip','-n',peer,'addr','add','10.88.0.2/24','dev','q33pc'],
        ['ip','-n',peer,'link','set','q33pc','up'],
        ['ip','-n',peer,'route','add','default','via','10.88.0.1']]:
        run(argv,'owned installer peer carrier')
    uri=urlparse((links/'phone1.qeli').read_text().strip())
    params=parse_qs(uri.query)
    check('generated link pins actual key and chosen transport',uri.scheme=='qeli' and
          uri.hostname=='10.88.0.1' and uri.port==443 and params.get('proto')==['tcp'] and
          params.get('mode')==['fake-tls'] and re.fullmatch('[0-9a-f]{64}',params['key'][0]))
    client='[qeli]\nserver = 10.88.0.1:443\nproto = tcp\nuser = '+unquote(uri.username)+'\npass = '+unquote(uri.password)+'\nkey = '+params['key'][0]+'\nmode = fake-tls\ndev = q33pcvpn\ngateway = true\ndns = off\nkill_switch = false\n[logging]\nlevel = info\n'
    (work/'client.conf').write_text(client);(work/'client.conf').chmod(0o600)
    (work/'release-binary').chmod(0o755)
    vpn('installer-'+args.installer)
    snapshot={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
              [conf,root/'etc/qeli/users.conf',*sorted(links.glob('*.qeli'))]}
    rc, repeat=chroot(['env',*setup,'bash','/installer.sh','10.88.0.1'],
                     'real installer refuses unforced reentry',required=False)
    check('unforced reentry refuses before state or running process changes',rc!=0 and
          prop('MainPID')==pid and all(hashlib.sha256((root/name).read_bytes()).hexdigest()==sha
                                    for name,sha in snapshot.items()))
    rc, sysctl=chroot(['sysctl','-p','/etc/sysctl.d/99-qeli-perf.conf'],
                     'actual restricted proc rejects tuning',required=False)
    check('restricted proc really refuses sysctl rather than a stub',rc!=0 and
          ('Read-only file system' in sysctl or 'permission denied' in sysctl),sysctl)
    check('installer never claims unqualified kernel tuning applied',
          'BBR/PMTU sysctl applied' not in text and 'BBR/PMTU probing applied' not in text and
          'BBR/PMTU probing.' not in text and 'kernel tuning incomplete' in text)

    if args.writable_mtu:
        check('real namespaced MTU probing changed from 0 to 1',
              chroot(['sysctl','-n','net.ipv4.tcp_mtu_probing'],'actual applied MTU value')[1].strip()=='1')
        receipts=list(links.glob('kernel-tuning-*'));assert len(receipts)==1
        receipt=receipts[0]
        check('per-run root recovery receipt retains actual MTU baseline',
              'net.ipv4.tcp_mtu_probing=0\n' in (receipt/'runtime.before').read_text() and
              receipt.stat().st_uid==0 and stat.S_IMODE(receipt.stat().st_mode)==0o700 and
              all(p.stat().st_uid==0 and stat.S_IMODE(p.stat().st_mode)==0o600 for p in receipt.iterdir()))
        rc, rollback=chroot(['bash','-e','/'+str((receipt/'restore.txt').relative_to(root))],
                            'actual partial kernel rollback from generated instructions',required=False)
        check('restore reports other readonly kernel writes unavailable',rc!=0)
        check('actual MTU runtime value is restored to 0',
              chroot(['sysctl','-n','net.ipv4.tcp_mtu_probing'],'actual restored MTU value')[1].strip()=='0')
        for file in ['etc/sysctl.d/99-qeli-perf.conf','etc/modules-load.d/qeli-bbr.conf']:
            check('prior persistent file bytes and mode restored '+file,
                  (root/file).read_text()=='# administrator prior '+file+'\n' and
                  stat.S_IMODE((root/file).stat().st_mode)==0o644)
