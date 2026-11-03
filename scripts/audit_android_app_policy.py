#!/usr/bin/env python3
"""Per-app UID routing and Private DNS observations in a disposable Release AVD."""
import hashlib
import ipaddress
import json
import re
import time
from android_lab_ui import AndroidVpnSettings, wait_until

PACKAGES = ('com.qeli.test', 'com.qeli.auditprobe')


def app_policy_lifecycle(arun, evidence, echo, dns, result):
    checks = result['app_policy'] = dict(socket_probes=[], dns_probes=[], private_dns=[], strict_DoT='NOT_QUALIFIED_NO_TRUSTED_ENDPOINT')
    settings = AndroidVpnSettings(arun, evidence, result, 'Qeli', prefix='policy-')
    uid_text = arun('shell', 'cmd', 'package', 'list', 'packages', '-U', 'com.qeli').stdout
    uids = dict(re.findall(r'package:(com\.qeli(?:\.test|\.auditprobe)?) uid:([0-9]+)', uid_text))
    assert set(uids) == {'com.qeli', *PACKAGES} and len(set(uids.values())) == 3, uid_text
    result['probe_uids'] = uids
    assert result['apps_mode'] in ('include', 'exclude')
    original = {key:arun('shell','settings','get','global',key).stdout.strip() for key in ('private_dns_mode','private_dns_specifier')}
    checks['original_private_dns'] = original
    profile = 'tcp' if result['recovery_transport'] == 'tcp' else 'udp'
    subnet = '10.86.0.' if profile == 'tcp' else '10.87.0.'
    v6 = 'fd86:29:1:' if profile == 'tcp' else 'fd86:29:2:'

    def journal(package):
        return arun('shell','su','0','cat',f'/data/user/0/{package}/files/q29-probes.log',check=False).stdout

    def broadcast(package, *args):
        return arun('shell','am','broadcast','--include-stopped-packages','--receiver-foreground','-n',package+'/com.qeli.SystemNetworkProbeReceiver',*args,timeout=15)

    def socket_probe(stage, package, route, family, protocol):
        size = 16384 if protocol == 'tcp' else 257
        tag = 'Q29PROTECTED'
        payload = bytearray((i*31+17)%251 for i in range(size));payload[:len(tag)] = tag.encode()
        digest = hashlib.sha256(payload).hexdigest()
        expected = bytes(payload)[::-1] if protocol == 'tcp' else b'Q29:'+payload
        needle = f'COMPLETE tag={tag} uid={uids[package]} family={family} protocol={protocol} bytes={size} '
        initial = sum(needle in line for line in journal(package).splitlines())
        before = len(echo.rows)
        response = broadcast(package,'--es','tag',tag,'--es','family',family,'--es','protocol',protocol,'--ei','payload_bytes',str(size))
        wait_until(lambda:sum(needle in line for line in journal(package).splitlines())>initial,'per-app sender did not finish',10)
        line = [line for line in journal(package).splitlines() if needle in line][-1]
        time.sleep(.15)
        seen = [row for row in echo.rows[before:] if row.get('payload_sha256')==digest and row.get('protocol')==protocol and (':' in row['peer'])==(family=='ipv6')]
        success = 'reply=Q29:'+tag in line
        assert success == (route != 'blocked'), (stage,package,route,line,seen)
        if success:
            assert len(seen)==1 and seen[0]['bytes']==size and f'sha256={digest}' in line and f'reply_sha256={hashlib.sha256(expected).hexdigest()}' in line, (line,seen)
            tunneled = seen[0]['peer'].startswith(v6 if family=='ipv6' else subnet)
            assert tunneled == (route=='vpn'), (stage,package,route,seen)
        else:assert 'error=' in line and not seen, (line,seen)
        row = dict(stage=stage,package=package,uid=int(uids[package]),family=family,protocol=protocol,expected_route=route,success=success,receipts=seen,line=line)
        checks['socket_probes'].append(row)
        (evidence/f'policy-{stage}-{package}-{family}-{protocol}.log').write_text(response.stdout+response.stderr+'\n'+line+'\n')

    def dns_probe(stage, package, route, mode='raw'):
        name = f'q29-{time.time_ns()}.test'
        before = time.time()
        output = broadcast(package,'--es','tag','Q29PROTECTED','--es','dns_name',name,'--es','dns_mode',mode)
        wait_until(lambda:any(f'name={name} ' in line and 'done_ms=' in line for line in journal(package).splitlines()),'per-app DNS sender did not finish',12)
        lines = [line for line in journal(package).splitlines() if f'name={name} ' in line and 'done_ms=' in line]
        assert len(lines)==1 and f'uid={uids[package]} ' in lines[0],lines
        line=lines[0];success='answers=' in line or 'reply_sha256=' in line
        if route is not None:assert success==(route!='blocked'),(stage,package,mode,line)
        if success and mode=='system':assert {str(ipaddress.ip_address(v)) for v in line.split(' answers=',1)[1].split(',')}=={'198.19.0.1','2001:db8:29::1'},line
        if not success:assert 'error=' in line,line
        time.sleep(.15)
        receipts=[p for p in dns.rows if p.get('name')==name and p.get('answered')]
        if success:
            assert {p['qtype'] for p in receipts} == ({1,28} if mode=='system' else {1}), receipts
            if route is not None:
                assert all(p['peer'].startswith(subnet)==(route=='vpn') for p in receipts),(route,receipts)
        else:assert not receipts,(line,receipts)
        row=dict(stage=stage,package=package,uid=int(uids[package]),mode=mode,name=name,expected_route=route,success=success,receipts=receipts,host_before=before,host_after=time.time(),line=line)
        checks['dns_probes'].append(row)
        (evidence/f'policy-dns-{stage}-{package}-{mode}.log').write_text(output.stdout+output.stderr+'\n'+line+'\n')
        return row

    def group(stage, vpn, lockdown):
        for package in PACKAGES:
            route = ('vpn' if package==PACKAGES[0] else 'blocked' if lockdown else 'physical') if vpn else 'blocked' if lockdown else 'physical'
            for family in ('ipv4','ipv6'):
                for protocol in ('tcp','udp'):socket_probe(stage,package,route,family,protocol)
            dns_probe(stage,package,route)
        (evidence/f'policy-{stage}-vpn.txt').write_text(arun('shell','dumpsys','vpn_management').stdout)
        print('APP_POLICY_COMPLETE '+stage,flush=True)

    def private_dns(stage):
        for mode in ('off','opportunistic','hostname'):
            arun('shell','settings','put','global','private_dns_specifier','q29-unreachable.invalid')
            arun('shell','settings','put','global','private_dns_mode',mode)
            time.sleep(2)
            actual={key:arun('shell','settings','get','global',key).stdout.strip() for key in original}
            assert actual==dict(private_dns_mode=mode,private_dns_specifier='q29-unreachable.invalid'),actual
            label=stage+'-'+mode
            (evidence/f'policy-dns-{label}-resolver.txt').write_text(arun('shell','dumpsys','dnsresolver').stdout)
            (evidence/f'policy-dns-{label}-connectivity.txt').write_text(arun('shell','dumpsys','connectivity').stdout)
            # A strict unreachable provider is a diagnostic, not a successful DoT fixture.
            rows=[dns_probe(label,PACKAGES[0],None if mode=='hostname' else 'vpn','system'),dns_probe(label,PACKAGES[0],'vpn','raw')]
            checks['private_dns'].append(dict(stage=stage,settings=actual,probes=rows,strict_endpoint='UNREACHABLE_NEGATIVE_DIAGNOSTIC' if mode=='hostname' else None))
        arun('shell','settings','put','global','private_dns_mode','off')
        time.sleep(1)

    def logs():return arun('shell','logcat','-d','-s','VpnSvc:D').stdout
    def policy(lockdown):
        actual={key:arun('shell','settings','get','secure',key).stdout.strip() for key in ('always_on_vpn_app','always_on_vpn_lockdown')}
        assert actual==dict(always_on_vpn_app='com.qeli',always_on_vpn_lockdown=str(int(lockdown))),actual
        checks.setdefault('system_policies',[]).append(actual)

    try:
        arun('shell','settings','put','global','private_dns_mode','off')
        group('baseline',False,False)
        arun('shell','am','start','-n','com.qeli/.MainActivity')
        old=logs().count('Android VPN CONNECTED:')
        settings.open();settings.switch('Always-on VPN',True)
        wait_until(lambda:logs().count('Android VPN CONNECTED:')>old,'per-app VPN did not publish CONNECTED',35)
        policy(False)
        group('connected-open',True,False)
        private_dns('open')
        settings.open();settings.switch('Block connections without VPN',True)
        policy(True)
        group('connected-lock',True,True)
        private_dns('lock')
        arun('shell','am','force-stop','com.qeli')
        wait_until(lambda:not arun('shell','pidof','com.qeli',check=False).stdout.strip(),'force-stop left Qeli process',10)
        policy(True);group('stopped-lock',False,True)
        old=logs().count('Android VPN CONNECTED:')
        arun('shell','am','start','-n','com.qeli/.MainActivity')
        settings.open();settings.switch('Block connections without VPN',False);settings.switch('Always-on VPN',False)
        settings.switch('Always-on VPN',True);settings.switch('Block connections without VPN',True)
        wait_until(lambda:logs().count('Android VPN CONNECTED:')>old,'per-app manual recovery did not publish CONNECTED',35)
        policy(True);group('recovery-lock',True,True)
        settings.open();settings.switch('Block connections without VPN',False)
        policy(False);group('lockdown-disabled',True,False)
        settings.open();settings.switch('Always-on VPN',False);settings.forget()
        wait_until(lambda:not re.search(r'^\d+: tun\d',arun('shell','su','0','ip','-o','link','show').stdout,re.M),'revoke left TUN',15)
        group('revoked',False,False)
        result['system_revoke']='PASS';checks['status']='PASS'
    finally:
        for key,value in original.items():
            arun('shell','settings','delete' if value=='null' else 'put','global',key,*([] if value=='null' else [value]))
        actual={key:arun('shell','settings','get','global',key).stdout.strip() for key in original}
        assert actual==original,(original,actual)
        checks['private_dns_settings_restored']=True
        (evidence/'app-policy.json').write_text(json.dumps(checks,indent=2)+'\n')