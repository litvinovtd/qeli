#!/usr/bin/env python3
"""Authenticated offline DoT fixture; test CA only in a disposable readonly Android AVD."""
import hashlib,json,re,socket,ssl,struct,subprocess,threading,time
from pathlib import Path
from android_lab_ui import wait_until
from audit_android_dns_fixture import response,PROVIDER,UNTRUSTED_PROVIDER

class DnsTlsFixture:
    def __init__(self,root,evidence):
        self.root,self.evidence=root,evidence;self.rows=[];self.lock=threading.Lock();self.closing=threading.Event();self.clients=[];self.workers=[]
        for args in (
            ['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Q29 disposable lab root','-keyout',str(root/'dot-ca.key'),'-out',str(root/'dot-ca.pem'),'-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],
            ['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+PROVIDER,'-keyout',str(root/'dot-server.key'),'-out',str(root/'dot-server.csr')]):
            subprocess.run(['openssl',*args],check=True,capture_output=True)
        (root/'dot.ext').write_text('subjectAltName=DNS:'+PROVIDER+',DNS:'+UNTRUSTED_PROVIDER+'\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        subprocess.run(['openssl','x509','-req','-in',str(root/'dot-server.csr'),'-CA',str(root/'dot-ca.pem'),'-CAkey',str(root/'dot-ca.key'),'-CAcreateserial','-days','2','-extfile',str(root/'dot.ext'),'-out',str(root/'dot-server.pem')],check=True,capture_output=True)
        self.cert_hash=subprocess.check_output(['openssl','x509','-in',str(root/'dot-ca.pem'),'-subject_hash_old','-noout'],text=True).strip();assert re.fullmatch('[0-9a-f]{8}',self.cert_hash)
        for name in ('dot-ca.pem','dot-server.pem','dot.ext'):(evidence/name).write_bytes((root/name).read_bytes())
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(root/'dot-server.pem',root/'dot-server.key')
        def server_name(sock,name,ctx):
            sock.q29_server_name=name;self.record(kind='SNI',name=name,peer=sock.getpeername()[0])
        context.set_servername_callback(server_name)
        self.context=context;self.sock=socket.socket();self.sock.bind(('198.19.0.53',853));self.sock.listen(16);self.sock.settimeout(.5)
        self.thread=threading.Thread(target=self.serve,daemon=True);self.thread.start()
    def record(self,**row):
        with self.lock:
            self.rows.append(dict(row,unix_time=time.time()));(self.evidence/'dot-receipts.json').write_text(json.dumps(self.rows,indent=2)+'\n')
    def serve(self):
        while not self.closing.is_set():
            try:client,peer=self.sock.accept()
            except socket.timeout:continue
            except OSError:
                if self.closing.is_set():break
                raise
            worker=threading.Thread(target=self.connection,args=(client,peer),daemon=True);self.workers.append(worker);worker.start()
    def connection(self,client,peer):
        try:
            client.settimeout(3)
            with self.context.wrap_socket(client,server_side=True) as stream:
                self.clients.append(stream);stream.settimeout(.5);self.record(kind='TLS_ACCEPT',peer=peer[0],server_name=stream.q29_server_name,version=stream.version(),cipher=stream.cipher())
                def exact(n):
                    data=b''
                    while len(data)<n and not self.closing.is_set():
                        try:chunk=stream.recv(n-len(data))
                        except socket.timeout:continue
                        if not chunk:return None
                        data+=chunk
                    return data if len(data)==n else None
                while not self.closing.is_set():
                    header=exact(2)
                    if header is None:break
                    n=struct.unpack('!H',header)[0];assert 17<=n<=4096
                    data=exact(n)
                    if data is None:break
                    reply,row=response(data);stream.sendall(struct.pack('!H',len(reply))+reply)
                    self.record(kind='DNS',peer=peer[0],server_name=stream.q29_server_name,**row,query_sha256=hashlib.sha256(data).hexdigest(),reply_sha256=hashlib.sha256(reply).hexdigest())
        except (ssl.SSLError,OSError) as error:
            if not self.closing.is_set():self.record(kind='TLS_REJECT',peer=peer[0],error=str(error))
        except BaseException as error:self.record(kind='FIXTURE_ERROR',error=repr(error))
        finally:client.close()
    def close(self):
        self.closing.set();self.sock.close()
        for client in self.clients:
            try:client.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        self.thread.join(3)
        for worker in self.workers:worker.join(4);assert not worker.is_alive()
        assert not self.thread.is_alive() and not any(v['kind']=='FIXTURE_ERROR' for v in self.rows)

class AndroidCaStore:
    def __init__(self,arun,evidence,dot):
        self.arun,self.evidence,self.dot=arun,evidence,dot;self.original={};self.mounted=[]
        self.pid=arun('shell','su','0','pidof','netd').stdout.strip();assert re.fullmatch('[0-9]+',self.pid),self.pid
        contexts={label:arun('shell','su','0','readlink',path).stdout.strip() for label,path in (('shell','/proc/self/ns/mnt'),('resolver','/proc/'+self.pid+'/ns/mnt'))}
        self.shared_mount=contexts['shell']==contexts['resolver'];assert all(v.startswith('mnt:[') for v in contexts.values()),contexts
        (evidence/'dot-resolver-mount-namespaces.json').write_text(json.dumps(dict(pid=self.pid,contexts=contexts),indent=2)+'\n')
    def run(self,*args,**kwargs):
        prefix=() if self.shared_mount else ('nsenter','-t',self.pid,'-m','--')
        return self.arun('shell','su','0',*prefix,*args,**kwargs)
    def digest(self,path):
        names=self.run('ls','-1',path).stdout.splitlines();assert names and all(re.fullmatch(r'[0-9a-f]{8}\.[0-9]+',n) for n in names),names
        return self.run('sha256sum',*(path+'/'+n for n in sorted(names))).stdout
    def install(self):
        self.arun('push',str(self.dot.root/'dot-ca.pem'),'/data/local/tmp/q29-dot-ca.pem')
        for index,path in enumerate(('/system/etc/security/cacerts','/apex/com.android.conscrypt/cacerts')):
            exists=self.run('ls','-ld',path,check=False)
            if exists.returncode!=0:
                assert 'No such file or directory' in exists.stderr+exists.stdout,(path,exists.stdout,exists.stderr)
                continue
            original=self.digest(path);self.original[path]=original
            dest='/data/local/tmp/q29-dot-cacerts-'+str(index)
            self.run('mkdir',dest);self.run('cp','-a',path+'/.',dest)
            target=dest+'/'+self.dot.cert_hash+'.0';assert self.run('test','-e',target,check=False).returncode!=0
            self.run('cp','/data/local/tmp/q29-dot-ca.pem',target);self.run('chmod','644',target)
            first=original.splitlines()[0].split()[-1];label=self.run('ls','-Z',first).stdout
            context=re.search(r'u:object_r:[a-z0-9_]+:s0',label);assert context,label
            self.run('chcon','-R',context.group(),dest);self.run('chmod','755',dest)
            self.run('mount','--bind',dest,path);self.mounted.append(path)
            current=self.digest(path);assert self.dot.cert_hash+'.0' in current
            (self.evidence/f'dot-ca-store-labels-{index}.txt').write_text(self.run('ls','-ldZ',path,path+'/'+self.dot.cert_hash+'.0').stdout)
        assert self.mounted,'no system CA directories found'
        mounted={p:self.digest(p) for p in self.mounted}
        (self.evidence/'dot-ca-store-mounted.json').write_text(json.dumps(mounted,indent=2)+'\n')
        (self.evidence/'dot-ca-store-before.json').write_text(json.dumps(self.original,indent=2)+'\n')
    def restore(self):
        for path in reversed(self.mounted):self.run('umount',path)
        actual={p:self.digest(p) for p in self.original};assert actual==self.original
        (self.evidence/'dot-ca-store-after.json').write_text(json.dumps(actual,indent=2)+'\n')


def private_dns_matrix(arun,evidence,result,startup,dot,probe):
    checks=result['trusted_dot']={'stages':[],'status':'RUNNING','certificate_verification':'ANDROID_SYSTEM_RESOLVER; TEMP_LAB_SYSTEM_CA; NO_PRODUCT_BYPASS'}
    original={key:arun('shell','settings','get','global',key).stdout.strip() for key in ('private_dns_mode','private_dns_specifier')}
    store=AndroidCaStore(arun,evidence,dot)
    def state(label):
        for name,args in (('connectivity',('dumpsys','connectivity')),('resolver',('dumpsys','dnsresolver')),('vpn',('dumpsys','vpn_management'))):
            (evidence/f'dot-{label}-{name}.txt').write_text(arun('shell',*args).stdout)
    def configure(name):
        arun('shell','settings','put','global','private_dns_mode','off');time.sleep(1)
        arun('shell','settings','put','global','private_dns_specifier',name)
        arun('shell','settings','put','global','private_dns_mode','hostname')
    def stage(label,name,positive):
        before=len(dot.rows);configure(name);state(label+'-configured')
        if positive:
            prefix='10.86.0.' if result['recovery_transport']=='tcp' else '10.87.0.'
            wait_until(lambda:any(v['kind']=='DNS' and v['peer'].startswith(prefix) and v['server_name']==name for v in dot.rows[before:]),'trusted DoT VPN validation absent',45)
        else:
            wait_until(lambda:any(v['kind']=='TLS_REJECT' for v in dot.rows[before:]),'invalid certificate/hostname was not rejected',25)
            time.sleep(2)
        probe_before=len(startup.rows)
        startup.probe('dot-'+label,positive,modes=('system',))
        if positive:
            nonce=startup.rows[probe_before]['name']
            answers=[v for v in dot.rows[before:] if v['kind']=='DNS' and v['name']==nonce and v['answered']]
            assert {v['qtype'] for v in answers}=={1,28} and all(v['server_name']==name and v['peer'].startswith(prefix) for v in answers),answers
        if label!='untrusted':startup.probe('dot-'+label,True,modes=('raw',))
        state(label);checks['stages'].append(dict(label=label,provider=name,expected_success=positive,receipt_start=before,receipt_end=len(dot.rows),status='PASS'))
        print('DOT_'+label.upper()+'_PASS',flush=True)
    try:
        stage('untrusted',UNTRUSTED_PROVIDER,False)
        store.install();stage('trusted',PROVIDER,True)
        checks['payloads']=[probe('Q29PROTECTED',True,label='dot-trusted-'+f+'-'+p,family=f,protocol=p,payload_bytes=16384 if p=='tcp' else 257) for f in ('ipv4','ipv6') for p in ('tcp','udp')]
        stage('mismatch','q29-dot-mismatch.test',False)
        stage('recovered',PROVIDER,True)
        checks['status']='PASS'
    except BaseException:
        checks['status']='FAIL';state('failure')
        for label,args in (('resolver-logcat',('logcat','-d','-v','epoch')),('kernel',('su','0','dmesg')),('clock',('date','-u'))):
            observed=arun('shell',*args,check=False);(evidence/f'dot-failure-{label}.txt').write_text(observed.stdout+observed.stderr)
        raise
    finally:
        for key,value in original.items():arun('shell','settings','delete' if value=='null' else 'put','global',key,*([] if value=='null' else [value]))
        actual={key:arun('shell','settings','get','global',key).stdout.strip() for key in original};assert actual==original
        store.restore();checks['settings_restored']=True;checks['CA_stores_restored']=True
        (evidence/'trusted-dot.json').write_text(json.dumps(checks,indent=2)+'\n')
