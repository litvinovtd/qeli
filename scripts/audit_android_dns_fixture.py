#!/usr/bin/env python3
"""One offline DNS reply builder shared by UDP and authenticated TLS fixtures."""
import re,socket,struct
PROVIDER = "q29-dot.test"
UNTRUSTED_PROVIDER = "q29-dot-untrusted.test"
PROVIDERS = (PROVIDER, UNTRUSTED_PROVIDER, "q29-dot-mismatch.test")

def response(data):
    assert len(data)>=17 and struct.unpack("!H",data[4:6])[0]==1
    offset=12;labels=[]
    while True:
        assert offset<len(data)
        length=data[offset];offset+=1
        if length==0:break
        assert length<=63 and offset+length<len(data)
        labels.append(data[offset:offset+length].decode("ascii"));offset+=length
    assert offset+4<=len(data)
    kind,klass=struct.unpack("!HH",data[offset:offset+4]);question=data[12:offset+4]
    name=".".join(labels).lower();answer=b""
    known=re.fullmatch(r"q29-[0-9]+\.test",name) or name in PROVIDERS
    if known and klass==1 and kind in (1,28) and not (name in PROVIDERS and kind==28):
        address="198.19.0.53" if name in PROVIDERS else "198.19.0.1" if kind==1 else "2001:db8:29::1"
        value=socket.inet_pton(socket.AF_INET if kind==1 else socket.AF_INET6,address)
        answer=b"\xc0\x0c"+struct.pack("!HHIH",kind,1,0,len(value))+value
    flags=0x8180 if known else 0x8183
    reply=data[:2]+struct.pack("!HHHHH",flags,1,bool(answer),0,0)+question+answer
    return reply,dict(name=name,qtype=kind,answered=bool(answer))
