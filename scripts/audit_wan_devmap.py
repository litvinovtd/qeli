#!/usr/bin/env python3
"""Experimental D06 frozen DEVMAP / xt_bpf guard; private lab fixture only."""
import ctypes
import errno
import os
from pathlib import Path
import platform
import struct


class Guard:
    def __init__(self, index, root, verifier_log, ingress_index):
        assert platform.machine()=='x86_64', 'prototype syscall ABI is x86_64 only'
        self.libc=ctypes.CDLL(None,use_errno=True);self.fds=[]
        self.root=Path(root);self.root.mkdir(mode=0o700,exist_ok=False)
        try:
            attr=bytearray(144);struct.pack_into('IIII',attr,0,14,4,4,1)
            self.map=self.call(0,attr);self.fds.append(self.map)
            key=ctypes.c_uint32(0);value=ctypes.c_uint32(index)
            attr=bytearray(144);struct.pack_into('I',attr,0,self.map);struct.pack_into('QQQ',attr,8,ctypes.addressof(key),ctypes.addressof(value),0)
            self.call(2,attr)
            # Freeze userspace writes; the kernel device-unregister notifier still removes entries.
            attr=bytearray(144);struct.pack_into('I',attr,0,self.map);self.call(22,attr)
            def ins(code,dst=0,src=0,off=0,imm=0):return struct.pack('BBhi',code,dst|(src<<4),off,imm)
            # Ignore unrelated ingress; return 1 (DROP) for missing or different actual WAN.
            code=b''.join([ins(0x61,6,1,off=40),ins(0x61,7,1,off=36),
                ins(0xb7,0,imm=0),ins(0x55,7,off=11,imm=ingress_index),
                ins(0x62,10,off=-4,imm=0),ins(0xbf,2,10),ins(0x07,2,imm=-4),
                ins(0x18,1,1,imm=self.map),ins(0),ins(0x85,imm=1),
                ins(0x15,0,off=3,imm=0),ins(0x61,1,0),ins(0xb7,0,imm=0),
                ins(0x1d,1,6,off=1),ins(0xb7,0,imm=1),ins(0x95)])
            instructions=ctypes.create_string_buffer(code);license=ctypes.create_string_buffer(b'GPL');log=ctypes.create_string_buffer(65536)
            attr=bytearray(144);struct.pack_into('IIQQIIQ',attr,0,1,len(code)//8,ctypes.addressof(instructions),ctypes.addressof(license),1,len(log),ctypes.addressof(log))
            try:
                self.program=self.call(5,attr);self.fds.append(self.program)
            finally:Path(verifier_log).write_bytes(log.value)
            self.pin(self.map,self.root/'map');self.pin(self.program,self.root/'program')
        except BaseException:
            self.close();raise

    def call(self,command,attr):
        buf=ctypes.create_string_buffer(bytes(attr));rc=self.libc.syscall(ctypes.c_long(321),ctypes.c_int(command),ctypes.byref(buf),ctypes.c_uint(len(attr)))
        if rc<0:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
        return rc

    def pin(self,fd,path):
        name=ctypes.create_string_buffer(os.fsencode(path));attr=bytearray(144)
        struct.pack_into('QI',attr,0,ctypes.addressof(name),fd);self.call(6,attr)

    @classmethod
    def reopen(cls, root):
        owner=cls.__new__(cls);owner.root=Path(root);owner.fds=[]
        owner.libc=ctypes.CDLL(None,use_errno=True)
        try:
            for name in ('map','program'):
                path=ctypes.create_string_buffer(os.fsencode(owner.root/name));attr=bytearray(144)
                struct.pack_into('Q',attr,0,ctypes.addressof(path));fd=owner.call(7,attr)
                owner.fds.append(fd);setattr(owner,name,fd)
            return owner
        except BaseException:
            owner.close();raise

    def lookup(self):
        key=ctypes.c_uint32(0);value=ctypes.c_uint32(0);attr=bytearray(144)
        struct.pack_into('I',attr,0,self.map);struct.pack_into('QQ',attr,8,ctypes.addressof(key),ctypes.addressof(value))
        try:self.call(1,attr)
        except OSError as error:
            if error.errno==errno.ENOENT:return None
            raise
        return value.value

    def update(self,index):
        key=ctypes.c_uint32(0);value=ctypes.c_uint32(index);attr=bytearray(144)
        struct.pack_into('I',attr,0,self.map);struct.pack_into('QQQ',attr,8,ctypes.addressof(key),ctypes.addressof(value),0)
        return self.call(2,attr)

    def close(self):
        for fd in self.fds:os.close(fd)
        self.fds.clear()
