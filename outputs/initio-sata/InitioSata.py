"""Experimental SATA diagnostic/retry utility for one verified Initio 3910.
No firmware flashing, driver installation, live CPU register access or hub reset.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime
import json
from pathlib import Path
import struct
import subprocess
import sys
import time
import uuid

INSTANCE = r'USB\VID_13FD&PID_3910\303030303030303030303030'
HEADER = bytes.fromhex('025685027050854a5822ff0235ea026e')
CONTROLS = (0xe00c, 0xe010, 0xe013, 0xe034)
BASE = Path(__file__).resolve().parent

class RecoveryError(RuntimeError):
    pass

def log(event, **data):
    item = {'time': datetime.now().astimezone().isoformat(), 'event': event, **data}
    print(json.dumps(item), flush=True)
    if LOG:
        with LOG.open('a', encoding='utf-8') as f:
            f.write(json.dumps(item) + '\n')

LOG = None

def discover():
    """Native Config Manager discovery; no PowerShell or cached port number."""
    cm = C.WinDLL('cfgmgr32')
    cm.CM_Locate_DevNodeW.argtypes = [C.POINTER(W.ULONG), W.LPWSTR, W.ULONG]
    cm.CM_Get_DevNode_Status.argtypes = [C.POINTER(W.ULONG), C.POINTER(W.ULONG), W.ULONG, W.ULONG]
    cm.CM_Get_Parent.argtypes = [C.POINTER(W.ULONG), W.ULONG, W.ULONG]
    cm.CM_Get_Device_IDW.argtypes = [W.ULONG, W.LPWSTR, W.ULONG, W.ULONG]
    cm.CM_Get_DevNode_PropertyW.argtypes = [W.ULONG, C.c_void_p, C.POINTER(W.ULONG), C.c_void_p, C.POINTER(W.ULONG), W.ULONG]
    node = W.ULONG()
    if cm.CM_Locate_DevNodeW(C.byref(node), C.create_unicode_buffer(INSTANCE), 0):
        raise RecoveryError('The expected Initio device is not connected. If Windows shows Code 43, physically unplug it for 30 seconds and reconnect.')
    state, problem = W.ULONG(), W.ULONG()
    if cm.CM_Get_DevNode_Status(C.byref(state), C.byref(problem), node, 0):
        raise RecoveryError('Cannot read device status.')
    if problem.value or not (state.value & 8):
        raise RecoveryError(f'Initio is not started (problem {problem.value}); no controller commands sent.')
    parent = W.ULONG()
    if cm.CM_Get_Parent(C.byref(parent), node, 0):
        raise RecoveryError('Cannot locate the parent hub.')
    name = C.create_unicode_buffer(512)
    if cm.CM_Get_Device_IDW(parent, name, len(name), 0):
        raise RecoveryError('Cannot read parent hub identity.')
    # DEVPKEY_Device_Address, devpkey.h, property ID 30.
    key = C.create_string_buffer(uuid.UUID('a45c254e-df1c-4efd-8020-67d146a850e0').bytes_le + struct.pack('<I',30))
    kind, port, size = W.ULONG(), W.ULONG(), W.ULONG(4)
    if cm.CM_Get_DevNode_PropertyW(node, key, C.byref(kind), C.byref(port), C.byref(size), 0):
        raise RecoveryError('Cannot determine current USB port.')
    if size.value != 4 or not 1 <= port.value <= 255:
        raise RecoveryError('Invalid USB port address.')
    return {'instance': INSTANCE, 'parent': name.value, 'port': port.value,
            'hub': '\\\\?\\' + name.value.replace('\\','#') + '#{f18a0e88-c30c-11d0-8815-00a0c906bed8}'}

class Hub:
    def __init__(self, target):
        self.port = target['port']
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.k.CreateFileW.argtypes = [W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
        self.k.CreateFileW.restype = W.HANDLE
        self.k.DeviceIoControl.argtypes = [W.HANDLE,W.DWORD,C.c_void_p,W.DWORD,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p]
        self.k.CloseHandle.argtypes = [W.HANDLE]
        self.h = self.k.CreateFileW(target['hub'],0xc0000000,3,None,3,0,None)
        if self.h == C.c_void_p(-1).value:
            self.h = None
            raise C.WinError(C.get_last_error())
        try:
            raw = self.ioctl(0x220448,struct.pack('<I',self.port)+bytes(508))
            if len(raw)<24 or raw[12:16]!=bytes.fromhex('fd131039'):
                raise RecoveryError('The actual port is not USB 13FD:3910; refusing access.')
            self.descriptor = raw[4:22].hex()
            self.speed_code = raw[23]  # Legacy EX speed; does not disambiguate SuperSpeed.
        except BaseException:
            self.close()
            raise
    def close(self):
        if self.h:
            self.k.CloseHandle(self.h)
            self.h = None
    def ioctl(self, code, payload):
        buf = C.create_string_buffer(payload,len(payload))
        actual = W.DWORD()
        if not self.k.DeviceIoControl(self.h,code,buf,len(payload),buf,len(payload),C.byref(actual),None):
            raise C.WinError(C.get_last_error())
        return buf.raw[:actual.value]
    def command(self,value,index=0,length=1,write=False):
        allowed = {0xe001,0xe002,0x8101,0x8201,0xba03,0xda02,0x8102,0x8202}
        if value not in allowed:
            raise RecoveryError('Command is outside this utility\'s allowlist.')
        raw = self.ioctl(0x220410,struct.pack('<IBBHHH',self.port,0x80,6,value,index,length)+bytes(length))
        if len(raw)<12:
            raise RecoveryError('Missing USB response header.')
        data = raw[12:]
        if not write and len(data)!=length:
            raise RecoveryError('Short USB response; stopping.')
        return data
    def hold(self): self.command(0xe001)
    def resume(self): self.command(0xe002,0x112)
    def spi_mode(self):
        self.command(0x8102,0)
        self.command(0x8202,0)
    def memory(self,address,size):
        if size%2:
            raise ValueError('Memory reads require pairs of bytes.')
        result=bytearray()
        # Select the memory bank before the low address, as in the verified dump.
        for a in range(address,address+size,2):
            self.command(0x8201,a>>16)
            self.command(0x8101,a&65535)
            result.extend(self.command(0xba03,length=2))
        return bytes(result)
    def read(self,address):return self.memory(0x10000+address,2)[0]
    def write(self,address,value):
        if address not in CONTROLS or not 0<=value<=255:
            raise RecoveryError('Write outside the four SATA control registers.')
        self.command(0x8101,address)
        self.command(0x8201,1)
        self.command(0xda02,value,2,write=True)
