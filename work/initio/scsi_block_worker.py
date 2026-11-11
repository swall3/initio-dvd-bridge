"""Guarded reads and bounded DVD authentication through the existing USB driver."""
import ctypes as C
from ctypes import wintypes as W
import struct,threading,time
from dvd_auth_commands import validate_auth_command
from dvd_device_identity import discover_disk_interface, STORAGE_SERIAL
class SPT(C.Structure):
    _fields_=[('Length',W.USHORT),('ScsiStatus',W.BYTE),('PathId',W.BYTE),('TargetId',W.BYTE),('Lun',W.BYTE),('CdbLength',W.BYTE),('SenseInfoLength',W.BYTE),('DataIn',W.BYTE),('DataTransferLength',W.ULONG),('TimeOutValue',W.ULONG),('DataBuffer',C.c_void_p),('SenseInfoOffset',W.ULONG),('Cdb',W.BYTE*16)]
class Packet(C.Structure):_fields_=[('s',SPT),('sense',W.BYTE*32)]
class ScsiRead:
    def __init__(self):
        self.k=C.WinDLL('kernel32',use_last_error=True)
        self.k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE];self.k.CreateFileW.restype=W.HANDLE
        self.k.DeviceIoControl.argtypes=[W.HANDLE,W.DWORD,C.c_void_p,W.DWORD,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p]
        self.k.CloseHandle.argtypes=[W.HANDLE]
        self.target=discover_disk_interface()
        self.h=self.k.CreateFileW(self.target['path'],0xc0000000,3,None,3,0,None)
        self.thread=None;self.result=None
        if self.h==C.c_void_p(-1).value:self.h=None;raise C.WinError(C.get_last_error())
        try:
            query=C.create_string_buffer(12);desc=C.create_string_buffer(4096);n=W.DWORD()
            if not self.k.DeviceIoControl(self.h,0x2d1400,query,12,desc,4096,C.byref(n),None):raise C.WinError(C.get_last_error())
            if not 36<=n.value<=len(desc):raise RuntimeError('Truncated SCSI target descriptor; no command sent')
            descriptor_size=struct.unpack_from('<I',desc.raw,4)[0]
            if not 36<=descriptor_size<=n.value:raise RuntimeError('Invalid SCSI target descriptor size; no command sent')
            def field(offset):
                pos=struct.unpack_from('<I',desc.raw,offset)[0]
                if not 36<=pos<descriptor_size:raise RuntimeError('Invalid SCSI identity offset; no command sent')
                value,separator,_=desc.raw[pos:descriptor_size].partition(b'\0')
                if not separator:raise RuntimeError('Unterminated SCSI identity; no command sent')
                return value.decode('ascii').strip()
            self.identity={'vendor':field(12),'product':field(16),'serial':field(24)}
            if self.identity!={'vendor':'Initio','product':'Ini-3910','serial':STORAGE_SERIAL}:raise RuntimeError('SCSI target identity mismatch; no command sent')
            if discover_disk_interface()!=self.target:raise RuntimeError('SCSI target changed during open; no command sent')
        except BaseException:self.close();raise
    def start(self,lba,count):
        if not (isinstance(lba,int) and isinstance(count,int) and 0<=lba<2**32 and 1<=count<=16):raise ValueError('Read outside bounded range')
        cdb=bytes((0x28,0))+lba.to_bytes(4,'big')+bytes((0,))+count.to_bytes(2,'big')+bytes((0,))
        self._begin(cdb,count*2048,'in',b'')
    def start_auth(self,cdb,size,direction,data_out=b''):
        cdb=validate_auth_command(cdb,size,direction,data_out)
        # GET CONFIGURATION has a ten-byte CDB; all DVD key/structure CDBs have12.
        self._begin(cdb[:10] if cdb[0]==0x46 else cdb,size,direction,bytes(data_out))
    def _begin(self,cdb,size,direction,data_out):
        if self.thread and self.thread.is_alive():raise RuntimeError('Previous SPTI still active')
        self.cdb=cdb;self.size=size;self.direction=direction;self.data_out=data_out;self.result=None
        self.thread=threading.Thread(target=self._run,daemon=True);self.thread.start()
    def _run(self):
        started=time.monotonic()
        try:
            p=Packet();data=C.create_string_buffer(max(1,self.size));n=W.DWORD()
            if self.data_out:C.memmove(data,self.data_out,len(self.data_out))
            p.s.Length=C.sizeof(SPT);p.s.CdbLength=len(self.cdb);p.s.SenseInfoLength=32;p.s.DataIn={'in':1,'out':0,'none':2}[self.direction];p.s.DataTransferLength=self.size;p.s.TimeOutValue=15;p.s.DataBuffer=C.addressof(data) if self.size else None;p.s.SenseInfoOffset=Packet.sense.offset
            for i,b in enumerate(self.cdb):p.s.Cdb[i]=b
            ok=self.k.DeviceIoControl(self.h,0x4d014,C.byref(p),C.sizeof(p),C.byref(p),C.sizeof(p),C.byref(n),None)
            payload=bytes(data.raw[:min(p.s.DataTransferLength,self.size)]) if self.direction=='in' else b''
            self.result={'ioctl_success':bool(ok),'win_error':0 if ok else C.get_last_error(),'scsi_status':p.s.ScsiStatus,'sense':bytes(p.sense).hex(),'transferred':p.s.DataTransferLength,'data':payload,'seconds':time.monotonic()-started}
        except Exception as e:self.result={'error':str(e),'seconds':time.monotonic()-started}
    def wait(self,seconds):
        if self.thread:self.thread.join(seconds)
        return self.result
    def close(self):
        if self.h and not(self.thread and self.thread.is_alive()):self.k.CloseHandle(self.h);self.h=None
