import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import sys
class SHELLEXECUTEINFO(C.Structure):
 _fields_=[('cbSize',W.DWORD),('fMask',W.ULONG),('hwnd',W.HWND),('lpVerb',W.LPCWSTR),('lpFile',W.LPCWSTR),('lpParameters',W.LPCWSTR),('lpDirectory',W.LPCWSTR),('nShow',C.c_int),('hInstApp',W.HINSTANCE),('lpIDList',C.c_void_p),('lpClass',W.LPCWSTR),('hkeyClass',W.HKEY),('dwHotKey',W.DWORD),('hIcon',W.HANDLE),('hProcess',W.HANDLE)]
s=C.WinDLL('shell32',use_last_error=True)
s.ShellExecuteExW.argtypes=[C.POINTER(SHELLEXECUTEINFO)]
s.ShellExecuteExW.restype=W.BOOL
e=SHELLEXECUTEINFO();e.cbSize=C.sizeof(e);e.fMask=0x40
e.lpVerb='runas';e.lpFile=sys.executable
e.lpParameters='"'+str(Path('work/initio/recover_failed_node.py').resolve())+'"'
e.lpDirectory=str(Path.cwd());e.nShow=0
if not s.ShellExecuteExW(C.byref(e)):raise C.WinError(C.get_last_error())
print('Elevated recovery launched',flush=True)
k=C.WinDLL('kernel32',use_last_error=True)
k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
k.CloseHandle.argtypes=[W.HANDLE]
result=k.WaitForSingleObject(e.hProcess,45000)
print('Completed' if result==0 else 'Still running',flush=True)
k.CloseHandle(e.hProcess)
