"""One native UAC prompt to enable/disable the fixed DVD watcher task.

Only two fixed actions are accepted. Elevation neither starts a second DVD
runtime nor stops the current movie; the installer manages only the watcher.
"""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import subprocess
import os
import sys

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve()
MANAGER = SCRIPT.with_name('manage_dvd_autostart.ps1')
POWERSHELL = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'


def action_args(action):
    if action not in ('Enable', 'Disable'):
        raise ValueError('Only Enable or Disable is supported')
    return [POWERSHELL, '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
            'Bypass', '-File', str(MANAGER), '-Action', action]


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    applying = len(args) == 2 and args[0] == '--apply'
    if applying:
        action = args[1]
    elif len(args) == 1:
        action = args[0]
    else:
        raise ValueError('Usage: launch_dvd_autostart_setup.py Enable|Disable')
    command = action_args(action)
    if applying:
        if not C.windll.shell32.IsUserAnAdmin():
            raise RuntimeError('Windows administrator approval is required')
        environment={k:v for k,v in os.environ.items() if k.upper()!='PSMODULEPATH'}
        environment['PSModulePath']=str(Path(POWERSHELL).parent/'Modules')
        with (ROOT / 'outputs/initio/dvd-autostart-setup.log').open('a', encoding='utf-8') as log:
            return subprocess.run(command, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                                  stdout=log, stderr=subprocess.STDOUT,
                                  creationflags=0x08000000, check=False,env=environment).returncode

    class ExecuteInfo(C.Structure):
        _fields_ = [('cbSize', W.DWORD), ('fMask', W.ULONG), ('hwnd', W.HWND),
                    ('lpVerb', W.LPCWSTR), ('lpFile', W.LPCWSTR),
                    ('lpParameters', W.LPCWSTR), ('lpDirectory', W.LPCWSTR),
                    ('nShow', C.c_int), ('hInstApp', W.HINSTANCE),
                    ('lpIDList', C.c_void_p), ('lpClass', W.LPCWSTR),
                    ('hkeyClass', W.HKEY), ('dwHotKey', W.DWORD),
                    ('hIcon', W.HANDLE), ('hProcess', W.HANDLE)]
    shell = C.WinDLL('shell32', use_last_error=True)
    shell.ShellExecuteExW.argtypes = [C.POINTER(ExecuteInfo)]
    shell.ShellExecuteExW.restype = W.BOOL
    user = C.WinDLL('user32')
    user.GetForegroundWindow.restype = W.HWND
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.WaitForSingleObject.restype = W.DWORD
    kernel.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    kernel.GetExitCodeProcess.restype = W.BOOL
    kernel.CloseHandle.argtypes = [W.HANDLE]
    info = ExecuteInfo()
    info.cbSize = C.sizeof(info)
    info.fMask = 0x40  # SEE_MASK_NOCLOSEPROCESS
    info.hwnd = user.GetForegroundWindow()
    info.lpVerb = 'runas'
    info.lpFile = sys.executable
    info.lpParameters = subprocess.list2cmdline([str(SCRIPT), '--apply', action])
    info.lpDirectory = str(ROOT)
    info.nShow = 0
    if not shell.ShellExecuteExW(C.byref(info)):
        raise C.WinError(C.get_last_error())
    print('Windows approved DVD autostart setup.', flush=True)
    try:
        waited = kernel.WaitForSingleObject(info.hProcess, 15000)
        if waited == 0:
            code = W.DWORD()
            if not kernel.GetExitCodeProcess(info.hProcess, C.byref(code)):
                raise C.WinError(C.get_last_error())
            print('Setup completed.' if code.value == 0 else 'Setup reported an error; see dvd-autostart-setup.log.', flush=True)
            return code.value
        if waited != 258:
            raise C.WinError(C.get_last_error())
        print('Setup continues; status is in outputs/initio/dvd-autostart-install.json.', flush=True)
        return 0
    finally:
        kernel.CloseHandle(info.hProcess)


if __name__ == '__main__':
    raise SystemExit(main())
