"""Unprivileged tray commands. Only explicit bridge setup/start requests elevate."""
import argparse
import base64
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'outputs/initio'
CONFIG=OUT/'tray-settings.json'


def read_json(path):
    try:
        value=json.loads(path.read_text(encoding='utf-8-sig'))
        return value if isinstance(value,dict) else {}
    except (OSError,ValueError):return {}


def process_alive(pid):
    if type(pid) is not int or pid<=0:return False
    k=C.WinDLL('kernel32',use_last_error=True)
    k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
    k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
    k.CloseHandle.argtypes=[W.HANDLE]
    h=k.OpenProcess(0x100000,False,pid)
    if not h:
        if C.get_last_error()==87:return False
        raise RuntimeError('Windows could not verify the DVD process')
    try:return k.WaitForSingleObject(h,0)==258
    finally:k.CloseHandle(h)


def select_drive(state):
    if state.get('status')!='ready':raise RuntimeError('The DVD is not ready yet.')
    matches=[d for d in state.get('devices',[]) if isinstance(d,dict) and d.get('readable') is True
             and d.get('name')=='CODEX USB DVD Bridge SCSI CdRom Device']
    if len(matches)!=1:raise RuntimeError('No single verified DVD drive was found.')
    drive=matches[0].get('drive','')
    if not isinstance(drive,str) or not re.fullmatch('[A-Z]:',drive):raise RuntimeError('Invalid DVD drive letter.')
    return drive


def query_identity(drive):
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE];k.CreateFileW.restype=W.HANDLE
    k.DeviceIoControl.argtypes=[W.HANDLE,W.DWORD,C.c_void_p,W.DWORD,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p]
    k.CloseHandle.argtypes=[W.HANDLE]
    h=k.CreateFileW('\\\\.\\'+drive,0,3,None,3,0,None)
    if h==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
    try:
        query=C.create_string_buffer(12);data=C.create_string_buffer(4096);count=W.DWORD()
        if not k.DeviceIoControl(h,0x2d1400,query,12,data,len(data),C.byref(count),None):raise C.WinError(C.get_last_error())
        if not 36<=count.value<=len(data):raise RuntimeError('Truncated drive identity')
        def field(offset):
            pos=struct.unpack_from('<I',data.raw,offset)[0]
            if not 36<=pos<count.value:raise RuntimeError('Invalid drive identity')
            value,sep,_=data.raw[pos:count.value].partition(b'\0')
            if not sep:raise RuntimeError('Invalid drive identity')
            return value.decode('ascii').strip()
        return data.raw[8],field(12),field(16)
    finally:k.CloseHandle(h)


def find_vlc():
    configured=read_json(CONFIG).get('vlc')
    candidates=[Path(configured)] if isinstance(configured,str) else []
    for env in ('ProgramFiles','ProgramFiles(x86)'):
        if os.environ.get(env):candidates.append(Path(os.environ[env])/'VideoLAN/VLC/vlc.exe')
    candidates.append(ROOT/'player/vlc.exe')
    for candidate in candidates:
        if candidate.is_absolute() and candidate.name.lower()=='vlc.exe' and candidate.is_file():return candidate
    return None


def vlc_command(files=None,drive=None):
    exe=find_vlc()
    if exe is None:raise RuntimeError('Choose your VLC executable first, or install VLC from videolan.org.')
    argv=[str(exe),'--no-one-instance','--no-one-instance-when-started-from-file',
          '--no-metadata-network-access','--no-qt-updates-notif','--no-qt-privacy-ask','--disc-caching=3000']
    if drive is not None:
        if not re.fullmatch('[A-Z]:',drive):raise RuntimeError('Invalid DVD drive letter')
        return argv+['dvd:///'+drive+'/']
    if not isinstance(files,list) or not 1<=len(files)<=100:raise RuntimeError('Select between 1 and 100 media files.')
    for name in files:
        if not isinstance(name,str) or not Path(name).is_absolute() or not Path(name).is_file():
            raise RuntimeError('Choose existing local audio or video files.')
    return argv+['--',*files]


def status():
    from dvd_device_identity import exact_device_status
    state=read_json(OUT/'dvd-bridge-runtime.json')
    alive=process_alive(state.get('pid'))
    device=exact_device_status()
    phase=state.get('status','stopped') if alive else 'stopped'
    drive=None
    if phase=='ready':
        try:drive=select_drive(state)
        except RuntimeError:phase='error'
    if not device['present']:phase='disconnected'
    setup=read_json(OUT/'dvd-autostart-install.json')
    watcher=read_json(OUT/'dvd-autostart.json')
    watching=process_alive(watcher.get('pid')) if watcher else False
    return {'phase':phase,'drive':drive,'device_present':device['present'],'runtime_alive':alive,
            'autostart':setup.get('status')=='enabled','watcher_alive':watching,
            'vlc':str(find_vlc() or ''),'error':state.get('error') or '',
            'audio':'DVD sound and audio/video files via VLC. Audio CDs are not supported by this bridge yet.'}


def execute(request):
    if not isinstance(request,dict):raise ValueError('Invalid command')
    action=request.get('action')
    if action=='status':return status()
    if action=='set-vlc':
        path=Path(request.get('path',''))
        if not path.is_absolute() or path.name.lower()!='vlc.exe' or not path.is_file():raise ValueError('Select vlc.exe')
        OUT.mkdir(parents=True,exist_ok=True)
        CONFIG.write_text(json.dumps({'vlc':str(path)},indent=2),encoding='utf-8')
        return {'message':'VLC selected.'}
    if action=='play-disc':
        state=read_json(OUT/'dvd-bridge-runtime.json');drive=select_drive(state)
        if not process_alive(state.get('pid')):raise RuntimeError('The DVD utility is no longer running.')
        if query_identity(drive)!=(5,'CODEX','USB DVD Bridge'):raise RuntimeError('The drive identity changed. Wait for Ready.')
        if read_json(OUT/'dvd-bridge-runtime.json')!=state:raise RuntimeError('DVD status changed. Try again.')
        command=vlc_command(drive=drive)
    elif action=='play-files':command=vlc_command(files=request.get('files'))
    elif action=='start':
        from dvd_autostart import kernel_api,mutex_exists,RUNTIME_LOCKS
        if any(mutex_exists(kernel_api(),name) for name in RUNTIME_LOCKS):raise RuntimeError('The DVD utility is already running or cleaning up.')
        command=[str(Path(sys.executable).with_name('python.exe')),str(ROOT/'work/initio/launch_dvd_bridge.py')]
    elif action=='stop':
        if not process_alive(read_json(OUT/'dvd-bridge-runtime.json').get('pid')):raise RuntimeError('No active DVD utility to stop.')
        (OUT/'dvd-bridge-stop.request').write_text('Stop requested from tray',encoding='utf-8')
        return {'message':'Stop requested. Wait for cleanup before removing the drive.'}
    elif action in ('enable','disable'):
        command=[str(Path(sys.executable).with_name('python.exe')),str(ROOT/'work/initio/launch_dvd_autostart_setup.py'),action.title()]
    else:raise ValueError('Unknown tray action')
    subprocess.Popen(command,cwd=str(ROOT),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,shell=False,creationflags=0x08000000 if action in ('start','enable','disable') else 0)
    return {'message':'Opening VLC.' if action.startswith('play-') else 'Windows approval requested. Status updates after approval.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True)
    args=parser.parse_args()
    try:
        request=json.loads(base64.b64decode(args.request,validate=True).decode('utf-8'))
        print(json.dumps({'ok':True,**execute(request)}))
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc)}))
        sys.exit(1)
