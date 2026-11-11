"""Experimental live Windows DVD interface using a loopback iSCSI target.

Requires an already elevated Python process. No new driver is installed.
The Windows session is nonpersistent, and cleanup operates on journaled IDs.
Only the physical Initio DVD is controlled. No unrelated storage volume is queried.
"""
import argparse
import ctypes
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

BASE = Path(__file__).resolve().parents[2]
WORK = BASE / 'work/initio'
OUT = BASE / 'outputs/initio'
LOG = OUT / 'dvd-bridge-runtime.jsonl'
STATE = OUT / 'dvd-bridge-runtime.json'
STOP = OUT / 'dvd-bridge-stop.request'
POWERSHELL = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
lock = threading.Lock()

def emit(event, **values):
    record = {'time':datetime.now().astimezone().isoformat(), 'event':event, **values}
    with lock:
        with LOG.open('a', encoding='utf-8') as f:
            f.write(json.dumps(record)+'\n')

def status(value, **fields):
    data = dict(status=value, pid=os.getpid(), time=datetime.now().astimezone().isoformat(), **fields)
    temp = STATE.with_suffix('.tmp')
    temp.write_text(json.dumps(data, indent=2), encoding='utf-8')
    # Windows readers may briefly hold the destination without delete sharing.
    # A transient status-file read must not derail hardware cleanup.
    deadline=time.monotonic()+2
    while True:
        try:
            temp.replace(STATE)
            break
        except PermissionError:
            if time.monotonic()>=deadline:raise
            time.sleep(.02)
    emit('status', **data)

def powershell(script, *args):
    # Native login/disconnect can take its own timeout. Never kill the lifecycle
    # helper halfway through a mutation and falsely claim cleanup completed.
    environment={k:v for k,v in os.environ.items() if k.upper()!='PSMODULEPATH'}
    environment['PSModulePath']=str(Path(POWERSHELL).parent/'Modules')
    if script == 'iscsi_windows_session.ps1':
        args = (*args, '-PythonPath', sys.executable)
    result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive',
                             '-ExecutionPolicy', 'Bypass', '-File', str(WORK/script), *args],
                            capture_output=True, text=True, creationflags=0x08000000, env=environment)
    emit('powershell_result', script=script, args=list(args), returncode=result.returncode,
         stdout=result.stdout, stderr=result.stderr)
    if result.returncode:
        raise RuntimeError(f'{script} failed: {result.stderr.strip()}')
    return result.stdout

def process_has_exited(pid):
    """Prove an old owner is gone without terminating or inspecting its work.

    A live reused PID is deliberately treated as still owned. Access denied or
    an unexpected native result is not evidence that a process has exited.
    """
    if type(pid) is not int or not 0 < pid <= 0xffffffff:
        raise RuntimeError('Previous runtime has no valid process identity')
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: this valid PID does not exist
            return True
        raise RuntimeError(f'Cannot establish whether previous runtime exited: WinError {error}')
    try:
        result = kernel.WaitForSingleObject(handle, 0)
        if result == 0:
            return True
        if result == 258:
            return False
        raise RuntimeError(f'Cannot establish previous runtime exit: wait result {result}')
    finally:
        kernel.CloseHandle(handle)


def reconcile_previous_runtime(collect):
    """Called only after run_with_ownership has acquired runtime ownership.

    Crashes and reboot can leave a ready status behind. Keep that evidence and
    the Stop request intact until its process is gone, the exact owned iSCSI
    cleanup succeeds, and a fresh read-only inventory permits a new session.
    """
    previous = None
    reconcile = False
    if STATE.exists():
        previous = json.loads(STATE.read_text(encoding='utf-8'))
        if not isinstance(previous, dict):
            raise RuntimeError('Previous runtime status is invalid')
        completed = previous.get('status') in ('stopped', 'failed')
        active = previous.get('status') in (
            'initializing', 'connecting', 'connected', 'ready',
            'optical_interface_verified_no_media', 'cleanup_incomplete',
            'stopping_after_error', 'stopping')
        if not completed and not active:
            raise RuntimeError('Previous runtime status is unknown; refusing recovery')
        if active:
            if not process_has_exited(previous.get('pid')):
                raise RuntimeError('Previous runtime is still running; no recovery performed')
            reconcile = True
    journal = OUT / 'iscsi-windows-session.json'
    if journal.exists():
        owned = json.loads(journal.read_text(encoding='utf-8-sig'))
        if not isinstance(owned, dict):
            raise RuntimeError('Previous iSCSI ownership journal is invalid')
        if owned.get('status') != 'cleaned':
            if previous is None:
                raise RuntimeError('Unfinished iSCSI ownership has no runtime identity; refusing recovery')
            if not reconcile and not process_has_exited(previous.get('pid')):
                raise RuntimeError('Previous runtime is still running; no recovery performed')
            reconcile = True
            emit('reconciling_owned_cleanup', previous_pid=previous.get('pid'))
            powershell('iscsi_windows_session.ps1', '-Action', 'Cleanup')
    before = collect()
    emit('preflight', inventory=before)
    if not before['start_guard']['allowed']:
        raise RuntimeError('Existing or unreadable iSCSI configuration prevents an isolated test')
    if reconcile:
        status('stopped', reconciled_previous_cleanup=True,
               previous_pid=previous.get('pid'))
    return before


def calibrate(reader):
    start = time.monotonic()
    a = reader.read_blocks(16, 1)
    b = reader.read_blocks(16, 1)
    if a != b:
        raise RuntimeError('Repeated physical-sector reads differ')
    # Independent one-block reads supply the reference for the larger USB DMA
    # transaction. No sparse file or invented sectors are used.
    reference = reader.read_blocks(16, 16)
    if reference[:2048] != a:
        raise RuntimeError('Sequential reference read differs')
    for count in (2, 4, 8, 16):
        reader.chunk_blocks = count
        actual = reader.read_blocks(16, count)
        if actual != reference[:count*2048]:
            raise RuntimeError(f'{count}-block USB transfer differs from individual reads')
        emit('transfer_calibrated', blocks=count, sha256=hashlib.sha256(actual).hexdigest())
    emit('physical_reader_verified', seconds=time.monotonic()-start,
         pvd_sha256=hashlib.sha256(a).hexdigest(), capacity=reader.info)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-media', action='store_true', help='Test the optical interface without opening the DVD hardware')
    parser.add_argument('--seconds', type=int, default=0, help='Optional bounded session duration; zero runs until Stop is requested')
    parser.add_argument('--stop', action='store_true', help='Request ordered cleanup from the active runtime')
    args = parser.parse_args()
    os.chdir(BASE)
    if args.stop:
        STOP.write_text(datetime.now().astimezone().isoformat(), encoding='utf-8')
        print('DVD bridge stop requested. Wait for status=stopped before unplugging or restarting it.')
        return
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('Windows administrator approval is required')
    from iscsi_windows_inventory import collect
    from iscsi_target import TargetServer
    from optical_lun import OpticalLun
    reconcile_previous_runtime(collect)
    reader = None
    lun = None
    server = None
    server_thread = None
    connect_attempted = False
    last_error = None
    server_ready = threading.Event()
    server_error = []
    # Status/ownership journals are never used to kill a process.
    if STOP.exists():
        STOP.unlink()
    try:
        status('initializing', no_media=args.no_media)
        if args.no_media:
            lun = OpticalLun()
        else:
            from live_usb_reader import LiveUsbReader
            reader = LiveUsbReader(chunk_blocks=1)
            calibrate(reader)
            lun = OpticalLun(read_blocks=reader.read_blocks, block_count=reader.info['blocks'],
                             block_size=2048, read_chunk_blocks=16,
                             max_transfer=256*1024, read_ahead_blocks=16,
                             backend_health=lambda: reader.error is None and not reader.stop_event.is_set(),
                             auth_command=reader.auth_command, css_feature=reader.css_feature)
        def target_log(event, **values):
            emit(event, **values)
            if event == 'listening':
                server_ready.set()
        server = TargetServer(lun, emit=target_log)
        def serve():
            try:
                server.serve_forever()
            except BaseException as exc:
                server_error.append(exc)
                server_ready.set()
                emit('server_error', error=str(exc))
        server_thread = threading.Thread(target=serve, name='Loopback DVD target', daemon=True)
        server_thread.start()
        if not server_ready.wait(5) or server_error:
            raise RuntimeError('Loopback DVD listener failed: '+str(server_error))
        status('connecting', no_media=args.no_media)
        connect_attempted = True
        powershell('iscsi_windows_session.ps1', '-Action', 'Connect')
        status('connected', no_media=args.no_media)
        started = time.monotonic()
        verified = False
        last_verify = 0
        while not STOP.exists() and (args.seconds == 0 or time.monotonic()-started < args.seconds):
            if server_error or not server_thread.is_alive():
                raise RuntimeError('Local target stopped unexpectedly')
            if reader and reader.error:
                raise RuntimeError('Physical DVD reader stopped: '+str(reader.error))
            if not verified and time.monotonic()-last_verify >= 5:
                last_verify = time.monotonic()
                output = powershell('verify_virtual_dvd.ps1')
                record = json.loads(output)
                (OUT/'virtual-dvd-verification.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
                verified = any(d.get('readable') for d in record['devices'])
                if verified:
                    status('ready', devices=record['devices'], verification_complete=record['verification_complete'])
                elif args.no_media and record['devices']:
                    status('optical_interface_verified_no_media', devices=record['devices'])
                    verified = True
            if not verified and time.monotonic()-started > 90:
                raise RuntimeError('Windows optical interface did not become readable within the test budget')
            time.sleep(.2)
        status('stopping')
    except BaseException as exc:
        last_error = str(exc)
        if reader is not None and reader.error is not None and lun is not None:
            # This backend has stopped permanently. Remove only the virtual
            # medium so Windows receives NO MEDIUM instead of retrying a
            # potentially recoverable NOT READY condition during logout.
            lun.set_media(None, 0)
            emit('virtual_media_removed', reason='terminal_reader_failure')
        emit('runtime_error', error=str(exc), type=type(exc).__name__)
        status('stopping_after_error', error=str(exc))
        raise
    finally:
        clean = True
        if connect_attempted:
            try:
                powershell('iscsi_windows_session.ps1', '-Action', 'Cleanup')
            except Exception as exc:
                clean = False
                emit('cleanup_error', error=str(exc))
                # Keep the target available while Windows still owns its
                # recorded session. A corrected helper can finish cleanup on
                # the next attempt without stranding a Windows optical device
                # behind a closed loopback socket.
                journal=OUT/'iscsi-windows-session.json'
                while journal.exists():
                    owned=json.loads(journal.read_text(encoding='utf-8-sig'))
                    if not owned.get('session_ids'):
                        break
                    status('cleanup_incomplete',error='Waiting for owned Windows session cleanup')
                    time.sleep(3)
                    try:
                        powershell('iscsi_windows_session.ps1','-Action','Cleanup')
                        clean=True
                        break
                    except Exception as retry_exc:
                        emit('cleanup_retry_error',error=str(retry_exc))
        if server:
            server.stop()
        if server_thread:
            server_thread.join(35)
            if server_thread.is_alive():
                clean = False
                emit('cleanup_error', error='Target worker has not exited')
        if server and not server.join_clients(timeout=95):
            # Do not resume the physical bridge while a client can still be
            # using it. Retain process and device ownership until the bounded
            # backend call returns; a second launcher must continue to refuse.
            status('cleanup_incomplete', error='Waiting for active DVD read to return')
            emit('cleanup_wait', reason='A client read has not returned')
            while not server.join_clients(timeout=5):
                pass
        if reader:
            try:
                reader.close()
            except Exception as exc:
                clean = False
                emit('cleanup_error', error=str(exc))
        status('stopped' if clean else 'cleanup_incomplete', error=last_error)

def run_with_ownership():
    if '--stop' in sys.argv[1:]:
        return main()
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    mutex = kernel.CreateMutexW(None, True, r'Local\CodexInitioDvdRuntime')
    if not mutex:
        raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error() == 183:
        kernel.CloseHandle(mutex)
        raise RuntimeError('The DVD interface is already running or still cleaning up')
    try:
        return main()
    finally:
        kernel.ReleaseMutex(mutex)
        kernel.CloseHandle(mutex)

if __name__ == '__main__':
    try:
        run_with_ownership()
    except BaseException as exc:
        emit('launcher_failure', error=str(exc), type=type(exc).__name__)
        raise
