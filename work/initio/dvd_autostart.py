"""Per-user elevated watcher for exactly one Initio DVD; no resets or kills.

Installed by manage_dvd_autostart.ps1 with an interactive logon task. Polling
only reads the PnP tree, never the disc. The existing runtime retains all device
and iSCSI ownership checks. One attempt per connection avoids restart loops and
respects manual Stop. A confirmed unplug rearms the next connection.
"""
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[2]
OUT = BASE / 'outputs/initio'
STATE = OUT / 'dvd-autostart.json'
LOG = OUT / 'dvd-autostart.jsonl'
STOP = OUT / 'dvd-autostart-stop.request'
RUNTIME_STATE = OUT / 'dvd-bridge-runtime.json'
RUNTIME = BASE / 'work/initio/dvd_bridge_runtime.py'
RUNTIME_LOCKS = (r'Local\CodexInitioDvdRuntime', r'Local\CodexInitioDvdReader')


@dataclass
class ConnectionPolicy:
    """Pure policy; failures never masquerade as physical removal."""
    debounce: float = 4.0
    present_since: float | None = None
    absent_since: float | None = None
    consumed: bool = False
    rearmed: bool = False

    def interrupted(self):
        self.present_since = None
        self.absent_since = None

    def step(self, now, *, present, started, busy):
        if not present:
            self.present_since = None
            if self.absent_since is None:
                self.absent_since = now
            if now - self.absent_since >= self.debounce:
                self.consumed = False
                self.rearmed = True
            return 'waiting_for_drive'
        self.absent_since = None
        if busy:
            if self.rearmed and not self.consumed:
                self.present_since = None
                return 'waiting_for_previous_cleanup'
            # Observe an existing/manual runtime without starting a competitor.
            # If it stops, remain stopped until the next physical connection.
            self.consumed = True
            self.present_since = None
            return 'runtime_active'
        if self.consumed:
            return 'waiting_for_reconnect'
        if not started:
            self.present_since = None
            return 'waiting_for_device_start'
        if self.present_since is None:
            self.present_since = now
        if now - self.present_since < self.debounce:
            return 'settling'
        self.consumed = True
        self.rearmed = False
        return 'launch'


def kernel_api():
    k = C.WinDLL('kernel32', use_last_error=True)
    k.OpenMutexW.argtypes = [W.DWORD, W.BOOL, W.LPCWSTR]
    k.OpenMutexW.restype = W.HANDLE
    k.CreateMutexW.argtypes = [C.c_void_p, W.BOOL, W.LPCWSTR]
    k.CreateMutexW.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    k.CloseHandle.restype = W.BOOL
    k.ReleaseMutex.argtypes = [W.HANDLE]
    k.ReleaseMutex.restype = W.BOOL
    return k


def mutex_exists(k, name):
    handle = k.OpenMutexW(0x100000, False, name)  # SYNCHRONIZE only
    if handle:
        k.CloseHandle(handle)
        return True
    error = C.get_last_error()
    if error == 2:
        return False
    raise C.WinError(error)  # Access denied is not evidence that a reader exited.


def read_runtime():
    try:
        record = json.loads(RUNTIME_STATE.read_text(encoding='utf-8'))
        return {key: record.get(key) for key in ('status', 'pid', 'time', 'error')}
    except (OSError, ValueError) as exc:
        return {'status': 'unavailable', 'error': str(exc)}


def emit(event, **fields):
    with LOG.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'time': datetime.now().astimezone().isoformat(),
                                 'event': event, **fields}) + '\n')


def write_status(status, **fields):
    record = {'status': status, 'pid': os.getpid(),
              'time': datetime.now().astimezone().isoformat(), **fields}
    temp = STATE.with_suffix('.tmp')
    temp.write_text(json.dumps(record, indent=2), encoding='utf-8')
    # Readers may momentarily hold the file without delete sharing.
    for attempt in range(25):
        try:
            temp.replace(STATE)
            return
        except PermissionError:
            if attempt == 24:
                raise
            time.sleep(.02)


def launch_runtime():
    # python.exe is required: inventory helpers capture stdout from child Python.
    python = Path(sys.executable).with_name('python.exe')
    with (OUT / 'dvd-autostart-runtime.log').open('a', encoding='utf-8') as stream:
        return subprocess.Popen([str(python), str(RUNTIME)], cwd=str(BASE),
                                stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.STDOUT, shell=False,
                                creationflags=0x08000000)


def main():
    if sys.argv[1:]:
        raise RuntimeError('The watcher does not accept commands or arguments')
    if not C.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('Install the administrator-approved DVD startup task first')
    from dvd_device_identity import exact_device_status, discover_disk_interface
    os.chdir(BASE)
    k = kernel_api()
    handle = k.CreateMutexW(None, True, r'Local\CodexInitioDvdAutostart')
    if not handle:
        raise C.WinError(C.get_last_error())
    if C.get_last_error() == 183:
        k.CloseHandle(handle)
        return
    policy = ConnectionPolicy()
    child = None
    last = None
    written = 0
    emit('watcher_started')
    try:
        while not STOP.exists():
            now = time.monotonic()
            try:
                if child is not None and child.poll() is not None:
                    emit('runtime_exited', child_pid=child.pid, exit_code=child.returncode)
                    child = None
                device = exact_device_status()
                busy = child is not None or any(mutex_exists(k, name) for name in RUNTIME_LOCKS)
                action = policy.step(now, present=device['present'],
                                     started=device['started'], busy=busy)
                if action == 'launch':
                    # Narrow the race with a second PnP/mutex check; runtime
                    # itself takes exclusive ownership and resolves identity.
                    fresh = exact_device_status()
                    if (fresh['present'] and fresh['started'] and
                            not any(mutex_exists(k, name) for name in RUNTIME_LOCKS)):
                        try:
                            # USB can start before its storage child appears.
                            # Only PnP is read here; do not consume an attempt
                            # until Windows exposes the exact disk interface.
                            discover_disk_interface()
                        except Exception:
                            policy.consumed = False
                            raise
                        child = launch_runtime()
                        emit('runtime_launched', child_pid=child.pid, instance=device['instance'])
                        action = 'runtime_starting'
                    else:
                        action = 'connection_changed_before_launch'
                fields = {'device': device, 'runtime': read_runtime(),
                          'child_pid': child.pid if child else None,
                          'attempted_this_connection': policy.consumed}
            except Exception as exc:
                # No controller reset, process termination or auto retry storm.
                # A discovery error cannot rearm this physical connection.
                action = 'watch_error'
                policy.interrupted()
                fields = {'error': str(exc), 'runtime': read_runtime()}
            signature = json.dumps([action, fields], sort_keys=True)
            if signature != last or now - written >= 30:
                write_status(action, **fields)
                if signature != last:
                    emit('watch_state', status=action, **fields)
                last, written = signature, now
            time.sleep(2)
        write_status('disabled', runtime=read_runtime())
        emit('watcher_stopped', runtime_left_running=True)
    finally:
        # The ordinary utility remains independent. Disabling autostart must
        # never stop a film, even when this watcher originally started it.
        k.ReleaseMutex(handle)
        k.CloseHandle(handle)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        emit('watcher_failed', error=str(exc))
        raise
