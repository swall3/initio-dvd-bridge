"""Serialized read-only sector backend for the experimentally recovered DVD.

Only the owning thread touches the bridge. Transport errors end the session and
resume the Initio CPU. Completed media/command errors fail only that request.
"""
import concurrent.futures
import ctypes
import queue
import threading
import time
import traceback
import live_usb_transport as t
from optical_lun import ScsiError, ScsiResult
from dvd_auth_commands import validate_auth_command, validate_auth_cdb


def completed_read_error(result):
    """Decode actual Windows autosense only after a completed CHECK CONDITION.

    Media changes, missing media, malformed sense, and transport errors remain
    fatal: this reader's capacity and optical view are fixed for the session.
    """
    if not result.get('ioctl_success') or result.get('scsi_status') != 2:
        return None
    try:
        sense = bytes.fromhex(result.get('sense', ''))
    except (TypeError, ValueError):
        return None
    if len(sense) < 8:
        return None
    fmt = sense[0] & 0x7f
    if fmt == 0x70 and len(sense) >= 14 and sense[7] >= 6:
        key, asc, ascq = sense[2] & 15, sense[12], sense[13]
    elif fmt == 0x72:
        key, asc, ascq = sense[1] & 15, sense[2], sense[3]
    else:
        return None
    if key not in (3, 5, 7):
        return None
    return ScsiError(key, asc, ascq)


class LiveUsbReader:
    def __init__(self, chunk_blocks=1):
        if chunk_blocks not in (1, 2, 4, 8, 16):
            raise ValueError('Unvalidated transfer size')
        self.chunk_blocks = chunk_blocks
        self.requests = queue.Queue()
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.cleanup_error = None
        self.info = None
        self.css_feature = None
        # A process must not exit normally while an SPTI operation still owns
        # this drive. close() remains bounded for the caller; this owner does not.
        self.thread = threading.Thread(target=self._run, name='DVD hardware owner', daemon=False)
        self.thread.start()
        if not self.ready.wait(30):
            self.close()
            raise TimeoutError('DVD initialization timed out')
        if self.error:
            self.close()
            raise RuntimeError(str(self.error)) from self.error

    def _service_pending(self, deadline, seen, watch=False):
        item = t.claim_pending(t.h, True, deadline, watch)
        if item:
            # Another Windows request may be claimed just as our SPTI finishes.
            # Its different CDB still owns a real USB context that must finish.
            # Keep the completion guard for a matching (possibly our own) CDB.
            own_cdb=getattr(t.disk,'cdb',None)
            watch_this=watch and (own_cdb is None or item['cdb']==own_cdb.ljust(12,b'\0'))
            t.service_pending(t.h, item, deadline, watch_this, seen)
            return True
        return False

    def _service_idle_pending(self, seen):
        # A completed synchronous acquisition can outlast the old idle budget
        # without ever starting a SATA command. Only a freshly revalidated TUR
        # may receive a separate service budget; active I/O never uses this path.
        started=time.monotonic()
        t.require_idle_worker()
        acquisition_deadline=started+20
        item=t.claim_pending(t.h,True,acquisition_deadline,False)
        t.check_bound(acquisition_deadline)
        if not item:return False
        if item['kind']=='tur':
            t.revalidate_idle_tur(t.h,item,acquisition_deadline)
            t.check_bound(acquisition_deadline)
            deadline=time.monotonic()+8
        else:
            # Other background commands retain the original overall8s bound.
            deadline=started+8
            t.check_bound(deadline)
        t.service_pending(t.h,item,deadline,False,seen)
        return True

    def _read(self, lba, blocks):
        # Give existing Windows work a small head start, then enqueue our read.
        # Disk-class probing can keep generating new CAPACITY/READ0 commands;
        # requiring an empty queue starves an otherwise valid SPTI request.
        deadline = time.monotonic() + 8
        seen = set()
        drained = 0
        while drained < 2 and t.read(t.h, 0xc051) & 0x10:
            self._service_pending(deadline, seen)
            drained += 1
        t.disk.start(lba, blocks)
        t.log('live_read_queued', lba=lba, blocks=blocks)
        deadline = time.monotonic() + 12
        serviced = 0
        while t.disk.result is None:
            t.check_bound(deadline)
            if serviced >= 64:
                raise RuntimeError('Unexpected queue size during sector read')
            if self._service_pending(deadline, seen, True):
                serviced += 1
            else:
                time.sleep(.002)
        t.disk.wait(.1)
        result = t.disk.result
        payload = result.get('data', b'')
        t.log('live_read_result', lba=lba, blocks=blocks,
              **{k: v for k, v in result.items() if k != 'data'})
        command_error = completed_read_error(result)
        if command_error is not None:
            raise command_error
        if not (result.get('ioctl_success') and result.get('scsi_status') == 0
                and result.get('transferred') == blocks * 2048
                and len(payload) == blocks * 2048):
            raise OSError('DVD read did not complete with exact data length')
        return payload

    def _auth(self, cdb, size, direction, data_out=b''):
        cdb=validate_auth_command(cdb,size,direction,data_out)
        kind=validate_auth_cdb(cdb,size,direction)
        deadline=time.monotonic()+8
        seen=set()
        for _ in range(2):
            if not(t.read(t.h,0xc051)&0x10):break
            self._service_pending(deadline,seen)
        t.disk.start_auth(cdb,size,direction,data_out)
        t.log('auth_queued',kind=kind,cdb=cdb.hex(),length=size,direction=direction)
        deadline=time.monotonic()+12
        serviced=0
        while t.disk.result is None:
            t.check_bound(deadline)
            if serviced>=64:raise RuntimeError('Unexpected queue size during DVD authentication')
            if self._service_pending(deadline,seen,True):serviced+=1
            else:time.sleep(.002)
        t.disk.wait(.1)
        result=t.disk.result
        t.log('auth_result',kind=kind,**{k:v for k,v in result.items() if k!='data'})
        if not result.get('ioctl_success'):
            raise OSError('DVD authentication transport did not complete')
        if result.get('scsi_status')==2:
            condition=completed_read_error(result)
            if condition is None:
                raise OSError('DVD authentication returned a terminal or malformed sense condition')
            return ScsiResult(2,sense=bytes.fromhex(result['sense']))
        data=result.get('data',b'')
        transferred=result.get('transferred')
        if (result.get('scsi_status')!=0 or type(transferred) is not int or
                not 0<=transferred<=size or
                (direction=='in' and len(data)!=transferred) or
                (direction!='in' and (data or transferred!=size))):
            raise OSError('DVD authentication returned an inconsistent transfer result')
        return ScsiResult(data=data)

    def _probe_css(self):
        result=self._auth(bytes.fromhex('460201060000000010000000'),16,'in')
        if result.status:
            t.log('css_feature_unavailable',sense=result.sense.hex())
            return
        data=result.data
        if len(data)>=16 and data[8:10]==b'\x01\x06' and data[11]==4:
            self.css_feature=data[8:16]
            t.log('css_feature_observed',descriptor=self.css_feature.hex())
        else:
            t.log('css_feature_absent',response=data.hex())

    def _complete_request(self, lba, blocks, future):
        try:
            data = bytearray()
            for offset in range(0, blocks, self.chunk_blocks):
                if self.stop_event.is_set():
                    raise RuntimeError('DVD reader stopped')
                count = min(blocks-offset, self.chunk_blocks)
                data.extend(self._read(lba+offset, count))
        except ScsiError as exc:
            # The USB command and its autosense completed. Preserve the drive's
            # real condition, discard any partial request data, and accept the
            # next request without reinitializing the bridge.
            t.log('live_read_check_condition', lba=lba, blocks=blocks,
                  key=exc.key, asc=exc.asc, ascq=exc.ascq)
            future.set_exception(exc)
        else:
            future.set_result(bytes(data))

    def _run(self):
        active = None
        mutex = None
        owns_transport = False
        try:
            from ctypes import wintypes
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
            kernel.CreateMutexW.restype = wintypes.HANDLE
            kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            mutex = kernel.CreateMutexW(None, True, r'Local\CodexInitioDvdReader')
            if not mutex:
                raise ctypes.WinError(ctypes.get_last_error())
            if ctypes.get_last_error() == 183:
                raise RuntimeError('Another DVD reader owns this device')
            owns_transport = True
            self.info = t.open_transport()
            self._probe_css()
            self.ready.set()
            idle_seen = set()
            while not self.stop_event.is_set():
                try:
                    lba, blocks, active = self.requests.get_nowait()
                except queue.Empty:
                    if not self._service_idle_pending(idle_seen):
                        # Completed host tags may be reused by later TUR polls.
                        # Duplicate protection applies only while this queue
                        # remains nonempty, not across the lifetime of a drive.
                        idle_seen.clear()
                        time.sleep(.01)
                    continue
                if lba=='auth':
                    active.set_result(self._auth(*blocks))
                else:
                    self._complete_request(lba, blocks, active)
                active = None
        except BaseException as exc:
            self.error = exc
            try:
                t.log('live_reader_error', error=str(exc), type=type(exc).__name__,traceback=traceback.format_exc())
            except BaseException as log_exc:
                self._cleanup_failed(log_exc)
            finally:
                if active and not active.done():
                    active.set_exception(exc)
        finally:
            self.stop_event.set()
            self.ready.set()
            try:
                while True:
                    try:
                        _, _, future = self.requests.get_nowait()
                        if not future.done():
                            future.set_exception(RuntimeError(str(self.error or 'DVD reader stopped')))
                    except queue.Empty:
                        break
            finally:
                try:
                    if owns_transport:
                        try:
                            t.close_transport()
                        except BaseException as exc:
                            self._cleanup_failed(exc)
                finally:
                    # Even an unexpected cleanup exception must not release the
                    # cross-process owner while Windows still has the IOCTL.
                    if owns_transport:
                        t.wait_for_worker()
                    if mutex:
                        try:
                            if owns_transport and not kernel.ReleaseMutex(mutex):
                                self._cleanup_failed(ctypes.WinError(ctypes.get_last_error()))
                        finally:
                            if not kernel.CloseHandle(mutex):
                                self._cleanup_failed(ctypes.WinError(ctypes.get_last_error()))

    def _cleanup_failed(self, exc):
        if self.cleanup_error is None:
            self.cleanup_error = exc
        else:
            self.cleanup_error = RuntimeError(str(self.cleanup_error) + '; ' + str(exc))

    def read_blocks(self, lba, blocks):
        if self.error or self.stop_event.is_set():
            raise OSError(str(self.error or 'DVD reader stopped'))
        if not (isinstance(lba, int) and isinstance(blocks, int)
                and lba >= 0 and 0 <= blocks <= 512
                and lba + blocks <= self.info['blocks']):
            raise ValueError('Read outside verified disc capacity or request limit')
        if not blocks:
            return b''
        future = concurrent.futures.Future()
        self.requests.put((lba, blocks, future))
        # Individual USB commands retain their 12-second bound. Do not abandon
        # an in-flight device request and start a second hardware owner.
        try:
            return future.result(timeout=90)
        except concurrent.futures.TimeoutError:
            self.stop_event.set()
            raise TimeoutError('DVD read exceeded the bounded request budget')

    def close(self):
        self.stop_event.set()
        self.thread.join(35)
        if self.thread.is_alive():
            raise RuntimeError('DVD cleanup incomplete: owner still shutting down; no replacement reader may start')
        if self.cleanup_error is not None:
            raise RuntimeError('DVD cleanup failed: ' + str(self.cleanup_error)) from self.cleanup_error

    def auth_command(self,cdb,expected_length,direction,data_out=b''):
        if self.error or self.stop_event.is_set():
            raise OSError(str(self.error or 'DVD reader stopped'))
        cdb=validate_auth_command(cdb,expected_length,direction,data_out)
        future=concurrent.futures.Future()
        self.requests.put(('auth',(cdb,expected_length,direction,bytes(data_out)),future))
        try:return future.result(timeout=30)
        except concurrent.futures.TimeoutError:
            self.stop_event.set()
            raise TimeoutError('DVD authentication exceeded its bounded request budget')

