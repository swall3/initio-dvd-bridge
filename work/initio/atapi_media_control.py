"""Fixed ATAPI ALLOW MEDIUM REMOVAL for a held, exclusively owned bridge.

No device is opened here. The caller supplies the existing held-CPU handle and
transport, and calls this only after finishing its queued Windows requests.
The command mirrors ROM 6097..6100 / 616F..617A and the proven TUR SATA path.
It never sends a USB data stage or CSW, resets a buffer, or changes CC32/CC33.
"""
import time


ALLOW_CDB = bytes.fromhex('1e0000000000000000000000')
CONTEXT_FIELDS = (0xcc01, 0xcc03, 0xcc0e, 0xcc2a, 0xcc2f,
                  *range(0xcc08, 0xcc0c), *range(0xcc10, 0xcc1c))


def unlock(h, transport):
    """Return actual ATA status/error and verified context-restoration results.

``status`` is 0 (success), 1 (device ERR), or None (no proven completion).
``ok`` requires successful completion and exact restoration. Failure leaves the
caller's physical-lock flag unchanged. No REQUEST SENSE consumes drive sense.
An active USB/SPTI request, pending CBW, or non-idle SATA engine is refused.
"""
    t = transport
    result = dict(ok=False, issued=False, completed=False, status=None,
                  task=None, error=None, context=None, restored=True,
                  failure=None, restoration_errors=[])
    saved = {}
    tag = None
    context = None
    dirty = False
    e03c_touched = False

    def check_context():
        if t.read(h, 0xc04c) != context:
            raise RuntimeError('Unlock context selection changed')
        if t.mem(h, 0x1cc04, 4) != tag:
            raise RuntimeError('Unlock context was reused by a Windows command')

    def check_idle_usb():
        if t.read(h, 0xd100) & 0x10:
            raise RuntimeError('USB reset state prevents synthetic unlock')
        if t.read(h, 0xd114) & 1:
            raise RuntimeError('USB data stage is active; unlock not issued')
        if t.read(h, 0xc051) & 0x10:
            raise RuntimeError('A Windows CBW is pending; unlock not issued')

    try:
        worker = getattr(getattr(t, 'disk', None), 'thread', None)
        if worker is not None and worker.is_alive():
            raise RuntimeError('Windows SPTI is still active; unlock not issued')
        check_idle_usb()
        if t.read(h, 0xe08c) & 0x88:
            raise RuntimeError('SATA is BUSY or requesting data; unlock not issued')
        if not t.read(h, 0xe014) & 1:
            raise RuntimeError('SATA link is unavailable; unlock not issued')
        if t.read(h, 0xe03c) != 0:
            raise RuntimeError('SATA translator has a pending command; unlock not issued')
        context = t.read(h, 0xc04c)
        result['context'] = context
        tag = t.mem(h, 0x1cc04, 4)
        saved = {address: t.read(h, address) for address in CONTEXT_FIELDS}
        check_context()
        desired = {0xcc01: saved[0xcc01] & 0x7f, 0xcc03: 0xc0,
                   0xcc0e: 2, 0xcc2a: 1, 0xcc2f: 0x40}
        desired.update({address: 0 for address in range(0xcc08, 0xcc0c)})
        desired.update({0xcc10 + i: value for i, value in enumerate(ALLOW_CDB)})
        dirty = True
        result['restored'] = False
        for address, value in desired.items():
            t.write(h, address, value)
        check_context()
        if any(t.read(h, address) != value for address, value in desired.items()):
            raise RuntimeError('Unlock context injection did not verify')
        check_idle_usb()
        for address in (0xe008, 0xe030, 0xe031, 0xe000, 0xe001):
            t.write(h, address, 0xff)
        e03c_touched = True
        t.write(h, 0xe03c, 1)
        try:
            t.write(h, 0xe01f, 1)
            t.write(h, 0xd1d0, context)
            deadline = time.monotonic() + .75
            while t.read(h, 0xd1d1) & 0x80:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Unlock translator did not finish')
                time.sleep(.002)
            for address in range(0xe188, 0xe18c):
                t.write(h, address, 0)
            check_context()
            t.write(h, 0xe024, 1)
            # Mark before issue: a failing USB debug response does not
            # establish that the device failed to accept the command.
            result['issued'] = True
            t.write(h, 0xe08c, 0x80)
        finally:
            t.write(h, 0xe03c, 0)
            e03c_touched = False
        deadline = time.monotonic() + 2
        status_received = False
        while True:
            event = t.read(h, 0xe000)
            status_event = t.read(h, 0xe030)
            task = t.read(h, 0xe08c)
            error = t.read(h, 0xe08d)
            result.update(task=task, error=error)
            if event & 0x10 or not t.read(h, 0xe014) & 1:
                raise RuntimeError('Unlock encountered a SATA transport failure')
            if status_event & 1:
                status_received = True
                t.write(h, 0xe030, 1)
                task, error = t.read(h, 0xe08c), t.read(h, 0xe08d)
                result.update(task=task, error=error)
            if status_received and not task & 0x80:
                result.update(completed=True, status=int(bool(task & 1)))
                t.write(h, 0xe030, 1)
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('Unlock command did not complete')
            time.sleep(.002)
        check_context()
    except Exception as exc:
        result['failure'] = str(exc)
    finally:
        if e03c_touched:
            try:
                t.write(h, 0xe03c, 0)
            except Exception as exc:
                result['restoration_errors'].append('E03C clear: ' + str(exc))
        if dirty:
            try:
                if t.read(h, 0xc04c) != context:
                    t.write(h, 0xc04c, context)
                # Never restore old CDB fields over a newly reused context.
                check_context()
                for address, value in saved.items():
                    try:
                        t.write(h, address, value)
                    except Exception as exc:
                        result['restoration_errors'].append(hex(address) + ': ' + str(exc))
                check_context()
                for address, value in saved.items():
                    actual = t.read(h, address)
                    if actual != value:
                        result['restoration_errors'].append(
                            f'{address:04x}: expected {value:02x}, got {actual:02x}')
                result['restored'] = not result['restoration_errors']
            except Exception as exc:
                result['restoration_errors'].append(str(exc))
                result['restored'] = False
    result['ok'] = (result['completed'] and result['status'] == 0
                    and result['restored'] and not result['failure']
                    and not result['restoration_errors'])
    return result
