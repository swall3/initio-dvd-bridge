"""Read-only Windows PnP identity for the one supported Initio DVD.

No disk is opened and no device command, rescan, reset, or power request is sent.
SetupAPI paths are opaque CreateFile names, never parsed or reconstructed:
https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetailw
https://learn.microsoft.com/windows-hardware/drivers/install/enumerating-installed-device-interface-classes
ConfigMgr NORMAL excludes phantom devices; status confirms DN_STARTED:
https://learn.microsoft.com/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_locate_devnodew
https://learn.microsoft.com/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_devnode_status
"""
import ctypes as C
from ctypes import wintypes as W
import uuid

USB_INSTANCE = r'USB\VID_13FD&PID_3910\303030303030303030303030'
DISK_INSTANCE = r'USBSTOR\Disk&Ven_Initio&Prod_Ini-3910&Rev_0104\303030303030303030303030&0'
STORAGE_SERIAL = '00000000000000000000'
CR_NO_SUCH_DEVNODE = 13
DN_STARTED = 0x8
DN_HAS_PROBLEM = 0x400


class GUID(C.Structure):
    _fields_ = [('Data1', W.DWORD), ('Data2', W.WORD), ('Data3', W.WORD),
                ('Data4', W.BYTE * 8)]


class InterfaceData(C.Structure):
    _fields_ = [('cbSize', W.DWORD), ('InterfaceClassGuid', GUID),
                ('Flags', W.DWORD), ('Reserved', C.c_size_t)]


class DeviceData(C.Structure):
    _fields_ = [('cbSize', W.DWORD), ('ClassGuid', GUID),
                ('DevInst', W.DWORD), ('Reserved', C.c_size_t)]


class DeviceIdentityError(RuntimeError):
    pass


class NativeInventory:
    def __init__(self):
        self.cm = C.WinDLL('cfgmgr32', use_last_error=True)
        self.cm.CM_Locate_DevNodeW.argtypes = [C.POINTER(W.ULONG), W.LPWSTR, W.ULONG]
        self.cm.CM_Get_DevNode_Status.argtypes = [C.POINTER(W.ULONG), C.POINTER(W.ULONG), W.ULONG, W.ULONG]
        self.cm.CM_Get_Device_IDW.argtypes = [W.ULONG, W.LPWSTR, W.ULONG, W.ULONG]
        self.cm.CM_Get_Parent.argtypes = [C.POINTER(W.ULONG), W.ULONG, W.ULONG]
        for name in ('CM_Locate_DevNodeW', 'CM_Get_DevNode_Status', 'CM_Get_Device_IDW', 'CM_Get_Parent'):
            getattr(self.cm, name).restype = W.ULONG

    def locate(self, instance):
        node = W.ULONG()
        result = self.cm.CM_Locate_DevNodeW(C.byref(node), C.create_unicode_buffer(instance), 0)
        if result == CR_NO_SUCH_DEVNODE:
            return None
        if result:
            raise DeviceIdentityError(f'Cannot locate DVD devnode: CONFIGRET {result}')
        return node.value

    def status(self, node):
        status, problem = W.ULONG(), W.ULONG()
        result = self.cm.CM_Get_DevNode_Status(C.byref(status), C.byref(problem), node, 0)
        if result:
            raise DeviceIdentityError(f'Cannot read DVD devnode status: CONFIGRET {result}')
        return status.value, problem.value if status.value & DN_HAS_PROBLEM else 0

    def instance(self, node):
        value = C.create_unicode_buffer(512)
        result = self.cm.CM_Get_Device_IDW(node, value, len(value), 0)
        if result:
            raise DeviceIdentityError(f'Cannot read disk ancestry: CONFIGRET {result}')
        return value.value

    def parent(self, node):
        parent = W.ULONG()
        result = self.cm.CM_Get_Parent(C.byref(parent), node, 0)
        if result == CR_NO_SUCH_DEVNODE:
            return None
        if result:
            raise DeviceIdentityError(f'Cannot read disk parent: CONFIGRET {result}')
        return parent.value

    def disk_interfaces(self):
        api = C.WinDLL('setupapi', use_last_error=True)
        api.SetupDiGetClassDevsW.argtypes = [C.POINTER(GUID), W.LPCWSTR, W.HWND, W.DWORD]
        api.SetupDiGetClassDevsW.restype = W.HANDLE
        api.SetupDiEnumDeviceInterfaces.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(GUID), W.DWORD, C.POINTER(InterfaceData)]
        api.SetupDiEnumDeviceInterfaces.restype = W.BOOL
        api.SetupDiGetDeviceInterfaceDetailW.argtypes = [W.HANDLE, C.POINTER(InterfaceData), C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.POINTER(DeviceData)]
        api.SetupDiGetDeviceInterfaceDetailW.restype = W.BOOL
        api.SetupDiDestroyDeviceInfoList.argtypes = [W.HANDLE]
        api.SetupDiDestroyDeviceInfoList.restype = W.BOOL
        guid = GUID.from_buffer_copy(uuid.UUID('53f56307-b6bf-11d0-94f2-00a0c91efb8b').bytes_le)
        info = api.SetupDiGetClassDevsW(C.byref(guid), None, None, 0x12)  # PRESENT | DEVICEINTERFACE
        if info == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        rows = []
        try:
            for index in range(1024):
                interface = InterfaceData()
                interface.cbSize = C.sizeof(interface)
                if not api.SetupDiEnumDeviceInterfaces(info, None, C.byref(guid), index, C.byref(interface)):
                    error = C.get_last_error()
                    if error == 259:  # ERROR_NO_MORE_ITEMS
                        return rows
                    raise C.WinError(error)
                needed = W.DWORD()
                ok = api.SetupDiGetDeviceInterfaceDetailW(info, C.byref(interface), None, 0, C.byref(needed), None)
                if ok or C.get_last_error() != 122 or not 8 <= needed.value <= 65536:
                    raise DeviceIdentityError('Invalid disk interface buffer size')
                buffer = C.create_string_buffer(needed.value)
                # setupapi.h packs the fixed header to 8 on Win64, 6 on Win32.
                # DevicePath begins at byte 4 on both architectures.
                W.DWORD.from_buffer(buffer).value = 8 if C.sizeof(C.c_void_p) == 8 else 6
                device = DeviceData()
                device.cbSize = C.sizeof(device)
                if not api.SetupDiGetDeviceInterfaceDetailW(info, C.byref(interface), buffer, len(buffer), C.byref(needed), C.byref(device)):
                    raise C.WinError(C.get_last_error())
                if not 8 <= needed.value <= len(buffer) or (needed.value - 4) % 2:
                    raise DeviceIdentityError('Truncated disk interface path')
                path = buffer.raw[4:needed.value].decode('utf-16-le')
                if '\0' not in path or not path.partition('\0')[0]:
                    raise DeviceIdentityError('Unterminated disk interface path')
                rows.append({'path': path.partition('\0')[0], 'devinst': device.DevInst})
            raise DeviceIdentityError('Disk interface enumeration exceeds limit')
        finally:
            api.SetupDiDestroyDeviceInfoList(info)


def exact_device_status(native=None):
    """Return exact USB presence/start status; API errors never mean removal."""
    native = native or NativeInventory()
    node = native.locate(USB_INSTANCE)
    if node is None:
        return {'instance': USB_INSTANCE, 'present': False, 'started': False,
                'problem': None, 'devinst': None}
    if native.instance(node).casefold() != USB_INSTANCE.casefold():
        raise DeviceIdentityError('Located USB devnode identity changed')
    status, problem = native.status(node)
    return {'instance': USB_INSTANCE, 'present': True,
            'started': bool(status & DN_STARTED) and not bool(status & DN_HAS_PROBLEM) and not problem,
            'problem': problem, 'devinst': node}


def _has_exact_usb_parent(native, node):
    seen = set()
    for _ in range(16):
        if node is None:
            return False
        if node in seen:
            raise DeviceIdentityError('Cyclic disk ancestry')
        seen.add(node)
        if native.instance(node).casefold() == USB_INSTANCE.casefold():
            status, problem = native.status(node)
            return bool(status & DN_STARTED) and not (status & DN_HAS_PROBLEM) and not problem
        node = native.parent(node)
    raise DeviceIdentityError('Disk ancestry exceeds limit')


def discover_disk_interface(native=None):
    """Find one current disk child of the exact USB identity; never use a number."""
    native = native or NativeInventory()
    before = exact_device_status(native)
    if not before['started']:
        raise DeviceIdentityError('The exact Initio DVD is absent or not started')
    matches = []
    for entry in native.disk_interfaces():
        instance = native.instance(entry['devinst'])
        # The exact disk instance additionally excludes another LUN/firmware.
        if instance.casefold() != DISK_INSTANCE.casefold():
            continue
        status, problem = native.status(entry['devinst'])
        if status & DN_STARTED and not (status & DN_HAS_PROBLEM) and not problem and _has_exact_usb_parent(native, entry['devinst']):
            matches.append({**entry, 'instance': instance, 'usb_instance': USB_INSTANCE})
    if exact_device_status(native) != before:
        raise DeviceIdentityError('DVD identity changed during discovery')
    if len(matches) != 1:
        raise DeviceIdentityError(f'Expected one exact Initio disk interface, found {len(matches)}')
    return matches[0]
