"""Offline exact-device discovery/open guards; no native or hardware access."""
import ctypes as C
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dvd_device_identity as d
import scsi_block_worker as s


class Inventory:
    def __init__(self):
        self.nodes = {1: d.USB_INSTANCE, 2: d.DISK_INSTANCE,
                      3: r'USB\VID_0BDA&PID_9210\TEST_OTHER_DISK',
                      4: r'USBSTOR\Disk&Ven_Realtek\TEST_OTHER_DISK&0'}
        self.parents = {2: 1, 4: 3, 1: None, 3: None}
        self.states = {node: (8, 0) for node in self.nodes}
        self.interfaces = [{'path': r'\\?\realtek-disk', 'devinst': 4},
                           {'path': r'\\?\exact-dvd-interface', 'devinst': 2}]
        self.located = 1
    def locate(self, instance):
        assert instance == d.USB_INSTANCE
        return self.located
    def instance(self, node):
        return self.nodes[node]
    def status(self, node):
        return self.states[node]
    def parent(self, node):
        return self.parents[node]
    def disk_interfaces(self):
        return list(self.interfaces)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.native = Inventory()

    def test_other_usb_disk_excluded_and_enumeration_order_irrelevant(self):
        a = d.discover_disk_interface(self.native)
        self.native.interfaces.reverse()
        self.assertEqual(a, d.discover_disk_interface(self.native))
        self.assertEqual(a['path'], r'\\?\exact-dvd-interface')
        self.assertNotIn('PhysicalDrive', a['path'])

    def test_changed_interface_path_is_discovered_again(self):
        self.native.interfaces[1]['path'] = r'\\?\dvd-after-reconnect'
        self.assertEqual(d.discover_disk_interface(self.native)['path'], r'\\?\dvd-after-reconnect')

    def test_absent_usb_does_not_enumerate_disks(self):
        self.native.located = None
        self.native.disk_interfaces = lambda: self.fail('Absent USB must not enumerate')
        self.assertFalse(d.exact_device_status(self.native)['present'])
        with self.assertRaises(d.DeviceIdentityError):
            d.discover_disk_interface(self.native)

    def test_failed_usb_node_is_present_but_not_started(self):
        self.native.states[1] = (d.DN_HAS_PROBLEM | d.DN_STARTED, 43)
        result = d.exact_device_status(self.native)
        self.assertTrue(result['present'])
        self.assertFalse(result['started'])
        self.assertEqual(result['problem'], 43)
        with self.assertRaises(d.DeviceIdentityError):
            d.discover_disk_interface(self.native)

    def test_query_errors_are_not_reported_as_removal(self):
        self.native.locate = lambda _: (_ for _ in ()).throw(OSError('denied'))
        with self.assertRaises(OSError):
            d.exact_device_status(self.native)

    def test_exact_disk_name_with_wrong_usb_parent_rejected(self):
        self.native.parents[2] = 3
        with self.assertRaises(d.DeviceIdentityError):
            d.discover_disk_interface(self.native)

    def test_unstarted_disk_and_duplicate_interfaces_rejected(self):
        self.native.states[2] = (0, 0)
        with self.assertRaises(d.DeviceIdentityError):
            d.discover_disk_interface(self.native)
        self.native.states[2] = (8, 0)
        self.native.interfaces.append({'path': r'\\?\duplicate-dvd', 'devinst': 2})
        with self.assertRaises(d.DeviceIdentityError):
            d.discover_disk_interface(self.native)

    def test_same_model_other_serial_and_other_lun_rejected(self):
        for instance in (d.DISK_INSTANCE.replace('&0', '&1'), d.DISK_INSTANCE + 'different'):
            self.native.nodes[2] = instance
            with self.assertRaises(d.DeviceIdentityError):
                d.discover_disk_interface(self.native)

    def test_ancestry_loop_fails_closed(self):
        self.native.parents[2] = 2
        with self.assertRaisesRegex(d.DeviceIdentityError, 'Cyclic'):
            d.discover_disk_interface(self.native)

    def test_disappearance_during_enumeration_rejected(self):
        def changing_interfaces():
            self.native.located = None
            return self.native.interfaces
        self.native.disk_interfaces = changing_interfaces
        with self.assertRaisesRegex(d.DeviceIdentityError, 'changed'):
            d.discover_disk_interface(self.native)

    def test_case_insensitive_windows_instance_ids(self):
        self.native.nodes = {node: name.lower() for node, name in self.native.nodes.items()}
        self.assertEqual(d.discover_disk_interface(self.native)['path'], r'\\?\exact-dvd-interface')


class Function:
    def __init__(self, callback): self.callback = callback
    def __call__(self, *args): return self.callback(*args)


def descriptor(vendor='Initio', product='Ini-3910', serial=d.STORAGE_SERIAL):
    raw = bytearray(36)
    for position, value in ((12, vendor), (16, product), (24, serial)):
        struct.pack_into('<I', raw, position, len(raw))
        raw.extend(value.encode('ascii') + b'\0')
    struct.pack_into('<II', raw, 0, 36, len(raw))
    return bytes(raw)


class WorkerOpenTests(unittest.TestCase):
    def open_mocked(self, raw=None, targets=None):
        raw = descriptor() if raw is None else raw
        target = {'path': r'\\?\dvd-current-interface', 'devinst': 2,
                  'instance': d.DISK_INSTANCE, 'usb_instance': d.USB_INSTANCE}
        calls = []
        def open_file(path, *args):
            calls.append(('open', path))
            return 123
        def ioctl(handle, code, query, size, out, capacity, count, overlap):
            calls.append(('ioctl', code))
            self.assertEqual(code, 0x2d1400, 'No SCSI/media command is permitted in identity tests')
            C.memmove(out, raw, len(raw))
            count._obj.value = len(raw)
            return True
        kernel = SimpleNamespace(CreateFileW=Function(open_file),
                                 DeviceIoControl=Function(ioctl),
                                 CloseHandle=Function(lambda handle: calls.append(('close', handle))))
        with patch.object(s.C, 'WinDLL', return_value=kernel), \
             patch.object(s, 'discover_disk_interface', side_effect=targets or [target, target]):
            try:
                worker = s.ScsiRead()
                worker.close()
                return calls, worker, None
            except Exception as exc:
                return calls, None, exc

    def test_open_uses_selected_interface_and_closes_handle(self):
        calls, worker, error = self.open_mocked()
        self.assertIsNone(error)
        self.assertEqual(calls, [('open', r'\\?\dvd-current-interface'), ('ioctl', 0x2d1400), ('close', 123)])
        self.assertEqual(worker.identity['serial'], d.STORAGE_SERIAL)

    def test_wrong_model_or_serial_closed_before_scsi(self):
        for raw in (descriptor(vendor='Realtek'), descriptor(serial='another-drive')):
            calls, worker, error = self.open_mocked(raw)
            self.assertIsInstance(error, RuntimeError)
            self.assertIsNone(worker)
            self.assertEqual(calls[-1], ('close', 123))

    def test_truncated_descriptor_rejected(self):
        for raw in (bytes(20), descriptor()[:-1]):
            calls, worker, error = self.open_mocked(raw)
            self.assertIsInstance(error, RuntimeError)
            self.assertEqual(calls[-1], ('close', 123))

    def test_out_of_bounds_offset_rejected(self):
        raw = bytearray(descriptor())
        struct.pack_into('<I', raw, 24, len(raw) + 1)
        calls, worker, error = self.open_mocked(bytes(raw))
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(calls[-1], ('close', 123))

    def test_discovery_failure_opens_nothing(self):
        calls, worker, error = self.open_mocked(targets=[d.DeviceIdentityError('not found')])
        self.assertIsInstance(error, d.DeviceIdentityError)
        self.assertEqual(calls, [])

    def test_interface_change_after_open_closes_before_scsi(self):
        a = {'path': r'\\?\first'}
        b = {'path': r'\\?\second'}
        calls, worker, error = self.open_mocked(targets=[a, b])
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(calls[-1], ('close', 123))


class NativeBoundaryTests(unittest.TestCase):
    def native(self, locate_result=0):
        def locate(out, instance, flags):
            self.assertEqual(flags, 0, 'Do not include phantoms or cancel removal')
            self.assertEqual(instance.value, d.USB_INSTANCE)
            out._obj.value = 7
            return locate_result
        library = SimpleNamespace(CM_Locate_DevNodeW=Function(locate),
            CM_Get_DevNode_Status=Function(lambda *a: 0),
            CM_Get_Device_IDW=Function(lambda *a: 0),
            CM_Get_Parent=Function(lambda *a: d.CR_NO_SUCH_DEVNODE))
        with patch.object(d.C, 'WinDLL', return_value=library):
            return d.NativeInventory()

    def test_normal_locator_distinguishes_absence_from_api_error(self):
        self.assertEqual(self.native().locate(d.USB_INSTANCE), 7)
        self.assertIsNone(self.native(d.CR_NO_SUCH_DEVNODE).locate(d.USB_INSTANCE))
        with self.assertRaises(d.DeviceIdentityError):
            self.native(51).locate(d.USB_INSTANCE)  # CR_ACCESS_DENIED

    def test_interface_abi_path_and_present_flag(self):
        calls = []
        path = r'\\?\opaque-disk-interface'
        payload = path.encode('utf-16-le') + b'\0\0'
        def get_class(guid, enumerator, window, flags):
            self.assertEqual(flags, 0x12)
            return 999
        def enum(handle, device, guid, index, interface):
            self.assertEqual(interface._obj.cbSize, C.sizeof(d.InterfaceData))
            if index:
                C.set_last_error(259)
                return False
            return True
        def detail(handle, interface, buffer, capacity, needed, device):
            needed._obj.value = 4 + len(payload)
            if buffer is None:
                C.set_last_error(122)
                return False
            self.assertEqual(d.W.DWORD.from_buffer(buffer).value, 8 if C.sizeof(C.c_void_p) == 8 else 6)
            self.assertEqual(device._obj.cbSize, C.sizeof(d.DeviceData))
            C.memmove(C.addressof(buffer) + 4, payload, len(payload))
            device._obj.DevInst = 27
            return True
        api = SimpleNamespace(SetupDiGetClassDevsW=Function(get_class),
            SetupDiEnumDeviceInterfaces=Function(enum),
            SetupDiGetDeviceInterfaceDetailW=Function(detail),
            SetupDiDestroyDeviceInfoList=Function(lambda h: calls.append(('destroy', h)) or True))
        native = self.native()
        with patch.object(d.C, 'WinDLL', return_value=api):
            self.assertEqual(native.disk_interfaces(), [{'path': path, 'devinst': 27}])
        self.assertEqual(calls, [('destroy', 999)])


if __name__ == '__main__':
    unittest.main()

